"""Raw command and byte acquisition for the archived SandMark implementation.

No method in this module emits a relation verdict, an admission fact, or an
expected label. The separate data-only plan declares all judgments.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import zipfile

HERE = Path(__file__).resolve().parent
ALGORITHMS = {row["algorithm"]: row for row in
              json.loads((HERE / "algorithm-contracts.json").read_text())["algorithms"]}
GRAMMARS = {
    "calc": "examples/java/calc/calc.g",
    "exprAST": "examples/java/exprAST/expr.g",
    "java": "examples/java/java/java.g",
}
TTT_INPUTS = {
    "first_player_win": b"1\n4\n2\n5\n3\n",
    "second_player_win": b"1\n4\n2\n5\n9\n6\n",
    "draw": b"1\n2\n3\n5\n4\n6\n8\n7\n9\n",
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_binding(path: Path, root: Path) -> dict:
    raw = path.read_bytes()
    return {"path": path.relative_to(root).as_posix(), "bytes": len(raw), "sha256": sha(raw)}


def jar_inventory(path: Path | io.BytesIO) -> list[dict]:
    with zipfile.ZipFile(path) as archive:
        names = [entry.filename for entry in archive.infolist()]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate ZIP entry names are outside this acquisition interface")
        return sorted([{"name": entry.filename, "bytes": len(raw), "sha256": sha(raw)}
                       for entry in archive.infolist()
                       for raw in [archive.read(entry)]], key=lambda row: row["name"])


def command(argv: list[str], cwd: Path, prefix: Path, *, stdin: bytes = b"",
            timeout: float) -> dict:
    """Keep actual command streams, timeout and process return code separately."""
    prefix.parent.mkdir(parents=True, exist_ok=True)
    started = time.time_ns()
    begin = time.perf_counter_ns()
    with prefix.with_suffix(".stdout.bin").open("wb") as stdout, \
            prefix.with_suffix(".stderr.bin").open("wb") as stderr:
        process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        timeout_observed = False
        try:
            process.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            timeout_observed = True
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
    result = {"argv": argv, "cwd": str(cwd), "stdin_hex": stdin.hex(),
              "returncode": process.returncode, "timeout": timeout_observed,
              "timeout_seconds": timeout, "start_unix_ns": started,
              "elapsed_ns": time.perf_counter_ns() - begin,
              "stdout_hex": prefix.with_suffix(".stdout.bin").read_bytes().hex(),
              "stderr_hex": prefix.with_suffix(".stderr.bin").read_bytes().hex()}
    prefix.with_suffix(".command.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def compile_bridge(acquisition: Path, output: Path, *, java: str = "java") -> dict:
    output.mkdir(parents=True, exist_ok=True)
    argv = [java, "com.sun.tools.javac.Main", "-encoding", "UTF-8", "-classpath",
            str(acquisition / "sandmark.jar"), "-d", str(output), str(HERE / "SandmarkBridge.java")]
    record = command(argv, output, output / "compile", timeout=30)
    if record["timeout"] or record["returncode"] != 0:
        raise RuntimeError("Bridge compilation failed; see retained command record")
    return record


class SandmarkAdapter:
    operations = {"sandmark.prepare", "sandmark.embed", "sandmark.extract",
                  "sandmark.transform", "sandmark.host"}

    def __init__(self, root: Path, acquisition: Path, bridge: Path, *, java: str = "java",
                 embed_timeout: float = 30, extract_timeout: float = 30,
                 host_timeout: float = 15):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.acquisition = acquisition.resolve()
        self.bridge = bridge.resolve()
        self.java = java
        self.embed_timeout = embed_timeout
        self.extract_timeout = extract_timeout
        self.host_timeout = host_timeout
        self.java_flags = ["-Djava.awt.headless=true", "-Dfile.encoding=UTF-8", "-Xmx512m"]

    def _path(self, relative: str) -> Path:
        path = (self.root / relative).resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("Artifact path escapes this case")
        return path

    def _files(self, folder: Path) -> list[dict]:
        return [file_binding(path, self.root) for path in sorted(folder.rglob("*")) if path.is_file()]

    def _jar(self, path: Path) -> dict:
        raw = path.read_bytes()
        binding = {"path": path.relative_to(self.root).as_posix(), "bytes": len(raw), "sha256": sha(raw)}
        return {**binding, "entries": jar_inventory(io.BytesIO(raw))}

    def _endpoint(self, folder: Path, args: dict, name: str) -> tuple[dict, list[dict]]:
        observation = folder / name
        observation.mkdir()
        target = self._path(args["artifact"])
        raw = target.read_bytes()
        (observation / "target.jar").write_bytes(raw)
        artifact = {"path": target.relative_to(self.root).as_posix(), "bytes": len(raw),
                    "sha256": sha(raw), "entries": jar_inventory(io.BytesIO(raw))}
        auxiliaries = []
        for field in ["original_file", "key_file"]:
            path = self._path(args[field])
            if path.exists():
                raw = path.read_bytes()
                (observation / (field + ".bin")).write_bytes(raw)
                auxiliaries.append({"path": path.relative_to(self.root).as_posix(),
                                    "bytes": len(raw), "sha256": sha(raw)})
        return artifact, auxiliaries

    def _bridge(self, operation: str, folder: Path, args: dict) -> tuple[dict, dict | None]:
        input_path = self._path(args["artifact"])
        original = self._path(args["original_file"])
        key_file = self._path(args["key_file"])
        argv = [self.java, *self.java_flags, "-cp",
                os.pathsep.join([str(self.bridge), str(self.acquisition / "sandmark.jar")]),
                "SandmarkBridge", operation, ALGORITHMS[args["algorithm"]]["class"],
                str(input_path), str(folder / "host_wm.jar"), str(folder / "api-result.json"),
                args["payload"], args["key"], str(original), str(key_file), str(args["seed"])]
        record = command(argv, folder, folder / "process",
                         timeout=self.embed_timeout if operation == "embed" else self.extract_timeout)
        result_path = folder / "api-result.json"
        result = json.loads(result_path.read_text()) if result_path.exists() else None
        return record, result

    def invoke(self, operation: str, arguments: dict, *, step_id: str, context_id: str) -> dict:
        if operation not in self.operations or not re.fullmatch(r"[A-Za-z0-9_.-]+", step_id):
            raise ValueError("Unknown operation or unsafe step identifier")
        folder = self.root / step_id
        folder.mkdir(exist_ok=False)
        try:
            value, unavailable = getattr(self, "_" + operation.split(".")[1])(folder, arguments)
            evidence = [{"kind": "sandmark-acquisition", "operation": operation,
                         "step_id": step_id, "context_id": context_id,
                         "files": self._files(folder)}]
            if unavailable is not None:
                evidence[0]["raw_observation"] = value
                return {"status": "UNAVAILABLE", "value": None,
                        "evidence": evidence, "reason": unavailable}
            return {"status": "OK", "value": value, "evidence": evidence, "reason": None}
        except Exception as problem:
            # Invalid inputs and tool/acquisition errors are not domain rejections.
            return {"status": "UNAVAILABLE", "value": None,
                    "evidence": [{"kind": "sandmark-acquisition-error",
                                  "exception": type(problem).__name__, "message": str(problem),
                                  "files": self._files(folder)}],
                    "reason": type(problem).__name__ + ": " + str(problem)}

    def _prepare(self, folder: Path, args: dict) -> tuple[dict, None]:
        host = args["host"]
        if host == "antlr-2.7.7":
            source = self.acquisition / "antlr-2.7.7/antlr.jar"
        elif host == "official-ttt":
            source = self.acquisition / "TTT.jar"
        else:
            raise ValueError("Unknown host")
        path = folder / "host.jar"
        shutil.copyfile(source, path)
        inventory = jar_inventory(path)
        return {"artifact": self._jar(path), "png_count": sum(row["name"].lower().endswith(".png") for row in inventory),
                "class_count": sum(row["name"].endswith(".class") for row in inventory),
                "host": host}, None

    def _embed(self, folder: Path, args: dict) -> tuple[dict, str | None]:
        # Canonical companion name is required by Stern's original filename fallback.
        shutil.copyfile(self._path(args["artifact"]), folder / "host.jar")
        bridge_args = {**args, "artifact": str((folder / "host.jar").relative_to(self.root)),
                       "original_file": str((folder / "host.jar").relative_to(self.root)),
                       "key_file": str((folder / "gtw.key").relative_to(self.root))}
        record, result = self._bridge("embed", folder, bridge_args)
        observation = {"command": record, "api": result}
        if record["timeout"]:
            return observation, "embedding process exceeded the declared acquisition timeout"
        if record["returncode"] != 0 or result is None or result.get("kind") != "embed-return":
            return observation, "embedding did not return a usable artifact"
        output = folder / "host_wm.jar"
        if not output.exists():
            return observation, "embedding returned without saving an artifact"
        return {"artifact": self._jar(output),
                "original_file": bridge_args["original_file"],
                "key_file": bridge_args["key_file"],
                "auxiliary_files": [file_binding(p, self.root) for p in [folder / "host.jar", folder / "gtw.key"] if p.exists()],
                "api": result, "command_returncode": record["returncode"]}, None

    def _extract(self, folder: Path, args: dict) -> tuple[dict, str | None]:
        artifact_before, auxiliary_before = self._endpoint(folder, args, "observed-before")
        record, result = self._bridge("extract", folder, args)
        artifact_after, auxiliary_after = self._endpoint(folder, args, "observed-after")
        observation = {"command": record, "api": result}
        if record["timeout"]:
            return observation, "extractor process exceeded the declared acquisition timeout"
        if record["returncode"] != 0 or result is None or result.get("kind") != "extract-return":
            return observation, "extractor did not return an observation"
        # Preserve every candidate in native iterator order. Stern is a candidate
        # verifier: its key argument is the candidate, not a secret-key rejection test.
        return {"mode": args["extractor_mode"], "candidates": result["candidates"],
                "candidate_java_types": result["candidate_java_types"],
                "supplied_key_or_candidate": args["key"],
                "stdout_hex": record["stdout_hex"], "stderr_hex": record["stderr_hex"],
                "command_returncode": record["returncode"],
                "artifact_before": artifact_before,
                "artifact_after": artifact_after,
                "auxiliary_before": auxiliary_before,
                "auxiliary_after": auxiliary_after}, None

    def _transform(self, folder: Path, args: dict) -> tuple[dict, None]:
        source = self._path(args["artifact"])
        target = folder / "host_wm.jar"
        before = self._jar(source)
        if args["kind"] == "relocation":
            shutil.copyfile(source, target)
        elif args["kind"] == "entry-identical-repack":
            with zipfile.ZipFile(source) as original, zipfile.ZipFile(target, "w") as transformed:
                for entry in reversed(original.infolist()):
                    info = zipfile.ZipInfo(entry.filename, date_time=(2001, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = entry.external_attr
                    transformed.writestr(info, original.read(entry))
        else:
            raise ValueError("Unknown transformation")
        original_target = folder / "host.jar"
        shutil.copyfile(self._path(args["original_file"]), original_target)
        old_key = self._path(args["key_file"])
        new_key = folder / "gtw.key"
        if old_key.exists():
            shutil.copyfile(old_key, new_key)
        return {"kind": args["kind"], "source": before, "artifact": self._jar(target),
                "original_file": str(original_target.relative_to(self.root)),
                "key_file": str(new_key.relative_to(self.root)),
                "auxiliary_files": [file_binding(p, self.root) for p in [original_target, new_key] if p.exists()]}, None

    def _host(self, folder: Path, args: dict) -> tuple[dict, str | None]:
        artifact = self._path(args["artifact"])
        tasks = GRAMMARS if args["host"] == "antlr-2.7.7" else TTT_INPUTS
        rows = []
        for name, task in tasks.items():
            work = folder / name
            work.mkdir()
            if args["host"] == "antlr-2.7.7":
                grammar = self.acquisition / "antlr-2.7.7" / task
                # Relative grammar name makes generated comments independent of arm directories.
                shutil.copyfile(grammar, work / grammar.name)
                output = work / "generated"
                output.mkdir()
                argv = [self.java, *self.java_flags, "-cp", str(artifact), "antlr.Tool",
                        "-o", "generated", grammar.name]
                stdin = b""
            elif args["host"] == "official-ttt":
                argv = [self.java, *self.java_flags, "-cp", str(artifact), "TTTGame"]
                output = work / "generated"
                output.mkdir()
                stdin = task
            else:
                raise ValueError("Unknown host")
            record = command(argv, work, work / "process", stdin=stdin, timeout=self.host_timeout)
            files = [{"path": p.relative_to(output).as_posix(), "bytes": p.stat().st_size,
                      "sha256": sha(p.read_bytes())} for p in sorted(output.rglob("*")) if p.is_file()]
            rows.append({"task": name, "returncode": record["returncode"], "timeout": record["timeout"],
                         "stdout_hex": record["stdout_hex"], "stderr_hex": record["stderr_hex"], "outputs": files})
        # A genuine process failure is retained as a raw host observation; it is
        # not an unavailable command. The plan decides which baseline premises
        # and equality predicates use it. Timeouts are unavailable observations.
        if any(row["timeout"] for row in rows):
            return {"tasks": rows}, "one or more host tasks exceeded the declared acquisition timeout"
        return {"tasks": rows, "returncodes": [row["returncode"] for row in rows]}, None
