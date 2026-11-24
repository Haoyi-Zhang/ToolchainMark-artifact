#!/usr/bin/env python3
"""Read-only independent receipt replay and SandMark byte reobservation."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.receiver import verify_receipt


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe(root, relative):
    require(isinstance(relative, str), "Non-string evidence path")
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()), "Evidence path escapes case")
    return path


def binding(path, root, *, recorded_path=None):
    return {"path": recorded_path or path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size, "sha256": sha(path)}


def inventory(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "Duplicate ZIP names")
        return sorted([{"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                       for name in names for data in [archive.read(name)]], key=lambda x: x["name"])


def jar(path, root, *, recorded_path=None):
    return {**binding(path, root, recorded_path=recorded_path), "entries": inventory(path)}


def command(folder, expected_argv, expected_cwd):
    value = read(folder / "process.command.json")
    require(value["argv"] == expected_argv, "Native argv differs from declared action")
    require(value["cwd"] == str(expected_cwd), "Native cwd mismatch")
    require(type(value["returncode"]) is int and type(value["timeout"]) is bool, "Malformed process result")
    require(type(value["elapsed_ns"]) is int and value["elapsed_ns"] >= 0, "Invalid process duration")
    require(value["stdout_hex"] == (folder / "process.stdout.bin").read_bytes().hex(), "stdout is not the retained bytes")
    require(value["stderr_hex"] == (folder / "process.stderr.bin").read_bytes().hex(), "stderr is not the retained bytes")
    return value


def reobserve(case, action, protocol, catalog, lock, counters):
    step = action["id"]
    folder = case / step
    if action["status"] == "SKIPPED":
        require(not folder.exists(), "Skipped action left an acquisition directory")
        return
    evidence = action["evidence"]
    require(len(evidence) == 1, "One acquisition document is required per adapter call")
    e = evidence[0]
    actual = [binding(p, case) for p in sorted(folder.rglob("*")) if p.is_file()]
    require(e["files"] == actual, "Acquisition file inventory or byte hash mismatch")
    counters["retained_files"] += len(actual)
    require(e["kind"] == "sandmark-acquisition", "Unexpected acquisition error requires explicit review")
    require(e["operation"] == action["operation"] and e["step_id"] == step and e["context_id"] == action["context_id"], "Acquisition identity mismatch")
    args = action["arguments"]
    native_case = Path(protocol["execution_root"]) / "cases" / action["context_id"]
    native_folder = native_case / step
    java = protocol["runtime"]["executable"]
    flags = ["-Djava.awt.headless=true", "-Dfile.encoding=UTF-8", "-Xmx512m"]
    operation = action["operation"].split(".")[1]
    if operation == "prepare":
        path = folder / "host.jar"
        expected_sha = (next(x["sha256"] for x in lock["artifacts"] if x["name"] == "TTT.jar")
                        if args["host"] == "official-ttt" else
                        next(x["sha256"] for x in lock["extracted_antlr_inputs"] if x["path"] == "antlr-2.7.7/antlr.jar"))
        require(sha(path) == expected_sha, "Host differs from pinned original input")
        entries = inventory(path)
        value = {"artifact": jar(path, case), "png_count": sum(x["name"].lower().endswith(".png") for x in entries),
                 "class_count": sum(x["name"].endswith(".class") for x in entries), "host": args["host"]}
    elif operation in {"embed", "extract"}:
        if operation == "embed":
            require((folder / "host.jar").read_bytes() == safe(case, args["artifact"]).read_bytes(), "Embedding input was substituted")
            target, original, key_file = native_folder / "host.jar", native_folder / "host.jar", native_folder / "gtw.key"
        else:
            target, original, key_file = [native_case / args[k] for k in ["artifact", "original_file", "key_file"]]
        tool = next(x["local_path"] for x in protocol["acquisition"]["artifacts"] if x["name"] == "sandmark.jar")
        argv = [java, *flags, "-cp", str(Path(protocol["execution_root"]) / "bridge") + ":" + tool,
                "SandmarkBridge", operation, catalog[args["algorithm"]], str(target), str(native_folder / "host_wm.jar"),
                str(native_folder / "api-result.json"), args["payload"], args["key"], str(original), str(key_file), str(args["seed"])]
        process = command(folder, argv, native_folder)
        counters["command_records"] += 1
        require(process["stdin_hex"] == "", "Unexpected bridge stdin")
        api = read(folder / "api-result.json") if (folder / "api-result.json").exists() else None
        if action["status"] == "UNAVAILABLE":
            require(e["raw_observation"] == {"command": process, "api": api}, "Unavailable observation is not bound to raw command data")
            require(process["timeout"] or process["returncode"] != 0 or api is None, "Successful bridge incorrectly marked unavailable")
            return
        require(not process["timeout"] and process["returncode"] == 0, "Successful action lacks a successful process")
        if operation == "embed":
            require(api == {"kind": "embed-return", "algorithm": catalog[args["algorithm"]]}, "Unexpected embed API response")
            value = {"artifact": jar(folder / "host_wm.jar", case), "original_file": (folder / "host.jar").relative_to(case).as_posix(),
                     "key_file": (folder / "gtw.key").relative_to(case).as_posix(),
                     "auxiliary_files": [binding(p, case) for p in [folder / "host.jar", folder / "gtw.key"] if p.exists()],
                     "api": api, "command_returncode": 0}
        else:
            require(api["kind"] == "extract-return", "Unexpected extraction API response")
            endpoints = {}
            for endpoint in ["before", "after"]:
                observed = folder / ("observed-" + endpoint)
                endpoints["artifact_" + endpoint] = jar(observed / "target.jar", case, recorded_path=args["artifact"])
                endpoints["auxiliary_" + endpoint] = [binding(observed / (field + ".bin"), case, recorded_path=args[field])
                                                     for field in ["original_file", "key_file"] if (observed / (field + ".bin")).exists()]
            value = {"mode": args["extractor_mode"], "candidates": api["candidates"], "candidate_java_types": api["candidate_java_types"],
                     "supplied_key_or_candidate": args["key"], "stdout_hex": process["stdout_hex"], "stderr_hex": process["stderr_hex"],
                     "command_returncode": 0, **endpoints}
            counters["retained_target_endpoint_pairs"] += 1
    elif operation == "transform":
        source, target = safe(case, args["artifact"]), folder / "host_wm.jar"
        require((folder / "host.jar").read_bytes() == safe(case, args["original_file"]).read_bytes(), "Original-program auxiliary changed")
        old_key = safe(case, args["key_file"])
        require((folder / "gtw.key").exists() == old_key.exists(), "Key-file presence changed")
        if old_key.exists():
            require((folder / "gtw.key").read_bytes() == old_key.read_bytes(), "Key-file auxiliary changed")
        # Direct byte checks accompany the independent expression replay. They do
        # not require the relation to pass: inconsistent outputs remain valid data.
        if args["kind"] == "relocation":
            actual_equal = source.read_bytes() == target.read_bytes()
            require(actual_equal == (sha(source) == sha(target)), "Hash comparison disagrees with direct bytes")
            counters["archive_byte_comparisons"] += 1
        else:
            with zipfile.ZipFile(source) as a, zipfile.ZipFile(target) as b:
                direct_equal = set(a.namelist()) == set(b.namelist()) and all(a.read(n) == b.read(n) for n in a.namelist())
                require(direct_equal == (inventory(source) == inventory(target)), "Entry hash comparison disagrees with actual bytes")
                counters["entry_byte_comparisons"] += len(a.namelist())
        value = {"kind": args["kind"], "source": jar(source, case), "artifact": jar(target, case),
                 "original_file": (folder / "host.jar").relative_to(case).as_posix(), "key_file": (folder / "gtw.key").relative_to(case).as_posix(),
                 "auxiliary_files": [binding(p, case) for p in [folder / "host.jar", folder / "gtw.key"] if p.exists()]}
    elif operation == "host":
        rows = []
        grammar = {"calc": ("calc.g", "examples/java/calc/calc.g"), "exprAST": ("expr.g", "examples/java/exprAST/expr.g"), "java": ("java.g", "examples/java/java/java.g")}
        ttt = {"first_player_win": b"1\n4\n2\n5\n3\n", "second_player_win": b"1\n4\n2\n5\n9\n6\n", "draw": b"1\n2\n3\n5\n4\n6\n8\n7\n9\n"}
        names = grammar if args["host"] == "antlr-2.7.7" else ttt
        for name in names:
            work = folder / name
            argv = [java, *flags, "-cp", str(native_case / args["artifact"])]
            if args["host"] == "antlr-2.7.7":
                filename, relative = grammar[name]
                argv += ["antlr.Tool", "-o", "generated", filename]
                pinned = next(x for x in lock["extracted_antlr_inputs"] if x["path"] == "antlr-2.7.7/" + relative)
                require(sha(work / filename) == pinned["sha256"], "ANTLR grammar input changed")
                stdin = b""
            else:
                argv += ["TTTGame"]
                stdin = ttt[name]
            process = command(work, argv, native_folder / name)
            require(process["stdin_hex"] == stdin.hex(), "Host task stdin changed")
            counters["command_records"] += 1
            generated = work / "generated"
            files = [binding(p, generated) for p in sorted(generated.rglob("*")) if p.is_file()]
            rows.append({"task": name, "returncode": process["returncode"], "timeout": process["timeout"],
                         "stdout_hex": process["stdout_hex"], "stderr_hex": process["stderr_hex"], "outputs": files})
        if action["status"] == "UNAVAILABLE":
            require(any(row["timeout"] for row in rows), "Host unavailable without a timeout")
            require(e["raw_observation"] == {"tasks": rows}, "Timeout observation differs from retained host data")
            return
        value = {"tasks": rows, "returncodes": [row["returncode"] for row in rows]}
    else:
        raise ValueError("Unsupported SandMark operation")
    require(action["status"] == "OK", "Completed acquisition was not available")
    require(action["value"] == value, "Typed observation does not match actual saved bytes/API result: " + step)
    counters["reobserved_actions"] += 1


def verify(run, *, allow_pilot=False):
    run = run.resolve()
    protocol, plan, frame = [read(run / name) for name in ["protocol-freeze.json", "plan.json", "study-frame.json"]]
    start, completion, summary = [read(run / name) for name in ["execution-start.json", "completion.json", "summary.json"]]
    require(start["protocol_freeze_sha256"] == sha(run / "protocol-freeze.json") == completion["protocol_freeze_sha256"], "Protocol freeze binding changed")
    require(completion["summary_sha256"] == sha(run / "summary.json"), "Summary binding changed")
    require(sha(run / "plan.json") == protocol["plan_sha256"] and sha(run / "study-frame.json") == protocol["frame_sha256"], "Frozen plan/frame changed")
    require(completion["source_bindings_after_execution"] == protocol["source_bindings"], "Producer changed during execution")
    for name, expected in protocol["source_bindings"].items():
        require(sha(safe(run / "producer-snapshot", name)) == expected, "Frozen producer snapshot changed")
    require(sha(run / "bridge/SandmarkBridge.class") == protocol["bridge_sha256"], "Compiled bridge changed")
    require(sha(run / "acquisition-lock.json") == protocol["acquisition_lock_sha256"], "Acquisition lock changed")
    lock = read(run / "acquisition-lock.json")
    catalog = {x["algorithm"]: x["class"] for x in read(run / "producer-snapshot/external_sandmark/algorithm-contracts.json")["algorithms"]}
    all_rows = frame["configurations"]
    if start["kind"] == "exploratory-pilot":
        require(allow_pilot, "Pilot is not a formal experiment")
        selected = [x for x in all_rows if x["id"] in start["configuration_ids"]]
    else:
        require(start["kind"] == "formal-full-frame", "Unknown execution kind")
        selected = all_rows
        require(len(selected) == frame["expected_configurations"] == 156, "Incomplete formal frame")
    require(start["configuration_ids"] == [x["id"] for x in selected], "Execution frame order changed")
    require(len(summary["configurations"]) == len(selected) == completion["configuration_count"] == summary["configuration_count"], "Configuration denominator mismatch")
    counters, judgments = Counter(), Counter()
    for item, row in zip(selected, summary["configurations"], strict=True):
        case = run / "cases" / item["id"]
        receipt = read(case / "receipt.json")
        require(row["id"] == item["id"] and row["inputs"] == item["inputs"] and row["repeat"] == item["repeat"], "Summary frame mismatch")
        require(sha(case / "receipt.json") == row["receipt_sha256"], "Case receipt changed")
        verify_receipt(plan, receipt, expected_inputs=item["inputs"], expected_context_id=item["id"])
        require(row["judgments"] == {x["id"]: x["verdict"] for x in receipt["obligations"]}, "Summary judgment mismatch")
        require(row["action_status"] == {x["id"]: x["status"] for x in receipt["actions"]}, "Summary status mismatch")
        for action in receipt["actions"]:
            reobserve(case, action, protocol, catalog, lock, counters)
        actions = {action["id"]: action for action in receipt["actions"]}
        baseline = actions["source-host"]
        if baseline["status"] == "OK":
            for step in ["embedded-host", "relocated-host", "repacked-host"]:
                changed = actions[step]
                if changed["status"] != "OK":
                    continue
                for old, new in zip(baseline["value"]["tasks"], changed["value"]["tasks"], strict=True):
                    before = case / "source-host" / old["task"] / "generated"
                    after = case / step / new["task"] / "generated"
                    source_bytes = {p.relative_to(before).as_posix(): p.read_bytes()
                                    for p in before.rglob("*") if p.is_file()}
                    changed_bytes = {p.relative_to(after).as_posix(): p.read_bytes()
                                     for p in after.rglob("*") if p.is_file()}
                    require((source_bytes == changed_bytes) == (old["outputs"] == new["outputs"]),
                            "Host file-hash equality disagrees with direct generated-file bytes")
                    counters["host_generated_file_byte_comparisons"] += len(set(source_bytes) & set(changed_bytes))
        judgments.update(row["judgments"].values())
    require(dict(judgments) == summary["judgments"] and sum(judgments.values()) == summary["obligation_count"], "Summary aggregate mismatch")
    return {"schema": "sandmark-study-receiver-v1", "verdict": "PASS", "kind": start["kind"],
            "configurations": len(selected), "obligations": sum(judgments.values()), "judgments": dict(judgments),
            "checks": dict(counters), "protocol_freeze_sha256": sha(run / "protocol-freeze.json"),
            "scope": "Independent declaration replay and saved-byte/API-result reobservation; no upstream bug confirmation, universal runtime guarantee, or atomic decoder-read attestation."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--allow-pilot", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(args.run, allow_pilot=args.allow_pilot)
    except Exception as problem:
        print(json.dumps({"schema": "sandmark-study-receiver-v1", "verdict": "FAIL", "error": str(problem)}))
        raise SystemExit(1)
    print(json.dumps(result, indent=2))
