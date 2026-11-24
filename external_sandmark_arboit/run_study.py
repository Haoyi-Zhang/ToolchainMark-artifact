"""Freeze and execute a bounded follow-up on retained generated Java sources."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

ARTIFACT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
DEFAULT_FORMAL = ARTIFACT / "results/external-sandmark/formal-01"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def load(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def binding(path):
    raw = path.read_bytes()
    return {"path": path.relative_to(ARTIFACT).as_posix(), "bytes": len(raw), "sha256": sha(raw)}


def command(root, name, argv, *, timeout):
    folder = root / "commands" / name
    folder.mkdir(parents=True)
    started = time.time_ns()
    try:
        result = subprocess.run(argv, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        status, code, stdout, stderr = "COMPLETED", result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        status, code, stdout, stderr = "TIMEOUT", None, error.stdout or b"", error.stderr or b""
    except OSError as error:
        status, code, stdout, stderr = "UNAVAILABLE", None, b"", str(error).encode()
    (folder / "stdout.bin").write_bytes(stdout)
    (folder / "stderr.bin").write_bytes(stderr)
    row = {"id": name, "argv": argv, "cwd": str(root), "stdin_hex": "", "status": status, "returncode": code,
           "stdout_hex": stdout.hex(), "stderr_hex": stderr.hex(), "timeout_seconds": timeout,
           "started_unix_ns": started, "elapsed_ns": time.time_ns() - started}
    write(folder / "command.json", row)
    return row


def parse_sets(row):
    if row["status"] != "COMPLETED" or row["returncode"] != 0:
        return None
    sets = {}
    for line in bytes.fromhex(row["stdout_hex"]).decode("ascii").splitlines():
        tag, name, vector = line.split("\t")
        if tag != "SET" or name in sets or len(bytes.fromhex(vector)) != 8192:
            raise ValueError("invalid membership output")
        sets[name] = bytes.fromhex(vector)
    return sets


def set_comparison(protocol, source, marked):
    if source is None or marked is None:
        return {"available": False}
    comparisons = []
    for old, new in protocol["old_to_marked_set_mapping"].items():
        different = sum((a ^ b).bit_count() for a, b in zip(source[old], marked[new]))
        comparisons.append({"source_set": old, "marked_set": new, "code_units": 65536, "different_memberships": different})
    spec = protocol["added_set_range"]
    expected = bytearray(8192)
    for value in range(spec["first"], spec["last"] + 1):
        expected[value >> 3] |= 1 << (value & 7)
    different = sum((a ^ b).bit_count() for a, b in zip(marked[spec["set"]], expected))
    return {"available": True, "existing_set_comparisons": comparisons,
            "added_set_comparison": {**spec, "code_units": 65536, "different_memberships": different},
            "total_membership_comparisons": 65536 * (len(comparisons) + 1),
            "total_different_memberships": different + sum(r["different_memberships"] for r in comparisons)}


def run(output, formal):
    if output.exists():
        raise ValueError("output exists; preserve it and choose a new directory")
    output.relative_to(ARTIFACT)
    protocol = load(HERE / "protocol.json")
    corpus = load(HERE / "corpus/index.json")
    formal_protocol = load(formal / "protocol-freeze.json")
    java = Path(formal_protocol["runtime"]["executable"])
    if sha(java.read_bytes()) != formal_protocol["runtime"]["executable_sha256"]:
        raise ValueError("Java runtime differs from the formal acquisition")
    for name in ("release", "lib/modules"):
        if name in formal_protocol["runtime"]:
            item = formal_protocol["runtime"][name]
            raw = (java.parent.parent / name).read_bytes()
            if len(raw) != item["bytes"] or sha(raw) != item["sha256"]:
                raise ValueError("Java runtime component changed: " + name)
    if corpus["input_count"] != len(corpus["inputs"]) or len({i["id"] for i in corpus["inputs"]}) != len(corpus["inputs"]):
        raise ValueError("corpus frame mismatch")
    for item in corpus["inputs"]:
        raw = (HERE / item["path"]).read_bytes()
        if len(raw) != item["bytes"] or sha(raw) != item["sha256"]:
            raise ValueError("corpus source mismatch")
    output.mkdir(parents=True)
    sources = [HERE / name for name in ("__init__.py", "run_study.py", "LexerProbe.java", "protocol.json", "corpus/index.json")]
    sources += [HERE / item["path"] for item in corpus["inputs"]]
    sources += [formal / "plan.json", formal / "study-frame.json", formal / "protocol-freeze.json", formal / "summary.json", formal / "completion.json"]
    jar_source = formal / "cases" / protocol["formal_cases"][0] / "source/host.jar"
    sources.append(jar_source)
    mappings, bundles = [], {}
    for case_id in protocol["formal_cases"]:
        for arm in protocol["formal_arms"]:
            folder = formal / "cases" / case_id / arm / "java/generated"
            files = [folder / name for name in protocol["generated_files"]]
            identities = [{"name": p.name, "sha256": sha(p.read_bytes()), "bytes": p.stat().st_size} for p in files]
            key = sha(canonical(identities))
            if key not in bundles:
                bundles[key] = {"id": f"bundle-{len(bundles) + 1}", "identity": key, "files": identities,
                                "representative_case": case_id, "representative_arm": arm}
            mappings.append({"case": case_id, "arm": arm, "bundle": bundles[key]["id"], "bundle_identity": key,
                             "files": [binding(p) for p in files]})
            sources.extend(files)
    sources = list(dict.fromkeys(sources))
    freeze = {"schema": "sandmark-arboit-followup-freeze-v1", "purpose": protocol["purpose"],
              "frozen_before_followup": True, "sources": [binding(p) for p in sources],
              "runtime": formal_protocol["runtime"], "java_source_identity_checked": True,
              "formal_root": formal.relative_to(ARTIFACT).as_posix(), "corpus_inputs": len(corpus["inputs"])}
    for p in sources:
        target = output / "input-snapshot" / p.relative_to(ARTIFACT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, target)
    write(output / "producer-freeze.json", freeze)
    write(output / "frame.json", {"mappings": mappings, "bundles": list(bundles.values()), "corpus": corpus,
          "modes": protocol["probe_modes"], "membership_domain": protocol["membership_domain"]})
    write(output / "protocol.json", protocol)
    runtime = output / "runtime"
    runtime.mkdir()
    jar = runtime / "antlr.jar"
    shutil.copyfile(jar_source, jar)
    java_base = [str(java), "-Dfile.encoding=UTF-8", f"-Xmx{protocol['native_limits']['max_heap_megabytes']}m"]
    records, by_bundle = [], {}
    for bundle in bundles.values():
        work = output / "bundles" / bundle["id"]
        src, classes = work / "src", work / "classes"
        src.mkdir(parents=True)
        classes.mkdir()
        original = formal / "cases" / bundle["representative_case"] / bundle["representative_arm"] / "java/generated"
        for item in bundle["files"]:
            shutil.copyfile(original / item["name"], src / item["name"])
        shutil.copyfile(HERE / "LexerProbe.java", src / "LexerProbe.java")
        compile_row = command(output, bundle["id"] + "/compile", java_base + ["com.sun.tools.javac.Main", "-encoding", "UTF-8",
            "-cp", str(jar), "-d", str(classes)] + [str(p) for p in sorted(src.glob("*.java"))],
            timeout=protocol["native_limits"]["compiler_seconds"])
        records.append(compile_row)
        by_bundle[bundle["id"]] = {"compile": compile_row, "probes": {}, "sets": None}
        if compile_row["status"] != "COMPLETED" or compile_row["returncode"] != 0:
            continue
        launch = java_base + ["-cp", str(classes) + ":" + str(jar), "LexerProbe"]
        set_row = command(output, bundle["id"] + "/sets", launch + ["sets"], timeout=protocol["native_limits"]["probe_seconds"])
        records.append(set_row)
        by_bundle[bundle["id"]]["sets"] = parse_sets(set_row)
        for item in corpus["inputs"]:
            input_path = output / "input-snapshot" / (HERE / item["path"]).relative_to(ARTIFACT)
            for mode in protocol["probe_modes"]:
                name = bundle["id"] + "/" + item["id"] + "/" + mode
                row = command(output, name, launch + [mode, str(input_path)], timeout=protocol["native_limits"]["probe_seconds"])
                records.append(row)
                by_bundle[bundle["id"]]["probes"][(item["id"], mode)] = row
    write(output / "commands.json", records)
    source_id = next(m["bundle"] for m in mappings if m["case"] == protocol["formal_cases"][0] and m["arm"] == "source-host")
    marked_id = next(m["bundle"] for m in mappings if m["case"] == protocol["formal_cases"][0] and m["arm"] == "embedded-host")
    comparisons = []
    for item in corpus["inputs"]:
        for mode in protocol["probe_modes"]:
            left = by_bundle[source_id]["probes"].get((item["id"], mode))
            right = by_bundle[marked_id]["probes"].get((item["id"], mode))
            available = left is not None and right is not None and left["status"] == right["status"] == "COMPLETED"
            equal = available and all(left[k] == right[k] for k in ("returncode", "stdout_hex", "stderr_hex"))
            comparisons.append({"input": item["id"], "mode": mode, "available": available, "identical": equal,
                                "source_command": None if left is None else left["id"], "marked_command": None if right is None else right["id"]})
    membership = set_comparison(protocol, by_bundle[source_id]["sets"], by_bundle[marked_id]["sets"])
    for item in freeze["sources"]:
        current = ARTIFACT / item["path"]
        if sha(current.read_bytes()) != item["sha256"]:
            raise ValueError("frozen input changed during follow-up: " + item["path"])
    write(output / "comparisons.json", comparisons)
    write(output / "membership-comparison.json", membership)
    summary = {"schema": "sandmark-arboit-followup-summary-v1", "purpose": protocol["purpose"],
               "formal_cases": len(protocol["formal_cases"]), "formal_case_arm_mappings": len(mappings),
               "distinct_source_bundles": len(bundles), "successful_compilations": sum(x["compile"]["returncode"] == 0 for x in by_bundle.values()),
               "corpus_inputs": len(corpus["inputs"]), "probe_pairs": len(comparisons),
               "available_pairs": sum(c["available"] for c in comparisons), "identical_pairs": sum(c["identical"] for c in comparisons),
               "native_commands": len(records), "membership_comparison": membership,
               "frozen_inputs_unchanged": True, "formal_results_unchanged": True,
               "interpretation": protocol["interpretation"]}
    write(output / "summary.json", summary)
    files = [p for p in sorted(output.rglob("*")) if p.is_file()]
    write(output / "complete.json", {"schema": "sandmark-arboit-followup-completion-v1", "status": "COMPLETE",
          "files": [{"path": p.relative_to(output).as_posix(), "bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in files]})
    print(json.dumps(summary, sort_keys=True, indent=2))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--formal", type=Path, default=DEFAULT_FORMAL)
    args = parser.parse_args()
    run(args.out.resolve(), args.formal.resolve())
