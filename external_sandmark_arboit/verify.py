"""Independently check retained Arboit follow-up commands, bytes, and comparisons.

No imports from the follow-up producer or generated Java code. This command
uses only the standard library and never launches Java or a compiler.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

ARTIFACT = Path(__file__).resolve().parents[1]
DEFAULT = ARTIFACT / "results/external-sandmark-arboit/exploratory-01"


class InvalidRecord(ValueError):
    pass


def check(condition, message):
    if not condition:
        raise InvalidRecord(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    def unique(items):
        data = {}
        for key, value in items:
            check(key not in data, "duplicate JSON key")
            data[key] = value
        return data
    return json.loads(path.read_text(), object_pairs_hook=unique)


def bound(root, item):
    path = Path(item["path"])
    check(not path.is_absolute() and ".." not in path.parts, "unsafe binding path")
    raw = (root / path).read_bytes()
    check(len(raw) == item["bytes"] and sha(raw) == item["sha256"], "byte binding mismatch: " + item["path"])
    return raw


def masks(record):
    if record["status"] != "COMPLETED" or record["returncode"] != 0:
        return None
    result = {}
    for line in bytes.fromhex(record["stdout_hex"]).decode("ascii").splitlines():
        parts = line.split("\t")
        check(len(parts) == 3 and parts[0] == "SET" and parts[1] not in result, "invalid membership table")
        bits = bytes.fromhex(parts[2])
        check(len(bits) == 8192, "membership table does not cover all UTF-16 code units")
        result[parts[1]] = bits
    return result


def verify(run):
    complete = read(run / "complete.json")
    check(complete["schema"] == "sandmark-arboit-followup-completion-v1" and complete["status"] == "COMPLETE", "incomplete follow-up")
    check(len({i["path"] for i in complete["files"]}) == len(complete["files"]), "duplicate completed file")
    check({i["path"] for i in complete["files"]} ==
          {p.relative_to(run).as_posix() for p in run.rglob("*") if p.is_file() and p != run / "complete.json"},
          "completion file domain differs from retained files")
    for item in complete["files"]:
        bound(run, item)
    freeze = read(run / "producer-freeze.json")
    check(freeze["schema"] == "sandmark-arboit-followup-freeze-v1" and freeze["frozen_before_followup"] is True, "missing source freeze")
    source_index = {item["path"]: item for item in freeze["sources"]}
    check(len(source_index) == len(freeze["sources"]), "duplicate frozen source")
    for item in freeze["sources"]:
        bound(run / "input-snapshot", item)
        bound(ARTIFACT, item)
    protocol = read(run / "protocol.json")
    frozen_protocol = read(run / "input-snapshot/external_sandmark_arboit/protocol.json")
    check(protocol == frozen_protocol and protocol["modifies_or_reclassifies_formal_results"] is False, "protocol scope mismatch")
    frame = read(run / "frame.json")
    corpus = read(run / "input-snapshot/external_sandmark_arboit/corpus/index.json")
    check(frame["corpus"] == corpus and frame["modes"] == protocol["probe_modes"], "corpus or mode frame changed")
    check(corpus["input_count"] == len(corpus["inputs"]) == freeze["corpus_inputs"], "corpus count mismatch")
    check(len({i["id"] for i in corpus["inputs"]}) == len(corpus["inputs"]), "duplicate corpus identifier")
    for item in corpus["inputs"]:
        path = "external_sandmark_arboit/" + item["path"]
        check(source_index[path]["sha256"] == item["sha256"] and source_index[path]["bytes"] == item["bytes"], "corpus bytes differ from its declaration")
    expected_pairs = [(c, a) for c in protocol["formal_cases"] for a in protocol["formal_arms"]]
    check([(m["case"], m["arm"]) for m in frame["mappings"]] == expected_pairs, "case/arm frame mismatch")
    bundles = {b["id"]: b for b in frame["bundles"]}
    check(len(bundles) == len(frame["bundles"]), "duplicate source bundle")
    formal = Path(freeze["formal_root"])
    parent_complete = read(run / "input-snapshot" / formal / "completion.json")
    parent_summary = bound(run / "input-snapshot", source_index[(formal / "summary.json").as_posix()])
    check(sha(parent_summary) == parent_complete["summary_sha256"], "parent formal completion mismatch")
    declared_configs = {r["id"]: r for r in read(run / "input-snapshot" / formal / "study-frame.json")["configurations"]}
    for mapping in frame["mappings"]:
        case = declared_configs[mapping["case"]]
        check(case["inputs"]["algorithm"] == "Static Arboit" and case["inputs"]["host"] == "antlr-2.7.7" and case["inputs"]["payload"] == "1234", "follow-up case is not the observed Arboit configuration")
        expected_files = [(formal / "cases" / mapping["case"] / mapping["arm"] / "java/generated" / n).as_posix() for n in protocol["generated_files"]]
        check([i["path"] for i in mapping["files"]] == expected_files, "source bundle file frame mismatch")
        identities = []
        for item in mapping["files"]:
            check(item == source_index[item["path"]], "source file identity changed")
            identities.append({"name": Path(item["path"]).name, "sha256": item["sha256"], "bytes": item["bytes"]})
        key = sha(canonical(identities))
        bundle = bundles[mapping["bundle"]]
        check(key == mapping["bundle_identity"] == bundle["identity"] and identities == bundle["files"], "incorrect deduplication of generated files")
    jar_path = (formal / "cases" / protocol["formal_cases"][0] / "source/host.jar").as_posix()
    jar = bound(run / "input-snapshot", source_index[jar_path])
    check((run / "runtime/antlr.jar").read_bytes() == jar, "runtime library differs from the original host")
    rows = read(run / "commands.json")
    commands = {r["id"]: r for r in rows}
    check(len(commands) == len(rows), "duplicate native command")
    expected_ids = []
    outcomes = {}
    for bid, bundle in bundles.items():
        src = run / "bundles" / bid / "src"
        for item in bundle["files"]:
            check(sha((src / item["name"]).read_bytes()) == item["sha256"], "compiled generated source differs from its bundle")
        check((src / "LexerProbe.java").read_bytes() == bound(run / "input-snapshot", source_index["external_sandmark_arboit/LexerProbe.java"]), "probe source changed")
        cid = bid + "/compile"
        expected_ids.append(cid)
        compile_row = commands[cid]
        old_root = Path(compile_row["cwd"])
        base = [freeze["runtime"]["executable"], "-Dfile.encoding=UTF-8", f"-Xmx{protocol['native_limits']['max_heap_megabytes']}m"]
        expected = base + ["com.sun.tools.javac.Main", "-encoding", "UTF-8", "-cp", str(old_root / "runtime/antlr.jar"), "-d", str(old_root / "bundles" / bid / "classes")]
        expected += [str(old_root / "bundles" / bid / "src" / name) for name in sorted(protocol["generated_files"] + ["LexerProbe.java"])]
        check(compile_row["argv"] == expected and compile_row["timeout_seconds"] == protocol["native_limits"]["compiler_seconds"], "compiler command differs from protocol")
        outcomes[bid] = {mode: Counter() for mode in protocol["probe_modes"]}
        if compile_row["status"] != "COMPLETED" or compile_row["returncode"] != 0:
            continue
        launch = base + ["-cp", str(old_root / "bundles" / bid / "classes") + ":" + str(old_root / "runtime/antlr.jar"), "LexerProbe"]
        expected_ids.append(bid + "/sets")
        check(commands[bid + "/sets"]["argv"] == launch + ["sets"], "membership command differs from protocol")
        for item in corpus["inputs"]:
            for mode in protocol["probe_modes"]:
                rid = bid + "/" + item["id"] + "/" + mode
                expected_ids.append(rid)
                row = commands[rid]
                source = old_root / "input-snapshot/external_sandmark_arboit" / item["path"]
                check(row["argv"] == launch + [mode, str(source)] and row["cwd"] == str(old_root), "probe used different input or compiled code")
                if row["status"] != "COMPLETED":
                    outcome = "unavailable"
                elif row["returncode"] != 0:
                    outcome = "nonzero_exit"
                elif row["stderr_hex"]:
                    outcome = "returned_with_diagnostics"
                else:
                    outcome = "returned_without_diagnostics"
                outcomes[bid][mode][outcome] += 1
    check([r["id"] for r in rows] == expected_ids, "missing, extra, or reordered native command")
    for row in rows:
        folder = run / "commands" / row["id"]
        check(read(folder / "command.json") == row, "indexed command differs from raw command record")
        check((folder / "stdout.bin").read_bytes().hex() == row["stdout_hex"] and (folder / "stderr.bin").read_bytes().hex() == row["stderr_hex"], "raw process streams differ")
        check(row["stdin_hex"] == "" and row["status"] in ("COMPLETED", "TIMEOUT", "UNAVAILABLE"), "invalid operational status or input")
        if not row["id"].endswith("/compile"):
            check(row["timeout_seconds"] == protocol["native_limits"]["probe_seconds"], "probe limit differs")
    first_case = protocol["formal_cases"][0]
    source_id = next(m["bundle"] for m in frame["mappings"] if m["case"] == first_case and m["arm"] == "source-host")
    marked_id = next(m["bundle"] for m in frame["mappings"] if m["case"] == first_case and m["arm"] == "embedded-host")
    comparisons = []
    for item in corpus["inputs"]:
        for mode in protocol["probe_modes"]:
            left = commands.get(source_id + "/" + item["id"] + "/" + mode)
            right = commands.get(marked_id + "/" + item["id"] + "/" + mode)
            available = left is not None and right is not None and left["status"] == right["status"] == "COMPLETED"
            identical = available and (left["returncode"], left["stdout_hex"], left["stderr_hex"]) == (right["returncode"], right["stdout_hex"], right["stderr_hex"])
            comparisons.append({"input": item["id"], "mode": mode, "available": available, "identical": identical,
                                "source_command": None if left is None else left["id"], "marked_command": None if right is None else right["id"]})
    check(comparisons == read(run / "comparisons.json"), "probe comparison differs from raw outcomes")
    source_sets = masks(commands[source_id + "/sets"]) if source_id + "/sets" in commands else None
    marked_sets = masks(commands[marked_id + "/sets"]) if marked_id + "/sets" in commands else None
    if source_sets is None or marked_sets is None:
        membership = {"available": False}
    else:
        mapping = protocol["old_to_marked_set_mapping"]
        spec = protocol["added_set_range"]
        check(set(source_sets) == set(mapping) and set(marked_sets) == set(mapping.values()) | {spec["set"]}, "membership set names differ from the observed source changes")
        existing = [{"source_set": old, "marked_set": new, "code_units": 65536,
                     "different_memberships": sum((a ^ b).bit_count() for a, b in zip(source_sets[old], marked_sets[new]))} for old, new in mapping.items()]
        expected = bytearray(8192)
        for value in range(65536):
            if spec["first"] <= value <= spec["last"]:
                expected[value // 8] |= 2 ** (value % 8)
        different = sum((a ^ b).bit_count() for a, b in zip(expected, marked_sets[spec["set"]]))
        membership = {"available": True, "existing_set_comparisons": existing,
                      "added_set_comparison": {**spec, "code_units": 65536, "different_memberships": different},
                      "total_membership_comparisons": 65536 * (len(existing) + 1),
                      "total_different_memberships": different + sum(r["different_memberships"] for r in existing)}
    check(membership == read(run / "membership-comparison.json"), "membership comparison differs from the actual Java tables")
    expected_summary = {"schema": "sandmark-arboit-followup-summary-v1", "purpose": protocol["purpose"],
               "formal_cases": len(protocol["formal_cases"]), "formal_case_arm_mappings": len(frame["mappings"]),
               "distinct_source_bundles": len(bundles), "successful_compilations": sum(commands[b + "/compile"]["returncode"] == 0 for b in bundles),
               "corpus_inputs": len(corpus["inputs"]), "probe_pairs": len(comparisons),
               "available_pairs": sum(c["available"] for c in comparisons), "identical_pairs": sum(c["identical"] for c in comparisons),
               "native_commands": len(rows), "membership_comparison": membership,
               "frozen_inputs_unchanged": True, "formal_results_unchanged": True,
               "interpretation": protocol["interpretation"]}
    check(read(run / "summary.json") == expected_summary, "summary does not follow from raw observations")
    return {"schema": "sandmark-arboit-followup-receiver-v1", "verdict": "PASS", "native_commands": len(rows),
            "case_arm_mappings": len(frame["mappings"]), "distinct_source_bundles": len(bundles),
            "corpus_inputs": len(corpus["inputs"]), "probe_pairs": len(comparisons),
            "identical_probe_pairs": sum(c["identical"] for c in comparisons), "probe_outcomes": outcomes,
            "membership_comparison": membership, "source_and_input_bindings_checked": True,
            "raw_streams_and_exact_commands_checked": True, "formal_results_unchanged": True,
            "native_programs_reexecuted": False,
            "scope": "Independent retained-record and byte audit; bounded functional observations, not universal parser equivalence or an additional native execution."}


def expected_container_paths(run=DEFAULT):
    complete = read(Path(run) / "complete.json")
    return sorted(str((Path(run) / row["path"]).relative_to(ARTIFACT)) for row in complete["files"] if row["path"].endswith(".jar"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=DEFAULT)
    args = parser.parse_args()
    try:
        report = verify(args.run.resolve())
    except (InvalidRecord, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(json.dumps({"schema": "sandmark-arboit-followup-receiver-v1", "verdict": "INVALID_RECORD", "reason": str(error)}))
        raise SystemExit(1)
    print(json.dumps(report, sort_keys=True, indent=2))
