"""Read-only verification of the complete retained projection measurement.

The checker does not import the projection constructor or an acquisition driver.
It derives both action selections from the declarations, checks every original
receipt and target judgment, and recomputes every reported measurement. Native
bytes are rechecked for the exported examples, not for every derived target.
The original studies have separate complete native-evidence receivers.

This checker was added after acquisition. Its output records current source and
metadata bindings; those bindings are not a retroactive pre-execution freeze.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import statistics
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contract_runtime.receiver import load_json, validate_plan, verify_receipt
from ctf_comparison.expressions import boolean
from evidence_projection.receiver import verify_bundle, verify_structure

ARTIFACT = Path(__file__).resolve().parents[1]
DEFAULT = ARTIFACT / "results/evidence-projection/completed"
CTF = ARTIFACT / "results/ctf-comparison/reference"
EXPECTED_FRAME = {
    "reference": (2100, 3000), "declarations": (36, 42), "identity": (12, 12),
    "state": (4356, 4356), "state-baseline": (540, 756),
    "llwm": (180, 720), "sandmark": (156, 1248),
}

# This retained study predates the native-binding repairs. Its producer freeze
# and source snapshot remain historical evidence, not a freeze of this checker.
RETAINED_SOURCE_FREEZE = {
    "bytes": 2572,
    "sha256": "96b79a7c691689698fff0da5ecace19f1055b5eb3dcc33ff75da7d6dcb72c292",
}
APPROVED_CURRENT_NATIVE_VALIDATION = {
    "declarative_study/native_io.py": {
        "bytes": 6876,
        "sha256": "f12ac789724f479375c681302db8ab09a0c236b36764c1309624116631c6c12d",
    },
    "declarative_study/verify.py": {
        "bytes": 35146,
        "sha256": "a84da63ffbf9dec4041b531f45fe2fc7844fd9da08e108fecaea587623d2347b",
    },
    "external_sandmark/verify_study.py": {
        "bytes": 17474,
        "sha256": "741415a6af4082cc0154fd4486119e0a840375c879b2af29ec818dce45864d7c",
    },
}
APPROVED_CURRENT_DEPENDENCIES = [{
    "path": "independent_observers/elf_observer.py",
    "bytes": 6475,
    "sha256": "dab8503ccf1d253e3296879bb9358540c5644c7eaac98264978aa6db579dd192",
}]

APPROVED_CURRENT_PRODUCER_ONLY = {
    "evidence_projection/run.py": {
        "bytes": 14466,
        "sha256": "f2ea1297abaf32e5d3a96d983d6c12dbf1d7d63a587bfb1d7a812c56cb0f742e",
    },
    "evidence_projection/run_history_control.py": {
        "bytes": 10061,
        "sha256": "43e4411a3b8e64435bd26c9c88d01614ed406995504aee9f58b808a9fbf9d6d0",
    },
    "evidence_projection/test_receiver.py": {
        "bytes": 7835,
        "sha256": "82dd90758defbdaa9adfdbc07423604ecff64797a48ae09b1b090491f48cf6c3",
    },
}


FRESH_SOURCE_DEPENDENCIES = {
    "evidence_projection/protocol.json", "contract_runtime/receiver.py",
    "declarative_study/native_io.py", "declarative_study/verify.py",
    "independent_observers/producer_current/independent_observer.py",
    "external_sandmark/verify_study.py", "ctf_comparison/expressions.py",
    "ctf_comparison/verify.py",
}


def fresh_source_paths():
    """Independently derive the source domain frozen by a new producer run."""
    paths = {path.relative_to(ARTIFACT).as_posix()
             for path in (ARTIFACT / "evidence_projection").glob("*.py")}
    paths.update(FRESH_SOURCE_DEPENDENCIES)
    return sorted(paths)


class InvalidMeasurement(ValueError):
    """A retained measurement disagrees with its declared source evidence."""


def need(condition, message):
    if not condition:
        raise InvalidMeasurement(message)


def compact(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def pretty(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def equal(actual, expected, where):
    if compact(actual) != compact(expected):
        if type(actual) is dict and type(expected) is dict:
            different = [key for key in sorted(set(actual) | set(expected))
                         if key not in actual or key not in expected
                         or compact(actual[key]) != compact(expected[key])]
            raise InvalidMeasurement(where + ": differing fields " + ", ".join(different))
        raise InvalidMeasurement(where + ": values differ")


def identity(path):
    raw = Path(path).read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def safe_path(root, relative):
    need(type(relative) is str and relative and "\\" not in relative,
         "invalid relative path")
    name = PurePosixPath(relative)
    need(bool(name.parts) and not name.is_absolute() and name.as_posix() == relative
         and not any(part in (".", "..") for part in name.parts),
         "noncanonical or escaping relative path: " + relative)
    root = Path(root).resolve()
    parts = name.parts
    if parts[:2] == ("results", "declarative-v6"):
        parts = ("results", "declarative", *parts[2:])
    result = root.joinpath(*parts)
    need(result.resolve().is_relative_to(root), "escaping path: " + relative)
    return result


def bound(root, row):
    need(type(row) is dict and set(row) == {"path", "bytes", "sha256"},
         "malformed file binding")
    need(type(row["bytes"]) is int and row["bytes"] >= 0, "invalid byte count")
    path = safe_path(root, row["path"])
    equal(identity(path), {key: row[key] for key in ("bytes", "sha256")},
          "file binding " + row["path"])
    return path


def read_lines(path):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def bad_constant(value):
        raise InvalidMeasurement("nonfinite JSON number: " + value)

    rows = []
    for ordinal, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        need(bool(line.strip()), f"empty measurement line {ordinal}")
        rows.append(json.loads(line, object_pairs_hook=pairs, parse_constant=bad_constant))
    return rows


def indexed(rows, keys, where):
    result = {}
    for row in rows:
        need(type(row) is dict, where + ": expected object")
        key = tuple(row[name] for name in keys)
        need(all(type(part) is str and part for part in key), where + ": invalid identity")
        need(key not in result, where + ": duplicate identity " + repr(key))
        result[key] = row
    return result


def ordered_examples(rows):
    # Directory traversal orders each path component; sorting complete strings
    # would reverse, for example, the state and state-baseline directories.
    return sorted(rows, key=lambda row: PurePosixPath(row["path"]).parts)


def derive_selection(plan, target):
    """Derive static verdict closure, complete prefix, and argument closure."""
    validate_plan(plan)
    obligations = {row["id"]: row for row in plan["obligations"]}
    need(target in obligations, "unknown target obligation")
    blocks = [row.get("parallel", [row]) for row in plan["actions"]]
    actions = {row["id"]: row for block in blocks for row in block}

    def references(expression):
        if type(expression) is not dict or "literal" in expression:
            return set(), set()
        action_names = {expression[tag] for tag in ("ref", "available") if tag in expression}
        verdict_names = {expression["verdict"]} if "verdict" in expression else set()
        if "op" in expression:
            for argument in expression["args"]:
                a, v = references(argument)
                action_names.update(a)
                verdict_names.update(v)
        return action_names, verdict_names

    selected_obligations, direct_actions, pending = set(), set(), [target]
    while pending:
        name = pending.pop()
        if name in selected_obligations:
            continue
        selected_obligations.add(name)
        obligation = obligations[name]
        for expression in [obligation["predicate"], *(g["expr"] for g in obligation["requires"])]:
            a, v = references(expression)
            direct_actions.update(a)
            pending.extend(v - selected_obligations)

    last = 0
    for ordinal, block in enumerate(blocks, 1):
        if any(row["id"] in direct_actions for row in block):
            last = ordinal
    prefix = [row["id"] for block in blocks[:last] for row in block]
    closure, pending = set(), list(direct_actions)
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        closure.add(name)
        action = actions[name]
        expressions = list(action["arguments"].values())
        if "when" in action:
            expressions.append(action["when"])
        for expression in expressions:
            a, v = references(expression)
            need(not v, "action unexpectedly depends on a verdict")
            pending.extend(a - closure)
    return {
        "action_blocks": last, "action_ids": prefix,
        "obligation_ids": [row["id"] for row in plan["obligations"]
                           if row["id"] in selected_obligations],
        "reference_action_ids": [row["id"] for block in blocks for row in block
                                 if row["id"] in closure],
    }


def external_case(item):
    row, study = item["frame_case"], item["study"]
    if study == "sandmark":
        return row["inputs"], row["id"]
    if study == "llwm":
        return {"interface": row["interface"], "variant": row["variant"],
                "payload": row["payload"], "payload_hex": row["payload"].encode().hex(),
                "key": "1234", "ordinary": "4321", "optimization": row["optimization"]}, row["id"]
    result = {"host": row["host"], "carrier": row["carrier"],
              "implementation": row["implementation"], "payload1": b"Morph-01".hex(),
              "payload2": b"Second-2".hex(), "key1": "key-alpha", "key2": "key-beta",
              "compiler": "gcc", "optimization": "O2", "host_inputs": [0, 1, 5, 13, 144, 99991]}
    if study == "state" or (study == "state-baseline" and row["relation"] == "SR01"):
        result.update(reuse_permitted=True, lockout_excluded=True)
    return result, row["id"] + ":declaration"


def context_from_original(dataset, study, metadata):
    """Bind current original metadata, without claiming an earlier new freeze."""
    def read(relative):
        path = safe_path(dataset, relative)
        metadata.append({"path": path.relative_to(ARTIFACT).as_posix(), **identity(path)})
        return load_json(path)

    if study == "sandmark":
        protocol = read("protocol-freeze.json")
        catalog_path = "producer-snapshot/external_sandmark/algorithm-contracts.json"
        catalog = read(catalog_path)
        lock = read("acquisition-lock.json")
        for relative, source in ((catalog_path, "external_sandmark/algorithm-contracts.json"),
                                 ("acquisition-lock.json", "external_sandmark/acquisition-lock.json")):
            need(identity(dataset / relative)["sha256"] == protocol["source_bindings"][source],
                 "SandMark context differs from its original source binding")
        classes = {row["algorithm"]: row["class"] for row in catalog["algorithms"]}
        need(len(classes) == len(catalog["algorithms"]), "duplicate SandMark algorithm")
        return {"profile": "sandmark", "protocol": protocol, "catalog": classes, "lock": lock}
    tools = read("environment.json")["tools"]
    need(type(tools) is dict and tools, "missing original native tool identities")
    llvm = None
    if study == "llwm":
        probes, setup = {}, {}
        for row in read("producer-freeze.json")["inputs"]:
            if row["path"].startswith("external_llwm/probes/") and row["path"].endswith(".c"):
                bound(dataset / "source-snapshot", row)
                need(row["path"] not in probes, "duplicate LLVM probe")
                probes[row["path"]] = row
        for row in read("setup/files.json"):
            need(PurePosixPath(row["path"]).parts[0] == "setup", "LLVM setup escapes setup domain")
            bound(dataset, row)
            need(row["path"] not in setup, "duplicate LLVM setup member")
            setup[row["path"]] = row
        need(bool(probes) and bool(setup), "empty LLVM binding context")
        llvm = {"probes": probes, "setup": setup}
    return {"profile": "declarative", "tools": tools, "llvm": llvm}


def member_rows(receipt, root, profile):
    need(profile in ("declarative", "sandmark"), "unknown native member profile")
    rows = {}
    for action in receipt["actions"]:
        for event in action["evidence"]:
            for field in ("files", "files_before", "files_after"):
                for entry in event.get(field, []):
                    relative = entry["blob" if profile == "declarative" else "path"]
                    path = safe_path(root, relative)
                    need(path.is_file(), "missing native member " + relative)
                    need(type(entry["bytes"]) is int and entry["bytes"] >= 0,
                         "invalid native content length")
                    digest = entry["sha256"]
                    need(type(digest) is str and len(digest) == 64
                         and all(c in "0123456789abcdef" for c in digest), "invalid native digest")
                    row = {"path": relative, "stored_bytes": path.stat().st_size,
                           "content_bytes": entry["bytes"], "content_identity": digest}
                    if relative in rows:
                        equal(rows[relative], row, "conflicting native member " + relative)
                    rows[relative] = row
    return [rows[key] for key in sorted(rows)]


def native_metrics(rows):
    by_content = {}
    for row in rows:
        digest, length = row["content_identity"], row["content_bytes"]
        need(digest not in by_content or by_content[digest] == length,
             "same native content has conflicting lengths")
        by_content[digest] = length
    return {"native_file_paths": len(rows),
            "native_storage_bytes": sum(row["stored_bytes"] for row in rows),
            "native_unique_contents": len(by_content),
            "native_unique_content_bytes": sum(by_content.values())}


def reference_verdicts(plan, receipt):
    """Use the independent baseline expression evaluator on the thin view."""
    actions = {row["id"]: {"status": row["status"], "value": row["value"]}
               for row in receipt["actions"]}
    prior = {}
    for obligation in plan["obligations"]:
        conditions = [boolean(g["expr"], receipt["inputs"], actions, prior).to_dict()
                      for g in obligation["requires"]]
        if any(g["state"] != "TRUE" for g in conditions):
            verdict = "INADMISSIBLE"
        else:
            result = boolean(obligation["predicate"], receipt["inputs"], actions, prior).to_dict()
            verdict = {"TRUE": "SATISFIED", "FALSE": "INCONSISTENT",
                       "ERROR": "INADMISSIBLE", "UNKNOWN": "INADMISSIBLE"}[result["state"]]
        prior[obligation["id"]] = verdict
    equal(prior, {row["id"]: row["verdict"] for row in receipt["obligations"]},
          "reference-closure verdict replay")


def reconstruct(item, plan, receipt, target, context, source, chosen):
    selected = set(chosen["obligation_ids"])
    sliced = {**receipt, "actions": receipt["actions"][:len(chosen["action_ids"])],
              "obligations": [o for o in receipt["obligations"] if o["id"] in selected]}
    equal([a["id"] for a in sliced["actions"]], chosen["action_ids"], "selected prefix order")
    projection = {key: chosen[key] for key in ("action_blocks", "action_ids", "obligation_ids")}
    bundle = {"schema": "toolchainmark-obligation-evidence", "target": target["id"],
              "source_plan": plan, "projection": projection,
              "receipt": sliced, "native_context": context}
    inputs, context_id = external_case(item)
    expected = {"expected_plan": plan, "expected_inputs": inputs,
                "expected_context_id": context_id, "expected_native_context": context,
                "expected_target": target["id"]}
    checked = verify_structure(bundle, **expected)
    equal(checked["target_judgment"], target, "complete target judgment preservation")
    reference_ids = set(chosen["reference_action_ids"])
    reference = {**sliced, "actions": [a for a in receipt["actions"] if a["id"] in reference_ids]}
    reference_verdicts({**plan, "obligations": [o for o in plan["obligations"] if o["id"] in selected]}, reference)
    typed = {"inputs": receipt["inputs"], "actions": [{key: a[key] for key in ("id", "status", "value")}
             for a in reference["actions"]], "obligations": sliced["obligations"]}
    native = member_rows(sliced, source, context["profile"])
    data = native_metrics(native)
    full_data = native_metrics(member_rows(receipt, source, context["profile"]))
    ref_data = native_metrics(member_rows(reference, source, context["profile"]))
    full = {"schema": "toolchainmark-complete-evidence", "target": target["id"],
            "source_plan": plan, "receipt": receipt, "native_context": context}
    bundle_bytes = len(compact(bundle)) + data["native_storage_bytes"]
    full_bundle_bytes = len(compact(full)) + full_data["native_storage_bytes"]
    record_bytes, full_record_bytes = len(compact(sliced)), len(compact(receipt))
    actions, full_actions = len(sliced["actions"]), len(receipt["actions"])
    row = {"dataset": item["dataset"], "study": item["study"], "case": item["case"],
           "target": target["id"], "stage": target["stage"], "judgment": target["verdict"],
           "accepted": checked["status"] == "PASS", "exact_target_preservation": True,
           "reference_replay_agreement": True, "actions": actions, "full_actions": full_actions,
           "reference_actions": len(reference["actions"]), "obligations": len(sliced["obligations"]),
           "full_obligations": len(receipt["obligations"]), "record_bytes": record_bytes,
           "full_record_bytes": full_record_bytes, "reference_record_bytes": len(compact(reference)),
           "typed_replay_bytes": len(compact(typed)), "bundle_bytes": bundle_bytes,
           "full_bundle_bytes": full_bundle_bytes, "bundle_metadata_bytes": len(compact(bundle)),
           "native_context_bytes": len(compact(context)), **data,
           **{"full_" + k: v for k, v in full_data.items()},
           **{"reference_" + k: v for k, v in ref_data.items()},
           "action_fraction": actions / full_actions if full_actions else 1,
           "record_fraction": record_bytes / full_record_bytes,
           "native_storage_fraction": data["native_storage_bytes"] / full_data["native_storage_bytes"]
                                      if full_data["native_storage_bytes"] else 1,
           "bundle_fraction": bundle_bytes / full_bundle_bytes}
    case = {"plan": plan, "inputs": inputs, "context_id": context_id,
            "native_context": context, "target": target["id"]}
    transport = {"dataset": item["dataset"], "case": item["case"], "study": item["study"],
                 "target": target["id"], "external_case_compact_bytes": len(compact(case)),
                 "external_case_indented_bytes": len(pretty(case)),
                 "compact_bytes": bundle_bytes + len(compact(case)),
                 "full_compact_bytes": full_bundle_bytes + len(compact(case)),
                 "indented_bytes": len(pretty(bundle)) + len(pretty(case)) + data["native_storage_bytes"],
                 "full_indented_bytes": len(pretty(full)) + len(pretty(case)) + full_data["native_storage_bytes"]}
    return row, transport, bundle, case, expected, native


def distribution(values):
    ordered = sorted(values)
    need(bool(ordered), "empty distribution")
    def quantile(q):
        location = (len(ordered) - 1) * q
        low = math.floor(location)
        high = min(low + 1, len(ordered) - 1)
        return ordered[low] + (ordered[high] - ordered[low]) * (location - low)
    return {"min": ordered[0], "q25": quantile(.25), "median": statistics.median(ordered),
            "q75": quantile(.75), "max": ordered[-1], "mean": statistics.mean(ordered)}


def summarize(rows, transport=False):
    def group(part):
        result = {"targets": len(part)}
        if transport:
            for mode in ("compact", "indented"):
                values = [(r[mode + "_bytes"], r["full_" + mode + "_bytes"]) for r in part]
                result[mode] = {"fractions": distribution([a / b for a, b in values]),
                                "smaller": sum(a < b for a, b in values),
                                "equal": sum(a == b for a, b in values),
                                "larger": sum(a > b for a, b in values),
                                "total_bytes": sum(a for a, b in values),
                                "full_total_bytes": sum(b for a, b in values)}
            return result
        result.update(source_receipts=len({(r["dataset"], r["case"]) for r in part}),
                      judgments=dict(Counter(r["judgment"] for r in part)))
        for field in ("accepted", "exact_target_preservation", "reference_replay_agreement"):
            result[field] = sum(r[field] for r in part)
        result["zero_action_reduction"] = sum(r["actions"] == r["full_actions"] for r in part)
        result["zero_native_storage_reduction"] = sum(r["native_storage_bytes"] == r["full_native_storage_bytes"] for r in part)
        for label, compare in (("smaller", lambda a, b: a < b), ("equal", lambda a, b: a == b),
                               ("larger", lambda a, b: a > b)):
            result[label + "_complete_bundles"] = sum(compare(r["bundle_bytes"], r["full_bundle_bytes"]) for r in part)
        result["distributions"] = {name: distribution([r[name] for r in part]) for name in
            ("action_fraction", "record_fraction", "native_storage_fraction", "bundle_fraction")}
        result["totals"] = {name: sum(r[name] for r in part) for name in
            ("actions", "full_actions", "reference_actions", "record_bytes", "full_record_bytes",
             "bundle_bytes", "full_bundle_bytes", "native_storage_bytes", "full_native_storage_bytes")}
        return result
    return {**group(rows), "by_study": {name: group([r for r in rows if r["study"] == name])
                                      for name in sorted({r["study"] for r in rows})}}


def original_frame(data):
    completion = load_json(CTF / "complete.json")
    need(completion["status"] == "COMPLETE" and completion["case_inputs"] == 7380
         and completion["stage_comparisons"] == 10134, "original complete frame is not the declared denominator")
    bindings = {r["path"]: r for r in completion["files"]}
    need(len(bindings) == len(completion["files"]), "duplicate CTF completion file")
    original = load_json(bound(CTF, bindings["frame.json"]))
    equal(load_json(data / "frame.json"), original, "projection frame versus original complete frame")
    indexed(original, ("dataset", "case"), "original frame")
    need(len(original) == 7380, "missing or extra source receipt")
    datasets = load_json(bound(CTF, bindings["datasets.json"]))
    expected = []
    for dataset in datasets:
        for row in dataset["files"]:
            bound(ARTIFACT, row)
        root = safe_path(ARTIFACT, dataset["path"])
        if dataset["study"] == "sandmark":
            planned = load_json(root / "study-frame.json")["configurations"]
            completed = load_json(root / "summary.json")["configurations"]
        else:
            planned = load_json(root / "frame.json")
            completed = load_json(root / "cases.json")
        equal([r["id"] for r in completed], [r["id"] for r in planned], "original native case completion")
        need(len(planned) == dataset["cases"], "native case count differs")
        for row in planned:
            expected.append((dataset["path"], dataset["study"], row["id"], dataset["purpose"],
                             row["repeat" if dataset["study"] == "sandmark" else "run"], row))
    equal([list(x) for x in expected], [[r[k] for k in ("dataset", "study", "case", "native_purpose", "native_run", "frame_case")]
          for r in original], "complete original native frames")
    equal(dict(Counter(r["study"] for r in original)), {k: v[0] for k, v in EXPECTED_FRAME.items()}, "study receipt denominator")
    for item in original:
        case_path = item["dataset"] + "/cases/" + item["case"]
        expected_plan = item["dataset"] + "/plan.json" if item["study"] == "sandmark" else case_path + "/plan.json"
        need(item["plan"]["path"] == expected_plan and item["receipt"]["path"] == case_path + "/receipt.json",
             "original plan or receipt is associated with a different case")
    return original


def check_source_freeze(data):
    data = Path(data).resolve()
    freeze_identity = identity(data / "source-freeze.json")
    freeze = load_json(data / "source-freeze.json")
    need(freeze["frozen_before_measurement"] is True,
         "missing retained pre-measurement source declaration")

    # The published measurement keeps its historical producer identity and
    # permits only the separately registered current validation repair profile.
    if compact(freeze_identity) == compact(RETAINED_SOURCE_FREEZE):
        paths, historical_native, current_native = set(), {}, {}
        historical_producer_only, current_producer_only = {}, {}
        for row in freeze["files"]:
            need(row["path"] not in paths, "duplicate frozen source path")
            paths.add(row["path"])
            bound(data / "source-snapshot", row)
            if row["path"] in APPROVED_CURRENT_NATIVE_VALIDATION:
                historical_native[row["path"]] = {key: row[key] for key in ("bytes", "sha256")}
                current_native[row["path"]] = identity(safe_path(ARTIFACT, row["path"]))
            elif row["path"] in APPROVED_CURRENT_PRODUCER_ONLY:
                historical_producer_only[row["path"]] = {key: row[key] for key in ("bytes", "sha256")}
                current_producer_only[row["path"]] = identity(safe_path(ARTIFACT, row["path"]))
            else:
                bound(ARTIFACT, row)
        actual = {p.relative_to(data / "source-snapshot").as_posix()
                  for p in (data / "source-snapshot").rglob("*") if p.is_file()}
        need(actual == paths, "source snapshot file set differs from retained freeze")
        need(set(historical_native) == set(APPROVED_CURRENT_NATIVE_VALIDATION),
             "retained native-validation source domain differs")
        need(set(historical_producer_only) == set(APPROVED_CURRENT_PRODUCER_ONLY),
             "retained producer-only source domain differs")
        dependencies = []
        if compact(current_native) == compact(historical_native):
            profile, changed = "historical-producer", 0
        else:
            equal(current_native, APPROVED_CURRENT_NATIVE_VALIDATION,
                  "unregistered current native-validation profile")
            for row in APPROVED_CURRENT_DEPENDENCIES:
                bound(ARTIFACT, row)
                dependencies.append(dict(row))
            profile, changed = "approved-repaired-native-validation", len(current_native)
        if compact(current_producer_only) == compact(historical_producer_only):
            producer_profile, producer_changed = "historical-producer-source", 0
        else:
            equal(current_producer_only, APPROVED_CURRENT_PRODUCER_ONLY,
                  "unregistered current producer-only source profile")
            producer_profile, producer_changed = "approved-fresh-run-lineage-fix", len(current_producer_only)
        equal(load_json(data / "protocol.json"),
              load_json(data / "source-snapshot/evidence_projection/protocol.json"),
              "measurement protocol versus frozen protocol")
        return {
            "producer_mode": "published-historical-producer",
            "historical_source_freeze": dict(RETAINED_SOURCE_FREEZE),
            "fresh_source_freeze": None,
            "snapshot_files_checked": len(paths),
            "historical_snapshot_files_checked": len(paths),
            "current_validation_profile": profile,
            "current_files_matching_historical_producer": len(paths) - changed - producer_changed,
            "current_registered_repaired_files": changed,
            "current_producer_profile": producer_profile,
            "current_registered_producer_only_files": [
                {"path": path, "historical_producer": historical_producer_only[path],
                 "current_producer": current_producer_only[path]} for path in sorted(current_producer_only)
            ],
            "current_native_validation_files": [
                {"path": path, "historical_producer": historical_native[path],
                 "current_validation": current_native[path]} for path in sorted(current_native)
            ],
            "additional_current_validation_dependencies": dependencies,
            "scope": "The retained freeze and all producer snapshot bytes are checked unchanged. "
                     "An approved repaired profile identifies current validation only; it does not "
                     "relabel historical measurements, replace their producer, or record new acquisition. "
                     "A separately pinned producer-only fix may enable new runs but is not used to validate old rows.",
        }

    # A newly generated measurement has a different producer freeze by design.
    # It is accepted only when both lifecycle records bind that exact freeze.
    # A changed historical freeze without those lifecycle bindings remains a
    # historical-integrity failure rather than silently becoming a fresh run.
    if not (data / "start.json").is_file() or not (data / "complete.json").is_file():
        equal(freeze_identity, RETAINED_SOURCE_FREEZE,
              "original retained producer freeze identity")
    start = load_json(data / "start.json")
    complete = load_json(data / "complete.json")
    if "source_freeze" not in start or "source_freeze" not in complete:
        equal(freeze_identity, RETAINED_SOURCE_FREEZE,
              "original retained producer freeze identity")
    equal(start.get("source_freeze"), freeze_identity,
          "fresh measurement start source freeze binding")
    equal(complete.get("source_freeze"), freeze_identity,
          "fresh measurement completion source freeze binding")
    rows, paths = {}, set()
    for row in freeze["files"]:
        need(row["path"] not in paths, "duplicate frozen source path")
        paths.add(row["path"])
        rows[row["path"]] = row
        bound(data / "source-snapshot", row)
        equal(identity(safe_path(ARTIFACT, row["path"])),
              {key: row[key] for key in ("bytes", "sha256")},
              "fresh current producer source " + row["path"])
    actual = {p.relative_to(data / "source-snapshot").as_posix()
              for p in (data / "source-snapshot").rglob("*") if p.is_file()}
    need(actual == paths, "source snapshot file set differs from fresh freeze")
    expected = set(fresh_source_paths())
    need(paths == expected, "fresh producer source domain differs")
    equal(load_json(data / "protocol.json"),
          load_json(data / "source-snapshot/evidence_projection/protocol.json"),
          "measurement protocol versus frozen protocol")
    return {
        "producer_mode": "fresh-current-producer",
        "historical_source_freeze": None,
        "fresh_source_freeze": freeze_identity,
        "snapshot_files_checked": len(paths),
        "historical_snapshot_files_checked": 0,
        "current_validation_profile": "fresh-current-producer",
        "current_files_matching_historical_producer": 0,
        "current_registered_repaired_files": 0,
        "current_producer_profile": "fresh-current-producer",
        "current_registered_producer_only_files": [],
        "current_native_validation_files": [],
        "additional_current_validation_dependencies": [],
        "scope": "A new local measurement whose start and completion records bind the same pre-measurement "
                 "source freeze. Every frozen source byte matches both its snapshot and the current producer. "
                 "This does not relabel the published historical measurement.",
    }


def verify(data=DEFAULT):
    started = time.perf_counter()
    data = Path(data).resolve()
    complete = load_json(data / "complete.json")
    need(complete["status"] == "COMPLETE" and complete["source_receipts"] == 7380
         and complete["targets"] == 10134, "incomplete projection measurement")
    for key, filename in (("summary", "summary.json"), ("measurements", "measurements.jsonl")):
        equal(identity(data / filename), complete[key], "completion binding " + filename)
    start = load_json(data / "start.json")
    need(start["purpose"] == "complete-retained-frame" and start["fresh_native_executions"] == 0,
         "unexpected measurement acquisition scope")
    need(datetime.fromisoformat(start["started_utc"]) <= datetime.fromisoformat(complete["completed_utc"]),
         "completion precedes measurement start")
    source_lineage = check_source_freeze(data)
    frame = original_frame(data)
    measured = read_lines(data / "measurements.jsonl")
    observed = indexed(measured, ("dataset", "case", "target"), "measurement")
    need(len(observed) == 10134, "missing or extra measured target")
    transport_paths = [data / "transport-measurements.jsonl", data / "transport-summary.json"]
    need(all(p.is_file() for p in transport_paths) or not any(p.exists() for p in transport_paths),
         "incomplete additional transport accounting")
    has_transport = all(p.is_file() for p in transport_paths)
    transport_rows = read_lines(transport_paths[0]) if has_transport else []
    transport_index = indexed(transport_rows, ("dataset", "case", "target"), "transport")
    if has_transport:
        need(set(transport_index) == set(observed), "transport and measured target sets differ")
    contexts, metadata, selection_cache, recalculated, transport_recalculated = {}, [], {}, [], []
    examples, example_bytes, seen_targets = {}, [], set()
    for item in frame:
        dataset = safe_path(ARTIFACT, item["dataset"])
        if item["dataset"] not in contexts:
            contexts[item["dataset"]] = context_from_original(dataset, item["study"], metadata)
        context = contexts[item["dataset"]]
        plan, receipt = [load_json(bound(ARTIFACT, item[name])) for name in ("plan", "receipt")]
        inputs, context_id = external_case(item)
        verify_receipt(plan, receipt, expected_inputs=inputs, expected_context_id=context_id)
        source = dataset / "cases" / item["case"] if item["study"] == "sandmark" else dataset
        for target in receipt["obligations"]:
            key = item["dataset"], item["case"], target["id"]
            need(key not in seen_targets, "duplicate original target")
            seen_targets.add(key)
            need(key in observed, "unmeasured original target " + repr(key))
            cache_key = item["plan"]["sha256"], target["id"]
            if cache_key not in selection_cache:
                selection_cache[cache_key] = derive_selection(plan, target["id"])
            row, transport, bundle, case, expected, native = reconstruct(
                item, plan, receipt, target, context, source, selection_cache[cache_key])
            equal(observed[key], row, "measurement " + repr(key))
            recalculated.append(row)
            if has_transport:
                equal(transport_index[key], transport, "transport " + repr(key))
                transport_recalculated.append(transport)
            example_key = item["study"], target["verdict"]
            if example_key not in examples:
                relative = "examples/" + item["study"] + "/" + target["verdict"].lower()
                path = data / relative
                retained = load_json(path / "bundle.json")
                equal(retained, bundle, "retained example versus original fields " + relative)
                equal(load_json(path / "case.json"), case, "retained external case " + relative)
                # This checks the exact member set, every retained member's bytes,
                # native process associations, and the independently derived prefix.
                report = verify_bundle(retained, path / "native", **expected)
                equal(report, load_json(path / "verification.json"), "retained native example verification")
                actual_size = sum(p.stat().st_size for p in (path / "native").rglob("*") if p.is_file())
                actual_size += (path / "bundle.json").stat().st_size + (path / "case.json").stat().st_size
                need(actual_size == transport["indented_bytes"], "example actual transport size differs")
                need((path / "bundle.json").read_bytes() == pretty(bundle)
                     and (path / "case.json").read_bytes() == pretty(case), "example serialization differs")
                examples[example_key] = relative
                example_bytes.append({"path": relative, "actual_verification_input_bytes": actual_size,
                                      "derived_bytes": transport["indented_bytes"]})
    need(seen_targets == set(observed), "measurement includes targets absent from original frame")
    equal([(r["dataset"], r["case"], r["target"]) for r in measured],
          [(r["dataset"], r["case"], r["target"]) for r in recalculated], "measurement order")
    equal(dict(Counter(r["study"] for r in recalculated)), {k: v[1] for k, v in EXPECTED_FRAME.items()},
          "stage denominator by original study")
    actual_examples = {p.parent.relative_to(data).as_posix() for p in (data / "examples").rglob("bundle.json")}
    need(actual_examples == set(examples.values()), "exported example frame differs from first study/verdict occurrences")
    calculated_summary = summarize(recalculated)
    summary = load_json(data / "summary.json")
    expected_keys = set(calculated_summary) | {"study", "purpose", "fresh_native_executions", "source_unchanged", "elapsed_seconds", "interpretation"}
    need(set(summary) == expected_keys, "summary schema differs")
    equal({key: summary[key] for key in calculated_summary}, calculated_summary, "aggregate projection metrics")
    need(summary["study"] == "complete-prefix evidence projection" and summary["purpose"] == "complete-retained-frame"
         and summary["fresh_native_executions"] == 0 and summary["source_unchanged"] is True,
         "summary acquisition scope differs")
    need(type(summary["elapsed_seconds"]) in (int, float) and math.isfinite(summary["elapsed_seconds"])
         and summary["elapsed_seconds"] >= 0 and type(summary["interpretation"]) is str,
         "invalid summary timing or interpretation")
    if has_transport:
        equal(transport_rows, transport_recalculated, "additional transport row order and values")
        retained = load_json(transport_paths[1])
        calculated = summarize(transport_recalculated, transport=True)
        equal({key: retained[key] for key in calculated}, calculated, "aggregate transport metrics")
        equal(retained["inputs"], {"measurements": identity(data / "measurements.jsonl"),
                                   "frame": identity(data / "frame.json")}, "transport source data")
        equal(retained["analysis_source"], identity(ARTIFACT / "evidence_projection/analyze_transport.py"),
              "transport analysis source")
        equal(retained["examples"], ordered_examples(example_bytes), "actual transport example sizes")
        need(retained["exported_examples_checked"] == len(examples), "transport example denominator differs")
    # Check both the retained producer and the selected current validation
    # profile again. This checker remains outside the earlier producer freeze.
    equal(check_source_freeze(data), source_lineage, "source lineage changed during validation")
    return {
        "schema": "toolchainmark-projection-results-receiver-v1", "verdict": "PASS",
        "source_receipts_checked": len(frame), "targets_checked": len(recalculated),
        "all_target_keys_unique_and_complete": True, "all_original_plan_receipt_bindings_checked": True,
        "independent_prefix_and_reference_closures_checked": True,
        "complete_target_judgments_preserved": True, "all_measurement_rows_and_derived_aggregates_recomputed": True,
        "measurement_recomputation_scope": "All measurement rows and derived aggregates are recomputed. Historical elapsed_seconds is only checked for a finite, nonnegative value; interpretation is only checked to be a string.",
        "native_contexts_checked": len(contexts), "native_context_bindings": metadata,
        "context_binding_scope": "Current validation against retained original metadata, not a new pre-execution freeze.",
        "native_examples_checked": len(examples), "native_example_members_and_bytes_checked": True,
        "full_native_byte_revalidation_for_all_targets": False,
        "native_byte_scope": "Every retained exported example is rechecked; original full native studies are checked by their dedicated receivers. This check does not rerun native tools.",
        "reference_comparator_scope": "Equality of mapped verdicts over the explicit reference closure; not equality of all diagnostic fields or a fresh causal estimate.",
        "historical_membership_scope": "Derived projections are compared with available bound original receipts; the standalone prefix receiver alone does not authenticate unavailable history.",
        "frozen_source_files_checked": source_lineage["snapshot_files_checked"],
        "source_lineage": source_lineage,
        "transport_accounting_checked": has_transport,
        "transport_targets_checked": len(transport_recalculated),
        "fresh_native_executions": 0,
        "validation_source": {"path": "evidence_projection/verify_results.py", **identity(Path(__file__))},
        "validation_source_created_after_acquisition": True,
        "inputs": {name: identity(data / name) for name in ("frame.json", "measurements.jsonl", "summary.json", "complete.json")},
        "elapsed_seconds": time.perf_counter() - started,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT)
    args = parser.parse_args(argv)
    try:
        report = verify(args.data)
    except (ValueError, OSError, KeyError, TypeError, IndexError) as problem:
        print(json.dumps({"schema": "toolchainmark-projection-results-receiver-v1", "verdict": "FAIL",
                          "error": str(problem)}, sort_keys=True, indent=2))
        return 1
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
