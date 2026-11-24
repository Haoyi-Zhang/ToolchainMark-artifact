"""Read-only binding and judgment checks for retained CTF comparisons.

Default verification uses only the standard library and the comparison's custom
expression implementation. It checks the retained data, not an attestation that
CTF executed. --rerun-ctf repeats the real official API and requires its runtime.
Neither mode executes native programs or claims independent observations.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from .expressions import BaselineInputError, boolean

ARTIFACT = Path(__file__).resolve().parents[1]
DEFAULT = ARTIFACT / "results/ctf-comparison/formal-01"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read(path):
    def pairs(items):
        answer = {}
        for key, value in items:
            if key in answer:
                raise BaselineInputError(f"duplicate key in {path.name}: {key}")
            answer[key] = value
        return answer
    def constant(name):
        raise BaselineInputError(f"nonfinite number in {path.name}: {name}")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def insist(condition, message):
    if not condition:
        raise BaselineInputError(message)


def bound(root, item):
    path = Path(item["path"])
    insist(not path.is_absolute() and ".." not in path.parts, "nonportable binding path")
    path = root / path
    raw = path.read_bytes()
    insist(len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"], f"changed bound file: {item['path']}")
    return path


def expected_case(plan, receipt):
    actions = {a["id"]: {"status": a["status"], "value": a["value"]} for a in receipt["actions"]}
    insist(len(actions) == len(receipt["actions"]), "duplicate action")
    observation = {"inputs": receipt["inputs"], "actions": actions}
    results, prior = [], {}
    insist([o["id"] for o in plan["obligations"]] == [o["id"] for o in receipt["obligations"]], "obligation frame changed")
    for obligation, framework in zip(plan["obligations"], receipt["obligations"]):
        gates = [{"name": g["name"], **boolean(g["expr"], observation["inputs"], actions, prior).to_dict()} for g in obligation["requires"]]
        failed = next((g for g in gates if g["state"] != "TRUE"), None)
        pred = None
        if failed is not None:
            mapped, official, reason, oracle_calls = "INADMISSIBLE", "INESTIMABLE", f"gate:{failed['name']}:{failed['state']}", 0
        else:
            pred = boolean(obligation["predicate"], observation["inputs"], actions, prior).to_dict()
            oracle_calls = 1
            if pred["state"] in ("ERROR", "UNKNOWN"):
                mapped, official, reason = "INADMISSIBLE", "INESTIMABLE", f"predicate:{pred['state']}"
            elif pred["state"] == "TRUE":
                mapped, official, reason = "SATISFIED", "PASS", "predicate-true"
            else:
                mapped, official, reason = "INCONSISTENT", "FAIL", "predicate-false"
        dataframe = {**observation, "prior_verdicts": dict(prior)}
        effect = {} if official == "INESTIMABLE" else {"effect_measure": "exact_observations",
                     "components": ["actions", "inputs", "prior_verdicts"], "content_sha256": digest(dataframe)}
        official_result = {"outcome": official, "passed": official == "PASS", "effect_estimate": effect,
                           "adequacy": {}, "effect_direction": ""}
        if official == "INESTIMABLE":
            official_result["error_message"] = reason
        results.append({"id": obligation["id"], "stage": obligation["stage"], "clause": obligation["clause"],
                        "ctf_result": official_result, "mapped_verdict": mapped, "reason": reason,
                        "gates": gates, "predicate": pred, "estimator_calls": 1, "oracle_calls": oracle_calls,
                        "dataframe_sha256": digest(dataframe), "framework_verdict": framework["verdict"],
                        "agreement": mapped == framework["verdict"]})
        prior[obligation["id"]] = mapped
    return {"observation_sha256": digest(observation), "results": results}


def verify(run, rerun_ctf=False):
    completion = read(run / "complete.json")
    insist(completion["schema"] == "toolchainmark-ctf-completion-v1" and completion["status"] == "COMPLETE", "incomplete comparison")
    output_paths = {item["path"] for item in completion["files"]}
    required = {"summary.json", "producer-freeze.json", "datasets.json", "frame.json", "cases.jsonl", "environment.json",
                "protocol.json", "source-surface.json", "plan-surface.json"}
    insist(output_paths == required, "completion file set differs from the protocol")
    for item in completion["files"]:
        bound(run, item)
    freeze = read(run / "producer-freeze.json")
    insist(freeze["schema"] == "toolchainmark-ctf-source-freeze-v1" and freeze["frozen_before_comparison"] is True, "source freeze missing")
    current_sources = 0
    for item in freeze["files"]:
        bound(run / "source-snapshot", item)
        path = ARTIFACT / item["path"]
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]:
            current_sources += 1
    insist(completion["source_files"] == len(freeze["files"]), "source count mismatch")
    upstream = read(run / "source-snapshot/ctf_comparison/UPSTREAM.json")
    for item in upstream["files"]:
        bound(run / "source-snapshot/ctf_comparison", item)
    environment = read(run / "environment.json")
    identity = environment["ctf_runtime"]
    insist(identity["commit"] == upstream["commit"] and identity["archive_sha256"] == upstream["archive_sha256"], "CTF identity mismatch")
    insist(identity["entry_point"] == "causal_testing.testing.causal_test_case.CausalTestCase.execute_test", "wrong CTF entry point")
    insist(identity["unmodified_upstream"] is True and identity["vendored_files_checked"] == len(upstream["files"]), "upstream binding incomplete")
    upstream_hashes = {item["path"]: item["sha256"] for item in upstream["files"]}
    insist(len(identity["classes"]) == 5, "incomplete official API origin list")
    for item in identity["classes"]:
        insist(upstream_hashes.get(item["source"]) == item["sha256"], "imported class source differs from upstream")
    datasets = read(run / "datasets.json")
    frame = read(run / "frame.json")
    expected_frame, dataset_case_count = [], 0
    for dataset in datasets:
        for item in dataset["files"]:
            bound(ARTIFACT, item)
        native = ARTIFACT / dataset["path"]
        sandmark = dataset.get("format") == "sandmark-study-v1"
        if sandmark:
            planned = read(native / "study-frame.json")["configurations"]
            native_summary = read(native / "summary.json")
            completed = native_summary["configurations"]
            native_completion = read(native / "completion.json")
            insist(native_completion["summary_sha256"] == hashlib.sha256((native / "summary.json").read_bytes()).hexdigest(), "SandMark completion summary mismatch")
            insist(native_summary["kind"] == "formal-full-frame" and native_completion["configuration_count"] == len(planned), "SandMark full frame incomplete")
            insist(dataset["study"] == "sandmark" and dataset["purpose"] == "formal", "SandMark dataset scope mismatch")
        else:
            planned = read(native / "frame.json")
            completed = read(native / "cases.json")
            native_summary = read(native / "summary.json")
            insist(dataset["study"] == native_summary["study"] and dataset["purpose"] == native_summary["purpose"], "native dataset scope mismatch")
        insist([c["id"] for c in planned] == [c["id"] for c in completed], "native frame/completion mismatch")
        insist(dataset["cases"] == len(planned), "dataset case count mismatch")
        dataset_case_count += len(planned)
        expected_frame.extend((dataset["path"], c["id"], c["repeat"] if sandmark else c["run"], c) for c in planned)
    insist([(r["dataset"], r["case"], r["native_run"], r["frame_case"]) for r in frame] == expected_frame, "selected comparison frame differs from complete native frames")
    rows = [json.loads(line) for line in (run / "cases.jsonl").read_text().splitlines()]
    insist(len(rows) == len(frame) == dataset_case_count == completion["case_inputs"], "missing or extra comparison case")
    if rerun_ctf:
        from .oracle import compare_receipt, runtime_identity
        runtime_identity()
    framework, official, mapped = Counter(), Counter(), Counter()
    by_study = {}
    stages, disagreements, calls, oracle_calls = 0, 0, 0, 0
    plans = set()
    for item, row in zip(frame, rows):
        plan = read(bound(ARTIFACT, item["plan"]))
        receipt = read(bound(ARTIFACT, item["receipt"]))
        insist(digest(plan) == receipt["plan_sha256"] and digest(receipt["inputs"]) == receipt["inputs_sha256"], "receipt canonical hash mismatch")
        expected = {"dataset": item["dataset"], "study": item["study"], "case": item["case"], "native_run": item["native_run"],
                    "plan_sha256": item["plan"]["sha256"], "receipt_sha256": item["receipt"]["sha256"], **expected_case(plan, receipt)}
        insist(canonical(row) == canonical(expected), f"retained CTF record disagrees with observations: {item['case']}")
        if rerun_ctf:
            actual = compare_receipt(plan, receipt)
            insist(canonical(actual) == canonical({k: expected[k] for k in ("observation_sha256", "results")}), "fresh official CTF result differs")
        plans.add(digest(plan))
        group = by_study.setdefault(item["study"], {"cases": 0, "stage_comparisons": 0, "disagreements": 0,
                                                   "ctf_outcomes": Counter(), "framework_verdicts": Counter(), "by_native_run": {}})
        group["cases"] += 1
        native_run = group["by_native_run"].setdefault(str(item["native_run"]), {"cases": 0, "stage_comparisons": 0, "disagreements": 0})
        native_run["cases"] += 1
        for result in row["results"]:
            stages += 1
            mismatch = not result["agreement"]
            disagreements += mismatch
            calls += result["estimator_calls"]
            oracle_calls += result["oracle_calls"]
            framework[result["framework_verdict"]] += 1
            official[result["ctf_result"]["outcome"]] += 1
            mapped[result["mapped_verdict"]] += 1
            group["stage_comparisons"] += 1
            group["disagreements"] += mismatch
            group["ctf_outcomes"][result["ctf_result"]["outcome"]] += 1
            group["framework_verdicts"][result["framework_verdict"]] += 1
            native_run["stage_comparisons"] += 1
            native_run["disagreements"] += mismatch
    summary = read(run / "summary.json")
    expected_summary = {"cases": len(frame), "stage_comparisons": stages, "disagreements": disagreements,
                        "framework_verdicts": dict(framework), "ctf_outcomes": dict(official), "ctf_mapped_verdicts": dict(mapped),
                        "actual_estimator_calls": calls, "actual_custom_oracle_calls": oracle_calls, "by_study": by_study}
    insist(summary["schema"] == "toolchainmark-ctf-comparison-v1", "unexpected comparison schema")
    insist(summary["purpose"] in ("formal", "pilot") and summary["ctf_commit"] == upstream["commit"], "comparison purpose or commit mismatch")
    for key, value in expected_summary.items():
        insist(canonical(summary[key]) == canonical(value), f"summary mismatch: {key}")
    insist(summary["source_and_data_unchanged"] is True and summary["same_native_observations"] is True, "missing scope declarations")
    insist(summary["statistical_inference"] is False and summary["fresh_native_execution"] is False, "unsupported scope declarations")
    insist(completion["stage_comparisons"] == stages, "completion denominator mismatch")
    protocol = read(run / "protocol.json")
    insist(protocol["schema"] == "toolchainmark-ctf-shared-observations-v1", "wrong protocol")
    insist(protocol["purpose"] == summary["purpose"], "purpose mismatch")
    insist(protocol["statistical_inference"] is False and protocol["fresh_native_execution"] is False,
            "protocol declares unsupported acquisition or inference")
    insist(protocol["independent_custom_expression_implementation"] is True, "missing implementation boundary")
    insist(protocol["observation_fields"] == ["inputs", "actions[].id", "actions[].status", "actions[].value"], "shared observation interface changed")
    insist(protocol["outcome_mapping"] == {"PASS": "SATISFIED", "FAIL": "INCONSISTENT", "INESTIMABLE": "INADMISSIBLE"}, "outcome mapping changed")
    if summary["purpose"] == "formal":
        insist(all(d["purpose"] == "formal" for d in datasets), "pilot mixed into formal comparison")
    return {"schema": "toolchainmark-ctf-receiver-v1", "verdict": "PASS", "purpose": summary["purpose"],
            "case_inputs": len(frame), "stage_comparisons": stages, "disagreements": disagreements,
            "ctf_outcomes": dict(official), "source_files": len(freeze["files"]), "current_source_matches": current_sources,
            "snapshot_source_bindings_checked": True, "dataset_bindings_checked": True, "exact_case_frame_checked": True,
            "ctf_commit": upstream["commit"], "distinct_plans": len(plans), "official_ctf_reexecuted": rerun_ctf,
            "native_programs_reexecuted": False,
            "scope": "Default: binding and consistency of retained records using the same custom CTF expression semantics; not independent observation or proof that the API executed. Optional flag reexecutes the unmodified official CTF entry point."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=DEFAULT)
    parser.add_argument("--rerun-ctf", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = verify(args.run.resolve(), args.rerun_ctf)
    except (BaselineInputError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(json.dumps({"schema": "toolchainmark-ctf-receiver-v1", "verdict": "INVALID_RECORD", "reason": str(error)}))
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
