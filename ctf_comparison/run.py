"""Freeze and run a real-CTF comparison over completed native study receipts.

Example (run from the artifact root with the documented CTF runtime):
  python3 -B -m ctf_comparison.run --purpose formal --data PATH --out NEW_PATH
No programs-under-test are executed by this command.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import shutil
import sys
import time

from .code_surface import measure_plan, measure_sources
from .expressions import BaselineInputError
from .oracle import compare_receipt, digest, runtime_identity

ARTIFACT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent


def sha_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BaselineInputError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def reject(value):
        raise BaselineInputError(f"nonfinite JSON number: {value}")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique, parse_constant=reject)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")


def relative(path):
    try:
        return path.resolve().relative_to(ARTIFACT).as_posix()
    except ValueError as exc:
        raise BaselineInputError("comparison datasets and output must be beneath the artifact root for portable bindings") from exc


def input_frame(datasets, purpose):
    frame, manifests, seen = [], [], set()
    for data in datasets:
        data_name = relative(data)
        if data_name in seen:
            raise BaselineInputError("duplicate dataset")
        seen.add(data_name)
        summary = load(data / "summary.json")
        sandmark = (data / "study-frame.json").is_file()
        if sandmark:
            inventory = load(data / "study-frame.json")
            planned = inventory["configurations"]
            measured = summary["configurations"]
            study = "sandmark"
            native_purpose = "formal" if summary["kind"] == "formal-full-frame" else "pilot"
            case_count = summary["configuration_count"]
            manifest_names = ("study-frame.json", "summary.json", "protocol-freeze.json", "plan.json", "execution-start.json", "completion.json")
            if len(planned) != inventory["expected_configurations"]:
                raise BaselineInputError("SandMark frame cardinality mismatch")
            complete = load(data / "completion.json")
            if complete["summary_sha256"] != sha_file(data / "summary.json") or complete["configuration_count"] != len(planned):
                raise BaselineInputError("SandMark completion binding mismatch")
        else:
            planned = load(data / "frame.json")
            measured = load(data / "cases.json")
            study, native_purpose, case_count = summary["study"], summary["purpose"], summary.get("cases")
            manifest_names = ("frame.json", "cases.json", "summary.json", "producer-freeze.json", "protocol.json")
        if purpose == "formal" and native_purpose != "formal":
            raise BaselineInputError("formal comparison cannot pool pilot or exploratory receipts")
        if type(planned) is not list or [case["id"] for case in planned] != [case["id"] for case in measured]:
            raise BaselineInputError(f"native planned/completed case frame mismatch: {data_name}")
        if type(case_count) is not int or case_count != len(planned):
            raise BaselineInputError("native summary does not describe the exact completed frame")
        dataset_files = []
        for name in manifest_names:
            path = data / name
            dataset_files.append({"path": relative(path), "bytes": path.stat().st_size, "sha256": sha_file(path)})
        ids = set()
        for case in planned:
            case_id = case["id"]
            if case_id in ids or not case_id or Path(case_id).is_absolute() or ".." in Path(case_id).parts:
                raise BaselineInputError("invalid or duplicate native case identifier")
            ids.add(case_id)
            base = data / "cases" / case_id
            row = {"dataset": data_name, "study": study, "native_purpose": native_purpose,
                   "case": case_id, "native_run": case["repeat"] if sandmark else case["run"], "frame_case": case}
            for kind in ("plan", "receipt"):
                path = data / "plan.json" if sandmark and kind == "plan" else base / f"{kind}.json"
                row[kind] = {"path": relative(path), "bytes": path.stat().st_size, "sha256": sha_file(path)}
            frame.append(row)
        manifests.append({"path": data_name, "study": study, "purpose": native_purpose,
                          "format": "sandmark-study-v1" if sandmark else "declarative-study-v1",
                          "cases": len(planned), "files": dataset_files})
    return frame, manifests


def source_freeze(output):
    candidates = [p for p in HERE.rglob("*") if p.is_file() and
                  (p.suffix in (".py", ".md", ".toml", ".json", ".txt")) and
                  "__pycache__" not in p.parts]
    files = []
    for path in sorted(candidates):
        name = relative(path)
        target = output / "source-snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        files.append({"path": name, "bytes": path.stat().st_size, "sha256": sha_file(path)})
    return {"schema": "toolchainmark-ctf-source-freeze-v1", "files": files,
            "frozen_before_comparison": True}


def tally(rows):
    framework, ctf, mapped = Counter(), Counter(), Counter()
    by_study = {}
    disagreements, estimator_calls, oracle_calls = 0, 0, 0
    for case in rows:
        group = by_study.setdefault(case["study"], {"cases": 0, "stage_comparisons": 0, "disagreements": 0,
                                                  "ctf_outcomes": Counter(), "framework_verdicts": Counter(), "by_native_run": {}})
        group["cases"] += 1
        run = group["by_native_run"].setdefault(str(case["native_run"]), {"cases": 0, "stage_comparisons": 0, "disagreements": 0})
        run["cases"] += 1
        for result in case["results"]:
            framework[result["framework_verdict"]] += 1
            ctf[result["ctf_result"]["outcome"]] += 1
            mapped[result["mapped_verdict"]] += 1
            mismatch = not result["agreement"]
            disagreements += mismatch
            estimator_calls += result["estimator_calls"]
            oracle_calls += result["oracle_calls"]
            group["stage_comparisons"] += 1
            group["disagreements"] += mismatch
            group["ctf_outcomes"][result["ctf_result"]["outcome"]] += 1
            group["framework_verdicts"][result["framework_verdict"]] += 1
            run["stage_comparisons"] += 1
            run["disagreements"] += mismatch
    return {"cases": len(rows), "stage_comparisons": sum(framework.values()), "disagreements": disagreements,
            "framework_verdicts": dict(framework), "ctf_outcomes": dict(ctf), "ctf_mapped_verdicts": dict(mapped),
            "actual_estimator_calls": estimator_calls, "actual_custom_oracle_calls": oracle_calls, "by_study": by_study}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True, action="append", help="Completed native study directory; repeat for multiple studies")
    parser.add_argument("--out", type=Path, required=True, help="New output directory beneath the artifact root")
    parser.add_argument("--purpose", choices=("pilot", "formal"), required=True)
    args = parser.parse_args(argv)
    output = args.out.resolve()
    relative(output)
    if output.exists():
        raise BaselineInputError("output already exists; choose a new directory")
    identity = runtime_identity()
    frame, datasets = input_frame([p.resolve() for p in args.data], args.purpose)
    if not frame:
        raise BaselineInputError("empty comparison frame")
    output.mkdir(parents=True)
    started = datetime.now(timezone.utc).isoformat()
    freeze = source_freeze(output)
    write(output / "producer-freeze.json", freeze)
    write(output / "frame.json", frame)
    write(output / "datasets.json", datasets)
    write(output / "environment.json", {"python": sys.version, "platform": platform.platform(),
          "packages": {name: version(name) for name in ("numpy", "pandas", "lifelines", "scipy")},
          "ctf_runtime": identity})
    write(output / "protocol.json", {"schema": "toolchainmark-ctf-shared-observations-v1", "purpose": args.purpose,
          "unit": "One stage obligation over one previously acquired native execution receipt",
          "observation_fields": ["inputs", "actions[].id", "actions[].status", "actions[].value"],
          "excluded_framework_fields": ["obligations", "guards", "argument_evaluations", "consumed_references", "gate_evaluations"],
          "outcome_mapping": {"PASS": "SATISFIED", "FAIL": "INCONSISTENT", "INESTIMABLE": "INADMISSIBLE"},
          "statistical_inference": False, "fresh_native_execution": False,
          "independent_custom_expression_implementation": True,
          "primary_question": "Do independent custom predicates through the real CTF API agree under the same declared observations?",
          "interpretation": "Equal outcomes establish no exclusive failure-detection advantage; acquisition and record validation are separate work."})
    write(output / "source-surface.json", measure_sources())
    start = time.perf_counter()
    rows, plans = [], {}
    with (output / "cases.jsonl").open("w", encoding="utf-8") as stream:
        for item in frame:
            plan = load(ARTIFACT / item["plan"]["path"])
            receipt = load(ARTIFACT / item["receipt"]["path"])
            if digest(plan) != receipt["plan_sha256"] or digest(receipt["inputs"]) != receipt["inputs_sha256"]:
                raise BaselineInputError("receipt canonical plan/input hashes disagree")
            answer = compare_receipt(plan, receipt)
            row = {"dataset": item["dataset"], "study": item["study"], "case": item["case"], "native_run": item["native_run"],
                   "plan_sha256": item["plan"]["sha256"], "receipt_sha256": item["receipt"]["sha256"], **answer}
            rows.append(row)
            stream.write(json.dumps(row, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n")
            key = digest(plan)
            plans.setdefault(key, {"canonical_sha256": key, **measure_plan(plan)})
    elapsed = time.perf_counter() - start
    # Verify both measurement code and complete data frame remained unchanged.
    bindings = list(freeze["files"])
    bindings += [item[kind] for item in frame for kind in ("plan", "receipt")]
    bindings += [item for dataset in datasets for item in dataset["files"]]
    for item in bindings:
        path = ARTIFACT / item["path"]
        if path.stat().st_size != item["bytes"] or sha_file(path) != item["sha256"]:
            raise BaselineInputError(f"input changed during comparison: {item['path']}")
    summary = {"schema": "toolchainmark-ctf-comparison-v1", "purpose": args.purpose,
               **tally(rows), "source_and_data_unchanged": True, "ctf_commit": identity["commit"],
               "same_native_observations": True, "fresh_native_execution": False,
               "statistical_inference": False, "elapsed_seconds": elapsed,
               "independence": "Custom expression evaluator imports neither executor, receiver, nor adapters; shared native observations are not an independent execution.",
               "comparison_scope": "Exact-data custom extension through real CTF entry point; not the stock causal inference estimators."}
    write(output / "summary.json", summary)
    write(output / "plan-surface.json", {"distinct_canonical_plans": len(plans), "plans": list(plans.values())})
    outputs = [p for p in sorted(output.iterdir()) if p.is_file()]
    write(output / "complete.json", {"schema": "toolchainmark-ctf-completion-v1", "status": "COMPLETE", "started_utc": started,
          "completed_utc": datetime.now(timezone.utc).isoformat(),
          "files": [{"path": p.name, "bytes": p.stat().st_size, "sha256": sha_file(p)} for p in outputs],
          "source_files": len(freeze["files"]), "case_inputs": len(frame), "stage_comparisons": summary["stage_comparisons"]})
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BaselineInputError, OSError, KeyError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "INVALID_COMPARISON_INPUT", "error": str(error)}), file=sys.stderr)
        raise SystemExit(1)
