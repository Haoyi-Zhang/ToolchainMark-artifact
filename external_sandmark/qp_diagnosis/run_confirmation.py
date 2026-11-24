#!/usr/bin/env python3
"""Freeze and run the original QP implementation on a fixed follow-up frame.

This study is conditional on the original 156-case study and is not an
independent estimate of algorithm failure prevalence. It changes no algorithm.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import platform
import shutil
import sys
import time

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.core import execute, validate_plan
from external_sandmark.acquire import acquire
from external_sandmark.adapter import SandmarkAdapter, command, compile_bridge
from external_sandmark.run_study import digest, write


def source_bindings():
    names = ["contract_runtime/core.py", "contract_runtime/__init__.py",
             "external_sandmark/adapter.py", "external_sandmark/acquire.py",
             "external_sandmark/run_study.py", "external_sandmark/SandmarkBridge.java",
             "external_sandmark/plan.json", "external_sandmark/algorithm-contracts.json",
             "external_sandmark/acquisition-lock.json",
             "external_sandmark/qp_diagnosis/run_confirmation.py",
             "external_sandmark/qp_diagnosis/confirmation-frame.json"]
    return {name: digest(ARTIFACT / name) for name in sorted(names)}


def freeze(output, cache):
    if output.exists():
        raise ValueError("Use a new output directory; previous attempts are retained")
    output.mkdir(parents=True)
    plan = json.loads((HERE.parent / "plan.json").read_text())
    validate_plan(plan, allowed_operations=SandmarkAdapter.operations)
    acquisition = acquire(cache)
    compile_bridge(cache, output / "bridge")
    java = Path(shutil.which("java") or "java").resolve()
    version = command([str(java), "-version"], output, output / "java-version", timeout=15)
    runtime = {"executable": str(java), "executable_sha256": digest(java),
               "platform": platform.platform(), "python": sys.version,
               "version_record": version}
    for name in ["release", "lib/modules"]:
        path = java.parent.parent / name
        if path.exists():
            runtime[name] = {"sha256": digest(path), "bytes": path.stat().st_size}
    for source, target in [(HERE.parent / "plan.json", "plan.json"),
                           (HERE / "confirmation-frame.json", "study-frame.json"),
                           (HERE.parent / "acquisition-lock.json", "acquisition-lock.json")]:
        shutil.copyfile(source, output / target)
    protocol = {"schema": "sandmark-qp-confirmation-freeze-v1", "frozen_unix_ns": time.time_ns(),
                "execution_root": str(output), "source_bindings": source_bindings(),
                "acquisition_lock_sha256": digest(output / "acquisition-lock.json"),
                "acquisition": acquisition, "runtime": runtime,
                "bridge_sha256": digest(output / "bridge/SandmarkBridge.class"),
                "plan_sha256": digest(output / "plan.json"),
                "frame_sha256": digest(output / "study-frame.json"), "max_workers": 2,
                "implementation": "unmodified archived sandmark.jar",
                "study_role": "post-diagnosis confirmation; separate from original 156 cases"}
    for relative in protocol["source_bindings"]:
        target = output / "producer-snapshot" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ARTIFACT / relative, target)
    write(output / "protocol-freeze.json", protocol)
    return {"frozen": str(output), "protocol_freeze_sha256": digest(output / "protocol-freeze.json"),
            "configurations": 10, "sources": len(protocol["source_bindings"])}


def run(output, cache):
    protocol = json.loads((output / "protocol-freeze.json").read_text())
    if protocol["source_bindings"] != source_bindings():
        raise ValueError("Producer changed after freeze")
    if digest(output / "bridge/SandmarkBridge.class") != protocol["bridge_sha256"]:
        raise ValueError("Compiled bridge changed")
    acquire(cache)
    plan = json.loads((output / "plan.json").read_text())
    frame = json.loads((output / "study-frame.json").read_text())
    if digest(output / "plan.json") != protocol["plan_sha256"] or digest(output / "study-frame.json") != protocol["frame_sha256"]:
        raise ValueError("Frozen plan/frame changed")
    if (output / "execution-start.json").exists():
        raise ValueError("Run already started; retain the attempt")
    write(output / "execution-start.json", {"started_unix_ns": time.time_ns(),
          "kind": "post-diagnosis-confirmation", "configuration_ids": [r["id"] for r in frame["configurations"]],
          "protocol_freeze_sha256": digest(output / "protocol-freeze.json")})
    rows, counts = [], Counter()
    for item in frame["configurations"]:
        case = output / "cases" / item["id"]
        adapter = SandmarkAdapter(case, cache, output / "bridge", java=protocol["runtime"]["executable"],
                                  embed_timeout=30, extract_timeout=30, host_timeout=15)
        receipt = execute(plan, item["inputs"], adapter, context_id=item["id"], max_workers=2)
        write(case / "receipt.json", receipt)
        judgments = {r["id"]: r["verdict"] for r in receipt["obligations"]}
        counts.update(judgments.values())
        row = {**item, "receipt_sha256": digest(case / "receipt.json"), "judgments": judgments,
               "action_status": {a["id"]: a["status"] for a in receipt["actions"]}}
        rows.append(row)
        print(json.dumps({"completed": len(rows), "id": item["id"], "payload": item["inputs"]["payload"],
                          "judgments": judgments}), flush=True)
    if source_bindings() != protocol["source_bindings"]:
        raise ValueError("Producer changed during execution")
    summary = {"schema": "sandmark-qp-confirmation-summary-v1", "kind": "post-diagnosis-confirmation",
               "configuration_count": len(rows), "obligation_count": sum(counts.values()),
               "judgments": dict(counts), "configurations": rows,
               "scope": "10 fresh executions of original QP on ANTLR; not merged with the original 156-case study"}
    write(output / "summary.json", summary)
    write(output / "completion.json", {"completed_unix_ns": time.time_ns(), "configuration_count": len(rows),
          "summary_sha256": digest(output / "summary.json"), "protocol_freeze_sha256": digest(output / "protocol-freeze.json"),
          "source_bindings_after_execution": source_bindings()})
    return {"completed": len(rows), "judgments": dict(counts)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["freeze", "run"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    result = globals()[args.operation](args.output.resolve(), args.cache.resolve())
    print(json.dumps(result, indent=2))
