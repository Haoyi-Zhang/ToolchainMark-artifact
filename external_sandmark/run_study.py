#!/usr/bin/env python3
"""Run the fixed SandMark frame through the shared contract executor."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.core import execute, validate_plan
from external_sandmark.acquire import acquire
from external_sandmark.adapter import SandmarkAdapter, command, compile_bridge


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n")


def source_bindings():
    paths = [HERE / name for name in ["acquire.py", "adapter.py", "run_study.py", "SandmarkBridge.java",
                                      "plan.json", "study-frame.json", "algorithm-contracts.json", "acquisition-lock.json"]]
    paths.append(ARTIFACT / "contract_runtime/core.py")
    return {p.relative_to(ARTIFACT).as_posix(): digest(p) for p in sorted(set(paths))}


def freeze(output: Path, cache: Path) -> dict:
    if output.exists():
        raise ValueError("A new freeze requires a new, empty output location")
    output.mkdir(parents=True)
    plan = json.loads((HERE / "plan.json").read_text())
    validate_plan(plan, allowed_operations=SandmarkAdapter.operations)
    acquisition = acquire(cache)
    compile_bridge(cache, output / "bridge")
    java = Path(shutil.which("java") or "java").resolve()
    env = command([str(java), "-version"], output, output / "java-version", timeout=15)
    runtime = {"executable": str(java), "executable_sha256": digest(java),
               "platform": platform.platform(), "python": sys.version,
               "version_record": env}
    jdk = java.parent.parent
    for name in ["release", "lib/modules"]:
        p = jdk / name
        if p.exists():
            runtime[name] = {"sha256": digest(p), "bytes": p.stat().st_size}
    protocol = {"schema": "sandmark-study-freeze-v1", "frozen_unix_ns": time.time_ns(),
                "execution_root": str(output),
                "source_bindings": source_bindings(),
                "acquisition_lock_sha256": digest(HERE / "acquisition-lock.json"),
                "acquisition": acquisition, "runtime": runtime,
                "bridge_sha256": digest(output / "bridge/SandmarkBridge.class"),
                "plan_sha256": digest(HERE / "plan.json"),
                "frame_sha256": digest(HERE / "study-frame.json"),
                "max_workers": 2,
                "formal_execution_started": False}
    for name in ["plan.json", "study-frame.json", "acquisition-lock.json"]:
        shutil.copyfile(HERE / name, output / name)
    for relative in protocol["source_bindings"]:
        target = output / "producer-snapshot" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ARTIFACT / relative, target)
    write(output / "protocol-freeze.json", protocol)
    return protocol


def run(output: Path, cache: Path, *, pilot_ids: list[str] | None = None) -> dict:
    output = output.resolve()
    cache = cache.resolve()
    protocol = json.loads((output / "protocol-freeze.json").read_text())
    if protocol["source_bindings"] != source_bindings():
        raise ValueError("Implementation changed after the experiment freeze")
    if digest(output / "bridge/SandmarkBridge.class") != protocol["bridge_sha256"]:
        raise ValueError("Bridge changed after the experiment freeze")
    acquire(cache)
    plan = json.loads((output / "plan.json").read_text())
    frame = json.loads((output / "study-frame.json").read_text())
    if digest(output / "plan.json") != protocol["plan_sha256"] or digest(output / "study-frame.json") != protocol["frame_sha256"]:
        raise ValueError("Frozen plan or frame changed")
    if (output / "execution-start.json").exists():
        raise ValueError("This run already started; preserve it and use a new run directory")
    configurations = frame["configurations"]
    if pilot_ids is not None:
        wanted = set(pilot_ids)
        configurations = [row for row in configurations if row["id"] in wanted]
        if len(configurations) != len(wanted):
            raise ValueError("Unknown or duplicate pilot case identifiers")
    write(output / "execution-start.json", {"started_unix_ns": time.time_ns(),
                                           "kind": "exploratory-pilot" if pilot_ids is not None else "formal-full-frame",
                                           "configuration_ids": [row["id"] for row in configurations],
                                           "protocol_freeze_sha256": digest(output / "protocol-freeze.json")})
    counts = Counter()
    rows = []
    for item in configurations:
        case_path = output / "cases" / item["id"]
        adapter = SandmarkAdapter(case_path, cache, output / "bridge",
                                  java=protocol["runtime"]["executable"],
                                  embed_timeout=frame["timeouts_seconds"]["embed"],
                                  extract_timeout=frame["timeouts_seconds"]["extract"],
                                  host_timeout=frame["timeouts_seconds"]["host_task"])
        receipt = execute(plan, item["inputs"], adapter, context_id=item["id"], max_workers=protocol["max_workers"])
        write(case_path / "receipt.json", receipt)
        judgments = {row["id"]: row["verdict"] for row in receipt["obligations"]}
        counts.update(judgments.values())
        row = {**item, "receipt_sha256": digest(case_path / "receipt.json"), "judgments": judgments,
               "action_status": {a["id"]: a["status"] for a in receipt["actions"]}}
        rows.append(row)
        print(json.dumps({"completed": len(rows), "case": item["id"], "algorithm": item["inputs"]["algorithm"],
                          "host": item["inputs"]["host"], "judgments": judgments}), flush=True)
    if protocol["source_bindings"] != source_bindings():
        raise ValueError("Implementation changed during experiment execution; retain incomplete evidence")
    summary = {"schema": "sandmark-study-summary-v1", "kind": "exploratory-pilot" if pilot_ids is not None else "formal-full-frame",
               "configuration_count": len(rows), "full_frame_configurations": frame["expected_configurations"],
               "obligation_count": sum(counts.values()), "judgments": dict(counts), "configurations": rows}
    write(output / "summary.json", summary)
    write(output / "completion.json", {"completed_unix_ns": time.time_ns(), "configuration_count": len(rows),
                                       "summary_sha256": digest(output / "summary.json"),
                                       "protocol_freeze_sha256": digest(output / "protocol-freeze.json"),
                                       "source_bindings_after_execution": source_bindings()})
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["freeze", "run"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--pilot-cases", nargs="+")
    args = parser.parse_args()
    if args.operation == "freeze":
        result = freeze(args.output.resolve(), args.cache.resolve())
        print(json.dumps({"frozen": str(args.output), "sources": len(result["source_bindings"])}))
    else:
        result = run(args.output, args.cache, pilot_ids=args.pilot_cases)
        print(json.dumps({"completed": result["configuration_count"], "judgments": result["judgments"]}))
