#!/usr/bin/env python3
"""Run the repository's offline implementation and receiver checks."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
from _process_runner import run_to_files

ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path(sys.executable)


def tail(path: str, limit: int = 6000) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError:
        return ""


def execute(name: str, command: list[str], *, timeout: int, log_dir: Path,
            env: dict[str, str] | None = None) -> dict:
    merged = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT), str(ROOT / "tests"))),
    }
    if env:
        merged.update(env)
    result = run_to_files(command, cwd=ROOT, log_dir=log_dir, name=name, timeout=timeout, env=merged)
    result["stdout_tail"] = tail(result["stdout"])
    result["stderr_tail"] = tail(result["stderr"])
    match = re.search(r"Ran (\d+) tests?", result["stdout_tail"] + "\n" + result["stderr_tail"])
    if match:
        result["test_cases"] = int(match.group(1))
    return result


def native_smoke(log_dir: Path) -> dict:
    compiler = shutil.which("gcc") or shutil.which("clang")
    if not compiler or not shutil.which("readelf") or not shutil.which("objcopy"):
        return {
            "name": "native declaration smoke",
            "returncode": 0,
            "seconds": 0.0,
            "skipped": True,
            "reason": "C compiler or GNU binary utilities unavailable",
        }
    with tempfile.TemporaryDirectory(prefix="toolchainmark-smoke-") as directory:
        output = Path(directory) / "declarations"
        first = execute(
            "native-declaration-acquisition",
            [str(PYTHON), "-B", "-m", "declarative_study.run", "--study", "declarations",
             "--workers", "1", "--pilot-limit", "2", "--out", str(output)],
            timeout=180,
            log_dir=log_dir,
        )
        if first["returncode"]:
            return first
        second = execute(
            "native-declaration-reception",
            [str(PYTHON), "-B", "-m", "declarative_study.verify", "--data", str(output)],
            timeout=180,
            log_dir=log_dir,
        )
        second["acquisition_seconds"] = first["seconds"]
        second["acquisition_stdout"] = first["stdout"]
        second["acquisition_stderr"] = first["stderr"]
        return second


def quick_commands() -> list[dict]:
    return [
        {"name": "repository hygiene", "command": [str(PYTHON), "-B", "scripts/check_repository.py"], "timeout": 180},
        {"name": "source syntax", "command": [str(PYTHON), "-B", "scripts/check_syntax.py"], "timeout": 180},
        {"name": "core model tests", "command": [str(PYTHON), "-B", "-m", "unittest", "discover", "-s", "tests", "-v"], "timeout": 300},
        {"name": "contract runtime controls", "command": [str(PYTHON), "-B", "-m", "unittest", "discover", "-s", "contract_runtime/tests", "-v"], "timeout": 300},
        {"name": "native binding controls", "command": [str(PYTHON), "-B", "-m", "unittest", "discover", "-s", "declarative_study/tests", "-v"], "timeout": 300},
        {"name": "correspondence controls", "command": [str(PYTHON), "-B", "-m", "unittest", "discover", "-s", "evidence_correspondence/tests", "-v"], "timeout": 300},
        {"name": "projection controls", "command": [str(PYTHON), "-B", "-m", "unittest", "-v", "evidence_projection.test_receiver", "evidence_projection.test_verify_results"], "timeout": 300},
        {"name": "history controls", "command": [str(PYTHON), "-B", "-m", "unittest", "discover", "-s", "evidence_projection/tests", "-v"], "timeout": 300},
        {"name": "state budget controls", "command": [str(PYTHON), "-B", "-m", "unittest", "discover", "-s", "state_budget/tests", "-v"], "timeout": 300},
        {"name": "GeMTest receiver controls", "command": [str(PYTHON), "-B", "-m", "unittest", "discover", "-s", "framework_comparison/tests", "-v"], "timeout": 300},
        {"name": "CTF API controls", "command": [str(PYTHON), "-B", "-m", "unittest", "discover", "-s", "ctf_comparison/tests", "-v"], "timeout": 300, "requires": ["pandas", "numpy", "scipy"]},
        {"name": "ELF observer controls", "command": [str(PYTHON), "-B", "-m", "unittest", "discover", "-s", "independent_observers/tests", "-v"], "timeout": 300},
        {"name": "optimized admission controls", "command": [str(PYTHON), "-O", "-B", "-m", "unittest", "-v", "tests.test_removal_admission", "tests.test_study_semantics"], "timeout": 300},
        {"name": "command line smoke", "command": [str(PYTHON), "-B", "-m", "toolchainmark.cli", "catalog"], "timeout": 120},
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full-evidence", action="store_true")
    parser.add_argument("--smoke-only", action="store_true")
    parser.add_argument("--report", type=Path, default=ROOT / ".validation" / "report.json")
    parser.add_argument("--log-dir", type=Path, default=ROOT / ".validation" / "steps")
    args = parser.parse_args()
    if args.full_evidence:
        command = [str(PYTHON), "-B", "scripts/check_full_evidence.py", "--report", str(args.report), "--log-dir", str(args.log_dir)]
        result = run_to_files(command, cwd=ROOT, log_dir=args.log_dir, name="full-evidence-wrapper", timeout=7200,
                              env={"PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT)))})
        return result["returncode"]

    results: list[dict] = []
    if not args.smoke_only:
        for spec in quick_commands():
            missing = [name for name in spec.get("requires", []) if importlib.util.find_spec(name) is None]
            if missing:
                result = {
                    "name": spec["name"],
                    "command": spec["command"],
                    "returncode": 0,
                    "seconds": 0.0,
                    "skipped": True,
                    "reason": "optional science dependencies unavailable: " + ", ".join(missing),
                }
            else:
                result = execute(spec["name"], spec["command"], timeout=spec["timeout"], log_dir=args.log_dir)
            results.append(result)
            label = "SKIP" if result.get("skipped") else ("PASS" if result["returncode"] == 0 else "FAIL")
            print(f"[{label}] {spec['name']} ({result['seconds']}s)", flush=True)
            if result["returncode"]:
                break
    if not results or all(item["returncode"] == 0 for item in results):
        smoke = native_smoke(args.log_dir)
        results.append(smoke)
        label = "SKIP" if smoke.get("skipped") else ("PASS" if smoke["returncode"] == 0 else "FAIL")
        print(f"[{label}] {smoke['name']} ({smoke['seconds']}s)", flush=True)

    verdict = "PASS" if all(item["returncode"] == 0 for item in results) else "FAIL"
    report = {
        "schema": "toolchainmark-quick-validation-v1",
        "verdict": verdict,
        "python": sys.version,
        "repository": ".",
        "checks": results,
        "executed": sum(not item.get("skipped", False) for item in results),
        "skipped": sum(item.get("skipped", False) for item in results),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"verdict": verdict, "checks": len(results), "report": str(args.report)}, indent=2))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
