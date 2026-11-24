#!/usr/bin/env python3
"""Run every complete-record receiver in a disposable evidence checkout."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from _process_runner import run_to_files

ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path(sys.executable)

CHECKS = (
    ("correspondence", ["-m", "evidence_correspondence.verify"], 600),
    ("projection", ["-m", "evidence_projection.verify_results"], 1800),
    ("history", ["-m", "evidence_projection.verify_history"], 600),
    ("state_budget", ["-m", "state_budget.verify"], 900),
    ("framework_comparison", ["-m", "framework_comparison.verify"], 900),
    ("ctf_comparison", ["-m", "ctf_comparison.verify", "--run", "results/ctf-comparison/formal-01"], 900),
    ("decoder_sessions", ["-m", "decoder_sessions.verify", "--data", "results/decoder-sessions/completed"], 1200),
    ("external_llwm", ["external_llwm/verify_study.py"], 600),
    ("external_sandmark", ["external_sandmark/verify_study.py", "--run", "results/external-sandmark/formal-01"], 900),
)


def sanitize(text: str) -> str:
    return text.replace(str(ROOT), ".").replace(str(PYTHON), "python")


def read_tail(path: str, limit: int = 8000) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError:
        return ""


def run(name: str, arguments: list[str], timeout: int, log_dir: Path) -> dict:
    command = [str(PYTHON), "-B", *arguments]
    env = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT))),
    }
    result = run_to_files(command, cwd=ROOT, log_dir=log_dir, name=name, timeout=timeout, env=env)
    stdout = read_tail(result["stdout"])
    stderr = read_tail(result["stderr"])
    result.update({
        "command": ["python", "-B", *arguments],
        "stdout_tail": sanitize(stdout),
        "stderr_tail": sanitize(stderr),
    })
    try:
        value = json.loads(Path(result["stdout"]).read_text(encoding="utf-8"))
        if isinstance(value, dict):
            result["receiver"] = value
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    match = re.search(r"Ran (\d+) tests?", stdout + "\n" + stderr)
    if match:
        result["test_cases"] = int(match.group(1))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / ".validation/full-evidence.json")
    parser.add_argument("--log-dir", type=Path, default=ROOT / ".validation/full-steps")
    args = parser.parse_args()
    marker = ROOT / "results/.full-evidence.json"
    if not marker.is_file():
        parser.error("complete evidence is not attached; obtain the separate evidence object "
                     "(see README.md and docs/FULL_EVIDENCE.md) and run scripts/import_evidence.py "
                     "in a disposable checkout")

    results = []
    for name, arguments, timeout in CHECKS:
        result = run(name, list(arguments), timeout, args.log_dir)
        results.append(result)
        print(f"[{'PASS' if result['returncode'] == 0 else 'FAIL'}] {name} ({result['seconds']}s)", flush=True)
        if result["returncode"]:
            break
    verdict = "PASS" if len(results) == len(CHECKS) and all(row["returncode"] == 0 for row in results) else "FAIL"
    report = {
        "schema": "toolchainmark-evidence-validation-v1",
        "verdict": verdict,
        "checks_expected": len(CHECKS),
        "checks": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"verdict": verdict, "checks": len(results), "report": str(args.report)}, indent=2))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
