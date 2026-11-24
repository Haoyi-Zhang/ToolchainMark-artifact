#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from _process_runner import run_to_files

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=("quick", "full"), default="quick")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--log-dir", type=Path, default=ROOT / "validation-logs")
    args = parser.parse_args()
    python = Path(sys.executable)
    env_command = [str(python), "-B", str(ROOT / "scripts" / "verify_environment.py")]
    if args.suite == "full":
        env_command.append("--require-science")
    entries = [("environment", env_command, 300)]
    if args.suite == "quick":
        target = ROOT / "scripts" / "check.py"
        command = [str(python), "-B", str(target),
                   "--report", str(args.log_dir / "quick-report.json"),
                   "--log-dir", str(args.log_dir / "quick-steps")]
    else:
        target = ROOT / "scripts" / "check_full_evidence.py"
        command = [str(python), "-B", str(target),
                   "--report", str(args.log_dir / "full-report.json"),
                   "--log-dir", str(args.log_dir / "full-steps")]
    if not target.exists():
        raise SystemExit(f"missing validation entry point: {target}")
    entries.append((args.suite, command, args.timeout))

    results = []
    env = {
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(ROOT),
        "HOME": str(args.log_dir / "home"),
        "XDG_CACHE_HOME": str(args.log_dir / "cache"),
        "TMPDIR": str(args.log_dir / "tmp"),
    }
    for path in (Path(env["HOME"]), Path(env["XDG_CACHE_HOME"]), Path(env["TMPDIR"])):
        path.mkdir(parents=True, exist_ok=True)
    for name, command, timeout in entries:
        result = run_to_files(command, cwd=ROOT, log_dir=args.log_dir, name=name, timeout=timeout, env=env)
        results.append(result)
        if result["returncode"] != 0:
            break
    status = {"suite": args.suite, "ok": all(row["returncode"] == 0 for row in results), "results": results}
    (args.log_dir / f"{args.suite}-status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(status, indent=2))
    if not status["ok"]:
        failed = results[-1]
        detail = ""
        for stream in ("stderr", "stdout"):
            try:
                detail = Path(failed[stream]).read_text(encoding="utf-8", errors="replace").strip()[-2000:]
            except (KeyError, OSError):
                continue
            if detail:
                break
        print(f"step '{failed.get('name', '?')}' failed (logs in {args.log_dir})"
              + (":\n" + detail if detail else ""), file=sys.stderr)
    return 0 if status["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
