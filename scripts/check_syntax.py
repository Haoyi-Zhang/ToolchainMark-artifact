#!/usr/bin/env python3
"""Compile Python source in memory without creating bytecode files."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {".venv", "results", "__pycache__"}


def main() -> int:
    checked = 0
    errors: list[str] = []
    for path in sorted(ROOT.rglob("*.py")):
        relative = path.relative_to(ROOT)
        if any(part in IGNORED for part in relative.parts):
            continue
        try:
            compile(path.read_text(encoding="utf-8"), relative.as_posix(), "exec")
            checked += 1
        except (SyntaxError, UnicodeError, OSError) as exc:
            errors.append(f"{relative.as_posix()}: {exc}")
    print(json.dumps({"verdict": "PASS" if not errors else "FAIL", "files": checked, "errors": errors}, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
