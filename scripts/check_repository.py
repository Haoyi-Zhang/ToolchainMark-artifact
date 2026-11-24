#!/usr/bin/env python3
"""Check the public repository surface without executing experiments."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".txt", ".toml", ".json", ".csv", ".sh", ".yml", ".yaml", ".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".tex"}
REQUIRED = {
    "README.md", "LICENSE", "THIRD_PARTY.md", "CONTRIBUTING.md", "SECURITY.md",
    "docs/ARCHITECTURE.md", "docs/RESEARCH_SCOPE.md", "docs/FULL_EVIDENCE.md",
    "docs/PROJECT_READINESS.md", "docs/VALIDATION.md",
    "scripts/install_local.py", "scripts/check.py", "scripts/import_evidence.py",
    "src/toolchainmark/__init__.py",
}
IGNORED_TEXT_ROOTS = {"results", "ctf_comparison/vendor", "external_llwm/vendor", "external_sandmark/qp_diagnosis"}


def under(path: Path, prefix: str) -> bool:
    return path.as_posix() == prefix or path.as_posix().startswith(prefix + "/")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    errors: list[str] = []
    warnings: list[str] = []
    runtime_roots = {".validation", "validation-logs"}
    def runtime_path(path: Path) -> bool:
        return any(part in runtime_roots or part.startswith(".venv")
                   for part in path.relative_to(ROOT).parts)
    files = [p for p in ROOT.rglob("*") if p.is_file() and not runtime_path(p)]
    relative = [p.relative_to(ROOT) for p in files]
    missing = sorted(REQUIRED - {p.as_posix() for p in relative})
    errors += ["missing required file: " + p for p in missing]

    forbidden_path = re.compile(r"(^|[-_.])(round[0-9]*|checkpoint|final|tosem02)([-_.]|$)", re.I)
    for rel, path in zip(relative, files):
        if path.is_symlink():
            errors.append("symbolic link: " + rel.as_posix())
        if any(part in {"__pycache__", ".pytest_cache", ".mypy_cache", ".test-work"} for part in rel.parts):
            errors.append("cache/work directory: " + rel.as_posix())
        if rel.parts and rel.parts[0] != "results" and forbidden_path.search(rel.as_posix()):
            errors.append("internal workflow label in path: " + rel.as_posix())
        if path.suffix.lower() in {".ttf", ".otf", ".woff", ".woff2"}:
            errors.append("font file in repository: " + rel.as_posix())

    private_patterns = ("/mnt/" + "data", "/home/" + "oai", "C:" + "\\Users\\")
    authorship_patterns = ("chat" + "gpt", "open" + "ai", "generative " + "ai", "system " + "prompt")
    parsed_python = 0
    json_files = 0
    for rel, path in zip(relative, files):
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(under(rel, prefix) for prefix in IGNORED_TEXT_ROOTS):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append("non-UTF-8 public text: " + rel.as_posix())
            continue
        lower = text.lower()
        for pattern in private_patterns:
            if pattern.lower() in lower:
                errors.append("private absolute path in " + rel.as_posix())
        for pattern in authorship_patterns:
            if pattern in lower:
                errors.append("internal authorship trace in " + rel.as_posix())
        if path.suffix == ".py":
            try:
                compile(text, rel.as_posix(), "exec")
                parsed_python += 1
            except SyntaxError as exc:
                errors.append(f"python syntax {rel}: {exc}")
        elif path.suffix == ".json":
            try:
                json.loads(text)
                json_files += 1
            except json.JSONDecodeError as exc:
                errors.append(f"json syntax {rel}: {exc}")
        elif path.suffix == ".toml":
            try:
                tomllib.loads(text)
            except tomllib.TOMLDecodeError as exc:
                errors.append(f"toml syntax {rel}: {exc}")

    if "__version__" in (ROOT / "src/toolchainmark/__init__.py").read_text(encoding="utf-8"):
        errors.append("package contains an internal release marker")

    # Duplicate reporting is advisory for compact fixtures and third-party files.
    groups: dict[tuple[bytes, int], list[str]] = {}
    total_bytes = 0
    for rel, path in zip(relative, files):
        data = path.read_bytes()
        total_bytes += len(data)
        groups.setdefault((hashlib.sha256(data).digest(), len(data)), []).append(rel.as_posix())
    duplicate_bytes = sum((len(paths) - 1) * size for (_, size), paths in groups.items() if size and len(paths) > 1)
    large_duplicate_groups = [
        {"bytes_each": size, "copies": len(paths), "paths": paths[:8]}
        for (_, size), paths in groups.items() if len(paths) > 1 and size >= 1_000_000
    ]
    if large_duplicate_groups:
        warnings.append("large duplicate content remains in compact fixtures")

    report = {
        "verdict": "PASS" if not errors else "FAIL",
        "files": len(files),
        "bytes": total_bytes,
        "duplicate_bytes": duplicate_bytes,
        "python_sources_parsed": parsed_python,
        "json_files_parsed": json_files,
        "large_duplicate_groups": large_duplicate_groups,
        "errors": errors,
        "warnings": warnings,
    }
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
