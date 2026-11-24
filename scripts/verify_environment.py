#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys

MARKER_NAME = "toolchainmark-environment.json"
SCIENCE_DISTRIBUTIONS = ("numpy", "pandas", "scipy")


def inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-science", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    prefix = Path(sys.prefix).resolve()
    problems: list[str] = []
    marker_path = prefix / MARKER_NAME
    marker = {}
    if sys.prefix == sys.base_prefix:
        problems.append("validation is not running inside a virtual environment")
    if not marker_path.is_file():
        problems.append(f"missing installer marker: {marker_path}")
    else:
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            problems.append(f"invalid installer marker: {error}")
    mode = marker.get("mode")
    if mode not in {"core", "science"}:
        problems.append(f"unrecognized environment mode: {mode!r}")
    if args.require_science and mode != "science":
        problems.append("the full suite requires an environment installed with --with-system-science")
    if marker.get("repository") and Path(marker["repository"]).resolve() != root:
        problems.append("environment marker belongs to a different checkout")

    allowed_external = [Path(item).resolve() for item in marker.get("allowed_external_site_packages", [])]
    for raw in sys.path:
        if not raw:
            continue
        path = Path(raw).resolve()
        text = str(path)
        if "site-packages" not in text:
            continue
        if inside(path, prefix):
            continue
        if mode == "science" and any(inside(path, allowed) for allowed in allowed_external):
            continue
        problems.append(f"unapproved external site-packages visible: {text}")

    for part in filter(None, os.environ.get("PYTHONPATH", "").split(os.pathsep)):
        path = Path(part).resolve()
        if path != root and root not in path.parents:
            problems.append(f"external PYTHONPATH entry: {path}")

    packages = []
    for path in root.iterdir():
        if path.is_dir() and (path / "__init__.py").exists() and path.name not in {"tests", "scripts"}:
            packages.append(path.name)
    src = root / "src"
    if src.is_dir():
        for path in src.iterdir():
            if path.is_dir() and (path / "__init__.py").exists():
                packages.append(path.name)
    loaded = {}
    for name in sorted(set(packages)):
        try:
            module = importlib.import_module(name)
            origin = Path(getattr(module, "__file__", "")).resolve()
            loaded[name] = str(origin)
            if not inside(origin, root) and not inside(origin, prefix):
                problems.append(f"{name} loaded from unexpected path: {origin}")
        except Exception as error:
            problems.append(f"cannot import {name}: {type(error).__name__}: {error}")

    science = {}
    if mode == "science":
        recorded = marker.get("science_distributions", {})
        for name in SCIENCE_DISTRIBUTIONS:
            try:
                actual = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                actual = None
            science[name] = actual
            if not actual:
                problems.append(f"science dependency unavailable: {name}")
            elif recorded.get(name) != actual:
                problems.append(f"science dependency changed since installation: {name} {recorded.get(name)!r} -> {actual!r}")

    report = {
        "ok": not problems,
        "mode": mode,
        "python": sys.executable,
        "prefix": sys.prefix,
        "packages": loaded,
        "science_distributions": science,
        "problems": problems,
    }
    print(json.dumps(report, indent=2))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
