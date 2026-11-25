#!/usr/bin/env python3
"""Attach complete study evidence to a disposable repository checkout."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil

FIXED_MAPPINGS = (
    ("evidence-correspondence", "evidence-correspondence"),
    ("evidence-projection", "evidence-projection"),
    ("state-budget", "state-budget"),
    ("framework-comparison", "framework-comparison"),
    ("ctf-comparison", "ctf-comparison"),
    ("decoder-sessions", "decoder-sessions"),
    ("llwm-native", "llwm-native"),
    ("external-sandmark", "external-sandmark"),
    ("external-sandmark-arboit", "external-sandmark-arboit"),
    ("external-sandmark-qp", "external-sandmark-qp"),
    ("independent-observers", "independent-observers"),
    ("postfreeze-challenge", "postfreeze-challenge"),
    ("recovery-extension", "recovery-extension"),
)


# Repository records added after the evidence object was deposited.
REPOSITORY_ONLY = {"evidence-correspondence": ("ctf-arm",)}


def count_tree(root: Path) -> tuple[int, int]:
    files = 0
    size = 0
    for path in root.rglob("*"):
        if path.is_file():
            files += 1
            size += path.stat().st_size
    return files, size


def locate_declarative(results: Path) -> Path:
    candidates = [
        path for path in results.iterdir()
        if path.is_dir() and path.name.startswith("declarative")
        and (path / "reference/frame.json").is_file()
    ]
    exact = [path for path in candidates if path.name == "declarative"]
    if len(exact) == 1:
        return exact[0]
    if len(candidates) != 1:
        raise ValueError("cannot identify one complete declarative-study directory")
    return candidates[0]


def copy_tree(source: Path, destination: Path, *, replace: bool, link: bool) -> dict:
    kept: list[str] = []
    holding = destination.parent / f".{destination.name}.repository-only"
    if destination.exists():
        if not replace:
            raise FileExistsError(f"destination exists; use --replace in a disposable checkout: {destination}")
        # Records that exist only in the repository and are not part of the
        # evidence object (REPOSITORY_ONLY) are kept; everything else is replaced.
        if holding.exists():
            shutil.rmtree(holding)
        for child in sorted(destination.iterdir()):
            if child.name in REPOSITORY_ONLY.get(destination.name, ()) and not (source / child.name).exists():
                holding.mkdir(exist_ok=True)
                shutil.move(str(child), holding / child.name)
                kept.append(child.name)
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, copy_function=os.link if link else shutil.copy2)
    for name in kept:
        shutil.move(str(holding / name), destination / name)
    if holding.exists():
        holding.rmdir()
    files, size = count_tree(destination)
    row = {"dataset": destination.name, "files": files, "bytes": size}
    if kept:
        row["repository_only_kept"] = kept
    return row


def add_compatibility_paths(destination: Path, historical_declarative_name: str) -> list[str]:
    created: list[str] = []
    neutral = destination / "results/declarative"
    if historical_declarative_name != "declarative":
        alias = destination / "results" / historical_declarative_name
        if alias.exists():
            shutil.rmtree(alias)
        shutil.copytree(neutral, alias, copy_function=os.link)
        created.append(alias.relative_to(destination).as_posix())

    ctf_root = destination / "results/ctf-comparison"
    reference = ctf_root / "reference"
    if ctf_root.is_dir() and not reference.exists():
        formal = [path for path in ctf_root.iterdir()
                  if path.is_dir() and (path / "complete.json").is_file()
                  and (path / "summary.json").is_file()]
        formal = [path for path in formal
                  if json.loads((path / "summary.json").read_text(encoding="utf-8")).get("purpose") == "formal"]
        if len(formal) == 1:
            shutil.copytree(formal[0], reference, copy_function=os.link)
            created.append(reference.relative_to(destination).as_posix())

    freeze_path = destination / "results/evidence-projection/completed/source-freeze.json"
    if freeze_path.is_file():
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        for row in freeze.get("files", []):
            relative = PurePosixPath(row.get("path", ""))
            target = destination.joinpath(*relative.parts)
            if target.exists() or relative.name != "independent_observer.py":
                continue
            candidate = destination / "independent_observers/producer_current/independent_observer.py"
            if candidate.is_file() and relative.parts[:1] == ("independent_observers",):
                target.parent.mkdir(parents=True, exist_ok=True)
                os.link(candidate, target)
                created.append(target.relative_to(destination).as_posix())
    return created


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="complete artifact directory")
    parser.add_argument("--destination", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--link", action="store_true", help="hard-link files for a local read-only validation checkout")
    args = parser.parse_args()
    source = args.source.resolve()
    destination = args.destination.resolve()
    if not (source / "contract_runtime").is_dir() or not (source / "results").is_dir():
        parser.error("source is not a complete artifact directory")
    if not (destination / "src/toolchainmark").is_dir():
        parser.error("destination is not a ToolchainMark repository")

    copied = []
    try:
        declarative = locate_declarative(source / "results")
        copied.append(copy_tree(declarative, destination / "results/declarative",
                                replace=args.replace, link=args.link))
        for old_name, new_name in FIXED_MAPPINGS:
            old = source / "results" / old_name
            if old.exists():
                copied.append(copy_tree(old, destination / "results" / new_name,
                                        replace=args.replace, link=args.link))
        compatibility = add_compatibility_paths(destination, declarative.name)
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))

    marker = destination / "results/.full-evidence.json"
    marker.write_text(json.dumps({
        "schema": "toolchainmark-full-evidence-import",
        "linked": args.link,
        "datasets": copied,
        "compatibility_paths": compatibility,
    }, indent=2) + "\n", encoding="utf-8")
    print(marker.read_text(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
