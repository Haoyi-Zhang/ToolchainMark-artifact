#!/usr/bin/env python3
"""Fetch exact original artifacts; no watermark implementation is reconstructed."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent


def acquire(destination: Path, *, local_archive: Path | None = None) -> dict:
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    lock = json.loads((HERE / "acquisition-lock.json").read_text())
    rows = []
    for item in lock["artifacts"]:
        target = destination / item["name"]
        origin = "existing verified cache"
        if not target.exists():
            if local_archive is not None:
                source = local_archive / item["name"]
                shutil.copyfile(source, target)
                origin = str(source.resolve())
            else:
                with urllib.request.urlopen(item["url"], timeout=60) as response:
                    target.write_bytes(response.read())
                origin = item["url"]
        raw = target.read_bytes()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError(f"Pinned artifact mismatch: {target}")
        rows.append({**item, "local_path": str(target), "acquired_from": origin})
    antlr = destination / "antlr-2.7.7"
    if not antlr.exists():
        with tarfile.open(destination / "antlr-2.7.7.tar.gz", "r:gz") as archive:
            archive.extractall(destination, filter="data")
    # Verify extracted inputs against the pinned archive on every invocation.
    inputs = ["antlr.jar", "LICENSE.txt", "examples/java/calc/calc.g",
              "examples/java/exprAST/expr.g", "examples/java/java/java.g"]
    with tarfile.open(destination / "antlr-2.7.7.tar.gz", "r:gz") as archive:
        for relative in inputs:
            entry = archive.extractfile("antlr-2.7.7/" + relative)
            if entry is None or entry.read() != (antlr / relative).read_bytes():
                raise ValueError(f"Extracted ANTLR input mismatch: {relative}")
    for item in lock["extracted_antlr_inputs"]:
        raw = (destination / item["path"]).read_bytes()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError(f"Pinned extracted input mismatch: {item['path']}")
    result = {"schema": "sandmark-acquisition-receipt-v1", "artifacts": rows,
              "antlr_input_files": inputs, "extracted_input_bindings": lock["extracted_antlr_inputs"]}
    (destination / "acquisition-receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--local-archive", type=Path)
    args = parser.parse_args()
    print(json.dumps(acquire(args.destination, local_archive=args.local_archive), indent=2))
