"""Exact delivery membership for retained SandMark session-study files.

The inventory identifies recorded files; it does not decide their scientific
judgments or attest historical acquisition. The independent session receiver
is a separate required package check.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re


INVENTORY_SHA256 = "c390a2cbf5ca6516d0ecb1099ec24c0cc3af4f864385addafc9be726fac78d8b"
DOMAIN = "artifact/results/decoder-sessions"
ROOTS = (
    DOMAIN + "/acquisition-controls",
    DOMAIN + "/completed",
    DOMAIN + "/formal-01",
    DOMAIN + "/pilot-01",
    DOMAIN + "/pilot-02",
    DOMAIN + "/pilot-03",
)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "Duplicate session-inventory object member")
        result[key] = value
    return result


def package_inventory(project_root=None):
    project = (Path(project_root).resolve() if project_root is not None
               else Path(__file__).resolve().parents[2])
    manifest = project / "artifact/decoder_sessions/inventory_manifest.json"
    raw = manifest.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == INVENTORY_SHA256,
         "Session inventory identity differs")
    declared = json.loads(raw, object_pairs_hook=unique_object)
    need(declared.get("schema") == "sandmark-session-delivery-inventory-v1"
         and declared.get("roots") == list(ROOTS),
         "Session inventory domain or schema differs")
    domain = project / DOMAIN
    need(domain.is_dir() and not domain.is_symlink(), "Session result domain is absent or linked")
    expected_roots = {PurePosixPath(name).name for name in ROOTS}
    need({path.name for path in domain.iterdir()} == expected_roots,
         "Session result domain has missing or undeclared roots")
    files = {}
    total_bytes = 0
    for item in declared["files"]:
        name = item["path"]
        need(type(name) is str, "Session inventory path is not text")
        path = PurePosixPath(name)
        need(not path.is_absolute() and ".." not in path.parts and "\\" not in name
             and path.as_posix() == name and name not in files
             and any(name.startswith(prefix + "/") for prefix in ROOTS),
             "Unsafe, duplicate, or out-of-scope session inventory path")
        role, fmt = item["role"], item["format"]
        need((role == "owned-native-output" and fmt in {"opaque", "java-class", "text", "json"})
             or (role == "scientific-artifact-container" and fmt in {"zip", "opaque"}),
             "Invalid session inventory role or byte format")
        need(type(item["bytes"]) is int and item["bytes"] >= 0
             and type(item["sha256"]) is str
             and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
             "Invalid session inventory byte identity")
        files[name] = {key: item[key] for key in ("sha256", "bytes", "format", "role")}
        total_bytes += item["bytes"]
    need(type(declared["file_count"]) is int and declared["file_count"] == len(files)
         and type(declared["total_bytes"]) is int and declared["total_bytes"] == total_bytes,
         "Session inventory denominator differs")
    actual = set()
    for prefix in ROOTS:
        folder = project / prefix
        need(folder.is_dir() and not folder.is_symlink(), "Session result root is absent or linked")
        for path in folder.rglob("*"):
            need(not path.is_symlink(), "Session result domain contains a symlink")
            if path.is_file():
                actual.add(path.relative_to(project).as_posix())
    need(actual == set(files), "Session roots have missing or undeclared files")
    return {"paths": sorted(name for name, item in files.items()
                             if item["role"] == "scientific-artifact-container"),
            "files": files}


def expected_container_paths(project_root=None):
    return set(package_inventory(project_root)["paths"])


def expected_file_roles(project_root=None):
    return package_inventory(project_root)["files"]
