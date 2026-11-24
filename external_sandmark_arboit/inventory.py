"""Pinned delivery domain for the separate generated-parser follow-up."""

import hashlib
import json
from pathlib import Path

INVENTORY_SHA256 = "2c13cae6a14abd728ea5c544aa0f702c282a5155f914924a5bf42e30612c2dc1"


def expected_file_roles(project_root=None):
    project = Path(project_root).resolve() if project_root is not None else Path(__file__).resolve().parents[2]
    path = project / "artifact/external_sandmark_arboit/inventory_manifest.json"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != INVENTORY_SHA256:
        raise ValueError("Arboit follow-up inventory identity mismatch")
    data = json.loads(raw)
    if data.get("schema") != "sandmark-arboit-delivery-inventory-v1":
        raise ValueError("Arboit follow-up inventory schema mismatch")
    rows = {}
    for item in data["files"]:
        name = item["path"]
        if (not isinstance(name, str) or not name.startswith("artifact/results/external-sandmark-arboit/")
                or Path(name).is_absolute() or ".." in Path(name).parts or name in rows):
            raise ValueError("Unsafe or duplicate Arboit inventory path")
        if item["role"] not in {"scientific-artifact-container", "owned-native-output"}:
            raise ValueError("Unknown Arboit file role")
        if item["format"] not in {"zip", "java-class", "opaque", "text", "json"}:
            raise ValueError("Unknown Arboit file format")
        rows[name] = {key: item[key] for key in ("sha256", "bytes", "format", "role")}
    return rows


def expected_container_paths(project_root=None):
    return {path for path, item in expected_file_roles(project_root).items()
            if item["role"] == "scientific-artifact-container"}
