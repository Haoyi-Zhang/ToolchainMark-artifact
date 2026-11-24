"""Exact delivery-domain provider for SandMark scientific byte artifacts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

INVENTORY_SHA256 = '41bea6c1e3dbe2a16399a75adb598a82618498e262107439489d5ff16edb00e7'


def expected_file_roles(project_root=None):
    project = Path(project_root).resolve() if project_root is not None else Path(__file__).resolve().parents[2]
    manifest = project / 'artifact/external_sandmark/inventory_manifest.json'
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != INVENTORY_SHA256:
        raise ValueError('SandMark scientific inventory identity mismatch')
    value = json.loads(raw)
    if value.get('schema') != 'sandmark-delivery-inventory-v1':
        raise ValueError('SandMark scientific inventory schema mismatch')
    rows = {}
    for row in value['files']:
        path = row['path']
        if (not isinstance(path, str) or not path.startswith('artifact/results/external-sandmark/')
                or Path(path).is_absolute() or '..' in Path(path).parts or path in rows):
            raise ValueError('Unsafe or duplicate SandMark inventory path')
        if row['role'] not in {'scientific-artifact-container', 'owned-native-output'}:
            raise ValueError('Unknown SandMark file role')
        if row['format'] not in {'zip', 'opaque', 'text', 'json', 'java-class'}:
            raise ValueError('Unknown SandMark byte format')
        rows[path] = {k: row[k] for k in ['sha256', 'bytes', 'format', 'role']}
    return rows


def expected_container_paths(project_root=None):
    return {path for path, row in expected_file_roles(project_root).items()
            if row['role'] == 'scientific-artifact-container'}
