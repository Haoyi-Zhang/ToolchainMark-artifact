"""File/serialization utilities; no scientific judgment or plan interpretation."""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + '\n')


def read_json(path: Path):
    return json.loads(path.read_text())


def binding(path: Path, root: Path) -> dict:
    return {'path': path.relative_to(root).as_posix(), 'sha256': file_digest(path), 'bytes': path.stat().st_size}


def clone_file(source: Path, target: Path) -> None:
    """Private writable inode; a filesystem reflink never aliases modifications."""
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open('rb') as src, target.open('xb') as dst:
            fcntl.ioctl(dst.fileno(), 0x40049409, src.fileno())
    except OSError:
        target.unlink(missing_ok=True)
        shutil.copyfile(source, target)


FILES = {'target': 'host_wm.jar', 'original': 'host.jar', 'key_file': 'gtw.key',
         'target_constraints': 'host_wm.smconfig', 'original_constraints': 'host.smconfig'}


def snapshot(folder: Path, run: Path, blobs: Path) -> dict:
    """Store every observed endpoint byte object, including unexpected changes."""
    result = {}
    for role, name in FILES.items():
        path = folder / name
        row = {'present': path.is_file(), 'bytes': None, 'sha256': None, 'blob': None}
        if row['present']:
            raw = path.read_bytes(); digest = sha(raw); blob = blobs / digest
            blob.parent.mkdir(parents=True, exist_ok=True)
            if not blob.exists():
                with tempfile.NamedTemporaryFile(dir=blobs, prefix='.capture-', delete=False) as handle:
                    handle.write(raw); temporary = Path(handle.name)
                try:
                    os.link(temporary, blob)
                except FileExistsError:
                    pass
                finally:
                    temporary.unlink()
            if file_digest(blob) != digest: raise ValueError('Existing snapshot blob differs')
            row.update(bytes=len(raw), sha256=digest, blob=blob.relative_to(run).as_posix())
        result[role] = row
    return result
