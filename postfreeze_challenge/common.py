"""Immutable plan identity, source binding and portable byte utilities."""
from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PLAN_SHA256 = '337e87e8da55bc284b222d1b5dfb57511070540d7ec0170eaf5f40b0ab530f24'
FREEZE_SHA256 = 'a60e4da161570ff0ea17fb0d8e7f5682e55cdb20e6ba467f608045cd3710bfe0'
PRODUCERS = ('__init__.py', 'common.py', 'recording.py', 'adapters.py', 'run.py', 'derive.py')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def utc():
    return datetime.now(timezone.utc).isoformat()


def safe_path(root, name):
    path = PurePosixPath(name)
    require(path.parts and not path.is_absolute() and '..' not in path.parts and
            '\\' not in name and ':' not in name and path.as_posix() == name, 'unsafe relative path')
    target = root.joinpath(*path.parts)
    require(target.resolve().is_relative_to(root.resolve()), 'path escapes root')
    return target


def load_plan(folder=HERE):
    raw = (folder / 'plan.json').read_bytes()
    require(sha(raw) == PLAN_SHA256, 'registered plan identity differs')
    plan = json.loads(raw)
    frozen = (folder / 'frozen-inputs.json').read_bytes()
    require(sha(frozen) == FREEZE_SHA256 == plan['source_freeze_sha256'], 'initial source freeze differs')
    return plan, json.loads(frozen)


def verify_frozen(root=ROOT, folder=HERE):
    plan, frozen = load_plan(folder)
    entries = frozen['files']
    require(len(entries) == len({row['path'] for row in entries}) == 42, 'frozen input domain differs')
    require(sha(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()) ==
            frozen['source_tree_sha256'], 'frozen source-tree digest differs')
    for entry in entries:
        path = safe_path(root, entry['path'])
        require(path.is_file() and path.stat().st_size == entry['bytes'] and
                sha(path.read_bytes()) == entry['sha256'], 'frozen source changed: ' + entry['path'])
    return plan, frozen


def checkout_inputs(frozen, root=ROOT, extra=()):
    """Current-checkout counterparts of the frozen v4 inputs, for a fresh campaign.

    After this challenge was recorded, the public repository renamed the v4
    implementation package to src/toolchainmark/ and edited some modules and
    campaign scripts, so the historical identities in frozen-inputs.json
    (still checked against the retained source snapshot by verify.py) can no
    longer match a checkout. A fresh campaign binds the same roles in the
    current checkout instead: the frozen hosts, specifications and campaign
    scripts at their paths, every module of src/toolchainmark/, and `extra`.
    """
    paths = [entry['path'] for entry in frozen['files'] if PurePosixPath(entry['path']).parts[0] != 'src']
    paths += sorted(path.relative_to(root).as_posix() for path in (root / 'src/toolchainmark').glob('*.py'))
    paths += list(extra)
    rows = []
    for name in paths:
        raw = safe_path(root, name).read_bytes()
        rows.append({'path': name, 'bytes': len(raw), 'sha256': sha(raw)})
    return rows


def verify_checkout(entries, root=ROOT):
    for entry in entries:
        path = safe_path(root, entry['path'])
        require(path.is_file() and path.stat().st_size == entry['bytes'] and
                sha(path.read_bytes()) == entry['sha256'], 'checkout input changed: ' + entry['path'])


def usage():
    own = resource.getrusage(resource.RUSAGE_SELF)
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'python_cpu_seconds': own.ru_utime + own.ru_stime,
            'waited_child_cpu_seconds': child.ru_utime + child.ru_stime}


def delta_usage(start):
    return {key: value - start[key] for key, value in usage().items()}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True).encode() + b'\n')


def put_blob(root, raw):
    """Publish complete deterministic gzip bytes atomically, deduplicated by SHA."""
    digest = sha(raw)
    relative = 'blobs/' + digest + '.bin.gz'
    target = safe_path(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    compressed = gzip.compress(raw, mtime=0)
    if not target.exists():
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.pending-', delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(compressed)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                pass
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    require(target.read_bytes() == compressed, 'content-addressed blob collision or corruption')
    return {'path': relative, 'bytes': len(raw), 'sha256': digest,
            'compressed_bytes': len(compressed), 'compressed_sha256': sha(compressed)}


def write_trace(path, data):
    raw = json_bytes(data)
    compressed = gzip.compress(raw, mtime=0)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        handle.write(compressed)
    return {'bytes': len(raw), 'sha256': sha(raw),
            'compressed_bytes': len(compressed), 'compressed_sha256': sha(compressed)}
