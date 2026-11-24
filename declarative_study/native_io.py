"""Native observation acquisition; it does not classify scientific outcomes.

Captured file versions are endpoint observations. They do not assert that an
untrusted process read those bytes throughout its execution.
"""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
import base64
import gzip
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

_RUN = subprocess.run
_CURRENT = ContextVar('toolchainmark_native_evidence', default=None)
_EXECUTABLES = {}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def capture_file(path, store):
    path, store = Path(path), Path(store)
    raw = path.read_bytes()
    digest = sha(raw)
    target = store / 'blobs' / (digest + '.bin.gz')
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        fd, temporary = tempfile.mkstemp(prefix='blob-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(gzip.compress(raw, mtime=0))
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return {'path': str(path.resolve()), 'sha256': digest, 'bytes': len(raw),
            'blob': target.relative_to(store).as_posix()}


def executable_identity(name):
    resolved = shutil.which(str(name)) or str(Path(name).resolve())
    path = Path(resolved)
    if not path.is_file():
        return {'path': resolved, 'sha256': None}
    stat = path.stat()
    key = (str(path.resolve()), stat.st_size, stat.st_mtime_ns)
    if key not in _EXECUTABLES:
        _EXECUTABLES[key] = sha(path.read_bytes())
    return {'path': str(path.resolve()), 'sha256': _EXECUTABLES[key]}


@contextmanager
def acquisition(store, step_id, context_id):
    evidence = []
    token = _CURRENT.set((Path(store), step_id, context_id, evidence))
    try:
        yield evidence
    finally:
        _CURRENT.reset(token)


def captured_run(*popenargs, **kwargs):
    active = _CURRENT.get()
    if active is None:
        return _RUN(*popenargs, **kwargs)
    store, step_id, context_id, evidence = active
    argv = kwargs.get('args', popenargs[0] if popenargs else None)
    if not isinstance(argv, (list, tuple)):
        raise TypeError('native acquisition requires an argv sequence')
    argv = [str(v) for v in argv]
    kw = dict(kwargs)
    text_mode = bool(kw.pop('text', False) or kw.pop('universal_newlines', False))
    encoding, errors = kw.pop('encoding', None), kw.pop('errors', None)
    text_mode = text_mode or encoding is not None or errors is not None
    encoding, errors = encoding or 'utf-8', errors or 'strict'
    data = kw.get('input')
    if isinstance(data, str):
        data = data.encode(encoding, errors)
        kw['input'] = data
    row = {'kind': 'process', 'step_id': step_id, 'context_id': context_id,
           'argv': argv, 'cwd': str(Path(kw.get('cwd') or os.getcwd()).resolve()),
           'stdin_hex': None if data is None else data.hex(),
           'executable': executable_identity(argv[0]), 'files_before': [], 'files_after': []}
    paths = []
    for token in argv[1:]:
        p = Path(token)
        if not p.is_absolute():
            p = Path(row['cwd']) / p
        if p.is_file():
            paths.append(p)
    # Include an invoked owned program, but not the installed compiler/utilities.
    executable = Path(argv[0])
    if executable.is_absolute() and executable.is_file() and store in executable.parents:
        paths.insert(0, executable)
    paths = list(dict.fromkeys(paths))
    for path in paths:
        row['files_before'].append(capture_file(path, store))
    started = time.perf_counter()
    try:
        result = _RUN(*popenargs, **kw)
        row.update(status='COMPLETED', returncode=result.returncode,
                   stdout_hex=(result.stdout or b'').hex(), stderr_hex=(result.stderr or b'').hex())
        if text_mode:
            if result.stdout is not None:
                result.stdout = result.stdout.decode(encoding, errors).replace('\r\n', '\n').replace('\r', '\n')
            if result.stderr is not None:
                result.stderr = result.stderr.decode(encoding, errors).replace('\r\n', '\n').replace('\r', '\n')
        return result
    except (OSError, subprocess.TimeoutExpired) as exc:
        row.update(status='UNAVAILABLE', error=type(exc).__name__, returncode=None,
                   stdout_hex=(getattr(exc, 'stdout', None) or b'').hex(),
                   stderr_hex=(getattr(exc, 'stderr', None) or b'').hex())
        raise
    finally:
        for path in paths:
            if path.is_file():
                row['files_after'].append(capture_file(path, store))
        row['seconds'] = time.perf_counter() - started
        evidence.append(row)


def install_proxy(module):
    current = getattr(module, 'subprocess', None)
    if current is None or getattr(current, '_contract_native_proxy', False):
        return
    class Proxy:
        _contract_native_proxy = True
        def __getattr__(self, name):
            return captured_run if name == 'run' else getattr(current, name)
    module.subprocess = Proxy()


def verify_file(record, store):
    if (type(record) is not dict or type(record.get('bytes')) is not int or record['bytes'] < 0
            or any(type(record.get(name)) is not str or not record[name] for name in ('path', 'blob', 'sha256'))
            or len(record['sha256']) != 64 or any(c not in '0123456789abcdef' for c in record['sha256'])):
        raise ValueError('captured file identity has invalid JSON field types or values')
    path = (Path(store) / record['blob']).resolve()
    if Path(store).resolve() not in path.parents:
        raise ValueError('blob path escapes study')
    raw = gzip.decompress(path.read_bytes())
    if len(raw) != record['bytes'] or sha(raw) != record['sha256']:
        raise ValueError('captured bytes differ from identity')
    return raw


def verify_evidence(receipt, store):
    """Check recorded byte objects and ownership, not historical process honesty."""
    count = 0
    for action in receipt['actions']:
        for item in action['evidence']:
            if item.get('step_id') != action['id'] or item.get('context_id') != receipt['context_id']:
                raise ValueError('evidence belongs to another action/context')
            for name in ('files_before', 'files_after', 'files'):
                for row in item.get(name, []):
                    verify_file(row, store)
                    count += 1
            if item['kind'] == 'process':
                for name in ('stdout_hex', 'stderr_hex'):
                    bytes.fromhex(item[name])
                if item['stdin_hex'] is not None:
                    bytes.fromhex(item['stdin_hex'])
    return count
