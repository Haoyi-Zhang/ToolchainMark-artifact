"""Native byte members and existing binding profiles for evidence projections."""
from __future__ import annotations

from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil


DECLARATIVE_OPERATIONS = {'session', 'build', 'extract', 'host', 'capture', 'inspect',
    'checksum_view', 'relocate', 'remove', 'corrupt', 'begin_overlap', 'end_overlap',
    'llvm_build', 'invoke', 'sections', 'strip_debug'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def native_context(dataset, study):
    dataset = Path(dataset)
    if study == 'sandmark':
        protocol = json.loads((dataset / 'protocol-freeze.json').read_text())
        catalog = json.loads((dataset / 'producer-snapshot/external_sandmark/algorithm-contracts.json').read_text())
        return {'profile': 'sandmark', 'protocol': protocol,
                'catalog': {row['algorithm']: row['class'] for row in catalog['algorithms']},
                'lock': json.loads((dataset / 'acquisition-lock.json').read_text())}
    from declarative_study.verify import llvm_binding_context
    return {'profile': 'declarative',
            'tools': json.loads((dataset / 'environment.json').read_text())['tools'],
            'llvm': llvm_binding_context(dataset) if study == 'llwm' else None}


def members(receipt, native_root, profile):
    """Each path is needed by a retained acquisition record, without guessing."""
    native_root = Path(native_root).resolve()
    selected = {}
    for action in receipt['actions']:
        for event in action['evidence']:
            for field in ('files', 'files_before', 'files_after'):
                for record in event.get(field, []):
                    relative = record['blob'] if profile == 'declarative' else record['path']
                    path = (native_root / relative).resolve()
                    need(path.is_relative_to(native_root) and path.is_file(), 'missing/escaping native member')
                    row = {'path': relative, 'stored_bytes': path.stat().st_size,
                           'content_bytes': record['bytes'], 'content_identity': record['sha256']}
                    if relative in selected:
                        need(selected[relative] == row, 'native member has conflicting identities')
                    selected[relative] = row
    return [selected[key] for key in sorted(selected)]


def metrics(items):
    contents = {}
    for row in items:
        key = row['content_identity']
        need(key not in contents or contents[key] == row['content_bytes'], 'content length disagreement')
        contents[key] = row['content_bytes']
    return {'native_file_paths': len(items), 'native_storage_bytes': sum(row['stored_bytes'] for row in items),
            'native_unique_contents': len(contents), 'native_unique_content_bytes': sum(contents.values())}


def populate(items, source, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for row in items:
        old, new = Path(source) / row['path'], destination / row['path']
        new.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(old, new)
        except OSError:
            shutil.copyfile(old, new)


def verify_native(receipt, root, context):
    profile = context['profile']
    selected = members(receipt, root, profile)
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    need(actual == {row['path'] for row in selected}, 'native member set differs from retained actions')
    if profile == 'declarative':
        need(set(context) == {'profile', 'tools', 'llvm'} and type(context['tools']) is dict,
             'malformed declarative native context')
        need(all(row['operation'] in DECLARATIVE_OPERATIONS for row in receipt['actions']),
             'operation unsupported by selected native profile')
        from declarative_study.native_io import verify_evidence
        from declarative_study.verify import value_bindings
        count = verify_evidence(receipt, root)
        result = value_bindings(receipt, root, llvm_context=context['llvm'], native_tools=context['tools'])
        result.pop('blobs')
        return {'profile': profile, 'captured_file_references': count, **result, **metrics(selected)}
    need(profile == 'sandmark' and set(context) == {'profile', 'protocol', 'catalog', 'lock'},
         'unknown native binding profile')
    need(all(row['operation'].startswith('sandmark.') for row in receipt['actions']),
         'operation unsupported by SandMark native profile')
    from external_sandmark.verify_study import reobserve
    counts = Counter()
    for action in receipt['actions']:
        reobserve(root, action, context['protocol'], context['catalog'], context['lock'], counts)
    return {'profile': profile, **dict(counts), **metrics(selected)}
