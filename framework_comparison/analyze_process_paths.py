"""Explain path differences in the completed paired study without changing it.

This is a post-acquisition analysis. The frozen comparison and its raw
differences remain intact. Only the two declared workspaces, decoder context
names, captured observer-private input paths, and objcopy's private section
destination are assigned corresponding names. All other bytes are compared.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re


def need(condition, message):
    if not condition:
        raise ValueError(message)


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)


def recorded_root(actions, case_id, arm):
    suffix = '/cases/' + case_id + '/' + arm + '-native'
    roots = {value[:value.index(suffix) + len(suffix)]
             for value in strings(actions) if value.startswith('/') and suffix in value}
    need(len(roots) == 1, 'ambiguous recorded native workspace')
    return roots.pop()


def raw_file(record, store):
    path = (store / record['blob']).resolve()
    need(path.is_relative_to(store.resolve()), 'byte object escapes study')
    raw = gzip.decompress(path.read_bytes())
    need(len(raw) == record['bytes'] and hashlib.sha256(raw).hexdigest() == record['sha256'],
         'retained byte object differs from recorded identity')
    return raw


PRIVATE = re.compile(r'/tmp/(?:[A-Za-z0-9_-]+-)?(carrier|section)-[A-Za-z0-9_-]+/([A-Za-z0-9_.-]+)')


def correspondence(left, right, store):
    """Derive a bijection only for the two documented private path roles."""
    maps = [{}, {}]
    rows = []
    need(len(left) == len(right), 'different evidence counts')
    for event, (a, b) in enumerate(zip(left, right)):
        need(a['kind'] == b['kind'], 'different evidence kinds')
        if a['kind'] != 'process':
            continue
        need(len(a['argv']) == len(b['argv']), 'different argv lengths')
        for index, (aa, bb) in enumerate(zip(a['argv'], b['argv'])):
            ma, mb = PRIVATE.search(aa), PRIVATE.search(bb)
            need(bool(ma) == bool(mb), 'private path role differs')
            if ma is None:
                continue
            pa, pb = ma.group(), mb.group()
            need(ma.groups() == mb.groups(), 'private path kind or basename differs')
            kind = ma.group(1)
            proof = []
            if kind == 'carrier':
                need(aa == pa and bb == pb, 'private carrier is not a whole argv token')
                for endpoint in ('files_before', 'files_after'):
                    ar = [x for x in a[endpoint] if x['path'] == pa]
                    br = [x for x in b[endpoint] if x['path'] == pb]
                    need(len(ar) == len(br) == 1, 'private input lacks a unique endpoint capture')
                    need(raw_file(ar[0], store) == raw_file(br[0], store),
                         'corresponding private input bytes differ')
                    proof.append({'endpoint': endpoint, 'bytes': ar[0]['bytes'],
                                  'left_blob': ar[0]['blob'], 'right_blob': br[0]['blob']})
                role = 'captured-observer-input'
            else:
                need(index == 2 and a['argv'][:2] == b['argv'][:2] == ['objcopy', '--dump-section']
                     and len(a['argv']) == len(b['argv']) == 4
                     and aa == '.wmrec=' + pa and bb == '.wmrec=' + pb,
                     'private section destination is not the declared utility role')
                role = 'section-dump-destination'
            if pa in maps[0] or pb in maps[1]:
                need(pa in maps[0] and pb in maps[1] and maps[0][pa] == maps[1][pb],
                     'private path correspondence is not bijective')
            else:
                label = '<' + role + '-' + str(len(maps[0])) + '/' + ma.group(2) + '>'
                maps[0][pa] = maps[1][pb] = label
                rows.append({'event': event, 'argv_position': index, 'role': role,
                             'left_path': pa, 'right_path': pb, 'capture_checks': proof,
                             'destination_bytes_retained': kind != 'section'})
    return maps, rows


def rename(value, replacements, key=None):
    if isinstance(value, str):
        if key in ('stdin_hex', 'stdout_hex', 'stderr_hex'):
            data = bytes.fromhex(value)
            for old, new in replacements:
                data = data.replace(old.encode(), new.encode())
            return data.hex()
        for old, new in replacements:
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [rename(item, replacements) for item in value]
    if isinstance(value, dict):
        return {name: rename(item, replacements, name) for name, item in value.items()
                if name != 'seconds'}
    return value


def leaves(left, right, path=''):
    if type(left) is not type(right):
        return [path + ':type']
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return [path + ':keys']
        return [p for k in left for p in leaves(left[k], right[k], path + '/' + k)]
    if isinstance(left, list):
        if len(left) != len(right):
            return [path + ':length']
        return [p for i, (a, b) in enumerate(zip(left, right))
                for p in leaves(a, b, path + '/' + str(i))]
    return [] if left == right else [path]


def analyze(store):
    store = Path(store).resolve()
    frame = json.loads((store / 'frame.json').read_text())
    original = json.loads((store / 'summary.json').read_text())
    cases, counts = [], Counter()
    for item in frame:
        case = store / 'cases' / item['id']
        contract = json.loads((case / 'contract.json').read_text())['receipt']
        gemtest = json.loads((case / 'gemtest.json').read_text())
        actions = [contract['actions'], gemtest['actions']]
        roots = [recorded_root(actions[i], item['id'], name)
                 for i, name in enumerate(('contract', 'gemtest'))]
        need([a['id'] for a in actions[0]] == [a['id'] for a in actions[1]], 'action frame differs')
        output = {'case': item['id'], 'path_correspondences': [], 'remaining_differences': []}
        for a, b in zip(*actions):
            maps, roles = correspondence(a['evidence'], b['evidence'], store)
            for row in roles:
                row['action'] = a['id']
                counts[row['role']] += 1
                counts['private_input_endpoint_byte_pairs'] += len(row['capture_checks'])
            output['path_correspondences'].extend(roles)
            renamed = [rename(row['evidence'], [(roots[i], '<native>'),
                        ([contract, gemtest][i]['context_id'], '<context>'), *maps[i].items()])
                       for i, row in enumerate((a, b))]
            differences = leaves(*renamed)
            output['remaining_differences'].extend({'action': a['id'], 'field': field}
                                                    for field in differences)
            counts['process_pairs'] += sum(x['kind'] == 'process' for x in a['evidence'])
            counts['action_pairs'] += 1
        counts['pairs_with_remaining_differences'] += bool(output['remaining_differences'])
        counts['remaining_differing_fields'] += len(output['remaining_differences'])
        cases.append(output)
    return {'analysis': 'post-acquisition explicit path correspondence',
            'original_pairs_with_raw_evidence_differences': original['observation_differences'],
            'pairs': len(cases), 'counts': dict(counts),
            'exclusions': ['elapsed seconds'],
            'interpretation': 'Recorded processes correspond after the enumerated workspace/context/private-path renamings. Private input bytes are directly compared. Section-dump destination bytes were not separately retained; this analysis does not claim their byte equality or historical process attestation.',
            'cases': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    result = analyze(args.data)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'cases'}, indent=2))
    return bool(result['counts']['remaining_differing_fields'])


if __name__ == '__main__':
    raise SystemExit(main())
