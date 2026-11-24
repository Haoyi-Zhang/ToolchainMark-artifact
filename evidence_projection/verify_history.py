#!/usr/bin/env python3
"""Read-only reception of the separate paired native history counterexample."""
from __future__ import annotations
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import itertools
import json
from pathlib import Path
import sys

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.receiver import InvalidRecord, verify_receipt
from declarative_study.native_io import verify_evidence, verify_file
from declarative_study.verify import value_bindings
from evidence_projection.receiver import required_projection, verify_structure


def need(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def identity(path):
    data = Path(path).read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def same(a, b):
    return json.dumps(a, sort_keys=True, allow_nan=False) == json.dumps(b, sort_keys=True, allow_nan=False)


def action_references(expression):
    if type(expression) is list:
        return set().union(*(action_references(x) for x in expression)) if expression else set()
    if type(expression) is not dict or 'literal' in expression:
        return set()
    names = {expression[tag] for tag in ('ref', 'available') if tag in expression}
    if 'op' in expression:
        names.update(action_references(expression['args']))
    return names


def reference_closure(plan):
    obligation = plan['obligations'][0]
    needed = action_references([obligation['predicate']] + [x['expr'] for x in obligation['requires']])
    actions = {row['id']: row for row in plan['actions']}
    pending = list(needed)
    while pending:
        action = actions[pending.pop()]
        dependencies = action_references(list(action['arguments'].values()) + [action.get('when', {'literal': True})])
        for name in dependencies - needed:
            needed.add(name); pending.append(name)
    return [action['id'] for action in plan['actions'] if action['id'] in needed]


def verify(data):
    data = Path(data).resolve()
    frame, protocol, plans, frozen = [read(data / name) for name in
                                     ('frame.json', 'protocol.json', 'plans.json', 'source-freeze.json')]
    expected_frame = [{'id': f'pass-{repeat}/{carrier}/{implementation}', 'pass': repeat,
                       'carrier': carrier, 'implementation': implementation}
                      for repeat, carrier, implementation in itertools.product(
                          (1, 2), ('string', 'symbol', 'section'), ('CLEAN', 'M23'))]
    need(same(frame, expected_frame) and protocol['pairs'] == len(frame)
         and protocol['native_executions'] == 2 * len(frame), 'paired history frame differs')
    need(frozen['frozen_before_execution'] is True, 'history source-freeze state differs')
    seen_sources = set()
    for row in frozen['files']:
        path = (data / 'source-snapshot' / row['path']).resolve()
        need(path.is_relative_to(data / 'source-snapshot') and row['path'] not in seen_sources
             and identity(path) == {key: row[key] for key in ('bytes', 'sha256')}, 'history source identity differs')
        seen_sources.add(row['path'])
    source = read(data / 'source-snapshot/declarative_study/plans/MR13.json')
    with_b, without_b = plans['with-B'], plans['without-B']
    expected = deepcopy(source); expected['id'] = 'HISTORY-REVISIT'
    original = source['obligations'][0]
    expected['obligations'] = [{**original, 'id': 'REVISIT', 'stage': 'decoder-revisit',
        'clause': 'A recovery after the declared history',
        'requires': [gate for gate in original['requires'] if gate['name'] != 'available:intervening'],
        'predicate': {'op': 'and', 'args': [original['predicate']['args'][0], original['predicate']['args'][2]]}}]
    need(same(with_b, expected), 'REVISIT differs from its declared two-A-observation obligation')
    direct = deepcopy(with_b); direct['id'] = 'DIRECT-REVISIT'
    direct['actions'] = [row for row in direct['actions'] if row['id'] != 'intervening']
    need(same(without_b, direct), 'paired plans differ by more than the declared B extraction')
    refs = reference_closure(with_b)
    need('intervening' not in refs, 'the supposedly unreferenced history action is referenced')
    wanted = {str(Path('cases') / case['id'] / arm / name) for case in frame
              for arm in ('with-B', 'without-B') for name in ('receipt.json', 'plan.json', 'verification.json')}
    actual = {path.relative_to(data).as_posix() for path in (data / 'cases').rglob('*.json')
              if path.name in {'receipt.json', 'plan.json', 'verification.json'}}
    need(actual == wanted, 'history receipt/plan domain differs')
    context = frozen['native_context']
    need(set(context) == {'profile', 'tools', 'llvm'} and context['profile'] == 'declarative'
         and context['llvm'] is None, 'history native context differs')
    pairs, controls, counts, blobs = [], [], Counter(), set()
    host_identity = identity(data / 'source-snapshot/hosts/H01-gcd.c')
    for case in frame:
        receipts, actions = {}, {}
        for arm in ('with-B', 'without-B'):
            directory = data / 'cases' / case['id'] / arm
            receipt = read(directory / 'receipt.json')
            need(same(read(directory / 'plan.json'), plans[arm]), 'case uses another history plan')
            hosts = {row['arguments']['host'] for row in receipt['actions'] if row['operation'] == 'build'}
            need(len(hosts) == 1, 'history host request is ambiguous')
            host = hosts.pop()
            need(type(host) is str and host.endswith('/hosts/H01-gcd.c'), 'history host role differs')
            inputs = {'host': host, 'carrier': case['carrier'], 'implementation': case['implementation'],
                'payload1': b'Morph-01'.hex(), 'payload2': b'Second-2'.hex(), 'key1': 'key-alpha',
                'key2': 'key-beta', 'compiler': 'gcc', 'optimization': 'O2',
                'host_inputs': [0, 1, 5, 13, 144, 99991]}
            verify_receipt(plans[arm], receipt, expected_inputs=inputs, expected_context_id=case['id'] + ':' + arm)
            counts['captured_file_references'] += verify_evidence(receipt, data)
            native = value_bindings(receipt, data, native_tools=context['tools'])
            blobs.update(native.pop('blobs')); counts.update(native)
            need(same(read(directory / 'verification.json'), {'status': 'PASS', **native}),
                 'saved history native check differs')
            for action in receipt['actions']:
                if action['operation'] == 'build' and action['status'] == 'OK':
                    matches = [row for event in action['evidence'] if event['kind'] == 'file-capture'
                               for row in event['files'] if row['path'] == host]
                    need(matches and all({key: row[key] for key in ('bytes', 'sha256')} == host_identity
                                         for row in matches), 'history host capture differs from frozen source')
            required = required_projection(plans[arm], 'REVISIT')
            bundle = {'schema': 'toolchainmark-obligation-evidence', 'target': 'REVISIT',
                      'source_plan': deepcopy(plans[arm]), 'projection': required,
                      'receipt': deepcopy(receipt), 'native_context': deepcopy(context)}
            selected = dict(expected_plan=plans[arm], expected_inputs=inputs,
                            expected_context_id=receipt['context_id'], expected_native_context=context,
                            expected_target='REVISIT')
            verify_structure(bundle, **selected)
            if arm == 'with-B':
                bundle['receipt']['actions'] = [row for row in bundle['receipt']['actions'] if row['id'] != 'intervening']
                try:
                    verify_structure(bundle, **selected)
                except InvalidRecord as error:
                    controls.append({'case': case['id'], 'deleted_action': 'intervening',
                                     'rejected': True, 'reason': str(error)})
                else:
                    raise ValueError('a deleted declared history action was accepted')
            receipts[arm] = receipt; actions[arm] = {row['id']: row for row in receipt['actions']}
            counts['native_traces_checked'] += 1
        need([x for x in actions['with-B'] if x != 'intervening'] == list(actions['without-B']),
             'paired raw action domain differs by more than B extraction')
        artifact_pairs = []
        for name in ('first', 'second'):
            left, right = [actions[arm][name]['value']['artifact'] for arm in ('with-B', 'without-B')]
            artifact_pairs.append({'artifact': name, 'equal': verify_file(left, data) == verify_file(right, data),
                                   'bytes': left['bytes']})
            counts['direct_artifact_byte_pairs'] += 1
        pairs.append({'case': case, 'artifact_pairs': artifact_pairs,
            'judgments': {arm: receipt['obligations'][0]['verdict'] for arm, receipt in receipts.items()},
            'before': {arm: actions[arm]['before']['value']['observation'] for arm in receipts},
            'after': {arm: actions[arm]['after']['value']['observation'] for arm in receipts},
            'reference_action_ids': refs, 'prefix_action_ids': required_projection(with_b, 'REVISIT')['action_ids']})
    need(same(pairs, read(data / 'pairs.json')), 'stored pair comparisons differ from retained byte/receipt observations')
    need(same(controls, read(data / 'deletion-controls.json')), 'stored deletion controls differ from actual receiver rejection')
    summary = {'pairs': len(pairs), 'native_executions': 2 * len(pairs),
        'artifact_byte_pairs': sum(len(pair['artifact_pairs']) for pair in pairs),
        'unequal_artifact_byte_pairs': sum(not row['equal'] for pair in pairs for row in pair['artifact_pairs']),
        'by_implementation': {name: {'pairs': sum(p['case']['implementation'] == name for p in pairs),
            'with_B': dict(Counter(p['judgments']['with-B'] for p in pairs if p['case']['implementation'] == name)),
            'without_B': dict(Counter(p['judgments']['without-B'] for p in pairs if p['case']['implementation'] == name))}
            for name in ('CLEAN', 'M23')}, 'missing_history_controls': len(controls),
        'rejected_missing_history_controls': sum(control['rejected'] for control in controls), 'source_unchanged': True}
    stored = read(data / 'summary.json')
    need(same(summary, {key: value for key, value in stored.items() if key != 'elapsed_seconds'}),
         'history aggregate differs from individual records')
    completion = read(data / 'complete.json')
    need(completion['status'] == 'COMPLETE' and completion['summary'] == identity(data / 'summary.json')
         and completion['pairs'] == identity(data / 'pairs.json'), 'history completion identity differs')
    return {'schema': 'native-history-receiver-v1', 'verdict': 'PASS', **summary,
            'source_snapshot_files_checked': len(seen_sources), 'checks': dict(counts),
            'unique_retained_blobs': len(blobs), 'native_programs_reexecuted': False,
            'scope': 'Separate12-pair controlled history activity: fixed plans, both raw native traces, direct paired bytes and actual missing-prefix rejections. The original MR13 activity is unchanged.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=ARTIFACT / 'results/evidence-projection/history-control')
    args = parser.parse_args()
    print(json.dumps(verify(args.data), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
