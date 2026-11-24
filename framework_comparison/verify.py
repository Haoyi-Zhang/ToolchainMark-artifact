#!/usr/bin/env python3
"""Read-only verification of the retained, paired native GeMTest activity.

The GeMTest arm is a sequence of raw adapter observations, not a contract
receipt. Its recorded order, resolved requests, and stage predicates are
checked directly; no missing contract event ordinals are invented. Native
observations in both arms use the same independent material/process binding.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
from xml.etree import ElementTree

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.receiver import verify_receipt
from ctf_comparison.expressions import boolean, evaluate, same
from declarative_study.native_io import verify_evidence, verify_file
from declarative_study.verify import value_bindings
from framework_comparison.analyze_process_paths import analyze, recorded_root


def need(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def identity(path):
    data = Path(path).read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def frame_for(protocol):
    return [{'id': f'pass-{run}/{relation}/{carrier}/{implementation}',
             'pass': run, 'relation': relation, 'carrier': carrier,
             'implementation': implementation, 'family': spec['family']}
            for run in protocol['passes']
            for relation, spec in protocol['relations'].items()
            for carrier in protocol['carriers']
            for implementation in spec['conditions']]


def expected_inputs(case, protocol, recorded_artifact):
    return {'host': str(Path(recorded_artifact) / protocol['host']),
            'carrier': case['carrier'], 'implementation': case['implementation'],
            'payload1': protocol['payloads'][0].encode().hex(),
            'payload2': protocol['payloads'][1].encode().hex(),
            'key1': protocol['keys'][0], 'key2': protocol['keys'][1],
            'compiler': protocol['compiler'], 'optimization': protocol['optimization'],
            'host_inputs': protocol['host_inputs'],
            **({'reuse_permitted': True, 'lockout_excluded': True}
               if case['relation'] == 'SR01' else {})}


def recorded_artifact_root(actions, host):
    suffix = '/' + host
    names = {row['arguments']['host'] for row in actions
             if row['operation'] == 'build' and row['status'] == 'OK'}
    need(len(names) == 1, 'ambiguous original host request')
    name = names.pop()
    need(type(name) is str and name.startswith('/') and name.endswith(suffix),
         'original host path does not have the frozen host role')
    return name[:-len(suffix)]


def baseline_requests(plan, record):
    """Check hand-written raw requests against the fixed plan's prefix.

    SKIPPED callback placeholders have no native evidence. They need not copy
    the interpreter's private reason text or argument-unavailability encoding.
    Available requests must have exactly the resolved argument values.
    """
    actions = record['actions']
    need([x['id'] for x in actions] == [x['id'] for x in plan['actions']],
         'baseline action domain/order differs from frozen plan')
    prefix = {}
    for specification, action in zip(plan['actions'], actions):
        need(action['operation'] == specification['operation'],
             'baseline operation differs from frozen plan')
        need(set(action) == {'id', 'operation', 'arguments', 'status', 'value', 'evidence', 'reason'},
             'baseline raw action schema differs')
        guard = boolean(specification.get('when', {'literal': True}),
                        record['inputs'], prefix, {})
        arguments = {name: evaluate(expr, record['inputs'], prefix, {})
                     for name, expr in specification['arguments'].items()}
        invoked = guard.state == 'TRUE' and all(x.state == 'VALUE' for x in arguments.values())
        if invoked:
            need(action['status'] in {'OK', 'UNAVAILABLE'}, 'an enabled baseline request was not attempted')
            need(same(action['arguments'], {name: x.value for name, x in arguments.items()}),
                 'baseline request differs from frozen prefix arguments')
        else:
            need(action['status'] == 'SKIPPED' and action['value'] is None and action['evidence'] == [],
                 'a disabled baseline request retains an attempted observation')
        need(type(action['evidence']) is list and
             (action['reason'] is None or type(action['reason']) is str), 'baseline evidence/reason type differs')
        if action['status'] == 'UNAVAILABLE':
            need(action['value'] is None, 'unavailable native callback retains a value')
        prefix[action['id']] = action


def judgments(plan, record):
    actions = {row['id']: row for row in record['actions']}
    prior = {}
    for obligation in plan['obligations']:
        gates = [boolean(gate['expr'], record['inputs'], actions, prior)
                 for gate in obligation['requires']]
        if any(gate.state != 'TRUE' for gate in gates):
            result = 'INADMISSIBLE'
        else:
            result = boolean(obligation['predicate'], record['inputs'], actions, prior)
            result = ('SATISFIED' if result.state == 'TRUE' else
                      'INCONSISTENT' if result.state == 'FALSE' else 'INADMISSIBLE')
        prior[obligation['id']] = result
    return prior


def normalize(value, root, context):
    if type(value) is str:
        return value.replace(root, '<native>').replace(context, '<context>')
    if type(value) is list:
        return [normalize(item, root, context) for item in value]
    if type(value) is dict:
        return {name: normalize(item, root, context) for name, item in value.items()
                if name != 'seconds'}
    return value


def byte_pairs(left, right, store, location, output):
    if type(left) is dict and type(right) is dict:
        if {'blob', 'sha256', 'bytes'} <= left.keys() and {'blob', 'sha256', 'bytes'} <= right.keys():
            a, b = verify_file(left, store), verify_file(right, store)
            output.append({'location': location, 'left': left['blob'], 'right': right['blob'],
                           'left_bytes': len(a), 'right_bytes': len(b), 'equal': a == b})
        else:
            for key in sorted(left.keys() & right.keys()):
                byte_pairs(left[key], right[key], store, location + '/' + key, output)
    elif type(left) is list and type(right) is list and len(left) == len(right):
        for index, (a, b) in enumerate(zip(left, right)):
            byte_pairs(a, b, store, location + '/' + str(index), output)


def comparison(case, contract, baseline, store):
    receipt = contract['receipt']
    left = {x['id']: x for x in receipt['actions']}
    right = {x['id']: x for x in baseline['actions']}
    roots = [recorded_root(rows, case['id'], name) for rows, name in
             ((receipt['actions'], 'contract'), (baseline['actions'], 'gemtest'))]
    contexts = [receipt['context_id'], baseline['context_id']]
    differences, pairs = [], []
    need(list(left) == list(right), 'paired action domains differ')
    for name in left:
        a, b = left[name], right[name]
        keys = ['operation', 'status', 'value']
        if a['status'] != 'SKIPPED' and b['status'] != 'SKIPPED':
            keys.append('arguments')
        keys.append('evidence')
        for key in keys:
            av, bv = [normalize(row[key], root, context)
                      for row, root, context in zip((a, b), roots, contexts)]
            if not same(av, bv):
                differences.append({'kind': 'native evidence' if key == 'evidence' else key,
                                    'action': name, 'contract': av, 'gemtest': bv})
        byte_pairs(a['value'], b['value'], store, name, pairs)
    primary = 'STATE' if case['relation'] == 'SR01' else case['relation']
    expected = {'SATISFIED': 'passed', 'INCONSISTENT': 'failed', 'INADMISSIBLE': 'skipped'}[
        baseline['judgments'][primary]]
    return {'case': case, 'judgment_equal': same(contract['judgments'], baseline['judgments']),
            'contract_judgments': contract['judgments'], 'gemtest_judgments': baseline['judgments'],
            'framework_outcome': baseline['framework']['test_result'],
            'framework_outcome_agrees': baseline['framework']['test_result'] == expected,
            'commands': {name: sum(item['kind'] == 'process' for action in rows for item in action['evidence'])
                         for name, rows in [('contract', receipt['actions']), ('gemtest', baseline['actions'])]},
            'observation_differences': differences, 'paired_bytes': pairs}


def canonical_comparison(row):
    row = dict(row)
    row['observation_differences'] = sorted(row['observation_differences'],
                                            key=lambda x: (x.get('action', ''), x['kind']))
    row['paired_bytes'] = sorted(row['paired_bytes'], key=lambda x: x['location'])
    return row


def framework_export(case, baseline):
    exported = baseline['framework']
    need(exported['framework'] == 'GeMTest' and exported['exported_by_official_data_exporter_hook'] is True,
         'framework exporter identity differs')
    need(exported['source_inputs'] == [{'case_id': case['id'], 'phase': 'source'}],
         'framework source input differs from frame')
    need(exported['transformation_name'] == 'generate_followups'
         and exported['relation_name'] == 'evaluate_obligations', 'framework callback names differ')
    need(exported['test_result'] in {'passed', 'failed', 'skipped'}
         and type(exported['relation_result']) is bool, 'framework outcome schema differs')
    need(exported['relation_result'] is (exported['test_result'] == 'passed'),
         'framework Boolean result differs from recorded pytest outcome')
    actions = baseline['actions']
    position = {row['id']: index for index, row in enumerate(actions)}
    source_last = {'MR08': 'recover', 'MR09': 'source-view', 'MR13': 'before', 'SR01': 'initial'}[case['relation']]
    def output_through(last):
        return {'case_id': case['id'], 'relation': case['relation'], 'inputs': baseline['inputs'],
                'actions': [{key: row[key] for key in ('id', 'status', 'value')}
                            for row in actions[:position[last] + 1]]}
    need(same(exported['source_outputs'], [output_through(source_last)]),
         'official source output differs from raw acquisition prefix')
    filtered = baseline['framework_events'] == ['source SUT', 'valid_input']
    if filtered:
        need(exported['test_result'] == 'skipped'
             and exported['followup_inputs'] == exported['followup_outputs'] == ['(not generated)'],
             'filtered source retains contradictory framework followups')
        return
    phases, last = {
        'MR08': (['followup'], ['moved-host']),
        'MR09': (['followup'], ['followup-value']),
        'MR13': (['intervening', 'after'], ['intervening', 'after']),
        'SR01': (['request-0', 'request-1'], ['request-0', 'request-1']),
    }[case['relation']]
    need(baseline['framework_events'] == ['source SUT', 'valid_input', 'general_transformation'] +
         ['followup SUT: ' + phase for phase in phases] + ['general_relation'],
         'framework callback event sequence differs')
    need(exported['followup_inputs'] == [{'case_id': case['id'], 'phase': phase} for phase in phases]
         and same(exported['followup_outputs'], [output_through(name) for name in last]),
         'official followup outputs differ from raw acquisition prefixes')


def verify_pair(case, store, protocol):
    store = Path(store).resolve()
    directory = store / 'cases' / case['id']
    contract, baseline = read(directory / 'contract.json'), read(directory / 'gemtest.json')
    need(same(contract['case'], case) and same(baseline['case'], case), 'record belongs to another case')
    plan = read(store / 'source-snapshot/declarative_study/plans' / (case['relation'] + '.json'))
    need(same(contract['plan'], plan), 'contract uses a different frozen plan')
    receipt = contract['receipt']
    origin = recorded_artifact_root(receipt['actions'], protocol['host'])
    inputs = expected_inputs(case, protocol, origin)
    need(same(baseline['inputs'], inputs), 'baseline inputs differ from frozen frame')
    need(baseline['context_id'] == case['id'] + ':gemtest', 'baseline context differs from frame')
    checked = verify_receipt(plan, receipt, expected_inputs=inputs,
                             expected_context_id=case['id'] + ':contract')
    need(same(contract['judgments'], {row['id']: row['verdict'] for row in receipt['obligations']}),
         'contract arm summary differs from receipt')
    baseline_requests(plan, baseline)
    recomputed = judgments(plan, baseline)
    need(same(recomputed, baseline['judgments']), 'baseline stage labels differ from primitive observations')
    framework_export(case, baseline)
    bindings = {}
    host_identity = identity(store / 'source-snapshot' / protocol['host'])
    for arm, record in [('contract', receipt), ('gemtest', baseline)]:
        files = verify_evidence(record, store)
        counts = value_bindings(record, store)
        # The host request is anchored to frozen source bytes rather than the
        # current unpacking directory. No tool-environment pin is invented.
        for action in record['actions']:
            if action['operation'] != 'build' or action['status'] != 'OK':
                continue
            records = [row for event in action['evidence'] if event['kind'] == 'file-capture'
                       for row in event['files'] if row['path'] == inputs['host']]
            need(records and all({key: row[key] for key in ('bytes', 'sha256')} == host_identity
                                 for row in records), 'build host capture differs from frozen source')
        counts['unique_blobs'] = len(counts.pop('blobs'))
        bindings[arm] = {'file_references': files, **counts}
    return comparison(case, contract, baseline, store), {'contract_plan': checked, 'native': bindings}


def summarized(rows):
    by_relation = {}
    for relation in dict.fromkeys(row['case']['relation'] for row in rows):
        subset = [row for row in rows if row['case']['relation'] == relation]
        by_relation[relation] = {
            'pairs': len(subset),
            'contract_judgments': dict(Counter(v for row in subset for v in row['contract_judgments'].values())),
            'gemtest_judgments': dict(Counter(v for row in subset for v in row['gemtest_judgments'].values())),
            'framework_outcomes': dict(Counter(row['framework_outcome'] for row in subset)),
            'judgment_differences': sum(not row['judgment_equal'] for row in subset),
            'observation_differences': sum(bool(row['observation_differences']) for row in subset),
            'commands': {arm: sum(row['commands'][arm] for row in subset) for arm in ('contract', 'gemtest')},
        }
    return {'pairs': len(rows), 'native_arms': 2 * len(rows),
            'stage_obligations_per_arm': sum(len(row['contract_judgments']) for row in rows),
            'judgment_differences': sum(not row['judgment_equal'] for row in rows),
            'framework_outcome_disagreements': sum(not row['framework_outcome_agrees'] for row in rows),
            'observation_differences': sum(bool(row['observation_differences']) for row in rows),
            'paired_byte_comparisons': sum(len(row['paired_bytes']) for row in rows),
            'paired_byte_differences': sum(not pair['equal'] for row in rows for pair in row['paired_bytes']),
            'unique_paired_byte_objects': len({(pair['left'], pair['right']) for row in rows for pair in row['paired_bytes']}),
            'by_relation': by_relation}


def verify(data):
    store = Path(data).resolve()
    protocol, frame, frozen = (read(store / name) for name in ('protocol.json', 'frame.json', 'producer-freeze.json'))
    need(same(protocol, frozen['protocol']) and same(frame, frozen['frame']), 'frozen activity declarations differ')
    need(frozen['purpose'] == 'formal' and same(frame, frame_for(protocol)), 'activity is not the exact formal frame')
    need(len(frame) == protocol['expected_pairs'], 'declared pair count differs')
    source_count = 0
    for directory, entries in [(store / 'source-snapshot', frozen['inputs']),
                               (store / 'source-snapshot/upstream', frozen['gemtest_sources'])]:
        names = set()
        for item in entries:
            path = (directory / item['path']).resolve()
            need(path.is_relative_to(directory.resolve()) and item['path'] not in names,
                 'frozen source path escapes or repeats')
            names.add(item['path'])
            need(identity(path) == {key: item[key] for key in ('bytes', 'sha256')}, 'frozen source bytes differ')
            source_count += 1
    wanted = {str(Path('cases') / case['id'] / name) for case in frame for name in ('contract.json', 'gemtest.json')}
    actual = {path.relative_to(store).as_posix() for path in (store / 'cases').rglob('*.json')
              if path.name in {'contract.json', 'gemtest.json'}}
    need(actual == wanted, 'retained paired record domain differs from formal frame')
    old_rows = read(store / 'comparisons.json')
    need(len(old_rows) == len(frame) and [row['case'] for row in old_rows] == frame,
         'retained comparison frame differs')
    rows, details, total = [], [], Counter()
    for case, old in zip(frame, old_rows):
        row, detail = verify_pair(case, store, protocol)
        need(same(canonical_comparison(row), canonical_comparison(old)),
             'retained comparison differs from portable recomputation: ' + case['id'])
        rows.append(row)
        details.append({'case': case['id'], **detail})
        for arm, counts in detail['native'].items():
            for name, count in counts.items():
                label = 'blob_case_memberships' if name == 'unique_blobs' else name
                total[arm + ':' + label] += count
    summary, stored_summary = summarized(rows), read(store / 'summary.json')
    need(summary['stage_obligations_per_arm'] == protocol['expected_stage_obligations_per_arm'],
         'declared obligation count differs')
    need(same(summary, {key: value for key, value in stored_summary.items() if key != 'execution'}),
         'stored summary differs from record-level recomputation')
    execution = read(store / 'execution.json')
    need(same(execution, stored_summary['execution']) and execution['producer_changes_during_run'] == [],
         'execution completion/source stability differs')
    xml = ElementTree.parse(store / 'pytest.xml')
    cases = list(xml.iter('testcase'))
    need(len(cases) == len(frame) and not list(xml.iter('error')), 'JUnit case/error domain differs')
    by_name = {}
    for node in cases:
        match = re.fullmatch(r'test_native_watermark\[sut_id=test_native_watermark, mr_id=framework_comparison\.gemtest_cases\.([^,]+), mtc=mtc_([0-9]+)\]', node.attrib['name'])
        need(match is not None, 'JUnit case name cannot be associated with fixed framework data')
        key = (match.group(1), int(match.group(2)))
        need(key not in by_name, 'duplicate JUnit framework case')
        by_name[key] = 'failed' if node.find('failure') is not None else 'skipped' if node.find('skipped') is not None else 'passed'
    indices = Counter()
    for row in rows:
        relation = row['case']['relation']
        indices[relation] += 1
        need(by_name.get((relation, indices[relation])) == row['framework_outcome'],
             'real pytest outcome differs from exporter case')
    expected_exit = 1 if any(row['framework_outcome'] == 'failed' for row in rows) else 0
    need(type(execution['exit_code']) is int and execution['exit_code'] == expected_exit,
         'pytest exit code differs from retained outcomes')
    path_analysis = analyze(store)
    need(same(path_analysis, read(store / 'process-path-analysis.json')),
         'post-acquisition path analysis differs from explicit role recomputation')
    return {'schema': 'paired-native-framework-receiver-v1', 'verdict': 'PASS',
            'summary': summary, 'source_snapshot_files_checked': source_count,
            'paired_records_checked': len(rows) * 2, 'native_binding_counts': dict(total),
            'framework_junit_cases_checked': len(cases),
            'process_path_analysis': {key: value for key, value in path_analysis.items() if key != 'cases'},
            'native_programs_reexecuted': False, 'official_framework_reexecuted': False,
            'scope': [
                'Both arms have native byte/process/result binding. Only contract receipts have interpreter event ordinals.',
                'GeMTest raw requests and stage predicates are checked against frozen plans without fabricating receipt events.',
                'Recorded tool executable identities are preserved and paired; no missing pre-execution native tool manifest is supplied retrospectively.',
                'The 184 originally differing raw pairs remain reported. Explicit path renaming is a separate post-acquisition analysis.',
                'Record consistency does not attest historical execution or unobserved decoder reads.'],
            'cases': details}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=ARTIFACT / 'results/framework-comparison/paired')
    parser.add_argument('--include-cases', action='store_true')
    args = parser.parse_args()
    result = verify(args.data)
    if not args.include_cases:
        result.pop('cases')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
