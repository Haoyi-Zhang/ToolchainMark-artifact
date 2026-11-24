#!/usr/bin/env python3
"""Read-only receiver for complete-prefix state cost records."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import itertools
import json
from pathlib import Path
import sys

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.receiver import verify_receipt
from declarative_study.native_io import verify_evidence
from declarative_study.verify import value_bindings


def need(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def identity(path):
    raw = Path(path).read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def same(a, b):
    return json.dumps(a, sort_keys=True, allow_nan=False) == json.dumps(b, sort_keys=True, allow_nan=False)



def normalize_input_bindings(data):
    """Treat the retained internal dataset label as an alias of the public path."""
    normalized = json.loads(json.dumps(data))
    for item in normalized.get('inputs', []):
        path = item.get('path', '')
        if path.startswith('results/declarative-v6/'):
            item['path'] = 'results/declarative/' + path[len('results/declarative-v6/'):]
    return normalized


def expected_schedule(protocol):
    answer = {'catalog': [], 'bfs': []}
    remaining = protocol['common_call_cap']
    for relation, calls in zip(protocol['catalog_order'], protocol['catalog_extract_costs']):
        if calls > remaining:
            break
        answer['catalog'].append({'name': relation, 'relation': relation, 'planned_extract_calls': calls})
        remaining -= calls
    remaining = protocol['common_call_cap']
    stopped = False
    for length in range(protocol['maximum_considered_suffix_length'] + 1):
        for word in itertools.product(protocol['alphabet'], repeat=length):
            if length + 1 > remaining:
                stopped = True
                break
            name = 'empty' if length == 0 else '_'.join(word).replace('+', 'p').replace('-', 'm')
            answer['bfs'].append({'name': name, 'word': list(word), 'planned_extract_calls': length + 1})
            remaining -= length + 1
        if stopped:
            break
    return answer


def expected_frame(protocol, schedule):
    frame = []
    for run in protocol['passes']:
        for carrier in protocol['carriers']:
            for implementation in protocol['implementations']:
                for arm in protocol['arm_order'][str(run)]:
                    for position, entry in enumerate(schedule[arm]):
                        inputs = {'host': str(Path(protocol['recorded_artifact_root']) / protocol['host']),
                            'carrier': carrier, 'implementation': implementation,
                            'payload1': protocol['payloads'][0].encode().hex(),
                            'payload2': protocol['payloads'][1].encode().hex(),
                            'key1': protocol['keys'][0], 'key2': protocol['keys'][1],
                            'compiler': protocol['compiler'], 'optimization': protocol['optimization'],
                            'host_inputs': protocol['host_inputs']}
                        if arm == 'bfs' or entry.get('relation') == 'SR01':
                            inputs.update(reuse_permitted=protocol['reuse_permitted'],
                                          lockout_excluded=protocol['lockout_excluded'])
                        frame.append({'id': f'pass-{run}/{carrier}/{implementation}/{arm}/{entry["name"]}',
                            'pass': run, 'carrier': carrier, 'implementation': implementation,
                            'arm': arm, 'position': position, **entry,
                            'plan': f'plans/{arm}/{entry["name"]}.json', 'inputs': inputs})
    return frame


def case_cost(case, receipt, acquisition):
    need(same(case, acquisition['case']), 'cost record belongs to another frame case')
    actions = {action['id']: action for action in receipt['actions']}
    trace = acquisition['extraction_call_trace']
    need(type(trace) is list and all(type(row.get('ordinal')) is int for row in trace)
         and [row['ordinal'] for row in trace] == list(range(1, len(trace) + 1)),
         'tested-call ordinals are not complete and monotone')
    need(len({row['step_id'] for row in trace}) == len(trace), 'one action records repeated tested calls')
    called = set()
    for row in trace:
        need(row['step_id'] in actions, 'tested call belongs to an unknown action')
        action = actions[row['step_id']]
        need(action['operation'] == 'extract' and action['status'] != 'SKIPPED',
             'tested call belongs to an unattempted extraction')
        need(row['context_id'] == receipt['context_id'] and row['binary'] == action['arguments']['binary']
             and row['key'] == action['arguments']['key'], 'tested-call request differs from the receipt')
        if action['status'] == 'OK':
            returns = [event for event in action['evidence'] if event['kind'] == 'python-return']
            need(len(returns) == 1 and same(row['observation'], returns[0]['return_value']),
                 'tested call differs from the raw extraction return')
            if row['observation']['kind'] == 'payload':
                need(row['exception'] is None, 'payload cost record also reports an exception')
            else:
                need(type(row['exception']) is dict and row['exception']['type'] == 'ExtractionError',
                     'typed rejection cost record lacks its recorded exception')
        called.add(row['step_id'])
    need({a['id'] for a in receipt['actions'] if a['operation'] == 'extract' and a['status'] == 'OK'} <= called,
         'available extraction is missing from measured cost')
    need([actions[row['step_id']]['start_event'] for row in trace] ==
         sorted(actions[row['step_id']]['start_event'] for row in trace), 'tested-call order differs from action order')
    need(type(acquisition['extract_calls']) is int and acquisition['extract_calls'] == len(trace),
         'stored extraction cost differs from call trace')
    commands = sum(event['kind'] == 'process' for a in receipt['actions'] for event in a['evidence'])
    need(type(acquisition['native_commands']) is int and acquisition['native_commands'] == commands,
         'stored native process count differs from records')
    need(same(acquisition['obligations'], {o['id']: o['verdict'] for o in receipt['obligations']})
         and same(acquisition['action_statuses'], dict(Counter(a['status'] for a in receipt['actions']))),
         'stored acquisition outcomes differ from receipt')
    for field in ('wall_seconds', 'parent_cpu_seconds', 'child_cpu_seconds'):
        need(type(acquisition[field]) in (int, float) and acquisition[field] >= 0,
             'invalid measured duration')
    return {'case': case['id'], 'pass': case['pass'], 'carrier': case['carrier'],
            'implementation': case['implementation'], 'arm': case['arm'], 'position': case['position'],
            'extract_calls': len(trace), 'planned_extract_calls': case['planned_extract_calls'],
            'native_commands': commands,
            'obligations': dict(Counter(o['verdict'] for o in receipt['obligations'])),
            'unavailable_actions': sum(a['status'] == 'UNAVAILABLE' for a in receipt['actions']),
            'exposed': any(o['verdict'] == 'INCONSISTENT' for o in receipt['obligations']),
            **{field: acquisition[field] for field in ('wall_seconds', 'parent_cpu_seconds', 'child_cpu_seconds')}}


def prefix(rows, point):
    selected, spent = [], 0
    for row in rows:
        if spent + row['extract_calls'] > point:
            break
        selected.append(row); spent += row['extract_calls']
    return {'complete_cases': len(selected), 'extract_calls': spent, 'exact_spending': spent == point,
            'native_commands': sum(row['native_commands'] for row in selected),
            'exposed': any(row['exposed'] for row in selected),
            'unavailable_actions': sum(row['unavailable_actions'] for row in selected),
            'obligations': dict(sum((Counter(row['obligations']) for row in selected), Counter())),
            **{field: sum(row[field] for row in selected)
               for field in ('wall_seconds', 'parent_cpu_seconds', 'child_cpu_seconds')}}


def recompute_summary(output):
    output = Path(output).resolve()
    protocol, frame = read(output / 'protocol.json'), read(output / 'frame.json')
    rows, groups = [], defaultdict(list)
    for case in frame:
        directory = output / 'cases' / case['id']
        row = case_cost(case, read(directory / 'receipt.json'), read(directory / 'acquisition.json'))
        rows.append(row); groups[(case['pass'], case['carrier'], case['implementation'], case['arm'])].append(row)
    by_arm = {}
    for arm in ('catalog', 'bfs'):
        part = [row for row in rows if row['arm'] == arm]
        by_arm[arm] = {'cases': len(part), 'extract_calls': sum(row['extract_calls'] for row in part),
            'native_commands': sum(row['native_commands'] for row in part),
            'obligations': dict(sum((Counter(row['obligations']) for row in part), Counter())),
            'unavailable_actions': sum(row['unavailable_actions'] for row in part),
            **{field: sum(row[field] for row in part) for field in ('wall_seconds', 'parent_cpu_seconds', 'child_cpu_seconds')}}
    matched, cap = [], []
    for point in protocol['strict_equal_spent_points']:
        configurations = []
        for run in protocol['passes']:
            for carrier in protocol['carriers']:
                for implementation in protocol['implementations']:
                    arms = {arm: prefix(groups[(run, carrier, implementation, arm)], point) for arm in ('catalog', 'bfs')}
                    configurations.append({'pass': run, 'carrier': carrier, 'implementation': implementation,
                                           'arms': arms, 'both_exact_spending': all(a['exact_spending'] for a in arms.values())})
        matched.append({'extract_call_point': point, 'configuration_pairs': len(configurations),
            'exactly_matched_configuration_pairs': sum(c['both_exact_spending'] for c in configurations),
            'exposed_implementations': {arm: sorted({c['implementation'] for c in configurations
                         if c['both_exact_spending'] and c['arms'][arm]['exposed']}) for arm in ('catalog', 'bfs')},
            'exposed_configurations': {arm: sum(c['both_exact_spending'] and c['arms'][arm]['exposed']
                                              for c in configurations) for arm in ('catalog', 'bfs')},
            'configurations': configurations})
    for (run, carrier, implementation, arm), part in groups.items():
        total = prefix(part, protocol['common_call_cap'])
        need(total['complete_cases'] == len(part), 'actual measured calls exceed the predeclared cap')
        cap.append({'pass': run, 'carrier': carrier, 'implementation': implementation, 'arm': arm,
                    'unused_call_cap': protocol['common_call_cap'] - total['extract_calls'], **total})
    return {'study': protocol['study'], 'scope': protocol['scope'], 'fresh_cases': len(rows),
            'actual_tested_extract_calls': sum(row['extract_calls'] for row in rows),
            'configuration_pairs': len(groups) // 2, 'by_arm': by_arm,
            'unavailable_actions': sum(row['unavailable_actions'] for row in rows),
            'measured_cost_differs_from_plan_cases': [row['case'] for row in rows
                                                    if row['extract_calls'] != row['planned_extract_calls']],
            'strict_equal_spending': matched,
            'common_cap': {'call_cap': protocol['common_call_cap'], 'equal_spending_claim': False,
                          'actual_calls_per_configuration': {arm: sorted({row['extract_calls'] for row in cap if row['arm'] == arm})
                                                             for arm in ('catalog', 'bfs')},
                          'unused_calls_per_configuration': {arm: sorted({row['unused_call_cap'] for row in cap if row['arm'] == arm})
                                                             for arm in ('catalog', 'bfs')},
                          'exposed_implementations': {arm: sorted({row['implementation'] for row in cap
                                                                if row['arm'] == arm and row['exposed']})
                                                     for arm in ('catalog', 'bfs')},
                          'configurations': cap},
            'cost_unit': protocol['cost_unit'],
            'retained_curve_is_fresh_execution': False}


def verify(output):
    output = Path(output).resolve()
    frozen = read(output / 'source-freeze.json')
    need(frozen['native_cases_executed'] == 0, 'source freeze was not recorded before execution')
    for item in frozen['sources']:
        path = (output / 'source-snapshot' / item['path']).resolve()
        need(path.is_relative_to(output / 'source-snapshot') and
             identity(path) == {key: item[key] for key in ('bytes', 'sha256')}, 'frozen source differs')
    for item in frozen['declarations']:
        path = (output / item['path']).resolve()
        need(path.is_relative_to(output) and identity(path) == {key: item[key] for key in ('bytes', 'sha256')},
             'frozen plan/frame/recount differs')
    protocol, frame, schedule = (read(output / name) for name in ('protocol.json', 'frame.json', 'schedule.json'))
    need(same(schedule, expected_schedule(protocol)), 'cost schedule differs from nonadaptive declared order')
    need(same(frame, expected_frame(protocol, schedule)), 'complete fresh case frame differs')
    need(len(frame) == protocol['expected_fresh_cases'], 'case denominator differs')
    wanted = {str(Path('cases') / case['id'] / name) for case in frame for name in ('receipt.json', 'acquisition.json')}
    actual = {path.relative_to(output).as_posix() for path in (output / 'cases').rglob('*.json')
              if path.name in {'receipt.json', 'acquisition.json'}}
    need(actual == wanted, 'native receipt/acquisition set differs')
    environment = read(output / 'environment.json')
    need(environment['workers'] == protocol['workers'] == 1, 'CPU accounting assumes sequential cases')
    counts = Counter(); all_blobs = set()
    host_source = identity(output / 'source-snapshot' / protocol['host'])
    for case in frame:
        receipt = read(output / 'cases' / case['id'] / 'receipt.json')
        plan = read(output / case['plan'])
        verify_receipt(plan, receipt, expected_inputs=case['inputs'], expected_context_id=case['id'] + ':cost-study')
        counts['file_references'] += verify_evidence(receipt, output)
        bindings = value_bindings(receipt, output, native_tools=environment['tools'])
        all_blobs.update(bindings.pop('blobs'))
        counts.update(bindings)
        for action in receipt['actions']:
            if action['operation'] == 'build' and action['status'] == 'OK':
                matches = [row for event in action['evidence'] if event['kind'] == 'file-capture'
                           for row in event['files'] if row['path'] == case['inputs']['host']]
                need(matches and all({key: row[key] for key in ('bytes', 'sha256')} == host_source for row in matches),
                     'original host capture differs from frozen host')
    retained = read(output / 'retained-input-bindings.json')['inputs']
    for item in retained:
        path = (ARTIFACT / item['path']).resolve()
        need(path.is_relative_to(ARTIFACT) and identity(path) == {key: item[key] for key in ('bytes', 'sha256')},
             'retained derivation input differs')
    # Recounting is read-only and separate from the new native denominator.
    from state_budget.derive_retained import derive
    derived, input_bindings = derive(ARTIFACT)
    need(same(derived, read(output / 'retained-depth-costs.json'))
         and same(normalize_input_bindings(input_bindings),
                  normalize_input_bindings(read(output / 'retained-input-bindings.json'))),
         'retained cost recount differs')
    summary, stored = recompute_summary(output), read(output / 'summary.json')
    timing = {'elapsed_seconds', 'parent_cpu_seconds', 'child_cpu_seconds', 'producer_sources_unchanged'}
    need(same(summary, {key: value for key, value in stored.items() if key not in timing}),
         'summary differs from measured call traces and obligations')
    need(stored['producer_sources_unchanged'] is True, 'producer source-stability record differs')
    completion, start = read(output / 'completion.json'), read(output / 'start.json')
    need(completion['status'] == 'COMPLETE' and completion['cases'] == len(frame)
         and completion['summary'] == identity(output / 'summary.json')
         and completion['source_freeze'] == start['source_freeze'] == identity(output / 'source-freeze.json'),
         'completion bindings differ')
    return {'schema': 'state-cost-receiver-v1', 'verdict': 'PASS', 'fresh_cases_checked': len(frame),
            'actual_tested_extract_calls': summary['actual_tested_extract_calls'],
            'native_bindings': {**counts, 'unique_blobs': len(all_blobs)},
            'source_snapshot_files_checked': len(frozen['sources']),
            'retained_derivation_inputs_checked': len(retained), 'native_programs_reexecuted': False,
            'strict_equal_spending': [{key: value for key, value in row.items() if key != 'configurations'}
                                      for row in summary['strict_equal_spending']],
            'common_cap': {key: value for key, value in summary['common_cap'].items() if key != 'configurations'},
            'unavailable_actions': summary['unavailable_actions']}


def expected_container_paths(project_root=None):
    artifact = ARTIFACT if project_root is None else Path(project_root).resolve() / 'artifact'
    output = artifact / 'results/state-budget/completed'
    paths = set()
    frame = read(output / 'frame.json')
    for case in frame:
        receipt = read(output / 'cases' / case['id'] / 'receipt.json')
        for action in receipt['actions']:
            for event in action['evidence']:
                for field in ('files', 'files_before', 'files_after'):
                    for row in event.get(field, []):
                        relative = Path(row['blob'])
                        need(len(relative.parts) == 2 and relative.parts[0] == 'blobs'
                             and relative.name == row['sha256'] + '.bin.gz', 'unexpected state-cost blob path')
                        paths.add((Path('artifact/results/state-budget/completed') / relative).as_posix())
    return sorted(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=ARTIFACT / 'results/state-budget/completed')
    args = parser.parse_args()
    print(json.dumps(verify(args.data), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
