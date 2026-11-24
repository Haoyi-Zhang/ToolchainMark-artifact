"""Compare retained paired native observations without executing the targets."""
from __future__ import annotations

from collections import Counter
import gzip
import json
from pathlib import Path


def normalize(value, root, context):
    if isinstance(value, str):
        return value.replace(str(root), '<native>').replace(context, '<context>')
    if isinstance(value, list):
        return [normalize(item, root, context) for item in value]
    if isinstance(value, dict):
        return {key: normalize(item, root, context) for key, item in value.items()
                if key != 'seconds'}
    return value


def byte_pairs(left, right, store, location, records):
    if isinstance(left, dict) and isinstance(right, dict):
        if {'blob', 'sha256', 'bytes'} <= set(left) and {'blob', 'sha256', 'bytes'} <= set(right):
            a = gzip.decompress((store / left['blob']).read_bytes())
            b = gzip.decompress((store / right['blob']).read_bytes())
            records.append({'location': location, 'left': left['blob'], 'right': right['blob'],
                            'left_bytes': len(a), 'right_bytes': len(b), 'equal': a == b})
        else:
            for key in left.keys() & right.keys():
                byte_pairs(left[key], right[key], store, location + '/' + key, records)
    elif isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        for index, (a, b) in enumerate(zip(left, right)):
            byte_pairs(a, b, store, location + '/' + str(index), records)


def compare_case(case, output):
    output = Path(output)
    directory = output / 'cases' / case['id']
    contract = json.loads((directory / 'contract.json').read_text())
    gemtest = json.loads((directory / 'gemtest.json').read_text())
    receipt = contract['receipt']
    left = {row['id']: row for row in receipt['actions']}
    right = {row['id']: row for row in gemtest['actions']}
    differences, pairs = [], []
    if list(left) != list(right):
        differences.append({'kind': 'action order', 'contract': list(left), 'gemtest': list(right)})
    contract_root, gemtest_root = directory / 'contract-native', directory / 'gemtest-native'
    for name in left.keys() & right.keys():
        a, b = left[name], right[name]
        keys = ('operation', 'status', 'value')
        if a['status'] != 'SKIPPED' and b['status'] != 'SKIPPED':
            keys += ('arguments',)
        for key in keys:
            av = normalize(a[key], contract_root, receipt['context_id'])
            bv = normalize(b[key], gemtest_root, gemtest['context_id'])
            if av != bv:
                differences.append({'kind': key, 'action': name, 'contract': av, 'gemtest': bv})
        av = normalize(a['evidence'], contract_root, receipt['context_id'])
        bv = normalize(b['evidence'], gemtest_root, gemtest['context_id'])
        if av != bv:
            differences.append({'kind': 'native evidence', 'action': name,
                                'contract': av, 'gemtest': bv})
        byte_pairs(a['value'], b['value'], output, name, pairs)
    # Select the named primary independently of JSON dictionary ordering.
    primary = 'STATE' if case['relation'] == 'SR01' else case['relation']
    expected_framework = {
        'SATISFIED': 'passed', 'INCONSISTENT': 'failed', 'INADMISSIBLE': 'skipped',
    }[gemtest['judgments'][primary]]
    commands = {}
    for label, actions in [('contract', receipt['actions']), ('gemtest', gemtest['actions'])]:
        commands[label] = sum(item.get('kind') == 'process'
                              for action in actions for item in action['evidence'])
    return {
        'case': case, 'judgment_equal': contract['judgments'] == gemtest['judgments'],
        'contract_judgments': contract['judgments'], 'gemtest_judgments': gemtest['judgments'],
        'framework_outcome': gemtest['framework']['test_result'],
        'framework_outcome_agrees': gemtest['framework']['test_result'] == expected_framework,
        'commands': commands, 'observation_differences': differences,
        'paired_bytes': pairs,
    }


def summarize(output):
    output = Path(output)
    frame = json.loads((output / 'frame.json').read_text())
    comparisons = [compare_case(case, output) for case in frame]
    by_relation = {}
    for relation in dict.fromkeys(case['relation'] for case in frame):
        rows = [row for row in comparisons if row['case']['relation'] == relation]
        by_relation[relation] = {
            'pairs': len(rows),
            'contract_judgments': dict(Counter(value for row in rows
                                               for value in row['contract_judgments'].values())),
            'gemtest_judgments': dict(Counter(value for row in rows
                                              for value in row['gemtest_judgments'].values())),
            'framework_outcomes': dict(Counter(row['framework_outcome'] for row in rows)),
            'judgment_differences': sum(not row['judgment_equal'] for row in rows),
            'observation_differences': sum(bool(row['observation_differences']) for row in rows),
            'commands': {arm: sum(row['commands'][arm] for row in rows)
                         for arm in ('contract', 'gemtest')},
        }
    result = {
        'pairs': len(comparisons), 'native_arms': 2 * len(comparisons),
        'stage_obligations_per_arm': sum(len(row['contract_judgments']) for row in comparisons),
        'judgment_differences': sum(not row['judgment_equal'] for row in comparisons),
        'framework_outcome_disagreements': sum(not row['framework_outcome_agrees'] for row in comparisons),
        'observation_differences': sum(bool(row['observation_differences']) for row in comparisons),
        'paired_byte_comparisons': sum(len(row['paired_bytes']) for row in comparisons),
        'paired_byte_differences': sum(not pair['equal'] for row in comparisons
                                     for pair in row['paired_bytes']),
        'unique_paired_byte_objects': len({(pair['left'], pair['right'])
                                         for row in comparisons for pair in row['paired_bytes']}),
        'by_relation': by_relation,
    }
    (output / 'comparisons.json').write_text(json.dumps(comparisons, indent=2, sort_keys=True) + '\n')
    (output / 'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result
