"""Recount retained state records; this module never executes native programs."""
from __future__ import annotations
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path


def derive(artifact):
    artifact = Path(artifact).resolve()
    bound, results = [], {}
    def read(path):
        data = path.read_bytes()
        bound.append({'path': path.relative_to(artifact).as_posix(), 'bytes': len(data),
                      'sha256': hashlib.sha256(data).hexdigest()})
        return json.loads(data)
    for study in ('state', 'state-baseline'):
        root = artifact / 'results/declarative' / study
        frame = read(root / 'frame.json')
        rows, groups = [], defaultdict(list)
        for case in frame:
            receipt = read(root / 'cases' / case['id'] / 'receipt.json')
            actions = [action for action in receipt['actions'] if action['operation'] == 'extract']
            calls = sum(event['kind'] == 'python-return' for action in actions for event in action['evidence'])
            attempted = sum(action['status'] != 'SKIPPED' for action in actions)
            if calls != attempted or any(action['status'] != 'OK' for action in actions):
                raise ValueError('Retained extraction accounting requires case-specific failure analysis.')
            row = {'case': case['id'], 'pass': case['run'], 'carrier': case['carrier'],
                   'implementation': case['implementation'], 'word': case.get('word'),
                   'relation': case.get('relation'), 'extract_calls': calls,
                   'native_commands': sum(event['kind'] == 'process'
                                          for action in receipt['actions'] for event in action['evidence']),
                   'obligations': dict(Counter(o['verdict'] for o in receipt['obligations'])),
                   'exposed': any(o['verdict'] == 'INCONSISTENT' for o in receipt['obligations'])}
            rows.append(row)
            groups[(case['run'], case['carrier'], case['implementation'])].append(row)
        depths = []
        if study == 'state':
            for depth in range(5):
                chosen = [row for row in rows if len(row['word']) <= depth]
                configurations = []
                for (run, carrier, implementation), part in groups.items():
                    selected = [row for row in part if len(row['word']) <= depth]
                    configurations.append({'pass': run, 'carrier': carrier, 'implementation': implementation,
                        'cases': len(selected), 'extract_calls': sum(r['extract_calls'] for r in selected),
                        'native_commands': sum(r['native_commands'] for r in selected),
                        'exposed': any(r['exposed'] for r in selected)})
                depths.append({'suffix_depth': depth, 'cases': len(chosen),
                    'extract_calls': sum(r['extract_calls'] for r in chosen),
                    'calls_per_configuration': sorted({c['extract_calls'] for c in configurations}),
                    'words_per_configuration': sorted({c['cases'] for c in configurations}),
                    'native_commands': sum(r['native_commands'] for r in chosen),
                    'exposed_implementations': sorted({c['implementation'] for c in configurations if c['exposed']}),
                    'configurations': configurations})
        results[study] = {'cases': len(rows), 'extract_calls': sum(r['extract_calls'] for r in rows),
                         'native_commands': sum(r['native_commands'] for r in rows),
                         'calls_per_configuration': sorted({sum(r['extract_calls'] for r in part)
                                                            for part in groups.values()}),
                         'depths': depths, 'rows': rows}
    return {'purpose': 'Post-acquisition recount of retained native records; no fresh executions.',
            'cost_observation': 'Recorded Python returns; all selected extract actions are OK and have one return.',
            'results': results}, {'inputs': bound}
