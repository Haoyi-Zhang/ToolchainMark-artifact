"""Recompute every separately planned SR01 denominator from retained rows."""
import ast
from collections import Counter
import csv
import json

from postfreeze_challenge.common import require
from .common import HERE, PRODUCERS, load_plan
from .model import assess

FIELDS = ('host', 'host_sha256', 'carrier', 'cohort', 'variant', 'relation_id', 'verdict',
          'reason', 'contract_json', 'request_json', 'admission_json', 'evidence_json', 'duration_seconds')
NON_TIMING = FIELDS[:-1]


def read_rows(path):
    with path.open(newline='', encoding='utf-8') as stream:
        reader = csv.DictReader(stream)
        require(tuple(reader.fieldnames or ()) == FIELDS, 'SR01 row schema differs')
        rows = list(reader)
    require(all(None not in row and None not in row.values() for row in rows), 'malformed SR01 CSV')
    return rows


def source_size(folder=HERE):
    sizes = []
    for name in PRODUCERS:
        raw = (folder / name).read_bytes()
        text = raw.decode('utf-8')
        sizes.append({'path': 'recovery_extension/' + name, 'bytes': len(raw),
                      'nonblank_lines_including_comments_and_docstrings': sum(bool(line.strip()) for line in text.splitlines()),
                      'function_definitions': sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                                                  for node in ast.walk(ast.parse(text)))})
    return sizes


def derive(data):
    plan, _ = load_plan(data)
    activities = json.loads((data / 'activities.json').read_text())
    expected = {(host, carrier, cohort['id']) for host in plan['hosts']
                for carrier in plan['carriers'] for cohort in plan['cohorts']}
    all_rows = {}
    reports = {}
    for name in plan['passes']:
        rows = read_rows(data / (name + '.csv'))
        keys = [(row['host'], row['carrier'], row['cohort']) for row in rows]
        require(len(rows) == len(set(keys)) == plan['cases_per_pass'] and set(keys) == expected,
                'SR01 planned case domain differs')
        for row in rows:
            result = assess(json.loads(row['evidence_json']), json.loads(row['contract_json']),
                            json.loads(row['request_json']))
            require(result == {'verdict': row['verdict'], 'reason': row['reason'],
                               'admission': json.loads(row['admission_json'])}, 'SR01 classification differs')
        cohorts = {}
        for cohort in plan['cohorts']:
            selected = [row for row in rows if row['cohort'] == cohort['id']]
            cohorts[cohort['id']] = {'cases': len(selected), 'verdicts': dict(sorted(Counter(row['verdict'] for row in selected).items())),
                                     'reasons': dict(sorted(Counter(row['reason'] for row in selected).items()))}
        reports[name] = {'cases': len(rows), 'verdicts': dict(sorted(Counter(row['verdict'] for row in rows).items())),
                         'cohorts': cohorts, 'measured_activity': activities[name]}
        all_rows[name] = dict(zip(keys, rows))
    a, b = [all_rows[name] for name in plan['passes']]
    differences = [{'key': list(key), 'field': field, 'first': a[key][field], 'second': b[key][field]}
                   for key in sorted(a) for field in NON_TIMING if a[key][field] != b[key][field]]
    return {'protocol': plan['protocol'], 'relation': 'SR01', 'planned_cases': plan['cases_per_pass'] * len(plan['passes']),
            'activities': reports, 'rerun': {'rows': len(a), 'fields': list(NON_TIMING),
                'field_comparisons': len(a) * len(NON_TIMING), 'differences': len(differences), 'examples': differences[:20]},
            'source_size': json.loads((data / 'source-size.json').read_text()),
            'scope': 'Adaptive extension after the frozen fourteen-relation campaign missed N02. '
                     'The three inapplicable cohorts test admission boundaries, not additional defect detection. '
                     'No pooling with the original catalog or postfreeze challenge scores.',
            'snapshot_scope': plan['snapshot_scope'], 'measurement_scope': plan['measurement']}
