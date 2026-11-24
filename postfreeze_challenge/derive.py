"""Recompute challenge summaries from all registered rows, including misses."""
from __future__ import annotations

import ast
from collections import Counter
import csv
import json
from pathlib import Path

from toolchainmark.study_validation import FIELDS, validate_rows
from .common import HERE, PRODUCERS, load_plan, require

NON_TIMING = tuple(field for field in FIELDS if field != 'duration_seconds')
KEY = ('host', 'carrier', 'defect_id', 'relation_id')


def read_rows(path):
    with path.open(newline='', encoding='utf-8') as stream:
        reader = csv.DictReader(stream)
        require(tuple(reader.fieldnames or ()) == FIELDS, 'matrix schema differs')
        rows = list(reader)
    require(all(None not in row and None not in row.values() for row in rows), 'malformed CSV row')
    return rows


def expected_keys(plan, full):
    relations = plan['relations'] if full else ['MR01']
    return {(host, carrier, variant, relation) for host in plan['hosts']
            for carrier in plan['carriers'] for variant in plan['cohorts'] for relation in relations}


def compare(left, right, fields=NON_TIMING):
    a = {tuple(row[key] for key in KEY): row for row in left}
    b = {tuple(row[key] for key in KEY): row for row in right}
    require(len(a) == len(left) and len(b) == len(right) and a.keys() == b.keys(), 'comparison key domain differs')
    examples = []
    differences = 0
    for key in sorted(a):
        for field in fields:
            if a[key][field] != b[key][field]:
                differences += 1
                if len(examples) < 20:
                    examples.append({'key': list(key), 'field': field,
                                     'left': a[key][field], 'right': b[key][field]})
    return {'rows': len(a), 'fields': list(fields), 'field_comparisons': len(a) * len(fields),
            'differences': differences, 'examples': examples}


def accounting(rows, plan):
    variants = {}
    for variant in plan['cohorts']:
        selected = [row for row in rows if row['defect_id'] == variant]
        grouped = {}
        for row in selected:
            grouped.setdefault((row['host'], row['carrier']), []).append(row)
        exposed = [list(key) for key, values in sorted(grouped.items())
                   if any(row['verdict'] == 'INCONSISTENT' for row in values)]
        admitted = [list(key) for key, values in sorted(grouped.items())
                    if any(row['verdict'] != 'INADMISSIBLE' for row in values)]
        variants[variant] = {
            'rows': len(selected), 'units': len(grouped), 'exposed_units': len(exposed),
            'units_with_admitted_case': len(admitted),
            'unexposed_units': [list(key) for key in sorted(grouped) if list(key) not in exposed],
            'all_inadmissible_units': [list(key) for key in sorted(grouped) if list(key) not in admitted],
            'verdicts': dict(sorted(Counter(row['verdict'] for row in selected).items())),
            'inconsistent_relations': dict(sorted(Counter(row['relation_id'] for row in selected
                                                         if row['verdict'] == 'INCONSISTENT').items())),
            'inadmissible_reasons': dict(sorted(Counter(row['reason'] for row in selected
                                                       if row['verdict'] == 'INADMISSIBLE').items())),
            'admitted_satisfied_reasons': dict(sorted(Counter(row['reason'] for row in selected
                                                             if row['verdict'] == 'SATISFIED').items())),
        }
    return {'rows': len(rows), 'verdicts': dict(sorted(Counter(row['verdict'] for row in rows).items())),
            'clean_control_gate': all(row['verdict'] == 'SATISFIED' for row in rows if row['defect_id'] == 'CLEAN'),
            'seeded_units': sum(variants[v]['units'] for v in plan['cohorts'] if v != 'CLEAN'),
            'exposed_seeded_units': sum(variants[v]['exposed_units'] for v in plan['cohorts'] if v != 'CLEAN'),
            'variants': variants}


def source_size(folder=HERE):
    result = []
    for name in PRODUCERS:
        path = folder / name
        raw = path.read_bytes()
        source = raw.decode('utf-8')
        tree = ast.parse(source, filename=name)
        result.append({'path': 'postfreeze_challenge/' + name, 'bytes': len(raw),
                       'nonblank_lines_including_comments_and_docstrings': sum(bool(line.strip()) for line in source.splitlines()),
                       'function_definitions': sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                                                   for node in ast.walk(tree))})
    return result


def derive(data):
    plan, _ = load_plan(data)
    activities = json.loads((data / 'activities.json').read_text())
    rows = {}
    result = {}
    for name in plan['activity_order']:
        selected = read_rows(data / (name + '.csv'))
        keys = [tuple(row[key] for key in KEY) for row in selected]
        require(len(keys) == len(set(keys)) and set(keys) == expected_keys(plan, name.startswith('full')),
                'planned activity domain differs: ' + name)
        validate_rows(selected, plan['classifier_protocol'])
        rows[name] = selected
        result[name] = accounting(selected, plan)
        result[name]['measured_activity'] = activities[name]
    comparisons = {
        'full_rerun': compare(rows['full-first'], rows['full-second']),
        'roundtrip_rerun': compare(rows['roundtrip-first'], rows['roundtrip-second']),
        'first_roundtrip_vs_full_MR01': compare(rows['roundtrip-first'], [r for r in rows['full-first'] if r['relation_id'] == 'MR01']),
        'second_roundtrip_vs_full_MR01': compare(rows['roundtrip-second'], [r for r in rows['full-second'] if r['relation_id'] == 'MR01']),
    }
    with (data / 'distinctions.csv').open(newline='', encoding='utf-8') as stream:
        distinctions = list(csv.DictReader(stream))
    require(len(distinctions) == plan['distinction_cases'], 'distinction trace domain incomplete')
    return {
        'protocol': plan['protocol'], 'classifier_protocol': plan['classifier_protocol'],
        'activities': result, 'comparisons': comparisons,
        'distinctions': {'cases': len(distinctions), 'matched': sum(row['matched'] == 'True' for row in distinctions)},
        'source_size': json.loads((data / 'source-size.json').read_text()),
        'scoring_scope': 'Four new trigger behaviors in known contract families; 216 host/carrier/behavior units per pass. '
                         'Hand-selected by designers familiar with the catalog, not field samples or four new semantic classes.',
        'timing_scope': 'Separate fresh MR01-only and full-catalog activities, four workers, counterbalanced order. '
                        'Measured on a shared host with recording and retention. No human-hours or production-cost inference.',
        'rerun_scope': 'Comparison of the eleven original stored non-timing fields, not identity of raw concurrent schedules.',
        'clean_control_gate': all(value['clean_control_gate'] for value in result.values()),
        'observed_rerun_differences': sum(value['differences'] for value in comparisons.values()),
    }
