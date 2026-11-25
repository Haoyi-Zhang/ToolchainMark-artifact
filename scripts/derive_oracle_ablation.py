"""Separate admission-gate effects from typed-rejection effects.

Fresh derivation over the retained 18,900-row admission matrix; no native
program runs.  The four negative relations (MR03, MR04, MR09, MR10) require a
specific typed rejection.  The ablation re-judges every admitted row of those
relations with an untyped oracle that accepts any rejection, keeps every other
row unchanged, and recounts row verdicts and exposed fault units
(subject x carrier x operator).  Admission is held fixed, so the comparison
isolates the typed predicate; the gate's own contribution is the set of
inadmissible rows, which by construction cannot be exposures.

    python -B scripts/derive_oracle_ablation.py [--matrix results/admission-study/matrix.csv.gz]
        [--out results/oracle-ablation/summary.json] [--check]
"""
from __future__ import annotations

import argparse
import collections
import csv
import gzip
import io
import json
from pathlib import Path

ARTIFACT = Path(__file__).resolve().parents[1]
REQUIRED = {  # relation -> (observation field, required rejection kind)
    'MR03': ('extraction', 'absent'),
    'MR04': ('followup', 'wrong-key'),
    'MR09': ('followup', 'absent'),
    'MR10': ('followup', 'checksum'),
}


def untyped(row):
    obs = json.loads(row['observations_json'])
    field, _ = REQUIRED[row['relation_id']]
    value = obs.get(field)
    if not isinstance(value, dict):
        raise ValueError(f'admitted negative row without {field}: {row["host"]} {row["defect_id"]}')
    return 'SATISFIED' if value.get('kind') == 'rejection' else 'INCONSISTENT'


def derive(matrix: Path):
    rows = list(csv.DictReader(io.TextIOWrapper(gzip.open(matrix), encoding='utf-8')))
    if len(rows) != 18900:
        raise ValueError(f'expected 18,900 rows, found {len(rows)}')
    typed_units, untyped_units, all_units = set(), set(), set()
    transitions = collections.Counter()
    by_relation = collections.defaultdict(collections.Counter)
    by_operator = collections.defaultdict(collections.Counter)
    verdicts = {'typed': collections.Counter(), 'untyped': collections.Counter()}
    for row in rows:
        unit = (row['host'], row['carrier'], row['defect_id'])
        if row['defect_id'] != 'CLEAN':
            all_units.add(unit)
        typed = row['verdict']
        ablated = typed
        if row['relation_id'] in REQUIRED and typed != 'INADMISSIBLE':
            ablated = untyped(row)
            # Sanity: the typed verdict must follow from the recorded observation.
            obs = json.loads(row['observations_json'])[REQUIRED[row['relation_id']][0]]
            expected = 'SATISFIED' if obs == {'kind': 'rejection', 'value': REQUIRED[row['relation_id']][1]} else 'INCONSISTENT'
            if expected != typed:
                raise ValueError(f'typed verdict not reproduced for {unit} {row["relation_id"]}')
            transitions[(typed, ablated)] += 1
            by_relation[row['relation_id']][(typed, ablated)] += 1
            if typed != ablated:
                by_operator[row['defect_id']][row['relation_id']] += 1
        verdicts['typed'][typed] += 1
        verdicts['untyped'][ablated] += 1
        if row['defect_id'] != 'CLEAN':
            if typed == 'INCONSISTENT':
                typed_units.add(unit)
            if ablated == 'INCONSISTENT':
                untyped_units.add(unit)
    clean_false = sum(1 for r in rows if r['defect_id'] == 'CLEAN' and r['verdict'] != 'SATISFIED')
    key = lambda pair: f'{pair[0]}->{pair[1]}'
    return {
        'schema': 'toolchainmark-oracle-ablation-v1',
        'rows': len(rows), 'fresh_native_execution': False,
        'gate': {'inadmissible_rows': verdicts['typed']['INADMISSIBLE'],
                 'note': 'Admission is identical in both arms; inadmissible rows cannot be exposures.'},
        'row_verdicts': {arm: dict(sorted(c.items())) for arm, c in verdicts.items()},
        'negative_relation_transitions': {key(k): v for k, v in sorted(transitions.items())},
        'by_relation': {r: {key(k): v for k, v in sorted(c.items())} for r, c in sorted(by_relation.items())},
        'changed_rows_by_operator': {op: dict(sorted(c.items())) for op, c in sorted(by_operator.items())},
        'fault_units': len(all_units),
        'exposed_units': {'typed': len(typed_units), 'untyped': len(untyped_units)},
        'units_exposed_only_by_typed_rejection': sorted('/'.join(u) for u in typed_units - untyped_units),
        'clean_rows_not_satisfied': clean_false,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', type=Path, default=ARTIFACT / 'results' / 'admission-study' / 'matrix.csv.gz')
    parser.add_argument('--out', type=Path, default=ARTIFACT / 'results' / 'oracle-ablation' / 'summary.json')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    summary = derive(args.matrix)
    if args.check:
        ok = json.loads(args.out.read_text()) == summary
        print(json.dumps({'verdict': 'PASS' if ok else 'FAIL', 'exposed_units': summary['exposed_units']}))
        return 0 if ok else 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: summary[k] for k in ('row_verdicts', 'negative_relation_transitions', 'exposed_units')}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
