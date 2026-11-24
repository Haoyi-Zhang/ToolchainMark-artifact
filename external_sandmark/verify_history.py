#!/usr/bin/env python3
"""Check retained exploratory evidence without adding it to formal counts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.receiver import verify_receipt
from external_sandmark.verify_study import binding, read, require, sha, verify


def verify_history(root):
    index = read(root / 'history-index.json')
    require(index['excluded_from_formal_denominator'] is True, 'Pilot history cannot join formal denominator')
    for item in index['records']:
        if 'source_index_sha256' not in item:
            continue
        folder = root / item['name']
        files = {p.relative_to(folder).as_posix(): sha(p) for p in folder.rglob('*') if p.is_file()}
        value = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        require(value == item['source_index_sha256'], 'Pilot tree differs from the retained original bytes')
        require(len(files) == item['files'], 'Pilot file count mismatch')
    # The first engine pilot predates physical endpoint snapshots. Verify its
    # actual level of evidence, without retroactively upgrading that protocol.
    first = root / 'engine-01'
    plan, frame, start, summary = [read(first / name) for name in ['plan.json', 'study-frame.json', 'execution-start.json', 'summary.json']]
    cases = {row['id']: row for row in frame['configurations']}
    files_checked = 0
    for identity in start['configuration_ids']:
        case = first / 'cases' / identity
        receipt = read(case / 'receipt.json')
        verify_receipt(plan, receipt, expected_inputs=cases[identity]['inputs'], expected_context_id=identity)
        for action in receipt['actions']:
            if action['status'] == 'SKIPPED':
                continue
            actual = [binding(p, case) for p in sorted((case / action['id']).rglob('*')) if p.is_file()]
            require(action['evidence'][0]['files'] == actual, 'Legacy pilot saved-byte binding mismatch')
            files_checked += len(actual)
    require(len(start['configuration_ids']) == summary['configuration_count'] == 26, 'Legacy pilot denominator mismatch')
    second = verify(root / 'engine-02', allow_pilot=True)
    return {'schema': 'sandmark-exploratory-history-receiver-v1', 'verdict': 'PASS',
            'excluded_from_formal_denominator': True,
            'engine_01': {'configurations': 26, 'saved_files_rechecked': files_checked,
                          'scope': 'Independent plan/receipt replay and retained-file byte bindings; predates physical endpoint snapshots.'},
            'engine_02': second,
            'earlier_api_cli_host_probes': 'Retained as exploratory provenance; not counted as formal contract executions.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ARTIFACT/'results/external-sandmark/pilots')
    args = parser.parse_args()
    try:
        report = verify_history(args.root.resolve())
    except Exception as problem:
        print(json.dumps({'schema': 'sandmark-exploratory-history-receiver-v1', 'verdict': 'FAIL', 'error': str(problem)}))
        raise SystemExit(1)
    print(json.dumps(report, indent=2))
