"""Apples-to-apples CTF arm for the 24 correspondence records.

Runs the official Causal Testing Framework test-case path (through the pinned
vendored source used by ``ctf_comparison``) on exactly the records judged by the
three checking layers, under the frozen protocol in ``ctf_arm_protocol.json``.
No native program is executed.  Needs the science environment (NumPy, Pandas,
SciPy).

    python -B -m evidence_correspondence.ctf_arm [--out results/evidence-correspondence/ctf-arm]
    python -B -m evidence_correspondence.ctf_arm --check
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))

CASES = ARTIFACT / 'results' / 'evidence-correspondence' / 'completed' / 'cases'
PROTOCOL = Path(__file__).resolve().parent / 'ctf_arm_protocol.json'
DEFAULT_OUT = ARTIFACT / 'results' / 'evidence-correspondence' / 'ctf-arm'
LAYER_SUMMARY = ARTIFACT / 'results' / 'evidence-correspondence' / 'completed' / 'summary.json'


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decide(plan, receipt, *, hash_binding: bool):
    from ctf_comparison.oracle import compare_receipt, digest
    try:
        if hash_binding and (digest(plan) != receipt.get('plan_sha256')
                             or digest(receipt.get('inputs')) != receipt.get('inputs_sha256')):
            return {'accepted': False, 'reason': 'canonical plan or input digest differs'}
        answer = compare_receipt(plan, receipt)
    except Exception as error:  # an input the CTF path cannot process is a rejection
        return {'accepted': False, 'reason': f'{type(error).__name__}: {error}'}
    disagreements = [r['id'] for r in answer['results'] if not r['agreement']]
    if disagreements:
        return {'accepted': False, 'reason': 'recomputed stage outcome differs: ' + ','.join(disagreements)}
    return {'accepted': True, 'reason': None,
            'stage_outcomes': [r['mapped_verdict'] for r in answer['results']]}


def run():
    names = sorted(p.name for p in CASES.iterdir() if p.is_dir())
    if len(names) != 24:
        raise SystemExit(f'expected 24 correspondence records, found {len(names)}')
    decisions = []
    for name in names:
        plan = json.loads((CASES / name / 'plan.json').read_text())
        receipt = json.loads((CASES / name / 'receipt.json').read_text())
        decisions.append({'record': name,
                          'plan_sha256': sha(CASES / name / 'plan.json'),
                          'receipt_sha256': sha(CASES / name / 'receipt.json'),
                          'ctf-api': decide(plan, receipt, hash_binding=False),
                          'ctf-api-with-hash-binding': decide(plan, receipt, hash_binding=True)})
    # Labels are attached only after every decision exists.
    for row in decisions:
        row['valid'] = row['record'].startswith('valid-')
    summary ={'schema': 'toolchainmark-correspondence-ctf-arm-v1',
               'protocol_sha256': sha(PROTOCOL), 'records': len(decisions),
               'valid_records': sum(r['valid'] for r in decisions),
               'contradictions': sum(not r['valid'] for r in decisions),
               'fresh_native_execution': False, 'arms': {}}
    for arm in ('ctf-api', 'ctf-api-with-hash-binding'):
        summary['arms'][arm] = {
            'valid_accepted': sum(r['valid'] and r[arm]['accepted'] for r in decisions),
            'contradictions_rejected': sum((not r['valid']) and not r[arm]['accepted'] for r in decisions),
            'rejected_records': [r['record'] for r in decisions if not r['valid'] and not r[arm]['accepted']],
        }
    summary['layer_summary_sha256'] = sha(LAYER_SUMMARY)
    return summary, decisions


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    parser.add_argument('--check', action='store_true', help='recompute and compare with the retained result')
    args = parser.parse_args(argv)
    summary, decisions = run()
    if args.check:
        retained = json.loads((args.out / 'summary.json').read_text())
        retained_rows = json.loads((args.out / 'decisions.json').read_text())
        ok = retained == summary and retained_rows == decisions
        print(json.dumps({'verdict': 'PASS' if ok else 'FAIL', 'arms': summary['arms']}, indent=2, sort_keys=True))
        return 0 if ok else 1
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    (args.out / 'decisions.json').write_text(json.dumps(decisions, indent=2, sort_keys=True) + '\n')
    print(json.dumps(summary['arms'], indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
