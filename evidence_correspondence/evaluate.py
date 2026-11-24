"""Evaluate three fixed checking layers without consulting control labels."""
from __future__ import annotations
from copy import deepcopy
import argparse
import json
from pathlib import Path
import sys
import time

CODE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_ROOT))
from ctf_comparison.expressions import boolean
from contract_runtime.receiver import verify_receipt
from declarative_study.native_io import verify_evidence
from declarative_study.verify import llvm_binding_context, value_bindings

TIERS = ('oracle-replay', 'plan-receiver', 'native-binding')


def oracle_replay(plan, receipt):
    """Recompute stage labels from raw operation values, including all gates.

    This invokes the independent expression implementation used by the retained
    comparison. It does not execute the official CTF API and makes no CTF claim.
    Execution order, argument provenance, and native material are outside this
    layer's observation set.
    """
    actions = {a['id']: {'status': a['status'], 'value': deepcopy(a['value'])}
               for a in receipt['actions']}
    if len(actions) != len(receipt['actions']):
        raise ValueError('duplicate primitive action identifier')
    prior, results = {}, []
    for obligation in plan['obligations']:
        gates = [boolean(g['expr'], receipt['inputs'], actions, prior)
                 for g in obligation['requires']]
        if any(g.state != 'TRUE' for g in gates):
            verdict = 'INADMISSIBLE'
        else:
            predicate = boolean(obligation['predicate'], receipt['inputs'], actions, prior)
            verdict = ('INADMISSIBLE' if predicate.state in ('UNKNOWN', 'ERROR') else
                       'SATISFIED' if predicate.value is True else 'INCONSISTENT')
        prior[obligation['id']] = verdict
        results.append({'id': obligation['id'], 'verdict': verdict})
    recorded = [{'id': row['id'], 'verdict': row['verdict']} for row in receipt['obligations']]
    if results != recorded:
        raise ValueError('stored stage labels differ from independent observation replay')
    return {'stage_verdicts': results}


def evaluate(plan, receipt, anchor, artifact):
    artifact = Path(artifact).resolve()
    store = artifact / anchor['store']
    results = []
    for tier in TIERS:
        started, cpu = time.perf_counter(), time.process_time()
        try:
            if tier == 'oracle-replay':
                detail = oracle_replay(plan, receipt)
            else:
                detail = verify_receipt(plan, receipt,
                    expected_inputs=anchor['expected_inputs'],
                    expected_context_id=anchor['expected_context_id'])
                if tier == 'native-binding':
                    files = verify_evidence(receipt, store)
                    context = llvm_binding_context(store) if anchor['study'] == 'llwm' else None
                    tools = json.loads((store / 'environment.json').read_text())['tools']
                    bindings = value_bindings(receipt, store, llvm_context=context, native_tools=tools)
                    bindings['unique_blobs'] = len(bindings.pop('blobs'))
                    detail = {'plan': detail, 'retained_file_bindings': files, 'native': bindings}
            result = {'tier': tier, 'accepted': True, 'detail': detail, 'error': None}
        except Exception as error:
            result = {'tier': tier, 'accepted': False, 'detail': None,
                      'error': {'type': type(error).__name__, 'message': str(error)}}
        result.update(wall_seconds=time.perf_counter() - started,
                      cpu_seconds=time.process_time() - cpu)
        results.append(result)
    return {'schema': 'execution-correspondence-layer-results-v1', 'layers': results,
            'native_programs_reexecuted': False, 'official_ctf_api_called': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--artifact', type=Path, required=True)
    args = parser.parse_args()
    read = lambda name: json.loads((args.case / name).read_text())
    print(json.dumps(evaluate(read('plan.json'), read('receipt.json'), read('anchor.json'), args.artifact),
                     sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
