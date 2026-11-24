"""Fresh paired native control for an unreferenced state-changing action."""
from __future__ import annotations

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import tempfile
import time

from contract_runtime.core import execute
from contract_runtime.receiver import verify_receipt, InvalidRecord
from declarative_study.native_io import executable_identity, verify_evidence, verify_file
from declarative_study.reference_adapter import ReferenceAdapter
from declarative_study.verify import value_bindings
from .project import project, selection
from .receiver import verify_bundle, verify_structure
from .native import members, populate
from .run import write, identity

ARTIFACT = Path(__file__).resolve().parents[1]


def plans():
    source = json.loads((ARTIFACT / 'declarative_study/plans/MR13.json').read_text())
    full = copy.deepcopy(source)
    full['id'] = 'HISTORY-REVISIT'
    obligation = full['obligations'][0]
    obligation.update(id='REVISIT', stage='decoder-revisit', clause='A recovery after the declared history')
    obligation['requires'] = [gate for gate in obligation['requires'] if gate['name'] != 'available:intervening']
    obligation['predicate']['args'].pop(1)  # REVISIT reads only the two A observations.
    direct = copy.deepcopy(full)
    direct['id'] = 'DIRECT-REVISIT'
    direct['actions'] = [action for action in direct['actions'] if action['id'] != 'intervening']
    return {'with-B': full, 'without-B': direct}


def run(output):
    output.mkdir(parents=True, exist_ok=False)
    declarations = plans()
    frame = [{'id': f'pass-{repeat}/{carrier}/{implementation}', 'pass': repeat,
              'carrier': carrier, 'implementation': implementation}
             for repeat, carrier, implementation in itertools.product(
                 (1, 2), ('string', 'symbol', 'section'), ('CLEAN', 'M23'))]
    protocol = {'question': 'Can deleting an action with no value-reference edge change a later stage judgment?',
        'unit': 'One fresh pair with and without the intervening B extraction',
        'pairs': 12, 'native_executions': 24,
        'conditions': 'CLEAN and pre-existing controlled cross-object behavior M23; three ELF carriers; two passes',
        'constant_operations': 'Both arms create a new decoder session, build A and B, and extract A before and after the intervention position.',
        'single_changed_operation': 'The with-B arm invokes extraction on B between the two A calls.',
        'stage': 'REVISIT requires stable A versions, equal request context, and the declared A payload on both A calls. It does not inspect the B call return.',
        'comparison': 'Direct byte equality of separately built A and B artifacts; final typed observations and REVISIT judgments',
        'arm_order': 'with-B first in pass 1; without-B first in pass 2',
        'scope': 'Controlled native history counterexample; not an external defect discovery or a modification of the existing MR13 dataset'}
    paths = list((ARTIFACT / 'src/toolchainmark').glob('*.py'))
    paths += [ARTIFACT / name for name in ('contract_runtime/core.py', 'contract_runtime/receiver.py',
        'contract_runtime/__init__.py', 'declarative_study/reference_adapter.py', 'declarative_study/native_io.py',
        'declarative_study/verify.py', 'declarative_study/plans/MR13.json', 'hosts/H01-gcd.c',
        'independent_observers/producer_current/independent_observer.py', 'evidence_projection/project.py',
        'evidence_projection/receiver.py', 'evidence_projection/native.py', 'evidence_projection/run.py',
        'evidence_projection/run_history_control.py')]
    frozen = []
    for path in sorted(set(paths)):
        relative = path.relative_to(ARTIFACT).as_posix()
        target = output / 'source-snapshot' / relative
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, target)
        frozen.append({'path': relative, **identity(path)})
    tools = {name: executable_identity(name) for name in ('gcc', 'nm', 'objcopy', 'readelf', 'strip')}
    context = {'profile': 'declarative', 'tools': tools, 'llvm': None}
    write(output / 'protocol.json', protocol); write(output / 'frame.json', frame)
    write(output / 'plans.json', declarations)
    write(output / 'source-freeze.json', {'files': frozen, 'frozen_before_execution': True,
          'frozen_utc': datetime.now(timezone.utc).isoformat(), 'native_context': context})
    pairs, controls = [], []
    started = time.perf_counter()
    for item in frame:
        inputs = {'host': str(ARTIFACT / 'hosts/H01-gcd.c'), 'carrier': item['carrier'],
                  'implementation': item['implementation'], 'payload1': b'Morph-01'.hex(),
                  'payload2': b'Second-2'.hex(), 'key1': 'key-alpha', 'key2': 'key-beta',
                  'compiler': 'gcc', 'optimization': 'O2', 'host_inputs': [0, 1, 5, 13, 144, 99991]}
        receipts = {}
        order = ('with-B', 'without-B') if item['pass'] == 1 else ('without-B', 'with-B')
        for arm in order:
            case = output / 'cases' / item['id'] / arm
            case.mkdir(parents=True)
            context_id = item['id'] + ':' + arm
            adapter = ReferenceAdapter(case / 'native', output)
            receipt = execute(declarations[arm], inputs, adapter, context_id=context_id)
            verify_receipt(declarations[arm], receipt, expected_inputs=inputs, expected_context_id=context_id)
            verify_evidence(receipt, output)
            bindings = value_bindings(receipt, output, native_tools=tools)
            bindings.pop('blobs')
            write(case / 'receipt.json', receipt); write(case / 'plan.json', declarations[arm])
            write(case / 'verification.json', {'status': 'PASS', **bindings})
            receipts[arm] = receipt
        saved = {arm: {a['id']: a for a in receipt['actions']} for arm, receipt in receipts.items()}
        artifact_pairs = []
        for name in ('first', 'second'):
            a, b = [saved[arm][name]['value']['artifact'] for arm in ('with-B', 'without-B')]
            artifact_pairs.append({'artifact': name, 'equal': verify_file(a, output) == verify_file(b, output),
                                   'bytes': a['bytes']})
        for arm in receipts:
            bundle = project(declarations[arm], receipts[arm], 'REVISIT', context)
            expected = dict(expected_plan=declarations[arm], expected_inputs=inputs,
                expected_context_id=receipts[arm]['context_id'], expected_native_context=context,
                expected_target='REVISIT')
            with tempfile.TemporaryDirectory(prefix='toolchainmark-history-') as temporary:
                populate(members(bundle['receipt'], output, 'declarative'), output, Path(temporary))
                verify_bundle(bundle, Path(temporary), **expected)
            if arm == 'with-B':
                # This field deletion preserves the cached final observations,
                # but the independent prefix checker must reject the missing history.
                altered = copy.deepcopy(bundle)
                altered['receipt']['actions'] = [a for a in altered['receipt']['actions'] if a['id'] != 'intervening']
                try:
                    verify_structure(altered, **expected)
                except InvalidRecord as problem:
                    controls.append({'case': item['id'], 'deleted_action': 'intervening',
                                     'rejected': True, 'reason': str(problem)})
                else:
                    raise ValueError('receiver accepted a missing declared history action')
        row = {'case': item, 'artifact_pairs': artifact_pairs,
               'judgments': {arm: receipt['obligations'][0]['verdict'] for arm, receipt in receipts.items()},
               'before': {arm: saved[arm]['before']['value']['observation'] for arm in receipts},
               'after': {arm: saved[arm]['after']['value']['observation'] for arm in receipts},
               'reference_action_ids': selection(declarations['with-B'], 'REVISIT')['reference_action_ids'],
               'prefix_action_ids': selection(declarations['with-B'], 'REVISIT')['action_ids']}
        pairs.append(row)
        write(output / 'pairs.json', pairs)
    for row in frozen:
        if identity(ARTIFACT / row['path']) != {key: row[key] for key in ('bytes', 'sha256')}:
            raise ValueError('source changed during native history control')
    result = {'pairs': len(pairs), 'native_executions': 2 * len(pairs),
              'artifact_byte_pairs': sum(len(r['artifact_pairs']) for r in pairs),
              'unequal_artifact_byte_pairs': sum(not p['equal'] for r in pairs for p in r['artifact_pairs']),
              'by_implementation': {name: {'pairs': len([r for r in pairs if r['case']['implementation'] == name]),
                  'with_B': dict(Counter(r['judgments']['with-B'] for r in pairs if r['case']['implementation'] == name)),
                  'without_B': dict(Counter(r['judgments']['without-B'] for r in pairs if r['case']['implementation'] == name))}
                  for name in ('CLEAN', 'M23')},
              'missing_history_controls': len(controls), 'rejected_missing_history_controls': sum(r['rejected'] for r in controls),
              'source_unchanged': True, 'elapsed_seconds': time.perf_counter() - started}
    write(output / 'deletion-controls.json', controls); write(output / 'summary.json', result)
    write(output / 'complete.json', {'status': 'COMPLETE', 'completed_utc': datetime.now(timezone.utc).isoformat(),
                                    'summary': identity(output / 'summary.json'), 'pairs': identity(output / 'pairs.json')})
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.out.resolve()), indent=2, sort_keys=True))
