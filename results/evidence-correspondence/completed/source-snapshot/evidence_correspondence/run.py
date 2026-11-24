"""Freeze and execute a retained-record checking-layer comparison.

The freeze command writes every source anchor and exact controlled patch before
the execute command evaluates any layer. No tested native program is launched.
"""
from __future__ import annotations
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from evidence_correspondence.design import BASES, CHANGES, patches_for


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def apply_patches(original, patches):
    value = deepcopy(original)
    for patch in patches:
        parent = value
        for token in patch['path'][:-1]:
            parent = parent[token]
        token = patch['path'][-1]
        if parent[token] != patch['before']:
            raise ValueError('patch preimage differs')
        if patch['op'] == 'replace': parent[token] = deepcopy(patch['after'])
        elif patch['op'] == 'remove': del parent[token]
        else: raise ValueError('unsupported controlled patch')
    return value


def expected_inputs(study, case):
    if study == 'llwm':
        return {'interface': case['interface'], 'variant': case['variant'], 'payload': case['payload'],
                'payload_hex': case['payload'].encode().hex(), 'key': '1234', 'ordinary': '4321',
                'optimization': case['optimization']}
    return {'host': case['host'], 'carrier': case['carrier'], 'implementation': case['implementation'],
            'payload1': b'Morph-01'.hex(), 'payload2': b'Second-2'.hex(), 'key1': 'key-alpha',
            'key2': 'key-beta', 'compiler': 'gcc', 'optimization': 'O2', 'host_inputs': [0, 1, 5, 13, 144, 99991]}


def source_paths():
    paths = list((ARTIFACT / 'evidence_correspondence').glob('*.py'))
    paths += [ARTIFACT / name for name in (
        'contract_runtime/__init__.py', 'contract_runtime/core.py', 'contract_runtime/receiver.py',
        'declarative_study/__init__.py', 'declarative_study/verify.py', 'declarative_study/native_io.py',
        'ctf_comparison/__init__.py', 'ctf_comparison/expressions.py',
        'independent_observers/producer-v2/independent_observer.py')]
    return sorted(set(paths))


def freeze(out):
    out.mkdir(parents=True, exist_ok=False)
    bindings, anchors, bases = {}, {}, {}
    def bind(path):
        relative = path.relative_to(ARTIFACT).as_posix()
        bindings[relative] = {'path': relative, 'sha256': sha(path), 'bytes': path.stat().st_size}
    def blobs(value, store):
        if isinstance(value, dict):
            if 'blob' in value and isinstance(value['blob'], str): bind(store / value['blob'])
            for child in value.values(): blobs(child, store)
        elif isinstance(value, list):
            for child in value: blobs(child, store)
    for name, (study, identity) in BASES.items():
        store = ARTIFACT / 'results/declarative-v6' / study
        directory = store / 'cases' / identity
        case = next(row for row in read(store / 'frame.json') if row['id'] == identity)
        anchor = {'study': study, 'source_case': identity, 'store': store.relative_to(ARTIFACT).as_posix(),
                  'expected_inputs': expected_inputs(study, case),
                  'expected_context_id': identity if study == 'llwm' else identity + ':declaration'}
        receipt, plan = read(directory / 'receipt.json'), read(directory / 'plan.json')
        if receipt['inputs'] != anchor['expected_inputs'] or receipt['context_id'] != anchor['expected_context_id']:
            raise ValueError('source receipt differs from the externally selected frame')
        anchor['receipt_source'] = (directory / 'receipt.json').relative_to(ARTIFACT).as_posix()
        anchor['plan_source'] = (directory / 'plan.json').relative_to(ARTIFACT).as_posix()
        for path in (directory / 'receipt.json', directory / 'plan.json', store / 'frame.json',
                     store / 'environment.json', store / 'producer-freeze.json'):
            bind(path)
        if study == 'llwm':
            bind(store / 'setup/files.json')
            for row in read(store / 'setup/files.json'): bind(store / row['path'])
            for row in read(store / 'producer-freeze.json')['inputs']:
                if row['path'].startswith('external_llwm/probes/') and row['path'].endswith('.c'):
                    bind(store / 'source-snapshot' / row['path'])
        blobs(receipt, store)
        target = out / 'bases' / name; target.mkdir(parents=True)
        shutil.copyfile(directory / 'receipt.json', target / 'receipt.json')
        shutil.copyfile(directory / 'plan.json', target / 'plan.json')
        write(target / 'anchor.json', anchor)
        anchors[name], bases[name] = anchor, receipt
    frame = []
    for name in BASES:
        frame.append({'id': 'valid-' + name, 'base': name, 'valid_record': True, 'patches': [],
                      'association': 'Unmodified native record, including its original scientific stage results.'})
    for name, base, reason in CHANGES:
        patches = patches_for(name, bases[base])
        frame.append({'id': name, 'base': base, 'valid_record': False,
                      'association': reason, 'patches': patches})
    if len(frame) != 24 or sum(row['valid_record'] for row in frame) != 6:
        raise ValueError('comparison frame differs from its declared size')
    source_bindings = []
    for path in source_paths():
        relative = path.relative_to(ARTIFACT)
        target = out / 'source-snapshot' / relative
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, target)
        source_bindings.append({'path': relative.as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size})
    protocol = {'schema': 'execution-correspondence-comparison-v1', 'created_utc': datetime.now(timezone.utc).isoformat(),
                'status': 'FROZEN_BEFORE_LAYER_EVALUATION', 'records': 24, 'valid_records': 6,
                'controlled_invalid_records': 18, 'layers': ['oracle-replay', 'plan-receiver', 'native-binding'],
                'planned_acceptance_decisions': 72, 'anchors': anchors, 'frame': frame,
                'source_bindings': source_bindings, 'dataset_bindings': sorted(bindings.values(), key=lambda x: x['path']),
                'scope': 'Controlled record-conformance comparison on retained native observations. Designers know the receivers and earlier repair controls. This is not blind fault discovery, independent native acquisition, or a CTF/GeMTest defect study.',
                'ground_truth': 'Valid controls are unchanged records from the selected frozen native cases, including scientific I/IA. Each invalid control violates its explicitly listed record association; scientific inconsistency and inadmissibility remain separate from record acceptance.',
                'selection': 'Six cases chosen to exercise host outputs, removal, parallel order, valid identity inadmissibility, and LLVM I/IA and S results. No population sampling or independence claim is made.'}
    write(out / 'protocol.json', protocol)
    write(out / 'freeze-receipt.json', {'protocol_sha256': sha(out / 'protocol.json'),
                                      'record_count': len(frame), 'layer_evaluations_performed': 0})
    return {'status': 'FROZEN', 'protocol_sha256': sha(out / 'protocol.json'), 'records': 24, 'decisions': 72}


def check_bindings(out, protocol):
    for row in protocol['source_bindings']:
        path = out / 'source-snapshot' / row['path']
        if sha(path) != row['sha256'] or path.stat().st_size != row['bytes']:
            raise ValueError('frozen checking source changed: ' + row['path'])
    for row in protocol['dataset_bindings']:
        path = ARTIFACT / row['path']
        if sha(path) != row['sha256'] or path.stat().st_size != row['bytes']:
            raise ValueError('retained source evidence changed: ' + row['path'])


def execute(out):
    protocol = read(out / 'protocol.json')
    frozen = read(out / 'freeze-receipt.json')
    if sha(out / 'protocol.json') != frozen['protocol_sha256']:
        raise ValueError('protocol differs from pre-execution freeze')
    if (out / 'execution-start.json').exists():
        raise ValueError('an attempted comparison already exists; use another output directory')
    driver = next(row for row in protocol['source_bindings'] if row['path'] == 'evidence_correspondence/run.py')
    if sha(Path(__file__)) != driver['sha256']:
        raise ValueError('the execution driver differs from its frozen source')
    check_bindings(out, protocol)
    write(out / 'execution-start.json', {'created_utc': datetime.now(timezone.utc).isoformat(),
            'protocol_sha256': sha(out / 'protocol.json'), 'python': sys.version,
            'native_programs_to_execute': 0, 'case_order': [row['id'] for row in protocol['frame']]})
    rows, start = [], time.perf_counter()
    for item in protocol['frame']:
        directory = out / 'cases' / item['id']; directory.mkdir(parents=True, exist_ok=False)
        base = out / 'bases' / item['base']
        write(directory / 'receipt.json', apply_patches(read(base / 'receipt.json'), item['patches']))
        shutil.copyfile(base / 'plan.json', directory / 'plan.json')
        shutil.copyfile(base / 'anchor.json', directory / 'anchor.json')
        write(directory / 'mutation.json', item)
        command = [sys.executable, '-B', str(out / 'source-snapshot/evidence_correspondence/evaluate.py'),
                   '--case', str(directory), '--artifact', str(ARTIFACT)]
        invoked = time.perf_counter()
        process = subprocess.run(command, cwd=out, capture_output=True, timeout=120)
        (directory / 'evaluation.stdout.json').write_bytes(process.stdout)
        (directory / 'evaluation.stderr.txt').write_bytes(process.stderr)
        call = {'argv': command, 'cwd': str(out), 'exit': process.returncode,
                'wall_seconds': time.perf_counter() - invoked,
                'stdout_sha256': hashlib.sha256(process.stdout).hexdigest(),
                'stderr_sha256': hashlib.sha256(process.stderr).hexdigest()}
        write(directory / 'invocation.json', call)
        if process.returncode != 0:
            raise RuntimeError('layer evaluation failed; the attempted record is retained: ' + item['id'])
        result = json.loads(process.stdout)
        write(directory / 'evaluation.json', result)
        rows.append({'id': item['id'], 'base': item['base'], 'valid_record': item['valid_record'],
                     'layers': result['layers']})
    counts = {tier: dict(Counter(('valid_accepted' if row['valid_record'] else 'invalid_accepted')
                                if layer['accepted'] else
                                ('valid_rejected' if row['valid_record'] else 'invalid_rejected')
                                for row in rows for layer in row['layers'] if layer['tier'] == tier))
              for tier in protocol['layers']}
    summary = {'schema': 'execution-correspondence-summary-v1', 'records': len(rows),
               'valid_records': sum(row['valid_record'] for row in rows),
               'controlled_invalid_records': sum(not row['valid_record'] for row in rows),
               'acceptance_decisions': sum(len(row['layers']) for row in rows),
               'layers': counts, 'rows': rows, 'wall_seconds': time.perf_counter() - start,
               'native_programs_reexecuted': False, 'official_ctf_api_called': False,
               'scope': protocol['scope']}
    write(out / 'summary.json', summary)
    check_bindings(out, protocol)
    if sha(Path(__file__)) != driver['sha256']:
        raise ValueError('the execution driver changed during checking')
    write(out / 'completion.json', {'completed_utc': datetime.now(timezone.utc).isoformat(),
          'protocol_sha256': sha(out / 'protocol.json'), 'summary_sha256': sha(out / 'summary.json'),
          'records': len(rows), 'acceptance_decisions': summary['acceptance_decisions'],
          'frozen_source_and_data_unchanged': True})
    return {k: summary[k] for k in ('records', 'valid_records', 'controlled_invalid_records', 'acceptance_decisions', 'layers', 'wall_seconds')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('freeze', 'execute'))
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(freeze(args.out.resolve()) if args.operation == 'freeze' else execute(args.out.resolve()), indent=2))


if __name__ == '__main__':
    main()
