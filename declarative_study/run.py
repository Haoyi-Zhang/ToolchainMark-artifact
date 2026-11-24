#!/usr/bin/env python3
"""Run newly acquired native observations through frozen JSON contracts."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent
sys.path.insert(0, str(ARTIFACT)); sys.path.insert(0, str(ARTIFACT / 'src'))
from contract_runtime.core import execute, validate_plan
from declarative_study.reference_adapter import ReferenceAdapter, Pipeline
from declarative_study.native_io import acquisition, executable_identity, sha
from declarative_study.build_plans import L, O
from declarative_study.state_words import words, make_plan, ControlledStatePipeline
from toolchainmark.admission import evaluate


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def baseline_inputs(carrier='string', implementation='CLEAN'):
    return {'host': str(ARTIFACT / 'hosts/H01-gcd.c'), 'carrier': carrier,
            'implementation': implementation, 'payload1': b'Morph-01'.hex(),
            'payload2': b'Second-2'.hex(), 'key1': 'key-alpha', 'key2': 'key-beta',
            'compiler': 'gcc', 'optimization': 'O2', 'host_inputs': [0, 1, 5, 13, 144, 99991]}


def sources(study):
    paths = []
    for directory in (ARTIFACT / 'contract_runtime', HERE, ARTIFACT / 'src/toolchainmark'):
        paths += list(directory.glob('*.py'))
    paths += list((HERE / 'plans').glob('*.json')) + [HERE / 'protocol.json', ARTIFACT / 'hosts/H01-gcd.c']
    if study == 'llwm':
        paths += list((ARTIFACT / 'external_llwm/vendor').rglob('*'))
        paths += list((ARTIFACT / 'external_llwm/probes').glob('*.c'))
        paths += [ARTIFACT / 'external_llwm' / name for name in
                  ('run_study.py', 'literal-output.patch', 'repair-identities.json', 'acquisition.json')]
    return sorted({p for p in paths if p.is_file()})


def freeze(out, study, frame):
    records = []
    for path in sources(study):
        relative = path.relative_to(ARTIFACT).as_posix()
        data = path.read_bytes()
        target = out / 'source-snapshot' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append({'path': relative, 'sha256': sha(data), 'bytes': len(data)})
    result = {'created_utc': datetime.now(timezone.utc).isoformat(), 'study': study,
              'inputs': records, 'frame': frame}
    write(out / 'producer-freeze.json', result)
    return result


def check_frozen(frozen):
    changed = [row['path'] for row in frozen['inputs']
               if sha((ARTIFACT / row['path']).read_bytes()) != row['sha256']]
    if changed:
        raise ValueError('Producer inputs changed during acquisition: ' + repr(changed))


def legacy_arm(directory, store, relation, inputs, context, factory):
    evidence, lock = [], threading.Lock()
    class LegacyCapture(factory):
        def build(self, request):
            with acquisition(store, 'legacy-build:' + request.work_dir.name, context) as local:
                try:
                    return super().build(request)
                finally:
                    with lock:
                        evidence.extend(local)
    pipeline = LegacyCapture(inputs['carrier'], inputs['implementation'])
    with acquisition(store, 'legacy-handler', context) as local:
        result = evaluate(relation, pipeline, Path(inputs['host']), directory)
    evidence.extend(local)
    return {'verdict': result.verdict, 'reason': result.reason, 'phase': result.phase,
            'admission': result.admission, 'observations': result.observations, 'evidence': evidence}


def declaration_variants():
    def get(name):
        return json.loads((HERE / 'plans' / (name + '.json')).read_text())
    baseline = get('MR01')
    yield 'MR01-baseline', baseline
    literal = get('MR01'); replacement = b'Declared-v6'.hex()
    def replace(value):
        if value == {'input': 'payload1', 'path': []}:
            return L(replacement)
        if isinstance(value, list): return [replace(x) for x in value]
        if isinstance(value, dict): return {k: replace(v) for k, v in value.items()}
        return value
    literal = replace(literal); literal['id'] = 'MR01-literal-request'
    yield literal['id'], literal
    inverted = get('MR01'); inverted['id'] = 'MR01-predicate-reversed'
    inverted['obligations'][-1]['predicate'] = O('not', inverted['obligations'][-1]['predicate'])
    yield inverted['id'], inverted
    skipped = get('MR08'); skipped['id'] = 'MR08-guard-false'
    next(row for row in skipped['actions'] if row['id'] == 'move')['when'] = L(False)
    yield skipped['id'], skipped
    compiler = get('MR06'); compiler['id'] = 'MR06-two-gcc-branches'
    def replace_compiler(value):
        if value == L('clang'): return L('gcc')
        if isinstance(value, list): return [replace_compiler(x) for x in value]
        if isinstance(value, dict): return {k: replace_compiler(v) for k, v in value.items()}
        return value
    compiler = replace_compiler(compiler)
    yield compiler['id'], compiler
    sequential = get('MR12'); sequential['id'] = 'MR12-sequential'
    actions = []
    for item in sequential['actions']:
        if 'parallel' in item: actions.extend(item['parallel'])
        elif item['id'] not in {'overlap-begin', 'overlap-end'}: actions.append(item)
    sequential['actions'] = actions
    yield sequential['id'], sequential


def frame_for(study, protocol):
    frame = []
    cfg = protocol[study]
    if study in ('reference', 'identity', 'state-baseline'):
        relations = cfg.get('relations', [cfg.get('relation')])
        for run, carrier, implementation, relation in itertools.product(range(1, 3), cfg['carriers'], cfg['implementations'], relations):
            frame.append({'id': f'pass-{run}/{carrier}/{implementation}/{relation}', 'run': run,
                          'carrier': carrier, 'implementation': implementation, 'relation': relation})
    elif study == 'declarations':
        for run, carrier, (name, plan) in itertools.product(range(1, 3), cfg['carriers'], list(declaration_variants())):
            frame.append({'id': f'pass-{run}/{carrier}/{name}', 'run': run, 'carrier': carrier,
                          'implementation': 'CLEAN', 'relation': name, 'plan': plan})
    elif study == 'state':
        for run, carrier, implementation, word in itertools.product(range(1, 3), cfg['carriers'], cfg['implementations'], list(words(cfg['maximum_generated_suffix_length']))):
            name = 'empty' if not word else '_'.join(word).replace('+', 'p').replace('-', 'm')
            frame.append({'id': f'pass-{run}/{carrier}/{implementation}/{name}', 'run': run,
                          'carrier': carrier, 'implementation': implementation, 'word': list(word)})
    elif study == 'llwm':
        for run, variant, interface, payload_id, optimization in itertools.product(range(1, 3), cfg['variants'], cfg['interfaces'], range(len(cfg['payloads'])), cfg['optimizations']):
            frame.append({'id': f'pass-{run}/{variant}/{interface}/payload-{payload_id}/{optimization}',
                          'run': run, 'variant': variant, 'interface': interface,
                          'payload': cfg['payloads'][payload_id], 'optimization': optimization})
    if study != 'llwm':
        for row in frame:
            row['host'] = str(ARTIFACT / 'hosts/H01-gcd.c')
    return frame


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study', required=True, choices=['reference', 'declarations', 'identity', 'state', 'state-baseline', 'llwm'])
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--pilot-limit', type=int)
    parser.add_argument('--llvm-bin', type=Path)
    parser.add_argument('--eigen-include', type=Path)
    args = parser.parse_args()
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False)
    protocol = json.loads((HERE / 'protocol.json').read_text())
    frame = frame_for(args.study, protocol)
    if args.pilot_limit is not None: frame = frame[:args.pilot_limit]
    write(out / 'protocol.json', protocol)
    write(out / 'frame.json', frame)
    frozen = freeze(out, args.study, frame)
    write(out / 'environment.json', {'python': sys.version, 'workers': args.workers,
        'purpose': 'pilot' if args.pilot_limit is not None else 'formal',
        'tools': {name: executable_identity(name) for name in ('gcc', 'clang', 'nm', 'objcopy', 'readelf', 'strip')}})
    plugins = tools = None
    if args.study == 'llwm':
        from declarative_study.llwm_adapter import LlwmAdapter
        spec = importlib.util.spec_from_file_location('llwm_v5_setup', ARTIFACT / 'external_llwm/run_study.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        if args.llvm_bin is None or args.eigen_include is None:
            raise ValueError('LLWM requires explicit LLVM 17 and Eigen include paths')
        tools = {name: (args.llvm_bin / name).resolve() for name in ('clang', 'opt', 'llvm-config')}
        tools.update({name: Path(shutil.which(name)).resolve() for name in ('readelf', 'strip')})
        plugins, setup_records = module.build_plugins(out, tools, args.eigen_include.resolve(), shutil.which('g++'))
    def one(case):
        start = time.perf_counter(); directory = out / 'cases' / case['id']; directory.mkdir(parents=True)
        if args.study == 'llwm':
            plan = json.loads((HERE / 'plans' / ('LLWM-' + case['interface'] + '.json')).read_text())
            inputs = {name: case[name] for name in ('interface', 'variant', 'payload', 'optimization')}
            inputs.update(payload_hex=case['payload'].encode().hex(), key='1234', ordinary='4321')
            adapter = LlwmAdapter(directory / 'native', out, tools, plugins, ARTIFACT / 'external_llwm/probes')
            receipt = execute(plan, inputs, adapter, context_id=case['id'])
            write(directory / 'plan.json', plan); write(directory / 'receipt.json', receipt)
            primary = {row['id']: row['verdict'] for row in receipt['obligations']}
            legacy = None
        else:
            inputs = baseline_inputs(case['carrier'], case['implementation'])
            inputs['host'] = case['host']
            if args.study == 'state':
                plan = make_plan(case['word']); inputs.update(reuse_permitted=True, lockout_excluded=True)
            else:
                plan = case.get('plan') or json.loads((HERE / 'plans' / (case['relation'] + '.json')).read_text())
            if args.study == 'state-baseline' and case['relation'] == 'SR01':
                inputs.update(reuse_permitted=True, lockout_excluded=True)
            factory = ControlledStatePipeline if args.study in ('state', 'identity', 'state-baseline') else Pipeline
            def run_new():
                adapter = ReferenceAdapter(directory / 'declared', out, pipeline_factory=factory)
                return execute(plan, inputs, adapter, context_id=case['id'] + ':declaration')
            legacy = None
            if args.study in ('reference', 'identity'):
                def run_old():
                    return legacy_arm(directory / 'legacy', out, case['relation'], inputs,
                                      case['id'] + ':legacy', factory)
                if case['run'] == 1: legacy, receipt = run_old(), run_new()
                else: receipt, legacy = run_new(), run_old()
                write(directory / 'legacy.json', legacy)
            else: receipt = run_new()
            write(directory / 'plan.json', plan); write(directory / 'receipt.json', receipt)
            primary = receipt['obligations'][-1]['verdict']
        summary = {k: v for k, v in case.items() if k != 'plan'}
        summary.update(primary=primary, legacy=None if legacy is None else legacy['verdict'],
                       seconds=time.perf_counter() - start,
                       action_statuses=dict(Counter(x['status'] for x in receipt['actions'])),
                       command_count=sum(e.get('kind') == 'process' for a in receipt['actions'] for e in a['evidence']))
        write(directory / 'case.json', summary)
        return summary
    started = time.perf_counter()
    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for n, row in enumerate(pool.map(one, frame), 1):
            rows.append(row)
            if n % 100 == 0: print(json.dumps({'study': args.study, 'completed': n, 'total': len(frame)}), flush=True)
    write(out / 'cases.json', rows)
    check_frozen(frozen)
    by_run = {}
    for run in (1, 2):
        selected = [x for x in rows if x['run'] == run]
        counts = Counter()
        for row in selected:
            if isinstance(row['primary'], dict): counts.update(row['primary'].values())
            else: counts[row['primary']] += 1
        by_run[str(run)] = {'cases': len(selected), 'verdicts': dict(counts),
                           'commands': sum(x['command_count'] for x in selected)}
    differences = [x['id'] for x in rows if x['legacy'] is not None and x['legacy'] != x['primary']]
    result = {'study': args.study, 'purpose': 'pilot' if args.pilot_limit is not None else 'formal',
              'cases': len(rows), 'seconds': time.perf_counter() - started, 'by_run': by_run,
              'legacy_primary_differences': differences, 'producer_inputs_unchanged': True}
    write(out / 'summary.json', result)
    print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__': main()
