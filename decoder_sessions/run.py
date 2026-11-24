#!/usr/bin/env python3
"""Freeze and acquire the declared SandMark session frame in a new directory."""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent
sys.path.insert(0, str(ARTIFACT))
from contract_runtime import execute, validate_plan
from decoder_sessions.adapter import SessionAdapter
from decoder_sessions.common import FILES, binding, clone_file, file_digest, read_json, write_json
from decoder_sessions.plans import make_plan

TOOL_SHA256 = '8310d3c80cc8adf13ec46f217fc458462ebe89ae498ce23c1c714ab878fb2ea9'
OWNED_SOURCES = ['SessionBridge.java', 'common.py', 'adapter.py', 'plans.py', 'protocol.json', 'run.py', 'analyze.py']


def source_paths():
    return [HERE / name for name in OWNED_SOURCES] + [ARTIFACT / 'contract_runtime' / name for name in ('core.py', '__init__.py')]


def sources():
    return {p.relative_to(ARTIFACT).as_posix(): {'sha256': file_digest(p), 'bytes': p.stat().st_size} for p in source_paths()}


def command(argv, cwd, prefix, environment, timeout=30):
    begin = time.time_ns()
    try:
        result = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True, timeout=timeout)
        stdout, stderr, code, timed_out = result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, code, timed_out = exc.stdout or b'', exc.stderr or b'', None, True
    prefix.with_suffix('.stdout.bin').write_bytes(stdout)
    prefix.with_suffix('.stderr.bin').write_bytes(stderr)
    record = {'argv': argv, 'cwd': str(cwd), 'environment': environment, 'stdin_hex': '', 'returncode': code, 'timeout': timed_out,
              'start_unix_ns': begin, 'elapsed_ns': time.time_ns() - begin,
              'stdout_hex': stdout.hex(), 'stderr_hex': stderr.hex()}
    write_json(prefix.with_suffix('.command.json'), record)
    return record


def make_inputs(cell, a, b, history, lifetime, pass_number):
    x = a['inputs']
    return {'cell': cell, 'algorithm': x['algorithm'], 'algorithm_class': a['algorithm_class'],
            'host': x['host'], 'archived_embedding_seed': x['seed'],
            'a_case': a['id'], 'b_case': b['id'], 'payload_a': x['payload'], 'payload_b': b['inputs']['payload'],
            'key_a': x['key'], 'key_b': b['inputs']['key'], 'history': history,
            'lifetime': lifetime, 'acquisition_pass': pass_number}


def freeze(output: Path, baseline: Path, tool: Path, *, kind: str, pilot_cells=None, pilot_passes=None, pilot_histories=None, workers=4):
    if output.exists(): raise ValueError('Use a new output directory; existing evidence cannot be overwritten')
    if output.is_relative_to(baseline): raise ValueError('The frozen baseline cannot contain new acquisition output')
    if file_digest(tool) != TOOL_SHA256: raise ValueError('Tool JAR differs from the pinned archived implementation')
    if workers not in range(1, 5): raise ValueError('At most four independent JVM words are permitted')
    if kind == 'formal' and any(v is not None for v in (pilot_cells, pilot_passes, pilot_histories)):
        raise ValueError('Formal acquisition cannot select a subset')
    output.mkdir(parents=True)
    protocol = read_json(HERE / 'protocol.json')
    write_json(output / 'protocol.json', protocol)
    source_hashes = sources()
    for path in source_paths():
        dst = output / 'producer-snapshot' / path.relative_to(ARTIFACT)
        dst.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, dst)
    prior_run = baseline / 'artifact/results/external-sandmark/formal-01'
    prior_frame = read_json(prior_run / 'study-frame.json')
    prior_summary = read_json(prior_run / 'summary.json')
    contracts = read_json(baseline / 'artifact/external_sandmark/algorithm-contracts.json')
    catalog = {row['algorithm']: row for row in contracts['algorithms']}
    prior = {row['id']: row for row in prior_summary['configurations']}
    prior_bindings = {}
    for path in (prior_run / 'study-frame.json', prior_run / 'summary.json',
                 baseline / 'artifact/external_sandmark/algorithm-contracts.json',
                 baseline / 'artifact/external_sandmark/acquisition-lock.json'):
        name = path.name
        target = output / 'prior-metadata' / name; target.parent.mkdir(exist_ok=True)
        shutil.copyfile(path, target)
        prior_bindings[name] = {'original_path': str(path), **binding(target, output)}
    cases = {}
    for row in prior_frame['configurations']:
        cid, inputs = row['id'], row['inputs']
        if prior[cid]['inputs'] != inputs: raise ValueError('Prior input definitions disagree')
        files = {}
        for role, filename in FILES.items():
            src = prior_run / 'cases' / cid / 'embed' / filename
            dst = output / 'inputs' / cid / filename
            info = {'present': src.is_file(), 'path': dst.relative_to(output).as_posix(),
                    'bytes': None, 'sha256': None, 'original_path': str(src)}
            if src.is_file():
                clone_file(src, dst); info.update(bytes=dst.stat().st_size, sha256=file_digest(dst))
            files[role] = info
        available = prior[cid]['action_status']['embed'] == 'OK' and files['target']['present']
        if inputs['algorithm'] in ('Davidson/Myhrvold', 'Stern'): available = available and files['original']['present']
        if inputs['algorithm'] == 'Graph Theoretic Watermark': available = available and files['key_file']['present']
        cases[cid] = {'id': cid, 'inputs': inputs, 'algorithm_class': catalog[inputs['algorithm']]['class'],
                      'prior_embed_status': prior[cid]['action_status']['embed'],
                      'prior_source_verdict': prior[cid]['judgments']['identity'],
                      'archived_marked_input_available': available, 'files': files}
    manifest = {'schema': 'sandmark-session-input-manifest-v1', 'prior_metadata': prior_bindings, 'cases': cases}
    write_json(output / 'input-manifest.json', manifest)
    lookup = {(r['inputs']['algorithm'], r['inputs']['host'], r['inputs']['seed'], r['inputs']['payload']): r for r in cases.values()}
    cycle = protocol['a_b_mapping']
    cells, words = [], []
    counter = 0
    for a in cases.values():
        x = a['inputs']; b = lookup[(x['algorithm'], x['host'], x['seed'], cycle[x['payload']])]
        cells.append({'id': 'cell-' + a['id'].split('-')[-1], 'a_case': a['id'], 'b_case': b['id']})
    for p in (1, 2):
        order = protocol['pass_orders'][str(p)]
        for cell in cells:
            a, b = cases[cell['a_case']], cases[cell['b_case']]
            for history in order['history']:
                for lifetime in order['lifetime']:
                    counter += 1
                    words.append({'id': f'word-{counter:06d}',
                                  'inputs': make_inputs(cell['id'], a, b, history, lifetime, p)})
    selected = words
    if kind == 'pilot':
        wanted = set(pilot_cells or [c['id'] for c in cells])
        passes = set(pilot_passes or [1, 2])
        histories = set(pilot_histories or ['AA', 'AAA', 'ABA'])
        if not wanted.issubset({c['id'] for c in cells}) or not passes.issubset({1, 2}) or not histories.issubset({'AA', 'AAA', 'ABA'}):
            raise ValueError('Unknown pilot selection')
        selected = [w for w in words if w['inputs']['cell'] in wanted and w['inputs']['acquisition_pass'] in passes
                    and w['inputs']['history'] in histories]
    if not selected: raise ValueError('Empty acquisition frame')
    frame = {'schema': 'sandmark-session-frame-v1', 'kind': kind, 'cells': cells,
             'full_planned_words': len(words), 'selected_word_count': len(selected), 'words': selected,
             'pilot_selection': {'cells': sorted(wanted), 'passes': sorted(passes), 'histories': sorted(histories)} if kind == 'pilot' else None}
    write_json(output / 'frame.json', frame)
    plan_bindings = {}
    for history in ('AA', 'AAA', 'ABA'):
        plan = make_plan(history); validate_plan(plan, SessionAdapter.operations)
        path = output / 'plans' / (history + '.json'); write_json(path, plan)
        plan_bindings[history] = binding(path, output)
    java = Path(shutil.which('java') or '').resolve()
    if not java.is_file(): raise ValueError('A JDK is required')
    runtime = {'java': {'path': str(java), 'sha256': file_digest(java), 'bytes': java.stat().st_size},
               'platform': platform.platform(), 'python': sys.version}
    for name in ('release', 'lib/modules'):
        path = java.parent.parent / name
        runtime[name] = {'path': str(path), 'sha256': file_digest(path), 'bytes': path.stat().st_size}
    command([str(java), '-version'], output, output / 'java-version', protocol['launch_environment'])
    bridge = output / 'bridge'; bridge.mkdir()
    compiled = command([str(java), 'com.sun.tools.javac.Main', '-encoding', 'UTF-8', '-classpath', str(tool),
                        '-d', str(bridge), str(output / 'producer-snapshot/decoder_sessions/SessionBridge.java')],
                       output, output / 'compile', protocol['launch_environment'], timeout=30)
    if compiled['returncode'] != 0 or compiled['timeout']: raise RuntimeError('Helper compilation failed; retain this output')
    frozen = {'schema': 'sandmark-session-freeze-v1', 'kind': kind, 'frozen_unix_ns': time.time_ns(),
              'execution_root': str(output), 'max_workers': workers, 'source_bindings': source_hashes,
              'protocol': binding(output / 'protocol.json', output), 'frame': binding(output / 'frame.json', output),
              'input_manifest': binding(output / 'input-manifest.json', output), 'plans': plan_bindings,
              'runtime': runtime, 'launch_environment': protocol['launch_environment'],
              'tool': {'path': str(tool), 'sha256': file_digest(tool), 'bytes': tool.stat().st_size},
              'helper_classes': [binding(p, output) for p in sorted(bridge.glob('*.class'))]}
    if sources() != source_hashes: raise ValueError('Producer changed during freeze')
    write_json(output / 'freeze.json', frozen)
    return frozen


def check_frozen(run: Path, frozen: dict, manifest: dict):
    if sources() != frozen['source_bindings']: raise ValueError('Producer source changed after freeze')
    for entry in [frozen['protocol'], frozen['frame'], frozen['input_manifest'], *frozen['plans'].values(), *frozen['helper_classes']]:
        path = run / entry['path']
        if file_digest(path) != entry['sha256'] or path.stat().st_size != entry['bytes']: raise ValueError('Frozen metadata/helper changed')
    for item in [frozen['tool'], frozen['runtime']['java'], frozen['runtime']['release'], frozen['runtime']['lib/modules']]:
        if file_digest(Path(item['path'])) != item['sha256']: raise ValueError('Runtime/tool identity changed')
    for case in manifest['cases'].values():
        for info in case['files'].values():
            path = run / info['path']
            if path.is_file() != info['present']: raise ValueError('Input presence changed')
            if info['present'] and (file_digest(path) != info['sha256'] or path.stat().st_size != info['bytes']):
                raise ValueError('Input capsule changed')


def acquire(run: Path):
    if (run / 'superseded.json').exists(): raise ValueError('This never-started freeze was superseded; it cannot be acquired')
    frozen = read_json(run / 'freeze.json'); frame = read_json(run / 'frame.json')
    manifest = read_json(run / 'input-manifest.json')
    check_frozen(run, frozen, manifest)
    if (run / 'execution-start.json').exists(): raise ValueError('Already started; no implicit resume or replacement')
    write_json(run / 'execution-start.json', {'started_unix_ns': time.time_ns(), 'freeze_sha256': file_digest(run / 'freeze.json'),
                                            'word_ids': [w['id'] for w in frame['words']]})
    plans = {h: read_json(run / 'plans' / (h + '.json')) for h in ('AA', 'AAA', 'ABA')}
    rows = []
    def cell_job(words):
        completed = []
        for word in words:
            adapter = SessionAdapter(run, word['id'], word['inputs'], manifest, frozen)
            try:
                receipt = execute(plans[word['inputs']['history']], word['inputs'], adapter, context_id=word['id'], max_workers=1)
            finally:
                adapter.cleanup()
            receipt_path = adapter.folder / 'receipt.json'; write_json(receipt_path, receipt)
            row = {**word, 'receipt': binding(receipt_path, run),
                   'judgments': {o['id']: o['verdict'] for o in receipt['obligations']},
                   'action_status': {a['id']: a['status'] for a in receipt['actions']}}
            write_json(adapter.folder / 'result.json', row); completed.append(row)
        return completed
    for p in (1, 2):
        groups = {}
        for word in frame['words']:
            if word['inputs']['acquisition_pass'] == p: groups.setdefault(word['inputs']['cell'], []).append(word)
        with ThreadPoolExecutor(max_workers=frozen['max_workers']) as pool:
            futures = {pool.submit(cell_job, words): cid for cid, words in groups.items()}
            for future in as_completed(futures):
                rows.extend(future.result())
                print(json.dumps({'completed_words': len(rows), 'pass': p, 'cell': futures[future]}), flush=True)
    rows.sort(key=lambda row: row['id'])
    check_frozen(run, frozen, manifest)
    counts = Counter(verdict for row in rows for verdict in row['judgments'].values())
    action_counts = Counter(status for row in rows for status in row['action_status'].values())
    summary = {'schema': 'sandmark-session-summary-v1', 'kind': frozen['kind'], 'word_count': len(rows),
               'obligation_count': sum(counts.values()), 'judgments': dict(counts), 'action_status': dict(action_counts),
               'words': rows,
               'scope': 'Local declared judgments; paired lifecycle attribution is derived separately from these raw receipts.'}
    write_json(run / 'summary.json', summary)
    write_json(run / 'completion.json', {'completed_unix_ns': time.time_ns(), 'freeze_sha256': file_digest(run / 'freeze.json'),
                                       'summary_sha256': file_digest(run / 'summary.json'), 'word_count': len(rows),
                                       'source_bindings_after_execution': sources()})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('freeze', 'run'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--tool', type=Path)
    parser.add_argument('--kind', choices=('pilot', 'formal'), default='formal')
    parser.add_argument('--pilot-cells', nargs='+')
    parser.add_argument('--pilot-passes', type=int, nargs='+')
    parser.add_argument('--pilot-histories', choices=('AA', 'AAA', 'ABA'), nargs='+')
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if args.operation == 'freeze':
        if args.baseline is None or args.tool is None: parser.error('Freeze requires --baseline and --tool')
        result = freeze(args.output.resolve(), args.baseline.resolve(), args.tool.resolve(), kind=args.kind,
                        pilot_cells=args.pilot_cells, pilot_passes=args.pilot_passes,
                        pilot_histories=args.pilot_histories, workers=args.workers)
        print(json.dumps({'frozen': str(args.output), 'kind': result['kind'], 'sources': len(result['source_bindings'])}))
    else:
        result = acquire(args.output.resolve())
        print(json.dumps({'completed_words': result['word_count'], 'judgments': result['judgments']}))


if __name__ == '__main__': main()
