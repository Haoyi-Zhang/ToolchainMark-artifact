"""Randomized and boundary host-input extension of the host-behaviour relation.

The catalog's host-behaviour relation (MR02) compares marked and unmarked
builds on six fixed integer inputs and standard output only.  This activity
asks whether a larger, predeclared input set and a stronger observation
(exit status, standard output, and standard error) change any judgment, and
whether sanitizer builds report undefined behaviour on any host input.

    python -B input_extension/run.py freeze  --out DIR    # writes DIR/protocol.json
    python -B input_extension/run.py execute --out DIR [--workers N]

``freeze`` fixes the input values, the case frame, and the source identities
before any build.  ``execute`` refuses to run if any frozen source changed or
if DIR already holds results.  Raw observations are written to
DIR/observations.jsonl.gz; ``verify.py`` recomputes every verdict from them.
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import datetime as dt
import gzip
import hashlib
import itertools
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT / 'src'))

from toolchainmark.model import BuildRequest  # noqa: E402
from toolchainmark.pipeline import Pipeline, _host_compile_flags  # noqa: E402
from toolchainmark.relations import INPUTS, KEY1, PAYLOAD1  # noqa: E402

SCHEMA = 'toolchainmark-input-extension-v1'
HOSTS = sorted(p.name for p in (ARTIFACT / 'hosts').glob('H*.c'))
CARRIERS = ('string', 'symbol', 'section')
VARIANTS = ('CLEAN', 'M10', 'M11')
CONFIGS = tuple(itertools.product(('gcc', 'clang'), ('O0', 'O2', 'Os')))
SANITIZER_FLAGS = ['-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                   '-fno-omit-frame-pointer']
TIMEOUT = 5
FROZEN_SOURCES = ['input_extension/run.py', 'src/toolchainmark/pipeline.py', 'src/toolchainmark/record.py',
                  'src/toolchainmark/model.py', 'src/toolchainmark/relations.py',
                  'src/toolchainmark/evidence_boundary.py'] + [f'hosts/{h}' for h in HOSTS]


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def input_sets():
    seed_material = hashlib.sha256(SCHEMA.encode()).digest()
    rng = random.Random(int.from_bytes(seed_material[:8], 'big'))
    randomized = [str(rng.getrandbits(64)) for _ in range(64)]
    return {
        'fixed': [str(v) for v in INPUTS],
        'boundary': [str(2**32 - 1), str(2**32), str(2**63 - 1), str(2**63), str(2**64 - 1)],
        'randomized': randomized,
        'malformed': ['abc', '12x', '18446744073709551616'],
    }


def frame():
    cases = []
    for host, carrier, variant, (compiler, opt) in itertools.product(HOSTS, CARRIERS, VARIANTS, CONFIGS):
        cases.append({'id': f'{host[:-2]}/{carrier}/{variant}/{compiler}-{opt}', 'host': host,
                      'carrier': carrier, 'variant': variant, 'compiler': compiler, 'optimization': opt})
    sanitizer = []
    for host, form in itertools.product(HOSTS, ('unmarked', 'string', 'symbol')):
        sanitizer.append({'id': f'{host[:-2]}/sanitizer/{form}', 'host': host, 'form': form})
    return cases, sanitizer


def tool_version(name):
    try:
        out = subprocess.run([name, '--version'], capture_output=True, text=True, timeout=10)
        return out.stdout.splitlines()[0] if out.stdout else out.stderr.strip()
    except OSError as error:
        return f'unavailable: {error}'


def freeze(out: Path):
    out.mkdir(parents=True, exist_ok=False)
    cases, sanitizer = frame()
    protocol = {
        'schema': SCHEMA,
        'frozen_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'question': ('Do a larger predeclared input set and the full process observation (exit status, '
                     'stdout, stderr) change any marked-versus-unmarked host judgment, and do sanitizer '
                     'builds report undefined behaviour on any input?'),
        'inputs': input_sets(),
        'random_seed_rule': 'first 8 bytes of SHA-256 of the schema name, big-endian, Python random.Random, 64 draws of getrandbits(64)',
        'observation': 'exit status, exact stdout bytes, exact stderr bytes; timeout %d s per execution' % TIMEOUT,
        'verdict_rule': ('For an input set S: INADMISSIBLE if either build failed or any execution in S timed out '
                         'or could not be launched; SATISFIED if the marked and unmarked observation triples are '
                         'equal on every input of S; otherwise INCONSISTENT.'),
        'cross_configuration_rule': ('For each host, the six unmarked CLEAN string-carrier builds must give equal '
                                     'observation triples on every input; a difference is reported, not repaired.'),
        'sanitizer_rule': ('gcc %s on the unmarked, string-marked and symbol-marked CLEAN source; a finding is any '
                           'run whose stderr contains a sanitizer report or whose exit status is the sanitizer '
                           'failure status.') % ' '.join(SANITIZER_FLAGS),
        'payload': PAYLOAD1.decode(), 'key': KEY1,
        'cases': cases, 'sanitizer_cases': sanitizer,
        'expected_counts': {'cases': len(cases), 'sanitizer_cases': len(sanitizer)},
        'success_criterion': 'None; every verdict is reported as observed.',
        'sources': {name: sha_bytes((ARTIFACT / name).read_bytes()) for name in FROZEN_SOURCES},
        'tools': {name: tool_version(name) for name in ('gcc', 'clang', 'objcopy', 'strip', 'nm')},
        'python': sys.version.split()[0], 'platform': platform.platform(),
    }
    (out / 'protocol.json').write_text(json.dumps(protocol, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'frozen': str(out / 'protocol.json'), **protocol['expected_counts']}))


def execute_binary(binary: Path, argument: str):
    try:
        proc = subprocess.run([str(binary), argument], capture_output=True, timeout=TIMEOUT)
        return {'status': 'OK', 'exit': proc.returncode,
                'stdout': proc.stdout.decode('utf-8', 'backslashreplace'),
                'stderr': proc.stderr.decode('utf-8', 'backslashreplace')}
    except subprocess.TimeoutExpired:
        return {'status': 'UNAVAILABLE', 'reason': 'timeout'}
    except OSError as error:
        return {'status': 'UNAVAILABLE', 'reason': f'launch: {error}'}


def all_inputs(protocol):
    return [(name, value) for name in ('fixed', 'boundary', 'randomized', 'malformed')
            for value in protocol['inputs'][name]]


def run_case(case, protocol, scratch):
    work = Path(tempfile.mkdtemp(dir=scratch))
    started = time.perf_counter()
    record = {'id': case['id'], 'builds': {}}
    try:
        for marked in (False, True):
            arm = 'marked' if marked else 'unmarked'
            pipeline = Pipeline(case['carrier'], case['variant'])
            try:
                result = pipeline.build(BuildRequest(ARTIFACT / 'hosts' / case['host'], PAYLOAD1, KEY1,
                                                     case['compiler'], case['optimization'], work / arm,
                                                     marked=marked))
            except Exception as error:  # build failure is an unavailable observation
                record['builds'][arm] = {'status': 'UNAVAILABLE', 'reason': f'{type(error).__name__}: {error}'}
                continue
            runs = [{'set': name, 'input': value, **execute_binary(result.binary, value)}
                    for name, value in all_inputs(protocol)]
            record['builds'][arm] = {'status': 'OK', 'binary_sha256': result.binary_sha256,
                                     'source_sha256': result.source_sha256,
                                     'command': ['SRC' if c == str(result.source) else 'BIN' if c == str(result.binary)
                                                 else c for c in result.command],
                                     'runs': runs}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    record['seconds'] = time.perf_counter() - started
    return record


def run_sanitizer(case, protocol, scratch):
    work = Path(tempfile.mkdtemp(dir=scratch))
    record = {'id': case['id']}
    try:
        host = ARTIFACT / 'hosts' / case['host']
        if case['form'] == 'unmarked':
            source = host
        else:
            built = Pipeline(case['form'], 'CLEAN').build(BuildRequest(host, PAYLOAD1, KEY1, 'gcc', 'O2', work / 'm'))
            source = built.source
        compile_flags, link_flags = _host_compile_flags(host)
        binary = work / 'san.bin'
        command = ['gcc', '-std=c11', *SANITIZER_FLAGS, *compile_flags, str(source), '-o', str(binary), *link_flags]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            record.update(status='UNAVAILABLE', reason=proc.stderr.strip()[-500:])
            return record
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:exitcode=97', UBSAN_OPTIONS='print_stacktrace=1:exitcode=98')
        runs = []
        for name, value in all_inputs(protocol):
            try:
                p = subprocess.run([str(binary), value], capture_output=True, timeout=TIMEOUT * 4, env=env)
                runs.append({'set': name, 'input': value, 'status': 'OK', 'exit': p.returncode,
                             'stdout': p.stdout.decode('utf-8', 'backslashreplace'),
                             'stderr': p.stderr.decode('utf-8', 'backslashreplace')[-2000:]})
            except subprocess.TimeoutExpired:
                runs.append({'set': name, 'input': value, 'status': 'UNAVAILABLE', 'reason': 'timeout'})
        record.update(status='OK', runs=runs)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return record


def execute(out: Path, workers: int):
    protocol = json.loads((out / 'protocol.json').read_text())
    for name, digest in protocol['sources'].items():
        if sha_bytes((ARTIFACT / name).read_bytes()) != digest:
            raise SystemExit(f'frozen source changed after freeze: {name}')
    if (out / 'observations.jsonl.gz').exists():
        raise SystemExit('results already exist; use a new directory')
    scratch = Path(tempfile.mkdtemp(prefix='tm-input-ext-'))
    started_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    t0 = time.perf_counter()
    rows = {}
    with futures.ProcessPoolExecutor(max_workers=workers) as pool:
        jobs = {pool.submit(run_case, case, protocol, str(scratch)): case['id'] for case in protocol['cases']}
        jobs.update({pool.submit(run_sanitizer, case, protocol, str(scratch)): case['id']
                     for case in protocol['sanitizer_cases']})
        for job in futures.as_completed(jobs):
            row = job.result()
            rows[row['id']] = row
    elapsed = time.perf_counter() - t0
    shutil.rmtree(scratch, ignore_errors=True)
    order = [c['id'] for c in protocol['cases']] + [c['id'] for c in protocol['sanitizer_cases']]
    with gzip.open(out / 'observations.jsonl.gz', 'wt', encoding='utf-8') as stream:
        for case_id in order:
            stream.write(json.dumps(rows[case_id], sort_keys=True) + '\n')
    completion = {'schema': SCHEMA + '-completion', 'started_utc': started_utc,
                  'completed_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'elapsed_seconds': elapsed, 'workers': workers, 'records': len(order),
                  'observations_sha256': sha_bytes((out / 'observations.jsonl.gz').read_bytes())}
    (out / 'completion.json').write_text(json.dumps(completion, indent=2, sort_keys=True) + '\n')
    print(json.dumps(completion, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('freeze', 'execute'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=os.cpu_count() or 2)
    args = parser.parse_args(argv)
    if args.mode == 'freeze':
        freeze(args.out)
    else:
        execute(args.out, args.workers)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
