#!/usr/bin/env python3
"""Freeze and execute paired native contract/GeMTest acquisitions."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent
sys.path.insert(0, str(ARTIFACT))
from framework_comparison.compare import summarize


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def frame_for(protocol):
    frame = []
    for run in protocol['passes']:
        for relation, spec in protocol['relations'].items():
            for carrier, implementation in itertools.product(protocol['carriers'], spec['conditions']):
                frame.append({'id': f'pass-{run}/{relation}/{carrier}/{implementation}',
                              'pass': run, 'relation': relation, 'carrier': carrier,
                              'implementation': implementation, 'family': spec['family']})
    return frame


def producer_files():
    paths = []
    for directory in [HERE, ARTIFACT / 'contract_runtime', ARTIFACT / 'src/toolchainmark']:
        paths += list(directory.glob('*.py'))
    paths += [ARTIFACT / 'declarative_study' / name for name in
              ['reference_adapter.py', 'state_words.py', 'build_plans.py', 'native_io.py']]
    paths += [HERE / 'protocol.json', ARTIFACT / 'hosts/H01-gcd.c']
    paths += [ARTIFACT / 'declarative_study/plans' / (name + '.json')
              for name in ['MR08', 'MR09', 'MR13', 'SR01']]
    return sorted(set(paths))


def freeze(output, protocol, frame, purpose):
    identities = []
    for path in producer_files():
        relative = path.relative_to(ARTIFACT)
        data = path.read_bytes()
        target = output / 'source-snapshot' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        identities.append({'path': relative.as_posix(), 'bytes': len(data),
                           'sha256': hashlib.sha256(data).hexdigest()})
    package = importlib.metadata.distribution('gemtest')
    native_package = []
    for entry in package.files:
        if str(entry).startswith('gemtest/') and str(entry).endswith('.py'):
            path = Path(package.locate_file(entry))
            data = path.read_bytes()
            target = output / 'source-snapshot/upstream' / str(entry)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            native_package.append({'path': str(entry), 'bytes': len(data),
                                   'sha256': hashlib.sha256(data).hexdigest()})
    result = {'study': 'native framework comparison', 'purpose': purpose,
              'frozen_utc': datetime.now(timezone.utc).isoformat(),
              'inputs': identities, 'gemtest_sources': native_package,
              'frame': frame, 'protocol': protocol,
              'environment': {'python': sys.version, 'gemtest': package.version,
                              'pytest': importlib.metadata.version('pytest')}}
    write(output / 'producer-freeze.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--pilot', action='store_true')
    args = parser.parse_args()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    protocol = json.loads((HERE / 'protocol.json').read_text())
    frame = frame_for(protocol)
    if args.pilot:
        selected = {('MR08', 'CLEAN'), ('MR08', 'M04'), ('MR09', 'CLEAN'),
                    ('MR09', 'M15'), ('MR13', 'cross-object'), ('MR13', 'replace-on-B'),
                    ('SR01', 'latch-1'), ('SR01', 'CLEAN')}
        frame = [case for case in frame if case['pass'] == 1 and case['carrier'] == 'string'
                 and (case['relation'], case['implementation']) in selected]
    elif len(frame) != protocol['expected_pairs']:
        raise ValueError('The declared frame size changed before execution.')
    write(output / 'protocol.json', protocol)
    write(output / 'frame.json', frame)
    frozen = freeze(output, protocol, frame, 'pilot' if args.pilot else 'formal')
    environment = os.environ.copy()
    environment['TOOLCHAINMARK_FRAMEWORK_RUN'] = str(output)
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    command = [sys.executable, '-B', '-m', 'pytest', str(HERE / 'gemtest_cases.py'),
               '--export-data', '-q', '--tb=no', '-p', 'no:cacheprovider',
               '--junitxml=' + str(output / 'pytest.xml')]
    start = time.perf_counter()
    with (output / 'pytest.stdout.txt').open('w') as stdout, (output / 'pytest.stderr.txt').open('w') as stderr:
        run = subprocess.run(command, cwd=HERE, env=environment, stdout=stdout, stderr=stderr)
    completed = datetime.now(timezone.utc).isoformat()
    changed = [item['path'] for item in frozen['inputs'] if
               hashlib.sha256((ARTIFACT / item['path']).read_bytes()).hexdigest() != item['sha256']]
    record = {'command': command, 'exit_code': run.returncode,
              'seconds': time.perf_counter() - start, 'completed_utc': completed,
              'producer_changes_during_run': changed}
    write(output / 'execution.json', record)
    if changed or run.returncode not in (0, 1):
        raise RuntimeError('Execution did not complete under the frozen protocol; inspect retained logs.')
    summary = summarize(output)
    summary['execution'] = record
    write(output / 'summary.json', summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
