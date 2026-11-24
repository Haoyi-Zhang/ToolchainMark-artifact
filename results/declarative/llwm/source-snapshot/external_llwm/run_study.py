#!/usr/bin/env python3
"""Execute the fixed LLWM native confirmation plan in a new output directory."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent
sys.path.insert(0, str(ARTIFACT / 'src'))
from tosem02.admission import Evidence, InadmissibleCase


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def identity(path, root):
    return {'path': path.relative_to(root).as_posix(), 'sha256': digest(path),
            'bytes': path.stat().st_size}


def command(role, args, records, *, cwd, stdin=None, executable=False):
    argv = [str(x) for x in args]
    row = {'role': role, 'argv': argv, 'cwd': str(cwd),
           'stdin_b64': None if stdin is None else base64.b64encode(stdin).decode()}
    if executable:
        row['binary_before_sha256'] = digest(argv[0])
    start = time.perf_counter()
    try:
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'} if executable else None
        result = subprocess.run(argv, cwd=cwd, input=stdin, capture_output=True,
                                timeout=45, env=env, check=False)
        row.update(returncode=result.returncode,
                   stdout_b64=base64.b64encode(result.stdout).decode(),
                   stderr_b64=base64.b64encode(result.stderr).decode(),
                   available=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        row.update(available=False, error=type(exc).__name__)
    row['seconds'] = time.perf_counter() - start
    if executable:
        row['binary_after_sha256'] = digest(argv[0])
    records.append(row)
    return row


def successful(row):
    return bool(row and row.get('available') and row.get('returncode') == 0)


def stdout(row):
    return base64.b64decode(row['stdout_b64'], validate=True)


def require_command(row):
    if not successful(row):
        raise RuntimeError('Command failed: ' + row['role'])
    return row


def judge(facts, predicate, reason):
    evidence = Evidence()
    try:
        for name, value in facts:
            evidence.require(name, value)
    except InadmissibleCase as exc:
        return {'verdict': 'INADMISSIBLE', 'reason': str(exc),
                'admission': evidence.facts}
    return {'verdict': 'SATISFIED' if predicate else 'INCONSISTENT',
            'reason': 'predicate-satisfied' if predicate else reason,
            'admission': evidence.facts}


def classify(row):
    """Current executable observation contract; receiver rederives separately."""
    by_role = {r['role']: r for r in row['commands']}
    ok = lambda role: successful(by_role.get(role))
    data = lambda role: stdout(by_role[role]) if ok(role) else b''
    build_ok = all(ok(role) for role in ('frontend', 'unmarked-link', 'embedding', 'marked-link'))
    expected = (row['payload'].encode() + data('unmarked-key') if row['interface'] == 'fgets'
                else data('unmarked-key') + row['payload'].encode())
    v = {}
    v['ER01'] = judge([('construction_completed', build_ok),
                      ('paired_key_invocations_completed', ok('unmarked-key') and ok('marked-key'))],
                     data('marked-key') == expected, 'literal-payload-output-mismatch')
    v['ER02'] = judge([('construction_completed', build_ok),
                      ('paired_ordinary_invocations_completed', ok('unmarked-ordinary') and ok('marked-ordinary'))],
                     data('marked-ordinary') == data('unmarked-ordinary'), 'ordinary-host-output-mismatch')
    source_ok = v['ER01']['verdict'] == 'SATISFIED'
    v['ER03'] = judge([('source_payload_valid', source_ok),
                      ('artifact_only_relocation', row.get('relocation_only_artifact') is True),
                      ('relocated_bytes_identical', row.get('relocated_bytes_identical') is True),
                      ('relocated_invocation_completed', ok('relocated-key'))],
                     data('relocated-key') == data('marked-key'), 'relocated-output-mismatch')
    debug_removed = (ok('debug-before') and ok('debug-after') and
                     b'.debug_info' in data('debug-before') and b'.debug_' not in data('debug-after'))
    v['ER04'] = judge([('source_payload_valid', source_ok),
                      ('debug_strip_completed', ok('strip-debug')),
                      ('debug_removal_observed', debug_removed),
                      ('stripped_invocation_completed', ok('stripped-key'))],
                     data('stripped-key') == data('marked-key'), 'debug-strip-output-mismatch')
    return v


def build_plugins(out, tools, eigen, cxx):
    setup = out / 'setup'
    setup.mkdir()
    records = []
    cfg = require_command(command('llvm-config', [tools['llvm-config'], '--cxxflags', '--ldflags', '--libs'],
                                  records, cwd=setup))
    flags = shlex.split(stdout(cfg).decode())
    plugins = {}
    repairs = json.loads((HERE / 'repair-identities.json').read_text())
    for variant in ('upstream', 'literal-output-repair'):
        target = setup / variant
        shutil.copytree(HERE / 'vendor', target / 'source')
        if variant != 'upstream':
            require_command(command('apply-literal-output-repair',
                            ['patch', '-p1', '--fuzz=0', '-i', HERE / 'literal-output.patch'],
                            records, cwd=target / 'source'))
        for rel, hashes in repairs.items():
            wanted = hashes['before' if variant == 'upstream' else 'after']
            if digest(target / 'source' / rel) != wanted:
                raise ValueError('Source/repair identity differs: ' + rel)
        for name, cls in [('semacall', 'SemaCall'), ('sidedata', 'Sidedata')]:
            wrapper = target / 'source' / (name + '-plugin.cpp')
            wrapper.write_text('#include "llwm/' + name + '/' + cls + '.cpp"\n'
                               '#include "lib/Passes/' + cls + '.cpp"\n')
            plugin = target / (name + '.so')
            require_command(command('build-' + variant + '-' + name,
                            [cxx, '-shared', '-fPIC', '-O2', '-I' + str(target / 'source/include'),
                             '-I' + str(eigen), *flags, wrapper, '-o', plugin], records, cwd=target))
            plugins[(variant, name)] = plugin
    write_json(setup / 'commands.json', records)
    write_json(setup / 'files.json', [identity(p, out) for p in sorted(setup.rglob('*'))
                                    if p.is_file() and p.name != 'files.json'])
    return plugins, records


def execute_case(out, tools, plugins, run, variant, interface, payload_id, payload,
                 optimization, *, key='1234', ordinary='4321', boundary=False):
    start = time.perf_counter()
    case_id = '/'.join((run, variant, interface, payload_id, optimization))
    directory = out / ('boundary' if boundary else 'cases') / case_id
    directory.mkdir(parents=True)
    records = []
    source = HERE / 'probes' / (interface + '.c')
    original_ir, marked_ir = directory / 'unmarked.ll', directory / 'marked.ll'
    unmarked, marked = directory / 'unmarked.bin', directory / 'marked.bin'
    row = {'case_id': case_id, 'run': run, 'variant': variant, 'interface': interface,
           'payload_id': payload_id, 'payload': payload, 'key': key,
           'ordinary_input': ordinary, 'optimization': optimization,
           'boundary': boundary, 'commands': records}
    built = successful(command('frontend', [tools['clang'], '-O1', '-g', '-emit-llvm', '-S', source,
                                            '-o', original_ir], records, cwd=directory))
    if built:
        base_link = command('unmarked-link', [tools['clang'], '-g', '-' + optimization, original_ir,
                                              '-o', unmarked], records, cwd=directory)
        part = 'atoi' if interface == 'atoi' else 'gets' if interface == 'fgets' else 'sidedata'
        name = 'sidedata' if interface == 'sidedata' else 'semacall'
        embedding = command('embedding', [tools['opt'], '-load-pass-plugin=' + str(plugins[(variant, name)]),
                            '-passes=' + name + '-watermark', '-' + part + '-key=' + key,
                            '-' + part + '-val=' + payload, '-S', original_ir, '-o', marked_ir],
                            records, cwd=directory)
        marked_link = (command('marked-link', [tools['clang'], '-g', '-' + optimization, marked_ir,
                                               '-o', marked], records, cwd=directory)
                       if successful(embedding) else None)
        built = successful(base_link) and successful(marked_link)
    if built:
        def invoke(role, binary, input_value):
            stdin = (input_value + '\n').encode() if interface == 'fgets' else None
            args = [binary] + ([] if interface == 'fgets' else [input_value])
            return command(role, args, records, cwd=binary.parent, stdin=stdin, executable=True)
        invoke('unmarked-key', unmarked, key)
        invoke('marked-key', marked, key)
        invoke('unmarked-ordinary', unmarked, ordinary)
        invoke('marked-ordinary', marked, ordinary)
        if not boundary:
            moved = directory / 'relocated'
            moved.mkdir()
            relocated = moved / 'program'
            shutil.copy2(marked, relocated)
            row['relocation_only_artifact'] = sorted(p.name for p in moved.iterdir()) == ['program']
            row['relocated_bytes_identical'] = marked.read_bytes() == relocated.read_bytes()
            invoke('relocated-key', relocated, key)
            stripped = directory / 'stripped.bin'
            command('debug-before', [tools['readelf'], '-W', '-S', marked], records, cwd=directory)
            strip_result = command('strip-debug', [tools['strip'], '--strip-debug', '-o', stripped, marked],
                                   records, cwd=directory)
            if successful(strip_result) and stripped.is_file():
                command('debug-after', [tools['readelf'], '-W', '-S', stripped], records, cwd=directory)
                invoke('stripped-key', stripped, key)
    if boundary:
        roles = {r['role']: r for r in records}
        available = all(successful(roles.get(s)) for s in ('unmarked-key', 'marked-key',
                                                          'unmarked-ordinary', 'marked-ordinary'))
        row['boundary_observations'] = {'paired_observations_available': available}
        if available:
            row['boundary_observations'].update(
                correct_key_literal_payload=stdout(roles['marked-key']) == stdout(roles['unmarked-key']) + payload.encode(),
                ordinary_output_changed=stdout(roles['marked-ordinary']) != stdout(roles['unmarked-ordinary']))
    else:
        row['verdicts'] = classify(row)
    row['files'] = [identity(p, out) for p in sorted(directory.rglob('*')) if p.is_file()]
    row['seconds'] = time.perf_counter() - start
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--llvm-bin', required=True, type=Path)
    parser.add_argument('--eigen-include', default=Path('/usr/include/eigen3'), type=Path)
    parser.add_argument('--cxx', default='g++')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plan = json.loads((HERE / 'plan.json').read_text())
    write_json(out / 'plan.json', plan)
    paths = [HERE / n for n in ('run_study.py', 'plan.json', 'acquisition.json',
                                'literal-output.patch', 'repair-identities.json')]
    paths += sorted((HERE / 'vendor').rglob('*')) + sorted((HERE / 'probes').glob('*.c'))
    paths += sorted((ARTIFACT / 'src/tosem02').glob('*.py'))
    frozen = [identity(p, ARTIFACT) for p in paths if p.is_file()]
    write_json(out / 'producer-inputs.json', {'created_utc': datetime.now(timezone.utc).isoformat(),
                                            'inputs': frozen})
    for row in frozen:
        target = out / 'source-snapshot' / row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ARTIFACT / row['path'], target)
    tools = {name: (args.llvm_bin / name).resolve() for name in ('clang', 'opt', 'llvm-config')}
    tools.update({name: Path(shutil.which(name) or name).resolve() for name in ('strip', 'readelf')})
    tools['cxx'] = Path(shutil.which(args.cxx) or args.cxx).resolve()
    probe_records = []
    for name, path in tools.items():
        result = require_command(command(name + '-version', [path, '--version'], probe_records, cwd=out))
        if name in ('clang', 'opt', 'llvm-config') and '17.' not in stdout(result).decode():
            raise ValueError('The declared upstream interface requires LLVM 17')
    write_json(out / 'environment.json', {'python': sys.version, 'platform': platform.platform(),
                'machine': platform.machine(), 'cpu_count': os.cpu_count(), 'versions': probe_records,
                'tools': {name: {'path': str(path), 'sha256': digest(path)} for name, path in tools.items()}})
    started = time.perf_counter()
    plugins, setup_records = build_plugins(out, tools, args.eigen_include.resolve(), str(tools['cxx']))
    all_rows, boundary_rows = [], []
    pass_times = {}
    for run in plan['passes']:
        pass_start = time.perf_counter()
        with (out / (run + '.jsonl')).open('x') as stream:
            for variant, interface, (payload_id, payload), optimization in itertools.product(
                    plan['variants'], plan['interfaces'], plan['payloads'].items(), plan['optimization_levels']):
                row = execute_case(out, tools, plugins, run, variant, interface, payload_id, payload, optimization)
                stream.write(json.dumps(row, sort_keys=True) + '\n'); stream.flush(); all_rows.append(row)
        with (out / (run + '-boundary.jsonl')).open('x') as stream:
            boundary = plan['boundary_cases']
            for variant, optimization in itertools.product(plan['variants'], plan['optimization_levels']):
                row = execute_case(out, tools, plugins, run, variant, 'atoi', 'known-prefix-boundary',
                    boundary['payload'], optimization, key=boundary['key'], ordinary=boundary['ordinary_input'], boundary=True)
                stream.write(json.dumps(row, sort_keys=True) + '\n'); stream.flush(); boundary_rows.append(row)
        pass_times[run] = time.perf_counter() - pass_start
        print(run, 'completed', flush=True)
    unchanged = all(digest(ARTIFACT / row['path']) == row['sha256'] for row in frozen)
    counts = {}
    for variant in plan['variants']:
        counts[variant] = {relation: dict(Counter(row['verdicts'][relation]['verdict'] for row in all_rows
                           if row['variant'] == variant)) for relation in plan['relations']}
    summary = {'schema': plan['schema'], 'cases': len(all_rows), 'cases_per_pass': plan['cases_per_pass'],
               'passes': len(plan['passes']), 'counts': counts, 'boundary_cases': len(boundary_rows),
               'boundary_counts': {variant: dict(Counter(str(row['boundary_observations'].get('ordinary_output_changed'))
                    for row in boundary_rows if row['variant'] == variant)) for variant in plan['variants']},
               'producer_inputs_unchanged': unchanged, 'producer_input_count': len(frozen),
               'command_count': sum(len(row['commands']) for row in all_rows),
               'boundary_command_count': sum(len(row['commands']) for row in boundary_rows),
               'timing': {'total_seconds_including_setup': time.perf_counter() - started,
                          'plugin_setup_command_seconds': sum(r['seconds'] for r in setup_records),
                          'pass_seconds_including_boundary': pass_times,
                          'main_case_seconds': {variant: sum(r['seconds'] for r in all_rows if r['variant'] == variant)
                                                for variant in plan['variants']}},
               'scope': plan['selection']}
    write_json(out / 'summary.json', summary)
    write_json(out / 'completion.json', {'completed_utc': datetime.now(timezone.utc).isoformat(),
                 'producer_inputs_unchanged': unchanged, 'main_rows': len(all_rows), 'boundary_rows': len(boundary_rows),
                 'raw_files': [identity(out / name, out) for name in
                     ('first.jsonl', 'second.jsonl', 'first-boundary.jsonl', 'second-boundary.jsonl')]})
    if not unchanged:
        raise RuntimeError('Producer changed during execution')
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
