#!/usr/bin/env python3
"""Verify the LLWM study from retained bytes and raw command observations.

This receiver executes no native program or compiler and imports neither the
producer classifier nor ToolchainMark admission code. It reconstructs ordinary
guarded judgments, verifies artifact and input identities, and checks the exact
confirmation frame. It cannot independently attest the historical execution.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import copy
import hashlib
import itertools
import json
import math
from pathlib import Path, PurePosixPath
import re
import shlex
import struct

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent
EXECUTION_ROLES = ('unmarked-key', 'marked-key', 'unmarked-ordinary',
                   'marked-ordinary', 'relocated-key', 'stripped-key')
BUILD_ROLES = ('frontend', 'unmarked-link', 'embedding', 'marked-link')
MAIN_ROLES = BUILD_ROLES + EXECUTION_ROLES[:4] + (
    'relocated-key', 'debug-before', 'strip-debug', 'debug-after', 'stripped-key')
BOUNDARY_ROLES = BUILD_ROLES + EXECUTION_ROLES[:4]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read(path):
    return json.loads(Path(path).read_text())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(value):
    return base64.b64decode(value, validate=True)


def stdout(command):
    return decode(command['stdout_b64'])


def success(command):
    return command is not None and command.get('available') is True and command.get('returncode') == 0


def verify_identity(item, root):
    relative = Path(item['path'])
    require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe retained path')
    path = root / relative
    data = path.read_bytes()
    require(len(data) == item['bytes'] and sha(data) == item['sha256'], 'identity differs: ' + str(path))
    return data


def elf_section_names(data):
    """Read bounded names from the retained x86-64 ELF64 section table."""
    def region(offset, length):
        require(offset >= 0 and length >= 0 and offset + length <= len(data), 'invalid ELF range')
        return data[offset:offset + length]
    h = struct.unpack('<16sHHIQQQIHHHHHH', region(0, 64))
    require(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[2] == 62 and h[8] == 64 and h[11] == 64,
            'unsupported retained ELF layout')
    require(0 < h[13] < h[12] < 65535, 'unsupported retained ELF section numbering')
    table = [struct.unpack('<IIQQQQIIQQ', region(h[6] + 64 * i, 64)) for i in range(h[12])]
    entry = table[h[13]]
    strings = region(entry[4], entry[5])
    names = []
    for entry in table:
        offset = entry[0]
        require(0 <= offset < len(strings), 'invalid ELF section name offset')
        end = strings.find(b'\0', offset)
        require(end >= 0, 'unterminated ELF section name')
        names.append(strings[offset:end].decode('ascii'))
    return names


def readelf_section_names(raw):
    # GNU readelf -W -S emits a single unwrapped row for each section.
    names = []
    for line in raw.decode('utf-8').splitlines():
        match = re.match(r'\s*\[\s*(\d+)\]\s+(.*)', line)
        if match and int(match.group(1)):
            names.append(match.group(2).split()[0])
    return names


def decide(facts, predicate, mismatch):
    """Ordinary assertions with the same declared prerequisite information."""
    checked = {}
    for name, established in facts:
        checked[name] = bool(established)
        if not established:
            return {'verdict': 'INADMISSIBLE', 'reason': name, 'admission': checked}
    return {'verdict': 'SATISFIED' if predicate else 'INCONSISTENT',
            'reason': 'predicate-satisfied' if predicate else mismatch,
            'admission': checked}


def ordinary_judgments(row, evidence):
    """Derive all four judgments from raw observations and byte-derived facts."""
    commands = {c['role']: c for c in row['commands']}
    ok = lambda role: success(commands.get(role))
    observed = lambda role: stdout(commands[role]) if ok(role) else None
    build_completed = all(ok(role) for role in BUILD_ROLES)
    source_host = observed('unmarked-key')
    payload = row['payload'].encode('utf-8')
    expected = None if source_host is None else (
        payload + source_host if row['interface'] == 'fgets' else source_host + payload)
    literal = decide([
        ('construction_completed', build_completed),
        ('paired_key_invocations_completed', ok('unmarked-key') and ok('marked-key'))],
        observed('marked-key') == expected, 'literal-payload-output-mismatch')
    ordinary = decide([
        ('construction_completed', build_completed),
        ('paired_ordinary_invocations_completed', ok('unmarked-ordinary') and ok('marked-ordinary'))],
        observed('marked-ordinary') == observed('unmarked-ordinary'), 'ordinary-host-output-mismatch')
    source_valid = literal['verdict'] == 'SATISFIED'
    relocated = decide([
        ('source_payload_valid', source_valid),
        ('artifact_only_relocation', evidence['only_artifact']),
        ('relocated_bytes_identical', evidence['same_relocated_bytes']),
        ('relocated_invocation_completed', ok('relocated-key'))],
        observed('relocated-key') == observed('marked-key'), 'relocated-output-mismatch')
    stripped = decide([
        ('source_payload_valid', source_valid),
        ('debug_strip_completed', ok('strip-debug')),
        ('debug_removal_observed', evidence['debug_removed'] and ok('debug-before') and ok('debug-after')),
        ('stripped_invocation_completed', ok('stripped-key'))],
        observed('stripped-key') == observed('marked-key'), 'debug-strip-output-mismatch')
    return {'ER01': literal, 'ER02': ordinary, 'ER03': relocated, 'ER04': stripped}


def apply_patch_text(original, patch_lines):
    """Apply exact unified hunks in memory; no patch subprocess or fuzzy match."""
    src = original.splitlines(keepends=True)
    result = []
    consumed = 0
    index = 0
    removed = added = 0
    while index < len(patch_lines):
        match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', patch_lines[index])
        require(match is not None, 'invalid patch hunk header')
        start = int(match.group(1)) - 1
        require(start >= consumed, 'overlapping patch hunks')
        result.extend(src[consumed:start])
        consumed = start
        used_old = used_new = 0
        index += 1
        while index < len(patch_lines) and not patch_lines[index].startswith('@@ '):
            line = patch_lines[index]
            require(line[:1] in (' ', '+', '-'), 'unsupported patch instruction')
            if line[0] in (' ', '-'):
                require(consumed < len(src) and src[consumed] == line[1:], 'patch context differs')
                consumed += 1
                used_old += 1
            if line[0] in (' ', '+'):
                result.append(line[1:])
                used_new += 1
            removed += int(line[0] == '-')
            added += int(line[0] == '+')
            index += 1
        require(used_old == int(match.group(2) or '1') and used_new == int(match.group(4) or '1'),
                'patch hunk length differs')
    result.extend(src[consumed:])
    return ''.join(result), removed, added


def source_and_setup(run, plan, stats):
    inputs = read(run / 'producer-inputs.json')['inputs']
    paths = {x['path'] for x in inputs}
    require(len(paths) == len(inputs), 'duplicate producer input')

    # The retained acquisition binds the exact producer snapshot that created it.
    # Repository refactors may rename the public Python package or remove code that
    # was not on the executed path; those maintenance changes must not invalidate
    # an otherwise complete historical record.  We therefore require the fixed
    # historical module surface in the retained snapshot, while requiring current
    # equality only for the acquisition plan, probes, patch, and upstream source.
    historical_modules = {
        '__init__.py', 'accounting.py', 'admission.py', 'catalog.py', 'cli.py',
        'derive.py', 'evidence_boundary.py', 'evidence_catalog.py', 'integrity.py',
        'model.py', 'pipeline.py', 'recheck.py', 'record.py', 'relations.py',
        'runner.py', 'study_coverage.py', 'study_validation.py', 'trace_runtime.py',
        'transform_admission.py',
    }
    source_items = [item for item in inputs if PurePosixPath(item['path']).parts[:1] == ('src',)]
    require(source_items, 'historical producer source is missing')
    source_roots = {PurePosixPath(item['path']).parts[1] for item in source_items
                    if len(PurePosixPath(item['path']).parts) == 3}
    require(len(source_roots) == 1, 'historical producer package layout differs')
    source_root = next(iter(source_roots))
    # A new execution of the shipped producer snapshots the current package, whose
    # module surface is accepted as well; the snapshot bytes are still verified below.
    current_modules = {p.name for p in (ARTIFACT / 'src/toolchainmark').glob('*.py')}
    require({PurePosixPath(item['path']).name for item in source_items} in (historical_modules, current_modules),
            'historical producer module surface differs')
    require(all(PurePosixPath(item['path']).parts[:2] == ('src', source_root)
                and len(PurePosixPath(item['path']).parts) == 3 for item in source_items),
            'historical producer source layout differs')

    current_inputs = {'external_llwm/' + x for x in (
        'plan.json', 'acquisition.json', 'literal-output.patch', 'repair-identities.json')}
    historical_only = {'external_llwm/run_study.py'}
    current_inputs.update(p.relative_to(ARTIFACT).as_posix() for p in (HERE / 'vendor').rglob('*') if p.is_file())
    current_inputs.update(p.relative_to(ARTIFACT).as_posix() for p in (HERE / 'probes').glob('*.c'))
    require(paths == current_inputs | historical_only | {item['path'] for item in source_items},
            'producer input set differs')
    for item in inputs:
        snapshot = verify_identity(item, run / 'source-snapshot')
        if item['path'] in current_inputs:
            require(verify_identity(item, ARTIFACT) == snapshot,
                    'current acquisition input differs from retained snapshot')
    require(read(HERE / 'plan.json') == plan == read(run / 'source-snapshot/external_llwm/plan.json'),
            'copied/frozen plan differs')
    acquisition = read(HERE / 'acquisition.json')
    require(acquisition['archive_sha256'] == plan['archive_sha256'] and acquisition['doi'] == plan['source_doi'],
            'source deposit identity differs')
    vendor_files = {p.relative_to(HERE).as_posix() for p in (HERE / 'vendor').rglob('*') if p.is_file()}
    require({x['path'] for x in acquisition['upstream_files']} == vendor_files, 'upstream source list differs')
    for item in acquisition['upstream_files']:
        verify_identity(item, HERE)
    setup_files = read(run / 'setup/files.json')
    require({x['path'] for x in setup_files} == {
        p.relative_to(run).as_posix() for p in (run / 'setup').rglob('*')
        if p.is_file() and p.name != 'files.json'}, 'setup file set differs')
    for item in setup_files:
        verify_identity(item, run)
    repairs = read(HERE / 'repair-identities.json')
    patch = (HERE / 'literal-output.patch').read_text().splitlines(keepends=True)
    hunks = {}
    index = 0
    while index < len(patch):
        require(patch[index].startswith('--- a/') and patch[index + 1].startswith('+++ b/'), 'invalid patch file header')
        filename = patch[index][6:].strip()
        require(patch[index + 1][6:].strip() == filename and filename not in hunks, 'patch filename differs')
        index += 2
        start = index
        while index < len(patch) and not patch[index].startswith('--- a/'):
            index += 1
        hunks[filename] = patch[start:index]
    expected_repairs = {'include/llwm/semacall/AtoiPatcher.hpp',
                        'include/llwm/semacall/GetsPatcher.hpp', 'include/llwm/Sidedata.hpp'}
    require(set(repairs) == set(hunks) == expected_repairs, 'repair must change exactly the three declared headers')
    changed = []
    removed_lines = added_lines = 0
    for source in sorted((HERE / 'vendor').rglob('*')):
        if not source.is_file():
            continue
        rel = source.relative_to(HERE / 'vendor').as_posix()
        upstream = run / 'setup/upstream/source' / rel
        repaired = run / 'setup/literal-output-repair/source' / rel
        require(source.read_bytes() == upstream.read_bytes(), 'upstream setup changed vendor bytes')
        if rel in hunks:
            expected_text, removed, added = apply_patch_text(source.read_text(), hunks[rel])
            require(repaired.read_text() == expected_text, 'repaired setup differs from literal patch')
            require(sha(source.read_bytes()) == repairs[rel]['before'] and
                    sha(repaired.read_bytes()) == repairs[rel]['after'], 'repair hashes differ')
            changed.append(rel)
            removed_lines += removed
            added_lines += added
        else:
            require(source.read_bytes() == repaired.read_bytes(), 'undeclared vendor repair')
    require(removed_lines == added_lines == 6, 'repair must replace exactly six source lines')
    expected_vendor = {p.relative_to(HERE / 'vendor').as_posix() for p in (HERE / 'vendor').rglob('*') if p.is_file()}
    for variant in plan['variants']:
        directory = run / 'setup' / variant / 'source'
        require({p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()} ==
                expected_vendor | {'semacall-plugin.cpp', 'sidedata-plugin.cpp'}, 'setup source contains undeclared files')
        for name, cls in (('semacall', 'SemaCall'), ('sidedata', 'Sidedata')):
            expected_wrapper = '#include "llwm/' + name + '/' + cls + '.cpp"\n#include "lib/Passes/' + cls + '.cpp"\n'
            require((directory / (name + '-plugin.cpp')).read_text() == expected_wrapper, 'plugin wrapper differs')
    stats['producer_input_bindings'] = len(inputs)
    stats['setup_file_bindings'] = len(setup_files)
    stats['upstream_vendor_file_bindings'] = len(acquisition['upstream_files'])
    return {'changed_headers': changed, 'removed_lines': removed_lines, 'added_lines': added_lines,
            'scope': 'Exact comparison with the retained acquisition manifest and source snapshots. '
                     'The public archive identity is recorded; this receiver does not fetch or re-extract the deposit.'}


def command_layout(row, directory, tools):
    commands = row['commands']
    expected_roles = BOUNDARY_ROLES if row['boundary'] else MAIN_ROLES
    require(tuple(c['role'] for c in commands) == expected_roles, 'missing, duplicate, or reordered command role')
    by_role = {c['role']: c for c in commands}
    old_directory = Path(by_role['frontend']['cwd'])
    relative_case = Path('boundary' if row['boundary'] else 'cases') / row['case_id']
    require(old_directory.parts[-len(relative_case.parts):] == relative_case.parts, 'historical case path differs')
    old_run = old_directory
    for _ in relative_case.parts:
        old_run = old_run.parent
    old_probe = Path(by_role['frontend']['argv'][5])
    require(old_probe.parts[-3:] == ('external_llwm', 'probes', row['interface'] + '.c'), 'probe input differs')
    interface = row['interface']
    part = {'atoi': 'atoi', 'fgets': 'gets', 'sidedata': 'sidedata'}[interface]
    name = 'sidedata' if interface == 'sidedata' else 'semacall'
    plugin = old_run / 'setup' / row['variant'] / (name + '.so')
    original_ir, marked_ir = old_directory / 'unmarked.ll', old_directory / 'marked.ll'
    original, marked = old_directory / 'unmarked.bin', old_directory / 'marked.bin'
    expected = {
        'frontend': [tools['clang']['path'], '-O1', '-g', '-emit-llvm', '-S', str(old_probe), '-o', str(original_ir)],
        'unmarked-link': [tools['clang']['path'], '-g', '-' + row['optimization'], str(original_ir), '-o', str(original)],
        'embedding': [tools['opt']['path'], '-load-pass-plugin=' + str(plugin), '-passes=' + name + '-watermark',
                      '-' + part + '-key=' + row['key'], '-' + part + '-val=' + row['payload'],
                      '-S', str(original_ir), '-o', str(marked_ir)],
        'marked-link': [tools['clang']['path'], '-g', '-' + row['optimization'], str(marked_ir), '-o', str(marked)],
    }
    binary_roles = {'unmarked-key': ('unmarked.bin', row['key']), 'marked-key': ('marked.bin', row['key']),
                    'unmarked-ordinary': ('unmarked.bin', row['ordinary_input']),
                    'marked-ordinary': ('marked.bin', row['ordinary_input'])}
    if not row['boundary']:
        binary_roles.update({'relocated-key': ('relocated/program', row['key']), 'stripped-key': ('stripped.bin', row['key'])})
        expected.update({
            'debug-before': [tools['readelf']['path'], '-W', '-S', str(marked)],
            'strip-debug': [tools['strip']['path'], '--strip-debug', '-o', str(old_directory / 'stripped.bin'), str(marked)],
            'debug-after': [tools['readelf']['path'], '-W', '-S', str(old_directory / 'stripped.bin')],
        })
    for role, (binary, input_value) in binary_roles.items():
        expected[role] = [str(old_directory / binary)] + ([] if interface == 'fgets' else [input_value])
    for record in commands:
        role = record['role']
        require(record['argv'] == expected[role], 'command arguments differ: ' + role)
        require(success(record), 'retained confirmation command did not complete: ' + role)
        require(isinstance(record['seconds'], (int, float)) and record['seconds'] >= 0, 'invalid elapsed time')
        decode(record['stdout_b64'])
        decode(record['stderr_b64'])
        if role in binary_roles:
            binary, input_value = binary_roles[role]
            expected_stdin = (input_value + '\n').encode() if interface == 'fgets' else None
            actual_stdin = None if record['stdin_b64'] is None else decode(record['stdin_b64'])
            require(actual_stdin == expected_stdin, 'actual standard input differs: ' + role)
            require(record['cwd'] == str((old_directory / binary).parent), 'executable working directory differs')
            actual_digest = sha((directory / binary).read_bytes())
            require(record['binary_before_sha256'] == record['binary_after_sha256'] == actual_digest,
                    'executable identity changed or differs: ' + role)
        else:
            require(record['stdin_b64'] is None and record['cwd'] == str(old_directory), 'construction/tool context differs')
    return by_role, old_run, old_probe.parents[2]


def verify_case(row, run, plan, tools, stats):
    case_id = '/'.join((row['run'], row['variant'], row['interface'], row['payload_id'], row['optimization']))
    require(row['case_id'] == case_id, 'case id differs from tuple')
    if row['boundary']:
        boundary = plan['boundary_cases']
        require(row['interface'] == boundary['interface'] and row['payload_id'] == 'known-prefix-boundary' and
                row['payload'] == boundary['payload'] and row['key'] == boundary['key'] and
                row['ordinary_input'] == boundary['ordinary_input'], 'boundary input differs')
    else:
        require(row['payload'] == plan['payloads'][row['payload_id']] and row['key'] == plan['key'] and
                row['ordinary_input'] == plan['numeric_distinct_control'], 'main input differs')
    relative = Path('boundary' if row['boundary'] else 'cases') / case_id
    directory = run / relative
    expected_files = {'unmarked.ll', 'marked.ll', 'unmarked.bin', 'marked.bin'}
    if not row['boundary']:
        expected_files |= {'relocated/program', 'stripped.bin'}
    require({p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()} == expected_files,
            'retained case file set differs')
    require(len(row['files']) == len(expected_files) and {x['path'] for x in row['files']} ==
            {(relative / p).as_posix() for p in expected_files}, 'case file manifest differs')
    for item in row['files']:
        verify_identity(item, run)
        stats['case_file_bindings'] += 1
    commands, old_run, old_artifact = command_layout(row, directory, tools)
    stats['raw_command_records'] += len(commands)
    stats['executable_pre_post_bindings'] += len(EXECUTION_ROLES[:4] if row['boundary'] else EXECUTION_ROLES)
    if row['interface'] == 'fgets':
        stats['actual_stdin_checks'] += len(EXECUTION_ROLES)
    for filename in ('unmarked.bin', 'marked.bin'):
        elf_section_names((directory / filename).read_bytes())
    if row['boundary']:
        observed = {'paired_observations_available': True,
                    'correct_key_literal_payload': stdout(commands['marked-key']) == stdout(commands['unmarked-key']) + row['payload'].encode(),
                    'ordinary_output_changed': stdout(commands['marked-ordinary']) != stdout(commands['unmarked-ordinary'])}
        require(row['boundary_observations'] == observed, 'boundary observation summary differs')
        return {'commands': commands, 'boundary': observed, 'old_run': old_run, 'old_artifact': old_artifact}
    marked = (directory / 'marked.bin').read_bytes()
    relocated = (directory / 'relocated/program').read_bytes()
    before_names = elf_section_names(marked)
    after_names = elf_section_names((directory / 'stripped.bin').read_bytes())
    require(before_names[1:] == readelf_section_names(stdout(commands['debug-before'])), 'raw before readelf names differ from ELF')
    require(after_names[1:] == readelf_section_names(stdout(commands['debug-after'])), 'raw after readelf names differ from ELF')
    evidence = {'only_artifact': sorted(p.name for p in (directory / 'relocated').iterdir()) == ['program'],
                'same_relocated_bytes': marked == relocated,
                'debug_removed': '.debug_info' in before_names and not any(x.startswith('.debug_') for x in after_names)}
    require(row['relocation_only_artifact'] == evidence['only_artifact'] and
            row['relocated_bytes_identical'] == evidence['same_relocated_bytes'], 'recorded relocation fact differs from bytes/directory')
    verdicts = ordinary_judgments(row, evidence)
    require(row['verdicts'] == verdicts, 'scientific verdict/gate differs from raw ordinary oracle')
    stats['ordinary_verdict_comparisons'] += len(verdicts)
    stats['elf_debug_postconditions'] += 1
    # The restricted payloads use only %% formatting, so no missing printf
    # arguments or undefined format conversions are needed to explain the defect.
    emitted_payload = row['payload'].encode()
    if row['variant'] == 'upstream':
        emitted_payload = emitted_payload.replace(b'%%', b'%')
    host = stdout(commands['unmarked-key'])
    predicted = emitted_payload + host if row['interface'] == 'fgets' else host + emitted_payload
    require(stdout(commands['marked-key']) == predicted, 'observed output does not match the restricted printf explanation')
    stats['restricted_format_explanations'] += 1
    return {'commands': commands, 'verdicts': verdicts, 'evidence': evidence,
            'old_run': old_run, 'old_artifact': old_artifact}


def verify_setup_commands(run, plan, environment, old_run, old_artifact, stats):
    commands = read(run / 'setup/commands.json')
    roles = ['llvm-config', 'build-upstream-semacall', 'build-upstream-sidedata',
             'apply-literal-output-repair', 'build-literal-output-repair-semacall',
             'build-literal-output-repair-sidedata']
    require([c['role'] for c in commands] == roles, 'plugin setup commands differ')
    require(all(success(c) and c['stdin_b64'] is None for c in commands), 'plugin setup command unavailable')
    tools = environment['tools']
    cfg = commands[0]
    require(cfg['argv'] == [tools['llvm-config']['path'], '--cxxflags', '--ldflags', '--libs'], 'LLVM flags query differs')
    flags = shlex.split(stdout(cfg).decode())
    eigen = set()
    for record in commands[1:]:
        role = record['role']
        decode(record['stdout_b64'])
        decode(record['stderr_b64'])
        if role == 'apply-literal-output-repair':
            require(record['argv'] == ['patch', '-p1', '--fuzz=0', '-i', str(old_artifact / 'external_llwm/literal-output.patch')] and
                    record['cwd'] == str(old_run / 'setup/literal-output-repair/source'), 'repair command differs')
            continue
        variant = 'upstream' if role.startswith('build-upstream-') else 'literal-output-repair'
        name = role.rsplit('-', 1)[1]
        target = old_run / 'setup' / variant
        argv = record['argv']
        require(len(argv) >= 9 and argv[5].startswith('-I'), 'missing Eigen include directory')
        eigen.add(argv[5])
        expected = [tools['cxx']['path'], '-shared', '-fPIC', '-O2', '-I' + str(target / 'source/include'),
                    argv[5], *flags, str(target / 'source' / (name + '-plugin.cpp')), '-o', str(target / (name + '.so'))]
        require(argv == expected and record['cwd'] == str(target), 'plugin compilation arguments differ')
    require(len(eigen) == 1, 'plugin builds use differing Eigen include roots')
    stats['setup_command_records'] = len(commands)
    return commands


def negative_controls(sample, evidence, tools, run):
    """Alter copies in memory; retained execution records are never changed."""
    controls = []
    damaged = copy.deepcopy(sample)
    next(c for c in damaged['commands'] if c['role'] == 'marked-key')['stdout_b64'] = base64.b64encode(b'wrong output').decode()
    require(ordinary_judgments(damaged, evidence)['ER01']['verdict'] == 'INCONSISTENT', 'output negative control failed')
    controls.append('changed successful key stdout yields ER01 inconsistency')
    unavailable = copy.deepcopy(sample)
    next(c for c in unavailable['commands'] if c['role'] == 'embedding')['available'] = False
    require(ordinary_judgments(unavailable, evidence)['ER01']['verdict'] == 'INADMISSIBLE', 'unavailable construction control failed')
    controls.append('unavailable embedding yields ER01 inadmissibility')
    changed = dict(evidence, same_relocated_bytes=False)
    require(ordinary_judgments(sample, changed)['ER03']['verdict'] == 'INADMISSIBLE', 'relocation identity control failed')
    controls.append('different relocated bytes yield ER03 inadmissibility')
    changed = dict(evidence, debug_removed=False)
    require(ordinary_judgments(sample, changed)['ER04']['verdict'] == 'INADMISSIBLE', 'debug postcondition control failed')
    controls.append('unestablished debug removal yields ER04 inadmissibility')
    altered = copy.deepcopy(sample)
    next(c for c in altered['commands'] if c['role'] == 'marked-key')['stdin_b64'] = base64.b64encode(b'4321\n').decode()
    directory = run / 'cases' / sample['case_id']
    try:
        command_layout(altered, directory, tools)
    except AssertionError as error:
        require('standard input' in str(error), 'stdin control failed for unrelated reason')
    else:
        raise AssertionError('changed fgets standard input was accepted')
    controls.append('wrong retained fgets stdin is rejected by invocation binding')
    altered = copy.deepcopy(sample)
    next(c for c in altered['commands'] if c['role'] == 'marked-key')['binary_after_sha256'] = '0' * 64
    try:
        command_layout(altered, directory, tools)
    except AssertionError as error:
        require('identity' in str(error), 'binary identity control failed for unrelated reason')
    else:
        raise AssertionError('changed executable identity was accepted')
    controls.append('changed post-execution digest is rejected by executable binding')
    return {'count': len(controls), 'controls': controls,
            'scope': 'In-memory receiver controls; not additional native executions or empirical defects.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, default=ARTIFACT / 'results/llwm-native')
    args = parser.parse_args()
    run = args.run.resolve()
    plan = read(run / 'plan.json')
    environment = read(run / 'environment.json')
    completion = read(run / 'completion.json')
    summary = read(run / 'summary.json')
    stats = Counter()
    repairs = source_and_setup(run, plan, stats)
    require(plan['passes'] == ['first', 'second'], 'unexpected repeat frame')
    expected_main = set(itertools.product(plan['passes'], plan['variants'], plan['interfaces'],
                                         plan['payloads'], plan['optimization_levels']))
    boundary = plan['boundary_cases']
    expected_boundary = {(p, v, boundary['interface'], 'known-prefix-boundary', o)
                         for p, v, o in itertools.product(boundary['passes'], boundary['variants'], boundary['optimization_levels'])}
    require(len(expected_main) == plan['main_cases_total'] == plan['cases_per_pass'] * len(plan['passes']), 'main plan denominator differs')
    require(len(expected_boundary) == boundary['cases_total'], 'boundary plan denominator differs')
    require({x['path'] for x in completion['raw_files']} ==
            {p + suffix for p in plan['passes'] for suffix in ('.jsonl', '-boundary.jsonl')}, 'completion raw file set differs')
    for item in completion['raw_files']:
        verify_identity(item, run)
    all_rows = []
    for pass_name in plan['passes']:
        for suffix, boundary_flag in (('.jsonl', False), ('-boundary.jsonl', True)):
            rows = [json.loads(line) for line in (run / (pass_name + suffix)).read_text().splitlines()]
            require(all(r['run'] == pass_name and r['boundary'] is boundary_flag for r in rows), 'raw pass/denominator assignment differs')
            all_rows.extend(rows)
    records = {}
    rows_by_key = {}
    for row in all_rows:
        key = tuple(row[x] for x in ('run', 'variant', 'interface', 'payload_id', 'optimization'))
        require(key not in records, 'duplicate case tuple')
        rows_by_key[key] = row
        records[key] = verify_case(row, run, plan, environment['tools'], stats)
    main_keys = {k for k in records if not rows_by_key[k]['boundary']}
    boundary_keys = set(records) - main_keys
    require(main_keys == expected_main and boundary_keys == expected_boundary, 'actual Cartesian product differs')
    historical_runs = {r['old_run'] for r in records.values()}
    historical_artifacts = {r['old_artifact'] for r in records.values()}
    require(len(historical_runs) == len(historical_artifacts) == 1, 'mixed historical roots')
    setup_commands = verify_setup_commands(run, plan, environment, next(iter(historical_runs)), next(iter(historical_artifacts)), stats)
    require({r['role'] for r in environment['versions']} == {name + '-version' for name in environment['tools']}, 'version probe set differs')
    for record in environment['versions']:
        name = record['role'][:-8]
        require(success(record) and record['argv'] == [environment['tools'][name]['path'], '--version'], 'tool version probe differs')
        if name in ('clang', 'opt', 'llvm-config'):
            require('17.' in stdout(record).decode(), 'LLVM version differs from declared interface')
    counts = {variant: {relation: dict(Counter(records[k]['verdicts'][relation]['verdict'] for k in main_keys if k[1] == variant))
                       for relation in plan['relations']} for variant in plan['variants']}
    boundary_counts = {variant: dict(Counter(str(records[k]['boundary']['ordinary_output_changed'])
                                           for k in boundary_keys if k[1] == variant)) for variant in plan['variants']}
    require(summary['counts'] == counts and summary['boundary_counts'] == boundary_counts, 'summary counts differ')
    require(summary['cases'] == completion['main_rows'] == len(main_keys) and
            summary['boundary_cases'] == completion['boundary_rows'] == len(boundary_keys), 'completion denominator differs')
    require(summary['producer_input_count'] == stats['producer_input_bindings'] and
            summary['producer_inputs_unchanged'] is True and completion['producer_inputs_unchanged'] is True,
            'source completion differs')
    for name, selected in (('command_count', main_keys), ('boundary_command_count', boundary_keys)):
        require(summary[name] == sum(len(rows_by_key[k]['commands']) for k in selected), 'command denominator differs')
    require(summary['schema'] == plan['schema'] and summary['passes'] == len(plan['passes']) and
            summary['cases_per_pass'] == plan['cases_per_pass'] and summary['scope'] == plan['selection'], 'summary frame differs')
    for variant in plan['variants']:
        value = sum(rows_by_key[k]['seconds'] for k in main_keys if k[1] == variant)
        require(math.isclose(value, summary['timing']['main_case_seconds'][variant], rel_tol=1e-12), 'elapsed case aggregation differs')
    require(math.isclose(sum(r['seconds'] for r in setup_commands),
                        summary['timing']['plugin_setup_command_seconds'], rel_tol=1e-12), 'setup timing aggregation differs')
    boundary_differences = []
    for key in sorted(k for k in records if k[0] == 'first'):
        other = ('second',) + key[1:]
        left, right = records[key], records[other]
        semantic = 'boundary' if rows_by_key[key]['boundary'] else 'verdicts'
        require(left[semantic] == right[semantic], 'repeated scientific judgment differs')
        stats['repeated_case_judgments'] += 1
        for role in EXECUTION_ROLES[:4] if rows_by_key[key]['boundary'] else EXECUTION_ROLES:
            for field in ('available', 'returncode', 'stdin_b64', 'stdout_b64', 'stderr_b64'):
                same = left['commands'][role][field] == right['commands'][role][field]
                if rows_by_key[key]['boundary']:
                    if not same:
                        boundary_differences.append({'case': list(key[1:]), 'role': role, 'field': field,
                            'first': left['commands'][role][field], 'second': right['commands'][role][field]})
                    stats['boundary_repeated_execution_fields'] += 1
                else:
                    require(same, 'repeated main execution observation differs')
                    stats['main_repeated_execution_fields'] += 1
    sample_key = ('first', 'literal-output-repair', 'fgets', 'middle', 'O0')
    controls = negative_controls(rows_by_key[sample_key], records[sample_key]['evidence'], environment['tools'], run)
    report = {'verdict': 'PASS', 'main_cases': len(main_keys), 'boundary_cases': len(boundary_keys),
              'counts': counts, 'boundary_counts': boundary_counts, 'checks': dict(stats),
              'repair': repairs, 'negative_controls': controls,
              'repetition': {
                  'main_projection': ['scientific judgments and gate prefixes', 'native invocation availability',
                      'exit status', 'actual standard input', 'raw standard output', 'raw standard error'],
                  'main_projection_differences': [],
                  'boundary_projection_differences': boundary_differences,
                  'boundary_change_indicators_repeated': True,
                  'excluded_from_equality_claim': ['IR bytes', 'ELF bytes', 'randomized embedding choices',
                      'debug compilation paths', 'timings', 'complete command records'],
                  'interpretation': 'Main output/exit/input observations repeat. All known-prefix boundary '
                      'cases have extra output, but some raw output bytes vary between passes. '
                      'The boundary output is not treated as stable recovery of the requested payload.'},
              'scope': 'Receiver rederivation from retained raw standard input/output, command arguments, source snapshots, '
                       'directories and ELF bytes. Ordinary guarded checks receive the same information and agree with '
                       'all stored judgments; this is not an additional native baseline arm. The local repair is '
                       'confirmed in the retained executions, not claimed to be accepted or confirmed by maintainers. '
                       'No historical execution attestation, universal wrong-key rejection, production prevalence, '
                       'or whole-toolchain correctness is established.'}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
