#!/usr/bin/env python3
"""Independently re-evaluate contracts and bind action values to saved native evidence."""
from __future__ import annotations
import argparse
from collections import Counter
import importlib.util
import hashlib
import re
import struct
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.receiver import verify_receipt
from declarative_study.native_io import verify_file, verify_evidence, sha

_SPEC = importlib.util.spec_from_file_location('independent_v5_byte_observer',
    ARTIFACT / 'independent_observers/producer-v2/independent_observer.py')
_PARSER = importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(_PARSER)


def need(condition, message):
    if not condition: raise ValueError(message)


def reobserve_material(raw, carrier, key, source_material=None):
    """Separate implementation of the precise representation-local intervention view."""
    if carrier == 'symbol':
        table = _PARSER.sections(raw); names = []
        for _, entry in table:
            if entry[1] != 2: continue
            need(entry[9] == 24 and entry[5] % 24 == 0, 'unsupported symbol layout')
            strings = table[entry[6]][1]
            text = _PARSER.bounded(raw, strings[4], strings[5])
            for offset in range(entry[4], entry[4] + entry[5], 24):
                symbol = struct.unpack('<IBBHQQ', _PARSER.bounded(raw, offset, 24))
                if symbol[1] >> 4 in (1, 2, 10):
                    name = _PARSER.name_at(text, symbol[0])
                    if name.startswith('wmrec_'): names.append(name)
        rows = []
        for name in names:
            fields = name.split('_')[1:]
            need(len(fields) == 6 and all(re.fullmatch('[0-9a-f]+', x) for x in fields), 'invalid carrier symbol')
            rows.append((fields[:-1], fields[-1]))
        rows.sort()
        need(bool(rows), 'empty symbol material')
        chunks = sorted((int(fields[2], 16), bytes.fromhex(fields[4])) for fields, _ in rows)
        length = int(rows[0][0][1], 16)
        payload_bytes = b''.join(chunk for _, chunk in chunks)[:length]
        return {'protected': [fields for fields, _ in rows],
                'checksums': [checksum for _, checksum in rows], 'payload_hex': payload_bytes.hex()}
    view = raw
    if carrier == 'section':
        hits = [sh for name, sh in _PARSER.sections(raw) if name == '.wmrec']
        need(len(hits) == 1, 'missing/ambiguous checksum section')
        view = _PARSER.bounded(raw, hits[0][4], hits[0][5])
    encoded_key = key.encode()
    def decode_at(start):
        need(view[start:start+4] == b'WMR2' and view[start+4] == 1, 'invalid checksum record')
        need(view[start+5:start+13] == hashlib.sha256(encoded_key).digest()[:8], 'key tag differs')
        length = int.from_bytes(view[start+13:start+15], 'big'); end = start + 15 + length + 8
        need(end <= len(view), 'checksum record overrun')
        stream = b''.join(hashlib.sha256(encoded_key + i.to_bytes(4, 'big')).digest() for i in range((length+31)//32))
        payload_bytes = bytes(a ^ b for a, b in zip(view[start+15:start+15+length], stream))
        return end, payload_bytes
    if source_material is None:
        offset = 0
        while True:
            start = view.find(b'WMR2', offset)
            need(start >= 0, 'no independently accepted source record')
            offset = start + 1
            try:
                end, payload_bytes = decode_at(start)
            except (ValueError, IndexError):
                continue
            if hashlib.sha256(payload_bytes).digest()[:8] == view[end-8:end]: break
    else:
        start, wanted_end = source_material['protected'][:2]
        end, payload_bytes = decode_at(start)
        need(end == wanted_end, 'followup does not retain source record bounds')
    return {'protected': [start, end, len(view), {'bytes_hex': view[:end-8].hex()}, {'bytes_hex': view[end:].hex()}],
            'checksums': [view[end-8:end].hex()], 'payload_hex': payload_bytes.hex()}


def llvm_binding_context(store):
    """Load byte identities independently of any one action's returned values."""
    store = Path(store)
    freeze = json.loads((store / 'producer-freeze.json').read_text())
    probes = {}
    for row in freeze['inputs']:
        if row['path'].startswith('external_llwm/probes/') and row['path'].endswith('.c'):
            raw = (store / 'source-snapshot' / row['path']).read_bytes()
            need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'frozen LLWM probe identity differs')
            need(row['path'] not in probes, 'duplicate frozen LLWM probe identity')
            probes[row['path']] = row
    setup = {}
    for row in json.loads((store / 'setup/files.json').read_text()):
        relative = Path(row['path'])
        need(not relative.is_absolute() and relative.parts and relative.parts[0] == 'setup'
             and '..' not in relative.parts and row['path'] not in setup, 'invalid/duplicate LLWM setup identity')
        raw = (store / relative).read_bytes()
        need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'LLWM setup bytes differ from manifest')
        setup[row['path']] = row
    return {'probes': probes, 'setup': setup}


def _same_bytes(left, right):
    return (type(left['bytes']) is int and type(right['bytes']) is int
            and left['sha256'] == right['sha256'] and left['bytes'] == right['bytes'])


def _same_json(left, right):
    # Python's equality aliases booleans and integers; JSON record types do not.
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return encode(left) == encode(right)


def _successful(command, description):
    need(command.get('status') == 'COMPLETED' and type(command.get('returncode')) is int
         and command['returncode'] == 0, description + ' lacks a successful native command')
    need(type(command.get('argv')) is list and bool(command['argv'])
         and all(type(token) is str for token in command['argv']), description + ' has an invalid argv')


def _process_target_binding(command, before, after, description, *, require_executable=False):
    """Bind already recorded process target versions to the action endpoints.

    This checks explicit observations only. It does not infer the bytes read
    between observations or attest that a historical process was executed.
    """
    need(before['path'] == after['path'], description + ' has different endpoint paths')
    for endpoint, wanted in (('files_before', before), ('files_after', after)):
        rows = [row for row in command[endpoint] if row['path'] == wanted['path']]
        need(len(rows) == 1 and _same_json(rows[0], wanted),
             description + ' process target version differs from action ' + endpoint)
    if command['argv'][0] == before['path']:
        executable = command.get('executable')
        if require_executable or executable is not None:
            need(type(executable) is dict and executable.get('path') == before['path']
                 and executable.get('sha256') == before['sha256'],
                 description + ' invoked executable identity differs from target version')


def _tool_binding(command, tools, name, description):
    """Bind installed tool observations when the study records an identity."""
    executable = command.get('executable')
    if tools is not None:
        need(name in tools and type(tools[name]) is dict, description + ' has no recorded tool identity')
        need(type(executable) is dict and _same_json(executable, tools[name]),
             description + ' tool identity differs from recorded environment')
        need(command['argv'][0] in (name, tools[name]['path']),
             description + ' executable request differs from recorded tool')
    else:
        basename = Path(command['argv'][0]).name
        need(basename == name or basename.endswith('-' + name),
             description + ' invokes a different tool')


def _debug_strip_binding(action, tools):
    value, arguments, evidence = action['value'], action['arguments'], action['evidence']
    commands = [(index, event) for index, event in enumerate(evidence) if event['kind'] == 'process']
    need(len(commands) == 1, 'debug stripping lacks exactly one native command')
    position, command = commands[0]
    _successful(command, 'debug stripping')
    _tool_binding(command, tools, 'strip', 'debug stripping')
    need(command['argv'][1:] == ['--strip-debug', '-o', value['binary'], arguments['binary']]
         and command['stdin_hex'] is None, 'debug stripping command differs from declared request')
    source, target = value['source'], value['artifact']
    need(source['path'] != target['path'], 'debug stripping source and destination coincide')
    _process_target_binding(command, source, source, 'debug stripping input')
    need(any(index < position and source in event.get('files', [])
             for index, event in enumerate(evidence) if event['kind'] == 'file-capture'),
         'debug stripping input lacks its pre-command capture')
    need(any(index > position and target in event.get('files', [])
             for index, event in enumerate(evidence) if event['kind'] == 'file-capture'),
         'debug stripping output lacks its post-command capture')
    # A fresh output is absent when captured_run inventories existing inputs.
    # If an output endpoint was recorded, it must agree with the returned file.
    output_versions = [row for row in command['files_after'] if row['path'] == target['path']]
    need(not output_versions or len(output_versions) == 1 and _same_json(output_versions[0], target),
         'debug stripping output differs from the process endpoint')


def _transformation_capture_binding(action):
    """Check captured input/output lineage without requiring a correct transform.

    An unchanged output remains valid evidence for a failed postcondition. For
    native commands that do mutate the copied target, check their observed
    target-version chain; pure Python transformations have no process chain.
    """
    value, arguments, evidence = action['value'], action['arguments'], action['evidence']
    captures = [(index, row) for index, event in enumerate(evidence)
                if event['kind'] == 'file-capture' for row in event['files']]
    inputs = [(index, row) for index, row in captures if row['path'] == arguments['binary']]
    outputs = [(index, row) for index, row in captures if _same_json(row, value['artifact'])]
    need(bool(inputs) and bool(outputs) and inputs[0][0] < outputs[-1][0],
         'transformation lacks ordered input/output captures')
    source = inputs[0][1]
    if 'source' in value:
        need(_same_json(source, value['source']), 'transformation input differs from captured source')
    if action['operation'] not in ('remove', 'corrupt'):
        return
    previous = {**source, 'path': value['binary']}
    observed_commands = 0
    for event in evidence:
        if event['kind'] != 'process':
            continue
        _successful(event, 'completed transformation')
        before = [row for row in event['files_before'] if row['path'] == value['binary']]
        after = [row for row in event['files_after'] if row['path'] == value['binary']]
        need(len(before) == len(after) == 1 and _same_json(before[0], previous),
             'transformation process input differs from preceding target version')
        need(value['binary'] in event['argv'], 'transformation command targets another artifact')
        previous = after[0]
        observed_commands += 1
    if observed_commands:
        need(_same_json(previous, value['artifact']),
             'transformation output differs from final process version')


def _llvm_build_binding(action, receipt, context, identity):
    """Bind the four acquisition stages to their declared request and versions."""
    value, arguments, evidence = action['value'], action['arguments'], action['evidence']
    commands = [x for x in evidence if x['kind'] == 'process']
    need(len(commands) == 4, 'LLWM build does not contain exactly four commands')
    for command in commands:
        _successful(command, 'LLWM build')
        need(command['stdin_hex'] is None, 'LLWM build unexpectedly consumes stdin')
    frontend, unmarked_link, embedding, marked_link = commands
    marked = Path(value['marked'])
    directory = marked.parent
    suffix = Path('cases') / receipt['context_id'] / 'native'
    need(directory.parts[-len(suffix.parts):] == suffix.parts and marked.name == 'marked.bin',
         'LLWM output path belongs to another case')
    need(all(command['cwd'] == str(directory) for command in commands), 'LLWM build working directory differs')
    recorded_store = Path(*directory.parts[:-len(suffix.parts)])
    original_ir, marked_ir = str(directory / 'unmarked.ll'), str(directory / 'marked.ll')
    unmarked = str(directory / 'unmarked.bin')
    need(value['unmarked'] == unmarked and value['unmarked_artifact']['path'] == unmarked
         and value['marked_artifact']['path'] == str(marked), 'LLWM output path differs from captured artifact')
    interface = arguments['interface']
    need(interface in {'atoi', 'fgets', 'sidedata'}, 'unsupported LLWM interface')
    probe_relative = 'external_llwm/probes/' + interface + '.c'
    need(probe_relative in context['probes'], 'LLWM probe is absent from frozen inputs')
    frontend_argv = frontend['argv']
    need(len(frontend_argv) == 8 and Path(frontend_argv[0]).name == 'clang'
         and frontend_argv[1:5] == ['-O1', '-g', '-emit-llvm', '-S']
         and frontend_argv[6:] == ['-o', original_ir], 'LLWM frontend command differs from declaration')
    source = frontend_argv[5]
    need(Path(source).parts[-3:] == Path(probe_relative).parts, 'LLWM frontend uses another probe')
    family = 'sidedata' if interface == 'sidedata' else 'semacall'
    part = {'atoi': 'atoi', 'fgets': 'gets', 'sidedata': 'sidedata'}[interface]
    plugin_relative = 'setup/' + arguments['variant'] + '/' + family + '.so'
    need(plugin_relative in context['setup'], 'LLWM plugin is absent from setup manifest')
    plugin = str(recorded_store / plugin_relative)
    need(Path(embedding['argv'][0]).name == 'opt' and embedding['argv'][1:] == [
        '-load-pass-plugin=' + plugin, '-passes=' + family + '-watermark',
        '-' + part + '-key=' + arguments['key'], '-' + part + '-val=' + arguments['payload'],
        '-S', original_ir, '-o', marked_ir], 'LLWM embedding request differs from declaration')
    for command, source_ir, output in ((unmarked_link, original_ir, unmarked), (marked_link, marked_ir, str(marked))):
        need(command['argv'][0] == frontend_argv[0] and command['argv'][1:] == [
            '-g', '-' + arguments['optimization'], source_ir, '-o', output],
            'LLWM link settings or intermediate path differ from declaration')
    captures = [(index, row) for index, event in enumerate(evidence)
                if event['kind'] == 'file-capture' for row in event['files']]
    def captured(path, after=None, before=None):
        rows = [row for index, row in captures if row['path'] == path
                and (after is None or index > after) and (before is None or index < before)]
        need(len(rows) == 1, 'LLWM missing/extra endpoint capture: ' + Path(path).name)
        identity(rows[0])
        return rows[0]
    positions = [evidence.index(command) for command in commands]
    probe = captured(source, before=positions[0])
    plugin_capture = captured(plugin, before=positions[2])
    original_capture = captured(original_ir, after=positions[0], before=positions[1])
    marked_capture = captured(marked_ir, after=positions[2], before=positions[3])
    need(_same_bytes(probe, context['probes'][probe_relative]), 'LLWM source bytes differ from frozen probe')
    need(_same_bytes(plugin_capture, context['setup'][plugin_relative]), 'LLWM plugin bytes differ from setup manifest')
    for command, source_capture in ((frontend, probe), (unmarked_link, original_capture),
                                    (embedding, original_capture), (marked_link, marked_capture)):
        for endpoint in ('files_before', 'files_after'):
            rows = [row for row in command[endpoint] if row['path'] == source_capture['path']]
            need(rows == [source_capture], 'LLWM command consumes another recorded source version')
    need(captured(unmarked, after=positions[3]) == value['unmarked_artifact']
         and captured(str(marked), after=positions[3]) == value['marked_artifact'],
         'LLWM returned output version differs from final capture')


def value_bindings(receipt, store, *, llvm_context=None, native_tools=None):
    physical = process_outputs = extraction_returns = 0
    blobs = set()
    carrier = receipt['inputs'].get('carrier')
    prior_builds = []
    for action in receipt['actions']:
        evidence = action['evidence']
        captures = []
        for entry in evidence:
            for name in ('files', 'files_before', 'files_after'):
                for record in entry.get(name, []):
                    captures.append(record); blobs.add(record['blob'])
        if action['status'] != 'OK': continue
        value = action['value']; operation = action['operation']; arguments = action['arguments']
        def identity(record):
            need(record in captures, 'action value cites an uncaptured version: ' + action['id'])
            return verify_file(record, store)
        if operation == 'session':
            need(_same_json(value, {'session_id': receipt['context_id'] + ':decoder',
                                   'carrier': arguments['carrier'], 'implementation': arguments['implementation']}),
                 'session descriptor differs from declared decoder context')
        if operation in ('begin_overlap', 'end_overlap'):
            need(_same_json(value, {'session_id': arguments['session'], 'operation': operation}),
                 'overlap descriptor differs from declared decoder context')
        if operation in ('extract', 'host', 'invoke', 'sections'):
            identity(value['before']); identity(value['after'])
            need(value['before']['path'] == arguments['binary'] and value['after']['path'] == arguments['binary'], 'observation cites another invocation target')
        if operation == 'extract':
            returns = [x for x in evidence if x['kind'] == 'python-return']
            need(len(returns) == 1, 'missing/extra raw extraction return')
            raw = returns[0]
            need(raw['return_value'] == value['observation'] and raw['before'] == value['before']
                 and raw['after'] == value['after'] and raw['key'] == value['key']
                 and raw['session_id'] == value['session_id'] == arguments['session']
                 and raw['binary'] == arguments['binary'] and raw['key'] == arguments['key'], 'extraction value differs from raw call')
            # State shortcuts can legitimately execute no native utility. Any
            # recorded utility observation of this target must nevertheless
            # agree with the version attributed to the extraction action.
            for event in evidence:
                if event['kind'] == 'process' and any(row['path'] == arguments['binary']
                        for endpoint in ('files_before', 'files_after') for row in event[endpoint]):
                    _process_target_binding(event, value['before'], value['after'], 'extraction')
            extraction_returns += 1
        if operation in ('inspect', 'checksum_view'):
            raw = identity(value['artifact'])
            need(value['artifact']['path'] == arguments['binary'] and value['key'] == arguments['key'], 'carrier observation cites another request')
            actual = _PARSER.observe(raw, carrier, value['key'])
            need(actual == value['observation'], 'physical carrier differs from captured bytes')
            if operation == 'checksum_view':
                material = reobserve_material(raw, carrier, value['key'], arguments.get('source_material'))
                need(material == value['material'], 'intervention material differs from captured representation')
            physical += 1
        if operation in ('invoke', 'sections'):
            commands = [x for x in evidence if x['kind'] == 'process']
            need(len(commands) == 1, 'available invocation lacks exactly one native command')
            cmd = commands[0]
            _successful(cmd, 'available invocation')
            _process_target_binding(cmd, value['before'], value['after'], operation,
                                    require_executable=native_tools is not None)
            if operation == 'invoke':
                wanted_argv = [arguments['binary']] + ([] if arguments['interface'] == 'fgets' else [arguments['input']])
                wanted_stdin = (arguments['input'] + '\n').encode().hex() if arguments['interface'] == 'fgets' else None
                need(cmd['argv'] == wanted_argv and cmd['stdin_hex'] == wanted_stdin, 'LLWM invocation differs from declared request')
                need(cmd['cwd'] == str(Path(arguments['binary']).parent), 'LLWM invocation working directory differs from target context')
                need(value['stdout_hex'] == cmd['stdout_hex'] and value['stderr_hex'] == cmd['stderr_hex']
                     and _same_json(value['returncode'], cmd['returncode']), 'invocation output differs from command')
            else:
                _tool_binding(cmd, native_tools, 'readelf', 'section observation')
                need(cmd['argv'][-1] == arguments['binary'] and cmd['argv'][1:-1] == ['-W', '-S']
                     and cmd['stdin_hex'] is None, 'section command observes another request')
                need(value['text'] == bytes.fromhex(cmd['stdout_hex']).decode('utf-8'), 'section text differs')
            process_outputs += 1
        if operation == 'host':
            commands = [x for x in evidence if x['kind'] == 'process']
            need(_same_json(value['inputs'], arguments['inputs']), 'host inputs differ from declared request')
            need(len(commands) == len(value['inputs']), 'host call count differs')
            outputs = []
            for cmd, number in zip(commands, value['inputs']):
                _successful(cmd, 'host observation')
                need(cmd['argv'] == [arguments['binary'], str(number)] and cmd['stdin_hex'] is None,
                     'host request differs')
                _process_target_binding(cmd, value['before'], value['after'], 'host observation',
                                        require_executable=native_tools is not None)
                outputs.append(bytes.fromhex(cmd['stdout_hex']).decode('utf-8').strip())
            need(outputs == value['outputs'], 'host values differ from raw output')
            process_outputs += len(commands)
        if operation in ('relocate', 'remove', 'corrupt', 'strip_debug'):
            identity(value['artifact'])
            if 'source' in value:
                identity(value['source'])
                need(value['source']['path'] == arguments['binary'], 'transform source differs from declaration')
            need(value['artifact']['path'] == value['binary'], 'transform output differs from captured object')
            _transformation_capture_binding(action)
            if operation == 'strip_debug':
                _debug_strip_binding(action, native_tools)
        if operation == 'capture':
            identity(value)
            need(value['path'] == arguments['binary'], 'capture observes another declared target')
        if operation == 'build':
            identity(value['artifact']); identity(value['source'])
            need(value['artifact']['path'] == value['binary'] and value['session_id'] == arguments['session'],
                 'build output path or session differs from declaration')
            commands = [x for x in evidence if x['kind'] == 'process' and '-std=c11' in x['argv']]
            # Cached controlled builds legitimately do not invoke a compiler again.
            if commands:
                need(len(commands) == 1, 'build has multiple compiler commands')
                command = commands[0]
                _successful(command, 'build')
                need(command['argv'] == value['command'] and type(value['returncode']) is int
                     and command['returncode'] == value['returncode'], 'build return differs from recorded compiler call')
                argv = command['argv']
                optimization_flags = [token for token in argv if re.fullmatch(r'-O(?:[0-3sgz]|fast)', token)]
                need(Path(argv[0]).name == value['compiler'] and optimization_flags == ['-' + value['optimization']]
                     and value['source']['path'] in argv and argv.count('-o') == 1
                     and argv.index('-o') + 1 < len(argv) and argv[argv.index('-o') + 1] == value['binary'],
                     'actual build settings differ')
                _tool_binding(command, native_tools, value['compiler'], 'native build')
                for endpoint in ('files_before', 'files_after'):
                    rows = [r for r in command[endpoint] if r['path'] == value['source']['path']]
                    need(rows == [value['source']], 'compiler input version differs from returned source')
                process_positions = [index for index, event in enumerate(evidence) if event['kind'] == 'process']
                need(any(index > max(process_positions) and value['artifact'] in event.get('files', [])
                         for index, event in enumerate(evidence) if event['kind'] == 'file-capture'),
                     'build output lacks a final capture after its commands')
                # Section insertion may modify the linked binary in place.
                versions = [row for event in evidence if event['kind'] == 'process'
                            for row in event['files_after'] if row['path'] == value['binary']]
                if versions:
                    need(versions[-1] == value['artifact'], 'build output differs from final process version')
            else:
                need(any(_same_json(previous['value'], value) and previous['end_event'] < action['start_event']
                         for previous in prior_builds), 'cached build has no preceding matching acquisition')
            prior_builds.append(action)
        if operation == 'llvm_build':
            identity(value['unmarked_artifact']); identity(value['marked_artifact'])
            if llvm_context is None:
                llvm_context = llvm_binding_context(store)
            _llvm_build_binding(action, receipt, llvm_context, identity)
    return {'physical_byte_reobservations': physical, 'raw_process_output_bindings': process_outputs,
            'typed_extraction_return_bindings': extraction_returns, 'blobs': blobs}


def verify(out):
    out = Path(out).resolve()
    freeze = json.loads((out / 'producer-freeze.json').read_text())
    for row in freeze['inputs']:
        path = out / 'source-snapshot' / row['path']
        need(path.is_file() and len(path.read_bytes()) == row['bytes'] and sha(path.read_bytes()) == row['sha256'],
             'frozen producer identity mismatch: ' + row['path'])
    frame = json.loads((out / 'frame.json').read_text())
    need(frame == freeze['frame'], 'frame differs from pre-execution freeze')
    cases = json.loads((out / 'cases.json').read_text())
    need(len(frame) == len(cases) and len({x['id'] for x in frame}) == len(frame), 'frame size/unique identity differs')
    need([x['id'] for x in cases] == [x['id'] for x in frame], 'case order/domain differs')
    actual_receipts = {p.parent.relative_to(out / 'cases').as_posix() for p in (out / 'cases').rglob('receipt.json')}
    need(actual_receipts == {x['id'] for x in frame}, 'receipt domain differs from plan')
    totals = Counter(); all_blobs = set(); semantic_rows = {}
    native_tools = json.loads((out / 'environment.json').read_text())['tools']
    llvm_context = llvm_binding_context(out) if freeze['study'] == 'llwm' else None
    for case, row in zip(frame, cases):
        directory = out / 'cases' / case['id']
        plan = json.loads((directory / 'plan.json').read_text())
        receipt = json.loads((directory / 'receipt.json').read_text())
        if freeze['study'] in ('reference', 'identity', 'state-baseline'):
            expected_plan = json.loads((out / 'source-snapshot/declarative_study/plans' / (case['relation'] + '.json')).read_text())
        elif freeze['study'] == 'llwm':
            expected_plan = json.loads((out / 'source-snapshot/declarative_study/plans' / ('LLWM-' + case['interface'] + '.json')).read_text())
        elif freeze['study'] == 'declarations':
            expected_plan = case['plan']
        else:
            from declarative_study.state_words import make_plan
            for rel in ('declarative_study/state_words.py', 'declarative_study/build_plans.py'):
                entry = next(x for x in freeze['inputs'] if x['path'] == rel)
                need(sha((ARTIFACT / rel).read_bytes()) == entry['sha256'], 'state plan generator differs from frozen implementation')
            expected_plan = make_plan(case['word'])
        need(plan == expected_plan, 'executed plan differs from frozen frame declaration')
        # Native frame input bindings are checked independently from receipt hashes.
        expected = {'interface': case['interface'], 'variant': case['variant'], 'payload': case['payload'],
                    'payload_hex': case['payload'].encode().hex(), 'key': '1234', 'ordinary': '4321',
                    'optimization': case['optimization']} if freeze['study'] == 'llwm' else {
                    'host': case.get('host', receipt['inputs']['host']), 'carrier': case['carrier'], 'implementation': case['implementation'],
                    'payload1': b'Morph-01'.hex(), 'payload2': b'Second-2'.hex(), 'key1': 'key-alpha',
                    'key2': 'key-beta', 'compiler': 'gcc', 'optimization': 'O2', 'host_inputs': [0,1,5,13,144,99991]}
        if freeze['study'] == 'state' or freeze['study'] == 'state-baseline' and case['relation'] == 'SR01':
            expected.update(reuse_permitted=True, lockout_excluded=True)
        if freeze['study'] != 'llwm':
            host_identity = next(x for x in freeze['inputs'] if x['path'] == 'hosts/H01-gcd.c')
            need(Path(expected['host']).name == 'H01-gcd.c', 'host path differs from frozen subject')
            if 'host' not in case:
                need(json.loads((out / 'environment.json').read_text())['purpose'] == 'pilot', 'formal frame omits host binding')
            for action in receipt['actions']:
                if action['operation'] == 'build' and action['status'] == 'OK':
                    host_captures = [r for e in action['evidence'] for r in e.get('files', []) if r['path'] == expected['host']]
                    need(len(host_captures) >= 1 and all(r['sha256'] == host_identity['sha256'] and r['bytes'] == host_identity['bytes'] for r in host_captures), 'native host bytes differ from frozen subject')
        context = case['id'] if freeze['study'] == 'llwm' else case['id'] + ':declaration'
        verify_receipt(plan, receipt, expected_inputs=expected, expected_context_id=context)
        totals['file_bindings'] += verify_evidence(receipt, out)
        bindings = value_bindings(receipt, out, llvm_context=llvm_context, native_tools=native_tools)
        all_blobs.update(bindings.pop('blobs')); totals.update(bindings)
        primary = {x['id']: x['verdict'] for x in receipt['obligations']} if freeze['study'] == 'llwm' else receipt['obligations'][-1]['verdict']
        need(primary == row['primary'], 'case summary differs from rederived primary judgment')
        statuses = dict(Counter(x['status'] for x in receipt['actions']))
        need(statuses == row['action_statuses'], 'case action count differs')
        semantic_rows[case['id']] = {'primary': primary, 'statuses': statuses,
            'obligations': [(x['id'], x['verdict']) for x in receipt['obligations']]}
        totals['receipts'] += 1; totals['obligations'] += len(receipt['obligations'])
        legacy_path = directory / 'legacy.json'
        if legacy_path.is_file():
            legacy = json.loads(legacy_path.read_text())
            need(legacy['verdict'] == row['legacy'], 'legacy summary differs')
            for e in legacy['evidence']:
                for key in ('files', 'files_before', 'files_after'):
                    for identity in e.get(key, []):
                        verify_file(identity, out); all_blobs.add(identity['blob']); totals['legacy_file_bindings'] += 1
    actual_blobs = {p.relative_to(out).as_posix() for p in (out / 'blobs').glob('*.bin.gz')}
    need(actual_blobs == all_blobs, 'saved blob domain differs from observation references')
    summary = json.loads((out / 'summary.json').read_text())
    need(summary['cases'] == len(frame), 'summary denominator differs')
    repeats = []
    for name, semantic in semantic_rows.items():
        if name.startswith('pass-1/'):
            other = 'pass-2/' + name[len('pass-1/'):]
            if other in semantic_rows:
                repeats.append((name, semantic == semantic_rows[other]))
    result = {'status': 'PASS', 'study': freeze['study'], 'counts': dict(totals),
              'unique_blobs': len(all_blobs), 'repeated_case_comparisons': len(repeats),
              'repeated_semantic_differences': [name for name, ok in repeats if not ok],
              'scope': 'Plan/receipt correspondence, recorded process and return bindings, retained bytes, physical carrier reobservation; not independent historical reexecution.'}
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--data', required=True, type=Path)
    p.add_argument('--report', type=Path); args = p.parse_args()
    result = verify(args.data)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, indent=2))
