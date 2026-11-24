#!/usr/bin/env python3
"""Receive retained SandMark session evidence without running Java or an adapter.

This implementation imports the independent plan receiver only. It independently
reconstructs the frame, native request/lifetime associations, endpoint bindings,
local summaries, and paired scientific comparisons. Raw process and Java journals
are acquisition evidence, not cryptographic attestation of memory identity.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.receiver import load_json, verify_receipt

ROLES = {'target': 'host_wm.jar', 'original': 'host.jar', 'key_file': 'gtw.key',
         'target_constraints': 'host_wm.smconfig', 'original_constraints': 'host.smconfig'}
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}
CYCLE = {'7': '42', '42': '1234', '1234': '7'}
SOURCE_FILES = {'decoder_sessions/' + name for name in
                ('SessionBridge.java', 'common.py', 'adapter.py', 'plans.py', 'protocol.json', 'run.py', 'analyze.py')} | {
                'contract_runtime/core.py', 'contract_runtime/__init__.py'}
PRIOR_METADATA = {
    'algorithm-contracts.json': '9638908b562883776689b9c703e4c9fdcd1daa74cf280c27a688c1aa2a63368d',
    'study-frame.json': 'fdf5922c7a831b67be1e67de0e2f4d797a826e733d1cae4695bacbb437c5f10b',
    'summary.json': '677ca22e69bb97b5b8b8f45c322b21496bf573fd0d661c34baf9262871d506c6',
    'acquisition-lock.json': '8784b84c812b97735f164138032dcbbe5a4bedfbb6c32f54168e0d91264fda93',
}
# Independently reviewed fixed study declarations. The early two-history pilot
# remains a separate acquisition; a supplied freeze cannot redefine its plan.
PILOT_PLAN_SHA = {
    'AA': '5dd29e782316f0a134d9c6323a6e81195ed03559e0ca56ade6dcdae71b576b65',
    'ABA': 'b3a4a6952739ed7f5fde8c973fd56597aa2b9c7ee4ef7f3002be180fd80074b8',
}
FORMAL_PLAN_SHA = {
    'AA': '4418f4abf2593653c828e83787b4f4911810024b0d9dd8fa97beaf6c5699fbdb',
    'AAA': '6878fe90552c281ec5e2cfb590453a203a55861883bebe17bcc43494068cf787',
    'ABA': 'a1b5218b3fc0228d5932987e1634cfb44054094036e5b70654056d2ca34e22ab',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def same(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(same(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def expect(actual, expected, message):
    require(same(actual, expected), message)


def integer(value, message, minimum=0):
    require(type(value) is int and value >= minimum, message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inside(root, name):
    require(type(name) is str and name and '\\' not in name, 'Invalid evidence pathname')
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and relative.as_posix() == name
            and all(p not in ('', '.', '..') for p in relative.parts), 'Noncanonical evidence pathname')
    path = root.joinpath(*relative.parts)
    require(path.resolve().is_relative_to(root.resolve()), 'Evidence escapes activity')
    for parent in (path, *path.parents):
        if parent == root:
            break
        require(not parent.is_symlink(), 'Evidence link is not supported')
    return path


def binding(root, name):
    path = inside(root, name)
    require(path.is_file(), 'Missing retained file: ' + name)
    return {'path': name, 'sha256': digest(path), 'bytes': path.stat().st_size}


def check_binding(root, row, expected_path=None):
    require(type(row) is dict and set(row) == {'path', 'sha256', 'bytes'}, 'Malformed file binding')
    if expected_path is not None:
        expect(row['path'], expected_path, 'File binding names another object')
    expect(row, binding(root, row['path']), 'Retained bytes differ: ' + str(row.get('path')))


def read_lines(path):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'Duplicate JSON journal member')
            out[key] = value
        return out
    def bad(value):
        raise ValueError('Nonfinite JSON journal value: ' + value)
    return [json.loads(line, object_pairs_hook=pairs, parse_constant=bad)
            for line in path.read_text().splitlines() if line.strip()]


class Receiver:
    def __init__(self, run):
        self.run = Path(run).resolve()
        self.freeze = load_json(self.run / 'freeze.json')
        self.protocol = load_json(self.run / 'protocol.json')
        self.frame = load_json(self.run / 'frame.json')
        self.manifest = load_json(self.run / 'input-manifest.json')
        self.plans = {h: load_json(self.run / 'plans' / (h + '.json')) for h in ('AA', 'AAA', 'ABA')
                      if (self.run / 'plans' / (h + '.json')).is_file()}
        self.counts = Counter()
        self.blobs = set()
        self.process_tokens = set()
        self.word_details = []

    def metadata(self, allow_pilot):
        f, p, frame, manifest = self.freeze, self.protocol, self.frame, self.manifest
        expect(f['schema'], 'sandmark-session-freeze-v1', 'Unexpected freeze schema')
        require(f['kind'] == 'formal' or (allow_pilot and f['kind'] == 'pilot'), 'Not a formal full frame')
        expect(frame['kind'], f['kind'], 'Frame/freeze activity kind differs')
        require(type(f['max_workers']) is int and 1 <= f['max_workers'] <= 4, 'Invalid worker bound')
        expect(f['launch_environment'], ENVIRONMENT, 'Launch environment differs from protocol')
        for field, name in [('protocol', 'protocol.json'), ('frame', 'frame.json'), ('input_manifest', 'input-manifest.json')]:
            check_binding(self.run, f[field], name)
        early_pilot = f['kind'] == 'pilot' and set(self.plans) == {'AA', 'ABA'}
        expected_histories = {'AA': ['A', 'A'], 'ABA': ['A', 'B', 'A']}
        if not early_pilot:
            expected_histories['AAA'] = ['A', 'A', 'A']
        plan_pins = PILOT_PLAN_SHA if early_pilot else FORMAL_PLAN_SHA
        expect(set(f['plans']), set(expected_histories), 'Plan set differs')
        expect(set(self.plans), set(expected_histories), 'Retained plan set differs')
        require(set(plan_pins) == set(expected_histories), 'Fixed declarations have not been independently reviewed')
        for h in expected_histories:
            check_binding(self.run, f['plans'][h], 'plans/' + h + '.json')
            expect(f['plans'][h]['sha256'], plan_pins[h], 'Fixed study plan was redefined: ' + h)
        source_set = set(f['source_bindings'])
        require(source_set == SOURCE_FILES or (early_pilot and source_set == SOURCE_FILES - {'decoder_sessions/analyze.py'}),
                'Incomplete producer/core snapshot')
        for name, item in f['source_bindings'].items():
            path = inside(self.run, 'producer-snapshot/' + name)
            expect(item, {'sha256': digest(path), 'bytes': path.stat().st_size}, 'Producer snapshot changed')
        expect(p, load_json(self.run / 'producer-snapshot/decoder_sessions/protocol.json'), 'Protocol differs from frozen source')
        for key, value in {'a_b_mapping': CYCLE, 'acquisition_passes': 2, 'startup_rng_seed': 0,
                           'harness_reseeds_between_requests': False, 'graph_list_cleared_before_each_request': True,
                           'request_timeout_seconds': 30, 'startup_timeout_seconds': 30,
                           'shutdown_timeout_seconds': 5, 'maximum_heap_mb': 512,
                           'maximum_candidates': 10000}.items():
            expect(p[key], value, 'Unsupported protocol setting: ' + key)
        expect(p['histories'], expected_histories, 'Request words differ')
        history_order = ['AA', 'ABA'] if early_pilot else ['AA', 'AAA', 'ABA']
        expect(p['pass_orders'], {'1': {'history': history_order, 'lifetime': ['P', 'O', 'R']},
                                  '2': {'history': list(reversed(history_order)), 'lifetime': ['R', 'O', 'P']}}, 'Pass order differs')
        expect(set(p['lifetimes']), {'P', 'O', 'R'}, 'Lifetime set differs')
        expect({row['path'] for row in f['helper_classes']},
               {'bridge/SessionBridge.class', 'bridge/SessionBridge$CandidateLimitException.class'}, 'Helper class set differs')
        for row in f['helper_classes']:
            check_binding(self.run, row)
        for item in (f['tool'], f['runtime']['java'], f['runtime']['release'], f['runtime']['lib/modules']):
            require(type(item['path']) is str and Path(item['path']).is_absolute(), 'Missing recorded executable path')
            integer(item['bytes'], 'Invalid pinned executable size', 1)
            require(re.fullmatch('[0-9a-f]{64}', item['sha256']) is not None, 'Malformed executable identity')
        expect(f['tool']['sha256'], '8310d3c80cc8adf13ec46f217fc458462ebe89ae498ce23c1c714ab878fb2ea9',
               'Unexpected SandMark toolkit')
        expect(set(manifest['prior_metadata']), set(PRIOR_METADATA), 'Original metadata set differs')
        for name, item in manifest['prior_metadata'].items():
            check_binding(self.run, {k: item[k] for k in ('path', 'sha256', 'bytes')}, 'prior-metadata/' + name)
            expect(item['sha256'], PRIOR_METADATA[name], 'Original study metadata was redefined: ' + name)
        prior_frame = load_json(self.run / 'prior-metadata/study-frame.json')
        prior_summary = load_json(self.run / 'prior-metadata/summary.json')
        contracts = load_json(self.run / 'prior-metadata/algorithm-contracts.json')
        catalog = {row['algorithm']: row['class'] for row in contracts['algorithms']}
        old_rows = prior_frame['configurations']
        require(len(old_rows) == 156 and len(catalog) == 13, 'Original frame is incomplete')
        require(len({r['id'] for r in old_rows}) == 156, 'Duplicate original case identity')
        factors = [(r['inputs']['algorithm'], r['inputs']['host'], r['inputs']['seed'], r['inputs']['payload']) for r in old_rows]
        require(len(set(factors)) == 156, 'Duplicate original factor configuration')
        expect(set(factors), {(algorithm, host, seed, payload) for algorithm in catalog
                             for host in ('antlr-2.7.7', 'official-ttt') for seed in (0, 1) for payload in CYCLE},
               'Original frame lacks complete factor coverage')
        old_summary = {row['id']: row for row in prior_summary['configurations']}
        expect(set(manifest['cases']), {row['id'] for row in old_rows}, 'Archive input set differs')
        expected_cells, lookup = [], {}
        for row in old_rows:
            cid, x = row['id'], row['inputs']
            item = manifest['cases'][cid]
            expect(item['id'], cid, 'Archive case identity differs')
            expect(item['inputs'], x, 'Archive input definition differs')
            expect(old_summary[cid]['inputs'], x, 'Prior frame/summary input mismatch')
            expect(item['algorithm_class'], catalog[x['algorithm']], 'Algorithm class differs from archive')
            expect(item['prior_embed_status'], old_summary[cid]['action_status']['embed'], 'Prior embedding status differs')
            expect(item['prior_source_verdict'], old_summary[cid]['judgments']['identity'], 'Prior source verdict differs')
            expect(set(item['files']), set(ROLES), 'Missing authorized file role')
            for role, filename in ROLES.items():
                entry = item['files'][role]
                expect(entry['path'], 'inputs/' + cid + '/' + filename, 'Input capsule path differs')
                require(type(entry['present']) is bool, 'File presence is not Boolean')
                path = inside(self.run, entry['path'])
                require(path.is_file() == entry['present'], 'Input capsule presence changed')
                if entry['present']:
                    expect({'path': entry['path'], 'sha256': entry['sha256'], 'bytes': entry['bytes']},
                           binding(self.run, entry['path']), 'Input capsule bytes changed')
                    self.counts['input_capsule_files'] += 1
                else:
                    expect([entry['bytes'], entry['sha256']], [None, None], 'Absent input has byte identity')
                # Also bind the new capsule to the supplied original activity when
                # verifying the complete project. A relocated activity can use its
                # self-contained prior manifest without that optional source tree.
                original = ARTIFACT / 'results/external-sandmark/formal-01/cases' / cid / 'embed' / filename
                if original.parent.is_dir():
                    require(original.is_file() == entry['present'], 'Capsule presence differs from supplied original')
                    if entry['present']:
                        require(original.read_bytes() == path.read_bytes(), 'Capsule differs from supplied original bytes')
                        self.counts['original_archive_byte_comparisons'] += 1
            expected_available = item['prior_embed_status'] == 'OK' and item['files']['target']['present']
            if x['algorithm'] in ('Davidson/Myhrvold', 'Stern'):
                expected_available = expected_available and item['files']['original']['present']
            if x['algorithm'] == 'Graph Theoretic Watermark':
                expected_available = expected_available and item['files']['key_file']['present']
            expect(item['archived_marked_input_available'], expected_available, 'Archive availability uses another gate')
            lookup[(x['algorithm'], x['host'], x['seed'], x['payload'])] = cid
        for row in old_rows:
            cid, x = row['id'], row['inputs']
            expected_cells.append({'id': 'cell-' + cid.split('-')[-1], 'a_case': cid,
                                   'b_case': lookup[(x['algorithm'], x['host'], x['seed'], CYCLE[x['payload']])]})
        expect(frame['cells'], expected_cells, 'Cyclic A/B frame differs')
        words = []
        for acquisition_pass in (1, 2):
            order = p['pass_orders'][str(acquisition_pass)]
            for cell in expected_cells:
                a, b = [manifest['cases'][cell[k]] for k in ('a_case', 'b_case')]
                x, y = a['inputs'], b['inputs']
                for history in order['history']:
                    for lifetime in order['lifetime']:
                        inputs = {'cell': cell['id'], 'algorithm': x['algorithm'], 'algorithm_class': a['algorithm_class'],
                                  'host': x['host'], 'archived_embedding_seed': x['seed'], 'a_case': a['id'], 'b_case': b['id'],
                                  'payload_a': x['payload'], 'payload_b': y['payload'], 'key_a': x['key'], 'key_b': y['key'],
                                  'history': history, 'lifetime': lifetime, 'acquisition_pass': acquisition_pass}
                        words.append({'id': 'word-%06d' % (len(words) + 1), 'inputs': inputs})
        expect(frame['full_planned_words'], 156 * len(expected_histories) * 3 * 2, 'Full denominator differs')
        if f['kind'] == 'formal':
            expect(frame['words'], words, 'Formal frame is selective or reordered')
        else:
            selected = {w['id'] for w in frame['words']}
            expect(frame['words'], [w for w in words if w['id'] in selected], 'Pilot selection is malformed')
        expect(frame['selected_word_count'], len(frame['words']), 'Selected denominator differs')
        self.counts['planned_words'] = len(frame['words'])
        self.counts['planned_request_slots'] = sum(len(p['histories'][w['inputs']['history']]) for w in frame['words'])

    def snapshot(self, data):
        expect(set(data), set(ROLES), 'Endpoint omits an authorized role or sidecar')
        for role, row in data.items():
            expect(set(row), {'present', 'bytes', 'sha256', 'blob'}, 'Malformed endpoint role')
            require(type(row['present']) is bool, 'Endpoint presence is not Boolean')
            if row['present']:
                expect(row['blob'], 'blobs/' + row['sha256'], 'Noncanonical endpoint blob')
                if row['blob'] not in self.blobs:
                    check_binding(self.run, {'path': row['blob'], 'sha256': row['sha256'], 'bytes': row['bytes']})
                    self.blobs.add(row['blob'])
                else:
                    integer(row['bytes'], 'Endpoint size is not an integer')
                    require(inside(self.run, row['blob']).stat().st_size == row['bytes'], 'Reused blob size differs')
            else:
                expect([row['bytes'], row['sha256'], row['blob']], [None, None, None], 'Absent role has content')
        self.counts['endpoint_maps'] += 1

    def process(self, word, index):
        wid, x = word['id'], word['inputs']
        prefix = 'words/' + wid + '/processes/process-%02d' % index
        folder = inside(self.run, prefix)
        command = load_json(folder / 'command.json')
        expect(set(command), {'schema', 'process_token', 'argv', 'cwd', 'environment', 'pid', 'returncode',
                              'timeouts', 'write_errors', 'start_unix_ns', 'elapsed_ns', 'stdin', 'stdout', 'stderr',
                              'ready', 'done'}, 'Unexpected process fields')
        expect(command['schema'], 'sandmark-session-process-v1', 'Process schema differs')
        token = wid + '-process-%02d' % index
        expect(command['process_token'], token, 'Process token differs from launch position')
        require(token not in self.process_tokens, 'Process token reused between words')
        self.process_tokens.add(token)
        recorded = Path(self.freeze['execution_root'])
        native_word = recorded / 'words' / wid
        argv = [self.freeze['runtime']['java']['path'], '-Djava.awt.headless=true', '-Dfile.encoding=UTF-8', '-Xmx512m',
                '-cp', str(recorded / 'bridge') + ':' + self.freeze['tool']['path'], 'SessionBridge', x['lifetime'],
                x['algorithm_class'], str(native_word / 'processes' / ('process-%02d' % index) / 'journal'), token]
        expect(command['argv'], argv, 'Java command differs from externally selected lifecycle')
        expect(command['cwd'], str(native_word), 'Java working directory differs')
        expect(command['environment'], self.freeze['launch_environment'], 'Java launch environment differs')
        integer(command['pid'], 'Invalid native PID', 1)
        require(type(command['returncode']) is int, 'Process has no integer exit status')
        integer(command['start_unix_ns'], 'Invalid process start time', 1)
        integer(command['elapsed_ns'], 'Invalid process duration')
        require(type(command['timeouts']) is list and len(command['timeouts']) == len(set(command['timeouts'])), 'Invalid timeout list')
        require(set(command['timeouts']) <= {'startup', 'first-a', 'middle-a', 'middle-b', 'last-a', 'shutdown'}, 'Unknown timeout stage')
        require(type(command['write_errors']) is list, 'Invalid write-error record')
        for e in command['write_errors']:
            expect(set(e), {'exception_class', 'message', 'attempted_hex'}, 'Malformed write error')
            require(all(type(v) is str for v in e.values()), 'Malformed write-error value')
            bytes.fromhex(e['attempted_hex'])
        for stream in ('stdin', 'stdout', 'stderr'):
            check_binding(self.run, command[stream], prefix + '/' + stream + '.bin')
        raw = (folder / 'stdin.bin').read_bytes()
        lines = raw.splitlines(keepends=True)
        require(all(line.endswith(b'\n') for line in lines), 'Incomplete native input line')
        if b'STOP\n' in lines:
            require(lines[-1] == b'STOP\n' and lines.count(b'STOP\n') == 1, 'Misplaced stop instruction')
            lines = lines[:-1]
        sent = []
        for line in lines:
            parts = line[:-1].split(b'\t')
            require(len(parts) == 6, 'Native request has wrong field count')
            decoded = [base64.b64decode(part, validate=True).decode('utf-8') for part in parts]
            require(line == b'\t'.join(base64.b64encode(v.encode()) for v in decoded) + b'\n', 'Noncanonical request encoding')
            sent.append((decoded, line))
        ready_path = folder / 'journal/ready.json'
        ready = load_json(ready_path) if ready_path.exists() else None
        if ready is not None:
            check_binding(self.run, command['ready'], prefix + '/journal/ready.json')
            expect(ready, {'kind': 'ready', 'process_token': token, 'pid': command['pid'], 'mode': x['lifetime'],
                           'algorithm_class': x['algorithm_class'], 'startup_rng_seed': 0}, 'Java startup identity differs')
        else:
            expect(command['ready'], None, 'Missing startup has a binding')
            require(not sent and (command['returncode'] != 0 or 'startup' in command['timeouts']), 'Missing startup without failed process')
        done_path = folder / 'journal/done.json'
        done = load_json(done_path) if done_path.exists() else None
        if done is not None:
            check_binding(self.run, command['done'], prefix + '/journal/done.json')
            expect(set(done), {'kind', 'process_token', 'requests_received', 'algorithm_constructions', 'application_constructions'}, 'Malformed completion journal')
            expect(done['kind'], 'process-complete', 'Unexpected process completion')
            expect(done['process_token'], token, 'Completion belongs to another process')
            for field in ('requests_received', 'algorithm_constructions', 'application_constructions'):
                integer(done[field], 'Invalid process completion count')
        else:
            expect(command['done'], None, 'Absent completion has a binding')
            require(command['returncode'] != 0 or command['timeouts'], 'Clean exit lacks completion journal')
        self.counts['java_processes'] += 1
        self.counts['process_timeouts'] += bool(command['timeouts'])
        self.counts['nonzero_process_exits'] += command['returncode'] != 0
        self.counts['startup_timeouts'] += 'startup' in command['timeouts']
        self.counts['shutdown_timeouts'] += 'shutdown' in command['timeouts']
        if done is not None:
            self.counts['process_completion_journals'] += 1
            self.counts['helper_requests_received'] += done['requests_received']
            self.counts['reported_algorithm_constructions'] += done['algorithm_constructions']
            self.counts['reported_application_constructions'] += done['application_constructions']
        return {'folder': folder, 'prefix': prefix, 'command': command, 'ready': ready, 'done': done,
                'sent': sent, 'requests': [], 'end_records': []}

    def native_return(self, native, request, process, ordinal):
        x, cmd = request['inputs'], process['command']
        base = {**request['fields'], 'process_token': cmd['process_token'], 'pid': cmd['pid'],
                'mode': x['lifetime'], 'algorithm_class': x['algorithm_class'], 'request_ordinal': ordinal}
        for key, value in base.items():
            expect(native.get(key), value, 'Native request association differs: ' + key)
        require(native.get('kind') in {'extract-return', 'null-iterator', 'candidate-limit', 'tool-exception'}, 'Unknown native return kind')
        require(type(native.get('iteration_complete')) is bool, 'Iterator completion is not Boolean')
        complete = native['kind'] == 'extract-return'
        if complete:
            expect(native['iteration_complete'], True, 'Incomplete enumeration labeled complete')
        elif native['kind'] in ('null-iterator', 'candidate-limit'):
            expect(native['iteration_complete'], False, 'Absent or capped enumeration labeled complete')
        # A property capture can fail after enumeration has completed. The
        # helper then preserves that fact in a tool-exception record, while the
        # adapter correctly keeps the overall observation unavailable.
        candidates, types = native.get('candidates'), native.get('candidate_java_types')
        require(type(candidates) is list and type(types) is list and len(candidates) == len(types) <= 10000,
                'Malformed native candidate vectors')
        for value, java_type in zip(candidates, types):
            require((value is None and java_type is None) or (type(value) is str and type(java_type) is str and java_type),
                    'Native candidate lost its null/type distinction')
        construction = {'algorithm_constructions': 1 if x['lifetime'] == 'R' else ordinal,
                        'algorithm_object_ordinal': 1 if x['lifetime'] == 'R' else ordinal,
                        'same_algorithm_reference_as_previous': None if ordinal == 1 else x['lifetime'] == 'R',
                        'same_application_reference_as_previous': None if ordinal == 1 else False,
                        'application_constructions': ordinal, 'parameter_key': request['fields']['key'],
                        'parameter_application_is_current': True, 'graph_list_cleared': True}
        for key, value in construction.items():
            if complete or key in native:
                expect(native.get(key), value, 'Native lifecycle or parameter association differs: ' + key)
        for phase in ('properties_before', 'properties_after'):
            if complete or phase in native:
                properties = native.get(phase)
                require(type(properties) is dict, 'Missing effective algorithm properties')
                for value in properties.values():
                    require(type(value) is dict and set(value) == {'java_type', 'text'}, 'Malformed property snapshot')
                    require((value['java_type'] is None and value['text'] is None)
                            or (type(value['java_type']) is str and type(value['text']) is str), 'Property loses type')
                if x['algorithm'] in ('Davidson/Myhrvold', 'Stern'):
                    expect(properties.get('Original File'), {'java_type': 'java.io.File', 'text': request['fields']['original_file']}, 'Original-program auxiliary differs')
                if x['algorithm'] == 'Graph Theoretic Watermark':
                    expect(properties.get('Key File'), {'java_type': 'java.io.File', 'text': request['fields']['key_file']}, 'GTW key auxiliary differs')
        if native['kind'] in ('tool-exception', 'candidate-limit'):
            require(type(native.get('exception_class')) is str, 'Exception class was omitted')
            require(native.get('exception_message') is None or type(native['exception_message']) is str, 'Malformed exception message')
        process['end_records'].append(native)
        self.counts['completed_request_slots' if complete else 'incomplete_native_returns'] += 1
        return complete

    def word(self, word):
        wid, x = word['id'], word['inputs']
        folder = self.run / 'words' / wid
        receipt = load_json(folder / 'receipt.json')
        verify_receipt(self.plans[x['history']], receipt, expected_inputs=x, expected_context_id=wid)
        actions = {row['id']: row for row in receipt['actions']}
        invocations = [{'operation': a['operation'], 'arguments': a['arguments'], 'step_id': a['id'], 'context_id': wid}
                       for a in receipt['actions'] if a['status'] != 'SKIPPED']
        expect(read_lines(folder / 'invocations.jsonl'), invocations, 'Actual adapter invocation sequence differs')
        for a in receipt['actions']:
            for item in a['evidence']:
                check_binding(self.run, item)
        prepare = load_json(folder / 'prepare.json')
        roles = {'A': x['a_case']}
        if x['history'] == 'ABA':
            roles['B'] = x['b_case']
        available = all(self.manifest['cases'][cid]['archived_marked_input_available'] for cid in roles.values())
        folders = {role: 'words/' + wid + '/work/' + role for role in roles}
        expect(prepare['all_inputs_available'], available, 'Availability omitted a required archived input')
        expect(prepare['folders'], folders, 'Work folder roles differ')
        expect(prepare['archived_cases'], roles, 'A/B source association differs')
        expect(set(prepare['initial_context']), set(roles) if available else set(), 'Initial context set differs')
        last_context = {}
        if available:
            self.counts['input_available_words'] += 1
            self.counts['input_available_request_slots'] += len(self.protocol['histories'][x['history']])
            for role, cid in roles.items():
                context = prepare['initial_context'][role]
                self.snapshot(context)
                for file_role, item in self.manifest['cases'][cid]['files'].items():
                    expected = {'present': item['present'], 'bytes': item['bytes'], 'sha256': item['sha256'],
                                'blob': 'blobs/' + item['sha256'] if item['present'] else None}
                    expect(context[file_role], expected, 'Initial endpoint differs from pinned capsule')
                last_context[role] = context
        else:
            require(not (folder / 'work').exists(), 'Unavailable word acquired a substitute input')
        expect(actions['prepare']['status'], 'OK', 'Input inventory unavailable')
        expect(actions['prepare']['value'], prepare, 'Prepare observation differs')
        expect(actions['prepare']['evidence'], [binding(self.run, 'words/' + wid + '/prepare.json')], 'Prepare evidence differs')
        process_dirs = sorted((folder / 'processes').glob('process-*')) if (folder / 'processes').exists() else []
        expect([p.name for p in process_dirs], ['process-%02d' % i for i in range(1, len(process_dirs) + 1)], 'Noncontiguous process frame')
        processes = [self.process(word, i) for i in range(1, len(process_dirs) + 1)]
        op = actions['open']
        if op['status'] == 'SKIPPED':
            require(not processes and not (folder / 'open.json').exists(), 'Skipped open launched a process')
        elif op['status'] == 'UNAVAILABLE':
            require(x['lifetime'] != 'P' and len(processes) == 1 and processes[0]['ready'] is None,
                    'Unavailable open lacks failed startup')
            value = {'session_id': wid, 'lifetime': x['lifetime'], 'ready': None,
                     'startup_process': processes[0]['command']}
            expect(load_json(folder / 'open.json'), value, 'Failed-open file differs')
            expect(op['value'], value, 'Failed-open observation differs')
            expect(op['evidence'], [binding(self.run, 'words/' + wid + '/open.json'),
                                    binding(self.run, processes[0]['prefix'] + '/command.json')],
                   'Failed-open native process is not referenced')
            expect(op['reason'], 'jvm-startup-unavailable', 'Unexpected open failure')
        else:
            require(x['lifetime'] == 'P' or (len(processes) == 1 and processes[0]['ready'] is not None), 'Open does not establish declared JVM')
            value = {'session_id': wid, 'lifetime': x['lifetime'], 'ready': None if x['lifetime'] == 'P' else processes[0]['ready']}
            expect(load_json(folder / 'open.json'), value, 'Open file differs')
            expect(op['value'], value, 'Open observation differs')
            expect(op['evidence'], [binding(self.run, 'words/' + wid + '/open.json')], 'Open evidence set differs')
        middle = [('middle-b', 'B')] if x['history'] == 'ABA' else ([('middle-a', 'A')] if x['history'] == 'AAA' else [])
        steps = [('first-a', 'A'), *middle, ('last-a', 'A')]
        attempted, request_details = 0, {}
        for sid, role in steps:
            action = actions[sid]
            req = folder / 'requests' / sid
            if action['status'] == 'SKIPPED':
                require(not req.exists(), 'Skipped request has acquisition files')
                request_details[sid] = {'status': 'SKIPPED'}
                continue
            attempted += 1
            self.counts['attempted_request_slots'] += 1
            proc = processes[attempted - 1] if x['lifetime'] == 'P' else processes[0]
            ordinal = 1 if x['lifetime'] == 'P' else attempted
            native_folder = Path(self.freeze['execution_root']) / folders[role]
            key = x['key_a' if role == 'A' else 'key_b']
            fields = {'request_id': sid, 'role': role, 'target': str(native_folder / ROLES['target']),
                      'key': key, 'original_file': str(native_folder / ROLES['original']),
                      'key_file': str(native_folder / ROLES['key_file'])}
            acquired = load_json(req / 'acquisition.json')
            expect(set(acquired), {'process_token', 'pid', 'request_id', 'message_written', 'elapsed_ns',
                                   'timed_out', 'result_present', 'result_file'}, 'Malformed request acquisition')
            for key2, value in {'process_token': proc['command']['process_token'], 'pid': proc['command']['pid'], 'request_id': sid}.items():
                expect(acquired[key2], value, 'Request/process association differs')
            integer(acquired['elapsed_ns'], 'Invalid request duration')
            for key2 in ('message_written', 'timed_out', 'result_present'):
                require(type(acquired[key2]) is bool, 'Acquisition flag is not Boolean')
            endfile = proc['folder'] / 'journal' / (sid + '.end.json')
            startfile = proc['folder'] / 'journal' / (sid + '.start.json')
            native = load_json(endfile) if endfile.exists() else None
            expect(acquired['result_present'], native is not None, 'API result availability differs')
            if proc['ready'] is None:
                expect(acquired['result_file'], None, 'Unstarted request names a result')
                require(not acquired['message_written'] and not (req / 'message.bin').exists(), 'Unstarted JVM received request')
            else:
                expect(acquired['result_file'], endfile.relative_to(self.run).as_posix(), 'Result pathname differs')
                expect(load_json(req / 'request.json'), fields, 'Decoded request differs from plan')
                raw = (req / 'message.bin').read_bytes()
                expected_raw = b'\t'.join(base64.b64encode(v.encode()) for v in fields.values()) + b'\n'
                require(raw == expected_raw, 'Actual request bytes differ from plan arguments')
                if acquired['message_written']:
                    require(ordinal <= len(proc['sent']), 'Request absent from native stdin')
                    expect(proc['sent'][ordinal - 1][0], list(fields.values()), 'Native stdin was reassigned')
                else:
                    require(any(e['attempted_hex'] == raw.hex() for e in proc['command']['write_errors']), 'Unsent request lacks write failure')
            if startfile.exists():
                start = load_json(startfile)
                expect(start, {**fields, 'process_token': proc['command']['process_token'], 'pid': proc['command']['pid'],
                               'mode': x['lifetime'], 'algorithm_class': x['algorithm_class'],
                               'request_ordinal': ordinal, 'kind': 'request-start'}, 'Native start journal differs')
            elif native is not None:
                raise ValueError('Completed return lacks request-start journal')
            expected_timeout = ('startup' in proc['command']['timeouts']) if proc['ready'] is None else sid in proc['command']['timeouts']
            expect(acquired['timed_out'], expected_timeout, 'Request timeout differs from process record')
            complete = self.native_return(native, {'inputs': x, 'fields': fields}, proc, ordinal) if native is not None else False
            if native is None:
                require(acquired['timed_out'] or proc['command']['returncode'] != 0 or not acquired['message_written'],
                        'Missing result lacks native failure evidence')
            before, after = load_json(req / 'before.json'), load_json(req / 'after.json')
            self.snapshot(before); self.snapshot(after)
            last_context[role] = after
            value = {'native': native, 'before': before, 'after': after, 'acquisition': acquired}
            expect(load_json(req / 'observation.json'), value, 'Grouped observation differs from raw files')
            expect(action['value'], value, 'Receipt value differs from native request and endpoints')
            evidence = [binding(self.run, (req / name).relative_to(self.run).as_posix())
                        for name in ('before.json', 'after.json', 'acquisition.json', 'observation.json')]
            if native is not None:
                evidence.append(binding(self.run, endfile.relative_to(self.run).as_posix()))
            expect(action['evidence'], evidence, 'Request evidence set differs')
            expect(action['status'], 'OK' if complete else 'UNAVAILABLE', 'Incomplete enumeration admitted')
            expect(action['reason'], None if complete else 'recognition-unavailable:' + (native['kind'] if native else 'no-return'),
                   'Native failure reason differs')
            proc['requests'].append(sid)
            request_details[sid] = {'status': action['status'], 'kind': native['kind'] if native else 'no-return',
                                    'candidates': native['candidates'] if native else None,
                                    'candidate_java_types': native['candidate_java_types'] if native else None,
                                    'exception_class': native.get('exception_class') if native else None,
                                    'endpoints_equal': same(before, after)}
        if op['status'] == 'OK':
            expect(len(processes), attempted if x['lifetime'] == 'P' else 1, 'Unexpected process restart or reuse')
        for proc in processes:
            starts = sorted(p.name for p in (proc['folder'] / 'journal').glob('*.start.json'))
            ends = sorted(p.name for p in (proc['folder'] / 'journal').glob('*.end.json'))
            self.counts['native_start_journals'] += len(starts)
            self.counts['native_end_journals'] += len(ends)
            require(set(starts) <= {sid + '.start.json' for sid in proc['requests']}, 'Undeclared request in native journal')
            expect(ends, sorted(e['request_id'] + '.end.json' for e in proc['end_records']), 'Native result set differs')
            require(len(proc['sent']) <= len(proc['requests']), 'Undeclared native stdin request')
            done = proc['done']
            if done is not None:
                expect(done['requests_received'], len(starts), 'Process completion request count differs')
                for key in ('algorithm_constructions', 'application_constructions'):
                    known = [e[key] for e in proc['end_records'] if key in e]
                    if known and len(ends) == len(starts):
                        expect(done[key], known[-1], 'Process completion lifecycle count differs')
        for role, context in last_context.items():
            for file_role, row in context.items():
                path = inside(self.run, folders[role] + '/' + ROLES[file_role])
                require(path.is_file() == row['present'], 'Final working context presence differs')
                if row['present']:
                    require(path.read_bytes() == inside(self.run, row['blob']).read_bytes(), 'Final working bytes differ from last capture')
                    self.counts['final_context_byte_comparisons'] += 1
        close = actions['close']
        if close['status'] == 'SKIPPED':
            require(not (folder / 'close.json').exists(), 'Skipped close has a declared return')
        else:
            expect(close['status'], 'OK', 'Session close did not record processes')
            value = {'session_id': wid, 'processes': [proc['command'] for proc in processes]}
            expect(load_json(folder / 'close.json'), value, 'Close file differs from raw process records')
            expect(close['value'], value, 'Close observation differs')
            expect(close['evidence'], [binding(self.run, 'words/' + wid + '/close.json')] +
                   [binding(self.run, proc['prefix'] + '/command.json') for proc in processes], 'Close evidence set differs')
        judgments = {o['id']: o['verdict'] for o in receipt['obligations']}
        result = {**word, 'receipt': binding(self.run, 'words/' + wid + '/receipt.json'), 'judgments': judgments,
                  'action_status': {a['id']: a['status'] for a in receipt['actions']}}
        expect(load_json(folder / 'result.json'), result, 'Word summary differs from independently received record')
        detail = {'id': wid, 'inputs': x, 'judgments': judgments, 'input_available': available,
                  'requests': request_details, 'java_processes': len(processes)}
        self.word_details.append(detail)
        return result

    def verify(self, allow_pilot=False):
        self.metadata(allow_pilot)
        start = load_json(self.run / 'execution-start.json')
        completion = load_json(self.run / 'completion.json')
        summary = load_json(self.run / 'summary.json')
        expect(start['freeze_sha256'], digest(self.run / 'freeze.json'), 'Start freeze differs')
        expect(completion['freeze_sha256'], digest(self.run / 'freeze.json'), 'Completion freeze differs')
        expect(completion['source_bindings_after_execution'], self.freeze['source_bindings'], 'Producer changed during acquisition')
        integer(self.freeze['frozen_unix_ns'], 'Invalid freeze time', 1)
        integer(start['started_unix_ns'], 'Invalid acquisition start', self.freeze['frozen_unix_ns'])
        integer(completion['completed_unix_ns'], 'Invalid completion time', start['started_unix_ns'])
        words = self.frame['words']
        expect(start['word_ids'], [w['id'] for w in words], 'Started word set differs from selected frame')
        expect(sorted(p.name for p in (self.run / 'words').iterdir()), sorted(w['id'] for w in words), 'Retained word directory set differs')
        rows = [self.word(word) for word in words]
        judgments = Counter(v for row in rows for v in row['judgments'].values())
        statuses = Counter(v for row in rows for v in row['action_status'].values())
        expect(summary['words'], rows, 'Activity rows differ from received words')
        expect(summary['kind'], self.freeze['kind'], 'Summary kind differs')
        expect(summary['word_count'], len(rows), 'Summary word count differs')
        expect(summary['obligation_count'], sum(judgments.values()), 'Obligation denominator differs')
        expect(summary['judgments'], dict(judgments), 'Summary verdict counts differ')
        expect(summary['action_status'], dict(statuses), 'Summary action counts differ')
        expect(completion['word_count'], len(rows), 'Completion denominator differs')
        expect(completion['summary_sha256'], digest(self.run / 'summary.json'), 'Completion summary differs')
        self.counts['unique_endpoint_blobs'] = len(self.blobs)
        self.counts['blocked_words'] = self.counts['planned_words'] - self.counts['input_available_words']
        saved_analysis = None
        analysis_path = self.run / 'paired-analysis.json'
        if self.freeze['kind'] == 'formal' or analysis_path.is_file():
            analysis_document = load_json(analysis_path)
            if self.freeze['kind'] == 'formal' or analysis_document.get('schema') == 'sandmark-session-paired-analysis-v2':
                saved_analysis = receive_analysis(analysis_document, self.word_details, self.counts, self.manifest,
                                                  self.freeze['kind'])
            else:
                require(self.freeze['kind'] == 'pilot' and set(self.plans) == {'AA', 'ABA'}
                        and analysis_document.get('schema') == 'sandmark-session-paired-analysis-v1',
                        'Unknown historical pilot analysis')
                saved_analysis = {'verdict': 'HISTORICAL_SUMMARY',
                    'scope': 'The two-history pilot summary is retained unchanged. Native records, judgments and the independent paired_analysis result above are checked; the later AAA-controlled interpretation does not apply to this summary.'}
            saved_analysis['file'] = binding(self.run, 'paired-analysis.json')
        return {'verdict': 'PASS', 'activity_kind': self.freeze['kind'], 'counters': dict(self.counts),
                'judgments': dict(judgments), 'action_status': dict(statuses), 'paired_analysis': paired_analysis(self.word_details),
                'algorithm_accounting': algorithm_accounting(self.word_details),
                'received_analysis': saved_analysis,
                'scope': 'Read-only independent frame, native command/request/lifecycle/context binding, common-plan interpretation, and paired derivation. No new Java execution; acquisition journals remain trusted observations.'}


def typed_candidates(request):
    if request.get('status') != 'OK':
        return None
    return list(zip(request['candidate_java_types'], request['candidates']))


def counter_equal(actual, expected, message):
    require(type(actual) is dict, message)
    for value in actual.values():
        integer(value, message)
    require(set(actual) <= set(expected), message)
    expect({k: actual.get(k, 0) for k in expected}, dict(expected), message)


def receive_analysis(document, words, counters, manifest, kind):
    """Check the saved analysis from already received native observations.

    Group membership, every Boolean comparison, all denominators, and raw
    acquisition counts are recomputed here. This code does not import or call
    the producer's analyzer, nor accept its verdicts as input observations.
    """
    expect(set(document), {'schema', 'kind', 'planned_words', 'local_obligations', 'judgments',
        'source_judgments', 'revisit_judgments', 'raw_acquisition', 'native_exception_categories',
        'by_algorithm', 'lifetime_triple_counts', 'history_triplet_counts', 'lifetime_triples',
        'history_triplets', 'input_population', 'interpretation'}, 'Saved analysis field set differs')
    expect(document['schema'], 'sandmark-session-paired-analysis-v2', 'Unknown saved analysis schema')
    expect(document['kind'], kind, 'Saved analysis kind differs')
    source = Counter(v for w in words for k, v in w['judgments'].items() if k != 'revisit')
    revisit = Counter(w['judgments']['revisit'] for w in words)
    expect(document['planned_words'], len(words), 'Saved analysis omits planned words')
    expect(document['local_obligations'], sum(source.values()) + sum(revisit.values()), 'Saved obligation total differs')
    for key, value in [('judgments', source + revisit), ('source_judgments', source), ('revisit_judgments', revisit)]:
        counter_equal(document[key], value, 'Saved judgment counts differ: ' + key)
    expected_algorithms = {}
    for name in sorted({w['inputs']['algorithm'] for w in words}):
        selected = [w for w in words if w['inputs']['algorithm'] == name]
        expected_algorithms[name] = {
            'source': dict(Counter(v for w in selected for k, v in w['judgments'].items() if k != 'revisit')),
            'revisit': dict(Counter(w['judgments']['revisit'] for w in selected)), 'words': len(selected)}
    expect(document['by_algorithm'], expected_algorithms, 'Saved algorithm accounting differs')
    qstatus = Counter(q['status'] for w in words for q in w['requests'].values())
    raw = {'input_available_words': counters['input_available_words'],
           'input_blocked_words': counters['blocked_words'], 'planned_request_slots': counters['planned_request_slots'],
           'adapter_request_attempts': qstatus['OK'] + qstatus['UNAVAILABLE'],
           'completed_typed_returns': qstatus['OK'], 'unavailable_requests': qstatus['UNAVAILABLE'],
           'unexecuted_request_slots': qstatus['SKIPPED'], 'jvm_processes': counters['java_processes'],
           'processes_with_timeout': counters['process_timeouts'], 'processes_with_nonzero_exit': counters['nonzero_process_exits'],
           'helper_requests_received': counters['helper_requests_received'],
           'algorithm_constructions_in_completed_processes': counters['reported_algorithm_constructions'],
           'application_constructions_in_completed_processes': counters['reported_application_constructions'],
           'request_start_journals': counters['native_start_journals'], 'request_end_journals': counters['native_end_journals']}
    counter_equal(document['raw_acquisition'], raw, 'Saved raw acquisition counts differ')
    errors = Counter((q['kind'], q['exception_class']) for w in words for q in w['requests'].values()
                     if q.get('kind') not in (None, 'no-return', 'extract-return'))
    expect(document['native_exception_categories'],
           [{'kind': k[0], 'exception_class': k[1], 'count': v} for k, v in sorted(errors.items())],
           'Saved native exception counts differ')
    expect(document['input_population'], {'archived_configurations': len(manifest['cases']),
           'usable_marked_inputs': sum(c['archived_marked_input_available'] for c in manifest['cases'].values())},
           'Saved input population differs')

    def stable(w):
        keys = ['first-a-source', 'last-a-source', 'revisit']
        if w['inputs']['history'] == 'AAA':
            keys.append('middle-a-source')
        return all(w['judgments'][k] == 'SATISFIED' for k in keys)

    def grouped(fields, selector):
        out = defaultdict(dict)
        for w in words:
            x = w['inputs']; key = tuple(x[k] for k in fields)
            require(x[selector] not in out[key], 'Duplicate word in scientific comparison group')
            out[key][x[selector]] = w
        return out

    lifetime = grouped(('cell', 'history', 'acquisition_pass'), 'lifetime')
    history = grouped(('cell', 'lifetime', 'acquisition_pass'), 'history')
    lifetime_rows, history_rows = [], []
    lifetime_counts, history_counts = Counter(), Counter()
    for key, group in sorted(lifetime.items()):
        if set(group) != {'P', 'O', 'R'}:
            lifetime_counts['incomplete_planned_triples'] += 1
            continue
        cold = stable(group['P'])
        decisions = {k: group[k]['judgments']['revisit'] for k in ('P', 'O', 'R')}
        object_loss = cold and stable(group['O']) and decisions['R'] == 'INCONSISTENT'
        process_loss = cold and any(decisions[k] == 'INCONSISTENT' for k in ('O', 'R'))
        slots = ['first-a', 'last-a'] if key[1] == 'AA' else [
            'first-a', 'middle-a' if key[1] == 'AAA' else 'middle-b', 'last-a']
        returns = {arm: [typed_candidates(group[arm]['requests'][s]) for s in slots] for arm in ('P', 'O', 'R')}
        complete = all(r is not None for arm in returns.values() for r in arm)
        equal = same(returns['P'], returns['O']) and same(returns['P'], returns['R']) if complete else None
        lifetime_rows.append({'cell': key[0], 'history': key[1], 'acquisition_pass': key[2],
            'words': {k: group[k]['id'] for k in ('P', 'O', 'R')}, 'revisit_verdicts': decisions,
            'stable_fresh_process_control': cold, 'object_lifetime_associated_loss': object_loss,
            'same_jvm_lifetime_associated_loss': process_loss, 'all_request_returns_complete': complete,
            'typed_candidate_sequences_equal': equal})
        for name, value in [('planned_triples', 1), ('stable_fresh_process_control', cold),
                            ('object_lifetime_associated_loss', object_loss), ('same_jvm_lifetime_associated_loss', process_loss),
                            ('complete_return_triples', complete), ('complete_return_triples_with_sequence_difference', complete and not equal)]:
            lifetime_counts[name] += value
    for key, group in sorted(history.items()):
        if set(group) != {'AA', 'AAA', 'ABA'}:
            history_counts['incomplete_planned_triplets'] += 1
            continue
        cold_controls = {h: lifetime.get((key[0], h, key[2]), {}).get('P') for h in ('AA', 'AAA', 'ABA')}
        cold_repeat = all(cold_controls[h] is not None and stable(cold_controls[h]) for h in ('AA', 'AAA'))
        cold_all = cold_repeat and cold_controls['ABA'] is not None and stable(cold_controls['ABA'])
        different_loss = cold_all and stable(group['AA']) and stable(group['AAA']) and group['ABA']['judgments']['revisit'] == 'INCONSISTENT'
        repeat_loss = cold_repeat and stable(group['AA']) and group['AAA']['judgments']['revisit'] == 'INCONSISTENT'
        comparisons = {}
        for a, b in (('AA', 'AAA'), ('AAA', 'ABA'), ('AA', 'ABA')):
            label = a + '-vs-' + b
            left, right = (typed_candidates(group[h]['requests']['last-a']) for h in (a, b))
            equal = multi = sets = None
            if left is not None and right is not None:
                equal, multi, sets = same(left, right), Counter(left) == Counter(right), set(left) == set(right)
                history_counts[label + ':complete_final_return_pairs'] += 1
                history_counts[label + ':final_typed_sequence_differences'] += not equal
                history_counts[label + ':final_typed_multiset_differences'] += not multi
                history_counts[label + ':final_typed_set_differences'] += not sets
            comparisons[label] = {'typed_final_sequence_equal': equal, 'typed_final_multiset_equal': multi,
                                  'typed_final_set_equal': sets}
        history_rows.append({'cell': key[0], 'lifetime': key[1], 'acquisition_pass': key[2],
            'words': {h: group[h]['id'] for h in ('AA', 'AAA', 'ABA')},
            'revisit_verdicts': {h: group[h]['judgments']['revisit'] for h in ('AA', 'AAA', 'ABA')},
            'stable_fresh_process_controls': cold_all, 'intervening_request_associated_loss': different_loss,
            'stable_fresh_process_repetition_controls': cold_repeat, 'third_request_repetition_associated_loss': repeat_loss,
            'descriptive_final_return_comparisons': comparisons})
        for name, value in [('planned_triplets', 1), ('stable_fresh_process_controls', cold_all),
                            ('stable_fresh_process_repetition_controls', cold_repeat),
                            ('intervening_request_associated_loss', different_loss), ('third_request_repetition_associated_loss', repeat_loss)]:
            history_counts[name] += value
    expect(document['lifetime_triples'], lifetime_rows, 'Saved lifetime comparison rows differ')
    expect(document['history_triplets'], history_rows, 'Saved history comparison rows differ')
    counter_equal(document['lifetime_triple_counts'], lifetime_counts, 'Saved lifetime denominators differ')
    counter_equal(document['history_triplet_counts'], history_counts, 'Saved history denominators differ')
    expect(document['interpretation'], 'Observational counts for the fixed archived inputs and bounded histories. Associations are not field-level causes; candidate order/multiplicity differences are descriptive. Shared inputs and nested comparisons are not independent defect samples.',
           'Saved interpretation differs from the fixed analysis')
    return {'verdict': 'PASS', 'source_judgments': dict(source), 'revisit_judgments': dict(revisit),
            'raw_acquisition': raw, 'lifetime_triple_counts': dict(lifetime_counts),
            'history_triplet_counts': dict(history_counts), 'checked_lifetime_rows': len(lifetime_rows),
            'checked_history_rows': len(history_rows)}


def algorithm_accounting(words):
    groups = defaultdict(list)
    for row in words:
        groups[row['inputs']['algorithm']].append(row)
    results = []
    for algorithm, rows in sorted(groups.items()):
        source = Counter(v for row in rows for k, v in row['judgments'].items() if k.endswith('-source'))
        revisit = Counter(row['judgments']['revisit'] for row in rows)
        by_lifetime = {arm: dict(Counter(row['judgments']['revisit'] for row in rows if row['inputs']['lifetime'] == arm))
                       for arm in ('P', 'O', 'R')}
        results.append({'algorithm': algorithm, 'planned_words': len(rows),
                        'input_available_words': sum(row['input_available'] for row in rows),
                        'completed_requests': sum(q['status'] == 'OK' for row in rows for q in row['requests'].values()),
                        'source_judgments': dict(source), 'revisit_judgments': dict(revisit), 'revisit_by_lifetime': by_lifetime})
    return results


def paired_analysis(words):
    groups, histories = defaultdict(dict), defaultdict(dict)
    for row in words:
        x = row['inputs']
        groups[(x['cell'], x['history'], x['acquisition_pass'])][x['lifetime']] = row
        histories[(x['cell'], x['lifetime'], x['acquisition_pass'])][x['history']] = row
    counts = Counter()
    losses, diagnostics = [], []
    def stable(row):
        required = ['first-a-source', 'last-a-source', 'revisit']
        if row['inputs']['history'] == 'AAA':
            required.append('middle-a-source')
        return all(row['judgments'].get(k) == 'SATISFIED' for k in required)
    for key, arms in sorted(groups.items()):
        if set(arms) != {'P', 'O', 'R'}:
            continue
        counts['complete_three_arm_groups'] += 1
        p, o, r = [arms[k] for k in ('P', 'O', 'R')]
        cold = stable(p)
        counts['stable_fresh_process_groups'] += cold
        for lifetime in ('O', 'R'):
            row = arms[lifetime]
            admitted = cold and row['judgments']['revisit'] in ('SATISFIED', 'INCONSISTENT')
            counts[lifetime + '_qualified_revisit_comparisons'] += admitted
            loss = admitted and row['judgments']['revisit'] == 'INCONSISTENT'
            counts[lifetime + '_process_lifetime_losses'] += loss
            if loss:
                losses.append({'cell': key[0], 'history': key[1], 'acquisition_pass': key[2], 'lifetime': lifetime,
                               'kind': 'process-lifetime-associated recovery loss', 'word': row['id']})
            if lifetime == 'R':
                qualified = admitted and stable(o)
                counts['R_object_lifetime_qualified_comparisons'] += qualified
                counts['R_object_lifetime_losses'] += qualified and loss
            for sid in ('first-a', 'last-a'):
                left, right = typed_candidates(p['requests'][sid]), typed_candidates(row['requests'][sid])
                if left is not None and right is not None:
                    counts[lifetime + '_completed_typed_comparisons'] += 1
                    seq, multi, sets = left == right, Counter(left) == Counter(right), set(left) == set(right)
                    counts[lifetime + '_typed_sequence_differences'] += not seq
                    counts[lifetime + '_typed_multiset_differences'] += not multi
                    counts[lifetime + '_typed_set_differences'] += not sets
                    if not seq:
                        diagnostics.append({'cell': key[0], 'history': key[1], 'acquisition_pass': key[2],
                                            'lifetime': lifetime, 'request': sid, 'word': row['id'],
                                            'same_multiset': multi, 'same_set': sets,
                                            'cold_candidates': len(left), 'arm_candidates': len(right)})
    for key, pair in sorted(histories.items()):
        if not {'AA', 'ABA'} <= set(pair) or key[1] == 'P':
            continue
        aa, aba = pair['AA'], pair['ABA']
        controls = [groups.get((key[0], h, key[2]), {}).get('P') for h in ('AA', 'ABA')]
        qualified = all(v is not None and stable(v) for v in controls) and aa['judgments']['revisit'] == 'SATISFIED' \
                    and aba['judgments']['revisit'] in ('SATISFIED', 'INCONSISTENT')
        counts[key[1] + '_extra_call_history_qualified_comparisons'] += qualified
        loss = qualified and aba['judgments']['revisit'] == 'INCONSISTENT'
        counts[key[1] + '_extra_call_history_losses'] += loss
        if loss:
            losses.append({'cell': key[0], 'lifetime': key[1], 'acquisition_pass': key[2], 'history': 'ABA',
                           'kind': 'AA-versus-ABA extra-call/history-associated recovery loss', 'word': aba['id']})
        if 'AAA' in pair:
            cold_aaa = groups.get((key[0], 'AAA', key[2]), {}).get('P')
            b_qualified = qualified and stable(aa) and stable(pair['AAA']) and cold_aaa is not None and stable(cold_aaa)
            counts[key[1] + '_intervening_request_qualified_comparisons'] += b_qualified
            b_loss = b_qualified and aba['judgments']['revisit'] == 'INCONSISTENT'
            counts[key[1] + '_intervening_request_associated_losses'] += b_loss
            if b_loss:
                losses.append({'cell': key[0], 'lifetime': key[1], 'acquisition_pass': key[2], 'history': 'ABA',
                               'kind': 'B-request-associated recovery loss with AA and AAA controls', 'word': aba['id']})
    return {'counts': dict(counts), 'losses': losses, 'typed_candidate_differences': diagnostics,
            'interpretation': 'Qualified recovery losses and descriptive typed candidate differences have separate denominators; repeated inputs are not independent defect samples.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=ARTIFACT / 'results/decoder-sessions/completed')
    parser.add_argument('--allow-pilot', action='store_true')
    parser.add_argument('--check-report', type=Path, help='Compare an existing received result; never write it')
    args = parser.parse_args()
    try:
        result = Receiver(args.data).verify(allow_pilot=args.allow_pilot)
        if args.check_report is not None:
            expect(load_json(args.check_report), result, 'Saved independent result differs from current evidence')
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        print(json.dumps({'verdict': 'FAIL', 'error': str(error)}))
        raise SystemExit(1)
    print(json.dumps(result, indent=2, ensure_ascii=True))


if __name__ == '__main__':
    main()
