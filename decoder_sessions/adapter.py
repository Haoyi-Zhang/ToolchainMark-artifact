"""Raw SandMark acquisition for declared words; scientific judgments live in plans."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import signal
import subprocess
import time

from decoder_sessions.common import FILES, binding, clone_file, read_json, snapshot, write_json


class NativeProcess:
    def __init__(self, adapter, ordinal: int):
        self.adapter = adapter
        self.folder = adapter.folder / 'processes' / f'process-{ordinal:02d}'
        self.folder.mkdir(parents=True)
        self.journal = self.folder / 'journal'
        self.journal.mkdir()
        self.token = adapter.word + f'-process-{ordinal:02d}'
        self.argv = [adapter.java, '-Djava.awt.headless=true', '-Dfile.encoding=UTF-8', '-Xmx512m',
                     '-cp', str(adapter.run / 'bridge') + os.pathsep + adapter.tool,
                     'SessionBridge', adapter.lifetime, adapter.algorithm, str(self.journal), self.token]
        self.start_ns = time.time_ns()
        self.start_monotonic = time.monotonic()
        self.stdout = (self.folder / 'stdout.bin').open('wb')
        self.stderr = (self.folder / 'stderr.bin').open('wb')
        self.stdin = bytearray()
        self.timeouts = []
        self.write_errors = []
        self.closed = False
        self.process = subprocess.Popen(self.argv, cwd=adapter.folder, env=adapter.environment, stdin=subprocess.PIPE,
                                        stdout=self.stdout, stderr=self.stderr, start_new_session=True)
        self.ready = self.wait_file(self.journal / 'ready.json', self.start_monotonic + 30, 'startup')

    def wait_file(self, path: Path, deadline: float, stage: str):
        while True:
            if path.is_file(): return read_json(path)
            if self.process.poll() is not None: return None
            if time.monotonic() >= deadline:
                self.timeouts.append(stage)
                self.kill()
                return None
            time.sleep(.01)

    def send(self, raw: bytes) -> bool:
        try:
            self.process.stdin.write(raw)
            self.process.stdin.flush()
            self.stdin.extend(raw)
            return True
        except (BrokenPipeError, OSError, ValueError) as error:
            self.write_errors.append({'exception_class': type(error).__name__, 'message': str(error),
                                      'attempted_hex': raw.hex()})
            return False

    def kill(self):
        if self.process.poll() is None:
            try: os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        self.process.wait()

    def recognize(self, request: str, role: str, folder: Path, key: str):
        fields = [request, role, str(folder / FILES['target']), key,
                  str(folder / FILES['original']), str(folder / FILES['key_file'])]
        raw = b'\t'.join(base64.b64encode(x.encode('utf-8')) for x in fields) + b'\n'
        req = self.adapter.folder / 'requests' / request
        req.mkdir(parents=True, exist_ok=True)
        (req / 'message.bin').write_bytes(raw)
        write_json(req / 'request.json', dict(zip(('request_id', 'role', 'target', 'key', 'original_file', 'key_file'), fields)))
        deadline = time.monotonic() + 30
        begin = time.monotonic_ns()
        sent = self.send(raw)
        result = self.wait_file(self.journal / (request + '.end.json'), deadline, request) if sent else None
        acquired = {'process_token': self.token, 'pid': self.process.pid, 'request_id': request,
                    'message_written': sent, 'elapsed_ns': time.monotonic_ns() - begin,
                    'timed_out': request in self.timeouts, 'result_present': result is not None,
                    'result_file': (self.journal / (request + '.end.json')).relative_to(self.adapter.run).as_posix()}
        write_json(req / 'acquisition.json', acquired)
        return result, acquired

    def close(self):
        if self.closed: return self.record
        if self.process.poll() is None:
            self.send(b'STOP\n')
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.timeouts.append('shutdown'); self.kill()
        try: self.process.stdin.close()
        except (BrokenPipeError, OSError): pass
        self.stdout.close(); self.stderr.close()
        (self.folder / 'stdin.bin').write_bytes(self.stdin)
        self.record = {'schema': 'sandmark-session-process-v1', 'process_token': self.token,
                       'argv': self.argv, 'cwd': str(self.adapter.folder), 'environment': self.adapter.environment,
                       'pid': self.process.pid,
                       'returncode': self.process.returncode, 'timeouts': self.timeouts,
                       'write_errors': self.write_errors, 'start_unix_ns': self.start_ns,
                       'elapsed_ns': int((time.monotonic() - self.start_monotonic) * 1e9),
                       'stdin': binding(self.folder / 'stdin.bin', self.adapter.run),
                       'stdout': binding(self.folder / 'stdout.bin', self.adapter.run),
                       'stderr': binding(self.folder / 'stderr.bin', self.adapter.run),
                       'ready': binding(self.journal / 'ready.json', self.adapter.run) if (self.journal / 'ready.json').exists() else None,
                       'done': binding(self.journal / 'done.json', self.adapter.run) if (self.journal / 'done.json').exists() else None}
        write_json(self.folder / 'command.json', self.record)
        self.closed = True
        return self.record


class SessionAdapter:
    operations = frozenset({'sessions.prepare', 'sessions.open', 'sessions.recognize', 'sessions.close'})

    def __init__(self, run: Path, word: str, inputs: dict, manifest: dict, freeze: dict):
        self.run, self.word, self.inputs, self.manifest = run, word, inputs, manifest
        self.folder = run / 'words' / word
        self.folder.mkdir(parents=True)
        self.java, self.tool = freeze['runtime']['java']['path'], freeze['tool']['path']
        self.environment = freeze['launch_environment']
        self.algorithm, self.lifetime = inputs['algorithm_class'], inputs['lifetime']
        self.processes = []
        self.persistent = None
        self.failed = False

    def _response(self, value, evidence, reason=None):
        return {'status': 'OK' if reason is None else 'UNAVAILABLE', 'value': value,
                'evidence': evidence, 'reason': reason}

    def invoke(self, operation, arguments, *, step_id, context_id):
        if context_id != self.word: raise ValueError('Word context differs')
        with (self.folder / 'invocations.jsonl').open('a') as out:
            import json
            out.write(json.dumps({'operation': operation, 'arguments': arguments, 'step_id': step_id,
                                  'context_id': context_id}, sort_keys=True) + '\n')
        if operation == 'sessions.prepare': return self.prepare(arguments)
        if operation == 'sessions.open': return self.open(arguments)
        if operation == 'sessions.recognize': return self.recognize(step_id, arguments)
        if operation == 'sessions.close': return self.close(arguments)
        raise ValueError('Unknown operation')

    def prepare(self, args):
        roles = {'A': args['a_case']}
        if args['history'] == 'ABA': roles['B'] = args['b_case']
        entries = {role: self.manifest['cases'][cid] for role, cid in roles.items()}
        available = all(entry['archived_marked_input_available'] for entry in entries.values())
        folders = {role: (self.folder / 'work' / role).relative_to(self.run).as_posix() for role in roles}
        observed = {}
        if available:
            for role, entry in entries.items():
                folder = self.run / folders[role]; folder.mkdir(parents=True)
                for file_role, info in entry['files'].items():
                    if info['present']:
                        clone_file(self.run / info['path'], folder / FILES[file_role])
                observed[role] = snapshot(folder, self.run, self.run / 'blobs')
        value = {'all_inputs_available': available, 'folders': folders,
                 'archived_cases': roles, 'initial_context': observed}
        write_json(self.folder / 'prepare.json', value)
        return self._response(value, [binding(self.folder / 'prepare.json', self.run)])

    def _start(self):
        process = NativeProcess(self, len(self.processes) + 1)
        self.processes.append(process)
        return process

    def open(self, args):
        if args != {'algorithm_class': self.algorithm, 'lifetime': self.lifetime}: raise ValueError('Session arguments differ')
        ready = None
        if self.lifetime != 'P':
            self.persistent = self._start(); ready = self.persistent.ready
            if ready is None:
                record = self.persistent.close(); self.failed = True
                value = {'session_id': self.word, 'lifetime': self.lifetime, 'ready': None,
                         'startup_process': record}
                write_json(self.folder / 'open.json', value)
                return self._response(value, [binding(self.folder / 'open.json', self.run),
                                             binding(self.persistent.folder / 'command.json', self.run)],
                                      'jvm-startup-unavailable')
        value = {'session_id': self.word, 'lifetime': self.lifetime, 'ready': ready}
        write_json(self.folder / 'open.json', value)
        return self._response(value, [binding(self.folder / 'open.json', self.run)])

    def recognize(self, step_id, args):
        if args['session'] != self.word or self.failed: raise ValueError('Unavailable or mismatched session')
        folder = self.run / args['folder']
        before = snapshot(folder, self.run, self.run / 'blobs')
        req = self.folder / 'requests' / step_id; req.mkdir(parents=True)
        write_json(req / 'before.json', before)
        process = self._start() if self.lifetime == 'P' else self.persistent
        if process.ready is None:
            native, acquired = None, {'process_token': process.token, 'pid': process.process.pid,
                                      'request_id': step_id, 'message_written': False,
                                      'elapsed_ns': 0, 'timed_out': 'startup' in process.timeouts,
                                      'result_present': False, 'result_file': None}
            write_json(req / 'acquisition.json', acquired)
        else:
            native, acquired = process.recognize(step_id, args['role'], folder, args['key'])
        if self.lifetime == 'P': process.close()
        after = snapshot(folder, self.run, self.run / 'blobs')
        write_json(req / 'after.json', after)
        value = {'native': native, 'before': before, 'after': after, 'acquisition': acquired}
        write_json(req / 'observation.json', value)
        evidence = [binding(req / name, self.run) for name in ('before.json', 'after.json', 'acquisition.json', 'observation.json')]
        if native is not None: evidence.append(binding(process.journal / (step_id + '.end.json'), self.run))
        complete = (type(native) is dict and native.get('kind') == 'extract-return'
                    and native.get('iteration_complete') is True
                    and type(native.get('candidates')) is list and type(native.get('candidate_java_types')) is list
                    and len(native['candidates']) == len(native['candidate_java_types'])
                    and all(v is None or type(v) is str for v in native['candidates'])
                    and all(v is None or type(v) is str for v in native['candidate_java_types']))
        if not complete:
            self.failed = True
            return self._response(value, evidence, 'recognition-unavailable:' + (native.get('kind', 'malformed') if type(native) is dict else 'no-return'))
        return self._response(value, evidence)

    def close(self, args):
        if args['session'] != self.word: raise ValueError('Close context differs')
        records = [process.close() for process in self.processes]
        value = {'session_id': self.word, 'processes': records}
        write_json(self.folder / 'close.json', value)
        evidence = [binding(self.folder / 'close.json', self.run)]
        evidence.extend(binding(process.folder / 'command.json', self.run) for process in self.processes)
        return self._response(value, evidence)

    def cleanup(self):
        for process in self.processes: process.close()
