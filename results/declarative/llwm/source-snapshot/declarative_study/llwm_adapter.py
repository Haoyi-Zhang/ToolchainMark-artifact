"""LLWM native operations for the common declaration interpreter.

Only process execution, byte capture, and literal output acquisition occur here.
ER01--ER04 gates and expected-output expressions are JSON declarations.
"""
from __future__ import annotations
from pathlib import Path
import shutil
from .native_io import acquisition, capture_file, captured_run


class LlwmAdapter:
    operations = {'llvm_build', 'invoke', 'relocate', 'strip_debug', 'sections'}

    def __init__(self, directory, store, tools, plugins, probe_dir):
        self.directory, self.store = Path(directory).resolve(), Path(store).resolve()
        self.directory.mkdir(parents=True, exist_ok=False)
        self.tools, self.plugins, self.probe_dir = tools, plugins, Path(probe_dir)

    def invoke(self, operation, arguments, *, step_id, context_id):
        with acquisition(self.store, step_id, context_id) as evidence:
            try:
                value = self._invoke(operation, arguments, step_id, context_id, evidence)
                return {'status': 'OK', 'value': value, 'evidence': evidence, 'reason': None}
            except Exception as exc:
                return {'status': 'UNAVAILABLE', 'value': None, 'evidence': evidence,
                        'reason': type(exc).__name__ + ': ' + str(exc)}

    def _invoke(self, operation, a, step_id, context_id, evidence):
        def capture(path):
            row = capture_file(path, self.store)
            evidence.append({'kind': 'file-capture', 'step_id': step_id,
                             'context_id': context_id, 'files': [row]})
            return row
        def run(args, *, cwd=None, stdin=None, execution=False):
            kwargs = {'cwd': cwd or self.directory, 'input': stdin, 'capture_output': True,
                      'timeout': 45, 'check': False}
            if execution:
                kwargs['env'] = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
            proc = captured_run([str(x) for x in args], **kwargs)
            if proc.returncode != 0:
                raise RuntimeError('nonzero native process exit: ' + str(proc.returncode))
            return proc
        if operation == 'llvm_build':
            source = self.probe_dir / (a['interface'] + '.c')
            original_ir, marked_ir = self.directory / 'unmarked.ll', self.directory / 'marked.ll'
            unmarked, marked = self.directory / 'unmarked.bin', self.directory / 'marked.bin'
            capture(source)
            run([self.tools['clang'], '-O1', '-g', '-emit-llvm', '-S', source, '-o', original_ir])
            capture(original_ir)
            run([self.tools['clang'], '-g', '-' + a['optimization'], original_ir, '-o', unmarked])
            part = {'atoi': 'atoi', 'fgets': 'gets', 'sidedata': 'sidedata'}[a['interface']]
            family = 'sidedata' if a['interface'] == 'sidedata' else 'semacall'
            plugin = self.plugins[(a['variant'], family)]
            capture(plugin)
            run([self.tools['opt'], '-load-pass-plugin=' + str(plugin), '-passes=' + family + '-watermark',
                 '-' + part + '-key=' + a['key'], '-' + part + '-val=' + a['payload'],
                 '-S', original_ir, '-o', marked_ir])
            capture(marked_ir)
            run([self.tools['clang'], '-g', '-' + a['optimization'], marked_ir, '-o', marked])
            return {'unmarked': str(unmarked), 'marked': str(marked),
                    'unmarked_artifact': capture(unmarked), 'marked_artifact': capture(marked)}
        binary = Path(a['binary'])
        if operation == 'invoke':
            before = capture(binary)
            stdin = (a['input'] + '\n').encode() if a['interface'] == 'fgets' else None
            args = [binary] + ([] if a['interface'] == 'fgets' else [a['input']])
            proc = run(args, cwd=binary.parent, stdin=stdin, execution=True)
            return {'stdout_hex': proc.stdout.hex(), 'stderr_hex': proc.stderr.hex(),
                    'returncode': proc.returncode, 'before': before, 'after': capture(binary)}
        if operation == 'relocate':
            destination = self.directory / step_id
            destination.mkdir()
            target = destination / 'program'
            source = capture(binary)
            shutil.copy2(binary, target)
            return {'binary': str(target), 'source': source, 'artifact': capture(target),
                    'entries': sorted(p.name for p in destination.iterdir())}
        if operation == 'strip_debug':
            target = self.directory / 'stripped.bin'
            source = capture(binary)
            run([self.tools['strip'], '--strip-debug', '-o', target, binary])
            return {'binary': str(target), 'source': source, 'artifact': capture(target)}
        if operation == 'sections':
            before = capture(binary)
            proc = run([self.tools['readelf'], '-W', '-S', binary])
            return {'text': proc.stdout.decode('utf-8'), 'before': before, 'after': capture(binary)}
        raise ValueError('unknown LLWM operation: ' + operation)
