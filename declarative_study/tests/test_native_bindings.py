"""Small saved-record controls; these acquire no native research cases."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from contract_runtime import execute
from contract_runtime.receiver import InvalidRecord, verify_receipt
from declarative_study.verify import llvm_binding_context, value_bindings


CONTEXT = 'pass-1/upstream/atoi/payload-0/O0'


class Records:
    """An in-memory byte store with real content identities, not expected verdicts."""

    def __init__(self):
        self.blobs = {}

    def file(self, path, raw):
        digest = hashlib.sha256(raw).hexdigest()
        blob = 'blobs/' + digest + '.bin.gz'
        self.blobs[blob] = raw
        return {'path': str(path), 'sha256': digest, 'bytes': len(raw), 'blob': blob}

    def read(self, record, _store):
        raw = self.blobs[record['blob']]
        if len(raw) != record['bytes'] or hashlib.sha256(raw).hexdigest() != record['sha256']:
            raise ValueError('in-memory byte identity mismatch')
        return raw

    @staticmethod
    def capture(row, step='build'):
        return {'kind': 'file-capture', 'step_id': step, 'context_id': CONTEXT, 'files': [row]}

    @staticmethod
    def command(argv, before, *, cwd='/old/producer/case', stdout=b'', step='build'):
        return {'kind': 'process', 'step_id': step, 'context_id': CONTEXT,
                'argv': argv, 'cwd': cwd, 'status': 'COMPLETED', 'returncode': 0,
                'stdin_hex': None, 'stdout_hex': stdout.hex(), 'stderr_hex': '',
                'files_before': deepcopy(before), 'files_after': deepcopy(before)}

    @staticmethod
    def receipt(actions, inputs=None):
        return {'context_id': CONTEXT, 'inputs': inputs or {}, 'actions': actions}

    def native(self):
        source = self.file('/old/producer/case/host.c', b'int main(void){return 0;}\n')
        binary = self.file('/old/producer/case/program', b'owned compiled fixture')
        argv = ['gcc', '-std=c11', '-O2', source['path'], '-o', binary['path']]
        compiler = self.command(argv, [source])
        value = {'source': source, 'artifact': binary, 'binary': binary['path'],
                 'compiler': 'gcc', 'optimization': 'O2', 'command': deepcopy(argv),
                 'returncode': 0, 'session_id': 'session-1'}
        return {'id': 'build', 'operation': 'build', 'status': 'OK',
                'arguments': {'session': 'session-1'}, 'value': value,
                'start_event': 1, 'end_event': 2,
                'evidence': [compiler, self.capture(source), self.capture(binary)]}

    def host(self):
        binary = self.file('/old/producer/case/program', b'owned host fixture')
        inputs = [0, 5]
        commands = [self.command([binary['path'], str(number)], [binary],
                                stdout=(str(number + 1) + '\n').encode(), step='host')
                    for number in inputs]
        return {'id': 'host', 'operation': 'host', 'status': 'OK',
                'arguments': {'binary': binary['path'], 'inputs': inputs},
                'value': {'inputs': deepcopy(inputs), 'outputs': ['1', '6'],
                          'before': binary, 'after': binary},
                'evidence': [self.capture(binary, 'host'), *commands, self.capture(binary, 'host')]}

    def llvm(self, interface='atoi', variant='upstream'):
        directory = Path('/old/producer/study/cases') / CONTEXT / 'native'
        original = str(directory / 'unmarked.ll'); marked_ir = str(directory / 'marked.ll')
        source = self.file('/old/project/artifact/external_llwm/probes/' + interface + '.c', b'owned probe source')
        family = 'sidedata' if interface == 'sidedata' else 'semacall'
        part = {'atoi': 'atoi', 'fgets': 'gets', 'sidedata': 'sidedata'}[interface]
        plugin_relative = 'setup/' + variant + '/' + family + '.so'
        plugin = self.file('/old/producer/study/' + plugin_relative, b'owned plugin bytes')
        unmarked_input = self.file(original, b'unmarked IR')
        marked_input = self.file(marked_ir, b'marked IR')
        unmarked = self.file(directory / 'unmarked.bin', b'unmarked executable')
        marked = self.file(directory / 'marked.bin', b'marked executable')
        clang = '/old/toolchain/bin/clang'; opt = '/old/toolchain/bin/opt'
        a = {'interface': interface, 'variant': variant, 'key': '1234', 'payload': 'A%%B', 'optimization': 'O0'}
        commands = [
            self.command([clang, '-O1', '-g', '-emit-llvm', '-S', source['path'], '-o', original], [source], cwd=str(directory)),
            self.command([clang, '-g', '-O0', original, '-o', unmarked['path']], [unmarked_input], cwd=str(directory)),
            self.command([opt, '-load-pass-plugin=' + plugin['path'], '-passes=' + family + '-watermark',
                          '-' + part + '-key=1234', '-' + part + '-val=A%%B', '-S', original, '-o', marked_ir],
                         [unmarked_input], cwd=str(directory)),
            self.command([clang, '-g', '-O0', marked_ir, '-o', marked['path']], [marked_input], cwd=str(directory))]
        action = {'id': 'build', 'operation': 'llvm_build', 'status': 'OK', 'arguments': a,
                  'value': {'marked': marked['path'], 'unmarked': unmarked['path'],
                            'marked_artifact': marked, 'unmarked_artifact': unmarked},
                  'evidence': [self.capture(source), commands[0], self.capture(unmarked_input), commands[1],
                               self.capture(plugin), commands[2], self.capture(marked_input), commands[3],
                               self.capture(unmarked), self.capture(marked)]}
        context = {'probes': {'external_llwm/probes/' + interface + '.c': source},
                   'setup': {plugin_relative: plugin}}
        return action, context


class NativeBindingTests(unittest.TestCase):
    def setUp(self):
        self.records = Records()
        self.reader = patch('declarative_study.verify.verify_file', side_effect=self.records.read)
        self.reader.start()
        self.addCleanup(self.reader.stop)

    def check(self, actions, **kwargs):
        return value_bindings(self.records.receipt(actions), '/different/receiver/root', **kwargs)

    def test_native_and_preceding_cached_build_are_accepted(self):
        first = self.records.native()
        cached = deepcopy(first)
        cached.update(id='cached', start_event=3, end_event=4)
        cached['evidence'] = [row for row in cached['evidence'] if row['kind'] != 'process']
        result = self.check([first, cached])
        self.assertEqual(len(result['blobs']), 2)

    def test_native_return_fields_are_bound_to_command_and_capture(self):
        for field, changed in [('command', ['other-compiler']), ('returncode', 7),
                               ('returncode', False), ('binary', '/other/output'), ('session_id', 'other')]:
            with self.subTest(field=field, changed=changed):
                action = self.records.native()
                action['value'][field] = changed
                with self.assertRaises(ValueError): self.check([action])

    def test_native_changed_raw_command_or_source_version_is_rejected(self):
        for change in ('optimization', 'returncode', 'source-version', 'late-output-version'):
            with self.subTest(change=change):
                action = self.records.native()
                command = action['evidence'][0]
                if change == 'optimization': command['argv'][2] = '-O0'
                elif change == 'returncode': command['returncode'] = 3
                elif change == 'source-version':
                    command['files_before'][0] = self.records.file(action['value']['source']['path'], b'other source')
                else:
                    command['files_after'].append(self.records.file(action['value']['binary'], b'other binary'))
                with self.assertRaises(ValueError): self.check([action])

    def test_cached_result_requires_completed_matching_predecessor(self):
        first = self.records.native()
        cached = deepcopy(first); cached.update(id='cached', start_event=3, end_event=4)
        cached['evidence'] = [row for row in cached['evidence'] if row['kind'] != 'process']
        with self.assertRaisesRegex(ValueError, 'preceding'): self.check([cached])
        first['end_event'] = 4
        with self.assertRaisesRegex(ValueError, 'preceding'): self.check([first, cached])
        first['end_event'] = 2; cached['value']['optimization'] = 'O0'
        with self.assertRaisesRegex(ValueError, 'preceding'): self.check([first, cached])

    def test_host_returned_inputs_and_raw_arguments_are_separate_checks(self):
        action = self.records.host()
        self.assertEqual(self.check([action])['raw_process_output_bindings'], 2)
        changed = deepcopy(action); changed['value']['inputs'] = [0, 6]
        with self.assertRaisesRegex(ValueError, 'host inputs'): self.check([changed])
        changed = deepcopy(action); changed['value']['inputs'] = [False, 5]
        with self.assertRaisesRegex(ValueError, 'host inputs'): self.check([changed])
        changed = deepcopy(action); changed['evidence'][1]['argv'][-1] = '6'
        with self.assertRaisesRegex(ValueError, 'host request'): self.check([changed])
        changed = deepcopy(action); changed['value']['outputs'][1] = '7'
        with self.assertRaisesRegex(ValueError, 'raw output'): self.check([changed])

    def test_changed_plan_is_rejected_before_correct_raw_record_is_reused(self):
        action = self.records.host()
        plan = {'schema': 'toolchainmark-contract-v1', 'id': 'host-fixture', 'inputs': {},
                'actions': [{'id': 'host', 'operation': 'host', 'arguments': {
                    key: {'literal': value} for key, value in action['arguments'].items()}}], 'obligations': []}
        class Adapter:
            operations = {'host'}
            def invoke(self, operation, arguments, **kwargs):
                return {'status': 'OK', 'value': action['value'], 'evidence': action['evidence'], 'reason': None}
        receipt = execute(plan, {}, Adapter(), context_id=CONTEXT)
        verify_receipt(plan, receipt)
        value_bindings(receipt, '/new/receiver/root')
        changed = deepcopy(plan)
        changed['actions'][0]['arguments']['inputs']['literal'] = [0, 6]
        with self.assertRaises(InvalidRecord): verify_receipt(changed, receipt)

    def test_llwm_all_three_interfaces_and_two_variants_accept_old_run_paths(self):
        for interface in ('atoi', 'fgets', 'sidedata'):
            for variant in ('upstream', 'literal-output-repair'):
                with self.subTest(interface=interface, variant=variant):
                    action, context = self.records.llvm(interface, variant)
                    self.assertEqual(len(self.check([action], llvm_context=context)['blobs']), 6)

    def test_llwm_changed_declared_arguments_do_not_relabel_raw_build(self):
        for field, changed in [('interface', 'fgets'), ('variant', 'literal-output-repair'),
                               ('key', '4321'), ('payload', 'other'), ('optimization', 'O2')]:
            with self.subTest(field=field):
                action, context = self.records.llvm()
                action['arguments'][field] = changed
                with self.assertRaises(ValueError): self.check([action], llvm_context=context)

    def test_llwm_raw_command_count_stage_request_and_intermediate_path_are_checked(self):
        for change in ('extra-command', 'key', 'optimization', 'source', 'intermediate', 'cwd', 'failed-link'):
            with self.subTest(change=change):
                action, context = self.records.llvm()
                commands = [e for e in action['evidence'] if e['kind'] == 'process']
                if change == 'extra-command': action['evidence'].append(deepcopy(commands[0]))
                elif change == 'key': commands[2]['argv'][3] = '-atoi-key=wrong'
                elif change == 'optimization': commands[1]['argv'][2] = '-O2'
                elif change == 'source': commands[0]['argv'][5] = '/other/probes/fgets.c'
                elif change == 'intermediate': commands[3]['argv'][3] = '/other/marked.ll'
                elif change == 'cwd': commands[0]['cwd'] = '/other/case'
                else: commands[3]['returncode'] = 1
                with self.assertRaises(ValueError): self.check([action], llvm_context=context)

    def test_llwm_frozen_probe_plugin_and_input_version_are_distinct_bindings(self):
        for change in ('probe', 'plugin', 'input-version', 'returned-output'):
            with self.subTest(change=change):
                action, context = self.records.llvm()
                if change in ('probe', 'plugin'):
                    group = context['probes' if change == 'probe' else 'setup']
                    key = next(iter(group)); group[key] = {**group[key], 'sha256': '0' * 64}
                elif change == 'input-version':
                    command = [e for e in action['evidence'] if e['kind'] == 'process'][2]
                    old = command['files_before'][0]
                    command['files_before'][0] = self.records.file(old['path'], b'another IR version')
                else:
                    action['value']['marked_artifact'] = self.records.file(action['value']['marked'], b'another output')
                with self.assertRaises(ValueError): self.check([action], llvm_context=context)

    def test_llwm_identity_loader_checks_saved_probe_and_setup_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = 'external_llwm/probes/atoi.c'; plugin = 'setup/upstream/semacall.so'
            raw_probe, raw_plugin = b'owned probe', b'owned plugin'
            for relative, raw in [('source-snapshot/' + probe, raw_probe), (plugin, raw_plugin)]:
                path = root / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            entry = lambda path, raw: {'path': path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            (root / 'producer-freeze.json').write_text(json.dumps({'inputs': [entry(probe, raw_probe)]}))
            (root / 'setup/files.json').write_text(json.dumps([entry(plugin, raw_plugin)]))
            self.assertEqual(set(llvm_binding_context(root)['probes']), {probe})
            (root / plugin).write_bytes(b'changed plugin')
            with self.assertRaisesRegex(ValueError, 'setup bytes'): llvm_binding_context(root)
            (root / plugin).write_bytes(raw_plugin)
            (root / 'source-snapshot' / probe).write_bytes(b'changed probe')
            with self.assertRaisesRegex(ValueError, 'frozen LLWM probe'): llvm_binding_context(root)


if __name__ == '__main__':
    unittest.main()
