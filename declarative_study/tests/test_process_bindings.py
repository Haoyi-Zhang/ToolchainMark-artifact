"""Recorded-observation controls using actual retained native byte objects.

These tests launch no target program and contribute no research-case denominator.
They preserve scientific S, I and IA results while rejecting contradictory record
associations. The existing complete studies supply the unmodified observations.
"""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from contract_runtime.receiver import verify_receipt
from declarative_study.native_io import verify_evidence
from declarative_study.verify import llvm_binding_context, value_bindings

ARTIFACT = Path(__file__).resolve().parents[2]
DATA = ARTIFACT / 'results/declarative'
CASES = {
    'host': ('reference', 'pass-1/string/CLEAN/MR02'),
    'remove': ('reference', 'pass-1/string/CLEAN/MR09'),
    'parallel': ('reference', 'pass-1/string/CLEAN/MR12'),
    'identity': ('identity', 'pass-1/string/replace-on-B/MR13'),
    'llvm-i': ('llwm', 'pass-1/upstream/atoi/payload-1/O0'),
    'llvm-s': ('llwm', 'pass-1/literal-output-repair/atoi/payload-1/O0'),
    'symbols': ('reference', 'pass-1/symbol/CLEAN/MR05'),
    'symbol-remove': ('reference', 'pass-1/symbol/CLEAN/MR09'),
}


def actions(receipt):
    return {row['id']: row for row in receipt['actions']}


def commands(action):
    return [row for row in action['evidence'] if row['kind'] == 'process']


class ProcessBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples = {}
        cls.context = llvm_binding_context(DATA / 'llwm')
        for name, (study, case) in CASES.items():
            root = DATA / study
            directory = root / 'cases' / case
            read = lambda path: json.loads(path.read_text())
            cls.samples[name] = (root, read(directory / 'plan.json'), read(directory / 'receipt.json'),
                                 read(root / 'environment.json')['tools'])

    def record(self, name):
        return deepcopy(self.samples[name][2])

    def check(self, name, receipt, *, plan_check=True):
        root, plan, _, tools = self.samples[name]
        if plan_check:
            verify_receipt(plan, receipt)
        verify_evidence(receipt, root)
        return value_bindings(receipt, root,
                              llvm_context=self.context if root.name == 'llwm' else None,
                              native_tools=tools)

    def test_all_real_positive_records_including_scientific_i_and_ia_are_valid(self):
        for name in CASES:
            with self.subTest(name=name):
                self.check(name, self.record(name))
        self.assertEqual(actions(self.record('identity'))['after']['status'], 'OK')
        self.assertEqual(self.record('identity')['obligations'][0]['verdict'], 'INADMISSIBLE')
        self.assertEqual(self.record('llvm-i')['obligations'][0]['verdict'], 'INCONSISTENT')

    def test_host_invoke_sections_and_extract_bind_both_process_target_versions(self):
        rows = [('host', 'base-host', 'marked-host'), ('llvm-s', 'unmarked-key', 'marked-key'),
                ('llvm-s', 'debug-before', 'debug-after'), ('symbols', 'first-value', 'second-value')]
        for name, target_id, alternate_id in rows:
            for endpoint in ('files_before', 'files_after'):
                with self.subTest(name=name, operation=target_id, endpoint=endpoint):
                    record = self.record(name); aa = actions(record)
                    target, other = aa[target_id], aa[alternate_id]
                    alternate = deepcopy(other['value']['before'])
                    alternate['path'] = target['arguments']['binary']
                    event = commands(target)[0]
                    index = next(i for i, row in enumerate(event[endpoint]) if row['path'] == alternate['path'])
                    self.assertNotEqual(event[endpoint][index]['sha256'], alternate['sha256'])
                    event[endpoint][index] = alternate
                    with self.assertRaisesRegex(ValueError, 'process target version'):
                        self.check(name, record)

    def test_debug_transform_binds_flags_exit_source_destination_and_presence(self):
        for change in ('flag', 'returncode', 'boolean-returncode', 'source', 'destination', 'absent'):
            with self.subTest(change=change):
                record = self.record('llvm-s'); aa = actions(record); action = aa['strip']; event = commands(action)[0]
                if change == 'flag': event['argv'][1] = '--strip-all'
                elif change == 'returncode': event['returncode'] = 3
                elif change == 'boolean-returncode': event['returncode'] = False
                elif change == 'source': event['argv'][-1] = aa['build']['value']['unmarked']
                elif change == 'destination': event['argv'][3] += '.other'
                else: action['evidence'].remove(event)
                with self.assertRaises(ValueError): self.check('llvm-s', record)

    def test_strip_capture_order_and_output_versions_are_part_of_binding(self):
        for change in ('input-order', 'output-order', 'output-version'):
            with self.subTest(change=change):
                record = self.record('llvm-s'); action = actions(record)['strip']; event = commands(action)[0]
                captures = [e for e in action['evidence'] if e['kind'] == 'file-capture']
                if change == 'input-order':
                    action['evidence'].remove(captures[0]); action['evidence'].append(captures[0])
                elif change == 'output-order':
                    action['evidence'].remove(captures[-1]); action['evidence'].insert(0, captures[-1])
                else:
                    other = deepcopy(action['value']['source']); other['path'] = action['value']['binary']
                    event['files_after'].append(other)
                with self.assertRaises(ValueError): self.check('llvm-s', record)

    def test_tools_and_invoked_program_identity_are_separate_bindings(self):
        for step in ('strip', 'debug-before', 'marked-key'):
            for change in ('identity', 'missing'):
                with self.subTest(step=step, change=change):
                    record = self.record('llvm-s'); event = commands(actions(record)[step])[0]
                    if change == 'missing': del event['executable']
                    else: event['executable']['sha256'] = '0' * 64
                    with self.assertRaisesRegex(ValueError, 'identity'):
                        self.check('llvm-s', record)

    def test_invoke_and_sections_do_not_accept_another_context_or_input(self):
        for step, field, replacement in [('marked-key', 'cwd', '/different/context'),
                                         ('debug-before', 'stdin_hex', '30')]:
            with self.subTest(step=step):
                record = self.record('llvm-s'); commands(actions(record)[step])[0][field] = replacement
                with self.assertRaises(ValueError): self.check('llvm-s', record)
        record = self.record('llvm-s'); actions(record)['marked-key']['value']['returncode'] = False
        with self.assertRaisesRegex(ValueError, 'invocation output'):
            self.check('llvm-s', record)

    def test_transform_process_chain_starts_at_captured_input(self):
        record = self.record('symbol-remove'); action = actions(record)['intervention']; event = commands(action)[0]
        replacement = deepcopy(action['value']['artifact'])
        index = next(i for i, row in enumerate(event['files_before']) if row['path'] == replacement['path'])
        self.assertNotEqual(event['files_before'][index]['sha256'], replacement['sha256'])
        event['files_before'][index] = replacement
        with self.assertRaisesRegex(ValueError, 'preceding target version'):
            self.check('symbol-remove', record)

    def test_conflicting_optimization_flags_cannot_retain_an_old_actual_setting(self):
        record = self.record('host'); action = actions(record)['unmarked']
        event = next(e for e in commands(action) if '-std=c11' in e['argv'])
        event['argv'].insert(2, '-O0'); action['value']['command'].insert(2, '-O0')
        with self.assertRaisesRegex(ValueError, 'actual build settings'):
            self.check('host', record)

    def test_session_descriptor_is_bound_to_the_recorded_decoder_context(self):
        record = self.record('host'); actions(record)['session']['value']['session_id'] += ':different'
        with self.assertRaisesRegex(ValueError, 'session descriptor'):
            self.check('host', record, plan_check=False)


if __name__ == '__main__':
    unittest.main()
