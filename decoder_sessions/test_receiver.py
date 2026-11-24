"""Focused native-binding controls over retained, copied decoder-session words.

No Java or acquisition adapter is invoked. The fixtures keep the actual process
outputs and locally change one association. Hashes and derived receipt fields
are refreshed so the tested rejection is not a stale-inventory side effect.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime import execute
from contract_runtime.receiver import verify_receipt
from decoder_sessions.verify import Receiver

PILOT = Path(os.environ.get(
    'DECODER_SESSION_BINDING_DATA',
    str(ARTIFACT / 'results/decoder-sessions/pilot-02')))


def read(path):
    # Fixture construction intentionally permits the duplicate-key negative;
    # the receiver under test must parse its raw file independently and reject.
    return json.loads(path.read_text())


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + '\n')


def binding(root, name):
    raw = (root / name).read_bytes()
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


class RetainedReturns:
    def __init__(self, actions):
        self.actions = {row['id']: deepcopy(row) for row in actions}
        self.operations = frozenset(row['operation'] for row in actions)

    def invoke(self, operation, arguments, *, step_id, context_id):
        row = self.actions[step_id]
        if (operation != row['operation'] or context_id != row['context_id']
                or canonical(arguments) != canonical(row['arguments'])):
            raise ValueError('A fixture mutation changed the declared native request')
        return {key: deepcopy(row[key]) for key in ('status', 'value', 'evidence', 'reason')}


class LocalWord:
    """Copy one word, its endpoint blobs, and the receiver's small metadata set."""
    def __init__(self, root, word):
        self.root, self.word = root, deepcopy(word)
        root.mkdir()
        for name in ('freeze.json', 'protocol.json', 'frame.json', 'input-manifest.json'):
            shutil.copyfile(PILOT / name, root / name)
        shutil.copytree(PILOT / 'plans', root / 'plans')
        self.folder = root / 'words' / word['id']
        self.folder.parent.mkdir()
        shutil.copytree(PILOT / 'words' / word['id'], self.folder)
        blobs = set()

        def collect(value):
            if type(value) is dict:
                if type(value.get('blob')) is str and value['blob'].startswith('blobs/'):
                    blobs.add(value['blob'])
                for item in value.values():
                    collect(item)
            elif type(value) is list:
                for item in value:
                    collect(item)

        for path in self.folder.rglob('*.json'):
            collect(read(path))
        for name in blobs:
            destination = root / name
            destination.parent.mkdir(exist_ok=True)
            shutil.copyfile(PILOT / name, destination)

    def native_path(self, step='last-a'):
        acquisition = read(self.folder / 'requests' / step / 'acquisition.json')
        return self.root / acquisition['result_file']

    def change_native(self, changes, step='last-a'):
        path = self.native_path(step)
        native = read(path)
        changes(native)
        write(path, native)

    def change_completion(self, **changes):
        path = self.folder / 'processes/process-01/journal/done.json'
        value = read(path)
        value.update(changes)
        write(path, value)

    def refresh(self, observation_change=None):
        """Rebind local bytes and recompute plan-derived fields, never native data."""
        receipt = read(self.folder / 'receipt.json')
        actions = {row['id']: row for row in receipt['actions']}
        commands = []
        for path in sorted((self.folder / 'processes').glob('process-*/command.json')):
            command = read(path)
            for key in ('stdin', 'stdout', 'stderr', 'ready', 'done'):
                row = command[key]
                if row is not None:
                    command[key] = binding(self.root, row['path'])
            write(path, command)
            commands.append(command)
        if (self.folder / 'close.json').is_file():
            close = read(self.folder / 'close.json')
            close['processes'] = commands
            write(self.folder / 'close.json', close)
            actions['close']['value'] = close
        actions['prepare']['value'] = read(self.folder / 'prepare.json')
        for step in ('first-a', 'middle-a', 'middle-b', 'last-a'):
            if step not in actions or actions[step]['status'] == 'SKIPPED':
                continue
            folder = self.folder / 'requests' / step
            acquired = read(folder / 'acquisition.json')
            end = self.root / acquired['result_file'] if acquired['result_file'] else None
            value = {'native': read(end) if end is not None and end.is_file() else None,
                     'before': read(folder / 'before.json'), 'after': read(folder / 'after.json'),
                     'acquisition': acquired}
            if observation_change is not None:
                observation_change(step, value)
            write(folder / 'observation.json', value)
            actions[step]['value'] = value
        for action in actions.values():
            action['evidence'] = [binding(self.root, row['path']) for row in action['evidence']]
        plan = read(self.root / 'plans' / (self.word['inputs']['history'] + '.json'))
        result = execute(plan, self.word['inputs'], RetainedReturns(receipt['actions']),
                         context_id=self.word['id'], max_workers=1)
        write(self.folder / 'receipt.json', result)
        write(self.folder / 'result.json', {
            **self.word,
            'receipt': binding(self.root, 'words/' + self.word['id'] + '/receipt.json'),
            'judgments': {row['id']: row['verdict'] for row in result['obligations']},
            'action_status': {row['id']: row['status'] for row in result['actions']}})


class NativeBindingControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (PILOT / 'completion.json').is_file():
            raise RuntimeError('A completed retained pilot is required; these controls never acquire it')
        cls.words = read(PILOT / 'frame.json')['words']

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='decoder-native-binding-')
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name)
        self.fixture_count = 0

    def fixture(self, algorithm='Stern', lifetime='R', history='AA'):
        word = next(row for row in self.words
                    if row['inputs']['algorithm'] == algorithm
                    and row['inputs']['lifetime'] == lifetime
                    and row['inputs']['history'] == history)
        self.fixture_count += 1
        return LocalWord(self.temporary / ('word-' + str(self.fixture_count)), word)

    def reject_native(self, local, reason):
        # These independent prerequisites demonstrate that a native association,
        # rather than plan interpretation or stale file hashes, is being tested.
        receipt = read(local.folder / 'receipt.json')
        plan = read(local.root / 'plans' / (local.word['inputs']['history'] + '.json'))
        report = verify_receipt(plan, receipt, expected_inputs=local.word['inputs'],
                                expected_context_id=local.word['id'])
        self.assertEqual(report['verdict'], 'PASS')
        for action in receipt['actions']:
            for row in action['evidence']:
                self.assertEqual(canonical(row), canonical(binding(local.root, row['path'])))
        with self.assertRaisesRegex(ValueError, reason):
            Receiver(local.root).word(local.word)

    def test_unmodified_success_blocked_and_known_failing_words_are_accepted(self):
        for algorithm, lifetime, expected in (
                ('Stern', 'R', {'SATISFIED'}),
                ('Steganography', 'P', {'INADMISSIBLE'}),
                ('Qu/Potkonjak', 'P', {'INCONSISTENT', 'INADMISSIBLE'})):
            with self.subTest(algorithm=algorithm):
                local = self.fixture(algorithm, lifetime)
                received = Receiver(local.root).word(local.word)
                self.assertEqual(set(received['judgments'].values()), expected)

    def test_reused_session_return_cannot_change_process_token(self):
        local = self.fixture()
        local.change_native(lambda row: row.update(process_token='another-process'))
        local.refresh()
        self.reject_native(local, 'Native request association differs: process_token')

    def test_reused_object_arm_cannot_report_a_fresh_object(self):
        local = self.fixture()
        local.change_native(lambda row: row.update(algorithm_constructions=2,
                            algorithm_object_ordinal=2, same_algorithm_reference_as_previous=False))
        local.change_completion(algorithm_constructions=2)
        local.refresh()
        self.reject_native(local, 'Native lifecycle or parameter association differs: algorithm_constructions')

    def test_fresh_object_arm_cannot_report_reuse(self):
        local = self.fixture(lifetime='O')
        local.change_native(lambda row: row.update(algorithm_constructions=1,
                            algorithm_object_ordinal=1, same_algorithm_reference_as_previous=True))
        local.change_completion(algorithm_constructions=1)
        local.refresh()
        self.reject_native(local, 'Native lifecycle or parameter association differs: algorithm_constructions')

    def test_key_and_authorized_auxiliary_contexts_remain_bound(self):
        for which in ('key', 'original', 'gtw-key'):
            with self.subTest(context=which):
                local = self.fixture('Graph Theoretic Watermark' if which == 'gtw-key' else 'Stern')
                if which == 'key':
                    local.change_native(lambda row: row.update(parameter_key='another-key'))
                    reason = 'Native lifecycle or parameter association differs: parameter_key'
                else:
                    prop = 'Key File' if which == 'gtw-key' else 'Original File'
                    def change(row):
                        for phase in ('properties_before', 'properties_after'):
                            row[phase][prop]['text'] = row['target']
                    local.change_native(change)
                    reason = 'GTW key auxiliary differs' if which == 'gtw-key' else 'Original-program auxiliary differs'
                local.refresh()
                self.reject_native(local, reason)

    def test_incomplete_iterator_cannot_be_labeled_complete(self):
        local = self.fixture()
        local.change_native(lambda row: row.update(kind='null-iterator', iteration_complete=True))
        local.refresh()
        self.reject_native(local, 'Absent or capped enumeration labeled complete')

    def test_endpoint_cannot_omit_authorized_smconfig_role(self):
        local = self.fixture()
        for name in ('before.json', 'after.json'):
            path = local.folder / 'requests/last-a' / name
            value = read(path)
            del value['original_constraints']
            write(path, value)
        local.refresh()
        self.reject_native(local, 'Endpoint omits an authorized role or sidecar')

    def test_candidate_type_is_structured_and_bound_to_raw_return(self):
        for malformed_raw in (True, False):
            with self.subTest(malformed_raw=malformed_raw):
                local = self.fixture()
                if malformed_raw:
                    local.change_native(lambda row: row['candidate_java_types'].__setitem__(0, False))
                    local.refresh()
                    reason = 'Native candidate lost its null/type distinction'
                else:
                    def change(step, value):
                        if step == 'last-a':
                            value['native']['candidate_java_types'][0] = 'java.math.BigInteger'
                    local.refresh(observation_change=change)
                    reason = 'Grouped observation differs from raw files'
                self.reject_native(local, reason)

    def test_boolean_and_integer_native_fields_are_not_interchangeable(self):
        for which in ('reference-flag', 'acquisition-flag', 'construction-count'):
            with self.subTest(field=which):
                local = self.fixture()
                if which == 'reference-flag':
                    local.change_native(lambda row: row.update(same_application_reference_as_previous=0))
                    reason = 'Native lifecycle or parameter association differs: same_application_reference_as_previous'
                elif which == 'construction-count':
                    local.change_native(lambda row: row.update(algorithm_constructions=True))
                    reason = 'Native lifecycle or parameter association differs: algorithm_constructions'
                else:
                    path = local.folder / 'requests/last-a/acquisition.json'
                    acquired = read(path)
                    acquired['timed_out'] = 0
                    write(path, acquired)
                    reason = 'Acquisition flag is not Boolean'
                local.refresh()
                self.reject_native(local, reason)

    def test_duplicate_raw_json_member_is_rejected_after_hash_refresh(self):
        local = self.fixture()
        path = local.native_path()
        original = path.read_text()
        path.write_text('{"request_ordinal": 99,' + original.lstrip()[1:])
        local.refresh()
        self.reject_native(local, 'duplicate JSON key: request_ordinal')

    def test_middle_call_cannot_disappear_from_invocation_journal(self):
        local = self.fixture(history='ABA')
        path = local.folder / 'invocations.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(sum(row['step_id'] == 'middle-b' for row in rows), 1)
        path.write_text(''.join(json.dumps(row, ensure_ascii=True) + '\n'
                                for row in rows if row['step_id'] != 'middle-b'))
        # The invocation journal has no file-binding envelope to refresh. All
        # receipt/native files remain intact; only this middle call is omitted.
        self.reject_native(local, 'Actual adapter invocation sequence differs')


if __name__ == '__main__':
    unittest.main()
