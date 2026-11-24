"""Exact native result types using one successful retained external case."""
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from contract_runtime import execute
from contract_runtime.receiver import verify_receipt
from external_sandmark.verify_study import binding, reobserve

ARTIFACT = Path(__file__).resolve().parents[2]


class TypedSandmarkBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = ARTIFACT / 'results/external-sandmark/formal-01'
        cls.case = root / 'cases/case-0004'
        read = lambda path: json.loads(path.read_text())
        cls.receipt = read(cls.case / 'receipt.json')
        cls.plan = read(root / 'plan.json')
        cls.protocol = read(root / 'protocol-freeze.json')
        cls.lock = read(root / 'acquisition-lock.json')
        cls.catalog = {row['algorithm']: row['class'] for row in
                       read(root / 'producer-snapshot/external_sandmark/algorithm-contracts.json')['algorithms']}
        cls.inputs = next(row['inputs'] for row in read(root / 'study-frame.json')['configurations'] if row['id'] == 'case-0004')

    def check(self, record):
        verify_receipt(self.plan, record, expected_inputs=self.inputs, expected_context_id='case-0004')
        counts = Counter()
        for action in record['actions']:
            reobserve(self.case, action, self.protocol, self.catalog, self.lock, counts)
        return counts

    def derive(self, record):
        actions = {row['id']: row for row in record['actions']}
        test = self
        class SavedObservationAdapter:
            operations = {row['operation'] for row in record['actions']}
            def invoke(self, operation, arguments, *, step_id, context_id):
                source = actions[step_id]
                test.assertEqual(operation, source['operation'])
                test.assertEqual(context_id, 'case-0004')
                test.assertEqual(json.dumps(arguments, sort_keys=True), json.dumps(source['arguments'], sort_keys=True))
                return {key: deepcopy(source[key]) for key in ('status', 'value', 'evidence', 'reason')}
        record['obligations'] = execute(self.plan, record['inputs'], SavedObservationAdapter(),
                                       context_id='case-0004')['obligations']

    def test_unchanged_retained_native_observations_are_accepted(self):
        self.check(deepcopy(self.receipt))
        self.assertEqual({row['verdict'] for row in self.receipt['obligations']}, {'SATISFIED'})

    def test_boolean_or_float_exit_code_cannot_create_a_false_host_inconsistency(self):
        for scalar in (False, 0.0):
            with self.subTest(json_type=type(scalar).__name__):
                record = deepcopy(self.receipt)
                action = next(row for row in record['actions'] if row['id'] == 'embedded-host')
                self.assertIs(type(action['value']['tasks'][0]['returncode']), int)
                action['value']['tasks'][0]['returncode'] = scalar
                self.derive(record)
                changed = next(row for row in record['obligations'] if row['id'] == 'embedding-host')
                self.assertEqual(changed['verdict'], 'INCONSISTENT')
                with self.assertRaisesRegex(ValueError, 'Typed observation'):
                    self.check(record)

    def test_integer_zero_cannot_replace_a_boolean_timeout_observation(self):
        record = deepcopy(self.receipt)
        action = next(row for row in record['actions'] if row['id'] == 'embedded-host')
        self.assertIs(action['value']['tasks'][0]['timeout'], False)
        action['value']['tasks'][0]['timeout'] = 0
        self.derive(record)
        with self.assertRaisesRegex(ValueError, 'Typed observation'):
            self.check(record)

    def test_empty_native_file_length_does_not_accept_false(self):
        record = deepcopy(self.receipt)
        action = next(row for row in record['actions'] if row['id'] == 'embedded-host')
        empty = next(row for row in action['evidence'][0]['files'] if row['bytes'] == 0)
        empty['bytes'] = False
        with self.assertRaisesRegex(ValueError, 'inventory or byte hash'):
            self.check(record)

    def test_ambiguous_or_nonfinite_raw_metadata_is_rejected_after_inventory_refresh(self):
        original_action = next(row for row in self.receipt['actions'] if row['id'] == 'embedded-host')
        for mutation in ('duplicate-returncode', 'nonfinite-timeout'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                case = Path(directory)
                shutil.copytree(self.case / 'embedded-host', case / 'embedded-host')
                command = case / 'embedded-host/first_player_win/process.command.json'
                raw = command.read_bytes()
                if mutation == 'duplicate-returncode':
                    self.assertEqual(json.loads(raw)['returncode'], 0)
                    command.write_bytes(b'{\n  "returncode": 7,\n' + raw[1:])
                    message = 'duplicate JSON key'
                else:
                    value = json.loads(raw)
                    value['timeout_seconds'] = float('nan')
                    command.write_text(json.dumps(value))
                    message = 'nonfinite JSON constant'
                action = deepcopy(original_action)
                action['evidence'][0]['files'] = [binding(path, case)
                    for path in sorted((case / 'embedded-host').rglob('*')) if path.is_file()]
                with self.assertRaisesRegex(ValueError, message):
                    reobserve(case, action, self.protocol, self.catalog, self.lock, Counter())


if __name__ == '__main__':
    unittest.main()
