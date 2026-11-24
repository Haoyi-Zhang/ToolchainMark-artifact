"""Read-only controls for the separately acquired native history pairs."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from evidence_projection.verify_history import ARTIFACT, read, verify


DATA = ARTIFACT / 'results/evidence-projection/history-control'


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


class HistoryReceptionControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='history-receiver-')
        self.data = Path(self.temporary.name) / 'relocated'
        shutil.copytree(DATA, self.data)

    def tearDown(self):
        self.temporary.cleanup()

    def test_original_pairs_relocate_without_native_execution(self):
        report = verify(self.data)
        self.assertEqual(report['native_executions'], 24)
        self.assertEqual(report['checks']['direct_artifact_byte_pairs'], 24)
        self.assertFalse(report['native_programs_reexecuted'])

    def test_deleted_intervening_action_cannot_preserve_full_history(self):
        path = self.data / 'cases/pass-1/string/M23/with-B/receipt.json'
        receipt = read(path)
        receipt['actions'] = [row for row in receipt['actions'] if row['id'] != 'intervening']
        write(path, receipt)
        with self.assertRaises(ValueError):
            verify(self.data)

    def test_modified_declared_plan_is_not_the_frozen_counterexample(self):
        path = self.data / 'plans.json'; plans = read(path)
        plans['with-B']['obligations'][0]['predicate'] = {'literal': True}
        write(path, plans)
        with self.assertRaisesRegex(ValueError, 'two-A-observation'):
            verify(self.data)

    def test_claimed_byte_inequality_does_not_replace_actual_bytes(self):
        path = self.data / 'pairs.json'; pairs = read(path)
        pairs[0]['artifact_pairs'][0]['equal'] = False
        write(path, pairs)
        with self.assertRaisesRegex(ValueError, 'pair comparisons'):
            verify(self.data)

    def test_stored_deletion_acceptance_does_not_replace_actual_receiver(self):
        path = self.data / 'deletion-controls.json'; controls = read(path)
        controls[0]['rejected'] = False
        write(path, controls)
        with self.assertRaisesRegex(ValueError, 'actual receiver rejection'):
            verify(self.data)


if __name__ == '__main__':
    unittest.main()
