"""Evidence-receiver controls over real frozen records, not native fault cases."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from evidence_correspondence.verify import ARTIFACT, read, verify
from evidence_correspondence.run import source_paths


DATA = ARTIFACT / 'results/evidence-correspondence/completed'


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ComparisonReceiverControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='record-comparison-receiver-')
        self.data = Path(self.temporary.name) / 'copied-study'
        shutil.copytree(DATA, self.data)
        self.protocol = read(self.data / 'protocol.json')

    def tearDown(self):
        self.temporary.cleanup()

    def test_complete_relocated_study_replays(self):
        result = verify(self.data)
        self.assertEqual(result['records'], 24)
        self.assertEqual(result['acceptance_decisions'], 72)

    def test_frozen_evaluator_includes_elf_parser_dependency(self):
        self.assertIn(ARTIFACT / 'independent_observers/elf_observer.py', source_paths())

    def test_undeclared_receipt_change_is_not_an_extra_control(self):
        path = self.data / 'cases' / self.protocol['frame'][0]['id'] / 'receipt.json'
        record = read(path); record['context_id'] += ':changed'; write(path, record)
        with self.assertRaisesRegex(ValueError, 'exactly the declared edit'):
            verify(self.data)

    def test_omitted_negative_record_is_rejected(self):
        name = next(row['id'] for row in self.protocol['frame'] if row['valid_record'] is False)
        shutil.rmtree(self.data / 'cases' / name)
        with self.assertRaisesRegex(ValueError, 'directory domain'):
            verify(self.data)

    def test_modified_frozen_checker_is_rejected(self):
        path = self.data / 'source-snapshot/evidence_correspondence/evaluate.py'
        path.write_bytes(path.read_bytes() + b'\n# changed after acquisition\n')
        with self.assertRaisesRegex(ValueError, 'frozen input differs'):
            verify(self.data)

    def test_coordinated_forged_decision_fails_actual_replay(self):
        item = next(row for row in self.protocol['frame'] if row['valid_record'] is False)
        directory = self.data / 'cases' / item['id']
        evaluation = read(directory / 'evaluation.json')
        layer = next(row for row in evaluation['layers'] if row['tier'] == 'native-binding')
        self.assertFalse(layer['accepted'])
        layer.update(accepted=True, error=None, detail={'forged': True})
        write(directory / 'evaluation.json', evaluation)
        write(directory / 'evaluation.stdout.json', evaluation)
        invocation = read(directory / 'invocation.json')
        invocation['stdout_sha256'] = digest(directory / 'evaluation.stdout.json')
        write(directory / 'invocation.json', invocation)
        summary = read(self.data / 'summary.json')
        next(row for row in summary['rows'] if row['id'] == item['id'])['layers'] = deepcopy(evaluation['layers'])
        counts = summary['layers']['native-binding']
        counts['invalid_rejected'] -= 1
        counts['invalid_accepted'] = counts.get('invalid_accepted', 0) + 1
        write(self.data / 'summary.json', summary)
        completion = read(self.data / 'completion.json')
        completion['summary_sha256'] = digest(self.data / 'summary.json')
        write(self.data / 'completion.json', completion)
        with self.assertRaisesRegex(ValueError, 'actual frozen-code replay'):
            verify(self.data)


if __name__ == '__main__':
    unittest.main()
