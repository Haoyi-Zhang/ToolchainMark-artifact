"""Retained-record and real relocation controls; no native programs execute."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from framework_comparison.verify import (
    ARTIFACT, baseline_requests, canonical_comparison, comparison, framework_export,
    read, verify_pair,
)
from framework_comparison.analyze_process_paths import correspondence, leaves, recorded_root, rename
from declarative_study.native_io import verify_evidence
from declarative_study.verify import value_bindings


STORE = ARTIFACT / 'results/framework-comparison/paired'
CASE = {'carrier': 'string', 'family': 'reference', 'id': 'pass-1/MR08/string/CLEAN',
        'implementation': 'CLEAN', 'pass': 1, 'relation': 'MR08'}


class RetainedReceiverControls(unittest.TestCase):
    def setUp(self):
        self.protocol = read(STORE / 'protocol.json')
        directory = STORE / 'cases' / CASE['id']
        self.contract = read(directory / 'contract.json')
        self.baseline = read(directory / 'gemtest.json')
        self.plan = self.contract['plan']

    def test_exact_record_copy_is_portable(self):
        original, _ = verify_pair(CASE, STORE, self.protocol)
        with tempfile.TemporaryDirectory(prefix='paired-receiver-relocation-') as temporary:
            target = Path(temporary)
            directory = target / 'cases' / CASE['id']
            directory.mkdir(parents=True)
            for name in ('contract.json', 'gemtest.json'):
                shutil.copy2(STORE / 'cases' / CASE['id'] / name, directory / name)
            shutil.copytree(STORE / 'source-snapshot', target / 'source-snapshot')
            shutil.copytree(STORE / 'blobs', target / 'blobs')
            relocated, _ = verify_pair(CASE, target, self.protocol)
            self.assertEqual(canonical_comparison(original), canonical_comparison(relocated))
            self.assertEqual(relocated['observation_differences'], [])

    def test_disabled_callback_cannot_keep_native_evidence(self):
        baseline = deepcopy(self.baseline)
        recover = next(row for row in baseline['actions'] if row['id'] == 'recover')
        recover['value']['observation'] = {'kind': 'rejection', 'value': 'absent'}
        with self.assertRaisesRegex(ValueError, 'disabled baseline request'):
            baseline_requests(self.plan, baseline)

    def test_changed_resolved_key_is_rejected(self):
        baseline = deepcopy(self.baseline)
        next(row for row in baseline['actions'] if row['id'] == 'recover')['arguments']['key'] = 'other-key'
        with self.assertRaisesRegex(ValueError, 'prefix arguments'):
            baseline_requests(self.plan, baseline)

    def test_raw_action_reordering_is_rejected_without_invented_events(self):
        baseline = deepcopy(self.baseline)
        baseline['actions'][0], baseline['actions'][1] = baseline['actions'][1], baseline['actions'][0]
        with self.assertRaisesRegex(ValueError, 'domain/order'):
            baseline_requests(self.plan, baseline)

    def test_framework_export_must_equal_actual_prefix(self):
        baseline = deepcopy(self.baseline)
        baseline['framework']['source_outputs'][0]['actions'][-1]['value']['key'] = 'other-key'
        with self.assertRaisesRegex(ValueError, 'source output'):
            framework_export(CASE, baseline)

    def test_native_endpoint_change_with_valid_alternate_bytes_is_rejected(self):
        baseline = deepcopy(self.baseline)
        source = next(row for row in baseline['actions'] if row['id'] == 'source')
        host = next(row for row in baseline['actions'] if row['id'] == 'source-host')
        command = next(event for event in host['evidence'] if event['kind'] == 'process')
        alternate = dict(source['value']['source'], path=host['arguments']['binary'])
        command['files_before'] = [alternate]
        # The byte object is real and its digest valid; the target association is false.
        verify_evidence(baseline, STORE)
        with self.assertRaisesRegex(ValueError, 'process target version'):
            value_bindings(baseline, STORE)

    def test_path_renaming_retains_nonpath_flags(self):
        case = dict(CASE, carrier='symbol', id='pass-1/MR09/symbol/CLEAN', relation='MR09')
        directory = STORE / 'cases' / case['id']
        contract = read(directory / 'contract.json')['receipt']
        baseline = read(directory / 'gemtest.json')
        a = next(row for row in contract['actions'] if row['id'] == 'source-view')
        b = deepcopy(next(row for row in baseline['actions'] if row['id'] == 'source-view'))
        command = next(event for event in b['evidence'] if event['kind'] == 'process')
        self.assertIn('-g', command['argv'])
        command['argv'][command['argv'].index('-g')] = '-u'
        maps, _ = correspondence(a['evidence'], b['evidence'], STORE)
        values = []
        for i, (row, record, arm) in enumerate(((a, contract, 'contract'), (b, baseline, 'gemtest'))):
            root = recorded_root(record['actions'], case['id'], arm)
            values.append(rename(row['evidence'], [(root, '<native>'),
                          (record['context_id'], '<context>'), *maps[i].items()]))
        self.assertTrue(leaves(*values))

    def test_comparison_preserves_real_typed_output_difference(self):
        baseline = deepcopy(self.baseline)
        next(row for row in baseline['actions'] if row['id'] == 'recover')['value']['observation']['value'] = '00'
        compared = comparison(CASE, self.contract, baseline, STORE)
        self.assertTrue(any(row['action'] == 'recover' and row['kind'] == 'value'
                            for row in compared['observation_differences']))


if __name__ == '__main__':
    unittest.main()
