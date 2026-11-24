"""Receive saved analysis changes against actually received pilot observations.

The native pilot is read once. Each negative changes only an in-memory derived
document; no Java execution, acquisition, or retained result edit occurs.
"""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import sys
import unittest

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.receiver import load_json
from decoder_sessions.verify import Receiver, receive_analysis

PILOT = Path(os.environ.get('DECODER_SESSION_ANALYSIS_DATA',
                           str(ARTIFACT / 'results/decoder-sessions/pilot-03')))


class AnalysisReceiverControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (PILOT / 'completion.json').is_file():
            raise RuntimeError('The completed third-history pilot is required; no acquisition is launched')
        cls.receiver = Receiver(PILOT)
        cls.received = cls.receiver.verify(allow_pilot=True)
        cls.document = load_json(PILOT / 'paired-analysis.json')

    def receive(self, document):
        return receive_analysis(document, self.receiver.word_details, self.receiver.counts,
                                self.receiver.manifest, self.receiver.freeze['kind'])

    def test_actual_saved_analysis_is_accepted(self):
        received = self.receive(deepcopy(self.document))
        self.assertEqual(received['verdict'], 'PASS')
        self.assertEqual(received['checked_lifetime_rows'], len(self.document['lifetime_triples']))
        self.assertEqual(received['checked_history_rows'], len(self.document['history_triplets']))
        self.assertEqual(self.received['received_analysis']['verdict'], 'PASS')

    def test_changed_lifetime_decision_is_rejected_even_with_changed_total(self):
        changed = deepcopy(self.document)
        row = changed['lifetime_triples'][0]
        field = 'object_lifetime_associated_loss'
        previous = row[field]
        self.assertIs(type(previous), bool)
        row[field] = not previous
        changed['lifetime_triple_counts'][field] += 1 if row[field] else -1
        with self.assertRaisesRegex(ValueError, 'Saved lifetime comparison rows differ'):
            self.receive(changed)

    def test_changed_raw_acquisition_count_is_rejected(self):
        changed = deepcopy(self.document)
        changed['raw_acquisition']['jvm_processes'] += 1
        with self.assertRaisesRegex(ValueError, 'Saved raw acquisition counts differ'):
            self.receive(changed)

    def test_omitted_or_reassigned_comparison_membership_is_rejected(self):
        for mutation in ('omit', 'reassign'):
            with self.subTest(mutation=mutation):
                changed = deepcopy(self.document)
                if mutation == 'omit':
                    changed['lifetime_triples'].pop()
                    changed['lifetime_triple_counts']['planned_triples'] -= 1
                else:
                    changed['lifetime_triples'][0]['words']['R'] = changed['lifetime_triples'][0]['words']['P']
                with self.assertRaisesRegex(ValueError, 'Saved lifetime comparison rows differ'):
                    self.receive(changed)

    def test_incomplete_history_denominator_cannot_disappear(self):
        changed = deepcopy(self.document)
        original = changed['history_triplet_counts']['incomplete_planned_triplets']
        self.assertGreater(original, 0)
        changed['history_triplet_counts']['incomplete_planned_triplets'] = 0
        with self.assertRaisesRegex(ValueError, 'Saved history denominators differ'):
            self.receive(changed)


if __name__ == '__main__':
    unittest.main()
