"""Controls for SR01 policy, unavailable observations and snapshot admission."""
from copy import deepcopy
import csv
import json
import unittest
from unittest.mock import patch

from .model import assess
from .common import load_plan
from .verify import DATA, reconstruct, verify
from postfreeze_challenge.verify import ByteReceiver, descriptor_bytes


def valid_case():
    snapshot = {'path': 'CASE/source/host', 'bytes': 100, 'sha256': 'a' * 64}
    payload = {'kind': 'payload', 'value': b'Morph-01'.hex()}
    evidence = {'snapshots': {label: dict(snapshot) for label in
        ('source', 'before_wrong_key', 'after_wrong_key', 'before_recovery', 'after_recovery')},
        'observations': {'source_carrier': payload, 'source': payload,
                         'wrong_key': {'kind': 'rejection', 'value': 'wrong-key'}, 'recovery': payload},
        'decoder_instances': 1, 'tested_calls': [{'path': snapshot['path'], 'key': key} for key in ('K1', 'K2', 'K1')]}
    contract = {'reuse_after_rejection_declared': True, 'lockout_excluded_by_contract': True}
    request = {'payload_hex': payload['value'], 'key': 'K1', 'wrong_key': 'K2'}
    return deepcopy(evidence), contract, request


class AdmissionTests(unittest.TestCase):
    def test_normal_recovery_and_latched_rejection_diverge(self):
        evidence, contract, request = valid_case()
        self.assertEqual(assess(evidence, contract, request)['verdict'], 'SATISFIED')
        evidence['observations']['recovery'] = {'kind': 'rejection', 'value': 'wrong-key'}
        self.assertEqual(assess(evidence, contract, request)['verdict'], 'INCONSISTENT')

    def test_allowed_lockout_is_not_blameworthy(self):
        evidence, contract, request = valid_case()
        evidence['observations']['recovery'] = {'kind': 'rejection', 'value': 'wrong-key'}
        contract['lockout_excluded_by_contract'] = False
        result = assess(evidence, contract, request)
        self.assertEqual((result['verdict'], result['reason']), ('INADMISSIBLE', 'lockout_excluded_by_contract'))

    def test_wrong_key_acceptance_does_not_establish_recovery_premise(self):
        evidence, contract, request = valid_case()
        evidence['observations']['wrong_key'] = evidence['observations']['source']
        result = assess(evidence, contract, request)
        self.assertEqual((result['verdict'], result['reason']), ('INADMISSIBLE', 'wrong_key_returns_typed_wrong_key_rejection'))

    def test_changed_target_is_not_attributed_to_decoder_state(self):
        evidence, contract, request = valid_case()
        for label in ('before_recovery', 'after_recovery'):
            evidence['snapshots'][label]['sha256'] = 'b' * 64
        evidence['observations']['recovery'] = {'kind': 'payload', 'value': b'Second-2'.hex()}
        result = assess(evidence, contract, request)
        self.assertEqual((result['verdict'], result['reason']), ('INADMISSIBLE', 'source_current_before_recovery'))

    def test_tool_failure_is_not_a_domain_recovery_failure(self):
        evidence, contract, request = valid_case()
        evidence['observations']['recovery'] = {'kind': 'rejection', 'value': 'tool'}
        result = assess(evidence, contract, request)
        self.assertEqual((result['verdict'], result['reason']), ('INADMISSIBLE', 'recovery_observation_available'))


class ReceptionTests(unittest.TestCase):
    def record(self, cohort_id):
        with (DATA / 'first.csv').open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        index = next(index for index, row in enumerate(rows) if row['cohort'] == cohort_id)
        with (DATA / 'first-traces.csv').open(newline='') as stream:
            descriptor = list(csv.DictReader(stream))[index]
        plan, _ = load_plan()
        cohort = next(item for item in plan['cohorts'] if item['id'] == cohort_id)
        return descriptor_bytes(DATA, descriptor), plan, cohort

    def test_original_is_read_only_without_native_subprocesses(self):
        with patch('subprocess.run', side_effect=AssertionError('receiver launched a subprocess')):
            result = verify()
        self.assertEqual((result['verdict'], result['native_cases']), ('PASS', 540))
        self.assertEqual(result['rerun']['differences'], 0)

    def test_policy_boundary_cannot_be_promoted_by_relabeling_admission(self):
        record, plan, cohort = self.record('latched-rejection-lockout-allowed')
        record['outcome']['verdict'] = 'INCONSISTENT'
        record['outcome']['reason'] = 'recovery_differs_after_typed_rejection'
        record['outcome']['admission']['reuse_after_rejection_declared'] = True
        record['outcome']['admission']['lockout_excluded_by_contract'] = True
        with self.assertRaisesRegex(ValueError, 'independently reconstructed premises'):
            reconstruct(ByteReceiver(DATA), record, plan, cohort)

    def test_changed_bytes_cannot_be_hidden_in_summary_evidence(self):
        record, plan, cohort = self.record('target-replaced-after-rejection')
        for label in ('before_recovery', 'after_recovery'):
            record['evidence']['snapshots'][label] = dict(record['evidence']['snapshots']['source'])
        with self.assertRaisesRegex(ValueError, 'stored SR01 evidence differs'):
            reconstruct(ByteReceiver(DATA), record, plan, cohort)

    def test_claimed_negative_premise_must_match_actual_wrong_key_call(self):
        record, plan, cohort = self.record('wrong-key-accepted')
        record['evidence']['observations']['wrong_key'] = {'kind': 'rejection', 'value': 'wrong-key'}
        with self.assertRaisesRegex(ValueError, 'stored SR01 evidence differs'):
            reconstruct(ByteReceiver(DATA), record, plan, cohort)


if __name__ == '__main__':
    unittest.main()
