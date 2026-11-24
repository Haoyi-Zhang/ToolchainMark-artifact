"""Observation/verdict consistency controls on immutable retained matrices.

No native execution is inferred from these checks. Tampered copies stay in
memory; every retained evidence file remains unchanged.
"""
import copy
import csv
import gzip
import importlib.util
import io
import json
import unittest
from pathlib import Path

from toolchainmark.study_validation import StudyInputError, validate_rows

ROOT = Path(__file__).resolve().parents[1]


def read_rows(path):
    raw = gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes()
    return list(csv.DictReader(io.StringIO(raw.decode('utf-8'))))


class StudySemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = read_rows(ROOT / 'results/native-execution/primary/first.csv.gz')
        cls.protocol = 'evidence-gated-v3-snapshot-coherence'
        spec = importlib.util.spec_from_file_location('study_semantic_derivation',
                    ROOT / 'scripts/derive_admission_study.py')
        cls.derivation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.derivation)

    def sample(self, relation, verdict='SATISFIED'):
        return copy.deepcopy(next(r for r in self.rows if r['relation_id'] == relation
                                  and r['verdict'] == verdict))

    def test_retained_protocols_validate_without_relabeled_rows(self):
        for path, protocol in [
            ('results/admission-study/matrix.csv.gz', 'evidence-gated-v1'),
            ('results/current-native/first.csv.gz', 'evidence-gated-v2-checksum-locality'),
            ('results/native-execution/primary/first.csv.gz', self.protocol),
        ]:
            with self.subTest(protocol=protocol):
                validate_rows(read_rows(ROOT / path), protocol)

    def test_every_relation_rejects_a_consistent_label_flip(self):
        # The Boolean exposure and reason are flipped together: mere label
        # cross-checks cannot detect this contradiction with observations.
        for index in range(1, 15):
            relation = f'MR{index:02d}'
            row = self.sample(relation)
            row.update(verdict='INCONSISTENT', reason='predicate-violated',
                       exposed=str(row['defect_id'] != 'CLEAN'))
            with self.subTest(relation=relation), self.assertRaisesRegex(
                    StudyInputError, 'verdict contradicts'):
                validate_rows([row], self.protocol)
        for relation in sorted({r['relation_id'] for r in self.rows if r['verdict']=='INCONSISTENT'}):
            row = self.sample(relation, 'INCONSISTENT')
            row.update(verdict='SATISFIED', reason='predicate-satisfied', exposed='False')
            with self.subTest(relation=relation, direction='inconsistent-to-satisfied'), \
                    self.assertRaisesRegex(StudyInputError, 'verdict contradicts'):
                validate_rows([row], self.protocol)

    def test_true_admission_flags_cannot_override_contradictory_observations(self):
        controls = [
            ('MR03', lambda o: o.update(carrier={'kind':'payload','value':'00'})),
            ('MR04', lambda o: o.update(source={'kind':'payload','value':'00'})),
            ('MR06', lambda o: o['builds'][1].update(actual=['gcc','O2'])),
            ('MR06', lambda o: o['extractions'].pop()),
            ('MR07', lambda o: o['builds'].pop()),
            ('MR09', lambda o: o.update(followup_carrier={'kind':'payload','value':'00'})),
            ('MR10', lambda o: o.update(followup_carrier={'kind':'rejection','value':'malformed'})),
            ('MR11', lambda o: o.update(requested=['gcc','O2'],actual=['gcc','O2'])),
            ('MR12', lambda o: o.update(both_payloads=False)),
            ('MR12', lambda o: o.update(execution_order='sequential-builds-then-extract')),
        ]
        for relation, mutate in controls:
            row = self.sample(relation); observations = json.loads(row['observations_json'])
            mutate(observations); row['observations_json'] = json.dumps(observations)
            with self.subTest(relation=relation), self.assertRaises(StudyInputError):
                validate_rows([row], self.protocol)

    def test_invalid_host_mismatch_and_unknown_rejection_fail(self):
        row = self.sample('MR02','INCONSISTENT')
        observations = json.loads(row['observations_json'])
        observations['mismatches'][0]['marked'] = observations['mismatches'][0]['base']
        row['observations_json'] = json.dumps(observations)
        with self.assertRaises(StudyInputError): validate_rows([row], self.protocol)
        row = self.sample('MR01','INCONSISTENT')
        row['observations_json'] = json.dumps({'extraction':{'kind':'rejection','value':'tool'}})
        with self.assertRaises(StudyInputError): validate_rows([row], self.protocol)

    def test_same_host_cannot_change_digest_inside_one_matrix(self):
        rows = [self.sample('MR01'),self.sample('MR02')]
        rows[1]['host'] = rows[0]['host']; rows[1]['host_sha256'] = '0'*64
        with self.assertRaisesRegex(StudyInputError,'conflicting source identities'):
            validate_rows(rows,self.protocol)

    def test_inadmissible_early_stop_keeps_its_incomplete_projection(self):
        row = self.sample('MR09')
        row.update(verdict='INADMISSIBLE',exposed='False',reason='isolated_workspace',
                   admission_json='{"subject_exists":true,"isolated_workspace":false}',
                   observations_json='{}')
        validate_rows([row], 'evidence-gated-v4-removal-coherence')

    def test_removal_coherence_is_explicit_and_cannot_be_mixed(self):
        integrity = self.sample('MR10')
        original = self.sample('MR09'); upgraded = copy.deepcopy(original)
        facts = json.loads(upgraded['admission_json'])
        for name in ('source_snapshot_matches_request','followup_snapshot_current',
                     'followup_unchanged_during_extraction'): facts[name] = True
        observed = json.loads(upgraded['observations_json'])
        observed['removal_snapshots'] = {
            'source':{'sha256':'1'*64,'bytes':31}, 'followup':{'sha256':'2'*64,'bytes':0}}
        upgraded['admission_json'] = json.dumps(facts)
        upgraded['observations_json'] = json.dumps(observed)
        protocol = self.derivation.matrix_protocol([integrity,upgraded])
        self.assertEqual(protocol,'evidence-gated-v4-removal-coherence')
        validate_rows([integrity,upgraded],protocol)
        with self.assertRaisesRegex(ValueError,'different MR09'):
            self.derivation.matrix_protocol([integrity,original,upgraded])
        facts.pop('followup_snapshot_current'); upgraded['admission_json'] = json.dumps(facts)
        with self.assertRaisesRegex(ValueError,'incomplete removal'):
            self.derivation.matrix_protocol([integrity,upgraded])


if __name__ == '__main__':
    unittest.main()
