"""Semantic regression cases for projection closure and independent checking."""
import copy
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from contract_runtime import execute
from contract_runtime.receiver import InvalidRecord
from .project import project, selection
from .receiver import required_projection, verify_structure


class Adapter:
    operations = {'observe'}
    def invoke(self, operation, arguments, *, step_id, context_id):
        return {'status': 'OK', 'value': arguments.get('ref', 1), 'reason': None, 'evidence': []}


def action(name, arguments=None, when=None):
    row = {'id': name, 'operation': 'observe', 'arguments': arguments or {}}
    if when is not None:
        row['when'] = when
    return row


def obligation(name, predicate, requires=None):
    return {'id': name, 'stage': 'test', 'clause': name,
            'requires': requires or [], 'predicate': predicate}


class ProjectionTests(unittest.TestCase):
    def make(self, actions, obligations, target='target'):
        plan = {'schema': 'toolchainmark-contract-v1', 'id': 'projection-control',
                'inputs': {}, 'actions': actions, 'obligations': obligations}
        receipt = execute(plan, {}, Adapter(), context_id='case')
        context = {'profile': 'test-only'}
        bundle = project(plan, receipt, target, context)
        expected = dict(expected_plan=plan, expected_inputs={}, expected_context_id='case',
                        expected_native_context=context, expected_target=target)
        return plan, receipt, bundle, expected

    def test_parallel_sibling_and_hidden_prefix_preserved(self):
        args = {'ref': {'literal': {'ref': 'not-an-action'}}}
        plan, receipt, bundle, expected = self.make(
            [action('hidden'), {'parallel': [action('a', args), action('b')]}, action('tail')],
            [obligation('target', {'available': 'a'})])
        self.assertEqual(bundle['projection']['action_ids'], ['hidden', 'a', 'b'])
        self.assertEqual(selection(plan, 'target')['reference_action_ids'], ['a'])
        self.assertEqual(required_projection(plan, 'target'), bundle['projection'])
        self.assertEqual(verify_structure(bundle, **expected)['status'], 'PASS')
        for deleted in ('hidden', 'b'):
            changed = copy.deepcopy(bundle)
            changed['receipt']['actions'] = [a for a in changed['receipt']['actions'] if a['id'] != deleted]
            with self.assertRaises(InvalidRecord):
                verify_structure(changed, **expected)

    def test_preceding_verdict_and_guard_closure(self):
        plan, receipt, bundle, expected = self.make(
            [action('guard-source'), action('observed', when={'available': 'guard-source'}), action('tail')],
            [obligation('source', {'available': 'observed'}),
             obligation('unrelated', {'literal': True}),
             obligation('target', {'op': 'eq', 'args': [{'verdict': 'source'}, {'literal': 'SATISFIED'}]})])
        self.assertEqual(bundle['projection']['obligation_ids'], ['source', 'target'])
        self.assertEqual(selection(plan, 'target')['reference_action_ids'], ['guard-source', 'observed'])
        self.assertEqual(verify_structure(bundle, **expected)['status'], 'PASS')
        changed = copy.deepcopy(bundle)
        changed['receipt']['obligations'].pop(0)
        with self.assertRaises(InvalidRecord):
            verify_structure(changed, **expected)
        changed = copy.deepcopy(bundle)
        changed['receipt']['actions'].pop(0)
        with self.assertRaises(InvalidRecord):
            verify_structure(changed, **expected)

    def test_empty_prefix_and_literal_json(self):
        plan, receipt, bundle, expected = self.make([action('unused')],
            [obligation('target', {'op': 'eq', 'args': [
                {'literal': {'verdict': 'missing', 'ref': 'missing'}},
                {'literal': {'verdict': 'missing', 'ref': 'missing'}}]})])
        self.assertEqual(bundle['projection']['action_ids'], [])
        self.assertEqual(verify_structure(bundle, **expected)['retained_actions'], 0)

    def test_scientific_inconsistency_is_valid_evidence(self):
        plan, receipt, bundle, expected = self.make([], [obligation('target', {'literal': False})])
        self.assertEqual(verify_structure(bundle, **expected)['target_judgment']['verdict'], 'INCONSISTENT')

    def test_scientific_inadmissibility_is_valid_evidence(self):
        plan, receipt, bundle, expected = self.make([], [obligation('target', {'literal': True},
            [{'name': 'condition', 'expr': {'literal': False}}])])
        self.assertEqual(verify_structure(bundle, **expected)['target_judgment']['verdict'], 'INADMISSIBLE')

    def test_externally_selected_identity_and_target(self):
        plan, receipt, bundle, expected = self.make([action('a')],
            [obligation('first', {'literal': True}), obligation('target', {'available': 'a'})])
        for field, value in [('expected_context_id', 'other'), ('expected_target', 'first'),
                             ('expected_inputs', {'invented': 1}), ('expected_native_context', {})]:
            changed = {**expected, field: value}
            with self.assertRaises(InvalidRecord):
                verify_structure(bundle, **changed)
        changed = copy.deepcopy(bundle)
        changed['source_plan']['id'] = 'another-plan'
        with self.assertRaises(InvalidRecord):
            verify_structure(changed, **expected)

    def test_changed_record_and_false_cutoff_are_rejected(self):
        plan, receipt, bundle, expected = self.make([action('a'), action('tail')],
            [obligation('target', {'available': 'a'})])
        for mutate in (
            lambda x: x['receipt']['obligations'][0].update(verdict='INCONSISTENT'),
            lambda x: x['projection'].update(action_blocks=2),
            lambda x: x['receipt']['actions'][0].update(start_event=2),
            lambda x: x['receipt'].update(plan_sha256='0' * 64),
        ):
            changed = copy.deepcopy(bundle); mutate(changed)
            with self.assertRaises(InvalidRecord):
                verify_structure(changed, **expected)

    def test_native_member_change_is_rejected_without_touching_source(self):
        from .native import members, native_context, populate
        from .receiver import verify_bundle
        artifact = Path(__file__).resolve().parents[1]
        source = artifact / 'results/declarative-v6/reference'
        case = source / 'cases/pass-1/string/CLEAN/MR01'
        plan, receipt = [json.loads((case / (name + '.json')).read_text()) for name in ('plan', 'receipt')]
        context = native_context(source, 'reference')
        bundle = project(plan, receipt, 'MR01', context)
        expected = dict(expected_plan=plan, expected_inputs=receipt['inputs'],
                        expected_context_id=receipt['context_id'], expected_native_context=context,
                        expected_target='MR01')
        selected = members(bundle['receipt'], source, context['profile'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(selected, source, root)
            self.assertEqual(verify_bundle(bundle, root, **expected)['status'], 'PASS')
            path = root / selected[0]['path']
            original = path.read_bytes()
            altered = bytearray(gzip.decompress(original)); altered[-1] ^= 1
            path.unlink()  # populate can use a hard link; never alter the source member.
            path.write_bytes(gzip.compress(altered, mtime=0))
            with self.assertRaises(ValueError):
                verify_bundle(bundle, root, **expected)
            self.assertEqual((source / selected[0]['path']).read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
