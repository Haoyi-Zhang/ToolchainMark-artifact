"""Behavioral controls for declared acquisition, availability and stage judgments.

These tests use small owned operation fixtures. They assert execution effects
and public receipts, rather than inspecting interpreter implementation details.
"""
from copy import deepcopy
import hashlib
import json
import math
import threading
import unittest

from contract_runtime import ExecutionConfigurationError, InputValidationError, PlanValidationError, execute, validate_plan


def lit(value):
    return {'literal': value}


def op(name, *args):
    return {'op': name, 'args': list(args)}


def action(name, operation='echo', arguments=None, **extra):
    return {'id': name, 'operation': operation, 'arguments': {} if arguments is None else arguments, **extra}


def obligation(name, predicate, gates=()):
    return {'id': name, 'stage': name + '-stage', 'clause': name + '-clause',
            'requires': [{'name': gate, 'expr': expr} for gate, expr in gates], 'predicate': predicate}


def plan(actions=(), obligations=(), inputs=None):
    return {'schema': 'toolchainmark-contract-v1', 'id': 'owned-test', 'inputs': {} if inputs is None else inputs,
            'actions': list(actions), 'obligations': list(obligations)}


class OwnedAdapter:
    operations = {'echo', 'unavailable', 'reject', 'raise', 'malformed'}

    def __init__(self):
        self.calls = []

    def invoke(self, operation, arguments, *, step_id, context_id):
        self.calls.append((operation, deepcopy(arguments), step_id, context_id))
        if operation == 'raise':
            raise OSError('owned acquisition failed')
        if operation == 'malformed':
            return {'status': 'OK', 'value': True, 'evidence': [], 'reason': None, 'verdict': 'SATISFIED'}
        if operation == 'unavailable':
            return {'status': 'UNAVAILABLE', 'value': {'diagnostic': 'no observation'}, 'evidence': [], 'reason': None}
        value = {'kind': 'rejection', 'category': 'wrong-key'} if operation == 'reject' else arguments.get('value')
        return {'status': 'OK', 'value': value, 'evidence': [{'step': step_id}], 'reason': None}


class PlanAndInputTests(unittest.TestCase):
    def test_forward_sibling_self_and_unknown_references_are_rejected_before_calls(self):
        bad = [
            plan([action('a', arguments={'value': {'ref': 'b'}}), action('b')]),
            plan([{'parallel': [action('a'), action('b', arguments={'value': {'ref': 'a'}})]}]),
            plan([action('a', when=lit(False), arguments={'value': {'ref': 'a'}})]),
            plan([action('a', arguments={'value': {'input': 'undeclared'}})]),
            plan([action('a', when={'verdict': 'later'})], [obligation('later', lit(True))]),
            plan([], [obligation('o', {'verdict': 'o'})]),
        ]
        for candidate in bad:
            adapter = OwnedAdapter()
            with self.subTest(candidate=candidate), self.assertRaises(PlanValidationError):
                execute(candidate, {}, adapter, context_id='owned')
            self.assertEqual(adapter.calls, [])

    def test_invalid_shape_ids_paths_and_arity_fail_validation(self):
        candidates = []
        changed = plan(); changed['unrecognized'] = True; candidates.append(changed)
        candidates += [plan([action('a'), action('a')]), plan([{'parallel': []}]),
                       plan([action('a', arguments={'value': {'input': 'x', 'path': [True]}})], inputs={'x': 'array'}),
                       plan([action('a', arguments={'value': {'input': 'x', 'path': [-1]}})], inputs={'x': 'array'}),
                       plan([], [obligation('o', op('eq', lit(1)))]),
                       plan([], [obligation('o', op('concat'))]),
                       plan([], [obligation('o', {'literal': True, 'op': 'and', 'args': []})]),
                       plan([], [obligation('o', lit(True), [('g', lit(True)), ('g', lit(True))])])]
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(PlanValidationError):
                validate_plan(candidate)

    def test_input_keys_and_exact_json_types_are_enforced(self):
        candidate = plan([action('a')], inputs={'count': 'integer', 'ratio': 'number', 'flag': 'boolean'})
        good = {'count': 2, 'ratio': 2.5, 'flag': True}
        for values in ({**good, 'count': True}, {**good, 'ratio': False}, {**good, 'flag': 1},
                       {**good, 'extra': None}, {'count': 2, 'ratio': 2.5}, {**good, 'ratio': math.inf}):
            adapter = OwnedAdapter()
            with self.subTest(values=values), self.assertRaises(InputValidationError):
                execute(candidate, values, adapter, context_id='owned')
            self.assertEqual(adapter.calls, [])
        self.assertEqual(execute(candidate, {**good, 'ratio': 2}, OwnedAdapter(), context_id='owned')['inputs']['ratio'], 2)

    def test_non_json_values_and_cycles_are_rejected(self):
        class StringSubclass(str):
            pass
        cycle = []; cycle.append(cycle)
        for value in (b'bytes', (1, 2), {1: 'nonstring key'}, cycle, float('nan'), StringSubclass('x')):
            with self.subTest(kind=type(value).__name__), self.assertRaises(PlanValidationError):
                validate_plan(plan([], [obligation('o', lit(value))]))

    def test_unknown_adapter_operation_and_insufficient_parallel_workers_fail_before_acquisition(self):
        adapter = OwnedAdapter()
        with self.assertRaises(PlanValidationError):
            execute(plan([action('a', 'missing')]), {}, adapter, context_id='owned')
        candidate = plan([action('earlier'), {'parallel': [action('a'), action('b')]}])
        with self.assertRaises(ExecutionConfigurationError):
            execute(candidate, {}, adapter, context_id='owned', max_workers=1)
        with self.assertRaises(ExecutionConfigurationError):
            execute(plan(), {}, adapter, context_id='owned', max_workers=True)
        self.assertEqual(adapter.calls, [])


class SemanticsTests(unittest.TestCase):
    def test_declaration_changes_actual_operation_arguments_without_changing_adapter(self):
        adapter = OwnedAdapter()
        candidate = plan([action('a', arguments={'value': op('concat', {'input': 'prefix'}, lit('one'))})],
                         [obligation('o', op('eq', {'ref': 'a'}, lit('Aone')))], {'prefix': 'string'})
        first = execute(candidate, {'prefix': 'A'}, adapter, context_id='one')
        changed = deepcopy(candidate)
        changed['actions'][0]['arguments']['value']['args'][1] = lit('two')
        second = execute(changed, {'prefix': 'A'}, adapter, context_id='two')
        self.assertEqual([call[1]['value'] for call in adapter.calls], ['Aone', 'Atwo'])
        self.assertEqual(first['obligations'][0]['verdict'], 'SATISFIED')
        self.assertEqual(second['obligations'][0]['verdict'], 'INCONSISTENT')
        self.assertNotEqual(first['plan_sha256'], second['plan_sha256'])

    def test_failed_source_does_not_abort_an_independent_host_obligation(self):
        candidate = plan([action('source', arguments={'value': lit('different-payload')}),
                          action('host', arguments={'value': lit('same-host-output')})], [
            obligation('source', op('eq', {'ref': 'source'}, lit('requested-payload'))),
            obligation('downstream', op('not', lit('invalid-if-executed')),
                       [('valid-source', op('eq', {'verdict': 'source'}, lit('SATISFIED')))]),
            obligation('host', op('eq', {'ref': 'host'}, lit('same-host-output'))),
        ])
        receipt = execute(candidate, {}, OwnedAdapter(), context_id='owned')
        self.assertEqual([item['verdict'] for item in receipt['obligations']], ['INCONSISTENT', 'INADMISSIBLE', 'SATISFIED'])
        self.assertIsNone(receipt['obligations'][1]['predicate'])
        self.assertEqual(receipt['obligations'][1]['reason'], 'gate:valid-source:FALSE')

    def test_unavailable_skipped_unknown_and_false_are_distinct_and_do_not_fabricate_calls(self):
        adapter = OwnedAdapter()
        candidate = plan([
            action('missing', 'unavailable'),
            action('false-guard', when={'available': 'missing'}, arguments={'value': op('len', lit(2))}),
            action('unknown-guard', when={'ref': 'missing'}),
            action('unknown-argument', arguments={'z': {'ref': 'missing'}, 'a': lit(1)}),
            action('invalid-guard', when=lit(0)),
        ], [obligation('o', op('eq', {'ref': 'unknown-argument'}, lit(None)))])
        receipt = execute(candidate, {}, adapter, context_id='owned')
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual([item['status'] for item in receipt['actions']], ['UNAVAILABLE'] + ['SKIPPED'] * 4)
        self.assertEqual([item['reason'] for item in receipt['actions'][1:]],
                         ['guard:FALSE', 'guard:UNKNOWN', 'argument:z:UNKNOWN', 'guard:ERROR'])
        self.assertEqual(receipt['actions'][1]['argument_evaluations'], {})
        self.assertEqual(receipt['actions'][3]['argument_evaluations']['a']['value'], 1)
        self.assertEqual(receipt['obligations'][0]['predicate']['state'], 'UNKNOWN')
        self.assertEqual(receipt['obligations'][0]['verdict'], 'INADMISSIBLE')

    def test_domain_rejection_is_ok_but_exception_and_malformed_response_are_unavailable(self):
        candidate = plan([action('domain', 'reject'), action('exception', 'raise'), action('malformed', 'malformed')], [
            obligation('domain', op('eq', {'ref': 'domain', 'path': ['category']}, lit('wrong-key'))),
            obligation('exception', op('eq', {'ref': 'exception'}, lit(None))),
        ])
        result = execute(candidate, {}, OwnedAdapter(), context_id='owned')
        self.assertEqual([item['status'] for item in result['actions']], ['OK', 'UNAVAILABLE', 'UNAVAILABLE'])
        self.assertEqual([item['reason'] for item in result['actions'][1:]], ['adapter-exception:OSError', 'adapter-output-invalid'])
        self.assertEqual([item['verdict'] for item in result['obligations']], ['SATISFIED', 'INADMISSIBLE'])

    def test_missing_paths_do_not_become_false_or_empty_values(self):
        candidate = plan([action('a', arguments={'value': {'input': 'document'}})], [
            obligation('null-is-known', op('eq', {'ref': 'a', 'path': ['present']}, lit(None))),
            obligation('missing-is-unknown', op('eq', {'ref': 'a', 'path': ['missing']}, lit(None))),
            obligation('wrong-path-kind', op('len', {'input': 'document', 'path': [0]})),
        ], {'document': 'object'})
        result = execute(candidate, {'document': {'present': None}}, OwnedAdapter(), context_id='owned')
        self.assertEqual([item['verdict'] for item in result['obligations']], ['SATISFIED', 'INADMISSIBLE', 'INADMISSIBLE'])
        self.assertEqual(result['obligations'][2]['predicate']['reason'], 'input-path-missing:document')

    def test_eager_boolean_operations_keep_unknown_and_child_errors(self):
        candidate = plan([action('a', 'unavailable')], [
            obligation('false-and-unknown', op('and', lit(False), {'ref': 'a'})),
            obligation('true-or-unknown', op('or', lit(True), {'ref': 'a'})),
            obligation('error-precedes-unknown', op('and', {'ref': 'a'}, op('len', lit(2)))),
        ])
        outcomes = execute(candidate, {}, OwnedAdapter(), context_id='owned')['obligations']
        self.assertEqual([item['predicate']['state'] for item in outcomes], ['UNKNOWN', 'UNKNOWN', 'ERROR'])
        self.assertEqual(outcomes[2]['predicate']['reason'], 'type-error:len')
        self.assertTrue(all(item['verdict'] == 'INADMISSIBLE' for item in outcomes))
        self.assertTrue(all(item['consumed_references'] == ['action:a'] for item in outcomes))

    def test_every_gate_is_recorded_and_first_unsatisfied_gate_controls_reason(self):
        candidate = plan([], [obligation('o', op('not', lit(2)),
            [('first', lit(False)), ('second', op('len', lit(2))), ('third', {'input': 'x', 'path': ['missing']})])], {'x': 'object'})
        outcome = execute(candidate, {'x': {}}, OwnedAdapter(), context_id='owned')['obligations'][0]
        self.assertEqual([gate['state'] for gate in outcome['gates']], ['FALSE', 'ERROR', 'UNKNOWN'])
        self.assertEqual(outcome['reason'], 'gate:first:FALSE')
        self.assertIsNone(outcome['predicate'])
        self.assertEqual(outcome['consumed_references'], ['input:x'])

    def test_type_sensitive_equality_membership_and_numeric_order(self):
        true_expressions = [op('ne', lit(True), lit(1)), op('ne', lit(1), lit(1.0)),
            op('eq', lit({'a': [True, None], 'b': 1}), lit({'b': 1, 'a': [True, None]})),
            op('not', op('contains', lit([True]), lit(1))), op('in', lit('b'), lit('abc')),
            op('lt', lit(1), lit(1.5)), op('le', lit('a'), lit('b')),
            op('all_distinct', lit([True, 1, 1.0])), op('all_equal', lit([])), op('all_distinct', lit([])),
            op('eq', op('concat', lit([1]), lit([True])), lit([1, True])),
            op('eq', op('concat_hex', lit('00'), lit('ff'), lit('')), lit('00ff')),
            op('eq', op('len', lit({'one': None})), lit(1))]
        candidate = plan([], [obligation('o' + str(i), expr) for i, expr in enumerate(true_expressions)])
        self.assertTrue(all(item['verdict'] == 'SATISFIED' for item in execute(candidate, {}, OwnedAdapter(), context_id='owned')['obligations']))

    def test_wrong_operator_types_are_errors_not_inconsistencies(self):
        expressions = [op('not', lit(1)), op('and', lit(True), lit(1)), op('contains', lit('abc'), lit(1)),
                       op('concat', lit('a'), lit([])), op('concat_hex', lit('FF')), op('concat_hex', lit('f')),
                       op('len', lit(None)), op('all_equal', lit({})), op('lt', lit(True), lit(1)),
                       op('le', lit('1'), lit(2)), lit([])]
        candidate = plan([], [obligation('o' + str(i), expr) for i, expr in enumerate(expressions)])
        outcomes = execute(candidate, {}, OwnedAdapter(), context_id='owned')['obligations']
        self.assertTrue(all(item['verdict'] == 'INADMISSIBLE' and item['predicate']['state'] == 'ERROR' for item in outcomes))

    def test_dependency_consumption_order_is_stable_and_deduplicated(self):
        candidate = plan([action('a', arguments={'z': {'input': 'x'}, 'a': {'input': 'y'}, 'm': {'input': 'x'}})],
                         [obligation('o', op('eq', {'ref': 'a'}, {'ref': 'a'}), [('known', {'available': 'a'})])],
                         {'x': 'integer', 'y': 'integer'})
        result = execute(candidate, {'x': 1, 'y': 2}, OwnedAdapter(), context_id='owned')
        self.assertEqual(result['actions'][0]['consumed_references'], ['input:y', 'input:x'])
        self.assertEqual(result['obligations'][0]['consumed_references'], ['action:a'])


class AcquisitionTests(unittest.TestCase):
    def test_later_mutations_do_not_rewrite_inputs_arguments_or_previous_outputs(self):
        class MutableAdapter:
            operations = {'first', 'later'}
            shared = {'items': [1]}
            def invoke(self, operation, arguments, *, step_id, context_id):
                if operation == 'first':
                    arguments['value'].append(99)
                    return {'status': 'OK', 'value': self.shared, 'evidence': [self.shared], 'reason': None}
                self.shared['items'][0] = 9
                return {'status': 'OK', 'value': None, 'evidence': [], 'reason': None}
        supplied = {'items': [1]}
        candidate = plan([action('first', 'first', {'value': {'input': 'items'}}), action('later', 'later')],
                         [obligation('preserved', op('eq', {'ref': 'first', 'path': ['items', 0]}, lit(1)))], {'items': 'array'})
        result = execute(candidate, supplied, MutableAdapter(), context_id='owned')
        self.assertEqual(supplied, {'items': [1]})
        self.assertEqual(result['inputs'], supplied)
        self.assertEqual(result['actions'][0]['arguments'], {'value': [1]})
        self.assertEqual(result['actions'][0]['value'], {'items': [1]})
        self.assertEqual(result['actions'][0]['evidence'], [{'items': [1]}])
        self.assertEqual(result['obligations'][0]['verdict'], 'SATISFIED')

    def test_invalid_adapter_output_types_cannot_supply_a_judgment(self):
        outputs = [{'status': True, 'value': 1, 'evidence': [], 'reason': None},
                   {'status': 'OK', 'value': 1, 'evidence': {}, 'reason': None},
                   {'status': 'OK', 'value': math.nan, 'evidence': [], 'reason': None},
                   {'status': 'OK', 'value': 1, 'evidence': [], 'reason': False}, None]
        for response in outputs:
            class BadAdapter:
                operations = {'bad'}
                def invoke(self, operation, arguments, *, step_id, context_id):
                    return response
            candidate = plan([action('a', 'bad')], [obligation('o', op('eq', {'ref': 'a'}, lit(1)))])
            with self.subTest(response=response):
                result = execute(candidate, {}, BadAdapter(), context_id='owned')
                self.assertEqual(result['actions'][0]['reason'], 'adapter-output-invalid')
                self.assertEqual(result['obligations'][0]['verdict'], 'INADMISSIBLE')

    def test_parallel_operations_really_overlap_and_following_actions_wait(self):
        class ParallelAdapter:
            operations = {'parallel', 'after'}
            def __init__(self):
                self.barrier = threading.Barrier(2)
                self.completed = set()
                self.lock = threading.Lock()
            def invoke(self, operation, arguments, *, step_id, context_id):
                if operation == 'parallel':
                    self.barrier.wait(timeout=3)
                    with self.lock:
                        self.completed.add(step_id)
                    value = step_id
                else:
                    value = sorted(self.completed)
                return {'status': 'OK', 'value': value, 'evidence': [], 'reason': None}
        candidate = plan([{'parallel': [action('left', 'parallel'), action('right', 'parallel')]}, action('after', 'after')],
                         [obligation('joined', op('eq', {'ref': 'after'}, lit(['left', 'right'])))])
        result = execute(candidate, {}, ParallelAdapter(), context_id='shared', max_workers=2)
        a, b, after = result['actions']
        self.assertEqual([item['id'] for item in result['actions']], ['left', 'right', 'after'])
        self.assertTrue(all(item['status'] == 'OK' for item in result['actions']))
        self.assertEqual(a['group'], 'parallel:0')
        self.assertEqual(b['group'], 'parallel:0')
        self.assertLess(max(a['start_event'], b['start_event']), min(a['end_event'], b['end_event']))
        self.assertLess(max(a['end_event'], b['end_event']), after['start_event'])
        self.assertEqual(sorted(item[k] for item in result['actions'] for k in ('start_event', 'end_event')), list(range(1, 7)))
        self.assertEqual(result['obligations'][0]['verdict'], 'SATISFIED')

    def test_skipped_parallel_siblings_have_ordered_records_without_invocations(self):
        adapter = OwnedAdapter()
        candidate = plan([{'parallel': [action('skip', when=lit(False)), action('run')]}])
        receipt = execute(candidate, {}, adapter, context_id='owned')
        self.assertEqual([call[2] for call in adapter.calls], ['run'])
        self.assertEqual([item['status'] for item in receipt['actions']], ['SKIPPED', 'OK'])
        self.assertLess(max(item['start_event'] for item in receipt['actions']), min(item['end_event'] for item in receipt['actions']))

    def test_hashes_bind_the_initial_detached_plan_and_inputs(self):
        candidate = plan([action('a')], [obligation('retained', lit(True))])
        initial = deepcopy(candidate)
        class MutatingCallerAdapter(OwnedAdapter):
            def invoke(self, *args, **kwargs):
                candidate['obligations'].clear()
                return super().invoke(*args, **kwargs)
        result = execute(candidate, {}, MutatingCallerAdapter(), context_id='owned')
        canonical = json.dumps(initial, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
        self.assertEqual(result['plan_sha256'], hashlib.sha256(canonical).hexdigest())
        self.assertEqual(result['inputs_sha256'], hashlib.sha256(b'{}').hexdigest())
        self.assertEqual(len(result['obligations']), 1)


if __name__ == '__main__':
    unittest.main()
