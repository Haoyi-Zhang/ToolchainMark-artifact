"""Execute a typed JSON workflow without adapter-supplied classifications.

Adapters acquire observations. This interpreter resolves declared dependencies,
runs sequential/parallel actions, and evaluates each obligation independently.
Its output contains only JSON snapshots and explicit observation availability.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import re
import threading


class PlanValidationError(ValueError):
    """The plan is not a well-formed declaration with valid dependencies."""


class InputValidationError(ValueError):
    """Supplied inputs do not match the declared JSON names and types."""


class ExecutionConfigurationError(ValueError):
    """The adapter or worker configuration cannot execute the declaration."""


class _InvalidJSON(ValueError):
    pass


_TYPES = {'string', 'integer', 'boolean', 'number', 'array', 'object', 'null'}
_ARITY = {'eq': 2, 'ne': 2, 'contains': 2, 'in': 2, 'lt': 2, 'le': 2,
          'not': 1, 'len': 1, 'all_equal': 1, 'all_distinct': 1,
          'and': None, 'or': None, 'concat': None, 'concat_hex': None}
_MISSING = object()


def _json_check(value, ancestors=None):
    ancestors = set() if ancestors is None else ancestors
    kind = type(value)
    if value is None or kind in (str, bool, int):
        return
    if kind is float:
        if not math.isfinite(value):
            raise _InvalidJSON('nonfinite number')
        return
    if kind not in (dict, list):
        raise _InvalidJSON('non-JSON value type: ' + kind.__name__)
    if id(value) in ancestors:
        raise _InvalidJSON('cyclic JSON container')
    ancestors.add(id(value))
    try:
        if kind is dict:
            if any(type(key) is not str for key in value):
                raise _InvalidJSON('JSON object key must be a string')
            children = value.values()
        else:
            children = value
        for child in children:
            _json_check(child, ancestors)
    finally:
        ancestors.remove(id(value))


def _encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _snapshot(value):
    _json_check(value)
    return json.loads(_encoded(value))


def _name(value):
    return type(value) is str and bool(value)


def _shape(value, required, optional=()):
    return type(value) is dict and set(required) <= set(value) <= set(required) | set(optional)


def _plan_require(condition, message):
    if not condition:
        raise PlanValidationError(message)


def _check_expr(expr, input_ids, action_ids, obligation_ids):
    _plan_require(type(expr) is dict, 'expression must be a tagged object')
    tags = set(expr) & {'literal', 'input', 'ref', 'available', 'verdict', 'op'}
    _plan_require(len(tags) == 1, 'expression must have exactly one tag')
    tag = next(iter(tags))
    if tag == 'literal':
        _plan_require(set(expr) == {'literal'}, 'literal has extra properties')
    elif tag in {'input', 'ref'}:
        _plan_require(_shape(expr, {tag}, {'path'}), 'reference has extra properties')
        domain = input_ids if tag == 'input' else action_ids
        _plan_require(_name(expr[tag]) and expr[tag] in domain, 'unknown or unavailable declaration: ' + tag)
        path = expr.get('path', [])
        _plan_require(type(path) is list and all(type(token) is str or type(token) is int and token >= 0 for token in path),
                      'path tokens must be strings or nonnegative integers')
    elif tag in {'available', 'verdict'}:
        domain = action_ids if tag == 'available' else obligation_ids
        _plan_require(set(expr) == {tag} and _name(expr[tag]) and expr[tag] in domain,
                      'unknown, future or disallowed declaration: ' + tag)
    else:
        _plan_require(set(expr) == {'op', 'args'} and type(expr['op']) is str and expr['op'] in _ARITY,
                      'unknown operator or operator properties')
        args = expr['args']
        _plan_require(type(args) is list, 'operator args must be an array')
        count = _ARITY[expr['op']]
        _plan_require(len(args) == count if count is not None else len(args) >= 1, 'operator arity mismatch: ' + expr['op'])
        for arg in args:
            _check_expr(arg, input_ids, action_ids, obligation_ids)


def validate_plan(plan, allowed_operations=None):
    """Return a detached JSON plan; reject malformed and forward dependencies."""
    try:
        plan = _snapshot(plan)
    except (ValueError, TypeError, RecursionError) as error:
        raise PlanValidationError('plan is not a finite JSON value') from error
    _plan_require(_shape(plan, {'schema', 'id', 'inputs', 'actions', 'obligations'}), 'plan properties differ')
    _plan_require(plan['schema'] == 'toolchainmark-contract-v1' and _name(plan['id']), 'plan schema/id differs')
    _plan_require(type(plan['inputs']) is dict and all(_name(key) and type(value) is str and value in _TYPES
                                                     for key, value in plan['inputs'].items()), 'invalid input declaration')
    allowed = None
    if allowed_operations is not None:
        _plan_require(type(allowed_operations) in (set, frozenset, list, tuple) and
                      all(_name(name) for name in allowed_operations), 'invalid allowed-operation collection')
        allowed = set(allowed_operations)
    _plan_require(type(plan['actions']) is list and type(plan['obligations']) is list, 'actions/obligations must be arrays')
    action_ids = set()
    for outer in plan['actions']:
        if type(outer) is dict and 'parallel' in outer:
            _plan_require(set(outer) == {'parallel'} and type(outer['parallel']) is list and bool(outer['parallel']),
                          'parallel group must contain a nonempty action array')
            group = outer['parallel']
        else:
            group = [outer]
        new_ids = set()
        for action in group:
            _plan_require(_shape(action, {'id', 'operation', 'arguments'}, {'when'}), 'invalid action properties')
            _plan_require(_name(action['id']) and action['id'] not in action_ids | new_ids, 'duplicate/invalid action id')
            _plan_require(_name(action['operation']) and (allowed is None or action['operation'] in allowed), 'unsupported operation')
            _plan_require(type(action['arguments']) is dict and all(_name(key) for key in action['arguments']), 'invalid action arguments')
            if 'when' in action:
                _check_expr(action['when'], plan['inputs'], action_ids, set())
            for expr in action['arguments'].values():
                _check_expr(expr, plan['inputs'], action_ids, set())
            new_ids.add(action['id'])
        action_ids.update(new_ids)
    obligation_ids = set()
    for obligation in plan['obligations']:
        _plan_require(_shape(obligation, {'id', 'stage', 'clause', 'requires', 'predicate'}), 'invalid obligation properties')
        _plan_require(_name(obligation['id']) and obligation['id'] not in obligation_ids, 'duplicate/invalid obligation id')
        _plan_require(_name(obligation['stage']) and _name(obligation['clause']) and type(obligation['requires']) is list,
                      'invalid obligation stage/clause/gates')
        gate_ids = set()
        for gate in obligation['requires']:
            _plan_require(_shape(gate, {'name', 'expr'}) and _name(gate['name']) and gate['name'] not in gate_ids,
                          'duplicate/invalid gate')
            _check_expr(gate['expr'], plan['inputs'], action_ids, obligation_ids)
            gate_ids.add(gate['name'])
        _check_expr(obligation['predicate'], plan['inputs'], action_ids, obligation_ids)
        obligation_ids.add(obligation['id'])
    return plan


def _merge(*dependencies):
    seen, result = set(), []
    for group in dependencies:
        for item in group:
            if item not in seen:
                seen.add(item)
                result.append(item)
    return result


def _result(state, value=None, reason=None, dependencies=()):
    return {'state': state, 'value': _snapshot(value), 'reason': reason, 'dependencies': list(dependencies)}


def _path(value, path):
    for token in path:
        if type(value) is dict and type(token) is str and token in value:
            value = value[token]
        elif type(value) is list and type(token) is int and 0 <= token < len(value):
            value = value[token]
        else:
            return _MISSING
    return value


def _equal(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(_equal(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    return left == right


def _apply(op, values):
    if op in {'eq', 'ne'}:
        equal = _equal(*values)
        return equal if op == 'eq' else not equal
    if op in {'and', 'or', 'not'}:
        if not all(type(value) is bool for value in values):
            raise TypeError
        return all(values) if op == 'and' else any(values) if op == 'or' else not values[0]
    if op in {'contains', 'in'}:
        container, member = values if op == 'contains' else values[::-1]
        if type(container) is list:
            return any(_equal(item, member) for item in container)
        if type(container) is str and type(member) is str:
            return member in container
        raise TypeError
    if op == 'concat':
        if all(type(value) is str for value in values):
            return ''.join(values)
        if all(type(value) is list for value in values):
            return [item for value in values for item in value]
        raise TypeError
    if op == 'concat_hex':
        if not all(type(value) is str and re.fullmatch(r'(?:[0-9a-f]{2})*', value) is not None for value in values):
            raise TypeError
        return ''.join(values)
    if op == 'len':
        if type(values[0]) not in (str, list, dict):
            raise TypeError
        return len(values[0])
    if op in {'all_equal', 'all_distinct'}:
        sequence = values[0]
        if type(sequence) is not list:
            raise TypeError
        return (all(_equal(sequence[0], item) for item in sequence[1:]) if op == 'all_equal' else
                all(not _equal(item, earlier) for index, item in enumerate(sequence) for earlier in sequence[:index]))
    if op in {'lt', 'le'}:
        if not (all(type(value) in (int, float) for value in values) or all(type(value) is str for value in values)):
            raise TypeError
        return values[0] < values[1] if op == 'lt' else values[0] <= values[1]
    raise RuntimeError('unvalidated operator')


def _evaluate(expr, inputs, actions, obligations):
    if 'literal' in expr:
        return _result('VALUE', expr['literal'])
    if 'input' in expr:
        name = expr['input']
        value = _path(inputs[name], expr.get('path', []))
        return (_result('UNKNOWN', reason='input-path-missing:' + name, dependencies=['input:' + name]) if value is _MISSING else
                _result('VALUE', value, dependencies=['input:' + name]))
    if 'ref' in expr or 'available' in expr:
        name = expr.get('ref', expr.get('available'))
        action = actions[name]
        if 'available' in expr:
            return _result('VALUE', action['status'] == 'OK', dependencies=['action:' + name])
        if action['status'] != 'OK':
            return _result('UNKNOWN', reason='action-unavailable:' + name, dependencies=['action:' + name])
        value = _path(action['value'], expr.get('path', []))
        return (_result('UNKNOWN', reason='action-path-missing:' + name, dependencies=['action:' + name]) if value is _MISSING else
                _result('VALUE', value, dependencies=['action:' + name]))
    if 'verdict' in expr:
        name = expr['verdict']
        return _result('VALUE', obligations[name]['verdict'], dependencies=['obligation:' + name])
    evaluated = [_evaluate(arg, inputs, actions, obligations) for arg in expr['args']]
    dependencies = _merge(*(item['dependencies'] for item in evaluated))
    for state in ('ERROR', 'UNKNOWN'):
        first = next((item for item in evaluated if item['state'] == state), None)
        if first is not None:
            return _result(state, reason=first['reason'], dependencies=dependencies)
    try:
        value = _apply(expr['op'], [item['value'] for item in evaluated])
    except TypeError:
        return _result('ERROR', reason='type-error:' + expr['op'], dependencies=dependencies)
    return _result('VALUE', value, dependencies=dependencies)


def _boolean(evaluation):
    if evaluation['state'] != 'VALUE':
        return evaluation
    if type(evaluation['value']) is not bool:
        return _result('ERROR', reason='boolean-required', dependencies=evaluation['dependencies'])
    return _result('TRUE' if evaluation['value'] else 'FALSE', evaluation['value'], dependencies=evaluation['dependencies'])


def _input_matches(value, name):
    mapping = {'string': str, 'integer': int, 'boolean': bool, 'array': list, 'object': dict, 'null': type(None)}
    return type(value) in (int, float) if name == 'number' else type(value) is mapping[name]


def execute(plan, inputs, adapter, *, context_id, max_workers=2):
    """Acquire every declared action and return independently classified clauses."""
    try:
        operations = adapter.operations
        invoke = adapter.invoke
    except Exception as error:
        raise ExecutionConfigurationError('adapter must expose operations and invoke') from error
    if type(operations) not in (set, frozenset) or not all(_name(name) for name in operations) or not callable(invoke):
        raise ExecutionConfigurationError('invalid adapter operation interface')
    plan = validate_plan(plan, operations)
    if not _name(context_id) or type(max_workers) is not int or max_workers < 1:
        raise ExecutionConfigurationError('invalid context_id or max_workers')
    for block in plan['actions']:
        if 'parallel' in block and len(block['parallel']) > max_workers:
            raise ExecutionConfigurationError('max_workers cannot realize declared parallel group')
    try:
        inputs = _snapshot(inputs)
    except (ValueError, TypeError, RecursionError) as error:
        raise InputValidationError('inputs are not finite JSON') from error
    if type(inputs) is not dict or inputs.keys() != plan['inputs'].keys() or not all(
            _input_matches(inputs[name], kind) for name, kind in plan['inputs'].items()):
        raise InputValidationError('input names or JSON types differ from declaration')
    counter, lock = 0, threading.Lock()
    actions, obligation_records = {}, {}
    def tick():
        nonlocal counter
        with lock:
            counter += 1
            return counter
    def acquire(action, group, prior, barrier=None):
        start = tick()
        if barrier is not None:
            barrier.wait()
        guard = (_boolean(_evaluate(action['when'], inputs, prior, {})) if 'when' in action else
                 _result('TRUE', True))
        evaluations = {}
        arguments = None
        dependencies = guard['dependencies']
        status, reason, value, evidence = 'SKIPPED', 'guard:' + guard['state'], None, []
        if guard['state'] == 'TRUE':
            evaluations = {name: _evaluate(expr, inputs, prior, {}) for name, expr in sorted(action['arguments'].items())}
            dependencies = _merge(dependencies, *(item['dependencies'] for item in evaluations.values()))
            failed = next((name for name, item in evaluations.items() if item['state'] != 'VALUE'), None)
            if failed is not None:
                reason = 'argument:' + failed + ':' + evaluations[failed]['state']
            else:
                arguments = {name: item['value'] for name, item in evaluations.items()}
                try:
                    response = invoke(action['operation'], _snapshot(arguments), step_id=action['id'], context_id=context_id)
                except Exception as error:
                    status, reason = 'UNAVAILABLE', 'adapter-exception:' + type(error).__name__
                else:
                    try:
                        response = _snapshot(response)
                        if not (_shape(response, {'status', 'value', 'evidence', 'reason'}) and
                                type(response['status']) is str and response['status'] in {'OK', 'UNAVAILABLE'} and
                                type(response['evidence']) is list and (response['reason'] is None or type(response['reason']) is str)):
                            raise _InvalidJSON('adapter result shape/types differ')
                        status, reason, value, evidence = (response[name] for name in ('status', 'reason', 'value', 'evidence'))
                    except (ValueError, TypeError, RecursionError, RuntimeError):
                        status, reason, value, evidence = 'UNAVAILABLE', 'adapter-output-invalid', None, []
        return {'id': action['id'], 'operation': action['operation'], 'arguments': _snapshot(arguments),
                'argument_evaluations': evaluations, 'context_id': context_id, 'status': status, 'reason': reason,
                'value': value, 'evidence': evidence, 'start_event': start, 'end_event': tick(), 'group': group,
                'guard': guard, 'consumed_references': dependencies}
    for index, block in enumerate(plan['actions']):
        if 'parallel' in block:
            group = block['parallel']
            barrier = threading.Barrier(len(group))
            prior = dict(actions)
            with ThreadPoolExecutor(max_workers=len(group)) as pool:
                futures = [pool.submit(acquire, action, 'parallel:' + str(index), prior, barrier) for action in group]
                records = [future.result() for future in futures]
        else:
            records = [acquire(block, None, actions)]
        for record in records:
            actions[record['id']] = record
    for obligation in plan['obligations']:
        gates = [{'name': gate['name'], **_boolean(_evaluate(gate['expr'], inputs, actions, obligation_records))}
                 for gate in obligation['requires']]
        dependencies = _merge(*(gate['dependencies'] for gate in gates))
        failed = next((gate for gate in gates if gate['state'] != 'TRUE'), None)
        predicate = None
        failed_gate = None
        if failed is not None:
            verdict, reason, failed_gate = 'INADMISSIBLE', 'gate:' + failed['name'] + ':' + failed['state'], failed['name']
        else:
            predicate = _boolean(_evaluate(obligation['predicate'], inputs, actions, obligation_records))
            dependencies = _merge(dependencies, predicate['dependencies'])
            if predicate['state'] in {'UNKNOWN', 'ERROR'}:
                verdict, reason = 'INADMISSIBLE', 'predicate:' + predicate['state']
            else:
                passed = predicate['state'] == 'TRUE'
                verdict, reason = ('SATISFIED', 'predicate-true') if passed else ('INCONSISTENT', 'predicate-false')
        obligation_records[obligation['id']] = {'id': obligation['id'], 'stage': obligation['stage'], 'clause': obligation['clause'],
            'gates': gates, 'predicate': predicate, 'verdict': verdict, 'reason': reason, 'failed_gate': failed_gate,
            'consumed_references': dependencies}
    return _snapshot({'schema': 'toolchainmark-execution-v1', 'plan_sha256': hashlib.sha256(_encoded(plan)).hexdigest(),
        'inputs': inputs, 'inputs_sha256': hashlib.sha256(_encoded(inputs)).hexdigest(), 'context_id': context_id,
        'actions': list(actions.values()), 'obligations': list(obligation_records.values())})
