"""Construct the three fully declared sequential experiments, without acquisition."""
from __future__ import annotations


def literal(value): return {'literal': value}
def inp(name): return {'input': name}
def ref(action, *path): return {'ref': action, 'path': list(path)}
def op(name, *args): return {'op': name, 'args': list(args)}
def available(action): return {'available': action}
def gate(name, expr): return {'name': name, 'expr': expr}


INPUTS = {key: 'string' for key in ('cell', 'algorithm', 'algorithm_class', 'host', 'a_case', 'b_case',
                                   'payload_a', 'payload_b', 'key_a', 'key_b', 'history', 'lifetime')}
INPUTS.update(archived_embedding_seed='integer', acquisition_pass='integer')


def make_plan(history: str) -> dict:
    if history not in ('AA', 'AAA', 'ABA'): raise ValueError('Unknown history')
    steps = [('first-a', 'A', 'payload_a', 'key_a')]
    if history == 'AAA': steps.append(('middle-a', 'A', 'payload_a', 'key_a'))
    if history == 'ABA': steps.append(('middle-b', 'B', 'payload_b', 'key_b'))
    steps.append(('last-a', 'A', 'payload_a', 'key_a'))
    actions = [
        {'id': 'prepare', 'operation': 'sessions.prepare', 'arguments': {
            'a_case': inp('a_case'), 'b_case': inp('b_case'), 'history': inp('history'),
            'algorithm_class': inp('algorithm_class')}},
        {'id': 'open', 'operation': 'sessions.open', 'when': ref('prepare', 'all_inputs_available'),
         'arguments': {'algorithm_class': inp('algorithm_class'), 'lifetime': inp('lifetime')}},
    ]
    previous = 'open'
    obligations = []
    for sid, role, payload, key in steps:
        actions.append({'id': sid, 'operation': 'sessions.recognize', 'when': available(previous),
                        'arguments': {'session': ref('open', 'session_id'), 'role': literal(role),
                                      'key': inp(key), 'folder': ref('prepare', 'folders', role)}})
        obligations.append({
            'id': sid + '-source', 'stage': 'source',
            'clause': 'The intended payload is among the fully enumerated native candidates for this request.',
            'requires': [gate('required archived inputs are available', ref('prepare', 'all_inputs_available')),
                         gate('recognition completed', available(sid)),
                         gate('request begins with its declared prepared input and auxiliary context',
                              op('eq', ref('prepare', 'initial_context', role), ref(sid, 'before'))),
                         gate('input and authorized auxiliary endpoint versions agree',
                              op('eq', ref(sid, 'before'), ref(sid, 'after')))],
            'predicate': op('contains', ref(sid, 'native', 'candidates'), inp(payload)),
        })
        previous = sid
    actions.append({'id': 'close', 'operation': 'sessions.close', 'when': available('open'),
                    'arguments': {'session': ref('open', 'session_id')}})
    gates = [gate('first A recovered its payload', op('eq', {'verdict': 'first-a-source'}, literal('SATISFIED'))),
             gate('returning A recognition completed', available('last-a')),
             gate('A versions and authorized auxiliary context are unchanged across the history',
                  op('and', op('eq', ref('first-a', 'before'), ref('first-a', 'after')),
                     op('eq', ref('first-a', 'after'), ref('last-a', 'before')),
                     op('eq', ref('last-a', 'before'), ref('last-a', 'after'))))]
    if history == 'ABA':
        gates.extend([gate('intervening B recognition completed', available('middle-b')),
                      gate('B begins with its declared prepared context',
                           op('eq', ref('prepare', 'initial_context', 'B'), ref('middle-b', 'before'))),
                      gate('B input and authorized auxiliary endpoints agree',
                           op('eq', ref('middle-b', 'before'), ref('middle-b', 'after')))])
    if history == 'AAA':
        gates.extend([gate('intermediate A recognition completed', available('middle-a')),
                      gate('the complete A-version chain agrees through the intermediate request',
                           op('and', op('eq', ref('first-a', 'after'), ref('middle-a', 'before')),
                              op('eq', ref('middle-a', 'before'), ref('middle-a', 'after')),
                              op('eq', ref('middle-a', 'after'), ref('last-a', 'before'))))])
    obligations.append({'id': 'revisit', 'stage': 'history',
                        'clause': 'A payload recovered before the declared history remains recoverable on returning to unchanged A.',
                        'requires': gates,
                        'predicate': op('contains', ref('last-a', 'native', 'candidates'), inp('payload_a'))})
    return {'schema': 'toolchainmark-contract-v1', 'id': 'sandmark-session-' + history.lower(),
            'inputs': INPUTS, 'actions': actions, 'obligations': obligations}
