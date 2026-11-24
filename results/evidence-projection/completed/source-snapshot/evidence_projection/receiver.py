"""Check a stage bundle without a producer or a complete original receipt.

The caller selects the original plan, case, and native binding context. The
check establishes a valid declared prefix and its recorded native bindings;
it does not prove membership in an unavailable historical JSON document.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from contract_runtime.receiver import (InvalidRecord, canonical_sha256, load_json,
                                      validate_plan, verify_receipt)


def insist(condition, message):
    if not condition:
        raise InvalidRecord(message)


def same(a, b):
    return json.dumps(a, sort_keys=True, ensure_ascii=True, allow_nan=False) == \
           json.dumps(b, sort_keys=True, ensure_ascii=True, allow_nan=False)


def required_projection(plan, target):
    """Independent iterative traversal, not the projection producer's helper."""
    plan = validate_plan(plan)
    obligations = {item['id']: item for item in plan['obligations']}
    insist(target in obligations, 'target is absent from the externally selected plan')
    wanted_obligations, wanted_actions = {target}, set()
    def enqueue_obligation(name, queue):
        item = obligations[name]
        queue.append(item['predicate'])
        queue.extend(gate['expr'] for gate in item['requires'])
    pending = []
    enqueue_obligation(target, pending)
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
            continue
        if not isinstance(node, dict) or 'literal' in node:
            continue
        for tag in ('ref', 'available'):
            if tag in node:
                wanted_actions.add(node[tag])
        if 'verdict' in node and node['verdict'] not in wanted_obligations:
            name = node['verdict']
            insist(name in obligations, 'unknown preceding obligation')
            wanted_obligations.add(name)
            enqueue_obligation(name, pending)
        if 'op' in node:
            pending.extend(node['args'])
    latest, prefix = 0, []
    blocks = []
    for ordinal, item in enumerate(plan['actions'], 1):
        block = item['parallel'] if 'parallel' in item else [item]
        blocks.append(block)
        if any(action['id'] in wanted_actions for action in block):
            latest = ordinal
    for block in blocks[:latest]:
        prefix.extend(action['id'] for action in block)
    return {'action_blocks': latest, 'action_ids': prefix,
            'obligation_ids': [item['id'] for item in plan['obligations']
                               if item['id'] in wanted_obligations]}


def verify_structure(bundle, *, expected_plan, expected_inputs, expected_context_id,
                     expected_native_context, expected_target):
    insist(type(expected_inputs) is dict and type(expected_context_id) is str and bool(expected_context_id)
           and type(expected_target) is str and bool(expected_target)
           and type(expected_native_context) is dict, 'external case selection is incomplete')
    insist(type(bundle) is dict and set(bundle) == {'schema', 'target', 'source_plan',
           'projection', 'receipt', 'native_context'}, 'unexpected bundle structure')
    insist(bundle['schema'] == 'toolchainmark-obligation-evidence', 'unknown bundle protocol')
    insist(bundle['target'] == expected_target, 'target differs from external selection')
    insist(same(bundle['source_plan'], expected_plan), 'source plan differs from external declaration')
    insist(same(bundle['native_context'], expected_native_context), 'native binding context differs')
    wanted = required_projection(expected_plan, bundle['target'])
    insist(same(bundle['projection'], wanted), 'projection is not the complete required block prefix')
    receipt = bundle['receipt']
    insist(receipt['plan_sha256'] == canonical_sha256(expected_plan), 'original plan identity differs')
    insist([row['id'] for row in receipt['actions']] == wanted['action_ids'], 'prefix action set/order differs')
    insist([row['id'] for row in receipt['obligations']] == wanted['obligation_ids'], 'obligation closure differs')
    induced = copy.deepcopy(expected_plan)
    induced['actions'] = induced['actions'][:wanted['action_blocks']]
    selected = set(wanted['obligation_ids'])
    induced['obligations'] = [row for row in induced['obligations'] if row['id'] in selected]
    internal = copy.deepcopy(receipt)
    # Only this local view has the induced plan's identity. The retained receipt
    # continues to identify the original declaration and original event order.
    internal['plan_sha256'] = canonical_sha256(induced)
    report = verify_receipt(induced, internal, expected_inputs=expected_inputs,
                            expected_context_id=expected_context_id)
    target = next(row for row in receipt['obligations'] if row['id'] == bundle['target'])
    return {'status': 'PASS', 'target': bundle['target'], 'target_judgment': target,
            'retained_actions': report['actions'], 'retained_obligations': report['obligations'],
            'original_event_ordinals_preserved': True,
            'scope': 'Valid complete-block prefix for the externally selected declaration and case; no original-record membership or fresh-execution claim.'}


def verify_bundle(bundle, native_root, *, expected_plan, expected_inputs,
                  expected_context_id, expected_native_context, expected_target):
    result = verify_structure(bundle, expected_plan=expected_plan, expected_inputs=expected_inputs,
                              expected_context_id=expected_context_id,
                              expected_native_context=expected_native_context,
                              expected_target=expected_target)
    from .native import verify_native
    result['native_checks'] = verify_native(bundle['receipt'], Path(native_root), expected_native_context)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--case', required=True, type=Path,
                        help='Externally selected original plan, inputs, context_id and native_context')
    parser.add_argument('--native', required=True, type=Path)
    args = parser.parse_args()
    case = load_json(args.case)
    try:
        answer = verify_bundle(load_json(args.bundle), args.native, expected_plan=case['plan'],
            expected_inputs=case['inputs'], expected_context_id=case['context_id'],
            expected_native_context=case['native_context'], expected_target=case['target'])
    except (ValueError, OSError, KeyError, TypeError) as problem:
        print(json.dumps({'status': 'INVALID_RECORD', 'error': str(problem)}))
        return 1
    print(json.dumps(answer, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
