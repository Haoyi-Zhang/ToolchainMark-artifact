"""Construct evidence projections; this module does not execute a toolchain."""
from __future__ import annotations

import copy
import json

from contract_runtime.receiver import canonical_sha256, validate_plan, verify_receipt


SCHEMA = 'toolchainmark-obligation-evidence'


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode()


def references(value, tags):
    if isinstance(value, dict):
        for tag in tags:
            if tag in value:
                yield value[tag]
        # Traverse the expression grammar, not arbitrary JSON. Literal objects
        # and path components do not introduce declaration references.
        if 'op' in value:
            yield from references(value['args'], tags)
    elif isinstance(value, list):
        for child in value:
            yield from references(child, tags)


def selection(plan, target):
    plan = validate_plan(plan)
    declared = {item['id']: item for item in plan['obligations']}
    if target not in declared:
        raise ValueError('unknown target obligation')
    included = set()

    def expressions(obligation):
        return [gate['expr'] for gate in obligation['requires']] + [obligation['predicate']]

    def add(name):
        if name not in included:
            included.add(name)
            for dependency in references(expressions(declared[name]), ('verdict',)):
                add(dependency)
    add(target)
    obligations = [item['id'] for item in plan['obligations'] if item['id'] in included]
    actions = set()
    for name in obligations:
        actions.update(references(expressions(declared[name]), ('ref', 'available')))
    blocks = [item.get('parallel', [item]) for item in plan['actions']]
    cutoff = max((index + 1 for index, block in enumerate(blocks)
                  if any(item['id'] in actions for item in block)), default=0)
    prefix = [item['id'] for block in blocks[:cutoff] for item in block]
    # This separate closure is measured as a value-dependency comparator.
    # It has no history-preservation guarantee for arbitrary stateful adapters.
    all_actions = {item['id']: item for block in blocks for item in block}
    reference_only = set(actions)
    pending = list(actions)
    while pending:
        name = pending.pop()
        action = all_actions[name]
        expressions_used = list(action['arguments'].values()) + [action.get('when', {'literal': True})]
        for dependency in references(expressions_used, ('ref', 'available')):
            if dependency not in reference_only:
                reference_only.add(dependency)
                pending.append(dependency)
    ordered_references = [item['id'] for block in blocks for item in block
                          if item['id'] in reference_only]
    return {'action_blocks': cutoff, 'action_ids': prefix, 'obligation_ids': obligations,
            'reference_action_ids': ordered_references}


def project(plan, receipt, target, native_context, *, check_full=True):
    if check_full:
        verify_receipt(plan, receipt)
    chosen = selection(plan, target)
    projected = copy.deepcopy(receipt)
    projected['actions'] = projected['actions'][:len(chosen['action_ids'])]
    keep = set(chosen['obligation_ids'])
    projected['obligations'] = [row for row in projected['obligations'] if row['id'] in keep]
    return {'schema': SCHEMA, 'target': target, 'source_plan': copy.deepcopy(plan),
            'projection': {key: chosen[key] for key in ('action_blocks', 'action_ids', 'obligation_ids')},
            'receipt': projected, 'native_context': copy.deepcopy(native_context)}


def internal_plan(bundle):
    """Return the explicitly induced plan, never mislabel it as a new execution."""
    plan = copy.deepcopy(bundle['source_plan'])
    plan['actions'] = plan['actions'][:bundle['projection']['action_blocks']]
    keep = set(bundle['projection']['obligation_ids'])
    plan['obligations'] = [item for item in plan['obligations'] if item['id'] in keep]
    return plan


def replay_only(plan, receipt, target):
    chosen = selection(plan, target)
    ids = set(chosen['reference_action_ids'])
    keep = set(chosen['obligation_ids'])
    return {'inputs': receipt['inputs'],
            'actions': [{key: row[key] for key in ('id', 'status', 'value')}
                        for row in receipt['actions'] if row['id'] in ids],
            'obligations': [row for row in receipt['obligations'] if row['id'] in keep]}
