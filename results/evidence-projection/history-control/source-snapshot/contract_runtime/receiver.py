"""Independently check a declared plan against an execution receipt.

This module deliberately imports neither the executor nor any adapter.  It
reconstructs expression results, dependencies, guards and stage verdicts from
the retained JSON.  Adapter-specific checks of command output and artifact
bytes are a separate layer: a consistent receipt is not execution attestation
or proof of what an extractor actually read between endpoint captures.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any


class InvalidRecord(ValueError):
    """The supplied plan/receipt is malformed or internally contradictory."""


PLAN_SCHEMA = "toolchainmark-contract-v1"
RECEIPT_SCHEMA = "toolchainmark-execution-v1"
INPUT_TYPES = {"string", "integer", "boolean", "number", "array", "object", "null"}
ARITIES = {
    "eq": (2, 2), "ne": (2, 2), "contains": (2, 2), "in": (2, 2),
    "lt": (2, 2), "le": (2, 2), "not": (1, 1), "len": (1, 1),
    "all_equal": (1, 1), "all_distinct": (1, 1),
    "and": (1, None), "or": (1, None), "concat": (1, None),
    "concat_hex": (1, None),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidRecord(message)


def _json_value(value: Any, where: str = "JSON", active=None) -> None:
    """Accept exact JSON types; reject Python coercions and nonfinite values."""
    kind = type(value)
    if value is None or kind in (str, bool, int):
        return
    if kind is float:
        _require(math.isfinite(value), where + ": nonfinite number")
        return
    if kind in (list, dict):
        active = set() if active is None else active
        _require(id(value) not in active, where + ": cyclic JSON value")
        active.add(id(value))
        try:
            if kind is list:
                for index, item in enumerate(value):
                    _json_value(item, f"{where}[{index}]", active)
            else:
                _require(all(type(key) is str for key in value), where + ": non-string key")
                for key, item in value.items():
                    _json_value(item, where + "." + key, active)
        finally:
            active.remove(id(value))
        return
    raise InvalidRecord(where + ": non-JSON type")


def canonical_sha256(value: Any) -> str:
    _json_value(value)
    data = json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def load_json(path: str | Path) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def bad_constant(value):
        raise InvalidRecord("nonfinite JSON constant: " + value)

    try:
        result = json.loads(Path(path).read_text(encoding="utf-8"),
                            object_pairs_hook=pairs, parse_constant=bad_constant)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InvalidRecord("cannot read JSON: " + str(error)) from error
    _json_value(result)
    return result


def _keys(value, required, optional=(), where="object"):
    _require(type(value) is dict, where + ": expected object")
    _require(set(required) <= set(value) <= set(required) | set(optional),
             where + ": missing or unexpected fields")


def _name(value, where):
    _require(type(value) is str and bool(value), where + ": expected nonempty string")


def _same(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (left.keys() == right.keys() and
                all(_same(left[key], right[key]) for key in left))
    if type(left) is list:
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def _path(value, where):
    _require(type(value) is list, where + ": path must be an array")
    _require(all(type(part) is str or (type(part) is int and part >= 0)
                 for part in value), where + ": invalid path component")


def _check_expression(expr, inputs, actions, obligations, where):
    _require(type(expr) is dict, where + ": expression must be an object")
    tags = set(expr) & {"literal", "input", "ref", "available", "verdict", "op"}
    _require(len(tags) == 1, where + ": expected one expression tag")
    tag = next(iter(tags))
    if tag == "literal":
        _keys(expr, {"literal"}, where=where)
        _json_value(expr["literal"], where)
    elif tag in {"input", "ref"}:
        _keys(expr, {tag}, {"path"}, where)
        _name(expr[tag], where)
        _path(expr.get("path", []), where)
        domain = inputs if tag == "input" else actions
        _require(expr[tag] in domain, where + ": unknown or future " + tag)
    elif tag in {"available", "verdict"}:
        _keys(expr, {tag}, where=where)
        _name(expr[tag], where)
        domain = actions if tag == "available" else obligations
        _require(expr[tag] in domain, where + ": unknown or future " + tag)
    else:
        _keys(expr, {"op", "args"}, where=where)
        _require(type(expr["op"]) is str and expr["op"] in ARITIES,
                 where + ": unknown expression operator")
        args = expr["args"]
        _require(type(args) is list, where + ": args must be an array")
        low, high = ARITIES[expr["op"]]
        _require(len(args) >= low and (high is None or len(args) <= high),
                 where + ": wrong operator arity")
        for index, argument in enumerate(args):
            _check_expression(argument, inputs, actions, obligations, f"{where}.args[{index}]")


def validate_plan(plan, allowed_operations=None):
    """Validate the language independently, including no-future-reference rules."""
    _json_value(plan, "plan")
    _keys(plan, {"schema", "id", "inputs", "actions", "obligations"}, where="plan")
    _require(plan["schema"] == PLAN_SCHEMA, "unknown plan schema")
    _name(plan["id"], "plan.id")
    _require(type(plan["inputs"]) is dict, "plan.inputs must be an object")
    for key, value in plan["inputs"].items():
        _name(key, "input name")
        _require(type(value) is str and value in INPUT_TYPES, "unknown input type")
    _require(type(plan["actions"]) is list, "plan.actions must be an array")
    _require(type(plan["obligations"]) is list, "plan.obligations must be an array")
    seen_actions = set()
    for index, entry in enumerate(plan["actions"]):
        _require(type(entry) is dict, "action/group must be an object")
        if "parallel" in entry:
            _keys(entry, {"parallel"}, where="parallel group")
            batch = entry["parallel"]
            _require(type(batch) is list and bool(batch), "empty or malformed parallel group")
        else:
            batch = [entry]
        group_ids = set()
        for action in batch:
            _keys(action, {"id", "operation", "arguments"}, {"when"}, "action")
            _name(action["id"], "action.id")
            _name(action["operation"], "action.operation")
            _require(action["id"] not in seen_actions | group_ids, "duplicate action id")
            if allowed_operations is not None:
                _require(action["operation"] in allowed_operations, "unsupported operation")
            _require(type(action["arguments"]) is dict, "arguments must be an object")
            for name, expr in action["arguments"].items():
                _name(name, "argument name")
                _check_expression(expr, plan["inputs"], seen_actions, set(),
                                  f"action[{index}].argument.{name}")
            if "when" in action:
                _check_expression(action["when"], plan["inputs"], seen_actions, set(),
                                  f"action[{index}].when")
            group_ids.add(action["id"])
        seen_actions.update(group_ids)
    seen_obligations = set()
    for index, obligation in enumerate(plan["obligations"]):
        _keys(obligation, {"id", "stage", "clause", "requires", "predicate"}, where="obligation")
        for key in ("id", "stage", "clause"):
            _name(obligation[key], "obligation." + key)
        _require(obligation["id"] not in seen_obligations, "duplicate obligation id")
        _require(type(obligation["requires"]) is list, "requires must be an array")
        gate_names = set()
        for gate in obligation["requires"]:
            _keys(gate, {"name", "expr"}, where="gate")
            _name(gate["name"], "gate.name")
            _require(gate["name"] not in gate_names, "duplicate gate name")
            _check_expression(gate["expr"], plan["inputs"], seen_actions, seen_obligations,
                              f"obligation[{index}].gate.{gate['name']}")
            gate_names.add(gate["name"])
        _check_expression(obligation["predicate"], plan["inputs"], seen_actions, seen_obligations,
                          f"obligation[{index}].predicate")
        seen_obligations.add(obligation["id"])
    return json.loads(json.dumps(plan, ensure_ascii=True, allow_nan=False))


def _check_inputs(plan, values):
    _json_value(values, "inputs")
    _require(type(values) is dict and values.keys() == plan["inputs"].keys(),
             "execution input names differ from declaration")
    exact = {"string": str, "integer": int, "boolean": bool,
             "array": list, "object": dict, "null": type(None)}
    for name, declaration in plan["inputs"].items():
        kind = type(values[name])
        matches = kind in (int, float) if declaration == "number" else kind is exact[declaration]
        _require(matches, "input type differs: " + name)


def _dependencies(*groups):
    seen = set()
    ordered = []
    for group in groups:
        for name in group:
            if name not in seen:
                seen.add(name)
                ordered.append(name)
    return ordered


@dataclass
class Evaluation:
    state: str
    value: Any = None
    reason: str | None = None
    dependencies: list[str] | None = None

    def as_dict(self):
        return {"state": self.state, "value": self.value, "reason": self.reason,
                "dependencies": list(self.dependencies or [])}


def _get_path(value, path):
    for part in path:
        if type(value) is dict and type(part) is str and part in value:
            value = value[part]
        elif type(value) is list and type(part) is int and 0 <= part < len(value):
            value = value[part]
        else:
            return False, None
    return True, value


def _operate(name, values):
    """Interpret only the small specified expression vocabulary."""
    if name == "eq":
        return _same(*values)
    if name == "ne":
        return not _same(*values)
    if name in {"and", "or", "not"}:
        if not all(type(value) is bool for value in values):
            raise TypeError
        if name == "and":
            return all(values)
        if name == "or":
            return any(values)
        return not values[0]
    if name in {"contains", "in"}:
        container, member = values if name == "contains" else list(reversed(values))
        if type(container) is str and type(member) is str:
            return member in container
        if type(container) is list:
            return any(_same(member, item) for item in container)
        raise TypeError
    if name == "concat":
        if all(type(value) is str for value in values):
            return "".join(values)
        if all(type(value) is list for value in values):
            return [item for value in values for item in value]
        raise TypeError
    if name == "concat_hex":
        if not all(type(value) is str and re.fullmatch(r"(?:[0-9a-f]{2})*", value)
                   for value in values):
            raise TypeError
        return "".join(values)
    if name == "len":
        if type(values[0]) not in (str, list, dict):
            raise TypeError
        return len(values[0])
    if name in {"all_equal", "all_distinct"}:
        items = values[0]
        if type(items) is not list:
            raise TypeError
        if name == "all_equal":
            return not items or all(_same(items[0], value) for value in items[1:])
        return all(not _same(items[i], items[j]) for i in range(len(items))
                   for j in range(i + 1, len(items)))
    if name in {"lt", "le"}:
        a, b = values
        if not ((type(a) in (int, float) and type(b) in (int, float)) or
                type(a) is type(b) is str):
            raise TypeError
        return a < b if name == "lt" else a <= b
    raise InvalidRecord("unvalidated operator")


def evaluate_expression(expr, inputs, actions, obligations):
    """Independent eager interpretation; callers first validate the plan."""
    if "literal" in expr:
        return Evaluation("VALUE", expr["literal"], dependencies=[])
    if "input" in expr:
        identity = expr["input"]
        found, value = _get_path(inputs[identity], expr.get("path", []))
        return Evaluation("VALUE" if found else "UNKNOWN", value,
                          None if found else "input-path-missing:" + identity,
                          ["input:" + identity])
    if "ref" in expr:
        identity = expr["ref"]
        action = actions[identity]
        dependencies = ["action:" + identity]
        if action["status"] != "OK":
            return Evaluation("UNKNOWN", reason="action-unavailable:" + identity,
                              dependencies=dependencies)
        found, value = _get_path(action["value"], expr.get("path", []))
        return Evaluation("VALUE" if found else "UNKNOWN", value,
                          None if found else "action-path-missing:" + identity, dependencies)
    if "available" in expr:
        identity = expr["available"]
        return Evaluation("VALUE", actions[identity]["status"] == "OK",
                          dependencies=["action:" + identity])
    if "verdict" in expr:
        identity = expr["verdict"]
        return Evaluation("VALUE", obligations[identity]["verdict"],
                          dependencies=["obligation:" + identity])
    evaluations = [evaluate_expression(argument, inputs, actions, obligations)
                   for argument in expr["args"]]
    dependencies = _dependencies(*(item.dependencies or [] for item in evaluations))
    for state in ("ERROR", "UNKNOWN"):
        failed = next((item for item in evaluations if item.state == state), None)
        if failed is not None:
            return Evaluation(state, reason=failed.reason, dependencies=dependencies)
    try:
        value = _operate(expr["op"], [item.value for item in evaluations])
    except (TypeError, ValueError, OverflowError):
        return Evaluation("ERROR", reason="type-error:" + expr["op"], dependencies=dependencies)
    return Evaluation("VALUE", value, dependencies=dependencies)


def _boolean(expr, inputs, actions, obligations):
    result = evaluate_expression(expr, inputs, actions, obligations)
    if result.state == "VALUE":
        if type(result.value) is not bool:
            return Evaluation("ERROR", reason="boolean-required", dependencies=result.dependencies)
        result.state = "TRUE" if result.value else "FALSE"
    return result


def _expect(actual, expected, where):
    _require(_same(actual, expected), where + ": recorded value differs from independent evaluation")


ACTION_KEYS = {
    "id", "operation", "arguments", "argument_evaluations", "context_id", "status",
    "reason", "value", "evidence", "start_event", "end_event", "group", "guard",
    "consumed_references",
}
OBLIGATION_KEYS = {
    "id", "stage", "clause", "gates", "predicate", "verdict", "reason",
    "failed_gate", "consumed_references",
}


def verify_receipt(plan, receipt, *, expected_inputs=None, expected_context_id=None):
    """Return a PASS report or raise InvalidRecord; never rewrite bad data as IA."""
    plan = validate_plan(plan)
    _json_value(receipt, "receipt")
    receipt = json.loads(json.dumps(receipt, ensure_ascii=True, allow_nan=False))
    _keys(receipt, {"schema", "plan_sha256", "inputs", "inputs_sha256", "context_id",
                    "actions", "obligations"}, where="receipt")
    _require(receipt["schema"] == RECEIPT_SCHEMA, "unknown receipt schema")
    _expect(receipt["plan_sha256"], canonical_sha256(plan), "plan hash")
    _check_inputs(plan, receipt["inputs"])
    _expect(receipt["inputs_sha256"], canonical_sha256(receipt["inputs"]), "input hash")
    if expected_inputs is not None:
        _expect(receipt["inputs"], expected_inputs, "externally planned inputs")
    _name(receipt["context_id"], "context id")
    if expected_context_id is not None:
        _expect(receipt["context_id"], expected_context_id, "externally planned context")
    _require(type(receipt["actions"]) is list, "receipt actions must be an array")
    _require(type(receipt["obligations"]) is list, "receipt obligations must be an array")
    batches = []
    for index, item in enumerate(plan["actions"]):
        group = "parallel:" + str(index) if "parallel" in item else None
        batches.append((group, item["parallel"] if group else [item]))
    action_count = sum(len(batch) for _, batch in batches)
    _require(len(receipt["actions"]) == action_count, "missing or extra action records")
    _require(len(receipt["obligations"]) == len(plan["obligations"]),
             "missing or extra obligation records")
    inputs, completed = receipt["inputs"], {}
    cursor = 0
    all_events = []
    previous_end = 0
    for group, batch in batches:
        records = receipt["actions"][cursor:cursor + len(batch)]
        starts, ends = [], []
        for declared, record in zip(batch, records):
            _keys(record, ACTION_KEYS, where="action record")
            identity = declared["id"]
            _expect(record["id"], identity, "action identity/order")
            _expect(record["operation"], declared["operation"], identity + " operation")
            _expect(record["context_id"], receipt["context_id"], identity + " context")
            _expect(record["group"], group, identity + " group")
            for name in ("start_event", "end_event"):
                _require(type(record[name]) is int and record[name] > 0,
                         identity + ": invalid event ordinal")
            _require(record["start_event"] < record["end_event"], identity + ": reversed event order")
            starts.append(record["start_event"])
            ends.append(record["end_event"])
            guard = _boolean(declared.get("when", {"literal": True}), inputs, completed, {})
            _expect(record["guard"], guard.as_dict(), identity + " guard")
            consumed = guard.dependencies or []
            skipped_reason = None
            argument_evaluations = {}
            resolved = None
            if guard.state != "TRUE":
                skipped_reason = "guard:" + guard.state
            else:
                evaluated = {}
                for name in sorted(declared["arguments"]):
                    evaluated[name] = evaluate_expression(declared["arguments"][name], inputs, completed, {})
                argument_evaluations = {name: value.as_dict() for name, value in evaluated.items()}
                consumed = _dependencies(consumed, *(item.dependencies or [] for item in evaluated.values()))
                failed = next(((name, value) for name, value in evaluated.items() if value.state != "VALUE"), None)
                if failed is not None:
                    skipped_reason = "argument:" + failed[0] + ":" + failed[1].state
                else:
                    resolved = {name: value.value for name, value in evaluated.items()}
            _expect(record["argument_evaluations"], argument_evaluations, identity + " argument evaluations")
            _expect(record["arguments"], resolved, identity + " resolved arguments")
            _expect(record["consumed_references"], consumed, identity + " consumed references")
            if skipped_reason is not None:
                _expect(record["status"], "SKIPPED", identity + " skipped status")
                _expect(record["reason"], skipped_reason, identity + " skipped reason")
                _expect(record["value"], None, identity + " skipped value")
                _expect(record["evidence"], [], identity + " skipped evidence")
            else:
                _require(type(record["status"]) is str and record["status"] in {"OK", "UNAVAILABLE"},
                         identity + ": invented skip or status")
                _require(record["reason"] is None or type(record["reason"]) is str,
                         identity + ": malformed adapter reason")
                _require(type(record["evidence"]) is list, identity + ": malformed evidence list")
        _require(min(starts) > previous_end, "operations overlap outside their declared parallel group")
        if group is not None:
            _require(max(starts) < min(ends), "parallel completion precedes a sibling start")
        previous_end = max(ends)
        all_events.extend(starts + ends)
        completed.update({record["id"]: record for record in records})
        cursor += len(batch)
    _require(sorted(all_events) == list(range(1, 2 * action_count + 1)),
             "event ordinals are missing, duplicated, or outside the execution")
    judged = {}
    for declared, record in zip(plan["obligations"], receipt["obligations"]):
        _keys(record, OBLIGATION_KEYS, where="obligation record")
        identity = declared["id"]
        for field in ("id", "stage", "clause"):
            _expect(record[field], declared[field], identity + " " + field)
        gates = []
        for gate in declared["requires"]:
            evaluated = _boolean(gate["expr"], inputs, completed, judged).as_dict()
            gates.append({"name": gate["name"], **evaluated})
        consumed = _dependencies(*(gate["dependencies"] for gate in gates))
        failed = next((gate for gate in gates if gate["state"] != "TRUE"), None)
        predicate = None
        if failed is not None:
            verdict, reason = "INADMISSIBLE", "gate:" + failed["name"] + ":" + failed["state"]
            failed_gate = failed["name"]
        else:
            predicate = _boolean(declared["predicate"], inputs, completed, judged).as_dict()
            consumed = _dependencies(consumed, predicate["dependencies"])
            failed_gate = None
            if predicate["state"] in {"UNKNOWN", "ERROR"}:
                verdict, reason = "INADMISSIBLE", "predicate:" + predicate["state"]
            elif predicate["state"] == "TRUE":
                verdict, reason = "SATISFIED", "predicate-true"
            else:
                verdict, reason = "INCONSISTENT", "predicate-false"
        expected = {"id": identity, "stage": declared["stage"], "clause": declared["clause"],
                    "gates": gates, "predicate": predicate, "verdict": verdict,
                    "reason": reason, "failed_gate": failed_gate,
                    "consumed_references": consumed}
        _expect(record, expected, identity + " obligation")
        judged[identity] = expected
    return {
        "schema": "toolchainmark-receipt-receiver-v1", "verdict": "PASS",
        "plan_id": plan["id"], "plan_sha256": receipt["plan_sha256"],
        "inputs_sha256": receipt["inputs_sha256"], "context_id": receipt["context_id"],
        "actions": action_count, "obligations": len(judged), "event_ordinals": len(all_events),
        "action_status_counts": dict(sorted(Counter(a["status"] for a in receipt["actions"]).items())),
        "verdict_counts": dict(sorted(Counter(o["verdict"] for o in judged.values()).items())),
        "external_inputs_checked": expected_inputs is not None,
        "external_context_checked": expected_context_id is not None,
        "checks": {"plan_schema_and_reference_order": True, "plan_and_input_hashes": True,
                   "exact_action_frame": True, "guards_and_arguments": True,
                   "consumed_dependencies": True, "event_order_and_parallel_groups": True,
                   "independent_stage_judgments": True},
        "scope": "Independent record/plan correspondence only; no native re-execution, adapter truth attestation, or atomic decoder-read guarantee.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--context-id")
    args = parser.parse_args(argv)
    try:
        report = verify_receipt(load_json(args.plan), load_json(args.receipt),
                                expected_inputs=load_json(args.inputs) if args.inputs else None,
                                expected_context_id=args.context_id)
    except (InvalidRecord, RecursionError) as error:
        print(json.dumps({"schema": "toolchainmark-receipt-receiver-v1", "verdict": "INVALID_RECORD",
                          "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
