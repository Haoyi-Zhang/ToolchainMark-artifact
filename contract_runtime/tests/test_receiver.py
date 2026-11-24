"""Independent receipts, semantic boundaries, and corrupt-record controls.

The valid fixtures below are written directly from the protocol.  They are not
created with the executor or with the receiver's expression evaluator.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from contract_runtime.receiver import (InvalidRecord, canonical_sha256,
                                       evaluate_expression, load_json,
                                       validate_plan, verify_receipt)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def expression(state, value=None, dependencies=(), reason=None):
    return {"state": state, "value": value, "reason": reason,
            "dependencies": list(dependencies)}


def fixture(enabled=True):
    plan = {
        "schema": "toolchainmark-contract-v1", "id": "receiver-handwritten-pair",
        "inputs": {"expected": "string", "enabled": "boolean"},
        "actions": [
            {"id": "a", "operation": "observe",
             "arguments": {"payload": {"input": "expected"}}},
            {"id": "b", "operation": "copy", "when": {"input": "enabled"},
             "arguments": {"payload": {"ref": "a", "path": ["payload"]}}},
        ],
        "obligations": [
            {"id": "source", "stage": "source", "clause": "literal source payload",
             "requires": [{"name": "source_available", "expr": {"available": "a"}}],
             "predicate": {"op": "eq", "args": [
                 {"ref": "a", "path": ["payload"]}, {"input": "expected"}]}},
            {"id": "preservation", "stage": "followup", "clause": "copy retains payload",
             "requires": [
                 {"name": "valid_source", "expr": {"op": "eq", "args": [
                     {"verdict": "source"}, {"literal": "SATISFIED"}]}},
                 {"name": "followup_available", "expr": {"available": "b"}},
             ],
             "predicate": {"op": "eq", "args": [
                 {"ref": "b", "path": ["payload"]}, {"ref": "a", "path": ["payload"]}]}},
        ],
    }
    inputs = {"expected": "AB", "enabled": enabled}
    first = {
        "id": "a", "operation": "observe", "arguments": {"payload": "AB"},
        "argument_evaluations": {"payload": expression("VALUE", "AB", ["input:expected"])},
        "context_id": "independent-fixture", "status": "OK", "reason": None,
        "value": {"payload": "AB"}, "evidence": [], "start_event": 1, "end_event": 2,
        "group": None, "guard": expression("TRUE", True),
        "consumed_references": ["input:expected"],
    }
    second = {
        "id": "b", "operation": "copy", "arguments": {"payload": "AB"} if enabled else None,
        "argument_evaluations": {"payload": expression("VALUE", "AB", ["action:a"])} if enabled else {},
        "context_id": "independent-fixture", "status": "OK" if enabled else "SKIPPED",
        "reason": None if enabled else "guard:FALSE", "value": {"payload": "AB"} if enabled else None,
        "evidence": [], "start_event": 3, "end_event": 4, "group": None,
        "guard": expression("TRUE" if enabled else "FALSE", enabled, ["input:enabled"]),
        "consumed_references": ["input:enabled", "action:a"] if enabled else ["input:enabled"],
    }
    source = {
        "id": "source", "stage": "source", "clause": "literal source payload",
        "gates": [{"name": "source_available", **expression("TRUE", True, ["action:a"])}],
        "predicate": expression("TRUE", True, ["action:a", "input:expected"]),
        "verdict": "SATISFIED", "reason": "predicate-true", "failed_gate": None,
        "consumed_references": ["action:a", "input:expected"],
    }
    preservation = {
        "id": "preservation", "stage": "followup", "clause": "copy retains payload",
        "gates": [
            {"name": "valid_source", **expression("TRUE", True, ["obligation:source"])},
            {"name": "followup_available", **expression("TRUE" if enabled else "FALSE", enabled, ["action:b"])},
        ],
        "predicate": expression("TRUE", True, ["action:b", "action:a"]) if enabled else None,
        "verdict": "SATISFIED" if enabled else "INADMISSIBLE",
        "reason": "predicate-true" if enabled else "gate:followup_available:FALSE",
        "failed_gate": None if enabled else "followup_available",
        "consumed_references": ["obligation:source", "action:b", "action:a"] if enabled else ["obligation:source", "action:b"],
    }
    receipt = {
        "schema": "toolchainmark-execution-v1", "plan_sha256": digest(plan),
        "inputs": inputs, "inputs_sha256": digest(inputs), "context_id": "independent-fixture",
        "actions": [first, second], "obligations": [source, preservation],
    }
    return plan, receipt


class ReceiverFrameTests(unittest.TestCase):
    def test_handwritten_valid_receipt_and_external_frame(self):
        plan, receipt = fixture()
        report = verify_receipt(plan, receipt, expected_inputs={"expected": "AB", "enabled": True},
                                expected_context_id="independent-fixture")
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["verdict_counts"], {"SATISFIED": 2})
        self.assertEqual(report["event_ordinals"], 4)

    def test_planned_skip_is_not_missing_record_or_satisfaction(self):
        plan, receipt = fixture(False)
        report = verify_receipt(plan, receipt)
        self.assertEqual(report["action_status_counts"], {"OK": 1, "SKIPPED": 1})
        self.assertEqual(report["verdict_counts"], {"INADMISSIBLE": 1, "SATISFIED": 1})

    def test_corrupt_record_dimensions_are_rejected(self):
        def mutate_path(receipt, path, value):
            node = receipt
            for part in path[:-1]:
                node = node[part]
            node[path[-1]] = value
        changes = [
            (["schema"], "wrong-schema"), (["plan_sha256"], "0" * 64),
            (["inputs_sha256"], "0" * 64), (["context_id"], "different-context"),
            (["actions", 0, "id"], "b"), (["actions", 0, "operation"], "hidden-read"),
            (["actions", 0, "arguments", "payload"], "CD"),
            (["actions", 0, "argument_evaluations", "payload", "value"], "CD"),
            (["actions", 0, "guard", "value"], False),
            (["actions", 0, "consumed_references"], []),
            (["actions", 1, "context_id"], "different-session"),
            (["actions", 1, "status"], ["OK"]),
            (["actions", 1, "start_event"], 2),
            (["actions", 1, "end_event"], 3),
            (["actions", 1, "group"], "parallel:0"),
            (["obligations", 1, "stage"], "invented-stage"),
            (["obligations", 1, "gates", 0, "dependencies"], []),
            (["obligations", 1, "predicate"], None),
            (["obligations", 1, "verdict"], "INCONSISTENT"),
            (["obligations", 1, "reason"], "predicate-false"),
        ]
        for path, value in changes:
            with self.subTest(path=path):
                plan, receipt = fixture()
                mutate_path(receipt, path, value)
                with self.assertRaises(InvalidRecord):
                    verify_receipt(plan, receipt)

    def test_missing_extra_and_reordered_actions(self):
        for choice in ("missing", "extra", "reordered"):
            with self.subTest(choice=choice):
                plan, receipt = fixture()
                if choice == "missing":
                    receipt["actions"].pop()
                elif choice == "extra":
                    receipt["actions"].append(copy.deepcopy(receipt["actions"][0]))
                else:
                    receipt["actions"].reverse()
                with self.assertRaises(InvalidRecord):
                    verify_receipt(plan, receipt)

    def test_extra_fields_and_obligations_rejected(self):
        for change in (lambda r: r.update(expected_verdict="SATISFIED"),
                       lambda r: r["actions"][0].update(admission=True),
                       lambda r: r["obligations"].append(copy.deepcopy(r["obligations"][0]))):
            plan, receipt = fixture()
            change(receipt)
            with self.assertRaises(InvalidRecord):
                verify_receipt(plan, receipt)

    def test_wrong_guard_cannot_fabricate_a_call(self):
        plan, receipt = fixture(False)
        receipt["actions"][1].update(status="OK", reason=None, value={"payload": "AB"})
        with self.assertRaises(InvalidRecord):
            verify_receipt(plan, receipt)

    def test_changed_output_requires_recomputed_judgment(self):
        plan, receipt = fixture()
        receipt["actions"][1]["value"]["payload"] = "CD"
        with self.assertRaises(InvalidRecord):
            verify_receipt(plan, receipt)
        receipt["obligations"][1].update(
            predicate=expression("FALSE", False, ["action:b", "action:a"]),
            verdict="INCONSISTENT", reason="predicate-false")
        self.assertEqual(verify_receipt(plan, receipt)["verdict_counts"],
                         {"INCONSISTENT": 1, "SATISFIED": 1})
        # This last receipt is internally consistent. Its empirical truth still
        # requires the separate command/byte receiver, not this interpreter.

    def test_external_inputs_cannot_be_replaced_with_another_valid_frame(self):
        plan, receipt = fixture(False)
        with self.assertRaises(InvalidRecord):
            verify_receipt(plan, receipt, expected_inputs={"expected": "AB", "enabled": True})
        with self.assertRaises(InvalidRecord):
            verify_receipt(plan, receipt, expected_context_id="other")

    def test_parallel_group_accepts_completion_order_but_requires_overlap(self):
        plan, receipt = fixture()
        plan["actions"][1]["arguments"] = {"payload": {"input": "expected"}}
        plan["actions"] = [{"parallel": plan["actions"]}]
        receipt["plan_sha256"] = digest(plan)
        a, b = receipt["actions"]
        a.update(start_event=1, end_event=4, group="parallel:0")
        b.update(start_event=2, end_event=3, group="parallel:0",
                 argument_evaluations={"payload": expression("VALUE", "AB", ["input:expected"])},
                 consumed_references=["input:enabled", "input:expected"])
        self.assertEqual(verify_receipt(plan, receipt)["verdict"], "PASS")
        a.update(start_event=1, end_event=2)
        b.update(start_event=3, end_event=4)
        with self.assertRaisesRegex(InvalidRecord, "sibling start"):
            verify_receipt(plan, receipt)

    def test_failed_obligation_does_not_cancel_an_independent_obligation(self):
        plan, receipt = fixture()
        plan["obligations"][0]["predicate"] = {"literal": False}
        source = receipt["obligations"][0]
        source.update(predicate=expression("FALSE", False), verdict="INCONSISTENT",
                      reason="predicate-false", consumed_references=["action:a"])
        dependent = receipt["obligations"][1]
        dependent["gates"][0] = {"name": "valid_source", **expression("FALSE", False, ["obligation:source"])}
        dependent.update(predicate=None, verdict="INADMISSIBLE", reason="gate:valid_source:FALSE",
                         failed_gate="valid_source", consumed_references=["obligation:source", "action:b"])
        plan["obligations"].append({"id": "independent", "stage": "host", "clause": "separate host clause",
                                    "requires": [], "predicate": {"literal": True}})
        receipt["obligations"].append({"id": "independent", "stage": "host", "clause": "separate host clause",
                                       "gates": [], "predicate": expression("TRUE", True),
                                       "verdict": "SATISFIED", "reason": "predicate-true",
                                       "failed_gate": None, "consumed_references": []})
        receipt["plan_sha256"] = digest(plan)
        self.assertEqual(verify_receipt(plan, receipt)["verdict_counts"],
                         {"INADMISSIBLE": 1, "INCONSISTENT": 1, "SATISFIED": 1})

    def test_argument_unknown_is_an_explicit_skip(self):
        plan, receipt = fixture()
        receipt["actions"][0].update(status="UNAVAILABLE", reason=None, value={"diagnostic": "not evidence"})
        receipt["actions"][1].update(
            status="SKIPPED", reason="argument:payload:UNKNOWN", arguments=None, value=None,
            argument_evaluations={"payload": expression("UNKNOWN", dependencies=["action:a"],
                                                        reason="action-unavailable:a")})
        first = receipt["obligations"][0]
        first.update(gates=[{"name": "source_available", **expression("FALSE", False, ["action:a"])}],
                     predicate=None, verdict="INADMISSIBLE", reason="gate:source_available:FALSE",
                     failed_gate="source_available", consumed_references=["action:a"])
        second = receipt["obligations"][1]
        second.update(gates=[{"name": "valid_source", **expression("FALSE", False, ["obligation:source"])},
                             {"name": "followup_available", **expression("FALSE", False, ["action:b"])}],
                      predicate=None, verdict="INADMISSIBLE", reason="gate:valid_source:FALSE",
                      failed_gate="valid_source", consumed_references=["obligation:source", "action:b"])
        self.assertEqual(verify_receipt(plan, receipt)["verdict_counts"], {"INADMISSIBLE": 2})


class ExpressionTests(unittest.TestCase):
    def evaluate(self, value, inputs=None, actions=None, obligations=None):
        return evaluate_expression(value, inputs or {}, actions or {}, obligations or {}).as_dict()

    def operator(self, name, *values):
        return self.evaluate({"op": name, "args": [{"literal": value} for value in values]})

    def test_equality_is_deep_and_type_sensitive(self):
        self.assertFalse(self.operator("eq", True, 1)["value"])
        self.assertFalse(self.operator("eq", 1, 1.0)["value"])
        self.assertFalse(self.operator("eq", {"a": [1]}, {"a": [True]})["value"])
        self.assertTrue(self.operator("eq", {"a": 1, "b": None}, {"b": None, "a": 1})["value"])

    def test_unknown_does_not_coerce_to_false_and_error_has_priority(self):
        missing = {"input": "x", "path": ["absent"]}
        expr = {"op": "and", "args": [{"literal": False}, missing]}
        self.assertEqual(self.evaluate(expr, {"x": {}}),
                         expression("UNKNOWN", dependencies=["input:x"], reason="input-path-missing:x"))
        expr["args"].append({"op": "len", "args": [{"literal": 7}]})
        self.assertEqual(self.evaluate(expr, {"x": {}}),
                         expression("ERROR", dependencies=["input:x"], reason="type-error:len"))

    def test_dependency_first_consumption_order_is_preserved(self):
        expr = {"op": "and", "args": [{"input": "b"}, {"input": "a"}, {"input": "b"}]}
        self.assertEqual(self.evaluate(expr, {"a": True, "b": True}),
                         expression("VALUE", True, ["input:b", "input:a"]))

    def test_canonical_hex_and_typed_concatenation(self):
        self.assertEqual(self.operator("concat_hex", "", "00ff", "ab")["value"], "00ffab")
        self.assertEqual(self.operator("concat_hex", "FF")["state"], "ERROR")
        self.assertEqual(self.operator("concat_hex", "a")["state"], "ERROR")
        self.assertEqual(self.operator("concat", [1], [True, None])["value"], [1, True, None])
        self.assertEqual(self.operator("concat", "a", ["b"])["state"], "ERROR")

    def test_membership_ordering_and_length_boundaries(self):
        self.assertFalse(self.operator("contains", [1], True)["value"])
        self.assertTrue(self.operator("in", "b", "abc")["value"])
        self.assertEqual(self.operator("contains", "abc", 1)["state"], "ERROR")
        self.assertTrue(self.operator("lt", 1, 1.5)["value"])
        self.assertEqual(self.operator("lt", True, 2)["state"], "ERROR")
        self.assertEqual(self.operator("len", {"a": 1})["value"], 1)
        self.assertTrue(self.operator("all_distinct", [1, True, 1.0])["value"])
        self.assertTrue(self.operator("all_equal", [])["value"])

    def test_unavailable_value_is_never_used_as_observation(self):
        actions = {"a": {"status": "UNAVAILABLE", "value": {"payload": "AB"}}}
        self.assertEqual(self.evaluate({"ref": "a", "path": ["payload"]}, actions=actions),
                         expression("UNKNOWN", dependencies=["action:a"], reason="action-unavailable:a"))
        self.assertEqual(self.evaluate({"available": "a"}, actions=actions),
                         expression("VALUE", False, ["action:a"]))


class PlanAndJSONTests(unittest.TestCase):
    def test_future_self_and_sibling_references_rejected(self):
        plan, _ = fixture()
        plan["actions"][0]["arguments"]["payload"] = {"ref": "b"}
        with self.assertRaises(InvalidRecord):
            validate_plan(plan)
        plan, _ = fixture()
        plan["actions"] = [{"parallel": plan["actions"]}]
        with self.assertRaises(InvalidRecord):
            validate_plan(plan)
        plan, _ = fixture()
        plan["obligations"][0]["predicate"] = {"verdict": "source"}
        with self.assertRaises(InvalidRecord):
            validate_plan(plan)

    def test_unknown_keys_and_wrong_arity_rejected(self):
        for expr in ({"literal": True, "op": "eq"}, {"op": "and", "args": []},
                     {"op": "eq", "args": [{"literal": True}]},
                     {"input": "expected", "path": [True]},
                     {"input": "unknown"}):
            plan, _ = fixture()
            plan["obligations"][0]["predicate"] = expr
            with self.assertRaises(InvalidRecord):
                validate_plan(plan)

    def test_exact_json_input_types_and_nonfinite_values(self):
        plan, receipt = fixture()
        plan["inputs"]["enabled"] = "integer"
        receipt["plan_sha256"] = digest(plan)
        with self.assertRaises(InvalidRecord):
            verify_receipt(plan, receipt)
        for value in (float("nan"), float("inf"), (1, 2), {1: "x"}):
            with self.subTest(value=str(value)):
                with self.assertRaises(InvalidRecord):
                    canonical_sha256(value)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(InvalidRecord):
            canonical_sha256(cycle)

    def test_json_reader_rejects_duplicate_and_nonfinite_json(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "record.json"
            for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}'):
                p.write_text(text)
                with self.assertRaises(InvalidRecord):
                    load_json(p)

    def test_validate_returns_an_independent_json_snapshot(self):
        plan, _ = fixture()
        validated = validate_plan(plan)
        plan["actions"][0]["operation"] = "changed"
        self.assertEqual(validated["actions"][0]["operation"], "observe")


class IndependentExecutorIntegrationTests(unittest.TestCase):
    """Exercise the public API; the receiver never imports the implementation."""

    def test_public_executor_receipts_match_independent_interpretation(self):
        from contract_runtime.core import execute

        class Adapter:
            operations = {"observe", "copy"}

            def __init__(self, mode="normal"):
                self.mode = mode

            def invoke(self, operation, arguments, *, step_id, context_id):
                if self.mode == "exception" and step_id == "a":
                    raise OSError("controlled unavailable observation")
                if self.mode == "malformed" and step_id == "a":
                    return {"status": "OK", "value": "incomplete protocol"}
                return {"status": "OK", "value": {"payload": arguments["payload"]},
                        "evidence": [], "reason": None}

        for mode in ("normal", "exception", "malformed"):
            for enabled in (True, False):
                with self.subTest(mode=mode, enabled=enabled):
                    plan, _ = fixture()
                    inputs = {"expected": "AB", "enabled": enabled}
                    receipt = execute(plan, inputs, Adapter(mode), context_id="integration")
                    report = verify_receipt(plan, receipt, expected_inputs=inputs,
                                            expected_context_id="integration")
                    self.assertEqual(report["verdict"], "PASS")
                    if mode != "normal":
                        self.assertEqual(report["verdict_counts"], {"INADMISSIBLE": 2})

    def test_public_parallel_and_runtime_error_receipts(self):
        from contract_runtime.core import execute

        class Adapter:
            operations = {"observe", "copy"}

            def invoke(self, operation, arguments, *, step_id, context_id):
                return {"status": "OK", "value": {"payload": arguments["payload"]},
                        "evidence": [], "reason": None}

        plan, _ = fixture()
        plan["actions"][1]["arguments"] = {"payload": {"input": "expected"}}
        plan["actions"] = [{"parallel": plan["actions"]}]
        plan["obligations"][0]["requires"].append({
            "name": "invalid_type_control", "expr": {"op": "and", "args": [
                {"input": "expected", "path": ["missing"]},
                {"op": "len", "args": [{"literal": 7}]},
            ]},
        })
        inputs = {"expected": "AB", "enabled": True}
        receipt = execute(plan, inputs, Adapter(), context_id="parallel-integration", max_workers=2)
        self.assertEqual(verify_receipt(plan, receipt)["verdict_counts"], {"INADMISSIBLE": 2})
        self.assertEqual(receipt["obligations"][0]["gates"][1]["reason"], "type-error:len")


if __name__ == "__main__":
    unittest.main()
