"""Tests of the actual pinned CTF entry point and independent expression code."""

import copy
import unittest

from ctf_comparison.expressions import BaselineInputError, boolean, evaluate
from ctf_comparison.oracle import compare_receipt, judge, observation_projection, runtime_identity


def literal(value):
    return {"literal": value}


def obligation(identifier="recover", requirements=None, predicate=None):
    return {"id": identifier, "stage": "extraction", "clause": "payload", "requires": requirements or [],
            "predicate": predicate if predicate is not None else {"op": "eq", "args": [
                {"ref": "read", "path": ["payload"]}, {"input": "expected"}]}}


def fixture():
    plan = {"obligations": [obligation()]}
    receipt = {"inputs": {"expected": "ab"}, "actions": [{"id": "read", "status": "OK", "value": {"payload": "ab"}}],
               "obligations": [{"id": "recover", "verdict": "SATISFIED"}]}
    return plan, receipt


class ActualCTFTests(unittest.TestCase):
    def test_real_pinned_origins(self):
        identity = runtime_identity()
        self.assertEqual(identity["vendored_files_checked"], 37)
        self.assertEqual(identity["commit"], "7ab4da9fc60ea9ee43b48963a5953fca3840c75d")
        self.assertTrue(all(row["source"].startswith("vendor/causal_testing/") for row in identity["classes"]))

    def test_official_pass_and_false_predicate_fail(self):
        plan, receipt = fixture()
        passing = compare_receipt(plan, receipt)["results"][0]
        self.assertEqual(passing["ctf_result"]["outcome"], "PASS")
        self.assertEqual((passing["estimator_calls"], passing["oracle_calls"]), (1, 1))
        receipt["actions"][0]["value"]["payload"] = "cd"
        failing = compare_receipt(plan, receipt)["results"][0]
        self.assertEqual(failing["ctf_result"]["outcome"], "FAIL")
        self.assertFalse(failing["agreement"])

    def test_failed_gate_uses_official_inestimable_without_oracle_call(self):
        plan, receipt = fixture()
        plan["obligations"][0]["requires"] = [{"name": "source-valid", "expr": literal(False)}]
        result = compare_receipt(plan, receipt)["results"][0]
        self.assertEqual(result["ctf_result"]["outcome"], "INESTIMABLE")
        self.assertEqual(result["ctf_result"]["error_message"], "gate:source-valid:FALSE")
        self.assertEqual((result["estimator_calls"], result["oracle_calls"]), (1, 0))

    def test_tool_unavailable_is_not_domain_rejection(self):
        plan, receipt = fixture()
        receipt["actions"][0]["status"] = "UNAVAILABLE"
        result = compare_receipt(plan, receipt)["results"][0]
        self.assertEqual(result["ctf_result"]["outcome"], "INESTIMABLE")
        self.assertEqual(result["reason"], "predicate:UNKNOWN")
        self.assertEqual(result["predicate"]["reason"], "action-unavailable:read")
        receipt["actions"][0].update(status="OK", value={"kind": "wrong-key"})
        plan["obligations"][0]["predicate"] = {"op": "eq", "args": [{"ref": "read", "path": ["kind"]}, literal("wrong-key")]}
        self.assertEqual(compare_receipt(plan, receipt)["results"][0]["ctf_result"]["outcome"], "PASS")

    def test_unknown_and_error_gates_have_distinct_diagnostics(self):
        plan, receipt = fixture()
        plan["obligations"][0]["requires"] = [
            {"name": "missing", "expr": {"ref": "read", "path": ["absent"]}},
            {"name": "bad-type", "expr": literal("false")},
        ]
        result = compare_receipt(plan, receipt)["results"][0]
        self.assertEqual([g["state"] for g in result["gates"]], ["UNKNOWN", "ERROR"])
        self.assertEqual(result["reason"], "gate:missing:UNKNOWN")
        self.assertEqual(result["oracle_calls"], 0)

    def test_framework_gates_and_judgments_do_not_enter_ctf(self):
        plan, receipt = fixture()
        original = judge(plan, observation_projection(receipt))
        receipt["obligations"][0].update(verdict="INADMISSIBLE", gates="corrupted", predicate="corrupted")
        receipt["actions"][0].update(guard="corrupted", consumed_references="corrupted", argument_evaluations="corrupted")
        self.assertEqual(judge(plan, observation_projection(receipt)), original)
        self.assertFalse(compare_receipt(plan, receipt)["results"][0]["agreement"])

    def test_prior_ctf_results_and_independent_obligations(self):
        plan, receipt = fixture()
        plan["obligations"] = [obligation("source", predicate=literal(False)),
            obligation("downstream", requirements=[{"name": "source-accepted", "expr": {"op": "eq", "args": [
                {"verdict": "source"}, literal("SATISFIED")]}}], predicate=literal(False)),
            obligation("independent", predicate=literal(True))]
        receipt["obligations"] = [{"id": name, "verdict": "SATISFIED"} for name in ("source", "downstream", "independent")]
        results = compare_receipt(plan, receipt)["results"]
        self.assertEqual([r["ctf_result"]["outcome"] for r in results], ["FAIL", "INESTIMABLE", "PASS"])
        self.assertEqual([r["oracle_calls"] for r in results], [1, 0, 1])

    def test_input_not_mutated(self):
        plan, receipt = fixture()
        before = copy.deepcopy((plan, receipt))
        compare_receipt(plan, receipt)
        self.assertEqual((plan, receipt), before)

    def test_malformed_input_is_not_scientific_inestimable(self):
        plan, receipt = fixture()
        plan["obligations"][0]["predicate"] = {"op": "undeclared", "args": [literal(True)]}
        with self.assertRaises(BaselineInputError):
            compare_receipt(plan, receipt)


class ExpressionTests(unittest.TestCase):
    def ev(self, name, args):
        return evaluate({"op": name, "args": [literal(arg) for arg in args]}, {}, {}, {})

    def test_type_sensitive_deep_equality(self):
        for pair in [(True, 1), (1, 1.0), ({"x": [1]}, {"x": [1.0]})]:
            self.assertFalse(self.ev("eq", list(pair)).value)
        self.assertTrue(self.ev("eq", [{"x": [False, 1]}, {"x": [False, 1]}]).value)

    def test_eager_unknown_and_error_priority(self):
        unknown = {"input": "row", "path": ["absent"]}
        expression = {"op": "and", "args": [literal(False), unknown]}
        self.assertEqual(boolean(expression, {"row": {}}, {}, {}).state, "UNKNOWN")
        expression["args"].append({"op": "not", "args": [literal(1)]})
        result = boolean(expression, {"row": {}}, {}, {})
        self.assertEqual((result.state, result.reason), ("ERROR", "type-error:not"))

    def test_sequence_and_membership_vocabulary(self):
        self.assertTrue(self.ev("all_equal", [[]]).value)
        self.assertTrue(self.ev("all_distinct", [[1, 1.0, True]]).value)
        self.assertFalse(self.ev("contains", [[1], True]).value)
        self.assertTrue(self.ev("in", ["b", "abc"]).value)
        self.assertEqual(self.ev("concat", [[1], [2, 3]]).value, [1, 2, 3])
        self.assertEqual(self.ev("concat_hex", ["ab00", "", "01"]).value, "ab0001")
        self.assertEqual(self.ev("concat_hex", ["Ab"]).state, "ERROR")
        self.assertEqual(self.ev("len", [{"a": 1}]).value, 1)

    def test_bool_numeric_and_path_boundaries(self):
        self.assertEqual(self.ev("lt", [True, 1]).state, "ERROR")
        self.assertTrue(self.ev("le", [1, 1.0]).value)
        self.assertEqual(boolean(literal(1), {}, {}, {}).state, "ERROR")
        with self.assertRaises(BaselineInputError):
            evaluate({"input": "row", "path": [True]}, {"row": [0, 1]}, {}, {})


if __name__ == "__main__":
    unittest.main()
