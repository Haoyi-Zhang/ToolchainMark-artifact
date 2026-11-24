"""Real CTF extension points for exact, shared-observation contract judgments.

No causal model, effect size, confidence interval, or sampling inference is
claimed. The custom estimator supplies an exact observation vector; the custom
effect applies the declared predicate. CTF itself performs PASS/FAIL dispatch
and maps our explicit evidence exception through its INESTIMABLE branch.
"""

import copy
import hashlib
import importlib
import json
from pathlib import Path
import sys

from .expressions import BaselineInputError, boolean

HERE = Path(__file__).resolve().parent
VENDOR = HERE / "vendor"
sys.path.insert(0, str(VENDOR))

import pandas as pd
from causal_testing.estimation.abstract_estimator import Estimator
from causal_testing.estimation.effect_estimate import EffectEstimate
from causal_testing.testing.causal_effect import CausalEffect
from causal_testing.testing.causal_test_case import CausalTestCase
from causal_testing.testing.causal_test_result import TestOutcome


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def runtime_identity():
    """Bind the actual imported CTF classes to the unmodified pinned sources."""
    upstream = json.loads((HERE / "UPSTREAM.json").read_text())
    checked = []
    for item in upstream["files"]:
        path = HERE / item["path"]
        raw = path.read_bytes()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise BaselineInputError(f"vendored source changed: {item['path']}")
    for cls in (Estimator, EffectEstimate, CausalEffect, CausalTestCase, TestOutcome):
        # The Enum is built by Enum(), so its defining module is still the
        # official causal_test_result module, not the standard enum module.
        module_name = "causal_testing.testing.causal_test_result" if cls is TestOutcome else cls.__module__
        module = importlib.import_module(module_name)
        origin = Path(module.__file__).resolve()
        try:
            relative = origin.relative_to(HERE).as_posix()
        except ValueError as exc:
            raise BaselineInputError("CTF import did not come from the pinned vendor directory") from exc
        if not relative.startswith("vendor/causal_testing/"):
            raise BaselineInputError("unexpected CTF module origin")
        checked.append({"class": cls.__name__, "module": module_name, "source": relative,
                        "sha256": hashlib.sha256(origin.read_bytes()).hexdigest()})
    return {"repository": upstream["repository"], "commit": upstream["commit"],
            "archive_sha256": upstream["archive_sha256"], "vendored_files_checked": len(upstream["files"]),
            "entry_point": "causal_testing.testing.causal_test_case.CausalTestCase.execute_test",
            "classes": checked, "unmodified_upstream": True}


class EvidenceNotApplicable(ValueError):
    """A declared gate or predicate lacks a usable exact observation."""


class ExactObservationEstimator(Estimator):
    """Supply one observed trace without estimating a population effect."""

    def __init__(self, requirements):
        self.requirements = copy.deepcopy(requirements)
        self.calls = 0
        self.gate_evaluations = []
        self.inestimable_reason = None
        super().__init__(treatment_variable="declared_action_trace", outcome_variable="observed_stage_contract")

    def add_modelling_assumptions(self):
        self.modelling_assumptions.append(
            "Exact supplied observations only; no causal identification, statistical effect estimate, or generalization."
        )

    def estimate_exact_observations(self, df):
        self.calls += 1
        if len(df) != 1 or list(df.columns) != ["inputs", "actions", "prior_verdicts"]:
            raise BaselineInputError("exact-data extension requires one three-component observation row")
        row = df.iloc[0]
        inputs, actions, prior = row["inputs"], row["actions"], row["prior_verdicts"]
        self.gate_evaluations = [
            {"name": requirement["name"], **boolean(requirement["expr"], inputs, actions, prior).to_dict()}
            for requirement in self.requirements
        ]
        for gate in self.gate_evaluations:
            if gate["state"] != "TRUE":
                self.inestimable_reason = f"gate:{gate['name']}:{gate['state']}"
                raise EvidenceNotApplicable(self.inestimable_reason)
        vector = pd.Series({"inputs": inputs, "actions": actions, "prior_verdicts": prior}, dtype=object)
        return EffectEstimate(effect_measure="exact_observations", effect_estimate=vector)


class DeclaredPredicate(CausalEffect):
    """Apply an exact declared relation to CTF's returned observation vector."""

    def __init__(self, predicate):
        super().__init__(effect_type="exact-observation-contract")
        self.predicate = copy.deepcopy(predicate)
        self.calls = 0
        self.evaluation = None
        self.inestimable_reason = None

    def apply(self, effect_estimate):
        self.calls += 1
        if effect_estimate.effect_measure != "exact_observations":
            raise BaselineInputError("unexpected effect measure")
        observation = effect_estimate.effect_estimate
        self.evaluation = boolean(self.predicate, observation["inputs"], observation["actions"], observation["prior_verdicts"])
        if self.evaluation.state in ("UNKNOWN", "ERROR"):
            self.inestimable_reason = f"predicate:{self.evaluation.state}"
            raise EvidenceNotApplicable(self.inestimable_reason)
        return self.evaluation.value


def observation_projection(receipt):
    """Discard every ToolchainMark judgment, gate, guard, and argument evaluation.

    These are shared operation observations, not an independently acquired trace.
    CTF computes earlier obligation verdicts itself, in declared order.
    """
    actions = {}
    for raw in receipt["actions"]:
        if raw["id"] in actions or raw["status"] not in ("OK", "UNAVAILABLE", "SKIPPED"):
            raise BaselineInputError("duplicate action identifier or unrecognized operational status")
        actions[raw["id"]] = {"status": raw["status"], "value": copy.deepcopy(raw["value"])}
    return {"inputs": copy.deepcopy(receipt["inputs"]), "actions": actions}


def judge(plan, observation):
    """Execute real CausalTestCases; no framework result enters this function."""
    results, prior = [], {}
    outcome_map = {"PASS": "SATISFIED", "FAIL": "INCONSISTENT", "INESTIMABLE": "INADMISSIBLE"}
    for obligation in plan["obligations"]:
        estimator = ExactObservationEstimator(obligation["requires"])
        effect = DeclaredPredicate(obligation["predicate"])
        case = CausalTestCase(expected_causal_effect=effect, effect_measure="exact_observations",
                              estimator=estimator, name=obligation["id"])
        data = {"inputs": copy.deepcopy(observation["inputs"]), "actions": copy.deepcopy(observation["actions"]),
                "prior_verdicts": copy.deepcopy(prior)}
        frame = pd.DataFrame([data], columns=["inputs", "actions", "prior_verdicts"])
        case.execute_test(df=frame, adequacy=False, suppress_estimation_errors=True)
        actual = case.result
        if actual is None or actual.outcome.name not in outcome_map:
            raise BaselineInputError("official CTF entry point did not produce a recognized result")
        if actual.outcome == TestOutcome.INESTIMABLE:
            expected_reason = estimator.inestimable_reason or effect.inestimable_reason
            if expected_reason is None or actual.error_message != expected_reason:
                raise BaselineInputError(f"unexpected exception suppressed by CTF: {actual.error_message}")
            reason = expected_reason
        else:
            reason = "predicate-true" if actual.passed else "predicate-false"
        official_result = actual.to_dict()
        # The complete observation vector is already bound once in the case
        # record. Bind CTF's actual returned vector by hash instead of copying it
        # into each stage record. This is an explicit serialization projection.
        if official_result["effect_estimate"]:
            estimate = official_result["effect_estimate"]
            official_result["effect_estimate"] = {
                "effect_measure": estimate["effect_measure"],
                "components": sorted(estimate["effect_estimate"]),
                "content_sha256": digest(estimate["effect_estimate"]),
            }
        mapped = outcome_map[actual.outcome.name]
        results.append({"id": obligation["id"], "stage": obligation["stage"], "clause": obligation["clause"],
                        "ctf_result": official_result, "mapped_verdict": mapped, "reason": reason,
                        "gates": estimator.gate_evaluations,
                        "predicate": None if effect.evaluation is None else effect.evaluation.to_dict(),
                        "estimator_calls": estimator.calls, "oracle_calls": effect.calls,
                        "dataframe_sha256": digest(data)})
        if obligation["id"] in prior:
            raise BaselineInputError("duplicate obligation identifier")
        prior[obligation["id"]] = mapped
    return results


def compare_receipt(plan, receipt):
    observation = observation_projection(receipt)
    results = judge(plan, observation)
    # Read framework judgments only after the complete CTF computation.
    recorded = receipt["obligations"]
    if [row["id"] for row in recorded] != [row["id"] for row in results]:
        raise BaselineInputError("framework obligation frame differs from the plan")
    for result, reference in zip(results, recorded):
        result["framework_verdict"] = reference["verdict"]
        result["agreement"] = result["mapped_verdict"] == reference["verdict"]
    return {"observation_sha256": digest(observation), "results": results}
