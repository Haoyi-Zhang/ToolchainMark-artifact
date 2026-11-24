#!/usr/bin/env python3
"""Materialize the reviewable, data-only SandMark frame and contract."""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def lit(value): return {"literal": value}
def inp(name): return {"input": name}
def ref(step, *path): return {"ref": step, "path": list(path)}
def op(name, *args): return {"op": name, "args": list(args)}
def avail(step): return {"available": step}
def verdict(step): return op("eq", {"verdict": step}, lit("SATISFIED"))


def action(name, operation, arguments, when=None):
    result = {"id": name, "operation": "sandmark." + operation, "arguments": arguments}
    if when is not None:
        result["when"] = when
    return result


def obligation(name, stage, clause, requirements, predicate):
    return {"id": name, "stage": stage, "clause": clause,
            "requires": [{"name": label, "expr": expression} for label, expression in requirements],
            "predicate": predicate}


def make_plan():
    png = op("or", op("not", inp("requires_png")), op("lt", lit(0), ref("source", "png_count")))
    extraction = {"algorithm": inp("algorithm"), "payload": inp("payload"), "key": inp("key"),
                  "seed": inp("seed"), "extractor_mode": inp("extractor_mode")}
    actions = [action("source", "prepare", {"host": inp("host")}),
               {"parallel": [
                   action("source-host", "host", {"host": inp("host"), "artifact": ref("source", "artifact", "path")}),
                   action("embed", "embed", {"algorithm": inp("algorithm"), "artifact": ref("source", "artifact", "path"),
                                                "payload": inp("payload"), "key": inp("key"), "seed": inp("seed")}, png)]}]
    def extraction_action(name, source):
        return action(name, "extract", {**extraction, "artifact": ref(source, "artifact", "path"),
                                        "original_file": ref(source, "original_file"),
                                        "key_file": ref(source, "key_file")}, avail(source))
    def transform_action(name, kind):
        return action(name, "transform", {"kind": lit(kind), "artifact": ref("embed", "artifact", "path"),
                                           "original_file": ref("embed", "original_file"),
                                           "key_file": ref("embed", "key_file")}, avail("embed"))
    actions.append({"parallel": [extraction_action("source-extract", "embed"),
                                 action("embedded-host", "host", {"host": inp("host"), "artifact": ref("embed", "artifact", "path")}, avail("embed"))]})
    actions.append({"parallel": [transform_action("relocate", "relocation"),
                                 transform_action("repack", "entry-identical-repack")]})
    actions.append({"parallel": [extraction_action("relocated-extract", "relocate"),
                                 extraction_action("repacked-extract", "repack")]})
    actions.append({"parallel": [action("relocated-host", "host", {"host": inp("host"), "artifact": ref("relocate", "artifact", "path")}, avail("relocate")),
                                 action("repacked-host", "host", {"host": inp("host"), "artifact": ref("repack", "artifact", "path")}, avail("repack"))]})
    def extraction_premises(step):
        return [("extractor returned", avail(step)),
                ("target endpoint bytes equal", op("eq", ref(step, "artifact_before", "sha256"), ref(step, "artifact_after", "sha256"))),
                ("auxiliary endpoint bytes equal", op("eq", ref(step, "auxiliary_before"), ref(step, "auxiliary_after")))]
    obligations = [obligation("identity", "source", "Requested payload belongs to the native candidate result on the original marked artifact.",
                              [("source acquired", avail("source")), ("documented PNG carrier present when required", png),
                               ("embedding returned an artifact", avail("embed")), *extraction_premises("source-extract")],
                              op("contains", ref("source-extract", "candidates"), inp("payload")))]
    def host_obligation(name, step):
        return obligation(name, "host", "Three declared application tasks preserve stdout, stderr, exit status and generated file bytes.",
                          [("baseline host observed", avail("source-host")),
                           ("baseline tasks completed successfully", op("eq", ref("source-host", "returncodes"), lit([0, 0, 0]))),
                           ("changed host observed", avail(step))],
                          op("eq", ref("source-host", "tasks"), ref(step, "tasks")))
    obligations.append(host_obligation("embedding-host", "embedded-host"))
    for transform, extraction_step, host_step, name in [
        ("relocate", "relocated-extract", "relocated-host", "relocation"),
        ("repack", "repacked-extract", "repacked-host", "repack")]:
        predicate = (op("eq", ref(transform, "source", "sha256"), ref(transform, "artifact", "sha256"))
                     if transform == "relocate" else
                     op("and", op("eq", ref(transform, "source", "entries"), ref(transform, "artifact", "entries")),
                        op("ne", ref(transform, "source", "sha256"), ref(transform, "artifact", "sha256"))))
        obligations.append(obligation(name + "-transformation", "transformation",
                                      "Relocation preserves all archive bytes; repacking changes the archive representation while preserving every named entry byte.",
                                      [("embedding returned", avail("embed")), ("transformation observed", avail(transform))], predicate))
        obligations.append(obligation(name + "-recovery", "extraction",
                                      "The requested payload remains in the native candidate result under the declared preservation transformation.",
                                      [("source payload recovered", verdict("identity")),
                                       ("transformation postcondition holds", verdict(name + "-transformation")),
                                       *extraction_premises(extraction_step)],
                                      op("contains", ref(extraction_step, "candidates"), inp("payload"))))
        obligations.append(host_obligation(name + "-host", host_step))
    return {"schema": "toolchainmark-contract-v1", "id": "sandmark-static-preservation-v1",
            "inputs": {"algorithm": "string", "host": "string", "payload": "string", "key": "string",
                       "seed": "integer", "extractor_mode": "string", "requires_png": "boolean"},
            "actions": actions, "obligations": obligations}


def make_frame():
    algorithms = json.loads((HERE / "algorithm-contracts.json").read_text())["algorithms"]
    rows = []
    for repeat in [1, 2]:
        for algorithm in algorithms:
            for host in ["antlr-2.7.7", "official-ttt"]:
                for payload in ["7", "42", "1234"]:
                    name = algorithm["algorithm"]
                    rows.append({"id": f"case-{len(rows)+1:04d}", "repeat": repeat,
                                 "inputs": {"algorithm": name, "host": host, "payload": payload,
                                            "key": payload if name == "Stern" else "17",
                                            "seed": repeat - 1,
                                            "extractor_mode": "candidate_verifier" if name == "Stern" else "candidate_set",
                                            "requires_png": name == "Steganography"}})
    return {"schema": "sandmark-study-frame-v1", "configurations": rows,
            "algorithm_count": 13, "host_count": 2, "payload_count": 3, "repetitions": 2,
            "expected_configurations": 156,
            "host_roles": {"antlr-2.7.7": "external grammar-generator application",
                           "official-ttt": "original SandMark command-line calibration sample"},
            "timeouts_seconds": {"embed": 30, "extract": 30, "host_task": 15},
            "limits": {"java_heap": "512m", "extractor_candidates": 10000},
            "repetition_seed_policy": "SandMark shared PRNG is seeded with 0 then 1; no universal determinism claim.",
            "applicability_policy": "All 156 configurations stay in the frame. Missing PNG carrier prevents only embedding and its dependents. Tool exceptions, timeouts and unavailable observations remain distinct from source inconsistencies.",
            "transformations": ["identity", "byte-identical relocation with original/key auxiliaries", "entry-identical ZIP repacking with original/key auxiliaries"],
            "exclusions": ["No dynamic SandMark algorithms", "No arbitrary obfuscation or adversarial attack", "No universal key-rejection claim", "No real-world prevalence estimate"]}


if __name__ == "__main__":
    (HERE / "plan.json").write_text(json.dumps(make_plan(), indent=2) + "\n")
    (HERE / "study-frame.json").write_text(json.dumps(make_frame(), indent=2) + "\n")
