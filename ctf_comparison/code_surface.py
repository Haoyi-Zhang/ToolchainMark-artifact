"""Auditable source-surface counts, not estimates of engineering effort."""

import hashlib
from pathlib import Path


ARTIFACT = Path(__file__).resolve().parents[1]


def measure_sources():
    groups = {
        "executor": [ARTIFACT / "contract_runtime/core.py", ARTIFACT / "contract_runtime/__init__.py"],
        "independent_record_receiver": [ARTIFACT / "contract_runtime/receiver.py"],
        "native_adapters": sorted((ARTIFACT / "declarative_study").glob("*adapter.py")) +
                           [ARTIFACT / "external_sandmark/adapter.py", ARTIFACT / "external_sandmark/SandmarkBridge.java"],
        "native_evidence_and_driver": [ARTIFACT / "declarative_study/native_io.py", ARTIFACT / "declarative_study/run.py",
                                       ARTIFACT / "declarative_study/verify.py", ARTIFACT / "external_sandmark/run_study.py",
                                       ARTIFACT / "external_sandmark/verify_study.py"],
        "ctf_custom_judgment": [ARTIFACT / "ctf_comparison/expressions.py", ARTIFACT / "ctf_comparison/oracle.py"],
        "ctf_acquisition_freeze_and_reporting": [ARTIFACT / "ctf_comparison/run.py", ARTIFACT / "ctf_comparison/code_surface.py"],
    }
    files = []
    for role, paths in groups.items():
        for path in paths:
            if not path.is_file():
                continue
            raw = path.read_bytes()
            lines = raw.decode("utf-8").splitlines()
            files.append({"role": role, "path": path.relative_to(ARTIFACT).as_posix(), "bytes": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest(), "physical_lines": len(lines),
                          "nonblank_noncomment_lines": sum(bool(line.strip()) and not line.lstrip().startswith(("#", "//")) for line in lines)})
    return {"schema": "toolchainmark-source-surface-v1", "files": files,
            "counting_rule": "Physical lines after excluding blank and full-line # or // comments; docstrings, block comments, and continuation lines count.",
            "scope": "Implementation surface only. These counts do not measure person-hours, difficulty, maintenance, or a causal productivity advantage.",
            "excluded": ["tests", "vendored CTF library", "retained native observation data", "JSON plans"],
            "comparison_note": "CTF consumes already acquired shared observations. The common native acquisition cost is not credited as a CTF saving."}


def measure_plan(plan):
    actions = [a for block in plan["actions"] for a in (block["parallel"] if "parallel" in block else [block])]
    return {"id": plan["id"], "inputs": dict(plan["inputs"]), "actions": len(actions),
            "operation_names": sorted({a["operation"] for a in actions}),
            "explicit_action_guards": sum("when" in a for a in actions),
            "parallel_groups": sum("parallel" in block for block in plan["actions"]),
            "obligations": len(plan["obligations"]),
            "required_gate_expressions": sum(len(o["requires"]) for o in plan["obligations"]),
            "predicate_expressions": len(plan["obligations"])}
