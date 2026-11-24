#!/usr/bin/env python3
"""Read-only verification of the QP diagnosis and separate confirmation frame."""
from __future__ import annotations

import argparse
from collections import Counter
import difflib
import hashlib
import json
from pathlib import Path
import sys
import zipfile

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.receiver import verify_receipt
from external_sandmark.verify_study import read, require, sha, safe, reobserve


def actual_command(root, stem):
    record = read(root / (stem + ".command.json"))
    for stream in ["stdout", "stderr"]:
        require(record[stream + "_hex"] == (root / (stem + "." + stream + ".bin")).read_bytes().hex(),
                "Diagnostic command stream does not match raw bytes")
    require(record["returncode"] == 0 and record["timeout"] is False, "Diagnostic command did not complete")
    require(record["stdin_hex"] == "", "Unexpected diagnostic stdin")
    return record


def traces(root, stem, tag):
    return [line.split("|", 2)[1:] for line in
            (root / (stem + ".stderr.bin")).read_text().splitlines()
            if line.startswith("QPTRACE " + tag + "|")]


def verify_diagnosis(root):
    require(root.name == "exploratory-01", "Unexpected diagnostic study")
    provenance = read(root / "diagnostic-provenance.json")
    require(provenance["kind"] == "post-hoc diagnosis, not a preregistered experiment", "Incorrect diagnostic status")
    for name, expected in provenance["source_bindings"].items():
        require(sha(safe(ARTIFACT, name)) == expected, "Diagnostic source changed")
    for name, expected in provenance["compiled_class_bindings"].items():
        require(sha(safe(root, name)) == expected, "Diagnostic compiled class changed")
    records = {stem: actual_command(root, stem) for stem in provenance["command_stems"]}
    require(len(records) == 9, "Incomplete diagnostic command set")
    for stem, record in records.items():
        require(hashlib.sha256(json.dumps(record["argv"], separators=(",", ":")).encode()).hexdigest()
                == provenance["command_argv_sha256"][stem], "Diagnostic native target changed")
    unmarked = (root / "unmarked-method-order.tsv").read_bytes()
    marked = (root / "marked-method-order.tsv").read_bytes()
    require(unmarked == marked, "Method traversal schedules differ")
    require(len(unmarked.splitlines()) == 2248, "Unexpected method population")
    comparison = read(root / "method-order-comparison.json")
    require(comparison["unmarked_methods"] == comparison["marked_methods"] == 2248 and
            comparison["all_row_differences"] == comparison["method_identity_order_differences"] == 0,
            "Method-order summary disagrees with bytes")
    formal = ARTIFACT / "results/external-sandmark/formal-01/cases/case-0045"
    require(sha(formal / "source/host.jar") == provenance["original_host_sha256"], "Original host changed")
    require(sha(formal / "embed/host_wm.jar") == provenance["formal_marked_sha256"], "Original marked output changed")
    entry_comparisons = 0
    with zipfile.ZipFile(formal / "embed/host_wm.jar") as original:
        for name in ["instrumented-host_wm.jar", "triple-host_wm.jar"]:
            with zipfile.ZipFile(root / name) as traced:
                require(set(original.namelist()) == set(traced.namelist()), "Instrumented output entry set changed")
                for entry in original.namelist():
                    require(original.read(entry) == traced.read(entry), "Instrumentation changed a target entry")
                    entry_comparisons += 1
    embedded = traces(root, "instrumented-embed", "EMBED")
    extracted = traces(root, "instrumented-extract", "EXTRACT")
    require([m for m, _ in embedded] == [m for m, _ in extracted], "Trace method order differs")
    e, x = "".join(b for _, b in embedded), "".join(b for _, b in extracted)
    payload = "".join(format(ord(c), "08b") for c in "1234")
    frame = "00010000" + payload
    require(len(e) == len(x) == 470 and len(embedded) == 206, "Unexpected diagnostic bit population")
    require(e == (frame + payload * 20)[:470], "Embedded trace does not encode the declared payload")
    require(traces(root, "instrumented-embed", "FRAME") == [[frame]], "Frame trace mismatch")
    require(traces(root, "instrumented-embed", "COUNT") == [["470", "40"]], "Capacity trace mismatch")
    require(traces(root, "instrumented-extract", "RECOVERED") == [[x]], "Recovered trace mismatch")
    require(x[:8] == "00000000" and x[8:40] == payload, "First decoded frame differs from diagnosis")
    require(traces(root, "instrumented-extract", "DECODED_LENGTH") == [["512", "462"]], "Decoder length evidence mismatch")
    first = next(i for i, (a, b) in enumerate(zip(e, x)) if a != b)
    require(first == 3, "First disagreement changed")
    expected_api = {"kind": "extract-return", "candidates": ["null"], "candidate_java_types": ["java.lang.String"]}
    for stem in ["instrumented", "triple"]:
        require(read(root / (stem + "-extract-api.json")) == expected_api, "Literal string recovery changed")
    method = "antlr.CppCodeGenerator.genInclude(Lantlr/TreeWalkerGrammar;)V"
    embed_line = ("QPTRACE EMBED_TRIPLE|" + method +
                  "|bit=1|nodes=7,9,10|before=1,1,1|after=1,2,2|edges=false,true,false")
    extract_line = ("QPTRACE EXTRACT_TRIPLE|" + method +
                    "|nodes=7,9,10|canonical=1,1,1|marked=1,2,2|edges=false,false,false")
    require(embed_line in (root / "triple-embed.stderr.bin").read_text().splitlines(), "Missing concrete encoding triple")
    require(extract_line in (root / "triple-extract.stderr.bin").read_text().splitlines(), "Missing concrete decoding triple")
    original_source = (HERE / "original-source/AssignLV.java").read_text()
    instrumented = (HERE / "instrumented/AssignLV.java").read_text()
    triple_source = (HERE / "instrumented-triples/AssignLV.java").read_text()
    for before, after, folder, old, new in [
        (original_source, instrumented, "instrumented", "original/AssignLV.java", "instrumented/AssignLV.java"),
        (instrumented, triple_source, "instrumented-triples", "instrumented/AssignLV.java", "instrumented-triples/AssignLV.java")]:
        actual = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=old, tofile=new))
        require(actual == (HERE / folder / "instrumentation.patch").read_text(), "Instrumentation patch differs from sources")
    return {"verdict": "PASS", "scope": "one post-hoc traced failing configuration",
            "native_commands": len(records), "method_order_rows_compared": 2248,
            "direct_instrumentation_entry_byte_comparisons": entry_comparisons,
            "embedded_bits": 470, "required_frame_bits": 40, "recovered_bits": 470,
            "changed_bit_positions": [i for i, (a, b) in enumerate(zip(e, x)) if a != b],
            "first_disagreement_bit_zero_based": first, "encoded_header": e[:8], "recovered_header": x[:8],
            "decoded_payload_length_bits": 512, "remaining_payload_bits": 462,
            "concrete_triple": {"node_indices": [7, 9, 10], "canonical_registers": [1, 1, 1],
                                "marked_registers": [1, 2, 2], "encoded_bit": "1", "decoded_bit": "0"},
            "candidates": ["null"]}


def verify_confirmation(run):
    protocol, plan, frame, start, summary, completion = [read(run / name) for name in
        ["protocol-freeze.json", "plan.json", "study-frame.json", "execution-start.json", "summary.json", "completion.json"]]
    require(start["kind"] == summary["kind"] == "post-diagnosis-confirmation", "Wrong study role")
    require(sha(run / "protocol-freeze.json") == start["protocol_freeze_sha256"] == completion["protocol_freeze_sha256"], "Freeze binding changed")
    require(sha(run / "summary.json") == completion["summary_sha256"], "Summary changed")
    require(sha(run / "plan.json") == protocol["plan_sha256"] == sha(HERE.parent / "plan.json"), "Plan is not the original shared plan")
    require(sha(run / "study-frame.json") == protocol["frame_sha256"] == sha(HERE / "confirmation-frame.json"), "Confirmation frame changed")
    require(protocol["source_bindings"] == completion["source_bindings_after_execution"], "Producer changed during confirmation")
    require(protocol["frozen_unix_ns"] < start["started_unix_ns"] < completion["completed_unix_ns"], "Invalid freeze/run chronology")
    for name, expected in protocol["source_bindings"].items():
        require(sha(safe(run / "producer-snapshot", name)) == expected == sha(safe(ARTIFACT, name)), "Producer source binding changed")
    require(sha(run / "bridge/SandmarkBridge.class") == protocol["bridge_sha256"], "Bridge changed")
    require(sha(run / "acquisition-lock.json") == protocol["acquisition_lock_sha256"], "Acquisition lock changed")
    expected = []
    for repeat in [1, 2]:
        for payload in ["7", "42", "0000", "1234", "9999"]:
            expected.append({"id": f"qp-confirm-{len(expected)+1:04d}", "repeat": repeat,
                "inputs": {"algorithm": "Qu/Potkonjak", "host": "antlr-2.7.7", "payload": payload,
                           "key": "17", "seed": repeat-1, "extractor_mode": "candidate_set", "requires_png": False}})
    require(frame["configurations"] == expected and frame["expected_configurations"] == 10, "Confirmation frame domain changed")
    require(start["configuration_ids"] == [r["id"] for r in expected], "Execution order changed")
    require(len(summary["configurations"]) == summary["configuration_count"] == completion["configuration_count"] == 10, "Confirmation denominator mismatch")
    lock = read(run / "acquisition-lock.json")
    catalog = {x["algorithm"]: x["class"] for x in read(run / "producer-snapshot/external_sandmark/algorithm-contracts.json")["algorithms"]}
    counters, counts, outcomes = Counter(), Counter(), []
    for item, row in zip(expected, summary["configurations"], strict=True):
        case = run / "cases" / item["id"]
        receipt = read(case / "receipt.json")
        require(all(row[k] == item[k] for k in item) and row["receipt_sha256"] == sha(case / "receipt.json"), "Case summary changed")
        verify_receipt(plan, receipt, expected_inputs=item["inputs"], expected_context_id=item["id"])
        judgments = {r["id"]: r["verdict"] for r in receipt["obligations"]}
        require(judgments == row["judgments"], "Judgment summary changed")
        require(row["action_status"] == {a["id"]: a["status"] for a in receipt["actions"]}, "Status summary changed")
        for action in receipt["actions"]:
            reobserve(case, action, protocol, catalog, lock, counters)
        actions = {a["id"]: a for a in receipt["actions"]}
        for step in ["embedded-host", "relocated-host", "repacked-host"]:
            for before, after in zip(actions["source-host"]["value"]["tasks"], actions[step]["value"]["tasks"], strict=True):
                old = case / "source-host" / before["task"] / "generated"
                new = case / step / after["task"] / "generated"
                ob = {p.relative_to(old).as_posix(): p.read_bytes() for p in old.rglob("*") if p.is_file()}
                nb = {p.relative_to(new).as_posix(): p.read_bytes() for p in new.rglob("*") if p.is_file()}
                require((ob == nb) == (before["outputs"] == after["outputs"]), "Host hash comparison differs from actual bytes")
                counters["host_generated_file_byte_comparisons"] += len(set(ob) & set(nb))
        counts.update(judgments.values())
        outcomes.append({"id": item["id"], "payload": item["inputs"]["payload"], "repeat": item["repeat"],
                         "candidates": actions["source-extract"]["value"]["candidates"], "judgments": judgments})
    require(dict(counts) == summary["judgments"] and sum(counts.values()) == summary["obligation_count"] == 80, "Aggregate counts changed")
    driver = actual_command(run, "driver")
    require(start["started_unix_ns"] >= driver["start_unix_ns"], "Driver does not surround execution")
    return {"verdict": "PASS", "configurations": 10, "obligations": 80, "judgments": dict(counts),
            "checks": dict(counters), "outcomes": outcomes,
            "scope": "Original implementation only; follow-up selected after the original failure; separate denominator"}


def verify(root):
    return {"schema": "sandmark-qp-diagnosis-receiver-v1", "verdict": "PASS",
            "diagnosis": verify_diagnosis(root / "exploratory-01"),
            "confirmation": verify_confirmation(root / "confirmation-01")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ARTIFACT / "results/external-sandmark-qp")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.root.resolve()), indent=2))
    except Exception as error:
        print(json.dumps({"verdict": "FAIL", "error": type(error).__name__ + ": " + str(error)}))
        sys.exit(1)
