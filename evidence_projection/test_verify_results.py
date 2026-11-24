"""Focused controls for the post-acquisition projection results receiver."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from . import verify_results as checked


def action(name, arguments=None, when=None):
    row = {"id": name, "operation": "observe", "arguments": arguments or {}}
    if when is not None:
        row["when"] = when
    return row


def obligation(name, predicate, requires=None):
    return {"id": name, "stage": "test", "clause": name,
            "requires": requires or [], "predicate": predicate}


def plan(actions, obligations):
    return {"schema": "toolchainmark-contract-v1", "id": "receiver-control",
            "inputs": {}, "actions": actions, "obligations": obligations}


class ResultControls(unittest.TestCase):
    def test_example_sorting_matches_directory_component_order(self):
        rows = [{"path": "examples/state-baseline/satisfied"},
                {"path": "examples/state/inconsistent"},
                {"path": "examples/state/satisfied"}]
        self.assertEqual([row["path"] for row in checked.ordered_examples(rows)],
                         ["examples/state/inconsistent", "examples/state/satisfied",
                          "examples/state-baseline/satisfied"])

    def test_duplicate_target_cannot_replace_a_missing_target(self):
        rows = [{"dataset": "d", "case": "c", "target": "a"},
                {"dataset": "d", "case": "c", "target": "a"}]
        with self.assertRaises(checked.InvalidMeasurement):
            checked.indexed(rows, ("dataset", "case", "target"), "control")

    def test_case_identity_is_part_of_target_identity(self):
        rows = [{"dataset": "d", "case": "a", "target": "x"},
                {"dataset": "d", "case": "b", "target": "x"}]
        self.assertEqual(len(checked.indexed(rows, ("dataset", "case", "target"), "control")), 2)

    def test_hidden_action_and_parallel_sibling_are_not_reference_dependencies(self):
        value = plan([action("hidden"), {"parallel": [action("a"), action("b")]}, action("tail")],
                     [obligation("target", {"available": "a"})])
        selected = checked.derive_selection(value, "target")
        self.assertEqual(selected["action_ids"], ["hidden", "a", "b"])
        self.assertEqual(selected["reference_action_ids"], ["a"])
        self.assertEqual(selected["action_blocks"], 2)

    def test_guard_and_prior_verdict_dependencies_are_retained(self):
        value = plan([action("condition"), action("observed", when={"available": "condition"}), action("tail")],
                     [obligation("prior", {"available": "observed"}),
                      obligation("unused", {"literal": True}),
                      obligation("target", {"op": "eq", "args": [{"verdict": "prior"}, {"literal": "SATISFIED"}]})])
        selected = checked.derive_selection(value, "target")
        self.assertEqual(selected["obligation_ids"], ["prior", "target"])
        self.assertEqual(selected["reference_action_ids"], ["condition", "observed"])
        self.assertEqual(selected["action_ids"], ["condition", "observed"])

    def test_argument_dependency_closure_is_transitive(self):
        value = plan([action("first"), action("second", {"x": {"ref": "first", "path": []}}),
                      action("third", {"x": {"ref": "second", "path": []}}), action("unused")],
                     [obligation("target", {"available": "third"})])
        self.assertEqual(checked.derive_selection(value, "target")["reference_action_ids"],
                         ["first", "second", "third"])

    def test_literal_reference_looking_data_does_not_extend_prefix(self):
        literal = {"literal": {"ref": "missing", "verdict": "missing", "available": "missing"}}
        value = plan([action("unused")], [obligation("target", {"op": "eq", "args": [literal, literal]})])
        selected = checked.derive_selection(value, "target")
        self.assertEqual(selected["action_ids"], [])
        self.assertEqual(selected["reference_action_ids"], [])

    def test_json_duplicate_keys_and_nonfinite_numbers_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rows.jsonl"
            for text in ('{"target":"a","target":"b"}\n', '{"n":NaN}\n', '\n'):
                path.write_text(text)
                with self.assertRaises(checked.InvalidMeasurement):
                    checked.read_lines(path)

    def test_bound_file_bytes_and_safe_paths_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "data.json"
            path.write_text("{}\n")
            row = {"path": "data.json", **checked.identity(path)}
            self.assertEqual(checked.bound(root, row), path)
            path.write_text("[]\n")
            with self.assertRaises(checked.InvalidMeasurement):
                checked.bound(root, row)
            for relative in ("../outside", "/absolute", "a//b", "a/./b", "a\\b"):
                with self.assertRaises(checked.InvalidMeasurement):
                    checked.safe_path(root, relative)

    def test_conflicting_native_content_lengths_are_rejected(self):
        a = {"path": "a", "stored_bytes": 3, "content_identity": "0" * 64, "content_bytes": 2}
        b = {"path": "b", "stored_bytes": 3, "content_identity": "0" * 64, "content_bytes": 4}
        with self.assertRaises(checked.InvalidMeasurement):
            checked.native_metrics([a, b])

    def test_recomputes_an_actual_retained_record_and_detects_metric_changes(self):
        data = checked.DEFAULT
        first = json.loads((checked.CTF / "frame.json").read_text())[0]
        declaration, receipt = [checked.load_json(checked.bound(checked.ARTIFACT, first[key]))
                                for key in ("plan", "receipt")]
        context = checked.context_from_original(checked.safe_path(checked.ARTIFACT, first["dataset"]), first["study"], [])
        target = receipt["obligations"][0]
        result = checked.reconstruct(first, declaration, receipt, target, context,
                                     checked.safe_path(checked.ARTIFACT, first["dataset"]),
                                     checked.derive_selection(declaration, target["id"]))
        with (data / "measurements.jsonl").open() as stream:
            stored = json.loads(stream.readline())
        checked.equal(stored, result[0], "actual first record")
        for field in ("actions", "native_storage_bytes", "typed_replay_bytes", "bundle_bytes"):
            changed = copy.deepcopy(stored)
            changed[field] += 1
            with self.assertRaises(checked.InvalidMeasurement):
                checked.equal(changed, result[0], "altered metric")
        changed = copy.deepcopy(stored)
        changed["accepted"] = 1
        with self.assertRaises(checked.InvalidMeasurement):
            checked.equal(changed, result[0], "boolean coercion")


class FreshSourceLineageControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.data = Path(self.temporary.name) / "fresh"
        snapshot = self.data / "source-snapshot"
        rows = []
        for relative in checked.fresh_source_paths():
            source = checked.ARTIFACT / relative
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            rows.append({"path": relative, **checked.identity(source)})
        self.data.mkdir(exist_ok=True)
        (self.data / "source-freeze.json").write_text(json.dumps(
            {"files": rows, "frozen_before_measurement": True}, indent=2) + "\n")
        shutil.copyfile(checked.ARTIFACT / "evidence_projection/protocol.json",
                        self.data / "protocol.json")
        frozen = checked.identity(self.data / "source-freeze.json")
        for name in ("start.json", "complete.json"):
            (self.data / name).write_text(json.dumps({"source_freeze": frozen}) + "\n")

    def test_fresh_source_freeze_is_bound_at_start_and_completion(self):
        report = checked.check_source_freeze(self.data)
        self.assertEqual(report["producer_mode"], "fresh-current-producer")
        self.assertEqual(report["snapshot_files_checked"], len(checked.fresh_source_paths()))

    def test_fresh_source_freeze_rejects_lifecycle_rebinding(self):
        path = self.data / "complete.json"
        path.write_text(json.dumps({"source_freeze": {"bytes": 0, "sha256": "0" * 64}}) + "\n")
        with self.assertRaisesRegex(checked.InvalidMeasurement,
                                    "fresh measurement completion source freeze binding"):
            checked.check_source_freeze(self.data)

    def test_fresh_source_snapshot_tampering_is_rejected(self):
        relative = checked.fresh_source_paths()[0]
        path = self.data / "source-snapshot" / relative
        path.write_bytes(path.read_bytes() + b"\n# changed after freeze\n")
        with self.assertRaises(checked.InvalidMeasurement):
            checked.check_source_freeze(self.data)


class SourceLineageControls(unittest.TestCase):
    """Small copies of actual retained sources, without measurement or native copies."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "artifact"
        self.data = Path(self.temporary.name) / "retained"
        self.data.mkdir()
        for name in ("source-freeze.json", "protocol.json"):
            shutil.copyfile(checked.DEFAULT / name, self.data / name)
        shutil.copytree(checked.DEFAULT / "source-snapshot", self.data / "source-snapshot")
        shutil.copytree(self.data / "source-snapshot", self.root)
        self.live = checked.ARTIFACT
        self.patcher = mock.patch.object(checked, "ARTIFACT", self.root)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def repaired(self):
        for name in ("declarative_study/native_io.py", "declarative_study/verify.py",
                     "external_sandmark/verify_study.py", "independent_observers/elf_observer.py"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.live / name, target)

    def test_original_source_profile_remains_distinct_and_accepted(self):
        report = checked.check_source_freeze(self.data)
        self.assertEqual(report["current_validation_profile"], "historical-producer")
        self.assertEqual(report["historical_snapshot_files_checked"], 15)
        self.assertEqual(report["current_files_matching_historical_producer"], 15)
        self.assertEqual(report["current_registered_repaired_files"], 0)
        self.assertEqual(report["additional_current_validation_dependencies"], [])

    def test_approved_producer_only_fix_preserves_historical_source_attribution(self):
        relatives = tuple(sorted(checked.APPROVED_CURRENT_PRODUCER_ONLY))
        for relative in relatives:
            shutil.copyfile(self.live / relative, self.root / relative)
        report = checked.check_source_freeze(self.data)
        self.assertEqual(report["current_producer_profile"], "approved-fresh-run-lineage-fix")
        self.assertEqual(len(report["current_registered_producer_only_files"]), len(relatives))
        for row in report["current_registered_producer_only_files"]:
            self.assertNotEqual(row["historical_producer"], row["current_producer"])
            self.assertEqual(row["historical_producer"],
                             checked.identity(self.data / "source-snapshot" / row["path"]))

    def test_repaired_profile_preserves_historical_source_attribution(self):
        self.repaired()
        report = checked.check_source_freeze(self.data)
        self.assertEqual(report["current_validation_profile"], "approved-repaired-native-validation")
        self.assertEqual(report["historical_snapshot_files_checked"], 15)
        self.assertEqual(report["current_files_matching_historical_producer"], 12)
        self.assertEqual(report["current_registered_repaired_files"], 3)
        self.assertEqual(len(report["additional_current_validation_dependencies"]), 1)
        for row in report["current_native_validation_files"]:
            self.assertNotEqual(row["historical_producer"], row["current_validation"])
            self.assertEqual(row["historical_producer"],
                             checked.identity(self.data / "source-snapshot" / row["path"]))

    def test_historical_source_tampering_rejects_even_with_approved_current_profile(self):
        self.repaired()
        path = self.data / "source-snapshot/declarative_study/native_io.py"
        path.write_bytes(path.read_bytes() + b"\n# changed historical bytes\n")
        with self.assertRaisesRegex(checked.InvalidMeasurement, "file binding declarative_study/native_io.py"):
            checked.check_source_freeze(self.data)

    def test_rebinding_the_historical_freeze_cannot_claim_a_new_producer(self):
        self.repaired()
        relative = "declarative_study/native_io.py"
        shutil.copyfile(self.root / relative, self.data / "source-snapshot" / relative)
        path = self.data / "source-freeze.json"
        freeze = json.loads(path.read_text())
        row = next(row for row in freeze["files"] if row["path"] == relative)
        row.update(checked.identity(self.root / relative))
        path.write_text(json.dumps(freeze))
        with self.assertRaisesRegex(checked.InvalidMeasurement, "original retained producer freeze identity"):
            checked.check_source_freeze(self.data)

    def test_unregistered_projection_source_change_rejects(self):
        self.repaired()
        path = self.root / "evidence_projection/project.py"
        path.write_bytes(path.read_bytes() + b"\n# unrelated change\n")
        with self.assertRaisesRegex(checked.InvalidMeasurement, "file binding evidence_projection/project.py"):
            checked.check_source_freeze(self.data)

    def test_wrong_registered_receiver_bytes_reject(self):
        self.repaired()
        path = self.root / "declarative_study/native_io.py"
        path.write_bytes(path.read_bytes() + b"\n# unreviewed receiver\n")
        with self.assertRaisesRegex(checked.InvalidMeasurement, "unregistered current native-validation profile"):
            checked.check_source_freeze(self.data)

    def test_mixed_original_and_repaired_profile_rejects(self):
        self.repaired()
        relative = "external_sandmark/verify_study.py"
        shutil.copyfile(self.data / "source-snapshot" / relative, self.root / relative)
        with self.assertRaisesRegex(checked.InvalidMeasurement, "unregistered current native-validation profile"):
            checked.check_source_freeze(self.data)

    def test_new_observer_dependency_is_bound_separately(self):
        self.repaired()
        path = self.root / "independent_observers/elf_observer.py"
        path.write_bytes(path.read_bytes() + b"\n# changed observer\n")
        with self.assertRaisesRegex(checked.InvalidMeasurement, "file binding independent_observers/elf_observer.py"):
            checked.check_source_freeze(self.data)


if __name__ == "__main__":
    unittest.main()
