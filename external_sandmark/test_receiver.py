"""Targeted controls on real retained SandMark observations, never on native results."""
from __future__ import annotations

from collections import Counter
import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from external_sandmark.verify_study import binding, read, reobserve, verify


class ReceiverControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.study_run = Path(os.environ.get("SANDMARK_TEST_RUN", "results/external-sandmark/formal-01")).resolve()
        cls.protocol = read(cls.study_run / "protocol-freeze.json")
        cls.lock = read(cls.study_run / "acquisition-lock.json")
        cls.catalog = {x["algorithm"]: x["class"] for x in read(cls.study_run / "producer-snapshot/external_sandmark/algorithm-contracts.json")["algorithms"]}
        cls.case = cls.study_run / "cases/case-0020"
        cls.receipt = read(cls.case / "receipt.json")

    def action(self, step):
        return copy.deepcopy(next(a for a in self.receipt["actions"] if a["id"] == step))

    def reobserve(self, case, action):
        reobserve(case, action, self.protocol, self.catalog, self.lock, Counter())

    def test_intact_saved_run(self):
        self.assertEqual(verify(self.study_run, allow_pilot=True)["verdict"], "PASS")

    def test_forged_typed_candidate_rejected(self):
        action = self.action("source-extract")
        action["value"]["candidates"] = ["forged"]
        with self.assertRaisesRegex(ValueError, "Typed observation"):
            self.reobserve(self.case, action)

    def test_rehashed_wrong_command_target_rejected(self):
        action = self.action("source-extract")
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / "case"
            shutil.copytree(self.case, case)
            path = case / "source-extract/process.command.json"
            record = read(path)
            record["argv"][-8] = record["argv"][-8].replace("embed/host_wm.jar", "source/host.jar")
            path.write_text(json.dumps(record))
            action["evidence"][0]["files"] = [binding(p, case) for p in sorted((case / "source-extract").rglob("*")) if p.is_file()]
            with self.assertRaisesRegex(ValueError, "argv"):
                self.reobserve(case, action)

    def test_missing_target_snapshot_rejected(self):
        action = self.action("source-extract")
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / "case"
            shutil.copytree(self.case, case)
            (case / "source-extract/observed-before/target.jar").unlink()
            with self.assertRaisesRegex(ValueError, "inventory"):
                self.reobserve(case, action)

    def test_changed_generated_file_rejected(self):
        action = self.action("embedded-host")
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / "case"
            shutil.copytree(self.case, case)
            path = next((case / "embedded-host/calc/generated").glob("*.java"))
            path.write_bytes(path.read_bytes() + b"\nchanged\n")
            with self.assertRaisesRegex(ValueError, "inventory"):
                self.reobserve(case, action)

    def test_forged_extractor_endpoint_digest_rejected(self):
        action = self.action("source-extract")
        action["value"]["artifact_before"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Typed observation"):
            self.reobserve(self.case, action)


if __name__ == "__main__":
    unittest.main()
