"""Targeted evidence controls for the post-hoc QP study receiver."""
from __future__ import annotations

import json
import errno
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from external_sandmark.qp_diagnosis.verify import ARTIFACT, verify, verify_diagnosis, verify_confirmation


def replace_bytes(path, raw):
    # Clones use hard links; replacement must never mutate the preserved source.
    replacement = path.with_name(path.name + ".replacement")
    replacement.write_bytes(raw)
    replacement.replace(path)


def clone_file(source, target):
    try:
        os.link(source, target)
    except OSError as error:
        if error.errno != errno.EXDEV:
            raise
        shutil.copy2(source, target)
    return target


class EvidenceControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="qp-evidence-control-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "study"
        shutil.copytree(ARTIFACT / "results/external-sandmark-qp", self.root, copy_function=clone_file)

    def tearDown(self):
        self.temporary.cleanup()

    def test_preserved_diagnosis_and_confirmation(self):
        self.assertEqual(verify(self.root)["verdict"], "PASS")

    def test_self_consistent_command_stream_cannot_forge_recovered_header(self):
        root = self.root / "exploratory-01"
        stream = root / "instrumented-extract.stderr.bin"
        raw = stream.read_bytes()
        old = b"QPTRACE RECOVERED|00000000"
        self.assertEqual(raw.count(old), 1)
        raw = raw.replace(old, b"QPTRACE RECOVERED|00010000")
        replace_bytes(stream, raw)
        command = root / "instrumented-extract.command.json"
        record = json.loads(command.read_text())
        record["stderr_hex"] = raw.hex()
        replace_bytes(command, (json.dumps(record, indent=2) + "\n").encode())
        with self.assertRaisesRegex(ValueError, "Recovered trace mismatch"):
            verify_diagnosis(root)

    def test_missing_physical_extractor_target_is_rejected(self):
        root = self.root / "confirmation-01"
        target = root / "cases/qp-confirm-0001/source-extract/observed-before/target.jar"
        target.unlink()
        with self.assertRaisesRegex(ValueError, "Acquisition file inventory"):
            verify_confirmation(root)

    def test_instrumented_artifact_must_match_original_entry_bytes(self):
        import zipfile
        root = self.root / "exploratory-01"
        target = root / "triple-host_wm.jar"
        replacement = target.with_suffix(".replacement")
        with zipfile.ZipFile(target) as source, zipfile.ZipFile(replacement, "w") as changed:
            first = True
            for item in source.infolist():
                data = source.read(item)
                if first and item.filename.endswith(".class"):
                    data = data[:-1] + bytes([data[-1] ^ 1])
                    first = False
                changed.writestr(item, data)
        replacement.replace(target)
        with self.assertRaisesRegex(ValueError, "Instrumentation changed a target entry"):
            verify_diagnosis(root)


if __name__ == "__main__":
    unittest.main()
