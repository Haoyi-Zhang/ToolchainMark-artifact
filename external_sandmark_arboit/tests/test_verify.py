"""Negative receiver controls on temporary copies, not new native samples."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from external_sandmark_arboit.verify import DEFAULT, InvalidRecord, verify


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def rebind(root):
    data = json.loads((root / "complete.json").read_text())
    for item in data["files"]:
        path = root / item["path"]
        item.update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    write(root / "complete.json", data)


class RetainedRecordControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="arboit-receiver-control-")
        self.root = Path(self.temp.name) / "run"
        shutil.copytree(DEFAULT, self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_positive_record(self):
        report = verify(self.root)
        self.assertEqual(report["identical_probe_pairs"], 40)
        self.assertEqual(report["membership_comparison"]["total_different_memberships"], 0)

    def test_rebound_wrong_denominator_is_rejected(self):
        path = self.root / "summary.json"
        data = json.loads(path.read_text())
        data["identical_pairs"] -= 1
        write(path, data)
        rebind(self.root)
        with self.assertRaisesRegex(InvalidRecord, "summary"):
            verify(self.root)

    def change_command(self, suffix, transform):
        index = self.root / "commands.json"
        data = json.loads(index.read_text())
        row = next(r for r in data if r["id"].endswith(suffix))
        transform(row)
        folder = self.root / "commands" / row["id"]
        (folder / "stdout.bin").write_bytes(bytes.fromhex(row["stdout_hex"]))
        (folder / "stderr.bin").write_bytes(bytes.fromhex(row["stderr_hex"]))
        write(folder / "command.json", row)
        write(index, data)
        rebind(self.root)

    def test_consistently_changed_raw_probe_is_rejected(self):
        self.change_command("/basic/tokens", lambda row: row.update(stdout_hex=(bytes.fromhex(row["stdout_hex"]) + b"changed\n").hex()))
        with self.assertRaisesRegex(InvalidRecord, "probe comparison"):
            verify(self.root)

    def test_consistently_changed_membership_is_rejected(self):
        def change(row):
            lines = bytes.fromhex(row["stdout_hex"]).decode().splitlines()
            tag, name, values = lines[0].split("\t")
            raw = bytearray.fromhex(values)
            raw[0] ^= 1
            lines[0] = "\t".join((tag, name, raw.hex()))
            row["stdout_hex"] = ("\n".join(lines) + "\n").encode().hex()
        self.change_command("/sets", change)
        with self.assertRaisesRegex(InvalidRecord, "membership comparison"):
            verify(self.root)

    def test_changed_compiler_argument_is_rejected(self):
        self.change_command("/compile", lambda row: row["argv"].append("-nowarn"))
        with self.assertRaisesRegex(InvalidRecord, "compiler command"):
            verify(self.root)

    def test_wrong_source_deduplication_is_rejected(self):
        path = self.root / "frame.json"
        data = json.loads(path.read_text())
        data["mappings"][0]["bundle"] = "bundle-2"
        write(path, data)
        rebind(self.root)
        with self.assertRaisesRegex(InvalidRecord, "deduplication"):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
