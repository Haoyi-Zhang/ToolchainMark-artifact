"""Tamper retained comparison copies; never edit native evidence or the run."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from .expressions import BaselineInputError
from .verify import DEFAULT, verify


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def bind_completion(root, name):
    """Update the outer checksum so a control must reach the semantic check."""
    path = root / name
    complete = json.loads((root / "complete.json").read_text())
    for item in complete["files"]:
        if item["path"] == name:
            item.update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    write(root / "complete.json", complete)


def run_controls(source):
    verify(source)
    controls = []
    for name in ("dropped-case", "changed-official-result", "changed-gate", "changed-frame", "changed-stage-denominator", "changed-upstream-source"):
        with tempfile.TemporaryDirectory(prefix="ctf-receiver-control-") as temporary:
            root = Path(temporary) / "run"
            shutil.copytree(source, root)
            if name in ("dropped-case", "changed-official-result", "changed-gate"):
                path = root / "cases.jsonl"
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                if name == "dropped-case":
                    rows.pop()
                elif name == "changed-official-result":
                    result = rows[0]["results"][0]
                    result["ctf_result"]["outcome"] = "FAIL" if result["ctf_result"]["outcome"] == "PASS" else "PASS"
                else:
                    gate = next(g for row in rows for r in row["results"] for g in r["gates"])
                    gate["state"] = "FALSE" if gate["state"] == "TRUE" else "TRUE"
                path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
                bind_completion(root, "cases.jsonl")
            elif name == "changed-frame":
                path = root / "frame.json"
                rows = json.loads(path.read_text())
                rows[0]["native_run"] += 100
                write(path, rows)
                bind_completion(root, "frame.json")
            elif name == "changed-stage-denominator":
                path = root / "summary.json"
                summary = json.loads(path.read_text())
                summary["stage_comparisons"] += 1
                write(path, summary)
                bind_completion(root, "summary.json")
            else:
                path = root / "source-snapshot/ctf_comparison/vendor/causal_testing/testing/causal_test_case.py"
                path.write_bytes(path.read_bytes() + b"\n# altered control\n")
            try:
                verify(root)
            except BaselineInputError as error:
                controls.append({"control": name, "result": "REJECTED", "reason": str(error)})
            else:
                raise AssertionError(f"tampered comparison accepted: {name}")
    return {"schema": "toolchainmark-ctf-receiver-controls-v1", "verdict": "PASS", "controls": controls,
            "count": len(controls), "modified_retained_inputs": False,
            "scope": "Receiver integrity controls on temporary copies, not additional scientific samples."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=DEFAULT)
    args = parser.parse_args()
    print(json.dumps(run_controls(args.run.resolve()), sort_keys=True, indent=2))
