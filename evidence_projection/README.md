# Evidence projection and native history

This module exports the evidence needed to check one declared stage judgment.
It keeps the original plan and external case selection, the target's static
closure of preceding obligations, and the complete action-block prefix through
the last referenced action. Every sibling of a retained parallel block remains
in that prefix. Earlier actions can affect opaque state even when their return
values are not referenced by the target.

## Construction and independent checking

`project.py` constructs the bundle. `receiver.py` derives the required prefix
and obligation closure independently, without importing that constructor. The
caller supplies the original plan, inputs, decoder context, native binding
context and target. The receiver checks a locally induced prefix declaration;
the saved receipt retains its original plan identity and event ordinals.

`native.py` enumerates the exact files named by retained action evidence. The
native checks use the existing declarative or SandMark binding profile to
reconstruct captured bytes, typed results and the implemented process/target
associations. A native bundle contains exactly the required member set.

A valid standalone bundle establishes correspondence to the externally selected
declaration and case. Historical membership additionally needs the original
record or an external commitment to it. The completed measurement retains the
original records, so it directly checks every retained action, obligation and
target judgment against that available source.

## Completed measurement

`results/evidence-projection/completed/` covers every one of the 10,134 stage
obligations in the complete 7,380-receipt CTF input frame. It creates derived
views; it acquires no new native executions. All targets produce accepted
prefixes with the original target judgment. Of those targets, 7,536 retain every
action, and 8,550 retain the same native storage byte count as their full record.

Three representations are measured: typed observation replay over explicit
references, complete action records over transitive argument/guard references,
and the conservative complete prefix. The reference-only comparison preserves
the recorded mapped verdicts. It does not establish the same dynamic history
or equality of every diagnostic field.

The frozen `measurements.jsonl` counts compact bundle metadata and native stored
files. The separate `transport-measurements.jsonl` also counts the externally
selected `case.json`, in both compact and indented formats. Both sides include
the same case material. Under that complete-input accounting, 3,090 projections
are smaller and 7,044 are larger; none is equal. These per-target totals repeat
shared evidence and are neither a compressed archive size nor the checker
installation size.

Eighteen exported examples are the first occurrence of each available
study/judgment combination. Each contains `bundle.json`, `case.json`, the exact
`native/` members and the recorded receiver output.

## Read-only reception

From `artifact/`:

```sh
python3 -B -m evidence_projection.verify_results
python3 -B -m evidence_projection.verify_history
```

The results receiver checks the unique complete target frame, original
plan/receipt bindings, independently derived prefix/reference selections,
target judgments, every quantitative row and aggregate, original native-context
metadata, and actual native bytes for all eighteen exported examples. It also
recomputes the additional transport accounting when present. It does not repeat
all 10,134 native-byte validations performed by the frozen measurement; the
underlying native studies have their own complete receivers.

The results checker and its current metadata bindings were added after
acquisition. They are distinct from the retained pre-measurement source freeze.
Historical elapsed time is checked for a valid recorded value; it is not
reconstructed. Actual checker commands, source identities, output and focused
control results are retained under `evidence_projection/validation/`.

To inspect one standalone bundle:

```sh
python3 -B -m evidence_projection.receiver \
  --bundle results/evidence-projection/completed/examples/reference/satisfied/bundle.json \
  --case results/evidence-projection/completed/examples/reference/satisfied/case.json \
  --native results/evidence-projection/completed/examples/reference/satisfied/native
```

This invocation relies on the supplied external case selection. The complete
results checker additionally compares that selection and bundle with the
available bound original record.

Focused controls can be repeated with:

```sh
python3 -B -m unittest evidence_projection.test_receiver evidence_projection.test_verify_results -v
python3 -B -m unittest discover -s evidence_projection/tests -v
```

## Native history control

`results/evidence-projection/history-control/` contains twelve fresh paired
configurations: CLEAN and the existing controlled cross-object behavior M23,
three carriers and two passes. Both arms create a decoder session, build A and
B, and recover A before and after the intervention position. The with-B arm
additionally extracts B between those A requests. The REVISIT predicate reads
the two A observations, not the B return value.

The six clean pairs agree. In the six M23 pairs, the with-B history is
inconsistent and the without-B history is satisfied. Direct comparisons find
the paired A and B artifact bytes equal. The control isolates this intervening
call's state effect; it does not execute an entire reference-only sliced plan
or demonstrate a newly discovered external defect.

The history receiver checks all 24 traces, their exact declarations and native
bindings, 60 typed extraction returns, and the 24 paired artifact-byte
comparisons. It also checks the retained invalid-prefix controls independently.

## Create new output

The following derives a fresh measurement from the fixed retained input frame,
then performs the additional transport analysis:

```sh
python3 -B -m evidence_projection.run --out ../reruns/projection
python3 -B -m evidence_projection.analyze_transport --data ../reruns/projection
python3 -B -m evidence_projection.verify_results --data ../reruns/projection
```

The output directory must not exist. The measurement performs all-target native
byte checks and can take several minutes. The separate history acquisition
requires the reference native toolchain and executes new programs:

```sh
PYTHONPATH=src python3 -B -m evidence_projection.run_history_control --out ../reruns/history-control
python3 -B -m evidence_projection.verify_history --data ../reruns/history-control
```

Native dependencies and the distinction between retained reception and new
acquisition are described in [REPRODUCIBILITY.md](../REPRODUCIBILITY.md).
