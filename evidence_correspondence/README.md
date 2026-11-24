# Checking execution-record correspondence

This study compares three checking layers on retained native observations. Six
unaltered records establish positive controls. Eighteen additional records each
change one specified association. The frozen frame therefore contains 24 records
and 72 layer-level acceptance decisions. These are controlled evidence records,
not additional native executions or newly discovered software defects.

## Checking responsibilities

| Layer | Information checked |
| --- | --- |
| Oracle replay | Declared stage requirements and predicates, raw action statuses/values, and earlier independently recomputed stage labels. The replay compares its labels with the labels recorded in the receipt. |
| Independent plan receiver | External input/context selection, exact action and obligation domains, declaration order, guards, resolved arguments, dependencies, event constraints, and all derived stage fields. |
| Native binding | The plan checks above plus retained-file identities, typed extraction returns, independently read carrier material, and the explicitly implemented process/target/output associations. |

Oracle replay uses the independent expression implementation retained in
`ctf_comparison/expressions.py`. This activity does not invoke the official CTF
API. The layers are a component comparison with different declared
responsibilities. Ordinary assertions and other frameworks can implement the
same added associations; the study does not measure their maximum capabilities.

## Positive records and ground truth

The selected cases are a clean host-output comparison, clean removal, clean
parallel construction, the controlled changed-artifact revisit, an unrepaired
LLVM literal-output case, and its repaired counterpart. They come from the
retained native `reference`, `identity`, and `llwm` frames. The changed-artifact
case legitimately has an inadmissible scientific judgment. The unrepaired LLVM
case legitimately has inconsistent and inadmissible judgments. Both are valid
records and must remain distinct from invalid evidence.

Each invalid control changes the association in the table below while retaining
its original plan and all other fields. An association can contain two fields:
parallel interval order changes two event ordinals; paired host-output corruption
changes one output on each side while preserving their equality. The exact JSON
paths and before/after values are frozen in `protocol.json` before checking.

| Controlled change | Violated association |
| --- | --- |
| `input-digest` | Input identity versus the unchanged input object. |
| `action-context` | Action context versus the externally selected case. |
| `action-order` | Receipt action order versus declaration order. |
| `parallel-order` | Sibling event intervals versus declared parallel order. |
| `guard-result` | Guard evaluation versus the attempted action record. |
| `resolved-argument` | A host input versus its declared input reference. |
| `consumed-reference` | The dependency list versus the consumed input. |
| `stored-verdict` | The stored scientific label versus observation replay. |
| `paired-host-values` | Equal typed host outputs versus retained stdout. |
| `process-target-before` | Process pre-call version versus action pre-call version. |
| `process-target-after` | Process post-call version versus action post-call version. |
| `strip-flag` | Native transformation flag versus the declared debug operation. |
| `strip-return` | Native nonzero return versus an available strip observation. |
| `strip-input` | Native strip input versus the declared marked input. |
| `strip-output` | Native strip destination versus its returned file capture. |
| `strip-command-missing` | A strip result versus its required process record. |
| `decoder-call-key` | Raw extraction-call key versus the declared/returned key. |
| `decoder-call-session` | Raw extraction-call session versus the live decoder context. |

The designers knew the implementations and the preceding binding-repair
controls. This is a controlled conformance experiment. The earlier nine
accepted malformed-record controls and their corrected outcomes remain under
`declarative_study/validation/record-correspondence/`; they do not enlarge this
study's denominator.

## Recorded results

The completed frozen activity produced all 72 acceptance decisions in 3.163
seconds of recorded wall time, including Python checker-process startup. Every
layer accepted all six valid records, including the original scientific
inconsistent and inadmissible results.

| Layer | Valid records accepted | Controlled invalid records rejected | Controlled invalid records accepted |
| --- | ---: | ---: | ---: |
| Oracle replay | 6 / 6 | 1 / 18 | 17 / 18 |
| Independent plan receiver | 6 / 6 | 8 / 18 | 10 / 18 |
| Native binding | 6 / 6 | 18 / 18 | 0 / 18 |

Oracle replay rejects the altered stored verdict. The plan receiver additionally
detects the seven changes to input identity, action context/order, parallel
order, guard evaluation, arguments, and dependencies. Native binding detects
the remaining ten changes to raw output, target versions, transformation
commands, and decoder-call parameters. These outcomes follow the respective
observation responsibilities in this fixed control set. The full per-record
results and measured CPU/wall times are in
`results/evidence-correspondence/completed/summary.json`.

## Reproduction

From `artifact/`, the retained comparison is checked with:

```bash
python3 -B -m evidence_correspondence.verify
```

The receiver checks the exact source/data bindings and declared changes, then
replays the frozen checking code. It launches Python checker processes and
reads saved native material; it does not launch the tested native programs.

To create a separate comparison using a new output directory:

```bash
python3 -B -m evidence_correspondence.run freeze --out /tmp/correspondence-check
python3 -B -m evidence_correspondence.run execute --out /tmp/correspondence-check
python3 -B -m evidence_correspondence.verify --data /tmp/correspondence-check
```

The freeze and execution steps are separate. A prior attempted output directory
cannot be reused. Every receipt, exact patch, checker stdout/stderr, timing, and
completion record is retained. Validity labels are not passed to the checking
layers. Receiver success means the recorded comparison is reproducible; it does
not require a desired detection rate.

The study uses the original content-addressed byte pools through their fixed
relative artifact locations. Its freeze records bind all referenced compressed
objects and setup inputs. No duplicate binary pool or new archive container is
created. Internally coherent fabricated acquisition and unobserved file changes
between endpoints remain outside the checked claim.
