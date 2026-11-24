# Qu/Potkonjak recovery diagnosis and confirmation

The archived Qu/Potkonjak implementation returned normally when embedding
`1234` in ANTLR 2.7.7 with key `17`, but its recognizer returned the Java string
`"null"`. The two observations in the original 156-configuration study are
fresh repetitions of this behavior. They are not two independently discovered
defects. This directory explains the observed failure and provides a separate,
pre-execution frozen confirmation frame. The algorithm has not been repaired,
and the original authors have not confirmed this diagnosis.

## What the retained evidence establishes

The four ASCII characters satisfy the implementation's 8-bit character and
power-of-two payload-length convention: 32 payload bits plus an 8-bit length
header require 40 bits. The original embedder reports 470 encoded bits. A
read-only method-order probe finds the same 2,248 method rows before and after
embedding, including the method-order comparator's instruction fields.

Two trace-only copies of `AssignLV.java` expose the encoding and recognition
steps. Every one of the 225 ZIP entries produced by each traced embedder is
byte-identical to the corresponding entry in the original failing marked JAR.
The first mismatch occurs at bit 3, counting from zero, in
`antlr.CppCodeGenerator.genInclude(TreeWalkerGrammar)`:

| Observation | Retained value |
| --- | --- |
| Canonical triple node indices | `(7, 9, 10)` |
| Canonical local-register indices | `(1, 1, 1)` |
| Encoded bit | `1` |
| Added constraint | First and third nodes must have different registers |
| Allocated local-register indices | `(1, 2, 2)` |
| Recognition test | First register differs from second, therefore decode `0` |

The added inequality does not ensure the equality on which the recognizer's
other branch depends. The same node triple is reconstructed at recognition.
The encoded header `00010000` becomes `00000000`; the original `FromBinary`
implementation maps that header to 512 payload bits, exceeding the 462 bits
remaining in the recovered stream. The recognizer consequently returns the
literal string `"null"`. This is neither a JSON null nor a process timeout.
Eleven bit positions differ over the complete 470-bit traced stream; the first
header disagreement is sufficient to explain this returned candidate.

The original host-output observations pass: the three official ANTLR grammars
generate equal process streams and byte-identical output files. Thus this
case separates successful embedding and preserved observed host behavior
from successful watermark recovery. It does not establish universal functional
equivalence of the marked application.

## Separate confirmation frame

`confirmation-frame.json` fixed the original implementation, ANTLR 2.7.7,
key `17`, payloads `7`, `42`, `0000`, `1234`, and `9999`, and two fresh executions
before confirmation began. The unchanged shared SandMark plan evaluates all
eight obligations, including relocation and entry-identical repacking.
The outer seeds are recorded as 0 and 1; QP resets its internal PRNG from the
key, so these repetitions are not independent key or random-seed samples.

| Payload | Source recovery in two executions | Host-output comparisons |
| --- | --- | --- |
| `7` | Both contain the supplied payload | All equal |
| `42` | Both contain the supplied payload | All equal |
| `0000` | Both return `["null"]` | All equal |
| `1234` | Both return `["null"]` | All equal |
| `9999` | Both return `["null"]` | All equal |

The confirmation has **10 configurations and 80 obligations: 62 SATISFIED,
6 INCONSISTENT, and 12 INADMISSIBLE**. The six inconsistencies are source
recovery failures. Their twelve downstream recovery obligations are
inadmissible because the corresponding source recovery premise is false.
These counts remain separate from the original 156-configuration study.
The confirmation was chosen after the original failure and its diagnosis;
it is not a random sample or a prevalence estimate.

## Files and verification

Native evidence is under `results/external-sandmark-qp/`:

- `exploratory-01/` retains all nine diagnostic commands, their raw streams,
  compiled probe classes, trace outputs, original candidate values, and the
  post-hoc `diagnostic-provenance.json`. This record does not claim a
  pre-execution freeze.
- `confirmation-01/` retains the frozen frame and plan, producer snapshot,
  protocol hash, actual run start and completion, all ten receipts, native
  commands and files, and the separate summary.
- `validation/` in this source directory retains read-only receiver and
  evidence-control outputs with the commands and source hashes used.

From the artifact directory:

```sh
python3 -B external_sandmark/qp_diagnosis/verify.py
python3 -B -m unittest external_sandmark.qp_diagnosis.test_receiver -v
```

The receiver does not rerun Java. It independently evaluates the shared
receipts and reconstructs observations from actual saved process records,
target snapshots, archive entries, and generated files. It checks 160 native
confirmation commands, 30 extraction endpoint pairs, 2,250 direct ZIP-entry
comparisons, and 600 generated-file byte comparisons. The diagnostic check
also compares 2,248 method rows and 450 actual ZIP entries across the two
trace variants. The negative controls cover a forged trace with a matching
command stream, a missing captured target, and a changed traced JAR entry.

To rerun the original-only confirmation, acquire the exact inputs using
`external_sandmark/acquire.py`, then use a new output directory:

```sh
python3 -B external_sandmark/qp_diagnosis/run_confirmation.py freeze \
  --output /tmp/qp-new/confirmation-01 --cache /path/to/sandmark-cache
python3 -B external_sandmark/qp_diagnosis/run_confirmation.py run \
  --output /tmp/qp-new/confirmation-01 --cache /path/to/sandmark-cache
```

The retained original confirmation's freeze SHA256 is
`026f2746c609582cbc3c6806bcc4b2fd15176e94454630c6a25a433a60a63a1b`.
`original-source/` contains only five relevant source files from the fixed
SandMark mirror commit `5e4642c83d802968cfa47c1a362fbecbd72f5802`, with their
repository paths, hashes, and original noncommercial copyright conditions.
The two `instrumentation.patch` files make all added tracing visible. The
full SandMark tool JAR is acquired separately; it is not redistributed here.

No local change to the encoder, allocator, recognizer, or validity predicate
is presented as a repair. A general correction would have to preserve
recoverability across interacting allocation constraints, beyond this
concrete failing triple and the tested payload neighborhood.
