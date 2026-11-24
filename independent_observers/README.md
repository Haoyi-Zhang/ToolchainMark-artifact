# Independent live observations and ordinary assertions

This study compares two implementations of the same removal and extraction
obligations. The ordinary-assertion arm acquires observations from live artifact
bytes using its own standard-library ELF/record parser. The ToolchainMark arm
executes the existing MR09 and TR01 implementations in a separate workspace.
Each arm builds its own native artifact; neither receives the other arm's
observations or admission facts.

## Run and verify

Use x86-64 Linux with Python 3.10 or later, GCC, Clang, and the GNU binary
utilities. The builds use GCC; the common setup also records the Clang version.
Hosts H13--H18 need the development headers/libraries for zlib, OpenSSL, SQLite,
libxml2, json-c, and libpng, as listed in
[REPRODUCIBILITY.md](../REPRODUCIBILITY.md). From the artifact directory:

```sh
python3 -B independent_observers/run.py --out /tmp/independent-observer-rerun
python3 -B independent_observers/verify.py --run /tmp/independent-observer-rerun
python3 -B independent_observers/evidence_necessity.py
```

The first command refuses an existing output directory. Add `--pilot` for one
host and one pass. The verifier defaults to the retained formal study and also
accepts `--run PATH`. Paths in the original command records are historical
execution paths; verification resolves retained artifacts from the selected
run directory. It does not need those original paths to exist.

The current five-file producer is `producer_current/`, frozen before `formal-02`.
The original `producer_legacy/` and the earlier retained study remain unchanged as historical evidence.
The wrapper defaults to the current protocol; the explicit legacy protocol option selects the older
producer. The verifier defaults to `formal-02` and can also check `formal-01`
with `--run`. `results/independent-observers/CURRENT.json` identifies the
current frame and separates all earlier executions.

## Experimental frame and result

The current locally frozen confirmation plan crosses 18 existing hosts, three carriers,
and four already constructed removal behaviors. Each pass contains 216 paired
cases, each with two fresh arm executions. Two passes therefore contain 432
paired cases and 864 native arm executions. The arm order alternates within a
pass and reverses for the second pass.

Two additional protocol-control pairs, one per pass, deliberately make a real
`nm` process fail inside the tested follow-up extractor. These four extra arm
executions are excluded from the 432-pair main frame and all fault-sensitivity
denominators. Both arms retain a satisfied removal postcondition and an
inadmissible extraction observation. Their four actual nonzero `nm` invocations
and raw diagnostics are independently verified.

| Behavior | Cases per pass | TR01 | MR09 |
| --- | ---: | --- | --- |
| Carrier removed, expected typed rejection | 54 | Satisfied | Satisfied |
| Completed removal is a no-op | 54 | Inconsistent | Inadmissible |
| Removed carrier, decoder returns fallback payload | 54 | Satisfied | Inconsistent |
| Removed carrier restored at tested extraction entry | 54 | Satisfied | Inadmissible |

Both arms produce these pairs with zero verdict or stage-diagnostic-category
disagreements. The read-only verifier checks 1,188 actual paired byte
comparisons, with zero mismatches. Another 108 paired after-extraction captures
are absent because both arms stop before testing extraction on the no-op
case. Missing captures are not counted as actual byte comparisons.

The verifier also checks 1,944 direct captures, 4,896 actual command records,
46 frozen producer/source/host/specification inputs against their saved
snapshots and current files, and 1,944 selected non-timing field comparisons
between passes. These totals are independently reconstructed from the retained
records rather than copied from the study summary.

Agreement establishes implementation agreement on these finite traces. It does
not show a detection advantage over equally informed ordinary assertions. The
four diagnoses are stage categories, not an independent root-cause diagnosis
experiment or a study of how users interpret error messages.

## Acquisition and shared dependencies

`producer_current/direct_oracle.py` imports no ToolchainMark code. Its observer reads
live bytes, retains each capture, and parses the declared ELF64/record format
without calling `nm`, `readelf`, or `objcopy`. It validates source payload,
completed transformation, the physical carrier postcondition, and artifact
identity at the declared extraction endpoints before comparing typed outcomes.
An unavailable operation or observation is not converted into a typed domain
rejection.

`producer_current/target_adapter.py` is the system-under-test wrapper. It uses the
existing controlled target implementations and exposes build, removal, and
extraction through a JSON-lines command protocol. The direct oracle treats the
target command as opaque and does not inspect cohort names or expected pairs.
This is implementation separation, not a blinded development process: both
observers implement the same published local format, and the independent
observer was written after inspecting it. No independent team or clean-room
development is claimed.

`producer_current/reference_arm.py` separately executes the current framework observer,
MR09, and TR01. Its postcondition view is captured after removal and before the
tested extraction. Classification from that captured view may be computed
after the extraction has returned. The restored-artifact behavior changes the
target at extraction entry; the final identity comparison observes the change.
Neither arm detects a change that is undone before the endpoint check.

The bounded ELF parser is sufficient for the retained x86-64 ELF fixtures and
their declared carrier layouts. It is not a general ELF parser, a security
boundary, or proof that all malformed records receive equivalent diagnoses.
The target implementations, hosts, carrier contract, compiler, and utilities
remain shared dependencies. This study is separate from a comparison against
an independently maintained watermark implementation.

## Auditable observation cost

Each pass has the following actual external command counts, including target
construction, transformation, extraction, and reference observation:

| Command | Direct assertions | Framework implementation |
| --- | ---: | ---: |
| GCC | 216 | 216 |
| `nm` | 126 | 486 |
| `objcopy` | 216 | 468 |
| `readelf` | 126 | 486 |
| `strip` | 54 | 54 |
| Total | 738 | 1,710 |

The direct observer performs 972 file captures and 432 parsed views per pass,
reading 15,281,128 bytes in total. Its observer itself invokes no ELF utilities;
the target still does. The framework binding repeats utility-backed observation
for the two stage obligations. These counts describe the supplied
implementations; the logical contract does not require the extra process
calls. The retained elapsed times include distinct process/protocol paths and
are descriptive costs, not a performance superiority claim.

The integration surface is also explicit. Both implementations require an
authoritative artifact, a supported carrier/postcondition interpretation,
typed operation outcomes, and extraction endpoint identity. The target adapter
has three operations. A different tool needs its own authoritative outputs,
operation-result mapping, and carrier observer. This inventory is not a timed
maintainer study and does not establish a reduction in engineering effort.

## Pilot history and source binding

`results/independent-observers/pilot-01` is retained as a failed pilot. The
independent symbol parser initially compared a hexadecimal key tag with raw
digest bytes. This caused all four symbol pilot cases to stop at source
validation. It was a defect in the new baseline observer, not in the tested
watermark target or framework. The five original producer files and raw
records remain available. The 41 artifact input files have recorded hashes;
their matching contents are preserved in the later full source snapshots.
They were not all separately snapshotted by the first pilot runner.

`pilot-02` contains the corrected 12-case pilot. It passes and retains all 46
producer/input snapshots. Invocation logging was then added, and a new formal
source manifest was frozen before `formal-01`.

A later protocol review found that the original target wrapper represented
every `ExtractionError` as a domain rejection, including the `tool` category.
No command in the four original formal cohorts failed, so that boundary did
not change their observed agreement. It nevertheless made the protocol
incorrect for an unavailable extraction utility. The current protocol recognizes only the
declared domain rejection kinds; tool errors are unavailable observations.
It also rejects unknown domain labels and malformed payload representations.

`pilot-03` checks the corrected current producer on the 12-case pilot plus one real
tool-failure control pair. A fresh current-protocol source freeze then precedes both passes
of `formal-02`. That is the current main denominator. Legacy and current-protocol executions are
not added together as independent evidence, and no pilot or protocol-control
execution is counted in the 432 main pairs.

## Evidence distinctions

The read-only verifier derives two trace-pair examples from each host/carrier
in each pass. A successful removal command and correct source payload cannot
separate a completed no-op from successful carrier removal. After removal,
the same physical carrier view and returned payload cannot separate a
fallback acceptance from an artifact restored during extraction. The latter
pair even has identical source, postcondition, and pre-extraction bytes; the
post-extraction bytes distinguish it.

These are necessity arguments under explicitly listed observation
projections. Other sufficient observations could make the same distinctions.
The companion `evidence_necessity.py` enumerates 32 abstract assignments to five
named predicates and checks ordinary-assertion equivalence. Those assignments
are mathematical valuations, not 32 additional native tests or a universal
five-bit lower bound.
