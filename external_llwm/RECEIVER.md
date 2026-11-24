# Independent receiver audit of the LLWM confirmation study

Run the receiver from the artifact directory:

```sh
python3 -B external_llwm/verify_study.py
```

The default is `results/llwm-native`; `--run PATH` selects another retained run.
The receiver invokes no compiler, watermark program, or external binary utility.
It imports neither the producer's classifier nor ToolchainMark admission code.
Historical absolute command paths are checked against their declared case
structure, while retained files are resolved under the selected run directory.

## What was verified

The confirmation frame has 180 main cases: two passes, two source variants,
three interfaces, five payloads, and three optimization settings. The 12 known
numeric-prefix boundary cases have a separate frame and denominator. Every
planned tuple is present exactly once in its pass.

The receiver binds 39 producer and input files to the current files and saved
source snapshots. It checks 12 vendored source files against the acquisition
manifest and compares both plugin build trees with those bytes. The local
repair changes exactly three headers by replacing six source lines; the other
vendored files are identical. The patch is applied again in memory using exact
context, with no fuzzy matching or subprocess. Wrapper source, plugin build
arguments, setup outputs, and 33 setup file identities are retained and checked.
This verifies correspondence with the saved source acquisition record; it does
not independently fetch or re-extract the public deposit.

For each actual command, the receiver checks its declared role, exact arguments,
working directory, completion, and raw stdout/stderr. In particular, the
`fgets` invocations must receive the recorded key or ordinary input followed
by one newline; an absent or different standard input is rejected. Recorded
execution-before and execution-after digests must both match the retained
binary. The audit checks 2,436 main/boundary command records, 1,128 retained case
files, 1,128 executable endpoint bindings, and 360 actual `fgets` inputs.

Relocation is reconstructed from the retained directory contents and byte
equality. Debug removal is independently checked by parsing the retained
ELF64 section tables, requiring `.debug_info` before stripping and no `.debug_`
sections afterward. The receiver also compares the raw `readelf` output with
those section names. These checks do not trust the row's relocation Boolean
or infer removal merely from a successful `strip` command.

## Judgment and comparison

The receiver expresses ER01--ER04 as ordinary guarded assertions using the
same contract information. It reproduces all 720 stored main-case judgments,
including their prerequisite prefixes and first failed prerequisite. This is
an independent rederivation from saved evidence, not an additional native
baseline arm. The separate `independent_observers` study supplies the fresh
live-acquisition comparison on the controlled removal cases.

| Variant | Main cases | ER01 | ER02 | ER03 | ER04 |
| --- | ---: | --- | --- | --- | --- |
| Upstream | 90 | 18 satisfied; 72 inconsistent | 90 satisfied | 18 satisfied; 72 inadmissible | 18 satisfied; 72 inadmissible |
| Local literal-output repair | 90 | 90 satisfied | 90 satisfied | 90 satisfied | 90 satisfied |

The upstream failure has one root cause shared by the exercised interfaces:
the generated output operation passes the recovered payload as the `printf`
format string. For example, the requested payload `A%%B` is emitted as `A%B`.
The repaired operation supplies `"%s"` as the format and the payload as data.
All tested percent payloads use paired percent characters, so the observed
literal-output error does not depend on missing variadic arguments or an
undefined format conversion. The receiver checks this restricted explanation
against all 180 main observations. The correct-key output channel remains
interface-specific: payload precedes host stdout for `fgets` and follows it
for `atoi` and sidedata.

Ordinary exact-output comparison detects the same error. The contract-specific
contribution to this example is the explicit stage interpretation: ER03 and
ER04 do not attribute a downstream relocation or strip violation to a source
that already fails literal payload recovery. The repair is locally confirmed
in the retained executions. No maintainer confirmation or acceptance is
claimed.

## Repetition and boundary variability

The main study repeats its scientific judgments and 2,700 native invocation
fields exactly: availability, exit status, actual standard input, raw stdout,
and raw stderr. This is a precisely specified projection of the records.
It excludes IR bytes, ELF bytes, random embedding choices, debug compilation
paths, timings, and complete command records.

All 12 known numeric-prefix boundary cases add output on the ordinary input
`12345abcd` despite embedding with the key `12345test`. The local literal-output
repair does not remove that documented limitation. The six paired boundary
`marked-ordinary` stdout observations differ between passes; their exact bytes
are retained as base64 in the verification report. The stable conclusion is
extra output in all cases, not stable recovery of the requested payload.
For example, one upstream observation begins with `host:12345` and `water`
but has different subsequent byte sequences in the two passes.

The upstream source initializes randomized embedding with `srand(time(NULL))`;
debug builds also retain compilation paths. Differences in generated IR or
ELF bytes therefore need not represent a failure to repeat the declared
output observations. The receiver preserves these distinctions rather than
comparing a broad set of fields and silently dropping disagreements.

## Receiver controls and limits

Six controls alter copies of records or reconstructed facts in memory. They
confirm that wrong successful key output yields an ER01 inconsistency,
unavailable embedding yields inadmissibility, and unestablished relocation
identity or debug removal blocks the corresponding downstream verdict. They
also confirm that changed `fgets` standard input or an executable endpoint
digest is rejected by invocation binding. They do not modify retained raw
records and are not additional native cases or observed watermark defects.

The receiver verifies the internal consistency and source binding of the saved
evidence. It is not an independently witnessed execution history. The ELF
reader is bounded to the retained x86-64 ELF64 layouts. Endpoint hashes do not
exclude changes that are undone between observations. One selected public
watermark artifact, synthetic interface probes, and one local repair do not
estimate defect prevalence or establish general watermark security, universal
wrong-key rejection, or whole-toolchain correctness.
