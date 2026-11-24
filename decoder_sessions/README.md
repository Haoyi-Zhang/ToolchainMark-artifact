# SandMark recognition across process and object lifetimes

This module invokes the original archived SandMark recognition APIs on retained
marked JARs. It compares a fresh JVM for each request (P), fresh algorithm
objects within one JVM (O), and one reused algorithm object within one JVM (R).
Every request constructs a fresh Application and recognition-parameter object.
Iterators are fully exhausted before a subsequent request changes configuration.

The three histories are AA, AAA and ABA. AAA holds the number of calls equal to
ABA while repeating A at the intermediate position. Each history begins in a
new process context; unrelated words do not share decoder memory. The shipped
SandMark GUI's selected-algorithm reuse and path-based Application reloading
motivate this sequential use. It is not a concurrency or thread-safety study.
See [API-CONTRACT.md](API-CONTRACT.md) for the primary source basis and
[RECORDS.md](RECORDS.md) for the observation and receiver interface.

## Fixed input population

The complete design retains all 156 original SandMark configurations: 13
algorithms, ANTLR 2.7.7 and the official TTT calibration sample, payloads `7`,
`42`, `1234`, and two archived embedding seeds. Each configuration supplies A;
B follows the fixed cycle `7→42→1234→7` in the same algorithm, host and embedding
seed. Previous source success is never an input-selection condition.

There are 127 retained marked JARs. Missing artifacts and the two known
Qu/Potkonjak source failures stay in the frame. The balanced design has 2,808
planned words and 7,488 planned request slots over three histories, three
lifetimes and two new acquisition passes. From the fixed archive, 2,268 words
have all required inputs, representing 6,042 request slots before any new
runtime failure. These are design counts; actual observations are reported
separately. Repeated words share source artifacts and are not independent
defect samples.

Stern verifies a supplied candidate. Its request key is that candidate; a
successful result is not an independently decoded secret. Other algorithms
retain their original candidate-enumeration interfaces. Native candidate text,
Java class names, nulls, exceptions and incomplete enumeration remain distinct.
The experiment does not demand unique candidates or canonical ordering.

## Retained results

The completed activity is in `results/decoder-sessions/completed/`. Both passes
finished with all 2,808 planned words retained. The 2,268 words with all required
inputs produced 6,042 complete iterator returns in 3,526 JVM processes. The
helper recorded 4,784 algorithm constructions and 6,042 fresh Applications.
There were no recognition exceptions, request/startup timeouts, or nonzero
process exits. The remaining 540 words were blocked by missing archived inputs;
their 1,446 request slots remain explicitly unexecuted.

| Local obligation | Planned | Satisfied | Inconsistent | Inadmissible |
| --- | ---: | ---: | ---: | ---: |
| Per-request source membership | 7,488 | 5,946 | 96 | 1,446 |
| A revisit | 2,808 | 2,232 | 0 | 576 |
| Total | 10,296 | 8,178 | 96 | 2,022 |

All 96 inconsistent observations are repetitions of the two retained
Qu/Potkonjak source failures. The 576 inadmissible revisits comprise the 540
input-blocked words and 36 words whose first-A source obligation fails. No
admitted revisit lost its intended payload. Each pass has the same local
counts: 4,089 satisfied, 48 inconsistent and 1,011 inadmissible.

The stricter AA/AAA/ABA comparison has 244 qualified comparisons in each
lifetime. Neither O nor R has a B-request-associated loss in those comparisons.
The P reference contributes another 244 qualified comparisons, but is not an
additional reuse arm. Across lifetimes, all 756 complete P/O/R triples have
equal typed candidate sequences. The descriptive final-return comparisons
also have no sequence, multiset or set differences: 762 AA versus AAA pairs,
744 AAA versus ABA pairs and 744 AA versus ABA pairs. These comparisons reuse the
same archived inputs; they do not represent independent defects or independent
population samples.

The complete numerical derivation is `paired-analysis.json`. It retains
qualification information, comparison membership, algorithm-level accounting,
and the raw-acquisition denominators. `summary.json` records local judgments,
while `completion.json` binds the completed frame and unchanged producer/core
identities. The new study finds stable short sequential recognition on the
available archived inputs; it does not find a new SandMark session defect.

## Verify the retained records

From `artifact/`, the independent receiver uses only Python and the delivered
records. It does not launch Java or need the original absolute runtime paths to
remain present:

```sh
python3 -B decoder_sessions/verify.py
```

To receive a separately acquired run, select its directory explicitly:

```sh
python3 -B decoder_sessions/verify.py --data /absolute/path/to/new-session-run
```

The receiver checks the fixed declarations and complete factor frame,
type-sensitive native requests and returns, process/object lifecycle evidence,
authorized file versions, local judgments, paired group membership, and the
saved measured counts. It independently derives these checks without importing the acquisition
adapter or analyzer. Acquisition journals remain recorded observations, not
proof of unobserved internal reads or cryptographic object identity.

The exact post-acquisition delivery inventory is
`decoder_sessions/inventory_manifest.json`, checked through `inventory.py`.
It covers the completed run and the five named ancillary roots, including the
failed first pilot and never-started two-history freeze. File membership and
byte identity do not replace scientific reception.

## Acquisition and judgments

`SessionBridge.java` acquires native observations. `adapter.py` manages actual
JVM lifetimes and input snapshots. `plans.py` defines the three executable
plans, and the existing `contract_runtime` interpreter runs each action and
derives stage judgments. The adapter contains no payload-membership predicate
or scientific verdict. `analyze.py` derives the separately declared paired
comparisons after acquisition.

Each source obligation checks its prepared input/context, stable endpoint
versions, completed enumeration and intended-payload membership. Revisit also
requires successful first-A recovery and completion of the intervening request.
B's source failure is recorded independently rather than being mistaken for
an A-revisit failure. A coherent change of the input context makes the relevant
claim inadmissible; a contradictory or malformed record is a separate reception
failure.

The primary attribution of a different intervening request requires successful
AA and every A-source/revisit in AAA in the same lifetime, an admitted ABA loss,
and stable matching P controls. This associates a result with the whole request
and its authorized context. It does not identify a particular field as its cause.
Typed candidate sequence, multiset and set differences are descriptive.

Before and after each call, the study captures target JAR, original JAR,
generated GTW key, and present or absent target/original `.smconfig` files.
The original filename conventions remain intact. Snapshot blobs retain exact
bytes without duplicating identical observations. This is an endpoint
observation, not atomic-read attestation.

The process environment is explicitly limited to a fixed PATH, C.UTF-8 locale
and UTC time zone. Ambient Java option/classpath injection variables are not
inherited. SandMark's global PRNG starts at zero once per JVM; the harness does
not reseed between requests. Algorithm-internal behavior, including QP's
key-based reseeding, remains unchanged. GraphList is cleared before each request
as in the shipped GUI.

Limits are 512 MB JVM heap, 10,000 candidates, 30 seconds for startup, 30 seconds
for each request after readiness, and 5 seconds for shutdown. The three
lifetime arms use the same bounds. A failed request stops the remaining word;
the harness never restarts a persistent JVM and calls it the same session.
Completed iterator returns and later shutdown failures are reported separately.
The limits are acquisition bounds, not an end-user performance guarantee.

## Run in a new directory

Run these commands from `artifact/`. Use a JDK with `jdk.compiler`; the native
study records the actual Java executable, module image, version and compiled
helper identities. The retained setup uses OpenJDK 21 on Linux. Up to four
independent cells run concurrently, with each cell's arm/history order preserved
and reversed in pass 2. Reduce `--workers` on a smaller machine.

Acquire the original tool using the existing pinned acquisition procedure and
retain its license notices:

```sh
python3 -B external_sandmark/acquire.py --destination /absolute/path/to/sandmark-cache
```

The `--baseline` argument is the unpacked project containing the retained
`artifact/results/external-sandmark/formal-01` data. The new run directory must
be outside that baseline. Freezing copies only the required input capsules and
producer snapshots; recognition never receives the frozen baseline files as
writable targets.

```sh
python3 -B decoder_sessions/run.py freeze \
  --baseline /absolute/path/to/unpacked-project \
  --tool /absolute/path/to/sandmark-cache/sandmark.jar \
  --output /absolute/path/to/new-session-run \
  --kind formal --workers 4
python3 -B decoder_sessions/run.py run --output /absolute/path/to/new-session-run
python3 -B decoder_sessions/analyze.py --run /absolute/path/to/new-session-run
```

Freezing binds the protocol, exact frame and plans, input capsules, helper,
producer source, native tool, and runtime before acquisition. An existing or
interrupted run cannot be silently resumed or overwritten. A source change
requires a new run directory. The unused two-history formal freeze is explicitly
superseded and cannot be executed through the current runner.

Pilot histories and the startup-failure controls are documented in
[PILOT-HISTORY.md](PILOT-HISTORY.md). They are excluded from the formal frame.
The startup controls deliberately omit the helper class while starting a real
JVM; they check unavailable-observation handling and perform no watermark
recognition. The original SandMark copyright and ANTLR notices remain those
provided in `external_sandmark/licenses/` and are not replaced by this module.

## Interpretation

Stable admitted results provide evidence for short sequential reuse on these
archived inputs. They do not prove arbitrary-history safety, thread safety,
current industrial prevalence, or an oracle-expressibility advantage over
existing testing frameworks. Existing source failures remain source failures
unless the new controls distinguish an additional lifecycle effect. The
formal result and independent reception reports are the basis for any measured
conclusion; frame arithmetic and pilot observations are not substitutes.
