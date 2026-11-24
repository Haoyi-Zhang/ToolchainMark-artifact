# SandMark 3.4: archived-tool preservation study

This study executes the original SandMark bytecode watermarkers through their
published Java API. A small Java bridge records the original algorithms'
iterator results and exceptions. The shared
`contract_runtime` interpreter executes `plan.json` and evaluates its eight
declared obligations. `adapter.py` acquires commands and bytes and supplies no
verdicts or admission labels.

## Fixed implementation and acquisition

The implementation comes from the Qualitas archive mirror
`JavaQualitasCorpus/sandmark-3.4`, commit
`5e4642c83d802968cfa47c1a362fbecbd72f5802`. The original `sandmark.jar` SHA256 is
`8310d3c80cc8adf13ec46f217fc458462ebe89ae498ce23c1c714ab878fb2ea9`.
This is an archived research implementation, not a current maintained release.
The current `sandmark.cs.arizona.edu` site no longer supplies relevant SandMark
documentation and is not used as implementation evidence.

`acquisition-lock.json` binds the exact original tool, original TTT sample, ANTLR
2.7.7 distribution, and the extracted host/grammar inputs. `acquire.py` retrieves
and checks these bytes. The original tool JAR bundles a modified BCEL class, so
the study uses that JAR's own classes and does not substitute a newer BCEL.

The SandMark copyright permits noncommercial use subject to its notice terms;
it is not an unrestricted permissive license. The archive explicitly notes that
third-party components can carry separate restrictions. The tool JAR includes
BCEL, DynamicJava and JUnit. The deliverable therefore supplies fixed acquisition
instructions instead of redistributing the entire corpus or its unrelated
dependencies. Read `licenses/SANDMARK-COPYRIGHT.txt` and
`licenses/SANDMARK-README-CD-SRC.txt` before acquiring or reusing the tool.
ANTLR's original license is retained in `licenses/ANTLR-LICENSE.txt`; its Python
generator attribution must not be lost by calling the entire distribution
public domain. The original host and transformed research artifacts retain the
corresponding notices and are not presented as newly authored software.

## Population and actual application tasks

`algorithm-contracts.json` records the thirteen static algorithms listed by the
original CLI, with source URLs, hashes, payload/key domains, carriers and reading
scope. `study-frame.json` contains all 156 configurations:

- 13 algorithms;
- the original ANTLR 2.7.7 JAR and original TTT JAR;
- payloads `7`, `42`, and `1234`;
- two repetitions, seeding SandMark's shared PRNG with 0 and 1.

The key is `17`, except that Stern receives the payload as its verification
candidate. Stern is a candidate verifier, not a blind decoder or a wrong-key
rejection experiment. Other extractors return native candidate sequences; the
contract checks membership of the requested payload without asserting uniqueness.
Davidson/Myhrvold and Stern retain the original JAR auxiliary. The Graph
Theoretic Watermark keeps its default CRT mode and the generated key file.

ANTLR is the external application. It runs three official grammar-generation
tasks (`calc.g`, `expr.g`, and `java.g`), retaining generated files as well as
stdout, stderr and exit status. Relative grammar names keep generated comments
independent of arm directories. The TTT program is an official calibration
sample, not a second production application. Its actual `TTTGame` CLI runs
predeclared first-player-win, second-player-win and draw input sequences.

No algorithm is removed because of an unfavorable pilot. Missing PNG carriers,
reported embedding capacity failures, process failures, timeouts, source payload
inconsistencies, transformation postconditions, and host-output differences remain
distinct in the raw receipts. Neither original host contains a PNG. Steganography
therefore remains in the frame with a false carrier premise and skipped dependent
calls. Adding an image after observing that outcome would change the host.

## Contracts and observation boundaries

The identity obligation tests recovery on the original marked program.
Relocation copies every archive byte; ZIP repacking reverses entry order and
changes container metadata/compression while retaining every named entry byte.
Recovery under either transformation requires successful source recovery and an
observed transformation postcondition. Independent host obligations compare the
three actual application tasks even when a recovery obligation is unavailable.

Every extraction records target and auxiliary bytes before and after the API
call, including separate physical snapshots. Equal endpoints are the stated
observation; they are not an atomic-read guarantee. The receiver re-reads these
snapshots, all native API result files, command streams, grammar inputs and
generated outputs, and independently replays the data-only contract.

Tool exceptions and timeouts are unavailable observations, not observations of a
domain rejection. Their original exception class/message and command result
remain available for reporting capacity failures separately. A successfully
returned host process with nonzero exit status remains an observed host result.
At most two historical Java processes run concurrently. Fixed acquisition bounds
are 30 seconds per embed/extract call, 15 seconds per host task, a 512 MB Java
heap, and at most 10,000 extracted candidates. These are experimental resource
bounds, not performance or compatibility guarantees for other environments.

## Reproduction

Run from the artifact directory. Use a JDK whose `jdk.compiler` module is
available; the protocol freeze records the actual runtime and module bytes.
The study was qualified using OpenJDK 21.0.13 on Linux; a user-space conda-forge
`openjdk=21` environment is described in the top-level README ("External tools").
The Graph Theoretic Watermark draws its Blowfish key from OS entropy, outside
the seeded SandMark PRNG; to reproduce the retained embeddings, the top-level
README replays the retained keys through the JCA provider `GtwKeyReplay.java`
(`gtw-key-replay.security`), without changing SandMark or the bridge.

```sh
python3 -B external_sandmark/acquire.py --destination /absolute/path/to/sandmark-cache
python3 -B external_sandmark/run_study.py freeze --cache /absolute/path/to/sandmark-cache --output /absolute/path/to/new-run
python3 -B external_sandmark/run_study.py run --cache /absolute/path/to/sandmark-cache --output /absolute/path/to/new-run
python3 -B external_sandmark/verify_study.py --run /absolute/path/to/new-run
```

The freeze precedes native acquisition, retains a producer snapshot, and binds
the frame, plan, tool acquisition, runtime and bridge. Existing run directories
cannot be reused. An interrupted or invalidated run remains incomplete and must
not be silently resumed or merged with another run. `--pilot-cases` creates an
explicitly exploratory subset; verification requires `--allow-pilot` for it and
never reports it as a complete formal frame.

The bounded study measures archived-tool execution and declared preservation
relations. It does not measure present-day deployment prevalence, arbitrary
obfuscation resistance, every key/payload domain, or upstream-confirmed defects.
