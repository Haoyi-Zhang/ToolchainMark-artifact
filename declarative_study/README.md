# Native studies driven by executable JSON contracts

This directory contains the reference ELF and LLVM adapters, JSON plans, frozen
study definitions, native acquisition driver, and retained-evidence verifier
for the six current studies. `contract_runtime` executes each plan's operations and
evaluates its stage obligations. The adapters perform native work and return
typed observations; the scientific gates and predicates remain in plan data.

All commands below start in the extracted **artifact directory**. They use
relative package paths and do not require the original machine's directories.

## Quick retained-data check

The 36-case declaration study is a small complete native frame whose retained
observations can be checked without compilers or third-party Python packages:

```sh
python3 -B -m declarative_study.verify \
  --data results/declarative/declarations
```

To check all six supplied studies:

```sh
for study in reference declarations identity state state-baseline llwm; do
  python3 -B -m declarative_study.verify \
    --data "results/declarative/$study"
done
```

The verifier uses only Python's standard library and retained data. It does not
execute native programs. It checks the frozen source copies, exact ordered case
and receipt domains, case inputs, declared plans, independent receipt semantics,
process/return bindings, and referenced file versions. It also reconstructs the
ELF representation observations used by the destructive and state checks using
a separate byte parser. For the legacy comparison arm, it checks retained byte
bindings and consistency of the stored primary-result summary; the independent
contract interpretation applies to the new interpreter receipts.

The printed report contains `status`, `study`, `counts`, `unique_blobs`,
`repeated_case_comparisons`, `repeated_semantic_differences`, and `scope`.
`status: PASS` describes successful verification of the record, even when some
scientific obligations are inconsistent or inadmissible. `--data` is required;
there is no default study. Optional `--report PATH` writes the same report to a
new location. Keep such reports outside the supplied frozen result directories.

## Six formal frames and their denominators

Every count below includes both recorded passes. A case is one interpreter
receipt; a receipt may contain several independently evaluated obligations.

| Study / supplied directory under `results/declarative/` | Complete frame | Interpreter receipts | Stage obligations |
| --- | --- | ---: | ---: |
| `reference` | 3 carriers × 25 implementations × 14 relations × 2 passes | 2,100 | 3,000 |
| `declarations` | 6 plan variants × 3 carriers × 2 passes | 36 | 42 |
| `identity` | 2 controlled behaviors × 3 carriers × 2 passes | 12 | 12 |
| `state` | 121 suffix words × 6 controlled behaviors × 3 carriers × 2 passes | 4,356 | 4,356 |
| `state-baseline` | 15 fixed checks × 6 controlled behaviors × 3 carriers × 2 passes | 540 | 756 |
| `llwm` | 2 source variants × 3 interfaces × 5 payloads × 3 optimization settings × 2 passes | 180 | 720 |

Together these directories contain 7,224 interpreter receipts and 8,886 stage
judgments. The reference and identity studies additionally execute the frozen
earlier handler in a separate native arm for every case. Their legacy executions
are not additional interpreter receipts. Arm order is reversed in pass 2.
The generated-word and fixed-catalog studies have different request budgets;
their inconsistency counts are not an equal-cost performance comparison.

SandMark's 156 receipts and 1,248 obligations are a separate native study under
[external_sandmark](../external_sandmark/README.md). The
[CTF comparison](../ctf_comparison/README.md) uses all seven studies' 7,380
receipts and 10,134 obligations as shared observations. CTF evaluation and its
API rerun add no native samples. Earlier retained studies and the separate SandMark
follow-ups retain their own denominators.

### Catalog migration, plan changes, and artifact identity

The reference frame uses `hosts/H01-gcd.c`, the `string`, `symbol`, and `section`
carriers, CLEAN plus M01--M24, and MR01--MR14. The two native arms agree on all
2,100 primary judgments: 1,514 satisfied, 474 inconsistent, and 112 inadmissible.
This tests migration of a controlled catalog onto the interpreter. It does not
estimate how often these faults occur in deployed products.

The declaration frame changes only plan data with the same acquisition adapter:
the baseline request, a different literal payload, a reversed predicate, a false
relocation guard, two GCC compiler branches, and sequential builds. The last
variant removes the staging-rendezvous actions and flattens the MR12 parallel
block. The receipts expose changed requests, actual skipped work, and changed
group structure, as well as the resulting judgments.

The identity frame compares CLEAN with a controlled `replace-on-B` behavior.
The latter replaces the first target while the second object is being read.
All six changed-target cases are inadmissible under the current MR13 identity
requirements, while the earlier handler reports inconsistency. All six unchanged
controls are satisfied in both arms. The added premise concerns observed target
versions; it does not establish an atomic decoder read.

### Bounded state exploration

`state_words.py` generates every suffix of length zero through four over
`A+`, `A-`, and `B+`: 1 + 3 + 9 + 27 + 81 = 121 words. Every case starts with
an `A+` source check, has a fresh decoder session, and then executes one complete
suffix without resets. `A+` and `B+` request the correct key on two different
artifacts; `A-` requests a distinct incorrect key on the first artifact.
The declarations permit ordinary decoder reuse and exclude an intentional
lockout policy.

The six behaviors are CLEAN, four explicit wrong-key rejection latches, and a
cross-object cache. These are controlled targets defined in `state_words.py`;
they are not newly discovered external defects. A latch activates after its
declared count of wrong-key rejections and then rejects subsequent requests.
The bounded words expose latches 1--3 and the cross-object behavior. Latch 4
needs four wrong-key requests followed by a correct request, beyond the declared
suffix depth, and remains undetected. The full word frame yields 3,468 satisfied
and 888 inconsistent judgments, with no inadmissible cases.

The separate fixed-check frame executes MR01--MR14 plus the existing SR01 on
the same six targets. Its 540 primary judgments comprise 528 satisfied and
12 inconsistent results. SR01 exposes latch 1; MR13 exposes the cross-object
cache. Exhaustiveness is restricted to the listed alphabet, depth, inputs, and
controlled targets. Neither frame establishes coverage of arbitrary decoder
states or longer request histories.

### Published LLVM implementation and the retained tool failure

The LLVM frame newly executes the acquired SemaCall `atoi` and `fgets`
interfaces and the SideData string interface through this common interpreter.
The acquired upstream source and a local literal-output repair are crossed with
payloads `ABCD`, `A%%B`, `%%AB`, `AB%%`, and `%%%%`, optimization settings `O0`,
`O2`, and `Os`, and two passes. The key is `1234`; the declared ordinary input is
`4321`. Acquisition provenance, source notices, and the six-line repair are in
[external_llwm](../external_llwm/README.md). Its older confirmation results are
separate from this new frame.

ER01 checks literal payload output; ER02 checks ordinary host output. ER03
checks artifact-only relocation after source validity and observed byte
identity. ER04 checks debug stripping after source validity and an observed
debug-removal postcondition. All four predicates are in `plans/LLWM-*.json`.
The producer reuses the original plugin build helper, not the earlier script's
classification function.

ER01 has 72 upstream percent-payload inconsistencies, 18 satisfied upstream
plain-payload controls, and 90 satisfied repaired cases. All 180 ER02 host
checks are satisfied. A real `OSError` with errno 26, `Text file busy`
(`ETXTBSY`), occurred while invoking the relocated program in
`pass-2/literal-output-repair/atoi/payload-1/Os` (`A%%B`). The `moved-key` action
is retained as unavailable and ER03 is inadmissible; ER01, ER02, and ER04 remain
satisfied in that case. The event was not retried or replaced in the recorded
frame. Across all 720 stage judgments, the counts are 503 satisfied,
72 inconsistent, and 145 inadmissible.

The verifier reports one repeated semantic difference for that paired
configuration. Repeatability is therefore not reported as universal agreement
of all current cases. Native binaries and IR may also vary because of the upstream
embedding's random choices and build paths; file-byte equality across complete
runs is not the repetition criterion.

## Re-execute into new directories

### Native prerequisites

Use Linux x86-64 with Python 3.11 or later; the recorded Python version is
3.12.14. The reference studies require `gcc`, `clang`, `nm`, `objcopy`,
`readelf`, and `strip` on `PATH`, a C library development environment, and a
filesystem that permits executing the generated ELF files. The recorded tools
were GCC 14.2.0, Clang 19.1.7, and GNU binutils 2.44. H01 uses the standard C
library. The driver records resolved executable paths and SHA-256 identities in
`environment.json` and native command records; that file is not a package
installer or a comprehensive version probe.

The reference compiler command uses `-std=c11 -fno-ident -no-pie` and the
declared optimization. Baseline builds request GCC and `O2`; individual plans
also request other settings. Native pipeline timeouts are 20 seconds for a
build, 5 seconds for a host invocation, and 5--20 seconds for the recorded GNU
tool operations. The MR12 staging rendezvous has a 20-second wait bound.

For the LLVM frame, additionally install a mutually compatible LLVM **17**
toolchain containing `clang`, `opt`, `llvm-config`, development headers, and
libraries; Eigen 3 headers; GNU `patch`; and `g++` on `PATH`. The measured LLVM
version is 17.0.6 and the C++ compiler is g++ 14.2.0. The LLVM directory must
contain those unversioned executable names. Make its shared libraries resolvable
before starting acquisition. The current runner accepts explicit LLVM and Eigen
paths; its helper obtains build flags from `llvm-config` rather than installing
or discovering a compatible LLVM release for the user.

The LLVM adapter and its plugin build helper use these steps:

- Frontend: `clang -O1 -g -emit-llvm -S` to produce the original IR.
- Plugin setup: `g++ -shared -fPIC -O2`, the vendor and Eigen include directories,
  and the flags returned by `llvm-config --cxxflags --ldflags --libs`.
- Embedding: `opt -load-pass-plugin=... -passes=semacall-watermark` or
  `-passes=sidedata-watermark`, with the declared interface key and payload.
  The `fgets` interface uses the upstream `gets` option prefix.
- Linking: `clang -g` with `-O0`, `-O2`, or `-Os` for both unmarked and marked IR.
- Debug observation/removal: `readelf -W -S` and `strip --strip-debug -o`.

LLVM native commands have a 45-second timeout. Executed probe programs receive
`PATH=/usr/bin:/bin` and `LC_ALL=C`; `fgets` receives its input plus newline on
stdin, while the other interfaces receive an argument. Exact argv, stdin,
stdout, stderr, and availability are retained.

### Commands

Each invocation creates its destination and refuses an existing directory.
It freezes the protocol, frame, and producer source copies before acquisition,
executes both passes, checks that producer inputs remain unchanged, and writes
the final summary. It does not resume an interrupted run. Keep an incomplete
run and choose another new directory for a fresh attempt.

For all five reference-interface frames, using the recorded case-worker counts:

```sh
for study in reference declarations identity state state-baseline; do
  case "$tm_v6_study" in
    reference|state) tm_v6_workers=4 ;;
    *) tm_v6_workers=2 ;;
  esac
  python3 -B -m declarative_study.run \
    --study "$tm_v6_study" \
    --out "../reruns/declarative-01/$tm_v6_study" \
    --workers "$tm_v6_workers"
  python3 -B -m declarative_study.verify \
    --data "../reruns/declarative-01/$tm_v6_study"
done
```

For LLVM, adjust the conventional dependency locations to the installed
toolchain and headers:

```sh
python3 -B -m declarative_study.run \
  --study llwm \
  --out ../reruns/declarative-01/llwm \
  --workers 2 \
  --llvm-bin /usr/lib/llvm-17/bin \
  --eigen-include /usr/include/eigen3

python3 -B -m declarative_study.verify \
  --data ../reruns/declarative-01/llwm
```

`--workers` defaults to 4 and controls concurrent study cases. The recorded
reference and state runs used 4; declarations, identity, state-baseline, and
LLVM used 2. The interpreter's within-plan parallel groups are a separate
setting. Optional `--pilot-limit N` acquires only the first N entries of the
ordered frame and marks the result as `purpose: pilot`. Such a prefix may
contain only part of the first pass and is not a complete formal study.
The runner has no `--cxx` argument; plugin setup resolves `g++` from `PATH`.

## Record layout and verification boundary

| File or directory within a run | Contents |
| --- | --- |
| `protocol.json`, `frame.json` | Copied study definition and exact ordered case frame. |
| `producer-freeze.json`, `source-snapshot/` | Pre-execution source identities and retained source bytes. |
| `environment.json` | Python, case-worker count, pilot/formal purpose, and selected executable identities. |
| `cases/<case-id>/plan.json`, `receipt.json` | Actual plan and `toolchainmark-execution-v1` receipt. |
| `cases/<case-id>/case.json` | Derived primary verdicts, action-status counts, command count, and elapsed time. |
| `cases/<case-id>/legacy.json` | Separately executed earlier-handler result, only in reference and identity comparisons. |
| `blobs/<sha256>.bin.gz` | Content-addressed captured file versions, compressed with a fixed gzip timestamp. |
| `cases.json`, `summary.json` | Ordered case summaries, per-pass counts, and recorded legacy primary differences. |
| `setup/` in LLVM runs | Original/repaired build trees, plugins, source/output identities, and setup command records. |

Within action evidence, a `process` record contains argv, cwd, executable
identity, input/output bytes in hexadecimal, completion or unavailability,
return code, and file captures before and after the command. A `file-capture`
binds a path to retained bytes. A `python-return` binds a reference extractor's
typed return to the particular artifact, key, session, and endpoint captures.
The reused LLVM setup helper records its command streams in Base64; these setup
records are distinct from the action-level hexadecimal process records.

Original absolute paths identify the acquired call and file role. Retained byte
objects are resolved relative to the selected run, so the original absolute
directories need not exist for verification. The runtime
[README](../contract_runtime/README.md),
[interface](../contract_runtime/ENGINE_DESIGN.md), and
[receipt specification](../contract_runtime/RECEIPT_SCHEMA.md) define the plan,
status, expression, and obligation semantics.

The native verifier rechecks these saved bindings and independently interprets
the receipt; it does not rerun historical commands or attest to an untrusted
acquisition process. Before/after identities establish observed endpoints, not
atomic reads or absence of an intervening change followed by restoration.
