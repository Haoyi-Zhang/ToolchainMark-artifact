# ToolchainMark

Research artifact for the paper *Execution Correspondence for Metamorphic Tests
of Software Watermark Toolchains* by Haoyi Zhang, Huaijin Ran, Xunzhu Tang and Kisub Kim (submitted to ACM TOSEM).

ToolchainMark checks whether a metamorphic-test judgment is supported by the
execution it names. It separates four questions that are often collapsed:

1. Does the retained record conform to the declared plan?
2. Can the scientific verdict be reconstructed from primitive observations?
3. Are those observations bound to the native commands and artifact bytes named
   by the record?
4. Does the record preserve request history that can affect a stateful tool?

This repository contains the implementation, native C host fixtures, separate
receiver implementations, positive and negative controls, compact reference
records, and experiment entry points. The complete retained evidence (145 MB
compressed, 4.6 GB extracted) is a separate object; see
[Complete evidence](#complete-evidence-separate-download).

## Repository layout

| Path | Content |
| --- | --- |
| `src/toolchainmark/` | Relation, admission, observation, and trace implementation; CLI |
| `tests/` | Core model tests (148) |
| `hosts/`, `specs/` | 18 C host programs; relation and mutant (operator) catalogs |
| `contract_runtime/` | Typed plans, execution semantics, receipt reception |
| `declarative_study/` | Native acquisition and reception (reference, state, identity, LLVM studies) |
| `evidence_correspondence/` | Layered predicate, plan, and native-binding checks |
| `evidence_projection/` | Per-obligation audit units and request-history controls |
| `state_budget/` | Fixed-order state-budget experiment and receiver |
| `framework_comparison/`, `ctf_comparison/` | GeMTest and Causal Testing Framework (CTF) comparisons |
| `decoder_sessions/` | Process and public-object lifetime controls |
| `external_llwm/`, `external_sandmark*/`, `external-transfer/` | External-tool drivers, receivers, source boundaries, license notices |
| `postfreeze_challenge/`, `recovery_extension/` | Post-freeze challenge and SR01 recovery extension |
| `independent_observers/` | Independent ELF observer |
| `results/` | Compact retained records and fixtures (not the complete evidence) |
| `scripts/` | Environment creation, validation, evidence import, derivation scripts |
| `docs/` | Architecture, evidence levels, reviewer guide, validation notes |

## Requirements

- Linux x86-64 (tested: Ubuntu 24.04 under WSL 2). macOS and native Windows are
  not supported for the compiler-dependent checks (they need GNU binutils, POSIX
  paths, and shell scripts); use Linux or WSL.
- Python 3.11 or newer (tested with 3.12.3). The core checks use only the
  standard library.
- GCC and Clang, GNU `binutils` (`readelf`, `objcopy`, `strip`), `make`.
- Development headers and libraries for hosts H13-H18: zlib, OpenSSL, SQLite,
  libxml2, json-c, libpng.
- Optional, for the CTF comparison: NumPy 2.3.5, Pandas 2.2.3, SciPy 1.17.0
  (`requirements-science.txt`).
- Hardware: any recent x86-64 machine; no network access is needed at run time.
  Disk: about 20 MB for this repository; 145 MB for the evidence archive and
  4.6 GB for its extracted contents (hard-linked, not copied, on import).
- Optional, only for new LLVM/SandMark acquisitions: LLVM 17 with Eigen 3 and
  a JDK 21 (see [External tools](#external-tools-new-llvm-and-sandmark-acquisitions)).

## Installation (Ubuntu/Debian)

```bash
sudo apt-get install -y python3 python3-venv make gcc clang binutils \
  zlib1g-dev libssl-dev libsqlite3-dev libxml2-dev libjson-c-dev libpng-dev

# Core environment (standard library only; registers this checkout).
python3 scripts/install_local.py .venv

# Optional science environment for the CTF control. install_local.py never
# downloads packages; it reuses the NumPy/Pandas/SciPy of the interpreter that
# runs it, so first create a base interpreter that has them.
python3 -m venv ../tm-science-base
../tm-science-base/bin/pip install -r requirements-science.txt
../tm-science-base/bin/python scripts/install_local.py .venv-science --with-system-science
```

### Without root: compilers and libraries from conda-forge

If `apt-get` is not available, install Clang and the H13-H18 headers and
libraries in user space with the static `micromamba` binary (tested with
micromamba 2.10.0, Clang 23.1.6, libxml2 2.15.4) and expose them to the build through
the standard compiler search variables. GCC and binutils still come from the
system; the environment's directory is appended to `PATH`, not prepended.

```bash
mkdir -p ~/deps/toolchainmark && cd ~/deps/toolchainmark
curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest | tar -xvj bin/micromamba
MAMBA_ROOT_PREFIX=$PWD/mamba bin/micromamba create -y -p $PWD/env -c conda-forge \
  clang zlib openssl sqlite libxml2 libxml2-devel json-c libpng zstd
cd -   # back to the repository root

export TM_DEPS=~/deps/toolchainmark/env
export PATH=$PATH:$TM_DEPS/bin
export CPATH=$TM_DEPS/include:$TM_DEPS/include/libxml2
export LIBRARY_PATH=$TM_DEPS/lib LD_LIBRARY_PATH=$TM_DEPS/lib
```

Keep these variables set in the shell that runs the checks below. `zstd` is
also needed to unpack the complete evidence.

`make install` and `make install-science PYTHON=../tm-science-base/bin/python`
wrap the two `install_local.py` calls. The validator rejects an external
`PYTHONPATH`, user-site imports, a changed dependency set, or an environment
created for another checkout.

## Quick check (about 1 minute)

```bash
.venv-science/bin/python -B scripts/validate.py --suite quick   # or: make check (core env)
```

The quick suite runs repository hygiene, source syntax, the core model tests,
contract runtime, native binding, record correspondence, evidence projection,
history, state budget, GeMTest reception, CTF API (13 tests; reported as SKIP in
the core environment, never as a pass), ELF observer, optimized-Python
admission, the CLI, and a small native acquisition followed by reception.
Expected output: one `[PASS]` line per step and
`validation-logs/quick-status.json` with `"ok": true`. The suite stops at the
first failing step.

## Reproducing the paper results

All commands run from the repository root with the core environment unless
noted. Outputs go to `reruns/` or `validation-logs/` (both git-ignored); saved
results under `results/` are never overwritten.

| Paper result | Command | Expected output | Runtime |
| --- | --- | --- | --- |
| Admission study (supplement): 18,900 rows; 756 clean satisfied; 972 stage-isolation; 17,172 active = 11,898 / 4,266 / 1,008; 69/72 design and 1,242/1,296 expanded units exposed; 207,900 rerun comparisons with 0 differences; bootstrap median suite size 9, 1,884 perfect replicates of 10,000, minimum 60.0% | `make reproduce-admission` | `reruns/admission-study/derived/`: `scientific_checks.json` and `rerun_comparison.json` report `PASS`; `summary.json` and `bootstrap_summary.json` contain the listed counts | ~5 s |
| Admission denominators and 378-row utility partition (read-only accounting) | `make verify-science` | JSON with `"verdict": "PASS"` (18 checks) | ~5 s |
| Correspondence challenge (main paper): 6 valid records accepted by all layers; of 18 contradictions, predicate replay rejects 1, plan reception 8, native binding 18 | `.venv/bin/python -B -m evidence_correspondence.verify` | JSON with `"verdict": "PASS"` and these layer counts | ~2 s |
| Request-history control (main paper): 6 faulty-decoder judgments change, 24 artifact pairs byte-identical, 12 history-removed records rejected | `.venv/bin/python -B -m evidence_projection.verify_history` | JSON with `"verdict": "PASS"` | <1 s |
| Unit and receiver controls (148 + 44 + 20 + 6 + 31 + 5 + 7 + 8 + 13 + 5 + 23 tests) | `.venv-science/bin/python -B scripts/validate.py --suite quick` | `"ok": true` | ~1 min |
| 10,134 per-obligation projections, state budget, GeMTest, CTF, 2,808 decoder-session words, LLVM and SandMark matrices | `make check-full` (after attaching the complete evidence) | `validation-logs/full-status.json` with `"ok": true` (9 receivers) | ~6 min |

Set `PYTHONPATH=src:.` when calling a module with a plain interpreter instead
of an environment created by `install_local.py`. `docs/POSTFREEZE_RESULTS.md`
summarizes the post-freeze challenge and SR01 recovery-extension results, whose
records are also part of the complete evidence.

## Complete evidence (separate download)

The projection, state-budget, GeMTest, CTF, decoder-session, LLVM, SandMark,
post-freeze, and recovery-extension receivers need the separate evidence object,
deposited on Zenodo, DOI [10.5281/zenodo.24491149](https://doi.org/10.5281/zenodo.24491149):

| File | Size | SHA-256 |
| --- | --- | --- |
| `ToolchainMark_evidence.tar.zst` | 144,511,949 bytes (145 MB; 4.6 GB, 222,193 files extracted) | `f5777734925dfb2627628e48f6ad7a1e0708aebaf80b8ff8d4e24ea85fa4993c` |

It unpacks to a single `artifact/` directory holding `contract_runtime/` and
the complete datasets under `results/` (`declarative-v6`,
`evidence-correspondence`, `evidence-projection`, `state-budget`,
`framework-comparison`, `ctf-comparison`, `decoder-sessions`, `llwm-native`,
`external-sandmark`, `external-sandmark-arboit`, `external-sandmark-qp`,
`independent-observers`, `postfreeze-challenge`, `recovery-extension`).
Unpack it next to (not inside) the repository; `zstd` must be on `PATH`.
Without it, `make check-full` stops with `complete evidence is not attached`,
and those receivers report missing files; the checks in the table above that
do not mention the evidence run on a plain checkout.

Attach it to a disposable copy of the checkout. From the directory that
contains this repository (here called `artifact/`), `tm-science-base/`, and the
downloaded archive:

```bash
sha256sum ToolchainMark_evidence.tar.zst      # compare with the table above
mkdir tm-evidence
tar --zstd -xf ToolchainMark_evidence.tar.zst -C tm-evidence
cp -r artifact tm-disposable
rm -rf tm-disposable/.venv tm-disposable/.venv-science tm-disposable/validation-logs tm-disposable/reruns
python3 tm-disposable/scripts/import_evidence.py \
  --source tm-evidence/artifact --destination tm-disposable --link --replace
cd tm-disposable
make install-science PYTHON=../tm-science-base/bin/python
make check-full
```

`--link` hard-links the files, so `tm-evidence/` and `tm-disposable/` must be
on the same filesystem. In the same evidence checkout, the remaining retained
records are received with:

```bash
for study in reference declarations identity state state-baseline llwm; do
  .venv-science/bin/python -B -m declarative_study.verify --data results/declarative/$study
done
.venv-science/bin/python -B postfreeze_challenge/verify.py
.venv-science/bin/python -B recovery_extension/verify.py
.venv-science/bin/python -B external_sandmark/qp_diagnosis/verify.py
.venv-science/bin/python -B -m external_sandmark_arboit.verify
```

Each prints JSON with `"status": "PASS"` or `"verdict": "PASS"`.

Reception of a retained record verifies its declared commands, bytes,
observations, and judgments; it does not relabel an archived external execution
as a new native acquisition. See `docs/FULL_EVIDENCE.md` and
`docs/REVIEWER_GUIDE.md`.

## External tools: new LLVM and SandMark acquisitions

The receivers above need no external tool. New native acquisitions are
optional; both can be set up in user space with the `micromamba` binary from
the installation section (the LLVM upstream source is vendored in
`external_llwm/vendor/`; SandMark, its TTT sample, and ANTLR 2.7.7 are
downloaded and SHA-256-checked by `external_sandmark/acquire.py`; read
`external_sandmark/licenses/` first):

```bash
cd ~/deps/toolchainmark
MAMBA_ROOT_PREFIX=$PWD/mamba bin/micromamba create -y -p $PWD/env-llvm17 -c conda-forge \
  llvmdev=17.0.6 clang=17.0.6 clangxx=17.0.6 eigen patch gxx_linux-64=14.2 zlib zstd libxml2
MAMBA_ROOT_PREFIX=$PWD/mamba bin/micromamba create -y -p $PWD/env-jdk21 -c conda-forge openjdk=21
cd -   # back to the repository root

# LLVM 17 (LLWM SemaCall/SideData), ~1 min; the output directory must not exist
L=~/deps/toolchainmark/env-llvm17
LD_LIBRARY_PATH=$L/lib python3 -B external_llwm/run_study.py --out /tmp/toolchainmark-llwm-rerun \
  --llvm-bin $L/bin --eigen-include $L/include/eigen3 --cxx $L/bin/x86_64-conda-linux-gnu-g++
python3 -B external_llwm/verify_study.py --run /tmp/toolchainmark-llwm-rerun

# SandMark 3.4 (network access for acquire.py only), ~7 min. Run it in the
# evidence checkout (tm-disposable/): the three JDK_JAVA_OPTIONS settings replay
# the retained Graph Theoretic Watermark keys (see below).
export PATH=$PATH:~/deps/toolchainmark/env-jdk21/bin
R=/tmp/gtw-key-replay
javac -d $R external_sandmark/GtwKeyReplay.java
export JDK_JAVA_OPTIONS="-Xbootclasspath/a:$R -Djava.security.properties=$PWD/external_sandmark/gtw-key-replay.security -Dtoolchainmark.gtw.key.replay=$PWD/results/external-sandmark/formal-01/cases"
python3 -B external_sandmark/acquire.py --destination /tmp/sandmark-cache
python3 -B external_sandmark/run_study.py freeze --cache /tmp/sandmark-cache --output /tmp/sandmark-run
python3 -B external_sandmark/run_study.py run --cache /tmp/sandmark-cache --output /tmp/sandmark-run
python3 -B external_sandmark/verify_study.py --run /tmp/sandmark-run
unset JDK_JAVA_OPTIONS
```

A new acquisition is a new measurement, not the retained one. In the check
for this package (conda-forge LLVM 17.0.6 / g++ 14.2.0, OpenJDK 21.0.13), the
LLVM rerun reproduced all four judgment counts of the retained 180-case frame
(only the documented boundary-case outputs vary).

SandMark is deterministic given its seed except for one input the harness does
not control: the Graph Theoretic Watermark (GTW) draws a fresh Blowfish key
through `javax.crypto.KeyGenerator` (OS entropy, independent of the
`sandmark.util.Random` seed the bridge sets) and writes it to `gtw.key`. With a
fresh key, about 1 in 60 GTW embeddings ends in
`java.lang.ArrayIndexOutOfBoundsException` inside SandMark's `StackSimulator`
(observed for different configurations in different reruns). `GtwKeyReplay` is
a JCA provider used only for reproduction: it makes that `KeyGenerator` return
the key recorded in the retained case (`results/external-sandmark/formal-01/cases/<case>/embed/gtw.key`).
SandMark and the bridge are unchanged; the JVM prints
`NOTE: Picked up JDK_JAVA_OPTIONS` to each stderr. With key replay, all 11
retained GTW embeddings are reproduced with entry-for-entry identical
watermarked JARs and identical keys, and three complete reruns gave the same
156 configurations every time: 155 equal the retained ones, and `case-0057`
(GTW, ANTLR, payload 1234, seed 0) completes (8 SATISFIED; 1,012 / 228 / 8
satisfied / inadmissible / inconsistent obligations in total). Its retained
embedding did not fail in SandMark: it was killed by the frame's fixed 30-second
embedding timeout (return code -9 after 30.1 s) on the original host, where
ANTLR GTW embeddings took 21-30 s, while the same embedding with the same key
takes about 12 s here. That retained `UNAVAILABLE` outcome is a resource-bound
timeout and is only reproduced on hardware about as slow as the original. The
paper reports the retained matrices (1,004 / 236 / 8).

`scripts/audit_references.py` audits the manuscript's citations and needs the
LaTeX sources, which are not part of this repository; it prints
`"verdict": "SKIPPED"` when they are absent.

### Fresh post-freeze and SR01 campaigns

Both campaigns compile and run their native cases with GCC/Clang and the H13-H18
libraries (environment from the installation section). The destination must not
exist:

```bash
python3 -B postfreeze_challenge/launch.py --study postfreeze --out /tmp/toolchainmark-postfreeze-fresh   # ~5 min
python3 -B postfreeze_challenge/verify.py --fresh --data /tmp/toolchainmark-postfreeze-fresh
python3 -B postfreeze_challenge/launch.py --study recovery --out /tmp/toolchainmark-recovery-fresh       # ~15 s
python3 -B recovery_extension/verify.py --fresh --data /tmp/toolchainmark-recovery-fresh
```

A fresh campaign binds the current checkout (hosts, specifications, campaign
scripts, `src/toolchainmark/`, producers); the retained records stay bound to
their own source snapshots. In the check for this package (GCC 13.3, Clang 23.1)
all 8,100 post-freeze rows, the 84 distinction traces and all 540 SR01 rows
equalled the retained values in every non-timing field once compiled-binary
sizes and SHA-256 values were masked (the retained run used Debian GCC 14.2 /
Clang 19.1), and both rederived `summary.json` files were identical to the
retained ones except timings and the producer source-size measurement.

## Validation status of this package

Re-checked on 2026-11-24 from a fresh copy of this directory on Ubuntu 24.04
(WSL 2, Python 3.12.3, system GCC 13.3 and GNU binutils, no root access),
following this README literally with the conda-forge "Without root" setup.
Every command above exited with status 0: the quick suite in the core
environment (CTF reported as SKIP) and in the science environment (all 15
steps PASS, 13 CTF tests included), `make install`/`make install-science`/
`make check`, `make reproduce-admission`, `make verify-science`, the
correspondence and history receivers (counts as in the table), the evidence
import, `make check-full` (all 9 receivers PASS, about 5 minutes), the six
declarative-study, post-freeze, SR01, QP-diagnosis and Arboit receivers, the
fresh post-freeze and SR01 campaigns with their `--fresh` receivers, and the
LLVM and key-replayed SandMark re-acquisitions with their receivers (agreement
with the retained records as described under "External tools"). `make check-full` on a
checkout without the evidence stops as documented, and
`scripts/audit_references.py` reports `SKIPPED` because the LaTeX sources are
not included.

## License

Original code is MIT licensed (`LICENSE`). Third-party source, templates,
external research inputs, and generated derivatives retain their own terms;
see `THIRD_PARTY.md` and the license files in the vendored directories before
redistribution.
