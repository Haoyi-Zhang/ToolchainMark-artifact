# Validation

The implementation and the complete retained evidence have different resource
profiles, so the repository exposes two explicit validation modes.

## Core environment

```bash
python3 scripts/install_local.py .venv
.venv/bin/python -B scripts/validate.py --suite quick
```

The core environment exposes only this checkout and the Python standard library.
The quick suite executes 14 checks and reports the CTF API control as one explicit
skip when its scientific dependencies are absent. The executed controls include
148 core-model tests, 44 contract-runtime tests, 20 native-binding tests, 6
correspondence tests, 31 projection tests, 5 history tests, 7 state-budget tests,
8 GeMTest receiver tests, 5 ELF-observer tests, and 23 optimized-Python admission
tests, followed by command-line and native-acquisition smoke checks.

## Science environment

```bash
python3 scripts/install_local.py .venv-science --with-system-science
.venv-science/bin/python -B scripts/validate.py --suite quick
```

This mode records and verifies the base interpreter's NumPy, Pandas, and SciPy
versions. It executes all 15 quick checks, including 13 CTF API controls. No
packages are downloaded by the installer.

## Complete evidence

After importing the separate evidence object into a disposable checkout:

```bash
.venv-science/bin/python -B scripts/validate.py --suite full --timeout 7200
```

The full suite invokes nine receiver entry points: correspondence, projection,
history, state budget, GeMTest, CTF, decoder sessions, LLVM, and SandMark. Each
child runs in its own process group and writes ordinary output files. A timeout
terminates the group, preventing a descendant from keeping a captured output
pipe open.

The current complete-evidence run receives 24 correspondence records and 72
layer decisions; 7,380 source receipts and 10,134 projected targets; 12 paired
history controls and 24 native traces; 900 state-budget cases; 384 GeMTest pairs;
7,380 CTF cases and 10,134 stage comparisons; 2,808 decoder-session words; the
180-case LLVM matrix; and 156 SandMark configurations with 1,248 obligations.
All nine receivers return PASS. These are record-reception results at the
evidence level stated by each study, not a claim that every external native
program was rerun in the validation environment.
