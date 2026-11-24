# Reviewer guide

The package separates implementation review from the larger retained-evidence
audit. A normal source checkout remains small; the separate evidence object
contains the active complete datasets used by the nine full receivers.

## 1. Review the self-contained implementation

```bash
python3 scripts/install_local.py .venv
.venv/bin/python -B scripts/validate.py --suite quick
```

This core environment registers only the checkout and the standard library. It
runs repository, syntax, model, runtime, native-binding, correspondence,
projection, history, state-budget, GeMTest, ELF-observer, optimized-Python,
command-line, and native-acquisition checks. The CTF control is reported as an
explicit skip because its scientific dependencies are intentionally absent.

## 2. Exercise the scientific API path

```bash
python3 scripts/install_local.py .venv-science --with-system-science
.venv-science/bin/python -B scripts/validate.py --suite quick
```

The installer performs no download. It records the NumPy, Pandas, and SciPy
versions and approved site-package roots. The environment verifier rejects a
changed dependency set, external `PYTHONPATH`, user-site imports, or an
environment created for another checkout.

## 3. Receive the complete evidence

```bash
tar --zstd -xf ToolchainMark_evidence.tar.zst
python3 scripts/import_evidence.py \
  --source /path/to/extracted/artifact \
  --destination /path/to/disposable/ToolchainMark \
  --link --replace
cd /path/to/disposable/ToolchainMark
python3 scripts/install_local.py .venv-science --with-system-science
.venv-science/bin/python -B scripts/validate.py --suite full --timeout 7200
```

The full suite receives correspondence, per-obligation projection,
request-history, state-budget, GeMTest, CTF, decoder-session, LLVM, and SandMark
records. Every child command writes to a regular log file and runs in a distinct
process group. A timeout terminates the entire group.

The evidence archive (DOI 10.5281/zenodo.24491149; file name, SHA-256 and
unpack location in the top-level README) is 145 MB compressed and 4.6 GB after
extraction. The full run is CPU- and metadata-intensive. On the five-core Linux
validation machine used for this package, projection took about four minutes and
decoder-session reception about one minute; the remaining receivers completed
in under half a minute each. Times depend on storage and processor speed.

A retained-record PASS means that the supplied commands, bytes, observations, and
declared judgments satisfy that receiver. It is not a new acquisition of an
external program and does not by itself constitute external-team reproduction.
