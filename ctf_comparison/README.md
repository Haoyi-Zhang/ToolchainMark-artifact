# Real CTF comparison on shared observations

This module runs the unmodified `CausalTestCase.execute_test` entry point of the
official Causal Testing Framework (CTF), pinned to commit
`7ab4da9fc60ea9ee43b48963a5953fca3840c75d`. `UPSTREAM.json` binds the original
archive and the 37 copied package, license, and project-metadata files. The
complete `causal_testing` package directory is retained; upstream repository
tests and documentation are not copied. The code is licensed under the included
original MIT license. The tested version is identified by commit, not an assumed
equivalence with the PyPI 16.0.0 distribution.

## Question and execution path

The comparison asks whether another extensible testing framework can produce
the same stage judgments from the same observations and declared predicates.
It uses CTF's real custom `Estimator` and `CausalEffect` interfaces:

1. Read a completed native receipt and its exact JSON plan. Project the receipt
   to input values and each action's identifier, operational status, and raw
   returned value. Drop the framework's guards, gate evaluations, dependencies,
   predicate evaluations, and scientific judgments.
2. For each declared stage obligation, the custom `ExactObservationEstimator`
   evaluates its requirements using independently implemented expressions. If
   any requirement is false, unknown, or ill typed, it raises a dedicated
   `ValueError` subclass. The official CTF error-handling branch returns
   `INESTIMABLE` when `suppress_estimation_errors=True`.
3. Otherwise the estimator returns a real `EffectEstimate` with a three-field
   observation vector: inputs, action observations, and earlier CTF judgments.
   The custom `DeclaredPredicate.apply` evaluates the declared predicate.
   CTF assigns `PASS` or `FAIL`; an unavailable or ill-typed predicate again
   reaches its official `INESTIMABLE` branch.
4. Continue all obligations, computing dependencies from CTF's own previous
   outcomes. Only after the complete CTF computation compare its mapped outcomes
   with the stored ToolchainMark judgments.

The fixed mapping is `PASS → SATISFIED`, `FAIL → INCONSISTENT`, and
`INESTIMABLE → INADMISSIBLE`. The exact-data extension deliberately computes no
causal effect, regression estimate, confidence interval, or population claim.
This is a real CTF extension comparison, not a comparison with its stock causal
inference estimators. Equal classifications show that the same information and
predicates do not provide an exclusive detection advantage to ToolchainMark.

`expressions.py` was independently implemented from the declared language and
imports neither the ToolchainMark executor nor its receiver or adapters. Native
observations are shared. This comparison does not acquire another execution,
re-read binaries, or replace the independent native evidence receiver. Those
acquisition and validation costs remain common to both interpretations.

## Reproduce

Run these commands from the `artifact` directory. The retained-record check
requires Python 3.12 and its standard library only:

```bash
python3 -B -m ctf_comparison.verify
```

The default target is `results/ctf-comparison/formal-01`. To inspect a different
retained run, use `--run PATH`. This check validates source snapshots, exact
native case frames, receipt and plan identities, all recomputed gate/predicate
outcomes, and summary denominators. It uses the comparison's custom expression
implementation and does not itself prove that CTF executed.

To execute the actual CTF API, first create an environment with the recorded
runtime dependencies. This imports the vendored source without modifying it;
the full distribution's optional estimator and dashboard dependencies are not
needed for the exercised API.

```bash
python3 -m venv /tmp/toolchainmark-ctf
/tmp/toolchainmark-ctf/bin/python -m pip install -r ctf_comparison/requirements-runtime.txt
/tmp/toolchainmark-ctf/bin/python -B -m unittest discover -s ctf_comparison/tests -p test_ctf.py -v
/tmp/toolchainmark-ctf/bin/python -B -m ctf_comparison.verify --rerun-ctf
```

A fresh comparison consumes complete native datasets already acquired by the
declarative study. It does not rerun the programs under test. Supply every
dataset being compared and a new output directory beneath `artifact`:

```bash
/tmp/toolchainmark-ctf/bin/python -B -m ctf_comparison.run \
  --purpose formal \
  --data results/declarative/reference \
  --data results/declarative/declarations \
  --data results/declarative/identity \
  --data results/declarative/state \
  --data results/declarative/state-baseline \
  --data results/declarative/llwm \
  --data results/external-sandmark/formal-01 \
  --out results/ctf-comparison/fresh-01
/tmp/toolchainmark-ctf/bin/python -B -m ctf_comparison.verify \
  --run results/ctf-comparison/fresh-01 --rerun-ctf
```

The retained formal comparison uses these seven complete datasets. The runner
also accepts other completed datasets following either retained frame protocol.
Declaration, identity, and request-word studies remain separate named strata.
`--purpose formal` rejects native pilot datasets. A native study's two passes
remain explicitly tagged in `by_native_run`; they are not claimed to be
independent software populations.

## Retained records and costs

Before invoking CTF, `run.py` freezes its source files, the pinned upstream
source, exact case frame, plan/receipt hashes, and native dataset manifests.
`cases.jsonl` records actual official outcomes, independently evaluated gates
and predicates, estimator/oracle call counts, and the observation-vector hash.
The vector serialized by CTF is represented by its components and hash because
the raw inputs and action values are already retained in the bound native
receipt. This is a documented projection of the actual CTF result.

`environment.json` records real module origins, source hashes, the commit, and
runtime package versions. `complete.json` is written only after every source
and input binding is checked again. Changes during measurement leave an
incomplete directory rather than replacing retained results.

`source-surface.json` reports bytes, physical lines, and lines remaining after
blank/full-line `#` or `//` comments are removed. Docstrings, block comments,
and continuation lines count.
It separates the interpreter, native adapters, evidence receiver, and custom
CTF judgment and reporting code. `plan-surface.json` reports actual input
declarations, operation kinds, guards, parallel groups, stage obligations, and
required gate expressions. These are auditable implementation sizes. They do
not measure development hours, difficulty, adoption cost, or maintenance gains.

The tests use the real upstream classes and include false, unknown, and
ill-typed gates; unavailable tool results versus typed domain rejection;
independent obligations after a failure; exact JSON type boundaries; and
controls that corrupt all supplied framework judgments while preserving the
raw observations. Malformed comparison input is an invalid record, separate
from CTF's scientific `INESTIMABLE` result.
