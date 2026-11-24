# Live comparison with GeMTest

This study runs the same four watermark-testing protocols through two fresh
native acquisitions: the declarative contract executor and the published
GeMTest framework. The comparison tests whether GeMTest can express and execute
the same checks when given the same low-level operations and premises. It also
checks the actual framework outcomes and retained program bytes. The completed
study is in `results/framework-comparison/paired/`.

## Framework and integration

The comparison uses the installed `gemtest==1.0.1` package and its real pytest
plugin. The official project is <https://github.com/tum-i4/gemtest>; its public
API is described at <https://tum-i4.github.io/gemtest-doc/> and in Speth and
Pretschner's *GeMTest: A General Metamorphic Testing Framework*,
<https://doi.org/10.1109/ICSE-Companion66252.2025.00020>. The retained
`producer-freeze.json` records the observed package version and every enumerated
Python source file in the installed distribution's package tree. The corresponding 31
upstream files are retained under `source-snapshot/upstream/gemtest/`. These
observed installed files define the executed framework; a separately inspected
repository snapshot does not substitute for that identity.

`gemtest_cases.py` uses `create_metamorphic_relation`, exhaustive testing,
`valid_input`, `general_transformation`, `general_relation`, and
`system_under_test`. The `data_exporter` callback is invoked by GeMTest's own
reporting hook with `--export-data`. The required pytest-html plugin is installed
through `requirements.txt` so that the reporting hook is active.

The source-validity callback receives the completed **source output**. It checks
source recovery for MR08 and both source recovery and the physical carrier view
for MR09. MR13 and SR01 execute their request sequences before interpreting
their endpoint and state premises. The transformation callback returns the
follow-up requests, and the system-under-test callback performs the actual
native operations for each request. The relation callback evaluates the
manually written predicates over the resulting observations.

Late applicability uses GeMTest's public metamorphic-test-case error field:
the callback assigns `SkippedMTC` to `mtc.error` and returns `False`, after which
the framework's existing error path produces a pytest skip. This is an explicit
integration with that public error representation, not a separate advertised
late-validity decorator. In the executed implementation, `gmt.skip()` is caught
specially during transformation; calling it from a general relation instead
enters the relation-error path. An exploratory integration failure established
this distinction before the formal protocol was frozen. It is not counted as a
framework defect or a benchmark outcome.

## Shared information and independent checks

Both arms use `ReferenceAdapter` and the same low-level native pipeline. Each
arm creates a fresh adapter, decoder state, and native working directory. The
contract arm interprets the data-only plan. The GeMTest arm uses independently
written action orchestration and predicates in `native_callbacks.py`; that
module does not import the contract interpreter, its expression evaluator, or
either receiver. Both arms therefore share native acquisition code and the
chosen scientific premises, while their orchestration and judgments are
implemented separately.

This design isolates agreement in execution and interpretation. It does not
establish independence from a defect in the shared native adapter. The cases
use known controlled implementation conditions, one GCD host, fixed payloads
and keys, GCC at `-O2`, and six declared host inputs. The three carriers are
string, symbol, and section. These are not an estimate of unknown-fault
discovery or prevalence in external watermark tools.

## Fixed frame and observed results

The full frame contains 384 pairs and 768 fresh native arms. MR08 and MR09 each
cover the clean implementation and all 24 controlled operator identities, three
carriers, and two passes. MR13 and SR01 each cover seven declared state
conditions, three carriers, and two passes. The arm order is reversed in the
second pass. Repetition checks the same declared configurations; it does not
create additional independent defect mechanisms.

| Protocol | Paired configurations | Stage judgments per arm | Actual pytest outcomes |
| --- | ---: | ---: | --- |
| MR08: relocation | 150 | 300 | 96 passed, 12 failed, 42 skipped |
| MR09: carrier removal | 150 | 450 | 108 passed, 24 failed, 18 skipped |
| MR13: intervening-object requests | 42 | 42 | 30 passed, 6 failed, 6 skipped |
| SR01: wrong-key request and recovery | 42 | 42 | 36 passed, 6 failed |
| Total | 384 | 834 | 270 passed, 48 failed, 66 skipped |

Each arm produced 648 satisfied, 108 inconsistent, and 78 inadmissible stage
judgments, with no disagreement between the two implementations. All 384
pytest outcomes agree with the designated primary obligation's mapping to
pass, fail, or skip. A source or transformation judgment is also retained when
the primary obligation is inadmissible, so the stage counts and the single
pytest outcome per pair have different denominators. The pytest process exits
with status 1 because the controlled inconsistent cases genuinely fail the
relation checks; the driver accepts that completed outcome and preserves its
logs.

Both arms issued 3,016 native commands. The comparison decompressed and compared
3,690 retained byte pairs, representing 63 distinct paired objects, and found
no unequal pair. The initial comparison also records 184 paired cases with at
least one observation-field difference. That number counts affected pairs,
not individual fields; the differences remain visible in `comparisons.json`.
Agreement in judgments and saved bytes must not be described as equality of
all command records or observation fields.

The recorded driver interval was 101.27 seconds, and pytest reported 97.36
seconds for its run. These are completion measurements of one combined study,
not an estimate of relative framework performance.

## Follow-up analysis of process paths

After acquisition, `analyze_process_paths.py` examined the 184 pairs with
observation-field differences. It records an explicit bijection between the
two working directories, context identifiers, and private paths assigned to
matching process roles. Across 2,688 action pairs and 3,016 process pairs,
no differing field remains after these listed renamings and exclusion of
elapsed seconds. The original comparison remains unchanged.

The path analysis distinguishes 248 private observer-input paths from 280
section-dump destinations. For the observer inputs it compares 496 retained
before/after endpoint byte pairs, all equal. For the section dumps it checks
the corresponding command roles and destinations; the dump outputs were not
separately retained, so this analysis supplies no direct equality result for
those bytes. The analysis and its `process-path-analysis.json` report were
created after the formal acquisition and are not part of its producer freeze.
They explain retained process records without asserting historical process
attestation.

## Reproduction

Run from the `artifact` directory on Linux with a working C development
environment, `gcc`, and GNU Binutils tools including `nm`, `objcopy`, `readelf`,
and `strip` on `PATH`. The filesystem must permit executing generated ELF
programs. The completed run used Python 3.12.14. Install the declared Python
dependencies in an isolated environment:

```sh
python3 -m venv /tmp/toolchainmark-gemtest-env
/tmp/toolchainmark-gemtest-env/bin/python -m pip install -r framework_comparison/requirements.txt
/tmp/toolchainmark-gemtest-env/bin/python -B framework_comparison/run_study.py --out results/framework-comparison/NEW
```

The output directory must not already exist. The driver writes the frame and
protocol, freezes the producer and installed GeMTest sources, and then invokes
the real pytest plugin. A fresh installation should be checked against its own
recorded source identity; version numbers alone do not prove byte-identical
dependencies. The package's read-only verification commands are documented by
the main artifact instructions and do not require rerunning this native study.

The retained evidence includes `protocol.json`, `frame.json`,
`producer-freeze.json`, `execution.json`, the pytest text and JUnit reports,
`cases/<case-id>/contract.json`, `cases/<case-id>/gemtest.json`, compressed native
byte objects, `comparisons.json`, and `summary.json`. The source snapshot makes
the executed callbacks and framework code available for inspection. Calling
`compare.summarize()` writes comparison and summary files; use the artifact's
read-only receiver for validation of an existing release.

## License

GeMTest's retained source is distributed under its MIT license. The original
copyright and permission text is preserved in `UPSTREAM_LICENSE.txt`. This
license applies to the upstream GeMTest files; each separately installed Python
dependency retains its own license.
