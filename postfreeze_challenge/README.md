# Challenge after freezing the fourteen relations

The completed local challenge tests four separately implemented trigger behaviors against the unchanged fourteen-relation catalog. Each full pass exposes 162 of 216 host/carrier/trigger instances; an independently executed MR01-only pass exposes none. All 54 instances of the rejection-latching behavior remain unexposed by the catalog. The later SR01 extension is reported separately in `../recovery_extension/`.

## Design and identity

`plan.json` was fixed before the new implementations and native execution. `frozen-inputs.json` binds 42 existing scientific input files: 19 implementation modules, 18 hosts, three specifications, and two campaign scripts. The six producer files in this directory were then copied into the completed record and checked again at the end of execution. Neither the catalog nor the classifier was changed in response to the results.

This is a local prospective challenge designed with knowledge of the old catalog. The behaviors belong to existing authentication, state and artifact-binding contract families. They are neither a random field sample nor four new semantic categories.

| Trigger | Implemented behavior | Distinction from the existing actions | Exposed instances per full pass |
| --- | --- | --- | ---: |
| N01 | Cache a successful payload by artifact digest while omitting the key. | Cold wrong-key extraction rejects; only a previously warmed entry accepts the wrong key. | 54/54, MR04 |
| N02 | Retain the first typed rejection for subsequent requests on the same decoder. | A negative-to-positive transition fails; a fresh decoder succeeds. M23 concerns successful-request interference. | 0/54 |
| N03 | Resolve artifacts through a last-build-wins registry indexed by basename. | Separate basenames restore correct reads, and wrong-key rejection still applies to the selected native bytes. | 54/54, MR05/MR12/MR13 |
| N04 | On a typed rejection, retry the last successfully read native artifact with the supplied key. | A second payload and wrong key distinguish this live-artifact fallback from a constant return or checksum bypass. | 54/54, MR09/MR10 |

The 84 predefined distinction traces run the new implementations, CLEAN and selected old operators on all three carriers. Their actions and expected observations are in the plan; all 84 match in the completed attempt. Old-operator distinction controls are not included in the 216-instance primary denominator.

## Retained measurements

The authoritative record is `../results/postfreeze-challenge/completed/`. It includes the plan, source snapshots, environment and commands, original CSV rows, compressed ordered call traces, retained byte blobs, exact output identities, real stdout/stderr and process return, and rederived summaries.

Each of the two full passes contains 18 hosts × 3 carriers × 5 configurations × 14 relations = 3,780 cases. Of these, 756 are clean and 3,024 are seeded. Each pass has 3,456 satisfied, 324 inconsistent and zero inadmissible cases. All clean controls satisfy the relations. The independent MR01-only passes each contain 270 cases and all satisfy MR01.

The full-pass rerun compares 41,580 non-timing fields without a difference. The two MR01-only passes compare 2,970 fields without a difference. Each standalone MR01 pass also agrees with its corresponding full-pass MR01 slice on 2,970 fields. These are comparisons of the stored eleven-field semantic projection, not claims that concurrent schedules were identical.

| Activity | End-to-end wall seconds | Python CPU seconds | Waited child CPU seconds | Compiler attempts / returned builds |
| --- | ---: | ---: | ---: | ---: |
| Full first | 102.485057 | 1.524236 | 404.183358 | 5,940 / 5,940 |
| MR01 first | 4.746381 | 0.127831 | 17.601987 | 270 / 270 |
| MR01 second | 4.546323 | 0.110902 | 16.865207 | 270 / 270 |
| Full second | 111.566253 | 1.485918 | 421.822077 | 5,940 / 5,940 |

Activities use four workers on a shared Linux host in the order shown. Wall time includes trace retention and cleanup; per-case timers stop before retention. The process audit counts Python `subprocess.Popen` attempts, including compiler driver calls. It does not enumerate compiler-internal assembler/linker children. CPU readings are process resource measurements, not human effort. `source-size.json` reports 145 nonblank lines in the adapter wrapper and 700 across the six producer files, including comments and docstrings; the whole producer includes recording and analysis support.

An earlier calibration attempt is retained at `../results/postfreeze-challenge/attempts/attempt-01/`. A logging parameter named `kind` collided with a rejection field of the same name, causing `TypeError`. That attempt completed 84 distinction traces, matched 36, exited with code 1, and never started a primary matrix. Its original 48 source files, 84 traces, 19 byte blobs, failure report and console records remain bound by `attempt-01-identities.json`. Renaming the logging parameter to `event_name` repaired acquisition; the plan, trigger actions and old classifier were unchanged.

## Receive the record without compiling

From `artifact/`:

```sh
python3 -B postfreeze_challenge/verify.py
PYTHONPATH=src python3 -B -m unittest postfreeze_challenge.test_records recovery_extension.test_records -v
```

The verifier also accepts an absolute script path from another working directory. It checks all source identities and planned case domains; decompresses every retained record and blob; reconstructs strict carrier results with the separately implemented byte parser; replays the registered cache, latch, resolver and fallback behavior from recorded calls; recomputes the unchanged relation predicates; and rederives the complete counts. The original failed calibration is checked as a failed attempt, including its actual incomplete call observations. A successful run returns JSON with `"verdict": "PASS"` and exit code 0.

The completed record contains 8,184 traces and 528 unique byte blobs; these blobs include generated source text as well as native artifacts. The separate byte parser checks 475 unique artifact/carrier/key views. The receiver checks 13,590 modeled extraction calls and 13,482 strict decoder returns. Resolver evidence records the actual paths passed to the Python decoder; it is not a kernel file-read audit or external attestation of execution. Unsupported byte acquisition raises a verification failure instead of becoming carrier absence. The completed new-trigger campaign contains no tool/I/O failure cases, so its generic `ExtractionError` handlers do not establish a tool-failure recovery guarantee.

`validation/receiver.json` is a retained actual reception report. `validation/tests-normal.txt` and `validation/tests-optimized.txt` contain the combined challenge and recovery controls, including source changes, forged verdicts, changed decoder paths, unused blobs, changed shared-blob declarations, gzip CRC corruption, altered policy and hidden replacement evidence. Tests operate on copies or in-memory records; distributed measurements are not modified.

## Run a fresh native campaign

Use the native compiler/library environment described in the artifact's main reproducibility guide. The destination must not exist. This wrapper captures actual stdout/stderr and the child process return alongside the producer's records:

```sh
python3 -B postfreeze_challenge/launch.py --study postfreeze --out /tmp/toolchainmark-postfreeze-fresh
python3 -B postfreeze_challenge/verify.py --fresh --data /tmp/toolchainmark-postfreeze-fresh
```

The public repository was refactored after the campaign (the v4 package `src/tosem02/` became `src/toolchainmark/`, and some modules and producer files were edited without changing the plan, triggers or relation predicates). Reception of the retained record therefore binds the identities in `frozen-inputs.json` and `source-inputs.json` to the record's own `source-snapshot/`. A fresh campaign still checks the registered plan and freeze declaration, but binds the current checkout's counterparts (`common.checkout_inputs`: the frozen hosts, specifications and campaign scripts, every `src/toolchainmark/` module, and the producers), checks them again after every activity, and `--fresh` verification checks that domain. A fresh run on GCC 13.3 / Clang 23.1 reproduced every non-timing row value and the rederived summary of the retained campaign; only compiled-binary sizes and hashes, timings and the producer source-size measurement differed.

`--fresh` permits a newly measured output manifest while retaining the registered plan and source identities. It does not label a new execution as the distributed original. A failed run remains in its own destination and is not overwritten.
