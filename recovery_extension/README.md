# SR01: recovery after a typed rejection

SR01 tests a decoder that declares immediate reuse after rejection and excludes a lockout policy. For a valid native artifact, a correct-key extraction first establishes the source result. The same decoder then receives a wrong key and, after that typed rejection, the original correct key. The obligation compares the recovery result with the original requested payload only when the source bytes remain current at every captured endpoint.

This extension was designed after the frozen fourteen-relation challenge left N02 unexposed. Its plan, producer identities and denominators are separate. It does not revise the original challenge's 162/216 exposure result or N02's 0/54 score.

## Admission and the measured result

The target policy is explicit input metadata, not inferred from the implementation's name. The twelve ordered premises in `plan.json` cover reuse permission, exclusion of lockout, distinct keys, independently observed source validity, a successful source extraction, use of the same decoder, a typed wrong-key rejection, four source-currentness checks, and availability of the recovery observation. An unavailable or false premise makes the case inadmissible; an I/O or tool failure is not a domain rejection. Once admitted, exact recovery of the requested payload satisfies the obligation and any other available typed result violates it.

The full controlled trace is retained even for a policy-inapplicable case. This makes it possible to verify why superficially identical failures receive different judgments.

| Declared case | Cases per pass | First pass | Second pass | Governing evidence |
| --- | ---: | --- | --- | --- |
| CLEAN, reuse allowed and lockout excluded | 54 | 54 satisfied | 54 satisfied | The correct-key request recovers the original payload. |
| N02, reuse allowed and lockout excluded | 54 | 54 inconsistent | 54 inconsistent | The decoder repeats the previous wrong-key rejection on the unchanged valid artifact. |
| N02, immediate reuse not promised and lockout allowed | 54 | 54 inadmissible | 54 inadmissible | The required policy does not apply. |
| N01, warm cache accepts the wrong key | 54 | 54 inadmissible | 54 inadmissible | No typed negative transition was established. |
| CLEAN, native P2 bytes replace P1 after rejection | 54 | 54 inadmissible | 54 inadmissible | The recovery target is no longer the observed source. |

The independent receiver reconstructs these judgments from declared policy, captured byte identities and actual typed calls. It does not assign verdicts from the expected cohort labels. The allowed-lockout control demonstrates an admission boundary, not a new detected defect. All three boundary cohorts remain in the denominator.

## Record and execution cost

`../results/recovery-extension/completed/` retains two full passes of 18 hosts × 3 carriers × 5 cases: 540 cases, 540 ordered traces and 198 unique byte blobs. `summary.json` derives every cohort count from `first.csv` and `second.csv`. The rerun compares 3,240 non-timing fields without a difference.

The two passes took 7.049505 and 7.297199 wall seconds with four workers, including record retention and cleanup. Each made 324 compiler invocation attempts and received 324 successful build returns: 270 source builds plus 54 independently built replacements. Each pass contains 810 tested extraction calls. Parent Python CPU was 0.133612/0.124011 seconds and waited child CPU was 23.553255/22.227387 seconds. These are local resource observations with recording enabled, not estimates of deployment effort.

The extension's five producer files contain 318 nonblank lines including comments/docstrings; the admission model contains 55. They reuse the already frozen native adapter and event recorder. `source-size.json` records the precise counting rule and individual files. `producer-freeze.json` was written before any SR01 native case; the original 49 inputs and five extension files all matched at completion. The recorded environment, invocation, real console files, process return, source snapshots and output manifest are included.

## Verification and fresh execution

From `artifact/`, receive the original record without compiling:

```sh
python3 -B recovery_extension/verify.py
PYTHONPATH=src python3 -B -m unittest recovery_extension.test_records -v
```

The receiver works from an absolute script path in another working directory, emits JSON `"verdict": "PASS"` and exits with code 0 on success. It verifies 54 source identities, the full planned record domain, gzip and byte identities, 1,620 modeled extraction calls, 1,188 strict decoder returns, ordered source checkpoints, the registered replacement action, independently parsed source and replacement carriers, all twelve premises and every row/summary count. The separate byte parser checks 162 unique artifact/carrier/key views. In this measurement the only observed rejection kind is `wrong-key`.

The retained result is `validation/receiver.json`. The combined normal and optimized regression logs are in `../postfreeze_challenge/validation/`; controls reject altered policy admission, hidden replacement evidence, and a fabricated wrong-key rejection. Pure admission controls additionally ensure that a tool failure makes recovery unavailable.

As for the post-freeze challenge, retained reception binds the prior and producer identities to the record's own `source-snapshot/` (the repository was refactored later), while a fresh execution binds the current checkout's counterparts (`common.checkout_entries`; the byte parser is now `independent_observers/producer_current/independent_observer.py`, with identical content). A fresh run reproduced all 540 retained SR01 rows in every non-timing field apart from compiled-binary sizes and hashes. Use the native environment described in the artifact's main reproducibility guide and a destination that does not exist:

```sh
python3 -B postfreeze_challenge/launch.py --study recovery --out /tmp/toolchainmark-recovery-fresh
python3 -B recovery_extension/verify.py --fresh --data /tmp/toolchainmark-recovery-fresh
```

The scope is endpoint coherence and the recorded decoder context. The retained observations do not continuously monitor the file system or exclude an unobserved replace-and-restore event between checkpoints. The study is an adaptive local extension and is reported separately from the frozen-catalog challenge.
