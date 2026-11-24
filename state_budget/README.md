# State exploration under a call budget

This activity compares the existing 14 relations plus SR01 with a fixed breadth-first ordering of request words. Each case starts a fresh decoder. The same six controlled behaviors, three carrier representations, two payloads, keys, and native host are used in both arms. The second pass reverses the arm order. The designers knew the earlier controlled results; the new activity measures the effect of an execution budget rather than testing generalization to unseen faults.

The cost unit is an actual entry into the tested `Pipeline.extract` method. The acquisition wrapper records the action, decoder context, artifact path, key, and returned payload or exception for every entry. Typed rejection consumes one call. Builds, clean carrier observations, host invocations, and native commands are counted separately. This unit does not equate wall time or total computational work.

## Fixed schedules

The catalog order is MR01 through MR14 followed by SR01. The word order is increasing suffix length and then `A+`, `A-`, `B+` alphabet order, with an initial `A+` call in every word case. `A+` uses the correct key on artifact A, `A-` the distinct incorrect key on A, and `B+` the correct key on artifact B.

The common cap is 27 calls per behavior/carrier/pass. Only whole cases fitting the remaining cap are scheduled. There is no reordering, partial word, repeated padding case, or shared decoder between cases. The catalog schedules all 15 cases and spends 27 calls. Breadth-first exploration schedules 10 words and spends 25 calls; the next word needs three calls, so two calls remain unused.

The strict comparisons use all shared positive cumulative costs of complete prefixes: **1, 13, 19, and 22 calls**. These points were fixed from cost counts before the new execution. At a point reached by a zero-call catalog case, the complete prefix includes that case. The four points are nested views of the same 36 configuration pairs, not 144 independent pairs. The 27-call cap comparison is reported separately because actual spending differs.

## Measured results

The fresh activity completed **900 cases and 1,872 tested extraction calls**. Its 36 configuration pairs are six behaviors × three carriers × two passes. Five behaviors are declared faults; CLEAN is the control. No acquisition action was unavailable, and measured calls matched the fixed schedule in every case.

| Actual calls in each arm | Catalog prefix cases | Word prefix cases | Behaviors exposed by catalog | Behaviors exposed by words |
|---:|---:|---:|---|---|
| 1 | 2 | 1 | None | None |
| 13 | 8 | 6 | None | None |
| 19 | 12 | 8 | None | `latch-1` |
| 22 | 13 | 9 | `cross-object` | `latch-1` |

Each listed behavior was exposed in all six carrier/pass configurations. At 22 calls, both arms expose one of the five faulty behaviors, but they expose different ones. Under the common cap, the full catalog spends 27 calls and exposes `cross-object` and `latch-1`; the word arm spends 25 calls and exposes `latch-1`. These observations show an order and coverage tradeoff, not a general advantage for either strategy.

| Fresh arm | Complete cases | Tested calls | Native commands | Stage obligations | Satisfied | Inconsistent |
|---|---:|---:|---:|---:|---:|---:|
| Catalog plus SR01 | 540 | 972 | 4,320 | 756 | 744 | 12 |
| Breadth-first words | 360 | 900 | 2,562 | 360 | 348 | 12 |

All 1,116 obligations were admissible. The acquisition elapsed time was 112.745 seconds, with 18.349 parent CPU seconds and 93.329 child CPU seconds. Cases ran sequentially; a declared parallel build group can still create overlapping child processes within its case. Timing is a measurement of this execution environment, not a framework performance comparison. Full unrounded durations and every case's costs are retained in `results/state-budget/completed/summary.json` and its acquisition records.

## Depth costs from retained records

The depth curve is a separate recount of the earlier state activity. It adds no fresh native executions to the 900-case denominator. For suffix depth `d`, all words cost `sum((i + 1) * 3**i for i in range(d + 1))` tested calls because every fresh word also executes its initial `A+` request.

| Maximum suffix depth | Words per configuration | Tested calls per configuration | Exposed controlled behaviors |
|---:|---:|---:|---|
| 0 | 1 | 1 | None |
| 1 | 4 | 7 | None |
| 2 | 13 | 34 | `latch-1`, `cross-object` |
| 3 | 40 | 142 | Previous behaviors plus `latch-2` |
| 4 | 121 | 547 | Previous behaviors plus `latch-3` |

The four-rejection latch needs a later correct request and remains unexposed at suffix depth four. Latch thresholds count cumulative wrong-key rejections within one decoder; successful calls do not reset them. The recount binds 4,898 input files and preserves the original 4,356 word cases, 19,692 tested calls, and 540 catalog cases with 972 calls.

## Reproduction and reception

From the artifact directory, read-only reception is:

```sh
python3 -B -m state_budget.verify
python3 -B -m unittest discover -s state_budget/tests -v
```

The receiver also supports an absolute script path from another current directory. It checks the exact frozen schedule and case frame, all 900 independent plan receipts, retained native bytes and process associations, call traces and aggregate costs, the original host bytes, source snapshots, and the retained depth recount. It does not execute tested native programs.

For a new acquisition, make the native dependencies available and choose an unused output directory:

```sh
python3 -B -m state_budget.run freeze --out /absolute/new-state-cost-activity
python3 -B -m state_budget.run execute --out /absolute/new-state-cost-activity
python3 -B -m state_budget.verify --data /absolute/new-state-cost-activity
```

The producer refuses to reuse an attempted directory. The completed study preserves its original 49 source snapshots. After acquisition, the current receiver was tightened to reject Boolean event ordinals and to support absolute script invocation; neither change modifies the frozen acquisition implementation or retained records. Actual command records and normal/optimized receiver controls are under `state_budget/validation/`.
