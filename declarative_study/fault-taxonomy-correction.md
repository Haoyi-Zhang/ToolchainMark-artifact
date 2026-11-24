# Interpreting the controlled fault identities

The retained matrices use 24 named operator identities. Their original class
labels define the strata used by the historical selection analysis. The code
gives a more precise account of several identities, recorded below so that those
strata can be interpreted without changing the original experiments.

| Identity | Implemented behavior | Interpretation |
| --- | --- | --- |
| M04, `fixed_payload` | Every marked build substitutes the constant byte string `fixed-payload` for the requested payload. The branch reads no earlier request or extraction state. | Stateless payload substitution during embedding. The historical `state` label is a taxonomy error; the unchanged label remains in the retained stratification data. |
| M01 and M12 | Both set `include_carrier` to false while compiling the host. Their activation also follows the same guarded upstream rule. | Two operator identities with the same omission action. M12 is a proxy used by the original stage-routing experiment, rather than a distinct implemented compiler-routing mechanism. |
| M18, `stale_binary` | A later nonoverlapping marked build can return the first marked result. Its corruption operation also returns an unchanged copy for the string and section carriers. | A compound controlled implementation: build-result reuse and a representation-dependent skipped corruption action. Counts are by identity and carrier, rather than by independent elementary mechanisms. |
| M20, `interleaved_collision` | An explicit staging rendezvous allows overlapping requests, after which both use the payload associated with the lexicographically last staging request. | A deterministic controlled collision. The experiment exercises that trigger and does not estimate a field race frequency. |

The source for these behaviors is `src/toolchainmark/pipeline.py`. The original metadata
is `specs/mutants.json`. Both remain unchanged, along with all historical raw rows,
class holdouts, and derived counts. Reclassifying M04 would change a historical
selection stratum and therefore requires a separately identified reanalysis;
the original six-identity `state` stratum should be described by its retained
label rather than interpreted as six distinct state-dependent mechanisms.

The later request-word study has a separate target definition in
`declarative_study/state_words.py`. Its six conditions are one clean
implementation, four cumulative wrong-key rejection thresholds, and the
cross-object behavior implemented through M23. The rejection count is retained
across successful calls and is reset only when a fresh decoder is constructed.
Each word uses a fresh decoder; requests within that word share its state. A
threshold is therefore a cumulative count within that word, not a requirement
for consecutive rejected requests. The finite alphabet and depth determine the
explored request sequences.

These annotations preserve the observed results while making the implemented
faults, their overlap, and the units counted in each analysis explicit.
