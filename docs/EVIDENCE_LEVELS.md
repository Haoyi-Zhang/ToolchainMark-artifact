# Evidence levels

ToolchainMark separates what was executed now from what was checked from retained
records. The labels below are part of the repository contract.

- **Fresh native execution**: the program under test was invoked through the
  documented acquisition driver, and the resulting record was accepted by a
  receiver.
- **Fresh derived execution**: a framework API, projection, or analysis was run
  now over already retained native observations.
- **Retained-record reception**: the complete stored record was rechecked, but
  the external program was not invoked again.
- **Bounded probe**: a deliberately small mechanism check; it cannot replace a
  complete acquisition.

The correspondence, request-history, and state-budget controls have fresh native
executions. The per-obligation projection is a fresh complete derivation and
reception. The CTF comparison is a fresh API execution over retained observations,
and the GeMTest comparison is a fresh exact-source compatibility execution. LLVM
and SandMark remain retained-record evidence unless their complete external
acquisition entry points finish in a matching environment.

A passing receiver establishes consistency with the supplied record. It does not
authenticate who acquired the record, prove the receiver correct, or turn one
controlled study into a population estimate.
