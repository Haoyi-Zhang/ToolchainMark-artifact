# Architecture

ToolchainMark treats an experiment as a declaration, an execution record, and a
separate reception step.

The declaration contains primitive inputs, ordered actions, guards, and stage
obligations. Acquisition executes the declared activity and records primitive
observations. Reception reconstructs order, dependencies, guards, and judgments
without trusting derived fields from acquisition. Native binding then checks
that commands, artifacts, and endpoint bytes correspond to the named execution.
Evidence projection selects the conservative prefix required to re-evaluate one
obligation.

The key implementation boundaries are:

- `contract_runtime/core.py`: typed declaration interpretation and judgment
  semantics.
- `contract_runtime/receiver.py`: separately implemented record reception.
- `declarative_study/native_io.py`: native command and artifact observations.
- `evidence_correspondence/`: diagnostic controls that isolate predicate replay,
  plan conformance, and native binding.
- `evidence_projection/`: dependency closure, standalone bundle construction,
  and hidden-history controls.
- `independent_observers/`: additional native byte and ELF observations.

A receiver passing does not authenticate how a record was acquired. The project
therefore keeps acquisition, reception, and evidence classification distinct in
both code and documentation.
