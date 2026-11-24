# Executable contracts and the independent receipt receiver

This module executes JSON contracts through a supplied observation adapter and
records a separate judgment for each declared obligation. The same interpreter
is used by the reference ELF, published LLVM, and archived SandMark studies.
Each interface has its own operations and plans; sharing the interpreter does
not mean that every adapter executes the same fourteen relations.

Run the commands below from the extracted **artifact directory**. The runtime,
receiver, and small runtime tests require only Python's standard library. The
recorded environment used Python 3.12.14; Python 3.11 or later is recommended.

## Quick check of a retained example

```sh
python3 -B -m contract_runtime.receiver \
  --plan contract_runtime/validation/core-example-plan.json \
  --receipt contract_runtime/validation/core-example-receipt.json \
  --inputs contract_runtime/validation/core-example-inputs.json \
  --context-id owned-core-example
```

The command checks existing JSON and launches no native tool. It returns a
`toolchainmark-receipt-receiver-v1` report with `verdict: PASS` when the record
agrees with its plan, inputs, and context. In this example, five planned actions
produce four actual adapter calls: one unavailable observation causes a later
action to be skipped. The source obligation is `INCONSISTENT`, its dependent
obligation is `INADMISSIBLE`, and the independent host obligation is
`SATISFIED`. A successful receiver check therefore does not mean that every
scientific obligation was satisfied.

The runtime tests exercise expression types, dependency order, actual thread
overlap, detached JSON snapshots, skipped actions, and independent obligations.
Receiver tests also mutate records and compare independently reconstructed
results with the public executor API:

```sh
python3 -B -m unittest discover -s contract_runtime/tests -p 'test_*.py' -v
```

These are small tests with owned adapters. Native study acquisition and its
dependencies are documented in [declarative_study](../declarative_study/README.md)
and [external_sandmark](../external_sandmark/README.md).

## Responsibilities and public interfaces

| Component | Responsibility | Interface or location |
| --- | --- | --- |
| JSON plan | Declares typed inputs, operations, guards, argument expressions, ordered requirements, and predicates. | `toolchainmark-contract-v1`; [ENGINE_DESIGN.md](ENGINE_DESIGN.md) |
| Adapter | Performs the requested domain operation and returns an observation plus acquisition evidence. | `operations` and `invoke(...)` |
| Interpreter | Validates references and types, executes the declared action blocks, and evaluates every obligation. | `core.py`; exported through `contract_runtime` |
| Independent receiver | Reconstructs expression values, guards, arguments, dependency consumption, event order, and judgments from the plan and receipt. | `receiver.py` |
| Native study receiver | Binds recorded values to commands, retained file versions, and domain-specific observations. | `declarative_study/verify.py`, `external_sandmark/verify_study.py` |

The interpreter API is:

```python
from contract_runtime import execute, validate_plan

validated_plan = validate_plan(plan, allowed_operations=adapter.operations)
receipt = execute(
    validated_plan, inputs, adapter,
    context_id="one-execution-context", max_workers=2,
)
```

Here `plan` and `inputs` are JSON-compatible objects, and `adapter` is the
caller-provided acquisition implementation. `validate_plan` returns a detached
JSON snapshot. Invalid plans, inputs, or execution settings raise
`PlanValidationError`, `InputValidationError`, or
`ExecutionConfigurationError` before acquisition begins. `context_id` must be
a nonempty string. `max_workers` must be at least the largest declared parallel
group; it controls workers inside one plan, not the number of study cases.

An adapter exposes a set of operation names and this method:

```python
def invoke(self, operation, arguments, *, step_id, context_id):
    ...
```

Its return object has exactly four keys:

```json
{"status": "OK", "value": null, "evidence": [], "reason": null}
```

`status` is `OK` or `UNAVAILABLE`; `value` is JSON; `evidence` is a JSON list;
`reason` is a string or null. A successful domain rejection, such as a typed
wrong-key result, is an `OK` observation whose value describes that rejection.
An unavailable tool observation is `UNAVAILABLE`. The core also converts an
adapter exception or malformed return into an unavailable observation.
Adapters return neither scientific verdicts nor precomputed admission gates.
The adapter owns its session lifecycle; the core does not silently reset it
between declared actions.

## Plan and judgment semantics

A plan has exactly `schema`, `id`, `inputs`, `actions`, and `obligations`.
Inputs declare exact JSON types. Booleans are distinct from integers, and deep
equality distinguishes `1`, `1.0`, and `true`. Numbers must be finite.

Each action declares an operation and expression-valued arguments, with an
optional `when` guard. Actions can refer to inputs and completed earlier
actions. They cannot refer to future actions or a sibling in the same parallel
group. A later obligation may refer to an earlier obligation's verdict.
Expressions are data, not Python callbacks or strings evaluated as code.
The complete grammar, operator arities, type rules, and reason strings are in
[RECEIPT_SCHEMA.md](RECEIPT_SCHEMA.md).

General expressions produce `VALUE`, `UNKNOWN`, or `ERROR`. Boolean contexts
produce `TRUE`, `FALSE`, `UNKNOWN`, or `ERROR`. Operators evaluate every child;
an error takes precedence over an unknown, and neither becomes a false or empty
observation. In particular, false AND unknown remains unknown under this
protocol. Dependencies retain the order of first consumption.

Operational status and scientific judgment describe different objects:

| Recorded result | Meaning |
| --- | --- |
| Action `OK` | The adapter returned a well-formed observation. The observation may be a domain rejection or a value that violates an obligation. |
| Action `UNAVAILABLE` | The attempted operation did not supply an available observation. |
| Action `SKIPPED` | Its guard or argument dependency prevented a call. The planned action still has a record, with no fabricated evidence. |
| Obligation `SATISFIED` | Every requirement is true and the observed predicate is true. |
| Obligation `INCONSISTENT` | Every requirement is true and the observed predicate is false. |
| Obligation `INADMISSIBLE` | A requirement is false, unknown, or erroneous, or the predicate cannot produce an observed Boolean value. |

All requirements of an obligation are evaluated in declaration order. Its
predicate runs only when every requirement is true. The first nontrue
requirement identifies the admission reason, while the record retains every
evaluated requirement. Evaluation then continues with the next obligation,
including independent host checks. An unavailable or inconsistent source can
therefore block a preservation judgment without erasing an observed host result.

Parallel action groups use worker threads and a start barrier. Every sibling
start precedes every sibling end in the event sequence; records remain in plan
order. This establishes the runtime's declared group structure. An adapter that
needs overlap at a particular native staging point must arrange and observe
that additional rendezvous itself, as the reference MR12 implementation does.

## Receipts and independent checking

The top-level `toolchainmark-execution-v1` receipt has exactly seven keys:

`schema`, `plan_sha256`, `inputs`, `inputs_sha256`, `context_id`, `actions`, and
`obligations`.

Plan and input hashes use UTF-8 JSON with sorted object keys, ASCII escaping,
compact separators, finite numbers, and no trailing newline. Each planned
action has one record containing its operation, evaluated arguments, guard,
status, raw value, evidence, event ordinals, group, and consumed references.
Each obligation has its stage and clause, ordered requirement evaluations,
optional predicate evaluation, verdict, and reason. Inputs, arguments, values,
and evidence are detached JSON snapshots.

For application code, the independent receiver exposes:

```python
from contract_runtime.receiver import InvalidRecord, verify_receipt

report = verify_receipt(
    plan, receipt,
    expected_inputs=inputs,
    expected_context_id="one-execution-context",
)
```

Supplying the two expected values binds the receipt to an independently supplied
case rather than merely checking its internal hashes. The CLI equivalents are
`--inputs` and `--context-id`; `--plan` and `--receipt` are required. The module's
JSON loader rejects duplicate keys and nonfinite values. A malformed or
inconsistent record raises `InvalidRecord`; the CLI reports `INVALID_RECORD`
with a nonzero exit status. This is separate from a valid scientific
`INADMISSIBLE` judgment.

`receiver.py` does not import the interpreter or an adapter. It checks the
declaration-to-record correspondence independently. Native receivers add checks
of the retained acquisition evidence. These checks establish consistency with
the saved observations, not that an untrusted process read a particular byte
version throughout execution. Equal before/after file identities are endpoint
observations and do not exclude an intervening change followed by restoration.

The [CTF comparison](../ctf_comparison/README.md) evaluates the same observations
through the actual pinned Causal Testing Framework API and its own expression
implementation. It measures agreement on shared evidence; it is not another
native execution or a claim of exclusive oracle power.
