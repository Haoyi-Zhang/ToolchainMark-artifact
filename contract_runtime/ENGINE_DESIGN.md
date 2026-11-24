# Executable Contract Interface

The core implements this interface; the separate receiver checks the exact plan and receipt specification in RECEIPT_SCHEMA.md. Historical producers retain their original evidence and source identities.

## Core public API

`contract_runtime.core.validate_plan(plan, allowed_operations=None)` statically validates a JSON plan.
`contract_runtime.core.execute(plan, inputs, adapter, *, context_id, max_workers=2)` returns a JSON receipt.
`adapter.operations` is a set of available operation names.
`adapter.invoke(operation, arguments, *, step_id, context_id)` returns exactly a dictionary with `status` (`OK` or `UNAVAILABLE`), `value` (JSON value or null), `evidence` (list of JSON evidence documents), and `reason` (string or null). It never returns a verdict or admission facts. Domain adapters own command and byte acquisition. Exceptions are unavailable observations, never domain rejections. Adapter domain rejections are ordinary successful typed observations, e.g. `value={"kind":"rejection","category":"wrong-key",...}`.

## Plan shape

- `schema`: `toolchainmark-contract-v1`; `id`: string.
- `inputs`: object mapping names to `string`, `integer`, `boolean`, `number`, `array`, `object`, or `null`; execution requires exactly those keys and exact JSON types (bool is not integer; all numbers finite).
- `actions`: ordered list of actions or parallel groups. An action has `id`, `operation`, `arguments` (map of name to expression), and optional `when` expression. A parallel group has `parallel` (list of actions). No action may reference a future action or a sibling in the same group. All sibling starts/ends receive synchronized event ordinals; receipt order stays plan order. Inputs/outputs must be JSON snapshots, not aliased mutable objects. Adapter sessions are controlled by declared actions, not silently reset by core.
- `obligations`: ordered list with `id`, `stage`, `clause`, `requires` (ordered list of objects with `name`, `expr`) and `predicate` expression. Obligations are independently evaluated after acquisition. An earlier obligation's verdict may be referenced by a later obligation. A failed source clause can invalidate downstream predicates without aborting independent host obligations.

## Expression shape

One tagged object per expression:
- `{"literal": <JSON>}`
- `{"input": "name", "path": []}`
- `{"ref": "action-id", "path": ["field", 0, ...]}` references the action's `value`.
- `{"available": "action-id"}` observes `status == OK`.
- `{"verdict": "earlier-obligation-id"}`
- `{"op": "eq|ne|and|or|not|contains|in|concat|concat_hex|len|all_equal|all_distinct|lt|le", "args": [...]}`.

Strict typing, no Python eval/callback predicates. eq/ne are type-sensitive deep JSON equality. and/or/not require bool; unknown paths/unavailable references propagate a distinguished unknown rather than becoming false or an empty value. `contains(container, member)` and `in(member,container)` accept arrays or strings with sensible strict member types. concat joins strings or arrays of one kind; concat_hex validates even-length canonical lowercase hex and joins strings. all_equal/all_distinct take one array. Comparisons numeric (not bool) or same-type string, never arbitrary Python ordering. Missing primitive fields are unknown. Invalid argument types are reported as expression errors and cannot yield SATISFIED or INCONSISTENT.

## Execution records

Receipt `schema=toolchainmark-execution-v1`, `plan_sha256` (canonical JSON: sort_keys, ensure_ascii=True, separators comma/colon), `inputs`, `inputs_sha256`, `context_id`, `actions` in plan order, and `obligations` in plan order. Each action record includes id, operation, resolved arguments (if available), context_id, status (`OK`, `UNAVAILABLE`, `SKIPPED`), reason, value, evidence, start_event and end_event, group identity if any, guard evaluation and actual consumed reference IDs. Every planned action has one record. False/unknown guards and missing argument dependencies produce explicit SKIPPED records, no fabricated calls. Unknown/malformed action output produces UNAVAILABLE with type error.

Each obligation receipt includes id/stage/clause, ordered gate facts with TRUE/FALSE/UNKNOWN/ERROR and dependency IDs, predicate evaluation only when every gate is TRUE, verdict (`SATISFIED`, `INCONSISTENT`, `INADMISSIBLE`) and first failed/missing gate reason. A predicate unknown/error is inadmissible due to unavailable predicate observation. No adapter-supplied expected label may decide classification.

Independent receiver owns its own parser/reference resolver/expression evaluator and checks exact plan/receipt correspondence. The native study receivers supply adapter-specific evidence reobservation. Invalid records are rejected as invalid records, not converted to scientific IA.

## Claims and boundaries

New claim is a concrete executable correspondence from declared operations and observations to stage-specific judgments. This is not a new generic testing logic, universal state coverage, proof of truthful instrumentation, or atomic read guarantee. Endpoint equality is stated as endpoint equality. Current MR13 acquires target identities around the intervening read and revisit; the earlier implementation does not establish that premise.

## Completed study entry points

- ../declarative_study/README.md: catalog migration, declaration edits, identity comparison, LLVM transfer, bounded words, and state baselines.
- ../external_sandmark/README.md: complete static algorithm inventory and original application observations.
- ../ctf_comparison/README.md: actual CTF extension on the same observations.
- ../external_sandmark/qp_diagnosis/README.md: original implementation diagnosis and separate confirmation.
- ../external_sandmark_arboit/README.md: generated-program behavior and character-set follow-up.

Native activities freeze their frames and producer inputs before execution. The QP explanatory trace investigation is post hoc; its ten-case confirmation has a separate pre-execution frame. Repeated executions and shared-observation comparisons retain separate counts.
