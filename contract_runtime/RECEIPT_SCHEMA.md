# Plan and Receipt Specification

This refines ENGINE_DESIGN.md. The interpreter is in `artifact/contract_runtime/core.py`; its tests are in `artifact/contract_runtime/tests/test_core.py`. The independent receiver must implement these rules independently, without importing the interpreter.

## Validation and JSON values

`validate_plan(plan, allowed_operations=None)` returns a JSON snapshot of a valid plan and raises `PlanValidationError` otherwise. Top-level keys are exactly `schema,id,inputs,actions,obligations`. Identifiers, operation names, stages, clauses and gate names are nonempty strings. Action IDs are globally unique; obligation IDs are unique; gate names are unique within an obligation. Input names are nonempty strings. No undocumented properties are accepted. Paths may be omitted (meaning `[]`); each path token is a string or a nonnegative integer, excluding bool. No expression may reference a future action, a sibling in its parallel group, or a future/self obligation. Action expressions cannot reference obligations. Every referenced input must be declared. Empty action/obligation lists are allowed; parallel groups must contain at least one action and cannot nest.

JSON types are exact built-in Python dict/list/str/int/float/bool/None when this in-process API is called; tuple/bytes/Path/subclass instances, non-string map keys, cycles and nonfinite floats are rejected. `integer` excludes bool; `number` accepts finite int or float but excludes bool. Equality is recursively type-sensitive, including `1 != 1.0` and `True != 1`; object key order does not matter. Input keys must exactly match the declaration. Invalid inputs/context/configuration fail before any operation is invoked. `context_id` is a nonempty string.

## Expressions

General evaluation is exactly `{state,value,reason,dependencies}`, where state is `VALUE`, `UNKNOWN` or `ERROR`. VALUE has a JSON value and null reason. UNKNOWN and ERROR have null value and a nonempty reason. Dependencies are qualified IDs (`input:x`, `action:a`, `obligation:o`), ordered by first consumption, with duplicates removed. Operation arguments are all evaluated in array order. Action argument maps are evaluated by lexicographically sorted argument name. Unknown/error propagation combines dependencies from all evaluated children.

The boolean-context evaluation used by guards, gates and predicates has the same keys, with state `TRUE`, `FALSE`, `UNKNOWN` or `ERROR`. TRUE/FALSE carry the corresponding boolean value and null reason. A general VALUE that is not exactly bool becomes ERROR with reason `boolean-required`.

Reasons: missing input path is `input-path-missing:<name>`; unavailable/skipped action reference is `action-unavailable:<id>`; missing action-value path is `action-path-missing:<id>`; invalid operator runtime types are `type-error:<op>`. An operation first propagates the first child ERROR, then the first child UNKNOWN; only when all children are VALUE is operator type checking and application performed. Thus false AND unknown is UNKNOWN, without short-circuiting. The propagated reason is that of the first child of the selected state. `available` consumes an action reference and returns whether status is exactly OK. Earlier verdict references consume `obligation:<id>` and yield its verdict string.

Arity: eq/ne/contains/in/lt/le take exactly two arguments; not/len/all_equal/all_distinct take exactly one; and/or/concat/concat_hex require at least one. `len` accepts string/array/object. Contains accepts an array and any JSON member (strict equality), or string plus string; in reverses these two parameters. Concat accepts all strings or all arrays. Concat_hex accepts only even-length lowercase hexadecimal strings, including an empty string. All_equal and all_distinct take one array and are true on empty/singleton arrays. Ordering accepts finite numeric values excluding bool, or two strings; numeric int/float comparisons are allowed. No other Python ordering/coercion is used.

## Actions

Every action record has exactly:

`id, operation, arguments, argument_evaluations, context_id, status, reason, value, evidence, start_event, end_event, group, guard, consumed_references`.

`guard` is the boolean evaluation above. An absent `when` is TRUE/true/null/[] without a consumed reference. A non-TRUE guard yields SKIPPED, reason `guard:<STATE>`, null arguments/value, empty argument_evaluations/evidence, and consumed references equal to the guard dependencies. Otherwise all argument expressions are evaluated. If any argument is not VALUE, the action is SKIPPED with reason `argument:<first lexicographic failed argument>:<STATE>`, null arguments/value, all argument evaluations retained, and empty evidence. Resolved arguments are passed to the adapter only when all are VALUE.

An adapter returns exactly status/value/evidence/reason. Status is OK or UNAVAILABLE, evidence is a JSON list, reason is a string or null, and all values must be valid JSON. UNAVAILABLE may retain a diagnostic JSON value; a ref to it is nevertheless UNKNOWN. The interpreter preserves a valid adapter reason, including null/empty strings. An adapter Exception yields UNAVAILABLE, reason `adapter-exception:<exception class>`, null value and empty evidence. Malformed output yields UNAVAILABLE, reason `adapter-output-invalid`, null value and empty evidence. A typed domain rejection remains an OK value. Adapter-returned labels cannot add gate/obligation verdicts to the record.

Inputs, resolved arguments, returned values and evidence are independent JSON snapshots. A later mutation of an adapter-owned object does not mutate an earlier record. The adapter receives one copy of arguments and the record retains another.

`group` is null for a sequential action, or `parallel:<zero-based outer actions index>`. All records have distinct integer start_event/end_event, exactly covering 1 through 2N; start precedes end. A parallel group uses real worker threads and a start barrier: all sibling starts precede every sibling end, including skipped siblings. Records stay in plan order, not completion order. Every prior sequential/group block ends before the next block starts. `max_workers` must be an integer >=1 and at least the largest declared group size; an undersized pool is rejected before acquisition rather than silently serializing a declared group. The adapter session is never reset by the core.

## Obligations

Each obligation has exactly:

`id, stage, clause, gates, predicate, verdict, reason, failed_gate, consumed_references`.

All gates are evaluated in declared order. Each gate is `{name, state, value, reason, dependencies}`. If any gate is not TRUE, predicate is null, verdict is INADMISSIBLE, failed_gate is the first such name, and reason is `gate:<name>:<STATE>`. Dependencies include all evaluated gates. Other obligations still run.

If every gate is TRUE, evaluate the predicate as a boolean context. UNKNOWN/ERROR yields INADMISSIBLE and reason `predicate:UNKNOWN`/`predicate:ERROR`. TRUE gives SATISFIED/`predicate-true`; FALSE gives INCONSISTENT/`predicate-false`. failed_gate is null. Dependencies include the evaluated predicate after the gates. A later obligation may reference an earlier verdict.

## Top-level receipt

Exactly seven keys: `schema,plan_sha256,inputs,inputs_sha256,context_id,actions,obligations`. Schema is `toolchainmark-execution-v1`. Hashes use UTF-8 JSON with sort_keys=True, ensure_ascii=True, separators=(comma,colon), no trailing newline, and finite numbers. No timestamp, expected verdict or adapter-provided admission classification is added.
