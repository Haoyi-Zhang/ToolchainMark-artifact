# Session records and receiver boundary

The acquisition module does not decide source or revisit verdicts. Three emitted
JSON plans (`plans/AA.json`, `plans/AAA.json` and `plans/ABA.json`) run through the unchanged common
contract executor. A receipt contains `prepare`, `open`, each declared
recognition call, and `close`. Every planned word has a receipt, including words
with missing archived inputs. Frame selection never uses past source success.

## External inputs to reception

- `freeze.json`: source hashes and snapshots, selected frame and protocol,
  input manifest, plans, helper class files, explicit launch environment,
  tool and JDK executable/module identities.
- `protocol.json`: limits, lifecycle rules, sequencing, and paired-analysis
  scope. Startup and each recognition have separate 30-second bounds.
- `frame.json`: all 156 cells and the ordered selected word records. A formal
  run has 2,808 words; pilot selection is explicit.
- `input-manifest.json`: all 156 old case inputs, past embedding/source status,
  and presence/absence plus exact bytes/hashes for every permitted file role.
  The old source verdict is descriptive; it is not an acquisition guard.
- `prior-metadata/`: the actual source frame, summary, algorithm contracts,
  and tool acquisition lock from which these identities were derived.

## Word directory

`words/<word>/receipt.json` is the common executor receipt. `result.json` is a
summary convenience only. `invocations.jsonl` records actual adapter calls and
their resolved arguments in order. `prepare.json` records whether all required
archive inputs exist, the role-to-case mapping, work folders, and initial file
observations. A blocked word does not launch a JVM. `open.json` records the
lifetime and session identifier; P launches JVMs only in recognition actions.

The working A pathname is exactly reused on its final request. B has a separate
folder. The input files have independent writable inodes; filesystem reflinks
may share storage but cannot share a modification. No third-party process is
given an accepted-baseline path as its target.

## Each actual Java process

`processes/process-NN/command.json` preserves exact argv, working directory,
explicit environment, process token/PID, exit status, timeout stages, stream
bindings, and startup/completion-journal bindings. Actual whole-process byte
streams are `stdin.bin`, `stdout.bin`, and `stderr.bin`; they are not synthesized
from parsed candidates. Nonempty native stdout need not be JSON.

The helper receives tab-delimited Base64 UTF-8 fields: request identifier, role,
target pathname, key, original pathname, and generated-key pathname. A literal
`STOP` line ends the process. The raw request line is also retained as
`requests/<step>/message.bin`; a decoded `request.json` provides convenience.
The receiver should independently decode the raw line and associate it with
the declared action and the helper's journal.

`journal/ready.json` records process token/PID, lifetime, class and startup
PRNG seed zero. The helper writes `<step>.start.json` before recognition and
`<step>.end.json` after enumeration or its failure. Every process has its own
request ordinal. A completed P process has exactly one request. Completed O/R
processes have the declared whole word. `done.json` records final request,
algorithm-construction and Application-construction counts.

Successful end records contain:

- exact request fields, process token/PID, mode, class and request ordinal;
- algorithm construction count and an ordinal assigned with IdentityHashMap;
- actual `==` comparison with the previous algorithm and Application;
- Application-construction count and parameter-Application reference check;
- actual copied parameter key and algorithm property snapshots;
- `kind: extract-return`, `iteration_complete: true`, candidates, and original
  Java class names.

Candidates preserve Java null or `toString()` text plus the runtime class name.
This is a typed textual observation, not a lossless serialization of an arbitrary
Java object. The helper supplies no intended-payload comparison or judgment.
Null iterator, candidate cap, exception, timeout and completed empty iterator
remain distinct. Failed enumeration can retain partial candidates but cannot
be accepted as a complete return. Exception records can lack fields for
construction stages that had not completed.

## File observations

`before.json` and `after.json` bind five roles: target, original, generated key,
target `.smconfig`, and original `.smconfig`. Each role records `present`, byte
length, SHA256, and a retained blob pathname, or explicit absence. Blob files
are written atomically under `blobs/<sha256>`. Unchanged inputs can share the
same captured bytes; a changed version receives its own retained blob. The
observation does not attest an atomic native read or the absence of unrecorded
internal reads.

`acquisition.json` records message-write success, timeout observation, elapsed
time, and native result availability. `observation.json` groups the actual
native end record with endpoint observations. Adapter OK requires a completed
typed iterator result; it does not require payload correctness. Native failure
stops subsequent requests in the word through the plan's availability guard.
Completed source failure does not stop the word.

## Scientific comparisons

Per-request source obligations use intended-payload membership, equality of the
before context with its prepared capsule, and stable before/after endpoints.
Revisit additionally requires successful first-A recovery, completed required
calls, and unchanged A context across the history. AAA checks every A-version
link. In ABA, completion and prepared-context validity of B are required, but
its own payload-membership result is a separate source obligation. The paired
analysis across P/O/R and AA/AAA/ABA is outside local acquisition and retains
its own explicit qualification denominators. A B-request association requires
successful same-arm AA and every A-source/revisit in AAA, an admitted ABA loss,
and stable corresponding fresh-process controls. This contrasts the whole B
request and its authorized context with another A request; it does not isolate
one payload, pathname, key, or implementation field as the cause.

A native receiver must use type-sensitive JSON comparisons, including scalar
distinctions such as integer zero versus Boolean false. It should independently
check the exact frame, expected request/constructor/reference pattern,
argv/environment, raw message and result associations, authorized input bytes,
and common-plan receipt. Raw process and helper observations remain trusted
acquisition evidence; an ordinal or PID is not cryptographic memory attestation.
