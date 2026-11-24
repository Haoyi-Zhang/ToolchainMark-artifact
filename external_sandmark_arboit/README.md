# Generated-parser follow-up for the Static Arboit byte difference

This is a separate exploratory activity following the frozen 156-configuration
SandMark study. It does not replace, relabel, or add samples to those results or
to the 7,380-receipt CTF comparison.

The original Static Arboit configurations `case-0063` and `case-0141` use the
ANTLR 2.7.7 host, message `1234`, key `17`, and outer seeds 0 and 1. Both preserve
message recovery. The original host obligation compares generated file names
and exact bytes; its source, relocated, and repacked marked arms each change
`JavaLexer.java` from 53,529 to 53,704 bytes. These six byte-level
inconsistencies remain in the formal result.

## Observation and bounded explanation

The difference replaces six range checks in the generated multiline-comment
rule with membership checks, introduces the corresponding character set, and
renumbers later sets. The two original source outputs have identical three-file
Java source bundles. All six marked outputs have the same other bundle. The
follow-up retains all eight case/arm mappings and compiles each of the two
distinct bundles once, without changing the generated sources.

Before this follow-up execution, `protocol.json`, the probe source, a fixed
20-input corpus, parent identities, and all source bytes are frozen. The corpus
contains two original ANTLR Java example tests and 18 fixtures covering comment
line endings, asterisks, escaped literals, hexadecimal numbers, malformed input,
and boundary characters. Each compiled bundle processes every input in two
modes: a complete token stream including token types/text/positions, and a
parser call with its returned AST or exception. Raw stdout, stderr, and exit
status are retained separately.

The completed follow-up has these observations:

- Both unchanged generated-source bundles compile successfully.
- All 40 input/mode pairs have identical exit status, stdout, and stderr across
  the two bundles. This entails 80 actual probe executions. For each bundle and
  each mode, 15 inputs return without diagnostics and five produce the same
  nonzero error outcomes. Equality is not being inferred from successful exits
  alone.
- The compiled Java code emits the membership of every public token set for
  all 65,536 UTF-16 code units. The five existing sets agree under their observed
  renumbering. The additional set equals the original inclusive range
  `U+0003` through `U+7FFE`. These six comparisons contain 393,216 individual
  memberships and no differences.
- The activity makes 84 native calls: two compilations, two membership probes,
  and 80 corpus probes. Reused source bytes are not counted as independently
  acquired parser implementations.

The evidence supports a change in generated representation with no functional
difference on the stated corpus and character-set predicates. It does not prove
equivalence on every parser input, in every calling context, or after external
mutation of the generated public `BitSet` fields. A strict generated-byte
contract and the bounded functional observations answer different questions.

## Verify and reproduce

From the `artifact` directory, the read-only receiver needs only Python's
standard library:

```bash
python3 -B -m external_sandmark_arboit.verify
python3 -B -m unittest discover -s external_sandmark_arboit/tests -p test_verify.py -v
```

Its default run is `results/external-sandmark-arboit/exploratory-01`; use
`--run PATH` for another retained run. The receiver imports neither the producer
nor the generated Java classes. It checks the exact source/corpus/case frame,
compiled-source identities, declared native commands, raw streams, all pairwise
comparisons, the complete UTF-16 tables, and the summary. It does not launch
native code or certify that an untrusted historical logger was truthful.

A new native execution uses the runtime identity recorded by the original
SandMark acquisition. Its Java 21 executable, release file, and module image
must match the retained identities. The ANTLR runtime JAR is copied from the
original formal host. `com.sun.tools.javac.Main` supplies the compiler; a
standalone `javac` launcher is unnecessary in this retained environment.

```bash
python3 -B -m external_sandmark_arboit.run_study \
  --formal results/external-sandmark/formal-01 \
  --out results/external-sandmark-arboit/fresh-01
python3 -B -m external_sandmark_arboit.verify \
  --run results/external-sandmark-arboit/fresh-01
```

The output directory must be new and beneath `artifact`. A changed runtime is
reported as a reproduction-environment mismatch; this command never edits a
frozen record to substitute another runtime. `producer-freeze.json` is written
before the new native calls. `complete.json` is written after source identities
are rechecked. Parent formal data remain read-only.

The retained history includes `pilot-01`, whose configured standalone `javac`
path was unavailable before any compiler call, and `pilot-02`, which compiled
both source variants through the JDK compiler main class. Those setup/probe
activities are separate from the 84-call follow-up.

## Files and rights

`LexerProbe.java` is the local observation harness. Generated source files and
the original ANTLR corpus inputs retain their source headers. ANTLR 2.7.7 was
developed by Terence Parr; its original `SOFTWARE RIGHTS` notice states that
ANTLR and its generated code are in the public domain and requests attribution.
The unchanged notice is retained as `LICENSE-ANTLR.txt`. The parent SandMark
acquisition retains the algorithm archive and its separate rights information.

`inventory_manifest.json` and `inventory.py` register the exact retained file
domain. Java class files are executable outputs of the recorded compiler;
stdout/stderr files are opaque byte observations; the two additional JAR copies
are explicitly registered scientific containers. They are not temporary files
that the package checker may silently discard.
