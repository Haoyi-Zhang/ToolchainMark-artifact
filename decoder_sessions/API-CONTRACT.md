# Primary source basis for sequential recognition

The fixed implementation is the Qualitas archive of SandMark 3.4 at commit
`5e4642c83d802968cfa47c1a362fbecbd72f5802`. The source and tool JAR are the same
archived materials already identified by `external_sandmark/acquisition-lock.json`.
The source tree was read directly; this is not a claim of a reproducible
source-to-binary build or a current maintained release.

## Interface and lifecycle

[`StaticWatermarker.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/watermark/StaticWatermarker.java)
defines `recognize(StaticRecognizeParameters)` as an iterator of found watermarks.
Its parameter factory copies the current global Key into a fresh request object.

The executable GUI supplies the basis for reuse. In
[`AlgorithmComboBox.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/gui/AlgorithmComboBox.java),
each selectable algorithm is constructed once and the selected object is
returned subsequently. Repeated actions in
[`RecognizeButton.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/gui/RecognizeButton.java)
reuse that object and clear the visualization GraphList.
[`CurrentApplicationTracker.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/gui/CurrentApplicationTracker.java)
reloads the Application when its pathname changes. This supports the studied
sequential path-switching lifecycle. Same-path GUI caching, overlapping
iterators, reused Applications, embedding-before-recognition histories, and
concurrent recognition are distinct uses and are not tested here.

[`SandmarkCLI.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/smash/SandmarkCLI.java)
sets Key, obtains parameters and fully exhausts the recognition iterator.
The study uses that observation policy with the public `recognize` call directly.
The GUI forwarding wrapper can catch `WatermarkingException` and return null;
that path is not used to erase native exception evidence.

The inspected API definitions and bundled watermarking help do not state an
explicit one-use, reset, or thread-safety rule. That limited reading is not a
universal safety guarantee. The study relies on the specific shipped sequential
use and deliberately excludes overlapping operations and recovery after errors.
R reuses the public StaticWatermarker algorithm object. Native implementations
such as QP, GTW and Arboit still construct a new internal recognizer or iterator
for each call. The harness does not force reuse of an exhausted iterator or
invent a reset interface that the original algorithm lacks.

## State and authorized context

[`Random.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/util/Random.java)
provides one JVM singleton initialized with seed zero. QP's
[`AssignLV.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/watermark/assignlv/AssignLV.java)
reseeds it from the request key during recognition; the harness preserves that
native behavior.

[`GTWRecognizer.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/watermark/gtw/GTWRecognizer.java)
retains the algorithm configuration and reads Key File during `next()`. Every
iterator therefore finishes before the next request changes that property.

Davidson/Myhrvold and Stern use an original JAR. In
[`ObjectWatermark.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/watermark/objectwm/ObjectWatermark.java),
Stern's first recognition derives the original pathname from the marked
filename, while later calls use the configured Original File. The study retains
the `host_wm.jar` / `host.jar` convention and configures the correct original on
every call. Stern verifies its supplied candidate and returns that candidate
after a positive verification.

Finally,
[`Application.java`](https://github.com/JavaQualitasCorpus/sandmark-3.4/blob/5e4642c83d802968cfa47c1a362fbecbd72f5802/src/sandmark/program/Application.java)
automatically reads a sibling `.smconfig` when one exists. The study therefore
binds this authorized SDK configuration as well as the target, original and
generated key, including explicit absence. This prevents an unrecorded context
change from being mistaken for a decoder-object effect.

The full inspected-file hashes and line ranges are in
`source-contract-index.json`. Statements about these selected paths do not
claim an exhaustive audit of every transitive SandMark implementation class.
