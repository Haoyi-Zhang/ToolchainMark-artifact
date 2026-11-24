# Native confirmation on the published LLWM implementation

This directory contains the acquired source subset, fixed confirmation plan,
three diagnostic host programs, a six-line literal-output repair, the native
producer, and an independent read-only receiver. It exercises SemaCall through
its `atoi` and `fgets` interfaces and SideData through its string interface.
These are two techniques and three interfaces from one published artifact,
not three independently sampled products.

The upstream source is from David Schwarzbeck, Jan Schuh, and Marcel Hammrich,
*Register Expansion, SemaCall, and SideData: 3 Low-overhead Dynamic Watermarks
Suitable for Automation in LLVM [Source code and Raw Experiment data]*,
Zenodo, 2024, <https://doi.org/10.5281/zenodo.14234819>. The acquisition manifest
records the archive SHA-256 and exact member paths/hashes. The retained vendor
files keep the upstream source bytes; `literal-output.patch` is applied only
to a separate build tree. The deposit's CC BY 4.0 terms and upstream README are
retained in `UPSTREAM-LICENSE.md` and `UPSTREAM-README.md`.

## Inspect and verify the supplied result

From the artifact directory:

```sh
python3 -B external_llwm/verify_study.py
```

This uses only the Python standard library and the retained files. It does not
run any native executable and does not need LLVM or Eigen. It checks the exact
180-case main frame and separate 12-case known-prefix frame, source/setup
identities, command arguments and raw input/output, binary endpoint digests,
actual relocation bytes, ELF debug-section removal, and all four judgments.
The detailed scope and the six observed boundary-output repetition differences
are described in [RECEIVER.md](RECEIVER.md).

The supplied raw result is under `results/llwm-native/`. `completion.json`
binds all four JSONL files; each row retains actual command observations and
the identities of its IR and ELF files. The producer snapshots are complete.
Absolute paths in command records identify the original execution; the
receiver resolves supplied files relative to the selected result directory.

## Re-execute the frozen study

Use an x86-64 Linux environment with:

- Python 3.10 or later; the recorded execution used Python 3.12.14.
- A matching LLVM 17 installation providing `clang`, `opt`, `llvm-config`,
  development headers, and link libraries. The recorded version was 17.0.6.
- A C++ compiler compatible with those LLVM headers/libraries. The recorded
  compiler was GNU g++ 14.2.0.
- Eigen 3 headers, GNU `patch`, and GNU `readelf`/`strip`. The recorded GNU
  binary utilities were version 2.44.

The LLVM directory must contain the unversioned executable names `clang`,
`opt`, and `llvm-config`. All three must belong to the same LLVM 17 toolchain.
An extracted toolchain must also be able to resolve its shared libraries;
configure its runtime library search path before running the producer.
The driver queries and retains tool versions and binary hashes and checks the
LLVM major version. It does not install dependencies or download source.

For a conventional installation, run from the artifact directory, adjusting
the two dependency paths if necessary:

```sh
python3 -B external_llwm/run_study.py \
  --out /tmp/toolchainmark-llwm-rerun \
  --llvm-bin /usr/lib/llvm-17/bin \
  --eigen-include /usr/include/eigen3 \
  --cxx g++

python3 -B external_llwm/verify_study.py \
  --run /tmp/toolchainmark-llwm-rerun
```

Without root access, the conda-forge LLVM 17.0.6 / Eigen / g++ 14.2 environment
and command shown in the top-level README ("External tools") work as well.

The output path must not exist. The producer preserves the declared plan and
source inputs before building the two upstream plugins and their two repaired
counterparts. It then executes both complete passes, including the separately
reported boundary cases. A second receiver command independently reconstructs
the resulting judgments. It does not assume that new IR/ELF bytes equal those
from the supplied execution.

The recorded environment used one compilation worker and needed approximately
68 seconds for the full producer, including approximately 33 seconds in plugin
setup commands. These are recorded costs for that environment, not a resource
guarantee or a speed comparison. Each native command has a 45-second timeout.

## Result and interpretation

The main frame crosses two source variants, three interfaces, five four-byte
payloads, three optimization settings, and two passes. The unmodified source
recovers `ABCD` literally in all 18 plain-payload cases. In the 72 percent-payload
cases, it passes the recovered text as a `printf` format string: for example,
requested `A%%B` becomes `A%B`. The local repair supplies `"%s"` as the format
and the recovered text as data. It satisfies literal output in all 90 repaired
cases. This is one shared root cause, independently reproduced through the
three exercised interfaces.

Ordinary exact-output comparison detects the same defect. ER01 compares the
correct-key output against the declared host-output channel plus literal
payload. ER02 checks the particular numeric-distinct ordinary input `4321`.
ER03 and ER04 require a source that satisfies ER01 before interpreting
artifact-only relocation or observed debug stripping. The 72 upstream cases
with invalid source output are therefore inadmissible for those downstream
preservation comparisons. A successful tool invocation alone cannot validate
the source premise.

The known numeric-prefix limitation uses key `12345test` and ordinary input
`12345abcd`. All 12 executions add output; the repair does not address this
documented behavior. Six paired raw outputs vary between passes. No stable
payload recovery or universal wrong-key rejection is claimed for this frame.
The upstream randomized embedding and debug paths can also produce different
IR/ELF bytes while the declared main output observations repeat.

The defect was identified through source inspection and exploratory native
probes before this locally frozen confirmation plan. This is not blind
discovery or external preregistration. The repair is confirmed by the retained
local executions; no maintainer acceptance or confirmation is claimed.
The hosts are synthetic diagnostic probes of the published interfaces, and
the results do not estimate defect prevalence in deployed watermark products.
