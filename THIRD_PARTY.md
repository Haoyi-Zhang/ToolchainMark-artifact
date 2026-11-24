# Third-party materials

The MIT license in this repository applies only to original ToolchainMark code.
The following materials retain their upstream terms.

- `external_llwm/vendor/` contains the attributed source subset from the public
  LLWM deposit at DOI `10.5281/zenodo.14234819`. The deposit is licensed under
  CC BY 4.0. `external_llwm/UPSTREAM-LICENSE.md` records attribution and local
  changes. LLVM and Eigen are external build dependencies and are not vendored.
- `external_sandmark/` contains selected source and diagnostic material from the
  archived SandMark source snapshot. The University of Arizona noncommercial
  notice and original copyright statements remain in
  `external_sandmark/licenses/` and the diagnostic source directories. The
  complete SandMark distribution is acquired separately and is not covered by
  this repository's MIT license.
- ANTLR material used by the SandMark experiments retains its component notices.
  Those notices do not extend to unrelated language runtimes.
- `ctf_comparison/vendor/causal_testing/` is the pinned Causal Testing Framework
  source used by the comparison and retains its upstream MIT license.
- `ctf_comparison/vendor/lifelines/exceptions.py` is the minimal upstream
  exception surface imported by that CTF path and retains the MIT notice in
  `ctf_comparison/vendor/LICENSE-LIFELINES.txt`.
- `framework_comparison/` documents the exact GeMTest source boundary used by
  the compatibility experiment. Any separately installed framework packages
  retain their own licenses.
- `external-transfer/` stores identities and acquisition instructions rather
  than redistributing upstream source whose redistribution terms were not
  established.

Generated native artifacts inherit the terms of their source inputs and tool
chains. Review the relevant module README before redistribution.
