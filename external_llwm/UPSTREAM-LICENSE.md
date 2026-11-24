# Upstream attribution and local changes

The vendored files are an unchanged subset of **Register Expansion, SemaCall, and SideData: 3 Low-overhead Dynamic Watermarks Suitable for Automation in LLVM [Source code and Raw Experiment data]**, deposited by David Schwarzbeck, Jan Schuh and Marcel Hammrich (2024; creators listed by the deposit), DOI https://doi.org/10.5281/zenodo.14234819.

The Zenodo deposit identifies its license as **Creative Commons Attribution 4.0 International**: https://creativecommons.org/licenses/by/4.0/ . The deposit metadata and exact archive/file identities are recorded alongside this notice. The upstream authors do not endorse this evaluation or the local repair. The original copyright, authorship and file notices are retained.

`literal-output.patch` is a local repair to three output-generation headers. It supplies a constant `%s` format and passes the generated message as the string argument. The native campaign keeps unmodified and repaired sources separate. The plugin wrapper and build recipe are local additions for linking the unchanged pass files against the public LLVM 17 installation. No upstream maintainer approval or historical upstream fix is asserted.

LLVM/Clang 17 and Eigen 3.4 are external build dependencies; their distributions and licenses are available from their publishers. The full compiler installation is not redistributed here.
