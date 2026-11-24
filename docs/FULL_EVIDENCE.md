# Full evidence collection

The code repository carries compact fixtures so that cloning, review, and
continuous integration remain practical. The complete evidence collection is a
separate research object because it contains native work directories and many
repeated artifact bytes. Keeping that object outside source control prevents a
large experimental archive from obscuring the implementation and tests.

The object is `ToolchainMark_evidence.tar.zst` (DOI 10.5281/zenodo.24491149;
size, SHA-256 and unpack location in the top-level README). It extracts to an
`artifact/` directory, which is the `--source` below. Attach it only to a
disposable checkout:

```bash
tar --zstd -xf ToolchainMark_evidence.tar.zst
python3 scripts/import_evidence.py \
  --source /path/to/extracted/artifact \
  --destination /path/to/disposable/ToolchainMark \
  --link --replace
```

`--link` uses hard links for a local read-only checkout and avoids another
multi-gigabyte byte copy. Omit it when source and destination are on different
filesystems. The importer refuses to overwrite source code, imports only the
active study datasets, normalizes the current declarative-study location, and
writes a machine-readable import report.

Create the recorded scientific-dependency environment and run the complete
receiver suite in that disposable checkout:

```bash
python3 scripts/install_local.py .venv-science --with-system-science
.venv-science/bin/python -B scripts/validate.py --suite full --timeout 7200
```

The complete suite receives correspondence, projection, request-history,
state-budget, GeMTest, CTF, decoder-session, LLVM, and SandMark records.
It rederives judgments and checks the retained byte and command bindings; it
does not claim that external native programs were newly executed. Run the
ordinary repository checks separately:

```bash
python3 scripts/install_local.py .venv
.venv/bin/python -B scripts/validate.py --suite quick
```

Do not commit the imported evidence tree. External inputs whose redistribution
terms are restricted remain outside both objects; their module documentation
defines the acquisition boundary.
