# Compact reference results

This directory contains the smallest retained fixtures needed by the offline test
and receiver-control suites. Large native work directories and repeated artifact
bytes are deliberately excluded from source control.

The compact files are not a substitute for the complete evidence collection. Use
`scripts/import_evidence.py` in a disposable checkout and then run
`scripts/check.py --full-evidence` to receive the full studies. The importer never
changes source code and refuses accidental overwrites unless explicitly asked.
