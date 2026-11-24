# Contributing

Changes should preserve the separation between acquisition, reception, and
scientific interpretation. A bug fix needs a control that exposes the original
behavior, a passing-path test, and a failure-path test. Do not alter retained
observations, expected outcomes, or denominators merely to make a check pass.

Before proposing a change, run:

```bash
python3 scripts/check.py
```

Large experiment outputs belong in the evidence collection, not in source
control. New third-party material must include its source and license boundary.
