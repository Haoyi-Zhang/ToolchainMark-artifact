"""Stable relation identifiers and shared test inputs.

The executable semantics live in :mod:`toolchainmark.admission`. Keeping one
implementation avoids drift between a catalog-only reference and the evaluator
used by the acquisition scripts.
"""

PAYLOAD1 = b"Morph-01"
PAYLOAD2 = b"Second-2"
KEY1 = "key-alpha"
KEY2 = "key-beta"
INPUTS = [0, 1, 5, 13, 144, 99991]
RELATION_IDS = tuple(f"MR{i:02d}" for i in range(1, 15))
