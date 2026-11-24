#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"
OUT=${1:?Supply a NEW matrix file for the evidence-gated design-subject run}
WORKERS=${2:-4}
python3 -m toolchainmark.cli run --out "$OUT" --design-only --workers "$WORKERS"
