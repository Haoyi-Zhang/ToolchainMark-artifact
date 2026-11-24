"""Run the unchanged, source-frozen independent observer study producer."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, default=root)
    parser.add_argument('--out', type=Path, required=True,
                        help='A new output directory; existing results are never replaced.')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--pilot', action='store_true')
    parser.add_argument('--protocol', choices=('legacy', 'current'), default='current')
    args = parser.parse_args()
    producer = 'producer_current' if args.protocol == 'current' else 'producer_legacy'
    command = [sys.executable, '-B', str(Path(__file__).parent / producer / 'run_study.py'),
               '--artifact', str(args.artifact.resolve()), '--out', str(args.out.resolve()),
               '--workers', str(args.workers)]
    if args.pilot:
        command.append('--pilot')
    return subprocess.call(command)


if __name__ == '__main__':
    raise SystemExit(main())
