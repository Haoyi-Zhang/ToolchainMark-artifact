"""Launch either frozen continuation producer and retain its real process receipt.

This convenience wrapper is not part of the recorded measurement producer.
It reproduces the original shell-level stdout/stderr/exit-code capture for a
fresh destination. It never writes the distributed original results.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from postfreeze_challenge.common import require, sha, utc, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study', required=True, choices=('postfreeze', 'recovery'))
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    require(not out.exists(), 'Refusing an existing study destination')
    out.parent.mkdir(parents=True, exist_ok=True)
    logs = Path(tempfile.mkdtemp(prefix='study-process-', dir=out.parent))
    module = 'postfreeze_challenge.run' if args.study == 'postfreeze' else 'recovery_extension.run'
    command = [sys.executable, '-B', '-m', module, '--out', str(out)]
    environment = dict(os.environ)
    environment['PYTHONPATH'] = os.pathsep.join((str(ROOT / 'src'), str(ROOT), environment.get('PYTHONPATH', '')))
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    with (logs / 'stdout.txt').open('wb') as stdout, (logs / 'stderr.txt').open('wb') as stderr:
        process = subprocess.run(command, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr, check=False)
    if not out.is_dir():
        print(f'Producer exited {process.returncode} before creating its record; console files retained at {logs}.')
        return process.returncode or 1
    entries = []
    for stream in ('stdout', 'stderr'):
        target = out / ('campaign.' + stream + '.txt')
        require(not target.exists(), 'Refusing an existing process console record')
        shutil.move(str(logs / (stream + '.txt')), target)
        entries.append({'path': target.name, 'bytes': target.stat().st_size, 'sha256': sha(target.read_bytes())})
    logs.rmdir()
    write_json(out / 'launch-receipt.json', {'recorded_utc': utc(), 'exit_code': process.returncode,
               'logs': entries, 'command': command, 'scope': 'Actual fresh producer process return and captured console files.'})
    print(f'Producer exited {process.returncode}; all emitted records retained at {out}.')
    return process.returncode


if __name__ == '__main__':
    raise SystemExit(main())
