"""Measure end-to-end cost of the principal fresh activities.

Run from an evidence-attached checkout (see README, "Complete evidence").
Each step runs the documented producer and receiver commands for one activity
into a new directory under reruns/, sequentially, and records wall time,
user and system CPU of the child processes, the peak resident set size of the
largest child, and the bytes written.  Orchestration, workspace setup and
cleanup are inside the measured interval.

    python3 -B scripts/measure_end_to_end.py --out results/end-to-end-cost/summary.json [--steps a,b]
    python3 -B scripts/measure_end_to_end.py --check results/end-to-end-cost/summary.json

The summary also records whether the fresh projection reproduces the retained
transport accounting and whether the fresh correspondence challenge reproduces
the 1/8/18 rejections (only when the complete evidence is attached).
``--check`` reruns nothing: it recounts the adaptation surface from the
current sources and validates the stored record.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = [sys.executable, '-B']


def steps(base: Path):
    return {
        'correspondence-challenge': [
            PY + ['-m', 'evidence_correspondence.run', 'freeze', '--out', str(base / 'correspondence')],
            PY + ['-m', 'evidence_correspondence.run', 'execute', '--out', str(base / 'correspondence')],
            PY + ['-m', 'evidence_correspondence.verify', '--data', str(base / 'correspondence')]],
        'history-control': [
            PY + ['-m', 'evidence_projection.run_history_control', '--out', str(base / 'history')],
            PY + ['-m', 'evidence_projection.verify_history', '--data', str(base / 'history')]],
        'state-budget': [
            PY + ['-m', 'state_budget.run', 'freeze', '--out', str(base / 'state-budget')],
            PY + ['-m', 'state_budget.run', 'execute', '--out', str(base / 'state-budget')],
            PY + ['-m', 'state_budget.verify', '--data', str(base / 'state-budget')]],
        'projection-population': [
            PY + ['-m', 'evidence_projection.run', '--out', str(base / 'projection')],
            PY + ['-m', 'evidence_projection.analyze_transport', '--data', str(base / 'projection')],
            PY + ['-m', 'evidence_projection.verify_results', '--data', str(base / 'projection')]],
    }


def tree_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    seen, total = set(), 0
    for item in path.rglob('*'):
        if item.is_file() and not item.is_symlink():
            st = item.stat()
            if (st.st_dev, st.st_ino) not in seen:
                seen.add((st.st_dev, st.st_ino))
                total += st.st_size
    return total


ADAPTERS = {
    'reference ELF carriers': ['declarative_study/reference_adapter.py'],
    'LLVM SemaCall/SideData': ['declarative_study/llwm_adapter.py', 'declarative_study/build_llwm_plan.py'],
    'SandMark static algorithms': ['external_sandmark/adapter.py', 'external_sandmark/SandmarkBridge.java'],
    'SandMark decoder sessions': ['decoder_sessions/adapter.py', 'decoder_sessions/SessionBridge.java'],
}
PLANS = {
    'reference ELF carriers': ['declarative_study/plans/MR%02d.json' % i for i in range(1, 15)]
                              + ['declarative_study/plans/SR01.json'],
    'LLVM SemaCall/SideData': ['declarative_study/plans/LLWM-%s.json' % n for n in ('atoi', 'fgets', 'sidedata')],
}


def adaptation_surface():
    """Domain-specific code and declarations a new watermark implementation must supply."""
    def lines(rel):
        text = (ROOT / rel).read_text(encoding='utf-8').splitlines()
        return sum(bool(x.strip()) and not x.lstrip().startswith(('#', '//')) for x in text)

    def plan_size(rel):
        plan = json.loads((ROOT / rel).read_text(encoding='utf-8'))
        actions = [a for block in plan['actions'] for a in (block['parallel'] if 'parallel' in block else [block])]
        return len(actions), len(plan['obligations']), sum(len(o['requires']) for o in plan['obligations'])

    out = {}
    for domain, files in ADAPTERS.items():
        row = {'adapter_files': files, 'adapter_lines': sum(lines(f) for f in files)}
        if domain in PLANS:
            sizes = [plan_size(p) for p in PLANS[domain]]
            row.update(plans=len(sizes), plan_actions=sum(s[0] for s in sizes),
                       plan_obligations=sum(s[1] for s in sizes), plan_requirements=sum(s[2] for s in sizes))
        out[domain] = row
    out['counting_rule'] = 'Lines excluding blank and full-line # or // comments; docstrings count.'
    return out


def measure(name, commands, base):
    env = dict(os.environ, PYTHONPATH=f'{ROOT / "src"}{os.pathsep}{ROOT}')
    record = {'step': name, 'commands': [' '.join(Path(c).name if i == 0 else c for i, c in enumerate(cmd))
                                         for cmd in commands]}
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak = 0
    start = time.perf_counter()
    for cmd in commands:
        log = output_log = base / f'{name}.stderr.log'
        with output_log.open('ab') as err:
            proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=err)
            _, wait_status, rusage = os.wait4(proc.pid, 0)
            proc.returncode = os.waitstatus_to_exitcode(wait_status)
        peak = max(peak, rusage.ru_maxrss)
        if proc.returncode != 0:
            record.update(status='FAILED', failed_command=' '.join(cmd[2:]),
                          stderr=log.read_text(errors='replace')[-2000:])
            return record
    wall = time.perf_counter() - start
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    output = base / {'correspondence-challenge': 'correspondence', 'history-control': 'history',
                     'state-budget': 'state-budget', 'projection-population': 'projection'}[name]
    record.update(status='PASS', wall_seconds=round(wall, 3),
                  user_cpu_seconds=round(after.ru_utime - before.ru_utime, 3),
                  system_cpu_seconds=round(after.ru_stime - before.ru_stime, 3),
                  peak_child_rss_mib=round(peak / 1024, 1), output_bytes=tree_bytes(output))
    return record


def relativize(summary, work: Path):
    """Replace the absolute work directory in recorded commands by its path relative to the checkout."""
    prefix = str(work.resolve())
    try:
        shown = work.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        shown = 'WORK'
    for step in summary['steps']:
        step['commands'] = [c.replace(prefix, shown) for c in step['commands']]
    return summary


def reproduction(work: Path):
    """Compare the fresh outputs with the retained evidence when it is attached to this checkout."""
    out = {}
    retained = ROOT / 'results' / 'evidence-projection' / 'completed' / 'transport-summary.json'
    fresh = work / 'projection' / 'transport-summary.json'
    if retained.exists() and fresh.exists():
        old, new = (json.loads(p.read_text(encoding='utf-8')) for p in (retained, fresh))
        out['projection_transport'] = {
            arm: {'fresh': {'median': new[arm]['fractions']['median'], 'max': new[arm]['fractions']['max'],
                            'larger': new[arm]['larger'], 'smaller': new[arm]['smaller']},
                  'retained': {'median': old[arm]['fractions']['median'], 'max': old[arm]['fractions']['max'],
                               'larger': old[arm]['larger'], 'smaller': old[arm]['smaller']}}
            for arm in ('compact', 'indented')}
        out['projection_transport']['identical'] = all(
            out['projection_transport'][arm]['fresh'] == out['projection_transport'][arm]['retained']
            for arm in ('compact', 'indented'))
    summary = work / 'projection' / 'summary.json'
    if summary.exists():
        out['projection_judgments'] = json.loads(summary.read_text(encoding='utf-8')).get('judgments')
    corr = work / 'correspondence' / 'summary.json'
    if corr.exists():
        layers = json.loads(corr.read_text(encoding='utf-8'))['layers']
        out['correspondence_rejections'] = {k: v['invalid_rejected'] for k, v in layers.items()}
    budget = work / 'state-budget' / 'summary.json'
    if budget.exists():
        data = json.loads(budget.read_text(encoding='utf-8'))
        out['state_budget'] = {k: data[k] for k in ('fresh_cases', 'actual_tested_extract_calls')}
    return out


def check(path: Path) -> int:
    """Recount the adaptation surface and validate the stored summary without rerunning anything."""
    stored = json.loads(path.read_text(encoding='utf-8'))
    errors = []
    if stored.get('schema') != 'toolchainmark-end-to-end-cost-v1':
        errors.append('schema')
    if stored.get('adaptation_surface') != adaptation_surface():
        errors.append('adaptation surface differs from the current sources')
    names = [s.get('step') for s in stored.get('steps', [])]
    if names != list(steps(Path('WORK'))):
        errors.append('steps differ from the declared protocol')
    for s in stored.get('steps', []):
        if s.get('status') != 'PASS' or not all(s.get(k, -1) >= 0 for k in (
                'wall_seconds', 'user_cpu_seconds', 'system_cpu_seconds', 'peak_child_rss_mib', 'output_bytes')):
            errors.append('step %s incomplete' % s.get('step'))
    rep = stored.get('reproduction', {})
    if rep.get('projection_transport', {}).get('identical') is not True:
        errors.append('projection transport not reproduced')
    if rep.get('correspondence_rejections') != {'oracle-replay': 1, 'plan-receiver': 8, 'native-binding': 18}:
        errors.append('correspondence counts not reproduced')
    print(json.dumps({'verdict': 'PASS' if not errors else 'FAIL', 'errors': errors}, indent=2))
    return 0 if not errors else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--steps', default='correspondence-challenge,history-control,state-budget,projection-population')
    parser.add_argument('--work', type=Path, default=ROOT / 'reruns' / 'end-to-end')
    parser.add_argument('--check', type=Path, help='validate a stored summary and exit')
    parser.add_argument('--finalize', type=Path,
                        help='add path-relativized commands and the reproduction record to a raw summary')
    args = parser.parse_args(argv)
    if args.check:
        return check(args.check)
    if args.finalize:
        raw = json.loads(args.finalize.read_text(encoding='utf-8'))
        raw = relativize(raw, args.work)
        raw['reproduction'] = reproduction(args.work.resolve())
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(raw, indent=2, sort_keys=True) + '\n')
        return 0
    if args.out is None:
        parser.error('--out is required')
    if args.work.exists():
        shutil.rmtree(args.work)
    args.work.mkdir(parents=True)
    plan = steps(args.work.resolve())
    results = [measure(name, plan[name], args.work.resolve()) for name in args.steps.split(',')]
    summary = {'schema': 'toolchainmark-end-to-end-cost-v1', 'platform': platform.platform(),
               'python': sys.version.split()[0], 'cpu_count': os.cpu_count(), 'steps': results,
               'adaptation_surface': adaptation_surface(),
               'scope': 'Sequential documented producer and receiver commands; wall time includes process start, '
                        'workspace creation, native tool invocations, record writing and cleanup.'}
    summary = relativize(summary, args.work)
    summary['reproduction'] = reproduction(args.work.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if all(r['status'] == 'PASS' for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
