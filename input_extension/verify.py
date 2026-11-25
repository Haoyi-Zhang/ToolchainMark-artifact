"""Recompute every input-extension verdict from the raw observations.

    python -B input_extension/verify.py --data DIR [--write]

Checks the frozen frame, the completion binding and the observation sets, then
derives (per case and input set) the marked-versus-unmarked verdict under two
observation rules: stdout only (the catalog's MR02 rule) and the full triple of
exit status, stdout and stderr.  ``--write`` stores DIR/summary.json; without
it the recomputed summary must equal the stored one.  Imports no runner and
executes no program.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import re
from pathlib import Path

SANITIZER_PATTERN = re.compile(r'(AddressSanitizer|LeakSanitizer|runtime error:|UndefinedBehaviorSanitizer)')
SETS = ('fixed', 'boundary', 'randomized', 'malformed')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def judge(case, chosen_sets, rule):
    builds = case['builds']
    if any(builds.get(arm, {}).get('status') != 'OK' for arm in ('unmarked', 'marked')):
        return 'INADMISSIBLE'
    left = [r for r in builds['unmarked']['runs'] if r['set'] in chosen_sets]
    right = [r for r in builds['marked']['runs'] if r['set'] in chosen_sets]
    require([(r['set'], r['input']) for r in left] == [(r['set'], r['input']) for r in right], 'input order differs')
    if any(r['status'] != 'OK' for r in left + right):
        return 'INADMISSIBLE'
    for a, b in zip(left, right):
        if rule == 'stdout' and a['stdout'] != b['stdout']:
            return 'INCONSISTENT'
        if rule == 'triple' and (a['exit'], a['stdout'], a['stderr']) != (b['exit'], b['stdout'], b['stderr']):
            return 'INCONSISTENT'
    return 'SATISFIED'


def derive(data: Path):
    protocol = json.loads((data / 'protocol.json').read_text())
    completion = json.loads((data / 'completion.json').read_text())
    raw = (data / 'observations.jsonl.gz').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == completion['observations_sha256'], 'observation digest mismatch')
    rows = [json.loads(line) for line in gzip.decompress(raw).decode('utf-8').splitlines() if line.strip()]
    by_id = {row['id']: row for row in rows}
    cases = protocol['cases']
    sanitizer = protocol['sanitizer_cases']
    require(len(by_id) == len(rows) == len(cases) + len(sanitizer), 'frame cardinality mismatch')
    require([r['id'] for r in rows] == [c['id'] for c in cases] + [c['id'] for c in sanitizer], 'frame order mismatch')
    expected_inputs = [(s, v) for s in SETS for v in protocol['inputs'][s]]

    verdicts = collections.defaultdict(collections.Counter)
    channel_differences = collections.Counter()
    unavailable_runs = 0
    executions = 0
    stdout_only_misses = []
    for case in cases:
        row = by_id[case['id']]
        for arm in ('unmarked', 'marked'):
            build = row['builds'][arm]
            if build['status'] == 'OK':
                require([(r['set'], r['input']) for r in build['runs']] == expected_inputs, 'run set mismatch')
                executions += len(build['runs'])
                unavailable_runs += sum(r['status'] != 'OK' for r in build['runs'])
        for label, chosen in (('fixed', ('fixed',)), ('randomized', ('randomized',)),
                              ('boundary', ('boundary',)), ('malformed', ('malformed',)),
                              ('all', SETS)):
            for rule in ('stdout', 'triple'):
                verdicts[f"{case['variant']}|{label}|{rule}"][judge(row, chosen, rule)] += 1
        if judge(row, SETS, 'triple') != judge(row, ('fixed',), 'stdout'):
            stdout_only_misses.append(case['id'])
        b = row['builds']
        if b['unmarked']['status'] == b['marked']['status'] == 'OK':
            for x, y in zip(b['unmarked']['runs'], b['marked']['runs']):
                if x['status'] == y['status'] == 'OK':
                    for channel in ('exit', 'stdout', 'stderr'):
                        if x[channel] != y[channel]:
                            channel_differences[f"{case['variant']}|{x['set']}|{channel}"] += 1

    # Cross-configuration agreement of unmarked CLEAN string builds.
    cross = {}
    for host in sorted({c['host'] for c in cases}):
        group = [by_id[c['id']] for c in cases if c['host'] == host and c['variant'] == 'CLEAN' and c['carrier'] == 'string']
        observed = [tuple((r['exit'], r['stdout'], r['stderr']) for r in g['builds']['unmarked']['runs'])
                    for g in group if g['builds']['unmarked']['status'] == 'OK']
        cross[host] = {'builds': len(observed), 'distinct_observation_vectors': len(set(observed))}

    findings = []
    sanitizer_runs = 0
    for case in sanitizer:
        row = by_id[case['id']]
        if row.get('status') != 'OK':
            findings.append({'id': case['id'], 'status': row.get('status'), 'reason': row.get('reason')})
            continue
        for r in row['runs']:
            sanitizer_runs += 1
            if r['status'] != 'OK' or SANITIZER_PATTERN.search(r.get('stderr', '')) or r.get('exit') in (97, 98):
                findings.append({'id': case['id'], 'set': r['set'], 'input': r['input'],
                                 'exit': r.get('exit'), 'stderr_head': r.get('stderr', '')[:300]})

    def tally(variant, label, rule):
        c = verdicts[f'{variant}|{label}|{rule}']
        return {'S': c['SATISFIED'], 'I': c['INCONSISTENT'], 'IA': c['INADMISSIBLE']}

    table = {variant: {f'{label}/{rule}': tally(variant, label, rule)
                       for label in ('fixed', 'boundary', 'randomized', 'malformed', 'all')
                       for rule in ('stdout', 'triple')}
             for variant in ('CLEAN', 'M10', 'M11')}
    return {
        'schema': protocol['schema'] + '-summary',
        'cases': len(cases), 'cases_per_variant': dict(collections.Counter(c['variant'] for c in cases)),
        'inputs_per_execution_set': {s: len(protocol['inputs'][s]) for s in SETS},
        'host_executions': executions, 'unavailable_host_executions': unavailable_runs,
        'build_failures': sum(by_id[c['id']]['builds'][a]['status'] != 'OK' for c in cases for a in ('unmarked', 'marked')),
        'verdicts': table,
        'channel_differences': dict(sorted(channel_differences.items())),
        'judgment_changes_against_catalog_rule': len(stdout_only_misses),
        'judgment_changes_examples': stdout_only_misses[:10],
        'cross_configuration': cross,
        'hosts_with_cross_configuration_difference': sorted(h for h, v in cross.items() if v['distinct_observation_vectors'] > 1),
        'sanitizer_cases': len(sanitizer), 'sanitizer_executions': sanitizer_runs,
        'sanitizer_findings': findings,
        'elapsed_seconds': completion['elapsed_seconds'], 'workers': completion['workers'],
        'tools': protocol['tools'],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args(argv)
    summary = derive(args.data)
    if args.write:
        (args.data / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
        ok = True
    else:
        ok = json.loads((args.data / 'summary.json').read_text()) == summary
    print(json.dumps({'verdict': 'PASS' if ok else 'FAIL', 'cases': summary['cases'],
                      'judgment_changes_against_catalog_rule': summary['judgment_changes_against_catalog_rule'],
                      'sanitizer_findings': len(summary['sanitizer_findings'])}, indent=2))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
