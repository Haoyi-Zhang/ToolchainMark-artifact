"""Read-only verification of fresh paired observations and retained producer inputs.

This verifies retained data, not an independently witnessed execution history.
The independent parser is replayed from the producer used by the live study.
No framework parser, admission code, or seeded extraction code is imported.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import statistics
import sys

HERE = Path(__file__).resolve().parent
observe = None


def read(path):
    return json.loads(Path(path).read_text())


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def require(value, description):
    if not value:
        raise AssertionError(description)


def diagnosis(pair, reason):
    if pair == ['SATISFIED', 'SATISFIED']:
        return 'both-clauses-satisfied'
    if pair == ['INCONSISTENT', 'INADMISSIBLE']:
        return 'transformation-postcondition-violated'
    if pair == ['SATISFIED', 'INCONSISTENT']:
        return 'extraction-clause-violated'
    if pair == ['SATISFIED', 'INADMISSIBLE'] and reason in {
            'target-changed-during-extraction', 'followup_unchanged_during_extraction'}:
        return 'observed-target-changed'
    return 'other-inadmissible-observation'


def source_checks(run, artifact, producer):
    manifest = read(run / 'source-inputs.json')
    require(len({(x['root'], x['path']) for x in manifest}) == len(manifest),
            'duplicate producer source identity')
    for item in manifest:
        saved = run / 'source-snapshot' / item['root'] / item['path']
        current = (producer if item['root'] == 'prototype' else artifact) / item['path']
        require(identity(saved.read_bytes())['sha256'] == item['sha256'], str(saved))
        require(identity(current.read_bytes())['sha256'] == item['sha256'], str(current))
    imports = {}
    for filename in ('independent_observer.py', 'direct_oracle.py'):
        tree = ast.parse((producer / filename).read_text())
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules += [x.name for x in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules.append(node.module or '')
        require(all(not x.startswith('toolchainmark') for x in modules), filename + ' imports framework')
        imports[filename] = sorted(set(modules))
    return {'frozen_inputs': len(manifest), 'current_and_snapshot_hashes_match': True,
            'observer_imports': imports}


def verify_case(case, row, plan, stats, tool_control=False):
    direct = read(case / 'direct.json')
    reference = read(case / 'reference.json')
    require(read(case / 'comparison.json') == row, str(case) + ': comparison differs')
    events = direct['observer_events']
    views = {}
    raw = {}
    for event in events:
        role = event['role']
        require(role not in raw, 'duplicate capture role')
        data = (case / 'direct/observations' / (role + '.bin')).read_bytes()
        raw[role] = data
        require(identity(data) == event['identity'], 'capture identity mismatch')
        if event['parse']:
            views[role] = observe(data, row['carrier'], plan['key'])
            require(views[role] == event['observation'], 'independent parser replay mismatch')
        else:
            require(event['observation'] is None, 'unparsed capture has a parsed view')
        stats['captured_files'] += 1
    protocols = [json.loads(line) for line in (case / 'direct/protocol.jsonl').read_text().splitlines()]
    for index, entry in enumerate(protocols):
        require(json.loads(entry['raw_response']) == entry['response'], 'raw protocol response mismatch')
        if tool_control and index == 3:
            require(entry['response']['status'] == 'unavailable' and
                    entry['response']['exception'] == 'ExtractionError' and
                    entry['response']['kind'] == 'tool', 'tool failure was converted to a domain outcome')
        else:
            require(entry['response']['status'] == 'ok', 'unexpected unavailable formal protocol step')
    require([p['request']['op'] for p in protocols[:3]] == ['build', 'extract', 'remove'],
            'missing source/removal protocol sequence')
    request = protocols[0]['request']
    require((Path(request['host']).name, request['payload'], request['key'],
             request['compiler'], request['optimization']) ==
            (row['host'], plan['payload_hex'], plan['key'], plan['compiler'], plan['optimization']),
            'build request differs from frozen plan')
    expected = {'kind': 'payload', 'value': plan['payload_hex']}
    require(views['source'] == expected == protocols[1]['response']['observation'],
            'source validity lacks matching physical and tested observations')
    require(raw['postcondition'] == raw['postcondition-current'], 'TR01 currentness mismatch')
    permitted = {'absent', 'wrong-key', 'checksum', 'malformed', 'version'} if row['carrier'] == 'string' else {'absent'}
    physical = views['postcondition']
    removed = physical['kind'] == 'rejection' and physical['value'] in permitted
    transform = 'SATISFIED' if removed else 'INCONSISTENT'
    extraction = 'INADMISSIBLE'
    if removed:
        require(len(protocols) == 4 and protocols[3]['request']['op'] == 'extract',
                'removed carrier lacks the tested extraction')
        require(raw['before-extraction'] == raw['postcondition'], 'pre-extraction identity mismatch')
        if raw['after-extraction'] == raw['postcondition'] and protocols[3]['response']['status'] == 'ok':
            extraction = 'SATISFIED' if protocols[3]['response']['observation'] == physical else 'INCONSISTENT'
    else:
        require(len(protocols) == 3 and 'after-extraction' not in raw,
                'unperformed downstream extraction must remain unobserved')
    computed_pair = [transform, extraction]
    for arm, result in (('direct', direct), ('reference', reference)):
        pair = [result['transform_verdict'], result['extraction_verdict']]
        require(pair == computed_pair == row[arm + '_pair'], 'stage verdict differs from retained evidence')
        require(diagnosis(pair, result['extraction_reason']) == row[arm + '_diagnosis'],
                'stage-diagnostic category mismatch')
    for role in ('source', 'postcondition', 'after-extraction'):
        p = case / 'reference/observations' / (role + '.bin')
        if role not in raw:
            require(not p.exists(), 'asymmetric missing byte snapshot')
            stats['paired_unperformed_after_capture'] += 1
        else:
            other = p.read_bytes()
            require(other == raw[role], 'arm artifact bytes differ')
            require(reference['snapshots'][role]['sha256'] == identity(other)['sha256'],
                    'reference byte identity differs')
            stats['actual_paired_byte_comparisons'] += 1
    facts = reference['extraction_record']['admission']
    observations = reference['extraction_record']['observations']
    require(observations['source_carrier'] == views['source'], 'framework source view differs')
    require(observations['followup_carrier'] == physical, 'framework follow-up view differs')
    require(facts['carrier_removed'] == removed, 'framework removal fact differs')
    for role, name in (('source', 'source'), ('postcondition', 'followup')):
        require(observations['removal_snapshots'][name] == identity(raw[role]),
                'framework snapshot identity differs')
    if removed:
        require(facts['followup_snapshot_current'] is True, 'framework precheck differs')
        if tool_control:
            require(reference['extraction_reason'] == 'execution-error:RuntimeError' and
                    'followup' not in observations and 'followup_unchanged_during_extraction' not in facts,
                    'framework tool failure was treated as a domain observation')
            require(direct['extraction_reason'] == 'extraction-unavailable' and
                    raw['after-extraction'] == raw['postcondition'], 'direct tool failure attribution differs')
        else:
            require(facts['followup_unchanged_during_extraction'] ==
                    (raw['after-extraction'] == raw['postcondition']), 'framework postcheck differs')
            require(observations['followup'] == protocols[3]['response']['observation'],
                    'tested extraction observation differs across arms')
    tr = reference['transform_record']
    require(all(tr['admission'].values()) and tr['observations']['followup_carrier'] == physical,
            'TR01 premises or physical view differ')
    require(reference['tested_followup_calls'] == int(removed), 'reference extraction call count differs')
    cost = direct['observer_cost']
    for key, value in {
            'captures': len(events), 'parsed_views': sum(e['parse'] for e in events),
            'captured_bytes': sum(e['identity']['bytes'] for e in events),
            'read_ns': sum(e['read_ns'] for e in events),
            'parse_ns': sum(e['parse_ns'] for e in events), 'elf_utility_calls': 0}.items():
        require(cost[key] == value, 'observer cost mismatch: ' + key)
    require(row['direct_observer_cost'] == cost, 'aggregated observer cost differs')
    for arm, path in (('direct', case / 'direct/target/commands.jsonl'),
                      ('reference', case / 'reference/commands.jsonl')):
        commands = [json.loads(line) for line in path.read_text().splitlines()]
        failed = [c for c in commands if c.get('returncode') != 0 or 'exception' in c]
        if tool_control:
            require(len(failed) == 1 and failed[0]['argv'] == ['nm', '--toolchainmark-control-invalid-option']
                    and failed[0].get('returncode') == 1 and 'exception' not in failed[0]
                    and failed[0]['stderr']['value'], 'control lacks its actual nonzero nm process')
            stats['nonzero_tool_processes'] += 1
        else:
            require(not failed, 'formal command did not complete successfully')
        counts = Counter(Path(c['argv'][0]).name for c in commands)
        require(dict(counts) == row['commands_by_executable'][arm], 'command count mismatch')
        require(counts['gcc'] == 1, 'fresh arm lacks exactly one native compilation')
        require(all('stdout' in c and 'stderr' in c and 'elapsed_ns' in c for c in commands),
                'command outputs were not retained')
        stats['retained_command_records'] += len(commands)
    return {'raw': raw, 'views': views, 'protocols': protocols, 'pair': computed_pair}


def trace_pairs(records, plan):
    witnessed = Counter()
    representative = {}
    for pass_name in plan['passes']:
        for host, carrier in itertools.product(plan['hosts'], plan['carriers']):
            prefix = (pass_name, host, carrier)
            no_op = records[prefix + ('skipped-removal',)]
            fallback = records[prefix + ('accepted-after-removal',)]
            restored = records[prefix + ('restored-during-extraction',)]
            def removal_prefix(r):
                return {'source_payload': r['protocols'][1]['response']['observation'],
                        'removal_completed': r['protocols'][2]['response']['status']}
            require(removal_prefix(no_op) == removal_prefix(fallback) and
                    no_op['pair'][0] != fallback['pair'][0], 'removal projection has no separating pair')
            def extraction_projection(r):
                return {'source_identity': identity(r['raw']['source']),
                        'source_payload': r['protocols'][1]['response']['observation'],
                        'removal_completed': r['protocols'][2]['response']['status'],
                        'postcondition_identity': identity(r['raw']['postcondition']),
                        'postcondition_view': r['views']['postcondition'],
                        'before_extraction_identity': identity(r['raw']['before-extraction']),
                        'tested_outcome': r['protocols'][3]['response']['observation']}
            require(extraction_projection(fallback) == extraction_projection(restored) and
                    fallback['pair'] != restored['pair'], 'endpoint projection has no separating pair')
            witnessed['removal_postcondition'] += 1
            witnessed['endpoint_identity'] += 1
            if not representative:
                representative = {
                    'case': [pass_name, host, carrier],
                    'removal_prefix_projection': removal_prefix(no_op),
                    'removal_pairs': [no_op['pair'], fallback['pair']],
                    'endpoint_projection': extraction_projection(fallback),
                    'endpoint_pairs': [fallback['pair'], restored['pair']]}
    return {'counts': dict(witnessed), 'representative': representative,
            'scope': 'Post-run trace-pair derivation under the explicitly listed projections. '
                     'This is neither a new blinded cohort nor a lower bound on all possible evidence encodings. '
                     'The no-op downstream extraction was not performed and is not imputed.'}


def main():
    artifact = HERE.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path,
                        default=artifact / 'results/independent-observers/formal-02')
    args = parser.parse_args()
    run = args.run.resolve()
    plan = read(run / 'plan.json')
    require(plan['phase'] == 'formal' and plan['passes'] == ['first', 'second'], 'expected the formal two-pass study')
    require(plan['protocol'] in ('independent-live-direct-oracle-v1', 'independent-live-direct-oracle-v2'),
            'unknown independent-observer protocol')
    producer = HERE / ('producer_current' if plan['protocol'].endswith('-v2') else 'producer_legacy')
    binding = source_checks(run, artifact, producer)
    global observe
    spec = importlib.util.spec_from_file_location('retained_independent_observer',
        run / 'source-snapshot/prototype/independent_observer.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    observe = module.observe
    expected = set(itertools.product(plan['hosts'], plan['carriers'], plan['cohorts']))
    require(len(expected) == plan['cases_per_pass'], 'plan cardinality differs')
    stats = Counter()
    all_rows = {}
    records = {}
    for pass_name in plan['passes']:
        rows = read(run / (pass_name + '.json'))
        keys = [(r['host'], r['carrier'], r['cohort']) for r in rows]
        require(len(keys) == len(set(keys)) and set(keys) == expected, 'case coverage differs from plan')
        for index, row in enumerate(rows):
            require(row.get('tool_failure_control', False) is False, 'protocol control entered main denominator')
            key = (row['host'], row['carrier'], row['cohort'])
            case = run / pass_name / Path(row['host']).stem / row['carrier'] / row['cohort']
            expected_order = ['reference', 'direct'] if (index + plan['passes'].index(pass_name)) % 2 else ['direct', 'reference']
            require(row['arm_order'] == expected_order, 'declared alternating arm order differs')
            records[(pass_name,) + key] = verify_case(case, row, plan, stats)
        summary = read(run / 'summary.json')['passes'][pass_name]
        require(summary['cases'] == len(rows), 'summary case count differs')
        for cohort in plan['cohorts']:
            group = [r for r in rows if r['cohort'] == cohort]
            item = summary['cohorts'][cohort]
            require(item['cases'] == len(group), 'cohort denominator differs')
            for arm in ('direct', 'reference'):
                require(item[arm + '_pairs'] == dict(Counter('/'.join(r[arm + '_pair']) for r in group)),
                        'cohort pair count differs')
            require(item['pair_disagreements'] == item['diagnostic_disagreements'] == item['byte_identity_mismatches'] == 0,
                    'summary disagreement count differs')
        for key, item in (('direct_observer_captures', 'captures'),
                          ('direct_observer_parsed_views', 'parsed_views'),
                          ('direct_observer_bytes', 'captured_bytes')):
            require(summary[key] == sum(r['direct_observer_cost'][item] for r in rows), 'summary observer cost differs')
        for arm in ('direct', 'reference'):
            require(summary['command_counts'][arm] == dict(sum((Counter(r['commands_by_executable'][arm]) for r in rows), Counter())),
                    'summary command cost differs')
            require(summary['median_coordinator_seconds'][arm] ==
                    statistics.median(r['coordinator_elapsed_ns'][arm] for r in rows) / 1e9,
                    'summary time differs')
        all_rows[pass_name] = rows
    fields = ('host', 'carrier', 'cohort', 'direct_pair', 'reference_pair',
              'direct_diagnosis', 'reference_diagnosis', 'paired_byte_identity', 'commands_by_executable')
    for first, second in zip(all_rows['first'], all_rows['second']):
        for name in fields:
            require(first[name] == second[name], 'non-timing rerun field differs: ' + name)
            stats['rerun_field_comparisons'] += 1
    summary = read(run / 'summary.json')
    require(summary['verdict'] == 'PASS' and summary['source_inputs_unchanged'] is True and
            summary['rerun_non_timing_differences'] == [], 'stored completion differs')
    control_report = {'cases': 0, 'fresh_arm_executions': 0, 'included_in_main_denominator': False}
    if plan['protocol'].endswith('-v2'):
        control_rows = read(run / 'protocol-controls.json')
        control_plan = plan['protocol_control']
        require(control_plan['cases_per_pass'] == 1 and len(control_rows) == len(plan['passes']),
                'protocol control denominator differs')
        control_stats = Counter()
        for index, (pass_name, row) in enumerate(zip(plan['passes'], control_rows)):
            require((row['host'], row['carrier'], row['cohort']) ==
                    (control_plan['host'], control_plan['carrier'], control_plan['cohort']) and
                    row['tool_failure_control'] is True, 'protocol control tuple differs')
            case = run / 'protocol-controls' / pass_name / Path(row['host']).stem / row['carrier'] / row['cohort']
            require(row['arm_order'] == (['reference', 'direct'] if index % 2 else ['direct', 'reference']),
                    'control arm order differs')
            verify_case(case, row, plan, control_stats, tool_control=True)
            require(row['direct_pair'] == row['reference_pair'] == control_plan['expected_pair'] ==
                    ['SATISFIED', 'INADMISSIBLE'], 'tool failure was counted as an extraction inconsistency')
        for field in fields:
            require(control_rows[0][field] == control_rows[1][field], 'protocol control rerun field differs')
        stored = summary['protocol_controls']
        require(stored['cases'] == len(control_rows) and stored['included_in_main_denominator'] is False
                and stored['agreement'] is True and stored['paired_verdicts'] == [r['direct_pair'] for r in control_rows],
                'stored protocol control summary differs')
        control_report = {'cases': len(control_rows), 'fresh_arm_executions': 2 * len(control_rows),
            'included_in_main_denominator': False, 'paired_verdicts': [r['direct_pair'] for r in control_rows],
            'checks': dict(control_stats), 'rerun_field_comparisons': len(fields),
            'scope': 'Actual nm processes fail after valid source/removal observations. '
                     'Both arms withhold the extraction verdict; controls are not mutant sensitivity units.'}
    report = {'schema': 'independent-live-direct-oracle-receiver-v2', 'run_protocol': plan['protocol'],
              'verdict': 'PASS', 'paired_cases': sum(map(len, all_rows.values())),
              'fresh_arm_executions': 2 * sum(map(len, all_rows.values())),
              'source_binding': binding, 'checks': dict(stats),
              'protocol_controls': control_report,
              'trace_pairs': trace_pairs(records, plan),
              'scope': 'Read-only replay of retained bytes, raw responses, command outputs, source bindings, and counts. '
                       'Does not certify an independently witnessed execution history, arbitrary parser inputs, '
                       'atomic read semantics, or efficacy on independently maintained watermark products.'}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
