"""Read-only SR01 receiver: reconstruct premises from native bytes and call order.

No native utilities, compiler, process launches or network calls are made. The
receiver uses the separate ELF/record parser and the declared decoder state
model; it derives SR01 facts directly rather than trusting stored admission
flags or assigning expected verdicts from cohort labels.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
import math
from pathlib import Path
import re
import sys

_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_root / 'src'))
sys.path.insert(0, str(_root))
if __package__ in (None, ''):
    __package__ = 'recovery_extension'

from postfreeze_challenge.common import require, sha
from postfreeze_challenge.verify import ByteReceiver, checked_manifest, descriptor_bytes
from .common import HERE, ROOT, PRODUCERS, checkout_entries, load_plan, verify_prior
from .derive import derive, read_rows, source_size

DATA = ROOT / 'results/recovery-extension/completed'
RECORDED_MANIFEST = '4d0a9386ae4184b10edad1320b1604c38ef5bdc863c6f9ab130f3d61015f7325'
PRODUCER_FREEZE = '9911126411dc4cdefb3615a6ed91d08be4c8801bd277cda5c5d06675de7aaf1b'


def expected_container_paths(project_root=None):
    project_root = ROOT.parent if project_root is None else Path(project_root)
    data = project_root / 'artifact/results/recovery-extension/completed'
    plan, _ = load_plan(data)
    raw = (data / 'record-manifest.json').read_bytes()
    require(sha(raw) == RECORDED_MANIFEST, 'SR01 container declaration differs from original measurement')
    records = {f'records/{name}/case-{index:06}.json.gz' for name in plan['passes']
               for index in range(1, plan['cases_per_pass'] + 1)}
    names = {entry['path'] for entry in json.loads(raw)['files'] if entry['path'].endswith('.gz')}
    require(records <= names and all(name in records or re.fullmatch(r'blobs/[0-9a-f]{64}\.bin\.gz', name)
                                    for name in names), 'SR01 compressed record domain differs')
    return {'artifact/results/recovery-extension/completed/' + name for name in names}


def reconstruct(receiver, record, plan, cohort):
    """Rebuild policy/byte/order facts without importing the SR01 producer model."""
    expected_contract = {key: cohort[key] for key in ('reuse_after_rejection_declared', 'lockout_excluded_by_contract')}
    request = {'payload_hex': plan['payloads']['P1'], 'key': plan['keys']['K1'], 'wrong_key': plan['keys']['K2']}
    require(record['variant'] == cohort['variant'] and record['contract'] == expected_contract and
            record['request'] == request, 'record changed its registered target or declared policy')
    host, carrier, cohort_id, relation = record['identity']
    require(cohort_id == cohort['id'] and relation == 'SR01', 'SR01 identity differs')
    observations = receiver.events(record, record['variant'], carrier)
    events = record['events']
    checkpoints = [event for event in events if event['event'] == 'recovery_checkpoint']
    labels = ['source', 'before_wrong_key', 'after_wrong_key', 'before_recovery', 'after_recovery']
    require([event['label'] for event in checkpoints] == labels and len(observations) == 3,
            'SR01 captured checkpoint/call domain differs')
    snapshots = {event['label']: event['artifact'] for event in checkpoints}
    calls = [event for event in events if event['event'] == 'extract_call']
    terminals = [event for event in events if event['event'] in {'extract_return', 'extract_rejection', 'extract_error'}]
    require(len(calls) == len(terminals) == 3, 'SR01 typed call trace is incomplete')
    source_event, before_bad, after_bad, before_good, after_good = checkpoints
    require(source_event['sequence'] < calls[0]['sequence'] < terminals[0]['sequence'] < before_bad['sequence'] <
            calls[1]['sequence'] < terminals[1]['sequence'] < after_bad['sequence'] < before_good['sequence'] <
            calls[2]['sequence'] < terminals[2]['sequence'] < after_good['sequence'],
            'SR01 observation/request order differs')
    require([call['artifact'] for call in calls] == [snapshots['source'], snapshots['before_wrong_key'], snapshots['before_recovery']],
            'SR01 checkpoints do not bind actual extraction inputs')
    require([event['artifact_after'] for event in terminals] == [snapshots['before_wrong_key'], snapshots['after_wrong_key'], snapshots['after_recovery']],
            'SR01 checkpoints do not bind completed extractions')
    builds = [event for event in events if event['event'] == 'build_call']
    replacements = [event for event in events if event['event'] == 'controlled_target_replacement']
    require(len(builds) == (2 if cohort['replace_after_rejection'] else 1) and
            len(replacements) == int(cohort['replace_after_rejection']), 'registered intervention action differs')
    for index, build in enumerate(builds):
        build_request = build['request']
        require(build_request['host'] == 'ARTIFACT/hosts/' + host and build_request['key'] == request['key'] and
                build_request['payload']['bytes_hex'] == plan['payloads']['P1' if index == 0 else 'P2'] and
                build_request['compiler'] == plan['compiler'] and build_request['optimization'] == plan['optimization'],
                'SR01 native build differs from registered request')
    if replacements:
        event = replacements[0]
        require(after_bad['sequence'] < event['sequence'] < before_good['sequence'] and
                event['target_before'] == snapshots['after_wrong_key'] and
                event['target_after'] == snapshots['before_recovery'] and
                event['source']['sha256'] == event['target_after']['sha256'],
                'controlled replacement bytes or ordering differ')
        require(receiver.strict(event['source']['sha256'], carrier, request['key']) ==
                {'kind': 'payload', 'value': plan['payloads']['P2']}, 'replacement is not independently observed P2')
    source_observation = receiver.strict(snapshots['source']['sha256'], carrier, request['key'])
    source_reads = [event for event in events if event['event'] == 'recovery_source_observation']
    require(len(source_reads) == 1 and source_reads[0]['observation'] == source_observation and
            source_reads[0]['artifact'] == snapshots['source'] and
            source_event['sequence'] < source_reads[0]['sequence'] < calls[0]['sequence'],
            'SR01 source carrier observation differs from separately parsed bytes')
    instances = sum(event['event'] == 'decoder_instance' for event in events)
    rebuilt = {'snapshots': snapshots, 'observations': {'source_carrier': source_observation,
               'source': observations[0], 'wrong_key': observations[1], 'recovery': observations[2]},
               'tested_calls': [{'path': call['path'], 'key': call['key']} for call in calls], 'decoder_instances': instances}
    require(record['evidence'] == rebuilt, 'stored SR01 evidence differs from captured bytes/calls')
    expected = {'kind': 'payload', 'value': request['payload_hex']}
    source = snapshots['source']
    domain = {'absent', 'wrong-key', 'checksum', 'malformed', 'version', 'path', 'sidecar'}
    recovery_valid = (observations[2]['kind'] == 'payload' or
                      observations[2]['kind'] == 'rejection' and observations[2]['value'] in domain)
    facts = {
        'reuse_after_rejection_declared': expected_contract['reuse_after_rejection_declared'] is True,
        'lockout_excluded_by_contract': expected_contract['lockout_excluded_by_contract'] is True,
        'keys_distinct': request['key'] != request['wrong_key'],
        'source_is_valid_requested_payload': source_observation == expected,
        'source_extracts_requested_payload': observations[0] == expected,
        'same_decoder_context': instances == 1 and [call['key'] for call in calls] ==
            [request['key'], request['wrong_key'], request['key']] and all(call['path'] == source['path'] for call in calls),
        'wrong_key_returns_typed_wrong_key_rejection': observations[1] == {'kind': 'rejection', 'value': 'wrong-key'},
        'source_current_before_wrong_key': source == snapshots['before_wrong_key'],
        'source_unchanged_during_wrong_key': snapshots['before_wrong_key'] == snapshots['after_wrong_key'],
        'source_current_before_recovery': source == snapshots['before_recovery'],
        'source_unchanged_during_recovery': snapshots['before_recovery'] == snapshots['after_recovery'],
        'recovery_observation_available': recovery_valid,
    }
    require(set(facts) == set(plan['premises']), 'SR01 premise domain differs')
    failed = next((name for name in plan['premises'] if not facts[name]), None)
    if failed:
        outcome = {'verdict': 'INADMISSIBLE', 'reason': failed, 'admission': facts}
    else:
        passed = observations[2] == expected
        outcome = {'verdict': 'SATISFIED' if passed else 'INCONSISTENT',
                   'reason': 'recovery_matches_request' if passed else 'recovery_differs_after_typed_rejection', 'admission': facts}
    require(record['outcome'] == outcome, 'SR01 verdict differs from independently reconstructed premises')
    require(record['error'] is None, 'completed original SR01 record contains an acquisition error')
    return outcome


def verify(data=DATA, fresh=False):
    data = data.resolve()
    # Retained reception binds prior and producer identities to the record's own
    # source snapshot (the repository was refactored later); a fresh run is still
    # bound to the current checkout. See postfreeze_challenge/verify.py.
    source_root = ROOT if fresh else data / 'source-snapshot'
    inputs = json.loads((data / 'source-inputs.json').read_text())['files']
    if fresh:
        # A fresh run binds the current checkout's counterparts (common.checkout_entries).
        plan, prior = load_plan(data)
        expected = checkout_entries(prior)
        require([item['path'] for item in inputs] == [item['path'] for item in expected],
                'SR01 source input domain differs')
    else:
        plan, prior = verify_prior(root=source_root, folder=data)
        freeze_raw = (data / 'producer-freeze.json').read_bytes()
        require(sha(freeze_raw) == PRODUCER_FREEZE, 'SR01 pre-execution producer identity differs')
        producers = json.loads(freeze_raw)['files']
        require({item['path'] for item in producers} == {'recovery_extension/' + name for name in PRODUCERS},
                'SR01 producer-file domain differs')
        require(inputs == prior['files'] + producers and len(inputs) == 54, 'SR01 source input domain differs')
    checked_manifest(source_root, inputs)
    checked_manifest(data / 'source-snapshot', inputs)
    require(source_size(source_root / 'recovery_extension') == json.loads((data / 'source-size.json').read_text()), 'SR01 source-size measurement differs')
    raw = (data / 'record-manifest.json').read_bytes()
    require(fresh or sha(raw) == RECORDED_MANIFEST, 'SR01 original measurement identity differs')
    names = checked_manifest(data, json.loads(raw)['files'])
    allowed = names | {'record-manifest.json', 'completion.json', 'campaign.stdout.txt', 'campaign.stderr.txt', 'launch-receipt.json'}
    require({path.relative_to(data).as_posix() for path in data.rglob('*') if path.is_file()} == allowed,
            'SR01 completed record file set differs')
    completion = json.loads((data / 'completion.json').read_text())
    require(completion['record_manifest_sha256'] == sha(raw) and completion['all_sources_unchanged'] is True and
            completion['source_files'] == len(inputs) and completion['passes'] == 2 and completion['cases_per_pass'] == 270,
            'SR01 completion identity or counts differ')
    receiver = ByteReceiver(data)
    cohorts = {item['id']: item for item in plan['cohorts']}
    counts = {}
    for name in plan['passes']:
        rows = read_rows(data / (name + '.csv'))
        with (data / (name + '-traces.csv')).open(newline='') as stream:
            traces = list(csv.DictReader(stream))
        require(len(rows) == len(traces) == plan['cases_per_pass'], 'SR01 trace/matrix domain differs')
        counter = Counter()
        for index, (row, descriptor) in enumerate(zip(rows, traces), 1):
            require(descriptor['record_path'] == f'records/{name}/case-{index:06}.json.gz' and int(descriptor['index']) == index,
                    'SR01 trace descriptor order differs')
            record = descriptor_bytes(data, descriptor)
            require(record['pass'] == name and record['index'] == index and
                    record['identity'] == [row['host'], row['carrier'], row['cohort'], row['relation_id']],
                    'SR01 record identity differs from row')
            require(row['host_sha256'] == sha((ROOT / 'hosts' / row['host']).read_bytes()), 'SR01 host identity differs')
            outcome = reconstruct(receiver, record, plan, cohorts[row['cohort']])
            require(row['variant'] == record['variant'] and row['verdict'] == outcome['verdict'] and row['reason'] == outcome['reason'],
                    'SR01 row judgment differs')
            for field in ('contract', 'request', 'evidence', 'admission'):
                require(json.loads(row[field + '_json']) == (outcome['admission'] if field == 'admission' else record[field]),
                        'SR01 row evidence differs from captured record')
            require(json.loads(descriptor['counts_json']) == record['counts'], 'SR01 index counters differ')
            for key, value in record['measured'].items():
                require(math.isfinite(value) and value >= 0 and float(descriptor[key]) == value, 'SR01 resource index differs')
            require(abs(float(row['duration_seconds']) - record['measured']['case_wall_seconds_before_retention']) <= 0.00000051,
                    'SR01 case timing differs')
            counter.update(record['counts'])
        counts[name] = dict(counter)
    require({'blobs/' + digest + '.bin.gz' for digest in receiver.raw} == {name for name in names if name.startswith('blobs/')},
            'SR01 retained blob domain has unbound or missing bytes')
    rederived = derive(data)
    require(rederived == json.loads((data / 'summary.json').read_text()), 'SR01 summary does not rederive')
    for name, event_counts in counts.items():
        measured = rederived['activities'][name]['measured_activity']
        require(measured['compiler_invocation_attempts'] == event_counts['compiler_invocation_attempts'] and
                measured['successful_build_returns'] == event_counts['successful_build_returns'], 'SR01 activity counters differ')
    launch = json.loads((data / 'launch-receipt.json').read_text())
    require(launch['exit_code'] == 0, 'SR01 completion has a nonzero process return')
    checked_manifest(data, launch['logs'])
    return {'verdict': 'PASS', 'protocol': plan['protocol'], 'source_files': len(inputs), 'native_cases': 540,
            'unique_retained_blobs': len(receiver.raw), 'unique_strict_byte_views': len(receiver.parsed),
            'byte_and_call_checks': dict(receiver.counts), 'activity_event_counts': counts,
            'observed_strict_rejection_kinds': dict(sorted(receiver.strict_rejection_kinds.items())),
            'observed_tested_rejection_kinds': dict(sorted(receiver.tested_rejection_kinds.items())),
            'rerun': rederived['rerun'], 'scope': 'Reconstructed source-carrier observations, call order, policy and endpoint premises; '
            'frozen trigger-state replay and all five complete cohort denominators. No cohort-label verdict oracle. '
            'No native activity, continuous file monitoring, or external execution attestation.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=DATA)
    parser.add_argument('--fresh', action='store_true')
    args = parser.parse_args()
    try:
        result = verify(args.data, args.fresh)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result = {'verdict': 'FAIL', 'error': type(error).__name__ + ': ' + str(error)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
