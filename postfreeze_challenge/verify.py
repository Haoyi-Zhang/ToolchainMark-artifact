"""Read-only reception of the frozen-catalog challenge and its retained failure.

This does not run compilers, hosts, binary utilities or network requests. The
separate byte parser reconstructs strict carrier results; a small state model
checks that recorded calls implement the preregistered local trigger behaviors.
Detection is still computed by the unchanged fourteen-relation predicates.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import gzip
import importlib.util
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys

_artifact_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_artifact_root / 'src'))
sys.path.insert(0, str(_artifact_root))
if __package__ in (None, ''):
    __package__ = 'postfreeze_challenge'

from toolchainmark.study_validation import validate_rows
from .common import HERE, ROOT, PRODUCERS, checkout_inputs, load_plan, require, safe_path, sha, verify_frozen
from .derive import derive, read_rows, source_size

DATA = ROOT / 'results/postfreeze-challenge/completed'
RECORDED_MANIFEST = '01269b076adad25f0b89b6b1d8ef026b76f3da9a3c1ac7d6994714b03722ad49'
FAILED_IDENTITIES = '6c20b5656f8406a19a61f818fd10f340b3f2fb15ef0ba9a15e41aa6b87c2ac17'
OBSERVER_PATH = 'independent_observers/producer_legacy/independent_observer.py'
OBSERVER_SHA256 = '4838ef13f86de5d421e049ae8355805a806e5420e1f8730fc1957c1ce6d471c3'


def expected_container_paths(project_root=None):
    """Exact project-relative gzip domain for the completed and failed attempts.

    Paths come from pinned original identities and the frozen record plan.
    verify() additionally reads every gzip and checks that the blob domain is
    exactly the union referenced by the valid planned records.
    """
    project_root = ROOT.parent if project_root is None else Path(project_root)
    artifact = project_root / 'artifact'
    data = artifact / 'results/postfreeze-challenge/completed'
    plan, _ = load_plan(data)
    raw = (data / 'record-manifest.json').read_bytes()
    require(sha(raw) == RECORDED_MANIFEST, 'container declaration is not the recorded measurement')
    records = {f'records/distinctions/case-{index:06}.json.gz' for index in range(1, 85)}
    for activity in plan['activity_order']:
        count = plan['rows_per_full_pass'] if activity.startswith('full') else plan['roundtrip_rows_per_pass']
        records.update(f'records/{activity}/case-{index:06}.json.gz' for index in range(1, count + 1))
    names = {entry['path'] for entry in json.loads(raw)['files'] if entry['path'].endswith('.gz')}
    require(records <= names and all(name in records or re.fullmatch(r'blobs/[0-9a-f]{64}\.bin\.gz', name)
                                    for name in names), 'compressed domain contains an unplanned record')
    result = {'artifact/results/postfreeze-challenge/completed/' + name for name in names}
    failed_raw = (artifact / 'postfreeze_challenge/attempt-01-identities.json').read_bytes()
    require(sha(failed_raw) == FAILED_IDENTITIES, 'failed-attempt container declaration differs')
    failed = {entry['path'] for entry in json.loads(failed_raw)['files'] if entry['path'].endswith('.gz')}
    failed_records = {f'records/distinctions/case-{index:06}.json.gz' for index in range(1, 85)}
    require(failed_records <= failed and all(name in failed_records or re.fullmatch(r'blobs/[0-9a-f]{64}\.bin\.gz', name)
                                           for name in failed), 'failed-attempt domain contains an unplanned record')
    result.update('artifact/results/postfreeze-challenge/attempts/attempt-01/' + name for name in failed)
    return result


def checked_manifest(root, entries):
    names = set()
    for item in entries:
        name = item['path']
        require(name not in names, 'duplicate manifest path')
        names.add(name)
        path = safe_path(root, name)
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == item['bytes']
                and sha(path.read_bytes()) == item['sha256'], 'record identity differs: ' + name)
    return names


def parser():
    path = ROOT / OBSERVER_PATH
    require(sha(path.read_bytes()) == OBSERVER_SHA256, 'separate parser identity differs')
    spec = importlib.util.spec_from_file_location('postfreeze_byte_observer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.observe


def descriptor_bytes(root, item):
    path = safe_path(root, item['record_path'])
    compressed = path.read_bytes()
    require(len(compressed) == int(item['compressed_bytes']) and sha(compressed) == item['compressed_sha256'],
            'trace compressed identity differs')
    raw = gzip.decompress(compressed)
    require(len(raw) == int(item['bytes']) and sha(raw) == item['sha256'], 'trace raw identity differs')
    return json.loads(raw)


def count_events(events):
    kinds = Counter(event['event'] for event in events)
    branches = [event for event in events if event['event'] == 'fault_branch']
    return {'subprocess_invocation_attempts': kinds['subprocess_attempt'],
            'compiler_invocation_attempts': sum(event['event'] == 'subprocess_attempt' and event['compiler_driver']
                                              for event in events),
            'successful_build_returns': kinds['build_return'], 'extraction_calls': kinds['extract_call'],
            'typed_extraction_rejections': kinds['extract_rejection'], 'fault_branch_entries': len(branches),
            'invalid_key_cache_hits': sum(event.get('effect') == 'wrong-key-cache-hit' for event in branches),
            'poisoned_session_reads': sum(event.get('effect') == 'replay-previous-rejection' for event in branches),
            'redirected_artifact_reads': sum(event.get('different_path') is True for event in branches),
            'changed_byte_target_reads': sum(event.get('different_bytes') is True for event in branches)}


class ByteReceiver:
    def __init__(self, data):
        self.data = data
        self.raw = {}
        self.blob_declarations = {}
        self.observe = parser()
        self.parsed = {}
        self.counts = Counter()
        self.strict_rejection_kinds = Counter()
        self.tested_rejection_kinds = Counter()

    def load_blobs(self, record):
        local = set()
        for item in record['blobs']:
            require(set(item) == {'path', 'bytes', 'sha256', 'compressed_bytes', 'compressed_sha256'},
                    'blob declaration schema differs')
            digest = item['sha256']
            require(item['path'] == 'blobs/' + digest + '.bin.gz' and digest not in local, 'blob path/domain differs')
            local.add(digest)
            if digest not in self.raw:
                compressed = safe_path(self.data, item['path']).read_bytes()
                require(len(compressed) == item['compressed_bytes'] and sha(compressed) == item['compressed_sha256'],
                        'blob compressed identity differs')
                raw = gzip.decompress(compressed)
                require(len(raw) == item['bytes'] and sha(raw) == digest, 'blob raw identity differs')
                self.raw[digest] = raw
                self.blob_declarations[digest] = dict(item)
            else:
                require(self.blob_declarations[digest] == item, 'shared blob declaration differs')
        return local

    def snapshot(self, value, local):
        require(set(value) == {'path', 'bytes', 'sha256'}, 'captured snapshot schema differs')
        require(value['path'].startswith('CASE/') and '..' not in PurePosixPath(value['path']).parts,
                'captured path is outside its owned workspace')
        require(value['sha256'] in local and len(self.raw[value['sha256']]) == value['bytes'],
                'captured snapshot is not bound to its retained bytes')
        return value['sha256']

    def strict(self, digest, carrier, key):
        identity = (digest, carrier, key)
        if identity not in self.parsed:
            # Unsupported/malformed ELF acquisition raises and fails verification;
            # it is never silently converted into a domain rejection.
            self.parsed[identity] = self.observe(self.raw[digest], carrier, key)
        self.counts['strict_byte_observations'] += 1
        return self.parsed[identity]

    def events(self, record, variant, carrier):
        local = self.load_blobs(record)
        events = record['events']
        require([event['sequence'] for event in events] == list(range(len(events))), 'event sequence differs')
        require(all(type(event['elapsed_ns']) is int and event['elapsed_ns'] >= 0 for event in events),
                'event timestamp is not a monotonic duration')
        require([event['elapsed_ns'] for event in events] == sorted(event['elapsed_ns'] for event in events),
                'event clock order differs')
        paths = {}
        used_snapshots = set()
        def snapshots(value):
            if isinstance(value, dict):
                if {'path', 'bytes', 'sha256'} <= value.keys():
                    digest = self.snapshot(value, local)
                    used_snapshots.add(digest)
                    paths[value['path']] = digest
                for child in value.values():
                    snapshots(child)
            elif isinstance(value, list):
                for child in value:
                    snapshots(child)
        pending = None
        cache = {}
        sticky = None
        registry = {}
        last = None
        outer = []
        strict_calls = {}
        for event in events:
            snapshots(event)
            kind = event['event']
            if kind == 'decoder_instance':
                require(event['variant'] == variant and event['carrier'] == carrier, 'decoder identity differs')
                require(pending is None, 'decoder reset during a pending extraction')
                cache, registry, sticky, last = {}, {}, None, None
            elif kind == 'resolver_registration':
                require(variant == 'N03', 'unexpected basename registry')
                registry[event['basename']] = event['selected']
            elif kind == 'build_return' and variant in {'CLEAN', 'N01', 'N02', 'N03', 'N04'}:
                call = events[event['call']]
                require(call['event'] == 'build_call', 'build return lacks its request')
                result, request = event['result'], call['request']
                require(result['requested_payload_hex'] == request['payload']['bytes_hex'] and
                        result['key'] == request['key'] and result['mutant_id'] == variant and
                        result['carrier'] == carrier, 'new trigger changed its build request')
                require(result['binary_sha256'] == event['binary']['sha256'] and
                        result['source_sha256'] == event['source']['sha256'], 'build result identity differs from captured bytes')
                require(result['actual_compiler'] == request['compiler'] and
                        result['actual_optimization'] == request['optimization'] and result['return_code'] == 0,
                        'new trigger changed realized build settings')
            elif kind == 'extract_call':
                require(pending is None, 'overlapping extraction trace outside declared sequences')
                path, key, digest = event['path'], event['key'], event['artifact']['sha256']
                require(event['artifact']['path'] == path, 'requested extraction path differs from capture')
                modeled = variant in {'CLEAN', 'N01', 'N02', 'N03', 'N04'}
                expected = None
                calls, effects = [], []
                if modeled:
                    def decode(target):
                        calls.append((target, key))
                        return self.strict(paths[target], carrier, key)
                    if variant == 'N01' and digest in cache:
                        expected, previous_key = cache[digest]
                        if key != previous_key:
                            effects.append('wrong-key-cache-hit')
                    elif variant == 'N02' and sticky is not None:
                        expected = {'kind': 'rejection', 'value': sticky}
                        effects.append('replay-previous-rejection')
                    elif variant == 'N03':
                        target = registry.get(PurePosixPath(path).name, path)
                        if target != path:
                            effects.append('basename-resolution')
                        expected = decode(target)
                    else:
                        expected = decode(path)
                        if variant == 'N01' and expected['kind'] == 'payload':
                            cache[digest] = (expected, key)
                        if variant == 'N02' and expected['kind'] == 'rejection':
                            sticky = expected['value']
                        if variant == 'N04':
                            if expected['kind'] == 'payload':
                                last = path
                            elif last is not None:
                                effects.append('recovery-artifact')
                                expected = decode(last)
                pending = {'sequence': event['sequence'], 'modeled': modeled, 'expected': expected,
                           'calls': calls, 'effects': effects, 'actual_calls': [], 'actual_effects': [],
                           'snapshot': event['artifact']}
            elif kind == 'decoder_invocation':
                require(pending is not None, 'decoder invocation outside an extraction')
                require(event['path'] == event['artifact']['path'],
                        'effective decoder path differs from its captured artifact')
                pending['actual_calls'].append((event['path'], event['key']))
                strict_calls[event['sequence']] = event
            elif kind in {'decoder_return', 'decoder_rejection'}:
                call = strict_calls.pop(event['call'])
                if kind == 'decoder_rejection':
                    self.strict_rejection_kinds[event['kind']] += 1
                if variant in {'CLEAN', 'N01', 'N02', 'N03', 'N04'}:
                    observed = {'kind': 'payload', 'value': event['payload_hex']} if kind == 'decoder_return' else {
                        'kind': 'rejection', 'value': event['kind']}
                    expected = self.strict(call['artifact']['sha256'], carrier, call['key'])
                    require(observed == expected, 'strict decoder return differs from separately parsed bytes')
                    self.counts['strict_decoder_returns_checked'] += 1
            elif kind == 'fault_branch':
                require(pending is not None, 'fault branch outside an extraction')
                pending['actual_effects'].append(event['effect'])
                if 'selected' in event:
                    require(event['different_path'] == (event['requested']['path'] != event['selected']['path']) and
                            event['different_bytes'] == (event['requested']['sha256'] != event['selected']['sha256']),
                            'redirect flags differ from actual path/byte identities')
            elif kind in {'extract_return', 'extract_rejection', 'extract_error'}:
                require(pending is not None and event['call'] == pending['sequence'], 'extraction terminal lacks its call')
                require(event['artifact_after'] == pending['snapshot'], 'extraction changed its declared target bytes')
                observed = ({'kind': 'payload', 'value': event['payload_hex']} if kind == 'extract_return' else
                            {'kind': 'rejection', 'value': event['kind']} if kind == 'extract_rejection' else
                            {'kind': 'error', 'value': event['exception']})
                if kind == 'extract_rejection':
                    self.tested_rejection_kinds[event['kind']] += 1
                if pending['modeled']:
                    require(observed == pending['expected'], 'recorded new-trigger behavior differs from its frozen definition')
                    require(pending['actual_calls'] == pending['calls'], 'effective decoder read path differs from frozen trigger')
                    require(pending['actual_effects'] == pending['effects'], 'fault-branch trace differs from its condition')
                    self.counts['modeled_extraction_calls_checked'] += 1
                outer.append(observed)
                pending = None
        require(pending is None and not strict_calls, 'incomplete extraction/decoder trace')
        require(local == used_snapshots, 'record declares a blob that no captured event uses')
        require(record['counts'] == count_events(events), 'event counters differ')
        self.counts['records_checked'] += 1
        return outer


def compare_record_to_row(record, row, observations):
    identity = [row[name] for name in ('host', 'carrier', 'defect_id', 'relation_id')]
    require(record['identity'] == identity, 'trace identity differs from matrix row')
    outcome = record['outcome']
    require(outcome['verdict'] == row['verdict'] and outcome['reason'] == row['reason'] and
            outcome['phase'] == row['phase'] and outcome['admission'] == json.loads(row['admission_json']) and
            outcome['observations'] == json.loads(row['observations_json']), 'matrix differs from original call outcome')
    require(abs(float(row['duration_seconds']) - record['measured']['case_wall_seconds_before_retention']) <= 0.00000051,
            'row timing differs from measured call record')
    if row['verdict'] == 'INADMISSIBLE':
        return
    fields = {'MR01': ['extraction'], 'MR03': ['extraction'], 'MR04': ['source', 'followup'],
              'MR05': ['first', 'second'], 'MR08': ['source', 'followup'],
              'MR09': ['source', 'followup'], 'MR10': ['source', 'followup'],
              'MR13': ['before', 'intervening', 'after'], 'MR14': ['before', 'after']}
    relation = row['relation_id']
    projection = outcome['observations']
    if relation in fields:
        require(observations == [projection[name] for name in fields[relation]], 'predicate projection differs from extraction calls')
    elif relation in {'MR06', 'MR07'}:
        require(observations == projection['extractions'], 'branch projection differs from extraction calls')
    elif relation == 'MR12':
        require(len(observations) == 2, 'overlap extraction count differs')
        p1 = {'kind': 'payload', 'value': b'Morph-01'.hex()}
        p2 = {'kind': 'payload', 'value': b'Second-2'.hex()}
        require(projection['both_expected'] == (observations == [p1, p2]) and
                projection['outputs_distinct'] == (observations[0] != observations[1]) and
                projection['both_payloads'] == all(item['kind'] == 'payload' for item in observations),
                'overlap projection differs from actual typed calls')
    else:
        require(observations == [], 'non-extraction relation records extraction calls')


def verify_failed_attempt(data):
    identity_path = HERE / 'attempt-01-identities.json'
    require(sha(identity_path.read_bytes()) == FAILED_IDENTITIES, 'retained failed-attempt declaration differs')
    failed = data.parent / 'attempts/attempt-01'
    manifest = json.loads(identity_path.read_text())
    names = checked_manifest(failed, manifest['files'])
    require(names == {p.relative_to(failed).as_posix() for p in failed.rglob('*') if p.is_file()},
            'retained failed-attempt file set differs')
    report = json.loads((failed / 'distinction-activity.json').read_text())
    require(report['cases'] == 84 and report['matched'] == 36 and not list(failed.glob('full-*.csv')),
            'failed attempt was promoted to a completed primary activity')
    require(json.loads((failed / 'launch-receipt.json').read_text())['exit_code'] == 1,
            'failed attempt exit is misreported')
    plan, _ = load_plan(failed)
    planned = {(trace['id'], carrier, variant): trace for trace in plan['distinction_traces']
               for carrier in plan['carriers'] for variant in trace['expected']}
    with (failed / 'distinctions.csv').open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    require(len(rows) == len(planned) and {(row['scenario'], row['carrier'], row['variant']) for row in rows} == planned.keys(),
            'failed attempt omitted a registered distinction')
    byte_reader = ByteReceiver(failed)
    matched = 0
    for index, row in enumerate(rows, 1):
        require(row['record_path'] == f'records/distinctions/case-{index:06}.json.gz', 'failed trace path differs')
        record = descriptor_bytes(failed, row)
        byte_reader.load_blobs(record)
        trace = planned[row['scenario'], row['carrier'], row['variant']]
        require(record['actions'] == trace['actions'] and record['expected'] == trace['expected'][row['variant']],
                'failed attempt altered a registered separation sequence')
        observed = [('payload:' + event['payload_hex']) if event['event'] == 'extract_return' else
                    ('rejection:' + event['kind']) if event['event'] == 'extract_rejection' else
                    ('error:' + event['exception']) for event in record['events']
                    if event['event'] in {'extract_return', 'extract_rejection', 'extract_error'}]
        require(observed == record['observations'] == json.loads(row['observations_json']) and
                count_events(record['events']) == record['counts'] == json.loads(row['counts_json']),
                'failed calibration report differs from actual incomplete call trace')
        passed = record['error'] is None and observed == record['expected']
        require(record['matched'] is passed and row['matched'] == str(passed), 'failed calibration match flag differs')
        matched += passed
    require(matched == report['matched'] and {'blobs/' + digest + '.bin.gz' for digest in byte_reader.raw} ==
            {name for name in names if name.startswith('blobs/')}, 'failed attempt bytes/counts differ')
    return len(names)


def verify(data=DATA, fresh=False):
    data = data.resolve()
    # The public repository was refactored after this campaign (package renamed,
    # producer files edited without changing the plan or predicates), so retained
    # reception binds the frozen identities to the record's own source snapshot,
    # as the LLWM receiver does. A fresh run is still bound to the current checkout.
    source_root = ROOT if fresh else data / 'source-snapshot'
    if fresh:
        # A fresh run binds the current checkout's counterparts (common.checkout_inputs).
        plan, frozen = load_plan(data)
        expected_inputs = {item['path'] for item in checkout_inputs(frozen)}
    else:
        plan, frozen = verify_frozen(root=source_root, folder=data)
        expected_inputs = {item['path'] for item in frozen['files']}
    manifest_raw = (data / 'record-manifest.json').read_bytes()
    require(fresh or sha(manifest_raw) == RECORDED_MANIFEST, 'original measurement manifest identity differs')
    names = checked_manifest(data, json.loads(manifest_raw)['files'])
    allowed = names | {'record-manifest.json', 'completion.json', 'campaign.stdout.txt', 'campaign.stderr.txt', 'launch-receipt.json'}
    require({p.relative_to(data).as_posix() for p in data.rglob('*') if p.is_file()} == allowed, 'completed record file set differs')
    completion = json.loads((data / 'completion.json').read_text())
    require(completion['record_manifest_sha256'] == sha(manifest_raw) and completion['all_sources_unchanged'] is True,
            'completion/source identity differs')
    sources = json.loads((data / 'source-inputs.json').read_text())['files']
    expected_sources = expected_inputs | {'postfreeze_challenge/' + name for name in PRODUCERS}
    require(len(sources) == len(expected_sources) == (len(expected_inputs) + 6 if fresh else 48) and
            {item['path'] for item in sources} == expected_sources, 'producer input domain differs')
    checked_manifest(source_root, sources)
    checked_manifest(data / 'source-snapshot', sources)
    require(json.loads((data / 'source-size.json').read_text()) == source_size(source_root / 'postfreeze_challenge'),
            'recorded source-size measurement differs')
    receiver = ByteReceiver(data)
    with (data / 'distinctions.csv').open(newline='', encoding='utf-8') as stream:
        distinctions = list(csv.DictReader(stream))
    planned = {(trace['id'], carrier, variant): trace for trace in plan['distinction_traces']
               for carrier in plan['carriers'] for variant in trace['expected']}
    require(len(distinctions) == len(planned) == 84 and
            {(row['scenario'], row['carrier'], row['variant']) for row in distinctions} == planned.keys(),
            'distinction key domain differs')
    for row in distinctions:
        record = descriptor_bytes(data, row)
        trace = planned[row['scenario'], row['carrier'], row['variant']]
        require(record['actions'] == trace['actions'] and record['expected'] == trace['expected'][row['variant']],
                'distinction changes its preregistered sequence or expectation')
        observed = receiver.events(record, row['variant'], row['carrier'])
        labels = [item['kind'] + ':' + item['value'] for item in observed]
        require(labels == record['observations'] == json.loads(row['observations_json']) == trace['expected'][row['variant']]
                and row['matched'] == 'True' and record['matched'] is True, 'distinction outcome differs')
    activity_counts = {}
    for activity in plan['activity_order']:
        rows = read_rows(data / (activity + '.csv'))
        validate_rows(rows, plan['classifier_protocol'])
        with (data / (activity + '-traces.csv')).open(newline='', encoding='utf-8') as stream:
            traces = list(csv.DictReader(stream))
        require(len(rows) == len(traces), 'trace/matrix count differs')
        counts = Counter()
        for index, (row, descriptor) in enumerate(zip(rows, traces), 1):
            require(int(descriptor['index']) == index and descriptor['record_path'] ==
                    f'records/{activity}/case-{index:06}.json.gz', 'trace index/order differs')
            record = descriptor_bytes(data, descriptor)
            require(record['activity'] == activity and record['index'] == index, 'record activity differs')
            observations = receiver.events(record, row['defect_id'], row['carrier'])
            compare_record_to_row(record, row, observations)
            require(json.loads(descriptor['counts_json']) == record['counts'], 'index counters differ from events')
            for key, value in record['measured'].items():
                require(math.isfinite(value) and value >= 0 and float(descriptor[key]) == value,
                        'index resource measurement differs')
            counts.update(record['counts'])
        activity_counts[activity] = dict(counts)
    expected_blobs = {'blobs/' + digest + '.bin.gz' for digest in receiver.raw}
    require(expected_blobs == {name for name in names if name.startswith('blobs/')}, 'unbound or missing retained blob')
    rederived = derive(data)
    require(rederived == json.loads((data / 'summary.json').read_text()), 'summary does not rederive from all rows')
    for activity, counts in activity_counts.items():
        measured = rederived['activities'][activity]['measured_activity']
        require(measured['compiler_invocation_attempts'] == counts['compiler_invocation_attempts'] and
                measured['successful_build_returns'] == counts['successful_build_returns'],
                'activity compiler/build counters differ from invocation traces')
    launch = json.loads((data / 'launch-receipt.json').read_text())
    require(launch['exit_code'] == 0, 'successful activity has a nonzero launch result')
    checked_manifest(data, launch['logs'])
    failed_files = verify_failed_attempt(data) if not fresh else None
    return {'verdict': 'PASS', 'protocol': plan['protocol'], 'frozen_input_files': len(expected_inputs),
            'producer_input_files': len(sources), 'relation_rows': 8100, 'distinction_traces': 84,
            'unique_retained_blobs': len(receiver.raw), 'unique_strict_byte_views': len(receiver.parsed),
            'byte_and_call_checks': dict(receiver.counts), 'activity_event_counts': activity_counts,
            'observed_strict_rejection_kinds': dict(sorted(receiver.strict_rejection_kinds.items())),
            'observed_tested_rejection_kinds': dict(sorted(receiver.tested_rejection_kinds.items())),
            'failed_attempt_files_preserved': failed_files, 'separate_byte_parser': {
                'path': OBSERVER_PATH, 'sha256': OBSERVER_SHA256},
            'scope': 'Read-only identities, complete planned rows, frozen relation predicates, native-call projections, '
                     'registered trigger-state replay, separately parsed strict carrier observations, and rederived counts. '
                     'The local record is not an external execution attestation; host stdout and kernel file-read events '
                     'are not independently reconstructed. No new native or network activity.'}


def main():
    parser_ = argparse.ArgumentParser(description=__doc__)
    parser_.add_argument('--data', type=Path, default=DATA)
    parser_.add_argument('--fresh', action='store_true', help='Check a fresh rerun without claiming the original measurement identity')
    args = parser_.parse_args()
    try:
        result = verify(args.data, args.fresh)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result = {'verdict': 'FAIL', 'error': type(error).__name__ + ': ' + str(error)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
