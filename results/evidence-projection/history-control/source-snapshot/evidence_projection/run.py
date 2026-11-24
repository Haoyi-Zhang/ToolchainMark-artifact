"""Measure and independently check projections of a fixed retained native frame."""
from __future__ import annotations

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import statistics
import sys
import tempfile
import time

from contract_runtime.receiver import load_json, verify_receipt
from ctf_comparison.verify import expected_case
from .native import members, metrics, native_context, populate, verify_native
from .project import encoded, project, replay_only, selection
from .receiver import verify_bundle

ARTIFACT = Path(__file__).resolve().parents[1]


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                               allow_nan=False) + '\n')


def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def bound(row):
    path = ARTIFACT / row['path']
    if identity(path) != {key: row[key] for key in ('bytes', 'sha256')}:
        raise ValueError('source native record changed: ' + row['path'])
    return path


def external_case(item):
    row, study = item['frame_case'], item['study']
    if study == 'sandmark':
        return row['inputs'], row['id']
    if study == 'llwm':
        return {'interface': row['interface'], 'variant': row['variant'], 'payload': row['payload'],
                'payload_hex': row['payload'].encode().hex(), 'key': '1234', 'ordinary': '4321',
                'optimization': row['optimization']}, row['id']
    values = {'host': row['host'], 'carrier': row['carrier'], 'implementation': row['implementation'],
              'payload1': b'Morph-01'.hex(), 'payload2': b'Second-2'.hex(), 'key1': 'key-alpha',
              'key2': 'key-beta', 'compiler': 'gcc', 'optimization': 'O2',
              'host_inputs': [0, 1, 5, 13, 144, 99991]}
    if study == 'state' or (study == 'state-baseline' and row['relation'] == 'SR01'):
        values.update(reuse_permitted=True, lockout_excluded=True)
    return values, row['id'] + ':declaration'


def freeze(output, frame):
    files = list((ARTIFACT / 'evidence_projection').glob('*.py'))
    files += [ARTIFACT / name for name in (
        'evidence_projection/protocol.json', 'contract_runtime/receiver.py',
        'declarative_study/native_io.py', 'declarative_study/verify.py',
        'independent_observers/producer-v2/independent_observer.py',
        'external_sandmark/verify_study.py', 'ctf_comparison/expressions.py', 'ctf_comparison/verify.py')]
    rows = []
    for path in sorted(set(files)):
        relative = path.relative_to(ARTIFACT).as_posix()
        target = output / 'source-snapshot' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        rows.append({'path': relative, **identity(path)})
    write(output / 'source-freeze.json', {'files': rows, 'frozen_before_measurement': True})
    write(output / 'frame.json', frame)
    write(output / 'protocol.json', load_json(ARTIFACT / 'evidence_projection/protocol.json'))
    return rows


def distribution(values):
    ordered = sorted(values)
    def percentile(q):
        position = (len(ordered) - 1) * q
        low = int(position); high = min(low + 1, len(ordered) - 1)
        return ordered[low] + (ordered[high] - ordered[low]) * (position - low)
    return {'min': min(ordered), 'q25': percentile(.25), 'median': statistics.median(ordered),
            'q75': percentile(.75), 'max': max(ordered), 'mean': statistics.mean(ordered)}


def summary(rows):
    def group(part):
        ratios = {name: [row[name] for row in part] for name in (
            'action_fraction', 'record_fraction', 'native_storage_fraction', 'bundle_fraction')}
        return {'targets': len(part), 'source_receipts': len({(r['dataset'], r['case']) for r in part}),
                'judgments': dict(Counter(r['judgment'] for r in part)),
                'accepted': sum(r['accepted'] for r in part),
                'exact_target_preservation': sum(r['exact_target_preservation'] for r in part),
                'reference_replay_agreement': sum(r['reference_replay_agreement'] for r in part),
                'zero_action_reduction': sum(r['actions'] == r['full_actions'] for r in part),
                'zero_native_storage_reduction': sum(r['native_storage_bytes'] == r['full_native_storage_bytes'] for r in part),
                'smaller_complete_bundles': sum(r['bundle_bytes'] < r['full_bundle_bytes'] for r in part),
                'equal_complete_bundles': sum(r['bundle_bytes'] == r['full_bundle_bytes'] for r in part),
                'larger_complete_bundles': sum(r['bundle_bytes'] > r['full_bundle_bytes'] for r in part),
                'distributions': {name: distribution(values) for name, values in ratios.items()},
                'totals': {name: sum(r[name] for r in part) for name in (
                    'actions', 'full_actions', 'reference_actions', 'record_bytes', 'full_record_bytes',
                    'bundle_bytes', 'full_bundle_bytes', 'native_storage_bytes', 'full_native_storage_bytes')}}
    return {**group(rows), 'by_study': {name: group([r for r in rows if r['study'] == name])
                                      for name in sorted({r['study'] for r in rows})}}


def run(output, pilot=False):
    if output.exists():
        raise ValueError('choose a new output directory')
    frame = load_json(ARTIFACT / 'results/ctf-comparison/formal-01/frame.json')
    if pilot:
        selected = {}
        for row in frame:
            selected.setdefault(row['study'], row)
        frame = list(selected.values())
    output.mkdir(parents=True)
    frozen = freeze(output, frame)
    write(output / 'start.json', {'started_utc': datetime.now(timezone.utc).isoformat(),
          'purpose': 'pilot' if pilot else 'complete-retained-frame', 'python': sys.version,
          'platform': platform.platform(), 'fresh_native_executions': 0})
    contexts, retained_examples, rows = {}, set(), []
    start = time.perf_counter()
    with (output / 'measurements.jsonl').open('w') as stream:
        for index, item in enumerate(frame):
            dataset = ARTIFACT / item['dataset']
            context = contexts.setdefault(item['dataset'], None)
            if context is None:
                context = native_context(dataset, item['study'])
                contexts[item['dataset']] = context
            plan, receipt = load_json(bound(item['plan'])), load_json(bound(item['receipt']))
            inputs, context_id = external_case(item)
            verify_receipt(plan, receipt, expected_inputs=inputs, expected_context_id=context_id)
            source = dataset / 'cases' / item['case'] if item['study'] == 'sandmark' else dataset
            full_members = members(receipt, source, context['profile'])
            full_metrics = metrics(full_members)
            with tempfile.TemporaryDirectory(prefix='toolchainmark-full-') as temporary:
                populate(full_members, source, Path(temporary))
                verify_native(receipt, Path(temporary), context)
            for target in receipt['obligations']:
                target_id = target['id']
                bundle = project(plan, receipt, target_id, context, check_full=False)
                chosen = selection(plan, target_id)
                expected = dict(expected_plan=plan, expected_inputs=inputs,
                    expected_context_id=context_id, expected_native_context=context, expected_target=target_id)
                chosen_members = members(bundle['receipt'], source, context['profile'])
                with tempfile.TemporaryDirectory(prefix='toolchainmark-stage-') as temporary:
                    populate(chosen_members, source, Path(temporary))
                    checked = verify_bundle(bundle, Path(temporary), **expected)
                expected_actions = [a for a in receipt['actions'] if a['id'] in chosen['action_ids']]
                expected_obligations = [o for o in receipt['obligations'] if o['id'] in chosen['obligation_ids']]
                if (bundle['receipt']['actions'] != expected_actions or
                        bundle['receipt']['obligations'] != expected_obligations or
                        checked['target_judgment'] != target):
                    raise ValueError('projection changed a retained field or target judgment')
                reference = copy.deepcopy(bundle['receipt'])
                reference['actions'] = [row for row in receipt['actions'] if row['id'] in chosen['reference_action_ids']]
                reference_plan = {**plan, 'obligations': [o for o in plan['obligations']
                                                       if o['id'] in chosen['obligation_ids']]}
                replay = expected_case(reference_plan, reference)
                if not all(row['agreement'] for row in replay['results']):
                    raise ValueError('explicit reference replay changes a stage judgment')
                reference_members = members(reference, source, context['profile'])
                data = metrics(chosen_members)
                full_bundle = {'schema': 'toolchainmark-complete-evidence', 'target': target_id,
                               'source_plan': plan, 'receipt': receipt, 'native_context': context}
                bundle_bytes = len(encoded(bundle)) + data['native_storage_bytes']
                full_bundle_bytes = len(encoded(full_bundle)) + full_metrics['native_storage_bytes']
                record_bytes, full_record_bytes = len(encoded(bundle['receipt'])), len(encoded(receipt))
                full_actions, actions = len(receipt['actions']), len(bundle['receipt']['actions'])
                row = {'dataset': item['dataset'], 'study': item['study'], 'case': item['case'],
                       'target': target_id, 'stage': target['stage'], 'judgment': target['verdict'],
                       'accepted': checked['status'] == 'PASS', 'exact_target_preservation': True,
                       'reference_replay_agreement': True,
                       'actions': actions, 'full_actions': full_actions,
                       'reference_actions': len(reference['actions']),
                       'obligations': len(bundle['receipt']['obligations']),
                       'full_obligations': len(receipt['obligations']),
                       'record_bytes': record_bytes, 'full_record_bytes': full_record_bytes,
                       'reference_record_bytes': len(encoded(reference)),
                       'typed_replay_bytes': len(encoded(replay_only(plan, receipt, target_id))),
                       'bundle_bytes': bundle_bytes, 'full_bundle_bytes': full_bundle_bytes,
                       'bundle_metadata_bytes': len(encoded(bundle)),
                       'native_context_bytes': len(encoded(context)),
                       **data, **{'full_' + k: v for k, v in full_metrics.items()},
                       **{'reference_' + k: v for k, v in metrics(reference_members).items()},
                       'action_fraction': actions / full_actions if full_actions else 1,
                       'record_fraction': record_bytes / full_record_bytes,
                       'native_storage_fraction': (data['native_storage_bytes'] / full_metrics['native_storage_bytes']
                                                   if full_metrics['native_storage_bytes'] else 1),
                       'bundle_fraction': bundle_bytes / full_bundle_bytes}
                stream.write(encoded(row).decode() + '\n'); stream.flush(); rows.append(row)
                example_key = item['study'], target['verdict']
                if example_key not in retained_examples:
                    retained_examples.add(example_key)
                    example = output / 'examples' / item['study'] / target['verdict'].lower()
                    write(example / 'bundle.json', bundle)
                    write(example / 'case.json', {'plan': plan, 'inputs': inputs, 'context_id': context_id,
                                                 'native_context': context, 'target': target_id})
                    populate(chosen_members, source, example / 'native')
                    write(example / 'verification.json', checked)
            if (index + 1) % 250 == 0:
                print(json.dumps({'completed_source_receipts': index + 1, 'checked_targets': len(rows)}), flush=True)
    for row in frozen:
        if identity(ARTIFACT / row['path']) != {key: row[key] for key in ('bytes', 'sha256')}:
            raise ValueError('measurement implementation changed during execution: ' + row['path'])
    if not pilot and (len(frame), len(rows)) != (7380, 10134):
        raise ValueError('formal denominator differs from frozen protocol')
    result = {'study': 'complete-prefix evidence projection', 'purpose': 'pilot' if pilot else 'complete-retained-frame',
              'fresh_native_executions': 0, 'source_unchanged': True, **summary(rows),
              'elapsed_seconds': time.perf_counter() - start,
              'interpretation': 'Derived views of the existing native frame. Byte sums across targets repeat shared evidence and are not independent samples or a compressed archive size. Prefix checks do not authenticate membership in an unavailable historical receipt.'}
    write(output / 'summary.json', result)
    write(output / 'complete.json', {'status': 'COMPLETE', 'completed_utc': datetime.now(timezone.utc).isoformat(),
          'summary': identity(output / 'summary.json'), 'measurements': identity(output / 'measurements.jsonl'),
          'source_receipts': len(frame), 'targets': len(rows)})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--pilot', action='store_true')
    args = parser.parse_args()
    answer = run(args.out.resolve(), args.pilot)
    print(json.dumps(answer, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
