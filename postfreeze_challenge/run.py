"""Execute the frozen new-trigger plan without modifying any old producer.

Run from artifact/ with: PYTHONPATH=src python3 -B -m postfreeze_challenge.run --out results/postfreeze-challenge
The destination must not exist. All planned cases and failures are retained.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

from toolchainmark.admission import evaluate
from toolchainmark.model import BuildRequest, ExtractionError
from toolchainmark.study_validation import FIELDS
from .adapters import ChallengePipeline
from .common import (HERE, ROOT, PRODUCERS, checkout_inputs, delta_usage, json_bytes, load_plan, require, sha,
                     usage, utc, verify_checkout, write_json, write_trace)
from .derive import derive, source_size
from .recording import Recorder, activate, deactivate


def typed_extract(pipeline, binary, key):
    try:
        return 'payload:' + pipeline.extract(binary, key).hex()
    except ExtractionError as error:
        return 'rejection:' + error.kind
    except Exception as error:
        return 'error:' + type(error).__name__


def finish_trace(recorder, out, relative, record):
    record['events'] = recorder.events
    record['blobs'] = recorder.persist_blobs(out)
    record['counts'] = recorder.counts()
    identity = write_trace(out / relative, record)
    return {'record_path': relative, **identity, 'counts_json': json.dumps(record['counts'], sort_keys=True)}


def run_distinctions(out, plan):
    rows = []
    started = time.perf_counter()
    cpu = usage()
    for trace in plan['distinction_traces']:
        for carrier in plan['carriers']:
            for variant, expected in trace['expected'].items():
                index = len(rows) + 1
                with tempfile.TemporaryDirectory(prefix='postfreeze-distinction-') as temporary:
                    workspace = Path(temporary)
                    recorder = Recorder(workspace)
                    activate(recorder)
                    observations = []
                    error = None
                    try:
                        pipeline = ChallengePipeline(carrier, variant, recorder)
                        artifacts = {}
                        builds = {}
                        for action in trace['actions']:
                            parts = action.split(':')
                            if parts[0] == 'build':
                                _, label, payload = parts
                                request = BuildRequest(ROOT / 'hosts' / plan['distinction_host'],
                                    bytes.fromhex(plan['payloads'][payload]), plan['keys']['K1'],
                                    'gcc', 'O2', workspace / label)
                                builds[label] = pipeline.build(request)
                                artifacts[label] = builds[label].binary
                            elif parts[0] == 'extract':
                                _, label, key = parts
                                observations.append(typed_extract(pipeline, artifacts[label], plan['keys'][key]))
                            elif parts[0] == 'copy':
                                _, label, name = parts
                                target = workspace / 'copies' / name
                                target.parent.mkdir(exist_ok=True)
                                shutil.copy2(artifacts[label], target)
                                artifacts[name] = target
                                recorder.event('calibration_copy', source=recorder.snapshot(artifacts[label]),
                                               target=recorder.snapshot(target))
                            elif parts[0] == 'remove':
                                _, label, name = parts
                                artifacts[name] = pipeline.remove_carrier(builds[label], workspace / name)
                            elif parts[0] == 'reset-decoder':
                                recorder.event('calibration_reset_decoder')
                                pipeline = ChallengePipeline(carrier, variant, recorder)
                            else:
                                raise ValueError('unregistered distinction action')
                    except Exception as caught:
                        error = {'type': type(caught).__name__, 'message': recorder.normalize(str(caught))}
                        recorder.event('calibration_error', **error)
                    finally:
                        deactivate()
                    matched = error is None and observations == expected
                    record = {'kind': 'distinction', 'scenario': trace['id'], 'carrier': carrier,
                              'variant': variant, 'actions': trace['actions'], 'observations': observations,
                              'expected': expected, 'matched': matched, 'error': error}
                    descriptor = finish_trace(recorder, out, f'records/distinctions/case-{index:06}.json.gz', record)
                    rows.append({'scenario': trace['id'], 'carrier': carrier, 'variant': variant,
                                 'observations_json': json.dumps(observations), 'expected_json': json.dumps(expected),
                                 'matched': str(matched), 'error_json': json.dumps(error), **descriptor})
                print(f'distinction {index}/{plan["distinction_cases"]} {trace["id"]} {carrier} {variant} '
                      f'{"MATCH" if matched else "DIFF"}', flush=True)
    write_csv(out / 'distinctions.csv', rows[0].keys(), rows)
    report = {'cases': len(rows), 'matched': sum(row['matched'] == 'True' for row in rows),
              'wall_seconds': time.perf_counter() - started, **delta_usage(cpu)}
    write_json(out / 'distinction-activity.json', report)
    require(report['matched'] == report['cases'] == plan['distinction_cases'],
            'Registered separation failed; all attempted traces retained, main matrices not started')


def execute_case(task):
    activity, index, host, carrier, variant, relation, destination = task
    out = Path(destination)
    with tempfile.TemporaryDirectory(prefix='postfreeze-case-') as temporary:
        workspace = Path(temporary)
        case_root = workspace / 'relation'
        recorder = Recorder(workspace)
        started = time.perf_counter()
        cpu = usage()
        activate(recorder)
        try:
            pipeline = ChallengePipeline(carrier, variant, recorder)
            outcome = evaluate(relation, pipeline, ROOT / 'hosts' / host, case_root)
        finally:
            deactivate()
        wall = time.perf_counter() - started
        measured = {'case_wall_seconds_before_retention': wall, **delta_usage(cpu)}
        row = dict(host=host, host_sha256=sha((ROOT / 'hosts' / host).read_bytes()), carrier=carrier,
                   defect_id=variant, relation_id=relation, verdict=outcome.verdict,
                   exposed=str(variant != 'CLEAN' and outcome.verdict == 'INCONSISTENT'),
                   reason=outcome.reason, phase=outcome.phase,
                   admission_json=json.dumps(outcome.admission, sort_keys=True, separators=(',', ':')),
                   observations_json=json.dumps(outcome.observations, sort_keys=True, separators=(',', ':')),
                   duration_seconds=f'{wall:.6f}')
        record = {'kind': 'relation', 'activity': activity, 'index': index,
                  'identity': [host, carrier, variant, relation], 'outcome': asdict(outcome), 'measured': measured}
        descriptor = finish_trace(recorder, out, f'records/{activity}/case-{index:06}.json.gz', record)
    # The activity timer includes the now-completed cleanup and blob retention.
    return row, {'index': index, 'host': host, 'carrier': carrier, 'variant': variant,
                 'relation': relation, **descriptor, **measured}


def write_csv(path, fields, rows):
    with path.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(fields))
        writer.writeheader()
        writer.writerows(rows)


def run_activity(out, name, plan):
    relations = plan['relations'] if name.startswith('full') else ['MR01']
    cases = [(host, carrier, variant, relation) for host in plan['hosts']
             for carrier in plan['carriers'] for variant in plan['cohorts'] for relation in relations]
    tasks = [(name, index, *case, str(out)) for index, case in enumerate(cases, 1)]
    started_utc = utc()
    started = time.perf_counter()
    cpu = usage()
    traces = []
    # A partial CSV is retained on any harness/process failure, never overwritten.
    partial = out / (name + '.partial.csv')
    with partial.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        with ProcessPoolExecutor(max_workers=plan['workers']) as pool:
            for i, (row, trace) in enumerate(pool.map(execute_case, tasks, chunksize=1), 1):
                writer.writerow(row)
                traces.append(trace)
                if i % 250 == 0 or i == len(tasks):
                    stream.flush()
                    print(f'{name} {i}/{len(tasks)}', flush=True)
    partial.rename(out / (name + '.csv'))
    write_csv(out / (name + '-traces.csv'), traces[0].keys(), traces)
    return {'rows': len(traces), 'workers': plan['workers'], 'started_utc': started_utc,
            'finished_utc': utc(), 'end_to_end_wall_seconds': time.perf_counter() - started,
            **delta_usage(cpu),
            'compiler_invocation_attempts': sum(json.loads(row['counts_json'])['compiler_invocation_attempts'] for row in traces),
            'successful_build_returns': sum(json.loads(row['counts_json'])['successful_build_returns'] for row in traces),
            'case_wall_sum_before_retention': sum(row['case_wall_seconds_before_retention'] for row in traces)}


def source_inputs(out, inputs):
    entries = []
    for entry in inputs:
        entries.append({**entry, 'role': 'checkout-input'})
    for name in PRODUCERS:
        path = HERE / name
        entries.append({'path': 'postfreeze_challenge/' + name, 'bytes': path.stat().st_size,
                        'sha256': sha(path.read_bytes()), 'role': 'new-challenge-producer'})
    for entry in entries:
        destination = out / 'source-snapshot' / entry['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / entry['path'], destination)
    write_json(out / 'source-inputs.json', {'files': entries, 'recorded_utc': utc()})
    return entries


def environment():
    versions = {}
    for name in ('gcc', 'clang', 'objcopy', 'nm', 'strip', 'readelf'):
        proc = subprocess.run([name, '--version'], text=True, capture_output=True, check=True)
        path = Path(shutil.which(name)).resolve()
        versions[name] = {'path': str(path), 'sha256': sha(path.read_bytes()),
                          'version': proc.stdout.splitlines()[0]}
    return {'recorded_utc': utc(), 'python': sys.version, 'python_executable': sys.executable,
            'platform': platform.platform(), 'machine': platform.machine(), 'tools': versions,
            'workers': 4, 'load_average': list(os.getloadavg()),
            'environment': {key: os.environ.get(key) for key in
                ('PATH', 'LD_LIBRARY_PATH', 'CPATH', 'LIBRARY_PATH', 'PKG_CONFIG_PATH')},
            'audit_scope': 'Python subprocess.Popen invocation attempts; compiler-internal children are not counted separately.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    require(not out.exists(), 'Refusing an existing challenge destination')
    # Fresh campaigns bind the current checkout (see common.checkout_inputs);
    # the plan and frozen-inputs declaration are still identity-checked.
    plan, frozen = load_plan()
    inputs = checkout_inputs(frozen)
    out.mkdir(parents=True)
    for name in ('plan.json', 'frozen-inputs.json'):
        shutil.copyfile(HERE / name, out / name)
    started = time.perf_counter()
    cpu = usage()
    try:
        write_json(out / 'invocation.json', {'argv': sys.argv, 'cwd': str(Path.cwd()), 'started_utc': utc()})
        sources = source_inputs(out, inputs)
        write_json(out / 'environment.json', environment())
        write_json(out / 'source-size.json', source_size())
        run_distinctions(out, plan)
        verify_checkout(inputs)
        activities = {}
        for name in plan['activity_order']:
            activities[name] = run_activity(out, name, plan)
            verify_checkout(inputs)
        write_json(out / 'activities.json', activities)
        summary = derive(out)
        write_json(out / 'summary.json', summary)
        for entry in sources:
            require(sha((ROOT / entry['path']).read_bytes()) == entry['sha256'],
                    'Producer changed during activity: ' + entry['path'])
        manifest = [{'path': path.relative_to(out).as_posix(), 'bytes': path.stat().st_size,
                     'sha256': sha(path.read_bytes())}
                    for path in sorted(out.rglob('*')) if path.is_file()]
        write_json(out / 'record-manifest.json', {'files': manifest,
                   'scope': 'Exact completed producer outputs before the completion receipt and externally captured console logs.'})
        write_json(out / 'completion.json', {'completed_utc': utc(), 'all_sources_unchanged': True,
                   'source_files': len(sources), 'full_matrices': 2, 'rows_per_full_matrix': 3780,
                   'roundtrip_matrices': 2, 'rows_per_roundtrip_matrix': 270,
                   'distinction_cases': plan['distinction_cases'],
                   'record_manifest_sha256': sha((out / 'record-manifest.json').read_bytes()),
                   'campaign_wall_seconds': time.perf_counter() - started, **delta_usage(cpu),
                   'clean_control_gate': summary['clean_control_gate'],
                   'observed_rerun_differences': summary['observed_rerun_differences']})
        print('completed postfreeze-catalog-challenge-v1', flush=True)
    except BaseException as error:
        if not (out / 'failure.json').exists():
            write_json(out / 'failure.json', {'failed_utc': utc(), 'type': type(error).__name__,
                       'message': str(error), 'traceback': traceback.format_exc(),
                       'scope': 'Failed attempt retained; no claim of completed challenge.'})
        raise


if __name__ == '__main__':
    main()
