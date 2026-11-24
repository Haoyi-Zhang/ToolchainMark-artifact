"""Execute the separately frozen SR01 plan with real native builds and extractions.

From artifact/: PYTHONPATH=src python3 -B -m recovery_extension.run --out results/recovery-extension/completed
An existing destination is refused; failures retain their original records.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import csv
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
import traceback

from toolchainmark.model import BuildRequest, ExtractionError
from independent_observers.producer_current.independent_observer import observe
from postfreeze_challenge.adapters import ChallengePipeline
from postfreeze_challenge.common import delta_usage, require, sha, usage, utc, verify_checkout, write_json
from postfreeze_challenge.recording import Recorder, activate, deactivate
from postfreeze_challenge.run import environment, finish_trace, write_csv
from .common import HERE, ROOT, PRODUCERS, checkout_entries, load_plan
from .derive import FIELDS, derive, source_size
from .model import PREMISES, assess


def extract(pipeline, path, key):
    try:
        return {'kind': 'payload', 'value': pipeline.extract(path, key).hex()}
    except ExtractionError as error:
        return {'kind': 'rejection', 'value': error.kind}
    except Exception as error:
        return {'kind': 'error', 'value': type(error).__name__}


def execute_case(task):
    name, index, host, carrier, cohort, plan, destination = task
    out = Path(destination)
    request = {'payload_hex': plan['payloads']['P1'], 'key': plan['keys']['K1'], 'wrong_key': plan['keys']['K2']}
    contract = {key: cohort[key] for key in ('reuse_after_rejection_declared', 'lockout_excluded_by_contract')}
    with tempfile.TemporaryDirectory(prefix='sr01-recovery-') as temporary:
        workspace = Path(temporary)
        recorder = Recorder(workspace)
        evidence = {'snapshots': {}, 'observations': {}, 'tested_calls': [], 'decoder_instances': 0}
        cpu = usage()
        started = time.perf_counter()
        activate(recorder)
        error = None
        try:
            pipeline = ChallengePipeline(carrier, cohort['variant'], recorder)
            result = pipeline.build(BuildRequest(ROOT / 'hosts' / host, bytes.fromhex(request['payload_hex']),
                                     request['key'], plan['compiler'], plan['optimization'], workspace / 'source'))
            path = result.binary
            def checkpoint(label):
                value = recorder.snapshot(path)
                evidence['snapshots'][label] = value
                recorder.event('recovery_checkpoint', label=label, artifact=value)
                return value
            source = checkpoint('source')
            try:
                source_observation = observe(recorder.raw_blobs[source['sha256']], carrier, request['key'])
            except Exception as caught:
                source_observation = {'kind': 'unavailable', 'value': type(caught).__name__}
            evidence['observations']['source_carrier'] = source_observation
            recorder.event('recovery_source_observation', observation=source_observation, artifact=source)
            evidence['observations']['source'] = extract(pipeline, path, request['key'])
            checkpoint('before_wrong_key')
            evidence['observations']['wrong_key'] = extract(pipeline, path, request['wrong_key'])
            checkpoint('after_wrong_key')
            if cohort['replace_after_rejection']:
                other = pipeline.build(BuildRequest(ROOT / 'hosts' / host, bytes.fromhex(plan['payloads']['P2']),
                                       request['key'], plan['compiler'], plan['optimization'], workspace / 'replacement'))
                before = recorder.snapshot(path)
                shutil.copyfile(other.binary, path)
                recorder.event('controlled_target_replacement', source=recorder.snapshot(other.binary),
                               target_before=before, target_after=recorder.snapshot(path))
            checkpoint('before_recovery')
            evidence['observations']['recovery'] = extract(pipeline, path, request['key'])
            checkpoint('after_recovery')
        except Exception as caught:
            error = {'type': type(caught).__name__, 'message': recorder.normalize(str(caught))}
            recorder.event('recovery_execution_error', **error)
        finally:
            deactivate()
        wall = time.perf_counter() - started
        measured = {'case_wall_seconds_before_retention': wall, **delta_usage(cpu)}
        evidence['tested_calls'] = [{'path': event['path'], 'key': event['key']}
                                    for event in recorder.events if event['event'] == 'extract_call']
        evidence['decoder_instances'] = sum(event['event'] == 'decoder_instance' for event in recorder.events)
        outcome = assess(evidence, contract, request)
        identity = [host, carrier, cohort['id'], 'SR01']
        record = {'kind': 'recovery', 'pass': name, 'index': index, 'identity': identity,
                  'variant': cohort['variant'], 'contract': contract, 'request': request, 'evidence': evidence,
                  'outcome': outcome, 'error': error, 'measured': measured}
        descriptor = finish_trace(recorder, out, f'records/{name}/case-{index:06}.json.gz', record)
        compact = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
        row = dict(host=host, host_sha256=sha((ROOT / 'hosts' / host).read_bytes()), carrier=carrier,
                   cohort=cohort['id'], variant=cohort['variant'], relation_id='SR01', verdict=outcome['verdict'],
                   reason=outcome['reason'], contract_json=compact(contract), request_json=compact(request),
                   admission_json=compact(outcome['admission']), evidence_json=compact(evidence),
                   duration_seconds=f'{wall:.6f}')
        return row, {'index': index, **descriptor, **measured}


def run_pass(out, name, plan):
    cases = [(host, carrier, cohort) for host in plan['hosts'] for carrier in plan['carriers'] for cohort in plan['cohorts']]
    tasks = [(name, index, *case, plan, str(out)) for index, case in enumerate(cases, 1)]
    traces = []
    started_utc, started, cpu = utc(), time.perf_counter(), usage()
    partial = out / (name + '.partial.csv')
    with partial.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        with ProcessPoolExecutor(max_workers=plan['workers']) as pool:
            for index, (row, trace) in enumerate(pool.map(execute_case, tasks, chunksize=1), 1):
                writer.writerow(row)
                traces.append(trace)
                if index % 90 == 0:
                    stream.flush()
                    print(f'SR01 {name} {index}/{len(tasks)}', flush=True)
    partial.rename(out / (name + '.csv'))
    write_csv(out / (name + '-traces.csv'), traces[0].keys(), traces)
    return {'cases': len(traces), 'workers': plan['workers'], 'started_utc': started_utc, 'finished_utc': utc(),
            'end_to_end_wall_seconds': time.perf_counter() - started, **delta_usage(cpu),
            'compiler_invocation_attempts': sum(json.loads(row['counts_json'])['compiler_invocation_attempts'] for row in traces),
            'successful_build_returns': sum(json.loads(row['counts_json'])['successful_build_returns'] for row in traces),
            'case_wall_sum_before_retention': sum(row['case_wall_seconds_before_retention'] for row in traces)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    require(not out.exists(), 'Refusing an existing SR01 destination')
    # Fresh campaigns bind the current checkout (recovery_extension.common.checkout_entries);
    # the registered plan and prior-freeze declaration are still identity-checked.
    plan, prior = load_plan()
    require(tuple(plan['premises']) == PREMISES, 'registered SR01 premise order differs')
    entries = checkout_entries(prior)
    out.mkdir(parents=True)
    started, cpu = time.perf_counter(), usage()
    try:
        for name in ('plan.json', 'frozen-inputs.json', 'producer-freeze.json'):
            shutil.copyfile(HERE / name, out / name)
        for entry in entries:
            target = out / 'source-snapshot' / entry['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / entry['path'], target)
        write_json(out / 'source-inputs.json', {'files': entries, 'recorded_utc': utc()})
        write_json(out / 'invocation.json', {'argv': sys.argv, 'cwd': str(Path.cwd()), 'started_utc': utc()})
        write_json(out / 'environment.json', environment())
        write_json(out / 'source-size.json', source_size())
        activities = {}
        for name in plan['passes']:
            activities[name] = run_pass(out, name, plan)
            verify_checkout(entries)
        write_json(out / 'activities.json', activities)
        summary = derive(out)
        write_json(out / 'summary.json', summary)
        for entry in entries:
            require(sha((ROOT / entry['path']).read_bytes()) == entry['sha256'], 'SR01 producer changed during execution')
        manifest = [{'path': path.relative_to(out).as_posix(), 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}
                    for path in sorted(out.rglob('*')) if path.is_file()]
        write_json(out / 'record-manifest.json', {'files': manifest})
        write_json(out / 'completion.json', {'completed_utc': utc(), 'all_sources_unchanged': True, 'source_files': len(entries),
                   'passes': len(plan['passes']), 'cases_per_pass': plan['cases_per_pass'],
                   'record_manifest_sha256': sha((out / 'record-manifest.json').read_bytes()),
                   'campaign_wall_seconds': time.perf_counter() - started, **delta_usage(cpu)})
        print('completed recovery-obligation-v1', flush=True)
    except BaseException as caught:
        write_json(out / 'failure.json', {'failed_utc': utc(), 'type': type(caught).__name__, 'message': str(caught),
                   'traceback': traceback.format_exc(), 'scope': 'Failed attempt retained; no completed-study claim.'})
        raise


if __name__ == '__main__':
    main()
