#!/usr/bin/env python3
"""Freeze and run a fixed whole-case schedule under a tested-call budget."""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import resource
import shutil
import sys
import time

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime.core import execute
from declarative_study import native_io
from declarative_study.reference_adapter import ReferenceAdapter
from declarative_study.state_words import ControlledStatePipeline, make_plan
from .derive_retained import derive


def write(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def read(path):
    return json.loads(Path(path).read_text())


def identity(path):
    raw = Path(path).read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def cpu(who):
    usage = resource.getrusage(who)
    return usage.ru_utime + usage.ru_stime


def schedules(protocol):
    catalog = []
    spent = 0
    for relation, cost in zip(protocol['catalog_order'], protocol['catalog_extract_costs']):
        if spent + cost > protocol['common_call_cap']:
            break
        spent += cost
        catalog.append({'name': relation, 'relation': relation, 'planned_extract_calls': cost})
    bfs, spent = [], 0
    words = [word for length in range(protocol['maximum_considered_suffix_length'] + 1)
             for word in itertools.product(protocol['alphabet'], repeat=length)]
    for word in words:
        cost = 1 + len(word)
        if spent + cost > protocol['common_call_cap']:
            break
        spent += cost
        name = 'empty' if not word else '_'.join(word).replace('+', 'p').replace('-', 'm')
        bfs.append({'name': name, 'word': list(word), 'planned_extract_calls': cost})
    return {'catalog': catalog, 'bfs': bfs}


def inputs(protocol, carrier, implementation, state):
    result = {'host': str(Path(protocol['recorded_artifact_root']) / protocol['host']),
              'carrier': carrier, 'implementation': implementation,
              'payload1': protocol['payloads'][0].encode().hex(),
              'payload2': protocol['payloads'][1].encode().hex(),
              'key1': protocol['keys'][0], 'key2': protocol['keys'][1],
              'compiler': protocol['compiler'], 'optimization': protocol['optimization'],
              'host_inputs': protocol['host_inputs']}
    if state:
        result.update(reuse_permitted=protocol['reuse_permitted'], lockout_excluded=protocol['lockout_excluded'])
    return result


def make_frame(protocol, ordered):
    result = []
    for run in protocol['passes']:
        for carrier in protocol['carriers']:
            for implementation in protocol['implementations']:
                for arm in protocol['arm_order'][str(run)]:
                    for position, entry in enumerate(ordered[arm]):
                        name = f'pass-{run}/{carrier}/{implementation}/{arm}/{entry["name"]}'
                        result.append({'id': name, 'pass': run, 'carrier': carrier,
                            'implementation': implementation, 'arm': arm, 'position': position,
                            **entry, 'plan': f'plans/{arm}/{entry["name"]}.json',
                            'inputs': inputs(protocol, carrier, implementation,
                                             arm == 'bfs' or entry.get('relation') == 'SR01')})
    return result


def producer_sources():
    sources = []
    for directory in ('state_budget', 'contract_runtime', 'src/toolchainmark'):
        sources.extend((ARTIFACT / directory).glob('*.py'))
    sources += [ARTIFACT / 'declarative_study' / name for name in
                ('reference_adapter.py', 'state_words.py', 'build_plans.py', 'native_io.py', 'verify.py')]
    sources += list((ARTIFACT / 'declarative_study/plans').glob('MR*.json'))
    sources += [ARTIFACT / name for name in ('declarative_study/plans/SR01.json',
                'independent_observers/producer_current/independent_observer.py',
                'state_budget/protocol.json', 'hosts/H01-gcd.c')]
    return sorted(set(sources))


def freeze(output):
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=False)
    protocol = read(ARTIFACT / 'state_budget/protocol.json')
    protocol['recorded_artifact_root'] = str(ARTIFACT)
    ordered = schedules(protocol); frame = make_frame(protocol, ordered)
    if len(frame) != protocol['expected_fresh_cases']:
        raise ValueError('Planned case count differs.')
    common = None
    for arm in ('catalog', 'bfs'):
        cost = 0; points = set()
        for entry in ordered[arm]:
            cost += entry['planned_extract_calls']; points.add(cost)
            plan = read(ARTIFACT / 'declarative_study/plans' / (entry['relation'] + '.json')) if arm == 'catalog' else make_plan(entry['word'])
            write(output / 'plans' / arm / (entry['name'] + '.json'), plan)
        common = points if common is None else common & points
    if sorted(common) != protocol['strict_equal_spent_points']:
        raise ValueError('Shared complete-prefix costs differ.')
    retained, retained_bindings = derive(ARTIFACT)
    write(output / 'retained-depth-costs.json', retained)
    write(output / 'retained-input-bindings.json', retained_bindings)
    write(output / 'protocol.json', protocol); write(output / 'schedule.json', ordered); write(output / 'frame.json', frame)
    sources = []
    for path in producer_sources():
        relative = path.relative_to(ARTIFACT)
        target = output / 'source-snapshot' / relative; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        sources.append({'path': relative.as_posix(), **identity(path)})
    declarations = [{'path': path.relative_to(output).as_posix(), **identity(path)}
                    for path in sorted(output.glob('plans/*/*.json'))]
    declarations += [{'path': name, **identity(output / name)} for name in
                     ('protocol.json', 'frame.json', 'schedule.json', 'retained-depth-costs.json', 'retained-input-bindings.json')]
    frozen = {'frozen_utc': datetime.now(timezone.utc).isoformat(), 'native_cases_executed': 0,
              'sources': sources, 'declarations': declarations}
    write(output / 'source-freeze.json', frozen)
    return {'status': 'FROZEN', 'cases': len(frame), 'source_files': len(sources),
            'strict_equal_spent_points': sorted(common), 'protocol_identity': identity(output / 'protocol.json')}


class CountedPipeline(ControlledStatePipeline):
    def __init__(self, carrier, implementation):
        super().__init__(carrier, implementation)
        self.call_trace = []

    def extract(self, binary, key):
        acquisition = native_io._CURRENT.get()
        row = {'ordinal': len(self.call_trace) + 1, 'binary': str(Path(binary).resolve()), 'key': key,
               'step_id': acquisition[1], 'context_id': acquisition[2]}
        self.call_trace.append(row)
        try:
            value = super().extract(binary, key)
        except Exception as error:
            row['observation'] = {'kind': 'rejection', 'value': error.kind} if hasattr(error, 'kind') else None
            row['exception'] = {'type': type(error).__name__, 'message': str(error)}
            raise
        else:
            row['observation'] = {'kind': 'payload', 'value': value.hex()}
            row['exception'] = None
            return value


def check_frozen(output, frozen):
    for item in frozen['sources']:
        if identity(ARTIFACT / item['path']) != {k: item[k] for k in ('bytes', 'sha256')}:
            raise ValueError('Producer source changed: ' + item['path'])
    for item in frozen['declarations']:
        if identity(output / item['path']) != {k: item[k] for k in ('bytes', 'sha256')}:
            raise ValueError('Frozen declaration changed: ' + item['path'])


def execute_study(output):
    output = Path(output).resolve(); frozen = read(output / 'source-freeze.json')
    if (output / 'start.json').exists():
        raise FileExistsError('Choose a newly frozen activity; previous attempts are retained.')
    check_frozen(output, frozen)
    protocol, frame = read(output / 'protocol.json'), read(output / 'frame.json')
    tools = {name: native_io.executable_identity(name) for name in ('gcc', 'clang', 'nm', 'objcopy', 'readelf', 'strip')}
    if any(value is None for value in tools.values()):
        raise RuntimeError('A declared native tool is unavailable before execution.')
    write(output / 'environment.json', {'python': sys.version, 'workers': 1, 'tools': tools,
                                       'cost_unit': protocol['cost_unit']})
    write(output / 'start.json', {'started_utc': datetime.now(timezone.utc).isoformat(),
                                 'source_freeze': identity(output / 'source-freeze.json')})
    started, self_cpu, child_cpu = time.perf_counter(), cpu(resource.RUSAGE_SELF), cpu(resource.RUSAGE_CHILDREN)
    for index, case in enumerate(frame):
        directory = output / 'cases' / case['id']; directory.mkdir(parents=True, exist_ok=False)
        plan = read(output / case['plan'])
        begin, parent_before, child_before = time.perf_counter(), cpu(resource.RUSAGE_SELF), cpu(resource.RUSAGE_CHILDREN)
        adapter = ReferenceAdapter(directory / 'native', output, pipeline_factory=CountedPipeline)
        receipt = execute(plan, case['inputs'], adapter, context_id=case['id'] + ':cost-study')
        trace = [] if adapter.pipeline is None else adapter.pipeline.call_trace
        record = {'case': case, 'extraction_call_trace': trace,
                  'extract_calls': len(trace),
                  'native_commands': sum(event['kind'] == 'process' for action in receipt['actions'] for event in action['evidence']),
                  'parent_cpu_seconds': cpu(resource.RUSAGE_SELF) - parent_before,
                  'child_cpu_seconds': cpu(resource.RUSAGE_CHILDREN) - child_before,
                  'wall_seconds': time.perf_counter() - begin,
                  'action_statuses': dict(Counter(action['status'] for action in receipt['actions'])),
                  'obligations': {row['id']: row['verdict'] for row in receipt['obligations']}}
        write(directory / 'receipt.json', receipt); write(directory / 'acquisition.json', record)
        if (index + 1) % 50 == 0:
            print(json.dumps({'completed_cases': index + 1, 'total_cases': len(frame)}), flush=True)
    check_frozen(output, frozen)
    timing = {'elapsed_seconds': time.perf_counter() - started,
              'parent_cpu_seconds': cpu(resource.RUSAGE_SELF) - self_cpu,
              'child_cpu_seconds': cpu(resource.RUSAGE_CHILDREN) - child_cpu}
    from .verify import recompute_summary
    summary = recompute_summary(output)
    summary.update(timing, producer_sources_unchanged=True)
    write(output / 'summary.json', summary)
    write(output / 'completion.json', {'status': 'COMPLETE', 'completed_utc': datetime.now(timezone.utc).isoformat(),
          'cases': len(frame), 'summary': identity(output / 'summary.json'), 'source_freeze': identity(output / 'source-freeze.json')})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('freeze', 'execute'))
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = freeze(args.out) if args.command == 'freeze' else execute_study(args.out)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
