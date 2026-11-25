"""Read-only reception of the controlled execution-record comparison.

Check the frozen frame, every exact mutation, source/data identities and all
saved checking-layer results. Re-evaluate the frozen checker code on retained
records; no tested native program or official CTF API is executed.
"""
from __future__ import annotations
from collections import Counter
from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import shutil
import tempfile

ARTIFACT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def equal(left, right):
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return encode(left) == encode(right)


def safe(root, name):
    require(type(name) is str and bool(name), 'empty/non-string relative path')
    relative = Path(name)
    require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe evidence path')
    # Retained records use the historical declarative-v6 path.  The public
    # repository stores the same frozen bytes under the neutral declarative
    # name, so resolve that one known compatibility alias without changing the
    # record itself.
    if relative.parts[:2] == ('results', 'declarative-v6'):
        relative = Path('results', 'declarative', *relative.parts[2:])
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()), 'evidence path escapes root')
    return path


def patched_record(original, patches):
    """Independent implementation of the two frozen JSON-edit operations."""
    result = deepcopy(original)
    require(type(patches) is list, 'patches must be an array')
    for entry in patches:
        require(entry['op'] in ('replace', 'remove') and type(entry['path']) is list and bool(entry['path']),
                'unsupported patch operation or path')
        require(set(entry) == ({'op', 'path', 'before', 'after'} if entry['op'] == 'replace' else {'op', 'path', 'before'}),
                'patch properties differ')
        parent = result
        for token in entry['path'][:-1]:
            require(type(token) in (int, str), 'invalid patch path token')
            parent = parent[token]
        token = entry['path'][-1]
        require(type(token) in (int, str) and equal(parent[token], entry['before']), 'patch preimage mismatch')
        if entry['op'] == 'remove':
            if type(parent) is list: parent.pop(token)
            else: del parent[token]
        else:
            parent[token] = deepcopy(entry['after'])
    return result


def without_timing(value):
    if isinstance(value, dict):
        return {key: without_timing(item) for key, item in value.items()
                if key not in ('wall_seconds', 'cpu_seconds')}
    if isinstance(value, list):
        return [without_timing(item) for item in value]
    return value


def verify(data, artifact=ARTIFACT):
    data, artifact = Path(data).resolve(), Path(artifact).resolve()
    compatibility = tempfile.TemporaryDirectory(prefix='toolchainmark-correspondence-')
    compatibility_root = Path(compatibility.name)
    legacy = compatibility_root / 'results' / 'declarative-v6'
    legacy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(artifact / 'results' / 'declarative', legacy)
    # Records frozen by the current runner name the neutral directory; expose
    # the same copied bytes under that name too, so fresh comparisons replay.
    (compatibility_root / 'results' / 'declarative').symlink_to(legacy, target_is_directory=True)
    try:
        protocol = read(data / 'protocol.json')
        freeze, start, completion, summary = [read(data / name) for name in
                ('freeze-receipt.json', 'execution-start.json', 'completion.json', 'summary.json')]
        digest = sha(data / 'protocol.json')
        require(digest == freeze['protocol_sha256'] == start['protocol_sha256'] == completion['protocol_sha256'],
                'protocol freeze/start/completion identities differ')
        require(freeze['layer_evaluations_performed'] == 0 and protocol['status'] == 'FROZEN_BEFORE_LAYER_EVALUATION',
                'pre-execution freeze state differs')
        require(sha(data / 'summary.json') == completion['summary_sha256'], 'completed summary identity differs')
        require(protocol['layers'] == ['oracle-replay', 'plan-receiver', 'native-binding'], 'checking-layer frame differs')
        require(len(protocol['frame']) == protocol['records'] == 24 and
                sum(row['valid_record'] is True for row in protocol['frame']) == protocol['valid_records'] == 6 and
                sum(row['valid_record'] is False for row in protocol['frame']) == protocol['controlled_invalid_records'] == 18,
                'record/frame denominator differs')
        for kind, root in (('source_bindings', data / 'source-snapshot'), ('dataset_bindings', artifact)):
            paths = set()
            for binding in protocol[kind]:
                require(binding['path'] not in paths, 'duplicate frozen input')
                paths.add(binding['path'])
                path = safe(root, binding['path'])
                require(path.stat().st_size == binding['bytes'] and sha(path) == binding['sha256'],
                        'frozen input differs: ' + binding['path'])
        identities = [row['id'] for row in protocol['frame']]
        require(len(set(identities)) == len(identities) and start['case_order'] == identities,
                'case identity/order differs')
        require({p.name for p in (data / 'cases').iterdir()} == set(identities), 'case directory domain differs')
        require([row['id'] for row in summary['rows']] == identities, 'summary case order differs')
        counts = {tier: Counter() for tier in protocol['layers']}
        decisions, patches, reruns = 0, 0, 0
        for item, recorded_summary in zip(protocol['frame'], summary['rows']):
            base = safe(data / 'bases', item['base'])
            anchor = read(base / 'anchor.json')
            require(equal(anchor, protocol['anchors'][item['base']]), 'base anchor differs from protocol')
            require(sha(base / 'receipt.json') == sha(safe(artifact, anchor['receipt_source'])) and
                    sha(base / 'plan.json') == sha(safe(artifact, anchor['plan_source'])), 'original base record changed')
            original = read(base / 'receipt.json')
            require(equal(original['inputs'], anchor['expected_inputs']) and original['context_id'] == anchor['expected_context_id'],
                    'external base inputs/context differ')
            require(bool(item['patches']) != item['valid_record'], 'valid/changed record label does not match the edit frame')
            altered = patched_record(original, item['patches'])
            require(equal(altered, original) == item['valid_record'], 'negative edit is empty or a positive record changed')
            directory = safe(data / 'cases', item['id'])
            require(equal(read(directory / 'mutation.json'), item), 'controlled change differs from frozen frame')
            require(equal(read(directory / 'receipt.json'), altered), 'record differs from exactly the declared edit')
            require(sha(directory / 'plan.json') == sha(base / 'plan.json') and
                    equal(read(directory / 'anchor.json'), anchor), 'case plan or external anchor changed')
            evaluation = read(directory / 'evaluation.json')
            require(equal(evaluation, read(directory / 'evaluation.stdout.json')), 'saved evaluation differs from original stdout')
            invocation = read(directory / 'invocation.json')
            require(invocation['exit'] == 0 and invocation['stdout_sha256'] == sha(directory / 'evaluation.stdout.json') and
                    invocation['stderr_sha256'] == sha(directory / 'evaluation.stderr.txt'), 'evaluation process record differs')
            require([r['tier'] for r in evaluation['layers']] == protocol['layers'], 'missing/extra layer decision')
            require(evaluation['native_programs_reexecuted'] is False and evaluation['official_ctf_api_called'] is False,
                    'evaluation scope changed')
            argv = [sys.executable, '-B', str(data / 'source-snapshot/evidence_correspondence/evaluate.py'),
                    '--case', str(directory), '--artifact', str(compatibility_root)]
            actual = subprocess.run(argv, cwd=data, capture_output=True, timeout=120)
            require(actual.returncode == 0, 'frozen layer evaluator failed during read-only reception')
            require(equal(without_timing(json.loads(actual.stdout)), without_timing(evaluation)),
                    'layer results differ from actual frozen-code replay')
            require(equal(recorded_summary, {'id': item['id'], 'base': item['base'],
                                            'valid_record': item['valid_record'], 'layers': evaluation['layers']}),
                    'case summary differs from observed decisions')
            for layer in evaluation['layers']:
                require(type(layer['accepted']) is bool, 'layer acceptance must be Boolean')
                require(type(layer['wall_seconds']) in (int, float) and layer['wall_seconds'] >= 0 and
                        type(layer['cpu_seconds']) in (int, float) and layer['cpu_seconds'] >= 0, 'invalid measured duration')
                key = ('valid_' if item['valid_record'] else 'invalid_') + ('accepted' if layer['accepted'] else 'rejected')
                counts[layer['tier']][key] += 1
                decisions += 1
            patches += len(item['patches']); reruns += 1
        observed_counts = {tier: dict(values) for tier, values in counts.items()}
        require(equal(summary['layers'], observed_counts), 'layer totals differ from individual observations')
        require(summary['records'] == completion['records'] == 24 and
                summary['acceptance_decisions'] == completion['acceptance_decisions'] == protocol['planned_acceptance_decisions'] == decisions == 72,
                'completed comparison denominator differs')
        require(summary['native_programs_reexecuted'] is False and summary['official_ctf_api_called'] is False,
                'summary execution scope changed')
        return {'schema': 'execution-correspondence-receiver-v1', 'verdict': 'PASS', 'records': 24,
                'valid_records': 6, 'controlled_invalid_records': 18, 'acceptance_decisions': decisions,
                'declared_patch_operations_checked': patches, 'frozen_checker_replays': reruns,
                'frozen_source_files': len(protocol['source_bindings']), 'retained_dataset_bindings': len(protocol['dataset_bindings']),
                'layers': observed_counts, 'native_programs_reexecuted': False, 'official_ctf_api_called': False,
                'scope': 'Exact frozen record edits, externally selected cases, saved byte identities and observed checking-layer outcomes. A PASS validates the retained comparison; it does not require a desired detection result or certify historical acquisition.'}


    finally:
        compatibility.cleanup()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=ARTIFACT / 'results/evidence-correspondence/completed')
    args = parser.parse_args()
    print(json.dumps(verify(args.data), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
