#!/usr/bin/env python3
"""Exercise real JVM startup failure; these controls are not watermark samples."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from contract_runtime import execute
from decoder_sessions.adapter import SessionAdapter
from decoder_sessions.common import clone_file, file_digest, read_json, write_json
from decoder_sessions.plans import make_plan


def controls(pilot: Path, output: Path):
    if output.exists(): raise ValueError('Use a new control directory')
    output.mkdir(parents=True)
    (output / 'bridge').mkdir()  # Deliberately empty; Java cannot load SessionBridge.
    frame = read_json(pilot / 'frame.json'); freeze = read_json(pilot / 'freeze.json')
    word = next(w for w in frame['words'] if w['inputs']['algorithm'] == 'Add Method and Field' and w['inputs']['history'] == 'AA')
    cid = word['inputs']['a_case']
    original = read_json(pilot / 'input-manifest.json')['cases'][cid]
    manifest = {'cases': {cid: original}}
    for info in original['files'].values():
        if info['present']: clone_file(pilot / info['path'], output / info['path'])
    records = []
    for mode in ('P', 'R'):
        inputs = {**word['inputs'], 'lifetime': mode}
        context = 'startup-control-' + mode.lower()
        adapter = SessionAdapter(output, context, inputs, manifest, freeze)
        try: receipt = execute(make_plan('AA'), inputs, adapter, context_id=context, max_workers=1)
        finally: adapter.cleanup()
        write_json(output / 'words' / context / 'receipt.json', receipt)
        actions = {a['id']: a for a in receipt['actions']}
        failed = actions['open'] if mode == 'R' else actions['first-a']
        if failed['status'] != 'UNAVAILABLE' or not failed['evidence']:
            raise ValueError('Real startup failure lost its unavailable status or evidence bindings')
        if any(o['verdict'] != 'INADMISSIBLE' for o in receipt['obligations']):
            raise ValueError('Startup failure was treated as a scientific inconsistency')
        process = adapter.processes[0].record
        if process['returncode'] == 0 or process['ready'] is not None or process['done'] is not None:
            raise ValueError('The intended missing-helper control did not occur')
        records.append({'context': context, 'lifetime': mode, 'failed_step': failed['id'],
                        'status': failed['status'], 'evidence_bindings': len(failed['evidence']),
                        'returncode': process['returncode'],
                        'judgments': {o['id']: o['verdict'] for o in receipt['obligations']}})
    report = {'schema': 'sandmark-session-acquisition-controls-v1', 'verdict': 'PASS',
              'controls': records, 'control_source_sha256': file_digest(Path(__file__)),
              'adapter_sha256': file_digest(HERE / 'adapter.py'),
              'scope': 'Two actual JVM launches with an intentionally empty helper class directory. No watermark recognition is invoked. These protocol controls are excluded from all pilot and formal scientific denominators.'}
    write_json(output / 'report.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pilot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    import json
    print(json.dumps(controls(args.pilot.resolve(), args.output.resolve()), indent=2))
