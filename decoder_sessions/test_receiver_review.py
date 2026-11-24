"""Independent fixed-study mutation controls using retained pilot observations.

These controls never execute Java. They edit temporary copies and regenerate
derived receipts where needed, so a stale hash is not the only reason a false
experimental association could be rejected. Retained acquisition is unchanged.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from contract_runtime import execute
from decoder_sessions import verify
from decoder_sessions.analyze import analyze

DEFAULT_PILOT = ARTIFACT / 'results/decoder-sessions/pilot-03'
if not (DEFAULT_PILOT / 'completion.json').is_file():
    DEFAULT_PILOT = ARTIFACT / 'results/decoder-sessions/pilot-02'
PILOT = Path(os.environ.get('DECODER_SESSION_REVIEW_DATA', str(DEFAULT_PILOT)))


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RetainedActions:
    """Supply the retained raw operation returns to a changed declaration."""
    def __init__(self, receipt):
        self.actions = {row['id']: deepcopy(row) for row in receipt['actions']}
        self.operations = frozenset(row['operation'] for row in receipt['actions'])

    def invoke(self, operation, arguments, *, step_id, context_id):
        old = self.actions[step_id]
        if operation != old['operation'] or arguments != old['arguments'] or context_id != old['context_id']:
            raise ValueError('The mutation unexpectedly changed native action arguments')
        return {key: deepcopy(old[key]) for key in ('status', 'value', 'evidence', 'reason')}


class ReceiverReviewControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (PILOT / 'completion.json').is_file():
            raise unittest.SkipTest('The completed retained pilot is required; no acquisition is launched')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='decoder-receiver-review-')
        self.addCleanup(self.temporary.cleanup)
        self.run = Path(self.temporary.name) / 'activity'
        shutil.copytree(PILOT, self.run)

    def receive(self):
        return verify.Receiver(self.run).verify(allow_pilot=True)

    def refresh_envelopes(self):
        frozen = read(self.run / 'freeze.json')
        frozen['input_manifest'] = verify.binding(self.run, 'input-manifest.json')
        for history in frozen['plans']:
            frozen['plans'][history] = verify.binding(self.run, 'plans/' + history + '.json')
        write(self.run / 'freeze.json', frozen)
        start = read(self.run / 'execution-start.json')
        start['freeze_sha256'] = sha(self.run / 'freeze.json')
        write(self.run / 'execution-start.json', start)
        completion = read(self.run / 'completion.json')
        completion['freeze_sha256'] = start['freeze_sha256']
        completion['summary_sha256'] = sha(self.run / 'summary.json')
        write(self.run / 'completion.json', completion)

    def rederive(self, selected_words, altered_actions=None):
        altered_actions = altered_actions or {}
        frame = read(self.run / 'frame.json')
        selected = set(selected_words)
        for word in frame['words']:
            if word['id'] not in selected:
                continue
            folder = self.run / 'words' / word['id']
            old = read(folder / 'receipt.json')
            returns = RetainedActions(old)
            for sid, changed in altered_actions.get(word['id'], {}).items():
                returns.actions[sid] = changed
            plan = read(self.run / 'plans' / (word['inputs']['history'] + '.json'))
            receipt = execute(plan, word['inputs'], returns, context_id=word['id'], max_workers=1)
            write(folder / 'receipt.json', receipt)
            row = {**word, 'receipt': verify.binding(self.run, 'words/' + word['id'] + '/receipt.json'),
                   'judgments': {o['id']: o['verdict'] for o in receipt['obligations']},
                   'action_status': {a['id']: a['status'] for a in receipt['actions']}}
            write(folder / 'result.json', row)
        summary = read(self.run / 'summary.json')
        rows = [read(self.run / 'words' / word['id'] / 'result.json') for word in frame['words']]
        judgments = Counter(v for row in rows for v in row['judgments'].values())
        statuses = Counter(v for row in rows for v in row['action_status'].values())
        summary.update(words=rows, judgments=dict(judgments), action_status=dict(statuses),
                       word_count=len(rows), obligation_count=sum(judgments.values()))
        write(self.run / 'summary.json', summary)
        self.refresh_envelopes()
        analysis_path = self.run / 'paired-analysis.json'
        if analysis_path.is_file() and read(analysis_path).get('schema') == 'sandmark-session-paired-analysis-v2':
            # Rebuild the temporary fixture's derived report as well as its
            # receipts. The independent receiver must judge the intended
            # native association, not reject an accidentally stale summary.
            analyze(self.run)

    def test_unmodified_retained_pilot_is_accepted(self):
        report = self.receive()
        self.assertEqual('PASS', report['verdict'])
        self.assertEqual(len(read(self.run / 'frame.json')['words']), report['counters']['planned_words'])

    def test_changed_plan_cannot_become_the_prespecified_study(self):
        frame = read(self.run / 'frame.json')
        history = frame['words'][0]['inputs']['history']
        plan_path = self.run / 'plans' / (history + '.json')
        plan = read(plan_path)
        plan['obligations'][0]['predicate'] = {'literal': True}
        write(plan_path, plan)
        words = [w['id'] for w in frame['words'] if w['inputs']['history'] == history]
        self.rederive(words)
        with self.assertRaises(ValueError):
            self.receive()

    def test_rebound_historical_source_verdict_is_rejected(self):
        summary_path = self.run / 'prior-metadata/summary.json'
        prior = read(summary_path)
        row = next(r for r in prior['configurations'] if r['judgments']['identity'] == 'SATISFIED')
        row['judgments']['identity'] = 'INCONSISTENT'
        write(summary_path, prior)
        manifest_path = self.run / 'input-manifest.json'
        manifest = read(manifest_path)
        manifest['cases'][row['id']]['prior_source_verdict'] = 'INCONSISTENT'
        entry = manifest['prior_metadata']['summary.json']
        entry.update(verify.binding(self.run, 'prior-metadata/summary.json'))
        write(manifest_path, manifest)
        self.refresh_envelopes()
        with self.assertRaises(ValueError):
            self.receive()

    def test_changed_capsule_cannot_retain_admitted_source_or_revisit(self):
        frame = read(self.run / 'frame.json')
        word = next(w for w in frame['words'] if w['inputs']['lifetime'] == 'P'
                    and read(self.run / 'words' / w['id'] / 'result.json')['judgments']['first-a-source'] == 'SATISFIED')
        plan = read(self.run / 'plans' / (word['inputs']['history'] + '.json'))
        def has_initial_context(value):
            if isinstance(value, dict):
                return (value.get('ref') == 'prepare' and value.get('path', [])[:1] == ['initial_context']) or any(
                    has_initial_context(v) for v in value.values())
            return isinstance(value, list) and any(has_initial_context(v) for v in value)
        if not has_initial_context(plan['obligations'][0]['requires']):
            self.skipTest('This retained pilot predates the explicit prepared-capsule premise')
        folder = self.run / 'words' / word['id']
        receipt = read(folder / 'receipt.json')
        action = deepcopy(next(a for a in receipt['actions'] if a['id'] == 'first-a'))
        req = folder / 'requests/first-a'
        before, after = read(req / 'before.json'), read(req / 'after.json')
        replacement = deepcopy(before['original'])
        self.assertTrue(replacement['present'])
        self.assertNotEqual(replacement['sha256'], before['target']['sha256'])
        before['target'] = deepcopy(replacement)
        after['target'] = deepcopy(replacement)
        write(req / 'before.json', before)
        write(req / 'after.json', after)
        value = read(req / 'observation.json')
        value.update(before=before, after=after)
        write(req / 'observation.json', value)
        action['value'] = value
        action['evidence'] = [verify.binding(self.run, row['path']) for row in action['evidence']]
        self.rederive([word['id']], {word['id']: {'first-a': action}})
        result = read(folder / 'result.json')
        self.assertEqual('INADMISSIBLE', result['judgments']['first-a-source'])
        self.assertEqual('INADMISSIBLE', result['judgments']['revisit'])
        self.assertEqual('PASS', self.receive()['verdict'])

    def test_failure_after_enumeration_remains_an_unavailable_return(self):
        selected = None
        for word in read(self.run / 'frame.json')['words']:
            folder = self.run / 'words' / word['id']
            receipt = read(folder / 'receipt.json')
            action = next(a for a in receipt['actions'] if a['id'] == 'first-a')
            if action['status'] == 'OK':
                selected = word, folder, action['value']['native']
                break
        self.assertIsNotNone(selected)
        word, folder, retained_native = selected
        native = deepcopy(retained_native)
        native['kind'] = 'tool-exception'
        native['exception_class'] = 'java.lang.IllegalStateException'
        native['exception_message'] = 'Property capture failed after iterator exhaustion'
        native.pop('properties_after')
        self.assertIs(native['iteration_complete'], True)
        process = {'command': read(folder / 'processes/process-01/command.json'), 'end_records': []}
        request = {'inputs': word['inputs'],
                   'fields': {key:native[key] for key in ('request_id','role','target','key','original_file','key_file')}}
        receiver = verify.Receiver(self.run)
        self.assertIs(receiver.native_return(native, request, process, 1), False)
        self.assertEqual(1, receiver.counts['incomplete_native_returns'])


if __name__ == '__main__':
    unittest.main()
