"""Hand-written GeMTest callbacks over shared native operations.

This module does not import the contract interpreter, its expression evaluator,
or either receiver. GeMTest supplies source execution, validity filtering,
follow-up execution, relation evaluation and the pytest outcome. The adapter is
shared deliberately: the comparison isolates orchestration and interpretation.
"""
from __future__ import annotations

import copy
from pathlib import Path
import time

from declarative_study.reference_adapter import ReferenceAdapter, Pipeline
from declarative_study.state_words import ControlledStatePipeline

SATISFIED = 'SATISFIED'
INCONSISTENT = 'INCONSISTENT'
INADMISSIBLE = 'INADMISSIBLE'


def inputs_for(case, artifact, protocol):
    return {
        'host': str((artifact / protocol['host']).resolve()),
        'carrier': case['carrier'], 'implementation': case['implementation'],
        'payload1': protocol['payloads'][0].encode().hex(),
        'payload2': protocol['payloads'][1].encode().hex(),
        'key1': protocol['keys'][0], 'key2': protocol['keys'][1],
        'compiler': protocol['compiler'], 'optimization': protocol['optimization'],
        'host_inputs': protocol['host_inputs'],
        **({'reuse_permitted': True, 'lockout_excluded': True}
           if case['relation'] == 'SR01' else {}),
    }


def classify(required, predicate):
    if not all(required):
        return INADMISSIBLE
    return SATISFIED if predicate else INCONSISTENT


class NativeCase:
    """One fresh decoder and a manually specified sequence of native calls."""

    def __init__(self, case, directory, store, inputs):
        self.case, self.directory, self.store = case, Path(directory), Path(store)
        self.inputs = inputs
        self.context = case['id'] + ':gemtest'
        factory = ControlledStatePipeline if case['family'] == 'state' else Pipeline
        self.adapter = ReferenceAdapter(self.directory, self.store, pipeline_factory=factory)
        self.actions = []
        self.by_id = {}
        self.started = time.perf_counter()
        self.finished = None
        self.framework_events = []

    def __repr__(self):
        return self.case['id']

    def available(self, name):
        return self.by_id.get(name, {}).get('status') == 'OK'

    def value(self, name, *path):
        if not self.available(name):
            return None
        value = self.by_id[name]['value']
        for key in path:
            value = value[key]
        return value

    def invoke(self, name, operation, **arguments):
        if name in self.by_id:
            raise ValueError('An action was invoked twice: ' + name)
        if any(value is None for value in arguments.values()):
            result = {'status': 'SKIPPED', 'value': None, 'evidence': [],
                      'reason': 'A required operation result is unavailable.'}
        else:
            result = self.adapter.invoke(operation, arguments, step_id=name,
                                         context_id=self.context)
        row = {'id': name, 'operation': operation, 'arguments': arguments, **result}
        self.actions.append(row)
        self.by_id[name] = row
        return result

    def skip(self, name, operation):
        if name not in self.by_id:
            row = {'id': name, 'operation': operation, 'arguments': None,
                   'status': 'SKIPPED', 'value': None, 'evidence': [],
                   'reason': 'The GeMTest source-output condition is false.'}
            self.actions.append(row)
            self.by_id[name] = row

    def session(self):
        return self.value('session', 'session_id')

    def build(self, name, payload='payload1', guarded=False):
        self.invoke(name, 'build', session=self.session(), host=self.inputs['host'],
                    payload_hex=self.inputs[payload], key=self.inputs['key1'],
                    compiler=self.inputs['compiler'], optimization=self.inputs['optimization'],
                    label=name, marked=True, guarded=guarded)

    def extract(self, name, source, key='key1'):
        self.invoke(name, 'extract', session=self.session(),
                    binary=self.value(source, 'binary'), key=self.inputs[key])

    def inspect(self, name, source):
        self.invoke(name, 'inspect', session=self.session(),
                    binary=self.value(source, 'binary'), key=self.inputs['key1'])

    def host(self, name, source):
        self.invoke(name, 'host', session=self.session(),
                    binary=self.value(source, 'binary'), inputs=self.inputs['host_inputs'])

    def payload(self, name, requested='payload1'):
        return self.value(name, 'observation') == {
            'kind': 'payload', 'value': self.inputs[requested]}

    def unchanged(self, name):
        return self.available(name) and self.value(name, 'before') == self.value(name, 'after')

    def source(self):
        self.framework_events.append('source SUT')
        relation = self.case['relation']
        self.invoke('session', 'session', carrier=self.inputs['carrier'],
                    implementation=self.inputs['implementation'])
        if relation in {'MR08', 'MR09'}:
            self.build('source', guarded=relation == 'MR09')
            self.extract('recover', 'source')
            if relation == 'MR09':
                self.inspect('source-view', 'source')
        else:
            self.build('first')
            self.build('second', 'payload2')
            if relation == 'MR13':
                self.extract('before', 'first')
            else:
                self.inspect('physical-A', 'first')
                self.inspect('physical-B', 'second')
                self.extract('initial', 'first')
        return self.output()

    def output(self):
        return copy.deepcopy({
            'case_id': self.case['id'], 'relation': self.case['relation'],
            'actions': [{key: row[key] for key in ('id', 'status', 'value')}
                        for row in self.actions], 'inputs': self.inputs})

    def source_condition(self, output):
        self.framework_events.append('valid_input')
        # GeMTest actually passes the completed source output to this callback.
        rows = {row['id']: row for row in output['actions']}
        wanted = {'kind': 'payload', 'value': output['inputs']['payload1']}
        def recovered(name):
            row = rows.get(name, {})
            return row.get('status') == 'OK' and row['value']['observation'] == wanted
        if self.case['relation'] == 'MR08':
            admitted = recovered('recover')
            if not admitted:
                for name, op in [('source-host', 'host'), ('move', 'relocate'),
                                 ('moved-value', 'extract'), ('moved-host', 'host')]:
                    self.skip(name, op)
            return admitted
        if self.case['relation'] == 'MR09':
            admitted = recovered('recover') and recovered('source-view')
            if not admitted:
                for name, op in [('intervention', 'remove'), ('followup-view', 'inspect'),
                                 ('followup-value', 'extract')]:
                    self.skip(name, op)
            return admitted
        # The state plans execute their requests before interpreting the initial
        # and endpoint premises. No source filter is introduced for those plans.
        return True

    def transform(self):
        self.framework_events.append('general_transformation')
        relation = self.case['relation']
        if relation == 'MR08':
            self.host('source-host', 'source')
            self.invoke('move', 'relocate', session=self.session(),
                        binary=self.value('source', 'binary'))
            phases = ['followup']
        elif relation == 'MR09':
            self.invoke('intervention', 'remove', session=self.session(),
                        binary=self.value('source', 'binary'))
            phases = ['followup']
        elif relation == 'MR13':
            phases = ['intervening', 'after']
        else:
            phases = ['request-0', 'request-1']
        return tuple({'case_id': self.case['id'], 'phase': phase} for phase in phases)

    def followup(self, phase):
        self.framework_events.append('followup SUT: ' + phase)
        relation = self.case['relation']
        if relation == 'MR08':
            self.extract('moved-value', 'move')
            self.host('moved-host', 'move')
        elif relation == 'MR09':
            self.inspect('followup-view', 'intervention')
            self.extract('followup-value', 'intervention')
        elif relation == 'MR13':
            self.extract(phase, 'second' if phase == 'intervening' else 'first')
        else:
            self.extract(phase, 'first', 'key2' if phase == 'request-0' else 'key1')
        return self.output()

    def judgments(self):
        relation = self.case['relation']
        if relation == 'MR08':
            source = classify([self.available('recover')], self.payload('recover'))
            required = [self.available(x) for x in
                        ['move', 'moved-value', 'source-host', 'moved-host']]
            required += [source == SATISFIED, self.value('move', 'entries') == ['program']]
            if self.available('move') and self.available('moved-value'):
                required += [self.value('move', 'source', 'sha256') ==
                             self.value('move', 'artifact', 'sha256'),
                             self.value('move', 'artifact') == self.value('moved-value', 'before'),
                             self.unchanged('moved-value')]
            primary = classify(required, self.payload('moved-value') and
                               self.value('source-host', 'outputs') ==
                               self.value('moved-host', 'outputs'))
            return {'SOURCE': source, 'MR08': primary}
        if relation == 'MR09':
            source = classify([self.available('recover'), self.available('source-view')],
                              self.payload('recover') and self.payload('source-view'))
            observation = self.value('followup-view', 'observation') or {}
            removed = observation.get('kind') == 'rejection' and (
                observation.get('value') == 'absent' or
                (self.inputs['carrier'] == 'string' and observation.get('value') in
                 {'wrong-key', 'checksum', 'malformed', 'version'}))
            transform = classify([self.available('intervention'), self.available('followup-view'),
                                  source == SATISFIED], removed)
            required = [self.available('followup-value'), source == SATISFIED,
                        transform == SATISFIED]
            if self.available('followup-view') and self.available('followup-value'):
                required += [self.value('followup-view', 'artifact') ==
                             self.value('followup-value', 'before'),
                             self.unchanged('followup-value')]
            primary = classify(required, self.value('followup-value', 'observation') == observation)
            return {'SOURCE': source, 'TRANSFORM': transform, 'MR09': primary}
        if relation == 'MR13':
            names = ['before', 'intervening', 'after']
            required = [self.available(x) for x in names]
            required += [self.unchanged('before'), self.unchanged('after'),
                         self.value('before', 'after') == self.value('after', 'before'),
                         self.value('before', 'session_id') == self.value('after', 'session_id'),
                         self.value('before', 'key') == self.value('after', 'key')]
            primary = classify(required, self.payload('before') and
                               self.payload('intervening', 'payload2') and self.payload('after'))
            return {'MR13': primary}
        required = [self.available(x) for x in
                    ['physical-A', 'physical-B', 'initial', 'request-0', 'request-1']]
        required += [self.inputs['reuse_permitted'], self.inputs['lockout_excluded'],
                     self.inputs['key1'] != self.inputs['key2'], self.payload('physical-A'),
                     self.payload('physical-B', 'payload2'), self.payload('initial'),
                     self.unchanged('initial')]
        for name in ['request-0', 'request-1']:
            required += [self.value(name, 'before') == self.value('first', 'artifact'),
                         self.unchanged(name), self.value(name, 'session_id') ==
                         self.value('initial', 'session_id')]
        predicate = (self.value('request-0', 'observation') ==
                     {'kind': 'rejection', 'value': 'wrong-key'} and self.payload('request-1'))
        return {'STATE': classify(required, predicate)}

    def record(self, framework):
        self.finished = time.perf_counter()
        return {'case': self.case, 'context_id': self.context, 'inputs': self.inputs,
                'actions': self.actions, 'judgments': self.judgments(),
                'framework_events': self.framework_events, 'framework': framework,
                'seconds': self.finished - self.started}
