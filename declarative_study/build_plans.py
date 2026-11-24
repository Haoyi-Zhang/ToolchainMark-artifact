#!/usr/bin/env python3
"""Generate data-only declarations; the runtime never imports this generator."""
from __future__ import annotations
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
L = lambda value: {'literal': value}
I = lambda name: {'input': name, 'path': []}
R = lambda name, *path: {'ref': name, 'path': list(path)}
A = lambda name: {'available': name}
V = lambda name: {'verdict': name}
O = lambda op, *args: {'op': op, 'args': list(args)}
EQ = lambda a, b: O('eq', a, b)
AND = lambda *args: O('and', *args)


def inputs():
    return {'host': 'string', 'carrier': 'string', 'implementation': 'string',
            'payload1': 'string', 'payload2': 'string', 'key1': 'string', 'key2': 'string',
            'compiler': 'string', 'optimization': 'string', 'host_inputs': 'array'}


class Declaration:
    def __init__(self, name):
        self.plan = {'schema': 'toolchainmark-contract-v1', 'id': name,
                     'inputs': inputs(), 'actions': [], 'obligations': []}
        self.action('session', 'session', carrier=I('carrier'), implementation=I('implementation'))
    def action(self, name, operation, when=None, **arguments):
        if operation != 'session':
            arguments['session'] = R('session', 'session_id')
        row = {'id': name, 'operation': operation, 'arguments': arguments}
        if when is not None:
            row['when'] = when
        self.plan['actions'].append(row)
        return row
    def build(self, name, payload='payload1', marked=True, guarded=False, compiler=None, optimization=None):
        return self.action(name, 'build', host=I('host'), label=L(name), payload_hex=I(payload),
                           key=I('key1'), marked=L(marked), guarded=L(guarded),
                           compiler=I('compiler') if compiler is None else L(compiler),
                           optimization=I('optimization') if optimization is None else L(optimization))
    def extract(self, name, source, key='key1', when=None):
        return self.action(name, 'extract', binary=R(source, 'binary'), key=I(key), when=when)
    def host(self, name, source, when=None):
        return self.action(name, 'host', binary=R(source, 'binary'), inputs=I('host_inputs'), when=when)
    def obligation(self, name, stage, clause, predicate, dependencies=(), gates=()):
        requires = [{'name': 'available:' + dep, 'expr': A(dep)} for dep in dependencies]
        requires += [{'name': key, 'expr': expr} for key, expr in gates]
        self.plan['obligations'].append({'id': name, 'stage': stage, 'clause': clause,
                                         'requires': requires, 'predicate': predicate})


def payload(obs, wanted='payload1'):
    return AND(EQ(R(obs, 'observation', 'kind'), L('payload')),
               EQ(R(obs, 'observation', 'value'), I(wanted)))


def rejection(obs, category):
    return EQ(R(obs, 'observation'), L({'kind': 'rejection', 'value': category}))


def unchanged(obs):
    return EQ(R(obs, 'before'), R(obs, 'after'))


def plan_for(number):
    name = f'MR{number:02d}'
    d = Declaration(name)
    final = lambda predicate, deps, gates=(): d.obligation(name, 'tested-contract', name,
                                                          predicate, deps, gates)
    if number == 1:
        d.build('source'); d.extract('recover', 'source')
        final(payload('recover'), ['recover'])
    elif number == 2:
        d.build('unmarked', marked=False); d.build('marked')
        d.host('base-host', 'unmarked'); d.host('marked-host', 'marked')
        final(EQ(R('base-host', 'outputs'), R('marked-host', 'outputs')), ['base-host', 'marked-host'])
    elif number == 3:
        d.build('unmarked', marked=False)
        d.action('physical', 'inspect', binary=R('unmarked', 'binary'), key=I('key1'))
        d.extract('reject', 'unmarked')
        final(rejection('reject', 'absent'), ['physical', 'reject'], [('carrier-absent', rejection('physical', 'absent'))])
    elif number == 4:
        d.build('source', guarded=True); d.extract('recover', 'source')
        d.extract('wrong', 'source', key='key2', when=payload('recover'))
        d.obligation('SOURCE', 'embedding', 'literal recovery', payload('recover'), ['recover'])
        final(rejection('wrong', 'wrong-key'), ['wrong'], [('source-valid', EQ(V('SOURCE'), L('SATISFIED'))),
              ('distinct-keys', O('ne', I('key1'), I('key2'))), ('same-endpoint-bytes', unchanged('wrong'))])
    elif number in (5, 12):
        if number == 12:
            d.action('overlap-begin', 'begin_overlap', parties=L(2))
        first, second = d.build('first'), d.build('second', payload='payload2')
        if number == 12:
            d.plan['actions'][-2:] = [{'parallel': [first, second]}]
            d.action('overlap-end', 'end_overlap')
        d.extract('first-value', 'first'); d.extract('second-value', 'second')
        final(AND(payload('first-value'), payload('second-value', 'payload2'),
                  O('ne', R('first-value', 'observation'), R('second-value', 'observation'))),
              ['first-value', 'second-value'])
    elif number in (6, 7):
        settings = [('gcc', 'O2'), ('clang', 'O2')] if number == 6 else [('gcc', x) for x in ('O0', 'O2', 'Os')]
        gates, deps, predicates = [], [], []
        for n, (compiler, opt) in enumerate(settings):
            b, e, h = f'build-{n}', f'extract-{n}', f'host-{n}'
            d.build(b, compiler=compiler, optimization=opt)
            gates.extend([(b + ':compiler', EQ(R(b, 'compiler'), L(compiler))),
                          (b + ':optimization', EQ(R(b, 'optimization'), L(opt)))])
        for n in range(len(settings)):
            b, e, h = f'build-{n}', f'extract-{n}', f'host-{n}'
            d.extract(e, b); d.host(h, b)
            deps.extend([b, e, h]); predicates.append(payload(e))
            if n:
                predicates.append(EQ(R(h, 'outputs'), R('host-0', 'outputs')))
        final(AND(*predicates), deps, gates)
    elif number == 8:
        d.build('source'); d.extract('recover', 'source')
        d.host('source-host', 'source', when=payload('recover'))
        d.action('move', 'relocate', binary=R('source', 'binary'), when=payload('recover'))
        d.extract('moved-value', 'move'); d.host('moved-host', 'move')
        d.obligation('SOURCE', 'embedding', 'literal recovery', payload('recover'), ['recover'])
        gates = [('source-valid', EQ(V('SOURCE'), L('SATISFIED'))),
                 ('artifact-only-directory', EQ(R('move', 'entries'), L(['program']))),
                 ('copy-bytes-match', EQ(R('move', 'source', 'sha256'), R('move', 'artifact', 'sha256'))),
                 ('moved-version-current', EQ(R('move', 'artifact'), R('moved-value', 'before'))),
                 ('moved-version-after', unchanged('moved-value'))]
        final(AND(payload('moved-value'), EQ(R('source-host', 'outputs'), R('moved-host', 'outputs'))),
              ['move', 'moved-value', 'source-host', 'moved-host'], gates)
    elif number in (9, 10):
        d.build('source', guarded=True); d.extract('recover', 'source')
        kind = 'inspect' if number == 9 else 'checksum_view'
        d.action('source-view', kind, binary=R('source', 'binary'), key=I('key1'))
        valid = AND(payload('recover'), payload('source-view'))
        d.action('intervention', 'remove' if number == 9 else 'corrupt',
                 binary=R('source', 'binary'), when=valid)
        args = {'binary': R('intervention', 'binary'), 'key': I('key1')}
        if number == 10:
            args['source_material'] = R('source-view', 'material')
        d.action('followup-view', kind, **args)
        d.extract('followup-value', 'intervention')
        d.obligation('SOURCE', 'embedding', 'literal recovery and physical source', valid, ['recover', 'source-view'])
        if number == 9:
            removed = AND(EQ(R('followup-view', 'observation', 'kind'), L('rejection')),
                O('or', rejection('followup-view', 'absent'),
                  AND(EQ(I('carrier'), L('string')),
                      O('in', R('followup-view', 'observation', 'value'),
                        L(['wrong-key', 'checksum', 'malformed', 'version'])))))
            postcondition = removed
        else:
            postcondition = AND(rejection('followup-view', 'checksum'),
                EQ(R('source-view', 'material', 'payload_hex'), R('followup-view', 'material', 'payload_hex')),
                EQ(R('source-view', 'material', 'protected'), R('followup-view', 'material', 'protected')),
                O('ne', R('source-view', 'material', 'checksums'), R('followup-view', 'material', 'checksums')))
        d.obligation('TRANSFORM', 'transformation', 'declared intervention postcondition', postcondition,
                     ['intervention', 'followup-view'], [('source-valid', EQ(V('SOURCE'), L('SATISFIED')))])
        final(EQ(R('followup-value', 'observation'), R('followup-view', 'observation')),
              ['followup-value'], [('source-valid', EQ(V('SOURCE'), L('SATISFIED'))),
               ('intervention-established', EQ(V('TRANSFORM'), L('SATISFIED'))),
               ('version-current', EQ(R('followup-view', 'artifact'), R('followup-value', 'before'))),
               ('version-after', unchanged('followup-value'))])
    elif number == 11:
        d.build('source', compiler='clang', optimization='Os')
        final(AND(EQ(R('source', 'compiler'), L('clang')), EQ(R('source', 'optimization'), L('Os'))), ['source'])
    elif number == 13:
        d.build('first'); d.build('second', payload='payload2')
        d.extract('before', 'first'); d.extract('intervening', 'second'); d.extract('after', 'first')
        final(AND(payload('before'), payload('intervening', 'payload2'), payload('after')),
              ['before', 'intervening', 'after'],
              [('first-call-endpoints', unchanged('before')), ('revisit-endpoints', unchanged('after')),
               ('same-version-on-revisit', EQ(R('before', 'after'), R('after', 'before'))),
               ('same-session', EQ(R('before', 'session_id'), R('after', 'session_id'))),
               ('same-key', EQ(R('before', 'key'), R('after', 'key')))])
    elif number == 14:
        d.build('first'); d.extract('before', 'first'); d.build('second'); d.extract('after', 'second')
        final(AND(payload('before'), payload('after')), ['before', 'after'])
    return d.plan


def main():
    for number in range(1, 15):
        path = HERE / 'plans' / (f'MR{number:02d}.json')
        path.write_text(json.dumps(plan_for(number), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
