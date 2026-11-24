#!/usr/bin/env python3
"""Emit the LLWM observation contract as data for the common interpreter."""
import json
from pathlib import Path
from .build_plans import L, I, R, A, V, O, EQ, AND


def make_plan(interface):
    plan = {'schema': 'toolchainmark-contract-v1', 'id': 'LLWM-' + interface,
            'inputs': {'interface': 'string', 'variant': 'string', 'payload': 'string',
                       'payload_hex': 'string', 'key': 'string', 'ordinary': 'string',
                       'optimization': 'string'}, 'actions': [], 'obligations': []}
    def action(name, operation, **arguments):
        plan['actions'].append({'id': name, 'operation': operation, 'arguments': arguments})
    def obligation(name, stage, clause, predicate, dependencies, gates=()):
        plan['obligations'].append({'id': name, 'stage': stage, 'clause': clause,
            'requires': [{'name': 'available:' + x, 'expr': A(x)} for x in dependencies] +
                        [{'name': name, 'expr': expr} for name, expr in gates], 'predicate': predicate})
    action('build', 'llvm_build', interface=I('interface'), variant=I('variant'),
           payload=I('payload'), key=I('key'), optimization=I('optimization'))
    for mode in ('key', 'ordinary'):
        for version in ('unmarked', 'marked'):
            action(version + '-' + mode, 'invoke', binary=R('build', version),
                   interface=I('interface'), input=I(mode))
    action('move', 'relocate', binary=R('build', 'marked'))
    action('moved-key', 'invoke', binary=R('move', 'binary'), interface=I('interface'), input=I('key'))
    action('debug-before', 'sections', binary=R('build', 'marked'))
    action('strip', 'strip_debug', binary=R('build', 'marked'))
    action('debug-after', 'sections', binary=R('strip', 'binary'))
    action('stripped-key', 'invoke', binary=R('strip', 'binary'), interface=I('interface'), input=I('key'))
    sequence = [I('payload_hex'), R('unmarked-key', 'stdout_hex')] if interface == 'fgets' else [R('unmarked-key', 'stdout_hex'), I('payload_hex')]
    obligation('ER01', 'extraction', 'literal payload output',
               EQ(R('marked-key', 'stdout_hex'), O('concat_hex', *sequence)),
               ['build', 'unmarked-key', 'marked-key'])
    obligation('ER02', 'host', 'ordinary host output',
               EQ(R('marked-ordinary', 'stdout_hex'), R('unmarked-ordinary', 'stdout_hex')),
               ['build', 'unmarked-ordinary', 'marked-ordinary'])
    obligation('ER03', 'extraction', 'byte-identical artifact-only relocation',
               EQ(R('moved-key', 'stdout_hex'), R('marked-key', 'stdout_hex')), ['move', 'moved-key'],
               [('source-valid', EQ(V('ER01'), L('SATISFIED'))),
                ('artifact-only', EQ(R('move', 'entries'), L(['program']))),
                ('same-bytes', EQ(R('move', 'source', 'sha256'), R('move', 'artifact', 'sha256'))),
                ('same-version-before', EQ(R('move', 'artifact'), R('moved-key', 'before'))),
                ('same-version-after', EQ(R('moved-key', 'before'), R('moved-key', 'after')))])
    obligation('ER04', 'extraction', 'debug-only removal',
               EQ(R('stripped-key', 'stdout_hex'), R('marked-key', 'stdout_hex')),
               ['strip', 'debug-before', 'debug-after', 'stripped-key'],
               [('source-valid', EQ(V('ER01'), L('SATISFIED'))),
                ('debug-present-before', O('contains', R('debug-before', 'text'), L('.debug_info'))),
                ('debug-absent-after', O('not', O('contains', R('debug-after', 'text'), L('.debug_')))),
                ('same-version-before', EQ(R('strip', 'artifact'), R('stripped-key', 'before'))),
                ('same-version-after', EQ(R('stripped-key', 'before'), R('stripped-key', 'after')))])
    return plan


if __name__ == '__main__':
    for interface in ('atoi', 'fgets', 'sidedata'):
        path = Path(__file__).resolve().parent / 'plans' / ('LLWM-' + interface + '.json')
        path.write_text(json.dumps(make_plan(interface), indent=2, sort_keys=True) + '\n')
