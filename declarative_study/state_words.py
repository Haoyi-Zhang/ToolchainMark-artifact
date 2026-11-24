"""Finite request words over a declared reusable-decoder interface.

Exhaustiveness is over the explicit finite alphabet and depth only. The targets
below are declared controlled behaviors, not newly discovered external defects.
"""
from __future__ import annotations
import itertools
from pathlib import Path
from .build_plans import Declaration, L, I, R, O, EQ, AND, payload, rejection, unchanged
from .reference_adapter import Pipeline, ExtractionError

ALPHABET = ('A+', 'A-', 'B+')


class ControlledStatePipeline(Pipeline):
    def __init__(self, carrier, implementation):
        self.threshold = int(implementation.split('-')[-1]) if implementation.startswith('latch-') else None
        self.rejections = 0
        self.replace_target = implementation == 'replace-on-B'
        self.build_targets = []
        self.replaced = False
        super().__init__(carrier, 'M23' if implementation == 'cross-object' else 'CLEAN')
    def build(self, request):
        result = super().build(request)
        self.build_targets.append(result.binary.resolve())
        return result
    def extract(self, binary, key):
        if self.threshold is not None and self.rejections >= self.threshold:
            raise ExtractionError('wrong-key', 'declared controlled rejection latch')
        try:
            value = super().extract(binary, key)
        except ExtractionError as exc:
            if exc.kind == 'wrong-key':
                self.rejections += 1
            raise
        if (self.replace_target and not self.replaced and len(self.build_targets) >= 2
                and Path(binary).resolve() == self.build_targets[1]):
            self.build_targets[0].write_bytes(self.build_targets[1].read_bytes())
            self.replaced = True
        return value


def words(depth):
    yield ()
    for length in range(1, depth + 1):
        yield from itertools.product(ALPHABET, repeat=length)


def make_plan(word):
    encoded = 'empty' if not word else '_'.join(word).replace('+', 'p').replace('-', 'm')
    d = Declaration('STATE-' + encoded)
    d.plan['inputs']['reuse_permitted'] = 'boolean'
    d.plan['inputs']['lockout_excluded'] = 'boolean'
    d.build('first'); d.build('second', payload='payload2')
    for name, source in [('physical-A', 'first'), ('physical-B', 'second')]:
        d.action(name, 'inspect', binary=R(source, 'binary'), key=I('key1'))
    d.extract('initial', 'first')
    deps = ['physical-A', 'physical-B', 'initial']
    gates = [('reuse-permitted', I('reuse_permitted')), ('lockout-excluded', I('lockout_excluded')),
             ('keys-distinct', O('ne', I('key1'), I('key2'))),
             ('physical-A-valid', payload('physical-A')), ('physical-B-valid', payload('physical-B', 'payload2')),
             ('initial-source-valid', payload('initial')), ('initial-endpoints', unchanged('initial'))]
    predicates = [L(True)]
    for index, symbol in enumerate(word):
        action = 'request-' + str(index)
        source = 'second' if symbol == 'B+' else 'first'
        d.extract(action, source, key='key2' if symbol == 'A-' else 'key1')
        deps.append(action)
        gates.extend([(action + ':version-before', EQ(R(action, 'before'), R(source, 'artifact'))),
                      (action + ':version-after', unchanged(action)),
                      (action + ':same-session', EQ(R(action, 'session_id'), R('initial', 'session_id')))])
        predicates.append(rejection(action, 'wrong-key') if symbol == 'A-' else
                          payload(action, 'payload2' if symbol == 'B+' else 'payload1'))
    d.obligation('STATE', 'decoder-context', 'reusable decoder on fixed artifact versions',
                 AND(*predicates), deps, gates)
    return d.plan
