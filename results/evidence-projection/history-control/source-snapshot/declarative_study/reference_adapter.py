"""Raw native ELF operations. Relation semantics live in JSON plans, not here."""
from __future__ import annotations
import dataclasses
from pathlib import Path
import shutil
import sys

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT / 'src'))
from tosem02 import pipeline as pipeline_module, record as record_module
from tosem02 import integrity as integrity_module, evidence_boundary as boundary_module
from tosem02.model import BuildRequest, ExtractionError
from tosem02.pipeline import Pipeline, run_host
from tosem02.integrity import carrier_snapshot, checksum_snapshot, IntegrityMaterial
from .native_io import acquisition, capture_file, install_proxy

for _module in (pipeline_module, record_module, integrity_module, boundary_module):
    install_proxy(_module)

DOMAIN = {'absent', 'wrong-key', 'checksum', 'malformed', 'version', 'path', 'sidecar'}


def material_to_json(material):
    def convert(value):
        if isinstance(value, bytes):
            return {'bytes_hex': value.hex()}
        if isinstance(value, (list, tuple)):
            return [convert(x) for x in value]
        return value
    return {'protected': convert(material.protected),
            'checksums': [x.hex() for x in material.checksums], 'payload_hex': material.payload.hex()}


def material_from_json(value):
    def convert(x):
        if isinstance(x, dict) and set(x) == {'bytes_hex'}:
            return bytes.fromhex(x['bytes_hex'])
        if isinstance(x, list):
            return tuple(convert(y) for y in x)
        return x
    return IntegrityMaterial(convert(value['protected']),
                             tuple(bytes.fromhex(x) for x in value['checksums']),
                             bytes.fromhex(value['payload_hex']))


class ReferenceAdapter:
    operations = {'session', 'build', 'extract', 'host', 'capture', 'inspect',
                  'checksum_view', 'relocate', 'remove', 'corrupt',
                  'begin_overlap', 'end_overlap'}

    def __init__(self, directory, store, *, pipeline_factory=Pipeline):
        self.directory, self.store = Path(directory).resolve(), Path(store).resolve()
        self.directory.mkdir(parents=True, exist_ok=False)
        self.factory, self.pipeline, self.session_id = pipeline_factory, None, None
        self.builds = {}

    def invoke(self, operation, arguments, *, step_id, context_id):
        with acquisition(self.store, step_id, context_id) as evidence:
            try:
                value = self._invoke(operation, arguments, step_id, context_id, evidence)
                return {'status': 'OK', 'value': value, 'evidence': evidence, 'reason': None}
            except Exception as exc:
                return {'status': 'UNAVAILABLE', 'value': None, 'evidence': evidence,
                        'reason': type(exc).__name__ + ': ' + str(exc)}

    def _invoke(self, operation, a, step_id, context_id, evidence):
        def observed(path):
            value = capture_file(path, self.store)
            evidence.append({'kind': 'file-capture', 'step_id': step_id,
                             'context_id': context_id, 'files': [value]})
            return value
        if operation == 'session':
            if self.pipeline is not None:
                raise ValueError('session already created')
            self.pipeline = self.factory(a['carrier'], a['implementation'])
            self.session_id = context_id + ':decoder'
            return {'session_id': self.session_id, 'carrier': a['carrier'],
                    'implementation': a['implementation']}
        if self.pipeline is None or a.get('session') != self.session_id:
            raise ValueError('operation must reference the declared live session')
        if operation == 'build':
            label = a['label']
            if not isinstance(label, str) or '/' in label or label in ('.', '..'):
                raise ValueError('build label must be a single directory name')
            host = Path(a['host'])
            observed(host)
            result = self.pipeline.build(BuildRequest(host, bytes.fromhex(a['payload_hex']), a['key'],
                a['compiler'], a['optimization'], self.directory / label, a['marked'], a['guarded']))
            self.builds[str(result.binary.resolve())] = result
            return {'binary': str(result.binary.resolve()), 'source': observed(result.source),
                    'artifact': observed(result.binary), 'compiler': result.actual_compiler,
                    'optimization': result.actual_optimization, 'command': [str(x) for x in result.command],
                    'returncode': result.return_code, 'session_id': self.session_id}
        if operation in {'begin_overlap', 'end_overlap'}:
            if operation == 'begin_overlap':
                self.pipeline.begin_overlapping_builds(a['parties'])
            else:
                self.pipeline.end_overlapping_builds()
            return {'session_id': self.session_id, 'operation': operation}
        binary = Path(a['binary']).resolve()
        if operation == 'capture':
            return observed(binary)
        if operation == 'extract':
            before = observed(binary)
            try:
                observation = {'kind': 'payload', 'value': self.pipeline.extract(binary, a['key']).hex()}
            except ExtractionError as exc:
                if exc.kind not in DOMAIN:
                    raise RuntimeError('extractor-tool-unavailable:' + exc.kind) from exc
                observation = {'kind': 'rejection', 'value': exc.kind}
            after = observed(binary)
            evidence.append({'kind': 'python-return', 'step_id': step_id, 'context_id': context_id,
                             'call': 'Pipeline.extract', 'binary': str(binary), 'key': a['key'],
                             'session_id': self.session_id, 'before': before, 'after': after,
                             'return_value': observation})
            return {'observation': observation, 'before': before, 'after': after,
                    'session_id': self.session_id, 'key': a['key']}
        if operation == 'host':
            before = observed(binary)
            output = [run_host(binary, item) for item in a['inputs']]
            return {'outputs': output, 'before': before, 'after': observed(binary),
                    'inputs': a['inputs']}
        if operation == 'inspect':
            snapshot = carrier_snapshot(self.pipeline.carrier, binary, a['key'])
            identity = observed(binary)
            if snapshot.artifact_bytes != binary.read_bytes():
                raise RuntimeError('live artifact differs from observer capture')
            return {'observation': snapshot.strict, 'artifact': identity, 'key': a['key'],
                    'observer': 'shared-format-clean-parser'}
        if operation == 'checksum_view':
            source = material_from_json(a['source_material']) if 'source_material' in a else None
            snapshot = checksum_snapshot(self.pipeline.carrier, binary, a['key'], source=source)
            identity = observed(binary)
            if snapshot.artifact_bytes != binary.read_bytes():
                raise RuntimeError('live artifact differs from checksum capture')
            return {'observation': snapshot.strict, 'artifact': identity,
                    'material': material_to_json(snapshot.material), 'key': a['key']}
        if operation == 'relocate':
            target_dir = self.directory / step_id
            target_dir.mkdir()
            target = target_dir / 'program'
            before = observed(binary)
            shutil.copy2(binary, target)
            return {'binary': str(target), 'source': before, 'artifact': observed(target),
                    'entries': sorted(p.name for p in target_dir.iterdir())}
        if operation in {'remove', 'corrupt'}:
            result = self.builds[str(binary)]
            observed(binary)
            fn = self.pipeline.remove_carrier if operation == 'remove' else self.pipeline.corrupt_carrier
            target = fn(result, self.directory / step_id)
            return {'binary': str(target.resolve()), 'artifact': observed(target)}
        raise ValueError('unknown native operation: ' + operation)
