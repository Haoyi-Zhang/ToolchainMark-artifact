"""Behavioral controls for challenge recording and independent reception."""
from copy import deepcopy
import csv
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from .recording import Recorder
from .common import ROOT, load_plan, sha, verify_frozen
from .verify import ByteReceiver, DATA, count_events, descriptor_bytes, verify
from toolchainmark.study_validation import validate_rows


def distinction(scenario, variant, carrier='symbol'):
    with (DATA / 'distinctions.csv').open(newline='') as stream:
        row = next(row for row in csv.DictReader(stream) if
                   (row['scenario'], row['variant'], row['carrier']) == (scenario, variant, carrier))
    return descriptor_bytes(DATA, row)


class RecordingTests(unittest.TestCase):
    def test_typed_rejection_kind_does_not_conflict_with_event_name(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = Recorder(Path(directory))
            recorder.event('extract_rejection', call=0, kind='wrong-key')
            self.assertEqual(recorder.events[0]['event'], 'extract_rejection')
            self.assertEqual(recorder.events[0]['kind'], 'wrong-key')
            self.assertEqual(recorder.counts()['typed_extraction_rejections'], 1)


class ReceptionTests(unittest.TestCase):
    def test_complete_original_is_read_only_without_native_subprocesses(self):
        with patch('subprocess.run', side_effect=AssertionError('receiver launched a subprocess')):
            result = verify()
        self.assertEqual(result['verdict'], 'PASS')
        self.assertEqual(result['relation_rows'], 8100)
        self.assertEqual(result['unique_retained_blobs'], 528)

    def test_relabeling_latched_rejection_is_rejected(self):
        record = distinction('D03-error-recovery', 'N02')
        rejects = [event for event in record['events'] if event['event'] == 'extract_rejection']
        rejects[1].update(event='extract_return', payload_hex=b'Morph-01'.hex())
        rejects[1].pop('kind')
        record['counts'] = count_events(record['events'])
        with self.assertRaisesRegex(ValueError, 'frozen definition'):
            ByteReceiver(DATA).events(record, 'N02', 'symbol')

    def test_decoder_path_must_bind_its_own_snapshot(self):
        record = distinction('D01-cold-key', 'N01')
        call = next(event for event in record['events'] if event['event'] == 'decoder_invocation')
        call['path'] = 'CASE/unrelated-artifact'
        with self.assertRaisesRegex(ValueError, 'effective decoder path differs from its captured artifact'):
            ByteReceiver(DATA).events(record, 'N01', 'symbol')

    def test_declared_blob_must_be_used_by_a_captured_event(self):
        record = distinction('D01-cold-key', 'N01')
        other = distinction('D06-recovery-artifact', 'N04')
        known = {item['sha256'] for item in record['blobs']}
        extra = next(item for item in other['blobs'] if item['sha256'] not in known)
        record['blobs'].append(deepcopy(extra))
        with self.assertRaisesRegex(ValueError, 'no captured event uses'):
            ByteReceiver(DATA).events(record, 'N01', 'symbol')

    def test_repeated_blob_cannot_change_its_compressed_identity(self):
        record = distinction('D01-cold-key', 'N01')
        receiver = ByteReceiver(DATA)
        receiver.events(record, 'N01', 'symbol')
        record['blobs'][0]['compressed_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'shared blob declaration differs'):
            receiver.events(record, 'N01', 'symbol')

    def test_resigned_compressed_identity_does_not_bypass_gzip_crc(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw = b'{"example":true}\n'
            broken = bytearray(gzip.compress(raw, mtime=0))
            broken[-8] ^= 1
            path = Path(temporary) / 'record.json.gz'
            path.write_bytes(broken)
            descriptor = {'record_path': path.name, 'bytes': len(raw), 'sha256': sha(raw),
                          'compressed_bytes': len(broken), 'compressed_sha256': sha(broken)}
            with self.assertRaises((OSError, EOFError)):
                descriptor_bytes(Path(temporary), descriptor)

    def test_changed_current_source_cannot_pass_initial_freeze(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary)
            path = candidate / 'src/toolchainmark/__init__.py'
            path.parent.mkdir(parents=True)
            path.write_text('# changed current source\n')
            with self.assertRaisesRegex(ValueError, 'frozen source changed'):
                verify_frozen(root=candidate)

    def test_changed_verdict_is_rejected_for_a_new_trigger_identity(self):
        with (DATA / 'full-first.csv').open(newline='') as stream:
            row = next(row for row in csv.DictReader(stream) if row['defect_id'] == 'N02'
                       and row['relation_id'] == 'MR04')
        protocol = load_plan()[0]['classifier_protocol']
        validate_rows([row], protocol)
        row.update(verdict='INCONSISTENT', exposed='True')
        with self.assertRaisesRegex(ValueError, 'contradicts|predicate|reason'):
            validate_rows([row], protocol)


if __name__ == '__main__':
    unittest.main()
