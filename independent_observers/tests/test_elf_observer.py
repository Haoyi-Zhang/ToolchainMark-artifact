"""Representation controls use retained ELF bytes, not the parser's encoder."""
import gzip
import json
from pathlib import Path
import struct
import unittest

from independent_observers.elf_observer import observe, sections
from declarative_study.verify import reobserve_material

ARTIFACT = Path(__file__).resolve().parents[2]


class FileBackedSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store = ARTIFACT / 'results/declarative/reference'
        receipt = json.loads((store / 'cases/pass-1/section/CLEAN/MR01/receipt.json').read_text())
        row = next(action for action in receipt['actions'] if action['operation'] == 'build')['value']['artifact']
        cls.raw = gzip.decompress((store / row['blob']).read_bytes())
        cls.key, cls.payload = receipt['inputs']['key1'], receipt['inputs']['payload1']
        cls.header = struct.unpack('<16sHHIQQQIHHHHHH', cls.raw[:64])
        cls.index, cls.section = next((i, entry) for i, (name, entry) in enumerate(sections(cls.raw)) if name == '.wmrec')

    def changed(self, field_offset, fmt, value, section_index=None):
        raw = bytearray(self.raw)
        index = self.index if section_index is None else section_index
        struct.pack_into(fmt, raw, self.header[6] + index * 64 + field_offset, value)
        return bytes(raw)

    def test_actual_file_backed_section_is_accepted(self):
        self.assertEqual(observe(self.raw, 'section', self.key), {'kind': 'payload', 'value': self.payload})
        self.assertEqual(reobserve_material(self.raw, 'section', self.key)['payload_hex'], self.payload)

    def test_null_and_nobits_sections_are_unavailable_to_both_section_views(self):
        for section_type in (0, 8):
            with self.subTest(section_type=section_type):
                changed = self.changed(4, '<I', section_type)
                with self.assertRaisesRegex(ValueError, 'no file-backed contents'):
                    observe(changed, 'section', self.key)
                with self.assertRaisesRegex(ValueError, 'no file-backed contents'):
                    reobserve_material(changed, 'section', self.key)
                # The same record bytes still exist in the different whole-file carrier.
                self.assertEqual(observe(changed, 'string', self.key), {'kind': 'payload', 'value': self.payload})

    def test_non_file_backed_section_name_table_cannot_supply_names(self):
        for section_type in (0, 8):
            with self.subTest(section_type=section_type):
                changed = self.changed(4, '<I', section_type, section_index=self.header[13])
                with self.assertRaisesRegex(ValueError, 'no file-backed contents'):
                    observe(changed, 'section', self.key)

    def test_compressed_flag_alone_preserves_the_measured_raw_dump_view(self):
        # The retained focused GNU probe returned these raw bytes unchanged.
        changed = self.changed(8, '<Q', self.section[2] | 0x800)
        self.assertEqual(observe(changed, 'section', self.key), {'kind': 'payload', 'value': self.payload})

    def test_wrong_key_remains_a_typed_rejection_for_an_available_section(self):
        self.assertEqual(observe(self.raw, 'section', self.key + ':different'),
                         {'kind': 'rejection', 'value': 'wrong-key'})


if __name__ == '__main__':
    unittest.main()
