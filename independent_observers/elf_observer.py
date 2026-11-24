"""Current independent observation of retained ELF64 carrier bytes.

This is derived from the preserved current acquisition observer, with
an explicit file-backed-section check. The preserved producer and its study
snapshots are unchanged. The implementation shares the documented wire format,
not the tested decoder's parser; it is not a general ELF security validator.

The section carrier is the raw dump-section byte view. A NULL or NOBITS section
has no such file contents, so observing it is unavailable rather than a payload
or a typed absence. Section flags alone are not decoded into another byte view.
"""
from __future__ import annotations

import hashlib
import struct


def bounded(data, offset, length):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ValueError('ELF byte range is unavailable')
    return data[offset:offset + length]


def section_bytes(data, entry):
    """Return bytes represented by a section, never unowned bytes at its offset."""
    if entry[1] in (0, 8):  # SHT_NULL and SHT_NOBITS have no file-backed contents.
        raise ValueError('ELF section has no file-backed contents')
    return bounded(data, entry[4], entry[5])


def name_at(strings, offset):
    if not 0 <= offset < len(strings):
        raise ValueError('ELF string offset is invalid')
    end = strings.find(b'\0', offset)
    if end < 0:
        raise ValueError('unterminated ELF string')
    return strings[offset:end].decode('utf-8', 'surrogateescape')


def sections(data):
    h = struct.unpack('<16sHHIQQQIHHHHHH', bounded(data, 0, 64))
    if h[0][:7] != b'\x7fELF\x02\x01\x01' or h[2] != 62 or h[8] != 64 or h[11] != 64:
        raise ValueError('unsupported executable ELF64 layout')
    if h[1] not in (2, 3) or not 0 < h[13] < h[12] < 65535:
        raise ValueError('unsupported ELF section numbering')
    table = [struct.unpack('<IIQQQQIIQQ', bounded(data, h[6] + i * 64, 64)) for i in range(h[12])]
    names = section_bytes(data, table[h[13]])
    return [(name_at(names, entry[0]), entry) for entry in table]


def domain(kind, value):
    return {'kind': kind, 'value': value}


def byte_record(data, key):
    """First valid raw record; exhausted invalid candidates retain typed priority."""
    errors, offset = set(), 0
    key = key.encode('utf-8')
    while True:
        pos = data.find(b'WMR2', offset)
        if pos < 0:
            break
        offset = pos + 1
        if pos + 15 > len(data):
            errors.add('malformed')
            continue
        if data[pos + 4] != 1:
            errors.add('version')
            continue
        size = int.from_bytes(data[pos + 13:pos + 15], 'big')
        end = pos + 15 + size + 8
        if end > len(data):
            errors.add('malformed')
            continue
        if data[pos + 5:pos + 13] != hashlib.sha256(key).digest()[:8]:
            errors.add('wrong-key')
            continue
        stream = b''.join(hashlib.sha256(key + i.to_bytes(4, 'big')).digest()
                          for i in range((size + 31) // 32))
        payload = bytes(a ^ b for a, b in zip(data[pos + 15:pos + 15 + size], stream))
        if hashlib.sha256(payload).digest()[:8] != data[end - 8:end]:
            errors.add('checksum')
            continue
        return domain('payload', payload.hex())
    for error in ('checksum', 'wrong-key', 'version', 'malformed'):
        if error in errors:
            return domain('rejection', error)
    return domain('rejection', 'absent')


def symbol_record(data, table, key):
    rows = []
    for _, entry in table:
        if entry[1] != 2:
            continue
        if entry[9] != 24 or entry[5] % 24 or not 0 <= entry[6] < len(table):
            raise ValueError('unsupported ELF symbol table')
        names = section_bytes(data, table[entry[6]][1])
        for off in range(entry[4], entry[4] + entry[5], 24):
            sym = struct.unpack('<IBBHQQ', bounded(data, off, 24))
            if sym[1] >> 4 not in (1, 2, 10):
                continue
            fields = name_at(names, sym[0]).split('_')
            if len(fields) != 7 or fields[0] != 'wmrec':
                continue
            widths = (16, 4, 4, 4, None, 16)
            if any((width is not None and len(value) != width)
                   or any(c not in '0123456789abcdef' for c in value)
                   for value, width in zip(fields[1:], widths)):
                continue
            if not 2 <= len(fields[5]) <= 8:
                continue
            if len(fields[5]) % 2:
                return domain('rejection', 'malformed')
            rows.append((fields[1], int(fields[2], 16), int(fields[3], 16),
                         int(fields[4], 16), bytes.fromhex(fields[5]), fields[6]))
    if not rows:
        return domain('rejection', 'absent')
    tags, lengths, totals, checks = ({row[index] for row in rows} for index in (0, 1, 3, 5))
    if any(len(values) != 1 for values in (tags, lengths, totals, checks)):
        return domain('rejection', 'malformed')
    length, total = next(iter(lengths)), next(iter(totals))
    if len(rows) != total or {row[2] for row in rows} != set(range(total)) or total != max(1, (length + 3) // 4):
        return domain('rejection', 'malformed')
    ordered = sorted(rows, key=lambda row: row[2])
    if length == 0:
        if ordered[0][4] != b'\x00':
            return domain('rejection', 'malformed')
        payload = b''
    else:
        if any(len(row[4]) != min(4, length - 4 * i) for i, row in enumerate(ordered)):
            return domain('rejection', 'malformed')
        payload = b''.join(row[4] for row in ordered)
    if next(iter(tags)) != hashlib.sha256(key.encode('utf-8')).digest()[:8].hex():
        return domain('rejection', 'wrong-key')
    if next(iter(checks)) != hashlib.sha256(payload).digest()[:8].hex():
        return domain('rejection', 'checksum')
    return domain('payload', payload.hex())


def observe(data, carrier, key):
    if carrier == 'string':
        return byte_record(data, key)
    table = sections(data)
    if carrier == 'symbol':
        return symbol_record(data, table, key)
    if carrier != 'section':
        raise ValueError('unknown declared carrier')
    hits = [entry for name, entry in table if name == '.wmrec']
    if not hits:
        return domain('rejection', 'absent')
    if len(hits) != 1:
        raise ValueError('ambiguous designated section')
    return byte_record(section_bytes(data, hits[0]), key)
