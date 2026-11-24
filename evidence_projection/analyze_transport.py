"""Additional size accounting for all files required as verification inputs.

The frozen measurement's bundle_bytes includes compact bundle JSON and native
members. This later accounting also includes the caller's case.json. It reports
both compact serialization and the indented format used by exported examples;
neither quantity is a ZIP-compressed size or the installed checker software.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from .native import native_context
from .project import encoded, project
from .run import ARTIFACT, bound, distribution, external_case, identity, write


def pretty(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode()


def summarize(rows):
    def group(part):
        answer = {'targets': len(part)}
        for mode in ('compact', 'indented'):
            numerator, denominator = mode + '_bytes', 'full_' + mode + '_bytes'
            answer[mode] = {'fractions': distribution([r[numerator] / r[denominator] for r in part]),
                'smaller': sum(r[numerator] < r[denominator] for r in part),
                'equal': sum(r[numerator] == r[denominator] for r in part),
                'larger': sum(r[numerator] > r[denominator] for r in part),
                'total_bytes': sum(r[numerator] for r in part),
                'full_total_bytes': sum(r[denominator] for r in part)}
        return answer
    return {**group(rows), 'by_study': {name: group([r for r in rows if r['study'] == name])
                                      for name in sorted({r['study'] for r in rows})}}


def analyze(data):
    data = data.resolve()
    frozen = json.loads((data / 'source-freeze.json').read_text())
    for row in frozen['files']:
        if identity(ARTIFACT / row['path']) != {key: row[key] for key in ('bytes', 'sha256')}:
            raise ValueError('measurement source changed before additional accounting: ' + row['path'])
    frame = json.loads((data / 'frame.json').read_text())
    measured = [json.loads(line) for line in (data / 'measurements.jsonl').read_text().splitlines()]
    by_case = {}
    for row in measured:
        by_case.setdefault((row['dataset'], row['case']), []).append(row)
    rows, contexts = [], {}
    for item in frame:
        plan, receipt = [json.loads(bound(item[name]).read_text()) for name in ('plan', 'receipt')]
        if item['dataset'] not in contexts:
            contexts[item['dataset']] = native_context(ARTIFACT / item['dataset'], item['study'])
        context = contexts[item['dataset']]
        inputs, context_id = external_case(item)
        for measured_row in by_case[item['dataset'], item['case']]:
            target = measured_row['target']
            bundle = project(plan, receipt, target, context, check_full=False)
            case = {'plan': plan, 'inputs': inputs, 'context_id': context_id,
                    'native_context': context, 'target': target}
            full = {'schema': 'toolchainmark-complete-evidence', 'target': target,
                    'source_plan': plan, 'receipt': receipt, 'native_context': context}
            native, full_native = [measured_row[name] for name in ('native_storage_bytes', 'full_native_storage_bytes')]
            if len(encoded(bundle)) + native != measured_row['bundle_bytes'] or \
                    len(encoded(full)) + full_native != measured_row['full_bundle_bytes']:
                raise ValueError('additional accounting differs from frozen size measurements')
            external_bytes = len(encoded(case))
            rows.append({'dataset': item['dataset'], 'case': item['case'], 'study': item['study'], 'target': target,
                'external_case_compact_bytes': external_bytes, 'external_case_indented_bytes': len(pretty(case)),
                'compact_bytes': len(encoded(bundle)) + external_bytes + native,
                'full_compact_bytes': len(encoded(full)) + external_bytes + full_native,
                'indented_bytes': len(pretty(bundle)) + len(pretty(case)) + native,
                'full_indented_bytes': len(pretty(full)) + len(pretty(case)) + full_native})
    keys = [(r['dataset'], r['case'], r['target']) for r in rows]
    if len(keys) != len(set(keys)) or len(keys) != len(measured):
        raise ValueError('transport accounting is not the complete unique measured target set')
    examples = []
    for path in sorted((data / 'examples').rglob('bundle.json')):
        case_path = path.with_name('case.json')
        bundle = json.loads(path.read_text()); case = json.loads(case_path.read_text())
        native = sum(p.stat().st_size for p in path.with_name('native').rglob('*') if p.is_file())
        actual = path.stat().st_size + case_path.stat().st_size + native
        calculated = len(pretty(bundle)) + len(pretty(case)) + native
        if actual != calculated:
            raise ValueError('indented serialization does not match actual exported files')
        examples.append({'path': path.parent.relative_to(data).as_posix(),
                         'actual_verification_input_bytes': actual, 'derived_bytes': calculated})
    result = {'analysis': 'additional complete verification-input accounting',
        'scope': 'bundle.json, externally selected case.json, and exact native members. The checker installation and optional verification report are supplied separately. Both arms include the same external case material. No ZIP compression is assumed.',
        'selection': 'Every target in the completed frozen projection measurement',
        **summarize(rows), 'exported_examples_checked': len(examples), 'examples': examples,
        'inputs': {'measurements': identity(data / 'measurements.jsonl'), 'frame': identity(data / 'frame.json')},
        'analysis_source': identity(Path(__file__))}
    with (data / 'transport-measurements.jsonl').open('w') as stream:
        for row in rows:
            stream.write(encoded(row).decode() + '\n')
    write(data / 'transport-summary.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, type=Path)
    args = parser.parse_args()
    result = analyze(args.data)
    print(json.dumps({key: result[key] for key in ('targets', 'compact', 'indented', 'exported_examples_checked')}, indent=2))
