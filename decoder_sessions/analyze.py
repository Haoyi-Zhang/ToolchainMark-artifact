#!/usr/bin/env python3
"""Derive local and paired descriptive outcomes from retained session receipts."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path


def read(path): return json.loads(path.read_text())
def stable(row):
    return all(value == 'SATISFIED' for key, value in row['judgments'].items()
               if key == 'revisit' or key.endswith('-a-source'))


def candidate_projection(action):
    if action['status'] != 'OK': return None
    native = action['value']['native']
    return list(zip(native['candidate_java_types'], native['candidates']))


def typed_key(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'))


def analyze(run):
    frame = read(run / 'frame.json')
    if not (run / 'completion.json').is_file(): raise ValueError('Acquisition has not completed')
    manifest = read(run / 'input-manifest.json')
    rows = []
    counts = Counter(); source_counts = Counter(); revisit_counts = Counter()
    algorithm_counts = defaultdict(lambda: {'source': Counter(), 'revisit': Counter(), 'words': 0})
    raw = Counter(); exceptions = Counter()
    for word in frame['words']:
        folder = run / 'words' / word['id']; receipt = read(folder / 'receipt.json')
        if typed_key(receipt['inputs']) != typed_key(word['inputs']): raise ValueError('Receipt input identity differs')
        actions = {action['id']: action for action in receipt['actions']}
        judgments = {item['id']: item['verdict'] for item in receipt['obligations']}
        row = {**word, 'judgments': judgments, 'actions': actions}
        rows.append(row); counts.update(judgments.values())
        local = algorithm_counts[word['inputs']['algorithm']]; local['words'] += 1
        for key, verdict in judgments.items():
            category = 'revisit' if key == 'revisit' else 'source'
            local[category][verdict] += 1
            (revisit_counts if category == 'revisit' else source_counts)[verdict] += 1
        if actions['prepare']['value']['all_inputs_available']:
            raw['input_available_words'] += 1
        else: raw['input_blocked_words'] += 1
        for action in receipt['actions']:
            if action['operation'] != 'sessions.recognize': continue
            raw['planned_request_slots'] += 1
            if action['status'] != 'SKIPPED': raw['adapter_request_attempts'] += 1
            if action['status'] == 'OK': raw['completed_typed_returns'] += 1
            if action['status'] == 'UNAVAILABLE': raw['unavailable_requests'] += 1
            if action['status'] == 'SKIPPED': raw['unexecuted_request_slots'] += 1
            native = (action['value'] or {}).get('native')
            if native and native.get('kind') != 'extract-return':
                exceptions[(native.get('kind'), native.get('exception_class'))] += 1
        for path in folder.glob('processes/*/command.json'):
            command = read(path); raw['jvm_processes'] += 1
            raw['processes_with_timeout'] += bool(command['timeouts'])
            raw['processes_with_nonzero_exit'] += command['returncode'] != 0
            done = path.parent / 'journal/done.json'
            if done.is_file():
                d = read(done)
                raw['helper_requests_received'] += d['requests_received']
                raw['algorithm_constructions_in_completed_processes'] += d['algorithm_constructions']
                raw['application_constructions_in_completed_processes'] += d['application_constructions']
        raw['request_start_journals'] += len(list(folder.glob('processes/*/journal/*.start.json')))
        raw['request_end_journals'] += len(list(folder.glob('processes/*/journal/*.end.json')))

    triples = defaultdict(dict)
    histories = defaultdict(dict)
    for row in rows:
        x = row['inputs']
        triples[(x['cell'], x['history'], x['acquisition_pass'])][x['lifetime']] = row
        histories[(x['cell'], x['lifetime'], x['acquisition_pass'])][x['history']] = row
    triple_rows = []
    triple_counts = Counter()
    for (cell, history, pass_number), arms in sorted(triples.items()):
        if set(arms) != {'P', 'O', 'R'}:
            triple_counts['incomplete_planned_triples'] += 1; continue
        triple_counts['planned_triples'] += 1
        cold = stable(arms['P'])
        triple_counts['stable_fresh_process_control'] += cold
        decisions = {m: arms[m]['judgments']['revisit'] for m in ('P', 'O', 'R')}
        obj_loss = cold and stable(arms['O']) and decisions['R'] == 'INCONSISTENT'
        jvm_loss = cold and (decisions['O'] == 'INCONSISTENT' or decisions['R'] == 'INCONSISTENT')
        triple_counts['object_lifetime_associated_loss'] += obj_loss
        triple_counts['same_jvm_lifetime_associated_loss'] += jvm_loss
        slots = ['first-a', 'last-a'] if history == 'AA' else ['first-a', 'middle-a' if history == 'AAA' else 'middle-b', 'last-a']
        projections = {m: [candidate_projection(arms[m]['actions'][s]) for s in slots] for m in arms}
        completed = all(all(v is not None for v in projections[m]) for m in arms)
        sequence_equal = None
        if completed:
            triple_counts['complete_return_triples'] += 1
            sequence_equal = len({typed_key(projections[m]) for m in arms}) == 1
            triple_counts['complete_return_triples_with_sequence_difference'] += not sequence_equal
        triple_rows.append({'cell': cell, 'history': history, 'acquisition_pass': pass_number,
                            'words': {m: arms[m]['id'] for m in arms}, 'revisit_verdicts': decisions,
                            'stable_fresh_process_control': cold, 'object_lifetime_associated_loss': obj_loss,
                            'same_jvm_lifetime_associated_loss': jvm_loss,
                            'all_request_returns_complete': completed, 'typed_candidate_sequences_equal': sequence_equal})
    history_rows = []
    history_counts = Counter()
    for (cell, lifetime, pass_number), pair in sorted(histories.items()):
        if set(pair) != {'AA', 'AAA', 'ABA'}:
            history_counts['incomplete_planned_triplets'] += 1; continue
        history_counts['planned_triplets'] += 1
        cold_aa = triples[(cell, 'AA', pass_number)].get('P')
        cold_aaa = triples[(cell, 'AAA', pass_number)].get('P')
        cold_aba = triples[(cell, 'ABA', pass_number)].get('P')
        cold_repeat = bool(cold_aa and cold_aaa and stable(cold_aa) and stable(cold_aaa))
        cold = bool(cold_repeat and cold_aba and stable(cold_aba))
        history_counts['stable_fresh_process_controls'] += cold
        history_counts['stable_fresh_process_repetition_controls'] += cold_repeat
        loss = cold and stable(pair['AA']) and stable(pair['AAA']) and pair['ABA']['judgments']['revisit'] == 'INCONSISTENT'
        repetition_loss = cold_repeat and stable(pair['AA']) and pair['AAA']['judgments']['revisit'] == 'INCONSISTENT'
        history_counts['intervening_request_associated_loss'] += loss
        history_counts['third_request_repetition_associated_loss'] += repetition_loss
        a = candidate_projection(pair['AA']['actions']['last-a'])
        aaa = candidate_projection(pair['AAA']['actions']['last-a'])
        b = candidate_projection(pair['ABA']['actions']['last-a'])
        diagnostic = {}
        for label, left, right in [('AA-vs-AAA', a, aaa), ('AAA-vs-ABA', aaa, b), ('AA-vs-ABA', a, b)]:
            seq = multiset = candidate_set = None
            if left is not None and right is not None:
                history_counts[label + ':complete_final_return_pairs'] += 1
                seq = typed_key(left) == typed_key(right)
                ka, kb = [typed_key(v) for v in left], [typed_key(v) for v in right]
                multiset = sorted(ka) == sorted(kb); candidate_set = set(ka) == set(kb)
                history_counts[label + ':final_typed_sequence_differences'] += not seq
                history_counts[label + ':final_typed_multiset_differences'] += not multiset
                history_counts[label + ':final_typed_set_differences'] += not candidate_set
            diagnostic[label] = {'typed_final_sequence_equal': seq, 'typed_final_multiset_equal': multiset,
                                  'typed_final_set_equal': candidate_set}
        history_rows.append({'cell': cell, 'lifetime': lifetime, 'acquisition_pass': pass_number,
                             'words': {h: pair[h]['id'] for h in pair},
                             'revisit_verdicts': {h: pair[h]['judgments']['revisit'] for h in pair},
                             'stable_fresh_process_controls': cold, 'intervening_request_associated_loss': loss,
                             'stable_fresh_process_repetition_controls': cold_repeat,
                             'third_request_repetition_associated_loss': repetition_loss,
                             'descriptive_final_return_comparisons': diagnostic})
    result = {
        'schema': 'sandmark-session-paired-analysis-v2', 'kind': frame['kind'],
        'planned_words': len(rows), 'local_obligations': sum(counts.values()), 'judgments': dict(counts),
        'source_judgments': dict(source_counts), 'revisit_judgments': dict(revisit_counts),
        'raw_acquisition': dict(raw),
        'native_exception_categories': [{'kind': k[0], 'exception_class': k[1], 'count': v} for k, v in sorted(exceptions.items())],
        'by_algorithm': {name: {k: dict(v) if isinstance(v, Counter) else v for k, v in value.items()} for name, value in algorithm_counts.items()},
        'lifetime_triple_counts': dict(triple_counts), 'history_triplet_counts': dict(history_counts),
        'lifetime_triples': triple_rows, 'history_triplets': history_rows,
        'input_population': {'archived_configurations': len(manifest['cases']),
                             'usable_marked_inputs': sum(c['archived_marked_input_available'] for c in manifest['cases'].values())},
        'interpretation': 'Observational counts for the fixed archived inputs and bounded histories. Associations are not field-level causes; candidate order/multiplicity differences are descriptive. Shared inputs and nested comparisons are not independent defect samples.',
    }
    (run / 'paired-analysis.json').write_text(json.dumps(result, indent=2, ensure_ascii=True) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.run.resolve())
    print(json.dumps({k: result[k] for k in ('planned_words', 'judgments', 'raw_acquisition', 'lifetime_triple_counts', 'history_triplet_counts')}, indent=2))
