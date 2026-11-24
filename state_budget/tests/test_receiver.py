"""Measured-call accounting controls over retained fresh records."""
from copy import deepcopy
import unittest

from state_budget.verify import ARTIFACT, case_cost, expected_frame, expected_schedule, prefix, read


DATA = ARTIFACT / 'results/state-budget/completed'


class MeasuredCallControls(unittest.TestCase):
    def setUp(self):
        self.protocol = read(DATA / 'protocol.json')
        self.frame = read(DATA / 'frame.json')
        self.case = next(case for case in self.frame if case['id'] == 'pass-1/string/latch-1/bfs/Am_Ap')
        directory = DATA / 'cases' / self.case['id']
        self.receipt = read(directory / 'receipt.json')
        self.acquisition = read(directory / 'acquisition.json')

    def test_real_inconsistent_case_retains_all_entered_calls(self):
        row = case_cost(self.case, self.receipt, self.acquisition)
        self.assertTrue(row['exposed'])
        self.assertEqual(row['extract_calls'], 3)
        self.assertEqual([x['observation']['kind'] for x in self.acquisition['extraction_call_trace']],
                         ['payload', 'rejection', 'rejection'])

    def test_missing_rejected_call_is_not_free(self):
        altered = deepcopy(self.acquisition)
        altered['extraction_call_trace'].pop()
        altered['extract_calls'] -= 1
        with self.assertRaisesRegex(ValueError, 'missing from measured cost'):
            case_cost(self.case, self.receipt, altered)

    def test_repeated_call_cannot_inflate_budget(self):
        altered = deepcopy(self.acquisition)
        entry = deepcopy(altered['extraction_call_trace'][-1])
        entry['ordinal'] += 1
        altered['extraction_call_trace'].append(entry)
        altered['extract_calls'] += 1
        with self.assertRaisesRegex(ValueError, 'repeated tested calls'):
            case_cost(self.case, self.receipt, altered)

    def test_boolean_is_not_an_event_ordinal(self):
        altered = deepcopy(self.acquisition)
        altered['extraction_call_trace'][0]['ordinal'] = True
        with self.assertRaisesRegex(ValueError, 'ordinals'):
            case_cost(self.case, self.receipt, altered)

    def test_rebound_wrong_key_call_is_rejected(self):
        altered = deepcopy(self.acquisition)
        altered['extraction_call_trace'][1]['key'] = self.case['inputs']['key1']
        with self.assertRaisesRegex(ValueError, 'request differs'):
            case_cost(self.case, self.receipt, altered)

    def test_schedule_leaves_unspent_cap_without_padding(self):
        ordered = expected_schedule(self.protocol)
        self.assertEqual(ordered, read(DATA / 'schedule.json'))
        self.assertEqual(expected_frame(self.protocol, ordered), self.frame)
        self.assertEqual(sum(x['planned_extract_calls'] for x in ordered['bfs']), 25)
        self.assertEqual(ordered['bfs'][-1]['word'], ['A-', 'B+'])
        self.assertEqual(ordered['catalog'][-1]['relation'], 'SR01')

    def test_zero_extract_case_remains_in_complete_prefix(self):
        selected = [case for case in self.frame if case['pass'] == 1 and case['carrier'] == 'string'
                    and case['implementation'] == 'CLEAN' and case['arm'] == 'catalog']
        rows = []
        for case in selected:
            directory = DATA / 'cases' / case['id']
            rows.append(case_cost(case, read(directory / 'receipt.json'), read(directory / 'acquisition.json')))
        result = prefix(rows, 1)
        self.assertEqual(result['extract_calls'], 1)
        self.assertEqual(result['complete_cases'], 2)
        self.assertTrue(result['exact_spending'])


if __name__ == '__main__':
    unittest.main()
