"""Run the real GeMTest decorators and pytest integration on native programs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import gemtest as gmt
from gemtest.metamorphic_error import SkippedMTC

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
from framework_comparison.native_callbacks import (
    NativeCase, inputs_for, SATISFIED, INADMISSIBLE,
)
from framework_comparison.paired_arm import acquire

OUTPUT = Path(os.environ['TOOLCHAINMARK_FRAMEWORK_RUN']).resolve()
PROTOCOL = json.loads((OUTPUT / 'protocol.json').read_text())
FRAME = json.loads((OUTPUT / 'frame.json').read_text())
CASES = {case['id']: case for case in FRAME}
ACTIVE = {}

RELATIONS = [gmt.create_metamorphic_relation(
    name=name,
    data=[{'case_id': case['id'], 'phase': 'source'} for case in FRAME
          if case['relation'] == name],
    testing_strategy=gmt.TestingStrategy.EXHAUSTIVE,
) for name in PROTOCOL['relations'] if any(case['relation'] == name for case in FRAME)]


@gmt.valid_input(*RELATIONS)
def available_source(output):
    return ACTIVE[output['case_id']].source_condition(output)


@gmt.general_transformation(*RELATIONS)
def generate_followups(mtc):
    return ACTIVE[mtc.source_input['case_id']].transform()


@gmt.general_relation(*RELATIONS)
def evaluate_obligations(mtc):
    job = ACTIVE[mtc.source_input['case_id']]
    job.framework_events.append('general_relation')
    judgments = job.judgments()
    primary = next(reversed(judgments.values()))
    if primary == INADMISSIBLE:
        # gmt.skip() is caught specially only during transformation in the
        # pinned implementation. For a premise observed after the follow-ups,
        # use the public MTC error object consumed by its normal pytest wrapper.
        mtc.error = SkippedMTC('The named stage premises are not established.')
        return False
    return primary == SATISFIED


def export_native_case(report):
    case_id = report.source_inputs[0]['case_id']
    job = ACTIVE[case_id]
    case_dir = OUTPUT / 'cases' / case_id
    framework = {
        'framework': 'GeMTest', 'mr_name': report.mr_name,
        'test_result': report.test_result, 'relation_result': report.relation_result,
        'source_inputs': report.source_inputs, 'source_outputs': report.source_outputs,
        'followup_inputs': report.followup_inputs, 'followup_outputs': report.followup_outputs,
        'transformation_name': report.transformation_name,
        'relation_name': report.relation_name,
        'exported_by_official_data_exporter_hook': True,
    }
    record = job.record(framework)
    (case_dir / 'gemtest.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    if job.case['pass'] == 2:
        acquire(job.case, job.inputs, OUTPUT, ARTIFACT)


@gmt.system_under_test(*RELATIONS, data_exporter=export_native_case)
def test_native_watermark(request):
    case = CASES[request['case_id']]
    if request['phase'] == 'source':
        case_dir = OUTPUT / 'cases' / case['id']
        case_dir.mkdir(parents=True, exist_ok=False)
        inputs = inputs_for(case, ARTIFACT, PROTOCOL)
        if case['pass'] == 1:
            acquire(case, inputs, OUTPUT, ARTIFACT)
        job = NativeCase(case, case_dir / 'gemtest-native', OUTPUT, inputs)
        ACTIVE[case['id']] = job
        return job.source()
    return ACTIVE[case['id']].followup(request['phase'])
