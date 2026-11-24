"""Acquire the contract arm; called outside GeMTest's scientific callbacks."""
from __future__ import annotations

import json
from pathlib import Path
import time

from contract_runtime.core import execute
from declarative_study.reference_adapter import ReferenceAdapter, Pipeline
from declarative_study.state_words import ControlledStatePipeline


def acquire(case, inputs, output, artifact):
    case_dir = Path(output) / 'cases' / case['id']
    target = case_dir / 'contract.json'
    if target.exists():
        raise FileExistsError('A paired native arm may not be reused: ' + str(target))
    plan = json.loads((artifact / 'declarative_study/plans' /
                       (case['relation'] + '.json')).read_text())
    factory = ControlledStatePipeline if case['family'] == 'state' else Pipeline
    adapter = ReferenceAdapter(case_dir / 'contract-native', output, pipeline_factory=factory)
    start = time.perf_counter()
    receipt = execute(plan, inputs, adapter, context_id=case['id'] + ':contract')
    record = {'case': case, 'seconds': time.perf_counter() - start,
              'plan': plan, 'receipt': receipt,
              'judgments': {row['id']: row['verdict'] for row in receipt['obligations']}}
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return record
