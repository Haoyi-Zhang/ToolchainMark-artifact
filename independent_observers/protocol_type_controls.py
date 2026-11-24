"""Small in-memory protocol controls, separate from all native denominators."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


def main():
    producer = Path(__file__).resolve().parent / 'producer_current'
    sys.path.insert(0, str(producer))
    spec = importlib.util.spec_from_file_location('direct_protocol_controls', producer / 'direct_oracle.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    checks = []
    for observation in ({'kind': 'rejection', 'value': 'tool'},
                        {'kind': 'rejection', 'value': 'unknown'},
                        {'kind': 'payload', 'value': 'xyz'},
                        {'kind': 'unexpected', 'value': 'absent'}):
        try:
            module.domain_observation({'status': 'ok', 'observation': observation})
        except ValueError:
            checks.append({'input': observation, 'result': 'rejected-invalid-domain-observation'})
        else:
            raise AssertionError('Invalid domain outcome was accepted')
    if module.domain_observation({'status': 'unavailable', 'exception': 'ExtractionError', 'kind': 'tool'}) is not None:
        raise AssertionError('Unavailable tool outcome was accepted as a domain observation')
    print(json.dumps({'verdict': 'PASS',
        'scope': 'In-memory protocol type controls; no native executions or additional fault sensitivity cases. '
                 'The actual nm-failure controls are separately included in formal-02.',
        'controls': checks, 'unavailable_tool_result_is_none': True}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
