"""SR01 admission from declared policy, typed calls and captured endpoint identities.

The policy is an explicit target contract. A decoder allowed to lock out after
failure is outside this obligation. Classification never uses a cohort name.
"""
from __future__ import annotations

import re

DOMAIN_REJECTIONS = {'absent', 'wrong-key', 'checksum', 'malformed', 'version', 'path', 'sidecar'}
PREMISES = ('reuse_after_rejection_declared', 'lockout_excluded_by_contract', 'keys_distinct',
            'source_is_valid_requested_payload', 'source_extracts_requested_payload',
            'same_decoder_context', 'wrong_key_returns_typed_wrong_key_rejection',
            'source_current_before_wrong_key', 'source_unchanged_during_wrong_key',
            'source_current_before_recovery', 'source_unchanged_during_recovery',
            'recovery_observation_available')


def valid_snapshot(value):
    return (isinstance(value, dict) and set(value) == {'path', 'bytes', 'sha256'} and
            isinstance(value['path'], str) and type(value['bytes']) is int and value['bytes'] > 0 and
            isinstance(value['sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['sha256']) is not None)


def same_snapshot(a, b):
    return valid_snapshot(a) and valid_snapshot(b) and a == b


def typed_observation(value):
    return (isinstance(value, dict) and set(value) == {'kind', 'value'} and
            isinstance(value['value'], str) and
            ((value['kind'] == 'payload' and re.fullmatch('(?:[0-9a-f]{2})*', value['value']) is not None) or
             (value['kind'] == 'rejection' and value['value'] in DOMAIN_REJECTIONS)))


def assess(evidence, contract, request):
    snapshots = evidence.get('snapshots', {})
    observations = evidence.get('observations', {})
    calls = evidence.get('tested_calls', [])
    source = snapshots.get('source')
    expected = {'kind': 'payload', 'value': request['payload_hex']}
    context_matches = (evidence.get('decoder_instances') == 1 and len(calls) == 3 and
                       valid_snapshot(source) and
                       [call.get('key') for call in calls] == [request['key'], request['wrong_key'], request['key']] and
                       all(call.get('path') == source['path'] for call in calls))
    facts = {
        'reuse_after_rejection_declared': contract.get('reuse_after_rejection_declared') is True,
        'lockout_excluded_by_contract': contract.get('lockout_excluded_by_contract') is True,
        'keys_distinct': request['key'] != request['wrong_key'],
        'source_is_valid_requested_payload': valid_snapshot(source) and observations.get('source_carrier') == expected,
        'source_extracts_requested_payload': observations.get('source') == expected,
        'same_decoder_context': context_matches,
        'wrong_key_returns_typed_wrong_key_rejection': observations.get('wrong_key') == {'kind': 'rejection', 'value': 'wrong-key'},
        'source_current_before_wrong_key': same_snapshot(source, snapshots.get('before_wrong_key')),
        'source_unchanged_during_wrong_key': same_snapshot(snapshots.get('before_wrong_key'), snapshots.get('after_wrong_key')),
        'source_current_before_recovery': same_snapshot(source, snapshots.get('before_recovery')),
        'source_unchanged_during_recovery': same_snapshot(snapshots.get('before_recovery'), snapshots.get('after_recovery')),
        'recovery_observation_available': typed_observation(observations.get('recovery')),
    }
    failed = next((name for name in PREMISES if not facts[name]), None)
    if failed:
        return {'verdict': 'INADMISSIBLE', 'reason': failed, 'admission': facts}
    passed = observations['recovery'] == expected
    return {'verdict': 'SATISFIED' if passed else 'INCONSISTENT',
            'reason': 'recovery_matches_request' if passed else 'recovery_differs_after_typed_rejection',
            'admission': facts}
