"""Data-only row contracts for the three retained admission protocols."""
import json
import math
import re

from .evidence_catalog import load
from .relations import INPUTS, PAYLOAD1, PAYLOAD2

FIELDS = ('host', 'host_sha256', 'carrier', 'defect_id', 'relation_id', 'verdict',
          'exposed', 'reason', 'phase', 'admission_json', 'observations_json',
          'duration_seconds')
LOCALITY = {'nonintervened_payload_preserved', 'checksum_material_changed',
            'nonchecksum_material_preserved'}
COHERENCE = {'source_snapshot_matches_request', 'followup_snapshot_current',
             'followup_unchanged_during_extraction'}


class StudyInputError(ValueError, AssertionError):
    # Preserve the original direct-call guard exception contract, without
    # relying on assert statements that disappear under optimized Python.
    pass


def object_json(value):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise StudyInputError('duplicate JSON evidence key')
            result[key] = value
        return result
    def nonfinite(value):
        raise StudyInputError('nonfinite JSON observation: ' + value)
    def finite_float(value):
        result=float(value)
        if not math.isfinite(result):nonfinite(value)
        return result
    try:
        result = json.loads(value, object_pairs_hook=pairs, parse_constant=nonfinite,parse_float=finite_float)
    except (ValueError, TypeError) as error:
        raise StudyInputError('invalid evidence JSON: ' + str(error)) from error
    if type(result) is not dict:
        raise StudyInputError('evidence must be a JSON object')
    return result


def validate_observations(observations, admitted):
    """Reject malformed typed observations without inventing missing traces."""
    def require(ok, message):
        if not ok:raise StudyInputError(message)
    def extraction(value):
        require(type(value) is dict and set(value)=={'kind','value'},'malformed extraction observation')
        require(value['kind'] in {'payload','rejection'} and type(value['value']) is str,
                'malformed typed extraction value')
        require((re.fullmatch('(?:[0-9a-f]{2})*',value['value']) is not None)
                if value['kind']=='payload' else value['value'] in {
                    'absent','wrong-key','checksum','malformed','version','path','sidecar'},
                'invalid payload/rejection encoding')
    def settings(value):
        require(type(value) is list and len(value)==2 and all(type(x) is str and x for x in value),
                'malformed build settings')
    for name,value in observations.items():
        if name in {'extraction','carrier','source','followup','first','second','before',
                    'after','intervening','source_carrier','followup_carrier'}:
            extraction(value)
        elif name=='extractions':
            require(type(value) is list and bool(value),'missing extraction vector')
            for item in value:extraction(item)
        elif name in {'both_expected','both_payloads','outputs_distinct','host_outputs_agree'}:
            require(type(value) is bool,'non-Boolean observation flag')
        elif name=='execution_order':require(type(value) is str and bool(value),'missing execution order')
        elif name in {'requested','actual'}:settings(value)
        elif name=='builds':
            require(type(value) is list and bool(value),'missing build observations')
            for build in value:
                require(type(build) is dict and set(build)=={'requested','actual'},'malformed build observation')
                settings(build['requested']);settings(build['actual'])
        elif name=='mismatches':
            require(type(value) is list,'malformed host mismatch vector')
            for mismatch in value:
                require(type(mismatch) is dict and set(mismatch)=={'input','base','marked'}
                        and type(mismatch['input']) is int
                        and all(type(mismatch[x]) is str for x in ('base','marked')),'malformed host mismatch')
        elif name=='integrity_intervention':
            require(type(value) is dict and set(value)==LOCALITY
                    and all(type(x) is bool for x in value.values()),'malformed locality observation')
            if admitted:require(all(x is True for x in value.values()),'failed observed locality counted as admitted')
        elif name in {'integrity_snapshots', 'removal_snapshots'}:
            require(type(value) is dict and bool(value) and set(value)<={'source','followup'},'malformed snapshots')
            for role,item in value.items():
                require(type(item) is dict and set(item)=={'sha256','bytes'}
                        and type(item['bytes']) is int and item['bytes']>=0
                        and (item['bytes']>0 or (name=='removal_snapshots' and role=='followup'))
                        and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}',item['sha256']) is not None,
                        'malformed snapshot identity')
            if admitted:require(set(value)=={'source','followup'}
                                and value['source']['sha256']!=value['followup']['sha256'],
                                'missing distinct intervention snapshots')


def validate_relation_semantics(row, observations):
    """Recompute admitted predicates from their recorded observation projection.

    This catches internal contradictions; it cannot certify unrecorded host
    outputs, the honesty of Boolean observation summaries, or execution itself.
    The payloads and requested branches are the frozen campaign inputs, not a
    user-supplied general relation domain.
    """
    def require(ok, message):
        if not ok:
            raise StudyInputError(message)
    def payload(value, expected=PAYLOAD1):
        return value == {'kind': 'payload', 'value': expected.hex()}
    relation = row['relation_id']
    for name in ('source', 'source_carrier'):
        if name in observations:
            require(payload(observations[name]), 'admitted source observation differs from requested payload')
    if relation == 'MR01':
        passed = payload(observations['extraction'])
    elif relation == 'MR02':
        mismatches = observations['mismatches']
        require(all(m['input'] in INPUTS and m['base'] != m['marked'] for m in mismatches),
                'recorded host mismatch does not establish a frozen-input mismatch')
        require(len({m['input'] for m in mismatches}) == len(mismatches), 'duplicate host mismatch input')
        passed = not mismatches
    elif relation == 'MR03':
        absent = {'kind': 'rejection', 'value': 'absent'}
        require(observations['carrier'] == absent, 'admitted absence differs from carrier observation')
        passed = observations['extraction'] == absent
    elif relation == 'MR04':
        passed = observations['followup'] == {'kind': 'rejection', 'value': 'wrong-key'}
    elif relation == 'MR05':
        require(observations['execution_order'] == 'sequential-builds-then-extract',
                'payload separation execution order differs')
        passed = payload(observations['first']) and payload(observations['second'], PAYLOAD2)
    elif relation in {'MR06', 'MR07'}:
        expected = [['gcc', 'O2'], ['clang', 'O2']] if relation == 'MR06' else [
            ['gcc', level] for level in ('O0', 'O2', 'Os')]
        require([b['requested'] for b in observations['builds']] == expected,
                'admitted build branch domain differs')
        require(all(b['actual'] == b['requested'] for b in observations['builds']),
                'admitted build branch was not executed as requested')
        require(len(observations['extractions']) == len(expected), 'build/extraction counts differ')
        passed = all(payload(x) for x in observations['extractions']) and observations['host_outputs_agree']
    elif relation == 'MR08':
        passed = payload(observations['followup']) and observations['host_outputs_agree']
    elif relation in {'MR09', 'MR10'}:
        physical = observations['followup_carrier']
        allowed = {'absent'}
        if relation == 'MR09' and row['carrier'] == 'string':
            allowed |= {'wrong-key', 'checksum', 'malformed', 'version'}
        if relation == 'MR10':
            allowed = {'checksum'}
        require(physical['kind'] == 'rejection' and physical['value'] in allowed,
                'admitted intervention differs from carrier observation')
        passed = observations['followup'] == physical
    elif relation == 'MR11':
        require(observations['requested'] == ['clang', 'Os'], 'frozen build request differs')
        passed = observations['actual'] == observations['requested']
    elif relation == 'MR12':
        require(observations['execution_order'] == 'overlapping-builds-then-extract',
                'overlap execution order differs')
        require(not observations['both_expected'] or
                (observations['both_payloads'] and observations['outputs_distinct']),
                'expected distinct payloads contradict overlap observations')
        passed = observations['both_expected']
    elif relation == 'MR13':
        passed = (payload(observations['before']) and payload(observations['intervening'], PAYLOAD2)
                  and payload(observations['after']))
    elif relation == 'MR14':
        passed = payload(observations['before']) and payload(observations['after'])
    else:
        raise StudyInputError('unknown relation identity')
    expected_verdict = 'SATISFIED' if passed else 'INCONSISTENT'
    require(row['verdict'] == expected_verdict, 'verdict contradicts recorded relation predicate')
    require(row['reason'] == ('predicate-satisfied' if passed else 'predicate-violated'),
            'admitted reason contradicts recorded relation predicate')


def validate_rows(rows, protocol):
    """Validate recorded evidence, never execute historical source or subjects.

    Historical rows keep their own required MR10 fields. Inadmissible rows can
    stop part-way through admission and therefore need not contain later facts.
    """
    declarations = {row['id']: row for row in load()}
    version = {'evidence-gated-v1': 1, 'evidence-gated-v2-checksum-locality': 2,
               'evidence-gated-v3-snapshot-coherence': 3,
               'evidence-gated-v4-removal-coherence': 4,
               'unresolved-no-admitted-MR10': 1}.get(protocol)
    if version is None:
        raise StudyInputError('unknown matrix evidence protocol')
    host_identities = {}
    for index, row in enumerate(rows):
        def require(ok, message):
            if not ok:
                raise StudyInputError(f'row {index + 1}: {message}')
        require(set(row) == set(FIELDS) and all(type(x) is str for x in row.values()),
                'CSV fields/value types differ')
        require(re.fullmatch('[0-9a-f]{64}', row['host_sha256']) is not None,
                'invalid host identity')
        require(host_identities.setdefault(row['host'], row['host_sha256']) == row['host_sha256'],
                'one host name has conflicting source identities')
        require(row['relation_id'] in declarations, 'unknown relation identity')
        require(row['verdict'] in {'SATISFIED', 'INCONSISTENT', 'INADMISSIBLE'}, 'unknown verdict')
        require(row['exposed'] in {'True', 'False'}, 'exposure must be Boolean')
        require((row['exposed'] == 'True') ==
                (row['defect_id'] != 'CLEAN' and row['verdict'] == 'INCONSISTENT'),
                'exposure differs from inconsistent nonclean verdict')
        require(bool(row['reason']) and bool(row['phase']), 'missing reason/phase')
        try:
            duration = float(row['duration_seconds'])
        except ValueError as error:
            raise StudyInputError('invalid duration') from error
        require(math.isfinite(duration) and duration > 0, 'duration must be finite and positive')
        facts = object_json(row['admission_json'])
        observations = object_json(row['observations_json'])
        validate_observations(observations,row['verdict']!='INADMISSIBLE')
        require(all(type(value) is bool for value in facts.values()), 'admission values must be Boolean')
        if row['verdict'] == 'INADMISSIBLE':
            # A failed first source check (or an earlier I/O failure) may
            # legitimately stop before any later admission fact is recorded.
            # Such rows remain non-attributing, never SATISFIED/INCONSISTENT.
            continue
        require({'subject_exists', 'isolated_workspace'} <= facts.keys(), 'missing base admission facts')
        declaration = declarations[row['relation_id']]
        required = set(declaration['required_admission_facts'])
        observed = set(declaration['observation_keys'])
        if row['relation_id'] == 'MR10':
            if version < 3:
                required -= COHERENCE
                observed.discard('integrity_snapshots')
            if version < 2:
                required -= LOCALITY
                observed.discard('integrity_intervention')
        if row['relation_id'] == 'MR09' and version < 4:
            required -= COHERENCE
            observed.discard('removal_snapshots')
        require(required <= facts.keys(), 'missing protocol-required admission facts')
        require(observed <= observations.keys(), 'missing required observations')
        require(all(value is True for value in facts.values()), 'failed premise counted as admitted')
        try:
            validate_relation_semantics(row, observations)
        except StudyInputError as error:
            raise StudyInputError(f'row {index + 1}: {error}') from error
