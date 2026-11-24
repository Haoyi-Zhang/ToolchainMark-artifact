"""A separate transformation-stage postcondition, outside the 14-MR catalog.

TR01 receives observations of one completed removal attempt. A no-op violates
that transformation postcondition but cannot establish the premise of an
extractor-focused removal relation. This is ordinary postcondition checking,
not a new watermark algorithm or an independent parser.
"""
from .admission import Evidence, InadmissibleCase, ScientificOutcome, no_accepted_carrier, payload_matches
from .integrity import CarrierSnapshot


def assess_removal_postcondition(carrier: str, source: CarrierSnapshot | None,
        followup: CarrierSnapshot | None, requested_payload: bytes, *,
        removal_requested: bool, transformation_completed: bool,
        postcondition_snapshot_current: bool) -> ScientificOutcome:
    """Judge the transform; the tested extractor is never consulted here."""
    evidence = Evidence(phase='transform-admission')
    try:
        evidence.require('source_observation_available', source is not None)
        evidence.observations['source'] = source.strict
        evidence.require('source_payload_valid', payload_matches(source.strict, requested_payload))
        evidence.require('removal_requested', removal_requested)
        evidence.require('transformation_completed', transformation_completed)
        evidence.require('postcondition_observation_available', followup is not None)
        evidence.observations['followup_carrier'] = followup.strict
        evidence.observations['removal_snapshots'] = {
            'source':source.identity(), 'followup':followup.identity()}
        evidence.require('postcondition_snapshot_current', postcondition_snapshot_current)
        evidence.phase = 'transform-postcondition'
        passed = no_accepted_carrier(carrier, followup.strict)
        return ScientificOutcome('SATISFIED' if passed else 'INCONSISTENT',
            'predicate-satisfied' if passed else 'predicate-violated', evidence.phase,
            dict(evidence.facts), dict(evidence.observations))
    except InadmissibleCase as error:
        return ScientificOutcome('INADMISSIBLE',str(error),evidence.phase,
            dict(evidence.facts),dict(evidence.observations))
