"""Four declared new trigger behaviors, with the old native builder unchanged.

These are independently written fault implementations in known contract
families. They are not four newly discovered classes of industrial defects.
Original M-identities are used only for separately reported separation traces.
"""
from __future__ import annotations

from pathlib import Path
import threading

from toolchainmark.model import ExtractionError
from toolchainmark.pipeline import Pipeline
from .common import sha


class ChallengePipeline(Pipeline):
    def __init__(self, carrier, variant, recorder):
        super().__init__(carrier, variant)
        self.recorder = recorder
        self.challenge_lock = threading.RLock()
        self._positive_cache = {}
        self._latched_rejection = None
        self._basename_targets = {}
        self._last_successful_artifact = None
        self.recorder.event('decoder_instance', variant=variant, carrier=carrier)

    def build(self, request):
        call = self.recorder.event('build_call', request=request)
        try:
            result = super().build(request)
        except Exception as error:
            self.recorder.event('build_error', call=call, exception=type(error).__name__, message=str(error))
            raise
        binary = self.recorder.snapshot(result.binary)
        source = self.recorder.snapshot(result.source)
        if self.mutant_id == 'N03':
            with self.challenge_lock:
                previous = self._basename_targets.get(result.binary.name)
                self._basename_targets[result.binary.name] = result.binary
                self.recorder.event('resolver_registration', call=call, basename=result.binary.name,
                                    previous=previous, selected=result.binary)
        self.recorder.event('build_return', call=call, result=result, binary=binary, source=source)
        return result

    def _decode(self, path, key):
        observation = self.recorder.snapshot(path)
        call = self.recorder.event('decoder_invocation', path=path, key=key, artifact=observation,
                                   implementation='frozen-strict-carrier' if self.mutant_id.startswith('N')
                                   else 'frozen-reference-with-declared-control')
        try:
            if self.mutant_id.startswith('N'):
                result = Pipeline._extract_carrier(self, path, key, validation=False)
            else:
                result = Pipeline.extract(self, path, key)
        except ExtractionError as error:
            self.recorder.event('decoder_rejection', call=call, kind=error.kind)
            raise
        except Exception as error:
            self.recorder.event('decoder_error', call=call, exception=type(error).__name__, message=str(error))
            raise
        self.recorder.event('decoder_return', call=call, payload_hex=result.hex())
        return result

    def _extract(self, binary, key):
        if self.mutant_id == 'N01':
            identity = sha(binary.read_bytes())
            with self.challenge_lock:
                cached = self._positive_cache.get(identity)
            if cached is not None:
                payload, original_key = cached
                self.recorder.event('cache_hit', artifact_sha256=identity, original_key=original_key,
                                    supplied_key=key)
                if key != original_key:
                    self.recorder.event('fault_branch', effect='wrong-key-cache-hit',
                                        original_key=original_key, supplied_key=key, artifact_sha256=identity)
                return payload
            payload = self._decode(binary, key)
            with self.challenge_lock:
                self._positive_cache[identity] = (payload, key)
            self.recorder.event('cache_store', artifact_sha256=identity, key=key, payload_hex=payload.hex())
            return payload
        if self.mutant_id == 'N02':
            if self._latched_rejection is not None:
                self.recorder.event('fault_branch', effect='replay-previous-rejection',
                                    previous_kind=self._latched_rejection)
                raise ExtractionError(self._latched_rejection, 'reused decoder retained a previous rejection')
            try:
                return self._decode(binary, key)
            except ExtractionError as error:
                self._latched_rejection = error.kind
                self.recorder.event('rejection_latched', kind=error.kind)
                raise
        if self.mutant_id == 'N03':
            with self.challenge_lock:
                target = self._basename_targets.get(binary.name, binary)
            if target.resolve() != binary.resolve():
                requested = self.recorder.snapshot(binary)
                selected = self.recorder.snapshot(target)
                self.recorder.event('fault_branch', effect='basename-resolution',
                                    requested=requested, selected=selected, different_path=True,
                                    different_bytes=requested.get('sha256') != selected.get('sha256'))
            return self._decode(target, key)
        if self.mutant_id == 'N04':
            try:
                payload = self._decode(binary, key)
            except ExtractionError:
                target = self._last_successful_artifact
                if target is None:
                    raise
                requested = self.recorder.snapshot(binary)
                selected = self.recorder.snapshot(target)
                self.recorder.event('fault_branch', effect='recovery-artifact', requested=requested,
                                    selected=selected, different_path=target.resolve() != binary.resolve(),
                                    different_bytes=requested.get('sha256') != selected.get('sha256'))
                return self._decode(target, key)
            self._last_successful_artifact = binary
            return payload
        return self._decode(binary, key)

    def extract(self, binary: Path, key):
        call = self.recorder.event('extract_call', path=binary, key=key,
                                   artifact=self.recorder.snapshot(binary))
        try:
            result = self._extract(binary, key)
        except ExtractionError as error:
            self.recorder.event('extract_rejection', call=call, kind=error.kind,
                                artifact_after=self.recorder.snapshot(binary))
            raise
        except Exception as error:
            self.recorder.event('extract_error', call=call, exception=type(error).__name__, message=str(error),
                                artifact_after=self.recorder.snapshot(binary))
            raise
        self.recorder.event('extract_return', call=call, payload_hex=result.hex(),
                            artifact_after=self.recorder.snapshot(binary))
        return result

    def remove_carrier(self, result, target_dir):
        call = self.recorder.event('removal_call', source=self.recorder.snapshot(result.binary))
        try:
            target = super().remove_carrier(result, target_dir)
        except Exception as error:
            self.recorder.event('removal_error', call=call, exception=type(error).__name__, message=str(error))
            raise
        self.recorder.event('removal_return', call=call, target=self.recorder.snapshot(target))
        return target

    def corrupt_carrier(self, result, target_dir):
        call = self.recorder.event('corruption_call', source=self.recorder.snapshot(result.binary))
        try:
            target = super().corrupt_carrier(result, target_dir)
        except Exception as error:
            self.recorder.event('corruption_error', call=call, exception=type(error).__name__, message=str(error))
            raise
        self.recorder.event('corruption_return', call=call, target=self.recorder.snapshot(target))
        return target
