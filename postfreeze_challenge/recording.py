"""Observation-only process audit and retained adapter-call records.

The audit hook records Python's subprocess invocation attempts; it does not
replace subprocess.run, any relation handler, or any observation function.
It does not see compiler-internal assembler/linker subprocesses.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
import os
from pathlib import Path
import sys
import threading
import time

from .common import ROOT, put_blob, sha

ACTIVE = None
INSTALLED = False


def install_hook():
    global INSTALLED
    if INSTALLED:
        return
    def hook(event, args):
        recorder = ACTIVE
        if recorder is not None and event == 'subprocess.Popen':
            executable, command, cwd, _environment = args
            name = Path(os.fsdecode(executable)).name
            recorder.event('subprocess_attempt', executable=os.fsdecode(executable),
                           command=command, cwd=os.fsdecode(cwd) if cwd else os.getcwd(),
                           compiler_driver=name in {'gcc', 'clang'})
    sys.addaudithook(hook)
    INSTALLED = True


def activate(recorder):
    global ACTIVE
    install_hook()
    if ACTIVE is not None:
        raise RuntimeError('overlapping case recorders in one worker')
    ACTIVE = recorder


def deactivate():
    global ACTIVE
    ACTIVE = None


class Recorder:
    def __init__(self, workspace: Path):
        self.workspace = workspace.resolve()
        self.events = []
        self.raw_blobs = {}
        self.lock = threading.RLock()
        self.zero_ns = time.perf_counter_ns()

    def normalize(self, value):
        if is_dataclass(value):
            return self.normalize(asdict(value))
        if isinstance(value, Path):
            value = str(value.resolve())
        if isinstance(value, bytes):
            return {'bytes_hex': value.hex()}
        if isinstance(value, dict):
            return {str(key): self.normalize(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.normalize(item) for item in value]
        if isinstance(value, str):
            return value.replace(str(self.workspace), 'CASE').replace(str(ROOT.resolve()), 'ARTIFACT')
        return value

    def event(self, event_name, **fields):
        with self.lock:
            row = {'sequence': len(self.events), 'event': event_name,
                   'elapsed_ns': time.perf_counter_ns() - self.zero_ns,
                   **self.normalize(fields)}
            self.events.append(row)
            return row['sequence']

    def snapshot(self, path):
        path = Path(path)
        # Logging an unavailable path must not alter the tested operation's
        # exception or turn a tool failure into carrier absence.
        try:
            raw = path.read_bytes()
        except OSError as error:
            return {'path': self.normalize(path), 'snapshot_error': type(error).__name__}
        digest = sha(raw)
        with self.lock:
            self.raw_blobs[digest] = raw
        return {'path': self.normalize(path), 'bytes': len(raw), 'sha256': digest}

    def persist_blobs(self, out):
        return [put_blob(out, raw) for _, raw in sorted(self.raw_blobs.items())]

    def counts(self):
        def count(event):
            return sum(row['event'] == event for row in self.events)
        return {'subprocess_invocation_attempts': count('subprocess_attempt'),
                'compiler_invocation_attempts': sum(row['event'] == 'subprocess_attempt' and
                    row['compiler_driver'] for row in self.events),
                'successful_build_returns': count('build_return'),
                'extraction_calls': count('extract_call'),
                'typed_extraction_rejections': count('extract_rejection'),
                'fault_branch_entries': count('fault_branch'),
                'invalid_key_cache_hits': sum(row['event'] == 'fault_branch' and
                    row.get('effect') == 'wrong-key-cache-hit' for row in self.events),
                'poisoned_session_reads': sum(row['event'] == 'fault_branch' and
                    row.get('effect') == 'replay-previous-rejection' for row in self.events),
                'redirected_artifact_reads': sum(row['event'] == 'fault_branch' and
                    row.get('different_path') is True for row in self.events),
                'changed_byte_target_reads': sum(row['event'] == 'fault_branch' and
                    row.get('different_bytes') is True for row in self.events)}
