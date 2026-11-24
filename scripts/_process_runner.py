#!/usr/bin/env python3
from __future__ import annotations
import os, signal, subprocess, tempfile, time
from pathlib import Path


def run_to_files(command, *, cwd: Path, log_dir: Path, name: str, timeout: int, env: dict[str,str] | None = None) -> dict:
    log_dir.mkdir(parents=True, exist_ok=True)
    out_path = log_dir / f"{name}.stdout.log"
    err_path = log_dir / f"{name}.stderr.log"
    started = time.time()
    merged = os.environ.copy()
    if env:
        merged.update(env)
    merged.setdefault("PYTHONNOUSERSITE", "1")
    merged.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    with out_path.open("wb") as out, err_path.open("wb") as err:
        proc = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            env=merged,
            close_fds=True,
            start_new_session=True,
        )
        timed_out = False
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)
            except Exception:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except Exception: pass
                proc.wait()
            rc = 124
    return {
        "name": name,
        "command": command,
        "returncode": rc,
        "timed_out": timed_out,
        "seconds": round(time.time()-started,3),
        "stdout": str(out_path),
        "stderr": str(err_path),
    }
