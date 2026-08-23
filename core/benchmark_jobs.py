#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Durable, single-owner benchmark jobs for the local Let's Infer node."""

from __future__ import annotations

import fcntl
import json
import os
import pathlib
import secrets
import signal
import subprocess
import time
from contextlib import contextmanager
from typing import Any, Iterator, Sequence, TextIO

from .site.state import data_root


SCHEMA_VERSION = 1
ACTIVE_STATES = {"starting", "running", "stopping"}
TERMINAL_STATES = {"completed", "failed", "cancelled"}


class BenchmarkJobError(RuntimeError):
    """The benchmark job state or lifecycle was invalid."""


def root() -> pathlib.Path:
    return data_root() / "benchmark-job"


def state_path() -> pathlib.Path:
    return root() / "state.json"


def progress_path() -> pathlib.Path:
    return root() / "progress.json"


def log_path() -> pathlib.Path:
    return root() / "benchmark.log"


def _prepare_root() -> pathlib.Path:
    path = root()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise BenchmarkJobError(f"benchmark job root is unsafe: {path}")
    path.chmod(0o700)
    return path


@contextmanager
def _locked() -> Iterator[None]:
    path = _prepare_root() / ".lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with os.fdopen(descriptor, "r+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
    finally:
        # fdopen owns and closes descriptor.
        pass


def _read_json(path: pathlib.Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise BenchmarkJobError(f"benchmark job file is unsafe: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BenchmarkJobError(f"cannot read benchmark job state: {error}") from error
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise BenchmarkJobError("benchmark job state has an unsupported schema")
    return value


def _write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    parent = _prepare_root()
    if path.parent != parent:
        raise BenchmarkJobError("benchmark job path escapes its state root")
    temporary = parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_state() -> dict[str, Any] | None:
    return _read_json(state_path())


def read_progress() -> dict[str, Any] | None:
    return _read_json(progress_path())


def _process_command(pid: int) -> str:
    proc = pathlib.Path("/proc") / str(pid) / "cmdline"
    try:
        if proc.is_file():
            return proc.read_bytes().replace(b"\0", b" ").decode(
                "utf-8", errors="replace"
            )
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def is_alive(state: dict[str, Any]) -> bool:
    pid = state.get("pid")
    job_id = state.get("job_id")
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 0
        or not isinstance(job_id, str)
        or not job_id
    ):
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    command = _process_command(pid)
    return "--job-worker" in command and job_id in command


def active_state() -> dict[str, Any] | None:
    state = read_state()
    if state is None or state.get("state") not in ACTIVE_STATES:
        return None
    return state if is_alive(state) else None


def _base_state(
    *,
    job_id: str,
    runtime: str,
    command: Sequence[str],
    output_directory: str,
    kind: str = "benchmark",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if kind not in {"benchmark", "verification"}:
        raise BenchmarkJobError(f"unsupported benchmark job kind: {kind}")
    return {
        "schema_version": SCHEMA_VERSION,
        "job_id": job_id,
        "state": "starting",
        "runtime": runtime,
        "kind": kind,
        "metadata": dict(metadata or {}),
        "pid": 0,
        "started_unix_ns": time.time_ns(),
        "updated_unix_ns": time.time_ns(),
        "output_directory": output_directory,
        "command": list(command),
        "log_path": str(log_path()),
        "progress_path": str(progress_path()),
    }


def start(
    command: Sequence[str],
    *,
    runtime: str,
    output_directory: str,
    kind: str = "benchmark",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Start one detached worker, refusing a second live benchmark."""
    with _locked():
        existing = active_state()
        if existing is not None:
            raise BenchmarkJobError(
                f"benchmark {existing['job_id']} is already active"
            )
        job_id = secrets.token_hex(16)
        worker_command = [*command, "--job-worker", "--job-id", job_id]
        state = _base_state(
            job_id=job_id,
            runtime=runtime,
            command=worker_command,
            output_directory=output_directory,
            kind=kind,
            metadata=metadata,
        )
        _write_json(state_path(), state)
        if progress_path().exists():
            progress_path().unlink()
        log_descriptor = os.open(
            log_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        try:
            with os.fdopen(log_descriptor, "w", encoding="utf-8") as log:
                process = subprocess.Popen(
                    worker_command,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True,
                    start_new_session=True,
                    close_fds=True,
                )
        except OSError as error:
            state.update(
                state="failed",
                error=f"cannot start benchmark worker: {error}",
                updated_unix_ns=time.time_ns(),
            )
            _write_json(state_path(), state)
            raise BenchmarkJobError(state["error"]) from error
        current = read_state() or state
        current.update(pid=process.pid, updated_unix_ns=time.time_ns())
        _write_json(state_path(), current)
        return current


def update_progress(job_id: str, value: dict[str, Any]) -> dict[str, Any]:
    """Atomically publish bounded progress for the active job owner."""

    if not isinstance(value, dict):
        raise BenchmarkJobError("benchmark progress must be an object")
    document = {"schema_version": SCHEMA_VERSION, **value}
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > 64 << 10:
        raise BenchmarkJobError("benchmark progress exceeds 64 KiB")
    with _locked():
        state = read_state()
        if state is None or state.get("job_id") != job_id:
            raise BenchmarkJobError("benchmark job identity changed")
        if state.get("state") not in ACTIVE_STATES:
            raise BenchmarkJobError("benchmark job is no longer active")
        _write_json(progress_path(), document)
    return document


def mark(job_id: str, state_name: str, *, error: str | None = None) -> dict[str, Any]:
    if state_name not in {"running", *TERMINAL_STATES}:
        raise BenchmarkJobError(f"unsupported benchmark job state: {state_name}")
    with _locked():
        state = read_state()
        if state is None or state.get("job_id") != job_id:
            raise BenchmarkJobError("benchmark job identity changed")
        state.update(
            state=state_name,
            pid=os.getpid() if state_name == "running" else state.get("pid", 0),
            updated_unix_ns=time.time_ns(),
        )
        if state_name in TERMINAL_STATES:
            state["finished_unix_ns"] = time.time_ns()
        if error:
            state["error"] = error
        _write_json(state_path(), state)
        return state


def request_stop() -> dict[str, Any]:
    with _locked():
        state = active_state()
        if state is None:
            raise BenchmarkJobError("no benchmark is active")
        state.update(state="stopping", updated_unix_ns=time.time_ns())
        _write_json(state_path(), state)
        try:
            os.kill(state["pid"], signal.SIGTERM)
        except ProcessLookupError:
            state.update(
                state="failed",
                error="benchmark worker disappeared before cancellation",
                finished_unix_ns=time.time_ns(),
                updated_unix_ns=time.time_ns(),
            )
            _write_json(state_path(), state)
        return state


def wait_for_exit(pid: int, timeout_seconds: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def tail_log(lines: int = 8) -> list[str]:
    path = log_path()
    if not path.is_file() or path.is_symlink():
        return []
    try:
        values = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return values[-max(0, lines) :]
