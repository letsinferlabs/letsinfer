#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Minimal, fail-closed macOS launchd user-service integration."""

from __future__ import annotations

import dataclasses
import os
import pathlib
import plistlib
import re
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence

from ..paths import logs_root as canonical_logs_root

LABEL_PREFIX = "ai.letsinfer."
NODE_LABEL = f"{LABEL_PREFIX}node"
GATEWAY_LABEL = f"{LABEL_PREFIX}gateway"
LABEL_RE = re.compile(r"^ai\.letsinfer\.[a-z][a-z0-9.-]{0,63}$")
Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
Sleeper = Callable[[float], None]
LAUNCHD_BOOTSTRAP_RETRY_ATTEMPTS = 30
LAUNCHD_BOOTSTRAP_RETRY_DELAY_SECONDS = 0.25


class MacOSServiceError(RuntimeError):
    """A launchd service cannot be installed or verified safely."""


@dataclasses.dataclass(frozen=True)
class LaunchAgent:
    label: str
    arguments: tuple[str, ...]
    environment: Mapping[str, str] = dataclasses.field(default_factory=dict)
    keep_alive: bool = True

    def validate(self) -> None:
        if not LABEL_RE.fullmatch(self.label):
            raise MacOSServiceError("launchd label is invalid")
        if not self.arguments or not pathlib.PurePath(self.arguments[0]).is_absolute():
            raise MacOSServiceError("launchd executable must be an absolute path")
        for value in (*self.arguments, *self.environment.keys(), *self.environment.values()):
            if not value or "\x00" in value or "\n" in value:
                raise MacOSServiceError("launchd values must be non-empty single lines")


def launch_agents_root(home: pathlib.Path | None = None) -> pathlib.Path:
    return (home or pathlib.Path.home()) / "Library" / "LaunchAgents"


def logs_root(home: pathlib.Path | None = None) -> pathlib.Path:
    if home is not None:
        return home / ".local" / "share" / "letsinfer" / "logs"
    return canonical_logs_root()


def launch_agent_path(label: str, home: pathlib.Path | None = None) -> pathlib.Path:
    if not LABEL_RE.fullmatch(label):
        raise MacOSServiceError("launchd label is invalid")
    return launch_agents_root(home) / f"{label}.plist"


def render_launch_agent(
    agent: LaunchAgent,
    *,
    home: pathlib.Path | None = None,
) -> bytes:
    agent.validate()
    logs = logs_root(home)
    payload: dict[str, object] = {
        "Label": agent.label,
        "ProgramArguments": list(agent.arguments),
        "RunAtLoad": True,
        "KeepAlive": agent.keep_alive,
        "ProcessType": "Background",
        "ThrottleInterval": 2,
        "Umask": 0o077,
        "StandardOutPath": str(logs / f"{agent.label}.log"),
        "StandardErrorPath": str(logs / f"{agent.label}.error.log"),
    }
    if agent.environment:
        payload["EnvironmentVariables"] = dict(sorted(agent.environment.items()))
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)


def _default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
    )


def _run(
    runner: Runner,
    command: Sequence[str],
    *,
    expected: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[str]:
    completed = runner(command)
    if completed.returncode not in expected:
        detail = (completed.stderr or completed.stdout).strip() or "launchctl failed"
        raise MacOSServiceError(f"{' '.join(command)}: {detail}")
    return completed


def _bootstrap_launch_agent(
    runner: Runner,
    domain: str,
    path: pathlib.Path,
    *,
    sleeper: Sleeper,
) -> None:
    command = ("launchctl", "bootstrap", domain, str(path))
    for attempt in range(LAUNCHD_BOOTSTRAP_RETRY_ATTEMPTS):
        completed = runner(command)
        if completed.returncode == 0:
            return
        detail = (completed.stderr or completed.stdout).strip() or "launchctl failed"
        retryable = (
            "Bootstrap failed: 5:" in detail and "Input/output error" in detail
        )
        if not retryable or attempt + 1 == LAUNCHD_BOOTSTRAP_RETRY_ATTEMPTS:
            raise MacOSServiceError(f"{' '.join(command)}: {detail}")
        sleeper(LAUNCHD_BOOTSTRAP_RETRY_DELAY_SECONDS)


def _atomic_bytes(path: pathlib.Path, value: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_text = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_text)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _snapshot(path: pathlib.Path) -> tuple[bytes, int] | None:
    if path.is_symlink():
        raise MacOSServiceError(f"launchd service cannot be a symlink: {path}")
    if not path.exists():
        return None
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid():
        raise MacOSServiceError(f"launchd service is not a user-owned file: {path}")
    return path.read_bytes(), stat.S_IMODE(details.st_mode)


def domain_target(label: str) -> str:
    if not LABEL_RE.fullmatch(label):
        raise MacOSServiceError("launchd label is invalid")
    return f"gui/{os.getuid()}/{label}"


def service_state(
    label: str,
    *,
    home: pathlib.Path | None = None,
    runner: Runner = _default_runner,
) -> tuple[str, str, None]:
    path = launch_agent_path(label, home)
    enabled = "enabled" if path.is_file() and not path.is_symlink() else "not-found"
    completed = runner(("launchctl", "print", domain_target(label)))
    active = "active" if completed.returncode == 0 else "inactive"
    return enabled, active, None


def user_domain_available(*, runner: Runner = _default_runner) -> bool:
    completed = runner(("launchctl", "print", f"gui/{os.getuid()}"))
    return completed.returncode == 0


def install_launch_agent(
    agent: LaunchAgent,
    *,
    no_start: bool = False,
    home: pathlib.Path | None = None,
    runner: Runner = _default_runner,
    sleeper: Sleeper = time.sleep,
) -> None:
    agent.validate()
    root = launch_agents_root(home)
    logs = logs_root(home)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    logs.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = launch_agent_path(agent.label, home)
    expected = render_launch_agent(agent, home=home)
    snapshot = _snapshot(path)
    target = domain_target(agent.label)
    was_loaded = runner(("launchctl", "print", target)).returncode == 0
    if was_loaded and snapshot is not None and snapshot[0] == expected:
        return
    domain = f"gui/{os.getuid()}"
    loaded = False
    try:
        if was_loaded:
            _run(runner, ("launchctl", "bootout", target))
        _atomic_bytes(path, expected, 0o600)
        if no_start:
            return
        _bootstrap_launch_agent(runner, domain, path, sleeper=sleeper)
        loaded = True
        _run(runner, ("launchctl", "enable", target))
        _run(runner, ("launchctl", "kickstart", "-k", target))
        _run(runner, ("launchctl", "print", target))
    except BaseException as failure:
        errors: list[str] = []
        if loaded:
            try:
                _run(
                    runner,
                    ("launchctl", "bootout", target),
                    expected=frozenset({0, 3}),
                )
            except MacOSServiceError as error:
                errors.append(str(error))
        try:
            if snapshot is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_bytes(path, snapshot[0], snapshot[1])
            if was_loaded and snapshot is not None:
                _bootstrap_launch_agent(runner, domain, path, sleeper=sleeper)
                _run(runner, ("launchctl", "kickstart", "-k", target))
        except (MacOSServiceError, OSError) as error:
            errors.append(str(error))
        if errors:
            raise MacOSServiceError(
                "launchd activation failed and rollback was incomplete: "
                + "; ".join(errors)
            ) from failure
        raise MacOSServiceError(
            f"launchd activation failed; previous service restored: {failure}"
        ) from failure


def remove_launch_agent(
    label: str,
    *,
    home: pathlib.Path | None = None,
    runner: Runner = _default_runner,
) -> None:
    """Unload and remove one user-owned Let's Infer launch agent."""

    path = launch_agent_path(label, home)
    snapshot = _snapshot(path)
    target = domain_target(label)
    if runner(("launchctl", "print", target)).returncode == 0:
        _run(
            runner,
            ("launchctl", "bootout", target),
            expected=frozenset({0, 3}),
        )
    if snapshot is not None:
        path.unlink()
