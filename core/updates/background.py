#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Best-effort, nonblocking update refreshes for short-lived CLI commands.

Normal commands render only :class:`~core.updates.manager.UpdateSnapshot` data
that has already passed the update manager's verification.  This module merely
asks a detached worker to refresh that durable cache for a later command (or a
live status view); it never turns unverified network data into UI state.
"""

from __future__ import annotations

import os
import pathlib
import sys
import threading
import time
from collections.abc import Callable, Mapping

from .manager import UpdateManager, UpdateSnapshot


BACKGROUND_REFRESH_INTERVAL_SECONDS = 60
DISABLE_BACKGROUND_UPDATE_ENV = "LETSINFER_DISABLE_BACKGROUND_UPDATE_CHECK"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_SPAWNED_REFRESH = """
import sys

sys.path.insert(0, sys.argv.pop(1))
try:
    from core.cli import _update_manager
    _update_manager().refresh()
except Exception:
    pass
"""


def snapshot_is_fresh(
    snapshot: UpdateSnapshot,
    *,
    now: float,
    max_age_seconds: int = BACKGROUND_REFRESH_INTERVAL_SECONDS,
) -> bool:
    """Return whether every cached record belongs to a recent atomic refresh."""
    if max_age_seconds < 0:
        raise ValueError("background update freshness cannot be negative")
    if not snapshot.records:
        return False
    checked_at = tuple(record.checked_at_unix for record in snapshot.records)
    oldest = min(checked_at)
    newest = max(checked_at)
    # A large future timestamp usually means the wall clock moved backwards.
    # Treat it as stale so one clock anomaly cannot suppress checks indefinitely.
    if newest > int(now) + max_age_seconds:
        return False
    return oldest >= int(now) - max_age_seconds


def _refresh_silently(manager: UpdateManager) -> None:
    try:
        manager.refresh()
    except Exception:
        # Background advice must never change the outcome of the user's command.
        pass


def _silence_and_close_inherited_descriptors() -> None:
    null_fd = os.open(os.devnull, os.O_RDWR)
    try:
        for descriptor in (0, 1, 2):
            os.dup2(null_fd, descriptor)
    finally:
        if null_fd > 2:
            os.close(null_fd)
    try:
        maximum = int(os.sysconf("SC_OPEN_MAX"))
    except (AttributeError, OSError, TypeError, ValueError):
        maximum = 65_536
    os.closerange(3, max(3, maximum))


def _launch_detached(callback: Callable[[], None]) -> bool:
    """Double-fork ``callback`` without retaining a child or terminal handles."""
    if not hasattr(os, "fork"):
        return False
    try:
        child = os.fork()
    except OSError:
        return False
    if child == 0:
        try:
            os.setsid()
            grandchild = os.fork()
            if grandchild != 0:
                os._exit(0)
            _silence_and_close_inherited_descriptors()
            callback()
        except BaseException:
            pass
        os._exit(0)

    # The first child does no network or disk work; reaping it prevents zombies
    # while the re-parented grandchild performs the refresh independently.
    while True:
        try:
            os.waitpid(child, 0)
            break
        except InterruptedError:
            continue
        except OSError:
            return False
    return True


def _reap_spawned_refresh(pid: int) -> None:
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass


def _launch_macos_refresh() -> bool:
    """Spawn a fresh interpreter without running Python after ``fork``."""

    if not hasattr(os, "posix_spawn"):
        return False
    root = pathlib.Path(__file__).resolve().parents[2]
    arguments = (
        sys.executable,
        "-I",
        "-B",
        "-c",
        _SPAWNED_REFRESH,
        str(root),
    )
    environment = dict(os.environ)
    environment[DISABLE_BACKGROUND_UPDATE_ENV] = "1"
    null_fd = os.open(os.devnull, os.O_RDWR)
    try:
        file_actions = (
            (os.POSIX_SPAWN_DUP2, null_fd, 0),
            (os.POSIX_SPAWN_DUP2, null_fd, 1),
            (os.POSIX_SPAWN_DUP2, null_fd, 2),
            (os.POSIX_SPAWN_CLOSE, null_fd),
        )
        pid = os.posix_spawn(
            sys.executable,
            arguments,
            environment,
            file_actions=file_actions,
        )
    except (AttributeError, OSError):
        return False
    finally:
        os.close(null_fd)
    threading.Thread(
        target=_reap_spawned_refresh,
        args=(pid,),
        daemon=True,
        name="letsinfer-update-reaper",
    ).start()
    return True


def request_background_refresh(
    manager: UpdateManager,
    *,
    snapshot: UpdateSnapshot | None = None,
    installed: bool = True,
    public_command: bool = True,
    explicit_check: bool = False,
    worker_context: bool = False,
    environ: Mapping[str, str] | None = None,
    clock: Callable[[], float] = time.time,
    max_age_seconds: int = BACKGROUND_REFRESH_INTERVAL_SECONDS,
    launcher: Callable[[Callable[[], None]], bool] | None = None,
) -> bool:
    """Request a verified cache refresh without blocking the current command.

    ``False`` means no worker was needed or could be launched.  Every failure is
    deliberately silent: explicit ``update check`` remains the user-facing,
    synchronous path for authoritative diagnostics.

    ``launcher`` is injectable so tests can prove scheduling behavior without
    forking or performing network I/O.
    """
    environment = os.environ if environ is None else environ
    disabled = environment.get(DISABLE_BACKGROUND_UPDATE_ENV, "").strip().lower()
    if (
        not installed
        or not public_command
        or explicit_check
        or worker_context
        or disabled in _TRUE_VALUES
    ):
        return False

    try:
        cached = manager.cached() if snapshot is None else snapshot
        # ``cached()`` deliberately hides records that no longer match the
        # installed identity.  A freshly installed runtime can therefore make
        # a recent core-only snapshot look fresh unless we also compare the
        # complete local component set.  This is local-only work; it performs
        # no network access.
        if len(cached.records) != len(manager.installed()):
            fresh = False
        else:
            fresh = snapshot_is_fresh(
                cached,
                now=clock(),
                max_age_seconds=max_age_seconds,
            )
        if fresh:
            return False
        if launcher is None and sys.platform == "darwin":
            return _launch_macos_refresh()
        launch = _launch_detached if launcher is None else launcher
        return bool(launch(lambda: _refresh_silently(manager)))
    except Exception:
        return False
