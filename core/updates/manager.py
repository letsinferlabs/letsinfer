#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""One durable, fail-safe update state plane for every Let's Infer node."""

from __future__ import annotations

import dataclasses
import functools
import json
import os
import pathlib
import re
import sqlite3
import stat
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from core.paths import data_root
from core.runtime_packs import RuntimePackError, catalog_release, load_catalog


SCHEMA_VERSION = 2
POLL_INTERVAL_SECONDS = 60 * 60
REFRESH_LEASE_SECONDS = 2 * 60
CORE_RELEASES_URL = (
    "https://api.github.com/repos/letsinferlabs/letsinfer/releases?per_page=30"
)
VERSION_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class UpdateError(RuntimeError):
    """Update state could not be read or refreshed safely."""


@dataclasses.dataclass(frozen=True)
class Component:
    kind: str
    subject: str
    installed_version: str
    installed_identity: str
    policy: str = "recommended"
    model: str | None = None
    runtime: str | None = None
    engine: str | None = None
    target: str | None = None
    target_contract_sha256: str | None = None
    installed_source: str | None = None
    display_subject: str | None = None
    apply_subject: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"core", "runtime"}:
            raise UpdateError(f"invalid update component kind: {self.kind}")
        if not self.subject or not self.installed_identity:
            raise UpdateError("update component identity is incomplete")
        if self.display_subject is not None and not self.display_subject:
            raise UpdateError("update component display identity is invalid")
        if self.apply_subject is not None and not self.apply_subject:
            raise UpdateError("update component apply identity is invalid")
        _version_parts(self.installed_version)
        if self.kind == "runtime":
            if not all((self.model, self.runtime, self.target)):
                raise UpdateError("runtime update component is incomplete")
            if not isinstance(self.target_contract_sha256, str) or not SHA256_RE.fullmatch(
                self.target_contract_sha256
            ):
                raise UpdateError("runtime target contract identity is invalid")


@dataclasses.dataclass(frozen=True)
class UpdateRecord:
    kind: str
    subject: str
    installed_version: str
    installed_identity: str
    available_version: str | None
    available_identity: str | None
    available_source: str | None
    status: str
    checked_at_unix: int
    verified_at_unix: int | None
    error_code: str | None
    display_subject: str | None = None
    apply_subject: str | None = None

    @property
    def available(self) -> bool:
        return self.status == "available" and self.available_version is not None

    @property
    def label(self) -> str:
        return self.display_subject or self.subject

    @property
    def apply(self) -> str:
        return self.apply_subject or self.subject


@dataclasses.dataclass(frozen=True)
class UpdateSnapshot:
    records: tuple[UpdateRecord, ...]
    busy: bool = False

    @property
    def available(self) -> tuple[UpdateRecord, ...]:
        return tuple(record for record in self.records if record.available)


@dataclasses.dataclass(frozen=True)
class _Candidate:
    version: str
    identity: str
    source: str


def _version_parts(value: str) -> tuple[int, int, int, tuple[str, ...] | None]:
    match = VERSION_RE.fullmatch(value)
    if match is None:
        raise UpdateError(f"unsupported release version: {value!r}")
    major, minor, patch = (int(match.group(index)) for index in range(1, 4))
    prerelease = match.group(4)
    identifiers = tuple(prerelease.split(".")) if prerelease is not None else None
    if identifiers is not None and any(
        identifier.isdecimal()
        and len(identifier) > 1
        and identifier.startswith("0")
        for identifier in identifiers
    ):
        raise UpdateError(f"unsupported release version: {value!r}")
    return major, minor, patch, identifiers


def compare_versions(left: str, right: str) -> int:
    """Compare SemVer releases without a packaging dependency."""
    left_major, left_minor, left_patch, left_pre = _version_parts(left)
    right_major, right_minor, right_patch, right_pre = _version_parts(right)
    left_base = left_major, left_minor, left_patch
    right_base = right_major, right_minor, right_patch
    if left_base != right_base:
        return (left_base > right_base) - (left_base < right_base)
    if left_pre is None or right_pre is None:
        return (left_pre is None) - (right_pre is None)
    for left_item, right_item in zip(left_pre, right_pre):
        if left_item == right_item:
            continue
        left_numeric = left_item.isdecimal()
        right_numeric = right_item.isdecimal()
        if left_numeric and right_numeric:
            return (int(left_item) > int(right_item)) - (
                int(left_item) < int(right_item)
            )
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return (left_item > right_item) - (left_item < right_item)
    return (len(left_pre) > len(right_pre)) - (len(left_pre) < len(right_pre))


def default_database_path() -> pathlib.Path:
    return data_root() / "updates.sqlite3"


def _safe_error_code(error: BaseException) -> str:
    if isinstance(error, RuntimePackError):
        return "catalog_invalid"
    if isinstance(error, (urllib.error.URLError, TimeoutError, OSError)):
        return "network_unavailable"
    if isinstance(error, (json.JSONDecodeError, UnicodeDecodeError, UpdateError)):
        return "source_invalid"
    return "refresh_failed"


def _github_candidate(
    installed_version: str,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> _Candidate:
    request = urllib.request.Request(
        CORE_RELEASES_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "letsinfer-update-manager/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with opener(request, timeout=8) as response:
        payload = response.read((1 << 20) + 1)
    if len(payload) > 1 << 20:
        raise UpdateError("core release metadata exceeds 1 MiB")
    value = json.loads(payload)
    if not isinstance(value, list):
        raise UpdateError("core release metadata must be an array")
    _major, _minor, _patch, installed_prerelease = _version_parts(installed_version)
    allow_prerelease = installed_prerelease is not None
    candidates: list[_Candidate] = []
    for release in value:
        if not isinstance(release, dict) or release.get("draft") is not False:
            continue
        tag = release.get("tag_name")
        release_id = release.get("id")
        prerelease = release.get("prerelease")
        html_url = release.get("html_url")
        if (
            not isinstance(tag, str)
            or not tag.startswith("v")
            or not isinstance(release_id, int)
            or isinstance(release_id, bool)
            or not isinstance(prerelease, bool)
            or not isinstance(html_url, str)
            or not html_url.startswith("https://github.com/letsinferlabs/letsinfer/")
        ):
            continue
        version = tag[1:]
        try:
            _version_parts(version)
        except UpdateError:
            continue
        if prerelease and not allow_prerelease:
            continue
        if (_version_parts(version)[3] is not None) != prerelease:
            continue
        candidates.append(_Candidate(version, f"github-release:{release_id}", html_url))
    if not candidates:
        raise UpdateError("no compatible core release was advertised")
    return max(
        candidates,
        key=functools.cmp_to_key(
            lambda left, right: compare_versions(left.version, right.version)
        ),
    )


class UpdateManager:
    """Refresh and expose one transactional update snapshot.

    Normal commands call :meth:`cached`, which performs no network I/O and does
    not create a database. The node agent and `update check` call
    :meth:`refresh`. A SQLite lease prevents concurrent network refreshes across
    the persistent agent and transient CLI processes.
    """

    def __init__(
        self,
        components: Callable[[], Sequence[Component]],
        *,
        database: pathlib.Path | None = None,
        catalog_location: Callable[[], str | None] | None = None,
        core_candidate: Callable[[str], _Candidate] | None = None,
        catalog_loader: Callable[[str], Mapping[str, Any]] = load_catalog,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._components = components
        self.database = database or default_database_path()
        self._catalog_location = catalog_location or (lambda: None)
        self._core_candidate = core_candidate or _github_candidate
        self._catalog_loader = catalog_loader
        self._clock = clock

    def _installed(self) -> tuple[Component, ...]:
        values = tuple(self._components())
        keys = [(value.kind, value.subject) for value in values]
        if len(keys) != len(set(keys)):
            raise UpdateError("installed update component identities are ambiguous")
        return values

    def installed(self) -> tuple[Component, ...]:
        """Return the identities against which cached advice is validated."""
        return self._installed()

    def _prepare_parent(self) -> None:
        parent = self.database.parent
        if parent.is_symlink():
            raise UpdateError(f"update state directory cannot be a symlink: {parent}")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        details = parent.stat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
            raise UpdateError(f"update state directory is not user-owned: {parent}")
        parent.chmod(0o700)

    def _connect(self, *, create: bool) -> sqlite3.Connection | None:
        if not create and not self.database.is_file():
            return None
        if self.database.is_symlink():
            raise UpdateError(f"update database cannot be a symlink: {self.database}")
        if self.database.exists():
            details = self.database.stat()
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) & 0o077
            ):
                raise UpdateError(
                    "update database must be private and user-owned"
                )
        if create:
            self._prepare_parent()
        try:
            if create:
                connection = sqlite3.connect(
                    self.database,
                    timeout=5,
                    isolation_level=None,
                )
            else:
                connection = sqlite3.connect(
                    self.database.absolute().as_uri() + "?mode=ro",
                    timeout=5,
                    isolation_level=None,
                    uri=True,
                )
        except sqlite3.Error as error:
            raise UpdateError(f"cannot open update state: {error}") from error
        connection.row_factory = sqlite3.Row
        try:
            if create:
                connection.executescript(
                    """
                    PRAGMA journal_mode=WAL;
                    PRAGMA synchronous=FULL;
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    ) STRICT;
                    CREATE TABLE IF NOT EXISTS records (
                        kind TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        installed_version TEXT NOT NULL,
                        installed_identity TEXT NOT NULL,
                        available_version TEXT,
                        available_identity TEXT,
                        available_source TEXT,
                        status TEXT NOT NULL,
                        checked_at_unix INTEGER NOT NULL,
                        verified_at_unix INTEGER,
                        error_code TEXT,
                        PRIMARY KEY (kind, subject)
                    ) STRICT;
                    CREATE TABLE IF NOT EXISTS refresh_lease (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        owner TEXT NOT NULL,
                        expires_at_unix INTEGER NOT NULL
                    ) STRICT;
                    """
                )
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key = 'schema_version'"
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO metadata(key, value) VALUES ('schema_version', ?)",
                        (str(SCHEMA_VERSION),),
                    )
                elif row["value"] != str(SCHEMA_VERSION):
                    raise UpdateError("unsupported update state schema")
                self.database.chmod(0o600)
            else:
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key = 'schema_version'"
                ).fetchone()
                if row is None or row["value"] != str(SCHEMA_VERSION):
                    raise UpdateError("unsupported update state schema")
        except BaseException as error:
            connection.close()
            if isinstance(error, UpdateError):
                raise
            if isinstance(error, (sqlite3.Error, OSError)):
                raise UpdateError(f"cannot initialize update state: {error}") from error
            raise
        return connection

    @staticmethod
    def _row_record(row: sqlite3.Row) -> UpdateRecord:
        return UpdateRecord(**dict(row))

    def cached(self) -> UpdateSnapshot:
        """Return only records bound to the currently installed identities."""
        try:
            connection = self._connect(create=False)
            if connection is None:
                return UpdateSnapshot(())
            try:
                installed = {
                    (component.kind, component.subject): component
                    for component in self._installed()
                }
                rows = connection.execute(
                    """SELECT kind, subject, installed_version, installed_identity,
                              available_version, available_identity, available_source,
                              status, checked_at_unix, verified_at_unix, error_code
                         FROM records ORDER BY kind, subject"""
                ).fetchall()
            finally:
                connection.close()
        except (UpdateError, RuntimePackError, sqlite3.Error, OSError):
            return UpdateSnapshot(())
        records = []
        for row in rows:
            record = self._row_record(row)
            component = installed.get((record.kind, record.subject))
            if component is not None and (
                record.installed_version == component.installed_version
                and record.installed_identity == component.installed_identity
            ):
                records.append(
                    dataclasses.replace(
                        record,
                        display_subject=component.display_subject,
                        apply_subject=component.apply_subject,
                    )
                )
        return UpdateSnapshot(tuple(records))

    def _acquire(self, connection: sqlite3.Connection, owner: str, now: int) -> bool:
        connection.execute("BEGIN IMMEDIATE")
        try:
            row = connection.execute(
                "SELECT owner, expires_at_unix FROM refresh_lease WHERE singleton = 1"
            ).fetchone()
            if row is not None and row["owner"] != owner and row["expires_at_unix"] > now:
                connection.execute("ROLLBACK")
                return False
            connection.execute(
                """INSERT INTO refresh_lease(singleton, owner, expires_at_unix)
                       VALUES (1, ?, ?)
                       ON CONFLICT(singleton) DO UPDATE SET
                           owner=excluded.owner,
                           expires_at_unix=excluded.expires_at_unix""",
                (owner, now + REFRESH_LEASE_SECONDS),
            )
            connection.execute("COMMIT")
            return True
        except BaseException:
            connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _runtime_candidate(
        component: Component,
        catalog: Mapping[str, Any],
    ) -> _Candidate:
        selected_runtime = None if component.policy == "recommended" else component.runtime
        target, target_sha, _runtime, version, source = catalog_release(
            dict(catalog),
            component.model or "",
            selected_runtime,
            component.target,
        )
        if target != component.target or target_sha != component.target_contract_sha256:
            raise UpdateError("runtime catalog changed the installed target contract")
        identity = source.rsplit("@sha256:", 1)[-1]
        return _Candidate(version, identity, source)

    def refresh(self) -> UpdateSnapshot:
        try:
            return self._refresh()
        except UpdateError:
            raise
        except (sqlite3.Error, OSError) as error:
            raise UpdateError(f"cannot refresh update state: {error}") from error

    def _refresh(self) -> UpdateSnapshot:
        """Refresh all components once and publish one atomic generation."""
        components = self._installed()
        now = int(self._clock())
        owner = uuid.uuid4().hex
        connection = self._connect(create=True)
        assert connection is not None
        try:
            if not self._acquire(connection, owner, now):
                return dataclasses.replace(self.cached(), busy=True)
            previous_rows = connection.execute(
                """SELECT kind, subject, installed_version, installed_identity,
                          available_version, available_identity, available_source,
                          status, checked_at_unix, verified_at_unix, error_code
                     FROM records"""
            ).fetchall()
            previous = {
                (row["kind"], row["subject"]): self._row_record(row)
                for row in previous_rows
            }
            candidates: dict[tuple[str, str], _Candidate] = {}
            errors: dict[tuple[str, str], str] = {}
            core = next((item for item in components if item.kind == "core"), None)
            if core is not None:
                try:
                    candidates[(core.kind, core.subject)] = self._core_candidate(
                        core.installed_version
                    )
                except Exception as error:
                    errors[(core.kind, core.subject)] = _safe_error_code(error)

            runtimes = [item for item in components if item.kind == "runtime"]
            eligible = [
                item
                for item in runtimes
                if item.policy in {"recommended", f"runtime:{item.runtime}"}
            ]
            if eligible:
                location = self._catalog_location()
                if location is None:
                    for item in eligible:
                        errors[(item.kind, item.subject)] = "catalog_unconfigured"
                else:
                    try:
                        catalog = self._catalog_loader(location)
                    except Exception as error:
                        code = _safe_error_code(error)
                        for item in eligible:
                            errors[(item.kind, item.subject)] = code
                    else:
                        for item in eligible:
                            try:
                                candidates[(item.kind, item.subject)] = self._runtime_candidate(
                                    item, catalog
                                )
                            except Exception as error:
                                errors[(item.kind, item.subject)] = _safe_error_code(error)

            records: list[UpdateRecord] = []
            for component in components:
                key = (component.kind, component.subject)
                candidate = candidates.get(key)
                previous_record = previous.get(key)
                if candidate is not None:
                    comparison = compare_versions(
                        candidate.version, component.installed_version
                    )
                    if (
                        comparison > 0
                        and component.kind == "runtime"
                        and component.installed_source is not None
                        and candidate.source == component.installed_source
                    ):
                        status = "integrity_error"
                        available = None
                        errors[key] = "new_version_reused_identity"
                    elif comparison > 0:
                        status = "available"
                        available = candidate
                    elif comparison == 0 and component.kind == "runtime" and (
                        component.installed_source is not None
                        and candidate.source != component.installed_source
                    ):
                        status = "integrity_error"
                        available = None
                        errors[key] = "same_version_identity_changed"
                    else:
                        status = "current"
                        available = None
                    record = UpdateRecord(
                        component.kind,
                        component.subject,
                        component.installed_version,
                        component.installed_identity,
                        available.version if available else None,
                        available.identity if available else None,
                        available.source if available else None,
                        status,
                        now,
                        now,
                        errors.get(key),
                    )
                elif component.policy not in {
                    "recommended",
                    f"runtime:{component.runtime}",
                } and component.kind == "runtime":
                    record = UpdateRecord(
                        component.kind,
                        component.subject,
                        component.installed_version,
                        component.installed_identity,
                        None,
                        None,
                        None,
                        "pinned",
                        now,
                        now,
                        None,
                    )
                elif previous_record is not None and (
                    previous_record.installed_version == component.installed_version
                    and previous_record.installed_identity == component.installed_identity
                    and previous_record.available
                ):
                    # A transient failure must not erase a previously verified
                    # update for the exact installed identity.
                    record = dataclasses.replace(
                        previous_record,
                        checked_at_unix=now,
                        error_code=errors.get(key, "refresh_failed"),
                    )
                else:
                    record = UpdateRecord(
                        component.kind,
                        component.subject,
                        component.installed_version,
                        component.installed_identity,
                        None,
                        None,
                        None,
                        "unknown",
                        now,
                        None,
                        errors.get(key, "refresh_failed"),
                    )
                record = dataclasses.replace(
                    record,
                    display_subject=component.display_subject,
                    apply_subject=component.apply_subject,
                )
                records.append(record)

            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute("DELETE FROM records")
                connection.executemany(
                    """INSERT INTO records(
                           kind, subject, installed_version, installed_identity,
                           available_version, available_identity, available_source,
                           status, checked_at_unix, verified_at_unix, error_code
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        (
                            record.kind,
                            record.subject,
                            record.installed_version,
                            record.installed_identity,
                            record.available_version,
                            record.available_identity,
                            record.available_source,
                            record.status,
                            record.checked_at_unix,
                            record.verified_at_unix,
                            record.error_code,
                        )
                        for record in records
                    ],
                )
                connection.execute(
                    "DELETE FROM refresh_lease WHERE singleton = 1 AND owner = ?",
                    (owner,),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            return UpdateSnapshot(tuple(records))
        finally:
            try:
                connection.execute(
                    "DELETE FROM refresh_lease WHERE singleton = 1 AND owner = ?", (owner,)
                )
            except sqlite3.Error:
                pass
            connection.close()


class UpdatePoller:
    """Bounded background refresh owned by the existing node-agent process."""

    def __init__(
        self,
        manager: UpdateManager,
        *,
        stop: threading.Event,
        interval_seconds: int = POLL_INTERVAL_SECONDS,
        jitter_seconds: int = 120,
    ) -> None:
        if interval_seconds < 1:
            raise UpdateError("update poll interval must be positive")
        if jitter_seconds < 0:
            raise UpdateError("update poll jitter cannot be negative")
        self.manager = manager
        self.stop = stop
        self.interval_seconds = interval_seconds
        self.jitter_seconds = jitter_seconds
        self.thread = threading.Thread(
            target=self._run,
            name="letsinfer-update-poller",
            daemon=True,
        )

    def _run(self) -> None:
        while not self.stop.is_set():
            jitter = 0
            try:
                self.manager.refresh()
                identity = "\0".join(
                    component.installed_identity
                    for component in self.manager.installed()
                )
                jitter = (
                    sum(identity.encode("utf-8")) % (self.jitter_seconds + 1)
                    if self.jitter_seconds
                    else 0
                )
            except Exception:
                pass
            if self.stop.wait(self.interval_seconds + jitter):
                return

    def start(self) -> None:
        self.thread.start()

    def join(self, timeout: float | None = None) -> None:
        self.thread.join(timeout)
