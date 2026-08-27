#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, idempotent member execution for engine-group lifecycle jobs."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import queue
import re
import sqlite3
import stat
import threading
import time
import unicodedata
from collections.abc import Callable, Iterator, Mapping
from typing import Any

from .contracts import OrchestrationError, validate_group_document
from .credentials import GroupCredentialError, credential_sha256
from ..paths import data_root
from ..runtime_sources import is_immutable_runtime_source


PROTOCOL = "letsinfer-engine-group-job-v2"
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_JOB_BYTES = 16 * 1024
MAX_RESULT_BYTES = 16 * 1024
MAX_CLOCK_SKEW_SECONDS = 30
MAX_JOB_LIFETIME_SECONDS = 300
MAX_QUEUED_JOBS = 16
FINAL_JOB_STATES = {"succeeded", "failed"}
GROUP_STATES = {"staged", "running", "stopped", "failed", "removed"}
ACTION_RESULT_STATE = {
    "stage": "staged",
    "start": "running",
    "recover": "running",
    "stop": "stopped",
    "remove": "removed",
}
SENSITIVE_RESULT_PARTS = {"secret", "password", "token", "private", "credential"}
LABELED_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|cookie|credential|password|secret|token)"
    r"(\s*[:=]\s*)(?:bearer\s+)?([^\s,;]+)"
)
MAX_ERROR_CHARS = 512


class MemberJobError(RuntimeError):
    """A group job is unauthenticated, invalid, replayed, or failed."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def default_job_store_path() -> pathlib.Path:
    return data_root() / "member-jobs.sqlite3"


def _private_directory(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise MemberJobError(f"member job directory cannot be a symlink: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise MemberJobError(f"member job directory must be user-owned: {path}")
    path.chmod(0o700)


def _bounded_json(value: Any, label: str, limit: int) -> str:
    try:
        payload = canonical_bytes(value)
    except (TypeError, ValueError) as error:
        raise MemberJobError(f"{label} is not canonical JSON") from error
    if len(payload) > limit:
        raise MemberJobError(f"{label} exceeds {limit} bytes")
    return payload.decode("utf-8").rstrip("\n")


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            any(part in str(key).lower() for part in SENSITIVE_RESULT_PARTS)
            or _contains_sensitive_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _safe_error(error: BaseException) -> str:
    """Persist one bounded diagnostic without credential values or controls."""

    name = type(error).__name__
    raw = LABELED_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        str(error),
    )
    neutral = "".join(
        character
        if character in {"\n", "\t"}
        or unicodedata.category(character) not in {"Cc", "Cf"}
        else "?"
        for character in raw
    )
    detail = " ".join(neutral.split())
    if not detail:
        return name
    available = MAX_ERROR_CHARS - len(name) - 2
    if len(detail) > available:
        detail = detail[: max(0, available - 2)].rstrip() + " …"
    return f"{name}: {detail}"


def validate_group_job(
    value: Any,
    *,
    expected_member_id: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Validate an exact coordinator-issued member lifecycle job."""
    required = {
        "protocol",
        "operation_id",
        "group_id",
        "action",
        "member_id",
        "plan_sha256",
        "runtime_digest",
        "manifest_sha256",
        "topology_sha256",
        "engine_credential_sha256",
        "expires_at_unix",
        "source",
        "task",
        "group",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("protocol") != PROTOCOL:
        raise MemberJobError("engine-group job schema is invalid")
    for key in ("operation_id", "group_id", "member_id"):
        if not isinstance(value.get(key), str) or not ID_RE.fullmatch(value[key]):
            raise MemberJobError(f"engine-group job {key} is invalid")
    if value["member_id"] != expected_member_id:
        raise MemberJobError("engine-group job targets a different member")
    for key in (
        "plan_sha256", "runtime_digest", "manifest_sha256", "topology_sha256",
        "engine_credential_sha256",
    ):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise MemberJobError(f"engine-group job {key} is invalid")
    action = value.get("action")
    if action not in ACTION_RESULT_STATE:
        raise MemberJobError("engine-group job action is invalid")
    source = value.get("source")
    if action == "stage":
        if not is_immutable_runtime_source(source):
            raise MemberJobError("stage jobs require an immutable runtime source")
    elif source is not None:
        raise MemberJobError("only stage jobs may carry a runtime source")
    current = int(time.time()) if now is None else now
    expires = value.get("expires_at_unix")
    if (
        not isinstance(expires, int)
        or isinstance(expires, bool)
        or expires < current - MAX_CLOCK_SKEW_SECONDS
        or expires > current + MAX_JOB_LIFETIME_SECONDS
    ):
        raise MemberJobError("engine-group job expiry is invalid")
    try:
        group = validate_group_document(value.get("group"))
    except OrchestrationError as error:
        raise MemberJobError(str(error)) from error
    if (
        group.get("group_id") != value["group_id"]
        or group.get("topology_sha256") != value["topology_sha256"]
        or group.get("manifest_sha256") != value["manifest_sha256"]
        or group.get("runtime_digest") != value["runtime_digest"]
    ):
        raise MemberJobError("engine-group job group document is invalid")
    if action == "stage" and source != group["release"]["source"]:
        raise MemberJobError("stage job source does not match the sealed group release")
    if hashlib.sha256(canonical_bytes(group)).hexdigest() != value["plan_sha256"]:
        raise MemberJobError("engine-group job plan digest is invalid")
    matching_resources = [
        item
        for item in group["resources"]
        if isinstance(item, dict) and item.get("node_id") == expected_member_id
    ]
    task = value.get("task")
    if len(matching_resources) != 1 or not isinstance(task, dict):
        raise MemberJobError("engine-group job resource assignment is invalid")
    assignment = matching_resources[0]
    required_task = {
        "task_id", "port_base", "port_count", "launcher", "command", "environment",
        "endpoint_owner", "readiness", "device_uuids",
    }
    if (
        set(task) != required_task
        or task.get("task_id") != assignment.get("task_id")
        or task.get("port_base") != assignment.get("port_base")
        or task.get("port_count") != assignment.get("port_count")
        or task.get("endpoint_owner") is not (task.get("task_id") == group["endpoint_owner"])
        or task.get("device_uuids") != assignment.get("device_uuids")
        or task.get("launcher") not in {"manifest", "runtime-command"}
        or not isinstance(task.get("command"), list)
        or not isinstance(task.get("environment"), dict)
        or not isinstance(task.get("readiness"), dict)
    ):
        raise MemberJobError("engine-group job task does not match its resource assignment")
    _bounded_json(value, "engine-group job", MAX_JOB_BYTES)
    return value


class MemberJobStore:
    """Private durable idempotency and desired-state journal for one member."""

    def __init__(
        self,
        path: pathlib.Path | None = None,
        *,
        recover_incomplete: bool = False,
    ) -> None:
        self.path = (path or default_job_store_path()).expanduser()
        _private_directory(self.path.parent)
        if self.path.is_symlink():
            raise MemberJobError("member job database cannot be a symlink")
        self.connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                plan_sha256 TEXT NOT NULL,
                runtime_digest TEXT NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                topology_sha256 TEXT NOT NULL,
                engine_credential_sha256 TEXT NOT NULL,
                member_id TEXT NOT NULL,
                task_json TEXT NOT NULL,
                source TEXT,
                state TEXT NOT NULL CHECK(state IN ('staged','running','stopped','failed','removed')),
                last_operation_id TEXT NOT NULL,
                updated_at_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS jobs (
                operation_id TEXT PRIMARY KEY,
                job_sha256 TEXT NOT NULL,
                group_id TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('stage','start','recover','stop','remove')),
                state TEXT NOT NULL CHECK(state IN ('running','succeeded','failed')),
                result_json TEXT,
                error TEXT,
                received_at_unix INTEGER NOT NULL,
                finished_at_unix INTEGER
            ) STRICT;
            """
        )
        columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(groups)")
        }
        if "role_json" in columns and "task_json" not in columns:
            self.connection.execute(
                "ALTER TABLE groups RENAME COLUMN role_json TO task_json"
            )
        if recover_incomplete:
            self.connection.execute(
                "UPDATE jobs SET state='failed',"
                "error='member agent restarted during operation',"
                "finished_at_unix=? WHERE state='running'",
                (int(time.time()),),
            )
        self._secure_files()

    def _secure_files(self) -> None:
        for path in (self.path, self.path.with_name(self.path.name + "-wal"), self.path.with_name(self.path.name + "-shm")):
            if path.exists():
                if path.is_symlink() or path.stat().st_uid != os.getuid():
                    raise MemberJobError(f"member job database file is unsafe: {path}")
                path.chmod(0o600)

    def close(self) -> None:
        self.connection.close()
        self._secure_files()

    def __enter__(self) -> "MemberJobStore":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        self.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()
            self._secure_files()

    def begin(self, job: Mapping[str, Any]) -> dict[str, Any] | None:
        serialized = _bounded_json(dict(job), "engine-group job", MAX_JOB_BYTES)
        job_sha256 = hashlib.sha256((serialized + "\n").encode("utf-8")).hexdigest()
        with self.transaction():
            existing = self.connection.execute(
                "SELECT * FROM jobs WHERE operation_id=?", (job["operation_id"],)
            ).fetchone()
            if existing is not None:
                row = dict(existing)
                if row["job_sha256"] != job_sha256:
                    raise MemberJobError("engine-group operation identity was replayed with different bytes")
                if row["state"] == "succeeded":
                    return json.loads(row["result_json"])
                if row["state"] == "failed":
                    raise MemberJobError(str(row["error"] or "engine-group operation failed"))
                raise MemberJobError("engine-group operation is already running")
            group = self.connection.execute(
                "SELECT * FROM groups WHERE group_id=?", (job["group_id"],)
            ).fetchone()
            if group is not None:
                current = dict(group)
                for key in (
                    "plan_sha256", "runtime_digest", "manifest_sha256", "topology_sha256",
                    "engine_credential_sha256", "member_id",
                ):
                    if current[key] != job[key]:
                        raise MemberJobError("engine-group identity changed without a new group identity")
                if current["state"] == "running" and job["action"] in {"stage", "remove"}:
                    raise MemberJobError("a running engine group must be stopped before this action")
                if job["action"] == "start" and current["state"] not in {"staged", "stopped", "running"}:
                    raise MemberJobError("engine group is not staged for start")
                if job["action"] == "recover" and current["state"] not in {
                    "staged", "stopped", "running", "failed",
                }:
                    raise MemberJobError("engine group is not available for recovery")
            elif job["action"] != "stage":
                raise MemberJobError("engine group must be staged before lifecycle actions")
            self.connection.execute(
                "INSERT INTO jobs(operation_id,job_sha256,group_id,action,state,received_at_unix) "
                "VALUES(?,?,?,?, 'running',?)",
                (job["operation_id"], job_sha256, job["group_id"], job["action"], int(time.time())),
            )
        return None

    def finish(self, job: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
        if _contains_sensitive_key(result):
            raise MemberJobError("engine-group result cannot contain credentials or secrets")
        safe_result = dict(result)
        result_json = _bounded_json(safe_result, "engine-group result", MAX_RESULT_BYTES)
        task_json = _bounded_json(job["task"], "engine-group task", MAX_JOB_BYTES)
        state = ACTION_RESULT_STATE[job["action"]]
        now = int(time.time())
        with self.transaction():
            changed = self.connection.execute(
                "UPDATE jobs SET state='succeeded',result_json=?,finished_at_unix=? "
                "WHERE operation_id=? AND state='running'",
                (result_json, now, job["operation_id"]),
            ).rowcount
            if changed != 1:
                raise MemberJobError("engine-group operation state changed concurrently")
            self.connection.execute(
                """INSERT INTO groups
                   (group_id,plan_sha256,runtime_digest,manifest_sha256,topology_sha256,
                    engine_credential_sha256,member_id,task_json,source,state,
                    last_operation_id,updated_at_unix)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(group_id) DO UPDATE SET
                    task_json=excluded.task_json,
                    source=COALESCE(excluded.source,groups.source),
                    state=excluded.state,
                    last_operation_id=excluded.last_operation_id,
                    updated_at_unix=excluded.updated_at_unix""",
                (
                    job["group_id"], job["plan_sha256"], job["runtime_digest"],
                    job["manifest_sha256"], job["topology_sha256"],
                    job["engine_credential_sha256"], job["member_id"], task_json,
                    job["source"], state, job["operation_id"], now,
                ),
            )
        return safe_result

    def fail(self, job: Mapping[str, Any], error: BaseException) -> None:
        reason = _safe_error(error)
        with self.transaction():
            self.connection.execute(
                "UPDATE jobs SET state='failed',error=?,finished_at_unix=? "
                "WHERE operation_id=? AND state='running'",
                (reason, int(time.time()), job["operation_id"]),
            )
            self.connection.execute(
                "UPDATE groups SET state='failed',last_operation_id=?,updated_at_unix=? "
                "WHERE group_id=?",
                (job["operation_id"], int(time.time()), job["group_id"]),
            )

    def group(self, group_id: str) -> dict[str, Any] | None:
        if not ID_RE.fullmatch(group_id):
            raise MemberJobError("engine-group identity is invalid")
        row = self.connection.execute(
            "SELECT * FROM groups WHERE group_id=?", (group_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["task"] = json.loads(result.pop("task_json"))
        return result

    def groups(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for value in self.connection.execute(
            "SELECT * FROM groups ORDER BY updated_at_unix,group_id"
        ):
            row = dict(value)
            row["task"] = json.loads(row.pop("task_json"))
            result.append(row)
        return result

    def job(self, operation_id: str) -> dict[str, Any] | None:
        if not ID_RE.fullmatch(operation_id):
            raise MemberJobError("engine-group operation identity is invalid")
        row = self.connection.execute(
            "SELECT operation_id,group_id,action,state,result_json,error,"
            "received_at_unix,finished_at_unix FROM jobs WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result_json = result.pop("result_json")
        result["result"] = (
            json.loads(result_json)
            if result_json is not None
            else None
        )
        return result


class MemberAgent:
    """Execute only schema-validated group lifecycle operations."""

    def __init__(
        self,
        *,
        member_id: str,
        handler: Callable[[Mapping[str, Any], str | None], Mapping[str, Any]],
        observer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        store_path: pathlib.Path | None = None,
    ) -> None:
        if not ID_RE.fullmatch(member_id):
            raise MemberJobError("member agent identity is invalid")
        self.member_id = member_id
        self.handler = handler
        self.observer = observer
        self.store_path = store_path
        with MemberJobStore(self.store_path, recover_incomplete=True):
            pass
        self._queue: queue.Queue[tuple[dict[str, Any], str | None] | None] = (
            queue.Queue(maxsize=MAX_QUEUED_JOBS)
        )
        self._worker = threading.Thread(
            target=self._work,
            name="letsinfer-child-lifecycle",
            daemon=True,
        )
        self._worker.start()

    def _validated(
        self, payload: Any, engine_credential: str | None
    ) -> dict[str, Any]:
        job = validate_group_job(payload, expected_member_id=self.member_id)
        if job["action"] == "stage":
            try:
                if engine_credential is None or credential_sha256(engine_credential) != job["engine_credential_sha256"]:
                    raise MemberJobError("engine-group stage credential does not match its digest")
            except GroupCredentialError as error:
                raise MemberJobError(str(error)) from error
        elif engine_credential is not None:
            raise MemberJobError("engine-group credentials are accepted only during stage")
        return job

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            job, engine_credential = item
            try:
                result = self.handler(job, engine_credential)
                if not isinstance(result, Mapping):
                    raise MemberJobError(
                        "member lifecycle handler returned an invalid result"
                    )
                with MemberJobStore(self.store_path) as store:
                    store.finish(job, result)
            except BaseException as error:
                try:
                    with MemberJobStore(self.store_path) as store:
                        store.fail(job, error)
                except BaseException:
                    pass
            finally:
                self._queue.task_done()

    def submit(
        self, payload: Any, *, engine_credential: str | None = None
    ) -> dict[str, Any]:
        """Durably accept one bounded job without holding the control request."""
        job = self._validated(payload, engine_credential)
        with MemberJobStore(self.store_path) as store:
            try:
                replay = store.begin(job)
            except MemberJobError as error:
                if str(error) != "engine-group operation is already running":
                    raise
                return {
                    "protocol": PROTOCOL,
                    "operation_id": job["operation_id"],
                    "replayed": True,
                    "state": "running",
                    "result": None,
                }
            if replay is not None:
                return {
                    "protocol": PROTOCOL,
                    "operation_id": job["operation_id"],
                    "replayed": True,
                    "state": "succeeded",
                    "result": replay,
                }
        try:
            self._queue.put_nowait((job, engine_credential))
        except queue.Full as error:
            with MemberJobStore(self.store_path) as store:
                store.fail(job, error)
            raise MemberJobError("member lifecycle queue is full") from error
        return {
            "protocol": PROTOCOL,
            "operation_id": job["operation_id"],
            "replayed": False,
            "state": "running",
            "result": None,
        }

    def execute(
        self, payload: Any, *, engine_credential: str | None = None
    ) -> dict[str, Any]:
        job = self._validated(payload, engine_credential)
        with MemberJobStore(self.store_path) as store:
            replay = store.begin(job)
            if replay is not None:
                return {"protocol": PROTOCOL, "operation_id": job["operation_id"], "replayed": True, "result": replay}
            try:
                result = self.handler(job, engine_credential)
                if not isinstance(result, Mapping):
                    raise MemberJobError("member lifecycle handler returned an invalid result")
                stored = store.finish(job, result)
            except BaseException as error:
                store.fail(job, error)
                if isinstance(error, MemberJobError):
                    raise
                raise MemberJobError(f"engine-group {job['action']} failed: {type(error).__name__}") from error
        return {"protocol": PROTOCOL, "operation_id": job["operation_id"], "replayed": False, "result": stored}

    def status(self, group_id: str) -> dict[str, Any]:
        with MemberJobStore(self.store_path) as store:
            group = store.group(group_id)
        protection_trip_latched = False
        if group is not None and self.observer is not None:
            observation = self.observer(group)
            if (
                not isinstance(observation, Mapping)
                or observation.get("state")
                not in {"staged", "running", "stopped", "failed", "removed"}
                or not isinstance(observation.get("protection_trip_latched"), bool)
            ):
                raise MemberJobError("member group observer returned an invalid state")
            group = {**group, "state": observation["state"]}
            protection_trip_latched = observation["protection_trip_latched"]
        return {
            "protocol": PROTOCOL,
            "group": group,
            "protection_trip_latched": protection_trip_latched,
        }

    def job_status(self, operation_id: str) -> dict[str, Any]:
        with MemberJobStore(self.store_path) as store:
            job = store.job(operation_id)
        return {"protocol": PROTOCOL, "job": job}

    def close(self) -> None:
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            return
