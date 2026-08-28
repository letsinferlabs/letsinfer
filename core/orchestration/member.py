#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, idempotent member execution for placement-group lifecycle jobs."""

from __future__ import annotations

import contextlib
import dataclasses
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

from .contracts import OrchestrationError, validate_placement_group_document
from .credentials import PlacementGroupCredentialError, credential_sha256
from ..paths import data_root
from ..runtime_sources import is_immutable_runtime_source


PROTOCOL = "letsinfer-placement-job-v1"
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_JOB_BYTES = 16 * 1024
MAX_RESULT_BYTES = 16 * 1024
MAX_CLOCK_SKEW_SECONDS = 30
MAX_JOB_LIFETIME_SECONDS = 300
MAX_QUEUED_JOBS = 16
FINAL_JOB_STATES = {"succeeded", "failed"}
PLACEMENT_STATES = {"staged", "running", "stopped", "failed", "removed"}
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
MEMBER_JOB_SCHEMA = """
CREATE TABLE IF NOT EXISTS placements (
    placement_id TEXT PRIMARY KEY,
    placement_group_id TEXT NOT NULL UNIQUE,
    plan_sha256 TEXT NOT NULL,
    runtime_digest TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    topology_sha256 TEXT NOT NULL,
    engine_credential_sha256 TEXT NOT NULL,
    node_id TEXT NOT NULL,
    placement_json TEXT NOT NULL,
    source TEXT,
    state TEXT NOT NULL CHECK(state IN ('staged','running','stopped','failed','removed')),
    last_operation_id TEXT NOT NULL,
    updated_at_unix INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS jobs (
    operation_id TEXT PRIMARY KEY,
    job_sha256 TEXT NOT NULL,
    placement_group_id TEXT NOT NULL,
    placement_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('stage','start','recover','stop','remove')),
    state TEXT NOT NULL CHECK(state IN ('running','succeeded','failed')),
    result_json TEXT,
    error TEXT,
    received_at_unix INTEGER NOT NULL,
    finished_at_unix INTEGER
) STRICT;
"""


class MemberJobError(RuntimeError):
    """A placement job is unauthenticated, invalid, replayed, or failed."""


@dataclasses.dataclass(frozen=True)
class MemberJobAdmission:
    """The durable result of accepting one member lifecycle operation."""

    replay: dict[str, Any] | None
    preempted_operation_ids: tuple[str, ...]


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


def validate_placement_job(
    value: Any,
    *,
    expected_node_id: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Validate an exact coordinator-issued member lifecycle job."""
    required = {
        "protocol",
        "operation_id",
        "placement_group_id",
        "placement_id",
        "action",
        "node_id",
        "plan_sha256",
        "runtime_digest",
        "manifest_sha256",
        "topology_sha256",
        "engine_credential_sha256",
        "expires_at_unix",
        "source",
        "placement",
        "placement_group",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("protocol") != PROTOCOL:
        raise MemberJobError("placement-group job schema is invalid")
    for key in ("operation_id", "placement_group_id", "placement_id", "node_id"):
        if not isinstance(value.get(key), str) or not ID_RE.fullmatch(value[key]):
            raise MemberJobError(f"placement-group job {key} is invalid")
    if value["node_id"] != expected_node_id:
        raise MemberJobError("placement job targets a different node")
    for key in (
        "plan_sha256", "runtime_digest", "manifest_sha256", "topology_sha256",
        "engine_credential_sha256",
    ):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise MemberJobError(f"placement-group job {key} is invalid")
    action = value.get("action")
    if action not in ACTION_RESULT_STATE:
        raise MemberJobError("placement-group job action is invalid")
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
        raise MemberJobError("placement-group job expiry is invalid")
    try:
        placement_group = validate_placement_group_document(
            value.get("placement_group")
        )
    except OrchestrationError as error:
        raise MemberJobError(str(error)) from error
    if (
        placement_group.get("placement_group_id") != value["placement_group_id"]
        or placement_group.get("topology_sha256") != value["topology_sha256"]
        or placement_group.get("manifest_sha256") != value["manifest_sha256"]
        or placement_group.get("runtime_digest") != value["runtime_digest"]
    ):
        raise MemberJobError("placement-group job group document is invalid")
    if action == "stage" and source != placement_group["release"]["source"]:
        raise MemberJobError(
            "stage job source does not match the sealed placement-group release"
        )
    if (
        hashlib.sha256(canonical_bytes(placement_group)).hexdigest()
        != value["plan_sha256"]
    ):
        raise MemberJobError("placement-group job plan digest is invalid")
    matching_placements = [
        item
        for item in placement_group["placements"]
        if isinstance(item, dict)
        and item.get("placement_id") == value["placement_id"]
        and item.get("node_id") == expected_node_id
    ]
    placement = value.get("placement")
    if len(matching_placements) != 1 or not isinstance(placement, dict):
        raise MemberJobError("placement job assignment is invalid")
    planned = matching_placements[0]
    required_placement = {
        "placement_id", "node_id", "task_id", "port_base", "port_count",
        "launcher", "command", "environment", "endpoint_owner", "readiness",
        "device_uuids",
    }
    if (
        set(placement) != required_placement
        or placement.get("placement_id") != planned.get("placement_id")
        or placement.get("node_id") != planned.get("node_id")
        or placement.get("task_id") != planned.get("task_id")
        or placement.get("port_base") != planned.get("port_base")
        or placement.get("port_count") != planned.get("port_count")
        or placement.get("endpoint_owner")
        is not (
            placement.get("placement_id")
            == placement_group["endpoint_placement_id"]
        )
        or placement.get("device_uuids") != planned.get("device_uuids")
        or placement.get("launcher") not in {"manifest", "runtime-command"}
        or not isinstance(placement.get("command"), list)
        or not isinstance(placement.get("environment"), dict)
        or not isinstance(placement.get("readiness"), dict)
    ):
        raise MemberJobError("placement job does not match its sealed assignment")
    _bounded_json(value, "placement job", MAX_JOB_BYTES)
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
        self.connection.executescript(MEMBER_JOB_SCHEMA)
        self._migrate_legacy_schema()
        if recover_incomplete:
            self.connection.execute(
                "UPDATE jobs SET state='failed',"
                "error='member agent restarted during operation',"
                "finished_at_unix=? WHERE state='running'",
                (int(time.time()),),
            )
        self._secure_files()

    def _migrate_legacy_schema(self) -> None:
        """Reset a terminal schema-three journal without discarding active work."""
        job_columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(jobs)")
        }
        if "group_id" not in job_columns:
            if not {"placement_group_id", "placement_id"}.issubset(job_columns):
                raise MemberJobError("member job database schema is invalid")
            return
        group_columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(groups)")
        }
        if not {"group_id", "state"}.issubset(group_columns):
            raise MemberJobError("legacy member job database schema is invalid")
        running_jobs = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE state='running'"
            ).fetchone()[0]
        )
        potentially_active = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM groups WHERE state NOT IN ('stopped','removed')"
            ).fetchone()[0]
        )
        current_placements = int(
            self.connection.execute("SELECT COUNT(*) FROM placements").fetchone()[0]
        )
        if running_jobs or potentially_active or current_placements:
            raise MemberJobError(
                "legacy member job state must be stopped or removed before the "
                "placement journal cut"
            )
        try:
            self.connection.executescript(
                """
                BEGIN IMMEDIATE;
                DROP TABLE jobs;
                DROP TABLE groups;
                DROP TABLE placements;
                """
                + MEMBER_JOB_SCHEMA
                + "COMMIT;"
            )
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

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

    def begin(self, job: Mapping[str, Any]) -> MemberJobAdmission:
        serialized = _bounded_json(dict(job), "placement-group job", MAX_JOB_BYTES)
        job_sha256 = hashlib.sha256((serialized + "\n").encode("utf-8")).hexdigest()
        with self.transaction():
            existing = self.connection.execute(
                "SELECT * FROM jobs WHERE operation_id=?", (job["operation_id"],)
            ).fetchone()
            if existing is not None:
                row = dict(existing)
                if row["job_sha256"] != job_sha256:
                    raise MemberJobError("placement-group operation identity was replayed with different bytes")
                if row["state"] == "succeeded":
                    return MemberJobAdmission(
                        replay=json.loads(row["result_json"]),
                        preempted_operation_ids=(),
                    )
                if row["state"] == "failed":
                    raise MemberJobError(str(row["error"] or "placement-group operation failed"))
                raise MemberJobError("placement-group operation is already running")
            placement = self.connection.execute(
                "SELECT * FROM placements WHERE placement_id=?", (job["placement_id"],)
            ).fetchone()
            if placement is not None:
                current = dict(placement)
                for key in (
                    "plan_sha256", "runtime_digest", "manifest_sha256", "topology_sha256",
                    "engine_credential_sha256", "placement_group_id", "node_id",
                ):
                    if current[key] != job[key]:
                        raise MemberJobError(
                            "placement identity changed without a new placement identity"
                        )
                if current["state"] == "running" and job["action"] in {"stage", "remove"}:
                    raise MemberJobError("a running placement must be stopped before this action")
                if job["action"] == "start" and current["state"] not in {"staged", "stopped", "running"}:
                    raise MemberJobError("placement is not staged for start")
                if job["action"] == "recover" and current["state"] not in {
                    "staged", "stopped", "running", "failed",
                }:
                    raise MemberJobError("placement is not available for recovery")
            elif job["action"] != "stage":
                raise MemberJobError("placement must be staged before lifecycle actions")
            running = [
                dict(row)
                for row in self.connection.execute(
                    "SELECT operation_id,action FROM jobs "
                    "WHERE placement_id=? AND state='running' ORDER BY received_at_unix,operation_id",
                    (job["placement_id"],),
                )
            ]
            preempted_operation_ids: tuple[str, ...] = ()
            if running:
                if job["action"] != "stop" or any(
                    row["action"] not in {"start", "recover"} for row in running
                ):
                    raise MemberJobError(
                        "another placement operation is already running"
                    )
                preempted_operation_ids = tuple(
                    str(row["operation_id"]) for row in running
                )
                placeholders = ",".join("?" for _item in preempted_operation_ids)
                self.connection.execute(
                    "UPDATE jobs SET state='failed',error=?,finished_at_unix=? "
                    f"WHERE operation_id IN ({placeholders}) AND state='running'",
                    (
                        "placement start was preempted by stop",
                        int(time.time()),
                        *preempted_operation_ids,
                    ),
                )
            self.connection.execute(
                "INSERT INTO jobs(operation_id,job_sha256,placement_group_id,placement_id,action,state,received_at_unix) "
                "VALUES(?,?,?,?,?, 'running',?)",
                (
                    job["operation_id"], job_sha256, job["placement_group_id"],
                    job["placement_id"], job["action"], int(time.time()),
                ),
            )
            if placement is not None:
                self.connection.execute(
                    "UPDATE placements SET last_operation_id=?,updated_at_unix=? "
                    "WHERE placement_id=?",
                    (
                        job["operation_id"],
                        int(time.time()),
                        job["placement_id"],
                    ),
                )
        return MemberJobAdmission(
            replay=None,
            preempted_operation_ids=preempted_operation_ids,
        )

    def finish(self, job: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
        if _contains_sensitive_key(result):
            raise MemberJobError("placement-group result cannot contain credentials or secrets")
        safe_result = dict(result)
        result_json = _bounded_json(safe_result, "placement-group result", MAX_RESULT_BYTES)
        placement_json = _bounded_json(
            job["placement"], "placement", MAX_JOB_BYTES
        )
        state = ACTION_RESULT_STATE[job["action"]]
        now = int(time.time())
        with self.transaction():
            changed = self.connection.execute(
                "UPDATE jobs SET state='succeeded',result_json=?,finished_at_unix=? "
                "WHERE operation_id=? AND state='running'",
                (result_json, now, job["operation_id"]),
            ).rowcount
            if changed != 1:
                raise MemberJobError("placement-group operation state changed concurrently")
            current = self.connection.execute(
                "SELECT last_operation_id FROM placements WHERE placement_id=?",
                (job["placement_id"],),
            ).fetchone()
            if (
                current is not None
                and current["last_operation_id"] != job["operation_id"]
            ):
                raise MemberJobError(
                    "placement-group operation was superseded concurrently"
                )
            self.connection.execute(
                """INSERT INTO placements
                   (placement_id,placement_group_id,plan_sha256,runtime_digest,
                    manifest_sha256,topology_sha256,engine_credential_sha256,
                    node_id,placement_json,source,state,
                    last_operation_id,updated_at_unix)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(placement_id) DO UPDATE SET
                    placement_json=excluded.placement_json,
                    source=COALESCE(excluded.source,placements.source),
                    state=excluded.state,
                    last_operation_id=excluded.last_operation_id,
                    updated_at_unix=excluded.updated_at_unix""",
                (
                    job["placement_id"], job["placement_group_id"],
                    job["plan_sha256"], job["runtime_digest"],
                    job["manifest_sha256"], job["topology_sha256"],
                    job["engine_credential_sha256"], job["node_id"],
                    placement_json, job["source"], state, job["operation_id"], now,
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
                "UPDATE placements SET state='failed',last_operation_id=?,updated_at_unix=? "
                "WHERE placement_id=? AND last_operation_id=?",
                (
                    job["operation_id"],
                    int(time.time()),
                    job["placement_id"],
                    job["operation_id"],
                ),
            )

    def is_running(self, operation_id: str) -> bool:
        """Return whether an admitted operation still owns execution."""
        if not ID_RE.fullmatch(operation_id):
            raise MemberJobError("placement-group operation identity is invalid")
        row = self.connection.execute(
            "SELECT state FROM jobs WHERE operation_id=?", (operation_id,)
        ).fetchone()
        return row is not None and row["state"] == "running"

    def placement_for_group(self, placement_group_id: str) -> dict[str, Any] | None:
        if not ID_RE.fullmatch(placement_group_id):
            raise MemberJobError("placement-group identity is invalid")
        row = self.connection.execute(
            "SELECT * FROM placements WHERE placement_group_id=?", (placement_group_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["placement"] = json.loads(result.pop("placement_json"))
        return result

    def placements(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for value in self.connection.execute(
            "SELECT * FROM placements ORDER BY updated_at_unix,placement_id"
        ):
            row = dict(value)
            row["placement"] = json.loads(row.pop("placement_json"))
            result.append(row)
        return result

    def job(self, operation_id: str) -> dict[str, Any] | None:
        if not ID_RE.fullmatch(operation_id):
            raise MemberJobError("placement-group operation identity is invalid")
        row = self.connection.execute(
            "SELECT operation_id,placement_group_id,placement_id,action,state,result_json,error,"
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
    """Execute only schema-validated placement lifecycle operations."""

    def __init__(
        self,
        *,
        member_id: str,
        handler: Callable[
            [Mapping[str, Any], str | None, Callable[[], bool]],
            Mapping[str, Any],
        ],
        observer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        store_path: pathlib.Path | None = None,
    ) -> None:
        if not ID_RE.fullmatch(member_id):
            raise MemberJobError("member agent identity is invalid")
        self.node_id = member_id
        self.handler = handler
        self.observer = observer
        self.store_path = store_path
        with MemberJobStore(self.store_path, recover_incomplete=True):
            pass
        self._ordinary_queue: queue.Queue[
            tuple[dict[str, Any], str | None] | None
        ] = (
            queue.Queue(maxsize=MAX_QUEUED_JOBS)
        )
        self._control_queue: queue.Queue[
            tuple[dict[str, Any], str | None] | None
        ] = queue.Queue(maxsize=MAX_QUEUED_JOBS)
        self._active_lock = threading.Lock()
        self._active_cancellations: dict[str, threading.Event] = {}
        self._ordinary_worker = threading.Thread(
            target=self._work,
            args=(self._ordinary_queue,),
            name="letsinfer-child-lifecycle",
            daemon=True,
        )
        self._control_worker = threading.Thread(
            target=self._work,
            args=(self._control_queue,),
            name="letsinfer-child-lifecycle-control",
            daemon=True,
        )
        self._ordinary_worker.start()
        self._control_worker.start()

    def _validated(
        self, payload: Any, engine_credential: str | None
    ) -> dict[str, Any]:
        job = validate_placement_job(payload, expected_node_id=self.node_id)
        if job["action"] == "stage":
            try:
                if engine_credential is None or credential_sha256(engine_credential) != job["engine_credential_sha256"]:
                    raise MemberJobError("placement-group stage credential does not match its digest")
            except PlacementGroupCredentialError as error:
                raise MemberJobError(str(error)) from error
        elif engine_credential is not None:
            raise MemberJobError("placement-group credentials are accepted only during stage")
        return job

    def _cancel_operations(self, operation_ids: tuple[str, ...]) -> None:
        """Signal every active operation superseded by an accepted stop."""
        with self._active_lock:
            for operation_id in operation_ids:
                cancellation = self._active_cancellations.get(operation_id)
                if cancellation is not None:
                    cancellation.set()

    def _work(
        self,
        work_queue: queue.Queue[tuple[dict[str, Any], str | None] | None],
    ) -> None:
        """Execute one bounded queue while preserving durable supersession."""
        while True:
            item = work_queue.get()
            if item is None:
                work_queue.task_done()
                return
            job, engine_credential = item
            cancellation = threading.Event()
            with self._active_lock:
                self._active_cancellations[job["operation_id"]] = cancellation
            try:
                with MemberJobStore(self.store_path) as store:
                    if not store.is_running(job["operation_id"]):
                        continue
                result = self.handler(
                    job, engine_credential, cancellation.is_set
                )
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
                with self._active_lock:
                    self._active_cancellations.pop(job["operation_id"], None)
                work_queue.task_done()

    def submit(
        self, payload: Any, *, engine_credential: str | None = None
    ) -> dict[str, Any]:
        """Durably accept one bounded job without holding the control request."""
        job = self._validated(payload, engine_credential)
        with MemberJobStore(self.store_path) as store:
            try:
                admission = store.begin(job)
            except MemberJobError as error:
                if str(error) != "placement-group operation is already running":
                    raise
                return {
                    "protocol": PROTOCOL,
                    "operation_id": job["operation_id"],
                    "replayed": True,
                    "state": "running",
                    "result": None,
                }
            if admission.replay is not None:
                return {
                    "protocol": PROTOCOL,
                    "operation_id": job["operation_id"],
                    "replayed": True,
                    "state": "succeeded",
                    "result": admission.replay,
                }
        self._cancel_operations(admission.preempted_operation_ids)
        work_queue = (
            self._control_queue
            if job["action"] in {"stop", "remove"}
            else self._ordinary_queue
        )
        try:
            work_queue.put_nowait((job, engine_credential))
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
            admission = store.begin(job)
            if admission.replay is not None:
                return {"protocol": PROTOCOL, "operation_id": job["operation_id"], "replayed": True, "result": admission.replay}
            self._cancel_operations(admission.preempted_operation_ids)
            cancellation = threading.Event()
            with self._active_lock:
                self._active_cancellations[job["operation_id"]] = cancellation
            try:
                result = self.handler(
                    job, engine_credential, cancellation.is_set
                )
                if not isinstance(result, Mapping):
                    raise MemberJobError("member lifecycle handler returned an invalid result")
                stored = store.finish(job, result)
            except BaseException as error:
                store.fail(job, error)
                if isinstance(error, MemberJobError):
                    raise
                raise MemberJobError(f"placement-group {job['action']} failed: {type(error).__name__}") from error
            finally:
                with self._active_lock:
                    self._active_cancellations.pop(job["operation_id"], None)
        return {"protocol": PROTOCOL, "operation_id": job["operation_id"], "replayed": False, "result": stored}

    def status(self, placement_group_id: str) -> dict[str, Any]:
        with MemberJobStore(self.store_path) as store:
            placement = store.placement_for_group(placement_group_id)
        protection_trip_latched = False
        if placement is not None and self.observer is not None:
            observation = self.observer(placement)
            if (
                not isinstance(observation, Mapping)
                or observation.get("state")
                not in {"staged", "running", "stopped", "failed", "removed"}
                or not isinstance(observation.get("protection_trip_latched"), bool)
            ):
                raise MemberJobError("placement observer returned an invalid state")
            placement = {**placement, "state": observation["state"]}
            protection_trip_latched = observation["protection_trip_latched"]
        return {
            "protocol": PROTOCOL,
            "placement": placement,
            "protection_trip_latched": protection_trip_latched,
        }

    def job_status(self, operation_id: str) -> dict[str, Any]:
        with MemberJobStore(self.store_path) as store:
            job = store.job(operation_id)
        return {"protocol": PROTOCOL, "job": job}

    def close(self) -> None:
        """Request bounded shutdown of both ordinary and control workers."""
        for work_queue in (self._ordinary_queue, self._control_queue):
            try:
                work_queue.put_nowait(None)
            except queue.Full:
                continue
