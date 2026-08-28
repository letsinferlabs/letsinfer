#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import hashlib
import pathlib
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from core.site import control
from core.orchestration.member import (
    MemberAgent,
    MemberJobError,
    MemberJobStore,
    PROTOCOL,
    canonical_bytes,
    validate_placement_job,
)
from core.orchestration import build_single_placement_group_plan
from core.orchestration.credentials import credential_sha256
from tests.orchestration.helpers import release_identity


class MemberJobTests(unittest.TestCase):
    node_id = "1" * 32
    credential = "A" * 43

    def legacy_database(
        self,
        path: pathlib.Path,
        *,
        group_state: str = "removed",
        job_state: str = "succeeded",
    ) -> None:
        """Create the exact schema-three member journal around legacy group IDs."""
        connection = sqlite3.connect(path)
        connection.executescript(
            """
            CREATE TABLE groups (
                group_id TEXT PRIMARY KEY,
                plan_sha256 TEXT NOT NULL,
                runtime_digest TEXT NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                topology_sha256 TEXT NOT NULL,
                engine_credential_sha256 TEXT NOT NULL,
                member_id TEXT NOT NULL,
                task_json TEXT NOT NULL,
                source TEXT,
                state TEXT NOT NULL
                  CHECK(state IN ('staged','running','stopped','failed','removed')),
                last_operation_id TEXT NOT NULL,
                updated_at_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE jobs (
                operation_id TEXT PRIMARY KEY,
                job_sha256 TEXT NOT NULL,
                group_id TEXT NOT NULL,
                action TEXT NOT NULL
                  CHECK(action IN ('stage','start','recover','stop','remove')),
                state TEXT NOT NULL CHECK(state IN ('running','succeeded','failed')),
                result_json TEXT,
                error TEXT,
                received_at_unix INTEGER NOT NULL,
                finished_at_unix INTEGER
            ) STRICT;
            """
        )
        group_id = "7" * 32
        operation_id = "8" * 32
        connection.execute(
            "INSERT INTO groups VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                group_id,
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
                "5" * 64,
                self.node_id,
                "{}",
                "registry.example/runtime@sha256:" + "6" * 64,
                group_state,
                operation_id,
                1_800_000_000,
            ),
        )
        connection.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)",
            (
                operation_id,
                "9" * 64,
                group_id,
                "remove",
                job_state,
                "{}" if job_state == "succeeded" else None,
                None,
                1_800_000_000,
                None if job_state == "running" else 1_800_000_001,
            ),
        )
        connection.commit()
        connection.close()

    def job(self, *, action: str = "stage", operation_id: str = "2" * 32) -> dict:
        release = release_identity()
        plan = build_single_placement_group_plan(
            member_id=self.node_id,
            member_address="member.local:9770",
            device_uuids=["GPU-fixture"],
            topology_sha256="4" * 64,
            manifest_sha256="5" * 64,
            runtime_digest="6" * 64,
            service_id="3" * 32,
            release=release,
            port_base=18000,
        )
        group = plan.document()
        placement = plan.placements[0]
        return {
            "protocol": PROTOCOL,
            "operation_id": operation_id,
            "placement_group_id": group["placement_group_id"],
            "placement_id": placement.placement_id,
            "action": action,
            "node_id": self.node_id,
            "plan_sha256": hashlib.sha256(canonical_bytes(group)).hexdigest(),
            "runtime_digest": group["runtime_digest"],
            "manifest_sha256": group["manifest_sha256"],
            "topology_sha256": group["topology_sha256"],
            "engine_credential_sha256": credential_sha256(self.credential),
            "expires_at_unix": int(time.time()) + 60,
            "source": release["source"] if action == "stage" else None,
            "placement": {
                "placement_id": placement.placement_id,
                "node_id": placement.node_id,
                "task_id": placement.task_id,
                "launcher": placement.launcher,
                "port_base": placement.port_base,
                "port_count": placement.port_count,
                "command": list(placement.command),
                "environment": dict(placement.environment),
                "endpoint_owner": placement.endpoint_owner,
                "readiness": dict(placement.readiness),
                "device_uuids": list(placement.device_uuids),
            },
            "placement_group": group,
        }

    def test_validation_binds_target_member_plan_and_pinned_source(self) -> None:
        value = self.job()
        self.assertIs(validate_placement_job(value, expected_node_id=self.node_id), value)
        changed = self.job()
        changed["placement_group"]["placements"][0]["address"] = "changed.local:9770"
        with self.assertRaisesRegex(MemberJobError, "identity does not match"):
            validate_placement_job(changed, expected_node_id=self.node_id)
        changed = self.job()
        changed["source"] = "registry.example/runtime:latest"
        with self.assertRaisesRegex(MemberJobError, "immutable"):
            validate_placement_job(changed, expected_node_id=self.node_id)

    def test_terminal_schema_three_member_journal_resets_before_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "jobs.sqlite3"
            self.legacy_database(database)
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=database,
                handler=lambda job, _credential, _cancelled: {
                    "state": job["action"]
                },
            )

            result = agent.execute(
                self.job(), engine_credential=self.credential
            )

            self.assertEqual(result["result"], {"state": "stage"})
            with MemberJobStore(database) as store:
                tables = {
                    row["name"]
                    for row in store.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                job_columns = {
                    row["name"]
                    for row in store.connection.execute("PRAGMA table_info(jobs)")
                }
            self.assertNotIn("groups", tables)
            self.assertIn("placement_group_id", job_columns)
            self.assertIn("placement_id", job_columns)
            self.assertNotIn("group_id", job_columns)

    def test_active_schema_three_member_journal_fails_closed(self) -> None:
        for group_state, job_state in (
            ("running", "succeeded"),
            ("removed", "running"),
            ("failed", "failed"),
        ):
            with self.subTest(group_state=group_state, job_state=job_state):
                with tempfile.TemporaryDirectory() as directory:
                    database = pathlib.Path(directory) / "jobs.sqlite3"
                    self.legacy_database(
                        database,
                        group_state=group_state,
                        job_state=job_state,
                    )
                    with self.assertRaisesRegex(
                        MemberJobError,
                        "legacy member job state must be stopped or removed",
                    ):
                        MemberJobStore(database)

    def test_disappearing_sqlite_sidecar_is_a_benign_close_race(self) -> None:
        """Tolerate SQLite unlinking a WAL sidecar while its mode is secured."""
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "jobs.sqlite3"
            sidecar = database.with_name(database.name + "-shm")
            store = MemberJobStore(database)
            real_exists = pathlib.Path.exists
            real_stat = pathlib.Path.stat

            def exists(path: pathlib.Path) -> bool:
                return True if path == sidecar else real_exists(path)

            def file_stat(path: pathlib.Path, *arguments, **options):
                if path == sidecar:
                    raise FileNotFoundError(sidecar)
                return real_stat(path, *arguments, **options)

            with (
                mock.patch.object(pathlib.Path, "exists", exists),
                mock.patch.object(pathlib.Path, "stat", file_stat),
            ):
                store._secure_files()
            store.close()

    def test_agent_is_idempotent_and_rejects_changed_replay(self) -> None:
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=pathlib.Path(directory) / "jobs.sqlite3",
                handler=lambda job, _credential, _cancelled: calls.append(job["action"]) or {"state": "staged"},
            )
            job = self.job()
            first = agent.execute(job, engine_credential=self.credential)
            second = agent.execute(job, engine_credential=self.credential)
            self.assertFalse(first["replayed"])
            self.assertTrue(second["replayed"])
            self.assertEqual(calls, ["stage"])
            changed = {**job, "expires_at_unix": job["expires_at_unix"] + 1}
            with self.assertRaisesRegex(MemberJobError, "different bytes"):
                agent.execute(changed, engine_credential=self.credential)

    def test_lifecycle_requires_stage_and_stop_before_remove(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=pathlib.Path(directory) / "jobs.sqlite3",
                handler=lambda job, _credential, _cancelled: {"state": job["action"]},
            )
            with self.assertRaisesRegex(MemberJobError, "staged"):
                agent.execute(self.job(action="start"))
            agent.execute(self.job(), engine_credential=self.credential)
            agent.execute(self.job(action="start", operation_id="9" * 32))
            with self.assertRaisesRegex(MemberJobError, "must be stopped"):
                agent.execute(self.job(action="remove", operation_id="a" * 32))
            agent.execute(self.job(action="stop", operation_id="b" * 32))
            removed = agent.execute(self.job(action="remove", operation_id="c" * 32))
            self.assertEqual(removed["result"]["state"], "remove")

    def test_result_storage_rejects_sensitive_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=pathlib.Path(directory) / "jobs.sqlite3",
                handler=lambda _job, _credential, _cancelled: {"api_token": "do-not-store"},
            )
            with self.assertRaisesRegex(MemberJobError, "credentials or secrets"):
                agent.execute(self.job(), engine_credential=self.credential)

    def test_status_uses_live_observer_and_reports_trip_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=pathlib.Path(directory) / "jobs.sqlite3",
                handler=lambda job, _credential, _cancelled: {"state": job["action"]},
                observer=lambda _group: {
                    "state": "failed",
                    "protection_trip_latched": True,
                },
            )
            stage = self.job()
            agent.execute(stage, engine_credential=self.credential)
            status = agent.status(stage["placement_group_id"])
            self.assertEqual(status["placement"]["state"], "failed")
            self.assertTrue(status["protection_trip_latched"])

    def test_submit_is_durable_and_asynchronous_for_long_lifecycle_work(self) -> None:
        started = threading.Event()
        release = threading.Event()

        def handler(job, credential, _cancelled):
            self.assertEqual(credential, self.credential)
            started.set()
            release.wait(timeout=5)
            return {"state": job["action"]}

        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "jobs.sqlite3"
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=database,
                handler=handler,
            )
            accepted = agent.submit(
                self.job(), engine_credential=self.credential
            )
            self.assertEqual(accepted["state"], "running")
            self.assertIsNone(accepted["result"])
            self.assertTrue(started.wait(timeout=2))
            self.assertEqual(
                agent.job_status("2" * 32)["job"]["state"], "running"
            )
            self.assertNotIn(self.credential.encode("ascii"), database.read_bytes())
            release.set()
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                status = agent.job_status("2" * 32)["job"]
                if status["state"] == "succeeded":
                    break
                time.sleep(0.01)
            self.assertEqual(status["result"], {"state": "stage"})

    def test_completed_job_status_round_trips_through_control_client(self) -> None:
        """Accept the exact completed MemberAgent payload at the coordinator boundary."""
        with tempfile.TemporaryDirectory() as directory:
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=pathlib.Path(directory) / "jobs.sqlite3",
                handler=lambda job, _credential, _cancelled: {
                    "state": job["action"]
                },
            )
            job = self.job()
            agent.execute(job, engine_credential=self.credential)
            response = agent.job_status(job["operation_id"])

            with mock.patch.object(
                control,
                "_member_control_request",
                return_value=response,
            ):
                observed = control.fetch_member_job_status(
                    "https://node.example:9770",
                    expected_member_id=self.node_id,
                    expected_certificate_sha256="f" * 64,
                    operation_id=job["operation_id"],
                )

            self.assertEqual(observed, response)
            self.assertEqual(
                observed["job"]["placement_id"], job["placement_id"]
            )
            malformed = {
                **response,
                "job": {**response["job"], "placement_id": "not-an-id"},
            }
            with (
                mock.patch.object(
                    control,
                    "_member_control_request",
                    return_value=malformed,
                ),
                self.assertRaisesRegex(
                    control.ControlError, "job-status payload"
                ),
            ):
                control.fetch_member_job_status(
                    "https://node.example:9770",
                    expected_member_id=self.node_id,
                    expected_certificate_sha256="f" * 64,
                    operation_id=job["operation_id"],
                )

    def test_stop_preempts_a_running_start_on_the_control_worker(self) -> None:
        start_entered = threading.Event()
        stop_entered = threading.Event()

        def handler(job, _credential, cancelled):
            if job["action"] == "start":
                start_entered.set()
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and not cancelled():
                    time.sleep(0.01)
                if cancelled():
                    raise RuntimeError("start cancelled")
                raise RuntimeError("start was not preempted")
            if job["action"] == "stop":
                stop_entered.set()
            return {"state": job["action"]}

        with tempfile.TemporaryDirectory() as directory:
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=pathlib.Path(directory) / "jobs.sqlite3",
                handler=handler,
            )
            staged = self.job()
            agent.execute(staged, engine_credential=self.credential)
            start = self.job(action="start", operation_id="9" * 32)
            stop = self.job(action="stop", operation_id="a" * 32)

            agent.submit(start)
            self.assertTrue(start_entered.wait(timeout=1))
            agent.submit(stop)
            self.assertTrue(stop_entered.wait(timeout=1))

            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                start_status = agent.job_status(start["operation_id"])["job"]
                stop_status = agent.job_status(stop["operation_id"])["job"]
                if (
                    start_status["state"] == "failed"
                    and stop_status["state"] == "succeeded"
                ):
                    break
                time.sleep(0.01)

            self.assertEqual(start_status["state"], "failed")
            self.assertEqual(
                start_status["error"],
                "placement start was preempted by stop",
            )
            self.assertEqual(stop_status["state"], "succeeded")
            placement = agent.status(staged["placement_group_id"])["placement"]
            self.assertEqual(placement["state"], "stopped")

    def test_async_failure_retains_bounded_redacted_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "jobs.sqlite3"

            def fail(_job, _credential, _cancelled):
                raise RuntimeError("adapter failed; api_key=do-not-store")

            agent = MemberAgent(
                member_id=self.node_id,
                store_path=database,
                handler=fail,
            )
            agent.submit(self.job(), engine_credential=self.credential)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                status = agent.job_status("2" * 32)["job"]
                if status["state"] == "failed":
                    break
                time.sleep(0.01)

            self.assertEqual(status["state"], "failed")
            self.assertNotIn("result_json", status)
            self.assertEqual(
                status["error"],
                "RuntimeError: adapter failed; api_key=[REDACTED]",
            )
            self.assertNotIn(b"do-not-store", database.read_bytes())


if __name__ == "__main__":
    unittest.main()
