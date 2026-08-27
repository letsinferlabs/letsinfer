#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import hashlib
import pathlib
import tempfile
import threading
import time
import unittest

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

    def test_agent_is_idempotent_and_rejects_changed_replay(self) -> None:
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=pathlib.Path(directory) / "jobs.sqlite3",
                handler=lambda job, _credential: calls.append(job["action"]) or {"state": "staged"},
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
                handler=lambda job, _credential: {"state": job["action"]},
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
                handler=lambda _job, _credential: {"api_token": "do-not-store"},
            )
            with self.assertRaisesRegex(MemberJobError, "credentials or secrets"):
                agent.execute(self.job(), engine_credential=self.credential)

    def test_status_uses_live_observer_and_reports_trip_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            agent = MemberAgent(
                member_id=self.node_id,
                store_path=pathlib.Path(directory) / "jobs.sqlite3",
                handler=lambda job, _credential: {"state": job["action"]},
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

        def handler(job, credential):
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

    def test_async_failure_retains_bounded_redacted_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "jobs.sqlite3"

            def fail(_job, _credential):
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
