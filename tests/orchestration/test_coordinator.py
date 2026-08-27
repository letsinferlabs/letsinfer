#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import os
import pathlib
import tempfile
import threading
import unittest
from unittest import mock

from core.orchestration import build_placement_group_plan
from core.orchestration.coordinator import (
    allocate_placement_ports,
    PlacementGroupOrchestrator,
    PlacementGroupOrchestrationError,
)
from core.orchestration.member import PROTOCOL
from core.orchestration.credentials import (
    credential_sha256,
    derive_placement_group_credential,
)
from core.site import state
from tests.gateway.helpers import insert_member, routing_facts, set_member_facts
from tests.orchestration.helpers import (
    parallel_connections,
    parallel_contract,
    release_identity,
)


class CoordinatorOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.environment = mock.patch.dict(
            os.environ, {"LETSINFER_HOME": str(root)}
        )
        self.environment.start()
        self.identity = state.setup_site()
        self.members = (self.identity.member_id, "e" * 32, "f" * 32)
        self.contract = parallel_contract()
        self.release = release_identity(
            manifest_sha256="2" * 64,
            runtime_digest="3" * 64,
        )
        self.store = state.SiteStore(identity=self.identity)
        set_member_facts(
            self.store,
            self.identity.member_id,
            routing_facts(self.identity.member_id),
        )
        insert_member(self.store, "e" * 32)
        insert_member(self.store, "f" * 32)
        self.service_id = self.store.ensure_model_service("model")["service_id"]
        self.plan = build_placement_group_plan(
            self.contract,
            member_ids=self.members,
            member_addresses={item: f"{index}.local:9770" for index, item in enumerate(self.members)},
            topology_sha256="1" * 64,
            manifest_sha256="2" * 64,
            runtime_digest="3" * 64,
            service_id=self.service_id,
            release=self.release,
            member_port_bases={item: 18000 for item in self.members},
            member_device_uuids={
                item: [f"GPU-{item[:8]}"] for item in self.members
            },
            connections=parallel_connections(self.members),
        )
        engine_credential_sha256 = credential_sha256(
            derive_placement_group_credential(self.plan.placement_group_id)
        )
        self.store.register_placement_group(
            self.plan.document(),
            source=str(self.release["source"]),
            model="model",
            runtime="runtime",
            target="target",
            capacity={
                "max_connections": 32,
                "max_active_requests": 4,
                "max_context_tokens": 65536,
                "interconnect": {
                    "kind": "connectx",
                    "rdma_required": False,
                    "minimum_speed_mbps": 0,
                    "minimum_mtu": 0,
                },
            },
            engine_credential_sha256=engine_credential_sha256,
        )
        self.store.reserve_placement_devices(
            self.plan.placement_group_id,
            [
                {
                    "placement_id": placement.placement_id,
                    "node_id": placement.node_id,
                    "device_uuids": list(placement.device_uuids),
                }
                for placement in self.plan.placements
            ],
        )
        self.records = {
            item: {
                "member_id": item,
                "address": f"{index}.local",
                "certificate_sha256": f"{index + 5:x}" * 64,
            }
            for index, item in enumerate(self.members)
        }

    def tearDown(self) -> None:
        self.store.close()
        self.environment.stop()
        self.temporary.cleanup()

    def orchestrator(self, submit, statuses=None) -> PlacementGroupOrchestrator:
        return PlacementGroupOrchestrator(
            store=self.store,
            plan=self.plan,
            source=str(self.release["source"]),
            members=self.records,
            submit=submit,
            status=statuses or (lambda _member, placement_group_id: {
                "protocol": PROTOCOL,
                "placement": {
                    "placement_group_id": placement_group_id,
                    "placement_id": next(
                        placement.placement_id
                        for placement in self.plan.placements
                        if placement.node_id == _member["member_id"]
                    ),
                    "state": "running",
                },
                "protection_trip_latched": False,
            }),
            job_status=lambda _member, operation_id: {
                "protocol": PROTOCOL,
                "job": {
                    "operation_id": operation_id,
                    "state": "succeeded",
                    "result": {"state": "complete"},
                },
            },
        )

    def test_port_allocation_is_member_local_deterministic_and_non_overlapping(self) -> None:
        allocated = allocate_placement_ports(
            self.contract,
            member_ids=self.members,
            occupied={
                self.identity.member_id: ((18000, 4),),
                "e" * 32: ((18000, 8),),
                "f" * 32: (),
            },
        )
        self.assertEqual(allocated[self.identity.member_id], 18004)
        self.assertEqual(allocated["e" * 32], 18008)
        self.assertEqual(allocated["f" * 32], 18000)

    def test_stage_and_start_follow_runtime_task_phases(self) -> None:
        calls: list[tuple[str, str, str]] = []
        first_phase = threading.Barrier(2)

        def submit(member, job, credential):
            calls.append((job["action"], job["placement"]["task_id"], member["member_id"]))
            if job["action"] == "start" and job["placement"]["task_id"] in {"task-1", "task-2"}:
                first_phase.wait(timeout=2)
            self.assertEqual(credential is not None, job["action"] == "stage")
            return {
                "protocol": PROTOCOL, "operation_id": job["operation_id"],
                "replayed": False, "state": "succeeded",
                "result": {"state": job["action"]},
            }

        orchestrator = self.orchestrator(submit)
        orchestrator.stage()
        orchestrator.start()
        starts = [item for item in calls if item[0] == "start"]
        self.assertEqual({item[1] for item in starts[:2]}, {"task-1", "task-2"})
        self.assertEqual(starts[2][1], "task-0")
        self.assertEqual(self.store.placement_groups()[0]["state"], "running")

    def test_failed_distributed_start_stops_every_started_task(self) -> None:
        calls: list[tuple[str, str]] = []

        def submit(_member, job, _credential):
            calls.append((job["action"], job["placement"]["task_id"]))
            if job["action"] == "start" and job["placement"]["task_id"] == "task-2":
                raise RuntimeError("synthetic failure")
            return {
                "protocol": PROTOCOL, "operation_id": job["operation_id"],
                "replayed": False, "state": "succeeded",
                "result": {"state": job["action"]},
            }

        orchestrator = self.orchestrator(submit)
        orchestrator.stage()
        with self.assertRaisesRegex(PlacementGroupOrchestrationError, "start failed"):
            orchestrator.start()
        self.assertIn(("stop", "task-1"), calls)
        self.assertEqual(self.store.placement_groups()[0]["state"], "failed")

    def test_stopped_group_removes_every_task_in_reverse_startup_order(self) -> None:
        calls: list[tuple[str, str]] = []

        def submit(_member, job, _credential):
            calls.append((job["action"], job["placement"]["task_id"]))
            return {
                "protocol": PROTOCOL,
                "operation_id": job["operation_id"],
                "replayed": False,
                "state": "succeeded",
                "result": {"state": job["action"]},
            }

        orchestrator = self.orchestrator(submit)
        orchestrator.stage()
        orchestrator.start()
        orchestrator.stop()
        removed = orchestrator.remove()
        removals = [item for item in calls if item[0] == "remove"]
        self.assertEqual(removals[0][1], "task-0")
        self.assertEqual({item[1] for item in removals[1:]}, {"task-1", "task-2"})
        self.assertEqual(removed["state"], "removed")
        self.assertEqual(removed["desired_state"], "removed")

    def test_failed_removal_retry_skips_already_removed_tasks(self) -> None:
        calls: list[tuple[str, str]] = []
        fail_task_two = True

        def submit(_member, job, _credential):
            nonlocal fail_task_two
            calls.append((job["action"], job["placement"]["task_id"]))
            if (
                job["action"] == "remove"
                and job["placement"]["task_id"] == "task-2"
                and fail_task_two
            ):
                fail_task_two = False
                raise RuntimeError("synthetic removal failure")
            return {
                "protocol": PROTOCOL,
                "operation_id": job["operation_id"],
                "replayed": False,
                "state": "succeeded",
                "result": {"state": job["action"]},
            }

        orchestrator = self.orchestrator(submit)
        orchestrator.stage()
        orchestrator.start()
        orchestrator.stop()
        with self.assertRaisesRegex(PlacementGroupOrchestrationError, "removal failed"):
            orchestrator.remove()
        first_removals = [item for item in calls if item[0] == "remove"]
        self.assertEqual({item[1] for item in first_removals}, {"task-0", "task-1", "task-2"})

        removed = orchestrator.remove()
        second_removals = [item for item in calls if item[0] == "remove"][
            len(first_removals):
        ]
        self.assertEqual(second_removals, [("remove", "task-2")])
        self.assertEqual(removed["state"], "removed")

    def test_remove_treats_member_absence_as_idempotent_success(self) -> None:
        submit = mock.Mock(side_effect=AssertionError("remove job must not be submitted"))
        orchestrator = self.orchestrator(
            submit,
            statuses=lambda _member, _placement_group_id: {
                "protocol": PROTOCOL,
                "placement": None,
                "protection_trip_latched": False,
            },
        )
        self.store.set_placement_group_allocation_state(self.plan.placement_group_id, "released")

        removed = orchestrator.remove()

        self.assertEqual(removed["state"], "removed")
        self.assertTrue(
            all(
                placement["state"] == "removed"
                for placement in removed["placements"]
            )
        )
        self.assertEqual(
            {row["state"] for row in self.store.device_allocations()},
            {"released"},
        )
        submit.assert_not_called()

    def test_remove_fails_closed_on_invalid_absent_member_status(self) -> None:
        orchestrator = self.orchestrator(
            mock.Mock(),
            statuses=lambda _member, _placement_group_id: {
                "protocol": PROTOCOL,
                "placement": None,
            },
        )

        with self.assertRaisesRegex(PlacementGroupOrchestrationError, "removal failed"):
            orchestrator.remove()

        self.assertEqual(self.store.placement_groups()[0]["state"], "failed")

    def test_remove_fails_closed_on_absent_member_with_protection_trip(self) -> None:
        orchestrator = self.orchestrator(
            mock.Mock(),
            statuses=lambda _member, _placement_group_id: {
                "protocol": PROTOCOL,
                "placement": None,
                "protection_trip_latched": True,
            },
        )

        with self.assertRaisesRegex(PlacementGroupOrchestrationError, "removal failed"):
            orchestrator.remove()

        self.assertEqual(self.store.placement_groups()[0]["state"], "failed")

    def test_reconcile_fails_distributed_group_when_one_member_is_missing(self) -> None:
        orchestrator = self.orchestrator(
            lambda _member, job, _credential: {
                "protocol": PROTOCOL, "operation_id": job["operation_id"],
                "replayed": False, "state": "succeeded",
                "result": {"state": job["action"]},
            },
            statuses=lambda member, placement_group_id: (
                (_ for _ in ()).throw(OSError("down"))
                if member["member_id"] == "f" * 32
                else {
                    "protocol": PROTOCOL,
                    "placement": {
                        "placement_group_id": placement_group_id,
                        "placement_id": next(
                            placement.placement_id
                            for placement in self.plan.placements
                            if placement.node_id == member["member_id"]
                        ),
                        "state": "running",
                    },
                    "protection_trip_latched": False,
                }
            ),
        )
        orchestrator.stage()
        orchestrator.start()
        result = orchestrator.reconcile()
        self.assertEqual(result["state"], "failed")
        self.assertEqual(
            next(
                item
                for item in result["placements"]
                if item["node_id"] == "f" * 32
            )["state"],
            "unreachable",
        )

    def test_unchanged_reconcile_does_not_append_audit_noise(self) -> None:
        def submit(_member, job, _credential):
            return {
                "protocol": PROTOCOL,
                "operation_id": job["operation_id"],
                "replayed": False,
                "state": "succeeded",
                "result": {"state": job["action"]},
            }

        orchestrator = self.orchestrator(submit)
        orchestrator.stage()
        orchestrator.start()
        before = self.store.connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]
        result = orchestrator.reconcile()
        after = self.store.connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]
        self.assertEqual(result["state"], "running")
        self.assertEqual(after, before)

    def test_explicit_recovery_uses_trip_acknowledgement_in_startup_order(self) -> None:
        calls: list[tuple[str, str]] = []

        def submit(_member, job, _credential):
            calls.append((job["action"], job["placement"]["task_id"]))
            return {
                "protocol": PROTOCOL,
                "operation_id": job["operation_id"],
                "replayed": False,
                "state": "succeeded",
                "result": {"state": job["action"]},
            }

        orchestrator = self.orchestrator(submit)
        orchestrator.stage()
        orchestrator.start()
        calls.clear()
        result = orchestrator.recover(acknowledge_trips=True)
        self.assertEqual(result["state"], "running")
        recovered = [task for event, task in calls if event == "recover"]
        stopped = [task for event, task in calls if event == "stop"]
        self.assertEqual(set(recovered[:2]), {"task-1", "task-2"})
        self.assertEqual(recovered[2], "task-0")
        self.assertEqual(stopped[0], "task-0")
        self.assertEqual(set(stopped[1:]), {"task-1", "task-2"})

    def test_cleanly_stopped_group_can_run_idempotent_recovery(self) -> None:
        calls: list[str] = []

        def submit(_member, job, _credential):
            calls.append(job["action"])
            return {
                "protocol": PROTOCOL,
                "operation_id": job["operation_id"],
                "replayed": False,
                "state": "succeeded",
                "result": {"state": job["action"]},
            }

        orchestrator = self.orchestrator(submit)
        orchestrator.stage()
        orchestrator.start()
        orchestrator.stop()
        self.assertEqual(
            {row["state"] for row in self.store.device_allocations()}, {"reserved"}
        )
        calls.clear()

        result = orchestrator.recover(acknowledge_trips=False)

        self.assertEqual(result["state"], "running")
        self.assertIn("stop", calls)
        self.assertIn("start", calls)
        self.assertEqual(
            {row["state"] for row in self.store.device_allocations()}, {"active"}
        )

if __name__ == "__main__":
    unittest.main()
