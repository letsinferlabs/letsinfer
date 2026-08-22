#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import os
import pathlib
import tempfile
import unittest
from unittest import mock

from core.orchestration import build_group_plan
from core.orchestration.coordinator import (
    allocate_group_ports,
    EngineGroupOrchestrator,
    GroupOrchestrationError,
)
from core.orchestration.member import PROTOCOL
from core.site import state


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
        self.contract = {
            "schema_version": 1,
            "strategy": "distributed",
            "member_count": 3,
            "engine_strategy": "tensor-parallel",
            "failure_policy": "whole-group",
            "minimum_healthy_members": 3,
            "startup_order": ["engine-member", "engine-coordinator"],
            "roles": {
                "engine-member": {
                    "assignment": "members",
                    "launcher": "runtime-command",
                    "port_count": 4,
                    "command": ["/opt/runtime/launch", "member"],
                    "environment": {},
                    "inference_endpoint": False,
                    "readiness": {
                        "kind": "exec", "command": ["/opt/runtime/ready"],
                        "interval_seconds": 1, "timeout_seconds": 1, "retries": 5,
                    },
                },
                "engine-coordinator": {
                    "assignment": "engine-coordinator",
                    "launcher": "runtime-command",
                    "port_count": 4,
                    "command": ["/opt/runtime/launch", "coordinator"],
                    "environment": {},
                    "inference_endpoint": True,
                    "readiness": {
                        "kind": "exec", "command": ["/opt/runtime/ready"],
                        "interval_seconds": 1, "timeout_seconds": 1, "retries": 5,
                    },
                },
            },
        }
        self.plan = build_group_plan(
            self.contract,
            member_ids=self.members,
            member_addresses={item: f"{index}.local:9770" for index, item in enumerate(self.members)},
            engine_coordinator_id=self.identity.member_id,
            topology_sha256="1" * 64,
            manifest_sha256="2" * 64,
            runtime_digest="3" * 64,
            member_port_bases={item: 18000 for item in self.members},
        )
        self.placement_id = "4" * 32
        self.store = state.SiteStore(identity=self.identity)
        self.store.set_placement({
            "placement_id": self.placement_id,
            "model": "model", "runtime": "runtime", "target": "target",
            "strategy": "distributed", "state": "starting",
            "topology_sha256": "1" * 64,
            "members": list(self.members), "endpoints": [], "capacity": {},
        })
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

    def orchestrator(self, submit, statuses=None) -> EngineGroupOrchestrator:
        return EngineGroupOrchestrator(
            store=self.store,
            plan=self.plan,
            placement_id=self.placement_id,
            source="registry.example/runtime@sha256:" + "9" * 64,
            members=self.records,
            submit=submit,
            status=statuses or (lambda _member, group_id: {
                "protocol": PROTOCOL,
                "group": {"group_id": group_id, "state": "running"},
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
        allocated = allocate_group_ports(
            self.contract,
            member_ids=self.members,
            engine_coordinator_id=self.identity.member_id,
            occupied={
                self.identity.member_id: ((18000, 4),),
                "e" * 32: ((18000, 8),),
                "f" * 32: (),
            },
        )
        self.assertEqual(allocated[self.identity.member_id], 18004)
        self.assertEqual(allocated["e" * 32], 18008)
        self.assertEqual(allocated["f" * 32], 18000)

    def test_stage_and_start_order_workers_before_engine_coordinator(self) -> None:
        calls: list[tuple[str, str, str]] = []

        def submit(member, job, credential):
            calls.append((job["action"], job["role"]["name"], member["member_id"]))
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
        self.assertEqual(
            [item[1] for item in starts],
            ["engine-member", "engine-member", "engine-coordinator"],
        )
        self.assertEqual(self.store.engine_groups()[0]["state"], "running")

    def test_failed_distributed_start_stops_every_started_role(self) -> None:
        calls: list[tuple[str, str]] = []

        def submit(_member, job, _credential):
            calls.append((job["action"], job["role"]["name"]))
            if job["action"] == "start" and len([item for item in calls if item[0] == "start"]) == 2:
                raise RuntimeError("synthetic failure")
            return {
                "protocol": PROTOCOL, "operation_id": job["operation_id"],
                "replayed": False, "state": "succeeded",
                "result": {"state": job["action"]},
            }

        orchestrator = self.orchestrator(submit)
        orchestrator.stage()
        with self.assertRaisesRegex(GroupOrchestrationError, "start failed"):
            orchestrator.start()
        self.assertIn(("stop", "engine-member"), calls)
        self.assertEqual(self.store.engine_groups()[0]["state"], "failed")

    def test_stopped_group_removes_every_member_in_reverse_role_order(self) -> None:
        calls: list[tuple[str, str]] = []

        def submit(_member, job, _credential):
            calls.append((job["action"], job["role"]["name"]))
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
        self.assertEqual(
            [item[1] for item in removals],
            ["engine-coordinator", "engine-member", "engine-member"],
        )
        self.assertEqual(removed["state"], "removed")
        self.assertEqual(removed["desired_state"], "removed")

    def test_reconcile_fails_distributed_group_when_one_member_is_missing(self) -> None:
        orchestrator = self.orchestrator(
            lambda _member, job, _credential: {
                "protocol": PROTOCOL, "operation_id": job["operation_id"],
                "replayed": False, "state": "succeeded",
                "result": {"state": job["action"]},
            },
            statuses=lambda member, group_id: (
                (_ for _ in ()).throw(OSError("down"))
                if member["member_id"] == "f" * 32
                else {
                    "protocol": PROTOCOL,
                    "group": {"group_id": group_id, "state": "running"},
                    "protection_trip_latched": False,
                }
            ),
        )
        orchestrator.stage()
        orchestrator.start()
        result = orchestrator.reconcile()
        self.assertEqual(result["state"], "failed")
        self.assertEqual(
            next(item for item in result["member_states"] if item["member_id"] == "f" * 32)["state"],
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
            calls.append((job["action"], job["role"]["name"]))
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
        self.assertEqual(
            [role for action, role in calls if action == "recover"],
            ["engine-member", "engine-member", "engine-coordinator"],
        )
        self.assertEqual(
            [role for action, role in calls if action == "stop"],
            ["engine-coordinator", "engine-member", "engine-member"],
        )

    def test_replica_recovery_does_not_restart_healthy_peer(self) -> None:
        contract = {
            "schema_version": 1,
            "strategy": "replicated",
            "member_count": 2,
            "engine_strategy": "replica-pool",
            "failure_policy": "replica-independent",
            "minimum_healthy_members": 1,
            "startup_order": ["replica"],
            "roles": {
                "replica": {
                    "assignment": "all",
                    "launcher": "manifest",
                    "port_count": 1,
                    "environment": {},
                    "inference_endpoint": True,
                    "readiness": {"kind": "manifest"},
                }
            },
        }
        members = self.members[:2]
        plan = build_group_plan(
            contract,
            member_ids=members,
            member_addresses={item: f"{index}.local" for index, item in enumerate(members)},
            engine_coordinator_id=members[0],
            topology_sha256="a" * 64,
            manifest_sha256="b" * 64,
            runtime_digest="c" * 64,
            member_port_bases={item: 19000 for item in members},
        )
        placement_id = "d" * 32
        self.store.set_placement({
            "placement_id": placement_id,
            "model": "model-b", "runtime": "runtime-b", "target": "target-b",
            "strategy": "replicated", "state": "starting",
            "topology_sha256": "a" * 64,
            "members": list(members), "endpoints": [], "capacity": {},
        })
        states = {item: "running" for item in members}
        calls: list[tuple[str, str]] = []

        def submit(member, job, _credential):
            calls.append((job["action"], member["member_id"]))
            if job["action"] == "start":
                states[member["member_id"]] = "running"
            elif job["action"] == "stop":
                states[member["member_id"]] = "stopped"
            return {
                "protocol": PROTOCOL,
                "operation_id": job["operation_id"],
                "state": "succeeded",
                "result": {"state": job["action"]},
            }

        orchestrator = EngineGroupOrchestrator(
            store=self.store,
            plan=plan,
            placement_id=placement_id,
            source="registry.example/runtime@sha256:" + "9" * 64,
            members={item: self.records[item] for item in members},
            submit=submit,
            status=lambda member, group_id: {
                "protocol": PROTOCOL,
                "group": {"group_id": group_id, "state": states[member["member_id"]]},
                "protection_trip_latched": False,
            },
            job_status=lambda _member, operation_id: {
                "protocol": PROTOCOL,
                "job": {
                    "operation_id": operation_id,
                    "state": "succeeded",
                    "result": {"state": "complete"},
                },
            },
        )
        orchestrator.stage()
        orchestrator.start()
        calls.clear()
        states[members[1]] = "failed"
        degraded = orchestrator.reconcile()
        self.assertEqual(degraded["state"], "degraded")
        result = orchestrator.recover_replicas()
        self.assertEqual(result["state"], "running")
        self.assertEqual(calls, [("stop", members[1]), ("start", members[1])])


if __name__ == "__main__":
    unittest.main()
