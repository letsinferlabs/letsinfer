#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import unittest

from core.orchestration import (
    OrchestrationError,
    build_group_plan,
    validate_orchestration_contract,
    validate_target_binding,
)
from tests.orchestration.helpers import (
    parallel_connections,
    parallel_contract,
    release_identity,
)


class OrchestrationContractTests(unittest.TestCase):
    def parallel(self) -> dict[str, object]:
        return parallel_contract()

    def test_replication_is_core_owned_and_single_targets_have_no_contract(self) -> None:
        self.assertIsNone(validate_target_binding(None, {"strategy": "single"}))
        with self.assertRaisesRegex(OrchestrationError, "cannot declare"):
            validate_target_binding(self.parallel(), {"strategy": "single"})

    def test_boolean_schema_and_numeric_role_fields_are_rejected(self) -> None:
        invalid = self.parallel()
        invalid["schema_version"] = True
        with self.assertRaisesRegex(OrchestrationError, "schema_version"):
            validate_orchestration_contract(invalid)

        invalid = self.parallel()
        invalid["tasks"][1]["port_count"] = True
        with self.assertRaisesRegex(OrchestrationError, "port_count"):
            validate_orchestration_contract(invalid)

    def test_parallel_contract_is_runtime_owned_and_whole_group(self) -> None:
        value = self.parallel()
        self.assertIs(validate_orchestration_contract(value), value)
        self.assertEqual(value["startup_order"], [["task-1", "task-2"], ["task-0"]])
        self.assertNotIn("rank", repr(value))

    def test_target_binding_rejects_missing_mismatched_and_single_contracts(self) -> None:
        placement = {
            "strategy": "parallel",
            "node_count": 3,
        }
        with self.assertRaisesRegex(OrchestrationError, "must contain exactly"):
            validate_target_binding(None, placement)
        changed = self.parallel()
        changed["tasks"].pop()
        changed["startup_order"] = [["task-1"], ["task-0"]]
        with self.assertRaisesRegex(OrchestrationError, "does not match"):
            validate_target_binding(changed, placement)

    def test_contract_rejects_shells_and_protected_environment(self) -> None:
        shell = self.parallel()
        shell["tasks"][1]["command"] = ["/bin/sh", "-c", "engine"]
        with self.assertRaisesRegex(OrchestrationError, "cannot invoke"):
            validate_orchestration_contract(shell)
        protected = self.parallel()
        protected["tasks"][1]["environment"] = {
            "LETSINFER_GROUP_ID": "forged"
        }
        with self.assertRaisesRegex(OrchestrationError, "reserved for core"):
            validate_orchestration_contract(protected)
        semantic = self.parallel()
        semantic["tasks"][0]["rank"] = 0
        with self.assertRaisesRegex(OrchestrationError, "invalid fields"):
            validate_orchestration_contract(semantic)

    def test_parallel_group_plan_is_deterministic_and_task_assigned(self) -> None:
        members = ("1" * 32, "2" * 32, "3" * 32)
        arguments = {
            "member_ids": members,
            "member_addresses": {
                "1" * 32: "member-a.local:9770",
                "2" * 32: "member-b.local:9770",
                "3" * 32: "member-c.local:9770",
            },
            "topology_sha256": "4" * 64,
            "manifest_sha256": "5" * 64,
            "runtime_digest": "6" * 64,
            "service_id": "7" * 32,
            "release": release_identity(),
            "member_port_bases": {
                "1" * 32: 18000,
                "2" * 32: 18000,
                "3" * 32: 18000,
            },
            "member_device_uuids": {
                member: [f"GPU-{member[:8]}"] for member in members
            },
            "connections": parallel_connections(members),
        }
        first = build_group_plan(self.parallel(), **arguments)
        second = build_group_plan(self.parallel(), **arguments)
        self.assertEqual(first, second)
        self.assertEqual(first.assignments[0].member_id, "1" * 32)
        self.assertEqual(
            [item.task_id for item in first.assignments],
            ["task-0", "task-1", "task-2"],
        )
        self.assertRegex(first.group_id, r"^[0-9a-f]{32}$")
        self.assertEqual(first.document()["resources"][0]["address"], "member-a.local:9770")
        self.assertNotIn("rank", first.document())

    def test_parallel_plan_rejects_disconnected_or_unverified_resources(self) -> None:
        members = ("1" * 32, "2" * 32, "3" * 32)
        with self.assertRaisesRegex(OrchestrationError, "do not join"):
            build_group_plan(
                self.parallel(),
                member_ids=members,
                member_addresses={member: f"{index}.local" for index, member in enumerate(members)},
                topology_sha256="4" * 64,
                manifest_sha256="5" * 64,
                runtime_digest="6" * 64,
                service_id="7" * 32,
                release=release_identity(),
                member_port_bases={member: 18000 for member in members},
                member_device_uuids={member: [f"GPU-{index}"] for index, member in enumerate(members)},
                connections=parallel_connections(members)[:1],
            )

    def test_one_node_parallel_runtime_can_consume_multiple_devices(self) -> None:
        contract = parallel_contract(1)
        placement = {"strategy": "parallel", "node_count": 1}
        self.assertIs(validate_target_binding(contract, placement), contract)
        member = "1" * 32
        plan = build_group_plan(
            contract,
            member_ids=(member,),
            member_addresses={member: "node.local"},
            topology_sha256="4" * 64,
            manifest_sha256="5" * 64,
            runtime_digest="6" * 64,
            service_id="7" * 32,
            release=release_identity(),
            member_port_bases={member: 18000},
            member_device_uuids={member: ["GPU-0", "GPU-1"]},
            connections=[],
        )
        self.assertEqual(plan.strategy, "parallel")
        self.assertEqual(plan.document()["resources"][0]["device_uuids"], ["GPU-0", "GPU-1"])

    def test_group_plan_rejects_incomplete_member_addresses(self) -> None:
        with self.assertRaisesRegex(OrchestrationError, "addresses"):
            build_group_plan(
                self.parallel(),
                member_ids=("1" * 32, "2" * 32, "3" * 32),
                member_addresses={"1" * 32: "a.local:9770"},
                topology_sha256="3" * 64,
                manifest_sha256="5" * 64,
                runtime_digest="6" * 64,
                service_id="7" * 32,
                release=release_identity(),
                member_port_bases={
                    "1" * 32: 18000,
                    "2" * 32: 18000,
                    "3" * 32: 18000,
                },
                member_device_uuids={
                    "1" * 32: ["GPU-1"],
                    "2" * 32: ["GPU-2"],
                    "3" * 32: ["GPU-3"],
                },
                connections=parallel_connections(
                    ("1" * 32, "2" * 32, "3" * 32)
                ),
            )


if __name__ == "__main__":
    unittest.main()
