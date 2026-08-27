#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Clean-break CLI integration tests for immutable runtime candidates."""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import io
import ipaddress
import json
import pathlib
import tempfile
import threading
import types
import unittest
from unittest import mock

from core import cli
from core.engine_protocol import artifact_storage_slug
from core.runtime_packs import RuntimePackError, candidate_id, validate_runtime_config
from tests.orchestration.helpers import parallel_contract
from tests.runtime_fixture import runtime_candidate


class LinuxHardwareInventoryTests(unittest.TestCase):
    def test_kernel_memory_blocks_report_installed_ram(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "block_size_bytes").write_text("80000000\n", encoding="ascii")
            for index in (0, *range(2, 49)):
                block = root / f"memory{index}"
                block.mkdir()
                (block / "state").write_text("online\n", encoding="ascii")

            self.assertEqual(cli.parse_linux_installed_memory_gib(root), 96)

            (root / "memory48" / "state").write_text(
                "offline\n", encoding="ascii"
            )
            self.assertEqual(cli.parse_linux_installed_memory_gib(root), 94)

            (root / "memory48" / "state").write_text(
                "going-offline\n", encoding="ascii"
            )
            with self.assertRaisesRegex(cli.LetsInferError, "state is invalid"):
                cli.parse_linux_installed_memory_gib(root)

    def test_kernel_memory_blocks_support_online_attribute(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "block_size_bytes").write_text("40000000\n", encoding="ascii")
            block = root / "memory0"
            block.mkdir()
            (block / "online").write_text("1\n", encoding="ascii")

            self.assertEqual(cli.parse_linux_installed_memory_gib(root), 1)

    def test_nvidia_memory_capacity_distinguishes_discrete_and_unified(self) -> None:
        self.assertEqual(cli.parse_nvidia_memory_capacity_gib(["32607"]), 32)
        self.assertIsNone(cli.parse_nvidia_memory_capacity_gib(["N/A"]))
        with self.assertRaisesRegex(cli.LetsInferError, "inconsistent"):
            cli.parse_nvidia_memory_capacity_gib(["32607", "N/A"])

    def test_host_fingerprint_separates_discrete_vram_and_installed_ram(self) -> None:
        values = {
            "compute_cap": ["12.0"],
            "addressing_mode": ["HMM"],
            "memory.total": ["32607"],
            "name": ["NVIDIA GeForce RTX 5090"],
            "uuid": ["GPU-fixture"],
        }
        with (
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli, "gpu_count", return_value=1),
            mock.patch.object(cli, "gpu_partitioning_mode", return_value="full-device"),
            mock.patch.object(
                cli,
                "nvidia_query",
                side_effect=lambda field, _count: values[field],
            ),
            mock.patch.object(cli.pathlib.Path, "read_text", return_value="MemTotal: 98570660 kB\n"),
            mock.patch.object(cli, "parse_linux_installed_memory_gib", return_value=96),
        ):
            fingerprint = cli.host_device_fingerprint()

        self.assertEqual(fingerprint["memory"]["topology"], "discrete")
        self.assertEqual(fingerprint["memory"]["total_gib"], 96)
        self.assertEqual(fingerprint["accelerator"]["minimum_memory_gib"], 32)

    def test_discrete_inventory_does_not_depend_on_an_active_addressing_mode(self) -> None:
        values = {
            "compute_cap": ["12.0"],
            "addressing_mode": ["None"],
            "memory.total": ["32607"],
            "name": ["NVIDIA GeForce RTX 5090"],
            "uuid": ["GPU-fixture"],
        }
        with (
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli, "gpu_count", return_value=1),
            mock.patch.object(
                cli, "gpu_partitioning_mode", return_value="full-device"
            ),
            mock.patch.object(
                cli,
                "nvidia_query",
                side_effect=lambda field, _count: values[field],
            ),
            mock.patch.object(
                cli.pathlib.Path,
                "read_text",
                return_value="MemTotal: 98570660 kB\n",
            ),
            mock.patch.object(
                cli, "parse_linux_installed_memory_gib", return_value=96
            ),
        ):
            fingerprint = cli.host_device_fingerprint()

        self.assertEqual(fingerprint["memory"]["topology"], "discrete")

    def test_host_fingerprint_requires_ats_for_unified_nvidia_memory(self) -> None:
        values = {
            "compute_cap": ["12.1"],
            "addressing_mode": ["HMM"],
            "memory.total": ["N/A"],
            "name": ["NVIDIA unified fixture"],
            "uuid": ["GPU-fixture"],
        }
        with (
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli, "gpu_count", return_value=1),
            mock.patch.object(cli, "gpu_partitioning_mode", return_value="full-device"),
            mock.patch.object(
                cli,
                "nvidia_query",
                side_effect=lambda field, _count: values[field],
            ),
            mock.patch.object(cli.pathlib.Path, "read_text", return_value="MemTotal: 125372456 kB\n"),
            self.assertRaisesRegex(cli.LetsInferError, "requires ATS"),
        ):
            cli.host_device_fingerprint()

    def test_host_fingerprint_keeps_true_nvidia_unified_memory_shared(self) -> None:
        values = {
            "compute_cap": ["12.1"],
            "addressing_mode": ["ATS"],
            "memory.total": ["N/A"],
            "name": ["NVIDIA GB10"],
            "uuid": ["GPU-fixture"],
        }
        with (
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli, "gpu_count", return_value=1),
            mock.patch.object(cli, "gpu_partitioning_mode", return_value="full-device"),
            mock.patch.object(
                cli,
                "nvidia_query",
                side_effect=lambda field, _count: values[field],
            ),
            mock.patch.object(cli.pathlib.Path, "read_text", return_value="MemTotal: 125372456 kB\n"),
            mock.patch.object(
                cli, "parse_linux_installed_memory_gib"
            ) as installed_memory,
        ):
            fingerprint = cli.host_device_fingerprint()

        self.assertEqual(fingerprint["memory"]["topology"], "unified")
        self.assertEqual(fingerprint["memory"]["total_gib"], 119)
        self.assertNotIn("minimum_memory_gib", fingerprint["accelerator"])
        installed_memory.assert_not_called()


class RuntimeCandidateCliTests(unittest.TestCase):
    def test_child_status_uses_the_actual_local_soc_name(self) -> None:
        identity = types.SimpleNamespace(role="child")
        hardware = {
            "accelerator": {"names": ["NVIDIA GB10"]},
        }
        with (
            mock.patch.object(cli, "identity_json", return_value={"role": "child"}),
            mock.patch.object(cli.socket, "gethostname", return_value="node-2"),
        ):
            node = cli._local_status_node(identity, hardware)

        self.assertEqual(node["hardware_name"], "NVIDIA GB10")
        self.assertEqual(node["hostname"], "node-2")

    def test_cached_inventory_prefers_soc_over_chassis_name(self) -> None:
        self.assertEqual(
            cli._hardware_display_name(
                None,
                {
                    "gpu_name": "NVIDIA GB10",
                    "dgx_name": "NVIDIA DGX Spark",
                    "product_name": "GX10",
                },
            ),
            "NVIDIA GB10",
        )

    def test_child_status_projects_its_validated_local_placement(self) -> None:
        member_id = "a" * 32
        placement_group_id = "b" * 32
        placement_id = "9" * 32
        identity = types.SimpleNamespace(member_id=member_id)
        placement = {"task_id": "task-1"}
        row = {
            "placement_group_id": placement_group_id,
            "placement_id": placement_id,
            "node_id": member_id,
            "plan_sha256": "c" * 64,
            "runtime_digest": "d" * 64,
            "manifest_sha256": "e" * 64,
            "topology_sha256": "f" * 64,
            "engine_credential_sha256": "1" * 64,
            "placement": placement,
            "state": "running",
            "updated_at_unix": 1_800_000_000,
        }
        config = {
            **{
                key: row[key]
                for key in (
                    "placement_id",
                    "node_id",
                    "plan_sha256",
                    "runtime_digest",
                    "manifest_sha256",
                    "topology_sha256",
                )
            },
            "_credential_sha256": row["engine_credential_sha256"],
            "runtime_version": "0.1.0-rc.2",
            "placement": placement,
            "_manifest": {
                "model": {"alias": "qwen3.8-flash-next"},
                "serving": {
                    "max_connections": 32,
                    "max_active_requests": 4,
                    "max_context_tokens": 65536,
                },
            },
            "_placement_group": {"release": {}},
        }
        store = mock.Mock()
        store.placements.return_value = [
            {
                **row,
                "placement_group_id": "2" * 32,
                "runtime_digest": "3" * 64,
                "state": "stopped",
            },
            row,
        ]
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        read_config = mock.Mock(return_value=config)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "member-jobs.sqlite3").write_bytes(b"journal")
            with (
                mock.patch.object(cli, "site_data_root", return_value=root),
                mock.patch.object(cli, "MemberJobStore", return_value=store_context),
                mock.patch.object(
                    cli, "_read_placement_group_config", read_config
                ),
                mock.patch.object(
                    cli,
                    "adapter_for",
                    return_value=types.SimpleNamespace(name="sglang"),
                ),
                mock.patch.object(
                    cli,
                    "target_contract",
                    return_value={"id": "dgx-spark-connectx-2"},
                ),
            ):
                groups = cli._local_placement_group_status(identity)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["placement_group_id"], placement_group_id)
        self.assertEqual(groups[0]["model"], "qwen3.8-flash-next")
        self.assertEqual(groups[0]["state"], "running")
        self.assertTrue(groups[0]["local_placement"])
        self.assertEqual(groups[0]["placements"][0]["task_id"], "task-1")
        read_config.assert_called_once_with(placement_group_id, repair_tls=False)

    def test_running_placement_group_projects_into_the_runtime_dashboard(self) -> None:
        placement_group_id = "a" * 32
        group = {
            "placement_group_id": placement_group_id,
            "model": "qwen3.8-flash-next",
            "runtime": (
                "qwen3.8-flash-next/sglang/dgx-spark-connectx-2@0.1.0-rc.2"
                "@sha256:" + "b" * 64
            ),
            "target": "dgx-spark-connectx-2",
            "capacity": {
                "max_connections": 16,
                "max_active_requests": 4,
                "max_context_tokens": 65536,
            },
            "desired_state": "running",
            "state": "running",
            "placements": [
                {
                    "placement_id": placement_group_id,
                    "node_id": "1" * 32,
                    "state": "running",
                }
            ],
        }
        inspection = {
            "Id": "c" * 64,
            "State": {"Status": "running"},
        }
        with (
            mock.patch.object(cli, "container_inspect", return_value=inspection),
            mock.patch.object(
                cli,
                "protection_status",
                return_value={
                    "phase": "armed",
                    "armed": True,
                    "trip_latched": False,
                },
            ),
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(member_id="1" * 32),
            ),
        ):
            projection = cli._placement_group_dashboard_projection([group])

        self.assertIsNotNone(projection)
        assert projection is not None
        self.assertEqual(projection["container"]["model"], group["model"])
        self.assertEqual(projection["container"]["engine"], "sglang")
        self.assertEqual(
            projection["container"]["target"], "dgx-spark-connectx-2"
        )
        self.assertEqual(projection["container"]["runtime_version"], "0.1.0-rc.2")
        self.assertTrue(projection["container"]["healthy"])
        self.assertEqual(projection["container"]["docker_health"], "none")
        self.assertEqual(
            cli._placement_group_dashboard_lifecycle(
                {
                    "state": "ready",
                    "reason": "runtime-not-installed",
                    "ready_services": 3,
                    "total_services": 3,
                },
                projection,
            ),
            {
                "ready": True,
                "transitional": False,
                "runtime_ready": True,
                "ready_services": 3,
                "total_services": 3,
                "state": "ready",
                "reason": "placement-group-ready",
            },
        )

    def test_native_placement_group_dashboard_uses_its_launch_agent(self) -> None:
        placement_group_id = "a" * 32
        group = {
            "placement_group_id": placement_group_id,
            "model": "qwen3.8-flash-next",
            "runtime": (
                "qwen3.8-flash-next/llama.cpp/apple-silicon@0.1.0"
                "@sha256:" + "b" * 64
            ),
            "target": "apple-silicon",
            "desired_state": "running",
            "state": "running",
            "placements": [
                {
                    "placement_id": placement_group_id,
                    "node_id": "1" * 32,
                    "state": "running",
                }
            ],
            "engine_distribution": {
                "kind": "native-archive",
                "payload_id": "sha256:" + "c" * 64,
            },
        }
        with (
            mock.patch.object(
                cli.macos_services,
                "service_state",
                return_value=("enabled", "active", None),
            ) as service_state,
            mock.patch.object(cli, "container_inspect") as inspect,
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(member_id="1" * 32),
            ),
        ):
            projection = cli._placement_group_dashboard_projection([group])

        self.assertIsNotNone(projection)
        assert projection is not None
        self.assertEqual(
            projection["container"]["name"], f"ai.letsinfer.engine.{placement_group_id}"
        )
        self.assertEqual(
            projection["container"]["kind"], "native-launch-agent"
        )
        self.assertTrue(projection["container"]["healthy"])
        self.assertTrue(projection["protection"]["armed"])
        service_state.assert_called_once_with(f"ai.letsinfer.engine.{placement_group_id}")
        inspect.assert_not_called()

    def test_dashboard_projection_requires_one_exact_runtime_identity(self) -> None:
        self.assertIsNone(cli._placement_group_dashboard_projection([]))
        self.assertIsNone(
            cli._placement_group_dashboard_projection([
                {
                    "placement_group_id": "a" * 32,
                    "model": "qwen3.8-flash-next",
                    "runtime": "runtime-a",
                    "target": "dgx-spark-connectx-2",
                }
            ])
        )

    def test_group_link_health_applies_only_to_sealed_connections(self) -> None:
        now = 1_800_000_000
        main_id = "a" * 32
        child_id = "b" * 32
        row = {
            "plan": {
                "placements": [{"node_id": main_id}, {"node_id": child_id}],
                "connections": [
                    {
                        "nodes": [main_id, child_id],
                        "kind": "connectx",
                        "speed_mbps": 200_000,
                        "mtu": 1500,
                        "rdma": True,
                    }
                ],
            }
        }
        store = mock.Mock()
        store.members.return_value = [
            {
                "member_id": member_id,
                "state": "active",
                "certificate_sha256": character * 64,
                "facts": {"observed_at_unix": now},
            }
            for member_id, character in ((main_id, "c"), (child_id, "d"))
        ]
        graph = mock.Mock(links={})
        with mock.patch.object(cli, "TopologyGraph", return_value=graph):
            self.assertEqual(
                cli._placement_group_required_link_failure(
                    row,
                    store,
                    now_unix=now,
                ),
                "required_link_unavailable",
            )
            graph.links = {
                (main_id, child_id): {
                    "kind": "connectx",
                    "speed_mbps": 200_000,
                    "mtu": 1500,
                    "rdma": True,
                }
            }
            self.assertIsNone(
                cli._placement_group_required_link_failure(
                    row,
                    store,
                    now_unix=now,
                )
            )
        store.reset_mock()
        self.assertIsNone(
            cli._placement_group_required_link_failure(
                {"plan": {"connections": [], "placements": []}},
                store,
                now_unix=now,
            )
        )
        store.members.assert_not_called()

    def test_link_loss_pauses_only_the_affected_placement_group(self) -> None:
        affected = {
            "placement_group_id": "a" * 32,
            "desired_state": "running",
            "state": "running",
            "updated_at_unix": 1,
        }
        independent = {
            "placement_group_id": "b" * 32,
            "desired_state": "running",
            "state": "running",
            "updated_at_unix": 1,
        }
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.placement_groups.return_value = [affected, independent]
        affected_orchestrator = mock.Mock()
        independent_orchestrator = mock.Mock(protection_trips={})
        independent_orchestrator.reconcile.return_value = {
            "state": "running",
            "placements": [],
        }
        with (
            mock.patch.object(
                cli,
                "_placement_group_lifecycle_lock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli,
                "_restore_placement_group_orchestrator",
                side_effect=(
                    (affected_orchestrator, {}),
                    (independent_orchestrator, {}),
                ),
            ),
            mock.patch.object(
                cli,
                "_placement_group_required_link_failure",
                side_effect=("required_link_unavailable", None),
            ),
            mock.patch.object(
                cli, "_pause_placement_group_for_link_loss"
            ) as pause,
            mock.patch.object(cli.time, "time", return_value=1000),
        ):
            summary = cli.reconcile_placement_groups_once()
        pause.assert_called_once_with(
            store,
            affected,
            affected_orchestrator,
            "required_link_unavailable",
        )
        affected_orchestrator.reconcile.assert_not_called()
        independent_orchestrator.reconcile.assert_called_once_with()
        self.assertEqual(summary["paused"], [affected["placement_group_id"]])
        self.assertEqual(summary["healthy"], [independent["placement_group_id"]])

    def test_link_pause_persists_reason_without_touching_siblings(self) -> None:
        row = {
            "placement_group_id": "a" * 32,
            "source": "registry.example/runtime@sha256:" + "c" * 64,
            "engine_credential_sha256": "d" * 64,
            "plan": {"placement_group_id": "a" * 32},
        }
        stopped = {
            "placements": [
                {
                    "placement_id": "b" * 32,
                    "node_id": "e" * 32,
                    "task_id": "task-0",
                    "state": "stopped",
                    "operation_id": None,
                    "error": None,
                }
            ]
        }
        paused = {"state": "stopped", "placements": stopped["placements"]}
        orchestrator = mock.Mock()
        orchestrator.stop.return_value = stopped
        store = mock.Mock()
        store.set_placement_group.return_value = paused
        result = cli._pause_placement_group_for_link_loss(
            store,
            row,
            orchestrator,
            "required_link_unavailable",
        )
        self.assertIs(result, paused)
        orchestrator.stop.assert_called_once_with()
        self.assertEqual(
            store.set_placement_group.call_args.kwargs["action"],
            "placement_group.stop",
        )
        self.assertEqual(
            store.set_placement_group.call_args.kwargs["desired_state"],
            "stopped",
        )
        self.assertEqual(
            store.set_placement_group.call_args.kwargs["error"],
            "required_link_unavailable",
        )

    def test_link_monitor_discovers_connectx_from_live_signed_facts(self) -> None:
        now = 1_800_000_000

        def member(member_id: str, address: str, direct_address: str) -> dict:
            return {
                "member_id": member_id,
                "address": address,
                "certificate_sha256": member_id[0] * 64,
                "state": "active",
                "facts": {
                    "observed_at_unix": now,
                    "network": {
                        "interfaces": [
                            {
                                "name": "enp1s0f0np0",
                                "addresses": [direct_address],
                                "rdma": True,
                            }
                        ],
                        "links": [],
                    },
                },
            }

        main = member("a" * 32, "home.local", "10.44.0.1")
        child = member("b" * 32, "child.local", "10.44.0.2")
        store = mock.MagicMock()
        store.__enter__.return_value.members.return_value = [main, child]
        with (
            mock.patch.object(
                cli, "read_site_identity", return_value=types.SimpleNamespace(role="main")
            ),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(cli.time, "time", return_value=now),
            mock.patch.object(cli, "request_member_link_probe") as probe,
        ):
            result = cli._refresh_site_links_once()

        self.assertEqual(
            result,
            {
                "refreshed": [f"{'a' * 32}->{'b' * 32}", f"{'b' * 32}->{'a' * 32}"],
                "failed": [],
            },
        )
        self.assertEqual(probe.call_count, 2)
        calls = {call.kwargs["expected_member_id"]: call.kwargs for call in probe.call_args_list}
        self.assertEqual(calls["a" * 32]["peer_endpoint"], "https://10.44.0.2:9770")
        self.assertEqual(calls["b" * 32]["peer_endpoint"], "https://10.44.0.1:9770")
        self.assertEqual(calls["a" * 32]["kind"], "connectx")

    def test_link_monitor_ignores_stale_or_unusable_direct_addresses(self) -> None:
        subject = {
            "member_id": "a" * 32,
            "address": "home.local",
            "facts": {
                "network": {
                    "interfaces": [
                        {"name": "mlx0", "addresses": ["192.0.2.1"], "rdma": True}
                    ],
                    "links": [],
                }
            },
        }
        peer = {
            "member_id": "b" * 32,
            "address": "child.local",
            "facts": {
                "network": {
                    "interfaces": [
                        {
                            "name": "mlx0",
                            "addresses": ["not-an-ip", "127.0.0.1", "fe80::2"],
                            "rdma": True,
                        }
                    ],
                    "links": [],
                }
            },
        }
        candidates = cli._member_link_probe_candidates(subject, peer)
        self.assertEqual(
            candidates,
            [
                {
                    "interface": "mlx0",
                    "kind": "connectx",
                    "peer_endpoint": "https://[fe80::2%mlx0]:9770",
                }
            ],
        )
        self.assertTrue(ipaddress.ip_address("fe80::2").is_link_local)

    def test_interactive_model_install_turns_same_model_choices_into_replicas(self) -> None:
        members = [
            {"member_id": "a" * 32, "display_name": "Home", "state": "active"},
            {"member_id": "b" * 32, "display_name": "Workshop", "state": "active"},
        ]
        store = mock.MagicMock()
        store.__enter__.return_value.members.return_value = members
        presenter = mock.Mock()
        presenter.prompt.choose.side_effect = ["ling-3-flash", "ling-3-flash"]
        arguments = argparse.Namespace(
            model=None,
            catalog="catalog.json",
            runtime=None,
            node=None,
            all_nodes=False,
            replace_existing=False,
            action_id="model.install",
        )
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(
                cli.CatalogManager,
                "load",
                return_value=types.SimpleNamespace(
                    document={"models": {"ling-3-flash": {}}}
                ),
            ),
            mock.patch.object(
                cli,
                "_fresh_site_topology",
                return_value=(mock.sentinel.identity, mock.sentinel.graph),
            ),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(cli, "_catalog_release_for_node"),
            mock.patch.object(cli, "install", return_value=0) as install,
        ):
            self.assertEqual(cli.model_install_command(arguments), 0)
        install.assert_called_once()
        self.assertEqual(install.call_args.args[0].model, "ling-3-flash")
        self.assertEqual(install.call_args.args[0].node, ["a" * 32, "b" * 32])

    def test_pairing_interrupts_are_graceful_at_each_interactive_wait(self) -> None:
        candidate = {
            "confirmation_code": "123456",
            "name": "Mac",
            "id": "controller-id",
        }

        for stage in ("controller", "confirmation", "completion"):
            with self.subTest(stage=stage):
                state = mock.Mock()
                state.condition = threading.Condition()
                state.candidate = None if stage == "controller" else candidate
                state.error = None
                state.deadline = cli.time.monotonic() + 30
                state.completed = False
                state.approved = None

                if stage in {"controller", "completion"}:
                    wait = mock.patch.object(
                        state.condition,
                        "wait",
                        side_effect=KeyboardInterrupt,
                    )
                else:
                    wait = contextlib.nullcontext()

                arguments = types.SimpleNamespace(
                    timeout=30,
                    config=None,
                    role="administrator",
                    action_id="auth.controller.add",
                )
                config = {
                    "installation_id": "i" * 64,
                    "watchdog_controller_allowlist_file": "/tmp/allowlist",
                    "watchdog_controller_ca_key_file": "/tmp/ca-key",
                    "watchdog_cert_file": "/tmp/cert",
                    "watchdog_key_file": "/tmp/key",
                    "watchdog_listen": "127.0.0.1",
                }
                server = mock.Mock()
                presenter = mock.Mock()
                confirmation = (
                    mock.patch.object(
                        cli.ui,
                        "confirm",
                        side_effect=KeyboardInterrupt,
                    )
                    if stage == "confirmation"
                    else mock.patch.object(cli.ui, "confirm", return_value=True)
                )

                with (
                    wait,
                    mock.patch.object(
                        cli, "_controller_management_config", return_value=config
                    ),
                    mock.patch.object(cli, "_reload_controller_authorization"),
                    mock.patch.object(
                        cli, "_ControllerPairingState", return_value=state
                    ),
                    mock.patch.object(cli, "_controller_pairing_tls_context"),
                    mock.patch.object(
                        cli, "_ControllerPairingServer", return_value=server
                    ),
                    mock.patch.object(cli, "_human_presenter", return_value=presenter),
                    mock.patch.object(
                        cli, "_command_activity", return_value=contextlib.nullcontext()
                    ),
                    mock.patch.object(
                        cli.ui,
                        "protect_stdout",
                        side_effect=lambda _owner: contextlib.nullcontext(),
                    ),
                    confirmation,
                    mock.patch.object(cli.secrets, "randbelow", return_value=12345678),
                ):
                    self.assertEqual(cli.pair_controller(arguments), 0)

                state.cancel.assert_called_once_with()
                presenter.result.assert_any_call(
                    "Pairing cancelled",
                    semantic=cli.command_ui.Semantic.INFO,
                )
                self.assertTrue(arguments.suppress_completion)
                server.shutdown.assert_called_once_with()
                server.server_close.assert_called_once_with()

    def test_cancelled_pairing_cannot_commit_a_controller(self) -> None:
        config = {
            "installation_id": "i" * 64,
            "watchdog_controller_ca_file": "/tmp/ca",
            "watchdog_controller_ca_key_file": "/tmp/ca-key",
        }
        state = cli._ControllerPairingState(
            config,
            "12345678",
            30,
            "administrator",
        )
        state.approved = True
        candidate = {
            "confirmation_code": "123456",
            "name": "Mac",
            "id": "controller-id",
        }

        def cancel_after_issuance(*_args: object) -> tuple[str, str]:
            state.cancel()
            return "certificate", "f" * 64

        with (
            mock.patch.object(
                cli, "_decode_controller_enrollment", return_value=candidate
            ),
            mock.patch.object(cli, "_verify_controller_key"),
            mock.patch.object(
                cli,
                "issue_controller_certificate",
                side_effect=cancel_after_issuance,
            ),
            mock.patch.object(cli, "_replace_controller") as replace,
            self.assertRaisesRegex(cli.LetsInferError, "pairing was cancelled"),
        ):
            state.enroll({})

        replace.assert_not_called()

    def test_controller_management_uses_core_plane_without_legacy_service(self) -> None:
        identity = types.SimpleNamespace(
            role="main",
            installation_id="a" * 64,
        )
        paths = {
            "watchdog_cert_file": pathlib.Path("/config/watchdog/server.crt"),
            "watchdog_key_file": pathlib.Path("/secrets/watchdog/server.key"),
            "watchdog_controller_ca_file": pathlib.Path("/config/watchdog/ca.crt"),
            "watchdog_controller_ca_key_file": pathlib.Path(
                "/secrets/watchdog/ca.key"
            ),
            "watchdog_controller_allowlist_file": pathlib.Path(
                "/config/watchdog/controllers.allow"
            ),
        }
        with (
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(
                cli, "default_watchdog_cert_path", return_value=paths["watchdog_cert_file"]
            ),
            mock.patch.object(
                cli, "default_watchdog_key_path", return_value=paths["watchdog_key_file"]
            ),
            mock.patch.object(
                cli,
                "default_watchdog_controller_ca_path",
                return_value=paths["watchdog_controller_ca_file"],
            ),
            mock.patch.object(
                cli,
                "default_watchdog_controller_ca_key_path",
                return_value=paths["watchdog_controller_ca_key_file"],
            ),
            mock.patch.object(
                cli,
                "default_controller_allowlist_path",
                return_value=paths["watchdog_controller_allowlist_file"],
            ),
            mock.patch.object(cli, "read_service_config") as legacy_config,
        ):
            config = cli._controller_management_config(None)

        legacy_config.assert_not_called()
        self.assertEqual(config["installation_id"], identity.installation_id)
        self.assertEqual(config["watchdog_listen"], "0.0.0.0")
        self.assertEqual(config["watchdog_port"], cli.WATCHDOG_TELEMETRY_PORT)
        for key, path in paths.items():
            self.assertEqual(config[key], str(path))

    def test_logs_resolve_the_only_local_placement_group_without_legacy_service(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            placement_group_id = "a" * 32
            member_id = "b" * 32
            task_id = "task-0"
            placement_id = "c" * 32
            name = f"letsinfer-placement-{placement_id}"
            group_root = root / placement_group_id
            group_root.mkdir()
            group_root.chmod(0o700)
            config = {
                "schema_version": 2,
                "placement_group_id": placement_group_id,
                "placement_id": placement_id,
                "node_id": member_id,
                "placement": {"task_id": task_id},
                "container_name": name,
            }
            config_path = group_root / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            config_path.chmod(0o600)
            inspection = {
                "Config": {
                    "Labels": {
                        cli.MANAGED_LABEL: "true",
                        cli.PLACEMENT_GROUP_ID_LABEL: placement_group_id,
                        cli.PLACEMENT_ID_LABEL: placement_id,
                        cli.PLACEMENT_NODE_LABEL: member_id,
                        cli.PLACEMENT_TASK_LABEL: task_id,
                    }
                }
            }
            arguments = types.SimpleNamespace(
                config=None,
                placement_group=None,
                tail=7,
                follow=False,
            )
            with (
                mock.patch.object(cli, "default_placement_group_root", return_value=root),
                mock.patch.object(
                    cli,
                    "qualification_service_config_path",
                    return_value=root / "missing-qualification.json",
                ),
                mock.patch.object(
                    cli,
                    "default_service_config_path",
                    return_value=root / "missing-service.json",
                ),
                mock.patch.object(cli, "container_inspect", return_value=inspection),
                mock.patch.object(cli, "run_passthrough") as passthrough,
            ):
                self.assertEqual(cli.logs(arguments), 0)

        passthrough.assert_called_once_with(
            ["docker", "logs", "--timestamps", "--tail", "7", name],
            visible=True,
        )

    def test_controller_listing_uses_the_core_plane_configuration(self) -> None:
        identity = types.SimpleNamespace(installation_id="a" * 64)
        config = {
            "installation_id": identity.installation_id,
            "watchdog_controller_allowlist_file": "/controllers.allow",
        }
        store = mock.MagicMock()
        store.controllers.return_value = []
        arguments = types.SimpleNamespace(
            config=None,
            operation="list",
            controller=None,
            json=True,
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                cli, "_controller_management_config", return_value=config
            ) as management_config,
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(cli, "SiteStore", return_value=store),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.controllers(arguments), 0)

        management_config.assert_called_once_with(None)
        self.assertEqual(json.loads(output.getvalue())["controllers"], [])

    def test_logs_require_an_exact_group_when_multiple_are_local(self) -> None:
        arguments = types.SimpleNamespace(
            config=None,
            placement_group=None,
            tail=200,
            follow=False,
        )
        with (
            mock.patch.object(
                cli,
                "qualification_service_config_path",
                return_value=pathlib.Path("/missing-qualification.json"),
            ),
            mock.patch.object(
                cli,
                "_local_placement_group_log_targets",
                return_value=[("a" * 32, "first"), ("b" * 32, "second")],
            ),
            self.assertRaisesRegex(
                cli.LetsInferError, "specify --placement-group"
            ),
        ):
            cli.logs(arguments)

    def test_placement_group_lifecycle_lock_serializes_threads(self) -> None:
        first_acquired = threading.Event()
        release_first = threading.Event()
        second_attempted = threading.Event()
        second_acquired = threading.Event()

        def first() -> None:
            with cli._placement_group_lifecycle_lock():
                first_acquired.set()
                release_first.wait(2)

        def second() -> None:
            second_attempted.set()
            with cli._placement_group_lifecycle_lock():
                second_acquired.set()

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            cli,
            "default_placement_group_root",
            return_value=pathlib.Path(directory) / "groups",
        ):
            first_thread = threading.Thread(target=first)
            second_thread = threading.Thread(target=second)
            first_thread.start()
            self.assertTrue(first_acquired.wait(1))
            second_thread.start()
            self.assertTrue(second_attempted.wait(1))
            self.assertFalse(second_acquired.wait(0.05))
            release_first.set()
            first_thread.join(2)
            second_thread.join(2)

        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())
        self.assertTrue(second_acquired.is_set())

    def test_benchmark_placement_borrows_only_overlapping_group_devices(self) -> None:
        member_id = "a" * 32
        placement_group_id = "b" * 32
        identity = types.SimpleNamespace(
            site_id="c" * 32,
            coordinator_id=member_id,
        )
        graph = mock.Mock()
        graph.members = {member_id: {"member_id": member_id}}
        graph.resolve.side_effect = cli.TopologyError("device is allocated")
        placement = types.SimpleNamespace(
            node_ids=(member_id,),
            device_uuids={member_id: ("GPU-0",)},
            topology_sha256="d" * 64,
        )
        unallocated = mock.Mock()
        unallocated.resolve.return_value = placement
        store = mock.Mock()
        store.device_allocations.return_value = [
            {
                "placement_id": "1" * 32,
                "node_id": member_id,
                "device_uuid": "GPU-0",
            },
            {
                "placement_id": "2" * 32,
                "node_id": member_id,
                "device_uuid": "GPU-1",
            },
        ]
        store.placements.return_value = [
            {
                "placement_id": "1" * 32,
                "placement_group_id": placement_group_id,
            },
            {
                "placement_id": "2" * 32,
                "placement_group_id": "e" * 32,
            },
        ]
        store.placement_groups.return_value = [
            {
                "placement_group_id": placement_group_id,
                "state": "running",
                "desired_state": "running",
            }
        ]
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        manifest = cli.runtime_execution_manifest(
            runtime_candidate(), qualified=False
        )
        with (
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(
                cli, "_fresh_site_topology", return_value=(identity, graph)
            ),
            mock.patch.object(cli, "TopologyGraph", return_value=unallocated) as topology,
            mock.patch.object(cli, "_site_store", return_value=store_context),
        ):
            resolved, groups = cli.resolve_benchmark_service_placement(
                manifest, "f" * 64
            )

        self.assertEqual(groups, (placement_group_id,))
        graph.resolve.assert_called_once()
        self.assertEqual(resolved["placement_node_ids"], [member_id])
        self.assertEqual(
            topology.call_args.kwargs["allocated_devices"], {member_id: ()}
        )

    def test_benchmark_placement_prefers_an_unallocated_device(self) -> None:
        member_id = "a" * 32
        identity = types.SimpleNamespace(
            site_id="b" * 32,
            coordinator_id=member_id,
        )
        placement = types.SimpleNamespace(
            node_ids=(member_id,),
            device_uuids={member_id: ("GPU-1",)},
            topology_sha256="c" * 64,
        )
        graph = mock.Mock()
        graph.members = {member_id: {"member_id": member_id}}
        graph.resolve.return_value = placement
        store = mock.Mock()
        store.device_allocations.return_value = [
            {
                "placement_id": "1" * 32,
                "node_id": member_id,
                "device_uuid": "GPU-0",
            }
        ]
        store.placements.return_value = [
            {
                "placement_id": "1" * 32,
                "placement_group_id": "d" * 32,
            }
        ]
        store.placement_groups.return_value = []
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        manifest = cli.runtime_execution_manifest(
            runtime_candidate(), qualified=False
        )
        with (
            mock.patch.object(
                cli, "_fresh_site_topology", return_value=(identity, graph)
            ),
            mock.patch.object(cli, "TopologyGraph") as topology,
            mock.patch.object(cli, "_site_store", return_value=store_context),
        ):
            _resolved, groups = cli.resolve_benchmark_service_placement(
                manifest, "e" * 64
            )

        self.assertEqual(groups, ())
        topology.assert_not_called()

    def test_parallel_benchmark_binds_one_exact_installed_group(self) -> None:
        member_ids = ("a" * 32, "b" * 32)
        placement_group_id = "c" * 32
        manifest_sha256 = "d" * 64
        identity = types.SimpleNamespace(
            site_id="e" * 32,
            coordinator_id=member_ids[0],
        )
        graph = mock.Mock()
        graph.members = {
            member_id: {"member_id": member_id} for member_id in member_ids
        }
        graph.resolve.side_effect = cli.TopologyError("devices are allocated")
        store = mock.Mock()
        store.placement_groups.return_value = [
            {
                "placement_group_id": placement_group_id,
                "manifest_sha256": manifest_sha256,
                "topology_sha256": "f" * 64,
                "state": "running",
                "desired_state": "running",
                "plan": {
                    "schema_version": 1,
                    "placement_group_id": placement_group_id,
                    "endpoint_placement_id": "1" * 32,
                    "release": {"target_id": "fixture-target"},
                    "placements": [
                        {
                            "placement_id": f"{index + 1:032x}",
                            "node_id": member_id,
                            "device_uuids": [device_uuid],
                        }
                        for index, (member_id, device_uuid) in enumerate(
                            zip(member_ids, ("GPU-0", "GPU-1"))
                        )
                    ]
                },
            }
        ]
        store.members.return_value = [
            {
                "member_id": member_id,
                "state": "active",
                "facts": {"observed_at_unix": 100},
            }
            for member_id in member_ids
        ]
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        manifest = cli.runtime_execution_manifest(
            runtime_candidate(), qualified=False
        )
        manifest["target"]["placement"] = {
            "strategy": "parallel",
            "node_count": 2,
            "interconnect": {
                "kind": "connectx",
                "rdma_required": True,
                "minimum_speed_mbps": 100_000,
                "minimum_mtu": 1500,
            },
        }
        store.placement_groups.return_value[0]["plan"]["release"][
            "target_id"
        ] = manifest["target"]["id"]
        with (
            mock.patch.object(
                cli, "_fresh_site_topology", return_value=(identity, graph)
            ),
            mock.patch.object(cli, "_site_store", return_value=store_context),
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(
                cli,
                "validate_placement_group_document",
                side_effect=lambda value: value,
            ),
            mock.patch.object(
                cli, "validate_placement_group_target_interconnect"
            ),
            mock.patch.object(
                cli, "_placement_group_required_link_failure", return_value=None
            ),
            mock.patch.object(cli.time, "time", return_value=100),
        ):
            resolved, groups = cli.resolve_benchmark_service_placement(
                manifest, manifest_sha256
            )

        self.assertEqual(groups, (placement_group_id,))
        self.assertEqual(resolved["placement_group_id"], placement_group_id)

    def test_qualification_reuses_only_a_stopped_resident_placement_group_slot(self) -> None:
        placement_group_id = "a" * 32
        placement = {"placement_id": "b" * 32}
        with (
            mock.patch.object(
                cli,
                "resolve_benchmark_service_placement",
                return_value=(placement, (placement_group_id,)),
            ),
            mock.patch.object(
                cli,
                "_benchmark_placement_group_intents",
                return_value={placement_group_id: False},
            ),
        ):
            self.assertIs(
                cli._resolve_qualification_service_placement({}, "c" * 64),
                placement,
            )

        with (
            mock.patch.object(
                cli,
                "resolve_benchmark_service_placement",
                return_value=(placement, (placement_group_id,)),
            ),
            mock.patch.object(
                cli,
                "_benchmark_placement_group_intents",
                return_value={placement_group_id: True},
            ),
            self.assertRaisesRegex(
                cli.LetsInferError,
                "requires conflicting resident placement groups to be stopped",
            ),
        ):
            cli._resolve_qualification_service_placement({}, "c" * 64)

    def test_benchmark_isolation_restores_running_group_on_success_and_failure(
        self,
    ) -> None:
        placement_group_id = "a" * 32
        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                events: list[str] = []

                def benchmark(command: list[str], **_: object) -> None:
                    events.append("benchmark")
                    if failure:
                        raise cli.LetsInferError("fixture benchmark failed")

                with (
                    mock.patch.object(
                        cli,
                        "qualification_service_config_path",
                        return_value=pathlib.Path(directory) / "missing.json",
                    ),
                    mock.patch.object(cli, "protection_trip_latched", return_value=False),
                    mock.patch.object(
                        cli,
                        "_unit_enabled_active",
                        return_value=("disabled", "inactive"),
                    ),
                    mock.patch.object(
                        cli,
                        "_benchmark_placement_group_intents",
                        return_value={placement_group_id: True},
                    ),
                    mock.patch.object(
                        cli,
                        "_stop_placement_group_by_id",
                        side_effect=lambda _placement_group_id: events.append("stop"),
                    ),
                    mock.patch.object(
                        cli,
                        "_start_placement_group_by_id",
                        side_effect=lambda _placement_group_id: events.append("start"),
                    ),
                    mock.patch.object(
                        cli,
                        "_gateway_is_idle",
                        side_effect=lambda: events.append("idle"),
                    ),
                    mock.patch.object(cli, "run_passthrough", side_effect=benchmark),
                ):
                    if failure:
                        with self.assertRaisesRegex(
                            cli.LetsInferError, "fixture benchmark failed"
                        ):
                            cli._run_benchmark_with_service_isolation(
                                ["matrix"], resident_placement_group_ids=(placement_group_id,)
                            )
                    else:
                        cli._run_benchmark_with_service_isolation(
                            ["matrix"], resident_placement_group_ids=(placement_group_id,)
                        )
                self.assertEqual(events, ["idle", "stop", "benchmark", "start"])

    def test_parallel_benchmark_restarts_and_keeps_running_exact_group(self) -> None:
        placement_group_id = "a" * 32
        events: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    cli,
                    "qualification_service_config_path",
                    return_value=pathlib.Path(directory) / "missing.json",
                ),
                mock.patch.object(
                    cli, "protection_trip_latched", return_value=False
                ),
                mock.patch.object(
                    cli,
                    "_unit_enabled_active",
                    return_value=("disabled", "inactive"),
                ),
                mock.patch.object(
                    cli,
                    "_benchmark_placement_group_intents",
                    return_value={placement_group_id: True},
                ),
                mock.patch.object(
                    cli,
                    "_gateway_is_idle",
                    side_effect=lambda: events.append("idle"),
                ),
                mock.patch.object(
                    cli,
                    "_stop_placement_group_by_id",
                    side_effect=lambda _placement_group_id: events.append("stop"),
                ),
                mock.patch.object(
                    cli,
                    "_start_placement_group_by_id",
                    side_effect=lambda _placement_group_id: events.append("start"),
                ),
                mock.patch.object(
                    cli,
                    "run_passthrough",
                    side_effect=lambda *_args, **_kwargs: events.append("benchmark"),
                ),
            ):
                cli._run_benchmark_with_service_isolation(
                    ["matrix"],
                    resident_placement_group_ids=(placement_group_id,),
                    benchmark_placement_group_id=placement_group_id,
                )

        self.assertEqual(events, ["idle", "stop", "start", "benchmark"])

    def test_stopped_placement_group_restoration_uses_start(self) -> None:
        placement_group_id = "a" * 32
        row = {
            "placement_group_id": placement_group_id,
            "state": "stopped",
            "desired_state": "stopped",
        }
        store = mock.Mock()
        store.placement_groups.return_value = [row]
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        orchestrator = mock.Mock()
        started = {"placement_group_id": placement_group_id, "state": "running"}
        orchestrator.start.return_value = started
        with (
            mock.patch.object(
                cli,
                "_placement_group_lifecycle_lock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch.object(cli, "_site_store", return_value=store_context),
            mock.patch.object(
                cli,
                "_restore_placement_group_orchestrator",
                return_value=(orchestrator, {}),
            ),
        ):
            cli._start_placement_group_by_id(placement_group_id)

        orchestrator.start.assert_called_once_with()
        orchestrator.recover.assert_not_called()

    def test_stopped_group_cannot_resume_before_link_reverification(self) -> None:
        placement_group_id = "a" * 32
        row = {
            "placement_group_id": placement_group_id,
            "state": "stopped",
            "desired_state": "stopped",
        }
        store = mock.Mock()
        store.placement_groups.return_value = [row]
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        with (
            mock.patch.object(
                cli,
                "_placement_group_lifecycle_lock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch.object(cli, "_site_store", return_value=store_context),
            mock.patch.object(
                cli,
                "_placement_group_required_link_failure",
                return_value="required_link_unavailable",
            ),
            mock.patch.object(cli, "_restore_placement_group_orchestrator") as restore,
            self.assertRaisesRegex(cli.LetsInferError, "required node link"),
        ):
            cli._start_placement_group_by_id(placement_group_id)
        restore.assert_not_called()

    def test_benchmark_failure_retains_original_error_when_restore_fails(self) -> None:
        placement_group_id = "a" * 32
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    cli,
                    "qualification_service_config_path",
                    return_value=pathlib.Path(directory) / "missing.json",
                ),
                mock.patch.object(cli, "protection_trip_latched", return_value=False),
                mock.patch.object(
                    cli,
                    "_unit_enabled_active",
                    return_value=("disabled", "inactive"),
                ),
                mock.patch.object(
                    cli,
                    "_benchmark_placement_group_intents",
                    return_value={placement_group_id: True},
                ),
                mock.patch.object(cli, "_gateway_is_idle"),
                mock.patch.object(cli, "_stop_placement_group_by_id"),
                mock.patch.object(
                    cli,
                    "_start_placement_group_by_id",
                    side_effect=cli.LetsInferError("fixture restore failed"),
                ),
                mock.patch.object(
                    cli,
                    "run_passthrough",
                    side_effect=cli.LetsInferError("fixture benchmark failed"),
                ),
            ):
                with self.assertRaisesRegex(
                    cli.LetsInferError,
                    "benchmark failed: fixture benchmark failed; service restoration "
                    "was incomplete: restore placement group .*: fixture restore failed",
                ):
                    cli._run_benchmark_with_service_isolation(
                        ["matrix"], resident_placement_group_ids=(placement_group_id,)
                    )

    def test_benchmark_isolation_restores_group_when_stop_fails(self) -> None:
        placement_group_id = "a" * 32
        events: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            def fail_stop(_placement_group_id: str) -> None:
                events.append("stop")
                raise cli.LetsInferError("fixture stop failed")

            with (
                mock.patch.object(
                    cli,
                    "qualification_service_config_path",
                    return_value=pathlib.Path(directory) / "missing.json",
                ),
                mock.patch.object(cli, "protection_trip_latched", return_value=False),
                mock.patch.object(
                    cli,
                    "_unit_enabled_active",
                    return_value=("disabled", "inactive"),
                ),
                mock.patch.object(
                    cli,
                    "_benchmark_placement_group_intents",
                    return_value={placement_group_id: True},
                ),
                mock.patch.object(
                    cli,
                    "_gateway_is_idle",
                    side_effect=lambda: events.append("idle"),
                ),
                mock.patch.object(
                    cli,
                    "_stop_placement_group_by_id",
                    side_effect=fail_stop,
                ),
                mock.patch.object(
                    cli,
                    "_start_placement_group_by_id",
                    side_effect=lambda _placement_group_id: events.append("start"),
                ),
            ):
                with self.assertRaisesRegex(cli.LetsInferError, "fixture stop failed"):
                    cli._run_benchmark_with_service_isolation(
                        ["matrix"], resident_placement_group_ids=(placement_group_id,)
                    )
        self.assertEqual(events, ["idle", "stop", "start"])

    def test_benchmark_stop_allows_resident_placement_group_restoration(self) -> None:
        with mock.patch.object(
            cli.benchmark_jobs,
            "read_state",
            return_value={
                "metadata": {"resident_placement_group_ids": ["a" * 32]},
            },
        ):
            self.assertEqual(cli._benchmark_stop_timeout_seconds(), 3_600)

    def test_detached_benchmark_binds_resident_placement_groups_into_worker_command(self) -> None:
        parsed = cli.parser().parse_args(["benchmark", "run", "model", "--c1"])
        arguments = cli._benchmark_namespace(parsed, runtime=parsed.model)
        command = cli._benchmark_self_command(
            arguments,
            pathlib.Path("/core/bin/letsinfer"),
            pathlib.Path("/evidence"),
            ("a" * 32,),
        )
        self.assertEqual(command[-2:], ["--resident-placement-group", "a" * 32])

    def test_control_bundle_install_accepts_concurrent_exact_publisher(self) -> None:
        manifest = {"release": "fixture-release"}
        adapter = types.SimpleNamespace(name="fixture-engine")
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)

            def collide(source: pathlib.Path, destination: pathlib.Path) -> None:
                self.assertTrue(source.name.startswith("."))
                destination.mkdir(mode=0o700)
                (destination / "runtime-execution.json").write_bytes(
                    cli.canonical_bytes(manifest)
                )
                raise OSError(errno.ENOTEMPTY, "Directory not empty")

            with (
                mock.patch.object(
                    cli,
                    "_core_release",
                    return_value=([], {"schema_version": 1}, "a" * 64),
                ),
                mock.patch.object(
                    cli,
                    "validate_control_bundle",
                    side_effect=lambda _root, path, _sha, **_kwargs: (path, manifest),
                ) as validate,
                mock.patch.object(cli, "adapter_for", return_value=adapter),
                mock.patch.object(
                    pathlib.Path,
                    "replace",
                    autospec=True,
                    side_effect=collide,
                ),
            ):
                root, runtime_manifest = cli.install_control_bundle(
                    pathlib.Path("/runtime-execution.json"),
                    manifest,
                    control_parent=parent,
                )

            self.assertTrue(root.is_dir())
            self.assertEqual(runtime_manifest, root / "runtime-execution.json")
            self.assertEqual(validate.call_count, 2)
            self.assertFalse(any(parent.glob(".*.install-*")))

    def test_control_bundle_validation_uses_its_recorded_source_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            source_content = b"historical source\n"
            source_manifest = {
                "schema_version": 1,
                "product": "letsinfer",
                "files": [
                    {
                        "path": "legacy/removed.py",
                        "bytes": len(source_content),
                        "mode": 0o644,
                        "sha256": hashlib.sha256(source_content).hexdigest(),
                    }
                ],
            }
            source_manifest_data = cli.canonical_bytes(source_manifest)
            runtime_manifest_data = b"{}\n"
            runtime_manifest_sha = hashlib.sha256(runtime_manifest_data).hexdigest()
            core_identity = hashlib.sha256(source_manifest_data).hexdigest()
            bundle_identity = cli._control_bundle_identity(
                core_identity, runtime_manifest_sha
            )
            root = parent / bundle_identity
            legacy = root / "legacy"
            legacy.mkdir(parents=True, mode=0o700)
            root.chmod(0o700)
            legacy.chmod(0o700)
            source = legacy / "removed.py"
            source.write_bytes(source_content)
            source.chmod(0o400)
            core_manifest = root / cli.CORE_SOURCE_MANIFEST
            core_manifest.write_bytes(source_manifest_data)
            core_manifest.chmod(0o400)
            runtime_manifest = root / "runtime-execution.json"
            runtime_manifest.write_bytes(runtime_manifest_data)
            runtime_manifest.chmod(0o400)

            with (
                mock.patch.object(cli, "validate_manifest"),
                mock.patch.object(cli, "verify_runtime_sources"),
                mock.patch.object(
                    cli,
                    "_core_release",
                    side_effect=AssertionError(
                        "control validation must not apply the current source policy"
                    ),
                ),
            ):
                installed_path, installed = cli.validate_control_bundle(
                    root, runtime_manifest, runtime_manifest_sha
                )
                self.assertEqual(installed_path, runtime_manifest.resolve())
                self.assertEqual(installed, {})

                unexpected = root / "unexpected.py"
                unexpected.write_text("unexpected\n", encoding="utf-8")
                unexpected.chmod(0o400)
                with self.assertRaisesRegex(
                    cli.LetsInferError, "source file set mismatch"
                ):
                    cli.validate_control_bundle(
                        root, runtime_manifest, runtime_manifest_sha
                    )

    def test_node_agent_memory_envelope_supports_runtime_staging(self) -> None:
        unit = cli.render_node_service(pathlib.Path("/opt/letsinfer"))
        self.assertIn("MemoryHigh=134217728\n", unit)
        self.assertIn("MemoryMax=201326592\n", unit)
        self.assertIn(
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n",
            unit,
        )

    def test_startup_oom_has_a_concise_engine_error(self) -> None:
        inspection = {
            "State": {
                "Running": False,
                "OOMKilled": True,
                "ExitCode": 137,
                "Error": "",
            }
        }
        with (
            mock.patch.object(cli, "container_inspect", return_value=inspection),
            self.assertRaisesRegex(
                cli.LetsInferError, "Engine container was OOM-killed during startup"
            ),
        ):
            cli.wait_for_ready(
                "engine",
                18000,
                1,
                pathlib.Path("/tmp/server.crt"),
                {},
            )

    def test_service_commits_runtime_selection_before_engine_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            events: list[str] = []
            config = {
                "name": "letsinfer-example",
                "source_root": str(root),
                "protection_root": str(root / "protection"),
            }
            manifest = {"container": {"startup_timeout_seconds": 30}}
            receipt = {"logical_model": "example-model"}
            completed = mock.Mock(returncode=0, stdout="", stderr="")

            def start(command: list[str]) -> None:
                if command[-1] == cli.ENGINE_SERVICE_NAME:
                    self.assertIn("selection", events)
                events.append(command[-1])

            with (
                mock.patch.object(
                    cli, "_unit_enabled_active", return_value=("disabled", "inactive")
                ),
                mock.patch.object(cli, "selections", return_value=[]),
                mock.patch.object(
                    cli, "write_selection", side_effect=lambda _receipt: events.append("selection")
                ),
                mock.patch.object(cli, "run", return_value=completed),
                mock.patch.object(cli, "run_passthrough", side_effect=start),
                mock.patch.object(
                    cli, "_service_state", return_value=("enabled", "active", 1024)
                ),
                mock.patch.object(cli, "wait_for_core_plane_ready"),
                mock.patch.object(cli, "render_engine_service", return_value="unit\n"),
                mock.patch.object(cli, "render_gateway_service", return_value="unit\n"),
                mock.patch.object(cli, "render_user_service", return_value="unit\n"),
                mock.patch.object(cli, "render_node_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_timer", return_value="unit\n"),
            ):
                cli.install_user_service(
                    root / "service.json",
                    config,
                    manifest,
                    no_start=False,
                    runtime_receipt=receipt,
                    unit_dir=root / "units",
                )

            self.assertLess(events.index("selection"), events.index(cli.ENGINE_SERVICE_NAME))

    def test_failed_service_activation_restores_runtime_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            events: list[str] = []
            config = {
                "name": "letsinfer-example",
                "source_root": str(root),
                "protection_root": str(root / "protection"),
            }
            manifest = {"container": {"startup_timeout_seconds": 30}}
            receipt = {"logical_model": "example-model"}
            completed = mock.Mock(returncode=0, stdout="", stderr="")

            def start(command: list[str]) -> None:
                if command[-1] == cli.ENGINE_SERVICE_NAME:
                    raise cli.LetsInferError("synthetic engine failure")

            with (
                mock.patch.object(
                    cli, "_unit_enabled_active", return_value=("disabled", "inactive")
                ),
                mock.patch.object(cli, "selections", return_value=[]),
                mock.patch.object(
                    cli, "write_selection", side_effect=lambda _receipt: events.append("selection")
                ),
                mock.patch.object(
                    cli,
                    "restore_selection",
                    side_effect=lambda _replacement, _previous: events.append("restore"),
                ),
                mock.patch.object(cli, "run", return_value=completed),
                mock.patch.object(cli, "run_passthrough", side_effect=start),
                mock.patch.object(
                    cli, "_service_state", return_value=("enabled", "active", 1024)
                ),
                mock.patch.object(cli, "wait_for_core_plane_ready"),
                mock.patch.object(cli, "container_inspect", return_value=None),
                mock.patch.object(cli, "render_engine_service", return_value="unit\n"),
                mock.patch.object(cli, "render_gateway_service", return_value="unit\n"),
                mock.patch.object(cli, "render_user_service", return_value="unit\n"),
                mock.patch.object(cli, "render_node_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_timer", return_value="unit\n"),
                self.assertRaisesRegex(cli.LetsInferError, "previous installation restored"),
            ):
                cli.install_user_service(
                    root / "service.json",
                    config,
                    manifest,
                    no_start=False,
                    runtime_receipt=receipt,
                    unit_dir=root / "units",
                )

            self.assertEqual(events, ["selection", "restore"])

    def test_qualification_placement_is_validated_without_gateway_registration(self) -> None:
        identity = types.SimpleNamespace(
            site_id="0" * 32,
            member_id="1" * 32,
        )
        adapter = types.SimpleNamespace(
            name="example-engine",
            token_count_path="/v1/count_tokens",
            token_count_protocol="engine-rendered-chat-count-v1",
        )
        config = {
            "placement_id": "2" * 32,
            "placement_node_ids": [identity.member_id],
            "model": "example-model",
            "topology_sha256": "3" * 64,
            "runtime_version": "1.2.3",
            "runtime_digest": "4" * 64,
            "engine_port": 18000,
            "engine_api_key_file": "/secrets/engine.key",
            "tls_cert_file": "/config/server.crt",
            "release": "runtime-release",
            "manifest_sha256": "5" * 64,
        }
        manifest = {
            "model": {"alias": "example-model"},
            "serving": {
                "max_connections": 16,
                "max_active_requests": 8,
                "max_context_tokens": 65536,
            },
        }
        with (
            mock.patch.object(cli, "read_site_identity", return_value=identity),
        ):
            self.assertIsNone(
                cli.update_service_placement(config, manifest, "running")
            )

    def test_core_prune_retains_installed_runtime_and_rollback_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            control = root / "control"
            current = control / ("1" * 64)
            previous = control / ("2" * 64)
            receipt = {
                "control_root": str(current),
                "history": [{"control_root": str(previous)}],
            }
            with (
                mock.patch.object(cli, "default_control_parent", return_value=control),
                mock.patch.object(
                    cli, "default_service_config_path", return_value=root / "service.json"
                ),
                mock.patch.object(
                    cli,
                    "qualification_service_config_path",
                    return_value=root / "qualification.json",
                ),
                mock.patch.object(
                    cli, "default_placement_group_root", return_value=root / "groups"
                ),
                mock.patch.object(cli, "selections", return_value=[receipt]),
                mock.patch.object(
                    cli, "core_watchdog_source_identity", return_value="3" * 64
                ),
            ):
                controls, watchdogs = cli._core_artifact_references()

            self.assertEqual(
                controls,
                {current.resolve(strict=False), previous.resolve(strict=False)},
            )
            self.assertEqual(watchdogs, {"3" * 64})

    def test_tls_generation_supports_split_config_and_secret_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            certificate = root / "config" / "tls" / "server.crt"
            private_key = root / "secrets" / "tls" / "server.key"

            def generate(command: list[str], **_: object) -> mock.Mock:
                pathlib.Path(command[command.index("-out") + 1]).write_text(
                    "certificate", encoding="ascii"
                )
                pathlib.Path(command[command.index("-keyout") + 1]).write_text(
                    "private-key", encoding="ascii"
                )
                return mock.Mock(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(cli, "run", side_effect=generate),
                mock.patch.object(cli, "validate_tls_material"),
                mock.patch.object(cli, "_certificate_names", return_value=["localhost"]),
            ):
                cli.ensure_tls_material(certificate, private_key)

            self.assertEqual(certificate.read_text(encoding="ascii"), "certificate")
            self.assertEqual(private_key.read_text(encoding="ascii"), "private-key")
            self.assertEqual(private_key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(certificate.stat().st_mode & 0o777, 0o644)

    def test_watchdog_tls_generation_supports_split_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / "config" / "watchdog"
            secrets = root / "secrets" / "watchdog"
            paths = (
                config / "server.crt",
                secrets / "server.key",
                config / "controller-ca.crt",
                secrets / "controller-ca.key",
                config / "local-controller.crt",
                secrets / "local-controller.key",
            )

            def generate(command: list[str], **_: object) -> mock.Mock:
                for option in ("-out", "-keyout"):
                    if option in command:
                        pathlib.Path(command[command.index(option) + 1]).write_text(
                            option, encoding="ascii"
                        )
                return mock.Mock(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(cli, "run", side_effect=generate),
                mock.patch.object(cli, "validate_watchdog_tls_material"),
                mock.patch.object(cli, "_validate_watchdog_controller_material"),
                mock.patch.object(cli, "_certificate_names", return_value=["localhost"]),
            ):
                cli.ensure_watchdog_tls_material(*paths)

            for path in paths:
                self.assertTrue(path.is_file())
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_first_runtime_can_create_a_qualification_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest_path = root / "runtime.json"
            manifest_path.write_text("{}\n", encoding="ascii")
            runtime = runtime_candidate()
            manifest = cli.runtime_execution_manifest(runtime, qualified=False)
            receipt = {
                "candidate_id": runtime["id"],
                "version": runtime["version"],
                "digest": "5" * 64,
                "policy": "local",
            }
            with (
                mock.patch.object(
                    cli, "default_service_config_path", return_value=root / "missing.json"
                ),
                mock.patch.object(
                    cli,
                    "_qualification_core_plane_config",
                    return_value={"watchdog_data_root": str(root / "watchdog")},
                ),
                mock.patch.object(
                    cli,
                    "install_control_bundle",
                    return_value=(root / "control", manifest_path),
                ),
                mock.patch.object(
                    cli,
                    "_resolve_qualification_service_placement",
                    return_value={
                        "placement_id": "6" * 32,
                        "placement_strategy": "single",
                        "placement_members": ["7" * 32],
                        "topology_sha256": "8" * 64,
                    },
                ),
            ):
                config = cli._qualification_config(
                    manifest_path=manifest_path,
                    manifest=manifest,
                    release_root=root,
                    manifest_sha256="9" * 64,
                    name="letsinfer-example",
                    port=18000,
                    model_cache=root / "models",
                    store_root=root / "store",
                    runtime_cache_root=root / "cache",
                    api_key_file=root / "engine.key",
                    tls_cert_file=root / "server.crt",
                    tls_key_file=root / "server.key",
                    evidence_dir=root / "evidence",
                    runtime_receipt=receipt,
                )

            self.assertTrue(config["qualification_mode"])
            self.assertEqual(config["runtime_name"], runtime["id"])
            self.assertEqual(
                config["protection_root"],
                str(
                    (root / "watchdog").resolve()
                    / cli.PROTECTION_ROOT_NAME
                    / ("6" * 32)
                ),
            )

    def test_qualification_core_plane_uses_the_managed_engine_key(self) -> None:
        with (
            mock.patch.object(
                cli,
                "verify_active_core_watchdog",
                return_value=(pathlib.Path("/watchdog"), "1" * 64),
            ),
            mock.patch.object(cli, "core_watchdog_source_identity", return_value="2" * 64),
            mock.patch.object(
                cli,
                "ensure_installation_identity",
                return_value={"installation_id": "3" * 64},
            ),
            mock.patch.object(
                cli,
                "default_engine_api_key_path",
                return_value=pathlib.Path("/secrets/engine/api-key"),
            ),
        ):
            config = cli._qualification_core_plane_config()

        self.assertEqual(config["engine_api_key_file"], "/secrets/engine/api-key")

    def test_legacy_commands_are_not_registered(self) -> None:
        parser = cli.parser()
        for command in (
            "setup",
            "hardware",
            "child",
            "alias",
            "list",
            "runtimes",
            "pack",
            "inspect",
            "install",
            "scale",
            "serve",
            "start",
            "stop",
            "restart",
            "recover",
            "upgrade",
            "rollback",
            "pair",
            "controllers",
            "key",
            "expose",
            "unexpose",
            "derive",
            "engines",
            "releases",
        ):
            with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args([command])

    def test_install_selects_runtime_not_engine(self) -> None:
        arguments = cli.parser().parse_args(
            [
                "model",
                "install",
                "example-model",
                "--runtime",
                "example-engine--example--model--test-target",
            ]
        )
        self.assertEqual(arguments.model, "example-model")
        self.assertEqual(
            arguments.runtime,
            "example-engine--example--model--test-target",
        )
        self.assertFalse(hasattr(arguments, "engine"))

    def test_direct_install_enters_managed_group_placement(self) -> None:
        arguments = types.SimpleNamespace(
            model="/tmp/runtime",
            runtime=None,
            runtime_policy=None,
            catalog=None,
        )
        manifest_path = pathlib.Path("/runtime/runtime-execution.json")
        control_root = pathlib.Path("/runtime/control")
        manifest = {"model": {"alias": "example-model"}}
        receipt = {"object_root": "/runtime/object"}
        runtime = mock.Mock(digest="a" * 64)
        placement = (mock.sentinel.identity, mock.sentinel.graph, mock.sentinel.placement)
        with (
            mock.patch.object(cli, "_install_catalog_nodes", return_value=None),
            mock.patch.object(
                cli,
                "_runtime_source_for_install",
                return_value=("/tmp/runtime", "local", None, None, None, False),
            ),
            mock.patch.object(
                cli,
                "prepare_runtime_install",
                return_value=(manifest_path, manifest, control_root, receipt),
            ),
            mock.patch.object(cli, "verify_runtime_sources"),
            mock.patch.object(cli, "verify_descriptor", return_value=runtime),
            mock.patch.object(cli, "sha256_file", return_value="b" * 64),
            mock.patch.object(cli, "target_contract", return_value={"id": "target"}),
            mock.patch.object(
                cli, "target_contract_sha256", return_value="c" * 64
            ),
            mock.patch.object(
                cli,
                "_direct_placement_group_release_identity",
                return_value=mock.sentinel.release,
            ) as release_identity,
            mock.patch.object(
                cli, "_resolve_direct_install_placement", return_value=placement
            ),
            mock.patch.object(cli, "install_placement_group", return_value=0) as group,
        ):
            self.assertEqual(cli.install(arguments), 0)

        immutable_source = "letsinfer-object:sha256:" + "a" * 64
        self.assertEqual(release_identity.call_args.kwargs["source"], immutable_source)
        self.assertEqual(group.call_args.kwargs["source"], immutable_source)
        self.assertEqual(group.call_args.kwargs["resolved_topology"], placement)

    def test_engine_identity_is_opaque_to_core(self) -> None:
        runtime = runtime_candidate()
        runtime["engine"]["id"] = "future-engine"
        runtime["id"] = candidate_id(
            "future-engine", runtime["model"]["uri"], runtime["target"]["id"]
        )
        validated = validate_runtime_config(runtime)
        execution = cli.runtime_execution_manifest(validated, qualified=False)
        self.assertEqual(execution["engine"]["name"], "future-engine")
        self.assertEqual(execution["image"]["reference"], runtime["engine"]["distribution"]["reference"])

    def test_parallel_runtime_derives_a_valid_execution_manifest(self) -> None:
        runtime = runtime_candidate()
        runtime["target"]["placement"] = {
            "strategy": "parallel",
            "node_count": 2,
            "interconnect": {
                "kind": "connectx",
                "rdma_required": True,
                "minimum_speed_mbps": 200000,
                "minimum_mtu": 1500,
            },
        }
        runtime["orchestration"] = {
            "schema_version": 3,
            "failure_policy": "whole-group",
            "endpoint_owner": "task-0",
            "startup_order": [["task-0", "task-1"]],
            "tasks": [
                {
                    "task_id": f"task-{index}",
                    "launcher": "runtime-command",
                    "port_count": 4,
                    "command": ["/opt/runtime/launch", f"task-{index}"],
                    "environment": {},
                    "readiness": {
                        "kind": "exec",
                        "command": ["/opt/runtime/ready"],
                        "interval_seconds": 1,
                        "timeout_seconds": 2,
                        "retries": 60,
                    },
                }
                for index in range(2)
            ],
        }

        execution = cli.runtime_execution_manifest(runtime, qualified=False)

        self.assertEqual(execution["orchestration"], runtime["orchestration"])
        cli.validate_manifest(execution)

    def test_execution_manifest_accepts_normalized_engine_payload_identity(self) -> None:
        runtime = runtime_candidate()
        payload = "sha256:" + "8" * 64
        runtime["engine"]["distribution"]["payload_id"] = payload
        execution = cli.runtime_execution_manifest(runtime, qualified=True)
        self.assertEqual(execution["image"]["payload_id"], payload)
        cli.validate_manifest(execution)

        execution["image"]["payload_id"] = "not-a-payload"
        with self.assertRaisesRegex(
            cli.LetsInferError, "must be a SHA-256 execution payload"
        ):
            cli.validate_manifest(execution)

    def test_execution_manifest_accepts_parallel_orchestration(self) -> None:
        runtime = runtime_candidate()
        runtime["target"]["placement"] = {
            "strategy": "parallel",
            "node_count": 3,
            "interconnect": {
                "kind": "ethernet",
                "rdma_required": False,
                "minimum_speed_mbps": 100_000,
                "minimum_mtu": 9_000,
            },
        }
        runtime["orchestration"] = parallel_contract()

        execution = cli.runtime_execution_manifest(runtime, qualified=True)

        self.assertEqual(execution["orchestration"], runtime["orchestration"])

    def test_rc80_execution_manifest_acquisition_is_normalized_exactly(self) -> None:
        execution = cli.runtime_execution_manifest(
            runtime_candidate(), qualified=True
        )
        acquisition = execution["model"].pop("acquisition")
        execution["model"]["acquisition_image"] = acquisition["image"]

        cli.validate_manifest(execution)

        self.assertEqual(execution["model"]["acquisition"], acquisition)
        self.assertNotIn("acquisition_image", execution["model"])

        malformed = cli.runtime_execution_manifest(
            runtime_candidate(), qualified=True
        )
        malformed["model"].pop("acquisition")
        malformed["model"]["acquisition_image"] = "unversioned"
        with self.assertRaisesRegex(cli.LetsInferError, "must be digest-pinned"):
            cli.validate_manifest(malformed)

        mixed = cli.runtime_execution_manifest(runtime_candidate(), qualified=True)
        mixed["model"]["acquisition_image"] = acquisition["image"]
        with self.assertRaisesRegex(cli.LetsInferError, "unsupported fields"):
            cli.validate_manifest(mixed)

    def test_model_store_mirrors_exact_hugging_face_identity_and_revision(self) -> None:
        execution = cli.runtime_execution_manifest(runtime_candidate(), qualified=False)
        artifact = execution["artifacts"][0]
        self.assertEqual(artifact_storage_slug(artifact), "example--model")
        root = pathlib.Path("/letsinfer/models")
        self.assertEqual(
            cli.artifact_snapshot_path(
                {**artifact, "storage_slug": artifact_storage_slug(artifact)}, root
            ),
            root / "example--model" / ("4" * 40),
        )

    def test_runtime_validation_rejects_an_unpinned_model_revision(self) -> None:
        runtime = runtime_candidate()
        runtime["artifacts"][0]["revision"] = "main"
        with self.assertRaisesRegex(RuntimePackError, "full commit SHA"):
            validate_runtime_config(runtime)

    def test_resolve_model_only_considers_installed_runtime_receipts(self) -> None:
        runtime = runtime_candidate()
        execution = cli.runtime_execution_manifest(runtime, qualified=False)
        manifest_path = pathlib.Path("/installed/runtime-execution.json")
        receipt = {
            "candidate_id": runtime["id"],
            "logical_model": runtime["logical_model"],
            "engine": runtime["engine"]["id"],
            "target": runtime["target"]["id"],
            "version": runtime["version"],
            "installed_at": "2026-08-21T00:00:00Z",
        }
        with mock.patch.object(
            cli,
            "installed_runtime_manifests",
            return_value=[(manifest_path, execution, receipt)],
        ):
            selected, selected_manifest = cli.resolve_model("example-model")
        self.assertEqual(selected, manifest_path)
        self.assertIs(selected_manifest, execution)

    def test_unknown_source_tree_is_not_runtime_discovery_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, "release.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(cli, "installed_runtime_manifests", return_value=[]):
                with self.assertRaisesRegex(cli.LetsInferError, "unknown model"):
                    cli.resolve_model(directory)


if __name__ == "__main__":
    unittest.main()
