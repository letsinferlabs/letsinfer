#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import copy
import contextlib
import pathlib
import tempfile
import unittest
from unittest import mock

from core import cli


class LocalEngineGroupExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.member_id = "a" * 32
        self.group_id = "b" * 32
        self.task = {
            "task_id": "task-1",
            "port_base": 18000,
            "port_count": 2,
            "launcher": "runtime-command",
            "command": ["/opt/runtime/member"],
            "environment": {"RUNTIME_MODE": "member"},
            "endpoint_owner": False,
            "readiness": {
                "kind": "exec",
                "command": ["/opt/runtime/ready"],
                "interval_seconds": 1,
                "timeout_seconds": 1,
                "retries": 2,
            },
        }
        self.group = {
            "schema_version": 3,
            "group_id": self.group_id,
            "service": "fixture-model",
            "release": {},
            "strategy": "parallel",
            "failure_policy": "whole-group",
            "topology_sha256": "1" * 64,
            "manifest_sha256": "2" * 64,
            "runtime_digest": "3" * 64,
            "runtime_execution_contract_sha256": "7" * 64,
            "endpoint_owner": "task-0",
            "startup_order": [["task-1"], ["task-0"]],
            "connections": [
                {
                    "nodes": sorted(("c" * 32, self.member_id)),
                    "kind": "connectx",
                    "speed_mbps": 200000,
                    "mtu": 9000,
                    "rdma": True,
                }
            ],
            "resources": [
                {
                    "node_id": "c" * 32,
                    "address": "coordinator.local:9770",
                    "task_id": "task-0",
                    "port_base": 18000,
                    "port_count": 2,
                    "device_uuids": ["GPU-fixture-0"],
                },
                {
                    "node_id": self.member_id,
                    "address": "member.local:9770",
                    "task_id": "task-1",
                    "port_base": 18000,
                    "port_count": 2,
                    "device_uuids": ["GPU-fixture-1"],
                },
            ],
        }
        self.config = {
            "group_id": self.group_id,
            "member_id": self.member_id,
            "plan_sha256": "4" * 64,
            "source": "registry.example/runtime@sha256:" + "5" * 64,
            "runtime_digest": "3" * 64,
            "manifest_sha256": "2" * 64,
            "topology_sha256": "1" * 64,
            "task": self.task,
            "object_root": str(root / "object"),
            "model_cache": str(root / "model"),
            "plugin_root": str(root / "plugins"),
            "store_root": str(root / "store"),
            "runtime_cache_root": str(root / "runtime-cache"),
            "credential_file": str(root / "engine.key"),
            "tls_certificate_file": str(root / "engine.crt"),
            "tls_key_file": str(root / "engine-tls.key"),
            "group_file": str(root / "group.json"),
            "container_name": "letsinfer-group-" + self.group_id,
            "protection_root": str(root / "watchdog" / "protected-engines" / self.group_id),
            "_manifest": {
                "serving": {},
                "container": {
                    "startup_timeout_seconds": 30,
                    "memory_bytes": 120259084288,
                },
            },
            "_group": self.group,
            "_credential_sha256": "6" * 64,
        }
        pathlib.Path(self.config["tls_certificate_file"]).write_text(
            "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
            encoding="ascii",
        )
        self.job = {
            "group_id": self.group_id,
            "member_id": self.member_id,
            "plan_sha256": "4" * 64,
            "runtime_digest": "3" * 64,
            "manifest_sha256": "2" * 64,
            "topology_sha256": "1" * 64,
            "engine_credential_sha256": "6" * 64,
            "task": self.task,
            "group": self.group,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_start_runs_only_sealed_runtime_command_and_arms_protection(self) -> None:
        inspection = {
            "Id": "d" * 64,
            "State": {"Running": True},
            "Config": {"Labels": {}},
        }
        executor = cli.LocalEngineGroupExecutor(self.member_id)
        with (
            mock.patch.object(cli, "_read_engine_group_config", return_value=self.config),
            mock.patch.object(
                cli, "storage_lock", return_value=contextlib.nullcontext()
            ),
            mock.patch.object(cli, "verify_active_core_watchdog"),
            mock.patch.object(cli, "authorize_serving_launch"),
            mock.patch.object(cli, "verify_host_target"),
            mock.patch.object(
                cli,
                "ensure_install_dependencies",
                return_value=("owner/model@revision",),
            ) as dependencies,
            mock.patch.object(cli, "verify_installed_runtime"),
            mock.patch.object(cli, "require_memory_reserve"),
            mock.patch.object(cli, "docker_command", return_value=["docker", "run"]) as command,
            mock.patch.object(cli, "container_inspect", side_effect=[None, inspection, inspection]),
            mock.patch.object(cli, "publish_protection_state") as protect,
            mock.patch.object(cli, "certificate_sha256", return_value="7" * 64),
            mock.patch.object(executor, "_wait_runtime_command") as ready,
            mock.patch.object(cli, "run") as run,
        ):
            result = executor.start(self.job)

        self.assertEqual(result["state"], "running")
        self.assertIsNone(result["endpoint"])
        self.assertEqual(
            result["model_artifacts_downloaded"], ["owner/model@revision"]
        )
        self.assertTrue(dependencies.call_args.kwargs["download"])
        run.assert_called_once_with(["docker", "run"])
        ready.assert_called_once_with(self.config["container_name"], self.task["readiness"])
        self.assertEqual([call.args[2] for call in protect.call_args_list], ["pending", "starting", "armed"])
        self.assertEqual(command.call_args.kwargs["group_context"]["task_id"], "task-1")

    def test_main_node_endpoint_owner_advertises_its_loopback_listener(self) -> None:
        task = {**self.task, "endpoint_owner": True}
        config = {**self.config, "task": task}
        executor = cli.LocalEngineGroupExecutor(self.member_id)
        with (
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=mock.Mock(role="main", member_id=self.member_id),
            ),
            mock.patch.object(cli, "certificate_sha256", return_value="7" * 64),
        ):
            local = executor._safe_result(config, "running")
        self.assertEqual(local["endpoint"], "https://127.0.0.1:18000")

        with (
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=mock.Mock(role="child", member_id=self.member_id),
            ),
            mock.patch.object(cli, "certificate_sha256", return_value="7" * 64),
        ):
            remote = executor._safe_result(config, "running")
        self.assertEqual(remote["endpoint"], "https://member.local:18000")

    def test_rdma_docker_options_are_exact_and_never_privileged(self) -> None:
        binding = {
            "interface": "enp1s0",
            "device": "mlx5_0",
            "local_address": "192.0.2.10",
            "peer_addresses": ["192.0.2.20"],
            "device_nodes": [
                {"path": "/dev/infiniband/rdma_cm", "major": 10, "minor": 57},
                {"path": "/dev/infiniband/uverbs0", "major": 231, "minor": 192},
            ],
        }
        options = cli._rdma_docker_options(binding, 120259084288)
        self.assertNotIn("--privileged", options)
        self.assertIn(
            "/dev/infiniband/uverbs0:/dev/infiniband/uverbs0:rwm", options
        )
        self.assertIn("memlock=120259084288:120259084288", options)
        self.assertIn("LETSINFER_RDMA_INTERFACE=enp1s0", options)
        self.assertIn("LETSINFER_RDMA_DEVICE=mlx5_0", options)

        invalid = {
            **binding,
            "device_nodes": [
                {"path": "/dev/null", "major": 1, "minor": 3}
            ],
        }
        with self.assertRaisesRegex(cli.LetsInferError, "device identity"):
            cli._rdma_docker_options(invalid, 120259084288)

    def test_group_rdma_binding_uses_only_the_sealed_interface_and_peers(self) -> None:
        group = copy.deepcopy(self.group)
        group["resources"][1]["rdma_interface"] = "enp1s0"
        resolved = {
            "interface": "enp1s0",
            "device": "mlx5_0",
            "local_address": "192.0.2.10",
            "peer_addresses": ["192.0.2.20"],
            "device_nodes": [
                {"path": "/dev/infiniband/rdma_cm", "major": 10, "minor": 57},
                {"path": "/dev/infiniband/uverbs0", "major": 231, "minor": 192},
            ],
        }
        with mock.patch.object(
            cli, "resolve_connectx_rdma_binding", return_value=resolved
        ) as resolver:
            self.assertEqual(
                cli._engine_group_rdma_binding(group, self.member_id), resolved
            )
        resolver.assert_called_once_with(
            "enp1s0",
            "member.local",
            ["coordinator.local"],
            minimum_speed_mbps=200000,
            minimum_mtu=9000,
        )
        self.assertIsNone(
            cli._engine_group_rdma_binding(self.group, self.member_id)
        )

    def test_reused_rdma_container_must_match_devices_memlock_and_binding(self) -> None:
        binding = {
            "interface": "enp1s0",
            "device": "mlx5_0",
            "local_address": "192.0.2.10",
            "peer_addresses": ["192.0.2.20"],
            "device_nodes": [
                {"path": "/dev/infiniband/rdma_cm", "major": 10, "minor": 57},
                {"path": "/dev/infiniband/uverbs0", "major": 231, "minor": 192},
            ],
        }
        inspection = {
            "HostConfig": {
                "Devices": [
                    {
                        "PathOnHost": item["path"],
                        "PathInContainer": item["path"],
                        "CgroupPermissions": "rwm",
                    }
                    for item in binding["device_nodes"]
                ],
                "Ulimits": [
                    {"Name": "memlock", "Soft": 1024, "Hard": 1024}
                ],
            },
            "Config": {
                "Env": [
                    "LETSINFER_RDMA_INTERFACE=enp1s0",
                    "LETSINFER_RDMA_DEVICE=mlx5_0",
                ]
            },
        }
        cli._require_matching_rdma_container(inspection, binding, 1024)
        with self.assertRaisesRegex(cli.LetsInferError, "memlock"):
            cli._require_matching_rdma_container(inspection, binding, 2048)
        with self.assertRaisesRegex(cli.LetsInferError, "non-RDMA"):
            cli._require_matching_rdma_container(inspection, None, 1024)

    def test_stop_disarms_before_removing_the_exact_managed_container(self) -> None:
        executor = cli.LocalEngineGroupExecutor(self.member_id)
        with (
            mock.patch.object(cli, "_read_engine_group_config", return_value=self.config),
            mock.patch.object(cli, "disarm_protection") as disarm,
            mock.patch.object(cli, "_stop_managed_container", return_value=0) as stop,
            mock.patch.object(cli, "certificate_sha256", return_value="7" * 64),
        ):
            result = executor.stop(self.job)

        self.assertEqual(result["state"], "stopped")
        disarm.assert_called_once()
        stop.assert_called_once_with(
            self.config["container_name"], pathlib.Path(self.config["credential_file"])
        )

    def test_stop_refuses_to_exit_before_watchdog_disarm_ack(self) -> None:
        executor = cli.LocalEngineGroupExecutor(self.member_id)
        with (
            mock.patch.object(cli, "_read_engine_group_config", return_value=self.config),
            mock.patch.object(
                cli,
                "disarm_protection",
                side_effect=cli.LetsInferError("Watchdog did not acknowledge"),
            ),
            mock.patch.object(cli, "_stop_managed_container") as stop,
        ):
            with self.assertRaisesRegex(
                cli.LetsInferError, "Watchdog did not acknowledge"
            ):
                executor.stop(self.job)
        stop.assert_not_called()

    def test_explicit_recovery_clears_only_its_trip_before_start(self) -> None:
        executor = cli.LocalEngineGroupExecutor(self.member_id)
        with (
            mock.patch.object(cli, "_read_engine_group_config", return_value=self.config),
            mock.patch.object(cli, "clear_protection_trip") as clear,
            mock.patch.object(
                executor, "_start_config", return_value={"state": "running"}
            ) as start,
        ):
            result = executor.recover(self.job)

        self.assertEqual(result, {"state": "running"})
        clear.assert_called_once_with(self.config)
        start.assert_called_once_with(self.config)

    def test_observation_rejects_stale_running_journal_without_container(self) -> None:
        executor = cli.LocalEngineGroupExecutor(self.member_id)
        journal = {
            "group_id": self.group_id,
            "member_id": self.member_id,
            "plan_sha256": self.config["plan_sha256"],
            "runtime_digest": self.config["runtime_digest"],
            "manifest_sha256": self.config["manifest_sha256"],
            "topology_sha256": self.config["topology_sha256"],
            "engine_credential_sha256": self.config["_credential_sha256"],
            "task": self.task,
            "state": "running",
        }
        with (
            mock.patch.object(cli, "_read_engine_group_config", return_value=self.config),
            mock.patch.object(cli, "container_inspect", return_value=None),
            mock.patch.object(
                cli,
                "protection_status",
                return_value={"armed": False, "trip_latched": False},
            ),
        ):
            result = executor.observe(journal)
        self.assertEqual(
            result, {"state": "failed", "protection_trip_latched": False}
        )

    def test_job_identity_mismatch_fails_before_side_effects(self) -> None:
        executor = cli.LocalEngineGroupExecutor(self.member_id)
        changed = dict(self.job)
        changed["runtime_digest"] = "9" * 64
        with mock.patch.object(cli, "_read_engine_group_config", return_value=self.config):
            with self.assertRaisesRegex(cli.LetsInferError, "differs from the staged"):
                executor.start(changed)

    def test_native_start_uses_the_sealed_launchd_job(self) -> None:
        native_manifest = {
            "serving": {},
            "container": {"startup_timeout_seconds": 2},
            "model": {"alias": "fixture-model"},
            "image": {
                "distribution": "native-archive",
                "platform": "macos/arm64",
                "payload_id": "sha256:" + "8" * 64,
            },
        }
        native = {**self.config, "_manifest": native_manifest}
        executor = cli.LocalEngineGroupExecutor(self.member_id)
        with (
            mock.patch.object(cli.platform, "system", return_value="Darwin"),
            mock.patch.object(cli, "_read_engine_group_config", return_value=native),
            mock.patch.object(
                cli, "storage_lock", return_value=contextlib.nullcontext()
            ),
            mock.patch.object(cli, "authorize_serving_launch"),
            mock.patch.object(cli, "verify_host_target"),
            mock.patch.object(
                cli, "ensure_install_dependencies", return_value=()
            ),
            mock.patch.object(cli, "verify_installed_runtime"),
            mock.patch.object(cli, "require_memory_reserve"),
            mock.patch.object(cli, "health_ready", return_value=True),
            mock.patch.object(cli, "certificate_sha256", return_value="7" * 64),
            mock.patch(
                "core.native_engine.native_launch_command",
                return_value=("/bin/engine", "serve"),
            ),
            mock.patch(
                "core.native_engine.native_launch_environment",
                return_value={"LETSINFER_NATIVE_ENGINE_ROOT": "/native"},
            ),
            mock.patch.object(cli.macos_services, "install_launch_agent") as install,
            mock.patch.object(
                cli.macos_services,
                "service_state",
                return_value=("enabled", "active", None),
            ),
        ):
            result = executor.start(self.job)

        self.assertEqual(result["state"], "running")
        agent = install.call_args.args[0]
        self.assertEqual(agent.arguments, ("/bin/engine", "serve"))
        self.assertEqual(agent.environment["LETSINFER_LISTEN_PORT"], "18000")
        self.assertEqual(agent.environment["LETSINFER_NATIVE_BACKEND_PORT"], "18001")
        self.assertEqual(agent.environment["LETSINFER_ENGINE_PROTOCOL"], "2")

if __name__ == "__main__":
    unittest.main()
