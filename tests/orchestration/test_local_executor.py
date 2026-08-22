#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

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
        self.role = {
            "name": "engine-member",
            "rank": 1,
            "role_rank": 0,
            "port_base": 18000,
            "port_count": 2,
            "launcher": "runtime-command",
            "command": ["/opt/runtime/member"],
            "environment": {"RUNTIME_MODE": "member"},
            "inference_endpoint": False,
            "readiness": {
                "kind": "exec",
                "command": ["/opt/runtime/ready"],
                "interval_seconds": 1,
                "timeout_seconds": 1,
                "retries": 2,
            },
        }
        self.group = {
            "schema_version": 1,
            "group_id": self.group_id,
            "strategy": "distributed",
            "engine_strategy": "tensor-parallel",
            "failure_policy": "whole-group",
            "minimum_healthy_members": 2,
            "topology_sha256": "1" * 64,
            "manifest_sha256": "2" * 64,
            "runtime_digest": "3" * 64,
            "engine_coordinator_id": "c" * 32,
            "startup_order": ["engine-member", "engine-coordinator"],
            "members": [
                {
                    "member_id": "c" * 32,
                    "address": "coordinator.local:9770",
                    "rank": 0,
                    "role_rank": 0,
                    "role": "engine-coordinator",
                    "port_base": 18000,
                    "port_count": 2,
                    "inference_endpoint": True,
                },
                {
                    "member_id": self.member_id,
                    "address": "member.local:9770",
                    "rank": 1,
                    "role_rank": 0,
                    "role": "engine-member",
                    "port_base": 18000,
                    "port_count": 2,
                    "inference_endpoint": False,
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
            "role": self.role,
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
                "container": {"startup_timeout_seconds": 30},
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
            "role": self.role,
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
            mock.patch.object(cli, "verify_active_core_watchdog"),
            mock.patch.object(cli, "authorize_serving_launch"),
            mock.patch.object(cli, "verify_host_target"),
            mock.patch.object(cli, "ensure_image"),
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
        run.assert_called_once_with(["docker", "run"])
        ready.assert_called_once_with(self.config["container_name"], self.role["readiness"])
        self.assertEqual([call.args[2] for call in protect.call_args_list], ["pending", "starting", "armed"])
        self.assertEqual(command.call_args.kwargs["group_context"]["role"], "engine-member")

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
            "role": self.role,
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

if __name__ == "__main__":
    unittest.main()
