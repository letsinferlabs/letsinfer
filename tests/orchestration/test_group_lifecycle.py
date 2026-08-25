#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import hashlib
import io
import pathlib
import types
import unittest
from unittest import mock

from core import cli


class _Store:
    def __init__(self) -> None:
        self.group_id = "1" * 32
        self.placement_id = "2" * 32
        self.placement = {
            "placement_id": self.placement_id,
            "model": "example-model",
            "runtime": "example/runtime@1.0.0@sha256:" + "3" * 64,
            "target": "two-node",
            "strategy": "parallel",
            "state": "running",
            "topology_sha256": "4" * 64,
            "members": ["5" * 32, "6" * 32],
            "endpoints": [
                {"member_id": "5" * 32, "url": "https://a:18000", "healthy": True}
            ],
            "capacity": {},
        }
        self.group = {
            "group_id": self.group_id,
            "placement_id": self.placement_id,
            "state": "running",
            "desired_state": "running",
            "members": [],
        }
        self.allocations = [
            {
                "group_id": self.group_id,
                "member_id": "5" * 32,
                "device_uuid": "GPU-fixture",
                "state": "active",
            }
        ]

    def __enter__(self):
        return self

    def __exit__(self, *_arguments):
        return None

    def placements(self):
        return [dict(self.placement)]

    def engine_groups(self):
        return [dict(self.group)]

    def device_allocations(self):
        return [dict(row) for row in self.allocations]

    def set_placement(self, value):
        self.placement = dict(value)
        return dict(value)


class EngineGroupLifecycleTests(unittest.TestCase):
    def test_plain_status_renders_runtime_task_without_retired_role(self) -> None:
        group = {
            "group_id": "1" * 32,
            "model": "example-model",
            "strategy": "single",
            "state": "failed",
            "desired_state": "stopped",
            "members": [
                {
                    "member_id": "5" * 32,
                    "task_id": "task-0",
                    "state": "failed",
                }
            ],
        }
        output = io.StringIO()
        arguments = argparse.Namespace(
            json=False,
            model=None,
            name=None,
            config=None,
            _single_snapshot=True,
        )
        with (
            mock.patch.object(cli, "site_identity_path") as identity_path,
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(role="main"),
            ),
            mock.patch.object(cli, "_engine_group_status", return_value=[group]),
            mock.patch("sys.stdout", output),
        ):
            identity_path.return_value.exists.return_value = True
            self.assertEqual(cli.status(arguments), 0)

        self.assertIn(
            f"MEMBER {'5' * 32} task=task-0 state=failed",
            output.getvalue(),
        )

    def test_restore_uses_current_control_bundle_manifest_path(self) -> None:
        member_id = "5" * 32
        runtime_digest = "6" * 64
        regenerated_manifest = {"target": {"placement": {}}}
        manifest_sha256 = hashlib.sha256(
            cli.canonical_bytes(regenerated_manifest)
        ).hexdigest()
        topology_sha256 = "8" * 64
        source = "registry.example/runtime@sha256:" + "9" * 64
        document = {
            "group_id": "1" * 32,
            "runtime_digest": runtime_digest,
            "manifest_sha256": manifest_sha256,
            "topology_sha256": topology_sha256,
            "release": {"source": source, "qualification": "qualified"},
            "resources": [{
                "node_id": member_id,
                "address": "https://node.local:9770",
                "device_uuids": ["GPU-0"],
                "port_base": 18000,
            }],
            "strategy": "single",
            "service_id": "3" * 32,
        }
        assignment = types.SimpleNamespace(member_id=member_id)
        plan = types.SimpleNamespace(
            assignments=(assignment,), document=lambda: document
        )
        restored = types.SimpleNamespace(
            engine_credential_sha256="a" * 64,
            states={member_id: {}},
            persisted_state=None,
        )
        row = {
            "group_id": document["group_id"],
            "runtime_digest": runtime_digest,
            "manifest_sha256": manifest_sha256,
            "topology_sha256": topology_sha256,
            "plan_sha256": hashlib.sha256(cli.canonical_bytes(document)).hexdigest(),
            "source": source,
            "placement_id": "2" * 32,
            "engine_credential_sha256": "a" * 64,
            "members": [{"member_id": member_id, "state": "failed"}],
            "state": "failed",
            "plan": document,
        }
        store = mock.Mock()
        control_root = pathlib.Path("/control/current")
        manifest_path = control_root / "runtime-execution.json"
        validate_bundle = mock.Mock(return_value=(
            manifest_path,
            regenerated_manifest,
        ))
        runtime = types.SimpleNamespace(
            digest=runtime_digest,
            runtime={"orchestration": None},
            runtime_path=pathlib.Path("/runtime/runtime.json"),
        )
        execution_manifest = mock.Mock(return_value=regenerated_manifest)
        install_bundle = mock.Mock(return_value=(control_root, manifest_path))
        with (
            mock.patch.object(cli, "validate_group_document", return_value=document),
            mock.patch.object(cli, "default_runtime_home", return_value=pathlib.Path("/runtime")),
            mock.patch.object(cli, "verify_descriptor", return_value=runtime),
            mock.patch.object(cli, "runtime_execution_manifest", execution_manifest),
            mock.patch.object(cli, "install_control_bundle", install_bundle),
            mock.patch.object(cli, "validate_control_bundle", validate_bundle),
            mock.patch.object(cli, "validate_target_binding", return_value=None),
            mock.patch.object(cli, "target_contract", return_value={"placement": {}}),
            mock.patch.object(cli, "build_single_group_plan", return_value=plan),
            mock.patch.object(
                cli,
                "_engine_group_member_controls",
                return_value={member_id: {}},
            ),
            mock.patch.object(cli, "_engine_group_transport", return_value=(None, None, None)),
            mock.patch.object(cli, "EngineGroupOrchestrator", return_value=restored),
        ):
            result, manifest = cli._restore_engine_group_orchestrator(store, row)
            self.assertEqual(
                install_bundle.call_args,
                mock.call(runtime.runtime_path, regenerated_manifest),
            )
            execution_manifest.return_value = {"target": {"placement": {"changed": True}}}
            install_bundle.reset_mock()
            with self.assertRaisesRegex(
                cli.LetsInferError,
                "runtime no longer reproduces its execution manifest",
            ):
                cli._restore_engine_group_orchestrator(store, row)

        self.assertIs(result, restored)
        self.assertEqual(manifest, regenerated_manifest)
        self.assertEqual(execution_manifest.call_count, 2)
        self.assertEqual(
            execution_manifest.call_args_list,
            [mock.call(runtime.runtime, qualified=True)] * 2,
        )
        install_bundle.assert_not_called()
        validate_bundle.assert_called_once_with(
            control_root,
            manifest_path,
            manifest_sha256,
        )

    def test_intentional_stop_marks_placement_stopped_not_failed(self) -> None:
        store = _Store()
        group = {
            "placement_id": store.placement_id,
            "desired_state": "stopped",
            "state": "stopped",
            "member_states": [
                {
                    "member_id": "5" * 32,
                    "state": "stopped",
                }
            ],
        }
        cli._sync_group_placement(store, group)
        self.assertEqual(store.placement["state"], "stopped")
        self.assertFalse(store.placement["endpoints"][0]["healthy"])

    def test_restart_stops_then_starts_without_acknowledging_trips(self) -> None:
        store = _Store()
        result = {
            "group_id": store.group_id,
            "placement_id": store.placement_id,
            "desired_state": "running",
            "state": "running",
            "member_states": [
                {
                    "member_id": "5" * 32,
                    "state": "running",
                }
            ],
        }
        orchestrator = mock.Mock()
        stopped = {
            **result,
            "desired_state": "stopped",
            "state": "stopped",
        }
        orchestrator.stop.return_value = stopped
        orchestrator.recover.return_value = result
        with (
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(role="main"),
            ),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli,
                "_restore_engine_group_orchestrator",
                return_value=(orchestrator, {}),
            ),
            mock.patch.object(cli, "_sync_group_placement") as sync,
        ):
            self.assertEqual(
                cli._engine_group_lifecycle("example-model", "restart"), result
            )
        orchestrator.stop.assert_called_once_with()
        orchestrator.recover.assert_called_once_with(acknowledge_trips=False)
        self.assertEqual(sync.call_args_list, [mock.call(store, stopped), mock.call(store, result)])

    def test_recovery_is_the_only_lifecycle_action_that_acknowledges_trips(self) -> None:
        store = _Store()
        result = {
            "group_id": store.group_id,
            "placement_id": store.placement_id,
            "desired_state": "running",
            "state": "running",
            "member_states": [],
        }
        orchestrator = mock.Mock()
        orchestrator.recover.return_value = result
        with (
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(role="main"),
            ),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli,
                "_restore_engine_group_orchestrator",
                return_value=(orchestrator, {}),
            ),
            mock.patch.object(cli, "_sync_group_placement") as sync,
        ):
            self.assertEqual(
                cli._engine_group_lifecycle("example-model", "recover"), result
            )
        orchestrator.recover.assert_called_once_with(acknowledge_trips=True)
        sync.assert_called_once_with(store, result)

    def test_model_selector_fails_closed_when_multiple_groups_match(self) -> None:
        store = _Store()
        second = dict(store.group)
        second["group_id"] = "7" * 32
        store.engine_groups = lambda: [dict(store.group), second]
        with self.assertRaisesRegex(cli.LetsInferError, "multiple engine groups"):
            cli._select_engine_group(store, "example-model")

    def test_remove_stops_running_group_before_member_cleanup(self) -> None:
        store = _Store()
        stopped = {
            "group_id": store.group_id,
            "placement_id": store.placement_id,
            "desired_state": "stopped",
            "state": "stopped",
            "member_states": [],
        }
        removed = {
            "group_id": store.group_id,
            "placement_id": store.placement_id,
            "desired_state": "removed",
            "state": "removed",
            "member_states": [],
        }
        orchestrator = mock.Mock()
        orchestrator.stop.return_value = stopped
        orchestrator.remove.return_value = removed
        with (
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(role="main"),
            ),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli,
                "_restore_engine_group_orchestrator",
                return_value=(orchestrator, {}),
            ),
            mock.patch.object(cli, "_sync_group_placement") as sync,
        ):
            self.assertEqual(
                cli._engine_group_lifecycle("example-model", "remove"), removed
            )
        orchestrator.stop.assert_called_once_with()
        orchestrator.remove.assert_called_once_with()
        self.assertEqual(sync.call_args_list, [mock.call(store, stopped), mock.call(store, removed)])

    def test_remove_retries_incomplete_group_without_stopping_again(self) -> None:
        for incomplete_state in ("failed", "removing"):
            with self.subTest(state=incomplete_state):
                store = _Store()
                store.group["desired_state"] = "removed"
                store.group["state"] = incomplete_state
                removed = {
                    "group_id": store.group_id,
                    "placement_id": store.placement_id,
                    "desired_state": "removed",
                    "state": "removed",
                    "member_states": [],
                }
                orchestrator = mock.Mock()
                orchestrator.remove.return_value = removed
                with (
                    mock.patch.object(
                        cli,
                        "read_site_identity",
                        return_value=types.SimpleNamespace(role="main"),
                    ),
                    mock.patch.object(cli, "_site_store", return_value=store),
                    mock.patch.object(
                        cli,
                        "_restore_engine_group_orchestrator",
                        return_value=(orchestrator, {}),
                    ),
                    mock.patch.object(cli, "_sync_group_placement") as sync,
                ):
                    self.assertEqual(
                        cli._engine_group_lifecycle("example-model", "remove"),
                        removed,
                    )
                orchestrator.stop.assert_not_called()
                orchestrator.remove.assert_called_once_with()
                sync.assert_called_once_with(store, removed)

    def test_replacement_removes_failed_group_with_released_allocation(self) -> None:
        store = _Store()
        store.group["desired_state"] = "stopped"
        store.group["state"] = "failed"
        store.allocations[0]["state"] = "released"
        removed = {
            "group_id": store.group_id,
            "placement_id": store.placement_id,
            "desired_state": "removed",
            "state": "removed",
            "member_states": [],
        }
        orchestrator = mock.Mock()
        orchestrator.remove.return_value = removed
        with (
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli,
                "_restore_engine_group_orchestrator",
                return_value=(orchestrator, {}),
            ),
            mock.patch.object(cli, "_sync_group_placement") as sync,
        ):
            cli._remove_engine_groups_by_id([store.group_id])

        orchestrator.stop.assert_not_called()
        orchestrator.remove.assert_called_once_with()
        sync.assert_called_once_with(store, removed)


if __name__ == "__main__":
    unittest.main()
