#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from core import cli
from tests.orchestration.helpers import release_identity


class _Store:
    def __init__(self) -> None:
        self.group_id = "1" * 32
        self.placement_id = "2" * 32
        self.placement = {
            "placement_id": self.placement_id,
            "service_id": "3" * 32,
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
            "updated_at_unix": 1,
        }
        self.group = {
            "group_id": self.group_id,
            "placement_id": self.placement_id,
            "runtime_digest": "6" * 64,
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
    def test_live_snapshot_keeps_metrics_when_engine_group_exists(self) -> None:
        group = {
            "group_id": "1" * 32,
            "model": "example-model",
            "runtime": "runtime-a",
            "target": "target-a",
            "strategy": "single",
            "state": "failed",
            "desired_state": "stopped",
            "members": [],
        }
        telemetry = {"fresh": True, "system": {"gpu": {"utilization": 42}}}
        output = io.StringIO()
        arguments = argparse.Namespace(
            json=True,
            model=None,
            name=None,
            config=None,
            _single_snapshot=True,
            _live_snapshot=True,
        )
        identity = types.SimpleNamespace(role="main", member_id="5" * 32)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with (
                mock.patch.object(cli, "site_identity_path") as identity_path,
                mock.patch.object(cli, "read_site_identity", return_value=identity),
                mock.patch.object(cli, "_engine_group_status", return_value=[group]),
                mock.patch.object(
                    cli, "active_service_config_path", return_value=root / "missing.json"
                ),
                mock.patch.object(cli, "site_config_root", return_value=root),
                mock.patch.object(
                    cli, "_service_state", return_value=("enabled", "active", 1024)
                ),
                mock.patch.object(cli, "api_status", side_effect=[200, 401, 200]),
                mock.patch.object(
                    cli,
                    "identity_json",
                    return_value={
                        "role": "main",
                        "machine_id": identity.member_id,
                        "display_name": "Example",
                    },
                ),
                mock.patch.object(
                    cli,
                    "_complete_local_node_status",
                    return_value={
                        "node": {},
                        "nodes": [{"member_id": identity.member_id, "state": "active"}],
                        "hardware": {},
                        "links": [],
                    },
                ),
                mock.patch.object(
                    cli, "_local_controller_telemetry", return_value=telemetry
                ),
                mock.patch.object(
                    cli, "runtime_lifecycle", return_value={"state": "absent"}
                ),
                mock.patch("sys.stdout", output),
            ):
                identity_path.return_value.exists.return_value = True
                self.assertEqual(cli.status(arguments), 1)

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["services"]["node_active"], "active")
        self.assertEqual(payload["telemetry"], telemetry)
        self.assertEqual(payload["engine_groups"], [group])

    def test_plain_status_renders_all_models_without_retired_role(self) -> None:
        group = {
            "group_id": "1" * 32,
            "model": "example-model",
            "runtime": "runtime-a",
            "target": "target-a",
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
        identity = types.SimpleNamespace(role="main", member_id="5" * 32)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with (
                mock.patch.object(cli, "site_identity_path") as identity_path,
                mock.patch.object(cli, "read_site_identity", return_value=identity),
                mock.patch.object(cli, "_engine_group_status", return_value=[group]),
                mock.patch.object(
                    cli, "active_service_config_path", return_value=root / "missing.json"
                ),
                mock.patch.object(cli, "site_config_root", return_value=root),
                mock.patch.object(
                    cli, "_service_state", return_value=("enabled", "active", 1024)
                ),
                mock.patch.object(cli, "api_status", side_effect=[200, 401, 200]),
                mock.patch.object(
                    cli,
                    "identity_json",
                    return_value={"role": "main", "member_id": identity.member_id},
                ),
                mock.patch.object(
                    cli,
                    "_complete_local_node_status",
                    return_value={
                        "node": {},
                        "nodes": [{"member_id": identity.member_id, "state": "active"}],
                        "hardware": {},
                        "links": [],
                    },
                ),
                mock.patch.object(cli, "_local_controller_telemetry", return_value={}),
                mock.patch.object(
                    cli, "runtime_lifecycle", return_value={"state": "ready"}
                ),
                mock.patch("sys.stdout", output),
            ):
                identity_path.return_value.exists.return_value = True
                self.assertEqual(cli.status(arguments), 0)

        self.assertIn("model=example-model state=failed replicas=1", output.getvalue())
        self.assertNotIn("MEMBER", output.getvalue())

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
                "port_count": 1,
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
            runtime={
                "orchestration": None,
                "engine": {"distribution": {"kind": "oci-container"}},
            },
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
        self.assertNotIn("updated_at_unix", store.placement)

    def test_start_of_cleanly_stopped_group_skips_recovery_stop(self) -> None:
        store = _Store()
        store.group.update({"state": "stopped", "desired_state": "stopped"})
        result = {
            "group_id": store.group_id,
            "placement_id": store.placement_id,
            "desired_state": "running",
            "state": "running",
            "member_states": [],
        }
        orchestrator = mock.Mock()
        orchestrator.start.return_value = result
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
                cli._engine_group_lifecycle("example-model", "start"), result
            )
        orchestrator.start.assert_called_once_with()
        orchestrator.recover.assert_not_called()
        sync.assert_called_once_with(store, result)

    def test_resume_does_not_restart_an_already_running_sibling(self) -> None:
        store = _Store()
        store.group["plan"] = {"group_id": store.group_id}
        with (
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(role="main"),
            ),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli, "_restore_engine_group_orchestrator"
            ) as restore,
        ):
            result = cli._engine_group_lifecycle("example-model", "start")
        assert result is not None
        self.assertEqual(result["state"], "running")
        self.assertEqual(result["desired_state"], "running")
        restore.assert_not_called()

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
        with tempfile.TemporaryDirectory() as directory:
            runtime_home = pathlib.Path(directory)
            (runtime_home / ".objects" / store.group["runtime_digest"]).mkdir(
                parents=True
            )
            with (
                mock.patch.object(cli, "_site_store", return_value=store),
                mock.patch.object(
                    cli,
                    "default_runtime_home",
                    return_value=runtime_home,
                ),
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

    def test_replacement_forgets_failed_group_after_runtime_object_was_pruned(self) -> None:
        member_id = "5" * 32
        plan = cli.build_single_group_plan(
            member_id=member_id,
            member_address="member.local",
            device_uuids=["GPU-fixture"],
            topology_sha256="4" * 64,
            manifest_sha256="5" * 64,
            runtime_digest="6" * 64,
            service_id="3" * 32,
            release=release_identity(),
            port_base=18000,
        )
        document = plan.document()
        row = {
            "group_id": plan.group_id,
            "placement_id": plan.group_id,
            "source": document["release"]["source"],
            "runtime_digest": document["runtime_digest"],
            "manifest_sha256": document["manifest_sha256"],
            "topology_sha256": document["topology_sha256"],
            "engine_credential_sha256": "d" * 64,
            "plan": document,
            "plan_sha256": hashlib.sha256(cli.canonical_bytes(document)).hexdigest(),
            "desired_state": "stopped",
            "state": "failed",
            "members": [{
                "member_id": member_id,
                "task_id": "task-0",
                "state": "failed",
                "operation_id": "e" * 32,
                "error": "GroupOrchestrationError",
            }],
        }
        placement = {
            "placement_id": plan.group_id,
            "service_id": document["service_id"],
            "model": "fixture-model",
            "runtime": "fixture-runtime",
            "target": "fixture-target",
            "strategy": "single",
            "state": "failed",
            "topology_sha256": document["topology_sha256"],
            "members": [member_id],
            "endpoints": [],
            "capacity": {},
        }
        allocation = {
            "group_id": plan.group_id,
            "member_id": member_id,
            "device_uuid": "GPU-fixture",
            "state": "released",
        }
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.engine_groups.return_value = [row]
        store.device_allocations.return_value = [allocation]
        store.placements.return_value = [placement]

        def persist(group, **changes):
            return {
                **group,
                "placement_id": changes["placement_id"],
                "desired_state": changes["desired_state"],
                "state": changes["state"],
                "member_states": changes["members"],
            }

        store.set_engine_group.side_effect = persist
        with tempfile.TemporaryDirectory() as directory, (
            mock.patch.object(cli, "_site_store", return_value=store)
        ), mock.patch.object(
            cli, "default_runtime_home", return_value=pathlib.Path(directory)
        ), mock.patch.object(cli, "_restore_engine_group_orchestrator") as restore:
            cli._remove_engine_groups_by_id([plan.group_id])

        restore.assert_not_called()
        self.assertEqual(
            store.set_engine_group.call_args.kwargs["desired_state"], "removed"
        )
        self.assertEqual(store.set_engine_group.call_args.kwargs["state"], "removed")
        store.set_group_allocation_state.assert_called_once_with(
            plan.group_id, "released"
        )
        self.assertEqual(store.set_placement.call_args.args[0]["state"], "stopped")

    def test_missing_runtime_object_never_forgets_potentially_active_group(self) -> None:
        member_id = "5" * 32
        document = {
            "group_id": "1" * 32,
            "resources": [{"node_id": member_id, "task_id": "task-0"}],
        }
        row = {
            "placement_id": "2" * 32,
            "source": "registry.example/runtime@sha256:" + "7" * 64,
            "engine_credential_sha256": "d" * 64,
            "desired_state": "running",
            "state": "running",
            "members": [{
                "member_id": member_id,
                "task_id": "task-0",
                "state": "running",
                "operation_id": None,
                "error": None,
            }],
        }
        store = mock.MagicMock()
        store.placements.return_value = [{
            "placement_id": row["placement_id"],
            "state": "running",
            "endpoints": [{"healthy": True}],
        }]
        with mock.patch.object(
            cli, "_validated_engine_group_document", return_value=document
        ):
            with self.assertRaisesRegex(cli.LetsInferError, "may still be active"):
                cli._remove_terminal_engine_group_without_runtime(
                    store,
                    row,
                    [{"state": "active"}],
                )

        store.set_engine_group.assert_not_called()


if __name__ == "__main__":
    unittest.main()
