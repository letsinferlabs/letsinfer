#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

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

    def __enter__(self):
        return self

    def __exit__(self, *_arguments):
        return None

    def placements(self):
        return [dict(self.placement)]

    def engine_groups(self):
        return [dict(self.group)]

    def set_placement(self, value):
        self.placement = dict(value)
        return dict(value)


class EngineGroupLifecycleTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
