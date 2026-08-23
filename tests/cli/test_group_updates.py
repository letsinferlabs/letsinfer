#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import contextlib
import pathlib
import types
import unittest
from unittest import mock

from core import cli
from tests.orchestration.helpers import release_identity


class _Store:
    def __init__(self, placements: list[dict], groups: list[dict]) -> None:
        self._placements = placements
        self._groups = groups

    def __enter__(self):
        return self

    def __exit__(self, *_arguments):
        return None

    def placements(self):
        return [dict(value) for value in self._placements]

    def engine_groups(self):
        return [dict(value) for value in self._groups]


def _release(version: str, source_digit: str) -> dict:
    value = release_identity()
    value.update({
        "logical_model": "example-model",
        "version": version,
        "source": "registry.example/runtime@sha256:" + source_digit * 64,
    })
    return value


def _group(
    digit: str,
    placement_digit: str,
    member_digit: str,
    release: dict,
    *,
    desired_state: str = "running",
    state: str = "running",
    updated_at_unix: int = 1,
) -> dict:
    return {
        "group_id": digit * 32,
        "placement_id": placement_digit * 32,
        "source": release["source"],
        "state": state,
        "desired_state": desired_state,
        "updated_at_unix": updated_at_unix,
        "plan": {
            "release": dict(release),
            "resources": [{"node_id": member_digit * 32}],
        },
    }


class QualifiedGroupUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old = _release("1.0.0", "7")
        self.new = _release("1.1.0", "8")
        self.arguments = argparse.Namespace(
            action_id="upgrade",
            runtime="example-model",
            to=None,
            catalog="catalog.json",
            dry_run=False,
            target=None,
        )

    @staticmethod
    def placements() -> list[dict]:
        return [
            {"placement_id": "2" * 32, "model": "example-model", "target": "fixture-target"},
            {"placement_id": "3" * 32, "model": "example-model", "target": "fixture-target"},
        ]

    def update_patches(self, store: _Store):
        descriptor = types.SimpleNamespace(digest="6" * 64)
        return (
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli.CatalogManager,
                "load",
                return_value=types.SimpleNamespace(document={"schema_version": 6}),
            ),
            mock.patch.object(
                cli,
                "catalog_release",
                return_value=(
                    "fixture-target",
                    self.old["target_contract_sha256"],
                    self.old["candidate_id"],
                    self.new["version"],
                    self.new["source"],
                ),
            ),
            mock.patch.object(cli, "catalog_release_record", return_value={}),
            mock.patch.object(cli, "catalog_target_contract", return_value={"placement": {}}),
            mock.patch.object(
                cli,
                "prepare_runtime_install",
                return_value=(
                    pathlib.Path("/control/release.json"),
                    {"model": {"alias": "example-model"}},
                    pathlib.Path("/control"),
                    {"object_root": "/objects/runtime"},
                ),
            ),
            mock.patch.object(cli, "verify_descriptor", return_value=descriptor),
            mock.patch.object(cli, "sha256_file", return_value="5" * 64),
            mock.patch.object(cli, "_group_release_identity", return_value=self.new),
            mock.patch.object(
                cli,
                "_fresh_site_topology",
                return_value=(mock.sentinel.identity, mock.sentinel.graph),
            ),
            mock.patch.object(
                cli,
                "_group_upgrade_placement",
                return_value=(mock.sentinel.constrained, mock.sentinel.placement),
            ),
        )

    def test_upgrade_rolls_each_replica_on_its_existing_node(self) -> None:
        first = _group("1", "2", "a", self.old)
        second = _group(
            "4", "3", "b", self.old, desired_state="stopped", state="stopped"
        )
        store = _Store(self.placements(), [first, second])
        patches = self.update_patches(store)
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            remove = stack.enter_context(
                mock.patch.object(cli, "_remove_engine_groups_by_id")
            )
            install = stack.enter_context(mock.patch.object(cli, "install_engine_group"))
            stack.enter_context(mock.patch.object(
                cli,
                "_active_group_id_for_release",
                side_effect=["c" * 32, "d" * 32],
            ))
            stop = stack.enter_context(
                mock.patch.object(cli, "_stop_engine_group_by_id")
            )
            self.assertEqual(cli.upgrade_runtime(self.arguments), 0)

        self.assertEqual(
            remove.call_args_list,
            [mock.call([first["group_id"]]), mock.call([second["group_id"]])],
        )
        self.assertEqual(install.call_count, 2)
        stop.assert_called_once_with("d" * 32)

    def test_failed_upgrade_cleans_partial_group_and_restores_exact_release(self) -> None:
        group = _group("1", "2", "a", self.old)
        store = _Store(self.placements()[:1], [group])
        patches = self.update_patches(store)
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            stack.enter_context(mock.patch.object(cli, "_remove_engine_groups_by_id"))
            stack.enter_context(mock.patch.object(
                cli, "install_engine_group", side_effect=RuntimeError("synthetic")
            ))
            cleanup = stack.enter_context(
                mock.patch.object(cli, "_cleanup_failed_group_release")
            )
            restore = stack.enter_context(mock.patch.object(
                cli, "_install_retained_group_release", return_value="e" * 32
            ))
            with self.assertRaisesRegex(
                cli.LetsInferError, "previous release restored"
            ):
                cli.upgrade_runtime(self.arguments)

        cleanup.assert_called_once_with(self.new["source"], ("a" * 32,))
        self.assertEqual(restore.call_args.kwargs["release"], self.old)

    def test_rollback_uses_latest_removed_release_on_the_same_node(self) -> None:
        self.arguments.action_id = "rollback"
        current = _group("1", "2", "a", self.new)
        previous = _group(
            "4",
            "5",
            "a",
            self.old,
            desired_state="removed",
            state="removed",
            updated_at_unix=10,
        )
        store = _Store(self.placements()[:1], [previous, current])
        with (
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(cli, "_remove_engine_groups_by_id") as remove,
            mock.patch.object(
                cli, "_install_retained_group_release", return_value="f" * 32
            ) as restore,
        ):
            self.assertEqual(cli.rollback_runtime(self.arguments), 0)

        remove.assert_called_once_with([current["group_id"]])
        self.assertEqual(restore.call_args.kwargs["release"], self.old)
        self.assertEqual(restore.call_args.kwargs["member_ids"], ("a" * 32,))


if __name__ == "__main__":
    unittest.main()
