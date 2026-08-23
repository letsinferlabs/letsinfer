#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import types
import unittest
from unittest import mock

from core import cli


def _members() -> list[dict]:
    return [
        {"member_id": "a" * 32, "display_name": "Home", "state": "active"},
        {"member_id": "b" * 32, "display_name": "Workshop", "state": "active"},
        {"member_id": "c" * 32, "display_name": "Offline", "state": "draining"},
    ]


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


class ReplicaSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = types.SimpleNamespace(member_id="a" * 32)

    def select(self, *, nodes=None, all_nodes=False):
        arguments = argparse.Namespace(node=nodes, all_nodes=all_nodes)
        return cli._selected_install_node_ids(arguments, self.identity, _members())

    def test_noninteractive_default_targets_only_the_main_node(self) -> None:
        with mock.patch.object(cli.sys.stdin, "isatty", return_value=False):
            self.assertEqual(self.select(), ("a" * 32,))

    def test_all_nodes_selects_only_active_nodes_in_stable_order(self) -> None:
        self.assertEqual(
            self.select(all_nodes=True),
            ("a" * 32, "b" * 32),
        )

    def test_repeated_ids_and_names_are_resolved_and_deduplicated(self) -> None:
        self.assertEqual(
            self.select(nodes=["Workshop", "a" * 32, "Workshop"]),
            ("b" * 32, "a" * 32),
        )

    def test_node_and_all_nodes_are_mutually_exclusive(self) -> None:
        with self.assertRaisesRegex(cli.LetsInferError, "cannot be combined"):
            self.select(nodes=["Home"], all_nodes=True)

    def test_unknown_or_ambiguous_node_fails_before_installation(self) -> None:
        with self.assertRaisesRegex(cli.LetsInferError, "unknown active node"):
            self.select(nodes=["Missing"])
        duplicates = _members() + [
            {"member_id": "d" * 32, "display_name": "Workshop", "state": "active"}
        ]
        with self.assertRaisesRegex(cli.LetsInferError, "ambiguous"):
            cli._selected_install_node_ids(
                argparse.Namespace(node=["Workshop"], all_nodes=False),
                self.identity,
                duplicates,
            )

    def test_interactive_replication_requires_an_explicit_yes(self) -> None:
        with (
            mock.patch.object(cli.sys.stdin, "isatty", return_value=True),
            mock.patch("builtins.input", return_value="yes"),
        ):
            self.assertEqual(self.select(), ("a" * 32, "b" * 32))
        with (
            mock.patch.object(cli.sys.stdin, "isatty", return_value=True),
            mock.patch("builtins.input", return_value=""),
        ):
            self.assertEqual(self.select(), ("a" * 32,))

    def test_scale_down_removes_a_stopped_group_before_a_running_group(self) -> None:
        placements = [
            {"placement_id": "1" * 32, "model": "example-model"},
            {"placement_id": "2" * 32, "model": "example-model"},
        ]
        groups = [
            {
                "group_id": "3" * 32,
                "placement_id": "1" * 32,
                "state": "running",
                "desired_state": "running",
                "updated_at_unix": 1,
            },
            {
                "group_id": "4" * 32,
                "placement_id": "2" * 32,
                "state": "stopped",
                "desired_state": "stopped",
                "updated_at_unix": 2,
            },
        ]
        arguments = argparse.Namespace(
            model="example-model", replicas=1, runtime=None, catalog="catalog.json"
        )
        with (
            mock.patch.object(cli, "resolved_catalog_location", return_value="catalog.json"),
            mock.patch.object(
                cli.CatalogManager,
                "load",
                return_value=types.SimpleNamespace(document={"schema_version": 6}),
            ),
            mock.patch.object(cli, "_site_store", return_value=_Store(placements, groups)),
            mock.patch.object(cli, "_remove_engine_groups_by_id") as remove,
        ):
            self.assertEqual(cli.scale_command(arguments), 0)
        remove.assert_called_once_with(["4" * 32])


if __name__ == "__main__":
    unittest.main()
