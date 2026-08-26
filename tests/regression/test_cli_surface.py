#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The public and internal CLI surface is complete, scoped, and dispatchable."""

from __future__ import annotations

import argparse
import ast
import contextlib
import io
import inspect
import pathlib
import re
import types
import unittest
from unittest import mock

from core import cli
from core.actions import ACTIONS, action
from tests.regression.cli_cases import CLI_CASES


PUBLIC_REFERENCE_COMMANDS = {
    "letsinfer status",
    "letsinfer doctor",
    "letsinfer node info",
    "letsinfer node list",
    "letsinfer node add",
    "letsinfer node pause CHILD",
    "letsinfer node resume CHILD",
    "letsinfer node remove CHILD",
    "letsinfer model list [MODEL]",
    "letsinfer model install [MODEL]",
    "letsinfer model remove MODEL",
    "letsinfer model pause MODEL",
    "letsinfer model resume MODEL",
    "letsinfer model restart MODEL",
    "letsinfer model recover MODEL",
    "letsinfer model rollback MODEL",
    "letsinfer model logs MODEL",
    "letsinfer benchmark run MODEL",
    "letsinfer benchmark list MODEL",
    "letsinfer benchmark status",
    "letsinfer benchmark stop",
    "letsinfer benchmark clean",
    "letsinfer benchmark verification run PULL_REQUEST_URL",
    "letsinfer benchmark verification status",
    "letsinfer benchmark verification stop",
    "letsinfer auth controller add",
    "letsinfer auth controller list",
    "letsinfer auth controller revoke CONTROLLER",
    "letsinfer auth key create NAME",
    "letsinfer auth key list",
    "letsinfer auth key show KEY",
    "letsinfer auth key rotate KEY",
    "letsinfer auth key revoke KEY",
    "letsinfer auth key update KEY",
    "letsinfer exposure status",
    "letsinfer exposure enable",
    "letsinfer exposure disable",
    "letsinfer audit list",
    "letsinfer audit show EVENT",
    "letsinfer audit verify",
    "letsinfer audit export --output FILE",
    "letsinfer update check",
    "letsinfer update core [VERSION]",
    "letsinfer update model [MODEL]",
    "letsinfer uninstall",
}


class CliSurfaceTests(unittest.TestCase):
    def test_every_runtime_prepare_call_declares_qualification(self) -> None:
        tree = ast.parse(inspect.getsource(cli))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "prepare_runtime_install"
        ]
        self.assertGreater(len(calls), 0)
        for call in calls:
            with self.subTest(line=call.lineno):
                self.assertIn(
                    "qualified",
                    {keyword.arg for keyword in call.keywords},
                    "runtime qualification must be explicit at every install boundary",
                )

    def test_every_registered_action_has_one_parseable_command(self) -> None:
        command_parser = cli.parser()
        self.assertEqual(set(CLI_CASES), set(ACTIONS))
        for action_id, arguments in CLI_CASES.items():
            with self.subTest(action=action_id):
                parsed = command_parser.parse_args(arguments)
                self.assertEqual(parsed.action_id, action_id)
                self.assertTrue(callable(parsed.action))

    def test_every_leaf_has_working_command_help(self) -> None:
        for action_id, arguments in CLI_CASES.items():
            with self.subTest(action=action_id), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    cli.parser().parse_args([*arguments, "--help"])
                self.assertEqual(stopped.exception.code, 0)

    def test_every_leaf_traverses_the_real_dispatcher_without_external_services(self) -> None:
        for action_id, arguments in CLI_CASES.items():
            calls: list[str] = []
            command_parser = cli.parser()
            parse_args = command_parser.parse_args

            def parse_and_replace(values: list[str]) -> argparse.Namespace:
                parsed = parse_args(values)
                parsed.action = lambda namespace: calls.append(namespace.action_id) or 0
                return parsed

            command_parser.parse_args = parse_and_replace  # type: ignore[method-assign]
            terminal = types.SimpleNamespace(interactive=False)
            with (
                self.subTest(action=action_id),
                mock.patch.object(cli, "parser", return_value=command_parser),
                mock.patch.object(
                    cli,
                    "_authorize_command",
                    side_effect=lambda namespace: (action(namespace.action_id), None),
                ),
                mock.patch.object(cli, "_audit_marker", return_value=None),
                mock.patch.object(cli, "_audit_command_result"),
                mock.patch.object(cli, "ACTION_PROGRESS", {}),
                mock.patch.object(cli.ui, "Terminal", return_value=terminal),
                mock.patch.object(cli.ui, "update_notice"),
            ):
                self.assertEqual(cli.main(arguments), 0)
            self.assertEqual(calls, [action_id])

    def test_legacy_topology_names_are_not_public_commands(self) -> None:
        help_text = cli.parser().format_help()
        for legacy in ("site", "member", "coordinator"):
            self.assertNotRegex(help_text, rf"(?:^|[,{{ ]){legacy}(?:[,}} ]|$)")

    def test_public_reference_explains_every_command_in_exactly_two_sentences(self) -> None:
        reference = (
            pathlib.Path(__file__).parents[2]
            / "documentation"
            / "reference"
            / "cli.md"
        ).read_text(encoding="utf-8")
        sections = re.findall(
            r"^### `(?P<command>letsinfer [^`]+)`\n\n(?P<body>.*?)(?=^### |^## |\Z)",
            reference,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertEqual({command for command, _body in sections}, PUBLIC_REFERENCE_COMMANDS)
        for command, body in sections:
            prose = re.sub(r"```.*?```", "", body, flags=re.DOTALL)
            prose = " ".join(prose.split())
            sentences = re.findall(r"[^.!?]+[.!?](?=\s|$)", prose)
            with self.subTest(command=command):
                self.assertEqual(len(sentences), 2, prose)


if __name__ == "__main__":
    unittest.main()
