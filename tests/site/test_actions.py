# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from core import cli
from core.actions import ACTIONS, AuditPolicy, CommandScope, MutationClass, validate_registry
from core.site.inventory import InventoryError
from core.site import state
from core.site.state import SiteIdentity


def member_identity() -> SiteIdentity:
    return SiteIdentity(
        site_id="1" * 32,
        member_id="2" * 32,
        installation_id="3" * 64,
        display_name="Home",
        role="member",
        coordinator_id="4" * 32,
        coordinator_address="coordinator.local",
        site_public_key_sha256="5" * 64,
        member_public_key_sha256="6" * 64,
        created_at_unix=1_700_000_000,
    )


class ActionRegistryTests(unittest.TestCase):
    def test_every_leaf_is_registered_once_and_every_site_mutation_is_coordinator_audited(self) -> None:
        root = cli.parser()
        leaves = cli._parser_action_ids(root)
        self.assertEqual(set(leaves), set(ACTIONS))
        self.assertEqual(len(leaves), len(ACTIONS))
        validate_registry(leaves)
        for action in ACTIONS.values():
            self.assertIsInstance(action.scope, CommandScope)
            if action.mutation is MutationClass.SITE and action.name != "setup":
                self.assertIs(action.scope, CommandScope.COORDINATOR)
                self.assertIs(action.audit, AuditPolicy.ALWAYS)

        def assert_help_and_no_aliases(parser: argparse.ArgumentParser) -> None:
            for entry in parser._actions:
                if not isinstance(entry, argparse._SubParsersAction):
                    continue
                children = list(entry.choices.values())
                self.assertEqual(
                    len(children),
                    len({id(child) for child in children}),
                    "CLI aliases are forbidden because they can obscure scope enforcement",
                )
                for child in children:
                    action_id = child.get_default("action_id")
                    if action_id is not None:
                        metadata = ACTIONS[action_id]
                        self.assertEqual(
                            child.epilog,
                            f"Execution scope: {metadata.scope.value}. "
                            f"Mutation class: {metadata.mutation.value}.",
                        )
                    assert_help_and_no_aliases(child)

        assert_help_and_no_aliases(root)

    def test_member_cannot_execute_or_proxy_a_coordinator_command(self) -> None:
        invoked = mock.Mock(return_value=0)
        arguments = argparse.Namespace(
            action_id="key.create", action=invoked, command="key", port=1,
        )
        stderr = io.StringIO()
        with (
            mock.patch.object(cli, "parser") as parser,
            mock.patch.object(cli, "read_site_identity", return_value=member_identity()),
            mock.patch.object(cli, "site_identity_path") as identity_path,
            contextlib.redirect_stderr(stderr),
        ):
            parser.return_value.parse_args.return_value = arguments
            identity_path.return_value.exists.return_value = True
            self.assertEqual(cli.main(["key", "create", "fixture"]), 1)
        invoked.assert_not_called()
        self.assertIn("command scope is coordinator", stderr.getvalue())
        self.assertIn("coordinator.local", stderr.getvalue())

    def test_connectx_invite_fails_before_site_mutation_without_verified_link(self) -> None:
        arguments = argparse.Namespace(
            mode="connectx",
            candidate_fingerprint="a" * 64,
            candidate_endpoint="https://192.0.2.20:9770",
            interface="enp1s0",
            expires_in=180,
            json=True,
        )
        with (
            mock.patch.object(
                cli,
                "verify_direct_connectx_interface",
                side_effect=InventoryError("direct ConnectX link does not have carrier"),
            ),
            mock.patch.object(cli, "_site_store") as site_store,
        ):
            with self.assertRaisesRegex(cli.LetsInferError, "carrier"):
                cli.member_invite_command(arguments)
        site_store.assert_not_called()

    def test_handler_prevalidation_failure_is_audited_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            environment = {"LETSINFER_HOME": str(root)}
            with mock.patch.dict(os.environ, environment):
                identity = state.setup_site("Home", "127.0.0.1")

                def reject(_arguments: argparse.Namespace) -> int:
                    raise cli.LetsInferError("prevalidation rejected")

                arguments = argparse.Namespace(
                    action_id="member.invite",
                    action=reject,
                    command="member",
                    port=1,
                )
                parsed = mock.MagicMock()
                parsed.parse_args.return_value = arguments
                stderr = io.StringIO()
                with (
                    mock.patch.object(cli, "parser", return_value=parsed),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(cli.main(["member", "invite"]), 1)
                with state.SiteStore(identity=identity) as store:
                    events = [
                        row
                        for row in store.audit_rows(limit=10)
                        if row["action"] == "member.invite"
                    ]
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["outcome"], "failed")

    def test_handler_owned_failure_audit_is_not_duplicated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            environment = {"LETSINFER_HOME": str(root)}
            with mock.patch.dict(os.environ, environment):
                identity = state.setup_site("Home", "127.0.0.1")

                def reject(_arguments: argparse.Namespace) -> int:
                    with state.SiteStore(identity=identity) as store:
                        store.record_action(
                            "member.invite", "fixture", "failed", "fixture"
                        )
                    raise cli.LetsInferError("mutation rejected")

                arguments = argparse.Namespace(
                    action_id="member.invite",
                    action=reject,
                    command="member",
                    port=1,
                )
                parsed = mock.MagicMock()
                parsed.parse_args.return_value = arguments
                with (
                    mock.patch.object(cli, "parser", return_value=parsed),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(cli.main(["member", "invite"]), 1)
                with state.SiteStore(identity=identity) as store:
                    events = [
                        row
                        for row in store.audit_rows(limit=10)
                        if row["action"] == "member.invite"
                    ]
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["outcome"], "failed")

    def test_audit_export_is_complete_private_verified_and_itself_audited(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            environment = {"LETSINFER_HOME": str(root)}
            with mock.patch.dict(os.environ, environment):
                identity = state.setup_site("Home", "127.0.0.1")
                with state.SiteStore(identity=identity) as store:
                    for index in range(25):
                        store.record_action(
                            "fixture.read", str(index), "success"
                        )
                    before = store.verify_audit()
                output = root / "audit.json"
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        cli.main(["audit", "export", "--output", str(output)]),
                        0,
                    )
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                exported = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(exported["schema_version"], 1)
                self.assertEqual(exported["site_id"], identity.site_id)
                self.assertEqual(exported["verification"], before)
                self.assertEqual(len(exported["events"]), before["events"])
                self.assertEqual(
                    [row["sequence"] for row in exported["events"]],
                    list(range(1, before["events"] + 1)),
                )
                with state.SiteStore(identity=identity) as store:
                    after = store.verify_audit()
                    latest = store.audit_rows(limit=1)[0]
                self.assertEqual(after["events"], before["events"] + 1)
                self.assertEqual(latest["action"], "audit.export")
                self.assertEqual(latest["outcome"], "success")


if __name__ == "__main__":
    unittest.main()
