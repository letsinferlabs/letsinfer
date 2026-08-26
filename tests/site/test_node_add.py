#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import tempfile
import time
import types
import unittest
from unittest import mock

from core import cli
from core.site import control
from core.site import node_add


class NodeAddContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.environment = mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": self.temporary.name},
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def request(self) -> dict[str, object]:
        return {
            "protocol": node_add.PROTOCOL,
            "request_id": "1" * 32,
            "main_node_id": "2" * 32,
            "main_name": "Home",
            "main_endpoint": "https://home.local:9770",
            "main_certificate_sha256": "3" * 64,
            "invite_id": "4" * 32,
            "membership_code": "12345678",
            "expires_at_unix": int(time.time()) + 180,
        }

    def test_request_store_is_private_exact_and_clearable(self) -> None:
        expected = self.request()
        self.assertEqual(node_add.store_request(expected), expected)
        self.assertEqual(node_add.pending_request(), expected)
        self.assertEqual(node_add.request_path().stat().st_mode & 0o777, 0o600)
        node_add.clear_request(str(expected["request_id"]))
        self.assertIsNone(node_add.pending_request())

    def test_manual_discovery_requires_a_pinned_certificate(self) -> None:
        with self.assertRaisesRegex(node_add.NodeAddError, "certificate"):
            node_add.discover_nodes(address="child.local")
        rows = node_add.discover_nodes(
            address="child.local",
            certificate_sha256="a" * 64,
        )
        self.assertEqual(
            rows,
            [
                {
                    "node_id": "unknown",
                    "machine_id": "unknown",
                    "name": "child.local",
                    "role": "unknown",
                    "state": "configured",
                    "endpoint": "https://child.local:9770",
                    "certificate_sha256": "a" * 64,
                    "address": "child.local",
                }
            ],
        )

    def test_request_sender_requires_exact_acknowledgement(self) -> None:
        client = mock.Mock()
        client.request.return_value = {
            "protocol": node_add.PROTOCOL,
            "request_id": "1" * 32,
            "status": "pending",
        }
        with mock.patch.object(node_add, "PinnedHTTPS", return_value=client) as pinned:
            result = node_add.send_request(
                "https://child.local:9770",
                "a" * 64,
                self.request(),
            )
        self.assertEqual(result["status"], "pending")
        pinned.assert_called_once_with("child.local", 9770, "a" * 64)
        client.request.assert_called_once_with(
            "POST", "/node/v1/add-request", self.request()
        )

    def test_json_node_add_lists_incoming_pending_and_discovered_state(self) -> None:
        identity = types.SimpleNamespace(site_id="1" * 32)
        incoming = self.request()
        store = mock.MagicMock()
        store.__enter__.return_value.members.return_value = [
            {
                "member_id": "5" * 32,
                "display_name": "Workshop",
                "address": "workshop.local",
                "state": "pending",
                "approval_expires_at_unix": incoming["expires_at_unix"],
            }
        ]
        discovered = [
            {
                "node_id": "6" * 32,
                "machine_id": "7" * 32,
                "name": "Studio",
                "role": "main",
                "state": "configured",
                "endpoint": "https://studio.local:9770",
                "certificate_sha256": "8" * 64,
                "address": "studio.local",
            }
        ]
        arguments = types.SimpleNamespace(
            timeout=5,
            address=None,
            certificate_sha256=None,
            json=True,
        )
        output = io.StringIO()
        with (
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(cli, "pending_node_add_request", return_value=incoming),
            mock.patch.object(cli, "discover_addable_nodes", return_value=discovered),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.node_add_command(arguments), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value["incoming_request"], incoming)
        self.assertEqual(value["pending_children"][0]["display_name"], "Workshop")
        self.assertEqual(value["discovered_nodes"], discovered)

    def test_control_state_delegates_a_bounded_add_request(self) -> None:
        provider = mock.Mock(
            return_value={
                "protocol": node_add.PROTOCOL,
                "request_id": "1" * 32,
                "status": "pending",
            }
        )
        state = object.__new__(control.SiteControlState)
        state.node_add_provider = provider
        result = state.node_add_request(self.request())
        self.assertEqual(result["status"], "pending")
        provider.assert_called_once_with(self.request())

    def test_main_selection_creates_invite_and_sends_pinned_request(self) -> None:
        identity = types.SimpleNamespace(
            site_id="1" * 32,
            display_name="Home",
            coordinator_address="home.local",
        )
        candidate = {
            "node_id": "2" * 32,
            "machine_id": "3" * 32,
            "name": "Workshop",
            "role": "main",
            "state": "configured",
            "endpoint": "https://workshop.local:9770",
            "certificate_sha256": "4" * 64,
            "address": "workshop.local",
        }
        store = mock.MagicMock()
        store.__enter__.return_value.create_invite.return_value = {
            "invite_id": "5" * 32,
            "code": "12345678",
            "expires_at_unix": int(time.time()) + 180,
        }
        presenter = mock.Mock()
        presenter.prompt.choose.return_value = (
            f"Workshop · workshop.local · {candidate['node_id']}"
        )
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(cli, "certificate_sha256", return_value="6" * 64),
            mock.patch.object(
                cli,
                "send_node_add_request",
                return_value={
                    "protocol": node_add.PROTOCOL,
                    "request_id": "7" * 32,
                    "status": "pending",
                },
            ) as send,
            mock.patch.object(cli.uuid, "uuid4", return_value=types.SimpleNamespace(hex="7" * 32)),
        ):
            self.assertEqual(
                cli._send_node_add_request(
                    types.SimpleNamespace(), identity, [candidate]
                ),
                0,
            )
        document = send.call_args.args[2]
        self.assertEqual(document["invite_id"], "5" * 32)
        self.assertEqual(document["membership_code"], "12345678")
        self.assertEqual(document["main_endpoint"], "https://home.local:9770")

    def test_candidate_approval_moves_then_clears_the_exact_request(self) -> None:
        request = self.request()
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = True
        arguments = types.SimpleNamespace(action_id="node.add")
        identity = types.SimpleNamespace(site_id="8" * 32)
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "site_move_command", return_value=0) as move,
            mock.patch.object(cli, "clear_node_add_request") as clear,
        ):
            self.assertEqual(
                cli._accept_node_add_request(arguments, identity, request),
                0,
            )
        self.assertEqual(move.call_args.args[0].endpoint, request["main_endpoint"])
        clear.assert_called_once_with(request["request_id"])


if __name__ == "__main__":
    unittest.main()
