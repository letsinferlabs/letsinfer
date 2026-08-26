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

    def test_node_add_uses_generic_platform_network_provider(self) -> None:
        plan = mock.sentinel.plan
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = True
        activity = mock.MagicMock()
        activity.enabled = False
        arguments = types.SimpleNamespace(action_id="node.add")
        with (
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli, "host_network_plan", return_value=plan),
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli.sys.stdin, "isatty", return_value=True),
            mock.patch.object(cli, "_command_activity", return_value=activity),
            mock.patch.object(
                cli,
                "apply_network_plan",
                return_value={"state": "configured"},
            ) as apply,
        ):
            cli._prepare_platform_network_for_node_add(arguments)
        apply.assert_called_once_with(plan)
        presenter.result.assert_called_once()

    def test_node_add_preserves_declined_platform_network_setup(self) -> None:
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = False
        with (
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(
                cli, "host_network_plan", return_value=mock.sentinel.plan
            ),
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli.sys.stdin, "isatty", return_value=True),
            mock.patch.object(cli, "apply_network_plan") as apply,
        ):
            cli._prepare_platform_network_for_node_add(
                types.SimpleNamespace(action_id="node.add")
            )
        apply.assert_not_called()
        presenter.result.assert_called_once()

    def test_request_store_is_private_exact_and_clearable(self) -> None:
        expected = self.request()
        self.assertEqual(node_add.store_request(expected), expected)
        self.assertEqual(node_add.pending_request(), expected)
        self.assertEqual(node_add.request_path().stat().st_mode & 0o777, 0o600)
        node_add.clear_request(str(expected["request_id"]))
        self.assertIsNone(node_add.pending_request())

    def test_child_node_add_detaches_then_enters_the_main_workflow(self) -> None:
        child = types.SimpleNamespace(role="child")
        with (
            mock.patch.object(cli, "read_site_identity", return_value=child),
            mock.patch.object(cli, "_detach_child_for_node_add") as detach,
            mock.patch.object(cli, "_node_add_workflow", return_value=0) as workflow,
        ):
            arguments = types.SimpleNamespace(action_id="node.add")
            self.assertEqual(cli.node_add_command(arguments), 0)
        detach.assert_called_once_with(arguments, child)
        workflow.assert_called_once_with(arguments)

    def test_child_detach_is_confirmed_staged_and_coordinator_removed(self) -> None:
        child = types.SimpleNamespace(
            role="child",
            site_id="1" * 32,
            member_id="2" * 32,
            coordinator_id="3" * 32,
            coordinator_address="homeai.localdomain",
        )
        replacement = types.SimpleNamespace(role="main", site_id="4" * 32)
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = True
        activity = mock.MagicMock()
        activity.enabled = False
        transaction = mock.MagicMock()
        transaction.__enter__.return_value = transaction
        transaction.config_backup = pathlib.Path("/tmp/old-config")
        transaction.secrets_backup = pathlib.Path("/tmp/old-secrets")
        transaction.commit.return_value = replacement
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli.sys.stdin, "isatty", return_value=True),
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli, "user_lingering_enabled", return_value=True),
            mock.patch.object(
                cli, "_unit_enabled_active", return_value=("disabled", "inactive")
            ),
            mock.patch.object(cli, "_snapshot_user_file", return_value=None),
            mock.patch.object(cli, "_command_activity", return_value=activity),
            mock.patch.object(
                cli, "LocalDetachTransaction", return_value=transaction
            ),
            mock.patch.object(cli, "setup_command", return_value=0) as setup,
            mock.patch.object(cli, "read_site_identity", return_value=replacement),
            mock.patch.object(cli, "install_core_plane_services") as install,
            mock.patch.object(cli, "wait_for_core_plane_ready") as ready,
            mock.patch.object(cli, "request_self_detach") as detach,
            mock.patch.object(
                cli,
                "site_ca_certificate_path",
                return_value=pathlib.Path("/tmp/config/site-ca.crt"),
            ),
            mock.patch.object(
                cli,
                "site_member_certificate_path",
                return_value=pathlib.Path("/tmp/config/member.crt"),
            ),
            mock.patch.object(
                cli,
                "site_member_key_path",
                return_value=pathlib.Path("/tmp/secrets/member.key"),
            ),
            mock.patch.object(
                cli, "site_config_root", return_value=pathlib.Path("/tmp/config")
            ),
            mock.patch.object(
                cli, "secrets_root", return_value=pathlib.Path("/tmp/secrets")
            ),
        ):
            cli._detach_child_for_node_add(
                types.SimpleNamespace(action_id="node.add", json=False), child
            )
        presenter.prompt.confirm.assert_called_once_with(
            "Detach this node from homeai and make it standalone?",
            require_tty=True,
        )
        install.assert_called_once_with(replacement, include_gateway=True)
        setup.assert_called_once()
        ready.assert_called_once_with(include_gateway=True)
        detach.assert_called_once()
        transaction.commit.assert_called_once()
        presenter.result.assert_called_once()

    def test_child_detach_decline_is_a_muted_normal_outcome(self) -> None:
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = False
        child = types.SimpleNamespace(
            role="child",
            coordinator_address="homeai.localdomain",
        )
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli.sys.stdin, "isatty", return_value=True),
            self.assertRaisesRegex(cli.CommandDenied, "Node detach cancelled"),
        ):
            cli._detach_child_for_node_add(
                types.SimpleNamespace(action_id="node.add"), child
            )

    def test_child_can_pause_itself_through_the_coordinator(self) -> None:
        identity = types.SimpleNamespace(
            role="child",
            member_id="2" * 32,
            coordinator_id="1" * 32,
            coordinator_address="home.local",
        )
        rows = [
            {
                "member_id": "1" * 32,
                "display_name": "homeai",
                "role": "main",
                "address": "home.local",
                "state": "active",
            },
            {
                "member_id": "2" * 32,
                "display_name": "node-2",
                "role": "child",
                "address": "node-2.local",
                "state": "active",
            },
        ]
        with (
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(cli, "_node_command_rows", return_value=rows),
            mock.patch.object(
                cli,
                "request_self_member_state",
                return_value={"member_id": identity.member_id, "state": "draining"},
            ) as request,
            mock.patch.object(cli, "_human_presenter", return_value=None),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                cli.member_drain_command(
                    types.SimpleNamespace(
                        member="self",
                        yes=True,
                        json=False,
                    )
                ),
                0,
            )
        request.assert_called_once_with(identity, paused=True)

    def test_node_inventory_marks_stale_facts_offline(self) -> None:
        identity = types.SimpleNamespace(role="main")
        store = mock.MagicMock()
        store.__enter__.return_value.members.return_value = [
            {
                "member_id": "1" * 32,
                "display_name": "homeai",
                "role": "main",
                "state": "active",
                "facts": {"observed_at_unix": 99},
            },
            {
                "member_id": "2" * 32,
                "display_name": "node-2",
                "role": "child",
                "state": "active",
                "facts": {"observed_at_unix": 90},
            },
        ]
        with (
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(cli.time, "time", return_value=100),
        ):
            rows = cli._node_command_rows(identity)
        by_id = {row["member_id"]: row for row in rows}
        self.assertEqual(by_id["1" * 32]["state"], "active")
        self.assertTrue(by_id["1" * 32]["online"])
        self.assertEqual(by_id["2" * 32]["state"], "offline")
        self.assertFalse(by_id["2" * 32]["online"])

    def test_child_node_inventory_uses_coordinator_observation_time(self) -> None:
        identity = types.SimpleNamespace(role="child")
        rows = [
            {
                "member_id": "1" * 32,
                "display_name": "homeai",
                "role": "main",
                "state": "active",
                "observed_at_unix": 100,
            },
            {
                "member_id": "2" * 32,
                "display_name": "node-2",
                "role": "child",
                "state": "draining",
                "observed_at_unix": 99,
            },
        ]
        with (
            mock.patch.object(
                cli, "fetch_coordinator_node_inventory", return_value=rows
            ),
            mock.patch.object(cli.time, "time", return_value=100),
        ):
            result = cli._node_command_rows(identity)
        by_id = {row["member_id"]: row for row in result}
        self.assertEqual(by_id["1" * 32]["state"], "active")
        self.assertEqual(by_id["2" * 32]["state"], "paused")

    def test_main_can_pause_itself_explicitly(self) -> None:
        identity = types.SimpleNamespace(
            role="main",
            member_id="1" * 32,
            coordinator_id="1" * 32,
        )
        row = {
            "member_id": identity.member_id,
            "display_name": "homeai",
            "role": "main",
            "state": "active",
        }
        store = mock.MagicMock()
        store.__enter__.return_value.set_member_draining.return_value = {
            "member_id": identity.member_id,
            "state": "draining",
        }
        with (
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(cli, "_node_command_rows", return_value=[row]),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(cli, "_human_presenter", return_value=None),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                cli.member_drain_command(
                    types.SimpleNamespace(member="self", yes=True, json=False)
                ),
                0,
            )
        store.__enter__.return_value.set_member_draining.assert_called_once_with(
            identity.member_id, True
        )

    def test_child_node_remove_reuses_coordinated_detach(self) -> None:
        identity = types.SimpleNamespace(
            role="child",
            member_id="2" * 32,
            coordinator_id="1" * 32,
        )
        row = {
            "member_id": identity.member_id,
            "display_name": "node-2",
            "role": "child",
            "state": "active",
        }
        arguments = types.SimpleNamespace(member=None, yes=False, json=False)
        with (
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(cli, "_node_command_rows", return_value=[row]),
            mock.patch.object(cli, "_human_presenter", return_value=mock.Mock()),
            mock.patch.object(cli.sys.stdin, "isatty", return_value=True),
            mock.patch.object(cli, "_detach_child_for_node_add") as detach,
        ):
            self.assertEqual(cli.member_remove_command(arguments), 0)
        detach.assert_called_once_with(arguments, identity)

    def test_denial_removes_request_and_exposes_bounded_status(self) -> None:
        expected = self.request()
        node_add.store_request(expected)
        self.assertEqual(
            node_add.deny_request(str(expected["request_id"])),
            {
                "protocol": node_add.PROTOCOL,
                "request_id": expected["request_id"],
                "status": "denied",
            },
        )
        self.assertIsNone(node_add.pending_request())
        self.assertEqual(
            node_add.request_status(str(expected["request_id"]))["status"],
            "denied",
        )
        self.assertEqual(node_add.decision_path().stat().st_mode & 0o777, 0o600)

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

    def test_avahi_discovery_decodes_name_and_deduplicates_node_addresses(self) -> None:
        node = "a" * 32
        machine = "b" * 32
        certificate = "c" * 64
        txt = (
            f'"node={node}" "machine={machine}" "tls={certificate}" '
            '"control=letsinfer-node-control-v1" "role=main" "state=configured"'
        )
        output = "\n".join(
            (
                "=;enP7s7;IPv6;Let\\039s\\032Infer\\032\\226\\128\\148"
                "\\032Home\\032\\0352;_letsinfer._tcp;local;"
                f"homeai-node-2.local;fdb7:cd9b:9a06:41a7::2;9770;{txt}",
                "=;enP7s7;IPv4;Let\\039s\\032Infer\\032\\226\\128\\148"
                "\\032Home\\032\\0352;_letsinfer._tcp;local;"
                f"homeai-node-2.local;192.168.1.215;9770;{txt}",
            )
        )
        self.assertEqual(
            node_add._parse_avahi(output),
            [
                {
                    "node_id": node,
                    "machine_id": machine,
                    "name": "homeai-node-2",
                    "role": "main",
                    "state": "configured",
                    "endpoint": "https://192.168.1.215:9770",
                    "certificate_sha256": certificate,
                    "address": "192.168.1.215",
                }
            ],
        )

    def test_avahi_discovery_rejects_conflicting_identity_for_one_node(self) -> None:
        node = "a" * 32
        machine = "b" * 32
        common = (
            f'"node={node}" "machine={machine}" '
            '"control=letsinfer-node-control-v1" "role=main" "state=configured"'
        )
        output = "\n".join(
            (
                "=;eth0;IPv4;Let\\039s\\032Infer\\032Home;_letsinfer._tcp;"
                f"local;one.local;192.168.1.2;9770;{common} \"tls={'c' * 64}\"",
                "=;eth0;IPv6;Let\\039s\\032Infer\\032Home;_letsinfer._tcp;"
                f"local;one.local;2001:db8::2;9770;{common} \"tls={'d' * 64}\"",
            )
        )
        with self.assertRaisesRegex(node_add.NodeAddError, "conflicting"):
            node_add._parse_avahi(output)

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

    def test_request_status_sender_uses_pinned_candidate(self) -> None:
        client = mock.Mock()
        client.request.return_value = {
            "protocol": node_add.PROTOCOL,
            "request_id": "1" * 32,
            "status": "denied",
        }
        with mock.patch.object(node_add, "PinnedHTTPS", return_value=client):
            result = node_add.query_request_status(
                "https://child.local:9770", "a" * 64, "1" * 32
            )
        self.assertEqual(result["status"], "denied")
        client.request.assert_called_once_with(
            "GET", f"/node/v1/add-request/{'1' * 32}"
        )

    def test_json_node_add_lists_incoming_pending_and_discovered_state(self) -> None:
        identity = types.SimpleNamespace(site_id="1" * 32, role="main")
        incoming = self.request()
        store = mock.MagicMock()
        store.__enter__.return_value.members.return_value = [
            {
                "member_id": "5" * 32,
                "display_name": "Workshop",
                "role": "child",
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

    def test_existing_child_is_not_repeated_as_a_discovered_node(self) -> None:
        member_id = "5" * 32
        child = {
            "member_id": member_id,
            "display_name": "Workshop",
            "address": "workshop.local",
            "state": "active",
            "approval_expires_at_unix": 1,
        }
        discovered = {
            "node_id": "6" * 32,
            "machine_id": member_id,
            "name": "Workshop",
            "address": "192.0.2.10",
        }
        with (
            mock.patch.object(cli, "_node_add_children", return_value=[child]),
            mock.patch.object(cli, "pending_node_add_request", return_value=None),
        ):
            snapshot = cli._node_add_snapshot(
                types.SimpleNamespace(site_id="1" * 32), [discovered]
            )
        self.assertEqual(snapshot["pending_children"], [])
        self.assertEqual(snapshot["discovered_nodes"], [])

    def test_live_surface_places_request_above_discovered_nodes(self) -> None:
        terminal = types.SimpleNamespace(paint=lambda value, *_styles: value)
        presenter = types.SimpleNamespace(terminal=terminal)
        request = self.request()
        snapshot = {
            "incoming_request": request,
            "pending_children": [],
            "discovered_nodes": [
                {
                    "node_id": "6" * 32,
                    "name": "homeai-node-2",
                    "address": "192.168.1.215",
                }
            ],
        }
        self.assertEqual(
            cli._node_add_surface(
                presenter,
                snapshot,
                ("accept", str(request["request_id"])),
            ),
            [
                "! Adoption request from Home",
                "[Accept] [Deny]",
                "",
                "Discovered Nodes",
                "   1  homeai-node-2 · 192.168.1.215",
                "'Enter' to select",
            ],
        )

    def test_live_discovery_refresh_surfaces_new_request_and_accepts(self) -> None:
        request = self.request()
        empty = {
            "incoming_request": None,
            "pending_children": [],
            "discovered_nodes": [],
        }
        incoming = {**empty, "incoming_request": request}
        stream = io.StringIO()
        prompt = mock.Mock()
        prompt.navigation_mode.return_value = contextlib.nullcontext()
        prompt.poll_navigation_key.side_effect = (None, "enter")
        presenter = types.SimpleNamespace(
            terminal=types.SimpleNamespace(paint=lambda value, *_styles: value),
            prompt=prompt,
            stream=stream,
        )
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli.sys.stdin, "isatty", return_value=True),
            mock.patch.object(
                cli,
                "_node_add_snapshot",
                side_effect=(empty, incoming),
            ),
            mock.patch.object(cli, "discover_addable_nodes", return_value=[]),
        ):
            action, value = cli._live_node_add_choice(
                types.SimpleNamespace(address=None, certificate_sha256=None),
                types.SimpleNamespace(site_id="8" * 32),
            )
        self.assertEqual(action, "accept")
        self.assertEqual(value, request)
        self.assertIn("Adoption request from Home", stream.getvalue())

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

        status_provider = mock.Mock(
            return_value={
                "protocol": node_add.PROTOCOL,
                "request_id": "1" * 32,
                "status": "pending",
            }
        )
        state.node_add_status_provider = status_provider
        self.assertEqual(state.node_add_status("1" * 32)["status"], "pending")
        status_provider.assert_called_once_with("1" * 32)

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
            "Workshop · workshop.local"
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
            mock.patch.object(
                cli,
                "_wait_for_node_add_response",
                return_value=0,
            ) as wait,
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
        wait.assert_called_once()

    def test_originating_node_reports_exact_denial(self) -> None:
        selected = {
            "name": "Workshop",
            "endpoint": "https://workshop.local:9770",
            "certificate_sha256": "4" * 64,
        }
        document = self.request()
        with (
            mock.patch.object(cli, "_command_activity", return_value=contextlib.nullcontext()),
            mock.patch.object(cli, "_node_add_children", return_value=[]),
            mock.patch.object(
                cli,
                "query_node_add_request_status",
                return_value={
                    "protocol": node_add.PROTOCOL,
                    "request_id": document["request_id"],
                    "status": "denied",
                },
            ),
            self.assertRaisesRegex(cli.CommandDenied, "Workshop denied the request"),
        ):
            cli._wait_for_node_add_response(
                types.SimpleNamespace(action_id="node.add", json=False),
                types.SimpleNamespace(),
                selected,
                document,
                set(),
            )

    def test_originating_node_finishes_when_the_child_is_already_active(self) -> None:
        selected = {
            "name": "Workshop",
            "machine_id": "5" * 32,
            "endpoint": "https://workshop.local:9770",
            "certificate_sha256": "4" * 64,
        }
        child = {
            "member_id": "5" * 32,
            "display_name": "Workshop",
            "address": "workshop.local",
            "state": "active",
            "approval_expires_at_unix": None,
        }
        presenter = mock.Mock()
        with (
            mock.patch.object(cli, "_command_activity", return_value=contextlib.nullcontext()),
            mock.patch.object(cli, "_node_add_children", return_value=[child]),
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
        ):
            self.assertEqual(
                cli._wait_for_node_add_response(
                    types.SimpleNamespace(action_id="node.add", json=False),
                    types.SimpleNamespace(),
                    selected,
                    self.request(),
                    set(),
                ),
                0,
            )
        presenter.result.assert_called_once_with(
            "Added Workshop",
            semantic=cli.command_ui.Semantic.SUCCESS,
            detail="5" * 32,
        )

    def test_single_legacy_pending_child_activates_without_picker_or_code(self) -> None:
        child = {
            "member_id": "5" * 32,
            "display_name": "Workshop",
            "address": "workshop.local",
            "state": "pending",
            "approval_expires_at_unix": 1,
        }
        presenter = mock.Mock()
        store = mock.MagicMock()
        store.__enter__.return_value.approve_member_locally.return_value = {
            "member_id": child["member_id"],
            "state": "active",
        }
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "_site_store", return_value=store),
        ):
            self.assertEqual(
                cli._approve_pending_child(
                    types.SimpleNamespace(action_id="node.add"), [child]
                ),
                0,
            )
        presenter.prompt.choose.assert_not_called()
        presenter.prompt.secret.assert_not_called()
        store.__enter__.return_value.approve_member_locally.assert_called_once_with(
            child["member_id"]
        )
        presenter.result.assert_called_once()

    def test_candidate_approval_moves_then_clears_the_exact_request(self) -> None:
        request = self.request()
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = True
        arguments = types.SimpleNamespace(action_id="node.add")
        identity = types.SimpleNamespace(site_id="8" * 32)
        plan = types.SimpleNamespace(active_placements=(), blocking_reasons=())
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "_site_store", return_value=mock.MagicMock()),
            mock.patch.object(cli, "plan_local_move", return_value=plan),
            mock.patch.object(cli, "site_move_command", return_value=0) as move,
            mock.patch.object(cli, "clear_node_add_request") as clear,
        ):
            self.assertEqual(
                cli._accept_node_add_request(arguments, identity, request),
                0,
            )
        self.assertEqual(move.call_args.args[0].endpoint, request["main_endpoint"])
        clear.assert_called_once_with(request["request_id"])

    def test_candidate_move_propagates_its_pre_transfer_audit(self) -> None:
        request = self.request()
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = True
        arguments = types.SimpleNamespace(action_id="node.add")
        identity = types.SimpleNamespace(site_id="8" * 32)
        plan = types.SimpleNamespace(active_placements=(), blocking_reasons=())

        def move(move_arguments: types.SimpleNamespace) -> int:
            move_arguments._mandatory_audit_satisfied = (
                cli._MANDATORY_AUDIT_SATISFIED
            )
            return 0

        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "_site_store", return_value=mock.MagicMock()),
            mock.patch.object(cli, "plan_local_move", return_value=plan),
            mock.patch.object(cli, "site_move_command", side_effect=move),
            mock.patch.object(cli, "clear_node_add_request"),
        ):
            self.assertEqual(
                cli._accept_node_add_request(arguments, identity, request),
                0,
            )
        self.assertIs(
            arguments._mandatory_audit_satisfied,
            cli._MANDATORY_AUDIT_SATISFIED,
        )

    def test_candidate_approval_confirms_stops_and_moves_active_model(self) -> None:
        request = self.request()
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = True
        arguments = types.SimpleNamespace(action_id="node.add", json=False)
        identity = types.SimpleNamespace(site_id="8" * 32)
        active = {
            "placement_id": "6" * 32,
            "model": "deepseek-v4-flash",
            "state": "running",
        }
        blocked = types.SimpleNamespace(
            active_placements=(active,),
            blocking_reasons=(
                "all source-site placements must be stopped before the move",
            ),
        )
        ready = types.SimpleNamespace(active_placements=(), blocking_reasons=())
        activity = mock.MagicMock()
        activity.enabled = False
        group_ids = ("7" * 32,)
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "_site_store", return_value=mock.MagicMock()),
            mock.patch.object(cli, "plan_local_move", side_effect=(blocked, ready)),
            mock.patch.object(
                cli,
                "_node_move_stop_targets",
                return_value=(group_ids, None),
            ) as resolve,
            mock.patch.object(
                cli,
                "_stop_node_move_models",
                return_value=(group_ids, None),
            ) as stop,
            mock.patch.object(cli, "_command_activity", return_value=activity),
            mock.patch.object(cli, "site_move_command", return_value=0) as move,
            mock.patch.object(cli, "clear_node_add_request") as clear,
        ):
            self.assertEqual(
                cli._accept_node_add_request(
                    arguments, identity, request, confirmed=True
                ),
                0,
            )
        presenter.prompt.confirm.assert_called_once_with(
            "Stop model deepseek-v4-flash and move this node into Home?",
            require_tty=True,
        )
        warning = presenter.panel.call_args.args[0]
        self.assertIn("This main node will become a child of Home", warning[0])
        self.assertEqual(
            warning[1],
            "OpenAI endpoint  Clients must switch to http://home.local:8000/v1; "
            "this node will no longer own it.",
        )
        self.assertIn("controller pairings", warning[2])
        self.assertIn("must be placed again by Home", warning[3])
        self.assertEqual(
            presenter.panel.call_args.kwargs["title"],
            "Main node authority will move",
        )
        resolve.assert_called_once_with((active,))
        stop.assert_called_once_with(group_ids, None)
        move.assert_called_once()
        clear.assert_called_once_with(request["request_id"])

    def test_candidate_move_failure_restores_the_models_and_keeps_request(self) -> None:
        request = self.request()
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = True
        arguments = types.SimpleNamespace(action_id="node.add", json=False)
        identity = types.SimpleNamespace(site_id="8" * 32)
        active = {
            "placement_id": "6" * 32,
            "model": "deepseek-v4-flash",
            "state": "running",
        }
        blocked = types.SimpleNamespace(
            active_placements=(active,),
            blocking_reasons=(
                "all source-site placements must be stopped before the move",
            ),
        )
        ready = types.SimpleNamespace(active_placements=(), blocking_reasons=())
        activity = mock.MagicMock()
        activity.enabled = False
        group_ids = ("7" * 32,)
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "_site_store", return_value=mock.MagicMock()),
            mock.patch.object(cli, "plan_local_move", side_effect=(blocked, ready)),
            mock.patch.object(
                cli,
                "_node_move_stop_targets",
                return_value=(group_ids, None),
            ),
            mock.patch.object(
                cli,
                "_stop_node_move_models",
                return_value=(group_ids, None),
            ),
            mock.patch.object(cli, "_command_activity", return_value=activity),
            mock.patch.object(
                cli, "site_move_command", side_effect=cli.LetsInferError("expired")
            ),
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(cli, "_restore_node_move_models") as restore,
            mock.patch.object(cli, "clear_node_add_request") as clear,
            self.assertRaisesRegex(cli.LetsInferError, "expired"),
        ):
            cli._accept_node_add_request(arguments, identity, request, confirmed=True)
        restore.assert_called_once_with(group_ids, None)
        clear.assert_not_called()

    def test_candidate_declining_model_stop_is_a_normal_cancellation(self) -> None:
        request = self.request()
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = False
        active = {
            "placement_id": "6" * 32,
            "model": "deepseek-v4-flash",
            "state": "running",
        }
        plan = types.SimpleNamespace(
            active_placements=(active,),
            blocking_reasons=(
                "all source-site placements must be stopped before the move",
            ),
        )
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "_site_store", return_value=mock.MagicMock()),
            mock.patch.object(cli, "plan_local_move", return_value=plan),
            mock.patch.object(cli, "_stop_node_move_models") as stop,
            self.assertRaisesRegex(cli.CommandDenied, "Node move cancelled"),
        ):
            cli._accept_node_add_request(
                types.SimpleNamespace(action_id="node.add", json=False),
                types.SimpleNamespace(site_id="8" * 32),
                request,
                confirmed=True,
            )
        stop.assert_not_called()

    def test_node_move_stops_a_running_qualification_candidate(self) -> None:
        placement_id = "6" * 32
        placement = {
            "placement_id": placement_id,
            "model": "nemotron-3.5-lightning",
            "state": "running",
        }
        qualification = {
            "qualification_mode": True,
            "placement_id": placement_id,
            "model": placement["model"],
        }
        store = mock.MagicMock()
        store.__enter__.return_value.engine_groups.return_value = []
        path = mock.Mock()
        path.is_file.return_value = True
        with (
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli, "qualification_service_config_path", return_value=path
            ),
            mock.patch.object(
                cli, "read_service_config", return_value=qualification
            ),
        ):
            self.assertEqual(
                cli._node_move_stop_targets((placement,)),
                ((), qualification),
            )

        with (
            mock.patch.object(
                cli, "_qualification_candidate_lifecycle", return_value=0
            ) as lifecycle,
            mock.patch.object(
                cli, "_stop_node_move_groups", return_value=()
            ),
        ):
            self.assertEqual(
                cli._stop_node_move_models((), qualification),
                ((), qualification),
            )
        lifecycle.assert_called_once_with(qualification, "stop")

    def test_candidate_move_stops_the_qualification_owner_then_moves(self) -> None:
        request = self.request()
        presenter = mock.Mock()
        presenter.prompt.confirm.return_value = True
        arguments = types.SimpleNamespace(action_id="node.add", json=False)
        identity = types.SimpleNamespace(site_id="8" * 32)
        active = {
            "placement_id": "6" * 32,
            "model": "nemotron-3.5-lightning",
            "state": "running",
        }
        qualification = {
            "qualification_mode": True,
            "placement_id": active["placement_id"],
            "model": active["model"],
        }
        blocked = types.SimpleNamespace(
            active_placements=(active,),
            blocking_reasons=(
                "all source-site placements must be stopped before the move",
            ),
        )
        ready = types.SimpleNamespace(active_placements=(), blocking_reasons=())
        activity = mock.MagicMock()
        activity.enabled = False
        with (
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "_site_store", return_value=mock.MagicMock()),
            mock.patch.object(cli, "plan_local_move", side_effect=(blocked, ready)),
            mock.patch.object(
                cli,
                "_node_move_stop_targets",
                return_value=((), qualification),
            ),
            mock.patch.object(
                cli,
                "_stop_node_move_models",
                return_value=((), qualification),
            ) as stop,
            mock.patch.object(cli, "_command_activity", return_value=activity),
            mock.patch.object(cli, "site_move_command", return_value=0) as move,
            mock.patch.object(cli, "clear_node_add_request"),
        ):
            self.assertEqual(
                cli._accept_node_add_request(
                    arguments, identity, request, confirmed=True
                ),
                0,
            )
        stop.assert_called_once_with((), qualification)
        move.assert_called_once()

    def test_node_move_rejects_an_unowned_running_placement(self) -> None:
        placement_id = "6" * 32
        store = mock.MagicMock()
        store.__enter__.return_value.engine_groups.return_value = []
        path = mock.Mock()
        path.is_file.return_value = False
        with (
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli, "qualification_service_config_path", return_value=path
            ),
            self.assertRaisesRegex(cli.LetsInferError, "active owner"),
        ):
            cli._node_move_stop_targets(
                (
                    {
                        "placement_id": placement_id,
                        "model": "nemotron-3.5-lightning",
                    },
                )
            )

    def test_node_move_resolves_only_stable_running_groups(self) -> None:
        placement_id = "6" * 32
        group_id = "7" * 32
        store = mock.MagicMock()
        store.__enter__.return_value.engine_groups.return_value = [
            {
                "placement_id": placement_id,
                "group_id": group_id,
                "state": "running",
                "desired_state": "running",
            }
        ]
        with mock.patch.object(cli, "_site_store", return_value=store):
            self.assertEqual(
                cli._node_move_running_group_ids(
                    ({"placement_id": placement_id},)
                ),
                (group_id,),
            )
        store.__enter__.return_value.engine_groups.return_value[0]["state"] = "stopping"
        with (
            mock.patch.object(cli, "_site_store", return_value=store),
            self.assertRaisesRegex(cli.LetsInferError, "current lifecycle"),
        ):
            cli._node_move_running_group_ids(({"placement_id": placement_id},))

    def test_partial_model_stop_restores_already_stopped_groups(self) -> None:
        first = "6" * 32
        second = "7" * 32
        with (
            mock.patch.object(
                cli,
                "_stop_engine_group_by_id",
                side_effect=(None, cli.LetsInferError("stop failed")),
            ),
            mock.patch.object(cli, "_restore_node_move_groups") as restore,
            self.assertRaisesRegex(cli.LetsInferError, "stop failed"),
        ):
            cli._stop_node_move_groups((first, second))
        restore.assert_called_once_with([first])


if __name__ == "__main__":
    unittest.main()
