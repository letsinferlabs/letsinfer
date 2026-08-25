#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import contextlib
import io
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from core import cli
from core.site.state import SiteIdentity


def member_identity() -> SiteIdentity:
    return SiteIdentity(
        site_id="1" * 32,
        member_id="2" * 32,
        installation_id="3" * 64,
        display_name="Home",
        role="child",
        coordinator_id="4" * 32,
        coordinator_address="coordinator.local",
        site_public_key_sha256="5" * 64,
        member_public_key_sha256="6" * 64,
        created_at_unix=1_700_000_000,
    )


class CoreServiceTests(unittest.TestCase):
    def test_watchdog_unit_keeps_control_plane_scheduling_and_memory_headroom(self) -> None:
        root = pathlib.Path("/private/watchdog")
        config = {
            "watchdog_binary_path": str(root / "letsinfer-watchdog"),
            "watchdog_data_root": str(root / "data"),
            "watchdog_listen": "127.0.0.1",
            "watchdog_port": 9768,
            "watchdog_cert_file": str(root / "server.crt"),
            "watchdog_key_file": str(root / "server.key"),
            "watchdog_controller_ca_file": str(root / "ca.crt"),
            "watchdog_controller_allowlist_file": str(root / "controllers.allow"),
            "watchdog_public_state_file": str(root / "site.state"),
            "gateway_telemetry_file": str(root / "gateway.state"),
        }
        contract = cli.core_watchdog_contract()
        unit = cli.render_user_service(config, {"watchdog": contract})
        self.assertIn(f"MemoryMin={contract['memory_high_bytes']}\n", unit)
        self.assertIn(f"MemoryLow={contract['memory_high_bytes']}\n", unit)
        self.assertIn("OOMPolicy=continue\n", unit)
        self.assertIn("Nice=0\n", unit)
        self.assertIn("CPUWeight=100\n", unit)
        self.assertNotIn("Nice=10\n", unit)

    def test_gateway_unit_is_lan_http_without_client_certificate_flags(self) -> None:
        config = {
            "gateway_listen": "0.0.0.0",
            "gateway_port": 8000,
            "gateway_telemetry_file": "/private/gateway.state",
            "gateway_queue_timeout_seconds": 0,
            "gateway_max_connections": 256,
        }
        unit = cli.render_gateway_service(
            pathlib.Path("/private/gateway.json"),
            config,
            pathlib.Path("/immutable/core"),
        )
        self.assertIn("gateway --listen 0.0.0.0 --port 8000", unit)
        self.assertIn(f"MemoryMin={cli.GATEWAY_MEMORY_HIGH_BYTES}\n", unit)
        self.assertIn(f"MemoryLow={cli.GATEWAY_MEMORY_HIGH_BYTES}\n", unit)
        self.assertIn("OOMPolicy=continue\n", unit)
        self.assertNotIn(" --cert ", unit)
        self.assertNotIn(" --key ", unit)

    def test_member_watchdog_allowlist_is_local_and_has_no_site_database(self) -> None:
        identity = member_identity()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "controllers.allow"
            with (
                mock.patch.object(cli, "certificate_sha256", return_value="7" * 64),
                mock.patch.object(cli, "SiteStore") as site_store,
            ):
                result = cli.ensure_member_watchdog_authorization(
                    identity, pathlib.Path("member-controller.crt"), path
                )
            value = result.read_text(encoding="ascii")

        site_store.assert_not_called()
        self.assertIn(f"installation_id={identity.installation_id}\n", value)
        self.assertRegex(value, r"controller=[0-9a-f]{32},7{64}\n")

    def test_setup_repairs_member_services_without_gateway_or_api_registry(self) -> None:
        identity = member_identity()
        arguments = argparse.Namespace(
            no_service=False,
            name="Home",
            address=None,
            json=True,
        )
        output = io.StringIO()
        with (
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli, "user_lingering_enabled", return_value=True),
            mock.patch.object(cli, "setup_site", return_value=identity),
            mock.patch.object(cli, "ensure_letsinfer_home"),
            mock.patch.object(cli, "ensure_core_watchdog_tls") as tls,
            mock.patch.object(cli, "refresh_local_member_facts"),
            mock.patch.object(cli, "install_core_plane_services") as install_services,
            mock.patch.object(cli, "SiteStore") as site_store,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.setup_command(arguments), 0)

        tls.assert_called_once_with()
        install_services.assert_called_once_with(identity, include_gateway=False)
        site_store.assert_not_called()
        self.assertNotIn("api_key_file", output.getvalue())

    def test_gateway_activation_failure_restores_its_previous_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            home = root / "home"
            config_root = root / "config"
            telemetry = root / "data/gateway.state"
            config_root.mkdir()
            config_path = config_root / "gateway.json"
            config_path.write_text('{"old":true}\n', encoding="utf-8")
            config_path.chmod(0o600)
            result = types.SimpleNamespace(returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(cli.platform, "system", return_value="Linux"),
                mock.patch.object(cli.pathlib.Path, "home", return_value=home),
                mock.patch.object(cli, "site_config_root", return_value=config_root),
                mock.patch.object(cli, "default_gateway_telemetry_path", return_value=telemetry),
                mock.patch.object(cli, "default_tls_cert_path", return_value=root / "tls.crt"),
                mock.patch.object(cli, "default_tls_key_path", return_value=root / "tls.key"),
                mock.patch.object(
                    cli,
                    "_unit_enabled_active",
                    return_value=("not-found", "inactive"),
                ),
                mock.patch.object(cli, "run", return_value=result),
                mock.patch.object(
                    cli,
                    "run_passthrough",
                    side_effect=RuntimeError("synthetic start failure"),
                ),
                mock.patch.object(cli, "_restore_unit_enablement"),
                self.assertRaisesRegex(cli.LetsInferError, "previous state restored"),
            ):
                cli.install_core_gateway_service(executable_root=root)

            self.assertEqual(config_path.read_text(encoding="utf-8"), '{"old":true}\n')
            self.assertFalse((home / ".config/systemd/user" / cli.GATEWAY_SERVICE_NAME).exists())


if __name__ == "__main__":
    unittest.main()
