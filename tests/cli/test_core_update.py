#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import io
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from core import cli as letsinfer


class CoreUpdateTests(unittest.TestCase):
    def _installed_tree(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        source = root / "prefix/lib/letsinfer/1.2.3/abc123"
        source.mkdir(parents=True)
        (source / "install.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        launcher = root / "prefix/bin/letsinfer"
        launcher.parent.mkdir(parents=True)
        launcher.write_text("#!/bin/sh\n", encoding="utf-8")
        return source.resolve(), launcher.resolve()

    def test_update_installs_core_then_rebinds_without_runtime_operations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source, launcher = self._installed_tree(pathlib.Path(directory))
            commands: list[list[str]] = []
            with (
                mock.patch.object(letsinfer, "source_root", return_value=source),
                mock.patch.object(letsinfer.benchmark_jobs, "active_state", return_value=None),
                mock.patch.object(
                    letsinfer, "run_passthrough", side_effect=lambda value: commands.append(list(value))
                ),
            ):
                result = letsinfer.update_core(argparse.Namespace(version="1.2.4-rc.1"))
            self.assertEqual(result, 0)
            self.assertEqual(
                commands,
                [
                    [
                        "/bin/sh",
                        str(source / "install.sh"),
                        "--no-setup",
                        "--prefix",
                        str(source.parents[3]),
                        "--version",
                        "1.2.4-rc.1",
                    ],
                    [str(launcher), "core-rebind"],
                ],
            )

    def test_update_refuses_a_checkout_and_an_active_benchmark(self) -> None:
        with mock.patch.object(
            letsinfer.benchmark_jobs,
            "active_state",
            return_value={"job_id": "job"},
        ), self.assertRaisesRegex(letsinfer.LetsInferError, "benchmark stop"):
            letsinfer.update_core(argparse.Namespace(version=None))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            letsinfer.benchmark_jobs, "active_state", return_value=None
        ), mock.patch.object(
            letsinfer, "source_root", return_value=pathlib.Path(directory)
        ), self.assertRaisesRegex(letsinfer.LetsInferError, "installed"):
            letsinfer.update_core(argparse.Namespace(version=None))

    def test_rebind_preserves_the_selected_runtime_without_rebinding_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            identity = root / "site.json"
            identity.write_text("{}\n", encoding="utf-8")
            config_path = root / "service.json"
            config_path.write_text("{}\n", encoding="utf-8")
            previous = {"model": "qwen3.8-27b"}
            site = mock.Mock(role="coordinator")
            output = io.StringIO()
            with (
                mock.patch.object(letsinfer, "site_identity_path", return_value=identity),
                mock.patch.object(letsinfer, "read_site_identity", return_value=site),
                mock.patch.object(letsinfer, "default_service_config_path", return_value=config_path),
                mock.patch.object(letsinfer, "read_service_config", return_value=previous),
                mock.patch.object(letsinfer, "_unit_enabled_active", return_value=("enabled", "inactive")),
                mock.patch.object(letsinfer, "install_core_plane_services") as install_services,
                redirect_stdout(output),
            ):
                result = letsinfer.rebind_core_services(argparse.Namespace())
            self.assertEqual(result, 0)
            install_services.assert_called_once_with(
                site, include_gateway=True
            )
            self.assertIn("runtime=qwen3.8-27b runtimes=unchanged", output.getvalue())

    def test_core_plane_handoff_quiesces_and_restores_runtime_services(self) -> None:
        commands: list[list[str]] = []
        identity = mock.Mock(role="coordinator")
        with (
            mock.patch.object(letsinfer.platform, "system", return_value="Linux"),
            mock.patch.object(
                letsinfer, "_unit_enabled_active", return_value=("enabled", "active")
            ),
            mock.patch.object(
                letsinfer,
                "run_passthrough",
                side_effect=lambda value: commands.append(list(value)),
            ),
            mock.patch.object(letsinfer, "install_site_service_only") as install_site,
            mock.patch.object(letsinfer, "install_core_watchdog_service") as install_watchdog,
            mock.patch.object(letsinfer, "install_core_gateway_service") as install_gateway,
        ):
            letsinfer.install_core_plane_services(identity, include_gateway=True)
        self.assertEqual(
            commands,
            [
                ["systemctl", "--user", "stop", letsinfer.RECOVERY_TIMER_NAME],
                ["systemctl", "--user", "stop", letsinfer.ENGINE_SERVICE_NAME],
                [
                    "systemctl",
                    "--user",
                    "start",
                    "--no-block",
                    letsinfer.ENGINE_SERVICE_NAME,
                ],
                ["systemctl", "--user", "start", letsinfer.RECOVERY_TIMER_NAME],
            ],
        )
        install_site.assert_called_once_with()
        install_watchdog.assert_called_once_with(identity, replace_active=True)
        install_gateway.assert_called_once_with(replace_active=True)

    def test_parser_exposes_only_the_public_update_command(self) -> None:
        parsed = letsinfer.parser().parse_args(["update", "--version", "1.2.3"])
        self.assertEqual(parsed.action_id, "update")
        help_text = letsinfer.parser().format_help()
        self.assertIn("update", help_text)
        self.assertNotIn("core-rebind", help_text)


if __name__ == "__main__":
    unittest.main()
