#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import io
import pathlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock
from types import SimpleNamespace

from core import cli as letsinfer


class CoreUpdateTests(unittest.TestCase):
    def test_interactive_update_preflights_sudo_then_owns_three_steps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            installer = root / "install.sh"
            installer.write_text("#!/bin/sh\n", encoding="utf-8")
            launcher = root / "letsinfer"
            launcher.write_text("#!/bin/sh\n", encoding="utf-8")
            events: list[object] = []

            class Progress:
                def __init__(self, *_: object, **__: object) -> None:
                    pass

                def __enter__(self) -> "Progress":
                    events.append("progress:start")
                    return self

                def advance(self) -> None:
                    events.append("progress:advance")

                def __exit__(self, *args: object) -> None:
                    events.append("progress:end")

            terminal = SimpleNamespace(
                interactive=True,
                success=lambda message: events.append(("success", message)),
            )

            def captured(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                events.append(("run", command))
                return subprocess.CompletedProcess(command, 0, "", "")

            with (
                mock.patch.object(letsinfer.benchmark_jobs, "active_state", return_value=None),
                mock.patch.object(
                    letsinfer,
                    "_installed_core_layout",
                    return_value=(pathlib.Path("/opt/letsinfer"), installer, launcher),
                ),
                mock.patch.object(
                    letsinfer, "run_passthrough",
                    side_effect=lambda command: events.append(("passthrough", command)),
                ),
                mock.patch.object(letsinfer, "run", side_effect=captured),
                mock.patch.object(letsinfer.ui, "Terminal", return_value=terminal),
                mock.patch.object(letsinfer.ui, "StepProgress", Progress),
            ):
                self.assertEqual(
                    letsinfer.update_core(argparse.Namespace(version="0.11.0-rc.16")), 0
                )
        self.assertEqual(events[0], ("passthrough", ["sudo", "-v"]))
        self.assertEqual(events[1], "progress:start")
        self.assertEqual(
            events[2],
            ("run", [
                "/bin/sh", str(installer), "--no-setup", "--no-progress",
                "--version", "0.11.0-rc.16",
            ]),
        )
        self.assertEqual(events.count("progress:advance"), 3)
        self.assertIn(("run", [str(launcher), "core-rebind"]), events)
        self.assertIn(("run", [str(launcher), "--help"]), events)
        self.assertEqual(events[-1], ("success", "Core updated"))

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
                        "--no-progress",
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
                mock.patch.object(
                    letsinfer,
                    "install_core_plane_services",
                    return_value={
                        "configured": True,
                        "compatible": True,
                        "error": None,
                    },
                ) as install_services,
                mock.patch.object(
                    letsinfer, "wait_for_core_plane_ready"
                ) as wait_ready,
                redirect_stdout(output),
            ):
                result = letsinfer.rebind_core_services(argparse.Namespace())
            self.assertEqual(result, 0)
            install_services.assert_called_once_with(
                site, include_gateway=True
            )
            wait_ready.assert_called_once_with(include_gateway=True)
            self.assertIn("runtime=qwen3.8-27b runtimes=unchanged", output.getvalue())

    def test_core_plane_readiness_requires_stable_services_and_gateway(self) -> None:
        with (
            mock.patch.object(letsinfer.platform, "system", return_value="Linux"),
            mock.patch.object(
                letsinfer,
                "_unit_enabled_active",
                return_value=("enabled", "active"),
            ) as unit_state,
            mock.patch.object(
                letsinfer,
                "api_status",
                side_effect=(None, 200, 200, 200),
            ) as gateway_status,
            mock.patch.object(letsinfer.time, "sleep") as sleep,
        ):
            letsinfer.wait_for_core_plane_ready(
                include_gateway=True,
                timeout_seconds=10,
                poll_seconds=0.1,
                stable_polls=3,
            )
        self.assertEqual(gateway_status.call_count, 4)
        self.assertEqual(unit_state.call_count, 12)
        self.assertEqual(sleep.call_count, 3)

    def test_core_plane_readiness_fails_closed_after_bounded_wait(self) -> None:
        with (
            mock.patch.object(letsinfer.platform, "system", return_value="Linux"),
            mock.patch.object(
                letsinfer,
                "_unit_enabled_active",
                return_value=("enabled", "activating"),
            ),
            mock.patch.object(
                letsinfer.time,
                "monotonic",
                side_effect=(0.0, 0.0, 2.0),
            ),
            mock.patch.object(letsinfer.time, "sleep"),
            self.assertRaisesRegex(
                letsinfer.LetsInferError, "did not become stable"
            ),
        ):
            letsinfer.wait_for_core_plane_ready(
                include_gateway=False,
                timeout_seconds=1,
                poll_seconds=0.1,
            )

    def test_core_plane_handoff_quiesces_and_restores_runtime_services(self) -> None:
        commands: list[list[str]] = []
        identity = mock.Mock(role="coordinator")
        manifest = {"watchdog": {"protection": {"warning_available_bytes": 4 << 30}}}
        with tempfile.TemporaryDirectory() as directory:
            config_path = pathlib.Path(directory) / "service.json"
            config_path.write_text("{}\n", encoding="utf-8")
            with (
                mock.patch.object(letsinfer.platform, "system", return_value="Linux"),
                mock.patch.object(
                    letsinfer, "default_service_config_path", return_value=config_path
                ),
                mock.patch.object(letsinfer, "read_service_config", return_value={}),
                mock.patch.object(
                    letsinfer, "configured_release", return_value=(config_path, manifest)
                ),
                mock.patch.object(
                    letsinfer, "_unit_enabled_active", return_value=("enabled", "active")
                ),
                mock.patch.object(
                    letsinfer,
                    "run_passthrough",
                    side_effect=lambda value: commands.append(list(value)),
                ),
                mock.patch.object(letsinfer, "install_site_service_only") as install_site,
                mock.patch.object(
                    letsinfer, "install_core_watchdog_service"
                ) as install_watchdog,
                mock.patch.object(
                    letsinfer, "install_core_gateway_service"
                ) as install_gateway,
            ):
                state = letsinfer.install_core_plane_services(
                    identity, include_gateway=True
                )
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
        self.assertTrue(state["compatible"])
        install_site.assert_called_once_with()
        install_watchdog.assert_called_once_with(
            identity, replace_active=True, runtime_manifest=manifest
        )
        install_gateway.assert_called_once_with(replace_active=True)

    def test_core_plane_handoff_stops_an_incompatible_runtime(self) -> None:
        commands: list[list[str]] = []
        identity = mock.Mock(role="coordinator")
        with tempfile.TemporaryDirectory() as directory:
            config_path = pathlib.Path(directory) / "service.json"
            config_path.write_text("{}\n", encoding="utf-8")
            with (
                mock.patch.object(letsinfer.platform, "system", return_value="Linux"),
                mock.patch.object(
                    letsinfer, "default_service_config_path", return_value=config_path
                ),
                mock.patch.object(letsinfer, "read_service_config", return_value={}),
                mock.patch.object(
                    letsinfer,
                    "configured_release",
                    side_effect=letsinfer.LetsInferError("runtime API is incompatible"),
                ),
                mock.patch.object(
                    letsinfer, "_unit_enabled_active", return_value=("enabled", "active")
                ),
                mock.patch.object(
                    letsinfer,
                    "run_passthrough",
                    side_effect=lambda value: commands.append(list(value)),
                ),
                mock.patch.object(letsinfer, "install_site_service_only"),
                mock.patch.object(
                    letsinfer, "install_core_watchdog_service"
                ) as install_watchdog,
                mock.patch.object(letsinfer, "install_core_gateway_service"),
            ):
                state = letsinfer.install_core_plane_services(
                    identity, include_gateway=True
                )
        self.assertFalse(state["compatible"])
        self.assertEqual(
            commands,
            [
                ["systemctl", "--user", "stop", letsinfer.RECOVERY_TIMER_NAME],
                ["systemctl", "--user", "stop", letsinfer.ENGINE_SERVICE_NAME],
            ],
        )
        install_watchdog.assert_called_once_with(
            identity, replace_active=True, runtime_manifest=None
        )

    def test_core_plane_handoff_uses_the_active_candidate_not_stale_resident(self) -> None:
        identity = mock.Mock(role="coordinator")
        candidate_manifest = {
            "watchdog": {"protection": {"warning_available_bytes": 4 << 30}}
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            resident = root / "service.json"
            candidate = root / "qualification.json"
            resident.write_text("{}\n", encoding="utf-8")
            candidate.write_text("{}\n", encoding="utf-8")

            def configured(config: object) -> tuple[pathlib.Path, dict[str, object]]:
                self.assertEqual(config, {"qualification_mode": True})
                return candidate, candidate_manifest

            with (
                mock.patch.object(letsinfer.platform, "system", return_value="Linux"),
                mock.patch.object(
                    letsinfer, "default_service_config_path", return_value=resident
                ),
                mock.patch.object(
                    letsinfer,
                    "qualification_service_config_path",
                    return_value=candidate,
                ),
                mock.patch.object(
                    letsinfer,
                    "read_service_config",
                    return_value={"qualification_mode": True},
                ),
                mock.patch.object(letsinfer, "configured_release", side_effect=configured),
                mock.patch.object(
                    letsinfer,
                    "_unit_enabled_active",
                    return_value=("enabled", "inactive"),
                ),
                mock.patch.object(letsinfer, "install_site_service_only"),
                mock.patch.object(
                    letsinfer, "install_core_watchdog_service"
                ) as install_watchdog,
                mock.patch.object(letsinfer, "install_core_gateway_service"),
            ):
                state = letsinfer.install_core_plane_services(
                    identity, include_gateway=True
                )

        self.assertTrue(state["qualification_active"])
        install_watchdog.assert_called_once_with(
            identity, replace_active=True, runtime_manifest=candidate_manifest
        )

    def test_parser_exposes_only_the_public_update_command(self) -> None:
        parsed = letsinfer.parser().parse_args(["update", "--version", "1.2.3"])
        self.assertEqual(parsed.action_id, "update")
        help_text = letsinfer.parser().format_help()
        self.assertIn("update", help_text)
        self.assertNotIn("core-rebind", help_text)


if __name__ == "__main__":
    unittest.main()
