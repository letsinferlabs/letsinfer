#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Clean-break CLI integration tests for immutable runtime candidates."""

from __future__ import annotations

import contextlib
import io
import pathlib
import tempfile
import unittest
from unittest import mock

from core import cli
from core.engine_protocol import artifact_storage_slug
from core.runtime_packs import RuntimePackError, candidate_id, validate_runtime_config
from tests.runtime_fixture import runtime_candidate


class RuntimeCandidateCliTests(unittest.TestCase):
    def test_service_commits_runtime_selection_before_engine_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            events: list[str] = []
            config = {
                "name": "letsinfer-example",
                "source_root": str(root),
                "protection_root": str(root / "protection"),
            }
            manifest = {"container": {"startup_timeout_seconds": 30}}
            receipt = {"logical_model": "example-model"}
            completed = mock.Mock(returncode=0, stdout="", stderr="")

            def start(command: list[str]) -> None:
                if command[-1] == cli.ENGINE_SERVICE_NAME:
                    self.assertIn("selection", events)
                events.append(command[-1])

            with (
                mock.patch.object(
                    cli, "_unit_enabled_active", return_value=("disabled", "inactive")
                ),
                mock.patch.object(cli, "selections", return_value=[]),
                mock.patch.object(
                    cli, "write_selection", side_effect=lambda _receipt: events.append("selection")
                ),
                mock.patch.object(cli, "run", return_value=completed),
                mock.patch.object(cli, "run_passthrough", side_effect=start),
                mock.patch.object(
                    cli, "_service_state", return_value=("enabled", "active", 1024)
                ),
                mock.patch.object(cli, "render_engine_service", return_value="unit\n"),
                mock.patch.object(cli, "render_gateway_service", return_value="unit\n"),
                mock.patch.object(cli, "render_user_service", return_value="unit\n"),
                mock.patch.object(cli, "render_site_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_timer", return_value="unit\n"),
            ):
                cli.install_user_service(
                    root / "service.json",
                    config,
                    manifest,
                    no_start=False,
                    runtime_receipt=receipt,
                    unit_dir=root / "units",
                )

            self.assertLess(events.index("selection"), events.index(cli.ENGINE_SERVICE_NAME))

    def test_failed_service_activation_restores_runtime_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            events: list[str] = []
            config = {
                "name": "letsinfer-example",
                "source_root": str(root),
                "protection_root": str(root / "protection"),
            }
            manifest = {"container": {"startup_timeout_seconds": 30}}
            receipt = {"logical_model": "example-model"}
            completed = mock.Mock(returncode=0, stdout="", stderr="")

            def start(command: list[str]) -> None:
                if command[-1] == cli.ENGINE_SERVICE_NAME:
                    raise cli.LetsInferError("synthetic engine failure")

            with (
                mock.patch.object(
                    cli, "_unit_enabled_active", return_value=("disabled", "inactive")
                ),
                mock.patch.object(cli, "selections", return_value=[]),
                mock.patch.object(
                    cli, "write_selection", side_effect=lambda _receipt: events.append("selection")
                ),
                mock.patch.object(
                    cli,
                    "restore_selection",
                    side_effect=lambda _replacement, _previous: events.append("restore"),
                ),
                mock.patch.object(cli, "run", return_value=completed),
                mock.patch.object(cli, "run_passthrough", side_effect=start),
                mock.patch.object(
                    cli, "_service_state", return_value=("enabled", "active", 1024)
                ),
                mock.patch.object(cli, "container_inspect", return_value=None),
                mock.patch.object(cli, "render_engine_service", return_value="unit\n"),
                mock.patch.object(cli, "render_gateway_service", return_value="unit\n"),
                mock.patch.object(cli, "render_user_service", return_value="unit\n"),
                mock.patch.object(cli, "render_site_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_timer", return_value="unit\n"),
                self.assertRaisesRegex(cli.LetsInferError, "previous installation restored"),
            ):
                cli.install_user_service(
                    root / "service.json",
                    config,
                    manifest,
                    no_start=False,
                    runtime_receipt=receipt,
                    unit_dir=root / "units",
                )

            self.assertEqual(events, ["selection", "restore"])

    def test_tls_generation_supports_split_config_and_secret_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            certificate = root / "config" / "tls" / "server.crt"
            private_key = root / "secrets" / "tls" / "server.key"

            def generate(command: list[str], **_: object) -> mock.Mock:
                pathlib.Path(command[command.index("-out") + 1]).write_text(
                    "certificate", encoding="ascii"
                )
                pathlib.Path(command[command.index("-keyout") + 1]).write_text(
                    "private-key", encoding="ascii"
                )
                return mock.Mock(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(cli, "run", side_effect=generate),
                mock.patch.object(cli, "validate_tls_material"),
                mock.patch.object(cli, "_certificate_names", return_value=["localhost"]),
            ):
                cli.ensure_tls_material(certificate, private_key)

            self.assertEqual(certificate.read_text(encoding="ascii"), "certificate")
            self.assertEqual(private_key.read_text(encoding="ascii"), "private-key")
            self.assertEqual(private_key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(certificate.stat().st_mode & 0o777, 0o644)

    def test_watchdog_tls_generation_supports_split_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / "config" / "watchdog"
            secrets = root / "secrets" / "watchdog"
            paths = (
                config / "server.crt",
                secrets / "server.key",
                config / "controller-ca.crt",
                secrets / "controller-ca.key",
                config / "local-controller.crt",
                secrets / "local-controller.key",
            )

            def generate(command: list[str], **_: object) -> mock.Mock:
                for option in ("-out", "-keyout"):
                    if option in command:
                        pathlib.Path(command[command.index(option) + 1]).write_text(
                            option, encoding="ascii"
                        )
                return mock.Mock(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(cli, "run", side_effect=generate),
                mock.patch.object(cli, "validate_watchdog_tls_material"),
                mock.patch.object(cli, "_validate_watchdog_controller_material"),
                mock.patch.object(cli, "_certificate_names", return_value=["localhost"]),
            ):
                cli.ensure_watchdog_tls_material(*paths)

            for path in paths:
                self.assertTrue(path.is_file())
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_first_runtime_can_create_a_qualification_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest_path = root / "runtime.json"
            manifest_path.write_text("{}\n", encoding="ascii")
            runtime = runtime_candidate()
            manifest = cli.runtime_execution_manifest(runtime)
            receipt = {
                "candidate_id": runtime["id"],
                "version": runtime["version"],
                "digest": "5" * 64,
                "policy": "local",
            }
            with (
                mock.patch.object(
                    cli, "default_service_config_path", return_value=root / "missing.json"
                ),
                mock.patch.object(
                    cli,
                    "_qualification_core_plane_config",
                    return_value={"watchdog_data_root": str(root / "watchdog")},
                ),
                mock.patch.object(
                    cli,
                    "install_control_bundle",
                    return_value=(root / "control", manifest_path),
                ),
                mock.patch.object(
                    cli,
                    "resolve_service_placement",
                    return_value={
                        "placement_id": "6" * 32,
                        "placement_strategy": "single",
                        "placement_members": ["7" * 32],
                        "topology_sha256": "8" * 64,
                    },
                ),
            ):
                config = cli._qualification_config(
                    manifest_path=manifest_path,
                    manifest=manifest,
                    release_root=root,
                    manifest_sha256="9" * 64,
                    name="letsinfer-example",
                    port=18000,
                    model_cache=root / "models",
                    store_root=root / "store",
                    runtime_cache_root=root / "cache",
                    api_key_file=root / "engine.key",
                    tls_cert_file=root / "server.crt",
                    tls_key_file=root / "server.key",
                    evidence_dir=root / "evidence",
                    runtime_receipt=receipt,
                )

            self.assertTrue(config["qualification_mode"])
            self.assertEqual(config["runtime_name"], runtime["id"])
            self.assertEqual(
                config["protection_root"],
                str(
                    (root / "watchdog").resolve()
                    / cli.PROTECTION_ROOT_NAME
                    / ("6" * 32)
                ),
            )

    def test_qualification_core_plane_uses_the_managed_engine_key(self) -> None:
        with (
            mock.patch.object(
                cli,
                "verify_active_core_watchdog",
                return_value=(pathlib.Path("/watchdog"), "1" * 64),
            ),
            mock.patch.object(cli, "core_watchdog_source_identity", return_value="2" * 64),
            mock.patch.object(
                cli,
                "ensure_installation_identity",
                return_value={"installation_id": "3" * 64},
            ),
            mock.patch.object(
                cli,
                "default_engine_api_key_path",
                return_value=pathlib.Path("/secrets/engine/api-key"),
            ),
        ):
            config = cli._qualification_core_plane_config()

        self.assertEqual(config["engine_api_key_file"], "/secrets/engine/api-key")

    def test_legacy_commands_are_not_registered(self) -> None:
        parser = cli.parser()
        for command in ("derive", "engines", "releases"):
            with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args([command])

    def test_install_selects_runtime_not_engine(self) -> None:
        arguments = cli.parser().parse_args(
            [
                "install",
                "example-model",
                "--runtime",
                "example-engine--example--model--test-target",
            ]
        )
        self.assertEqual(arguments.model, "example-model")
        self.assertEqual(
            arguments.runtime,
            "example-engine--example--model--test-target",
        )
        self.assertFalse(hasattr(arguments, "engine"))

    def test_engine_identity_is_opaque_to_core(self) -> None:
        runtime = runtime_candidate()
        runtime["engine"]["id"] = "future-engine"
        runtime["id"] = candidate_id(
            "future-engine", runtime["model"]["uri"], runtime["target"]["id"]
        )
        validated = validate_runtime_config(runtime)
        execution = cli.runtime_execution_manifest(validated)
        self.assertEqual(execution["engine"]["name"], "future-engine")
        self.assertEqual(execution["image"]["reference"], runtime["engine"]["oci"]["reference"])

    def test_model_store_mirrors_exact_hugging_face_identity_and_revision(self) -> None:
        execution = cli.runtime_execution_manifest(runtime_candidate())
        artifact = execution["artifacts"][0]
        self.assertEqual(artifact_storage_slug(artifact), "example--model")
        root = pathlib.Path("/letsinfer/models")
        self.assertEqual(
            cli.artifact_snapshot_path(
                {**artifact, "storage_slug": artifact_storage_slug(artifact)}, root
            ),
            root / "example--model" / ("4" * 40),
        )

    def test_runtime_validation_rejects_an_unpinned_model_revision(self) -> None:
        runtime = runtime_candidate()
        runtime["artifacts"][0]["revision"] = "main"
        with self.assertRaisesRegex(RuntimePackError, "full commit SHA"):
            validate_runtime_config(runtime)

    def test_resolve_model_only_considers_installed_runtime_receipts(self) -> None:
        runtime = runtime_candidate()
        execution = cli.runtime_execution_manifest(runtime)
        manifest_path = pathlib.Path("/installed/runtime-execution.json")
        receipt = {
            "candidate_id": runtime["id"],
            "logical_model": runtime["logical_model"],
            "engine": runtime["engine"]["id"],
            "target": runtime["target"]["id"],
            "version": runtime["version"],
            "installed_at": "2026-08-21T00:00:00Z",
        }
        with mock.patch.object(
            cli,
            "installed_runtime_manifests",
            return_value=[(manifest_path, execution, receipt)],
        ):
            selected, selected_manifest = cli.resolve_model("example-model")
        self.assertEqual(selected, manifest_path)
        self.assertIs(selected_manifest, execution)

    def test_unknown_source_tree_is_not_runtime_discovery_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, "release.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(cli, "installed_runtime_manifests", return_value=[]):
                with self.assertRaisesRegex(cli.LetsInferError, "unknown model"):
                    cli.resolve_model(directory)


if __name__ == "__main__":
    unittest.main()
