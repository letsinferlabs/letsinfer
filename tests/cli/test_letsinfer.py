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
