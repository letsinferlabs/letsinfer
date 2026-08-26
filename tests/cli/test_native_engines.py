#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import io
import json
import os
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

from core import cli, engine_distribution, native_engine, native_model_acquisition
from core.runtime_packs import RuntimePackError, validate_runtime_config
from tests.runtime_fixture import runtime_candidate


class EngineDistributionTests(unittest.TestCase):
    def native_archive(self) -> dict[str, object]:
        return {
            "kind": "native-archive",
            "platform": "macos/arm64",
            "payload_id": "sha256:" + "1" * 64,
            "source_revision": "2" * 40,
            "entrypoint": "adapter/engine-adapter",
            "port_count": 2,
            "archive": {
                "url": "https://example.invalid/engine.tar.gz",
                "sha256": "3" * 64,
                "bytes": 1024,
                "format": "tar.gz",
                "strip_prefix": "engine-release",
            },
            "upstream_executable": "bin/engine",
        }

    def test_distribution_variants_are_closed(self) -> None:
        native = self.native_archive()
        self.assertEqual(
            engine_distribution.validate_engine_distribution(
                native, target_platform="macos/arm64"
            ),
            native,
        )
        embedded = {
            "kind": "embedded-application",
            "platform": "ios/arm64",
            "payload_id": "sha256:" + "4" * 64,
            "source_revision": "5" * 40,
            "entrypoint": "engines/mlc",
            "port_count": 1,
            "bundle_id": "ai.letsinfer.ios",
            "signing_policy": "deployment-managed",
            "minimum_version": "1.0.0",
            "embedded_engine": "mlc-metal",
        }
        self.assertEqual(
            engine_distribution.validate_engine_distribution(
                embedded, target_platform="ios/arm64"
            ),
            embedded,
        )
        for changed in (
            {**native, "platform": "linux/arm64"},
            {**native, "unexpected": True},
            {**embedded, "signing_policy": "development"},
        ):
            with self.assertRaises(engine_distribution.EngineDistributionError):
                engine_distribution.validate_engine_distribution(
                    changed, target_platform="macos/arm64"
                )

    def test_runtime_schema_accepts_native_distribution_only_with_native_acquisition(
        self,
    ) -> None:
        runtime = runtime_candidate()
        runtime["target"]["platform"] = "macos/arm64"
        runtime["target"]["accelerator"].update(
            vendor="apple", architecture="apple-silicon"
        )
        runtime["engine"]["distribution"] = self.native_archive()
        runtime["benchmark"]["contract"]["tokenizer"]["engine_image_sha256"] = (
            "1" * 64
        )
        runtime["model"]["acquisition"] = {
            "kind": "huggingface-http",
            "client": "huggingface-http-v1",
        }
        self.assertEqual(validate_runtime_config(runtime), runtime)
        runtime["model"]["acquisition"] = {
            "kind": "oci-container",
            "image": "registry.example/acquire@sha256:" + "3" * 64,
        }
        with self.assertRaisesRegex(RuntimePackError, "native Engines require"):
            validate_runtime_config(runtime)

    def test_native_execution_view_preserves_distribution(self) -> None:
        runtime = runtime_candidate()
        runtime["target"]["platform"] = "macos/arm64"
        runtime["target"]["accelerator"].update(
            vendor="apple", architecture="apple-silicon"
        )
        runtime["engine"]["distribution"] = self.native_archive()
        runtime["benchmark"]["contract"]["tokenizer"]["engine_image_sha256"] = (
            "1" * 64
        )
        runtime["model"]["acquisition"] = {
            "kind": "huggingface-http",
            "client": "huggingface-http-v1",
        }
        manifest = cli.runtime_execution_manifest(runtime, qualified=False)
        self.assertEqual(manifest["image"]["distribution"], "native-archive")
        self.assertEqual(
            manifest["model"]["acquisition"],
            runtime["model"]["acquisition"],
        )

    def test_native_dependency_download_policy_is_explicit(self) -> None:
        runtime = runtime_candidate()
        runtime["target"]["platform"] = "macos/arm64"
        runtime["target"]["accelerator"].update(
            vendor="apple", architecture="apple-silicon"
        )
        runtime["engine"]["distribution"] = self.native_archive()
        runtime["model"]["acquisition"] = {
            "kind": "huggingface-http",
            "client": "huggingface-http-v1",
        }
        runtime["benchmark"]["contract"]["tokenizer"]["engine_image_sha256"] = (
            "1" * 64
        )
        manifest = cli.runtime_execution_manifest(runtime, qualified=False)
        with (
            mock.patch(
                "core.native_engine.verify_staged_native_engine",
                side_effect=native_engine.NativeEngineError("absent"),
            ),
            mock.patch("core.native_engine.stage_native_engine") as stage,
            self.assertRaisesRegex(cli.LetsInferError, "downloads are disabled"),
        ):
            cli.ensure_image(
                manifest,
                build=False,
                pull=False,
                artifact_root=pathlib.Path("/runtime"),
            )
        stage.assert_not_called()


class NativeEngineStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.environment = mock.patch.dict(
            os.environ, {"LETSINFER_HOME": str(self.root / "home")}
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_archive_stage_binds_upstream_and_adapter(self) -> None:
        runtime_root = self.root / "runtime"
        adapter = runtime_root / "adapter" / "engine-adapter"
        adapter.parent.mkdir(parents=True)
        adapter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        adapter.chmod(0o755)
        frontend = adapter.with_name("native_frontend.py")
        frontend.write_text("PROTOCOL = 2\n", encoding="utf-8")
        source_archive = self.root / "source.tar.gz"
        payload = b"#!/bin/sh\nexit 0\n"
        with tarfile.open(source_archive, "w:gz") as archive:
            info = tarfile.TarInfo("engine-release/bin/engine")
            info.mode = 0o755
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        distribution: dict[str, object] = {
            "kind": "native-archive",
            "platform": "macos/arm64",
            "payload_id": "sha256:" + "0" * 64,
            "source_revision": "2" * 40,
            "entrypoint": "adapter/engine-adapter",
            "port_count": 2,
            "archive": {
                "url": "https://example.invalid/engine.tar.gz",
                "sha256": native_engine.sha256_file(source_archive),
                "bytes": source_archive.stat().st_size,
                "format": "tar.gz",
                "strip_prefix": "engine-release",
            },
            "upstream_executable": "bin/engine",
        }
        distribution["payload_id"] = native_engine.calculated_payload_id(
            distribution, runtime_root
        )
        first_payload = distribution["payload_id"]
        frontend.write_text("PROTOCOL = 2\nMODE = 'changed'\n", encoding="utf-8")
        self.assertNotEqual(
            native_engine.calculated_payload_id(distribution, runtime_root),
            first_payload,
        )
        frontend.write_text("PROTOCOL = 2\n", encoding="utf-8")

        def download(_value: object, output: pathlib.Path) -> None:
            output.write_bytes(source_archive.read_bytes())

        with (
            mock.patch.object(native_engine.platform, "system", return_value="Darwin"),
            mock.patch.object(native_engine.platform, "machine", return_value="arm64"),
            mock.patch.object(native_engine, "_download_archive", side_effect=download),
        ):
            staged = native_engine.stage_native_engine(distribution, runtime_root)
        executable = staged / "upstream" / "bin" / "engine"
        self.assertTrue(executable.is_file())
        self.assertTrue(os.access(executable, os.X_OK))
        receipt = json.loads((staged / "receipt.json").read_text())
        self.assertEqual(receipt["distribution"], distribution)
        (staged / "receipt.json").write_text("{}\n", encoding="utf-8")
        with (
            mock.patch.object(native_engine.platform, "system", return_value="Darwin"),
            mock.patch.object(native_engine.platform, "machine", return_value="arm64"),
            mock.patch.object(native_engine, "_download_archive", side_effect=download),
        ):
            repaired = native_engine.stage_native_engine(distribution, runtime_root)
        self.assertEqual(repaired, staged)
        repaired_receipt = json.loads((repaired / "receipt.json").read_text())
        self.assertEqual(repaired_receipt["schema_version"], 3)

    def test_python_stage_uses_a_relocatable_interpreter(self) -> None:
        runtime_root = self.root / "runtime"
        adapter = runtime_root / "adapter" / "engine-adapter"
        adapter.parent.mkdir(parents=True)
        adapter.write_text("print('adapter')\n", encoding="utf-8")
        lock = runtime_root / "engine" / "requirements.lock"
        lock.parent.mkdir()
        lock.write_text("example==1 --hash=sha256:" + "a" * 64 + "\n")
        source_archive = self.root / "python.tar.gz"
        interpreter = b"#!/bin/sh\nprintf '3.11.16\\n'\n"
        with tarfile.open(source_archive, "w:gz") as archive:
            info = tarfile.TarInfo("python/bin/python3")
            info.mode = 0o755
            info.size = len(interpreter)
            archive.addfile(info, io.BytesIO(interpreter))
        distribution: dict[str, object] = {
            "kind": "python-standalone",
            "platform": "macos/arm64",
            "payload_id": "sha256:" + "0" * 64,
            "source_revision": "2" * 40,
            "entrypoint": "adapter/engine-adapter",
            "port_count": 2,
            "python": {
                "implementation": "cpython",
                "version": "3.11.16",
                "archive": {
                    "url": "https://example.invalid/python.tar.gz",
                    "sha256": native_engine.sha256_file(source_archive),
                    "bytes": source_archive.stat().st_size,
                    "format": "tar.gz",
                    "strip_prefix": "python",
                },
            },
            "requirements_lock": "engine/requirements.lock",
        }
        distribution["payload_id"] = native_engine.calculated_payload_id(
            distribution, runtime_root
        )

        def download(_value: object, output: pathlib.Path) -> None:
            output.write_bytes(source_archive.read_bytes())

        with (
            mock.patch.object(native_engine.platform, "system", return_value="Darwin"),
            mock.patch.object(native_engine.platform, "machine", return_value="arm64"),
            mock.patch.object(native_engine, "_download_archive", side_effect=download),
            mock.patch.object(native_engine, "_run"),
        ):
            staged = native_engine.stage_native_engine(distribution, runtime_root)
        command = native_engine.native_launch_command(distribution, runtime_root)
        self.assertEqual(pathlib.Path(command[0]), staged / "python/bin/python3")
        self.assertTrue(pathlib.Path(command[0]).is_file())
        self.assertEqual(
            native_engine.native_launch_environment(distribution, runtime_root)[
                "PYTHONPATH"
            ].split(os.pathsep),
            [str(runtime_root / "adapter"), str(staged / "site-packages")],
        )


class NativeModelAcquisitionTests(unittest.TestCase):
    def test_snapshot_inventory_is_exact_and_filters_one_file(self) -> None:
        response = [
            {"type": "directory", "path": "docs"},
            {
                "type": "file",
                "path": "model.gguf",
                "size": 12,
                "lfs": {"oid": "sha256:" + "a" * 64},
            },
            {"type": "file", "path": "README.md", "size": 3, "lfs": None},
        ]
        with mock.patch.object(
            native_model_acquisition,
            "_read_json",
            return_value=(response, None),
        ):
            records = native_model_acquisition.snapshot_files(
                "Owner/Model", "b" * 40, filename="model.gguf"
            )
        self.assertEqual(
            records,
            ({"path": "model.gguf", "bytes": 12, "sha256": "a" * 64},),
        )

    def test_snapshot_rejects_traversal(self) -> None:
        response = [{"type": "file", "path": "../model.gguf", "size": 1, "lfs": None}]
        with (
            mock.patch.object(
                native_model_acquisition,
                "_read_json",
                return_value=(response, None),
            ),
            self.assertRaises(native_model_acquisition.NativeModelAcquisitionError),
        ):
            native_model_acquisition.snapshot_files("Owner/Model", "b" * 40)


if __name__ == "__main__":
    unittest.main()
