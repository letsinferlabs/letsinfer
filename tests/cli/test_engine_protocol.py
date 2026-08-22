#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import copy
import unittest

from core import cli
from core.engine_protocol import (
    ENGINE_ADAPTER,
    ENGINE_PROTOCOL_VERSION,
    EngineManifestError,
    artifact_container_path,
    launch_for,
    validate_engine_manifest,
)
from tests.runtime_fixture import runtime_candidate


class EngineProtocolTests(unittest.TestCase):
    def manifest(self) -> dict:
        return cli.runtime_execution_manifest(runtime_candidate())

    def test_arbitrary_engine_uses_one_fixed_protocol_entrypoint(self) -> None:
        manifest = self.manifest()
        adapter = validate_engine_manifest(manifest)
        launch = launch_for(manifest, manifest["serving"], 18000)
        self.assertEqual(adapter.name, "example-engine")
        self.assertEqual(launch.command, (ENGINE_ADAPTER, "serve"))
        self.assertEqual(
            dict(launch.environment)["LETSINFER_ENGINE_PROTOCOL"],
            str(ENGINE_PROTOCOL_VERSION),
        )
        self.assertNotIn("example-engine", launch.command)

    def test_model_identity_maps_to_exact_hf_revision_directory(self) -> None:
        manifest = self.manifest()
        self.assertEqual(
            artifact_container_path(manifest, "model"),
            "/models/example--model/" + "4" * 40,
        )

    def test_runtime_cannot_override_protocol_environment(self) -> None:
        runtime = runtime_candidate()
        runtime["engine"]["environment"]["LETSINFER_LISTEN_PORT"] = "1"
        with self.assertRaisesRegex(Exception, "without LETSINFER_"):
            cli.runtime_execution_manifest(runtime)

    def test_unknown_engine_arguments_are_adapter_owned_and_opaque(self) -> None:
        runtime = runtime_candidate()
        runtime["engine"]["arguments"] = [
            "--future-engine-switch",
            "opaque-value",
            "${artifact:model}",
        ]
        manifest = cli.runtime_execution_manifest(runtime)
        self.assertEqual(
            manifest["engine"]["arguments"], runtime["engine"]["arguments"]
        )
        validate_engine_manifest(manifest)

    def test_partial_artifact_interpolation_is_rejected(self) -> None:
        manifest = self.manifest()
        manifest = copy.deepcopy(manifest)
        manifest["engine"]["arguments"] = ["prefix-${artifact:model}"]
        with self.assertRaisesRegex(EngineManifestError, "complete engine argument"):
            validate_engine_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
