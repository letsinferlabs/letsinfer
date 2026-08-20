# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
import pathlib
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import urllib.request
from unittest import mock


from core import cli as letsinfer


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]

FIXTURE_ROOT = letsinfer.source_root() / "tests/fixtures"
TEST_MANIFESTS = FIXTURE_ROOT / "manifests"
RUNTIME_SOURCE_FIXTURE = FIXTURE_ROOT / "runtime-source"
VLLM_MANIFEST_PATH = TEST_MANIFESTS / "vllm.json"
SGLANG_MANIFEST_PATH = TEST_MANIFESTS / "sglang.json"
LLAMA_CPP_MANIFEST_PATH = TEST_MANIFESTS / "llama-cpp.json"
DWARFSTAR_MANIFEST_PATH = TEST_MANIFESTS / "dwarfstar.json"


@contextlib.contextmanager
def materialized_release_sources(manifest: dict):
    """Build the runtime-owned source tree used by fixture verification."""
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        for artifact in manifest.get("source_artifacts", []):
            relative = pathlib.Path(artifact["path"])
            candidates = (
                letsinfer.source_root() / relative,
                RUNTIME_SOURCE_FIXTURE / relative,
            )
            source = next((item for item in candidates if item.is_file()), None)
            if source is None:
                raise AssertionError(f"missing fixture source: {relative}")
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        yield root


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = VLLM_MANIFEST_PATH
        cls.manifest = json.loads(cls.path.read_text(encoding="utf-8"))

    def test_real_manifest_and_pinned_sources_verify(self) -> None:
        letsinfer.validate_manifest(self.manifest)
        with materialized_release_sources(self.manifest) as root:
            letsinfer.verify_release_sources(self.manifest, root)

    def test_watchdog_stream_capacity_is_bounded_by_core(self) -> None:
        old_runtime = copy.deepcopy(self.manifest)
        old_runtime["watchdog"]["max_controllers"] = 2
        letsinfer.validate_manifest(old_runtime)
        too_many = copy.deepcopy(self.manifest)
        too_many["watchdog"]["max_controllers"] = 17
        with self.assertRaisesRegex(letsinfer.LetsInferError, "cannot exceed 16"):
            letsinfer.validate_manifest(too_many)

    def test_every_registered_manifest_and_pinned_source_verifies(self) -> None:
        observed = []
        for path, manifest in letsinfer.manifests(TEST_MANIFESTS):
            letsinfer.validate_manifest(manifest)
            with materialized_release_sources(manifest) as root:
                letsinfer.verify_release_sources(manifest, root)
            observed.append((path.name, manifest["engine"]["name"]))
        self.assertEqual(
            {engine for _, engine in observed},
            {"vllm", "sglang", "llama.cpp", "dwarfstar"},
        )

    def test_manifest_discovery_ignores_hidden_transfer_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            shutil.copy2(VLLM_MANIFEST_PATH, root / VLLM_MANIFEST_PATH.name)
            (root / "._vllm.json").write_bytes(b"\x00\x05transfer metadata")
            found = letsinfer.manifests(root)
        self.assertEqual([path.name for path, _ in found], ["vllm.json"])

    def test_runtime_manifests_do_not_pin_the_core_control_plane(self) -> None:
        required_paths = list((REPOSITORY_ROOT / "core").rglob("*.py"))
        required_paths.extend((REPOSITORY_ROOT / "benchmarks").glob("*.py"))
        required_paths.extend(
            (REPOSITORY_ROOT / "benchmarks/load-plans").glob("*.json")
        )
        required_paths.extend(
            (REPOSITORY_ROOT / "benchmarks/prompts").glob("*.md")
        )
        required = {
            path.relative_to(REPOSITORY_ROOT).as_posix()
            for path in required_paths
        }
        required.update({"bin/letsinfer", "bin/letsinfer-recovery"})
        for path, manifest in letsinfer.manifests(TEST_MANIFESTS):
            shipped = {
                entry["path"] for entry in manifest.get("source_artifacts", [])
            }
            self.assertFalse(
                required & shipped,
                f"{path.name} pins core files: {sorted(required & shipped)}",
            )

    def test_core_has_no_default_model_registry(self) -> None:
        with mock.patch.dict(os.environ, {"LETSINFER_RELEASES_DIR": ""}):
            self.assertEqual(letsinfer.manifests(), [])

    def test_explicit_empty_release_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(letsinfer.LetsInferError, "no release manifests"):
                letsinfer.manifests(pathlib.Path(directory))

    def test_engine_registry_includes_dwarfstar(self) -> None:
        self.assertEqual(
            set(letsinfer.ADAPTERS), {"vllm", "sglang", "llama.cpp", "dwarfstar"}
        )

    def test_watchdog_protocol_identity_is_shared_across_core_and_native(self) -> None:
        self.assertEqual(letsinfer.WATCHDOG_PROTOCOL_VERSION, 3)
        header = (
            REPOSITORY_ROOT / "watchdog/include/watchdog/protobuf.h"
        ).read_text(encoding="utf-8")
        proto = (REPOSITORY_ROOT / "watchdog/proto/watchdog.proto").read_text(
            encoding="utf-8"
        )
        self.assertIn("#define WATCHDOG_PROTOCOL_VERSION 3u", header)
        inference_fields = {
            25: "active_requests",
            26: "queued_requests",
            27: "requests_received",
            28: "requests_admitted",
            29: "requests_completed",
            30: "requests_failed",
            31: "requests_cancelled",
            32: "requests_retried",
            33: "input_tokens",
            34: "output_tokens",
            35: "cached_tokens",
            36: "queue_milliseconds",
            37: "ttft_milliseconds",
            38: "decode_milliseconds",
            39: "exact_token_requests",
            40: "prefix_cache_hits",
            41: "usage_records_dropped",
            42: "usage_write_errors",
        }
        for field_number, proto_name in inference_fields.items():
            self.assertRegex(
                proto,
                rf"(?:uint32|uint64) {proto_name} = {field_number};",
            )
        for _, manifest in letsinfer.manifests(TEST_MANIFESTS):
            self.assertEqual(manifest["watchdog"]["protocol_version"], 3)


    def test_release_identity_is_shared_by_core_and_watchdog(self) -> None:
        self.assertEqual(letsinfer.PRODUCT_VERSION, "0.11.0-rc.18")
        watchdog_main = (
            REPOSITORY_ROOT / "watchdog/src/main_linux.c"
        ).read_text(encoding="utf-8")
        watchdog_build = (
            REPOSITORY_ROOT / "watchdog/CMakeLists.txt"
        ).read_text(encoding="utf-8")
        self.assertIn('#define WATCHDOG_VERSION "0.11.0-rc.18"', watchdog_main)
        self.assertIn("project(letsinfer_watchdog VERSION 0.11.0 LANGUAGES C)", watchdog_build)

    def test_native_tuning_lives_only_in_runtime_owned_engine_fields(self) -> None:
        self.assertNotIn("runtime", self.manifest)
        self.assertIn("--max-model-len", self.manifest["engine"]["arguments"])
        self.assertIn("VLLM_TARGET_DEVICE", self.manifest["engine"]["environment"])

    def test_parallel_structured_engine_recipes_are_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["runtime"] = {"max_model_len": 262144}
        with self.assertRaisesRegex(letsinfer.LetsInferError, "manifest.runtime is unsupported"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(self.manifest)
        changed["serving"]["max_num_seqs"] = 4
        with self.assertRaisesRegex(letsinfer.LetsInferError, "native engine settings"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(self.manifest)
        changed["engine"]["structured_options"] = {"max_num_seqs": 4}
        with self.assertRaisesRegex(letsinfer.LetsInferError, "unsupported fields"):
            letsinfer.validate_manifest(changed)

    def test_stable_requires_registry_image_and_qualified_serving(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["status"] = "stable"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "registry digest"):
            letsinfer.validate_manifest(changed)

    def test_candidate_may_be_registered_before_serving_is_qualified(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["serving"]["qualified"] = False
        changed["serving"]["blocked_by"] = "qualification-pending"
        letsinfer.validate_manifest(changed)

    def test_release_manifest_rejects_prose(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["image"]["note"] = "Internal build commentary must not ship."
        with self.assertRaisesRegex(letsinfer.LetsInferError, "forbidden prose fields"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(self.manifest)
        changed["serving"]["blocked_by"] = "qualification has not run"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "prose or whitespace"):
            letsinfer.validate_manifest(changed)

    def test_release_manifest_schema_is_closed_at_every_owned_boundary(self) -> None:
        cases = (
            ("top", lambda value: value.__setitem__("internal_commentary", "machine-token")),
            ("image", lambda value: value["image"].__setitem__("rationale", "machine-token")),
            ("model", lambda value: value["model"].__setitem__("variant_hint", "machine-token")),
            ("cache", lambda value: value["cache"].__setitem__("tuning_hint", "machine-token")),
            (
                "artifact",
                lambda value: value["source_artifacts"][0].__setitem__(
                    "internal_source", "machine-token"
                ),
            ),
            (
                "watchdog",
                lambda value: value["watchdog"].__setitem__(
                    "deployment_hint", "machine-token"
                ),
            ),
            (
                "gate",
                lambda value: value["serving"]["gate"].__setitem__(
                    "timeline", "machine-token"
                ),
            ),
        )
        for label, mutate in cases:
            changed = copy.deepcopy(self.manifest)
            mutate(changed)
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    letsinfer.LetsInferError, "unsupported fields"
                ):
                    letsinfer.validate_manifest(changed)

    def test_release_manifest_rejects_boolean_schema_and_numeric_fields(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["schema_version"] = True
        with self.assertRaisesRegex(letsinfer.LetsInferError, "schema_version"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(self.manifest)
        changed["container"]["startup_timeout_seconds"] = True
        with self.assertRaisesRegex(letsinfer.LetsInferError, "startup_timeout_seconds"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(self.manifest)
        changed["serving"]["gate"]["bench_block"] = "internal benchmark commentary"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "prose or whitespace"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(self.manifest)
        changed["internal_commentary"] = "do not publish this"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "prose or whitespace"):
            letsinfer.validate_manifest(changed)

    def test_watchdog_protection_thresholds_fail_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["watchdog"]["protection"]["graceful_available_bytes"] = 17 << 30
        with self.assertRaisesRegex(letsinfer.LetsInferError, "warning > graceful"):
            letsinfer.validate_manifest(changed)

    def test_runtime_memory_floor_is_required_without_an_implicit_default(self) -> None:
        changed = copy.deepcopy(self.manifest)
        del changed["container"]["runtime_min_available_gib"]
        with self.assertRaisesRegex(
            letsinfer.LetsInferError,
            "manifest.container.runtime_min_available_gib must be positive",
        ):
            letsinfer.validate_manifest(changed)

        watchdog_main = (
            REPOSITORY_ROOT / "watchdog/src/main_linux.c"
        ).read_text(encoding="utf-8")
        initializer = watchdog_main.split("static const struct option", 1)[0]
        for field in (
            "warning_available_bytes",
            "graceful_available_bytes",
            "emergency_available_bytes",
            "swap_stop_bytes",
            "psi_some_us",
            "psi_full_us",
            "state_failures",
            "containment_grace_ms",
        ):
            self.assertNotIn(f".{field}", initializer)

    def test_watchdog_warning_may_exceed_runtime_admission_floor(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["container"]["runtime_min_available_gib"] = 12
        changed["watchdog"]["protection"]["graceful_available_bytes"] = 10 << 30
        letsinfer.validate_manifest(changed)

        changed["watchdog"]["protection"]["warning_available_bytes"] = 11 << 30
        with self.assertRaisesRegex(letsinfer.LetsInferError, "at least"):
            letsinfer.validate_manifest(changed)

    def stable_manifest(self) -> dict:
        changed = copy.deepcopy(self.manifest)
        changed["status"] = "stable"
        changed["image"]["distribution"] = "registry-digest"
        changed["image"]["reference"] = f"registry.example/letsinfer@sha256:{'b' * 64}"
        commit = "c" * 40
        serving = changed["serving"]
        serving["qualified"] = True
        serving.pop("blocked_by", None)
        common_path = "evidence/serving/common-results.json"
        engine_path = "evidence/serving/engine-results.json"
        common_sha = "d" * 64
        engine_sha = "1" * 64
        changed["source_artifacts"].extend(
            [
                {"path": common_path, "sha256": common_sha},
                {"path": engine_path, "sha256": engine_sha},
            ]
        )
        serving["gate"] = {
            "measured_commit": commit,
            "bench_block": "stable-serving-qualification-v1",
            "evidence_directory": "evidence/serving",
            "results_sha256": engine_sha,
            "common": {
                "contract": "letsinfer-openai-v1-common",
                "measured_commit": commit,
                "evidence_reference": common_path,
                "results_sha256": common_sha,
            },
            "engine": {
                "contract": "vllm-letsinfer-prefix-v1",
                "measured_commit": commit,
                "evidence_reference": engine_path,
                "results_sha256": engine_sha,
            },
        }
        return changed

    def test_stable_requires_common_and_engine_evidence(self) -> None:
        changed = self.stable_manifest()
        del changed["serving"]["gate"]["common"]
        with self.assertRaisesRegex(letsinfer.LetsInferError, "common"):
            letsinfer.validate_manifest(changed)

    def test_stable_evidence_is_portable_source_pinned_and_same_commit(self) -> None:
        changed = self.stable_manifest()
        letsinfer.validate_manifest(changed)
        gate = changed["serving"]["gate"]
        gate["common"]["evidence_reference"] = "/private/results.json"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "contained evidence"):
            letsinfer.validate_manifest(changed)
        changed = self.stable_manifest()
        changed["serving"]["gate"]["engine"]["measured_commit"] = "4" * 40
        with self.assertRaisesRegex(letsinfer.LetsInferError, "commits must match"):
            letsinfer.validate_manifest(changed)

    def test_cache_contract_does_not_create_an_upstream_flag_registry(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["engine"]["arguments"] = ["--max-num-seqs", "2"]
        letsinfer.validate_manifest(changed)
        command = letsinfer.launch_for(changed, changed["serving"], 8000).command
        self.assertEqual(command[command.index("--max-num-seqs") + 1], "2")

    def test_engine_identity_and_model_format_are_fail_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["engine"]["model_format"] = "gguf-file"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "model_format"):
            letsinfer.validate_manifest(changed)

    def test_persistent_cache_declares_output_replay_policy(self) -> None:
        changed = copy.deepcopy(self.manifest)
        del changed["cache"]["replay_output_policy"]
        with self.assertRaisesRegex(letsinfer.LetsInferError, "replay_output_policy"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(self.manifest)
        changed["cache"]["replay_output_policy"] = "engine-specific-hook"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "replay_output_policy"):
            letsinfer.validate_manifest(changed)

    def test_model_acquisition_image_must_be_digest_pinned(self) -> None:
        changed = copy.deepcopy(self.manifest)
        for invalid in (
            "example/acquirer:latest",
            "example/acquirer@sha256:not-a-digest",
        ):
            changed["model"]["acquisition_image"] = invalid
            with self.assertRaisesRegex(letsinfer.LetsInferError, "acquisition_image"):
                letsinfer.validate_manifest(changed)

    def test_target_contract_is_explicit_and_fail_closed(self) -> None:
        self.assertEqual(
            self.manifest["target"],
            {
                "id": "fixture-unified",
                "platform": "linux/arm64",
                "accelerator": {
                    "vendor": "example",
                    "architecture": "accelerator-v1",
                    "count": 1,
                    "partitioning": "full-device",
                },
                "memory": {
                    "topology": "unified",
                    "minimum_total_gib": 118,
                },
                "placement": {
                    "strategy": "single",
                    "member_count": 1,
                    "engine_strategy": "single-node",
                    "interconnect": {
                        "kind": "any",
                        "rdma_required": False,
                        "minimum_speed_mbps": 0,
                        "minimum_mtu": 0,
                    },
                },
            },
        )
        for target, message in (
            (
                {**self.manifest["target"], "id": "Fixture Target"},
                "target.id",
            ),
            (
                {
                    **self.manifest["target"],
                    "accelerator": {
                        **self.manifest["target"]["accelerator"],
                        "count": 0,
                    },
                },
                "accelerator.count",
            ),
            (
                {
                    **self.manifest["target"],
                    "memory": {
                        "topology": "shared",
                        "minimum_total_gib": 118,
                    },
                },
                "memory.topology",
            ),
            (
                {**self.manifest["target"], "unexpected": True},
                "exactly",
            ),
        ):
            with self.subTest(target=target):
                changed = copy.deepcopy(self.manifest)
                changed["target"] = target
                with self.assertRaisesRegex(letsinfer.LetsInferError, message):
                    letsinfer.validate_manifest(changed)

        discrete = copy.deepcopy(self.manifest)
        discrete["target"] = {
            "id": "fixture-discrete",
            "platform": "linux/amd64",
            "accelerator": {
                "vendor": "example",
                "architecture": "accelerator-v2",
                "count": 1,
                "partitioning": "full-device",
                "minimum_memory_gib": 31,
            },
            "memory": {"topology": "discrete", "minimum_total_gib": 32},
            "placement": copy.deepcopy(self.manifest["target"]["placement"]),
        }
        discrete["container"]["min_gpu_free_gib"] = 8
        discrete["container"]["runtime_min_gpu_free_gib"] = 4
        wheel = next(
            artifact
            for artifact in discrete["runtime_plugins"]["artifacts"]
            if artifact["path"].endswith(".whl")
        )
        wheel["path"] = wheel["path"].replace("aarch64", "x86_64")
        letsinfer.validate_manifest(discrete)

        wheel["path"] = wheel["path"].replace("x86_64", "aarch64")
        with self.assertRaisesRegex(letsinfer.LetsInferError, "wheel architecture"):
            letsinfer.validate_manifest(discrete)

    def test_unified_target_rejects_separate_gpu_memory_floors(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["container"]["min_gpu_free_gib"] = 8
        with self.assertRaisesRegex(letsinfer.LetsInferError, "unified-memory"):
            letsinfer.validate_manifest(changed)

    def test_artifact_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "artifact").write_text("wrong", encoding="utf-8")
            with self.assertRaisesRegex(letsinfer.LetsInferError, "mismatch"):
                letsinfer.verify_artifacts(root, [{"path": "artifact", "sha256": "0" * 64}])

    def test_artifact_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            (root / "artifact").symlink_to(target)
            with self.assertRaisesRegex(letsinfer.LetsInferError, "regular in-tree file"):
                letsinfer.verify_artifacts(
                    root,
                    [{"path": "artifact", "sha256": letsinfer.sha256_file(target)}],
                )


class CommandTests(unittest.TestCase):
    def test_active_memory_pressure_threshold_uses_runtime_service_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "service.json"
            path.write_text("{}\n", encoding="utf-8")
            path.chmod(0o600)
            with mock.patch.object(
                letsinfer,
                "read_service_config",
                return_value={"memory_pressure_available_bytes": 12 << 30},
            ):
                self.assertEqual(
                    letsinfer.active_memory_pressure_available_bytes(path),
                    12 << 30,
                )

    def test_active_memory_pressure_threshold_uses_core_without_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "missing.json"
            self.assertEqual(
                letsinfer.active_memory_pressure_available_bytes(path),
                letsinfer.core_watchdog_contract()["protection"][
                    "warning_available_bytes"
                ],
            )

    @classmethod
    def setUpClass(cls) -> None:
        path = VLLM_MANIFEST_PATH
        cls.manifest = json.loads(path.read_text(encoding="utf-8"))

    def test_local_telemetry_control_errors_are_retryable(self) -> None:
        state = mock.Mock()
        state.accept_telemetry.side_effect = letsinfer.ControlError("stale sample")
        with self.assertRaisesRegex(letsinfer.TelemetryError, "stale sample"):
            letsinfer._accept_local_telemetry(state, {"sample": 1}, "1" * 32)

    def test_public_help_hides_internal_service_entry_points(self) -> None:
        root = letsinfer.parser()
        help_text = root.format_help()
        usage = help_text.split("\n\n", 1)[0]
        for command in ("service-start", "service-stop", "gateway", "site-agent"):
            self.assertNotIn(f"    {command} ", help_text)
            self.assertNotIn(command, usage)
        parsed = root.parse_args(["site-agent"])
        self.assertEqual(parsed.action_id, "site-agent")

    def command_text(self) -> str:
        command = letsinfer.docker_command(
            self.manifest,
            name="test",
            manifest_sha256="a" * 64,
            runtime_digest="b" * 64,
            port=8000,
            model_cache=pathlib.Path("/models"),
            plugin_root=pathlib.Path("/plugins"),
            store_root=pathlib.Path("/store"),
            runtime_cache_root=pathlib.Path("/runtime-cache"),
            api_key_file=pathlib.Path("/secrets/api-key"),
            tls_cert_file=pathlib.Path("/secrets/server.crt"),
            tls_key_file=pathlib.Path("/secrets/server.key"),
        )
        return command[-1]

    def engine_manifest(self, engine: str) -> dict:
        paths = {
            "vllm": VLLM_MANIFEST_PATH,
            "sglang": SGLANG_MANIFEST_PATH,
            "llama.cpp": LLAMA_CPP_MANIFEST_PATH,
            "dwarfstar": DWARFSTAR_MANIFEST_PATH,
        }
        return json.loads(paths[engine].read_text(encoding="utf-8"))

    def docker_for(self, manifest: dict) -> list[str]:
        return letsinfer.docker_command(
            manifest,
            name="test",
            manifest_sha256="a" * 64,
            runtime_digest="b" * 64,
            port=8000,
            model_cache=pathlib.Path("/models"),
            plugin_root=pathlib.Path("/plugins"),
            store_root=pathlib.Path("/store"),
            runtime_cache_root=pathlib.Path("/runtime-cache"),
            api_key_file=pathlib.Path("/secrets/api-key"),
            tls_cert_file=pathlib.Path("/secrets/server.crt"),
            tls_key_file=pathlib.Path("/secrets/server.key"),
        )

    def test_container_is_managed_and_systemd_owns_restart(self) -> None:
        command = letsinfer.docker_command(
            self.manifest,
            name="test",
            manifest_sha256="a" * 64,
            runtime_digest="b" * 64,
            port=8123,
            model_cache=pathlib.Path("/models"),
            plugin_root=pathlib.Path("/plugins"),
            store_root=pathlib.Path("/store"),
            runtime_cache_root=pathlib.Path("/runtime-cache"),
            api_key_file=pathlib.Path("/secrets/api-key"),
            tls_cert_file=pathlib.Path("/secrets/server.crt"),
            tls_key_file=pathlib.Path("/secrets/server.key"),
        )
        self.assertEqual(command[command.index("--restart") + 1], "no")
        self.assertIn("io.letsinfer.managed=true", command)
        self.assertIn(f"{letsinfer.MANIFEST_SHA_LABEL}={'a' * 64}", command)
        self.assertIn(f"{letsinfer.RUNTIME_DIGEST_LABEL}={'b' * 64}", command)
        self.assertNotIn("io.letsinfer.profile", " ".join(command))
        self.assertIn("io.letsinfer.port=8123", command)
        for index, value in enumerate(command):
            if value.startswith("io.letsinfer."):
                self.assertGreater(index, 0)
                self.assertEqual(command[index - 1], "--label")
        self.assertIn("io.letsinfer.security=tls-api-key-v1", command)
        self.assertIn("--read-only", command)
        self.assertIn("--user", command)
        self.assertIn("--cap-drop", command)
        self.assertIn("no-new-privileges=true", command)
        self.assertIn("--health-cmd", command)
        self.assertEqual(
            command[command.index("--health-cmd") + 1],
            "bash -c ': >/dev/tcp/127.0.0.1/8123'",
        )
        self.assertIn("/models/hub:/root/.cache/huggingface/hub:ro", command)
        self.assertNotIn("VLLM_API_KEY=", " ".join(command))

    def test_target_cpu_affinity_is_strict_and_emitted(self) -> None:
        manifest = self.engine_manifest("sglang")
        manifest["container"]["cpuset_cpus"] = "5-9,15-19"
        letsinfer.validate_manifest(manifest)
        command = self.docker_for(manifest)
        self.assertEqual(command[command.index("--cpuset-cpus") + 1], "5-9,15-19")

        for invalid in (
            "",
            "05-9",
            "9-5",
            "5-9,8-10",
            "15-19,5-9",
            "5 - 9",
            "0,8192",
        ):
            changed = copy.deepcopy(manifest)
            changed["container"]["cpuset_cpus"] = invalid
            with self.subTest(cpuset=invalid), self.assertRaisesRegex(
                letsinfer.LetsInferError, "cpuset_cpus"
            ):
                letsinfer.validate_manifest(changed)

    def test_existing_container_requires_exact_manifest_and_runtime_identity(self) -> None:
        command = self.docker_for(self.manifest)
        labels = {
            command[index + 1].split("=", 1)[0]: command[index + 1].split("=", 1)[1]
            for index, value in enumerate(command)
            if value == "--label"
        }
        inspection = {
            "Config": {"Labels": labels},
            "Image": self.manifest["image"]["immutable_id"],
        }
        letsinfer.require_matching_container(
            inspection,
            self.manifest,
            8000,
            manifest_sha256="a" * 64,
            runtime_digest="b" * 64,
        )

        labels.pop(letsinfer.MANIFEST_SHA_LABEL)
        with self.assertRaisesRegex(letsinfer.LetsInferError, "manifest-sha256"):
            letsinfer.require_matching_container(
                inspection,
                self.manifest,
                8000,
                manifest_sha256="a" * 64,
                runtime_digest="b" * 64,
            )

        labels[letsinfer.MANIFEST_SHA_LABEL] = "a" * 64
        labels[letsinfer.RUNTIME_DIGEST_LABEL] = "c" * 64
        with self.assertRaisesRegex(letsinfer.LetsInferError, "runtime-digest"):
            letsinfer.require_matching_container(
                inspection,
                self.manifest,
                8000,
                manifest_sha256="a" * 64,
                runtime_digest="b" * 64,
            )

    def test_existing_container_restart_policy_fails_closed(self) -> None:
        letsinfer.require_systemd_restart_authority(
            {"HostConfig": {"RestartPolicy": {"Name": "no"}}}
        )
        with self.assertRaisesRegex(
            letsinfer.LetsInferError, "invalid restart policy"
        ):
            letsinfer.require_systemd_restart_authority(
                {"HostConfig": {"RestartPolicy": {"Name": "always"}}}
            )

    def test_vllm_tls_key_option_occurs_once_with_its_exact_value(self) -> None:
        launch = letsinfer.launch_for(self.manifest, self.manifest["serving"], 8000)
        command = list(launch.command)
        self.assertEqual(command.count("--ssl-keyfile"), 1)
        index = command.index("--ssl-keyfile")
        self.assertEqual(command[index + 1], "/run/secrets/letsinfer-tls.key")

    def test_sglang_adapter_is_isolated_and_uses_secret_at_runtime(self) -> None:
        manifest = self.engine_manifest("sglang")
        letsinfer.validate_manifest(manifest)
        command = self.docker_for(manifest)
        text = command[-1]
        self.assertIn("python3 -m sglang.launch_server", text)
        self.assertIn("--config /tmp/letsinfer-sglang.yaml", text)
        self.assertIn("api-key: %s", text)
        self.assertIn("log-level: warning", text)
        self.assertNotIn("api_key: %s", text)
        self.assertNotIn("--api-key", text)
        self.assertIn("--hicache-storage-backend file", text)
        self.assertIn('"max_size":68719476736', text)
        self.assertIn("--enable-cache-report", text)
        self.assertIn("--moe-runner-backend flashinfer_cutlass", text)
        self.assertNotIn("--kv-transfer-config", text)
        self.assertNotIn("/plugins:ro", command)
        self.assertIn("/store:/root/.cache/letsinfer-prefix-store", command)
        self.assertIn("io.letsinfer.engine=sglang", command)
        adapter = letsinfer.adapter_for(manifest)
        self.assertEqual(adapter.token_count_path, "/v1/messages/count_tokens")
        self.assertEqual(
            adapter.token_count_protocol,
            "sglang-anthropic-count-tokens-v1",
        )

    def test_named_artifact_reference_is_exactly_acquired_and_expanded(self) -> None:
        manifest = self.engine_manifest("sglang")
        manifest["artifacts"].append({
            "name": "draft",
            "format": "huggingface-snapshot",
            "repository": "example/dflash-drafter",
            "revision": "c" * 40,
        })
        manifest["engine"]["arguments"].extend(
            ["--speculative-draft-model-path", "${artifact:draft}"]
        )
        letsinfer.validate_manifest(manifest)

        artifacts = letsinfer.model_artifacts(manifest)
        self.assertEqual([artifact["name"] for artifact in artifacts], ["model", "draft"])
        self.assertEqual(artifacts[1]["repository"], "example/dflash-drafter")
        self.assertEqual(
            artifacts[1]["cache_repository"],
            "models--example--dflash-drafter",
        )

        launch = letsinfer.launch_for(manifest, manifest["serving"], 8000)
        command = list(launch.command)
        index = command.index("--speculative-draft-model-path")
        self.assertEqual(
            command[index + 1],
            "/root/.cache/huggingface/hub/models--example--dflash-drafter/"
            f"snapshots/{'c' * 40}",
        )
        self.assertNotIn("--speculative-draft-model-path", launch.protected_arguments)

        changed = copy.deepcopy(manifest)
        changed["artifacts"][1]["revision"] = "main"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "exact 40-hex"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(manifest)
        changed["engine"]["arguments"][-1] = "${artifact:missing}"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "unknown artifact"):
            letsinfer.validate_manifest(changed)

    def test_named_artifact_contract_fails_closed(self) -> None:
        manifest = self.engine_manifest("sglang")
        draft = {
            "name": "draft",
            "format": "huggingface-snapshot",
            "repository": "example/draft",
            "revision": "c" * 40,
        }

        cases = []
        changed = copy.deepcopy(manifest)
        changed["artifacts"] = []
        cases.append((changed, "non-empty"))
        changed = copy.deepcopy(manifest)
        changed["model"]["artifact"] = "missing"
        cases.append((changed, "put manifest.model.artifact first"))
        changed = copy.deepcopy(manifest)
        changed["artifacts"].append(copy.deepcopy(changed["artifacts"][0]))
        cases.append((changed, "duplicate name"))
        changed = copy.deepcopy(manifest)
        changed["artifacts"][0]["name"] = "Bad/Name"
        changed["model"]["artifact"] = "Bad/Name"
        cases.append((changed, "portable artifact name"))
        changed = copy.deepcopy(manifest)
        changed["artifacts"].extend(
            [
                {**draft, "name": "z-draft"},
                {**draft, "name": "a-draft"},
            ]
        )
        cases.append((changed, "sort remaining artifacts"))
        changed = copy.deepcopy(manifest)
        changed["artifacts"].append(draft)
        changed["engine"]["arguments"].extend(
            ["--future-path", "prefix-${artifact:draft}"]
        )
        cases.append((changed, "complete engine argument token"))

        for changed, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                letsinfer.LetsInferError, message
            ):
                letsinfer.validate_manifest(changed)

        changed = self.engine_manifest("llama.cpp")
        changed["artifacts"][0]["filename"] = "../model.gguf"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "contained .gguf"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(manifest)
        changed["model"]["drafter"] = draft
        with self.assertRaisesRegex(letsinfer.LetsInferError, "unsupported fields"):
            letsinfer.validate_manifest(changed)

        changed = copy.deepcopy(manifest)
        changed["artifacts"][0]["mount_path"] = "machine-token"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "contain exactly"):
            letsinfer.validate_manifest(changed)

    def test_equal_named_artifact_sources_share_one_acquisition(self) -> None:
        manifest = self.engine_manifest("sglang")
        manifest["artifacts"].append(
            {**manifest["artifacts"][0], "name": "replica"}
        )
        letsinfer.validate_manifest(manifest)
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(letsinfer, "run_passthrough") as run,
            mock.patch.object(
                letsinfer,
                "verify_model_snapshot",
                return_value=pathlib.Path(directory) / "snapshot",
            ),
        ):
            letsinfer.acquire_model_snapshot(manifest, pathlib.Path(directory))
        self.assertEqual(run.call_count, 1)

    def test_sglang_letsinfer_cache_is_core_owned_and_exactly_configured(self) -> None:
        manifest = self.engine_manifest("sglang")
        manifest["engine"]["cache_provider"] = "sglang-letsinfer-prefix-v1"
        manifest["cache"] = {
            "provider": "sglang-letsinfer-prefix-v1",
            "persistent": True,
            "replay_output_policy": "restored-repeat-exact",
            "prewarm": True,
            "host_cache_gib": 4,
            "durable_capacity_bytes": 68719476736,
            "resident_capacity_bytes": 0,
            "ttl_seconds": 604800,
            "direct_reads": True,
        }
        letsinfer.validate_manifest(manifest)
        command = self.docker_for(manifest)
        text = command[-1]
        self.assertIn("--hicache-storage-backend dynamic", text)
        self.assertIn("LetsInferHiCacheStorage", text)
        self.assertIn("python3 -m pip install -q --no-index --no-deps", text)
        self.assertIn("/plugins:/plugins:ro", command)
        self.assertIn("/store:/root/.cache/letsinfer-prefix-store", command)
        self.assertTrue(letsinfer.requires_core_cache_plugin(manifest))
        self.assertNotIn("runtime_plugins", manifest)

    def test_sglang_radix_only_lane_has_no_persistent_mount(self) -> None:
        manifest = self.engine_manifest("sglang")
        manifest["engine"]["cache_provider"] = "sglang-radix-v1"
        manifest["cache"] = {
            "provider": "sglang-radix-v1",
            "persistent": False,
            "prewarm": False,
        }
        letsinfer.validate_manifest(manifest)
        command = self.docker_for(manifest)
        text = command[-1]
        self.assertNotIn("--enable-hierarchical-cache", text)
        self.assertNotIn("/plugins:ro", command)
        self.assertNotIn("/store:/root/.cache/letsinfer-prefix-store", command)

    def test_sglang_cache_provider_and_persistence_fail_closed(self) -> None:
        manifest = self.engine_manifest("sglang")
        manifest["engine"]["cache_provider"] = "sglang-letsinfer-prefix-v1"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "cache.provider"):
            letsinfer.validate_manifest(manifest)
        manifest = self.engine_manifest("sglang")
        manifest["cache"]["persistent"] = False
        with self.assertRaisesRegex(letsinfer.LetsInferError, "cache.persistent"):
            letsinfer.validate_manifest(manifest)

    def test_llama_cpp_adapter_requires_exact_gguf_and_file_auth(self) -> None:
        manifest = self.engine_manifest("llama.cpp")
        letsinfer.validate_manifest(manifest)
        command = self.docker_for(manifest)
        text = command[-1]
        self.assertIn("/app/llama-server", text)
        self.assertIn("fixture.gguf", text)
        self.assertIn("--api-key-file /run/secrets/letsinfer-api-key", text)
        self.assertIn("--ssl-key-file /run/secrets/letsinfer-tls.key", text)
        self.assertEqual(text.count("--port"), 1)
        self.assertNotIn("/plugins:ro", command)
        self.assertIn("io.letsinfer.engine=llama.cpp", command)
        launch = letsinfer.launch_for(manifest, manifest["serving"], 8000)
        self.assertTrue(
            {"--model", "-m", "--alias", "-a"}.issubset(
                launch.protected_arguments
            )
        )

    def test_dwarfstar_adapter_uses_paired_models_and_secure_gateway(self) -> None:
        manifest = self.engine_manifest("dwarfstar")
        letsinfer.validate_manifest(manifest)
        command = self.docker_for(manifest)
        text = command[-1]
        self.assertIn("python3 /plugins/dwarfstar_gateway.py", text)
        self.assertIn("--api-key-file /run/secrets/letsinfer-api-key", text)
        self.assertIn("--tls-cert-file /run/secrets/letsinfer-tls.crt", text)
        self.assertIn("/opt/dwarfstar/ds4-server --model", text)
        self.assertIn("--cuda", text)
        self.assertIn("base.gguf", text)
        self.assertIn("drafter.gguf", text)
        self.assertIn("--host 127.0.0.1", text)
        self.assertIn("--port @LETSINFER_BACKEND_PORT@", text)
        self.assertIn("--no-update-check", text)
        self.assertNotIn("profile", text)
        self.assertIn("/plugins:/plugins:ro", command)
        self.assertIn("/store:/root/.cache/letsinfer-prefix-store", command)
        self.assertIn("DS4_SERVER_COALESCE_MAX=6", command)
        self.assertIn("DS4_LETSINFER_CACHE=1", command)
        self.assertIn("DS4_LETSINFER_CACHE_LIB=/plugins/libletsinfer_prefix_capi.so", command)
        self.assertIn("io.letsinfer.engine=dwarfstar", command)

    def test_dwarfstar_pair_is_acquired_as_two_exact_artifacts(self) -> None:
        manifest = self.engine_manifest("dwarfstar")
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(letsinfer, "run_passthrough") as run,
            mock.patch.object(
                letsinfer,
                "verify_model_snapshot",
                return_value=pathlib.Path(directory) / "snapshot",
            ),
        ):
            letsinfer.acquire_model_snapshot(manifest, pathlib.Path(directory))

        self.assertEqual(run.call_count, 2)
        scripts = [call.args[0][-1] for call in run.call_args_list]
        self.assertIn("example/base-model", scripts[0])
        self.assertIn("base.gguf", scripts[0])
        self.assertIn("example/drafter-model", scripts[1])
        self.assertIn("drafter.gguf", scripts[1])

    def test_dwarfstar_manifest_defaults_to_container_runtime_admission_floor(self) -> None:
        manifest = self.engine_manifest("dwarfstar")
        manifest["container"]["runtime_min_available_gib"] = 7
        letsinfer.validate_manifest(manifest)
        command = self.docker_for(manifest)[-1]
        self.assertIn("--mem-floor-gb 7", command)

    def test_dwarfstar_drafter_identity_fails_closed(self) -> None:
        manifest = self.engine_manifest("dwarfstar")
        manifest["artifacts"][1]["revision"] = "latest"
        with self.assertRaisesRegex(letsinfer.LetsInferError, "artifacts\[1\].revision"):
            letsinfer.validate_manifest(manifest)

    def test_dwarfstar_runtime_tuning_is_opaque_to_core(self) -> None:
        manifest = self.engine_manifest("dwarfstar")
        manifest["engine"]["arguments"].extend(
            ["--future-native-option", "runtime-owned"]
        )
        manifest["engine"]["environment"]["DS4_FUTURE_TUNING"] = "enabled"
        letsinfer.validate_manifest(manifest)
        launch = letsinfer.launch_for(manifest, manifest["serving"], 8000)
        self.assertEqual(launch.command[-2:], ("--future-native-option", "runtime-owned"))
        self.assertEqual(dict(launch.environment)["DS4_FUTURE_TUNING"], "enabled")

    def test_dwarfstar_cache_policy_is_runtime_declared(self) -> None:
        manifest = self.engine_manifest("dwarfstar")
        manifest["cache"]["prefix_lookup"] = True
        letsinfer.validate_manifest(manifest)
        environment = dict(
            letsinfer.launch_for(manifest, manifest["serving"], 8000).environment
        )
        self.assertEqual(environment["DS4_LETSINFER_CACHE_PREFIX"], "1")

    def test_dwarfstar_gateway_capacity_is_independent_of_native_scheduler(self) -> None:
        manifest = self.engine_manifest("dwarfstar")
        manifest["serving"]["max_connections"] = 16
        manifest["serving"]["max_active_requests"] = 16
        manifest["engine"]["environment"]["DS4_SERVER_COALESCE_MAX"] = "8"
        letsinfer.validate_manifest(manifest)

        launch = letsinfer.launch_for(manifest, manifest["serving"], 8000)
        environment = dict(launch.environment)
        self.assertEqual(environment["DS4_SERVER_COALESCE_MAX"], "8")
        active_index = launch.command.index("--max-active-requests")
        self.assertEqual(launch.command[active_index + 1], "16")

    def test_dwarfstar_gateway_accepts_declared_core_capacity(self) -> None:
        manifest = self.engine_manifest("dwarfstar")
        manifest["serving"]["max_connections"] = 128
        manifest["serving"]["max_active_requests"] = 128
        manifest["engine"]["environment"]["DS4_SERVER_COALESCE_MAX"] = "128"
        letsinfer.validate_manifest(manifest)

        launch = letsinfer.launch_for(manifest, manifest["serving"], 8000)
        environment = dict(launch.environment)
        self.assertEqual(environment["DS4_SERVER_COALESCE_MAX"], "128")
        connection_index = launch.command.index("--max-connections")
        active_index = launch.command.index("--max-active-requests")
        self.assertEqual(launch.command[connection_index + 1], "128")
        self.assertEqual(launch.command[active_index + 1], "128")

    def test_dwarfstar_requires_portable_target_and_native_bridge(self) -> None:
        manifest = self.engine_manifest("dwarfstar")
        manifest["target"] = {
            "platform": "linux/arm64",
            "memory_model": "unified",
            "gpu_count": 1,
            "gpu_partitioning": "full-device",
        }
        manifest["runtime_plugins"].pop("native_builder")
        manifest["runtime_plugins"]["artifacts"] = [
            manifest["runtime_plugins"]["artifacts"][0]
        ]
        with self.assertRaisesRegex(
            letsinfer.LetsInferError, "id, platform, accelerator, memory, and placement"
        ):
            letsinfer.validate_manifest(manifest)

        manifest = self.engine_manifest("dwarfstar")
        manifest["runtime_plugins"]["artifacts"] = [
            manifest["runtime_plugins"]["artifacts"][0]
        ]
        with self.assertRaisesRegex(
            letsinfer.LetsInferError, "gateway and Let's Infer native cache bridge"
        ):
            letsinfer.validate_manifest(manifest)

    def test_unqualified_serving_is_not_servable_even_as_dry_run(self) -> None:
        manifest = json.loads(SGLANG_MANIFEST_PATH.read_text(encoding="utf-8"))
        stderr = io.StringIO()
        with (
            materialized_release_sources(manifest) as source_root,
            mock.patch.object(
                letsinfer,
                "resolve_model",
                return_value=(SGLANG_MANIFEST_PATH, manifest),
            ),
            mock.patch.object(
                letsinfer, "manifest_source_root", return_value=source_root
            ),
            mock.patch.object(letsinfer, "verify_release_sources"),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(letsinfer.command_action("serve"), None),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            status = letsinfer.main(
                [
                    "serve",
                    "fixture-model",
                    "--engine",
                    "sglang",
                    "--dry-run",
                ]
            )
        self.assertEqual(status, 1)
        self.assertIn("not qualified", stderr.getvalue())

    def test_unqualified_serving_requires_explicit_qualification_evidence(self) -> None:
        serving = copy.deepcopy(self.manifest["serving"])
        serving["qualified"] = False
        serving["blocked_by"] = "qualification-pending"
        with self.assertRaisesRegex(
            letsinfer.LetsInferError, "requires an explicit --evidence-dir"
        ):
            letsinfer.authorize_serving_launch(
                serving,
                qualification_mode=True,
                evidence_dir=None,
            )
        letsinfer.authorize_serving_launch(
            serving,
            qualification_mode=True,
            evidence_dir="/tmp/letsinfer-qualification",
        )

    def test_qualification_serve_inherits_the_installed_internal_engine_port(self) -> None:
        parsed = letsinfer.parser().parse_args(
            [
                "serve",
                "fixture-model",
                "--qualification-mode",
                "--evidence-dir",
                "/tmp/evidence",
            ]
        )
        self.assertIsNone(parsed.port)

    def test_qualification_handoff_quiesces_and_can_restore_resident_units(self) -> None:
        states = {
            letsinfer.RECOVERY_TIMER_NAME: ("enabled", "active"),
            letsinfer.ENGINE_SERVICE_NAME: ("static", "active"),
        }
        commands: list[list[str]] = []

        def unit_state(name: str) -> tuple[str, str]:
            return states[name]

        def command(value: list[str]) -> None:
            commands.append(list(value))
            name = value[-1]
            states[name] = (
                states[name][0],
                "inactive" if "stop" in value else "active",
            )

        with (
            mock.patch.object(letsinfer, "_unit_enabled_active", side_effect=unit_state),
            mock.patch.object(letsinfer, "run_passthrough", side_effect=command),
            mock.patch.object(letsinfer, "_restore_resident_watchdog_projection"),
        ):
            previous = letsinfer._quiesce_resident_runtime_for_qualification()
            letsinfer._restore_resident_runtime_after_qualification(previous)

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

    def test_qualification_handoff_resets_stale_resident_unit_failures(self) -> None:
        states = {
            letsinfer.RECOVERY_TIMER_NAME: ("enabled", "inactive"),
            letsinfer.ENGINE_SERVICE_NAME: ("static", "failed"),
        }
        with (
            mock.patch.object(
                letsinfer, "_unit_enabled_active", side_effect=lambda name: states[name]
            ),
            mock.patch.object(letsinfer, "run_passthrough"),
            mock.patch.object(letsinfer, "run") as run,
        ):
            letsinfer._quiesce_resident_runtime_for_qualification()
        run.assert_called_once_with(
            ["systemctl", "--user", "reset-failed", letsinfer.ENGINE_SERVICE_NAME]
        )

    def test_retiring_failed_candidate_archives_and_clears_only_its_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            state_path = root / "qualification.json"
            state_path.write_text("{}\n", encoding="utf-8")
            protection_root = root / "protection"
            protection_root.mkdir()
            trip = protection_root / letsinfer.PROTECTION_TRIP_NAME
            trip.write_text('{"reason":"candidate-failed"}\n', encoding="utf-8")
            trip.chmod(0o600)
            evidence = root / "evidence"
            config = {
                "qualification_mode": True,
                "qualification_evidence_dir": str(evidence),
                "protection_root": str(protection_root),
                "name": "letsinfer-sglang",
                "engine_api_key_file": str(root / "key"),
            }
            with (
                mock.patch.object(
                    letsinfer, "qualification_service_config_path", return_value=state_path
                ),
                mock.patch.object(letsinfer, "read_service_config", return_value=config),
                mock.patch.object(
                    letsinfer, "configured_release", return_value=(root, {"model": {}})
                ),
                mock.patch.object(letsinfer, "update_service_placement"),
                mock.patch.object(letsinfer, "disarm_protection"),
                mock.patch.object(letsinfer, "container_inspect", return_value=None),
                mock.patch.object(letsinfer, "_restore_resident_watchdog_projection"),
            ):
                letsinfer._retire_qualification_candidate(remove_container=True)

            self.assertFalse(state_path.exists())
            self.assertFalse(trip.exists())
            self.assertEqual(
                (evidence / "retired-protection-trip.json").read_text(encoding="utf-8"),
                '{"reason":"candidate-failed"}\n',
            )

    def test_qualification_activation_atomically_replaces_the_single_slot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "qualification.json"
            config = {"schema_version": letsinfer.SERVICE_CONFIG_VERSION, "value": "rc.5"}
            manifest = {"model": {"alias": "qwen3.8-27b"}}
            with (
                mock.patch.object(
                    letsinfer, "qualification_service_config_path", return_value=path
                ),
                mock.patch.object(
                    letsinfer,
                    "_unit_enabled_active",
                    return_value=("static", "inactive"),
                ),
                mock.patch.object(
                    letsinfer, "_retire_qualification_candidate"
                ) as retire,
                mock.patch.object(letsinfer, "_quiesce_resident_placement") as quiesce,
                mock.patch.object(letsinfer, "write_watchdog_public_state") as watchdog,
                mock.patch.object(letsinfer, "update_service_placement") as placement,
            ):
                self.assertEqual(
                    letsinfer._activate_qualification_candidate(config, manifest), path
                )
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), config)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            retire.assert_called_once_with(remove_container=True)
            quiesce.assert_called_once_with()
            watchdog.assert_called_once_with(config, manifest)
            placement.assert_called_once_with(config, manifest, "starting")

    def test_qualification_activation_refuses_a_live_resident_engine(self) -> None:
        with mock.patch.object(
            letsinfer,
            "_unit_enabled_active",
            return_value=("static", "active"),
        ), self.assertRaisesRegex(
            letsinfer.LetsInferError, "resident engine service to be stopped"
        ):
            letsinfer._activate_qualification_candidate({}, {})

    def test_candidate_stop_preserves_the_slot_and_container(self) -> None:
        config = {
            "qualification_mode": True,
            "name": "letsinfer-sglang",
            "engine_port": 18000,
            "manifest_sha256": "a" * 64,
        }
        manifest = {"container": {}}
        inspection = {"State": {"Running": True}}
        with (
            mock.patch.object(
                letsinfer, "configured_release", return_value=(pathlib.Path("/release"), manifest)
            ),
            mock.patch.object(letsinfer, "container_inspect", return_value=inspection),
            mock.patch.object(letsinfer, "require_matching_container") as matching,
            mock.patch.object(letsinfer, "require_systemd_restart_authority") as authority,
            mock.patch.object(letsinfer, "disarm_protection") as disarm,
            mock.patch.object(letsinfer, "run") as run,
            mock.patch.object(letsinfer, "update_service_placement") as placement,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                letsinfer._qualification_candidate_lifecycle(config, "stop"), 0
            )
        matching.assert_called_once()
        authority.assert_called_once_with(inspection)
        disarm.assert_called_once_with(config, wait_for_ack=False)
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["docker", "update", "--restart", "no", "letsinfer-sglang"],
                ["docker", "stop", "--time", "120", "letsinfer-sglang"],
            ],
        )
        placement.assert_called_once_with(config, manifest, "stopped")

    def test_candidate_recover_clears_trip_and_rearms_exact_container(self) -> None:
        config = {
            "qualification_mode": True,
            "name": "letsinfer-sglang",
            "engine_port": 18000,
            "manifest_sha256": "a" * 64,
            "tls_cert_file": "/tls.crt",
            "engine_api_key_file": "/engine-key",
        }
        manifest = {"container": {"startup_timeout_seconds": 60}}
        stopped = {"State": {"Running": False}}
        running = {"State": {"Running": True}}
        with (
            mock.patch.object(
                letsinfer, "configured_release", return_value=(pathlib.Path("/release"), manifest)
            ),
            mock.patch.object(
                letsinfer, "container_inspect", side_effect=[stopped, running, running]
            ),
            mock.patch.object(letsinfer, "require_matching_container"),
            mock.patch.object(letsinfer, "require_systemd_restart_authority"),
            mock.patch.object(letsinfer, "clear_protection_trip", return_value=True) as clear,
            mock.patch.object(letsinfer, "write_watchdog_public_state"),
            mock.patch.object(letsinfer, "update_service_placement") as placement,
            mock.patch.object(letsinfer.secrets, "token_hex", return_value="b" * 32),
            mock.patch.object(letsinfer, "publish_protection_state") as protection,
            mock.patch.object(letsinfer, "require_memory_reserve"),
            mock.patch.object(letsinfer, "run") as run,
            mock.patch.object(letsinfer, "wait_for_ready"),
            mock.patch.object(letsinfer, "model_identity_ready", return_value=True),
            mock.patch.object(letsinfer, "prewarm"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                letsinfer._qualification_candidate_lifecycle(config, "recover"), 0
            )
        clear.assert_called_once_with(config)
        run.assert_called_once_with(["docker", "start", "letsinfer-sglang"])
        self.assertEqual(
            [call.args[1] for call in protection.call_args_list],
            ["b" * 32, "b" * 32, "b" * 32],
        )
        self.assertEqual(
            [call.args[2] for call in placement.call_args_list],
            ["starting", "running"],
        )

    def test_lifecycle_commands_prefer_the_active_candidate(self) -> None:
        arguments = argparse.Namespace(config=None, model=None)
        candidate_path = mock.Mock()
        candidate_path.is_file.return_value = True
        candidate = {"qualification_mode": True, "model": "qwen3.8-27b"}
        with (
            mock.patch.object(
                letsinfer, "qualification_service_config_path", return_value=candidate_path
            ),
            mock.patch.object(letsinfer, "read_service_config", return_value=candidate),
            mock.patch.object(
                letsinfer, "_qualification_candidate_lifecycle", return_value=0
            ) as lifecycle,
            mock.patch.object(letsinfer, "_engine_group_lifecycle") as group,
        ):
            self.assertEqual(letsinfer.restart_service(arguments), 0)
        lifecycle.assert_called_once_with(candidate, "restart")
        group.assert_not_called()

    def test_stop_with_explicit_name_does_not_stop_resident_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = pathlib.Path(directory) / "service.json"
            config_path.write_text("{}\n", encoding="utf-8")
            config = {
                "name": "installed-engine",
                "engine_api_key_file": "/tmp/key",
            }
            arguments = argparse.Namespace(
                config=str(config_path),
                name="qualification-engine",
                container_only=False,
            )
            with (
                mock.patch.object(letsinfer, "read_service_config", return_value=config),
                mock.patch.object(letsinfer, "run") as run,
                mock.patch.object(letsinfer, "run_passthrough") as run_passthrough,
                mock.patch.object(letsinfer, "disarm_protection") as disarm,
                mock.patch.object(
                    letsinfer, "_stop_managed_container", return_value=0
                ) as stop_container,
            ):
                self.assertEqual(letsinfer.stop(arguments), 0)

        run.assert_not_called()
        run_passthrough.assert_not_called()
        disarm.assert_called_once_with(config)
        stop_container.assert_called_once_with(
            "qualification-engine", letsinfer.expanded_path("/tmp/key")
        )

    def test_stop_without_name_stops_active_resident_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = pathlib.Path(directory) / "service.json"
            config_path.write_text("{}\n", encoding="utf-8")
            config = {"name": "installed-engine"}
            arguments = argparse.Namespace(
                config=str(config_path),
                name=None,
                container_only=False,
            )
            active = mock.Mock(returncode=0)
            with (
                mock.patch.object(letsinfer, "read_service_config", return_value=config),
                mock.patch.object(letsinfer, "run", return_value=active) as run,
                mock.patch.object(letsinfer, "run_passthrough") as run_passthrough,
                mock.patch.object(letsinfer, "_stop_managed_container") as stop_container,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(letsinfer.stop(arguments), 0)

        run.assert_called_once_with(
            ["systemctl", "--user", "is-active", letsinfer.ENGINE_SERVICE_NAME], check=False
        )
        run_passthrough.assert_called_once_with(
            ["systemctl", "--user", "stop", letsinfer.ENGINE_SERVICE_NAME]
        )
        stop_container.assert_not_called()

    def test_acquire_is_a_separate_exact_artifact_command(self) -> None:
        arguments = letsinfer.parser().parse_args(
            ["acquire", "fixture-model", "--engine", "vllm"]
        )
        self.assertIs(arguments.action, letsinfer.acquire)
        self.assertEqual(arguments.engine, "vllm")

    def test_mem_available_is_floor_gib(self) -> None:
        self.assertEqual(
            letsinfer.parse_mem_available_gib("MemTotal: 999 kB\nMemAvailable: 121634816 kB\n"),
            116,
        )

    def test_platform_names_are_canonicalized_without_cross_arch_fallback(self) -> None:
        self.assertEqual(letsinfer.normalize_platform("Linux/aarch64"), "linux/arm64")
        self.assertEqual(letsinfer.normalize_platform("linux/x86_64"), "linux/amd64")

    def test_host_device_fingerprint_uses_stable_target_capabilities(self) -> None:
        queries = {
            "compute_cap": ["12.1"],
            "addressing_mode": ["ATS"],
            "memory.total": ["N/A"],
            "name": ["NVIDIA GB10"],
            "uuid": ["GPU-fixture"],
        }
        with (
            mock.patch.object(letsinfer, "gpu_count", return_value=1),
            mock.patch.object(
                letsinfer, "nvidia_query", side_effect=lambda field, _: queries[field]
            ),
            mock.patch.object(
                letsinfer, "gpu_partitioning_mode", return_value="full-device"
            ),
            mock.patch.object(letsinfer, "host_platform", return_value="linux/arm64"),
            mock.patch.object(
                pathlib.Path,
                "read_text",
                return_value="MemTotal:       125306980 kB\n",
            ),
        ):
            fingerprint = letsinfer.host_device_fingerprint()

        self.assertEqual(fingerprint["platform"], "linux/arm64")
        self.assertEqual(fingerprint["accelerator"]["architecture"], "sm_121")
        self.assertEqual(fingerprint["accelerator"]["count"], 1)
        self.assertEqual(fingerprint["accelerator"]["partitioning"], "full-device")
        self.assertEqual(fingerprint["accelerator"]["uuids"], ["GPU-fixture"])
        self.assertEqual(fingerprint["memory"]["topology"], "unified")
        self.assertEqual(fingerprint["memory"]["total_gib"], 119)

    def test_hardware_reports_catalog_target_resolution(self) -> None:
        fingerprint = {
            "platform": "linux/arm64",
            "accelerator": {
                "vendor": "nvidia",
                "architecture": "sm_121",
                "count": 1,
                "partitioning": "full-device",
            },
            "memory": {"topology": "unified", "total_gib": 119},
        }
        output = io.StringIO()
        with (
            mock.patch.object(letsinfer, "host_device_fingerprint", return_value=fingerprint),
            mock.patch.object(letsinfer, "resolved_catalog_location", return_value="catalog.json"),
            mock.patch.object(letsinfer, "load_catalog", return_value={"targets": {}}),
            mock.patch.object(
                letsinfer, "compatible_catalog_targets", return_value=["fixture-target"]
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                letsinfer.hardware(argparse.Namespace(json=True, catalog=None)), 0
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["detected"], fingerprint)
        self.assertEqual(payload["compatible_targets"], ["fixture-target"])
        self.assertEqual(payload["selected_target"], "fixture-target")

    def test_hardware_fingerprint_hashes_machine_and_physical_gpu_ids(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(letsinfer.platform, "system", return_value="Linux"),
            mock.patch.object(letsinfer, "gpu_count", return_value=2),
            mock.patch.object(
                letsinfer,
                "nvidia_query",
                return_value=["GPU-b", "GPU-a"],
            ),
        ):
            machine_id = pathlib.Path(directory) / "machine-id"
            machine_id.write_text("0123456789abcdef0123456789abcdef\n", encoding="ascii")
            observed = letsinfer.host_hardware_fingerprint_sha256(machine_id)

        expected = hashlib.sha256(
            letsinfer.canonical_bytes(
                {
                    "contract": "letsinfer-hardware-fingerprint-v1",
                    "gpu_uuids": ["GPU-a", "GPU-b"],
                    "machine_id": "0123456789abcdef0123456789abcdef",
                }
            )
        ).hexdigest()
        self.assertEqual(observed, expected)

    def test_gpu_partitioning_is_full_device_or_fails_closed(self) -> None:
        completed = mock.Mock(returncode=0, stdout="0, [N/A]\n1, Disabled\n", stderr="")
        with mock.patch.object(letsinfer, "run", return_value=completed):
            self.assertEqual(letsinfer.gpu_partitioning_mode(2), "full-device")
        completed.stdout = "0, Enabled\n"
        with mock.patch.object(letsinfer, "run", return_value=completed):
            self.assertEqual(letsinfer.gpu_partitioning_mode(1), "mig")
        completed.stdout = "0, Unknown\n"
        with (
            mock.patch.object(letsinfer, "run", return_value=completed),
            self.assertRaisesRegex(letsinfer.LetsInferError, "unknown"),
        ):
            letsinfer.gpu_partitioning_mode(1)

    def test_model_acquisition_uses_its_own_pinned_image(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        acquisition = f"example/acquirer@sha256:{'a' * 64}"
        manifest["model"]["acquisition_image"] = acquisition
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(letsinfer, "run_passthrough") as run,
            mock.patch.object(
                letsinfer,
                "verify_model_snapshot",
                return_value=pathlib.Path(directory) / "snapshot",
            ),
        ):
            letsinfer.acquire_model_snapshot(manifest, pathlib.Path(directory))

        command = run.call_args.args[0]
        self.assertIn(acquisition, command)
        self.assertNotIn(manifest["image"]["base"], command)
        self.assertEqual(command[command.index("--platform") + 1], "linux/arm64")


class InstallTests(unittest.TestCase):
    def test_cli_launcher_resolves_an_install_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            launcher = pathlib.Path(directory) / "letsinfer"
            launcher.symlink_to(letsinfer.source_root() / "bin/letsinfer")
            result = subprocess.run(
                [str(launcher), "--help"],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Let's Infer inference releases", result.stdout)

    def test_install_downloads_dependencies_by_default(self) -> None:
        arguments = letsinfer.parser().parse_args(["install", "model/runtime/target"])
        self.assertTrue(arguments.download_dependencies)

        arguments = letsinfer.parser().parse_args(
            ["install", "model/runtime/target", "--no-download"]
        )
        self.assertFalse(arguments.download_dependencies)

    def test_install_dependency_resolution_reuses_complete_shared_stores(self) -> None:
        manifest = json.loads(DWARFSTAR_MANIFEST_PATH.read_text(encoding="utf-8"))
        model_cache = pathlib.Path("/shared/huggingface")
        runtime_root = pathlib.Path("/shared/letsinfer/runtime")
        with (
            mock.patch.object(letsinfer, "verify_model_snapshot") as verify,
            mock.patch.object(letsinfer, "acquire_model_snapshot") as acquire,
            mock.patch.object(letsinfer, "ensure_image") as image,
        ):
            letsinfer.ensure_install_dependencies(
                manifest,
                model_cache=model_cache,
                runtime_artifact_root=runtime_root,
                download=True,
                build_image=True,
            )

        verify.assert_called_once_with(manifest, model_cache)
        acquire.assert_not_called()
        image.assert_called_once_with(
            manifest,
            build=True,
            pull=True,
            artifact_root=runtime_root,
        )

    def test_install_dependency_resolution_acquires_missing_model(self) -> None:
        manifest = json.loads(DWARFSTAR_MANIFEST_PATH.read_text(encoding="utf-8"))
        model_cache = pathlib.Path("/shared/huggingface")
        with (
            mock.patch.object(
                letsinfer,
                "verify_model_snapshot",
                side_effect=letsinfer.LetsInferError("missing"),
            ),
            mock.patch.object(letsinfer, "acquire_model_snapshot") as acquire,
            mock.patch.object(letsinfer, "ensure_image") as image,
        ):
            letsinfer.ensure_install_dependencies(
                manifest,
                model_cache=model_cache,
                runtime_artifact_root=None,
                download=True,
                build_image=False,
            )

        acquire.assert_called_once_with(manifest, model_cache)
        image.assert_called_once_with(
            manifest,
            build=False,
            pull=True,
            artifact_root=None,
        )

    def test_install_dependency_resolution_fails_closed_without_downloads(self) -> None:
        manifest = json.loads(DWARFSTAR_MANIFEST_PATH.read_text(encoding="utf-8"))
        with (
            mock.patch.object(
                letsinfer,
                "verify_model_snapshot",
                side_effect=letsinfer.LetsInferError("missing"),
            ),
            mock.patch.object(letsinfer, "acquire_model_snapshot") as acquire,
            mock.patch.object(letsinfer, "ensure_image") as image,
            self.assertRaisesRegex(
                letsinfer.LetsInferError, "dependency downloads are disabled"
            ),
        ):
            letsinfer.ensure_install_dependencies(
                manifest,
                model_cache=pathlib.Path("/shared/huggingface"),
                runtime_artifact_root=None,
                download=False,
                build_image=False,
            )

        acquire.assert_not_called()
        image.assert_not_called()

    def test_ready_wait_requires_endpoint_and_docker_health(self) -> None:
        starting = {"State": {"Running": True, "Health": {"Status": "starting"}}}
        healthy = {"State": {"Running": True, "Health": {"Status": "healthy"}}}
        manifest = {"container": {"runtime_min_available_gib": 16}}
        with (
            mock.patch.object(
                letsinfer, "container_inspect", side_effect=[starting, healthy]
            ) as inspect,
            mock.patch.object(letsinfer, "require_memory_reserve"),
            mock.patch.object(letsinfer, "health_ready", return_value=True) as endpoint,
            mock.patch.object(letsinfer.time, "monotonic", return_value=0),
            mock.patch.object(letsinfer.time, "sleep"),
        ):
            letsinfer.wait_for_ready(
                "letsinfer-test", 8000, 30, pathlib.Path("/tmp/server.crt"), manifest
            )

        self.assertEqual(inspect.call_count, 2)
        endpoint.assert_called_once_with(8000, pathlib.Path("/tmp/server.crt"))

    def test_protection_handshake_is_private_and_trip_latched(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "name": "letsinfer-test",
                "watchdog_data_root": directory,
                "protection_root": directory,
            }
            generation = "a" * 32
            letsinfer.publish_protection_state(
                config, generation, "pending", wait_for_ack=False
            )
            state, _, trip = letsinfer.protection_paths(config)
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)
            self.assertIn("phase=pending\n", state.read_text(encoding="utf-8"))

            trip.write_text("{}\n", encoding="utf-8")
            trip.chmod(0o600)
            with self.assertRaisesRegex(letsinfer.LetsInferError, "trip is latched"):
                letsinfer.publish_protection_state(
                    config, generation, "pending", wait_for_ack=False
                )
            self.assertTrue(letsinfer.clear_protection_trip(config))
            self.assertFalse(trip.exists())

    def test_watchdog_status_descriptor_is_private_exact_and_manifest_addressed(self) -> None:
        manifest = json.loads(DWARFSTAR_MANIFEST_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "watchdog_data_root": directory,
                "release": "0.11.0-rc.2",
                "model": manifest["model"]["alias"],
                "engine": manifest["engine"]["name"],
                "runtime_name": "-",
                "runtime_version": "-",
                "installation_id": "b" * 64,
                "manifest_sha256": "a" * 64,
                "engine_port": 18000,
                "gateway_port": 8000,
            }
            path = letsinfer.write_watchdog_public_state(config, manifest)

            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o077, 0)
            self.assertEqual(path.name, f"{'a' * 64}.state")
            text = path.read_text(encoding="utf-8")
            self.assertIn("version=1\n", text)
            self.assertIn("engine=dwarfstar\n", text)
            self.assertIn("runtime_name=-\n", text)
            self.assertIn("manifest_sha256=" + "a" * 64 + "\n", text)
            self.assertIn("installation_id=" + "b" * 64 + "\n", text)
            self.assertIn("max_active_requests=", text)
            self.assertIn("inference_port=8000\n", text)
            active = path.parent / "site.state"
            self.assertEqual(active.read_text(encoding="utf-8"), text)
            self.assertEqual(active.stat().st_mode & 0o777, 0o600)

            config["release"] = "not portable\n"
            with self.assertRaisesRegex(letsinfer.LetsInferError, "not portable"):
                letsinfer.write_watchdog_public_state(config, manifest)

    def test_control_bundle_is_manifest_addressed_exact_and_reusable(self) -> None:
        manifest_path = VLLM_MANIFEST_PATH
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory) / "control"
            root, installed_manifest = letsinfer.install_control_bundle(
                manifest_path,
                manifest,
                control_parent=parent,
                artifact_roots=(letsinfer.source_root(), RUNTIME_SOURCE_FIXTURE),
            )
            digest = letsinfer.sha256_file(manifest_path)
            _records, _core_manifest, core_identity = letsinfer._core_release(
                letsinfer.source_root()
            )
            self.assertEqual(
                root,
                parent / letsinfer._control_bundle_identity(core_identity, digest),
            )
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                installed_manifest,
                root / "releases" / manifest_path.name,
            )
            _, installed = letsinfer.validate_control_bundle(
                root, installed_manifest, digest
            )
            self.assertEqual(installed["release"], manifest["release"])
            reused_root, reused_manifest = letsinfer.install_control_bundle(
                manifest_path,
                manifest,
                control_parent=parent,
                artifact_roots=(letsinfer.source_root(), RUNTIME_SOURCE_FIXTURE),
            )
            self.assertEqual((reused_root, reused_manifest), (root, installed_manifest))

    def test_core_update_rebinds_the_same_runtime_manifest(self) -> None:
        manifest_path = VLLM_MANIFEST_PATH
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            temporary = pathlib.Path(directory)
            updated_core = temporary / "updated-core"
            records, _manifest, _identity = letsinfer._core_release(
                letsinfer.source_root()
            )
            for record in records:
                target = updated_core / record["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(record["content"])
                target.chmod(record["mode"])
            readme = updated_core / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8") + "\nCore-only test revision.\n",
                encoding="utf-8",
            )

            parent = temporary / "control"
            first_root, first_manifest = letsinfer.install_control_bundle(
                manifest_path,
                manifest,
                control_parent=parent,
                artifact_roots=(letsinfer.source_root(), RUNTIME_SOURCE_FIXTURE),
            )
            second_root, second_manifest = letsinfer.install_control_bundle(
                manifest_path,
                manifest,
                control_parent=parent,
                artifact_roots=(letsinfer.source_root(), RUNTIME_SOURCE_FIXTURE),
                core_source_root=updated_core,
            )

            self.assertNotEqual(first_root, second_root)
            self.assertEqual(
                letsinfer.sha256_file(first_manifest),
                letsinfer.sha256_file(second_manifest),
            )
            letsinfer.validate_control_bundle(
                first_root, first_manifest, letsinfer.sha256_file(manifest_path)
            )
            letsinfer.validate_control_bundle(
                second_root, second_manifest, letsinfer.sha256_file(manifest_path)
            )

    def test_config_rebind_uses_artifacts_from_the_previous_bundle(self) -> None:
        source = pathlib.Path("/previous-control")
        manifest_path = source / "releases/release.json"
        rebound_root = pathlib.Path("/current-control")
        rebound_manifest = rebound_root / "releases/release.json"
        config = {
            "source_root": str(source),
            "manifest_path": str(manifest_path),
            "manifest_sha256": "a" * 64,
            "model": "example-model",
            "engine": "vllm",
        }
        manifest = json.loads(VLLM_MANIFEST_PATH.read_text(encoding="utf-8"))
        config["model"] = manifest["model"]["alias"]
        config["engine"] = manifest["engine"]["name"]
        with mock.patch.object(
            letsinfer,
            "validate_control_bundle",
            return_value=(manifest_path, manifest),
        ), mock.patch.object(
            letsinfer, "source_root", return_value=pathlib.Path("/current-core")
        ), mock.patch.object(
            letsinfer,
            "install_control_bundle",
            return_value=(rebound_root, rebound_manifest),
        ) as install:
            rebound = letsinfer.bind_config_to_control_bundle(config)

        install.assert_called_once_with(
            manifest_path,
            manifest,
            artifact_roots=(source, pathlib.Path("/current-core")),
        )
        self.assertEqual(rebound["source_root"], str(rebound_root))
        self.assertEqual(rebound["manifest_path"], str(rebound_manifest))

    def test_rollback_retains_exact_old_bundle_without_accepting_its_schema(self) -> None:
        manifest = json.loads(VLLM_MANIFEST_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root, manifest_path = letsinfer.install_control_bundle(
                VLLM_MANIFEST_PATH,
                manifest,
                control_parent=pathlib.Path(directory) / "control",
                artifact_roots=(letsinfer.source_root(), RUNTIME_SOURCE_FIXTURE),
            )
            config = {
                "source_root": str(root),
                "manifest_path": str(manifest_path),
                "manifest_sha256": letsinfer.sha256_file(manifest_path),
            }
            with mock.patch.object(
                letsinfer,
                "validate_manifest",
                side_effect=letsinfer.LetsInferError("old runtime API"),
            ):
                self.assertTrue(
                    letsinfer.retained_control_bundle_for_rollback(config)
                )
            config["manifest_sha256"] = "0" * 64
            self.assertFalse(letsinfer.retained_control_bundle_for_rollback(config))

    def test_control_bundle_tampering_fails_closed(self) -> None:
        manifest_path = VLLM_MANIFEST_PATH
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root, installed_manifest = letsinfer.install_control_bundle(
                manifest_path,
                manifest,
                control_parent=pathlib.Path(directory) / "control",
                artifact_roots=(letsinfer.source_root(), RUNTIME_SOURCE_FIXTURE),
            )
            core_cli = root / "core/cli.py"
            core_cli.chmod(0o600)
            core_cli.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(letsinfer.LetsInferError, "mismatch"):
                letsinfer.validate_control_bundle(
                    root,
                    installed_manifest,
                    letsinfer.sha256_file(manifest_path),
                )

    def test_runtime_plugin_install_is_exact_and_removes_old_build_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source"
            target = root / "runtime"
            home = root / "home"
            connector = source / "plugins/connector.py"
            connector.parent.mkdir(parents=True)
            connector.write_text("connector\n", encoding="utf-8")
            wheel = root / "store.whl"
            wheel.write_bytes(b"wheel")
            (target / "target/debug").mkdir(parents=True)
            (target / "target/debug/junk").write_text("junk", encoding="utf-8")
            manifest = {
                "engine": {"name": "vllm"},
                "runtime_plugins": {
                    "artifacts": [
                        {
                            "path": "connector.py",
                            "source_path": "plugins/connector.py",
                            "sha256": letsinfer.sha256_file(connector),
                        },
                        {
                            "path": "dist/store.whl",
                            "sha256": letsinfer.sha256_file(wheel),
                        },
                    ]
                }
            }

            with (
                mock.patch.object(pathlib.Path, "home", return_value=home),
                mock.patch.object(letsinfer, "source_root", return_value=source),
            ):
                letsinfer.install_runtime_plugins(
                    manifest, plugin_root=target, wheel_source=wheel
                )

            letsinfer.verify_artifacts(target, manifest["runtime_plugins"]["artifacts"])
            self.assertFalse((target / "target").exists())

    def test_dwarfstar_plugin_install_builds_core_bridge_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source"
            target = root / "runtime"
            target_repacked = root / "runtime-repacked"
            home = root / "home"
            gateway = source / "adapters/dwarfstar/gateway.py"
            gateway.parent.mkdir(parents=True)
            gateway.write_text("gateway\n", encoding="utf-8")
            bridge = root / "libletsinfer_prefix_capi.so"
            bridge.write_bytes(b"bridge")
            manifest = {
                "engine": {"name": "dwarfstar"},
                "runtime_plugins": {
                    "artifacts": [
                        {
                            "path": "dwarfstar_gateway.py",
                            "source_path": "adapters/dwarfstar/gateway.py",
                            "sha256": letsinfer.sha256_file(gateway),
                        },
                        {
                            "path": "libletsinfer_prefix_capi.so",
                            "sha256": letsinfer.sha256_file(bridge),
                        },
                    ]
                },
            }

            with (
                mock.patch.object(pathlib.Path, "home", return_value=home),
                mock.patch.object(letsinfer, "source_root", return_value=source),
                mock.patch.object(
                    letsinfer,
                    "build_runtime_native_artifact",
                    return_value=bridge,
                ) as build,
            ):
                letsinfer.install_runtime_plugins(
                    manifest,
                    plugin_root=target,
                    wheel_source=None,
                )
                letsinfer.install_runtime_plugins(
                    manifest,
                    plugin_root=target_repacked,
                    wheel_source=None,
                )

            build.assert_called_once()
            letsinfer.verify_artifacts(target, manifest["runtime_plugins"]["artifacts"])
            letsinfer.verify_artifacts(
                target_repacked, manifest["runtime_plugins"]["artifacts"]
            )

    def test_engine_launcher_is_oneshot(self) -> None:
        unit = letsinfer.render_engine_service(
            pathlib.Path("/tmp/service.json"),
            1800,
            pathlib.Path("/immutable/control"),
        )
        self.assertIn("Type=oneshot", unit)
        self.assertIn("RemainAfterExit=yes", unit)
        self.assertNotIn("Restart=", unit)
        self.assertIn("After=letsinfer.service", unit)
        self.assertIn("Environment=PYTHONDONTWRITEBYTECODE=1", unit)
        self.assertIn("service-start", unit)
        self.assertIn("service-stop", unit)
        self.assertIn("/immutable/control/bin/letsinfer", unit)

    def test_cli_does_not_write_bytecode_into_its_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            shutil.copytree(
                REPOSITORY_ROOT / "core",
                root / "core",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            (root / "bin").mkdir()
            shutil.copy2(REPOSITORY_ROOT / "bin/letsinfer", root / "bin/letsinfer")
            subprocess.run(
                [str(root / "bin/letsinfer"), "engines"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertFalse(any(root.rglob("__pycache__")))

    def test_watchdog_is_resident_and_memory_bounded(self) -> None:
        config = {
            "watchdog_binary_path": "/immutable/watchdog/letsinfer-watchdog",
            "watchdog_data_root": "/data/watchdog",
            "watchdog_listen": "127.0.0.1",
            "watchdog_port": 9768,
            "watchdog_cert_file": "/secrets/server.crt",
            "watchdog_key_file": "/secrets/server.key",
            "watchdog_controller_ca_file": "/secrets/controller-ca.crt",
            "watchdog_controller_allowlist_file": "/secrets/controllers.allow",
            "watchdog_public_state_file": "/data/watchdog/service-state/manifest.state",
            "gateway_telemetry_file": "/data/watchdog/gateway.state",
        }
        manifest = {
            "watchdog": {
                "memory_high_bytes": letsinfer.CONTROL_PLANE_MEMORY_HIGH_BYTES,
                "memory_max_bytes": letsinfer.CONTROL_PLANE_MEMORY_LIMIT_BYTES,
                "sample_interval_ms": 1000,
                "flush_interval_ms": 10000,
                "max_controllers": 2,
                "protection": {
                    "warning_available_bytes": 16 << 30,
                    "graceful_available_bytes": 12 << 30,
                    "emergency_available_bytes": 8 << 30,
                    "swap_stop_bytes": 1 << 30,
                    "psi_some_us": 150000,
                    "psi_full_us": 50000,
                    "state_failures": 8,
                    "containment_grace_ms": 3000,
                },
            }
        }
        service = letsinfer.render_user_service(config, manifest)
        recovery = letsinfer.render_recovery_service(
            "letsinfer-single-stream", pathlib.Path("/data/watchdog")
        )
        timer = letsinfer.render_recovery_timer()
        self.assertIn("Type=simple", service)
        self.assertIn("Restart=always", service)
        self.assertIn("MemoryMax=31457280", service)
        self.assertIn("letsinfer-watchdog", service)
        self.assertIn(f"Wants={letsinfer.SITE_SERVICE_NAME}\n", service)
        self.assertNotIn(f"Wants={letsinfer.ENGINE_SERVICE_NAME}", service)
        self.assertNotIn(f"Wants={letsinfer.GATEWAY_SERVICE_NAME}", service)
        self.assertIn('--controller-ca "/secrets/controller-ca.crt"', service)
        self.assertIn("--max-controllers 16", service)
        self.assertIn('--gateway-metrics "/data/watchdog/gateway.state"', service)
        self.assertIn("--protect-root", service)
        self.assertIn("/data/watchdog/protected-engines", service)
        self.assertIn("--warning-bytes 17179869184", service)
        self.assertNotIn("After=letsinfer-engine.service", service)
        self.assertIn("Type=oneshot", recovery)
        self.assertIn("/data/watchdog/protection-trip.json", recovery)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertNotIn("PrivateTmp=", service)
        self.assertNotIn("ProtectSystem=", service)
        self.assertNotIn("ProtectHome=", service)
        self.assertNotIn("ReadWritePaths=", service)
        self.assertIn("OnActiveSec=1min", timer)
        self.assertIn("OnUnitActiveSec=1min", timer)
        self.assertNotIn("OnBootSec=", timer)
        self.assertIn("Persistent=true", timer)

    def test_site_agent_is_separate_persistent_and_memory_bounded(self) -> None:
        unit = letsinfer.render_site_service(pathlib.Path("/immutable/control"))
        self.assertIn("Description=Let's Infer private site agent", unit)
        self.assertIn("Type=simple", unit)
        self.assertIn("Restart=always", unit)
        self.assertIn(f"MemoryHigh={letsinfer.SITE_AGENT_MEMORY_HIGH_BYTES}", unit)
        self.assertIn(f"MemoryMax={letsinfer.SITE_AGENT_MEMORY_LIMIT_BYTES}", unit)
        self.assertIn("MemorySwapMax=0", unit)
        self.assertIn(f"TasksMax={letsinfer.SITE_AGENT_TASK_LIMIT}", unit)
        self.assertIn("site-agent --listen 0.0.0.0 --port 9770", unit)
        self.assertIn("/immutable/control/bin/letsinfer", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("WantedBy=default.target", unit)

    def test_site_link_monitor_renews_configured_directional_proofs(self) -> None:
        left_id, right_id = "1" * 32, "2" * 32
        left_certificate, right_certificate = "a" * 64, "b" * 64

        def member(
            member_id: str,
            address: str,
            certificate: str,
            peer_id: str,
            peer_certificate: str,
            interface: str,
        ) -> dict:
            return {
                "member_id": member_id,
                "address": address,
                "certificate_sha256": certificate,
                "state": "active",
                "facts": {
                    "network": {
                        "links": [
                            {
                                "peer_member_id": peer_id,
                                "peer_certificate_sha256": peer_certificate,
                                "interface": interface,
                                "kind": "connectx",
                            }
                        ]
                    }
                },
            }

        rows = [
            member(
                left_id,
                "192.0.2.10",
                left_certificate,
                right_id,
                right_certificate,
                "enp1s0",
            ),
            member(
                right_id,
                "192.0.2.11",
                right_certificate,
                left_id,
                left_certificate,
                "enp2s0",
            ),
        ]
        store = mock.MagicMock()
        store.members.return_value = rows
        context = mock.MagicMock()
        context.__enter__.return_value = store
        with (
            mock.patch.object(
                letsinfer,
                "read_site_identity",
                return_value=types.SimpleNamespace(role="coordinator"),
            ),
            mock.patch.object(letsinfer, "_site_store", return_value=context),
            mock.patch.object(letsinfer, "request_member_link_probe") as probe,
        ):
            result = letsinfer._refresh_site_links_once()
        self.assertEqual(
            result,
            {
                "refreshed": [f"{left_id}->{right_id}", f"{right_id}->{left_id}"],
                "failed": [],
            },
        )
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(probe.call_args_list[0].kwargs["interface"], "enp1s0")
        self.assertEqual(probe.call_args_list[1].kwargs["interface"], "enp2s0")

    def test_api_key_is_private_and_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "config/api-key"
            letsinfer.ensure_api_key(path)
            first = path.read_text(encoding="ascii")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            letsinfer.ensure_api_key(path)
            self.assertEqual(path.read_text(encoding="ascii"), first)
            letsinfer.ensure_api_key(path, rotate=True)
            self.assertNotEqual(path.read_text(encoding="ascii"), first)

    def test_evidence_log_redaction_removes_every_known_secret(self) -> None:
        value = letsinfer.redact_secrets(
            "before alpha between beta after", ("alpha", "beta")
        )
        self.assertEqual(
            value, "before [REDACTED] between [REDACTED] after"
        )

    def test_tls_material_is_generated_and_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            cert = root / "tls/server.crt"
            key = root / "tls/server.key"
            letsinfer.ensure_tls_material(cert, key)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(cert.stat().st_mode & 0o777, 0o644)
            letsinfer.validate_tls_material(cert, key)

    def test_runtime_mount_targets_are_private_and_user_owned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "runtime-home"
            letsinfer.ensure_runtime_home(root)
            for relative in (
                ".",
                ".cache",
                ".cache/huggingface",
                ".cache/huggingface/hub",
                ".cache/letsinfer-prefix-store",
            ):
                path = root / relative
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_restart_reactivates_recovery_timer(self) -> None:
        enabled = mock.Mock(returncode=0, stdout="static\n")
        arguments = mock.Mock(config="/tmp/letsinfer-service.json")
        with (
            mock.patch.object(letsinfer, "read_service_config"),
            mock.patch.object(letsinfer, "protection_trip_latched", return_value=False),
            mock.patch.object(letsinfer, "clear_protection_trip") as clear,
            mock.patch.object(letsinfer, "run", return_value=enabled) as run,
            mock.patch.object(letsinfer, "run_passthrough") as restart,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(letsinfer.restart_service(arguments), 0)

        restart.assert_called_once_with(
            ["systemctl", "--user", "restart", letsinfer.ENGINE_SERVICE_NAME]
        )
        run.assert_any_call(
            ["systemctl", "--user", "restart", letsinfer.RECOVERY_TIMER_NAME]
        )
        clear.assert_not_called()

    def test_recover_explicitly_acknowledges_trip_before_restart(self) -> None:
        enabled = mock.Mock(returncode=0, stdout="static\n")
        arguments = mock.Mock(config="/tmp/letsinfer-service.json")
        with (
            mock.patch.object(letsinfer, "read_service_config"),
            mock.patch.object(
                letsinfer, "clear_protection_trip", return_value=True
            ) as clear,
            mock.patch.object(letsinfer, "run", return_value=enabled),
            mock.patch.object(letsinfer, "run_passthrough") as restart,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(letsinfer.recover_service(arguments), 0)
        clear.assert_called_once()
        restart.assert_called_once_with(
            ["systemctl", "--user", "restart", letsinfer.ENGINE_SERVICE_NAME]
        )

    def test_install_fails_before_mutation_without_boot_lingering(self) -> None:
        manifest = {
            "serving": {"qualified": True},
        }
        arguments = mock.Mock(
            model="model", engine="vllm", no_service=False
        )
        with (
            mock.patch.object(letsinfer, "_runtime_source_for_install", return_value=None),
            mock.patch.object(
                letsinfer, "resolve_model", return_value=(pathlib.Path("release.json"), manifest)
            ),
            mock.patch.object(letsinfer, "verify_release_sources"),
            mock.patch.object(letsinfer, "user_lingering_enabled", return_value=False),
            self.assertRaisesRegex(letsinfer.LetsInferError, "enable-linger"),
        ):
            letsinfer.install(arguments)

    def test_status_reports_auth_and_model_identity_independently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = pathlib.Path(directory) / "service.json"
            config_path.write_text("{}", encoding="utf-8")
            arguments = mock.Mock()
            arguments.config = str(config_path)
            arguments.name = None
            arguments.json = True
            config = {
                "name": "letsinfer-test",
                "engine_port": 18000,
                "gateway_port": 8000,
                "tls_cert_file": "/tmp/server.crt",
                "engine_api_key_file": "/tmp/engine-api-key",
                "gateway_api_key_file": "/tmp/gateway-api-key",
            }
            inspection = {
                "State": {"Status": "running", "Health": {"Status": "healthy"}},
                "Config": {
                    "Labels": {
                        letsinfer.MANAGED_LABEL: "true",
                        letsinfer.PORT_LABEL: "18000",
                    }
                },
                "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
            }
            with (
                mock.patch.object(letsinfer, "read_service_config", return_value=config),
                mock.patch.object(
                    letsinfer, "_service_state", return_value=("enabled", "active", 1)
                ),
                mock.patch.object(letsinfer, "container_inspect", return_value=inspection),
                mock.patch.object(letsinfer, "health_ready", return_value=True),
                mock.patch.object(
                    letsinfer, "inference_auth_status", side_effect=[401, 400]
                ),
                mock.patch.object(
                    letsinfer, "api_status", side_effect=[200, 401, 200]
                ),
                mock.patch.object(
                    letsinfer,
                    "configured_release",
                    return_value=(
                        pathlib.Path("x"),
                        {
                            "serving": {
                                "max_connections": 8,
                                "max_active_requests": 1,
                                "max_context_tokens": 262144,
                            }
                        },
                    ),
                ),
                mock.patch.object(letsinfer, "model_identity_ready", return_value=True),
                mock.patch.object(
                    letsinfer,
                    "protection_status",
                    return_value={"armed": True, "phase": "armed", "trip_latched": False},
                ),
                mock.patch.object(
                    letsinfer, "_unit_enabled_active", return_value=("enabled", "active")
                ),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(letsinfer.status(arguments), 0)
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["container"]["api_key_required"])
            self.assertTrue(payload["container"]["model_identity"])
            self.assertTrue(payload["service"]["gateway_health"])
            self.assertTrue(payload["service"]["gateway_authenticated"])
            self.assertEqual(payload["lifecycle"]["state"], "ready")

    def test_status_keeps_a_reachable_api_visible_when_runtime_metadata_is_incompatible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = pathlib.Path(directory) / "service.json"
            config_path.write_text("{}", encoding="utf-8")
            arguments = argparse.Namespace(
                config=str(config_path), name=None, model=None, json=True
            )
            config = {
                "name": "letsinfer-test",
                "model": "qwen3.8-27b",
                "engine_port": 18000,
                "gateway_port": 8000,
                "tls_cert_file": "/tmp/server.crt",
                "engine_api_key_file": "/tmp/engine-api-key",
                "gateway_api_key_file": "/tmp/gateway-api-key",
            }
            inspection = {
                "State": {"Status": "running", "Health": {"Status": "healthy"}},
                "Config": {
                    "Labels": {
                        letsinfer.MANAGED_LABEL: "true",
                        letsinfer.PORT_LABEL: "18000",
                    }
                },
                "HostConfig": {"RestartPolicy": {"Name": "no"}},
            }
            with (
                mock.patch.object(letsinfer, "read_service_config", return_value=config),
                mock.patch.object(
                    letsinfer,
                    "configured_release",
                    side_effect=letsinfer.LetsInferError("runtime API is incompatible"),
                ),
                mock.patch.object(
                    letsinfer, "_service_state", return_value=("enabled", "active", 1)
                ),
                mock.patch.object(letsinfer, "container_inspect", return_value=inspection),
                mock.patch.object(letsinfer, "health_ready", return_value=True),
                mock.patch.object(
                    letsinfer, "inference_auth_status", side_effect=[401, 400]
                ),
                mock.patch.object(
                    letsinfer, "api_status", side_effect=[200, 401, 200]
                ),
                mock.patch.object(letsinfer, "model_alias_ready", return_value=True),
                mock.patch.object(
                    letsinfer,
                    "protection_status",
                    return_value={"armed": True, "phase": "armed", "trip_latched": False},
                ),
                mock.patch.object(
                    letsinfer, "_unit_enabled_active", return_value=("enabled", "active")
                ),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(letsinfer.status(arguments), 1)
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["container"]["model_identity"])
            self.assertTrue(payload["service"]["gateway_authenticated"])
            self.assertTrue(payload["service"]["gateway_model_identity"])
            self.assertFalse(payload["service"]["runtime_metadata_ready"])
            self.assertEqual(
                payload["lifecycle"]["reason"], "runtime-metadata-incompatible"
            )

    def test_status_prefers_live_qualification_candidate_over_stale_boot_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            candidate_path = root / "qualification.json"
            candidate_path.write_text("{}\n", encoding="utf-8")
            candidate = {
                "name": "letsinfer-benchmark",
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "release": "qwen3.8-27b-sglang-0.1.0-rc.5",
                "runtime_version": "0.1.0-rc.5",
                "qualification_mode": True,
                "engine_port": 18000,
                "gateway_port": 8000,
                "tls_cert_file": "/tmp/server.crt",
                "engine_api_key_file": "/tmp/engine-api-key",
                "gateway_api_key_file": "/tmp/gateway-api-key",
            }
            manifest = {
                "serving": {
                    "max_connections": 128,
                    "max_active_requests": 8,
                    "max_context_tokens": 262144,
                }
            }
            inspection = {
                "State": {"Status": "running", "Health": {"Status": "healthy"}},
                "Config": {
                    "Labels": {
                        letsinfer.MANAGED_LABEL: "true",
                        letsinfer.PORT_LABEL: "18000",
                        letsinfer.RELEASE_LABEL: candidate["release"],
                        letsinfer.MODEL_LABEL: "qwen3.8-27b",
                        letsinfer.ENGINE_LABEL: "sglang",
                        letsinfer.TARGET_ID_LABEL: "dgx-spark",
                    }
                },
                "HostConfig": {"RestartPolicy": {"Name": "no"}},
            }

            def service_state(name: str = letsinfer.SERVICE_NAME) -> tuple[str, str, int]:
                state = "inactive" if name == letsinfer.ENGINE_SERVICE_NAME else "active"
                return "enabled", state, 19 * 1024 * 1024

            arguments = argparse.Namespace(
                config=None, name=None, model=None, json=True
            )
            with (
                mock.patch.object(
                    letsinfer, "active_service_config_path", return_value=candidate_path
                ) as active_path,
                mock.patch.object(
                    letsinfer, "site_identity_path", return_value=root / "missing-site.json"
                ),
                mock.patch.object(letsinfer, "read_service_config", return_value=candidate),
                mock.patch.object(
                    letsinfer,
                    "configured_release",
                    return_value=(pathlib.Path("candidate.json"), manifest),
                ),
                mock.patch.object(letsinfer, "_service_state", side_effect=service_state),
                mock.patch.object(letsinfer, "container_inspect", return_value=inspection),
                mock.patch.object(letsinfer, "health_ready", return_value=True),
                mock.patch.object(
                    letsinfer, "inference_auth_status", side_effect=[401, 400]
                ),
                mock.patch.object(
                    letsinfer, "api_status", side_effect=[200, 401, 200]
                ),
                mock.patch.object(letsinfer, "model_identity_ready", return_value=True),
                mock.patch.object(
                    letsinfer,
                    "protection_status",
                    return_value={
                        "armed": True,
                        "phase": "armed",
                        "trip_latched": False,
                    },
                ),
                mock.patch.object(
                    letsinfer,
                    "_unit_enabled_active",
                    return_value=("disabled", "inactive"),
                ),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(letsinfer.status(arguments), 0)

            active_path.assert_called_once_with()
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["service"]["runtime_mode"], "qualification")
            self.assertEqual(payload["lifecycle"]["state"], "ready")
            self.assertEqual(payload["lifecycle"]["ready_services"], 3)
            self.assertEqual(payload["lifecycle"]["total_services"], 3)
            self.assertEqual(payload["container"]["runtime_version"], "0.1.0-rc.5")
            self.assertEqual(payload["container"]["capacity"]["max_context_tokens"], 262144)
            self.assertEqual(payload["container"]["capacity"]["max_active_requests"], 8)
            self.assertTrue(payload["service"]["gateway_model_identity"])

    def test_model_identity_uses_the_public_alias_not_upstream_repository(self) -> None:
        manifest = {
            "model": {
                "alias": "qwen3.8-27b",
                "id": "RadixArk/Qwen3.8-27B-NVFP4",
            }
        }
        with mock.patch.object(
            letsinfer,
            "api_json",
            return_value=(200, {"data": [{"id": "qwen3.8-27b"}]}),
        ):
            self.assertTrue(
                letsinfer.model_identity_ready(
                    manifest,
                    18000,
                    pathlib.Path("server.crt"),
                    pathlib.Path("api-key"),
                )
            )

    def test_status_reports_a_ready_site_before_runtime_installation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            identity_path = root / "site.json"
            identity_path.write_text("{}\n", encoding="utf-8")
            identity = types.SimpleNamespace(
                role="coordinator",
                member_id="homeai",
            )
            arguments = argparse.Namespace(
                model=None, name=None, config=None, json=True
            )
            with (
                mock.patch.object(
                    letsinfer, "site_identity_path", return_value=identity_path
                ),
                mock.patch.object(
                    letsinfer, "default_service_config_path", return_value=root / "runtime.json"
                ),
                mock.patch.object(letsinfer, "read_site_identity", return_value=identity),
                mock.patch.object(letsinfer, "_engine_group_status", return_value=[]),
                mock.patch.object(
                    letsinfer,
                    "identity_json",
                    return_value={
                        "display_name": "Home",
                        "role": "coordinator",
                        "member_id": "homeai",
                    },
                ),
                mock.patch.object(
                    letsinfer,
                    "_service_state",
                    side_effect=[
                        ("enabled", "active", 1),
                        ("enabled", "active", 2),
                    ],
                ),
                mock.patch.object(letsinfer, "site_config_root", return_value=root),
                mock.patch.object(letsinfer, "api_status", side_effect=[200, 401, 200]),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(letsinfer.status(arguments), 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["runtime"], None)
            self.assertEqual(payload["identity"]["role"], "coordinator")
            self.assertTrue(payload["services"]["gateway_authenticated"])

    def test_service_configuration_resolves_exact_release(self) -> None:
        manifest = {
            "release": "model-engine-r1",
            "model": {"alias": "model"},
            "engine": {"name": "sglang"},
            "watchdog": {
                "protection": {"warning_available_bytes": 12 << 30}
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = pathlib.Path(directory) / "release.json"
            manifest_path.write_text("exact manifest\n", encoding="utf-8")
            config = {
                "release": "model-engine-r1",
                "model": "model",
                "engine": "sglang",
                "manifest_sha256": letsinfer.sha256_file(manifest_path),
                "source_root": directory,
                "manifest_path": str(manifest_path),
                "memory_pressure_available_bytes": 12 << 30,
            }
            with mock.patch.object(
                letsinfer,
                "validate_control_bundle",
                return_value=(manifest_path, manifest),
            ) as validate:
                _, resolved = letsinfer.configured_release(config)

            self.assertIs(resolved, manifest)
            validate.assert_called_once_with(
                pathlib.Path(directory),
                manifest_path,
                config["manifest_sha256"],
            )

            config["manifest_sha256"] = "0" * 64
            with (
                mock.patch.object(
                    letsinfer,
                    "validate_control_bundle",
                    side_effect=letsinfer.LetsInferError("manifest hash mismatch"),
                ),
                self.assertRaisesRegex(letsinfer.LetsInferError, "manifest hash"),
            ):
                letsinfer.configured_release(config)

            config["manifest_sha256"] = letsinfer.sha256_file(manifest_path)
            config["model"] = "different-alias"
            with (
                mock.patch.object(
                    letsinfer,
                    "validate_control_bundle",
                    return_value=(manifest_path, manifest),
                ),
                self.assertRaisesRegex(letsinfer.LetsInferError, "alias"),
            ):
                letsinfer.configured_release(config)

            config["model"] = "model"
            config["memory_pressure_available_bytes"] = 16 << 30
            with (
                mock.patch.object(
                    letsinfer,
                    "validate_control_bundle",
                    return_value=(manifest_path, manifest),
                ),
                self.assertRaisesRegex(
                    letsinfer.LetsInferError, "memory-pressure threshold"
                ),
            ):
                letsinfer.configured_release(config)

    def test_service_start_uses_configured_runtime_object_without_selections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config_path = root / "service.json"
            config_path.write_text("{}\n", encoding="utf-8")
            digest = "a" * 64
            runtime_root = root / "objects" / digest
            manifest = {
                "model": {"alias": "model"},
                "engine": {"name": "dwarfstar"},
            }
            config = {
                "engine": "dwarfstar",
                "model": "model",
                "release": "model-dwarfstar-r1",
                "engine_port": 18000,
                "name": "letsinfer-dwarfstar",
                "model_cache": "/model-cache",
                "plugin_root": "/plugins",
                "store_root": "/store",
                "runtime_cache_root": "/runtime-cache",
                "engine_api_key_file": "/api-key",
                "tls_cert_file": "/server.crt",
                "tls_key_file": "/server.key",
                "runtime_name": "model/dwarfstar/target",
                "runtime_version": "0.1.0",
                "runtime_digest": digest,
                "source_root": str(root),
            }
            pack = types.SimpleNamespace(
                digest=digest,
                descriptor={
                    "name": config["runtime_name"],
                    "version": config["runtime_version"],
                    "model": "model",
                    "engine": "dwarfstar",
                    "target": "target",
                },
            )
            adapter = types.SimpleNamespace(name="dwarfstar")
            with (
                mock.patch.object(letsinfer, "read_service_config", return_value=config),
                mock.patch.object(letsinfer, "source_root", return_value=root),
                mock.patch.object(
                    letsinfer,
                    "configured_release",
                    return_value=(root / "release.json", manifest),
                ),
                mock.patch.object(letsinfer, "default_runtime_home", return_value=root),
                mock.patch.object(letsinfer, "verify_descriptor", return_value=pack) as verify,
                mock.patch.object(letsinfer, "adapter_for", return_value=adapter),
                mock.patch.object(letsinfer, "target_contract", return_value={"id": "target"}),
                mock.patch.object(letsinfer, "update_service_placement") as placement,
                mock.patch.object(letsinfer, "serve", return_value=0) as serve,
            ):
                self.assertEqual(
                    letsinfer.serve_from_config(argparse.Namespace(config=str(config_path))),
                    0,
                )

            verify.assert_called_once_with(runtime_root)
            self.assertEqual(
                [call.args[2] for call in placement.call_args_list],
                ["starting", "running"],
            )
            self.assertEqual(serve.call_args.args[0].runtime_artifact_root, runtime_root)
            self.assertEqual(serve.call_args.args[0].runtime_digest, digest)

    def test_failed_service_upgrade_restores_previous_bundle_and_runtime(self) -> None:
        old_config = {
            "schema_version": letsinfer.SERVICE_CONFIG_VERSION,
            "name": "old-container",
            "source_root": "/immutable/old",
            "manifest_path": "/immutable/old/releases/old.json",
            "manifest_sha256": "a" * 64,
        }
        new_config = {
            "schema_version": letsinfer.SERVICE_CONFIG_VERSION,
            "name": "new-container",
            "watchdog_binary_path": "/watchdog/letsinfer-watchdog",
            "watchdog_data_root": "/watchdog/data",
            "protection_root": "/watchdog/data/protected-engines/" + "a" * 32,
            "watchdog_listen": "127.0.0.1",
            "watchdog_port": 9768,
            "watchdog_cert_file": "/watchdog/server.crt",
            "watchdog_key_file": "/watchdog/server.key",
            "watchdog_controller_ca_file": "/watchdog/controller-ca.crt",
            "watchdog_controller_allowlist_file": "/watchdog/controllers.allow",
            "watchdog_public_state_file": "/watchdog/data/service-state/manifest.state",
            "gateway_listen": "0.0.0.0",
            "gateway_protocol": "http",
            "gateway_port": 8000,
            "gateway_max_connections": 128,
            "gateway_queue_timeout_seconds": 300,
            "gateway_telemetry_file": "/watchdog/data/gateway.state",
            "tls_cert_file": "/tls/server.crt",
            "tls_key_file": "/tls/server.key",
        }
        manifest = {
            "container": {"startup_timeout_seconds": 30},
            "watchdog": {
                "memory_high_bytes": letsinfer.CONTROL_PLANE_MEMORY_HIGH_BYTES,
                "memory_max_bytes": letsinfer.CONTROL_PLANE_MEMORY_LIMIT_BYTES,
                "sample_interval_ms": 1000,
                "flush_interval_ms": 10000,
                "max_controllers": 2,
                "protection": {
                    "warning_available_bytes": 16 << 30,
                    "graceful_available_bytes": 12 << 30,
                    "emergency_available_bytes": 8 << 30,
                    "swap_stop_bytes": 1 << 30,
                    "psi_some_us": 150000,
                    "psi_full_us": 50000,
                    "state_failures": 8,
                    "containment_grace_ms": 3000,
                },
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config_path = root / "config/service.json"
            unit_dir = root / "systemd"
            config_path.parent.mkdir(parents=True)
            unit_dir.mkdir()
            config_path.write_text("old config\n", encoding="utf-8")
            config_path.chmod(0o600)
            unit_paths = (
                unit_dir / letsinfer.SERVICE_NAME,
                unit_dir / letsinfer.SITE_SERVICE_NAME,
                unit_dir / letsinfer.ENGINE_SERVICE_NAME,
                unit_dir / letsinfer.GATEWAY_SERVICE_NAME,
                unit_dir / letsinfer.RECOVERY_SERVICE_NAME,
                unit_dir / letsinfer.RECOVERY_TIMER_NAME,
            )
            for index, path in enumerate(unit_paths):
                path.write_text(f"old unit {index}\n", encoding="utf-8")
                path.chmod(0o644)

            starts = 0

            def service_command(command: list[str]) -> None:
                nonlocal starts
                if command[-2:] == ["start", letsinfer.SERVICE_NAME]:
                    starts += 1
                    if starts == 1:
                        raise letsinfer.LetsInferError("new service failed")

            states = {
                letsinfer.SERVICE_NAME: ("enabled", "active"),
                letsinfer.SITE_SERVICE_NAME: ("enabled", "active"),
                letsinfer.ENGINE_SERVICE_NAME: ("static", "active"),
                letsinfer.GATEWAY_SERVICE_NAME: ("enabled", "inactive"),
                letsinfer.RECOVERY_TIMER_NAME: ("not-found", "inactive"),
            }
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            bound_old_config = {
                **old_config,
                "source_root": "/immutable/old",
                "manifest_path": "/immutable/old/releases/old.json",
                "manifest_sha256": "a" * 64,
            }
            new_config["source_root"] = "/immutable/new"
            with (
                mock.patch.object(
                    letsinfer,
                    "_unit_enabled_active",
                    side_effect=lambda name: states[name],
                ),
                mock.patch.object(
                    letsinfer, "read_service_config", return_value=old_config
                ),
                mock.patch.object(
                    letsinfer,
                    "bind_config_to_control_bundle",
                    return_value=bound_old_config,
                ),
                mock.patch.object(
                    letsinfer,
                    "configured_release",
                    return_value=(pathlib.Path("/immutable/old/releases/old.json"), manifest),
                ),
                mock.patch.object(letsinfer, "run", return_value=completed),
                mock.patch.object(
                    letsinfer,
                    "_service_state",
                    return_value=("enabled", "active", 8 * 1024 * 1024),
                ),
                mock.patch.object(
                    letsinfer, "run_passthrough", side_effect=service_command
                ) as commands,
                self.assertRaisesRegex(
                    letsinfer.LetsInferError, "previous installation restored"
                ),
            ):
                letsinfer.install_user_service(
                    config_path,
                    new_config,
                    manifest,
                    no_start=False,
                    unit_dir=unit_dir,
                )

            # Roll back the exact prior current-schema configuration and release.
            self.assertEqual(config_path.read_text(), "old config\n")
            for index, path in enumerate(unit_paths):
                self.assertEqual(path.read_text(), f"old unit {index}\n")
            self.assertEqual(starts, 2)
            commands.assert_any_call(
                ["systemctl", "--user", "stop", letsinfer.SERVICE_NAME]
            )
            commands.assert_any_call(
                ["systemctl", "--user", "start", letsinfer.SERVICE_NAME]
            )
            commands.assert_any_call(
                ["systemctl", "--user", "stop", letsinfer.ENGINE_SERVICE_NAME]
            )
            commands.assert_any_call(
                ["systemctl", "--user", "start", letsinfer.ENGINE_SERVICE_NAME]
            )

    def test_no_start_refuses_to_replace_active_service(self) -> None:
        states = {
            letsinfer.SERVICE_NAME: ("enabled", "active"),
            letsinfer.SITE_SERVICE_NAME: ("enabled", "inactive"),
            letsinfer.ENGINE_SERVICE_NAME: ("static", "inactive"),
            letsinfer.GATEWAY_SERVICE_NAME: ("enabled", "inactive"),
            letsinfer.RECOVERY_TIMER_NAME: ("not-found", "inactive"),
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            letsinfer,
            "_unit_enabled_active",
            side_effect=lambda name: states[name],
        ), self.assertRaisesRegex(letsinfer.LetsInferError, "--no-start"):
            letsinfer.install_user_service(
                pathlib.Path(directory) / "service.json",
                {"name": "new-container"},
                {"container": {"startup_timeout_seconds": 30}},
                no_start=True,
                unit_dir=pathlib.Path(directory) / "systemd",
            )

    def test_service_upgrade_refuses_transitional_unit_state(self) -> None:
        states = {
            letsinfer.SERVICE_NAME: ("enabled", "activating"),
            letsinfer.SITE_SERVICE_NAME: ("enabled", "inactive"),
            letsinfer.ENGINE_SERVICE_NAME: ("static", "inactive"),
            letsinfer.GATEWAY_SERVICE_NAME: ("enabled", "inactive"),
            letsinfer.RECOVERY_TIMER_NAME: ("not-found", "inactive"),
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            letsinfer,
            "_unit_enabled_active",
            side_effect=lambda name: states[name],
        ), self.assertRaisesRegex(letsinfer.LetsInferError, "activating"):
            letsinfer.install_user_service(
                pathlib.Path(directory) / "service.json",
                {"name": "new-container"},
                {"container": {"startup_timeout_seconds": 30}},
                no_start=False,
                unit_dir=pathlib.Path(directory) / "systemd",
            )

    def test_restore_enablement_reports_systemctl_failure(self) -> None:
        failed = mock.Mock(returncode=1, stdout="", stderr="permission denied")
        with mock.patch.object(letsinfer, "run", return_value=failed), self.assertRaisesRegex(
            letsinfer.LetsInferError, "permission denied"
        ):
            letsinfer._restore_unit_enablement(letsinfer.SERVICE_NAME, "enabled")

    def test_current_service_config_has_no_runtime_mode(self) -> None:
        parsed = letsinfer.parser().parse_args(
            ["serve", "model", "--engine", "vllm", "--dry-run"]
        )
        self.assertFalse(hasattr(parsed, "profile"))

    def test_service_config_symlink_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            link = root / "service.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(letsinfer.LetsInferError, "symlink"):
                letsinfer.read_service_config(link)

    def test_direct_serve_reuses_installed_watchdog_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "service.json"
            path.write_text("{}\n", encoding="utf-8")
            with (
                mock.patch.object(
                    letsinfer, "default_service_config_path", return_value=path
                ),
                mock.patch.object(
                    letsinfer,
                    "read_service_config",
                    return_value={"name": "installed-engine", "watchdog_port": 9768},
                ),
            ):
                config = letsinfer.protection_config_for_serve(
                    None, name="qualification-engine"
                )
        self.assertIsNotNone(config)
        self.assertEqual(config["name"], "qualification-engine")
        self.assertEqual(config["watchdog_port"], 9768)


class RuntimeImageBuildTests(unittest.TestCase):
    def _manifest(self) -> dict:
        path = LLAMA_CPP_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        expected = "sha256:" + "a" * 64
        manifest["image"] = {
            "distribution": "local-image-id",
            "reference": expected,
            "immutable_id": expected,
        }
        return manifest

    def test_runtime_owned_image_build_is_engine_agnostic_and_exact(self) -> None:
        manifest = self._manifest()
        expected = manifest["image"]["immutable_id"]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image = root / "image"
            image.mkdir()
            packages = root / "packages"
            packages.mkdir()
            base = "registry.example/runtime@sha256:" + "b" * 64
            (image / "Dockerfile").write_text(
                f"FROM {base} AS engine\n"
                "COPY packages/requirements.lock /runtime/requirements.lock\n"
                "RUN python3 -m pip install --require-hashes "
                "-r /runtime/requirements.lock\n"
                "FROM engine AS final\n",
                encoding="utf-8",
            )
            (packages / "requirements.lock").write_text(
                "example==1.0 --hash=sha256:" + "c" * 64 + "\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    letsinfer,
                    "image_id",
                    side_effect=[letsinfer.LetsInferError("absent"), expected],
                ),
                mock.patch.object(letsinfer, "run_passthrough") as build,
                mock.patch.object(
                    letsinfer,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, expected + "\n", ""),
                ),
            ):
                self.assertEqual(
                    letsinfer.ensure_image(manifest, build=True, artifact_root=root),
                    expected,
                )
            command = build.call_args.args[0]
            self.assertEqual(
                command[:4], ["docker", "buildx", "build", "--pull=false"]
            )
            self.assertIn("--provenance=false", command)
            self.assertIn("type=docker,rewrite-timestamp=true", command)
            self.assertIn("SOURCE_DATE_EPOCH=0", command)
            self.assertIn(f"LETSINFER_EXPECTED_IMAGE_ID={expected}", command)
            self.assertIn("linux/arm64", command)
            self.assertEqual(pathlib.Path(command[-1]), root.resolve())

    def test_runtime_owned_image_rejects_mutable_external_base(self) -> None:
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image = root / "image"
            image.mkdir()
            (image / "Dockerfile").write_text(
                "FROM python:3.13\nRUN pip install example\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    letsinfer, "image_id", side_effect=letsinfer.LetsInferError("absent")
                ),
                mock.patch.object(letsinfer, "run_passthrough") as build,
                self.assertRaisesRegex(letsinfer.LetsInferError, "pinned by sha256 digest"),
            ):
                letsinfer.ensure_image(manifest, build=True, artifact_root=root)
            build.assert_not_called()

    def test_runtime_owned_image_rejects_result_identity_mismatch(self) -> None:
        manifest = self._manifest()
        actual = "sha256:" + "d" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image = root / "image"
            image.mkdir()
            (image / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            with (
                mock.patch.object(
                    letsinfer, "image_id", side_effect=letsinfer.LetsInferError("absent")
                ),
                mock.patch.object(letsinfer, "run_passthrough"),
                mock.patch.object(
                    letsinfer,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, actual + "\n", ""),
                ),
                self.assertRaisesRegex(letsinfer.LetsInferError, "identity differs"),
            ):
                letsinfer.ensure_image(manifest, build=True, artifact_root=root)

    def test_runtime_owned_image_is_not_built_when_disabled(self) -> None:
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image = root / "image"
            image.mkdir()
            (image / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            with (
                mock.patch.object(
                    letsinfer, "image_id", side_effect=letsinfer.LetsInferError("absent")
                ),
                mock.patch.object(letsinfer, "run_passthrough") as build,
                self.assertRaisesRegex(letsinfer.LetsInferError, "absent"),
            ):
                letsinfer.ensure_image(manifest, build=False, artifact_root=root)
            build.assert_not_called()

    def test_registry_image_is_not_pulled_when_downloads_are_disabled(self) -> None:
        manifest = self._manifest()
        digest = "sha256:" + "d" * 64
        manifest["image"] = {
            "distribution": "registry-digest",
            "reference": f"registry.example/runtime@{digest}",
            "immutable_id": digest,
        }
        with (
            mock.patch.object(
                letsinfer, "image_id", side_effect=letsinfer.LetsInferError("absent")
            ),
            mock.patch.object(letsinfer, "run_passthrough") as pull,
            self.assertRaisesRegex(letsinfer.LetsInferError, "downloads are disabled"),
        ):
            letsinfer.ensure_image(manifest, build=False, pull=False)
        pull.assert_not_called()

    def test_missing_runtime_dockerfile_never_falls_back_to_core(self) -> None:
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with (
                mock.patch.object(
                    letsinfer, "image_id", side_effect=letsinfer.LetsInferError("absent")
                ),
                mock.patch.object(letsinfer, "run_passthrough") as build,
                self.assertRaisesRegex(
                    letsinfer.LetsInferError, "does not contain image/Dockerfile"
                ),
            ):
                letsinfer.ensure_image(manifest, build=True, artifact_root=root)
            build.assert_not_called()


class RuntimePluginBuildTests(unittest.TestCase):
    def test_native_builder_outputs_are_owned_by_the_calling_user(self) -> None:
        payload = b"native bridge"
        expected = hashlib.sha256(payload).hexdigest()
        manifest = {
            "target": json.loads(
                DWARFSTAR_MANIFEST_PATH.read_text(encoding="utf-8")
            )["target"],
            "runtime_plugins": {
                "native_builder": {
                    "image": "builder.example/rust@sha256:" + "d" * 64,
                    "source_root": "bridge",
                    "source_date_epoch": 1785594180,
                    "entrypoint": "cargo",
                    "arguments": ["build", "--release", "--locked"],
                    "output": "release/libletsinfer_prefix_capi.so",
                },
                "artifacts": [
                    {"path": "dwarfstar_gateway.py", "sha256": "a" * 64},
                    {"path": "libletsinfer_prefix_capi.so", "sha256": expected},
                ],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source"
            (source / "bridge").mkdir(parents=True)
            (source / "bridge/Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
            output = root / "build"
            output.mkdir()

            def build(command: list[str]) -> None:
                artifact = output / "native-output/release/libletsinfer_prefix_capi.so"
                artifact.parent.mkdir(parents=True)
                artifact.write_bytes(payload)

            with mock.patch.object(letsinfer, "run_passthrough", side_effect=build) as run:
                artifact = letsinfer.build_runtime_native_artifact(
                    manifest, output, artifact_root=source
                )

            self.assertEqual(artifact.read_bytes(), payload)
            command = run.call_args.args[0]
            self.assertIn(f"LETSINFER_OUTPUT_UID={os.getuid()}", command)
            self.assertIn(f"LETSINFER_OUTPUT_GID={os.getgid()}", command)
            self.assertIn("CARGO_TARGET_DIR=/output", command)
            self.assertIn(f"{output / 'native-output'}:/artifact", command)
            self.assertIn("install -D -m 0755", " ".join(command))
            self.assertIn("chown -R", " ".join(command))


class ControllerTests(unittest.TestCase):
    def test_controller_exposes_only_latest_placement_per_model(self) -> None:
        rows = [
            {
                "placement_id": "1" * 32,
                "model": "example-model",
                "state": "running",
                "updated_at_unix": 10,
            },
            {
                "placement_id": "2" * 32,
                "model": "example-model",
                "state": "stopped",
                "updated_at_unix": 20,
            },
            {
                "placement_id": "3" * 32,
                "model": "other-model",
                "state": "running",
                "updated_at_unix": 15,
            },
        ]
        current = letsinfer._current_controller_placements(rows)
        self.assertEqual(
            [(row["model"], row["placement_id"]) for row in current],
            [("example-model", "2" * 32), ("other-model", "3" * 32)],
        )

        tied = [
            dict(rows[0], updated_at_unix=30),
            dict(rows[1], updated_at_unix=30),
        ]
        self.assertEqual(
            letsinfer._current_controller_placements(tied)[0]["state"],
            "running",
        )

    def _local_controller_certificate(self, root: pathlib.Path) -> pathlib.Path:
        key = root / "local.key"
        certificate = root / "local.crt"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes",
                "-days", "36500", "-subj", "/CN=local",
                "-keyout", str(key), "-out", str(certificate),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        certificate.chmod(0o600)
        return certificate

    def test_installation_identity_and_controller_authorization_are_private_and_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            local_key = root / "local.key"
            local_cert = root / "local.crt"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:3072",
                    "-nodes", "-days", "36500",
                    "-subj", "/CN=local", "-keyout", str(local_key), "-out", str(local_cert),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            local_cert.chmod(0o600)
            with mock.patch.dict(
                os.environ,
                {
                    "LETSINFER_CONFIG_HOME": str(root / "config"),
                    "LETSINFER_DATA_HOME": str(root / "data"),
                },
            ):
                identity = letsinfer.setup_site("Home", "127.0.0.1")
                first = letsinfer.ensure_installation_identity()
                second = letsinfer.ensure_installation_identity()
                self.assertEqual(first, second)
                allowlist = letsinfer.ensure_controller_authorization(
                    identity, local_cert, root / "controllers.allow"
                )
                self.assertEqual(
                    letsinfer.ensure_controller_authorization(
                        identity, local_cert, allowlist
                    ),
                    allowlist,
                )
                with letsinfer.SiteStore(identity=identity) as store:
                    rows = store.controllers()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["role"], "administrator")
                self.assertEqual(allowlist.stat().st_mode & 0o777, 0o600)
                self.assertIn(
                    f"controller={letsinfer.local_controller_id(identity.installation_id)},",
                    allowlist.read_text(encoding="ascii"),
                )

    def test_controller_cli_has_one_fixed_pairing_port(self) -> None:
        paired = letsinfer.parser().parse_args(["pair"])
        self.assertEqual(paired.timeout, letsinfer.CONTROLLER_PAIRING_TIMEOUT_SECONDS)
        self.assertFalse(hasattr(paired, "port"))
        listed = letsinfer.parser().parse_args(["controllers", "list"])
        self.assertEqual(listed.operation, "list")
        forgotten = letsinfer.parser().parse_args(
            ["controllers", "forget", "Desk Mac"]
        )
        self.assertEqual(forgotten.controller, "Desk Mac")

    def test_controller_install_uses_internal_install_contract_and_returns_identity(self) -> None:
        principal = letsinfer.ControllerPrincipal("a" * 32, "administrator", "b" * 64)
        receipt = {
            "model": "example-model",
            "engine": "vllm",
            "name": "example-runtime",
            "version": "1.2.3",
            "digest": "c" * 64,
            "installed_at_unix_ns": 10,
        }
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.__exit__.return_value = None
        with (
            mock.patch.object(letsinfer, "install", return_value=0) as install,
            mock.patch.object(letsinfer, "selections", return_value=[receipt]),
            mock.patch.object(letsinfer, "_site_store", return_value=store),
        ):
            result = letsinfer._controller_site_action(
                principal,
                "install",
                {"model": "example-model", "engine": "vllm"},
                "d" * 32,
            )
        install.assert_called_once()
        self.assertEqual(result["resource"], "runtime")
        self.assertEqual(
            result["identifier"],
            "example-runtime@1.2.3@sha256:" + "c" * 64,
        )
        self.assertEqual(
            store.record_action.call_args.kwargs["correlation_id"], "d" * 32
        )

    def test_controller_topology_and_exposure_forward_actor_identity(self) -> None:
        principal = letsinfer.ControllerPrincipal("a" * 32, "administrator", "b" * 64)
        topology = {
            "change_required": True,
            "plan_id": "c" * 32,
            "runtime_identity": "runtime@1@sha256:" + "d" * 64,
        }
        with mock.patch.object(
            letsinfer, "_topology_plan_document", return_value=topology
        ) as planner:
            result = letsinfer._controller_site_action(
                principal,
                "topology-plan",
                {"model": "example-model", "engine": None},
                "e" * 32,
            )
        self.assertEqual(result["state"], "pending")
        self.assertEqual(planner.call_args.kwargs["actor_type"], "controller")
        self.assertEqual(planner.call_args.kwargs["actor_id"], "a" * 32)
        self.assertEqual(planner.call_args.kwargs["correlation_id"], "e" * 32)

        exposure = {
            "provider": "tailscale-funnel",
            "public_url": "https://example.ts.net",
        }
        with mock.patch.object(
            letsinfer, "_enable_public_exposure", return_value=exposure
        ) as enable:
            result = letsinfer._controller_site_action(
                principal, "expose", {}, "f" * 32
            )
        self.assertEqual(result["state"], "enabled")
        self.assertEqual(enable.call_args.kwargs["origin_interface"], "controller-api")

    def test_controller_cli_rejects_incomplete_operations_and_unsafe_timeout(self) -> None:
        config = {
            "installation_id": "1" * 64,
            "watchdog_controller_allowlist_file": "/private/controllers.allow",
        }
        with mock.patch.object(letsinfer, "read_service_config", return_value=config):
            with self.assertRaisesRegex(letsinfer.LetsInferError, "requires"):
                letsinfer.controllers(argparse.Namespace(
                    config=None, operation="forget", controller=None, json=False
                ))
            with self.assertRaisesRegex(letsinfer.LetsInferError, "does not accept"):
                letsinfer.controllers(argparse.Namespace(
                    config=None, operation="list", controller="extra", json=False
                ))
        with self.assertRaisesRegex(letsinfer.LetsInferError, "timeout"):
            letsinfer.pair_controller(argparse.Namespace(config=None, timeout=181))
        with self.assertRaisesRegex(letsinfer.LetsInferError, "timeout"):
            letsinfer.pair_controller(argparse.Namespace(config=None, timeout=29))

    def test_controller_names_are_canonical_and_terminal_safe(self) -> None:
        self.assertEqual(letsinfer._validate_controller_name("Desk Mac"), "Desk Mac")
        with self.assertRaisesRegex(letsinfer.LetsInferError, "invalid"):
            letsinfer._validate_controller_name("Desk\u2028Mac")
        with self.assertRaisesRegex(letsinfer.LetsInferError, "invalid"):
            letsinfer._validate_controller_name("Cafe\u0301")

    def test_pairing_code_and_confirmation_contract(self) -> None:
        installation = "1" * 64
        session = "2" * 32
        nonce = "3" * 64
        controller = "4" * 32
        public_key = "5" * 64
        self.assertEqual(
            letsinfer.controller_confirmation_code(
                installation, session, nonce, controller, public_key
            ),
            "833267",
        )
        self.assertEqual(letsinfer.format_pairing_code("12345678"), "123-45-678")
        payload = {
            "protocol": letsinfer.CONTROLLER_PAIRING_PROTOCOL,
            "setup_code": "00000000",
            "controller_id": controller,
            "name": "Desk Mac",
            "public_key_spki": base64.b64encode(b"x" * 91).decode("ascii"),
            "proof": base64.b64encode(b"y" * 72).decode("ascii"),
        }
        with self.assertRaisesRegex(letsinfer.LetsInferError, "did not match"):
            letsinfer._decode_controller_enrollment(
                payload,
                installation_id=installation,
                session_id=session,
                nonce=nonce,
                setup_code="12345678",
            )

    def test_repair_replaces_the_same_controller_and_reloads_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            allowlist = root / "controllers.allow"
            controller_id = "2" * 32
            certificate = self._local_controller_certificate(root)
            with mock.patch.dict(
                os.environ,
                {
                    "LETSINFER_CONFIG_HOME": str(root / "config"),
                    "LETSINFER_DATA_HOME": str(root / "data"),
                },
            ):
                identity = letsinfer.setup_site("Home", "127.0.0.1")
                letsinfer.ensure_controller_authorization(identity, certificate, allowlist)
                config = {
                    "installation_id": identity.installation_id,
                    "watchdog_controller_allowlist_file": str(allowlist),
                }
                active = subprocess.CompletedProcess([], 0, "active\n", "")
                certificate_pem = (
                    "-----BEGIN CERTIFICATE-----\nremote\n"
                    "-----END CERTIFICATE-----\n"
                )
                with (
                    mock.patch.object(letsinfer, "run", return_value=active),
                    mock.patch.object(
                        letsinfer, "_reload_controller_authorization"
                    ) as reload,
                ):
                    letsinfer._replace_controller(
                        config,
                        {"id": controller_id, "name": "Desk Mac"},
                        certificate_pem,
                        "6" * 64,
                        "operator",
                    )
                with letsinfer.SiteStore(identity=identity) as store:
                    paired = [
                        row for row in store.controllers()
                        if row["controller_id"] == controller_id
                    ]
                self.assertEqual(len(paired), 1)
                self.assertEqual(paired[0]["name"], "Desk Mac")
                self.assertEqual(paired[0]["role"], "operator")
                self.assertEqual(paired[0]["certificate_sha256"], "6" * 64)
                reload.assert_called_once_with(config, require_active=True)

    def test_forget_revokes_only_a_remote_controller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            allowlist = root / "controllers.allow"
            certificate = self._local_controller_certificate(root)
            with mock.patch.dict(
                os.environ,
                {
                    "LETSINFER_CONFIG_HOME": str(root / "config"),
                    "LETSINFER_DATA_HOME": str(root / "data"),
                },
            ):
                identity = letsinfer.setup_site("Home", "127.0.0.1")
                letsinfer.ensure_controller_authorization(identity, certificate, allowlist)
                with letsinfer.SiteStore(identity=identity) as store:
                    store.upsert_controller(
                        controller_id="4" * 32,
                        name="Desk Mac",
                        role="administrator",
                        certificate_sha256="5" * 64,
                        certificate_pem=(
                            "-----BEGIN CERTIFICATE-----\nremote\n"
                            "-----END CERTIFICATE-----\n"
                        ),
                    )
                    letsinfer.write_controller_allowlist(
                        store, identity.installation_id, allowlist
                    )
                config = {
                    "installation_id": identity.installation_id,
                    "watchdog_controller_allowlist_file": str(allowlist),
                }
                arguments = argparse.Namespace(
                    config=None,
                    operation="forget",
                    controller="Desk Mac",
                    json=False,
                )
                with (
                    mock.patch.object(
                        letsinfer, "read_service_config", return_value=config
                    ),
                    mock.patch.object(
                        letsinfer, "_reload_controller_authorization"
                    ) as reload,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(letsinfer.controllers(arguments), 0)
                with letsinfer.SiteStore(identity=identity) as store:
                    rows = store.controllers()
                self.assertEqual(
                    [row["controller_id"] for row in rows],
                    [letsinfer.local_controller_id(identity.installation_id)],
                )
                reload.assert_called_once_with(config)

    def test_controller_certificate_requires_key_possession(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            ca_key = root / "ca.key"
            ca_cert = root / "ca.crt"
            controller_key = root / "controller.key"
            public_der = root / "controller.der"
            challenge_path = root / "challenge"
            proof_path = root / "proof"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:3072",
                    "-nodes", "-days", "36500",
                    "-subj", "/CN=controller-ca", "-addext", "basicConstraints=critical,CA:TRUE",
                    "-keyout", str(ca_key), "-out", str(ca_cert),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            ca_key.chmod(0o600)
            ca_cert.chmod(0o600)
            subprocess.run(
                [
                    "openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-out", str(controller_key),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    "openssl", "pkey", "-in", str(controller_key), "-pubout",
                    "-outform", "DER", "-out", str(public_der),
                ],
                check=True,
            )
            public = public_der.read_bytes()
            candidate = {
                "id": "4" * 32,
                "name": "Desk Mac",
                "public_key": public,
                "public_key_sha256": hashlib.sha256(public).hexdigest(),
            }
            candidate["challenge"] = letsinfer.controller_pairing_challenge(
                "1" * 64,
                "2" * 32,
                "3" * 64,
                candidate["id"],
                candidate["name"],
                candidate["public_key_sha256"],
            )
            challenge_path.write_bytes(candidate["challenge"])
            subprocess.run(
                [
                    "openssl", "dgst", "-sha256", "-sign", str(controller_key),
                    "-out", str(proof_path), str(challenge_path),
                ],
                check=True,
            )
            candidate["proof"] = proof_path.read_bytes()
            certificate, fingerprint = letsinfer.issue_controller_certificate(
                candidate, ca_cert, ca_key
            )
            self.assertIn("BEGIN CERTIFICATE", certificate)
            self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")
            issued = root / "issued.crt"
            issued.write_text(certificate, encoding="ascii")
            lifetime = subprocess.run(
                [
                    "openssl", "x509", "-in", str(issued), "-noout", "-checkend",
                    str(50 * 365 * 24 * 60 * 60),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(lifetime.returncode, 0)
            details = subprocess.run(
                ["openssl", "x509", "-in", str(issued), "-noout", "-text"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("TLS Web Client Authentication", details)
            self.assertIn(f"URI:urn:letsinfer:controller:{candidate['id']}", details)

            invalid = dict(candidate)
            invalid["proof"] = bytes([candidate["proof"][0] ^ 1]) + candidate["proof"][1:]
            with self.assertRaisesRegex(letsinfer.LetsInferError, "command failed"):
                letsinfer.issue_controller_certificate(invalid, ca_cert, ca_key)

    def test_https_pairing_round_trip_is_key_bound_and_one_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            server_cert = root / "server.crt"
            server_key = root / "server.key"
            controller_ca = root / "controller-ca.crt"
            controller_ca_key = root / "controller-ca.key"
            local_cert = root / "local-controller.crt"
            local_key = root / "local-controller.key"
            letsinfer.ensure_watchdog_tls_material(
                server_cert,
                server_key,
                controller_ca,
                controller_ca_key,
                local_cert,
                local_key,
            )
            installation = "1" * 64
            state = letsinfer._ControllerPairingState(
                {
                    "installation_id": installation,
                    "watchdog_port": 9768,
                    "watchdog_controller_ca_file": str(controller_ca),
                    "watchdog_controller_ca_key_file": str(controller_ca_key),
                },
                "12345678",
                30,
                "administrator",
            )
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if getattr(ssl, "HAS_TLSv1_3", False):
                tls.minimum_version = ssl.TLSVersion.TLSv1_3
                tls.maximum_version = ssl.TLSVersion.TLSv1_3
            tls.load_cert_chain(server_cert, server_key)
            server = letsinfer._ControllerPairingServer(
                ("127.0.0.1", 0), letsinfer._ControllerPairingHandler
            )
            server.pairing_state = state
            server.tls_context = tls
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                origin = f"https://127.0.0.1:{server.server_port}"
                with urllib.request.urlopen(
                    origin + "/pair/v1/hello", context=context, timeout=5
                ) as response:
                    hello = json.load(response)
                self.assertEqual(hello["installation_id"], installation)

                controller_key = root / "controller.key"
                controller_public = root / "controller.der"
                challenge = root / "challenge"
                proof = root / "proof"
                subprocess.run(
                    [
                        "openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                        "ec_paramgen_curve:P-256", "-out", str(controller_key),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                subprocess.run(
                    [
                        "openssl", "pkey", "-in", str(controller_key), "-pubout",
                        "-outform", "DER", "-out", str(controller_public),
                    ],
                    check=True,
                )
                public = controller_public.read_bytes()
                public_sha = hashlib.sha256(public).hexdigest()
                challenge.write_bytes(letsinfer.controller_pairing_challenge(
                    installation,
                    hello["session_id"],
                    hello["nonce"],
                    "2" * 32,
                    "Desk Mac",
                    public_sha,
                ))
                subprocess.run(
                    [
                        "openssl", "dgst", "-sha256", "-sign", str(controller_key),
                        "-out", str(proof), str(challenge),
                    ],
                    check=True,
                )
                payload = json.dumps({
                    "protocol": letsinfer.CONTROLLER_PAIRING_PROTOCOL,
                    "setup_code": "12345678",
                    "controller_id": "2" * 32,
                    "name": "Desk Mac",
                    "public_key_spki": base64.b64encode(public).decode("ascii"),
                    "proof": base64.b64encode(proof.read_bytes()).decode("ascii"),
                }).encode("utf-8")
                request = urllib.request.Request(
                    origin + "/pair/v1/enroll",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                result: list[dict] = []
                errors: list[BaseException] = []

                def enroll() -> None:
                    try:
                        with urllib.request.urlopen(
                            request, context=context, timeout=10
                        ) as response:
                            result.append(json.load(response))
                    except BaseException as error:
                        errors.append(error)

                with mock.patch.object(letsinfer, "_replace_controller"):
                    enrollment = threading.Thread(target=enroll, daemon=True)
                    enrollment.start()
                    with state.condition:
                        self.assertTrue(state.condition.wait_for(
                            lambda: state.candidate is not None, timeout=5
                        ))
                        state.approved = True
                        state.condition.notify_all()
                    enrollment.join(timeout=10)
                self.assertFalse(enrollment.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(result[0]["status"], "paired")
                self.assertEqual(result[0]["controller_id"], "2" * 32)
                self.assertIn("BEGIN CERTIFICATE", result[0]["certificate_pem"])
                with self.assertRaisesRegex(
                    letsinfer.LetsInferError, "already been used"
                ):
                    state.enroll(json.loads(payload))
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)


class RuntimeCommandTests(unittest.TestCase):
    def test_benchmark_status_attaches_to_the_active_job(self) -> None:
        arguments = letsinfer.parser().parse_args(["benchmark"])
        state = {"job_id": "active-benchmark", "state": "running"}
        with (
            mock.patch.object(
                letsinfer.benchmark_jobs, "active_state", return_value=state
            ),
            mock.patch.object(letsinfer, "_follow_benchmark_job") as follow,
        ):
            self.assertEqual(letsinfer.benchmark_runtime(arguments), 0)
        follow.assert_called_once_with("active-benchmark")

    def test_benchmark_dashboard_shows_current_completed_and_future_cells(self) -> None:
        terminal = letsinfer.ui.Terminal(
            io.StringIO(), environ={"TERM": "dumb", "COLUMNS": "80"}
        )
        rendered = letsinfer._benchmark_dashboard(
            {
                "state": "running",
                "runtime": "fixture-model",
                "output_directory": "/evidence/fixture",
            },
            {
                "message": "Loading runtime for 64k-c1",
                "phase": "workload:64k-c1:loading",
                "expected_minutes": [18, 37],
                "selected_cells": ["32k-c1", "64k-c1", "128k-c1"],
                "completed_cells": ["32k-c1"],
                "current_cell": "64k-c1",
            },
            243,
            terminal,
            "*",
        )
        self.assertIn("WORKLOADS", rendered)
        self.assertIn("1/3", rendered)
        self.assertIn("32k-c1", rendered)
        self.assertIn("complete", rendered)
        self.assertIn("64k-c1", rendered)
        self.assertIn("running", rendered)
        self.assertIn("128k-c1", rendered)
        self.assertIn("waiting", rendered)
        self.assertIn("ELAPSED   4m 03s", rendered)

    def test_benchmark_cli_delegates_without_engine_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            runner = root / "benchmarks/runtime_matrix.py"
            executable = root / "bin/letsinfer"
            runner.parent.mkdir(parents=True)
            executable.parent.mkdir(parents=True)
            runner.write_text("# runner\n", encoding="utf-8")
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            service_config = root / "service.json"
            service_config.write_text("{}\n", encoding="utf-8")
            (root / "runtime.json").write_text(
                '{"benchmark":{}}\n', encoding="utf-8"
            )
            arguments = letsinfer.parser().parse_args(
                [
                    "benchmark",
                    "fixture-paired-model/dwarfstar/fixture-unified",
                    "--c1",
                    "--64k",
                    "--output-directory",
                    "/tmp/evidence",
                    "--job-worker",
                    "--job-id",
                    "fixture-job",
                ]
            )
            with (
                mock.patch.object(
                    letsinfer,
                    "resolve_model",
                    return_value=(root / "releases/release.json", {}),
                ),
                mock.patch.object(
                    letsinfer, "manifest_source_root", return_value=root
                ),
                mock.patch.object(letsinfer, "verify_release_sources"),
                mock.patch.object(
                    letsinfer,
                    "runtime_receipt_for_manifest",
                    return_value={
                        "object_root": str(root),
                        "digest": "d" * 64,
                        "installation_id": "e" * 64,
                    },
                ),
                mock.patch.object(
                    letsinfer,
                    "verify_descriptor",
                    return_value=types.SimpleNamespace(
                        digest="d" * 64, descriptor={"benchmark": {}}
                    ),
                ),
                mock.patch.object(
                    letsinfer,
                    "adapter_for",
                    return_value=types.SimpleNamespace(
                        name="dwarfstar",
                        token_count_path="/v1/token-count",
                        token_count_protocol="letsinfer-token-count-v1",
                    ),
                ),
                mock.patch.object(
                    letsinfer, "_run_benchmark_with_service_isolation"
                ) as run,
                mock.patch.object(letsinfer.benchmark_jobs, "mark"),
                mock.patch.object(
                    letsinfer, "default_service_config_path", return_value=service_config
                ),
                mock.patch.object(
                    letsinfer,
                    "read_service_config",
                    return_value={
                        "gateway_port": 8000,
                        "engine_port": 18000,
                        "engine_api_key_file": "/engine/api-key",
                        "gateway_api_key_file": "/gateway/api-key",
                        "tls_cert_file": "/tls/server.crt",
                        "protection_root": "/watchdog/protected/runtime",
                        "watchdog_port": 9768,
                        "watchdog_controller_ca_file": "/watchdog/controller-ca.crt",
                        "watchdog_local_controller_cert_file": (
                            "/watchdog/local-controller.crt"
                        ),
                        "watchdog_local_controller_key_file": (
                            "/watchdog/local-controller.key"
                        ),
                    },
                ),
                mock.patch.object(
                    letsinfer, "_unit_enabled_active", return_value=("enabled", "active")
                ),
            ):
                self.assertEqual(letsinfer.benchmark_runtime(arguments), 0)

        command = run.call_args.args[0]
        self.assertEqual(command[:2], [sys.executable, str(runner.resolve())])
        self.assertEqual(
            command[command.index("--runtime") + 1],
            "fixture-paired-model/dwarfstar/fixture-unified",
        )
        self.assertEqual(
            command[command.index("--letsinfer-bin") + 1], str(executable.resolve())
        )
        self.assertEqual(
            command[command.index("--runtime-config") + 1],
            str((root / "runtime.json").resolve()),
        )
        self.assertIn("--token-count-path", command)
        self.assertIn("--c1", command)
        self.assertIn("--64k", command)
        self.assertIn("--installation-id", command)
        self.assertIn("--benchmark-timestamp-unix-ns", command)
        self.assertIn("--benchmark-contract-sha256", command)
        self.assertIn("--watchdog-port", command)
        self.assertIn("--watchdog-controller-cert-file", command)
        self.assertEqual(command[command.index("--base-url") + 1], "http://127.0.0.1:8000")
        self.assertEqual(command[command.index("--engine-port") + 1], "18000")
        self.assertEqual(
            command[command.index("--token-count-base-url") + 1],
            "https://127.0.0.1:18000",
        )
        self.assertEqual(
            command[command.index("--token-count-api-key-file") + 1],
            "/engine/api-key",
        )
        self.assertEqual(command[command.index("--api-key-file") + 1], "/gateway/api-key")
        self.assertEqual(command[command.index("--ca-cert-file") + 1], "/tls/server.crt")
        self.assertEqual(
            command[command.index("--watchdog-trip-file") + 1],
            "/watchdog/protected/runtime/protection-trip.json",
        )
        self.assertNotIn("--c4", command)
        self.assertNotIn("--measured-commit", command)

    def test_benchmark_suspends_and_restores_active_engine(self) -> None:
        command = ["runner", "--c1"]
        with (
            mock.patch.object(
                letsinfer,
                "_unit_enabled_active",
                side_effect=[("static", "active"), ("enabled", "active")],
            ),
            mock.patch.object(letsinfer, "run_passthrough") as run,
        ):
            letsinfer._run_benchmark_with_service_isolation(command)

        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["systemctl", "--user", "stop", letsinfer.RECOVERY_TIMER_NAME],
                ["systemctl", "--user", "stop", letsinfer.ENGINE_SERVICE_NAME],
                command,
                ["systemctl", "--user", "start", letsinfer.ENGINE_SERVICE_NAME],
                ["systemctl", "--user", "restart", letsinfer.RECOVERY_TIMER_NAME],
            ],
        )

    def test_benchmark_failure_still_restores_active_engine(self) -> None:
        command = ["runner", "--c1"]

        def execute(actual: list[str]) -> None:
            if actual == command:
                raise letsinfer.LetsInferError("benchmark failed")

        with (
            mock.patch.object(
                letsinfer,
                "_unit_enabled_active",
                side_effect=[("static", "active"), ("enabled", "active")],
            ),
            mock.patch.object(
                letsinfer, "run_passthrough", side_effect=execute
            ) as run,
        ):
            with self.assertRaisesRegex(letsinfer.LetsInferError, "benchmark failed"):
                letsinfer._run_benchmark_with_service_isolation(command)

        self.assertEqual(
            [call.args[0] for call in run.call_args_list[-2:]],
            [
                ["systemctl", "--user", "start", letsinfer.ENGINE_SERVICE_NAME],
                ["systemctl", "--user", "restart", letsinfer.RECOVERY_TIMER_NAME],
            ],
        )

    def test_benchmark_trip_leaves_engine_and_recovery_stopped(self) -> None:
        command = ["runner", "--c8", "--128k"]
        config = {"protection_root": "/watchdog/protected/runtime"}

        def execute(actual: list[str]) -> None:
            if actual == command:
                raise letsinfer.LetsInferError("host memory pressure")

        with (
            mock.patch.object(
                letsinfer,
                "_unit_enabled_active",
                side_effect=[("static", "active"), ("enabled", "active")],
            ),
            mock.patch.object(
                letsinfer,
                "protection_trip_latched",
                side_effect=[False, True],
            ),
            mock.patch.object(
                letsinfer, "run_passthrough", side_effect=execute
            ) as run,
        ):
            with self.assertRaisesRegex(
                letsinfer.LetsInferError,
                "remain stopped until explicit letsinfer recover",
            ):
                letsinfer._run_benchmark_with_service_isolation(
                    command,
                    protection_config=config,
                )

        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["systemctl", "--user", "stop", letsinfer.RECOVERY_TIMER_NAME],
                ["systemctl", "--user", "stop", letsinfer.ENGINE_SERVICE_NAME],
                command,
            ],
        )

    def test_benchmark_refuses_preexisting_protection_trip(self) -> None:
        with (
            mock.patch.object(
                letsinfer, "protection_trip_latched", return_value=True
            ),
            mock.patch.object(letsinfer, "_unit_enabled_active") as unit_state,
        ):
            with self.assertRaisesRegex(
                letsinfer.LetsInferError,
                "already tripped",
            ):
                letsinfer._run_benchmark_with_service_isolation(
                    ["runner"],
                    protection_config={"protection_root": "/watchdog"},
                )
        unit_state.assert_not_called()

    def test_benchmark_cli_list_does_not_create_an_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            runner = root / "benchmarks/runtime_matrix.py"
            executable = root / "bin/letsinfer"
            runner.parent.mkdir(parents=True)
            executable.parent.mkdir(parents=True)
            runner.write_text("# runner\n", encoding="utf-8")
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "runtime.json").write_text(
                '{"benchmark":{}}\n', encoding="utf-8"
            )
            arguments = letsinfer.parser().parse_args(
                ["benchmark", "model/engine/target", "--c1", "--list"]
            )
            with (
                mock.patch.object(
                    letsinfer,
                    "resolve_model",
                    return_value=(root / "releases/release.json", {}),
                ),
                mock.patch.object(
                    letsinfer, "manifest_source_root", return_value=root
                ),
                mock.patch.object(letsinfer, "verify_release_sources"),
                mock.patch.object(
                    letsinfer,
                    "runtime_receipt_for_manifest",
                    return_value={"object_root": str(root), "digest": "d" * 64},
                ),
                mock.patch.object(
                    letsinfer,
                    "verify_descriptor",
                    return_value=types.SimpleNamespace(
                        digest="d" * 64, descriptor={"benchmark": {}}
                    ),
                ),
                mock.patch.object(
                    letsinfer,
                    "adapter_for",
                    return_value=types.SimpleNamespace(
                        name="dwarfstar",
                        token_count_path="/v1/token-count",
                        token_count_protocol="letsinfer-token-count-v1",
                    ),
                ),
                mock.patch.object(letsinfer, "run_passthrough") as run,
            ):
                self.assertEqual(letsinfer.benchmark_runtime(arguments), 0)

        command = run.call_args.args[0]
        self.assertIn("--list", command)
        self.assertNotIn("--output-directory", command)

    def test_releases_lists_only_installed_runtime_manifests(self) -> None:
        release = json.loads(DWARFSTAR_MANIFEST_PATH.read_text(encoding="utf-8"))
        receipt = {"name": "fixture-paired-model/dwarfstar/fixture-unified"}
        output = io.StringIO()
        with (
            mock.patch.object(
                letsinfer,
                "installed_runtime_manifests",
                return_value=[(pathlib.Path("/control/releases/release.json"), release, receipt)],
            ),
            mock.patch.object(
                letsinfer,
                "manifests",
                side_effect=AssertionError("source fixtures must not be listed"),
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(letsinfer.list_releases(argparse.Namespace()), 0)
        self.assertIn("fixture-paired-model-r1", output.getvalue())

    def test_newest_current_runtime_receipt_wins(self) -> None:
        release_path = DWARFSTAR_MANIFEST_PATH
        release = json.loads(release_path.read_text(encoding="utf-8"))
        older_path = pathlib.Path("/control/older/releases/release.json")
        newer_path = pathlib.Path("/control/newer/releases/release.json")
        older = {
            "schema_version": 1,
            "name": "fixture-paired-model/dwarfstar/fixture-unified",
            "installed_at": "2026-08-13T10:00:00-04:00",
        }
        newer = {
            "schema_version": 1,
            "name": "fixture-paired-model/dwarfstar/fixture-unified",
            "installed_at": "2026-08-13T11:00:00-04:00",
        }
        with (
            mock.patch.object(letsinfer, "manifests", return_value=[]),
            mock.patch.object(
                letsinfer,
                "installed_runtime_manifests",
                return_value=[
                    (older_path, release, older),
                    (newer_path, release, newer),
                ],
            ),
        ):
            path, _ = letsinfer.resolve_model(
                "fixture-paired-model", "dwarfstar", target="fixture-unified"
            )
        self.assertEqual(path, newer_path)

    def test_exact_model_alias_wins_over_derived_shared_checkpoint_id(self) -> None:
        release = json.loads(DWARFSTAR_MANIFEST_PATH.read_text(encoding="utf-8"))
        derived = copy.deepcopy(release)
        derived["release"] = "derived-local"
        derived["model"]["alias"] = "derived-model"
        canonical_path = pathlib.Path("/control/canonical/releases/release.json")
        derived_path = pathlib.Path("/control/derived/releases/release.json")
        canonical_receipt = {
            "schema_version": 1,
            "name": "fixture-paired-model/dwarfstar/fixture-unified",
            "installed_at": "2026-08-15T22:00:00-04:00",
        }
        derived_receipt = {
            "schema_version": 1,
            "name": "derived-model/dwarfstar/fixture-unified",
            "installed_at": "2026-08-15T21:00:00-04:00",
        }
        with (
            mock.patch.object(letsinfer, "manifests", return_value=[]),
            mock.patch.object(
                letsinfer,
                "installed_runtime_manifests",
                return_value=[
                    (canonical_path, release, canonical_receipt),
                    (derived_path, derived, derived_receipt),
                ],
            ),
        ):
            path, _ = letsinfer.resolve_model(
                "fixture-paired-model", "dwarfstar", target="fixture-unified"
            )
        self.assertEqual(path, canonical_path)

    def test_derive_cli_keeps_letsinfer_options_before_engine_separator(self) -> None:
        with (
            mock.patch.object(letsinfer, "derive_runtime", return_value=0) as action,
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(letsinfer.command_action("derive"), None),
            ),
        ):
            self.assertEqual(
                letsinfer.main(
                    [
                        "derive",
                        "model/vllm",
                        "--name",
                        "custom",
                        "--without=--old-flag",
                        "--",
                        "--max-num-seqs",
                        "4",
                    ]
                ),
                0,
            )
        parsed = action.call_args.args[0]
        self.assertEqual(parsed.name, "custom")
        self.assertEqual(parsed.without, ["--old-flag"])
        self.assertEqual(parsed.engine_arguments, ["--", "--max-num-seqs", "4"])

    def test_catalog_install_resolution_propagates_target_identity(self) -> None:
        source = "ghcr.io/example/runtime@sha256:" + "a" * 64
        with (
            mock.patch.object(
                letsinfer, "resolved_catalog_location", return_value="catalog.json"
            ),
            mock.patch.object(letsinfer, "load_catalog", return_value={"models": {}}),
            mock.patch.object(
                letsinfer,
                "_catalog_site_release",
                return_value=(
                    ("fixture-target", "b" * 64, "dwarfstar", "1.2.3", source),
                    mock.sentinel.choice,
                ),
            ) as resolve,
        ):
            selected = letsinfer._runtime_source_for_install(
                "fixture-model", None, None
            )

        self.assertEqual(
            selected,
            (source, "recommended", "1.2.3", "fixture-target", "b" * 64),
        )
        resolve.assert_called_once_with({"models": {}}, "fixture-model", None)

    def test_install_target_is_always_resolved_from_the_site(self) -> None:
        root = letsinfer.parser()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            root.parse_args(["install", "example-model", "--target", "machine-a"])
        parsed = root.parse_args(["install", "example-model"])
        self.assertFalse(hasattr(parsed, "target"))

    def test_install_imports_unqualified_runtime_without_activating_it(self) -> None:
        release_path = DWARFSTAR_MANIFEST_PATH
        release = json.loads(release_path.read_text(encoding="utf-8"))
        release["serving"]["qualified"] = False
        release["serving"]["blocked_by"] = "test-qualification-pending"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source"
            source.mkdir()
            runtime = {
                "schema_version": letsinfer.RUNTIME_SCHEMA_VERSION,
                "name": "fixture-paired-model/dwarfstar/fixture-unified",
                "version": "0.1.0",
                "model": "fixture-paired-model",
                "engine": "dwarfstar",
                "target": "fixture-unified",
                "status": "candidate",
                "release_manifest": "release.json",
                "core_compatibility": {"api": 2},
            }
            (source / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
            (source / "release.json").write_text(json.dumps(release), encoding="utf-8")
            arguments = argparse.Namespace(
                model=str(source),
                engine="dwarfstar",
                catalog=None,
                store_root=str(root / "store"),
                runtime_cache_root=str(root / "runtime-cache"),
                api_key_file=str(root / "credentials" / "api-key"),
                tls_cert_file=str(root / "credentials" / "server.crt"),
                tls_key_file=str(root / "credentials" / "server.key"),
            )
            stdout = io.StringIO()
            with (
                mock.patch.dict(
                    "os.environ", {"LETSINFER_RUNTIME_HOME": str(root / "runtimes")}
                ),
                mock.patch.object(
                    letsinfer, "default_control_parent", return_value=root / "control"
                ),
                mock.patch.object(letsinfer, "ensure_install_dependencies") as dependencies,
                mock.patch.object(letsinfer, "install_runtime_plugins") as plugins,
                mock.patch.object(letsinfer, "verify_installed_release") as verified,
                mock.patch.object(letsinfer, "ensure_runtime_home") as runtime_home,
                mock.patch.object(letsinfer, "ensure_api_key") as api_key,
                mock.patch.object(letsinfer, "ensure_tls_material") as tls,
                mock.patch.object(
                    letsinfer,
                    "host_hardware_fingerprint_sha256",
                    return_value="f" * 64,
                ),
                contextlib.redirect_stdout(stdout),
            ):
                self.assertEqual(letsinfer.install(arguments), 0)
                receipt = letsinfer.selections()[0]
            self.assertEqual(
                receipt["name"], "fixture-paired-model/dwarfstar/fixture-unified"
            )
            self.assertEqual(
                receipt["target_contract_sha256"],
                letsinfer.target_contract_sha256(letsinfer.target_contract(release)),
            )
            self.assertIn("activation=blocked", stdout.getvalue())
            dependencies.assert_called_once()
            self.assertTrue(dependencies.call_args.kwargs["download"])
            plugins.assert_called_once()
            verified.assert_called_once()
            runtime_home.assert_called_once()
            api_key.assert_called_once()
            tls.assert_called_once()

    def test_candidate_install_honors_no_download_without_activation(self) -> None:
        release = json.loads(DWARFSTAR_MANIFEST_PATH.read_text(encoding="utf-8"))
        release["serving"]["qualified"] = False
        release["serving"]["blocked_by"] = "test-qualification-pending"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source"
            source.mkdir()
            runtime = {
                "schema_version": letsinfer.RUNTIME_SCHEMA_VERSION,
                "name": "fixture-paired-model/dwarfstar/fixture-unified",
                "version": "0.1.0",
                "model": "fixture-paired-model",
                "engine": "dwarfstar",
                "target": "fixture-unified",
                "status": "candidate",
                "release_manifest": "release.json",
                "core_compatibility": {"api": 2},
            }
            (source / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
            (source / "release.json").write_text(json.dumps(release), encoding="utf-8")
            arguments = argparse.Namespace(
                model=str(source),
                engine="dwarfstar",
                catalog=None,
                download_dependencies=False,
                store_root=str(root / "store"),
                runtime_cache_root=str(root / "runtime-cache"),
                api_key_file=str(root / "credentials" / "api-key"),
                tls_cert_file=str(root / "credentials" / "server.crt"),
                tls_key_file=str(root / "credentials" / "server.key"),
            )
            with (
                mock.patch.dict(
                    "os.environ", {"LETSINFER_RUNTIME_HOME": str(root / "runtimes")}
                ),
                mock.patch.object(
                    letsinfer, "default_control_parent", return_value=root / "control"
                ),
                mock.patch.object(letsinfer, "ensure_install_dependencies") as dependencies,
                mock.patch.object(letsinfer, "install_runtime_plugins"),
                mock.patch.object(letsinfer, "verify_installed_release"),
                mock.patch.object(letsinfer, "ensure_runtime_home"),
                mock.patch.object(letsinfer, "ensure_api_key"),
                mock.patch.object(letsinfer, "ensure_tls_material"),
                mock.patch.object(
                    letsinfer,
                    "host_hardware_fingerprint_sha256",
                    return_value="f" * 64,
                ),
            ):
                self.assertEqual(letsinfer.install(arguments), 0)

            self.assertFalse(dependencies.call_args.kwargs["download"])

    def test_runtime_manifest_can_override_non_core_engine_environment(self) -> None:
        release_path = DWARFSTAR_MANIFEST_PATH
        release = json.loads(release_path.read_text(encoding="utf-8"))
        release["engine"]["environment"] = {
            "DS4_CONT_PREFILL_CHUNK": "6144",
            "DS4_DSPARK_REJECTION_TOP2": "1",
            "DS4_DSPARK_VERIFY_FIT_ROWS": None,
        }
        letsinfer.validate_manifest(release)
        environment = dict(
            letsinfer.launch_for(release, release["serving"], 8000).environment
        )
        self.assertEqual(environment["DS4_CONT_PREFILL_CHUNK"], "6144")
        self.assertEqual(environment["DS4_DSPARK_REJECTION_TOP2"], "1")
        self.assertNotIn("DS4_DSPARK_VERIFY_FIT_ROWS", environment)

    def test_runtime_manifest_owns_native_engine_arguments(self) -> None:
        release = json.loads(VLLM_MANIFEST_PATH.read_text(encoding="utf-8"))
        release["engine"]["arguments"] = [
            "--max-num-seqs",
            "4",
            "--future-parser",
            "fixture-parser",
        ]
        letsinfer.validate_manifest(release)
        command = letsinfer.launch_for(release, release["serving"], 8000).command
        self.assertEqual(command.count("--max-num-seqs"), 1)
        self.assertEqual(command[command.index("--max-num-seqs") + 1], "4")
        self.assertEqual(command[-2:], ("--future-parser", "fixture-parser"))

    def test_runtime_manifest_cannot_change_core_engine_arguments(self) -> None:
        release = json.loads(VLLM_MANIFEST_PATH.read_text(encoding="utf-8"))
        release["engine"]["arguments"] = ["--host", "0.0.0.0"]
        with self.assertRaisesRegex(
            letsinfer.LetsInferError, "Let's Infer-owned engine argument --host"
        ):
            letsinfer.validate_manifest(release)

    def test_runtime_manifest_cannot_override_letsinfer_environment(self) -> None:
        release_path = DWARFSTAR_MANIFEST_PATH
        release = json.loads(release_path.read_text(encoding="utf-8"))
        for name in ("LETSINFER_API_KEY", "DS4_LETSINFER_CACHE_DIR"):
            changed = copy.deepcopy(release)
            changed["engine"]["environment"] = {name: "unsafe"}
            with self.subTest(name=name), self.assertRaisesRegex(
                letsinfer.LetsInferError, "Let's Infer-owned"
            ):
                letsinfer.validate_manifest(changed)

    def test_derive_replaces_appends_and_removes_without_engine_schema(self) -> None:
        parent_path = VLLM_MANIFEST_PATH
        parent = json.loads(parent_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            arguments = argparse.Namespace(
                runtime="fixture-model",
                engine="vllm",
                name="custom-runtime",
                without=["--async-scheduling"],
                port=8000,
                engine_arguments=["--", "--max-num-seqs", "4", "--future-flag"],
            )
            with (
                materialized_release_sources(parent) as source_root,
                mock.patch.dict(
                    "os.environ", {"LETSINFER_RUNTIME_HOME": str(root / "runtimes")}
                ),
                mock.patch.object(
                    letsinfer, "default_control_parent", return_value=root / "control"
                ),
                mock.patch.object(
                    letsinfer,
                    "resolve_model",
                    return_value=(parent_path, parent),
                ),
                mock.patch.object(
                    letsinfer, "manifest_source_root", return_value=source_root
                ),
                mock.patch.object(
                    letsinfer,
                    "host_hardware_fingerprint_sha256",
                    return_value="f" * 64,
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(letsinfer.derive_runtime(arguments), 0)
                receipt = letsinfer.selections()[0]
                manifest = letsinfer.read_json(pathlib.Path(receipt["manifest_path"]))
            launch = letsinfer.launch_for(manifest, manifest["serving"], 8000)
            command = list(launch.command)
            self.assertEqual(command[command.index("--max-num-seqs") + 1], "4")
            self.assertIn("--future-flag", command)
            self.assertNotIn("--async-scheduling", command)
            self.assertFalse(manifest["serving"]["qualified"])

    def test_derive_preserves_dwarfstar_image_and_model_identity(self) -> None:
        parent_path = DWARFSTAR_MANIFEST_PATH
        parent = json.loads(parent_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            arguments = argparse.Namespace(
                runtime="fixture-paired-model",
                engine="dwarfstar",
                name="fixture-paired-model-exact",
                without=[],
                port=8000,
                engine_arguments=[
                    "--",
                    "--kv-disk-dir",
                    "/root/.cache/letsinfer-prefix-store/native-kv",
                    "--kv-disk-space-mb",
                    "8192",
                    "--kv-cache-reject-different-quant",
                ],
            )
            with (
                materialized_release_sources(parent) as source_root,
                mock.patch.dict(
                    "os.environ", {"LETSINFER_RUNTIME_HOME": str(root / "runtimes")}
                ),
                mock.patch.object(
                    letsinfer, "default_control_parent", return_value=root / "control"
                ),
                mock.patch.object(
                    letsinfer,
                    "resolve_model",
                    return_value=(parent_path, parent),
                ),
                mock.patch.object(
                    letsinfer, "manifest_source_root", return_value=source_root
                ),
                mock.patch.object(
                    letsinfer,
                    "host_hardware_fingerprint_sha256",
                    return_value="f" * 64,
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(letsinfer.derive_runtime(arguments), 0)
                receipt = letsinfer.selections()[0]
                manifest = letsinfer.read_json(pathlib.Path(receipt["manifest_path"]))
            self.assertEqual(manifest["image"], parent["image"])
            self.assertEqual(manifest["model"]["id"], parent["model"]["id"])
            self.assertEqual(manifest["artifacts"], parent["artifacts"])
            command = list(
                letsinfer.launch_for(manifest, manifest["serving"], 8000).command
            )
            self.assertIn("--kv-disk-dir", command)
            self.assertIn("--kv-cache-reject-different-quant", command)

    def test_derive_cannot_change_letsinfer_owned_listener(self) -> None:
        parent_path = VLLM_MANIFEST_PATH
        parent = json.loads(parent_path.read_text(encoding="utf-8"))
        arguments = argparse.Namespace(
            runtime="fixture-model",
            engine="vllm",
            name="unsafe",
            without=[],
            port=8000,
            engine_arguments=["--", "--host", "127.0.0.1"],
        )
        with (
            materialized_release_sources(parent) as source_root,
            mock.patch.object(
                letsinfer,
                "resolve_model",
                return_value=(parent_path, parent),
            ),
            mock.patch.object(
                letsinfer, "manifest_source_root", return_value=source_root
            ),
            self.assertRaisesRegex(letsinfer.LetsInferError, "Let's Infer owns"),
        ):
            letsinfer.derive_runtime(arguments)


if __name__ == "__main__":
    unittest.main()
