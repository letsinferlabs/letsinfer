#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Runtime-pack artifact, receipt, catalog, and argv-overlay regressions."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
from unittest import mock

from core import runtime_packs


class RuntimePackTests(unittest.TestCase):
    class _Response:
        def __init__(
            self,
            data: bytes,
            url: str,
            headers: dict[str, str] | None = None,
        ) -> None:
            self._stream = io.BytesIO(data)
            self._url = url
            self.headers = headers or {}

        def __enter__(self) -> "RuntimePackTests._Response":
            return self

        def __exit__(self, *_arguments: object) -> None:
            return None

        def geturl(self) -> str:
            return self._url

        def read(self, size: int = -1) -> bytes:
            return self._stream.read(size)

    def _oci_manifest(self, payload: bytes, *, size: int | None = None) -> bytes:
        return json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.empty.v1+json",
                    "digest": "sha256:" + hashlib.sha256(b"{}").hexdigest(),
                    "size": 2,
                },
                "layers": [
                    {
                        "mediaType": runtime_packs.PACK_MEDIA_TYPE,
                        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                        "size": len(payload) if size is None else size,
                        "annotations": {
                            "org.opencontainers.image.title": "runtime.letsinfer"
                        },
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def test_benchmark_model_identity_binds_exact_file_or_snapshot(self) -> None:
        self.assertEqual(
            runtime_packs.benchmark_model_sha256(
                {
                    "model": {"artifact": "model"},
                    "artifacts": [
                        {
                            "name": "model",
                            "repository": "owner/model",
                            "revision": "b" * 40,
                            "sha256": "a" * 64,
                        }
                    ],
                }
            ),
            "a" * 64,
        )
        snapshot = {
            "model": {"artifact": "model"},
            "artifacts": [
                {
                    "name": "model",
                    "repository": "owner/model",
                    "revision": "b" * 40,
                }
            ],
        }
        expected = hashlib.sha256(
            runtime_packs.canonical_bytes(
                {"repository": "owner/model", "revision": "b" * 40}
            )
        ).hexdigest()
        self.assertEqual(runtime_packs.benchmark_model_sha256(snapshot), expected)

    def test_companion_executable_is_found_beside_installed_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_root = pathlib.Path(directory)
            launcher = bin_root / "letsinfer"
            companion = bin_root / "oras"
            launcher.write_text("launcher\n", encoding="utf-8")
            companion.write_text("tool\n", encoding="utf-8")
            companion.chmod(0o755)
            with mock.patch.dict(
                os.environ, {"LETSINFER_LAUNCHER_DIR": str(bin_root)}
            ), mock.patch.object(
                runtime_packs.sys, "argv", ["-c"]
            ), mock.patch.object(runtime_packs.shutil, "which", return_value=None):
                self.assertEqual(
                    runtime_packs._companion_executable("oras"), str(companion)
                )

    def test_native_public_oci_pull_verifies_manifest_and_layer(self) -> None:
        payload = b"runtime-pack"
        manifest = self._oci_manifest(payload)
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        reference = f"registry.example/owner/runtime@sha256:{manifest_digest}"
        manifest_url = (
            "https://registry.example/v2/owner/runtime/manifests/sha256:"
            + manifest_digest
        )
        challenge = (
            'Bearer realm="https://auth.example/token",'
            'service="registry.example",scope="repository:owner/runtime:pull"'
        )
        unauthorized = urllib.error.HTTPError(
            manifest_url,
            401,
            "unauthorized",
            {"WWW-Authenticate": challenge},
            io.BytesIO(),
        )
        responses = [
            unauthorized,
            self._Response(b'{"token":"public-token"}', "https://auth.example/token"),
            self._Response(manifest, manifest_url),
            self._Response(
                payload,
                "https://objects.example/runtime",
                {"Content-Length": str(len(payload))},
            ),
        ]
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            runtime_packs, "_oci_open", side_effect=responses
        ) as opener:
            destination = pathlib.Path(directory)
            runtime_packs._native_pull_public_oci(reference, destination)
            self.assertEqual((destination / "runtime.letsinfer").read_bytes(), payload)
            retry = opener.call_args_list[2].args[0]
            self.assertEqual(retry.get_header("Authorization"), "Bearer public-token")

    def test_oci_redirect_strips_cross_origin_credentials_and_host(self) -> None:
        source_url = (
            "https://registry.example/v2/owner/runtime/blobs/sha256:abc"
        )
        redirect = urllib.error.HTTPError(
            source_url,
            307,
            "temporary redirect",
            {"Location": "https://objects.example/signed"},
            io.BytesIO(),
        )
        response = self._Response(b"payload", "https://objects.example/signed")
        request = urllib.request.Request(
            source_url,
            headers={
                "Authorization": "Bearer secret",
                "Host": "registry.example",
                "User-Agent": "letsinfer/oci-pull",
            },
        )
        with mock.patch.object(
            runtime_packs._OCI_OPENER, "open", side_effect=[redirect, response]
        ) as opener:
            self.assertIs(runtime_packs._oci_open(request), response)
            redirected = opener.call_args_list[1].args[0]
            headers = {key.lower(): value for key, value in redirected.header_items()}
            self.assertNotIn("authorization", headers)
            self.assertNotIn("host", headers)
            self.assertEqual(headers["user-agent"], "letsinfer/oci-pull")

    def test_oci_redirect_rejects_https_downgrade(self) -> None:
        source_url = (
            "https://registry.example/v2/owner/runtime/blobs/sha256:abc"
        )
        redirect = urllib.error.HTTPError(
            source_url,
            307,
            "temporary redirect",
            {"Location": "http://objects.example/signed"},
            io.BytesIO(),
        )
        with mock.patch.object(
            runtime_packs._OCI_OPENER, "open", side_effect=redirect
        ), self.assertRaisesRegex(
            runtime_packs.RuntimePackError, "redirected away from HTTPS"
        ):
            runtime_packs._oci_open(urllib.request.Request(source_url))

    def test_native_public_oci_pull_rejects_manifest_digest_mismatch(self) -> None:
        payload = b"runtime-pack"
        manifest = self._oci_manifest(payload)
        reference = "registry.example/owner/runtime@sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            runtime_packs,
            "_oci_open",
            return_value=self._Response(
                manifest,
                "https://registry.example/v2/owner/runtime/manifests/sha256:" + "0" * 64,
            ),
        ):
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "manifest digest differs"
            ):
                runtime_packs._native_pull_public_oci(
                    reference, pathlib.Path(directory)
                )

    def test_native_public_oci_pull_rejects_layer_digest_mismatch(self) -> None:
        expected = b"runtime-pack"
        actual = b"runtime-pock"
        manifest = self._oci_manifest(expected)
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        reference = f"registry.example/owner/runtime@sha256:{manifest_digest}"
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            runtime_packs,
            "_oci_open",
            side_effect=[
                self._Response(
                    manifest,
                    "https://registry.example/v2/owner/runtime/manifests/sha256:"
                    + manifest_digest,
                ),
                self._Response(
                    actual,
                    "https://objects.example/runtime",
                    {"Content-Length": str(len(actual))},
                ),
            ],
        ):
            destination = pathlib.Path(directory)
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "layer digest differs"
            ):
                runtime_packs._native_pull_public_oci(reference, destination)
            self.assertFalse((destination / "runtime.letsinfer").exists())
            self.assertFalse((destination / ".runtime.letsinfer.partial").exists())

    def test_native_public_oci_pull_rejects_oversized_layer(self) -> None:
        payload = b"runtime-pack"
        manifest = self._oci_manifest(
            payload, size=runtime_packs.MAX_PACK_BYTES + 1
        )
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        reference = f"registry.example/owner/runtime@sha256:{manifest_digest}"
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            runtime_packs,
            "_oci_open",
            return_value=self._Response(
                manifest,
                "https://registry.example/v2/owner/runtime/manifests/sha256:"
                + manifest_digest,
            ),
        ):
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "layer size is invalid"
            ):
                runtime_packs._native_pull_public_oci(
                    reference, pathlib.Path(directory)
                )

    def test_private_oci_requires_optional_oras_fallback(self) -> None:
        reference = "registry.example/owner/runtime@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            runtime_packs,
            "_native_pull_public_oci",
            side_effect=runtime_packs._OciAuthenticationRequired("private"),
        ), mock.patch.object(
            runtime_packs, "_companion_executable", return_value=None
        ):
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "requires registry authentication"
            ):
                runtime_packs._pull_oci(reference, pathlib.Path(directory))

    def test_private_oci_uses_oras_when_available(self) -> None:
        reference = "registry.example/owner/runtime@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            runtime_packs,
            "_native_pull_public_oci",
            side_effect=runtime_packs._OciAuthenticationRequired("private"),
        ), mock.patch.object(
            runtime_packs, "_companion_executable", return_value="/opt/letsinfer/oras"
        ), mock.patch.object(
            runtime_packs.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ) as run:
            runtime_packs._pull_oci(reference, pathlib.Path(directory))
            self.assertEqual(run.call_args.args[0][0], "/opt/letsinfer/oras")

    def test_production_catalog_and_trust_key_are_zero_configuration_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "LETSINFER_HOME": directory,
                "LETSINFER_CATALOG": "",
                "LETSINFER_CATALOG_PUBLIC_KEY": "",
            },
            clear=False,
        ):
            self.assertEqual(
                runtime_packs.resolved_catalog_location(),
                runtime_packs.DEFAULT_CATALOG_URL,
            )
            public_key = runtime_packs._catalog_public_key(None)
            self.assertEqual(public_key, runtime_packs.BUILTIN_CATALOG_PUBLIC_KEY)
            self.assertTrue(public_key.is_file())

    def _single_placement(self) -> dict[str, object]:
        return {
            "strategy": "single",
            "member_count": 1,
            "engine_strategy": "local",
            "interconnect": {
                "kind": "any",
                "rdma_required": False,
                "minimum_speed_mbps": 0,
                "minimum_mtu": 0,
            },
        }

    def _benchmark(self) -> dict[str, object]:
        return {
            "schema_version": runtime_packs.BENCHMARK_SCHEMA_VERSION,
            "suite": "letsinfer-code-prose-v1",
            "generator": {"id": "letsinfer-code-prose", "version": 2},
            "tokenizer": {
                "capability": "engine-rendered-chat-count-v1",
                "model_sha256": "1" * 64,
                "engine_image_sha256": "2" * 64,
                "render_contract": "openai-chat-user-v1",
            },
            "request": {
                "output_tokens": 128,
                "min_completion_tokens": 1,
                "require_natural_stop": True,
                "temperature": 0,
                "seed": 42,
            },
            "sample_interval_seconds": 5,
            "cases": [
                {
                    "id": "32k",
                    "prompt_tokens": 32768,
                    "concurrencies": [1, 2, 4, 8, 16],
                }
            ],
        }

    def _source(self, root: pathlib.Path) -> pathlib.Path:
        source = root / "source"
        source.mkdir()
        config = {
            "schema_version": runtime_packs.RUNTIME_SCHEMA_VERSION,
            "id": "example-engine--example--model--fixture-unified",
            "version": "1.2.3",
            "logical_model": "example-model",
            "status": "candidate",
            "target": {
                "id": "fixture-unified",
                "platform": "linux/arm64",
                "accelerator": {
                    "vendor": "example",
                    "architecture": "accelerator-v1",
                    "count": 1,
                    "partitioning": "full-device",
                },
                "memory": {"topology": "unified", "minimum_total_gib": 32},
                "placement": self._single_placement(),
            },
            "engine": {
                "id": "example-engine",
                "protocol": {"version": 1},
                "oci": {
                    "reference": "ghcr.io/example/engine@sha256:" + "a" * 64,
                    "immutable_id": "sha256:" + "b" * 64,
                },
                "model_format": "huggingface-snapshot",
                "cache_provider": "example-cache-v1",
                "arguments": [],
                "environment": {},
            },
            "model": {
                "uri": "hf://example/model",
                "artifact": "model",
                "acquisition": {
                    "image": "ghcr.io/example/acquire@sha256:" + "c" * 64
                },
            },
            "artifacts": [
                {
                    "name": "model",
                    "uri": "hf://example/model",
                    "format": "huggingface-snapshot",
                    "revision": "d" * 40,
                }
            ],
            "container": {
                "memory_bytes": 32 * (1 << 30),
                "shm_bytes": 1 << 30,
                "min_available_gib": 16,
                "runtime_min_available_gib": 2,
                "startup_timeout_seconds": 60,
            },
            "cache": {
                "provider": "example-cache-v1",
                "persistent": False,
                "prewarm": False,
                "replay_output_policy": None,
                "config": {},
            },
            "serving": {
                "qualified": False,
                "blocked_by": "fixture-qualification",
                "max_connections": 8,
                "max_active_requests": 4,
                "max_context_tokens": 32768,
            },
            "benchmark": {"contract": self._benchmark(), "record": None},
        }
        (source / "runtime.json").write_text(
            json.dumps(config), encoding="utf-8"
        )
        payload = source / "payload" / "runtime.txt"
        payload.parent.mkdir()
        payload.write_text("synthetic runtime payload\n", encoding="utf-8")
        return source

    def test_archive_is_deterministic_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = self._source(root)
            first = root / "first.letsinfer"
            second = root / "second.letsinfer"
            expected = runtime_packs.build_archive(source, first)
            runtime_packs.build_archive(source, second)
            self.assertEqual(runtime_packs.sha256_file(first), runtime_packs.sha256_file(second))
            with runtime_packs.materialize(first) as installed:
                self.assertEqual(installed.digest, expected.digest)
                self.assertEqual(
                    installed.descriptor["candidate"]["id"],
                    "example-engine--example--model--fixture-unified",
                )

    def test_unsupported_runtime_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(pathlib.Path(directory))
            config_path = source / "runtime.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["schema_version"] = 1
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "unsupported runtime schema_version"
            ):
                runtime_packs.describe_source(source)

    def test_boolean_runtime_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(pathlib.Path(directory))
            config_path = source / "runtime.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["schema_version"] = True
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "unsupported runtime schema_version"
            ):
                runtime_packs.describe_source(source)

    def test_runtime_source_and_descriptor_reject_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(pathlib.Path(directory))
            config_path = source / "runtime.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["source_revision"] = "not-a-core-contract"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "source has unsupported fields"
            ):
                runtime_packs.describe_source(source)

            del config["source_revision"]
            config_path.write_text(json.dumps(config), encoding="utf-8")
            pack = runtime_packs.describe_source(source)
            descriptor = dict(pack.descriptor)
            descriptor["image_source_revision"] = "not-a-core-contract"
            (source / runtime_packs.RUNTIME_DESCRIPTOR).write_bytes(
                runtime_packs.canonical_bytes(descriptor)
            )
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "descriptor fields are invalid"
            ):
                runtime_packs.verify_descriptor(source)

    def test_benchmark_contract_is_declarative_and_strict(self) -> None:
        value = self._benchmark()
        self.assertIs(runtime_packs.validate_benchmark_contract(value), value)
        changed = json.loads(json.dumps(value))
        changed["command"] = ["arbitrary-runtime-script"]
        with self.assertRaisesRegex(
            runtime_packs.RuntimePackError, "must contain exactly"
        ):
            runtime_packs.validate_benchmark_contract(changed)

    def test_benchmark_contract_requires_exact_tokenizer_identity(self) -> None:
        value = self._benchmark()
        value["tokenizer"]["model_sha256"] = "latest"  # type: ignore[index]
        with self.assertRaisesRegex(runtime_packs.RuntimePackError, "must be a SHA-256"):
            runtime_packs.validate_benchmark_contract(value)

    def test_artifact_tampering_and_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = self._source(root)
            with self.assertRaisesRegex(runtime_packs.RuntimePackError, "symlinks"):
                (source / "link").symlink_to(source / "runtime.json")
                runtime_packs.describe_source(source)
            (source / "link").unlink()
            pack = runtime_packs.describe_source(source)
            object_root = runtime_packs.store_pack(pack, root / "runtime-home")
            (object_root / "payload/runtime.txt").chmod(0o755)
            with self.assertRaisesRegex(runtime_packs.RuntimePackError, "identity mismatch"):
                runtime_packs.verify_descriptor(object_root)

    def test_descriptor_requires_current_artifact_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(pathlib.Path(directory))
            pack = runtime_packs.describe_source(source)
            descriptor = dict(pack.descriptor)
            descriptor.pop("artifact_schema_version")
            (source / runtime_packs.RUNTIME_DESCRIPTOR).write_bytes(
                runtime_packs.canonical_bytes(descriptor)
            )
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError,
                "descriptor fields are invalid",
            ):
                runtime_packs.verify_descriptor(source)

    def test_unsupported_artifact_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(pathlib.Path(directory))
            pack = runtime_packs.describe_source(source)
            descriptor = dict(pack.descriptor)
            descriptor["artifact_schema_version"] = 1
            (source / runtime_packs.RUNTIME_DESCRIPTOR).write_bytes(
                runtime_packs.canonical_bytes(descriptor)
            )
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError,
                "unsupported runtime artifact_schema_version",
            ):
                runtime_packs.verify_descriptor(source)

    def test_boolean_artifact_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(pathlib.Path(directory))
            pack = runtime_packs.describe_source(source)
            descriptor = dict(pack.descriptor)
            descriptor["artifact_schema_version"] = True
            (source / runtime_packs.RUNTIME_DESCRIPTOR).write_bytes(
                runtime_packs.canonical_bytes(descriptor)
            )
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError,
                "unsupported runtime artifact_schema_version",
            ):
                runtime_packs.verify_descriptor(source)

    def test_current_descriptor_requires_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(pathlib.Path(directory))
            pack = runtime_packs.describe_source(source)
            descriptor = dict(pack.descriptor)
            descriptor["files"] = [dict(record) for record in pack.descriptor["files"]]
            descriptor["files"][0].pop("mode")
            (source / runtime_packs.RUNTIME_DESCRIPTOR).write_bytes(
                runtime_packs.canonical_bytes(descriptor)
            )
            with self.assertRaisesRegex(runtime_packs.RuntimePackError, "mode must be"):
                runtime_packs.verify_descriptor(source)

    def test_pack_rejects_invalid_public_benchmark_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = self._source(root)
            benchmark_path = source / "benchmark.json"
            benchmark_path.write_text("{}\n", encoding="utf-8")
            config_path = source / "runtime.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["benchmark"]["record"] = {
                "path": "benchmark.json",
                "sha256": runtime_packs.sha256_file(benchmark_path),
                "id": "0" * 64,
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "invalid runtime benchmark record"
            ):
                runtime_packs.build_archive(source, root / "runtime.letsinfer")

    def test_archive_member_count_is_bounded_during_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive_path = root / "oversized.letsinfer"
            with tarfile.open(archive_path, "w") as archive:
                for name in ("one", "two", "three"):
                    info = tarfile.TarInfo(name)
                    info.size = 1
                    archive.addfile(info, io.BytesIO(b"x"))
            destination = root / "unpacked"
            destination.mkdir()
            with (
                mock.patch.object(runtime_packs, "MAX_PACK_FILES", 1),
                self.assertRaisesRegex(runtime_packs.RuntimePackError, "exceeds 2 members"),
            ):
                runtime_packs._extract_archive(archive_path, destination)

    def test_selection_retains_bounded_rollback_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = pathlib.Path(directory)
            installed_at_ns = 1_786_900_000_000_000_000
            hardware_sha = "3" * 64
            base = {
                "schema_version": runtime_packs.SELECTION_SCHEMA_VERSION,
                "candidate_id": "example-engine--example--model--fixture-unified",
                "logical_model": "example-model",
                "engine": "example-engine",
                "target": "fixture-unified",
                "target_contract_sha256": "4" * 64,
                "version": "1.0.0",
                "digest": "1" * 64,
                "object_root": "/objects/one",
                "manifest_path": "/objects/one/runtime.json",
                "control_root": "/control/one",
                "installed_at": "2026-08-13T00:00:00-04:00",
                "installed_at_unix_ns": installed_at_ns,
                "hardware_fingerprint_sha256": hardware_sha,
                "installation_id": runtime_packs.installation_identity(
                    hardware_sha, "1" * 64, installed_at_ns
                ),
                "policy": "recommended",
                "source": "registry/one@sha256:" + "1" * 64,
                "history": [],
            }
            with mock.patch.object(runtime_packs, "_publish_candidate_view"):
                runtime_packs.write_selection(base, home)
            replacement = dict(base)
            replacement.update(
                {
                    "version": "2.0.0",
                    "digest": "2" * 64,
                    "object_root": "/objects/two",
                    "manifest_path": "/objects/two/runtime.json",
                    "control_root": "/control/two",
                    "source": "registry/two@sha256:" + "2" * 64,
                    "installation_id": runtime_packs.installation_identity(
                        hardware_sha, "2" * 64, installed_at_ns
                    ),
                }
            )
            with mock.patch.object(runtime_packs, "_publish_candidate_view"):
                runtime_packs.write_selection(replacement, home)
            selected = runtime_packs.selections(home)[0]
            self.assertEqual(selected["digest"], "2" * 64)
            self.assertEqual(selected["history"][-1]["digest"], "1" * 64)

    def test_installation_identity_binds_hardware_runtime_and_timestamp(self) -> None:
        first = runtime_packs.installation_identity("1" * 64, "2" * 64, 3)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            first,
            runtime_packs.installation_identity("1" * 64, "2" * 64, 4),
        )
        self.assertNotEqual(
            first,
            runtime_packs.installation_identity("4" * 64, "2" * 64, 3),
        )

    def test_catalog_requires_digest_pinned_variants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "catalog.json"
            catalog = {
                "schema_version": runtime_packs.CATALOG_SCHEMA_VERSION,
                "targets": {
                    "fixture-unified": {
                        "match": {
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
                                "minimum_total_gib": 32,
                            },
                            "placement": self._single_placement(),
                        }
                    }
                },
                "models": {
                    "example-model": {
                        "targets": {
                            "fixture-unified": {
                                "recommended": "example-engine--example--model--fixture-unified",
                                "candidates": {
                                    "example-engine--example--model--fixture-unified": {
                                        "version": "1.2.3",
                                        "source": "ghcr.io/example/model@sha256:" + "a" * 64,
                                        "qualified": True,
                                        "engine": "example-engine",
                                        "engine_oci": "ghcr.io/example/engine@sha256:" + "b" * 64,
                                        "model_uri": "hf://example/model",
                                        "benchmark": {
                                            "id": "c" * 64,
                                            "suite": "letsinfer-code-prose-v1",
                                            "score": 1.0,
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
            path.write_text(json.dumps(catalog), encoding="utf-8")
            loaded = runtime_packs.load_catalog(str(path))
            self.assertEqual(
                runtime_packs.compatible_catalog_targets(
                    loaded,
                    {
                        "platform": "linux/arm64",
                        "accelerator": {
                            "vendor": "example",
                            "architecture": "accelerator-v1",
                            "count": 1,
                            "partitioning": "full-device",
                        },
                        "memory": {"topology": "unified", "total_gib": 64},
                    },
                ),
                ["fixture-unified"],
            )
            self.assertEqual(
                runtime_packs.catalog_release(
                    loaded,
                    "example-model",
                    None,
                    device={
                        "platform": "linux/arm64",
                        "accelerator": {
                            "vendor": "example",
                            "architecture": "accelerator-v1",
                            "count": 1,
                            "partitioning": "full-device",
                        },
                        "memory": {"topology": "unified", "total_gib": 64},
                    },
                ),
                (
                    "fixture-unified",
                    runtime_packs.target_contract_sha256(
                        catalog["targets"]["fixture-unified"]["match"]
                    ),
                    "example-engine--example--model--fixture-unified",
                    "1.2.3",
                    "ghcr.io/example/model@sha256:" + "a" * 64,
                ),
            )
            catalog["models"]["example-model"]["targets"]["fixture-unified"]["candidates"][
                "example-engine--example--model--fixture-unified"
            ]["source"] = "latest"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(runtime_packs.RuntimePackError, "digest-pinned"):
                runtime_packs.load_catalog(str(path))

    def test_unsupported_catalog_schema_is_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "catalog.json"
            path.write_text(
                json.dumps({"schema_version": 2, "models": {}}), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "unsupported runtime catalog"
            ):
                runtime_packs.load_catalog(str(path))

            path.write_text(
                json.dumps({"schema_version": True, "targets": {}, "models": {}}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "unsupported runtime catalog"
            ):
                runtime_packs.load_catalog(str(path))

    def test_signed_catalog_binds_exact_bytes_and_trusted_ed25519_key(self) -> None:
        catalog = {
            "schema_version": runtime_packs.CATALOG_SCHEMA_VERSION,
            "targets": {
                "fixture-unified": {
                    "match": {
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
                            "minimum_total_gib": 32,
                        },
                        "placement": self._single_placement(),
                    }
                }
            },
            "models": {
                "example-model": {
                    "targets": {
                        "fixture-unified": {
                            "recommended": "example-engine--example--model--fixture-unified",
                            "candidates": {
                                "example-engine--example--model--fixture-unified": {
                                    "version": "1.0.0",
                                    "source": "registry.example/runtime@sha256:" + "a" * 64,
                                    "qualified": True,
                                    "engine": "example-engine",
                                    "engine_oci": "registry.example/engine@sha256:" + "b" * 64,
                                    "model_uri": "hf://example/model",
                                    "benchmark": {
                                        "id": "c" * 64,
                                        "suite": "letsinfer-code-prose-v1",
                                        "score": 1.0,
                                    },
                                }
                            },
                        }
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "catalog.json"
            private_key = root / "catalog.key"
            public_key = root / "catalog.pub"
            signature = root / "catalog.raw.sig"
            path.write_bytes(runtime_packs.canonical_bytes(catalog))
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl", "pkey", "-in", str(private_key), "-pubout",
                    "-out", str(public_key),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign", "-inkey", str(private_key),
                    "-rawin", "-in", str(path), "-out", str(signature),
                ],
                check=True,
                capture_output=True,
            )
            public_der = subprocess.run(
                [
                    "openssl", "pkey", "-pubin", "-in", str(public_key),
                    "-outform", "DER",
                ],
                check=True,
                capture_output=True,
            ).stdout
            (root / "catalog.json.sig").write_bytes(
                runtime_packs.canonical_bytes(
                    {
                        "schema_version": 1,
                        "algorithm": "ed25519",
                        "key_id_sha256": hashlib.sha256(public_der).hexdigest(),
                        "catalog_sha256": runtime_packs.sha256_file(path),
                        "signature_base64": base64.b64encode(
                            signature.read_bytes()
                        ).decode("ascii"),
                    }
                )
            )
            self.assertEqual(
                runtime_packs.load_catalog(str(path), public_key=str(public_key)),
                catalog,
            )
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "content identity differs"
            ):
                runtime_packs.load_catalog(str(path), public_key=str(public_key))

    def test_remote_catalog_requires_valid_detached_signature(self) -> None:
        class Response:
            def __init__(self, url: str, data: bytes) -> None:
                self.url = url
                self.data = data

            def __enter__(self):
                return self

            def __exit__(self, *_arguments):
                return False

            def geturl(self) -> str:
                return self.url

            def read(self, _limit: int) -> bytes:
                return self.data

        location = "https://catalog.example/catalog.json"
        responses = [Response(location, b"{}"), Response(location + ".sig", b"{}")]
        with (
            mock.patch.object(
                runtime_packs.urllib.request, "urlopen", side_effect=responses
            ),
            self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "signature schema is unsupported"
            ),
        ):
            runtime_packs.load_catalog(location)

    def test_catalog_rejects_embedded_or_unknown_model_targets(self) -> None:
        contract = {
            "id": "fixture-unified",
            "platform": "linux/arm64",
            "accelerator": {
                "vendor": "example",
                "architecture": "accelerator-v1",
                "count": 1,
                "partitioning": "full-device",
            },
            "memory": {"topology": "unified", "minimum_total_gib": 32},
            "placement": self._single_placement(),
        }
        catalog = {
            "schema_version": runtime_packs.CATALOG_SCHEMA_VERSION,
            "targets": {"fixture-unified": {"match": contract}},
            "models": {
                "example-model": {
                    "targets": {
                        "missing-target": {
                            "recommended": "example-engine",
                            "engines": {
                                "example-engine": {
                                    "version": "1.0.0",
                                    "source": "registry/runtime@sha256:" + "a" * 64,
                                }
                            },
                        }
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(runtime_packs.RuntimePackError, "unknown target"):
                runtime_packs.load_catalog(str(path))

    def test_catalog_target_identity_is_canonical_and_model_independent(self) -> None:
        contract = {
            "id": "fixture-discrete-dual",
            "platform": "linux/amd64",
            "accelerator": {
                "vendor": "example",
                "architecture": "accelerator-v2",
                "count": 2,
                "partitioning": "full-device",
                "minimum_memory_gib": 31,
            },
            "memory": {"topology": "discrete", "minimum_total_gib": 64},
            "placement": self._single_placement(),
        }
        digest = runtime_packs.target_contract_sha256(contract)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        changed = json.loads(json.dumps(contract))
        changed["memory"]["minimum_total_gib"] = 65
        self.assertNotEqual(digest, runtime_packs.target_contract_sha256(changed))

    def test_automatic_catalog_resolution_rejects_ambiguous_targets(self) -> None:
        device = {
            "platform": "linux/arm64",
            "accelerator": {
                "vendor": "example",
                "architecture": "accelerator-v1",
                "count": 1,
                "partitioning": "full-device",
            },
            "memory": {"topology": "unified", "total_gib": 64},
        }
        base_contract = {
            "platform": device["platform"],
            "accelerator": device["accelerator"],
            "memory": {"topology": "unified", "minimum_total_gib": 32},
            "placement": self._single_placement(),
        }
        catalog = {
            "schema_version": runtime_packs.CATALOG_SCHEMA_VERSION,
            "targets": {
                target: {
                    "match": {"id": target, **json.loads(json.dumps(base_contract))}
                }
                for target in ("fixture-a", "fixture-b")
            },
            "models": {
                "example-model": {
                    "targets": {
                        target: {
                            "recommended": "example-engine",
                            "engines": {
                                "example-engine": {
                                    "version": "1.0.0",
                                    "source": "registry/runtime@sha256:" + digest * 64,
                                }
                            },
                        }
                        for target, digest in (("fixture-a", "a"), ("fixture-b", "b"))
                    }
                }
            },
        }
        with self.assertRaisesRegex(runtime_packs.RuntimePackError, "ambiguous"):
            runtime_packs.catalog_release(catalog, "example-model", None, device=device)

    def test_target_matching_covers_discrete_multi_gpu_contracts(self) -> None:
        contract = {
            "id": "fixture-discrete-dual",
            "platform": "linux/amd64",
            "accelerator": {
                "vendor": "example",
                "architecture": "accelerator-v2",
                "count": 2,
                "partitioning": "full-device",
                "minimum_memory_gib": 31,
            },
            "memory": {"topology": "discrete", "minimum_total_gib": 64},
            "placement": self._single_placement(),
        }
        device = {
            "platform": "linux/amd64",
            "accelerator": {
                "vendor": "example",
                "architecture": "accelerator-v2",
                "count": 2,
                "partitioning": "full-device",
                "minimum_memory_gib": 31,
            },
            "memory": {"topology": "discrete", "total_gib": 96},
        }
        self.assertTrue(runtime_packs.target_matches(contract, device))
        device["accelerator"]["count"] = 1
        self.assertFalse(runtime_packs.target_matches(contract, device))

        for path in (("accelerator", "count"), ("memory", "total_gib")):
            invalid = copy.deepcopy(device)
            invalid["accelerator"]["count"] = 2
            invalid[path[0]][path[1]] = True
            with self.subTest(path=path):
                self.assertFalse(runtime_packs.target_matches(contract, invalid))


if __name__ == "__main__":
    unittest.main()
