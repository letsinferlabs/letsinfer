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
from unittest import mock

from core import runtime_packs


class RuntimePackTests(unittest.TestCase):
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

    def test_production_catalog_and_trust_key_are_zero_configuration_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "LETSINFER_CONFIG_HOME": directory,
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
            "generator": {"id": "letsinfer-code-prose", "version": 1},
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
            "name": "example-model/example-engine/fixture-unified",
            "version": "1.2.3",
            "model": "example-model",
            "engine": "example-engine",
            "target": "fixture-unified",
            "status": "stable",
            "release_manifest": "release.json",
            "core_compatibility": {"api": 2},
        }
        (source / "runtime.json").write_text(
            json.dumps(config), encoding="utf-8"
        )
        (source / "release.json").write_text("{}\n", encoding="utf-8")
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
                    installed.descriptor["name"], "example-model/example-engine/fixture-unified"
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

    def test_boolean_runtime_versions_and_compatibility_are_rejected(self) -> None:
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

            config["schema_version"] = runtime_packs.RUNTIME_SCHEMA_VERSION
            config["core_compatibility"]["api"] = True
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "core_compatibility.api"
            ):
                runtime_packs.describe_source(source)

            config["core_compatibility"]["api"] = 1
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "must be 2"
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
                runtime_packs.RuntimePackError, "descriptor has unsupported fields"
            ):
                runtime_packs.verify_descriptor(source)

    def test_derived_parent_identity_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(pathlib.Path(directory))
            config_path = source / "runtime.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["parent"] = {
                "release": "parent-r1",
                "manifest_sha256": "a" * 64,
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            runtime_packs.describe_source(source)

            config["parent"]["mutable_ref"] = "latest"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "must contain exactly"
            ):
                runtime_packs.describe_source(source)

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
                (source / "link").symlink_to(source / "release.json")
                runtime_packs.describe_source(source)
            (source / "link").unlink()
            pack = runtime_packs.describe_source(source)
            object_root = runtime_packs.store_pack(pack, root / "runtime-home")
            (object_root / "release.json").chmod(0o755)
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
                "artifact_schema_version",
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
            (source / "benchmark.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "invalid runtime benchmark.json"
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
                "name": "example-model/example-engine/fixture-unified",
                "model": "example-model",
                "engine": "example-engine",
                "target": "fixture-unified",
                "target_contract_sha256": "4" * 64,
                "version": "1.0.0",
                "digest": "1" * 64,
                "object_root": "/objects/one",
                "manifest_path": "/control/one/releases/release.json",
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
            runtime_packs.write_selection(base, home)
            replacement = dict(base)
            replacement.update(
                {
                    "version": "2.0.0",
                    "digest": "2" * 64,
                    "object_root": "/objects/two",
                    "manifest_path": "/control/two/releases/release.json",
                    "control_root": "/control/two",
                    "source": "registry/two@sha256:" + "2" * 64,
                    "installation_id": runtime_packs.installation_identity(
                        hardware_sha, "2" * 64, installed_at_ns
                    ),
                }
            )
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
                                "recommended": "example-engine",
                                "engines": {
                                    "example-engine": {
                                        "version": "1.2.3",
                                        "source": "ghcr.io/example/model@sha256:" + "a" * 64,
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
                    "example-engine",
                    "1.2.3",
                    "ghcr.io/example/model@sha256:" + "a" * 64,
                ),
            )
            catalog["models"]["example-model"]["targets"]["fixture-unified"]["engines"][
                "example-engine"
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
                            "recommended": "example-engine",
                            "engines": {
                                "example-engine": {
                                    "version": "1.0.0",
                                    "source": "registry.example/runtime@sha256:" + "a" * 64,
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


class ArgumentOverlayTests(unittest.TestCase):
    def test_replace_repeat_remove_and_append(self) -> None:
        parent = runtime_packs.overlay_clauses(
            [
                "--max-num-seqs",
                "1",
                "--lora",
                "a",
                "--lora",
                "b",
                "--enable-prefix-caching",
            ]
        )
        supplied = runtime_packs.overlay_clauses(
            ["--max-num-seqs", "4", "--lora", "c", "--future-flag"]
        )
        resolved, difference = runtime_packs.apply_overlay(
            parent,
            supplied,
            ["--enable-prefix-caching"],
        )
        self.assertEqual(
            runtime_packs.flatten_clauses(resolved),
            ("--max-num-seqs", "4", "--lora", "c", "--future-flag"),
        )
        self.assertEqual(difference["removed"], [["--enable-prefix-caching"]])
        self.assertEqual(difference["added"], [["--future-flag"]])
        self.assertEqual(len(difference["replaced"]), 2)

    def test_short_options_replace_without_treating_negative_values_as_flags(self) -> None:
        parent = runtime_packs.overlay_clauses(
            ["-ngl", "99", "--rope-scale", "-1", "-fa"]
        )
        supplied = runtime_packs.overlay_clauses(["-ngl", "80", "-ctk", "q8_0"])
        resolved, difference = runtime_packs.apply_overlay(parent, supplied, ["-fa"])
        self.assertEqual(
            runtime_packs.flatten_clauses(resolved),
            ("-ngl", "80", "--rope-scale", "-1", "-ctk", "q8_0"),
        )
        self.assertEqual(difference["removed"], [["-fa"]])
        self.assertEqual(difference["added"], [["-ctk", "q8_0"]])

    def test_without_conflict_and_ambiguous_value_guidance(self) -> None:
        supplied = runtime_packs.overlay_clauses(["--feature"])
        with self.assertRaisesRegex(runtime_packs.RuntimePackError, "supplied and removed"):
            runtime_packs.apply_overlay([], supplied, ["--feature"])
        with self.assertRaisesRegex(runtime_packs.RuntimePackError, "unexpected"):
            runtime_packs.overlay_clauses(["value", "--feature"])


if __name__ == "__main__":
    unittest.main()
