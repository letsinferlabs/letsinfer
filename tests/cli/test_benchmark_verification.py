#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Community benchmark-verification contract regressions."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

from benchmarks import benchmark_record
from core import benchmark_verification as verification
from core import cli, runtime_packs
from tests.runtime_fixture import runtime_candidate


class BenchmarkVerificationTests(unittest.TestCase):
    def _pr(self) -> verification.PullRequest:
        return verification.PullRequest(
            123,
            "https://github.com/letsinferlabs/runtimes/pull/123",
            "OPEN",
            "main",
            "b" * 40,
            "a" * 40,
            verification.GitHubIdentity("Author", 41, "User"),
            ("sglang--owner--model--dgx-spark/runtime.json",),
        )

    def _benchmark(self, identity: str, multiplier: float = 1.0) -> dict:
        rows = []
        for domain, value in (("code", 30.0), ("prose", 60.0)):
            rows.append(
                {
                    "workload": "pp32768,tg128,c1",
                    "prompt_domain": domain,
                    "prompt_suite": "letsinfer-code-prose-v1",
                    "prompt_set_sha256": "8" * 64,
                    "actual_prompt_tokens": [32711],
                    "is_prefix_cached": False,
                    "aggregate_tps": value * multiplier,
                    "decode_tps": value * multiplier,
                    "ttft_seconds": 30.0,
                    "ttft_statistic": "single",
                    "ttft_p95_seconds": None,
                    "max_gpu_usage_percent": 96.0,
                    "max_gpu_temperature_c": 64.0,
                    "max_cpu_temperature_c": 62.0,
                    "max_cpu_usage_percent": 8.0,
                    "max_cpu_clock_mhz": 3900.0,
                    "max_gpu_clock_mhz": 2500.0,
                    "max_vram_clock_mhz": -1,
                    "max_system_ram_clock_mhz": -1,
                    "max_nvme_usage_percent": 20.0,
                    "max_nvme_temperature_c": 44.0,
                    "max_nvme_read_kib_per_second": 10.0,
                    "max_nvme_write_kib_per_second": 5.0,
                    "telemetry": {
                        "interval_seconds": 1,
                        "columns": benchmark_record.TELEMETRY_COLUMNS,
                        "samples": [
                            "0,96,64,8,62,3900,2500,-1,-1,20,44,10,5"
                        ],
                    },
                }
            )
        results_sha = benchmark_record.results_sha256(rows)
        subject = {
            "candidate_id": "sglang--owner--model--dgx-spark",
            "runtime_version": "1.2.3",
            "model_uri": "hf://owner/model",
            "model_revision": "9" * 40,
            "engine_oci": "ghcr.io/letsinferlabs/engines/test@sha256:" + identity * 64,
            "target": "dgx-spark",
            "target_contract_sha256": "5" * 64,
        }
        timestamp_ns = 1_787_465_000_000_000_000
        installation = "6" * 64
        contract = "4" * 64
        return {
            "schema_version": 4,
            "id": benchmark_record.benchmark_id(
                installation, timestamp_ns, subject, contract, results_sha
            ),
            "installation_id": installation,
            "timestamp": timestamp_ns // 1_000_000_000,
            "timestamp_unix_ns": timestamp_ns,
            "subject": subject,
            "benchmark_contract_sha256": contract,
            "results_sha256": results_sha,
            "results": rows,
        }

    def _subject(self) -> dict:
        subject = {
            "candidate_id": "sglang--owner--model--dgx-spark",
            "runtime_version": "1.2.3",
            "runtime_pack_sha256": "1" * 64,
            "runtime_oci_manifest_digest": "sha256:" + "2" * 64,
            "engine_oci_manifest_digest": "sha256:" + "3" * 64,
            "model_revisions": [],
            "benchmark_contract_sha256": "4" * 64,
            "target_contract_sha256": "5" * 64,
        }
        subject["execution_sha256"] = verification.sha256_bytes(
            verification.canonical_bytes(subject)
        )
        return subject

    def test_pr_url_and_candidate_selection_are_exact(self) -> None:
        pr = self._pr()
        self.assertEqual(verification.parse_pr_url(pr.url), 123)
        self.assertEqual(
            verification.select_candidate(pr, None),
            "sglang--owner--model--dgx-spark",
        )
        with self.assertRaisesRegex(verification.VerificationError, "requires an open"):
            verification.parse_pr_url("https://github.com/other/repo/pull/123")

    def test_archive_extraction_rejects_links_and_traversal(self) -> None:
        for name, link in (("../escape", False), ("repo/link", True)):
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode="w:gz") as archive:
                item = tarfile.TarInfo(name)
                if link:
                    item.type = tarfile.SYMTYPE
                    item.linkname = "/etc/passwd"
                    archive.addfile(item)
                else:
                    data = b"bad"
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
            payload.seek(0)
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(verification.VerificationError):
                    verification.extract_repository_archive(
                        payload, pathlib.Path(temporary) / "out"
                    )

    def test_deterministic_oci_identity_changes_with_pack(self) -> None:
        first = verification.runtime_oci_manifest_digest(
            candidate="sglang--owner--model--dgx-spark",
            version="1.2.3",
            pack_sha256="1" * 64,
            pack_bytes=100,
        )
        second = verification.runtime_oci_manifest_digest(
            candidate="sglang--owner--model--dgx-spark",
            version="1.2.3",
            pack_sha256="2" * 64,
            pack_bytes=100,
        )
        self.assertRegex(first, r"sha256:[0-9a-f]{64}")
        self.assertNotEqual(first, second)

    def test_signed_comment_round_trips_full_paired_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = verification.device_identity(pathlib.Path(temporary) / "identity")
            record = verification.verification_record(
                pr=self._pr(),
                verifier=verification.GitHubIdentity("Verifier", 99, "User"),
                device=device,
                subject=self._subject(),
                candidate_benchmark=self._benchmark("a", 1.1),
                baseline_benchmark=self._benchmark("b"),
                restoration={"passed": True, "resident_runtime_digest": "7" * 64},
            )
            body = verification.build_comment(record, device)
            envelope, expanded = verification.parse_comment(body)
        self.assertLessEqual(len(body.encode("utf-8")), 60_000)
        self.assertEqual(expanded, record)
        self.assertEqual(envelope["github_id"], 99)
        self.assertAlmostEqual(
            record["run_score"]["overall"]["change_percent"], 10.0
        )

    def test_comment_tampering_breaks_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = verification.device_identity(pathlib.Path(temporary) / "identity")
            record = verification.verification_record(
                pr=self._pr(),
                verifier=verification.GitHubIdentity("Verifier", 99, "User"),
                device=device,
                subject=self._subject(),
                candidate_benchmark=self._benchmark("a"),
                baseline_benchmark=self._benchmark("b"),
                restoration={"passed": True},
            )
            body = verification.build_comment(record, device)
        marker = f"<!-- {verification.COMMENT_MARKER}\n"
        start = body.index(marker) + len(marker)
        end = body.index("\n-->\n", start)
        envelope = json.loads(body[start:end])
        envelope["github_id"] = 100
        tampered = (
            body[:start]
            + json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            + body[end:]
        )
        with self.assertRaisesRegex(verification.VerificationError, "signature"):
            verification.parse_comment(tampered)

    def test_signed_blocking_failure_round_trips_without_fake_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = verification.device_identity(pathlib.Path(temporary) / "identity")
            record = verification.verification_record(
                pr=self._pr(),
                verifier=verification.GitHubIdentity("Verifier", 99, "User"),
                device=device,
                subject=self._subject(),
                candidate_benchmark=None,
                baseline_benchmark=self._benchmark("b"),
                restoration={"passed": True},
                failure={
                    "category": "out_of_memory",
                    "phase": "benchmark:candidate",
                    "message": "candidate exhausted accelerator memory",
                },
            )
            body = verification.build_comment(record, device)
            _envelope, expanded = verification.parse_comment(body)
        self.assertIsNone(expanded["candidate"])
        self.assertIsNone(expanded["run_score"])
        self.assertFalse(expanded["safety"]["passed"])
        self.assertIn("blocking failure", body)

    def test_declared_runtime_author_is_informational(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = verification.device_identity(pathlib.Path(temporary) / "identity")
            record = verification.verification_record(
                pr=self._pr(),
                verifier=verification.GitHubIdentity("RuntimeAuthor", 99, "User"),
                device=device,
                subject=self._subject(),
                candidate_benchmark=self._benchmark("a"),
                baseline_benchmark=self._benchmark("b"),
                restoration={"passed": True},
                runtime_author_ids={99},
            )
        self.assertFalse(record["counts_toward_consensus"])

    def test_noninteractive_gh_preflight_never_installs(self) -> None:
        with (
            mock.patch.object(verification, "gh_version", return_value=None),
            mock.patch.object(
                verification, "gh_install_command", return_value=["brew", "install", "gh"]
            ),
            mock.patch.object(verification, "_run") as run,
        ):
            with self.assertRaisesRegex(verification.VerificationError, "run `brew install gh`"):
                verification.ensure_gh(interactive=False, install=True)
        run.assert_not_called()

    def test_gh_preflight_rejects_cli_before_attestation_security_fix(self) -> None:
        with mock.patch.object(
            verification, "gh_version", return_value=(2, 96, 0)
        ), self.assertRaisesRegex(
            verification.VerificationError, "2.97.0 or newer"
        ):
            verification.ensure_gh(interactive=False)

    def test_every_verifier_payload_requires_trusted_finalizer_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for name in ("bundle.json", "runtime.letsinfer"):
                (root / name).write_bytes(name.encode())
            with mock.patch.dict(
                os.environ, {"LETSINFER_ATTESTATION_TOKEN": "attestation-token"}
            ), mock.patch.object(verification, "_run") as run:
                verification.verify_bundle_attestations(root, gh="/usr/bin/gh")
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            command = call.args[0]
            self.assertEqual(command[:3], ["/usr/bin/gh", "attestation", "verify"])
            self.assertIn("--repo", command)
            self.assertIn(verification.REPOSITORY, command)
            self.assertIn("--cert-identity", command)
            self.assertIn(verification.FINALIZER_CERT_IDENTITY, command)
            self.assertEqual(
                call.kwargs["environment"]["GH_TOKEN"], "attestation-token"
            )

    def _reuse_bundle(self, root: pathlib.Path) -> tuple[pathlib.Path, verification.PullRequest]:
        source = root / "source"
        source.mkdir()
        runtime = runtime_candidate()
        (source / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
        pack = root / "runtime.letsinfer"
        runtime_packs.build_archive(source, pack)
        pack_sha = verification.sha256_file(pack)
        subject = verification.execution_subject(
            runtime, pack_sha256=pack_sha, pack_bytes=pack.stat().st_size
        )
        subject.pop("execution_sha256")
        subject.update(
            {
                "artifact_schema_version": 1,
                "repository": verification.REPOSITORY,
                "pull_request": 123,
                "proposal_head_sha": "a" * 40,
                "proposal_base_sha": "b" * 40,
                "proposal_tree_sha256": "b" * 64,
                "engine_mode": "reuse-engine",
                "build_workflow_run_id": 11,
            }
        )
        subject["execution_sha256"] = verification.sha256_bytes(
            verification.canonical_bytes(subject)
        )
        config = json.dumps(
            {
                "candidate": runtime["id"],
                "media_type": runtime_packs.PACK_MEDIA_TYPE,
                "schema_version": 1,
                "version": runtime["version"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        manifest_digest = subject["runtime_oci_manifest_digest"]
        plan = {
            "candidate": runtime["id"],
            "version": runtime["version"],
            "tag": f"ghcr.io/letsinferlabs/runtimes/{runtime['id']}:{runtime['id']}-{runtime['version']}",
            "source": f"ghcr.io/letsinferlabs/runtimes/{runtime['id']}@{manifest_digest}",
            "manifest_digest": manifest_digest,
            "manifest_bytes": 0,
            "config_digest": "sha256:" + hashlib.sha256(config).hexdigest(),
            "layer_digest": "sha256:" + pack_sha,
            "layer_bytes": pack.stat().st_size,
        }
        bundle_root = root / "bundle"
        bundle_root.mkdir()
        pack.replace(bundle_root / "runtime.letsinfer")
        engine = {
            "mode": "reuse-engine",
            "reference": runtime["engine"]["oci"]["reference"],
            "config_digest": runtime["engine"]["oci"]["immutable_id"],
        }
        payloads = {
            "runtime-plan.json": verification.canonical_bytes(plan),
            "candidate-audit.json": b"{}\n",
            "runtime.spdx.json": b"{}\n",
            "provenance.json": verification.canonical_bytes(
                {"subject": subject, "engine": engine}
            ),
        }
        for name, data in payloads.items():
            (bundle_root / name).write_bytes(data)
        names = {
            "runtime.letsinfer",
            "runtime-plan.json",
            "candidate-audit.json",
            "runtime.spdx.json",
            "provenance.json",
        }
        checksums = {
            name: {
                "sha256": verification.sha256_file(bundle_root / name),
                "bytes": (bundle_root / name).stat().st_size,
            }
            for name in sorted(names)
        }
        (bundle_root / "checksums.json").write_bytes(
            verification.canonical_bytes(checksums)
        )
        document = {
            "schema_version": 1,
            "repository": verification.REPOSITORY,
            "pull_request": 123,
            "proposal_head_sha": "a" * 40,
            "proposal_base_sha": "b" * 40,
            "proposal_tree_sha256": "b" * 64,
            "candidate": runtime["id"],
            "runtime_authors": [
                {"github_login": "Author", "github_id": 41, "github_type": "User"}
            ],
            "mode": "reuse-engine",
            "artifact_name": f"verification-bundle-pr-123-{'a' * 40}",
            "build_workflow": {"path": ".github/workflows/build-verifier.yml", "run_id": 11, "workflow_sha": "b" * 40},
            "finalizer_workflow": {"path": ".github/workflows/finalize-verifier.yml", "run_id": 12, "workflow_sha": "c" * 40},
            "subject": subject,
            "engine": engine,
            "runtime": plan,
            "checksums_sha256": verification.sha256_file(bundle_root / "checksums.json"),
        }
        (bundle_root / "bundle.json").write_bytes(
            verification.canonical_bytes(document)
        )
        pr = verification.PullRequest(
            123,
            "https://github.com/letsinferlabs/runtimes/pull/123",
            "OPEN",
            "main",
            "b" * 40,
            "a" * 40,
            verification.GitHubIdentity("Author", 41, "User"),
            (f"{runtime['id']}/runtime.json",),
        )
        return bundle_root, pr

    def test_verifier_bundle_is_exact_and_tamper_evident(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, pr = self._reuse_bundle(pathlib.Path(temporary))
            bundle = verification.validate_verifier_bundle(
                root, pr=pr, candidate="example-engine--example--model--test-target"
            )
            self.assertIsNone(bundle.engine_archive)
            (root / "candidate-audit.json").write_bytes(b'{"tampered":true}\n')
            with self.assertRaisesRegex(verification.VerificationError, "payload differs"):
                verification.validate_verifier_bundle(
                    root, pr=pr, candidate="example-engine--example--model--test-target"
                )

    def test_verification_image_override_is_private_and_exact(self) -> None:
        config = "sha256:" + "9" * 64
        manifest = cli.runtime_execution_manifest(
            runtime_candidate(),
            qualified=False,
            image_override={
                "distribution": "local-image-id",
                "reference": config,
                "immutable_id": config,
            },
        )
        self.assertEqual(
            manifest["image"],
            {
                "distribution": "local-image-id",
                "reference": config,
                "immutable_id": config,
            },
        )

    def test_oci_layout_converts_to_exact_docker_rootfs(self) -> None:
        compact = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":")
        ).encode()
        layer_buffer = io.BytesIO()
        with tarfile.open(fileobj=layer_buffer, mode="w") as layer_archive:
            payload = b"verified engine"
            item = tarfile.TarInfo("opt/letsinfer/engine")
            item.size = len(payload)
            layer_archive.addfile(item, io.BytesIO(payload))
        layer_tar = layer_buffer.getvalue()
        layer_blob = gzip.compress(layer_tar, mtime=0)
        diff_id = "sha256:" + hashlib.sha256(layer_tar).hexdigest()
        config = compact(
            {
                "architecture": "arm64",
                "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": [diff_id]},
            }
        )
        config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
        layer_digest = "sha256:" + hashlib.sha256(layer_blob).hexdigest()
        manifest = compact(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": config_digest,
                    "size": len(config),
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": layer_digest,
                        "size": len(layer_blob),
                    }
                ],
            }
        )
        manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        index = compact(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": manifest_digest,
                        "size": len(manifest),
                        "platform": {"os": "linux", "architecture": "arm64"},
                    }
                ],
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            oci = root / "engine.oci.tar"
            with tarfile.open(oci, "w") as archive:
                for name, data in (
                    ("oci-layout", compact({"imageLayoutVersion": "1.0.0"})),
                    ("index.json", index),
                    (f"blobs/sha256/{config_digest[7:]}", config),
                    (f"blobs/sha256/{layer_digest[7:]}", layer_blob),
                    (f"blobs/sha256/{manifest_digest[7:]}", manifest),
                ):
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
            identity = verification._oci_archive_identity(
                oci,
                expected_manifest=manifest_digest,
                expected_config=config_digest,
                expected_platform="linux/arm64",
            )
            docker = root / "engine.docker.tar"
            verification._docker_archive_from_oci(
                oci,
                docker,
                expected_manifest=manifest_digest,
                expected_config=config_digest,
                expected_platform="linux/arm64",
                tag="letsinfer-verifier/test:head",
            )
            with tarfile.open(docker, "r") as archive:
                docker_manifest = json.loads(archive.extractfile("manifest.json").read())
                converted_layer = archive.extractfile(
                    docker_manifest[0]["Layers"][0]
                ).read()
        self.assertEqual(identity["manifest_digest"], manifest_digest)
        self.assertEqual(converted_layer, layer_tar)

    def test_thin_oci_layout_hydrates_verified_external_layers(self) -> None:
        compact = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":")
        ).encode()

        def layer(payload: bytes) -> tuple[bytes, bytes, str, str]:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                item = tarfile.TarInfo("opt/letsinfer/" + payload.decode())
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            expanded = buffer.getvalue()
            compressed = gzip.compress(expanded, mtime=0)
            return (
                expanded,
                compressed,
                "sha256:" + hashlib.sha256(expanded).hexdigest(),
                "sha256:" + hashlib.sha256(compressed).hexdigest(),
            )

        base_tar, base_blob, base_diff, base_digest = layer(b"base")
        patch_tar, patch_blob, patch_diff, patch_digest = layer(b"patch")
        layers = [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": base_digest,
                "size": len(base_blob),
            },
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": patch_digest,
                "size": len(patch_blob),
            },
        ]
        config = compact(
            {
                "architecture": "arm64",
                "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": [base_diff, patch_diff]},
            }
        )
        config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
        manifest = compact(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": config_digest,
                    "size": len(config),
                },
                "layers": layers,
            }
        )
        manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        repository = "ghcr.io/letsinferlabs/engine-images"
        source_reference = repository + "@sha256:" + "7" * 64
        target_reference = repository + "@" + manifest_digest
        inventory = compact(
            {
                "schema_version": 1,
                "source_reference": source_reference,
                "target_repository": repository,
                "manifest_digest": manifest_digest,
                "layers": [
                    {
                        "index": 0,
                        **layers[0],
                        "diff_id": base_diff,
                    }
                ],
            }
        )
        index = compact(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": manifest_digest,
                        "size": len(manifest),
                        "platform": {"os": "linux", "architecture": "arm64"},
                    }
                ],
            }
        )
        remote = verification._RemoteEngineImage(
            layers=(layers[0],),
            diff_ids=(base_diff,),
        )
        registry = mock.Mock()
        registry.image.return_value = remote
        registry.download_blob.side_effect = (
            lambda _descriptor, destination: destination.write_bytes(base_blob)
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            oci = root / "engine.oci.tar"
            with tarfile.open(oci, "w") as archive:
                for name, data in (
                    ("oci-layout", compact({"imageLayoutVersion": "1.0.0"})),
                    ("index.json", index),
                    (f"blobs/sha256/{config_digest[7:]}", config),
                    (f"blobs/sha256/{patch_digest[7:]}", patch_blob),
                    (f"blobs/sha256/{manifest_digest[7:]}", manifest),
                    (verification.EXTERNAL_ENGINE_BLOBS_FILE, inventory),
                ):
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
            with mock.patch.object(
                verification, "_PublicEngineRegistry", return_value=registry
            ):
                identity = verification._oci_archive_identity(
                    oci,
                    expected_manifest=manifest_digest,
                    expected_config=config_digest,
                    expected_platform="linux/arm64",
                    expected_reference=target_reference,
                )
                docker = root / "engine.docker.tar"
                verification._docker_archive_from_oci(
                    oci,
                    docker,
                    expected_manifest=manifest_digest,
                    expected_config=config_digest,
                    expected_platform="linux/arm64",
                    tag="letsinfer-verifier/test:thin",
                    expected_reference=target_reference,
                )
            with tarfile.open(docker, "r") as archive:
                docker_manifest = json.loads(archive.extractfile("manifest.json").read())
                converted = [
                    archive.extractfile(name).read()
                    for name in docker_manifest[0]["Layers"]
                ]

        self.assertEqual(identity["manifest_digest"], manifest_digest)
        self.assertEqual(converted, [base_tar, patch_tar])
        registry.probe_blob.assert_called_once_with(layers[0])
        registry.download_blob.assert_called_once()

    def test_local_engine_cleanup_preserves_preexisting_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            verification._write_local_engine_receipt(
                verification.local_engine_receipt_path(root),
                {
                    "schema_version": 1,
                    "config_digest": "sha256:" + "9" * 64,
                    "tag": "test/image:head",
                    "preexisting": True,
                    "loaded": True,
                    "cleaned": False,
                },
            )
            with mock.patch.object(verification, "_run") as run:
                verification.cleanup_local_engine(root)
            run.assert_not_called()
            receipt = json.loads(
                verification.local_engine_receipt_path(root).read_text()
            )
            self.assertTrue(receipt["cleaned"])

    def test_local_engine_reuses_preexisting_config_without_ephemeral_tag(self) -> None:
        config = "sha256:" + "9" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "engine.oci.tar"
            archive.touch()
            bundle = verification.VerifierBundle(
                root=root,
                document={"engine": {}},
                runtime_pack=root / "runtime.letsinfer",
                engine_archive=archive,
                engine_config_digest=config,
                engine_tag="letsinfer-verifier/test:head",
            )
            with mock.patch.object(
                verification, "_docker_image_id", return_value=config
            ), mock.patch.object(verification, "_docker_archive_from_oci") as convert:
                receipt = verification.load_local_engine(bundle, root)
        convert.assert_not_called()
        self.assertIsNotNone(receipt)
        self.assertTrue(receipt["preexisting"])


if __name__ == "__main__":
    unittest.main()
