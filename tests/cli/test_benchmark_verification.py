#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Community benchmark-verification contract regressions."""

from __future__ import annotations

import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

from benchmarks import benchmark_record
from core import benchmark_verification as verification


class BenchmarkVerificationTests(unittest.TestCase):
    def _pr(self) -> verification.PullRequest:
        return verification.PullRequest(
            123,
            "https://github.com/letsinferlabs/runtimes/pull/123",
            "OPEN",
            "main",
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


if __name__ == "__main__":
    unittest.main()
