#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the machine-readable public benchmark record."""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from benchmarks import benchmark_record


class BenchmarkRecordTests(unittest.TestCase):
    def record(self) -> dict:
        installation_id = "1" * 64
        contract_sha = "2" * 64
        timestamp_ns = 1_786_931_286_123_456_789
        results = [
            {
                "workload": "pp32768,tg128,c1",
                "prompt_domain": "code",
                "prompt_suite": "letsinfer-code-prose-v1",
                "prompt_set_sha256": "3" * 64,
                "actual_prompt_tokens": [32711],
                "aggregate_tps": 3.5,
                "decode_tps": 28.5,
                "ttft_seconds": 31.8,
                "ttft_statistic": "single",
                "ttft_p95_seconds": None,
                "is_prefix_cached": False,
                "max_gpu_usage_percent": 96.0,
                "max_gpu_temperature_c": 74.0,
                "max_cpu_temperature_c": 69.5,
                "max_cpu_usage_percent": 88.0,
                "max_cpu_clock_mhz": 3800.0,
                "max_gpu_clock_mhz": 2400.0,
                "max_vram_clock_mhz": -1,
                "max_system_ram_clock_mhz": -1,
                "max_nvme_usage_percent": 72.0,
                "max_nvme_temperature_c": 48.5,
                "max_nvme_read_kib_per_second": 1024.0,
                "max_nvme_write_kib_per_second": 512.0,
                "telemetry": {
                    "interval_seconds": 1,
                    "columns": benchmark_record.TELEMETRY_COLUMNS,
                    "samples": [
                        "0,96,74,88,69.5,3800,2400,-1,-1,72,48.5,1024,512"
                    ],
                },
            }
        ]
        results_sha = benchmark_record.results_sha256(results)
        return {
            "schema_version": benchmark_record.SCHEMA_VERSION,
            "id": benchmark_record.benchmark_id(
                installation_id, timestamp_ns, contract_sha, results_sha
            ),
            "installation_id": installation_id,
            "timestamp": timestamp_ns // 1_000_000_000,
            "timestamp_unix_ns": timestamp_ns,
            "benchmark_contract_sha256": contract_sha,
            "results_sha256": results_sha,
            "results": results,
        }

    def test_record_identity_and_metrics_validate(self) -> None:
        value = self.record()
        self.assertIs(benchmark_record.validate_record(value), value)
        value["results"][0]["is_prefix_cached"] = "false"
        value["results_sha256"] = benchmark_record.results_sha256(value["results"])
        value["id"] = benchmark_record.benchmark_id(
            value["installation_id"],
            value["timestamp_unix_ns"],
            value["benchmark_contract_sha256"],
            value["results_sha256"],
        )
        with self.assertRaisesRegex(
            benchmark_record.BenchmarkRecordError, "is_prefix_cached"
        ):
            benchmark_record.validate_record(value)

    def test_record_id_is_cryptographically_bound(self) -> None:
        value = self.record()
        value["timestamp_unix_ns"] += 1
        with self.assertRaisesRegex(
            benchmark_record.BenchmarkRecordError, "id does not match"
        ):
            benchmark_record.validate_record(value)

    def test_unsupported_schema_is_rejected(self) -> None:
        value = self.record()
        value["schema_version"] = 1
        with self.assertRaisesRegex(
            benchmark_record.BenchmarkRecordError, "schema_version must be 3"
        ):
            benchmark_record.validate_record(value)

        value = self.record()
        value["schema_version"] = True
        with self.assertRaisesRegex(
            benchmark_record.BenchmarkRecordError, "schema_version must be 3"
        ):
            benchmark_record.validate_record(value)

    def test_code_and_prose_rows_share_a_workload_identity(self) -> None:
        value = self.record()
        prose = dict(value["results"][0])
        prose["prompt_domain"] = "prose"
        prose["prompt_set_sha256"] = "4" * 64
        value["results"].append(prose)
        value["results_sha256"] = benchmark_record.results_sha256(value["results"])
        value["id"] = benchmark_record.benchmark_id(
            value["installation_id"],
            value["timestamp_unix_ns"],
            value["benchmark_contract_sha256"],
            value["results_sha256"],
        )
        self.assertIs(benchmark_record.validate_record(value), value)

    def test_watchdog_summary_includes_timeline_and_matching_maxima(self) -> None:
        samples = [
            {
                "sequence": 1,
                "unix_ms": 1_000,
                "cpu_percent": 60,
                "gpu_percent": 90,
                "system_temp_deci_c": 650,
                "gpu_temp_deci_c": 700,
                "disk_percent": 71,
                "nvme_temp_deci_c": 470,
                "disk_read_kib_s": 512,
                "disk_write_kib_s": 256,
                "cpu_clock_mhz": 3200,
                "gpu_clock_mhz": 1500,
                "vram_clock_mhz": -1,
                "system_ram_clock_mhz": -1,
            },
            {
                "sequence": 2,
                "unix_ms": 2_000,
                "cpu_percent": 67,
                "gpu_percent": 95,
                "system_temp_deci_c": 690,
                "gpu_temp_deci_c": 740,
                "disk_percent": 72,
                "nvme_temp_deci_c": 485,
                "disk_read_kib_s": 1024,
                "disk_write_kib_s": 512,
                "cpu_clock_mhz": 3800,
                "gpu_clock_mhz": 2100,
                "vram_clock_mhz": -1,
                "system_ram_clock_mhz": -1,
            },
        ]
        maxima = benchmark_record.watchdog_summary(samples, 1_000)

        self.assertEqual(maxima["max_gpu_usage_percent"], 95.0)
        self.assertEqual(maxima["max_gpu_temperature_c"], 74.0)
        self.assertEqual(maxima["max_cpu_temperature_c"], 69.0)
        self.assertEqual(maxima["max_cpu_usage_percent"], 67.0)
        self.assertEqual(maxima["max_cpu_clock_mhz"], 3800.0)
        self.assertEqual(maxima["max_gpu_clock_mhz"], 2100.0)
        self.assertEqual(maxima["max_vram_clock_mhz"], -1.0)
        self.assertEqual(maxima["max_system_ram_clock_mhz"], -1.0)
        self.assertEqual(maxima["max_nvme_usage_percent"], 72.0)
        self.assertEqual(maxima["max_nvme_temperature_c"], 48.5)
        self.assertEqual(maxima["max_nvme_read_kib_per_second"], 1024.0)
        self.assertEqual(maxima["max_nvme_write_kib_per_second"], 512.0)
        self.assertEqual(maxima["telemetry"]["samples"], [
            "0,90,70,60,65,3200,1500,-1,-1,71,47,512,256",
            "1,95,74,67,69,3800,2100,-1,-1,72,48.5,1024,512",
        ])

    def test_unavailable_telemetry_uses_explicit_sentinels(self) -> None:
        value = self.record()
        result = value["results"][0]
        for field in (
            "max_gpu_usage_percent",
            "max_gpu_temperature_c",
            "max_cpu_temperature_c",
            "max_cpu_usage_percent",
        ):
            result[field] = None
        for field in (
            "max_cpu_clock_mhz",
            "max_gpu_clock_mhz",
            "max_vram_clock_mhz",
            "max_system_ram_clock_mhz",
            "max_nvme_usage_percent",
            "max_nvme_temperature_c",
            "max_nvme_read_kib_per_second",
            "max_nvme_write_kib_per_second",
        ):
            result[field] = -1
        result["telemetry"] = {
            "interval_seconds": None,
            "columns": benchmark_record.TELEMETRY_COLUMNS,
            "samples": [],
        }
        value["results_sha256"] = benchmark_record.results_sha256(value["results"])
        value["id"] = benchmark_record.benchmark_id(
            value["installation_id"],
            value["timestamp_unix_ns"],
            value["benchmark_contract_sha256"],
            value["results_sha256"],
        )
        self.assertIs(benchmark_record.validate_record(value), value)


if __name__ == "__main__":
    unittest.main()
