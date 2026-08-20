#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Create and validate Let's Infer's machine-readable public benchmark record."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import re
from typing import Any


SHA256_RE = re.compile(r"[0-9a-f]{64}")
WORKLOAD_RE = re.compile(r"pp[1-9][0-9]*,tg[1-9][0-9]*,c[1-9][0-9]*")
SCHEMA_VERSION = 3
RESULT_FIELDS = {
    "workload",
    "prompt_domain",
    "prompt_suite",
    "prompt_set_sha256",
    "actual_prompt_tokens",
    "aggregate_tps",
    "decode_tps",
    "ttft_seconds",
    "ttft_statistic",
    "ttft_p95_seconds",
    "is_prefix_cached",
    "max_gpu_usage_percent",
    "max_gpu_temperature_c",
    "max_cpu_temperature_c",
    "max_cpu_usage_percent",
    "max_cpu_clock_mhz",
    "max_gpu_clock_mhz",
    "max_vram_clock_mhz",
    "max_system_ram_clock_mhz",
    "max_nvme_usage_percent",
    "max_nvme_temperature_c",
    "max_nvme_read_kib_per_second",
    "max_nvme_write_kib_per_second",
    "telemetry",
}
RECORD_FIELDS = {
    "schema_version",
    "id",
    "installation_id",
    "timestamp",
    "timestamp_unix_ns",
    "benchmark_contract_sha256",
    "results_sha256",
    "results",
}
TELEMETRY_COLUMNS = [
    "elapsed_seconds",
    "gpu_usage_percent",
    "gpu_temperature_c",
    "cpu_usage_percent",
    "cpu_temperature_c",
    "cpu_clock_mhz",
    "gpu_clock_mhz",
    "vram_clock_mhz",
    "system_ram_clock_mhz",
    "nvme_usage_percent",
    "nvme_temperature_c",
    "nvme_read_kib_per_second",
    "nvme_write_kib_per_second",
]


class BenchmarkRecordError(ValueError):
    """The public benchmark record is invalid."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def benchmark_id(
    installation_id: str,
    timestamp_unix_ns: int,
    benchmark_contract_sha256: str,
    results_sha256: str,
) -> str:
    for value, label in (
        (installation_id, "installation_id"),
        (benchmark_contract_sha256, "benchmark_contract_sha256"),
        (results_sha256, "results_sha256"),
    ):
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise BenchmarkRecordError(f"{label} must be a SHA-256")
    if (
        not isinstance(timestamp_unix_ns, int)
        or isinstance(timestamp_unix_ns, bool)
        or timestamp_unix_ns <= 0
    ):
        raise BenchmarkRecordError("timestamp_unix_ns must be positive")
    material = {
        "benchmark_contract_sha256": benchmark_contract_sha256,
        "contract": "letsinfer-benchmark-identity-v1",
        "installation_id": installation_id,
        "results_sha256": results_sha256,
        "timestamp_unix_ns": timestamp_unix_ns,
    }
    return hashlib.sha256(canonical_bytes(material)).hexdigest()


def results_sha256(results: Any) -> str:
    if not isinstance(results, list) or not results:
        raise BenchmarkRecordError("benchmark record results must be non-empty")
    return hashlib.sha256(canonical_bytes(results)).hexdigest()


def _number(value: Any, field: str, *, nullable: bool = False) -> float | None:
    if value is None and nullable:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise BenchmarkRecordError(f"{field} must be a positive finite number")
    return float(value)


def _temperature(value: Any, field: str) -> None:
    if value is None:
        return
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not -100 <= float(value) <= 250
    ):
        raise BenchmarkRecordError(f"{field} must be null or a temperature in Celsius")


def _percent(value: Any, field: str) -> None:
    if value is not None and (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 <= float(value) <= 100
    ):
        raise BenchmarkRecordError(f"{field} must be null or from 0 through 100")


def _clock(value: Any, field: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or (float(value) != -1 and float(value) <= 0)
    ):
        raise BenchmarkRecordError(
            f"{field} must be -1 or a positive finite frequency in MHz"
        )


def _unknown_or_percent(value: Any, field: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or (float(value) != -1 and not 0 <= float(value) <= 100)
    ):
        raise BenchmarkRecordError(f"{field} must be -1 or from 0 through 100")


def _unknown_or_temperature(value: Any, field: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or (float(value) != -1 and not -100 <= float(value) <= 250)
    ):
        raise BenchmarkRecordError(
            f"{field} must be -1 or a temperature in Celsius"
        )


def _unknown_or_rate(value: Any, field: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or (float(value) != -1 and float(value) < 0)
    ):
        raise BenchmarkRecordError(
            f"{field} must be -1 or a non-negative finite rate"
        )


def _timeline_number(
    raw: str,
    field: str,
    *,
    temperature: bool = False,
    clock: bool = False,
    unknown: bool = False,
    rate: bool = False,
) -> float | None:
    if raw == "":
        return None
    try:
        value = float(raw)
    except ValueError as error:
        raise BenchmarkRecordError(f"{field} is not numeric") from error
    if not math.isfinite(value):
        raise BenchmarkRecordError(f"{field} must be finite")
    if unknown and value == -1:
        return value
    if clock:
        if value != -1 and value <= 0:
            raise BenchmarkRecordError(f"{field} must be -1 or positive MHz")
    elif rate:
        if value < 0:
            raise BenchmarkRecordError(f"{field} must be non-negative")
    elif temperature:
        if not -100 <= value <= 250:
            raise BenchmarkRecordError(f"{field} is outside the Celsius range")
    elif not 0 <= value <= 100:
        raise BenchmarkRecordError(f"{field} must be from 0 through 100")
    return value


def _validate_telemetry(result: dict[str, Any], where: str) -> None:
    telemetry = result.get("telemetry")
    if not isinstance(telemetry, dict) or set(telemetry) != {
        "interval_seconds",
        "columns",
        "samples",
    }:
        raise BenchmarkRecordError(
            f"{where}.telemetry must contain interval_seconds, columns, and samples"
        )
    if telemetry.get("columns") != TELEMETRY_COLUMNS:
        raise BenchmarkRecordError(f"{where}.telemetry.columns is not the standard schema")
    samples = telemetry.get("samples")
    if not isinstance(samples, list) or any(not isinstance(row, str) for row in samples):
        raise BenchmarkRecordError(f"{where}.telemetry.samples must be CSV strings")
    interval = telemetry.get("interval_seconds")
    if samples and interval != 1:
        raise BenchmarkRecordError(f"{where}.telemetry.interval_seconds must be 1")
    if not samples and interval is not None:
        raise BenchmarkRecordError(
            f"{where}.telemetry.interval_seconds must be null without samples"
        )

    observed: dict[str, list[float]] = {
        "max_gpu_usage_percent": [],
        "max_gpu_temperature_c": [],
        "max_cpu_usage_percent": [],
        "max_cpu_temperature_c": [],
        "max_cpu_clock_mhz": [],
        "max_gpu_clock_mhz": [],
        "max_vram_clock_mhz": [],
        "max_system_ram_clock_mhz": [],
        "max_nvme_usage_percent": [],
        "max_nvme_temperature_c": [],
        "max_nvme_read_kib_per_second": [],
        "max_nvme_write_kib_per_second": [],
    }
    previous_elapsed = -1.0
    for index, sample in enumerate(samples):
        fields = sample.split(",")
        if len(fields) != len(TELEMETRY_COLUMNS):
            raise BenchmarkRecordError(
                f"{where}.telemetry.samples[{index}] must have "
                f"{len(TELEMETRY_COLUMNS)} CSV fields"
            )
        try:
            elapsed = float(fields[0])
        except ValueError as error:
            raise BenchmarkRecordError(
                f"{where}.telemetry.samples[{index}] elapsed time is invalid"
            ) from error
        if not math.isfinite(elapsed) or elapsed < 0 or elapsed <= previous_elapsed:
            raise BenchmarkRecordError(
                f"{where}.telemetry.samples[{index}] elapsed time must increase"
            )
        previous_elapsed = elapsed
        parsed = (
            _timeline_number(fields[1], f"{where}.telemetry.samples[{index}].gpu_usage"),
            _timeline_number(
                fields[2],
                f"{where}.telemetry.samples[{index}].gpu_temperature",
                temperature=True,
            ),
            _timeline_number(fields[3], f"{where}.telemetry.samples[{index}].cpu_usage"),
            _timeline_number(
                fields[4],
                f"{where}.telemetry.samples[{index}].cpu_temperature",
                temperature=True,
            ),
            _timeline_number(
                fields[5],
                f"{where}.telemetry.samples[{index}].cpu_clock",
                clock=True,
            ),
            _timeline_number(
                fields[6],
                f"{where}.telemetry.samples[{index}].gpu_clock",
                clock=True,
            ),
            _timeline_number(
                fields[7],
                f"{where}.telemetry.samples[{index}].vram_clock",
                clock=True,
            ),
            _timeline_number(
                fields[8],
                f"{where}.telemetry.samples[{index}].system_ram_clock",
                clock=True,
            ),
            _timeline_number(
                fields[9],
                f"{where}.telemetry.samples[{index}].nvme_usage",
                unknown=True,
            ),
            _timeline_number(
                fields[10],
                f"{where}.telemetry.samples[{index}].nvme_temperature",
                temperature=True,
                unknown=True,
            ),
            _timeline_number(
                fields[11],
                f"{where}.telemetry.samples[{index}].nvme_read",
                rate=True,
                unknown=True,
            ),
            _timeline_number(
                fields[12],
                f"{where}.telemetry.samples[{index}].nvme_write",
                rate=True,
                unknown=True,
            ),
        )
        for field, value in zip(observed, parsed):
            if value is not None:
                observed[field].append(value)

    for field, values in observed.items():
        declared = result.get(field)
        expected = (
            max(values)
            if values
            else -1
            if field.endswith("_clock_mhz") or field.startswith("max_nvme_")
            else None
        )
        if declared != expected:
            raise BenchmarkRecordError(
                f"{where}.{field} must equal its telemetry timeline maximum"
            )


def validate_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RECORD_FIELDS:
        raise BenchmarkRecordError(
            "benchmark record must contain exactly " + ", ".join(sorted(RECORD_FIELDS))
        )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        raise BenchmarkRecordError(
            f"benchmark record schema_version must be {SCHEMA_VERSION}"
        )
    timestamp_ns = value.get("timestamp_unix_ns")
    timestamp = value.get("timestamp")
    if (
        not isinstance(timestamp, int)
        or isinstance(timestamp, bool)
        or timestamp != timestamp_ns // 1_000_000_000
    ):
        raise BenchmarkRecordError("timestamp must be the Unix-second form of timestamp_unix_ns")
    results = value.get("results")
    actual_results_sha = results_sha256(results)
    if value.get("results_sha256") != actual_results_sha:
        raise BenchmarkRecordError("benchmark record results_sha256 does not match results")
    seen: set[tuple[str, str]] = set()
    for index, result in enumerate(results):
        where = f"results[{index}]"
        if not isinstance(result, dict) or set(result) != RESULT_FIELDS:
            raise BenchmarkRecordError(
                f"{where} must contain exactly " + ", ".join(sorted(RESULT_FIELDS))
            )
        workload = result.get("workload")
        if not isinstance(workload, str) or not WORKLOAD_RE.fullmatch(workload):
            raise BenchmarkRecordError(f"{where}.workload is invalid")
        domain = result.get("prompt_domain")
        if domain not in {"code", "prose"}:
            raise BenchmarkRecordError(f"{where}.prompt_domain must be code or prose")
        suite = result.get("prompt_suite")
        if suite != "letsinfer-code-prose-v1":
            raise BenchmarkRecordError(f"{where}.prompt_suite is unsupported")
        prompt_set = result.get("prompt_set_sha256")
        if not isinstance(prompt_set, str) or not SHA256_RE.fullmatch(prompt_set):
            raise BenchmarkRecordError(f"{where}.prompt_set_sha256 must be a SHA-256")
        actual_prompt_tokens = result.get("actual_prompt_tokens")
        concurrency = int(workload.rsplit(",c", 1)[1])
        if (
            not isinstance(actual_prompt_tokens, list)
            or len(actual_prompt_tokens) != concurrency
            or any(
                not isinstance(item, int)
                or isinstance(item, bool)
                or item <= 0
                for item in actual_prompt_tokens
            )
        ):
            raise BenchmarkRecordError(
                f"{where}.actual_prompt_tokens must contain one positive integer per stream"
            )
        identity = (workload, domain)
        if identity in seen:
            raise BenchmarkRecordError(
                f"duplicate benchmark workload/domain: {workload} {domain}"
            )
        seen.add(identity)
        _number(result.get("aggregate_tps"), f"{where}.aggregate_tps")
        _number(result.get("decode_tps"), f"{where}.decode_tps", nullable=True)
        ttft = _number(result.get("ttft_seconds"), f"{where}.ttft_seconds")
        statistic = result.get("ttft_statistic")
        if statistic not in {"single", "mean", "p50"}:
            raise BenchmarkRecordError(
                f"{where}.ttft_statistic must be single, mean, or p50"
            )
        p95 = _number(
            result.get("ttft_p95_seconds"),
            f"{where}.ttft_p95_seconds",
            nullable=True,
        )
        if statistic == "p50" and (p95 is None or p95 < ttft):
            raise BenchmarkRecordError(f"{where}.ttft_p95_seconds must be at least p50")
        if statistic != "p50" and p95 is not None:
            raise BenchmarkRecordError(f"{where}.ttft_p95_seconds must be null")
        if not isinstance(result.get("is_prefix_cached"), bool):
            raise BenchmarkRecordError(f"{where}.is_prefix_cached must be boolean")
        for field in ("max_gpu_temperature_c", "max_cpu_temperature_c"):
            _temperature(result.get(field), f"{where}.{field}")
        for field in ("max_gpu_usage_percent", "max_cpu_usage_percent"):
            _percent(result.get(field), f"{where}.{field}")
        for field in (
            "max_cpu_clock_mhz",
            "max_gpu_clock_mhz",
            "max_vram_clock_mhz",
            "max_system_ram_clock_mhz",
        ):
            _clock(result.get(field), f"{where}.{field}")
        _unknown_or_percent(
            result.get("max_nvme_usage_percent"),
            f"{where}.max_nvme_usage_percent",
        )
        _unknown_or_temperature(
            result.get("max_nvme_temperature_c"),
            f"{where}.max_nvme_temperature_c",
        )
        for field in (
            "max_nvme_read_kib_per_second",
            "max_nvme_write_kib_per_second",
        ):
            _unknown_or_rate(result.get(field), f"{where}.{field}")
        _validate_telemetry(result, where)
    expected_id = benchmark_id(
        value.get("installation_id"),
        timestamp_ns,
        value.get("benchmark_contract_sha256"),
        actual_results_sha,
    )
    if value.get("id") != expected_id:
        raise BenchmarkRecordError("benchmark record id does not match its bound inputs")
    return value


def _compact(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.3f}".rstrip("0").rstrip(".")


def watchdog_summary(
    watchdog_samples: list[dict[str, int]],
    measurement_started_unix_ms: int,
) -> dict[str, Any]:
    """Compact Watchdog's independent one-second samples for one workload."""
    samples: list[str] = []
    for index, sample in enumerate(watchdog_samples):
        required = {
            "sequence",
            "unix_ms",
            "cpu_percent",
            "gpu_percent",
            "system_temp_deci_c",
            "gpu_temp_deci_c",
            "disk_percent",
            "nvme_temp_deci_c",
            "disk_read_kib_s",
            "disk_write_kib_s",
            "cpu_clock_mhz",
            "gpu_clock_mhz",
            "vram_clock_mhz",
            "system_ram_clock_mhz",
        }
        if not isinstance(sample, dict) or set(sample) != required:
            raise BenchmarkRecordError(f"invalid Watchdog sample {index}")
        if any(
            not isinstance(sample[field], int) or isinstance(sample[field], bool)
            for field in required
        ):
            raise BenchmarkRecordError(f"non-integer Watchdog sample {index}")
        elapsed = (sample["unix_ms"] - measurement_started_unix_ms) / 1000.0
        if elapsed < 0:
            raise BenchmarkRecordError(f"Watchdog sample {index} predates the workload")
        gpu_usage = None if sample["gpu_percent"] == 255 else sample["gpu_percent"]
        cpu_usage = None if sample["cpu_percent"] == 255 else sample["cpu_percent"]
        gpu_temp = (
            None
            if sample["gpu_temp_deci_c"] == -32768
            else sample["gpu_temp_deci_c"] / 10.0
        )
        cpu_temp = (
            None
            if sample["system_temp_deci_c"] == -32768
            else sample["system_temp_deci_c"] / 10.0
        )
        nvme_usage = sample["disk_percent"]
        nvme_temp = (
            -1
            if sample["nvme_temp_deci_c"] == -1
            else sample["nvme_temp_deci_c"] / 10.0
        )
        values = (
            elapsed,
            gpu_usage,
            gpu_temp,
            cpu_usage,
            cpu_temp,
            sample["cpu_clock_mhz"],
            sample["gpu_clock_mhz"],
            sample["vram_clock_mhz"],
            sample["system_ram_clock_mhz"],
            nvme_usage,
            nvme_temp,
            sample["disk_read_kib_s"],
            sample["disk_write_kib_s"],
        )
        samples.append(",".join(_compact(value) for value in values))

    timeline = {
        "interval_seconds": 1,
        "columns": TELEMETRY_COLUMNS,
        "samples": samples,
    }
    result: dict[str, Any] = {
        "max_gpu_usage_percent": None,
        "max_gpu_temperature_c": None,
        "max_cpu_usage_percent": None,
        "max_cpu_temperature_c": None,
        "max_cpu_clock_mhz": -1,
        "max_gpu_clock_mhz": -1,
        "max_vram_clock_mhz": -1,
        "max_system_ram_clock_mhz": -1,
        "max_nvme_usage_percent": -1,
        "max_nvme_temperature_c": -1,
        "max_nvme_read_kib_per_second": -1,
        "max_nvme_write_kib_per_second": -1,
        "telemetry": timeline,
    }
    field_indexes = {
        "max_gpu_usage_percent": 1,
        "max_gpu_temperature_c": 2,
        "max_cpu_usage_percent": 3,
        "max_cpu_temperature_c": 4,
        "max_cpu_clock_mhz": 5,
        "max_gpu_clock_mhz": 6,
        "max_vram_clock_mhz": 7,
        "max_system_ram_clock_mhz": 8,
        "max_nvme_usage_percent": 9,
        "max_nvme_temperature_c": 10,
        "max_nvme_read_kib_per_second": 11,
        "max_nvme_write_kib_per_second": 12,
    }
    for field, index in field_indexes.items():
        values = [
            float(row.split(",")[index])
            for row in samples
            if row.split(",")[index] != ""
        ]
        result[field] = max(
            values,
            default=-1 if field.endswith("_clock_mhz") or field.startswith("max_nvme_") else None,
        )
    return result


def read_record(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkRecordError(f"cannot read benchmark record {path}: {error}") from error
    return validate_record(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=pathlib.Path)
    arguments = parser.parse_args()
    value = read_record(arguments.record)
    print(
        f"VALID benchmark_id={value['id']} results={len(value['results'])} "
        f"record={arguments.record}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkRecordError as error:
        raise SystemExit(f"FATAL: {error}") from error
