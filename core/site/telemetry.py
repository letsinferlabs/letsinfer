#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, signed machine telemetry and logical-node aggregation."""

from __future__ import annotations

import collections
import hashlib
import http.client
import json
import os
import pathlib
import re
import socket
import ssl
import stat
import struct
import threading
import time
import urllib.parse
import zlib
from collections.abc import Callable, Iterator, Mapping
from typing import Any

from .state import (
    SiteError,
    SiteIdentity,
    member_certificate_path,
    member_key_path,
    member_proof,
    site_ca_certificate_path,
)


PROTOCOL = "letsinfer-node-telemetry-v1"
TELEMETRY_SCHEMA_VERSION = 2
RECORD_MAGIC = 0x3152494C
RECORD_VERSION = 2
RECORD_BYTES = 284
RAW_RING_CAPACITY = 86_400
MAX_SAMPLE_AGE_SECONDS = 5
MAX_MEMBERS = 64
HISTORY_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 4096
MAX_WATCHDOG_FRAME_BYTES = 65_536
WATCHDOG_REQUEST_ID = 1
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

COUNTER_FIELDS = (
    "requests_received",
    "requests_admitted",
    "requests_completed",
    "requests_failed",
    "requests_cancelled",
    "requests_retried",
    "input_tokens",
    "output_tokens",
    "cached_tokens",
    "queue_milliseconds",
    "ttft_milliseconds",
    "decode_milliseconds",
    "exact_token_requests",
    "prefix_cache_hits",
    "usage_records_dropped",
    "usage_write_errors",
)

RATE_FIELDS = (
    "requests_per_second",
    "failures_per_second",
    "cancellations_per_second",
    "retries_per_second",
    "input_tokens_per_second",
    "output_tokens_per_second",
    "aggregate_tokens_per_second",
    "cached_tokens_per_second",
    "prefill_tokens_per_second",
    "decode_tokens_per_second",
    "average_queue_milliseconds",
    "average_ttft_milliseconds",
    "average_decode_milliseconds",
    "prefix_cache_hit_ratio",
    "exact_token_ratio",
)


class TelemetryError(RuntimeError):
    """A local sample, signed update, or aggregate is unsafe or invalid."""


def _protobuf_varint(value: int) -> bytes:
    if value < 0:
        raise TelemetryError("cannot encode a negative protobuf varint")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7f) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _protobuf_uint(field: int, value: int) -> bytes:
    return _protobuf_varint(field << 3) + _protobuf_varint(value)


def _protobuf_message(field: int, value: bytes) -> bytes:
    return (
        _protobuf_varint((field << 3) | 2)
        + _protobuf_varint(len(value))
        + value
    )


def _read_protobuf_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 64, 7):
        if offset >= len(data):
            raise TelemetryError("Watchdog protobuf varint is truncated")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte & 0x80 == 0:
            return value, offset
    raise TelemetryError("Watchdog protobuf varint is oversized")


def _protobuf_fields(data: bytes) -> Iterator[tuple[int, int | bytes]]:
    offset = 0
    while offset < len(data):
        key, offset = _read_protobuf_varint(data, offset)
        field, wire = key >> 3, key & 7
        if field == 0:
            raise TelemetryError("Watchdog protobuf field zero is invalid")
        if wire == 0:
            value, offset = _read_protobuf_varint(data, offset)
            yield field, value
        elif wire == 2:
            length, offset = _read_protobuf_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise TelemetryError("Watchdog protobuf message is truncated")
            yield field, data[offset:end]
            offset = end
        else:
            raise TelemetryError(f"Watchdog protobuf wire type {wire} is unsupported")


def _protobuf_sint32(value: int) -> int:
    decoded = (value >> 1) ^ -(value & 1)
    if not -(2**31) <= decoded < 2**31:
        raise TelemetryError("Watchdog signed metric is out of range")
    return decoded


def decode_watchdog_protocol_sample(payload: bytes, *, member_id: str) -> dict[str, Any]:
    """Decode the bounded native Watchdog sample used by latest/live streams."""

    values: dict[int, int | bytes] = dict(_protobuf_fields(payload))
    gpu_raw = values.get(9)
    if not isinstance(gpu_raw, bytes):
        raise TelemetryError("Watchdog sample has no GPU metrics")
    gpu: dict[int, int | bytes] = dict(_protobuf_fields(gpu_raw))

    def uint(source: Mapping[int, int | bytes], field: int) -> int:
        value = source.get(field)
        if not isinstance(value, int) or isinstance(value, bool):
            raise TelemetryError(f"Watchdog sample field {field} is missing")
        return value

    def packed(source: Mapping[int, int | bytes], field: int) -> list[int]:
        value = source.get(field)
        if not isinstance(value, bytes):
            return []
        return _decode_packed_varints(value)

    flags = uint(values, 4)
    counters = {
        name: uint(values, field)
        for name, field in zip(COUNTER_FIELDS, range(27, 43))
    }
    return validate_sample({
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "member_id": member_id,
        "sequence": uint(values, 1),
        "unix_ms": uint(values, 2),
        "monotonic_ms": uint(values, 3),
        "system": {
            "cpu_core_percent": [_unknown_percent(value) for value in packed(values, 6)],
            "cpu_percent": _unknown_percent(uint(values, 5)),
            "gpu_percent": _unknown_percent(uint(gpu, 1)),
            "memory_percent": _unknown_percent(uint(values, 7)),
            "disk_percent": _unknown_percent(uint(values, 8)),
            "gpu_memory_percent": _unknown_percent(uint(gpu, 2)),
            "gpu_engine_percent": [_unknown_percent(value) for value in packed(gpu, 3)],
            "system_temp_deci_c": _unknown_temperature(_protobuf_sint32(uint(values, 10))),
            "gpu_temp_deci_c": _unknown_temperature(_protobuf_sint32(uint(gpu, 4))),
            "nvme_temp_deci_c": _unknown_temperature(_protobuf_sint32(uint(values, 11))),
            "power_deci_w": uint(gpu, 5),
            "load1_centi": uint(values, 12),
            "memory_used_mib": uint(values, 13),
            "memory_total_mib": uint(values, 14),
            "disk_used_mib": uint(values, 15),
            "disk_total_mib": uint(values, 16),
            "network_rx_kib_s": uint(values, 17),
            "network_tx_kib_s": uint(values, 18),
            "disk_read_kib_s": uint(values, 19),
            "disk_write_kib_s": uint(values, 20),
            "cpu_clock_mhz": _unknown_clock(uint(values, 23)),
            "gpu_clock_mhz": _unknown_clock(uint(gpu, 6)),
            "vram_clock_mhz": _unknown_clock(uint(gpu, 7)),
            "system_ram_clock_mhz": _unknown_clock(uint(values, 24)),
        },
        "inference": {
            "gateway_available": bool(flags & (1 << 3)),
            "active_requests": uint(values, 25),
            "connected_clients": uint(values, 43),
            "queued_requests": uint(values, 26),
            **counters,
        },
        "workload": {
            "type": uint(values, 22),
            "id": uint(values, 21),
            "gpu_available": bool(flags & (1 << 1)),
            "throttled": bool(flags & (1 << 2)),
        },
    })


def _decode_packed_varints(data: bytes) -> list[int]:
    values: list[int] = []
    offset = 0
    while offset < len(data):
        value, offset = _read_protobuf_varint(data, offset)
        values.append(value)
    return values


def _read_watchdog_exact(
    stream: ssl.SSLSocket, length: int, stop_event: threading.Event
) -> bytes:
    output = bytearray()
    while len(output) < length and not stop_event.is_set():
        try:
            chunk = stream.recv(length - len(output))
        except TimeoutError:
            continue
        if not chunk:
            raise TelemetryError("Watchdog closed the live telemetry connection")
        output.extend(chunk)
    if len(output) != length:
        raise TelemetryError("Watchdog telemetry subscription stopped")
    return bytes(output)


def watchdog_live_samples(
    *,
    member_id: str,
    port: int,
    ca_file: pathlib.Path,
    controller_cert_file: pathlib.Path,
    controller_key_file: pathlib.Path,
    stop_event: threading.Event,
) -> Iterator[dict[str, Any]]:
    """Yield current and future samples from Watchdog's authenticated live feed."""

    if not 1 <= port <= 65_535:
        raise TelemetryError("Watchdog telemetry port is invalid")
    for path, label in (
        (ca_file, "server certificate"),
        (controller_cert_file, "controller certificate"),
        (controller_key_file, "controller key"),
    ):
        if path.is_symlink() or not path.is_file():
            raise TelemetryError(f"Watchdog {label} is not a regular file")
    request = _protobuf_uint(1, WATCHDOG_REQUEST_ID) + _protobuf_message(
        11, _protobuf_uint(1, 0)
    )
    frame = len(request).to_bytes(4, "big") + request
    context = ssl.create_default_context(cafile=str(ca_file))
    context.load_cert_chain(str(controller_cert_file), str(controller_key_file))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as stream:
                stream.settimeout(1)
                stream.sendall(frame)
                while not stop_event.is_set():
                    length = int.from_bytes(
                        _read_watchdog_exact(stream, 4, stop_event), "big"
                    )
                    if not 1 <= length <= MAX_WATCHDOG_FRAME_BYTES:
                        raise TelemetryError("Watchdog telemetry frame is invalid")
                    envelope = list(_protobuf_fields(
                        _read_watchdog_exact(stream, length, stop_event)
                    ))
                    request_ids = [value for field, value in envelope if field == 1]
                    bodies = [(field, value) for field, value in envelope if field != 1]
                    if request_ids != [WATCHDOG_REQUEST_ID] or len(bodies) != 1:
                        raise TelemetryError("Watchdog telemetry envelope is invalid")
                    field, body = bodies[0]
                    if field in {10, 13} and isinstance(body, bytes):
                        yield decode_watchdog_protocol_sample(body, member_id=member_id)
                    elif field == 16 and isinstance(body, bytes):
                        raise TelemetryError("Watchdog rejected the telemetry subscription")
    except (OSError, ssl.SSLError) as error:
        raise TelemetryError(f"Watchdog live telemetry failed: {error}") from error


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _unknown_percent(value: int) -> int:
    return -1 if value == 255 else value


def _unknown_temperature(value: int) -> int:
    return -1 if value == -32768 else value


def _unknown_clock(value: int) -> int:
    return -1 if value == 0xFFFFFFFF else value


def _u64(record: bytes, offset: int) -> int:
    return int(struct.unpack_from("<Q", record, offset)[0])


def _u32(record: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", record, offset)[0])


def decode_watchdog_record(record: bytes, *, member_id: str) -> dict[str, Any]:
    if not ID_RE.fullmatch(member_id):
        raise TelemetryError("telemetry member identity is invalid")
    if (
        len(record) != RECORD_BYTES
        or _u32(record, 0) != RECORD_MAGIC
        or struct.unpack_from("<H", record, 4)[0] != RECORD_VERSION
        or struct.unpack_from("<H", record, 6)[0] != RECORD_BYTES
        or _u32(record, 280) != zlib.crc32(record[:280])
    ):
        raise TelemetryError("Watchdog telemetry record is corrupt or unsupported")
    core_count = record[32]
    if core_count > 32:
        raise TelemetryError("Watchdog telemetry core count is invalid")
    flags = record[33]
    counter_offsets = range(148, 276, 8)
    counters = {
        field: _u64(record, offset)
        for field, offset in zip(COUNTER_FIELDS, counter_offsets)
    }
    sample = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "member_id": member_id,
        "sequence": _u64(record, 8),
        "unix_ms": _u64(record, 16),
        "monotonic_ms": _u64(record, 24),
        "system": {
            "cpu_core_percent": [_unknown_percent(value) for value in record[40 : 40 + core_count]],
            "cpu_percent": _unknown_percent(record[34]),
            "gpu_percent": _unknown_percent(record[35]),
            "memory_percent": _unknown_percent(record[36]),
            "disk_percent": _unknown_percent(record[37]),
            "gpu_memory_percent": _unknown_percent(record[38]),
            "gpu_engine_percent": [_unknown_percent(value) for value in record[72:78]],
            "system_temp_deci_c": _unknown_temperature(struct.unpack_from("<h", record, 78)[0]),
            "gpu_temp_deci_c": _unknown_temperature(struct.unpack_from("<h", record, 80)[0]),
            "nvme_temp_deci_c": _unknown_temperature(struct.unpack_from("<h", record, 82)[0]),
            "power_deci_w": int(struct.unpack_from("<H", record, 84)[0]),
            "load1_centi": int(struct.unpack_from("<H", record, 86)[0]),
            "memory_used_mib": _u32(record, 88),
            "memory_total_mib": _u32(record, 92),
            "disk_used_mib": _u32(record, 96),
            "disk_total_mib": _u32(record, 100),
            "network_rx_kib_s": _u32(record, 104),
            "network_tx_kib_s": _u32(record, 108),
            "disk_read_kib_s": _u32(record, 112),
            "disk_write_kib_s": _u32(record, 116),
            "cpu_clock_mhz": _unknown_clock(_u32(record, 124)),
            "gpu_clock_mhz": _unknown_clock(_u32(record, 128)),
            "vram_clock_mhz": _unknown_clock(_u32(record, 132)),
            "system_ram_clock_mhz": _unknown_clock(_u32(record, 136)),
        },
        "inference": {
            "gateway_available": bool(flags & (1 << 3)),
            "active_requests": _u32(record, 140),
            "connected_clients": _u32(record, 276),
            "queued_requests": _u32(record, 144),
            **counters,
        },
        "workload": {
            "type": int(record[39]),
            "id": _u32(record, 120),
            "gpu_available": bool(flags & (1 << 1)),
            "throttled": bool(flags & (1 << 2)),
        },
    }
    return validate_sample(sample)


def _bounded_integer(value: Any, where: str, *, minimum: int = 0, maximum: int = 2**64 - 1) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise TelemetryError(f"{where} is invalid")
    return value


def validate_sample(value: Any) -> dict[str, Any]:
    required = {
        "schema_version", "member_id", "sequence", "unix_ms", "monotonic_ms",
        "system", "inference", "workload",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != TELEMETRY_SCHEMA_VERSION
    ):
        raise TelemetryError("member telemetry has an unsupported schema")
    if not isinstance(value.get("member_id"), str) or not ID_RE.fullmatch(value["member_id"]):
        raise TelemetryError("member telemetry identity is invalid")
    for field in ("sequence", "unix_ms", "monotonic_ms"):
        _bounded_integer(value[field], f"member telemetry {field}")
    system = value.get("system")
    system_fields = {
        "cpu_core_percent", "cpu_percent", "gpu_percent", "memory_percent",
        "disk_percent", "gpu_memory_percent", "gpu_engine_percent",
        "system_temp_deci_c", "gpu_temp_deci_c", "nvme_temp_deci_c",
        "power_deci_w", "load1_centi", "memory_used_mib", "memory_total_mib",
        "disk_used_mib", "disk_total_mib", "network_rx_kib_s", "network_tx_kib_s",
        "disk_read_kib_s", "disk_write_kib_s", "cpu_clock_mhz", "gpu_clock_mhz",
        "vram_clock_mhz", "system_ram_clock_mhz",
    }
    if not isinstance(system, dict) or set(system) != system_fields:
        raise TelemetryError("member telemetry system fields are invalid")
    for field in ("cpu_core_percent", "gpu_engine_percent"):
        values = system[field]
        maximum = 32 if field == "cpu_core_percent" else 6
        if (
            not isinstance(values, list)
            or len(values) > maximum
            or any(
                not isinstance(item, int)
                or isinstance(item, bool)
                or item < -1
                or item > 100
                for item in values
            )
        ):
            raise TelemetryError(f"member telemetry system.{field} is invalid")
    for field in ("cpu_percent", "gpu_percent", "memory_percent", "disk_percent", "gpu_memory_percent"):
        _bounded_integer(system[field], f"member telemetry system.{field}", minimum=-1, maximum=100)
    for field in system_fields - {
        "cpu_core_percent", "gpu_engine_percent", "cpu_percent", "gpu_percent",
        "memory_percent", "disk_percent", "gpu_memory_percent",
    }:
        _bounded_integer(system[field], f"member telemetry system.{field}", minimum=-32768, maximum=2**32 - 1)
    inference = value.get("inference")
    inference_fields = {
        "gateway_available",
        "active_requests",
        "connected_clients",
        "queued_requests",
        *COUNTER_FIELDS,
    }
    if not isinstance(inference, dict) or set(inference) != inference_fields or not isinstance(inference["gateway_available"], bool):
        raise TelemetryError("member telemetry inference fields are invalid")
    for field in inference_fields - {"gateway_available"}:
        _bounded_integer(inference[field], f"member telemetry inference.{field}")
    workload = value.get("workload")
    if (
        not isinstance(workload, dict)
        or set(workload) != {"type", "id", "gpu_available", "throttled"}
        or not isinstance(workload["gpu_available"], bool)
        or not isinstance(workload["throttled"], bool)
    ):
        raise TelemetryError("member telemetry workload fields are invalid")
    _bounded_integer(workload["type"], "member telemetry workload.type", maximum=255)
    _bounded_integer(workload["id"], "member telemetry workload.id", maximum=2**32 - 1)
    return value


def read_latest_watchdog_sample(
    path: pathlib.Path,
    *,
    member_id: str,
    now_unix_ms: int | None = None,
) -> dict[str, Any]:
    now_ms = now_unix_ms if now_unix_ms is not None else int(time.time() * 1000)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TelemetryError(f"Watchdog telemetry ring is unavailable: {error}") from error
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_mode & 0o022
            or status.st_size != RAW_RING_CAPACITY * RECORD_BYTES
        ):
            raise TelemetryError("Watchdog telemetry ring ownership or size is invalid")
        newest: dict[str, Any] | None = None
        current_bucket = now_ms // 1000
        for bucket in range(current_bucket, max(-1, current_bucket - MAX_SAMPLE_AGE_SECONDS - 1), -1):
            offset = (bucket % RAW_RING_CAPACITY) * RECORD_BYTES
            record = os.pread(descriptor, RECORD_BYTES, offset)
            try:
                candidate = decode_watchdog_record(record, member_id=member_id)
            except TelemetryError:
                continue
            if candidate["unix_ms"] // 1000 != bucket:
                continue
            if newest is None or candidate["sequence"] > newest["sequence"]:
                newest = candidate
        if newest is None or not 0 <= now_ms - newest["unix_ms"] <= MAX_SAMPLE_AGE_SECONDS * 1000:
            raise TelemetryError("Watchdog telemetry has no fresh sample")
        return newest
    finally:
        os.close(descriptor)


def signed_sample(sample: Mapping[str, Any]) -> dict[str, Any]:
    validated = validate_sample(dict(sample))
    statement = {"protocol": PROTOCOL, "sample": validated}
    try:
        signature = member_proof(statement)
    except SiteError as error:
        raise TelemetryError(str(error)) from error
    return {**statement, "signature": signature}


class TelemetryAggregator:
    """Fixed-size logical-site view with monotonic reset compensation."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self.lock = threading.RLock()
        self.members: dict[str, dict[str, Any]] = {}
        self.previous: dict[str, dict[str, int]] = {}
        self.offsets: dict[str, dict[str, int]] = {}
        self.windows: dict[str, dict[str, int] | None] = {}
        self.history: collections.deque[dict[str, Any]] = collections.deque(maxlen=HISTORY_SECONDS)

    @staticmethod
    def _counter_window(
        previous_sample: Mapping[str, Any] | None,
        current_sample: Mapping[str, Any],
    ) -> dict[str, int] | None:
        if previous_sample is None:
            return None
        elapsed_ms = (
            int(current_sample["monotonic_ms"])
            - int(previous_sample["monotonic_ms"])
        )
        if elapsed_ms <= 0:
            # A member reboot resets its monotonic clock while the durable
            # Watchdog sequence continues. Fall back to the signed wall clock
            # for that one boundary window.
            elapsed_ms = int(current_sample["unix_ms"]) - int(
                previous_sample["unix_ms"]
            )
        if elapsed_ms <= 0:
            return None
        previous = previous_sample["inference"]
        current = current_sample["inference"]
        window = {"elapsed_milliseconds": elapsed_ms}
        for field in COUNTER_FIELDS:
            current_value = int(current[field])
            previous_value = int(previous[field])
            window[field] = (
                current_value - previous_value
                if current_value >= previous_value
                else current_value
            )
        return window

    @staticmethod
    def _rates(windows: list[Mapping[str, int]]) -> dict[str, float | None]:
        unavailable = {field: None for field in RATE_FIELDS}
        if not windows:
            return unavailable

        def wall_rate(counter: str) -> float:
            return sum(
                float(window[counter]) * 1000.0 / float(window["elapsed_milliseconds"])
                for window in windows
            )

        totals = {
            field: sum(int(window[field]) for window in windows)
            for field in COUNTER_FIELDS
        }
        completed = totals["requests_completed"]
        settled = (
            completed
            + totals["requests_failed"]
            + totals["requests_cancelled"]
        )
        exact = totals["exact_token_requests"]
        prefill_tokens = max(0, totals["input_tokens"] - totals["cached_tokens"])
        live_prefill_rate = sum(
            float(max(0, window["input_tokens"] - window["cached_tokens"]))
            * 1000.0
            / float(window["elapsed_milliseconds"])
            for window in windows
        )
        live_decode_rate = wall_rate("output_tokens")
        return {
            "requests_per_second": wall_rate("requests_received"),
            "failures_per_second": wall_rate("requests_failed"),
            "cancellations_per_second": wall_rate("requests_cancelled"),
            "retries_per_second": wall_rate("requests_retried"),
            "input_tokens_per_second": wall_rate("input_tokens"),
            "output_tokens_per_second": wall_rate("output_tokens"),
            "aggregate_tokens_per_second": wall_rate("output_tokens"),
            "cached_tokens_per_second": wall_rate("cached_tokens"),
            "prefill_tokens_per_second": (
                float(prefill_tokens) * 1000.0 / totals["ttft_milliseconds"]
                if exact > 0 and totals["ttft_milliseconds"] > 0
                else live_prefill_rate if prefill_tokens > 0 else None
            ),
            "decode_tokens_per_second": (
                float(totals["output_tokens"]) * 1000.0
                / totals["decode_milliseconds"]
                if exact > 0 and totals["decode_milliseconds"] > 0
                else live_decode_rate if totals["output_tokens"] > 0 else None
            ),
            "average_queue_milliseconds": (
                float(totals["queue_milliseconds"]) / settled
                if settled > 0
                else None
            ),
            "average_ttft_milliseconds": (
                float(totals["ttft_milliseconds"]) / completed
                if completed > 0 and totals["ttft_milliseconds"] > 0
                else None
            ),
            "average_decode_milliseconds": (
                float(totals["decode_milliseconds"]) / completed
                if completed > 0 and totals["decode_milliseconds"] > 0
                else None
            ),
            "prefix_cache_hit_ratio": (
                float(totals["prefix_cache_hits"]) / exact if exact > 0 else None
            ),
            "exact_token_ratio": (
                float(exact) / settled if settled > 0 else None
            ),
        }

    def update(self, sample: Mapping[str, Any]) -> dict[str, Any]:
        validated = validate_sample(dict(sample))
        member_id = validated["member_id"]
        now_ms = int(self.clock() * 1000)
        if not 0 <= now_ms - validated["unix_ms"] <= MAX_SAMPLE_AGE_SECONDS * 1000:
            raise TelemetryError("member telemetry sample is stale or future-dated")
        with self.lock:
            if member_id not in self.members and len(self.members) >= MAX_MEMBERS:
                raise TelemetryError("site telemetry member limit exceeded")
            prior_sample = self.members.get(member_id)
            if prior_sample is not None:
                if validated == prior_sample:
                    return self._snapshot(now_ms)
                if validated["sequence"] <= prior_sample["sequence"]:
                    raise TelemetryError("member telemetry sequence did not advance")
            self.windows[member_id] = self._counter_window(
                prior_sample, validated
            )
            current = validated["inference"]
            previous = self.previous.setdefault(member_id, {})
            offsets = self.offsets.setdefault(member_id, {})
            for field in COUNTER_FIELDS:
                if field in previous and current[field] < previous[field]:
                    offsets[field] = offsets.get(field, 0) + previous[field]
                previous[field] = current[field]
            self.members[member_id] = validated
            snapshot = self._snapshot(now_ms)
            history_point = {
                "schema_version": TELEMETRY_SCHEMA_VERSION,
                "unix_ms": snapshot["unix_ms"],
                "aggregate": snapshot["aggregate"],
            }
            if not self.history or self.history[-1]["unix_ms"] // 1000 != now_ms // 1000:
                self.history.append(history_point)
            else:
                self.history[-1] = history_point
            return snapshot

    def reconcile_members(self, active_member_ids: set[str]) -> None:
        """Forget live state for identities that are no longer site members."""
        if (
            len(active_member_ids) > MAX_MEMBERS
            or any(not isinstance(member_id, str) or not ID_RE.fullmatch(member_id)
                   for member_id in active_member_ids)
        ):
            raise TelemetryError("active telemetry member identities are invalid")
        with self.lock:
            removed = set(self.members) - active_member_ids
            for member_id in removed:
                self.members.pop(member_id, None)
                self.previous.pop(member_id, None)
                self.offsets.pop(member_id, None)
                self.windows.pop(member_id, None)

    def _snapshot(self, now_ms: int) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        totals = {field: 0 for field in COUNTER_FIELDS}
        active_requests = 0
        connected_clients = 0
        queued_requests = 0
        fresh_windows: list[Mapping[str, int]] = []
        for member_id in sorted(self.members):
            sample = self.members[member_id]
            stale = not 0 <= now_ms - sample["unix_ms"] <= MAX_SAMPLE_AGE_SECONDS * 1000
            inference = sample["inference"]
            logical = {
                field: self.offsets[member_id].get(field, 0) + inference[field]
                for field in COUNTER_FIELDS
            }
            for field, amount in logical.items():
                totals[field] += amount
            if not stale:
                active_requests += inference["active_requests"]
                connected_clients += inference["connected_clients"]
                queued_requests += inference["queued_requests"]
                window = self.windows.get(member_id)
                if window is not None:
                    fresh_windows.append(window)
            rows.append(
                {
                    "sample": sample,
                    "stale": stale,
                    "logical_counters": logical,
                    "rates": self._rates(
                        []
                        if stale or self.windows.get(member_id) is None
                        else [self.windows[member_id]]  # type: ignore[list-item]
                    ),
                }
            )
        return {
            "schema_version": TELEMETRY_SCHEMA_VERSION,
            "unix_ms": now_ms,
            "members": rows,
            "aggregate": {
                "active_requests": active_requests,
                "connected_clients": connected_clients,
                "queued_requests": queued_requests,
                **totals,
                "rates": self._rates(fresh_windows),
            },
        }

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return self._snapshot(int(self.clock() * 1000))

    def recent(self, *, seconds: int | None = None) -> list[dict[str, Any]]:
        with self.lock:
            rows = list(self.history)
            if seconds is None:
                return rows
            if not isinstance(seconds, int) or isinstance(seconds, bool) or not 0 <= seconds <= HISTORY_SECONDS:
                raise TelemetryError(
                    f"telemetry history must be between 0 and {HISTORY_SECONDS} seconds"
                )
            if seconds == 0:
                return []
            cutoff_ms = int(self.clock() * 1000) - seconds * 1000
            return [row for row in rows if row["unix_ms"] >= cutoff_ms]


def _member_id_from_certificate(certificate: Mapping[str, Any]) -> str:
    identities = [
        value.removeprefix("urn:letsinfer:member:")
        for kind, value in certificate.get("subjectAltName", ())
        if kind == "URI" and value.startswith("urn:letsinfer:member:")
    ]
    if len(identities) != 1 or not ID_RE.fullmatch(identities[0]):
        raise TelemetryError("telemetry peer member identity is invalid")
    return identities[0]


def post_member_sample(
    endpoint: str,
    *,
    identity: SiteIdentity,
    document: Mapping[str, Any],
) -> None:
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise TelemetryError("telemetry coordinator endpoint must be an HTTPS origin")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(site_ca_certificate_path())
    context.load_cert_chain(member_certificate_path(), member_key_path())
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 9770,
        context=context,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    payload = canonical_bytes(dict(document))
    try:
        connection.connect()
        if connection.sock is None:
            raise TelemetryError("telemetry TLS connection is unavailable")
        if _member_id_from_certificate(connection.sock.getpeercert()) != identity.coordinator_id:
            raise TelemetryError("telemetry TLS peer is not the site coordinator")
        connection.request(
            "POST",
            "/node/v1/telemetry",
            body=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise TelemetryError(f"telemetry publication failed: {error}") from error
    finally:
        connection.close()
    if len(raw) > MAX_RESPONSE_BYTES:
        raise TelemetryError("telemetry response is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TelemetryError("telemetry response is invalid") from error
    if response.status != 200 or value != {"protocol": PROTOCOL, "accepted": True}:
        detail = value.get("error") if isinstance(value, dict) else None
        raise TelemetryError(str(detail or "telemetry publication was rejected"))


class TelemetryPublisher:
    """One bounded background publisher; failures never stop safety/control."""

    def __init__(
        self,
        identity: SiteIdentity,
        *,
        watchdog_port: int,
        watchdog_ca_file: pathlib.Path,
        watchdog_controller_cert_file: pathlib.Path,
        watchdog_controller_key_file: pathlib.Path,
        local_accept: Callable[[Mapping[str, Any], str], None] | None = None,
        endpoint: str | None = None,
    ) -> None:
        if (local_accept is None) == (endpoint is None):
            raise TelemetryError("telemetry publisher requires exactly one destination")
        self.identity = identity
        self.watchdog_port = watchdog_port
        self.watchdog_ca_file = watchdog_ca_file
        self.watchdog_controller_cert_file = watchdog_controller_cert_file
        self.watchdog_controller_key_file = watchdog_controller_key_file
        self.local_accept = local_accept
        self.endpoint = endpoint
        self.stop_event = threading.Event()
        self.last_sequence: int | None = None
        self.last_error: str | None = None
        self.thread = threading.Thread(
            target=self._run, name="letsinfer-node-telemetry", daemon=True
        )

    def start(self) -> None:
        self.thread.start()

    def alive(self) -> bool:
        """Return whether the single telemetry worker is still supervised."""

        return self.thread.is_alive()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                for sample in watchdog_live_samples(
                    member_id=self.identity.member_id,
                    port=self.watchdog_port,
                    ca_file=self.watchdog_ca_file,
                    controller_cert_file=self.watchdog_controller_cert_file,
                    controller_key_file=self.watchdog_controller_key_file,
                    stop_event=self.stop_event,
                ):
                    if sample["sequence"] == self.last_sequence:
                        continue
                    if self.local_accept is not None:
                        # The main node delivers its own Watchdog sample directly
                        # inside this process.  Do not invoke the external OpenSSL
                        # signing path for data that never crosses a trust boundary.
                        self.local_accept(sample, self.identity.member_id)
                    else:
                        document = signed_sample(sample)
                        post_member_sample(
                            str(self.endpoint), identity=self.identity, document=document
                        )
                    self.last_sequence = sample["sequence"]
                    self.last_error = None
                if not self.stop_event.is_set():
                    self.stop_event.wait(1.0)
            except TelemetryError as error:
                if self.stop_event.is_set():
                    break
                self.last_error = str(error)[:256]
            self.stop_event.wait(1.0)

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=REQUEST_TIMEOUT_SECONDS + 1)


def document_sha256(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(dict(document))).hexdigest()
