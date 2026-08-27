#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed Apple Silicon capability and memory discovery."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import subprocess
import time
from collections.abc import Iterator
from typing import Any

from .site.telemetry import (
    COUNTER_FIELDS,
    TELEMETRY_SCHEMA_VERSION,
    TelemetryError,
    validate_sample,
)
from .site.topology import validate_member_facts


class AppleHardwareError(RuntimeError):
    """Apple hardware identity or live capacity is unavailable."""


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except OSError as error:
        raise AppleHardwareError(f"required Apple tool is unavailable: {command[0]}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise AppleHardwareError(f"{pathlib.Path(command[0]).name} failed: {detail}")
    return result.stdout.strip()


def _run_bytes(command: list[str]) -> bytes:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except OSError as error:
        raise AppleHardwareError(f"required Apple tool is unavailable: {command[0]}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        raise AppleHardwareError(f"{pathlib.Path(command[0]).name} failed: {detail}")
    return result.stdout


def _sysctl(name: str) -> str:
    return _run(["/usr/sbin/sysctl", "-n", name])


def platform_uuid() -> str:
    output = _run(
        ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]
    )
    matches = re.findall(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"', output)
    if len(matches) != 1:
        raise AppleHardwareError("IOPlatformUUID is unavailable or ambiguous")
    return matches[0].lower()


def chip_name() -> str:
    brand = _sysctl("machdep.cpu.brand_string")
    if not brand or len(brand.encode("utf-8")) > 128:
        raise AppleHardwareError("Apple chip identity is unavailable")
    return brand


def total_memory_gib() -> int:
    try:
        value = int(_sysctl("hw.memsize")) // (1024**3)
    except ValueError as error:
        raise AppleHardwareError("Apple unified-memory size is invalid") from error
    if value <= 0:
        raise AppleHardwareError("Apple unified-memory size is unavailable")
    return value


def _available_memory_bytes(output: str) -> int:
    page_match = re.search(r"page size of ([0-9]+) bytes", output)
    if page_match is None:
        raise AppleHardwareError("vm_stat page size is unavailable")
    page_size = int(page_match.group(1))
    wanted = {
        "Pages free",
        "Pages inactive",
        "Pages speculative",
        "Pages purgeable",
    }
    pages = 0
    for line in output.splitlines():
        label, separator, raw = line.partition(":")
        if separator and label in wanted:
            try:
                pages += int(raw.strip().rstrip("."))
            except ValueError as error:
                raise AppleHardwareError("vm_stat counter is invalid") from error
    return max(0, pages * page_size)


def available_memory_gib() -> int:
    return _available_memory_bytes(_run(["/usr/bin/vm_stat"])) // (1024**3)


def _cpu_ticks() -> tuple[int, int, int, int]:
    """Read aggregate CPU ticks through the stable Mach host API."""

    if os.uname().sysname != "Darwin":
        raise AppleHardwareError("Mach CPU statistics require macOS")
    try:
        import ctypes

        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        library.mach_host_self.restype = ctypes.c_uint
        library.host_statistics.argtypes = (
            ctypes.c_uint,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_uint),
        )
        ticks = (ctypes.c_uint * 4)()
        count = ctypes.c_uint(4)
        result = library.host_statistics(
            library.mach_host_self(),
            3,  # HOST_CPU_LOAD_INFO
            ctypes.cast(ticks, ctypes.POINTER(ctypes.c_int)),
            ctypes.byref(count),
        )
    except (AttributeError, OSError) as error:
        raise AppleHardwareError("Mach CPU statistics are unavailable") from error
    if result != 0 or count.value != 4:
        raise AppleHardwareError("Mach CPU statistics failed")
    return tuple(int(value) for value in ticks)  # type: ignore[return-value]


def _gpu_metrics(payload: bytes, total_memory_bytes: int) -> dict[str, Any]:
    try:
        rows = plistlib.loads(payload)
    except plistlib.InvalidFileException as error:
        raise AppleHardwareError("Apple GPU statistics are invalid") from error
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise AppleHardwareError("Apple GPU statistics are unavailable or ambiguous")
    values = rows[0].get("PerformanceStatistics")
    if not isinstance(values, dict):
        raise AppleHardwareError("Apple GPU performance statistics are unavailable")

    def percent(name: str) -> int:
        value = values.get(name)
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100 else -1

    allocated = values.get("Alloc system memory")
    memory_percent = (
        min(100, max(0, round(allocated * 100 / total_memory_bytes)))
        if isinstance(allocated, int)
        and not isinstance(allocated, bool)
        and allocated >= 0
        and total_memory_bytes > 0
        else -1
    )
    engines = [
        value
        for value in (
            percent("Renderer Utilization %"),
            percent("Tiler Utilization %"),
        )
        if value >= 0
    ]
    return {
        "gpu_percent": percent("Device Utilization %"),
        "gpu_memory_percent": memory_percent,
        "gpu_engine_percent": engines,
    }


def _default_interface(output: str) -> str:
    match = re.search(r"^\s*interface:\s*([A-Za-z0-9._-]+)\s*$", output, re.MULTILINE)
    if match is None:
        raise AppleHardwareError("default network interface is unavailable")
    return match.group(1)


def _network_counters(output: str, interface: str) -> tuple[int, int]:
    rows: list[tuple[int, int]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 10 or fields[0] != interface or not fields[2].startswith("<Link#"):
            continue
        try:
            rows.append((int(fields[-5]), int(fields[-2])))
        except ValueError as error:
            raise AppleHardwareError("network byte counters are invalid") from error
    if len(rows) != 1:
        raise AppleHardwareError("default network byte counters are unavailable")
    return rows[0]


def _gateway_inference(path: pathlib.Path, *, now_unix: float) -> dict[str, Any]:
    fields = {
        "active_requests",
        "connected_clients",
        "queued_requests",
        *COUNTER_FIELDS,
    }
    unavailable = {
        "gateway_available": False,
        **{field: 0 for field in fields},
    }
    if not path.exists():
        return unavailable
    if path.is_symlink():
        raise AppleHardwareError("gateway telemetry cannot be a symlink")
    details = path.stat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_mode & 0o022
        or details.st_size > 16 * 1024
    ):
        raise AppleHardwareError("gateway telemetry ownership or size is invalid")
    try:
        values = dict(
            line.partition("=")[::2]
            for line in path.read_text(encoding="ascii").splitlines()
            if "=" in line
        )
        if set(values) != fields | {"version"} or values.get("version") != "2":
            raise ValueError
        counters = {field: int(values[field]) for field in fields}
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise AppleHardwareError("gateway telemetry is invalid") from error
    if any(value < 0 for value in counters.values()):
        raise AppleHardwareError("gateway telemetry contains a negative counter")
    age = max(0.0, now_unix - details.st_mtime)
    return {
        "gateway_available": age <= 3.5,
        **counters,
    }


class AppleTelemetrySampler:
    """Produce the generic telemetry contract from non-privileged macOS APIs."""

    def __init__(
        self,
        member_id: str,
        *,
        data_path: pathlib.Path,
        gateway_telemetry_path: pathlib.Path,
    ) -> None:
        self.member_id = member_id
        self.data_path = data_path
        self.gateway_telemetry_path = gateway_telemetry_path
        self.total_memory_bytes = total_memory_gib() * 1024**3
        self.previous_cpu: tuple[int, int, int, int] | None = None
        self.previous_network: tuple[int, int] | None = None
        self.previous_monotonic: float | None = None
        self.sequence = 0

    def _cpu_percent(self, current: tuple[int, int, int, int]) -> int:
        previous = self.previous_cpu
        self.previous_cpu = current
        if previous is None:
            return -1
        deltas = [max(0, value - prior) for value, prior in zip(current, previous)]
        total = sum(deltas)
        return min(100, max(0, round(100 * (deltas[0] + deltas[1] + deltas[3]) / total))) if total else -1

    def _network_rates(
        self,
        current: tuple[int, int],
        now_monotonic: float,
    ) -> tuple[int, int]:
        previous = self.previous_network
        previous_time = self.previous_monotonic
        self.previous_network = current
        self.previous_monotonic = now_monotonic
        if previous is None or previous_time is None or now_monotonic <= previous_time:
            return -1, -1
        elapsed = now_monotonic - previous_time
        return tuple(
            min(2**32 - 1, max(0, round((value - prior) / elapsed / 1024)))
            for value, prior in zip(current, previous)
        )  # type: ignore[return-value]

    def sample(self) -> dict[str, Any]:
        now_unix_ms = int(time.time() * 1000)
        now_monotonic = time.monotonic()
        self.sequence = max(self.sequence + 1, now_unix_ms)

        available_bytes = min(
            self.total_memory_bytes,
            _available_memory_bytes(_run(["/usr/bin/vm_stat"])),
        )
        memory_used = self.total_memory_bytes - available_bytes
        disk = shutil.disk_usage(self.data_path)
        try:
            interface = _default_interface(
                _run(["/sbin/route", "-n", "get", "default"])
            )
            network = _network_counters(
                _run(["/usr/sbin/netstat", "-ibn", "-I", interface]),
                interface,
            )
            rx_rate, tx_rate = self._network_rates(network, now_monotonic)
        except AppleHardwareError:
            self.previous_network = None
            self.previous_monotonic = None
            rx_rate, tx_rate = -1, -1
        try:
            gpu = _gpu_metrics(
                _run_bytes(["/usr/sbin/ioreg", "-r", "-c", "AGXAccelerator", "-d", "1", "-a"]),
                self.total_memory_bytes,
            )
        except AppleHardwareError:
            gpu = {
                "gpu_percent": -1,
                "gpu_memory_percent": -1,
                "gpu_engine_percent": [],
            }
        try:
            inference = _gateway_inference(
                self.gateway_telemetry_path,
                now_unix=now_unix_ms / 1000,
            )
        except AppleHardwareError:
            inference = {
                "gateway_available": False,
                **{
                    field: 0
                    for field in {
                        "active_requests",
                        "connected_clients",
                        "queued_requests",
                        *COUNTER_FIELDS,
                    }
                },
            }
        return validate_sample({
            "schema_version": TELEMETRY_SCHEMA_VERSION,
            "member_id": self.member_id,
            "sequence": self.sequence,
            "unix_ms": now_unix_ms,
            "monotonic_ms": int(now_monotonic * 1000),
            "system": {
                "cpu_core_percent": [],
                "cpu_percent": self._cpu_percent(_cpu_ticks()),
                **gpu,
                "memory_percent": round(memory_used * 100 / self.total_memory_bytes),
                "disk_percent": round(disk.used * 100 / disk.total),
                "system_temp_deci_c": -1,
                "gpu_temp_deci_c": -1,
                "nvme_temp_deci_c": -1,
                "power_deci_w": -1,
                "load1_centi": max(0, min(65_535, round(os.getloadavg()[0] * 100))),
                "memory_used_mib": memory_used // 1024**2,
                "memory_total_mib": self.total_memory_bytes // 1024**2,
                "disk_used_mib": min(2**32 - 1, disk.used // 1024**2),
                "disk_total_mib": min(2**32 - 1, disk.total // 1024**2),
                "network_rx_kib_s": rx_rate,
                "network_tx_kib_s": tx_rate,
                "disk_read_kib_s": -1,
                "disk_write_kib_s": -1,
                "cpu_clock_mhz": -1,
                "gpu_clock_mhz": -1,
                "vram_clock_mhz": -1,
                "system_ram_clock_mhz": -1,
            },
            "inference": inference,
            "workload": {
                "type": 0,
                "id": 0,
                "gpu_available": True,
                "throttled": False,
            },
        })

    def samples(self, stop_event: Any) -> Iterator[dict[str, Any]]:
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                yield self.sample()
            except (AppleHardwareError, OSError) as error:
                raise TelemetryError(
                    f"macOS telemetry collection failed: {error}"
                ) from error
            stop_event.wait(max(0.0, 1.0 - (time.monotonic() - started)))


def device_fingerprint() -> dict[str, Any]:
    if os.uname().sysname != "Darwin" or os.uname().machine != "arm64":
        raise AppleHardwareError("Apple native Engines require Apple Silicon macOS")
    identifier = hashlib.sha256(platform_uuid().encode("ascii")).hexdigest()
    return {
        "platform": "macos/arm64",
        "accelerator": {
            "vendor": "apple",
            "architecture": "apple-silicon",
            "count": 1,
            "partitioning": "full-device",
            "names": [chip_name()],
            "minimum_memory_gib": total_memory_gib(),
            "uuids": [f"APPLE-{identifier}"],
        },
        "memory": {
            "topology": "unified",
            "total_gib": total_memory_gib(),
            "addressing_modes": ["UNIFIED"],
        },
    }


def member_facts(
    member_id: str,
    *,
    data_path: pathlib.Path,
    product_version: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    device = device_fingerprint()
    usage = shutil.disk_usage(data_path)
    available = available_memory_gib()
    facts = {
        "schema_version": 1,
        "member_id": member_id,
        "observed_at_unix": int(time.time()) if now_unix is None else now_unix,
        "platform": device["platform"],
        "accelerator": {
            "vendor": device["accelerator"]["vendor"],
            "architecture": device["accelerator"]["architecture"],
            "count": 1,
            "partitioning": "full-device",
            "minimum_memory_gib": device["accelerator"]["minimum_memory_gib"],
            "devices": list(device["accelerator"]["uuids"]),
        },
        "memory": {
            "topology": "unified",
            "total_gib": device["memory"]["total_gib"],
            "available_gib": available,
        },
        "storage": {
            "total_gib": usage.total // (1024**3),
            "available_gib": usage.free // (1024**3),
            "cache_available_gib": usage.free // (1024**3),
        },
        "network": {"interfaces": [], "links": []},
        "software": {
            "driver": "Metal",
            "container_runtime": "native-process",
            "letsinfer_version": product_version,
        },
        "health": {
            "state": "healthy",
            "memory_pressure": available <= 1,
            "protection_trip": False,
            "max_temperature_c": -1,
        },
    }
    return validate_member_facts(facts)


def hardware_fingerprint_sha256() -> str:
    material = {
        "contract": "letsinfer-apple-hardware-fingerprint-v1",
        "device": device_fingerprint(),
        "platform_uuid": platform_uuid(),
    }
    return hashlib.sha256(
        (json.dumps(material, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
