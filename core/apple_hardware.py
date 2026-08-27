#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed Apple Silicon capability and memory discovery."""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import pathlib
import plistlib
import re
import shutil
import socket
import stat
import struct
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


class _SMCVersion(ctypes.Structure):
    _fields_ = [
        ("major", ctypes.c_uint8),
        ("minor", ctypes.c_uint8),
        ("build", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("release", ctypes.c_uint16),
    ]


class _SMCLimits(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint16),
        ("length", ctypes.c_uint16),
        ("cpu", ctypes.c_uint32),
        ("gpu", ctypes.c_uint32),
        ("memory", ctypes.c_uint32),
    ]


class _SMCKeyInfo(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("attributes", ctypes.c_uint8),
    ]


class _SMCKeyData(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_uint32),
        ("version", _SMCVersion),
        ("limits", _SMCLimits),
        ("info", _SMCKeyInfo),
        ("result", ctypes.c_uint8),
        ("status", ctypes.c_uint8),
        ("data8", ctypes.c_uint8),
        ("data32", ctypes.c_uint32),
        ("bytes", ctypes.c_uint8 * 32),
    ]


def _fourcc(value: str) -> int:
    encoded = value.encode("ascii")
    if len(encoded) != 4:
        raise AppleHardwareError("Apple SMC key is invalid")
    return int.from_bytes(encoded, "big")


def _smc_temperature(raw: bytes, data_type: int) -> float | None:
    """Decode the temperature formats used by Apple Silicon SMC keys."""

    try:
        if data_type == _fourcc("flt ") and len(raw) == 4:
            value = float(struct.unpack("<f", raw)[0])
        elif data_type == _fourcc("sp78") and len(raw) == 2:
            value = int.from_bytes(raw, "big", signed=True) / 256
        elif data_type == _fourcc("fpe2") and len(raw) == 2:
            value = int.from_bytes(raw, "big") / 4
        else:
            return None
    except (OverflowError, struct.error):
        return None
    return value if math.isfinite(value) and 10 <= value <= 150 else None


def _temperature_group(key: str) -> str | None:
    # Apple does not publish the individual SMC key map. These stable families
    # are used by established Apple Silicon monitoring tools.
    if key.startswith(("Tp", "Te", "Ts")):
        return "cpu"
    # TRDX is the GPU die hotspot on current Apple Silicon. Some M4 Tg keys
    # expose calibration offsets such as -4.0 and 1.8 rather than temperatures.
    if key == "TRDX" or key.startswith("Tg"):
        return "gpu"
    return None


class _AppleSMCTemperatureReader:
    """Read Apple Silicon CPU/GPU sensors without root or subprocesses."""

    _SELECTOR = 2
    _READ_BYTES = 5
    _READ_INDEX = 8
    _READ_INFO = 9

    def __init__(self) -> None:
        if os.uname().sysname != "Darwin" or os.uname().machine != "arm64":
            raise AppleHardwareError(
                "Apple SMC temperatures require Apple Silicon macOS"
            )
        if ctypes.sizeof(_SMCKeyData) != 80:
            raise AppleHardwareError("Apple SMC data layout is unsupported")
        try:
            self._iokit = ctypes.CDLL(
                "/System/Library/Frameworks/IOKit.framework/IOKit"
            )
            self._system = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
            self._configure_functions()
            self._connection = self._open_connection()
            self._keys = self._discover_temperature_keys()
        except (AttributeError, OSError) as error:
            raise AppleHardwareError(
                "Apple SMC temperatures are unavailable"
            ) from error
        if not any(group == "cpu" for group, _, _ in self._keys):
            self.close()
            raise AppleHardwareError(
                "Apple SMC CPU temperature keys are unavailable"
            )

    def _configure_functions(self) -> None:
        self._iokit.IOServiceMatching.argtypes = (ctypes.c_char_p,)
        self._iokit.IOServiceMatching.restype = ctypes.c_void_p
        self._iokit.IOServiceGetMatchingServices.argtypes = (
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint),
        )
        self._iokit.IOServiceGetMatchingServices.restype = ctypes.c_int
        self._iokit.IOIteratorNext.argtypes = (ctypes.c_uint,)
        self._iokit.IOIteratorNext.restype = ctypes.c_uint
        self._iokit.IORegistryEntryGetName.argtypes = (
            ctypes.c_uint,
            ctypes.c_void_p,
        )
        self._iokit.IORegistryEntryGetName.restype = ctypes.c_int
        self._iokit.IOObjectRelease.argtypes = (ctypes.c_uint,)
        self._iokit.IOObjectRelease.restype = ctypes.c_int
        self._iokit.IOServiceOpen.argtypes = (
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint),
        )
        self._iokit.IOServiceOpen.restype = ctypes.c_int
        self._iokit.IOServiceClose.argtypes = (ctypes.c_uint,)
        self._iokit.IOServiceClose.restype = ctypes.c_int
        self._iokit.IOConnectCallStructMethod.argtypes = (
            ctypes.c_uint,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
        )
        self._iokit.IOConnectCallStructMethod.restype = ctypes.c_int
        self._system.mach_task_self.argtypes = ()
        self._system.mach_task_self.restype = ctypes.c_uint

    def _open_connection(self) -> int:
        matching = self._iokit.IOServiceMatching(b"AppleSMC")
        if not matching:
            raise AppleHardwareError("Apple SMC service is unavailable")
        iterator = ctypes.c_uint()
        if self._iokit.IOServiceGetMatchingServices(
            0, matching, ctypes.byref(iterator)
        ) != 0:
            raise AppleHardwareError("Apple SMC service lookup failed")
        connection = ctypes.c_uint()
        try:
            while True:
                service = int(self._iokit.IOIteratorNext(iterator.value))
                if service == 0:
                    break
                try:
                    name = ctypes.create_string_buffer(128)
                    if (
                        self._iokit.IORegistryEntryGetName(service, name) == 0
                        and name.value == b"AppleSMCKeysEndpoint"
                        and self._iokit.IOServiceOpen(
                            service,
                            self._system.mach_task_self(),
                            0,
                            ctypes.byref(connection),
                        )
                        == 0
                    ):
                        break
                finally:
                    self._iokit.IOObjectRelease(service)
        finally:
            self._iokit.IOObjectRelease(iterator.value)
        if connection.value == 0:
            raise AppleHardwareError("Apple SMC connection failed")
        return int(connection.value)

    def _call(self, input_data: _SMCKeyData) -> _SMCKeyData | None:
        output = _SMCKeyData()
        output_size = ctypes.c_size_t(ctypes.sizeof(output))
        status = self._iokit.IOConnectCallStructMethod(
            self._connection,
            self._SELECTOR,
            ctypes.byref(input_data),
            ctypes.sizeof(input_data),
            ctypes.byref(output),
            ctypes.byref(output_size),
        )
        if (
            status != 0
            or output.result != 0
            or output_size.value != ctypes.sizeof(output)
        ):
            return None
        return output

    def _key_info(self, key: int) -> _SMCKeyInfo | None:
        request = _SMCKeyData()
        request.key = key
        request.data8 = self._READ_INFO
        response = self._call(request)
        return None if response is None else response.info

    def _key_value(self, key: int, info: _SMCKeyInfo) -> float | None:
        if info.size > 32:
            return None
        request = _SMCKeyData()
        request.key = key
        request.info = info
        request.data8 = self._READ_BYTES
        response = self._call(request)
        if response is None:
            return None
        return _smc_temperature(bytes(response.bytes[: info.size]), info.type)

    def _discover_temperature_keys(self) -> list[tuple[str, int, _SMCKeyInfo]]:
        count_info = self._key_info(_fourcc("#KEY"))
        if count_info is None:
            raise AppleHardwareError("Apple SMC key count is unavailable")
        request = _SMCKeyData()
        request.key = _fourcc("#KEY")
        request.info = count_info
        request.data8 = self._READ_BYTES
        response = self._call(request)
        if response is None or count_info.size != 4:
            raise AppleHardwareError("Apple SMC key count is invalid")
        count = int.from_bytes(bytes(response.bytes[:4]), "big")
        if not 0 < count <= 65_536:
            raise AppleHardwareError("Apple SMC key count is out of range")

        keys: list[tuple[str, int, _SMCKeyInfo]] = []
        for index in range(count):
            request = _SMCKeyData()
            request.data8 = self._READ_INDEX
            request.data32 = index
            indexed = self._call(request)
            if indexed is None:
                continue
            try:
                name = indexed.key.to_bytes(4, "big").decode("ascii")
            except UnicodeDecodeError:
                continue
            group = _temperature_group(name)
            info = self._key_info(indexed.key) if group is not None else None
            if info is not None and info.size <= 32:
                keys.append((group, indexed.key, info))
        return keys

    def read(self) -> tuple[int, int]:
        values: dict[str, list[float]] = {"cpu": [], "gpu": []}
        for group, key, info in self._keys:
            value = self._key_value(key, info)
            if value is not None:
                values[group].append(value)
        return tuple(
            round(max(values[group]) * 10) if values[group] else -1
            for group in ("cpu", "gpu")
        )  # type: ignore[return-value]

    def close(self) -> None:
        connection = getattr(self, "_connection", 0)
        if connection:
            self._iokit.IOServiceClose(connection)
            self._connection = 0

    def __del__(self) -> None:
        try:
            self.close()
        except (AttributeError, OSError):
            pass


_AUTOMATIC_TEMPERATURE_READER = object()


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
        temperature_reader: Any = _AUTOMATIC_TEMPERATURE_READER,
    ) -> None:
        self.member_id = member_id
        self.data_path = data_path
        self.gateway_telemetry_path = gateway_telemetry_path
        self.total_memory_bytes = total_memory_gib() * 1024**3
        self.previous_cpu: tuple[int, int, int, int] | None = None
        self.previous_network: tuple[int, int] | None = None
        self.previous_monotonic: float | None = None
        self.sequence = 0
        if temperature_reader is _AUTOMATIC_TEMPERATURE_READER:
            try:
                self.temperature_reader = _AppleSMCTemperatureReader()
            except AppleHardwareError:
                self.temperature_reader = None
        else:
            self.temperature_reader = temperature_reader

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
        cpu_temperature, gpu_temperature = -1, -1
        if self.temperature_reader is not None:
            try:
                cpu_temperature, gpu_temperature = self.temperature_reader.read()
            except (AppleHardwareError, OSError):
                pass
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
                "system_temp_deci_c": cpu_temperature,
                "gpu_temp_deci_c": gpu_temperature,
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
    chip = str(device["accelerator"]["names"][0])
    device_uuid = str(device["accelerator"]["uuids"][0])
    try:
        product_name = _sysctl("hw.model")
    except AppleHardwareError:
        product_name = None
    if (
        not isinstance(product_name, str)
        or not product_name
        or len(product_name.encode("utf-8")) > 128
    ):
        product_name = None
    inventory = {
        "hostname": socket.gethostname()[:255] or None,
        "operating_system": "macOS",
        "kernel_version": os.uname().release[:255] or None,
        "product_vendor": "Apple Inc.",
        "product_name": product_name,
        "product_version": None,
        "serial_number": None,
        "serial_source": None,
        "system_uuid": None,
        "machine_id_sha256": device_uuid.removeprefix("APPLE-"),
        "dmi_serial_requires_privilege": False,
        "board_vendor": "Apple Inc.",
        "board_name": product_name,
        "board_version": None,
        "board_serial": None,
        "chassis_vendor": "Apple Inc.",
        "chassis_type": None,
        "chassis_serial": None,
        "bios_vendor": "Apple Inc.",
        "bios_version": None,
        "bios_date": None,
        "cpu_model": chip,
        "cpu_core_count": os.cpu_count(),
        "gpu_name": chip,
        "gpu_uuid": device_uuid,
        "nvidia_driver_version": None,
        "dgx_name": None,
        "dgx_software_version": None,
        "dgx_base_build_version": None,
        "dgx_build_date": None,
        "dgx_commit_id": None,
        "dgx_platform": None,
        "dgx_update_date": None,
        "nvme_model": None,
        "nvme_serial": None,
        "nvme_firmware": None,
        "network_addresses": [],
        "default_network_interface": None,
        "uptime_seconds": int(time.monotonic()),
        "process_count": None,
        "active_users": [],
        "login_session_count": None,
        "last_login": None,
        "firmware_update_count": None,
        "containers": [],
    }
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
        "inventory": inventory,
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
