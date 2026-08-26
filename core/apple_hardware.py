#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed Apple Silicon capability and memory discovery."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import time
from typing import Any

from .site.topology import validate_member_facts


class AppleHardwareError(RuntimeError):
    """Apple hardware identity or live capacity is unavailable."""


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as error:
        raise AppleHardwareError(f"required Apple tool is unavailable: {command[0]}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise AppleHardwareError(f"{pathlib.Path(command[0]).name} failed: {detail}")
    return result.stdout.strip()


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


def available_memory_gib() -> int:
    output = _run(["/usr/bin/vm_stat"])
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
    return max(0, pages * page_size // (1024**3))


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
