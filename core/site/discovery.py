#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Public, credential-free DNS-SD advertisement for a Let's Infer member."""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

from .control import PROTOCOL, ControlError
from .state import SiteIdentity


SERVICE_TYPE = "_letsinfer._tcp"
MAX_TXT_VALUE_BYTES = 200
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DISCOVERY_TXT_FIELDS = {
    "protocol",
    "node",
    "machine",
    "role",
    "state",
    "key",
    "tls",
    "control",
    "inference",
    "inference_port",
}


def _txt_value(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ControlError(f"discovery {field} must be text")
    normalized = unicodedata.normalize("NFC", value.strip())
    if (
        not normalized
        or len(normalized.encode("utf-8")) > MAX_TXT_VALUE_BYTES
        or any(unicodedata.category(character).startswith("C") for character in normalized)
        or "=" in normalized
    ):
        raise ControlError(f"discovery {field} is invalid")
    return normalized


def advertisement(
    identity: SiteIdentity,
    *,
    port: int,
    certificate_sha256: str,
    direct_connectx: bool = False,
    adoptable: bool = False,
) -> dict[str, Any]:
    if not isinstance(port, int) or isinstance(port, bool) or port not in range(1, 65536):
        raise ControlError("discovery port is invalid")
    if not isinstance(certificate_sha256, str) or not SHA256_RE.fullmatch(
        certificate_sha256
    ):
        raise ControlError("discovery certificate identity is invalid")
    if not isinstance(direct_connectx, bool) or not isinstance(adoptable, bool):
        raise ControlError("discovery state flags are invalid")
    if adoptable and not direct_connectx:
        raise ControlError("discovery adoption requires a direct ConnectX link")
    record = {
        "name": _txt_value(f"Let's Infer — {identity.display_name}", "name"),
        "service_type": SERVICE_TYPE,
        "port": port,
        "txt": {
            "protocol": "1",
            "node": identity.site_id,
            "machine": identity.member_id,
            "role": identity.role,
            "state": "adoptable" if adoptable else "configured",
            "key": identity.member_public_key_sha256,
            "tls": certificate_sha256,
            "control": PROTOCOL,
            "inference": "http",
            "inference_port": "8000",
        },
    }
    if direct_connectx:
        record["txt"]["direct"] = "connectx"
    for key, value in record["txt"].items():
        _txt_value(key, "TXT key")
        _txt_value(value, f"TXT {key}")
    return record


def publisher_command(
    record: Mapping[str, Any],
    *,
    search_path: str | None = None,
) -> list[str]:
    name = _txt_value(record.get("name"), "name")
    service_type = record.get("service_type")
    port = record.get("port")
    txt = record.get("txt")
    if (
        service_type != SERVICE_TYPE
        or not isinstance(port, int)
        or isinstance(port, bool)
        or port not in range(1, 65536)
    ):
        raise ControlError("discovery record endpoint is invalid")
    if not isinstance(txt, Mapping) or not txt:
        raise ControlError("discovery TXT record is invalid")
    fields = set(txt)
    if not DISCOVERY_TXT_FIELDS.issubset(fields) or fields - (
        DISCOVERY_TXT_FIELDS | {"direct"}
    ):
        raise ControlError("discovery TXT record fields are invalid")
    if "direct" in txt and txt.get("direct") != "connectx":
        raise ControlError("discovery direct-link hint is invalid")
    fields = [f"{_txt_value(key, 'TXT key')}={_txt_value(value, f'TXT {key}')}" for key, value in sorted(txt.items())]
    avahi = shutil.which("avahi-publish-service", path=search_path)
    if avahi:
        return [avahi, name, SERVICE_TYPE, str(port), *fields]
    dns_sd = shutil.which("dns-sd", path=search_path)
    if dns_sd:
        return [dns_sd, "-R", name, SERVICE_TYPE, "local", str(port), *fields]
    raise ControlError(
        "DNS-SD publisher is unavailable; install avahi-utils on Linux"
    )


class Publisher:
    def __init__(self, command: Sequence[str]) -> None:
        if not command or not pathlib.Path(command[0]).is_absolute():
            raise ControlError("discovery publisher command is invalid")
        self.command = list(command)
        self.process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        if self.process is not None:
            raise ControlError("discovery publisher is already started")
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as error:
            raise ControlError(f"cannot start DNS-SD publisher: {error}") from error
        try:
            result = self.process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            return
        raise ControlError(f"DNS-SD publisher exited during startup with status {result}")

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self) -> None:
        process = self.process
        self.process = None
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
