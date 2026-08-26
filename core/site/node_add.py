#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded LAN discovery and explicit node-add requests."""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import time
import urllib.parse
import uuid
from collections.abc import Mapping
from typing import Any

from .control import ControlError, DEFAULT_PORT, PinnedHTTPS
from .discovery import SERVICE_TYPE
from .state import data_root


PROTOCOL = "letsinfer-node-add-v1"
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_REQUEST_SECONDS = 300
MAX_DISCOVERY_SECONDS = 15


class NodeAddError(RuntimeError):
    """Node discovery or a pending add request is invalid."""


def request_path() -> pathlib.Path:
    return data_root() / "node-add-request.json"


def _private_document(path: pathlib.Path) -> dict[str, Any]:
    if path.is_symlink():
        raise NodeAddError("node-add request cannot be a symlink")
    try:
        details = path.stat()
        raw = path.read_bytes()
    except OSError as error:
        raise NodeAddError(f"cannot read node-add request: {error}") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) & 0o077
        or len(raw) > 16 * 1024
    ):
        raise NodeAddError("node-add request must be small, private, and user-owned")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NodeAddError("node-add request is invalid JSON") from error
    return validate_request(value)


def validate_request(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "protocol",
        "request_id",
        "main_node_id",
        "main_name",
        "main_endpoint",
        "main_certificate_sha256",
        "invite_id",
        "membership_code",
        "expires_at_unix",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise NodeAddError("node-add request schema is invalid")
    if value.get("protocol") != PROTOCOL:
        raise NodeAddError("node-add request protocol is invalid")
    for field in ("request_id", "main_node_id", "invite_id"):
        if not isinstance(value.get(field), str) or not ID_RE.fullmatch(value[field]):
            raise NodeAddError(f"node-add request {field} is invalid")
    if not isinstance(value.get("main_name"), str) or not value["main_name"].strip():
        raise NodeAddError("node-add request main name is invalid")
    if (
        not isinstance(value.get("main_certificate_sha256"), str)
        or not SHA256_RE.fullmatch(value["main_certificate_sha256"])
    ):
        raise NodeAddError("node-add request main certificate is invalid")
    if (
        not isinstance(value.get("membership_code"), str)
        or not re.fullmatch(r"[0-9]{8}", value["membership_code"])
    ):
        raise NodeAddError("node-add membership code is invalid")
    endpoint = urllib.parse.urlsplit(str(value.get("main_endpoint", "")))
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.path not in {"", "/"}
        or endpoint.username
        or endpoint.password
        or endpoint.query
        or endpoint.fragment
    ):
        raise NodeAddError("node-add main endpoint is invalid")
    expiry = value.get("expires_at_unix")
    if not isinstance(expiry, int) or isinstance(expiry, bool):
        raise NodeAddError("node-add request expiry is invalid")
    return dict(value)


def store_request(value: Mapping[str, Any]) -> dict[str, Any]:
    document = validate_request(value)
    now = int(time.time())
    if not now < document["expires_at_unix"] <= now + MAX_REQUEST_SECONDS:
        raise NodeAddError("node-add request lifetime is invalid")
    path = request_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(
                json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
                + b"\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return document


def pending_request() -> dict[str, Any] | None:
    path = request_path()
    if not path.exists():
        return None
    value = _private_document(path)
    if value["expires_at_unix"] <= int(time.time()):
        path.unlink()
        return None
    return value


def clear_request(request_id: str) -> None:
    path = request_path()
    if not path.exists():
        return
    value = _private_document(path)
    if value["request_id"] != request_id:
        raise NodeAddError("node-add request changed before completion")
    path.unlink()


def send_request(
    endpoint: str,
    certificate_sha256: str,
    document: Mapping[str, Any],
) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise NodeAddError("node-add candidate endpoint is invalid")
    try:
        result = PinnedHTTPS(
            parsed.hostname,
            parsed.port or DEFAULT_PORT,
            certificate_sha256,
        ).request("POST", "/node/v1/add-request", validate_request(document))
    except ControlError as error:
        raise NodeAddError(str(error)) from error
    if set(result) != {"protocol", "request_id", "status"} or (
        result.get("protocol") != PROTOCOL
        or result.get("request_id") != document.get("request_id")
        or result.get("status") != "pending"
    ):
        raise NodeAddError("node-add candidate returned an invalid acknowledgement")
    return result


def _parse_avahi(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in output.splitlines():
        fields = line.split(";")
        if len(fields) < 10 or fields[0] != "=" or fields[4] != SERVICE_TYPE:
            continue
        address = fields[7]
        try:
            port = int(fields[8])
        except ValueError:
            continue
        txt: dict[str, str] = {}
        for item in fields[9:]:
            for token in re.findall(r'"([^"]+)"|([^ ]+)', item):
                value = token[0] or token[1]
                key, separator, content = value.partition("=")
                if separator:
                    txt[key] = content
        if (
            not ID_RE.fullmatch(txt.get("node", ""))
            or not ID_RE.fullmatch(txt.get("machine", ""))
            or not SHA256_RE.fullmatch(txt.get("tls", ""))
            or txt.get("control") != "letsinfer-node-control-v1"
        ):
            continue
        host = f"[{address}]" if ":" in address else address
        records.append(
            {
                "node_id": txt["node"],
                "machine_id": txt["machine"],
                "name": fields[3].removeprefix("Let's Infer — "),
                "role": txt.get("role", "unknown"),
                "state": txt.get("state", "configured"),
                "endpoint": f"https://{host}:{port}",
                "certificate_sha256": txt["tls"],
                "address": address,
            }
        )
    return records


def discover_nodes(
    *,
    timeout_seconds: int = 5,
    address: str | None = None,
    certificate_sha256: str | None = None,
) -> list[dict[str, Any]]:
    if not 1 <= timeout_seconds <= MAX_DISCOVERY_SECONDS:
        raise NodeAddError("node discovery timeout must be between 1 and 15 seconds")
    if address is not None:
        if certificate_sha256 is None or not SHA256_RE.fullmatch(certificate_sha256):
            raise NodeAddError("manual node discovery requires its certificate SHA-256")
        parsed = urllib.parse.urlsplit(
            address if "://" in address else f"https://{address}"
        )
        if not parsed.hostname:
            raise NodeAddError("manual node address is invalid")
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        return [
            {
                "node_id": "unknown",
                "machine_id": "unknown",
                "name": parsed.hostname,
                "role": "unknown",
                "state": "configured",
                "endpoint": f"https://{host}:{parsed.port or DEFAULT_PORT}",
                "certificate_sha256": certificate_sha256,
                "address": parsed.hostname,
            }
        ]
    avahi = shutil.which("avahi-browse")
    if avahi is None:
        raise NodeAddError(
            "node discovery requires avahi-browse; use --address with --certificate-sha256"
        )
    try:
        completed = subprocess.run(
            [avahi, "-rpt", SERVICE_TYPE],
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        if isinstance(error, subprocess.TimeoutExpired):
            output = error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            return _parse_avahi(output)
        raise NodeAddError(f"node discovery failed: {error}") from error
    if completed.returncode not in {0, 124}:
        raise NodeAddError(
            "node discovery failed: "
            + (completed.stderr.strip() or f"status {completed.returncode}")
        )
    return _parse_avahi(completed.stdout)
