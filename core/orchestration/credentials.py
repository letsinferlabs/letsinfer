#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator-only derivation of internal engine-group credentials."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import pathlib
import re
import secrets
import stat
import tempfile

from ..paths import config_root

ID_RE = re.compile(r"^[0-9a-f]{32}$")
MASTER_BYTES = 32


class GroupCredentialError(RuntimeError):
    """The private group-credential root is absent or unsafe."""


def default_master_path() -> pathlib.Path:
    return config_root() / "group-credential.key"


def _private_directory(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise GroupCredentialError("group credential directory cannot be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise GroupCredentialError("group credential directory must be user-owned")
    path.chmod(0o700)


def ensure_master(path: pathlib.Path | None = None) -> bytes:
    target = (path or default_master_path()).expanduser()
    _private_directory(target.parent)
    if target.exists():
        if target.is_symlink():
            raise GroupCredentialError("group credential key cannot be a symlink")
        details = target.stat()
        payload = target.read_bytes()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) & 0o077
            or len(payload) != MASTER_BYTES
        ):
            raise GroupCredentialError("group credential key is unsafe or invalid")
        return payload
    descriptor, temporary_name = tempfile.mkstemp(prefix=".group-credential.", dir=target.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        payload = secrets.token_bytes(MASTER_BYTES)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError:
            pass
    finally:
        temporary.unlink(missing_ok=True)
    return ensure_master(target)


def derive_group_credential(group_id: str, *, master: bytes | None = None) -> str:
    if not isinstance(group_id, str) or not ID_RE.fullmatch(group_id):
        raise GroupCredentialError("engine-group identity is invalid")
    key = ensure_master() if master is None else master
    if not isinstance(key, bytes) or len(key) != MASTER_BYTES:
        raise GroupCredentialError("group credential master is invalid")
    digest = hmac.new(
        key,
        b"letsinfer-engine-group-v1\0" + group_id.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def credential_sha256(value: str) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value)
    ):
        raise GroupCredentialError("engine-group credential is invalid")
    return hashlib.sha256(value.encode("ascii")).hexdigest()
