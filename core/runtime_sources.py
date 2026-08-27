#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable source identities for runtime-pack bytes."""

from __future__ import annotations

import re


OCI_RUNTIME_SOURCE_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
LOCAL_RUNTIME_SOURCE_RE = re.compile(
    r"^letsinfer-object:sha256:([0-9a-f]{64})$"
)


def is_immutable_runtime_source(value: object) -> bool:
    return isinstance(value, str) and bool(
        OCI_RUNTIME_SOURCE_RE.fullmatch(value)
        or LOCAL_RUNTIME_SOURCE_RE.fullmatch(value)
    )


def local_runtime_source(digest: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("local runtime object digest must be a SHA-256")
    return f"letsinfer-object:sha256:{digest}"


def local_runtime_digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = LOCAL_RUNTIME_SOURCE_RE.fullmatch(value)
    return None if match is None else match.group(1)
