#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Closed Engine distribution identities shared by runtime and orchestration code."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Mapping
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
REGISTRY_DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
PLATFORM_RE = re.compile(r"^[a-z0-9._-]+/[a-z0-9._-]+$")
BUNDLE_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$"
)
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
RELATIVE_PATH_RE = re.compile(
    r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$"
)

OCI_KIND = "oci-container"
NATIVE_ARCHIVE_KIND = "native-archive"
PYTHON_STANDALONE_KIND = "python-standalone"
EMBEDDED_APP_KIND = "embedded-application"
KINDS = frozenset(
    {OCI_KIND, NATIVE_ARCHIVE_KIND, PYTHON_STANDALONE_KIND, EMBEDDED_APP_KIND}
)


class EngineDistributionError(ValueError):
    """An Engine distribution is incomplete, ambiguous, or mutable."""


def _relative_path(value: Any, where: str) -> str:
    if not isinstance(value, str) or RELATIVE_PATH_RE.fullmatch(value) is None:
        raise EngineDistributionError(f"{where} must be a contained relative path")
    return value


def _https_url(value: Any, where: str) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 2048:
        raise EngineDistributionError(f"{where} must be a bounded HTTPS URL")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise EngineDistributionError(f"{where} must be a credential-free HTTPS URL")
    return value


def validate_engine_distribution(
    value: Any,
    *,
    target_platform: str | None = None,
) -> dict[str, Any]:
    """Validate one immutable executable-delivery identity."""

    if not isinstance(value, Mapping):
        raise EngineDistributionError("runtime.engine.distribution must be an object")
    result = dict(value)
    kind = result.get("kind")
    if kind not in KINDS:
        raise EngineDistributionError("runtime.engine.distribution.kind is unsupported")
    if kind == OCI_KIND:
        if set(result) not in (
            {"kind", "reference", "immutable_id"},
            {"kind", "reference", "immutable_id", "base"},
            {"kind", "reference", "immutable_id", "payload_id"},
            {"kind", "reference", "immutable_id", "base", "payload_id"},
        ):
            raise EngineDistributionError("OCI Engine distribution fields are invalid")
        if not REGISTRY_DIGEST_RE.fullmatch(str(result.get("reference", ""))):
            raise EngineDistributionError("OCI Engine reference must be digest-pinned")
        if not SHA256_ID_RE.fullmatch(str(result.get("immutable_id", ""))):
            raise EngineDistributionError("OCI Engine immutable_id must be a SHA-256")
        if "base" in result and not REGISTRY_DIGEST_RE.fullmatch(
            str(result.get("base", ""))
        ):
            raise EngineDistributionError("OCI Engine base must be digest-pinned")
        if "payload_id" in result and not SHA256_ID_RE.fullmatch(
            str(result.get("payload_id", ""))
        ):
            raise EngineDistributionError("OCI Engine payload_id must be a SHA-256")
        return result

    common = {
        "kind",
        "platform",
        "payload_id",
        "source_revision",
        "entrypoint",
        "port_count",
    }
    platform = result.get("platform")
    if not isinstance(platform, str) or PLATFORM_RE.fullmatch(platform) is None:
        raise EngineDistributionError("native Engine platform must be os/architecture")
    if target_platform is not None and platform != target_platform:
        raise EngineDistributionError(
            "native Engine platform must equal the runtime target platform"
        )
    if not SHA256_ID_RE.fullmatch(str(result.get("payload_id", ""))):
        raise EngineDistributionError("native Engine payload_id must be a SHA-256")
    if not GIT_REVISION_RE.fullmatch(str(result.get("source_revision", ""))):
        raise EngineDistributionError(
            "native Engine source_revision must be a full Git commit"
        )
    _relative_path(result.get("entrypoint"), "native Engine entrypoint")
    if (
        not isinstance(result.get("port_count"), int)
        or isinstance(result.get("port_count"), bool)
        or result["port_count"] not in range(1, 5)
    ):
        raise EngineDistributionError("native Engine port_count must be from 1 through 4")

    if kind == NATIVE_ARCHIVE_KIND:
        if set(result) != common | {"archive", "upstream_executable"}:
            raise EngineDistributionError("native archive Engine fields are invalid")
        archive = result.get("archive")
        if not isinstance(archive, Mapping) or set(archive) != {
            "url",
            "sha256",
            "bytes",
            "format",
            "strip_prefix",
        }:
            raise EngineDistributionError("native Engine archive fields are invalid")
        _https_url(archive.get("url"), "native Engine archive URL")
        if not SHA256_RE.fullmatch(str(archive.get("sha256", ""))):
            raise EngineDistributionError("native Engine archive SHA-256 is invalid")
        if (
            not isinstance(archive.get("bytes"), int)
            or isinstance(archive.get("bytes"), bool)
            or archive["bytes"] <= 0
            or archive["bytes"] > 1 << 30
        ):
            raise EngineDistributionError("native Engine archive size is invalid")
        if archive.get("format") not in {"tar.gz", "zip"}:
            raise EngineDistributionError("native Engine archive format is unsupported")
        _relative_path(archive.get("strip_prefix"), "native Engine strip_prefix")
        _relative_path(
            result.get("upstream_executable"),
            "native Engine upstream_executable",
        )
        if result["port_count"] < 2:
            raise EngineDistributionError(
                "native archive Engine requires a separate backend port"
            )
        return result

    if kind == PYTHON_STANDALONE_KIND:
        if set(result) != common | {"python", "requirements_lock"}:
            raise EngineDistributionError("Python Engine distribution fields are invalid")
        python = result.get("python")
        if not isinstance(python, Mapping) or set(python) != {
            "implementation",
            "version",
            "archive",
        }:
            raise EngineDistributionError("native Engine Python identity is invalid")
        if python.get("implementation") != "cpython" or not re.fullmatch(
            r"3\.(?:1[0-9]|[89])\.[0-9]+", str(python.get("version", ""))
        ):
            raise EngineDistributionError("native Engine requires an exact CPython version")
        archive = python.get("archive")
        if not isinstance(archive, Mapping) or set(archive) != {
            "url",
            "sha256",
            "bytes",
            "format",
            "strip_prefix",
        }:
            raise EngineDistributionError("native Engine Python archive is invalid")
        _https_url(archive.get("url"), "native Engine Python archive URL")
        if not SHA256_RE.fullmatch(str(archive.get("sha256", ""))):
            raise EngineDistributionError("native Engine Python archive SHA-256 is invalid")
        if (
            not isinstance(archive.get("bytes"), int)
            or isinstance(archive.get("bytes"), bool)
            or archive["bytes"] <= 0
            or archive["bytes"] > 1 << 30
        ):
            raise EngineDistributionError("native Engine Python archive size is invalid")
        if archive.get("format") not in {"tar.gz", "zip"}:
            raise EngineDistributionError("native Engine Python archive format is invalid")
        _relative_path(
            archive.get("strip_prefix"), "native Engine Python strip_prefix"
        )
        _relative_path(
            result.get("requirements_lock"),
            "native Engine requirements_lock",
        )
        if result["port_count"] < 2:
            raise EngineDistributionError(
                "Python Engine requires a separate backend port"
            )
        return result

    if set(result) != common | {
        "bundle_id",
        "signing_policy",
        "minimum_version",
        "embedded_engine",
    }:
        raise EngineDistributionError("embedded application Engine fields are invalid")
    if BUNDLE_ID_RE.fullmatch(str(result.get("bundle_id", ""))) is None:
        raise EngineDistributionError("embedded Engine bundle_id is invalid")
    if result.get("signing_policy") != "deployment-managed":
        raise EngineDistributionError("embedded Engine signing policy is invalid")
    if VERSION_RE.fullmatch(str(result.get("minimum_version", ""))) is None:
        raise EngineDistributionError("embedded Engine minimum_version is invalid")
    if SAFE_NAME_RE.fullmatch(str(result.get("embedded_engine", ""))) is None:
        raise EngineDistributionError("embedded Engine name is invalid")
    return result


def distribution_payload_sha256(value: Mapping[str, Any]) -> str | None:
    """Return the execution payload digest without its ``sha256:`` prefix."""

    distribution = validate_engine_distribution(value)
    payload = distribution.get("payload_id")
    return payload.removeprefix("sha256:") if isinstance(payload, str) else None


def distribution_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the compact signed-catalog identity for a full distribution."""

    distribution = validate_engine_distribution(value)
    if distribution["kind"] == OCI_KIND:
        result = {
            "kind": OCI_KIND,
            "reference": distribution["reference"],
        }
        if distribution.get("payload_id") is not None:
            result["payload_id"] = distribution["payload_id"]
        return result
    return {
        "kind": distribution["kind"],
        "platform": distribution["platform"],
        "payload_id": distribution["payload_id"],
        "source_revision": distribution["source_revision"],
    }


def validate_distribution_projection(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EngineDistributionError("catalog Engine distribution must be an object")
    result = dict(value)
    if result.get("kind") == OCI_KIND:
        if set(result) not in (
            {"kind", "reference"},
            {"kind", "reference", "payload_id"},
        ) or REGISTRY_DIGEST_RE.fullmatch(str(result.get("reference", ""))) is None:
            raise EngineDistributionError("catalog OCI Engine identity is invalid")
        if "payload_id" in result and SHA256_ID_RE.fullmatch(
            str(result["payload_id"])
        ) is None:
            raise EngineDistributionError("catalog OCI payload identity is invalid")
        return result
    if set(result) != {"kind", "platform", "payload_id", "source_revision"}:
        raise EngineDistributionError("catalog native Engine identity is invalid")
    if result.get("kind") not in {
        NATIVE_ARCHIVE_KIND,
        PYTHON_STANDALONE_KIND,
        EMBEDDED_APP_KIND,
    } or PLATFORM_RE.fullmatch(str(result.get("platform", ""))) is None:
        raise EngineDistributionError("catalog native Engine kind or platform is invalid")
    if SHA256_ID_RE.fullmatch(str(result.get("payload_id", ""))) is None or GIT_REVISION_RE.fullmatch(
        str(result.get("source_revision", ""))
    ) is None:
        raise EngineDistributionError("catalog native Engine payload is invalid")
    return result
