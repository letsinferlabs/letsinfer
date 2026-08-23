#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Signed runtime-revocation ledger and catalog projection.

Revocation is deliberately outside the immutable runtime catalog schema.  The
catalog says what was qualified; this ledger says which qualified bytes must no
longer be selected or installed.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Any


SCHEMA_VERSION = 1
SIGNATURE_SCHEMA_VERSION = 1
MAX_LEDGER_BYTES = 1 << 20
MAX_SIGNATURE_BYTES = 16 << 10
SHA256_RE = re.compile(r"[0-9a-f]{64}")
OCI_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
REASON_CODES = {
    "compromised-verifier-key",
    "fraudulent-evidence",
    "incorrect-target",
    "invalid-benchmark-contract",
    "output-correctness-failure",
    "safety-failure",
    "structurally-invalid-evidence",
}


class RevocationError(RuntimeError):
    """A revocation ledger or signature is invalid."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def empty_ledger() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "sequence": 0,
        "generated_at_unix": 0,
        "revocations": [],
    }


def _identity(value: Any, where: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"github_login", "github_id", "github_type"}
        or not isinstance(value.get("github_login"), str)
        or re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", value["github_login"]
        )
        is None
        or not isinstance(value.get("github_id"), int)
        or isinstance(value.get("github_id"), bool)
        or value["github_id"] <= 0
        or value.get("github_type") not in {"User", "Organization", "Bot"}
    ):
        raise RevocationError(f"{where} must identify one GitHub actor")


def validate_ledger(value: Any) -> dict[str, Any]:
    fields = {"schema_version", "sequence", "generated_at_unix", "revocations"}
    if not isinstance(value, dict) or set(value) != fields:
        raise RevocationError("revocation ledger schema is invalid")
    for field in ("sequence", "generated_at_unix"):
        if (
            not isinstance(value.get(field), int)
            or isinstance(value.get(field), bool)
            or value[field] < 0
        ):
            raise RevocationError(f"revocation ledger {field} is invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise RevocationError("revocation ledger schema version is unsupported")
    entries = value.get("revocations")
    if not isinstance(entries, list):
        raise RevocationError("revocation ledger entries must be an array")
    identities: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        where = f"revocations[{index}]"
        entry_fields = {
            "runtime_oci_digest",
            "consensus_sha256",
            "actor",
            "revoked_at_unix",
            "reason_code",
            "verification_ids",
            "replacement",
        }
        if not isinstance(entry, dict) or set(entry) != entry_fields:
            raise RevocationError(f"{where} schema is invalid")
        digest = entry.get("runtime_oci_digest")
        consensus = entry.get("consensus_sha256")
        if not isinstance(digest, str) or OCI_DIGEST_RE.fullmatch(digest) is None:
            raise RevocationError(f"{where}.runtime_oci_digest is invalid")
        if not isinstance(consensus, str) or SHA256_RE.fullmatch(consensus) is None:
            raise RevocationError(f"{where}.consensus_sha256 is invalid")
        identity = (digest, consensus)
        if identity in identities:
            raise RevocationError("revocation ledger repeats an immutable release")
        identities.add(identity)
        _identity(entry.get("actor"), f"{where}.actor")
        timestamp = entry.get("revoked_at_unix")
        if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp <= 0:
            raise RevocationError(f"{where}.revoked_at_unix is invalid")
        if entry.get("reason_code") not in REASON_CODES:
            raise RevocationError(f"{where}.reason_code is unsupported")
        verification_ids = entry.get("verification_ids")
        if (
            not isinstance(verification_ids, list)
            or not verification_ids
            or any(
                not isinstance(item, str)
                or SHA256_RE.fullmatch(item) is None
                for item in verification_ids
            )
            or verification_ids != sorted(set(verification_ids))
        ):
            raise RevocationError(f"{where}.verification_ids is invalid")
        replacement = entry.get("replacement")
        if replacement is not None and (
            not isinstance(replacement, dict)
            or set(replacement) != {"candidate", "version", "source"}
            or not isinstance(replacement.get("candidate"), str)
            or not isinstance(replacement.get("version"), str)
            or VERSION_RE.fullmatch(replacement["version"]) is None
            or not isinstance(replacement.get("source"), str)
            or re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", replacement["source"])
            is None
        ):
            raise RevocationError(f"{where}.replacement is invalid")
    if entries != sorted(
        entries, key=lambda item: (item["runtime_oci_digest"], item["consensus_sha256"])
    ):
        raise RevocationError("revocation ledger entries are not canonical")
    return value


def _download(location: str, limit: int, label: str) -> bytes:
    if not location.startswith("https://"):
        raise RevocationError(f"remote {label} must use HTTPS")
    request = urllib.request.Request(
        location, headers={"User-Agent": "letsinfer-revocation-ledger/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if not response.geturl().startswith("https://"):
                raise RevocationError(f"{label} redirected away from HTTPS")
            data = response.read(limit + 1)
    except (OSError, urllib.error.URLError) as error:
        raise RevocationError(f"cannot download {label}: {error}") from error
    if len(data) > limit:
        raise RevocationError(f"{label} exceeds {limit} bytes")
    return data


def verify_signature(
    data: bytes, signature_data: bytes, public_key: pathlib.Path
) -> None:
    try:
        signature = json.loads(signature_data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RevocationError("revocation signature is invalid JSON") from error
    fields = {
        "schema_version",
        "algorithm",
        "key_id_sha256",
        "document_kind",
        "document_sha256",
        "signature_base64",
    }
    if (
        not isinstance(signature, dict)
        or set(signature) != fields
        or signature.get("schema_version") != SIGNATURE_SCHEMA_VERSION
        or signature.get("algorithm") != "ed25519"
        or signature.get("document_kind") != "letsinfer.revocations"
        or signature.get("document_sha256") != hashlib.sha256(data).hexdigest()
    ):
        raise RevocationError("revocation signature schema or identity is invalid")
    try:
        public_der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        raw = base64.b64decode(signature["signature_base64"], validate=True)
    except (OSError, subprocess.CalledProcessError, ValueError, binascii.Error) as error:
        raise RevocationError("revocation signature key or encoding is invalid") from error
    if signature.get("key_id_sha256") != hashlib.sha256(public_der).hexdigest() or len(raw) != 64:
        raise RevocationError("revocation signature uses an untrusted key")
    with tempfile.TemporaryDirectory(prefix="letsinfer-revocation-") as temporary:
        root = pathlib.Path(temporary)
        document = root / "revocations.json"
        raw_signature = root / "signature.bin"
        document.write_bytes(data)
        raw_signature.write_bytes(raw)
        try:
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                    str(public_key), "-rawin", "-in", str(document), "-sigfile",
                    str(raw_signature),
                ],
                check=True,
                capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise RevocationError("revocation signature verification failed") from error


def load_ledger(
    location: str, *, public_key: pathlib.Path | None = None
) -> tuple[dict[str, Any], bytes, bytes | None]:
    remote = location.startswith(("https://", "http://"))
    if remote:
        if public_key is None:
            raise RevocationError("remote revocation ledger requires a trust key")
        data = _download(location, MAX_LEDGER_BYTES, "revocation ledger")
        signature_data = _download(
            location + ".sig", MAX_SIGNATURE_BYTES, "revocation signature"
        )
        verify_signature(data, signature_data, public_key)
    else:
        path = pathlib.Path(location).expanduser()
        try:
            data = path.read_bytes()
        except OSError as error:
            raise RevocationError(f"cannot read revocation ledger: {error}") from error
        if len(data) > MAX_LEDGER_BYTES:
            raise RevocationError("revocation ledger is too large")
        signature_path = path.with_name(path.name + ".sig")
        signature_data = signature_path.read_bytes() if signature_path.is_file() else None
        if signature_data is not None:
            if public_key is None:
                raise RevocationError("signed revocation ledger requires a trust key")
            verify_signature(data, signature_data, public_key)
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RevocationError("revocation ledger is invalid JSON") from error
    return validate_ledger(document), data, signature_data


def _version_key(value: str) -> tuple[Any, ...]:
    match = re.fullmatch(
        r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+]([0-9A-Za-z.-]+))?", value
    )
    if match is None:
        return (0, 0, 0, ((0, value),))
    suffix = match.group(4)
    parts = () if suffix is None else tuple(
        (1, int(item)) if item.isdigit() else (0, item) for item in suffix.split(".")
    )
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)), parts)


def apply_to_catalog(
    catalog: dict[str, Any], ledger: dict[str, Any]
) -> dict[str, Any]:
    """Return the active selection view after applying signed revocations."""

    validate_ledger(ledger)
    result = copy.deepcopy(catalog)
    revoked = {
        (entry["runtime_oci_digest"], entry["consensus_sha256"])
        for entry in ledger["revocations"]
    }
    for model in result.get("models", {}).values():
        for target in model.get("targets", {}).values():
            candidates = target.get("candidates", {})
            for candidate, candidate_record in list(candidates.items()):
                releases = candidate_record.get("releases", {})
                for version, release in list(releases.items()):
                    source = str(release.get("source", ""))
                    digest = source.rsplit("@", 1)[-1]
                    consensus = release.get("verification", {}).get("consensus_sha256")
                    if (digest, consensus) in revoked:
                        del releases[version]
                if not releases:
                    del candidates[candidate]
                else:
                    candidate_record["latest"] = max(releases, key=_version_key)
            choices = [
                (
                    release["benchmark"]["score"],
                    _version_key(version),
                    candidate,
                    version,
                )
                for candidate, candidate_record in candidates.items()
                for version, release in candidate_record["releases"].items()
                if isinstance(release.get("benchmark"), dict)
            ]
            target["recommended"] = (
                None
                if not choices
                else {
                    "candidate": max(choices)[2],
                    "version": max(choices)[3],
                }
            )
    return result
