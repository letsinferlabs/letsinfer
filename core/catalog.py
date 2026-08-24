#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""One verified, atomic runtime-catalog cache shared by every core command."""

from __future__ import annotations

import dataclasses
import errno
import hashlib
import json
import os
import pathlib
import shutil
import stat
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

from core.paths import data_root, ensure_private_directory
from core.revocations import (
    RevocationError,
    apply_to_catalog,
    canonical_bytes as revocation_bytes,
    empty_ledger,
    load_ledger,
)
from core.runtime_packs import (
    MAX_CATALOG_BYTES,
    MAX_CATALOG_SIGNATURE_BYTES,
    RuntimePackError,
    canonical_bytes,
    load_catalog,
    resolved_catalog_location,
    _catalog_public_key,
)


CACHE_SCHEMA_VERSION = 2
DEFAULT_MAX_AGE_SECONDS = 60 * 60


class CatalogError(RuntimeError):
    """The production catalog could not be resolved safely."""


def _snapshot_identity(catalog_data: bytes, revocations_data: bytes) -> str:
    digest = hashlib.sha256()
    for label, value in (
        (b"letsinfer.catalog.v1\0", catalog_data),
        (b"letsinfer.revocations.v1\0", revocations_data),
    ):
        digest.update(label)
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


@dataclasses.dataclass(frozen=True)
class CatalogSnapshot:
    document: dict[str, Any]
    source: str
    catalog_sha256: str
    verified_at_unix: int
    stale: bool
    revocations: dict[str, Any] = dataclasses.field(default_factory=empty_ledger)

    @property
    def age_seconds(self) -> int:
        return max(0, int(time.time()) - self.verified_at_unix)


def _download(location: str, limit: int, label: str) -> bytes:
    if not location.startswith("https://"):
        raise CatalogError(f"remote {label} must use HTTPS")
    request = urllib.request.Request(
        location,
        headers={"User-Agent": "letsinfer-catalog-manager/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if not response.geturl().startswith("https://"):
                raise CatalogError(f"{label} redirected away from HTTPS")
            data = response.read(limit + 1)
    except (OSError, urllib.error.URLError) as error:
        raise CatalogError(f"cannot download {label}: {error}") from error
    if len(data) > limit:
        raise CatalogError(f"{label} exceeds {limit} bytes")
    return data


class CatalogManager:
    """Resolve the signed catalog and retain only immutable verified snapshots."""

    def __init__(
        self,
        location: str | None = None,
        *,
        root: pathlib.Path | None = None,
        max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
        clock=time.time,
    ) -> None:
        self.location = resolved_catalog_location(location)
        self.root = root or data_root() / "catalog"
        self.max_age_seconds = max_age_seconds
        self._clock = clock

    @property
    def _objects(self) -> pathlib.Path:
        return self.root / "objects"

    @property
    def _current(self) -> pathlib.Path:
        return self.root / "current.json"

    def _prepare(self) -> None:
        ensure_private_directory(self.root)
        ensure_private_directory(self._objects)

    @staticmethod
    def _regular(path: pathlib.Path) -> None:
        if path.is_symlink() or not path.is_file():
            raise CatalogError(f"catalog cache entry is not a regular file: {path}")
        details = path.stat()
        if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise CatalogError(f"catalog cache entry is not private: {path}")

    def _read_cached(self) -> CatalogSnapshot | None:
        if not self._current.exists():
            return None
        try:
            self._regular(self._current)
            pointer = json.loads(self._current.read_text(encoding="utf-8"))
            if (
                not isinstance(pointer, dict)
                or set(pointer) != {"schema_version", "snapshot_sha256"}
                or pointer.get("schema_version") != CACHE_SCHEMA_VERSION
            ):
                raise CatalogError("catalog cache pointer is invalid")
            identity = pointer.get("snapshot_sha256")
            if (
                not isinstance(identity, str)
                or len(identity) != 64
                or any(character not in "0123456789abcdef" for character in identity)
            ):
                raise CatalogError("catalog cache identity is invalid")
            object_root = self._objects / identity
            catalog_path = object_root / "catalog.json"
            signature_path = object_root / "catalog.json.sig"
            revocations_path = object_root / "revocations.json"
            revocations_signature_path = object_root / "revocations.json.sig"
            metadata_path = object_root / "metadata.json"
            for path in (
                catalog_path,
                signature_path,
                revocations_path,
                revocations_signature_path,
                metadata_path,
            ):
                self._regular(path)
            data = catalog_path.read_bytes()
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if (
                not isinstance(metadata, dict)
                or set(metadata)
                != {
                    "schema_version",
                    "source",
                    "snapshot_sha256",
                    "catalog_sha256",
                    "revocations_sha256",
                    "verified_at_unix",
                }
                or metadata.get("schema_version") != CACHE_SCHEMA_VERSION
                or metadata.get("snapshot_sha256") != identity
                or metadata.get("catalog_sha256")
                != hashlib.sha256(data).hexdigest()
                or metadata.get("revocations_sha256")
                != hashlib.sha256(revocations_path.read_bytes()).hexdigest()
                or _snapshot_identity(data, revocations_path.read_bytes()) != identity
                or not isinstance(metadata.get("source"), str)
                or not isinstance(metadata.get("verified_at_unix"), int)
            ):
                raise CatalogError("catalog cache metadata is invalid")
            document = load_catalog(str(catalog_path))
            ledger, _ledger_data, _signature = load_ledger(
                str(revocations_path), public_key=_catalog_public_key(None)
            )
            document = apply_to_catalog(document, ledger)
            now = int(self._clock())
            return CatalogSnapshot(
                document=document,
                source=metadata["source"],
                catalog_sha256=metadata["catalog_sha256"],
                verified_at_unix=metadata["verified_at_unix"],
                stale=(
                    metadata["source"] != self.location
                    or now - metadata["verified_at_unix"] > self.max_age_seconds
                ),
                revocations=ledger,
            )
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RuntimePackError,
            RevocationError,
        ) as error:
            raise CatalogError(f"catalog cache is invalid: {error}") from error

    def _write_pointer(self, identity: str) -> None:
        descriptor, temporary_value = tempfile.mkstemp(
            prefix=".current.", dir=self.root
        )
        temporary = pathlib.Path(temporary_value)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(
                    canonical_bytes(
                        {
                            "schema_version": CACHE_SCHEMA_VERSION,
                            "snapshot_sha256": identity,
                        }
                    )
                )
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o600)
            os.replace(temporary, self._current)
        finally:
            temporary.unlink(missing_ok=True)

    def refresh(self) -> CatalogSnapshot:
        if self.location is None:
            raise CatalogError("runtime catalog is not configured")
        if not self.location.startswith("https://"):
            try:
                document = load_catalog(self.location)
                data = pathlib.Path(self.location).expanduser().read_bytes()
                ledger_path = pathlib.Path(self.location).expanduser().with_name(
                    "revocations.json"
                )
                if ledger_path.is_file():
                    ledger, _ledger_data, _signature = load_ledger(
                        str(ledger_path), public_key=_catalog_public_key(None)
                    )
                else:
                    ledger = empty_ledger()
                document = apply_to_catalog(document, ledger)
            except (OSError, RuntimePackError, RevocationError) as error:
                raise CatalogError(str(error)) from error
            return CatalogSnapshot(
                document,
                self.location,
                hashlib.sha256(data).hexdigest(),
                int(self._clock()),
                False,
                ledger,
            )
        data = _download(self.location, MAX_CATALOG_BYTES, "runtime catalog")
        signature = _download(
            self.location + ".sig",
            MAX_CATALOG_SIGNATURE_BYTES,
            "runtime catalog signature",
        )
        ledger_location = self.location.rsplit("/", 1)[0] + "/revocations.json"
        public_key = _catalog_public_key(None)
        if public_key is None:
            raise CatalogError("runtime catalog trust key is unavailable")
        try:
            ledger, ledger_data, ledger_signature = load_ledger(
                ledger_location, public_key=public_key
            )
        except RevocationError as error:
            raise CatalogError(str(error)) from error
        if ledger_signature is None:
            raise CatalogError("remote revocation ledger is unsigned")
        self._prepare()
        incoming = pathlib.Path(
            tempfile.mkdtemp(prefix=".incoming-", dir=self.root)
        )
        incoming.chmod(0o700)
        try:
            catalog_path = incoming / "catalog.json"
            signature_path = incoming / "catalog.json.sig"
            revocations_path = incoming / "revocations.json"
            revocations_signature_path = incoming / "revocations.json.sig"
            catalog_path.write_bytes(data)
            signature_path.write_bytes(signature)
            revocations_path.write_bytes(ledger_data)
            revocations_signature_path.write_bytes(ledger_signature)
            catalog_path.chmod(0o600)
            signature_path.chmod(0o600)
            revocations_path.chmod(0o600)
            revocations_signature_path.chmod(0o600)
            document = apply_to_catalog(load_catalog(str(catalog_path)), ledger)
            catalog_identity = hashlib.sha256(data).hexdigest()
            identity = _snapshot_identity(data, ledger_data)
            verified_at = int(self._clock())
            metadata = {
                "schema_version": CACHE_SCHEMA_VERSION,
                "source": self.location,
                "snapshot_sha256": identity,
                "catalog_sha256": catalog_identity,
                "revocations_sha256": hashlib.sha256(ledger_data).hexdigest(),
                "verified_at_unix": verified_at,
            }
            metadata_path = incoming / "metadata.json"
            metadata_path.write_bytes(canonical_bytes(metadata))
            metadata_path.chmod(0o600)
            destination = self._objects / identity
            try:
                incoming.replace(destination)
            except OSError as error:
                if error.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise
                shutil.rmtree(incoming)
            self._write_pointer(identity)
            return CatalogSnapshot(
                document,
                self.location,
                catalog_identity,
                verified_at,
                False,
                ledger,
            )
        except BaseException:
            if incoming.exists():
                shutil.rmtree(incoming)
            raise

    def load(
        self, *, refresh: bool = False, allow_stale: bool = True
    ) -> CatalogSnapshot:
        try:
            cached = self._read_cached()
        except CatalogError:
            # A damaged local cache is never authoritative. Attempt a fresh,
            # signed download instead of making every catalog consumer fail
            # permanently on the same bad pointer or object.
            cached = None
        if cached is not None and not refresh and not cached.stale:
            return cached
        try:
            return self.refresh()
        except (CatalogError, RuntimePackError):
            if cached is not None and allow_stale:
                return dataclasses.replace(cached, stale=True)
            raise
