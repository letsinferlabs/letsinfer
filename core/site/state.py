#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator identity, policy, and tamper-evident site storage."""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as dt
import getpass
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
import unicodedata
import urllib.parse
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, TypeVar

from core.paths import config_root as canonical_config_root
from core.paths import data_root as canonical_data_root
from core.paths import secrets_root as canonical_secrets_root
from core.orchestration import OrchestrationError, validate_placement_group_document
from core.exact_tokens import TOKEN_COUNT_PROTOCOLS
from core.runtime_sources import is_immutable_runtime_source


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")
KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
SCHEMA_VERSION = 4
CHECKPOINT_INTERVAL = 100
MAX_REASON_BYTES = 512
MAX_TAG_BYTES = 128
MAX_CONTROLLERS = 64
MAX_PLACEMENT_MEMBERS = 64
MAX_PLACEMENT_PREFIX_KEYS = 4096
ADOPTION_WINDOW_SECONDS = 600
T = TypeVar("T")


class SiteError(RuntimeError):
    """A fail-closed site identity, policy, or audit error."""


@dataclasses.dataclass(frozen=True)
class SiteIdentity:
    site_id: str
    member_id: str
    installation_id: str
    display_name: str
    role: str
    coordinator_id: str
    coordinator_address: str
    site_public_key_sha256: str
    member_public_key_sha256: str
    created_at_unix: int


def config_root() -> pathlib.Path:
    return canonical_config_root()


def data_root() -> pathlib.Path:
    return canonical_data_root()


def secrets_root() -> pathlib.Path:
    return canonical_secrets_root()


def identity_path() -> pathlib.Path:
    return config_root() / "site.json"


def site_key_path() -> pathlib.Path:
    return secrets_root() / "site.key"


def site_public_key_path() -> pathlib.Path:
    return config_root() / "site.pub"


def site_ca_certificate_path() -> pathlib.Path:
    return config_root() / "site-ca.crt"


def member_key_path() -> pathlib.Path:
    return secrets_root() / "member.key"


def member_public_key_path() -> pathlib.Path:
    return config_root() / "member.pub"


def member_certificate_path() -> pathlib.Path:
    return config_root() / "member.crt"


def pending_installation_path() -> pathlib.Path:
    return config_root() / "installation-pending.json"


def database_path() -> pathlib.Path:
    return data_root() / "site.sqlite3"


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _private_directory(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise SiteError(f"private directory cannot be a symlink: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise SiteError(f"private directory is not user-owned: {path}")
    path.chmod(0o700)


def _atomic_private(path: pathlib.Path, payload: bytes) -> None:
    _private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _private_file(path: pathlib.Path, *, minimum_bytes: int = 1) -> bytes:
    if path.is_symlink():
        raise SiteError(f"private file cannot be a symlink: {path}")
    try:
        details = path.stat()
        payload = path.read_bytes()
    except OSError as error:
        raise SiteError(f"cannot read private file {path}: {error}") from error
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise SiteError(f"private file must be regular, user-owned, and mode 0600: {path}")
    if len(payload) < minimum_bytes:
        raise SiteError(f"private file is unexpectedly short: {path}")
    return payload


def _run(command: Sequence[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(command, input=input_bytes, capture_output=True, check=False)
    except OSError as error:
        raise SiteError(f"required command is unavailable: {command[0]}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SiteError(f"command failed: {' '.join(command)}: {detail}")
    return completed.stdout


def _generate_identity_key(private: pathlib.Path, public: pathlib.Path) -> str:
    if private.exists() or public.exists():
        if not private.exists() or not public.exists():
            raise SiteError("cryptographic identity is incomplete")
    else:
        _private_directory(private.parent)
        with tempfile.TemporaryDirectory(prefix=".identity-", dir=private.parent) as temporary:
            root = pathlib.Path(temporary)
            staged_private = root / "identity.key"
            staged_public = root / "identity.pub"
            _run([
                "openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-out", str(staged_private),
            ])
            _run(["openssl", "pkey", "-in", str(staged_private), "-pubout", "-out", str(staged_public)])
            _atomic_private(private, staged_private.read_bytes())
            _atomic_private(public, staged_public.read_bytes())
    _private_file(private, minimum_bytes=128)
    public_bytes = _private_file(public, minimum_bytes=128)
    derived = _run(["openssl", "pkey", "-in", str(private), "-pubout"])
    if derived.strip() != public_bytes.strip():
        raise SiteError("cryptographic identity key pair does not match")
    der = _run(["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()


def _public_key_fingerprint(public: pathlib.Path) -> str:
    _private_file(public, minimum_bytes=128)
    der = _run(["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()


def _certificate_fingerprint(certificate: pathlib.Path) -> str:
    der = _run(["openssl", "x509", "-in", str(certificate), "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()


def _validate_site_ca(
    certificate: pathlib.Path,
    public_key: pathlib.Path,
    *,
    private_key: pathlib.Path | None = None,
) -> None:
    _private_file(certificate, minimum_bytes=256)
    _private_file(public_key, minimum_bytes=128)
    certificate_public = _run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-pubkey"]
    )
    expected_public = _run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-pubout"]
    )
    if certificate_public.strip() != expected_public.strip():
        raise SiteError("site CA certificate does not match the logical site identity")
    if private_key is not None:
        private_public = _run(
            ["openssl", "pkey", "-in", str(private_key), "-pubout"]
        )
        if certificate_public.strip() != private_public.strip():
            raise SiteError("site CA certificate and private key do not match")
    _run(["openssl", "verify", "-CAfile", str(certificate), str(certificate)])
    if _run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-checkend", "2592000"]
    ) is None:  # pragma: no cover - _run either returns bytes or raises.
        raise SiteError("site CA certificate expires within 30 days")


def _validate_member_certificate(
    certificate: pathlib.Path,
    member_public_key: pathlib.Path,
    site_ca: pathlib.Path,
    member_id: str,
) -> str:
    _private_file(certificate, minimum_bytes=256)
    _run(["openssl", "verify", "-purpose", "sslserver", "-CAfile", str(site_ca), str(certificate)])
    _run(["openssl", "verify", "-purpose", "sslclient", "-CAfile", str(site_ca), str(certificate)])
    certificate_public = _run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-pubkey"]
    )
    expected_public = _run(
        ["openssl", "pkey", "-pubin", "-in", str(member_public_key), "-pubout"]
    )
    if certificate_public.strip() != expected_public.strip():
        raise SiteError("member certificate does not match the member identity")
    extensions = _run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName"]
    ).decode("utf-8", errors="replace")
    expected_uri = f"URI:urn:letsinfer:member:{member_id}"
    if expected_uri not in extensions:
        raise SiteError("member certificate identity is invalid")
    _run(["openssl", "x509", "-in", str(certificate), "-noout", "-checkend", "2592000"])
    return _certificate_fingerprint(certificate)


def _issue_member_certificate(
    member_id: str,
    member_public_key: pathlib.Path,
    *,
    output: pathlib.Path,
) -> str:
    if not ID_RE.fullmatch(member_id):
        raise SiteError("member certificate identity is invalid")
    site_ca = site_ca_certificate_path()
    _validate_site_ca(site_ca, site_public_key_path(), private_key=site_key_path())
    extensions = output.with_suffix(".ext")
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        f"subjectAltName=URI:urn:letsinfer:member:{member_id}\n",
        encoding="ascii",
    )
    extensions.chmod(0o600)
    _run([
        "openssl", "x509", "-new", "-force_pubkey", str(member_public_key),
        "-subj", f"/CN=Let's Infer member {member_id}",
        "-CA", str(site_ca), "-CAkey", str(site_key_path()),
        "-set_serial", f"0x{secrets.token_hex(20)}", "-days", "36500",
        "-sha256", "-extfile", str(extensions), "-out", str(output),
    ])
    output.chmod(0o600)
    return _validate_member_certificate(output, member_public_key, site_ca, member_id)


def _ensure_coordinator_control_credentials(identity: SiteIdentity) -> str:
    if identity.role != "main":
        raise SiteError("only the main node can create node control credentials")
    site_ca = site_ca_certificate_path()
    member_certificate = member_certificate_path()
    existing = [site_ca.exists(), member_certificate.exists()]
    if any(existing) and not all(existing):
        raise SiteError("site control credentials are incomplete")
    if not site_ca.exists():
        with tempfile.TemporaryDirectory(prefix=".site-control-", dir=config_root()) as temporary:
            root = pathlib.Path(temporary)
            ca = root / "site-ca.crt"
            member = root / "member.crt"
            _run([
                "openssl", "req", "-new", "-x509", "-key", str(site_key_path()),
                "-sha256", "-days", "36500", "-subj", f"/CN=Let's Infer site {identity.site_id}",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
                "-out", str(ca),
            ])
            ca.chmod(0o600)
            _atomic_private(site_ca, ca.read_bytes())
            try:
                _issue_member_certificate(identity.member_id, member_public_key_path(), output=member)
                _atomic_private(member_certificate, member.read_bytes())
            except BaseException:
                site_ca.unlink(missing_ok=True)
                raise
    _validate_site_ca(site_ca, site_public_key_path(), private_key=site_key_path())
    return _validate_member_certificate(
        member_certificate, member_public_key_path(), site_ca, identity.member_id
    )


def _display_name(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value.strip())
    if not normalized or len(normalized) > 64 or len(normalized.encode("utf-8")) > 128:
        raise SiteError("site display name is invalid")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise SiteError("site display name contains control characters")
    return normalized


def _prepare_installation_identity() -> dict[str, Any]:
    """Create or reuse the physical installation identity before site enrollment."""
    path = pending_installation_path()
    if path.exists():
        try:
            value = json.loads(_private_file(path, minimum_bytes=64))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SiteError("pending installation identity is invalid") from error
        if (
            not isinstance(value, dict)
            or set(value) != {"installation_id", "created_at_unix"}
            or not isinstance(value.get("installation_id"), str)
            or not SHA256_RE.fullmatch(value["installation_id"])
            or not isinstance(value.get("created_at_unix"), int)
            or isinstance(value["created_at_unix"], bool)
            or value["created_at_unix"] <= 0
            or value["created_at_unix"] > int(time.time()) + 300
        ):
            raise SiteError("pending installation identity is invalid")
        return value
    value = {
        "installation_id": secrets.token_hex(32),
        "created_at_unix": int(time.time()),
    }
    _atomic_private(path, _canonical_bytes(value))
    return value


def _identity_from(value: Mapping[str, Any]) -> SiteIdentity:
    required = {
        "schema_version", "site_id", "member_id", "installation_id", "display_name", "role",
        "coordinator_id", "coordinator_address", "site_public_key_sha256",
        "member_public_key_sha256", "created_at_unix",
    }
    if (
        set(value) != required
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        raise SiteError("site identity schema is invalid")
    for field in ("site_id", "member_id", "coordinator_id"):
        if not isinstance(value.get(field), str) or not ID_RE.fullmatch(str(value[field])):
            raise SiteError(f"site identity {field} is invalid")
    for field in ("installation_id", "site_public_key_sha256", "member_public_key_sha256"):
        if not isinstance(value.get(field), str) or not SHA256_RE.fullmatch(str(value[field])):
            raise SiteError(f"site identity {field} is invalid")
    if value.get("role") not in {"main", "child"}:
        raise SiteError("node identity role is invalid")
    if not isinstance(value.get("coordinator_address"), str) or not value["coordinator_address"].strip():
        raise SiteError("site coordinator address is invalid")
    if not isinstance(value.get("created_at_unix"), int) or isinstance(value["created_at_unix"], bool) or value["created_at_unix"] <= 0:
        raise SiteError("site identity timestamp is invalid")
    return SiteIdentity(
        site_id=str(value["site_id"]), member_id=str(value["member_id"]),
        installation_id=str(value["installation_id"]), display_name=_display_name(str(value["display_name"])),
        role=str(value["role"]), coordinator_id=str(value["coordinator_id"]),
        coordinator_address=str(value["coordinator_address"]),
        site_public_key_sha256=str(value["site_public_key_sha256"]),
        member_public_key_sha256=str(value["member_public_key_sha256"]),
        created_at_unix=int(value["created_at_unix"]),
    )


def read_identity(path: pathlib.Path | None = None) -> SiteIdentity:
    source = path or identity_path()
    payload = _private_file(source, minimum_bytes=128)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SiteError("site identity is not valid JSON") from error
    if not isinstance(value, dict):
        raise SiteError("site identity must be a JSON object")
    identity = _identity_from(value)
    if identity.role == "main":
        site_fingerprint = _generate_identity_key(site_key_path(), site_public_key_path())
    else:
        if site_key_path().exists():
            raise SiteError("a member must not hold the logical site private key")
        site_fingerprint = _public_key_fingerprint(site_public_key_path())
    member_fingerprint = _generate_identity_key(member_key_path(), member_public_key_path())
    if identity.site_public_key_sha256 != site_fingerprint or identity.member_public_key_sha256 != member_fingerprint:
        raise SiteError("site identity does not match its cryptographic keys")
    _validate_site_ca(
        site_ca_certificate_path(),
        site_public_key_path(),
        private_key=site_key_path() if identity.role == "main" else None,
    )
    _validate_member_certificate(
        member_certificate_path(),
        member_public_key_path(),
        site_ca_certificate_path(),
        identity.member_id,
    )
    return identity


def read_exposure_for_cleanup(
    path: pathlib.Path | None = None,
) -> dict[str, Any] | None:
    """Read only the owned exposure row when the site identity is unreadable.

    Uninstall must remain able to remove a corrupt or obsolete control plane,
    but it must not reset an unrelated public endpoint.  This narrow reader
    accepts only the exact private database and exposure-table shape that
    Let's Infer owns.  It never creates or migrates state.
    """

    source = path or database_path()
    if source.is_symlink():
        raise SiteError(f"site database cannot be a symlink: {source}")
    if not source.exists():
        return None
    try:
        details = source.stat()
    except OSError as error:
        raise SiteError(f"cannot inspect site database {source}: {error}") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise SiteError(
            f"site database must be regular, user-owned, and mode 0600: {source}"
        )
    for sidecar in (
        source.with_name(source.name + "-wal"),
        source.with_name(source.name + "-shm"),
    ):
        if not sidecar.exists() and not sidecar.is_symlink():
            continue
        try:
            sidecar_details = sidecar.stat()
        except OSError as error:
            raise SiteError(
                f"cannot inspect site database sidecar {sidecar}: {error}"
            ) from error
        if (
            sidecar.is_symlink()
            or not stat.S_ISREG(sidecar_details.st_mode)
            or sidecar_details.st_uid != os.getuid()
            or stat.S_IMODE(sidecar_details.st_mode) & 0o077
        ):
            raise SiteError(f"site database sidecar is unsafe: {sidecar}")
    expected_columns = (
        "singleton",
        "provider",
        "public_url",
        "state",
        "inference_target",
        "configuration_sha256",
        "updated_at_unix",
    )
    encoded = urllib.parse.quote(str(source), safe="/")
    try:
        connection = sqlite3.connect(f"file:{encoded}?mode=ro", uri=True, timeout=1.0)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            table = connection.execute(
                "SELECT type FROM sqlite_master WHERE name='exposure'"
            ).fetchone()
            if table is None:
                return None
            if table["type"] != "table":
                raise SiteError("site exposure storage is not a table")
            columns = tuple(
                row["name"]
                for row in connection.execute('PRAGMA table_info("exposure")')
            )
            if columns != expected_columns:
                raise SiteError("site exposure schema is invalid")
            rows = connection.execute(
                "SELECT singleton,provider,public_url,state,inference_target,"
                "configuration_sha256,updated_at_unix FROM exposure"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise SiteError("site exposure state cannot be read safely") from error
    if not rows:
        return None
    if len(rows) != 1:
        raise SiteError("site exposure state contains multiple records")
    value = dict(rows[0])
    if (
        value.get("singleton") != 1
        or value.get("provider") != "tailscale-funnel"
        or value.get("state") not in {"disabled", "enabled", "failed"}
        or not isinstance(value.get("public_url"), str)
        or not isinstance(value.get("inference_target"), str)
        or not value["inference_target"]
        or not isinstance(value.get("configuration_sha256"), str)
        or not SHA256_RE.fullmatch(value["configuration_sha256"])
        or type(value.get("updated_at_unix")) is not int
        or value["updated_at_unix"] <= 0
    ):
        raise SiteError("site exposure record is invalid")
    return value


def has_active_placement_groups_for_cleanup(
    path: pathlib.Path | None = None,
) -> bool:
    """Fail closed if unreadable node identity hides live distributed work."""

    source = path or database_path()
    if source.is_symlink():
        raise SiteError(f"site database cannot be a symlink: {source}")
    if not source.exists():
        return False
    # Reuse the same file and WAL safety validation as the exposure reader.
    # Its return value is irrelevant here; a malformed exposure row must still
    # block deletion because it may represent an owned public endpoint.
    read_exposure_for_cleanup(source)
    encoded = urllib.parse.quote(str(source), safe="/")
    try:
        connection = sqlite3.connect(f"file:{encoded}?mode=ro", uri=True, timeout=1.0)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            table = connection.execute(
                "SELECT type FROM sqlite_master WHERE name='placement_groups'"
            ).fetchone()
            if table is None:
                return False
            if table["type"] != "table":
                raise SiteError("placement-group storage is not a table")
            columns = {
                row["name"]
                for row in connection.execute('PRAGMA table_info("placement_groups")')
            }
            if not {
                "placement_group_id",
                "desired_state",
                "state",
                "plan_json",
            }.issubset(
                columns
            ):
                raise SiteError("placement-group cleanup schema is invalid")
            row = connection.execute(
                "SELECT COUNT(*) AS active FROM placement_groups "
                "WHERE desired_state IS NOT 'removed' OR state IS NOT 'removed'"
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise SiteError("placement-group cleanup state cannot be read safely") from error
    return bool(row["active"])


def setup_site(display_name: str = "Home", coordinator_address: str | None = None) -> SiteIdentity:
    destination = identity_path()
    if destination.exists():
        return read_identity(destination)
    if destination.is_symlink():
        raise SiteError("site identity cannot be a symlink")
    site_fingerprint = _generate_identity_key(site_key_path(), site_public_key_path())
    member_fingerprint = _generate_identity_key(member_key_path(), member_public_key_path())
    member_id_file = config_root() / "member-id"
    if member_id_file.exists():
        member_id = _private_file(member_id_file, minimum_bytes=32).decode("ascii").strip()
        if not ID_RE.fullmatch(member_id):
            raise SiteError("pending member identity is invalid")
    else:
        member_id = uuid.uuid4().hex
        _atomic_private(member_id_file, (member_id + "\n").encode("ascii"))
    installation = _prepare_installation_identity()
    now = int(installation["created_at_unix"])
    value = {
        "schema_version": SCHEMA_VERSION,
        "site_id": uuid.uuid4().hex,
        "member_id": member_id,
        "installation_id": installation["installation_id"],
        "display_name": _display_name(display_name),
        "role": "main",
        "coordinator_id": member_id,
        "coordinator_address": (coordinator_address or socket.getfqdn() or socket.gethostname()).strip(),
        "site_public_key_sha256": site_fingerprint,
        "member_public_key_sha256": member_fingerprint,
        "created_at_unix": now,
    }
    _atomic_private(destination, _canonical_bytes(value))
    identity = _identity_from(value)
    _ensure_coordinator_control_credentials(identity)
    with SiteStore(identity=identity, initialize=True) as store:
        store.initialize_coordinator(identity)
    pending_installation_path().unlink(missing_ok=True)
    return read_identity(destination)


def _safe_json(value: Any) -> str:
    return _canonical_bytes(value).decode("utf-8").rstrip("\n")


def _state_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _bounded_reason(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = " ".join(str(value).split())
    encoded = normalized.encode("utf-8")[:MAX_REASON_BYTES]
    return encoded.decode("utf-8", errors="ignore")


class SiteStore:
    """The coordinator's sole authoritative SQLite site database."""

    def __init__(
        self,
        path: pathlib.Path | None = None,
        *,
        identity: SiteIdentity | None = None,
        initialize: bool = False,
    ) -> None:
        self.identity = identity or read_identity()
        if self.identity.role != "main":
            raise SiteError(
                "the authoritative node database is main-node-only; "
                f"coordinator={self.identity.coordinator_id}@{self.identity.coordinator_address}"
            )
        self.path = path or database_path()
        _private_directory(self.path.parent)
        if self.path.is_symlink():
            raise SiteError("site database cannot be a symlink")
        if not initialize and not self.path.exists():
            raise SiteError("site database is missing; rerun the installer")
        self.connection = sqlite3.connect(str(self.path), isolation_level=None, timeout=5.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA trusted_schema=OFF")
        self._create_schema()
        self._secure_database_files()

    def __enter__(self) -> "SiteStore":
        return self

    def __exit__(self, *_arguments: object) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    def _secure_database_files(self) -> None:
        for path in (
            self.path,
            self.path.with_name(self.path.name + "-wal"),
            self.path.with_name(self.path.name + "-shm"),
        ):
            if path.exists():
                if path.is_symlink() or not path.is_file():
                    raise SiteError(f"site database sidecar is unsafe: {path}")
                path.chmod(0o600)

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS site_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS members (
                member_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('main','child')),
                address TEXT NOT NULL,
                public_key_sha256 TEXT NOT NULL UNIQUE,
                public_key_pem TEXT NOT NULL,
                certificate_sha256 TEXT NOT NULL UNIQUE,
                certificate_pem TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending','active','draining','offline','removed')),
                approval_code_hash TEXT,
                approval_expires_at_unix INTEGER,
                facts_json TEXT NOT NULL,
                facts_signature_base64 TEXT,
                facts_sha256 TEXT,
                joined_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS controllers (
                controller_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('viewer','operator','administrator')),
                certificate_sha256 TEXT NOT NULL UNIQUE,
                certificate_pem TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL,
                revoked_at_unix INTEGER
            ) STRICT;
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                secret_hash TEXT NOT NULL,
                models_json TEXT NOT NULL,
                expires_at_unix INTEGER,
                revoked_at_unix INTEGER,
                requests_per_minute INTEGER,
                tokens_per_minute INTEGER,
                concurrency_limit INTEGER,
                context_limit INTEGER,
                tenant TEXT,
                application TEXT,
                created_at_unix INTEGER NOT NULL,
                rotated_from TEXT REFERENCES api_keys(key_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS model_aliases (
                alias TEXT PRIMARY KEY,
                model TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS membership_invites (
                invite_id TEXT PRIMARY KEY,
                mode TEXT NOT NULL CHECK(mode IN ('lan','remote','connectx')),
                code_hash TEXT NOT NULL,
                nonce TEXT NOT NULL,
                candidate_public_key_sha256 TEXT,
                direct_interface TEXT,
                expires_at_unix INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                consumed_at_unix INTEGER,
                created_at_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS model_services (
                service_id TEXT PRIMARY KEY,
                model TEXT NOT NULL UNIQUE,
                desired_state TEXT NOT NULL CHECK(desired_state IN ('running','stopped','removed')),
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS placement_groups (
                placement_group_id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL REFERENCES model_services(service_id),
                source TEXT NOT NULL,
                model TEXT NOT NULL,
                runtime TEXT NOT NULL,
                target TEXT NOT NULL,
                runtime_digest TEXT NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                topology_sha256 TEXT NOT NULL,
                engine_credential_sha256 TEXT NOT NULL,
                runtime_execution_contract_sha256 TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                plan_sha256 TEXT NOT NULL,
                desired_state TEXT NOT NULL CHECK(desired_state IN ('running','stopped','removed')),
                state TEXT NOT NULL CHECK(state IN
                    ('staging','staged','starting','running','degraded','stopping','stopped',
                     'recovering','removing','removed','failed')),
                endpoint_json TEXT,
                capacity_json TEXT NOT NULL,
                last_error TEXT,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS placements (
                placement_id TEXT PRIMARY KEY,
                placement_group_id TEXT NOT NULL REFERENCES placement_groups(placement_group_id),
                node_id TEXT NOT NULL REFERENCES members(member_id),
                task_id TEXT NOT NULL,
                address TEXT NOT NULL,
                port_base INTEGER NOT NULL,
                port_count INTEGER NOT NULL,
                device_uuids_json TEXT NOT NULL,
                rdma_interface TEXT,
                endpoint_owner INTEGER NOT NULL CHECK(endpoint_owner IN (0,1)),
                state TEXT NOT NULL CHECK(state IN
                    ('pending','staging','staged','starting','running','stopping',
                     'stopped','removing','removed','failed','unreachable')),
                operation_id TEXT,
                error TEXT,
                updated_at_unix INTEGER NOT NULL,
                UNIQUE(placement_group_id,node_id),
                UNIQUE(placement_group_id,task_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS device_allocations (
                allocation_id TEXT PRIMARY KEY,
                placement_id TEXT NOT NULL REFERENCES placements(placement_id),
                node_id TEXT NOT NULL REFERENCES members(member_id),
                device_uuid TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('reserved','active','draining','released')),
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL,
                UNIQUE(placement_id,node_id,device_uuid)
            ) STRICT;
            CREATE UNIQUE INDEX IF NOT EXISTS device_allocations_exclusive
              ON device_allocations(node_id,device_uuid)
              WHERE state IN ('reserved','active','draining');
            CREATE TABLE IF NOT EXISTS topology_plans (
                plan_id TEXT PRIMARY KEY,
                model TEXT NOT NULL,
                current_sha256 TEXT,
                proposed_json TEXT NOT NULL,
                proposed_sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending','applied','cancelled')),
                created_at_unix INTEGER NOT NULL,
                applied_at_unix INTEGER
            ) STRICT;
            CREATE TABLE IF NOT EXISTS exposure (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                provider TEXT NOT NULL,
                public_url TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('disabled','enabled','failed')),
                inference_target TEXT NOT NULL,
                configuration_sha256 TEXT NOT NULL,
                updated_at_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS adoption_window (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                nonce TEXT NOT NULL,
                expires_at_unix INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS request_summaries (
                request_id TEXT PRIMARY KEY,
                key_id TEXT,
                model TEXT NOT NULL,
                placement_group_id TEXT,
                placement_id TEXT,
                node_id TEXT,
                received_unix_ms INTEGER NOT NULL,
                completed_unix_ms INTEGER,
                status TEXT NOT NULL,
                input_tokens INTEGER,
                output_tokens INTEGER,
                cached_tokens INTEGER,
                queue_ms INTEGER,
                ttft_ms INTEGER,
                decode_ms INTEGER,
                retries INTEGER NOT NULL DEFAULT 0,
                exact_tokens INTEGER NOT NULL DEFAULT 0
            ) STRICT;
            CREATE TABLE IF NOT EXISTS usage_rollups (
                bucket_unix INTEGER NOT NULL,
                resolution TEXT NOT NULL CHECK(resolution IN ('minute','hour')),
                key_id TEXT NOT NULL,
                model TEXT NOT NULL,
                requests INTEGER NOT NULL,
                errors INTEGER NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cached_tokens INTEGER NOT NULL,
                PRIMARY KEY(bucket_unix,resolution,key_id,model)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                correlation_id TEXT NOT NULL,
                timestamp_unix_ns INTEGER NOT NULL,
                site_id TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                origin_member_id TEXT NOT NULL,
                origin_interface TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                before_sha256 TEXT,
                after_sha256 TEXT,
                outcome TEXT NOT NULL CHECK(outcome IN ('success','denied','failed')),
                reason TEXT,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            ) STRICT;
            CREATE TABLE IF NOT EXISTS audit_checkpoints (
                sequence INTEGER PRIMARY KEY REFERENCES audit_events(sequence),
                event_hash TEXT NOT NULL,
                signature_base64 TEXT NOT NULL,
                created_at_unix_ns INTEGER NOT NULL
            ) STRICT;
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
              BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'audit events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
              BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'audit events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_checkpoints_no_update
              BEFORE UPDATE ON audit_checkpoints BEGIN SELECT RAISE(ABORT,'audit checkpoints are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_checkpoints_no_delete
              BEFORE DELETE ON audit_checkpoints BEGIN SELECT RAISE(ABORT,'audit checkpoints are append-only'); END;
            """
        )
        self._migrate_placement_group_schema()

    def _migrate_placement_group_schema(self) -> None:
        """Perform the one clean pre-launch cut only after legacy state is empty."""

        group_columns = {
            str(row["name"])
            for row in self.connection.execute(
                "PRAGMA table_info(placement_groups)"
            )
        }
        placement_columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(placements)")
        }
        legacy = (
            "placement_id" in group_columns
            or "service_id" in placement_columns
            or "members_json" in placement_columns
        )
        if not legacy:
            return
        non_removed = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM placement_groups "
                "WHERE state!='removed' OR desired_state!='removed'"
            ).fetchone()[0]
        )
        unreleased = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM device_allocations WHERE state!='released'"
            ).fetchone()[0]
        )
        if non_removed or unreleased:
            raise SiteError(
                "legacy placement state must be removed and its devices released "
                "before the schema-4 placement cut"
            )
        try:
            self.connection.executescript(
                """
                BEGIN IMMEDIATE;
                DROP TABLE device_allocations;
                DROP TABLE placement_groups;
                DROP TABLE placements;
                DROP TABLE request_summaries;
                CREATE TABLE placement_groups (
                    placement_group_id TEXT PRIMARY KEY,
                    service_id TEXT NOT NULL REFERENCES model_services(service_id),
                    source TEXT NOT NULL,
                    model TEXT NOT NULL,
                    runtime TEXT NOT NULL,
                    target TEXT NOT NULL,
                    runtime_digest TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    topology_sha256 TEXT NOT NULL,
                    engine_credential_sha256 TEXT NOT NULL,
                    runtime_execution_contract_sha256 TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    plan_sha256 TEXT NOT NULL,
                    desired_state TEXT NOT NULL
                      CHECK(desired_state IN ('running','stopped','removed')),
                    state TEXT NOT NULL CHECK(state IN
                      ('staging','staged','starting','running','degraded',
                       'stopping','stopped','recovering','removing','removed','failed')),
                    endpoint_json TEXT,
                    capacity_json TEXT NOT NULL,
                    last_error TEXT,
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL
                ) STRICT;
                CREATE TABLE placements (
                    placement_id TEXT PRIMARY KEY,
                    placement_group_id TEXT NOT NULL
                      REFERENCES placement_groups(placement_group_id),
                    node_id TEXT NOT NULL REFERENCES members(member_id),
                    task_id TEXT NOT NULL,
                    address TEXT NOT NULL,
                    port_base INTEGER NOT NULL,
                    port_count INTEGER NOT NULL,
                    device_uuids_json TEXT NOT NULL,
                    rdma_interface TEXT,
                    endpoint_owner INTEGER NOT NULL CHECK(endpoint_owner IN (0,1)),
                    state TEXT NOT NULL CHECK(state IN
                      ('pending','staging','staged','starting','running','stopping',
                       'stopped','removing','removed','failed','unreachable')),
                    operation_id TEXT,
                    error TEXT,
                    updated_at_unix INTEGER NOT NULL,
                    UNIQUE(placement_group_id,node_id),
                    UNIQUE(placement_group_id,task_id)
                ) STRICT;
                CREATE TABLE device_allocations (
                    allocation_id TEXT PRIMARY KEY,
                    placement_id TEXT NOT NULL REFERENCES placements(placement_id),
                    node_id TEXT NOT NULL REFERENCES members(member_id),
                    device_uuid TEXT NOT NULL,
                    state TEXT NOT NULL
                      CHECK(state IN ('reserved','active','draining','released')),
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    UNIQUE(placement_id,node_id,device_uuid)
                ) STRICT;
                CREATE UNIQUE INDEX device_allocations_exclusive
                  ON device_allocations(node_id,device_uuid)
                  WHERE state IN ('reserved','active','draining');
                CREATE TABLE request_summaries (
                    request_id TEXT PRIMARY KEY,
                    key_id TEXT,
                    model TEXT NOT NULL,
                    placement_group_id TEXT,
                    placement_id TEXT,
                    node_id TEXT,
                    received_unix_ms INTEGER NOT NULL,
                    completed_unix_ms INTEGER,
                    status TEXT NOT NULL,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    cached_tokens INTEGER,
                    queue_ms INTEGER,
                    ttft_ms INTEGER,
                    decode_ms INTEGER,
                    retries INTEGER NOT NULL DEFAULT 0,
                    exact_tokens INTEGER NOT NULL DEFAULT 0
                ) STRICT;
                UPDATE site_meta SET value='4'
                 WHERE key='schema_version' AND value='3';
                COMMIT;
                """
            )
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise


    def initialize_coordinator(self, identity: SiteIdentity) -> None:
        with self.transaction():
            existing = dict(self.connection.execute("SELECT key,value FROM site_meta"))
            expected = {
                "schema_version": str(SCHEMA_VERSION),
                "site_id": identity.site_id,
                "coordinator_id": identity.coordinator_id,
                "site_public_key_sha256": identity.site_public_key_sha256,
            }
            if existing and existing != expected:
                raise SiteError("site database identity does not match site.json")
            for key, value in expected.items():
                self.connection.execute("INSERT OR IGNORE INTO site_meta(key,value) VALUES(?,?)", (key, value))
            now = int(time.time())
            self.connection.execute(
                "INSERT OR IGNORE INTO adoption_window(singleton,nonce,expires_at_unix) "
                "VALUES(1,?,?)",
                (secrets.token_hex(32), now + ADOPTION_WINDOW_SECONDS),
            )
            self.connection.execute(
                """INSERT OR IGNORE INTO members
                   (member_id,display_name,role,address,public_key_sha256,public_key_pem,
                    certificate_sha256,certificate_pem,state,approval_code_hash,
                    approval_expires_at_unix,facts_json,
                    facts_signature_base64,facts_sha256,joined_at_unix,updated_at_unix)
                   VALUES(?,?,?,?,?,?,?,?,'active',NULL,NULL,'{}',NULL,NULL,?,?)""",
                (identity.member_id, socket.gethostname(), "main", identity.coordinator_address,
                 identity.member_public_key_sha256,
                 _private_file(member_public_key_path(), minimum_bytes=128).decode("ascii"),
                 _certificate_fingerprint(member_certificate_path()),
                 _private_file(member_certificate_path(), minimum_bytes=256).decode("ascii"),
                 now, now),
            )
            if not self.connection.execute("SELECT 1 FROM audit_events LIMIT 1").fetchone():
                self._append_audit(
                    action="node.setup", target=identity.site_id, outcome="success",
                    before_sha256=None, after_sha256=_state_hash(dataclasses.asdict(identity)),
                    reason=None, actor_type="local-user", actor_id=getpass.getuser(),
                    origin_interface="cli", correlation_id=uuid.uuid4().hex,
                )

    def adoption(self, *, now_unix: int | None = None) -> dict[str, Any]:
        """Describe whether this untouched single-member site can be adopted."""
        now = int(time.time()) if now_unix is None else now_unix
        row = self.connection.execute(
            "SELECT nonce,expires_at_unix FROM adoption_window WHERE singleton=1"
        ).fetchone()
        reasons: list[str] = []
        if row is None:
            reasons.append("adoption_window_missing")
            nonce = None
            expires = None
        else:
            nonce = str(row["nonce"])
            expires = int(row["expires_at_unix"])
            if not SHA256_RE.fullmatch(nonce):
                reasons.append("adoption_nonce_invalid")
            if expires < now:
                reasons.append("adoption_window_expired")
        members = self.connection.execute(
            "SELECT member_id,role,state FROM members WHERE state!='removed'"
        ).fetchall()
        if (
            len(members) != 1
            or members[0]["member_id"] != self.identity.member_id
            or members[0]["role"] != "main"
            or members[0]["state"] != "active"
        ):
            reasons.append("site_is_not_single_member")
        if self.connection.execute(
            "SELECT COUNT(*) FROM controllers WHERE revoked_at_unix IS NULL"
        ).fetchone()[0] > 1:
            reasons.append("external_controller_exists")
        if self.connection.execute(
            "SELECT COUNT(*) FROM api_keys WHERE revoked_at_unix IS NULL"
        ).fetchone()[0] > 1:
            reasons.append("additional_api_credentials_exist")
        if self.connection.execute(
            "SELECT COUNT(*) FROM placements"
        ).fetchone()[0]:
            reasons.append("runtime_placement_exists")
        exposure = self.connection.execute(
            "SELECT state FROM exposure WHERE singleton=1"
        ).fetchone()
        if exposure is not None and exposure["state"] != "disabled":
            reasons.append("public_exposure_exists")
        return {
            "eligible": not reasons,
            "nonce": nonce if not reasons else None,
            "expires_at_unix": expires,
            "reasons": reasons,
        }

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()
            self._secure_database_files()

    def _append_audit(
        self,
        *,
        action: str,
        target: str,
        outcome: str,
        before_sha256: str | None,
        after_sha256: str | None,
        reason: str | None,
        actor_type: str,
        actor_id: str,
        origin_interface: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        previous = self.connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(previous[0]) if previous else "0" * 64
        event = {
            "event_id": uuid.uuid4().hex,
            "correlation_id": correlation_id,
            "timestamp_unix_ns": time.time_ns(),
            "site_id": self.identity.site_id,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "origin_member_id": self.identity.member_id,
            "origin_interface": origin_interface,
            "action": action,
            "target": target,
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
            "outcome": outcome,
            "reason": _bounded_reason(reason),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(bytes.fromhex(previous_hash) + _canonical_bytes(event)).hexdigest()
        event["event_hash"] = event_hash
        cursor = self.connection.execute(
            """INSERT INTO audit_events
               (event_id,correlation_id,timestamp_unix_ns,site_id,actor_type,actor_id,
                origin_member_id,origin_interface,action,target,before_sha256,after_sha256,
                outcome,reason,previous_hash,event_hash)
               VALUES(:event_id,:correlation_id,:timestamp_unix_ns,:site_id,:actor_type,:actor_id,
                      :origin_member_id,:origin_interface,:action,:target,:before_sha256,:after_sha256,
                      :outcome,:reason,:previous_hash,:event_hash)""",
            event,
        )
        sequence = int(cursor.lastrowid)
        event["sequence"] = sequence
        if sequence % CHECKPOINT_INTERVAL == 0:
            signature = _run(["openssl", "dgst", "-sha256", "-sign", str(site_key_path())], input_bytes=event_hash.encode("ascii"))
            self.connection.execute(
                "INSERT INTO audit_checkpoints(sequence,event_hash,signature_base64,created_at_unix_ns) VALUES(?,?,?,?)",
                (sequence, event_hash, base64.b64encode(signature).decode("ascii"), time.time_ns()),
            )
        return event

    def mutate(
        self,
        *,
        action: str,
        target: str,
        before: Any,
        callback: Callable[[sqlite3.Connection], T],
        after: Callable[[sqlite3.Connection, T], Any],
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> T:
        correlation = correlation_id or uuid.uuid4().hex
        try:
            with self.transaction():
                result = callback(self.connection)
                self._append_audit(
                    action=action, target=target, outcome="success",
                    before_sha256=_state_hash(before), after_sha256=_state_hash(after(self.connection, result)),
                    reason=None, actor_type=actor_type, actor_id=actor_id or getpass.getuser(),
                    origin_interface=origin_interface, correlation_id=correlation,
                )
                return result
        except BaseException as error:
            try:
                with self.transaction():
                    self._append_audit(
                        action=action, target=target, outcome="failed",
                        before_sha256=_state_hash(before), after_sha256=None, reason=type(error).__name__,
                        actor_type=actor_type, actor_id=actor_id or getpass.getuser(),
                        origin_interface=origin_interface, correlation_id=correlation,
                    )
            except BaseException as audit_error:
                raise SiteError("site mutation failed and its audit event could not be recorded") from audit_error
            raise

    def record_denied(
        self,
        action: str,
        target: str,
        reason: str,
        *,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> None:
        with self.transaction():
            self._append_audit(
                action=action, target=target, outcome="denied", before_sha256=None,
                after_sha256=None, reason=reason, actor_type=actor_type,
                actor_id=actor_id or getpass.getuser(), origin_interface=origin_interface,
                correlation_id=correlation_id or uuid.uuid4().hex,
            )

    def record_action(
        self,
        action: str,
        target: str,
        outcome: str,
        reason: str | None = None,
        *,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> None:
        if outcome not in {"success", "failed", "denied"}:
            raise SiteError("invalid audit outcome")
        with self.transaction():
            self._append_audit(
                action=action, target=target, outcome=outcome, before_sha256=None,
                after_sha256=None, reason=reason, actor_type=actor_type,
                actor_id=actor_id or getpass.getuser(), origin_interface=origin_interface,
                correlation_id=correlation_id or uuid.uuid4().hex,
            )

    def controllers(self, *, include_revoked: bool = False) -> list[dict[str, Any]]:
        where = "" if include_revoked else " WHERE revoked_at_unix IS NULL"
        rows = self.connection.execute(
            "SELECT * FROM controllers" + where + " ORDER BY controller_id"
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row_value in rows:
            row = dict(row_value)
            row.pop("certificate_pem")
            result.append(row)
        return result

    def upsert_controller(
        self,
        *,
        controller_id: str,
        name: str,
        role: str,
        certificate_sha256: str,
        certificate_pem: str,
    ) -> dict[str, Any]:
        if not ID_RE.fullmatch(controller_id):
            raise SiteError("controller identity is invalid")
        controller_name = _display_name(name)
        if role not in {"viewer", "operator", "administrator"}:
            raise SiteError("controller role is invalid")
        if not SHA256_RE.fullmatch(certificate_sha256):
            raise SiteError("controller certificate fingerprint is invalid")
        try:
            certificate_bytes = certificate_pem.encode("ascii")
        except (AttributeError, UnicodeEncodeError) as error:
            raise SiteError("controller certificate is invalid") from error
        if (
            not certificate_pem.startswith("-----BEGIN CERTIFICATE-----\n")
            or not certificate_pem.rstrip().endswith("-----END CERTIFICATE-----")
            or len(certificate_bytes) > 16_384
        ):
            raise SiteError("controller certificate is invalid")
        previous = self.connection.execute(
            "SELECT * FROM controllers WHERE controller_id=?", (controller_id,)
        ).fetchone()
        active = int(self.connection.execute(
            "SELECT COUNT(*) FROM controllers WHERE revoked_at_unix IS NULL AND controller_id!=?",
            (controller_id,),
        ).fetchone()[0])
        if active >= MAX_CONTROLLERS:
            raise SiteError("controller registry is full")
        now = int(time.time())
        row = {
            "controller_id": controller_id,
            "name": controller_name,
            "role": role,
            "certificate_sha256": certificate_sha256,
            "certificate_pem": certificate_pem,
            "created_at_unix": now,
            "revoked_at_unix": None,
        }

        def write(connection: sqlite3.Connection) -> dict[str, Any]:
            connection.execute(
                """INSERT INTO controllers
                   (controller_id,name,role,certificate_sha256,certificate_pem,
                    created_at_unix,revoked_at_unix)
                   VALUES(:controller_id,:name,:role,:certificate_sha256,:certificate_pem,
                          :created_at_unix,:revoked_at_unix)
                   ON CONFLICT(controller_id) DO UPDATE SET
                     name=excluded.name,
                     role=excluded.role,
                     certificate_sha256=excluded.certificate_sha256,
                     certificate_pem=excluded.certificate_pem,
                     created_at_unix=excluded.created_at_unix,
                     revoked_at_unix=NULL""",
                row,
            )
            return row

        return self.mutate(
            action="pair",
            target=controller_id,
            before=dict(previous) if previous is not None else {},
            callback=write,
            after=lambda _connection, result: result,
        )

    def revoke_controller(self, controller_id: str) -> dict[str, Any]:
        if not ID_RE.fullmatch(controller_id):
            raise SiteError("controller identity is invalid")
        previous = self.connection.execute(
            "SELECT * FROM controllers WHERE controller_id=? AND revoked_at_unix IS NULL",
            (controller_id,),
        ).fetchone()
        if previous is None:
            raise SiteError("controller is not active")
        now = int(time.time())

        def revoke(connection: sqlite3.Connection) -> dict[str, Any]:
            changed = connection.execute(
                "UPDATE controllers SET revoked_at_unix=? WHERE controller_id=? AND revoked_at_unix IS NULL",
                (now, controller_id),
            ).rowcount
            if changed != 1:
                raise SiteError("controller changed concurrently")
            result = dict(previous)
            result["revoked_at_unix"] = now
            return result

        return self.mutate(
            action="controllers.forget",
            target=controller_id,
            before=dict(previous),
            callback=revoke,
            after=lambda _connection, result: result,
        )

    def audit_rows(self, *, limit: int = 100, event_id: str | None = None) -> list[dict[str, Any]]:
        if limit < 1 or limit > 10_000:
            raise SiteError("audit limit must be between 1 and 10000")
        if event_id is not None:
            rows = self.connection.execute("SELECT * FROM audit_events WHERE event_id=?", (event_id,)).fetchall()
        else:
            rows = self.connection.execute("SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def iter_audit_rows(self) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            "SELECT * FROM audit_events ORDER BY sequence"
        ):
            yield dict(row)

    def verify_audit(self) -> dict[str, Any]:
        previous_hash = "0" * 64
        count = 0
        for row_value in self.connection.execute("SELECT * FROM audit_events ORDER BY sequence"):
            row = dict(row_value)
            stored_hash = row.pop("event_hash")
            sequence = row.pop("sequence")
            if row["previous_hash"] != previous_hash:
                raise SiteError(f"audit chain previous hash mismatch at sequence {sequence}")
            computed = hashlib.sha256(bytes.fromhex(previous_hash) + _canonical_bytes(row)).hexdigest()
            if computed != stored_hash:
                raise SiteError(f"audit event hash mismatch at sequence {sequence}")
            previous_hash = stored_hash
            count += 1
        for checkpoint in self.connection.execute("SELECT * FROM audit_checkpoints ORDER BY sequence"):
            event = self.connection.execute("SELECT event_hash FROM audit_events WHERE sequence=?", (checkpoint["sequence"],)).fetchone()
            if event is None or event[0] != checkpoint["event_hash"]:
                raise SiteError(f"audit checkpoint mismatch at sequence {checkpoint['sequence']}")
            signature = base64.b64decode(checkpoint["signature_base64"], validate=True)
            with tempfile.NamedTemporaryFile() as temporary:
                temporary.write(signature)
                temporary.flush()
                _run([
                    "openssl", "dgst", "-sha256", "-verify", str(site_public_key_path()),
                    "-signature", temporary.name,
                ], input_bytes=checkpoint["event_hash"].encode("ascii"))
        return {"valid": True, "events": count, "head_sha256": previous_hash}

    def create_invite(
        self,
        mode: str,
        *,
        candidate_public_key_sha256: str | None = None,
        direct_interface: str | None = None,
        lifetime_seconds: int = 180,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        if mode not in {"lan", "remote", "connectx"}:
            raise SiteError("membership invite mode is invalid")
        if lifetime_seconds < 30 or lifetime_seconds > 600:
            raise SiteError("membership invite lifetime must be between 30 and 600 seconds")
        if mode == "connectx":
            if not isinstance(candidate_public_key_sha256, str) or not SHA256_RE.fullmatch(candidate_public_key_sha256):
                raise SiteError("ConnectX invite must bind the candidate public key")
            if not isinstance(direct_interface, str) or not SAFE_NAME_RE.fullmatch(direct_interface):
                raise SiteError("ConnectX invite must bind a verified direct interface")
        elif candidate_public_key_sha256 is not None or direct_interface is not None:
            raise SiteError("code-based invite cannot carry direct-link authorization")
        invite_id = uuid.uuid4().hex
        nonce = secrets.token_hex(32)
        code = None if mode == "connectx" else f"{secrets.randbelow(100_000_000):08d}"
        code_secret = code or secrets.token_urlsafe(32)
        now = int(time.time())
        row = {
            "invite_id": invite_id,
            "mode": mode,
            "code_hash": self._hash_secret(code_secret),
            "nonce": nonce,
            "candidate_public_key_sha256": candidate_public_key_sha256,
            "direct_interface": direct_interface,
            "expires_at_unix": now + lifetime_seconds,
            "attempts": 0,
            "consumed_at_unix": None,
            "created_at_unix": now,
        }

        def insert(connection: sqlite3.Connection) -> dict[str, Any]:
            connection.execute(
                """INSERT INTO membership_invites
                   (invite_id,mode,code_hash,nonce,candidate_public_key_sha256,direct_interface,
                    expires_at_unix,attempts,consumed_at_unix,created_at_unix)
                   VALUES(:invite_id,:mode,:code_hash,:nonce,:candidate_public_key_sha256,
                          :direct_interface,:expires_at_unix,:attempts,:consumed_at_unix,:created_at_unix)""",
                row,
            )
            return {
                "schema_version": 1,
                "invite_id": invite_id,
                "mode": mode,
                "nonce": nonce,
                "code": code,
                "expires_at_unix": row["expires_at_unix"],
                "candidate_public_key_sha256": candidate_public_key_sha256,
                "direct_interface": direct_interface,
            }

        return self.mutate(
            action="child.invite", target=invite_id, before={}, callback=insert,
            after=lambda _connection, result: {key: value for key, value in result.items() if key != "code"},
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def public_invite(self, invite_id: str) -> dict[str, Any]:
        if not ID_RE.fullmatch(invite_id):
            raise SiteError("membership invite identity is invalid")
        row = self.connection.execute(
            "SELECT * FROM membership_invites WHERE invite_id=?", (invite_id,)
        ).fetchone()
        if row is None:
            raise SiteError("membership invite does not exist")
        invite = dict(row)
        if invite["consumed_at_unix"] is not None:
            self.record_denied(
                "child.invite.use",
                invite_id,
                "invite_already_consumed",
                actor_type="member-candidate",
                actor_id="unknown",
                origin_interface="pairing",
            )
            raise SiteError("membership invite was already consumed")
        if invite["expires_at_unix"] < int(time.time()):
            self.record_denied(
                "child.invite.use",
                invite_id,
                "invite_expired",
                actor_type="member-candidate",
                actor_id="unknown",
                origin_interface="pairing",
            )
            raise SiteError("membership invite expired")
        if invite["attempts"] >= 5:
            self.record_denied(
                "child.invite.use",
                invite_id,
                "invite_attempt_limit",
                actor_type="member-candidate",
                actor_id="unknown",
                origin_interface="pairing",
            )
            raise SiteError("membership invite attempt limit reached")
        return {
            "invite_id": invite["invite_id"],
            "mode": invite["mode"],
            "nonce": invite["nonce"],
            "expires_at_unix": invite["expires_at_unix"],
            "candidate_public_key_sha256": invite["candidate_public_key_sha256"],
            "direct_interface": invite["direct_interface"],
        }

    def enroll_member(
        self,
        *,
        invite_id: str,
        code: str | None,
        member_id: str,
        member_name: str,
        member_address: str,
        member_public_key: str,
        installation_id: str,
        installation_created_at_unix: int,
        proof_signature: str,
    ) -> dict[str, Any]:
        if not ID_RE.fullmatch(invite_id) or not ID_RE.fullmatch(member_id):
            raise SiteError("membership request identity is invalid")
        if not SHA256_RE.fullmatch(installation_id):
            raise SiteError("member installation identity is invalid")
        if (
            not isinstance(installation_created_at_unix, int)
            or isinstance(installation_created_at_unix, bool)
            or installation_created_at_unix <= 0
            or installation_created_at_unix > int(time.time()) + 300
        ):
            raise SiteError("member installation timestamp is invalid")
        name = _display_name(member_name)
        if not isinstance(member_address, str) or not member_address.strip() or len(member_address) > 255:
            raise SiteError("membership address is invalid")
        row = self.connection.execute(
            "SELECT * FROM membership_invites WHERE invite_id=?", (invite_id,)
        ).fetchone()
        if row is None:
            raise SiteError("membership invite does not exist")
        invite = dict(row)
        now = int(time.time())
        if invite["consumed_at_unix"] is not None:
            raise SiteError("membership invite was already consumed")
        if invite["expires_at_unix"] < now:
            raise SiteError("membership invite expired")
        if invite["attempts"] >= 5:
            raise SiteError("membership invite attempt limit reached")
        fingerprint = member_public_key_fingerprint(member_public_key)
        transcript = {
            "contract": "letsinfer-child-enrollment-v1",
            "site_id": self.identity.site_id,
            "invite_id": invite_id,
            "nonce": invite["nonce"],
            "member_id": member_id,
            "member_name": name,
            "member_address": member_address,
            "member_public_key_sha256": fingerprint,
            "installation_id": installation_id,
            "installation_created_at_unix": installation_created_at_unix,
        }
        try:
            verified_fingerprint = verify_member_proof(member_public_key, transcript, proof_signature)
        except SiteError:
            with self.transaction():
                self.connection.execute(
                "UPDATE membership_invites SET attempts=attempts+1 WHERE invite_id=?",
                    (invite_id,),
                )
                self._append_audit(
                    action="child.enroll", target=member_id, outcome="denied",
                    before_sha256=None, after_sha256=None, reason="invalid_member_proof",
                    actor_type="member-candidate", actor_id=member_id,
                    origin_interface="pairing", correlation_id=uuid.uuid4().hex,
                )
            raise
        if verified_fingerprint != fingerprint:
            raise SiteError("member proof key identity mismatch")
        if invite["mode"] == "connectx":
            if code is not None or fingerprint != invite["candidate_public_key_sha256"]:
                with self.transaction():
                    self.connection.execute(
                        "UPDATE membership_invites SET attempts=attempts+1 WHERE invite_id=?",
                        (invite_id,),
                    )
                    self._append_audit(
                        action="child.enroll",
                        target=member_id,
                        outcome="denied",
                        before_sha256=None,
                        after_sha256=None,
                        reason=(
                            "connectx_code_not_allowed"
                            if code is not None
                            else "unapproved_connectx_identity"
                        ),
                        actor_type="member-candidate",
                        actor_id=member_id,
                        origin_interface="pairing",
                        correlation_id=uuid.uuid4().hex,
                    )
                raise SiteError(
                    "ConnectX enrollment does not use a setup code"
                    if code is not None
                    else "candidate does not match the approved ConnectX identity"
                )
        else:
            if not isinstance(code, str) or not re.fullmatch(r"[0-9]{8}", code) or not self.verify_secret(code, invite["code_hash"]):
                with self.transaction():
                    self.connection.execute(
                        "UPDATE membership_invites SET attempts=attempts+1 WHERE invite_id=?",
                        (invite_id,),
                    )
                    self._append_audit(
                        action="child.enroll", target=member_id, outcome="denied",
                        before_sha256=None, after_sha256=None, reason="invalid_setup_code",
                        actor_type="member-candidate", actor_id=member_id,
                        origin_interface="pairing", correlation_id=uuid.uuid4().hex,
                    )
                raise SiteError("membership setup code is incorrect")
        with tempfile.TemporaryDirectory(prefix="letsinfer-child-certificate-") as temporary:
            root = pathlib.Path(temporary)
            public_key_path = root / "member.pub"
            certificate_path = root / "member.crt"
            public_key_path.write_text(member_public_key, encoding="ascii")
            public_key_path.chmod(0o600)
            certificate_sha256 = _issue_member_certificate(
                member_id, public_key_path, output=certificate_path
            )
            certificate_pem = certificate_path.read_text(encoding="ascii")
        membership = {
            "schema_version": 1,
            "site_id": self.identity.site_id,
            "member_id": member_id,
            "installation_id": installation_id,
            "installation_created_at_unix": installation_created_at_unix,
            "display_name": self.identity.display_name,
            "coordinator_id": self.identity.coordinator_id,
            "coordinator_address": self.identity.coordinator_address,
            "site_public_key_sha256": self.identity.site_public_key_sha256,
            "member_public_key_sha256": fingerprint,
            "member_certificate_sha256": certificate_sha256,
            "state": (
                "active"
                if invite["mode"] in {"connectx", "lan"}
                else "pending"
            ),
            "approval_expires_at_unix": (
                invite["expires_at_unix"]
                if invite["mode"] == "remote"
                else None
            ),
            "issued_at_unix": now,
        }
        comparison_code = (
            f"{int(hashlib.sha256(_canonical_bytes(transcript)).hexdigest(), 16) % 1_000_000:06d}"
            if invite["mode"] == "remote"
            else None
        )
        approval_code_hash = (
            None if comparison_code is None else self._hash_secret(comparison_code)
        )
        existing = self.connection.execute(
            "SELECT * FROM members WHERE member_id=? OR public_key_sha256=?",
            (member_id, fingerprint),
        ).fetchall()
        if len(existing) > 1 or (
            existing
            and (
                existing[0]["member_id"] != member_id
                or existing[0]["public_key_sha256"] != fingerprint
                or existing[0]["state"] != "removed"
            )
        ):
            raise SiteError("membership physical identity is already registered")
        before = (
            {
                "member_id": member_id,
                "public_key_sha256": fingerprint,
                "state": "removed",
            }
            if existing
            else {}
        )

        def enroll(connection: sqlite3.Connection) -> dict[str, Any]:
            if existing:
                changed = connection.execute(
                    """UPDATE members SET display_name=?,role='child',address=?,
                       public_key_pem=?,certificate_sha256=?,certificate_pem=?,state=?,
                       approval_code_hash=?,approval_expires_at_unix=?,facts_json='{}',
                       facts_signature_base64=NULL,facts_sha256=NULL,joined_at_unix=?,
                       updated_at_unix=? WHERE member_id=? AND state='removed'
                       AND public_key_sha256=?""",
                    (
                        name,
                        member_address,
                        member_public_key,
                        certificate_sha256,
                        certificate_pem,
                        membership["state"],
                        approval_code_hash,
                        membership["approval_expires_at_unix"],
                        now,
                        now,
                        member_id,
                        fingerprint,
                    ),
                ).rowcount
                if changed != 1:
                    raise SiteError("removed membership changed concurrently")
            else:
                connection.execute(
                    """INSERT INTO members
                       (member_id,display_name,role,address,public_key_sha256,public_key_pem,
                        certificate_sha256,certificate_pem,state,approval_code_hash,
                        approval_expires_at_unix,facts_json,
                        facts_signature_base64,facts_sha256,joined_at_unix,updated_at_unix)
                       VALUES(?,?,'child',?,?,?,?,?,?,?,?, '{}',NULL,NULL,?,?)""",
                    (
                        member_id,
                        name,
                        member_address,
                        fingerprint,
                        member_public_key,
                        certificate_sha256,
                        certificate_pem,
                        membership["state"],
                        approval_code_hash,
                        membership["approval_expires_at_unix"],
                        now,
                        now,
                    ),
                )
            changed = connection.execute(
                "UPDATE membership_invites SET consumed_at_unix=? WHERE invite_id=? AND consumed_at_unix IS NULL",
                (now, invite_id),
            ).rowcount
            if changed != 1:
                raise SiteError("membership invite changed concurrently")
            return membership

        signature = sign_site_document(membership)
        try:
            document = self.mutate(
                action="child.enroll", target=member_id, before=before, callback=enroll,
                after=lambda _connection, result: result,
                actor_type="member-candidate", actor_id=member_id, origin_interface="pairing",
            )
        except sqlite3.IntegrityError as error:
            raise SiteError("membership identity conflicts with retained state") from error
        return {
            "document": document,
            "signature": signature,
            "site_public_key": _private_file(site_public_key_path(), minimum_bytes=128).decode("ascii"),
            "site_ca_certificate": _private_file(
                site_ca_certificate_path(), minimum_bytes=256
            ).decode("ascii"),
            "member_certificate": certificate_pem,
            "comparison_code": comparison_code,
        }

    def approve_member(
        self,
        member_id: str,
        comparison_code: str,
        *,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        if not ID_RE.fullmatch(member_id):
            raise SiteError("member identity is invalid")
        if not isinstance(comparison_code, str) or not re.fullmatch(r"[0-9]{6}", comparison_code):
            raise SiteError("member comparison code must contain six digits")
        current = self.connection.execute(
            "SELECT * FROM members WHERE member_id=? AND state='pending'", (member_id,)
        ).fetchone()
        if current is None:
            raise SiteError("member is not awaiting approval")
        now = int(time.time())
        if current["approval_expires_at_unix"] < now:
            raise SiteError("member approval expired")
        if not self.verify_secret(comparison_code, str(current["approval_code_hash"])):
            self.record_denied(
                "child.approve",
                member_id,
                "comparison_code_mismatch",
                actor_type=actor_type,
                actor_id=actor_id,
                origin_interface=origin_interface,
                correlation_id=correlation_id,
            )
            raise SiteError("member comparison code is incorrect")
        before = {"member_id": member_id, "state": "pending"}

        def approve(connection: sqlite3.Connection) -> dict[str, Any]:
            changed = connection.execute(
                """UPDATE members SET state='active',approval_code_hash=NULL,
                   approval_expires_at_unix=NULL,updated_at_unix=?
                   WHERE member_id=? AND state='pending'""",
                (now, member_id),
            ).rowcount
            if changed != 1:
                raise SiteError("member changed concurrently")
            return {"member_id": member_id, "state": "active"}

        return self.mutate(
            action="child.approve", target=member_id, before=before,
            callback=approve, after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def approve_member_locally(
        self,
        member_id: str,
        *,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Activate one legacy pending child after explicit local node-add intent."""

        if not ID_RE.fullmatch(member_id):
            raise SiteError("member identity is invalid")
        current = self.connection.execute(
            "SELECT * FROM members WHERE member_id=? AND state='pending'", (member_id,)
        ).fetchone()
        if current is None:
            raise SiteError("member is not awaiting approval")
        before = {"member_id": member_id, "state": "pending"}
        now = int(time.time())

        def approve(connection: sqlite3.Connection) -> dict[str, Any]:
            changed = connection.execute(
                """UPDATE members SET state='active',approval_code_hash=NULL,
                   approval_expires_at_unix=NULL,updated_at_unix=?
                   WHERE member_id=? AND state='pending'""",
                (now, member_id),
            ).rowcount
            if changed != 1:
                raise SiteError("member changed concurrently")
            return {"member_id": member_id, "state": "active"}

        return self.mutate(
            action="child.approve",
            target=member_id,
            before=before,
            callback=approve,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def members(self, *, include_removed: bool = False) -> list[dict[str, Any]]:
        where = "" if include_removed else " WHERE state!='removed'"
        rows = self.connection.execute(
            "SELECT * FROM members" + where + " ORDER BY role,member_id"
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row_value in rows:
            row = dict(row_value)
            row["facts"] = json.loads(row.pop("facts_json"))
            row.pop("public_key_pem")
            row.pop("certificate_pem")
            row.pop("approval_code_hash")
            result.append(row)
        return result

    def update_member_facts(
        self,
        member_id: str,
        facts: Mapping[str, Any],
        signature_base64: str,
        *,
        actor_type: str = "member",
        origin_interface: str = "member-agent",
    ) -> dict[str, Any]:
        member = self.connection.execute(
            "SELECT * FROM members WHERE member_id=? AND state!='removed'", (member_id,)
        ).fetchone()
        if member is None:
            raise SiteError("member is not active in this site")
        if facts.get("member_id") != member_id:
            raise SiteError("member facts identity does not match the authenticated member")
        fingerprint = verify_member_proof(
            str(member["public_key_pem"]), facts, signature_base64
        )
        if fingerprint != member["public_key_sha256"]:
            raise SiteError("member facts key does not match the enrolled identity")
        facts_json = _safe_json(dict(facts))
        facts_hash = _state_hash(dict(facts))
        # Authenticated inventory is a bounded, replace-in-place observation,
        # not an authoritative site mutation. Auditing each live sample
        # would create an unbounded event stream and obscure actual control
        # changes; the signed bytes and their digest remain in the one member
        # row and topology plans bind the exact snapshot they consume.
        with self.transaction():
            changed = self.connection.execute(
                """UPDATE members SET facts_json=?,facts_signature_base64=?,facts_sha256=?,
                   updated_at_unix=? WHERE member_id=? AND state!='removed'""",
                (facts_json, signature_base64, facts_hash, int(time.time()), member_id),
            ).rowcount
            if changed != 1:
                raise SiteError("member changed concurrently")
        return dict(facts)

    def verify_active_member_statement(
        self,
        member_id: str,
        statement: Mapping[str, Any],
        signature_base64: str,
    ) -> str:
        """Verify a bounded transient statement without persisting its body."""
        member = self.connection.execute(
            "SELECT public_key_pem,public_key_sha256 FROM members "
            "WHERE member_id=? AND state IN ('active','draining')",
            (member_id,),
        ).fetchone()
        if member is None:
            raise SiteError("member is not active in this site")
        fingerprint = verify_member_proof(
            str(member["public_key_pem"]), statement, signature_base64
        )
        if fingerprint != member["public_key_sha256"]:
            raise SiteError("member statement key does not match the enrolled identity")
        return fingerprint

    def set_member_draining(
        self,
        member_id: str,
        draining: bool,
        *,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Stop or resume new request admission without interrupting active work."""
        if not ID_RE.fullmatch(member_id):
            raise SiteError("member identity is invalid")
        current = self.connection.execute(
            "SELECT member_id,state FROM members WHERE member_id=? AND state!='removed'",
            (member_id,),
        ).fetchone()
        if current is None:
            raise SiteError("member is not active in this site")
        current_state = str(current["state"])
        desired_state = "draining" if draining else "active"
        allowed_state = "active" if draining else "draining"
        before = {"member_id": member_id, "state": current_state}

        def update(connection: sqlite3.Connection) -> dict[str, Any]:
            observed = connection.execute(
                "SELECT state FROM members WHERE member_id=? AND state!='removed'",
                (member_id,),
            ).fetchone()
            if observed is None:
                raise SiteError("member changed concurrently")
            observed_state = str(observed["state"])
            if observed_state not in {allowed_state, desired_state}:
                verb = "paused" if draining else "resumed"
                raise SiteError(f"member in state {observed_state!r} cannot be {verb}")
            if observed_state != desired_state:
                changed = connection.execute(
                    "UPDATE members SET state=?,updated_at_unix=? "
                    "WHERE member_id=? AND state=?",
                    (desired_state, int(time.time()), member_id, observed_state),
                ).rowcount
                if changed != 1:
                    raise SiteError("member changed concurrently")
            return {"member_id": member_id, "state": desired_state}

        return self.mutate(
            action="child.drain" if draining else "child.resume",
            target=member_id,
            before=before,
            callback=update,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def remove_member(
        self,
        member_id: str,
        *,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        if member_id == self.identity.coordinator_id:
            raise SiteError("the active coordinator cannot remove itself")
        current = self.connection.execute(
            "SELECT * FROM members WHERE member_id=? AND state!='removed'", (member_id,)
        ).fetchone()
        if current is None:
            raise SiteError("member is not active in this site")
        placement = self.connection.execute(
            "SELECT p.placement_id,p.placement_group_id FROM placements AS p "
            "JOIN placement_groups AS g USING(placement_group_id) "
            "WHERE p.node_id=? AND (g.state!='removed' OR g.desired_state!='removed') "
            "ORDER BY p.placement_id LIMIT 1",
            (member_id,),
        ).fetchone()
        if placement is not None:
            raise SiteError(
                "node owns placement "
                f"{placement['placement_id']} in placement group "
                f"{placement['placement_group_id']}; remove it first"
            )
        before = dict(current)
        before.pop("public_key_pem")
        before.pop("certificate_pem")

        def remove(connection: sqlite3.Connection) -> dict[str, Any]:
            changed = connection.execute(
                "UPDATE members SET state='removed',updated_at_unix=? WHERE member_id=? AND state!='removed'",
                (int(time.time()), member_id),
            ).rowcount
            if changed != 1:
                raise SiteError("member changed concurrently")
            return {"member_id": member_id, "state": "removed"}

        return self.mutate(
            action="child.remove", target=member_id, before=before,
            callback=remove, after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def aliases(self) -> dict[str, str]:
        return dict(self.connection.execute("SELECT alias,model FROM model_aliases ORDER BY alias"))

    def set_alias(self, alias: str, model: str) -> dict[str, str]:
        if not SAFE_NAME_RE.fullmatch(alias) or not SAFE_NAME_RE.fullmatch(model):
            raise SiteError("model alias and model must use lowercase safe names")
        current = self.connection.execute(
            "SELECT model FROM model_aliases WHERE alias=?", (alias,)
        ).fetchone()
        before = {} if current is None else {"alias": alias, "model": current[0]}
        now = int(time.time())

        def update(connection: sqlite3.Connection) -> dict[str, str]:
            connection.execute(
                """INSERT INTO model_aliases(alias,model,created_at_unix,updated_at_unix)
                   VALUES(?,?,?,?) ON CONFLICT(alias) DO UPDATE SET
                   model=excluded.model,updated_at_unix=excluded.updated_at_unix""",
                (alias, model, now, now),
            )
            return {"alias": alias, "model": model}

        return self.mutate(
            action="alias.set", target=alias, before=before,
            callback=update, after=lambda _connection, result: result,
        )

    def remove_alias(self, alias: str) -> dict[str, str]:
        current = self.connection.execute(
            "SELECT model FROM model_aliases WHERE alias=?", (alias,)
        ).fetchone()
        if current is None:
            raise SiteError("model alias is not registered")
        before = {"alias": alias, "model": current[0]}

        def remove(connection: sqlite3.Connection) -> dict[str, str]:
            connection.execute("DELETE FROM model_aliases WHERE alias=?", (alias,))
            return {"alias": alias, "model": current[0]}

        return self.mutate(
            action="alias.remove", target=alias, before=before,
            callback=remove, after=lambda _connection, result: {},
        )

    def ensure_model_service(
        self,
        model: str,
        *,
        desired_state: str = "running",
        actor_type: str = "system",
        actor_id: str = "main",
        origin_interface: str = "orchestrator",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Create or return the one durable public service for a logical model."""
        if not isinstance(model, str) or not SAFE_NAME_RE.fullmatch(model):
            raise SiteError("logical model service name is invalid")
        if desired_state not in {"running", "stopped", "removed"}:
            raise SiteError("logical model service desired state is invalid")
        identity = hashlib.sha256(
            _canonical_bytes(
                {
                    "contract": "letsinfer-model-service-v1",
                    "node_id": self.identity.site_id,
                    "model": model,
                }
            )
        ).hexdigest()[:32]
        current = self.connection.execute(
            "SELECT * FROM model_services WHERE service_id=?", (identity,)
        ).fetchone()
        before = {} if current is None else dict(current)
        now = int(time.time())
        created = now if current is None else int(current["created_at_unix"])
        row = {
            "service_id": identity,
            "model": model,
            "desired_state": desired_state,
            "created_at_unix": created,
            "updated_at_unix": now,
        }

        def update(connection: sqlite3.Connection) -> dict[str, Any]:
            connection.execute(
                """INSERT INTO model_services
                   (service_id,model,desired_state,created_at_unix,updated_at_unix)
                   VALUES(:service_id,:model,:desired_state,:created_at_unix,:updated_at_unix)
                   ON CONFLICT(service_id) DO UPDATE SET
                    desired_state=excluded.desired_state,
                    updated_at_unix=excluded.updated_at_unix""",
                row,
            )
            return dict(row)

        return self.mutate(
            action="service.ensure",
            target=identity,
            before=before,
            callback=update,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def model_services(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM model_services ORDER BY model"
            )
        ]

    def register_placement_group(
        self,
        plan: Mapping[str, Any],
        *,
        source: str,
        model: str,
        runtime: str,
        target: str,
        capacity: Mapping[str, Any],
        engine_credential_sha256: str,
        actor_type: str = "system",
        actor_id: str = "main",
        origin_interface: str = "orchestrator",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Register one immutable placement group and its individual placements."""

        try:
            document = validate_placement_group_document(dict(plan))
        except OrchestrationError as error:
            raise SiteError(str(error)) from error
        placement_group_id = document["placement_group_id"]
        if (
            not is_immutable_runtime_source(source)
            or source != document["release"]["source"]
            or not isinstance(engine_credential_sha256, str)
            or not SHA256_RE.fullmatch(engine_credential_sha256)
        ):
            raise SiteError("placement-group source or credential identity is invalid")
        for value, label in ((model, "model"), (runtime, "runtime"), (target, "target")):
            if (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 1024
                or any(unicodedata.category(character).startswith("C") for character in value)
            ):
                raise SiteError(f"placement-group {label} is invalid")
        safe_capacity = dict(capacity)
        capacity_fields = {
            "max_connections",
            "max_active_requests",
            "max_context_tokens",
            "interconnect",
        }
        if set(safe_capacity) != capacity_fields:
            raise SiteError("placement-group capacity has invalid fields")
        for key in ("max_connections", "max_active_requests", "max_context_tokens"):
            value = safe_capacity[key]
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise SiteError(f"placement-group capacity {key} must be positive")
        interconnect = safe_capacity["interconnect"]
        if not isinstance(interconnect, dict) or set(interconnect) != {
            "kind",
            "rdma_required",
            "minimum_speed_mbps",
            "minimum_mtu",
        }:
            raise SiteError("placement-group interconnect has invalid fields")
        service = self.connection.execute(
            "SELECT model FROM model_services WHERE service_id=?",
            (document["service_id"],),
        ).fetchone()
        if service is None or service["model"] != model:
            raise SiteError("placement group does not belong to its model service")
        plan_json = _safe_json(document)
        plan_sha256 = hashlib.sha256(_canonical_bytes(document)).hexdigest()
        now = int(time.time())
        current = self.connection.execute(
            "SELECT * FROM placement_groups WHERE placement_group_id=?",
            (placement_group_id,),
        ).fetchone()
        before = {} if current is None else dict(current)
        if current is not None and (
            current["plan_sha256"] != plan_sha256
            or current["source"] != source
            or current["engine_credential_sha256"] != engine_credential_sha256
        ):
            raise SiteError("placement-group immutable identity changed")
        group_row = {
            "placement_group_id": placement_group_id,
            "service_id": document["service_id"],
            "source": source,
            "model": model,
            "runtime": runtime,
            "target": target,
            "runtime_digest": document["runtime_digest"],
            "manifest_sha256": document["manifest_sha256"],
            "topology_sha256": document["topology_sha256"],
            "engine_credential_sha256": engine_credential_sha256,
            "runtime_execution_contract_sha256": document[
                "runtime_execution_contract_sha256"
            ],
            "plan_json": plan_json,
            "plan_sha256": plan_sha256,
            "desired_state": "running",
            "state": "staging",
            "endpoint_json": None,
            "capacity_json": _safe_json(safe_capacity),
            "last_error": None,
            "created_at_unix": now if current is None else int(current["created_at_unix"]),
            "updated_at_unix": now,
        }
        placement_rows = [
            {
                "placement_id": item["placement_id"],
                "placement_group_id": placement_group_id,
                "node_id": item["node_id"],
                "task_id": item["task_id"],
                "address": item["address"],
                "port_base": item["port_base"],
                "port_count": item["port_count"],
                "device_uuids_json": _safe_json(item["device_uuids"]),
                "rdma_interface": item.get("rdma_interface"),
                "endpoint_owner": int(
                    item["placement_id"] == document["endpoint_placement_id"]
                ),
                "state": "pending",
                "operation_id": None,
                "error": None,
                "updated_at_unix": now,
            }
            for item in document["placements"]
        ]

        def update(connection: sqlite3.Connection) -> str:
            connection.execute(
                """INSERT INTO placement_groups
                   (placement_group_id,service_id,source,model,runtime,target,
                    runtime_digest,manifest_sha256,topology_sha256,
                    engine_credential_sha256,runtime_execution_contract_sha256,
                    plan_json,plan_sha256,desired_state,state,endpoint_json,
                    capacity_json,last_error,created_at_unix,updated_at_unix)
                   VALUES(:placement_group_id,:service_id,:source,:model,:runtime,:target,
                    :runtime_digest,:manifest_sha256,:topology_sha256,
                    :engine_credential_sha256,:runtime_execution_contract_sha256,
                    :plan_json,:plan_sha256,:desired_state,:state,:endpoint_json,
                    :capacity_json,:last_error,:created_at_unix,:updated_at_unix)
                   ON CONFLICT(placement_group_id) DO NOTHING""",
                group_row,
            )
            for row in placement_rows:
                connection.execute(
                    """INSERT INTO placements
                       (placement_id,placement_group_id,node_id,task_id,address,
                        port_base,port_count,device_uuids_json,rdma_interface,
                        endpoint_owner,state,operation_id,error,updated_at_unix)
                       VALUES(:placement_id,:placement_group_id,:node_id,:task_id,:address,
                        :port_base,:port_count,:device_uuids_json,:rdma_interface,
                        :endpoint_owner,:state,:operation_id,:error,:updated_at_unix)
                       ON CONFLICT(placement_id) DO NOTHING""",
                    row,
                )
            return placement_group_id

        identifier = self.mutate(
            action="placement_group.register",
            target=placement_group_id,
            before=before,
            callback=update,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )
        return self.placement_group(identifier)

    def reserve_placement_devices(
        self,
        placement_group_id: str,
        placements: Sequence[Mapping[str, Any]],
        *,
        actor_type: str = "system",
        actor_id: str = "main",
        origin_interface: str = "orchestrator",
        correlation_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if not isinstance(placement_group_id, str) or not ID_RE.fullmatch(
            placement_group_id
        ):
            raise SiteError("placement-group device identity is invalid")
        planned = {
            str(row["placement_id"]): dict(row)
            for row in self.connection.execute(
                "SELECT placement_id,node_id,device_uuids_json FROM placements "
                "WHERE placement_group_id=?",
                (placement_group_id,),
            )
        }
        requested: list[tuple[str, str, str]] = []
        for placement in placements:
            if not isinstance(placement, Mapping) or set(placement) != {
                "placement_id",
                "node_id",
                "device_uuids",
            }:
                raise SiteError("placement device assignment is invalid")
            placement_id = placement["placement_id"]
            node_id = placement["node_id"]
            device_uuids = placement["device_uuids"]
            expected = planned.get(str(placement_id))
            if (
                expected is None
                or expected["node_id"] != node_id
                or not isinstance(device_uuids, list)
                or device_uuids != json.loads(expected["device_uuids_json"])
            ):
                raise SiteError("placement device assignment differs from its plan")
            requested.extend(
                (str(placement_id), str(node_id), device_uuid)
                for device_uuid in device_uuids
            )
        if not requested or len(requested) != len(set(requested)):
            raise SiteError("placement device assignment is empty or duplicated")
        now = int(time.time())
        rows = [
            {
                "allocation_id": hashlib.sha256(
                    _canonical_bytes(
                        {
                            "contract": "letsinfer-placement-device-v1",
                            "placement_id": placement_id,
                            "node_id": node_id,
                            "device_uuid": device_uuid,
                        }
                    )
                ).hexdigest()[:32],
                "placement_id": placement_id,
                "node_id": node_id,
                "device_uuid": device_uuid,
                "state": "reserved",
                "created_at_unix": now,
                "updated_at_unix": now,
            }
            for placement_id, node_id, device_uuid in sorted(requested)
        ]
        current = [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM device_allocations WHERE placement_id IN "
                "(SELECT placement_id FROM placements WHERE placement_group_id=?) "
                "ORDER BY placement_id,device_uuid",
                (placement_group_id,),
            )
        ]

        def update(connection: sqlite3.Connection) -> list[dict[str, Any]]:
            conflicts = connection.execute(
                """SELECT node_id,device_uuid,placement_id FROM device_allocations
                   WHERE state IN ('reserved','active','draining')
                     AND placement_id NOT IN
                       (SELECT placement_id FROM placements WHERE placement_group_id=?)""",
                (placement_group_id,),
            ).fetchall()
            conflict_map = {
                (str(row["node_id"]), str(row["device_uuid"])): str(row["placement_id"])
                for row in conflicts
            }
            for _placement_id, node_id, device_uuid in requested:
                owner = conflict_map.get((node_id, device_uuid))
                if owner is not None:
                    raise SiteError(
                        f"device {device_uuid} on node {node_id} is allocated "
                        f"to placement {owner}"
                    )
            connection.execute(
                "UPDATE device_allocations SET state='released',updated_at_unix=? "
                "WHERE placement_id IN "
                "(SELECT placement_id FROM placements WHERE placement_group_id=?) "
                "AND state!='released'",
                (now, placement_group_id),
            )
            for row in rows:
                connection.execute(
                    """INSERT INTO device_allocations
                       (allocation_id,placement_id,node_id,device_uuid,state,
                        created_at_unix,updated_at_unix)
                       VALUES(:allocation_id,:placement_id,:node_id,:device_uuid,:state,
                        :created_at_unix,:updated_at_unix)
                       ON CONFLICT(allocation_id) DO UPDATE SET
                        state='reserved',updated_at_unix=excluded.updated_at_unix""",
                    row,
                )
            return [dict(row) for row in rows]

        return self.mutate(
            action="placement.reserve",
            target=placement_group_id,
            before=current,
            callback=update,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def set_placement_group_allocation_state(
        self,
        placement_group_id: str,
        state: str,
        *,
        actor_type: str = "system",
        actor_id: str = "main",
        origin_interface: str = "orchestrator",
        correlation_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if not ID_RE.fullmatch(placement_group_id) or state not in {
            "reserved",
            "active",
            "draining",
            "released",
        }:
            raise SiteError("placement allocation transition is invalid")
        current = [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM device_allocations WHERE placement_id IN "
                "(SELECT placement_id FROM placements WHERE placement_group_id=?) "
                "ORDER BY placement_id,device_uuid",
                (placement_group_id,),
            )
        ]
        if not current:
            raise SiteError("placement group has no device allocation")
        allowed = {
            "reserved": {"reserved", "active", "draining", "released"},
            "active": {"active", "draining"},
            "draining": {"draining", "reserved", "released"},
            "released": {"released"},
        }
        invalid = sorted(
            {
                str(row["state"])
                for row in current
                if state not in allowed[str(row["state"])]
            }
        )
        if invalid:
            raise SiteError(
                "placement allocation transition is invalid: "
                + ",".join(invalid)
                + f" -> {state}"
            )
        now = int(time.time())

        def update(connection: sqlite3.Connection) -> list[dict[str, Any]]:
            connection.execute(
                "UPDATE device_allocations SET state=?,updated_at_unix=? "
                "WHERE placement_id IN "
                "(SELECT placement_id FROM placements WHERE placement_group_id=?)",
                (state, now, placement_group_id),
            )
            return [
                {**row, "state": state, "updated_at_unix": now}
                for row in current
            ]

        return self.mutate(
            action=f"placement.{state}",
            target=placement_group_id,
            before=current,
            callback=update,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def device_allocations(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        where = (
            " WHERE state IN ('reserved','active','draining')" if active_only else ""
        )
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM device_allocations"
                + where
                + " ORDER BY node_id,device_uuid,placement_id"
            )
        ]

    def set_placement_group(
        self,
        placement_group: Mapping[str, Any],
        *,
        source: str,
        engine_credential_sha256: str,
        desired_state: str,
        state: str,
        placements: Sequence[Mapping[str, Any]],
        action: str,
        error: str | None = None,
        actor_type: str = "system",
        actor_id: str = "main",
        origin_interface: str = "orchestrator",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Atomically persist one placement-group and all placement states."""

        try:
            document = validate_placement_group_document(dict(placement_group))
        except OrchestrationError as validation_error:
            raise SiteError(str(validation_error)) from validation_error
        placement_group_id = document["placement_group_id"]
        current = self.connection.execute(
            "SELECT * FROM placement_groups WHERE placement_group_id=?",
            (placement_group_id,),
        ).fetchone()
        if current is None:
            raise SiteError("placement group is not registered")
        plan_sha256 = hashlib.sha256(_canonical_bytes(document)).hexdigest()
        if (
            current["plan_sha256"] != plan_sha256
            or current["source"] != source
            or current["engine_credential_sha256"] != engine_credential_sha256
        ):
            raise SiteError("placement-group immutable identity changed")
        if desired_state not in {"running", "stopped", "removed"}:
            raise SiteError("placement-group desired state is invalid")
        allowed_states = {
            "staging",
            "staged",
            "starting",
            "running",
            "degraded",
            "stopping",
            "stopped",
            "recovering",
            "removing",
            "removed",
            "failed",
        }
        if state not in allowed_states:
            raise SiteError("placement-group observed state is invalid")
        if action not in {
            "placement_group.stage",
            "placement_group.start",
            "placement_group.stop",
            "placement_group.remove",
            "placement_group.reconcile",
            "placement_group.recover",
        }:
            raise SiteError("placement-group audit action is invalid")
        planned_ids = [item["placement_id"] for item in document["placements"]]
        safe_placements = [dict(item) for item in placements]
        fields = {
            "placement_id",
            "node_id",
            "task_id",
            "state",
            "operation_id",
            "error",
        }
        if (
            len(safe_placements) != len(planned_ids)
            or any(set(item) != fields for item in safe_placements)
            or [item["placement_id"] for item in safe_placements] != planned_ids
        ):
            raise SiteError("placement state does not match its placement group")
        now = int(time.time())
        before = {
            "placement_group": dict(current),
            "placements": [
                dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM placements WHERE placement_group_id=? "
                    "ORDER BY task_id",
                    (placement_group_id,),
                )
            ],
        }

        def update(connection: sqlite3.Connection) -> str:
            connection.execute(
                "UPDATE placement_groups SET desired_state=?,state=?,last_error=?,"
                "updated_at_unix=? WHERE placement_group_id=?",
                (
                    desired_state,
                    state,
                    _bounded_reason(error),
                    now,
                    placement_group_id,
                ),
            )
            for placement in safe_placements:
                connection.execute(
                    "UPDATE placements SET state=?,operation_id=?,error=?,"
                    "updated_at_unix=? WHERE placement_id=? AND placement_group_id=?",
                    (
                        placement["state"],
                        placement["operation_id"],
                        _bounded_reason(placement["error"]),
                        now,
                        placement["placement_id"],
                        placement_group_id,
                    ),
                )
            return placement_group_id

        identifier = self.mutate(
            action=action,
            target=placement_group_id,
            before=before,
            callback=update,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )
        return self.placement_group(identifier)

    def set_placement_group_endpoint(
        self,
        placement_group_id: str,
        endpoint: Mapping[str, Any] | None,
        *,
        state: str,
    ) -> dict[str, Any]:
        if not ID_RE.fullmatch(placement_group_id):
            raise SiteError("placement-group identity is invalid")
        if state not in {
            "staging",
            "staged",
            "starting",
            "running",
            "degraded",
            "stopping",
            "stopped",
            "recovering",
            "removing",
            "removed",
            "failed",
        }:
            raise SiteError("placement-group endpoint state is invalid")
        group = self.placement_group(placement_group_id)
        safe_endpoint = None if endpoint is None else dict(endpoint)
        if safe_endpoint is not None:
            required = {
                "placement_id",
                "node_id",
                "url",
                "credential_file",
                "ca_file",
                "token_count_path",
                "token_count_protocol",
                "max_active_requests",
                "max_context_tokens",
                "healthy",
                "memory_pressure",
                "temperature_c",
                "prefix_keys",
            }
            if set(safe_endpoint) != required:
                raise SiteError("placement-group endpoint has invalid fields")
            endpoint_placement = next(
                (
                    placement
                    for placement in group["placements"]
                    if placement["placement_id"] == safe_endpoint["placement_id"]
                ),
                None,
            )
            if endpoint_placement is None:
                raise SiteError("placement-group endpoint placement is invalid")
            if (
                endpoint_placement["endpoint_owner"] is not True
                or safe_endpoint["node_id"] != endpoint_placement["node_id"]
            ):
                raise SiteError("placement-group endpoint owner is invalid")
            if not isinstance(safe_endpoint["url"], str):
                raise SiteError("placement-group endpoint URL is invalid")
            try:
                parsed_url = urllib.parse.urlsplit(safe_endpoint["url"])
                endpoint_port = parsed_url.port
            except (UnicodeError, ValueError) as error:
                raise SiteError("placement-group endpoint URL is invalid") from error
            if (
                parsed_url.scheme not in {"http", "https"}
                or not parsed_url.hostname
                or parsed_url.username is not None
                or parsed_url.password is not None
                or parsed_url.query
                or parsed_url.fragment
                or parsed_url.path not in {"", "/"}
            ):
                raise SiteError("placement-group endpoint URL is invalid")
            if endpoint_port is None or not 1 <= endpoint_port <= 65535:
                raise SiteError("placement-group endpoint URL port is invalid")
            for field in ("credential_file", "ca_file"):
                value = safe_endpoint[field]
                if value is None and field == "ca_file":
                    continue
                if (
                    not isinstance(value, str)
                    or not value
                    or not pathlib.PurePath(value).is_absolute()
                    or "\x00" in value
                ):
                    raise SiteError(
                        f"placement-group endpoint {field.replace('_', ' ')} is invalid"
                    )
            token_count_path = safe_endpoint["token_count_path"]
            token_count_protocol = safe_endpoint["token_count_protocol"]
            if (token_count_path is None) != (token_count_protocol is None):
                raise SiteError("placement-group endpoint token-count contract is incomplete")
            if token_count_path is not None and (
                not isinstance(token_count_path, str)
                or not token_count_path.startswith("/")
                or "://" in token_count_path
                or "\x00" in token_count_path
                or token_count_protocol not in TOKEN_COUNT_PROTOCOLS
            ):
                raise SiteError("placement-group endpoint token-count contract is invalid")
            for field in ("max_active_requests", "max_context_tokens"):
                value = safe_endpoint[field]
                if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                    raise SiteError(f"placement-group endpoint {field} must be positive")
            if not isinstance(safe_endpoint["healthy"], bool) or not isinstance(
                safe_endpoint["memory_pressure"], bool
            ):
                raise SiteError("placement-group endpoint health is invalid")
            temperature = safe_endpoint["temperature_c"]
            if (
                not isinstance(temperature, (int, float))
                or isinstance(temperature, bool)
                or not math.isfinite(float(temperature))
                or not -1 <= float(temperature) <= 250
            ):
                raise SiteError("placement-group endpoint temperature is invalid")
            prefix_keys = safe_endpoint["prefix_keys"]
            if (
                not isinstance(prefix_keys, list)
                or len(prefix_keys) > MAX_PLACEMENT_PREFIX_KEYS
                or len(prefix_keys) != len(set(prefix_keys))
                or any(
                    not isinstance(prefix, str)
                    or not prefix
                    or len(prefix.encode("utf-8")) > MAX_TAG_BYTES
                    for prefix in prefix_keys
                )
            ):
                raise SiteError("placement-group endpoint prefix keys are invalid")
        if state == "running" and safe_endpoint is None:
            raise SiteError("running placement group requires one endpoint")
        if state == "running" and any(
            placement["state"] != "running" for placement in group["placements"]
        ):
            raise SiteError(
                "running placement group requires every placement to be running"
            )
        now = int(time.time())
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                "UPDATE placement_groups SET state=?,endpoint_json=?,updated_at_unix=? "
                "WHERE placement_group_id=?",
                (
                    state,
                    None if safe_endpoint is None else _safe_json(safe_endpoint),
                    now,
                    placement_group_id,
                ),
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise
        return self.placement_group(placement_group_id)

    def placement_group(self, placement_group_id: str) -> dict[str, Any]:
        if not isinstance(placement_group_id, str) or not ID_RE.fullmatch(
            placement_group_id
        ):
            raise SiteError("placement-group identity is invalid")
        row_value = self.connection.execute(
            "SELECT * FROM placement_groups WHERE placement_group_id=?",
            (placement_group_id,),
        ).fetchone()
        if row_value is None:
            raise SiteError("placement group is not registered")
        row = dict(row_value)
        row["plan"] = json.loads(row.pop("plan_json"))
        row["capacity"] = json.loads(row.pop("capacity_json"))
        endpoint_json = row.pop("endpoint_json")
        row["endpoint"] = (
            None if endpoint_json is None else json.loads(endpoint_json)
        )
        row["placements"] = []
        for placement_value in self.connection.execute(
            "SELECT * FROM placements WHERE placement_group_id=? ORDER BY task_id",
            (placement_group_id,),
        ):
            placement = dict(placement_value)
            placement["device_uuids"] = json.loads(
                placement.pop("device_uuids_json")
            )
            placement["endpoint_owner"] = bool(placement["endpoint_owner"])
            row["placements"].append(placement)
        return row

    def placement_groups(self) -> list[dict[str, Any]]:
        return [
            self.placement_group(str(row["placement_group_id"]))
            for row in self.connection.execute(
                "SELECT placement_group_id FROM placement_groups "
                "ORDER BY created_at_unix,placement_group_id"
            )
        ]

    def placements(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for row_value in self.connection.execute(
            "SELECT * FROM placements ORDER BY placement_group_id,task_id"
        ):
            row = dict(row_value)
            row["device_uuids"] = json.loads(row.pop("device_uuids_json"))
            row["endpoint_owner"] = bool(row["endpoint_owner"])
            result.append(row)
        return result


    def create_topology_plan(
        self,
        model: str,
        *,
        current: Sequence[Mapping[str, Any]],
        proposed: Mapping[str, Any],
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        if not SAFE_NAME_RE.fullmatch(model):
            raise SiteError("topology plan model is invalid")
        proposed_value = dict(proposed)
        proposed_json = _safe_json(proposed_value)
        if len(proposed_json.encode("utf-8")) > 64 * 1024:
            raise SiteError("topology plan is too large")
        current_value = [dict(item) for item in current]
        current_sha256 = _state_hash(current_value) if current_value else None
        proposed_sha256 = _state_hash(proposed_value)
        plan_id = uuid.uuid4().hex
        now = int(time.time())
        previous = [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM topology_plans WHERE model=? AND state='pending' "
                "ORDER BY created_at_unix,plan_id",
                (model,),
            )
        ]
        row = {
            "plan_id": plan_id,
            "model": model,
            "current_sha256": current_sha256,
            "proposed_json": proposed_json,
            "proposed_sha256": proposed_sha256,
            "state": "pending",
            "created_at_unix": now,
            "applied_at_unix": None,
        }

        def insert(connection: sqlite3.Connection) -> dict[str, Any]:
            connection.execute(
                "UPDATE topology_plans SET state='cancelled' "
                "WHERE model=? AND state='pending'",
                (model,),
            )
            connection.execute(
                """INSERT INTO topology_plans
                   (plan_id,model,current_sha256,proposed_json,proposed_sha256,
                    state,created_at_unix,applied_at_unix)
                   VALUES(:plan_id,:model,:current_sha256,:proposed_json,:proposed_sha256,
                          :state,:created_at_unix,:applied_at_unix)""",
                row,
            )
            result = dict(row)
            result["proposed"] = proposed_value
            result.pop("proposed_json")
            return result

        return self.mutate(
            action="topology.plan",
            target=model,
            before=previous,
            callback=insert,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def topology_plans(self, *, include_closed: bool = False) -> list[dict[str, Any]]:
        where = "" if include_closed else " WHERE state='pending'"
        rows = self.connection.execute(
            "SELECT * FROM topology_plans" + where + " ORDER BY created_at_unix,plan_id"
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row_value in rows:
            row = dict(row_value)
            row["proposed"] = json.loads(row.pop("proposed_json"))
            result.append(row)
        return result

    @staticmethod
    def _hash_secret(secret: str, *, salt: bytes | None = None) -> str:
        chosen_salt = salt or secrets.token_bytes(16)
        # API secrets are generated with 256 bits of entropy, so a salted
        # one-way digest is both brute-force safe and cheap enough for every
        # inference request. This is not a human-password KDF.
        digest = hashlib.sha256(chosen_salt + secret.encode("ascii")).digest()
        return (
            "sha256-v1$"
            f"{base64.urlsafe_b64encode(chosen_salt).decode().rstrip('=')}$"
            f"{base64.urlsafe_b64encode(digest).decode().rstrip('=')}"
        )

    @staticmethod
    def verify_secret(secret: str, encoded: str) -> bool:
        try:
            algorithm, salt_text, digest_text = encoded.split("$", 2)
            if algorithm != "sha256-v1":
                return False
            salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
            expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
            actual = hashlib.sha256(salt + secret.encode("ascii")).digest()
            return secrets.compare_digest(actual, expected)
        except (ValueError, TypeError, UnicodeError):
            return False

    @classmethod
    def authenticate_key_from_authority(
        cls,
        token: str,
        *,
        identity: SiteIdentity,
        path: pathlib.Path | None = None,
    ) -> dict[str, Any] | None:
        """Read one key directly from the current coordinator authority.

        Gateway authentication deliberately bypasses its reloadable routing
        snapshot. This keeps revocation and policy changes effective on the
        first request after the SQLite transaction commits without rebuilding
        topology for every request.
        """
        if identity.role != "main":
            raise SiteError(
                "the authoritative node database is main-node-only; "
                f"coordinator={identity.coordinator_id}@{identity.coordinator_address}"
            )
        match = re.fullmatch(r"li_([0-9a-f]{16})_([A-Za-z0-9_-]{32,})", token)
        if match is None:
            return None
        database = path or database_path()
        if database.is_symlink():
            raise SiteError("site database cannot be a symlink")
        try:
            details = database.stat()
        except OSError as error:
            raise SiteError("site database is unavailable") from error
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) & 0o077
        ):
            raise SiteError("site database must be a private user-owned file")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                database.resolve().as_uri() + "?mode=ro",
                uri=True,
                isolation_level=None,
                timeout=5.0,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            row = connection.execute(
                "SELECT * FROM api_keys WHERE key_id=?", (match.group(1),)
            ).fetchone()
        except sqlite3.Error as error:
            raise SiteError("site key authority is unavailable") from error
        finally:
            if connection is not None:
                connection.close()
        if row is None or row["revoked_at_unix"] is not None:
            return None
        if row["expires_at_unix"] is not None and row["expires_at_unix"] <= int(time.time()):
            return None
        if not cls.verify_secret(match.group(2), row["secret_hash"]):
            return None
        result = dict(row)
        result.pop("secret_hash")
        result["models"] = json.loads(result.pop("models_json"))
        return result

    def create_key(
        self,
        name: str,
        *,
        models: Sequence[str] = (),
        expires_at_unix: int | None = None,
        requests_per_minute: int | None = None,
        tokens_per_minute: int | None = None,
        concurrency_limit: int | None = None,
        context_limit: int | None = None,
        tenant: str | None = None,
        application: str | None = None,
        rotated_from: str | None = None,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        if not SAFE_NAME_RE.fullmatch(name):
            raise SiteError("API key name must be a lowercase safe name")
        for label, value in (
            ("requests_per_minute", requests_per_minute), ("tokens_per_minute", tokens_per_minute),
            ("concurrency_limit", concurrency_limit), ("context_limit", context_limit),
        ):
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value <= 0):
                raise SiteError(f"{label} must be positive")
        if expires_at_unix is not None and (
            not isinstance(expires_at_unix, int) or isinstance(expires_at_unix, bool)
        ):
            raise SiteError("expires_at_unix must be an integer")
        for label, value in (("tenant", tenant), ("application", application)):
            if value is not None and (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > MAX_TAG_BYTES
            ):
                raise SiteError(f"{label} is invalid")
        if isinstance(models, (str, bytes)) or any(
            not isinstance(model, str) for model in models
        ):
            raise SiteError("API key model scope must be a sequence of model names")
        normalized_models = sorted(set(models))
        if any(not SAFE_NAME_RE.fullmatch(model) for model in normalized_models):
            raise SiteError("API key model scope contains an invalid model")
        key_id = secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)
        token = f"li_{key_id}_{secret}"
        now = int(time.time())
        row = {
            "key_id": key_id, "name": name, "secret_hash": self._hash_secret(secret),
            "models_json": _safe_json(normalized_models), "expires_at_unix": expires_at_unix,
            "revoked_at_unix": None, "requests_per_minute": requests_per_minute,
            "tokens_per_minute": tokens_per_minute, "concurrency_limit": concurrency_limit,
            "context_limit": context_limit, "tenant": tenant, "application": application,
            "created_at_unix": now, "rotated_from": rotated_from,
        }

        def insert(connection: sqlite3.Connection) -> dict[str, Any]:
            connection.execute(
                """INSERT INTO api_keys
                   (key_id,name,secret_hash,models_json,expires_at_unix,revoked_at_unix,
                    requests_per_minute,tokens_per_minute,concurrency_limit,context_limit,
                    tenant,application,created_at_unix,rotated_from)
                   VALUES(:key_id,:name,:secret_hash,:models_json,:expires_at_unix,:revoked_at_unix,
                          :requests_per_minute,:tokens_per_minute,:concurrency_limit,:context_limit,
                          :tenant,:application,:created_at_unix,:rotated_from)""",
                row,
            )
            public = {
                key: value
                for key, value in row.items()
                if key not in {"secret_hash", "models_json"}
            }
            public["models"] = normalized_models
            return public

        public = self.mutate(
            action="key.create", target=key_id, before={}, callback=insert,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )
        return public, token

    def keys(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT key_id,name,models_json,expires_at_unix,revoked_at_unix,
                      requests_per_minute,tokens_per_minute,concurrency_limit,context_limit,
                      tenant,application,created_at_unix,rotated_from
               FROM api_keys ORDER BY created_at_unix,key_id"""
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["models"] = json.loads(item.pop("models_json"))
            result.append(item)
        return result

    def key(self, key_id_or_name: str) -> dict[str, Any]:
        row = self.connection.execute(
            """SELECT key_id,name,models_json,expires_at_unix,revoked_at_unix,
                      requests_per_minute,tokens_per_minute,concurrency_limit,context_limit,
                      tenant,application,created_at_unix,rotated_from
               FROM api_keys WHERE key_id=? OR name=?""",
            (key_id_or_name, key_id_or_name),
        ).fetchone()
        if row is None:
            raise SiteError(f"API key is not registered: {key_id_or_name}")
        result = dict(row)
        result["models"] = json.loads(result.pop("models_json"))
        return result

    def revoke_key(
        self,
        key_id_or_name: str,
        *,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        current = self.key(key_id_or_name)
        if current["revoked_at_unix"] is not None:
            raise SiteError("API key is already revoked")

        def revoke(connection: sqlite3.Connection) -> dict[str, Any]:
            now = int(time.time())
            changed = connection.execute(
                "UPDATE api_keys SET revoked_at_unix=? WHERE key_id=? AND revoked_at_unix IS NULL",
                (now, current["key_id"]),
            ).rowcount
            if changed != 1:
                raise SiteError("API key changed concurrently")
            return self.key(current["key_id"])

        return self.mutate(
            action="key.revoke", target=current["key_id"], before=current,
            callback=revoke, after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def rotate_key(
        self,
        key_id_or_name: str,
        *,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        current = self.key(key_id_or_name)
        if current["revoked_at_unix"] is not None:
            raise SiteError("revoked API key cannot be rotated")
        key_id = secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)
        token = f"li_{key_id}_{secret}"
        now = int(time.time())
        archived_name = f"{current['name']}-revoked-{current['key_id']}"
        row = {
            "key_id": key_id,
            "name": current["name"],
            "secret_hash": self._hash_secret(secret),
            "models_json": _safe_json(current["models"]),
            "expires_at_unix": current["expires_at_unix"],
            "revoked_at_unix": None,
            "requests_per_minute": current["requests_per_minute"],
            "tokens_per_minute": current["tokens_per_minute"],
            "concurrency_limit": current["concurrency_limit"],
            "context_limit": current["context_limit"],
            "tenant": current["tenant"],
            "application": current["application"],
            "created_at_unix": now,
            "rotated_from": current["key_id"],
        }

        def rotate(connection: sqlite3.Connection) -> dict[str, Any]:
            changed = connection.execute(
                """UPDATE api_keys SET name=?,revoked_at_unix=?
                   WHERE key_id=? AND revoked_at_unix IS NULL""",
                (archived_name, now, current["key_id"]),
            ).rowcount
            if changed != 1:
                raise SiteError("API key changed concurrently")
            connection.execute(
                """INSERT INTO api_keys
                   (key_id,name,secret_hash,models_json,expires_at_unix,revoked_at_unix,
                    requests_per_minute,tokens_per_minute,concurrency_limit,context_limit,
                    tenant,application,created_at_unix,rotated_from)
                   VALUES(:key_id,:name,:secret_hash,:models_json,:expires_at_unix,:revoked_at_unix,
                          :requests_per_minute,:tokens_per_minute,:concurrency_limit,:context_limit,
                          :tenant,:application,:created_at_unix,:rotated_from)""",
                row,
            )
            return self.key(key_id)

        created = self.mutate(
            action="key.rotate",
            target=current["key_id"],
            before=current,
            callback=rotate,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )
        return created, token

    def update_key_policy(
        self,
        key_id_or_name: str,
        *,
        models: Sequence[str] | None = None,
        expires_at_unix: int | None = None,
        requests_per_minute: int | None = None,
        tokens_per_minute: int | None = None,
        concurrency_limit: int | None = None,
        context_limit: int | None = None,
        tenant: str | None = None,
        application: str | None = None,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        current = self.key(key_id_or_name)
        if models is not None and (
            isinstance(models, (str, bytes))
            or any(not isinstance(model, str) for model in models)
        ):
            raise SiteError("API key model scope must be a sequence of model names")
        normalized_models = current["models"] if models is None else sorted(set(models))
        if any(not SAFE_NAME_RE.fullmatch(model) for model in normalized_models):
            raise SiteError("API key model scope contains an invalid model")
        values = {
            "models_json": _safe_json(normalized_models),
            "expires_at_unix": expires_at_unix,
            "requests_per_minute": requests_per_minute,
            "tokens_per_minute": tokens_per_minute,
            "concurrency_limit": concurrency_limit,
            "context_limit": context_limit,
            "tenant": tenant,
            "application": application,
            "key_id": current["key_id"],
        }
        for label in ("requests_per_minute", "tokens_per_minute", "concurrency_limit", "context_limit"):
            value = values[label]
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value <= 0):
                raise SiteError(f"{label} must be positive")
        if expires_at_unix is not None and (
            not isinstance(expires_at_unix, int) or isinstance(expires_at_unix, bool)
        ):
            raise SiteError("expires_at_unix must be an integer")
        for label in ("tenant", "application"):
            value = values[label]
            if value is not None and (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > MAX_TAG_BYTES
            ):
                raise SiteError(f"{label} is invalid")

        def update(connection: sqlite3.Connection) -> dict[str, Any]:
            connection.execute(
                """UPDATE api_keys SET models_json=:models_json,expires_at_unix=:expires_at_unix,
                   requests_per_minute=:requests_per_minute,tokens_per_minute=:tokens_per_minute,
                   concurrency_limit=:concurrency_limit,context_limit=:context_limit,
                   tenant=:tenant,application=:application WHERE key_id=:key_id""",
                values,
            )
            return self.key(current["key_id"])

        return self.mutate(
            action="key.policy", target=current["key_id"], before=current,
            callback=update, after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )

    def authenticate_key(self, token: str) -> dict[str, Any] | None:
        match = re.fullmatch(r"li_([0-9a-f]{16})_([A-Za-z0-9_-]{32,})", token)
        if match is None:
            return None
        row = self.connection.execute("SELECT * FROM api_keys WHERE key_id=?", (match.group(1),)).fetchone()
        if row is None or row["revoked_at_unix"] is not None:
            return None
        if row["expires_at_unix"] is not None and row["expires_at_unix"] <= int(time.time()):
            return None
        if not self.verify_secret(match.group(2), row["secret_hash"]):
            return None
        result = dict(row)
        result.pop("secret_hash")
        result["models"] = json.loads(result.pop("models_json"))
        return result

    def exposure(self) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM exposure WHERE singleton=1"
        ).fetchone()
        return None if row is None else dict(row)

    def set_exposure(
        self,
        *,
        provider: str,
        public_url: str,
        state: str,
        inference_target: str,
        configuration_sha256: str,
        actor_type: str = "local-user",
        actor_id: str | None = None,
        origin_interface: str = "cli",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        if provider != "tailscale-funnel":
            raise SiteError("exposure provider is invalid")
        if state not in {"disabled", "enabled", "failed"}:
            raise SiteError("exposure state is invalid")
        if (
            not isinstance(public_url, str)
            or (state == "enabled" and not public_url.startswith("https://"))
            or not isinstance(inference_target, str)
            or not inference_target
            or not SHA256_RE.fullmatch(configuration_sha256)
        ):
            raise SiteError("exposure identity is invalid")
        before = self.exposure()
        value = {
            "singleton": 1,
            "provider": provider,
            "public_url": public_url,
            "state": state,
            "inference_target": inference_target,
            "configuration_sha256": configuration_sha256,
            "updated_at_unix": int(time.time()),
        }

        def update(connection: sqlite3.Connection) -> dict[str, Any]:
            connection.execute(
                """INSERT INTO exposure
                   (singleton,provider,public_url,state,inference_target,
                    configuration_sha256,updated_at_unix)
                   VALUES(:singleton,:provider,:public_url,:state,:inference_target,
                          :configuration_sha256,:updated_at_unix)
                   ON CONFLICT(singleton) DO UPDATE SET
                    provider=excluded.provider,public_url=excluded.public_url,
                    state=excluded.state,inference_target=excluded.inference_target,
                    configuration_sha256=excluded.configuration_sha256,
                    updated_at_unix=excluded.updated_at_unix""",
                value,
            )
            return value

        return self.mutate(
            action={
                "enabled": "exposure.enable",
                "disabled": "exposure.disable",
                "failed": "exposure.fail",
            }[state],
            target=provider,
            before=before,
            callback=update,
            after=lambda _connection, result: result,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )


def identity_json(identity: SiteIdentity) -> dict[str, Any]:
    """Return the public node vocabulary without leaking legacy field names."""
    return {
        "node_id": identity.site_id,
        "machine_id": identity.member_id,
        "installation_id": identity.installation_id,
        "display_name": identity.display_name,
        "role": identity.role,
        "main_id": identity.coordinator_id,
        "main_address": identity.coordinator_address,
        "node_public_key_sha256": identity.site_public_key_sha256,
        "machine_public_key_sha256": identity.member_public_key_sha256,
        "created_at_unix": identity.created_at_unix,
    }


def sign_site_document(document: Mapping[str, Any]) -> str:
    identity = read_identity()
    if identity.role != "main":
        raise SiteError("only the main node can sign node documents")
    signature = _run(
        ["openssl", "dgst", "-sha256", "-sign", str(site_key_path())],
        input_bytes=_canonical_bytes(document),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_site_document(
    document: Mapping[str, Any], signature_base64: str, public_key: pathlib.Path | None = None
) -> None:
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except ValueError as error:
        raise SiteError("site document signature is invalid") from error
    with tempfile.NamedTemporaryFile() as temporary:
        temporary.write(signature)
        temporary.flush()
        _run(
            [
                "openssl", "dgst", "-sha256", "-verify",
                str(public_key or site_public_key_path()), "-signature", temporary.name,
            ],
            input_bytes=_canonical_bytes(document),
        )


def prepare_member_identity() -> dict[str, Any]:
    if identity_path().exists():
        raise SiteError("this machine already belongs to a Let's Infer site")
    fingerprint = _generate_identity_key(member_key_path(), member_public_key_path())
    member_id_path = config_root() / "member-id"
    if member_id_path.exists():
        member_id = _private_file(member_id_path, minimum_bytes=32).decode("ascii").strip()
        if not ID_RE.fullmatch(member_id):
            raise SiteError("pending member identity is invalid")
    else:
        member_id = uuid.uuid4().hex
        _atomic_private(member_id_path, (member_id + "\n").encode("ascii"))
    public_pem = _private_file(member_public_key_path(), minimum_bytes=128).decode("ascii")
    installation = _prepare_installation_identity()
    return {
        "schema_version": 1,
        "member_id": member_id,
        "member_public_key": public_pem,
        "member_public_key_sha256": fingerprint,
        **installation,
    }


def existing_member_identity(identity: SiteIdentity | None = None) -> dict[str, Any]:
    """Return the configured physical-machine identity for an explicit node move.

    This exposes only the public enrollment material.  It deliberately does not
    make a configured coordinator look like an unconfigured join candidate to
    ordinary enrollment callers.
    """
    current = identity or read_identity()
    if read_identity() != current:
        raise SiteError("configured member identity changed")
    fingerprint = _public_key_fingerprint(member_public_key_path())
    if fingerprint != current.member_public_key_sha256:
        raise SiteError("configured member public key fingerprint changed")
    public_pem = _private_file(
        member_public_key_path(), minimum_bytes=128
    ).decode("ascii")
    return {
        "schema_version": 1,
        "member_id": current.member_id,
        "member_public_key": public_pem,
        "member_public_key_sha256": fingerprint,
        "installation_id": current.installation_id,
        "created_at_unix": current.created_at_unix,
    }


def member_proof(transcript: Mapping[str, Any]) -> str:
    if identity_path().exists():
        read_identity()
    else:
        prepare_member_identity()
    signature = _run(
        ["openssl", "dgst", "-sha256", "-sign", str(member_key_path())],
        input_bytes=_canonical_bytes(transcript),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_member_proof(
    public_key_pem: str, transcript: Mapping[str, Any], signature_base64: str
) -> str:
    if not isinstance(public_key_pem, str) or len(public_key_pem.encode("ascii", errors="ignore")) > 4096:
        raise SiteError("member public key is invalid")
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except ValueError as error:
        raise SiteError("member proof is invalid") from error
    with tempfile.TemporaryDirectory(prefix="letsinfer-child-proof-") as temporary:
        public = pathlib.Path(temporary) / "member.pub"
        signature_path = pathlib.Path(temporary) / "proof.sig"
        public.write_text(public_key_pem, encoding="ascii")
        signature_path.write_bytes(signature)
        der = _run(["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"])
        _run(
            ["openssl", "dgst", "-sha256", "-verify", str(public), "-signature", str(signature_path)],
            input_bytes=_canonical_bytes(transcript),
        )
    return hashlib.sha256(der).hexdigest()


def member_public_key_fingerprint(public_key_pem: str) -> str:
    if not isinstance(public_key_pem, str) or len(public_key_pem.encode("ascii", errors="ignore")) > 4096:
        raise SiteError("member public key is invalid")
    with tempfile.TemporaryDirectory(prefix="letsinfer-child-key-") as temporary:
        public = pathlib.Path(temporary) / "member.pub"
        public.write_text(public_key_pem, encoding="ascii")
        der = _run(["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()


def install_member_identity(
    membership: Mapping[str, Any],
    signature_base64: str,
    site_public_key_pem: str,
    site_ca_certificate_pem: str,
    member_certificate_pem: str,
) -> SiteIdentity:
    if identity_path().exists():
        raise SiteError("this machine already belongs to a Let's Infer site")
    required = {
        "schema_version", "site_id", "member_id", "installation_id",
        "installation_created_at_unix", "display_name",
        "coordinator_id", "coordinator_address", "site_public_key_sha256",
        "member_public_key_sha256", "member_certificate_sha256", "state",
        "approval_expires_at_unix", "issued_at_unix",
    }
    if (
        not isinstance(membership, Mapping)
        or set(membership) != required
        or type(membership.get("schema_version")) is not int
        or membership.get("schema_version") != 1
    ):
        raise SiteError("membership document schema is invalid")
    candidate = prepare_member_identity()
    if membership["member_id"] != candidate["member_id"] or membership["member_public_key_sha256"] != candidate["member_public_key_sha256"]:
        raise SiteError("membership document belongs to a different member identity")
    if membership["state"] not in {"pending", "active"}:
        raise SiteError("membership document state is invalid")
    if (
        membership["installation_id"] != candidate["installation_id"]
        or membership["installation_created_at_unix"]
        != candidate["created_at_unix"]
    ):
        raise SiteError("membership document installation identity mismatch")
    if membership["state"] == "pending":
        if not isinstance(membership["approval_expires_at_unix"], int) or isinstance(
            membership["approval_expires_at_unix"], bool
        ):
            raise SiteError("pending membership approval expiry is invalid")
    elif membership["approval_expires_at_unix"] is not None:
        raise SiteError("active membership cannot have an approval expiry")
    try:
        site_public_bytes = site_public_key_pem.encode("ascii")
        site_ca_bytes = site_ca_certificate_pem.encode("ascii")
        member_certificate_bytes = member_certificate_pem.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as error:
        raise SiteError("membership credentials are invalid") from error
    with tempfile.TemporaryDirectory(prefix="letsinfer-child-") as temporary:
        root = pathlib.Path(temporary)
        site_public = root / "site.pub"
        site_ca = root / "site-ca.crt"
        member_certificate = root / "member.crt"
        for path, payload in (
            (site_public, site_public_bytes),
            (site_ca, site_ca_bytes),
            (member_certificate, member_certificate_bytes),
        ):
            path.write_bytes(payload)
            path.chmod(0o600)
        if _public_key_fingerprint(site_public) != membership["site_public_key_sha256"]:
            raise SiteError("membership site key fingerprint mismatch")
        verify_site_document(membership, signature_base64, site_public)
        _validate_site_ca(site_ca, site_public)
        certificate_fingerprint = _validate_member_certificate(
            member_certificate,
            member_public_key_path(),
            site_ca,
            str(membership["member_id"]),
        )
        if certificate_fingerprint != membership["member_certificate_sha256"]:
            raise SiteError("membership certificate fingerprint mismatch")
    value = {
        "schema_version": SCHEMA_VERSION,
        "site_id": membership["site_id"],
        "member_id": membership["member_id"],
        "installation_id": membership["installation_id"],
        "display_name": membership["display_name"],
        "role": "child",
        "coordinator_id": membership["coordinator_id"],
        "coordinator_address": membership["coordinator_address"],
        "site_public_key_sha256": membership["site_public_key_sha256"],
        "member_public_key_sha256": membership["member_public_key_sha256"],
        "created_at_unix": membership["installation_created_at_unix"],
    }
    _atomic_private(site_public_key_path(), site_public_bytes)
    _atomic_private(site_ca_certificate_path(), site_ca_bytes)
    _atomic_private(member_certificate_path(), member_certificate_bytes)
    _atomic_private(identity_path(), _canonical_bytes(value))
    _atomic_private(
        config_root() / "membership.json",
        _canonical_bytes({"document": dict(membership), "signature": signature_base64}),
    )
    pending = config_root() / "member-id"
    if pending.exists():
        pending.unlink()
    pending_installation_path().unlink(missing_ok=True)
    return read_identity()
