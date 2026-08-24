#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded TLS enrollment and authenticated child-control transport."""

from __future__ import annotations

import hashlib
import http.client
import http.server
import json
import pathlib
import re
import socket
import ssl
import tempfile
import threading
import urllib.parse
import dataclasses
import collections
import time
import secrets
from collections.abc import Callable, Mapping
from typing import Any

from core.orchestration.member import MemberAgent, MemberJobError
from core.orchestration.member import PROTOCOL as GROUP_JOB_PROTOCOL

from .state import (
    SiteError,
    SiteIdentity,
    SiteStore,
    install_member_identity,
    member_certificate_path,
    member_key_path,
    member_proof,
    prepare_member_identity,
    site_ca_certificate_path,
)
from .inventory import (
    InventoryError,
    select_direct_connectx_interface,
    verify_direct_connectx_peer,
    verify_direct_peer_interface,
)
from .links import LinkError, LinkStore, link_from_proof, validate_link
from .topology import validate_member_facts
from .telemetry import PROTOCOL as TELEMETRY_PROTOCOL
from .telemetry import TelemetryAggregator, TelemetryError, validate_sample


PROTOCOL = "letsinfer-node-control-v1"
LINK_PROTOCOL = "letsinfer-node-link-v1"
DEFAULT_PORT = 9770
MAX_BODY_BYTES = 16 * 1024
REQUEST_TIMEOUT_SECONDS = 15
ENROLLMENT_RATE_LIMIT = 12
ENROLLMENT_RATE_WINDOW_SECONDS = 60
MAX_RATE_LIMIT_PEERS = 256
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ControlError(RuntimeError):
    """Enrollment or private site-control traffic failed closed."""


class RateLimitError(ControlError):
    """Unauthenticated enrollment traffic exceeded its bounded allowance."""


@dataclasses.dataclass(frozen=True)
class EnrollmentResult:
    identity: SiteIdentity
    state: str
    comparison_code: str | None
    approval_expires_at_unix: int | None


@dataclasses.dataclass(frozen=True)
class EnrollmentPackage:
    """Validated coordinator response, not yet installed on the candidate."""

    document: dict[str, Any]
    signature: str
    site_public_key: str
    site_ca_certificate: str
    member_certificate: str
    comparison_code: str | None

    @property
    def state(self) -> str:
        return str(self.document["state"])

    @property
    def approval_expires_at_unix(self) -> int | None:
        value = self.document["approval_expires_at_unix"]
        return value if isinstance(value, int) and not isinstance(value, bool) else None


class PeerRateLimiter:
    """Small, bounded per-peer window for unauthenticated enrollment traffic."""

    def __init__(
        self,
        *,
        limit: int = ENROLLMENT_RATE_LIMIT,
        window_seconds: float = ENROLLMENT_RATE_WINDOW_SECONDS,
        max_peers: int = MAX_RATE_LIMIT_PEERS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_peers = max_peers
        self.clock = clock
        self.requests: dict[str, collections.deque[float]] = {}
        self.lock = threading.Lock()

    def allow(self, peer: str) -> bool:
        now = self.clock()
        cutoff = now - self.window_seconds
        with self.lock:
            for key in list(self.requests):
                values = self.requests[key]
                while values and values[0] <= cutoff:
                    values.popleft()
                if not values:
                    self.requests.pop(key, None)
            if peer not in self.requests and len(self.requests) >= self.max_peers:
                oldest = min(self.requests, key=lambda key: self.requests[key][-1])
                self.requests.pop(oldest, None)
            values = self.requests.setdefault(peer, collections.deque())
            if len(values) >= self.limit:
                return False
            values.append(now)
            return True


def certificate_sha256_der(certificate_der: bytes) -> str:
    if not isinstance(certificate_der, bytes) or not certificate_der:
        raise ControlError("peer certificate is unavailable")
    return hashlib.sha256(certificate_der).hexdigest()


def _member_id_from_certificate(certificate: Mapping[str, Any]) -> str:
    values = certificate.get("subjectAltName", ())
    identities = [
        value.removeprefix("urn:letsinfer:member:")
        for kind, value in values
        if kind == "URI" and value.startswith("urn:letsinfer:member:")
    ]
    if len(identities) != 1 or not ID_RE.fullmatch(identities[0]):
        raise ControlError("peer member certificate identity is invalid")
    return identities[0]


def enrollment_transcript(
    challenge: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    member_name: str,
    member_address: str,
) -> dict[str, Any]:
    required = {
        "protocol", "site_id", "invite_id", "nonce", "mode", "expires_at_unix",
        "coordinator_id", "coordinator_address", "site_public_key_sha256",
        "coordinator_certificate_sha256",
    }
    if not isinstance(challenge, Mapping) or set(challenge) != required:
        raise ControlError("membership challenge schema is invalid")
    if challenge.get("protocol") != PROTOCOL:
        raise ControlError("membership challenge protocol is invalid")
    for key in ("site_id", "invite_id", "coordinator_id"):
        if not isinstance(challenge.get(key), str) or not ID_RE.fullmatch(str(challenge[key])):
            raise ControlError(f"membership challenge {key} is invalid")
    if not isinstance(challenge.get("nonce"), str) or not SHA256_RE.fullmatch(str(challenge["nonce"])):
        raise ControlError("membership challenge nonce is invalid")
    for key in ("site_public_key_sha256", "coordinator_certificate_sha256"):
        if not isinstance(challenge.get(key), str) or not SHA256_RE.fullmatch(str(challenge[key])):
            raise ControlError(f"membership challenge {key} is invalid")
    if challenge.get("mode") not in {"lan", "remote", "connectx"}:
        raise ControlError("membership challenge mode is invalid")
    if not isinstance(challenge.get("expires_at_unix"), int) or isinstance(
        challenge.get("expires_at_unix"), bool
    ):
        raise ControlError("membership challenge expiry is invalid")
    if not isinstance(challenge.get("coordinator_address"), str) or not challenge["coordinator_address"]:
        raise ControlError("membership coordinator address is invalid")
    if set(candidate) != {
        "schema_version", "member_id", "member_public_key", "member_public_key_sha256",
        "installation_id", "created_at_unix",
    } or type(candidate.get("schema_version")) is not int or candidate.get("schema_version") != 1:
        raise ControlError("pending member identity is invalid")
    return {
        "contract": "letsinfer-child-enrollment-v1",
        "site_id": challenge["site_id"],
        "invite_id": challenge["invite_id"],
        "nonce": challenge["nonce"],
        "member_id": candidate["member_id"],
        "member_name": member_name,
        "member_address": member_address,
        "member_public_key_sha256": candidate["member_public_key_sha256"],
        "installation_id": candidate["installation_id"],
        "installation_created_at_unix": candidate["created_at_unix"],
    }


class PinnedHTTPS:
    def __init__(self, host: str, port: int, certificate_sha256: str) -> None:
        if not SHA256_RE.fullmatch(certificate_sha256):
            raise ControlError("coordinator certificate fingerprint is invalid")
        self.host = host
        self.port = port
        self.certificate_sha256 = certificate_sha256

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(
            self.host, self.port, context=context, timeout=REQUEST_TIMEOUT_SECONDS
        )
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        try:
            connection.connect()
            if connection.sock is None:
                raise ControlError("coordinator TLS connection is unavailable")
            observed = certificate_sha256_der(connection.sock.getpeercert(binary_form=True))
            if observed != self.certificate_sha256:
                raise ControlError("coordinator TLS certificate fingerprint changed")
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_BODY_BYTES + 1)
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            raise ControlError(f"membership connection failed: {error}") from error
        finally:
            connection.close()
        if len(raw) > MAX_BODY_BYTES:
            raise ControlError("membership response is too large")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ControlError("membership response is not valid JSON") from error
        if not isinstance(value, dict):
            raise ControlError("membership response is invalid")
        if response.status != 200:
            raise ControlError(str(value.get("error", "membership request was rejected")))
        return value


def request_membership(
    endpoint: str,
    *,
    invite_id: str,
    code: str | None,
    coordinator_certificate_sha256: str,
    member_name: str,
    member_address: str,
    candidate: Mapping[str, Any] | None = None,
) -> EnrollmentPackage:
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise ControlError("membership endpoint must be an HTTPS origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ControlError("membership endpoint contains unsupported components")
    port = parsed.port or DEFAULT_PORT
    if not ID_RE.fullmatch(invite_id):
        raise ControlError("membership invite identity is invalid")
    client = PinnedHTTPS(parsed.hostname, port, coordinator_certificate_sha256)
    challenge = client.request("GET", f"/node/v1/enroll/{invite_id}")
    if challenge.get("coordinator_certificate_sha256") != coordinator_certificate_sha256:
        raise ControlError("membership challenge does not match the pinned coordinator")
    if challenge.get("mode") != "connectx" and code is None:
        raise ControlError("code-based membership requires the setup code")
    if challenge.get("mode") == "connectx" and code is not None:
        raise ControlError("ConnectX membership does not use a setup code")
    candidate_document = dict(candidate) if candidate is not None else prepare_member_identity()
    transcript = enrollment_transcript(
        challenge,
        candidate_document,
        member_name=member_name,
        member_address=member_address,
    )
    proof = member_proof(transcript)
    response = client.request(
        "POST",
        "/node/v1/enroll",
        {
            "protocol": PROTOCOL,
            "invite_id": invite_id,
            "code": code,
            "member_id": candidate_document["member_id"],
            "member_name": member_name,
            "member_address": member_address,
            "member_public_key": candidate_document["member_public_key"],
            "installation_id": candidate_document["installation_id"],
            "installation_created_at_unix": candidate_document["created_at_unix"],
            "proof_signature": proof,
        },
    )
    required = {
        "protocol", "document", "signature", "site_public_key", "site_ca_certificate",
        "member_certificate", "comparison_code",
    }
    if set(response) != required or response.get("protocol") != PROTOCOL:
        raise ControlError("membership enrollment response schema is invalid")
    document = response["document"]
    if not isinstance(document, dict):
        raise ControlError("membership document schema is invalid")
    comparison_code = response["comparison_code"]
    if document["state"] == "pending":
        if not isinstance(comparison_code, str) or re.fullmatch(r"[0-9]{6}", comparison_code) is None:
            raise ControlError("pending membership comparison code is invalid")
    elif comparison_code is not None:
        raise ControlError("active membership cannot require comparison approval")
    for field in (
        "signature", "site_public_key", "site_ca_certificate", "member_certificate"
    ):
        if not isinstance(response[field], str) or not response[field]:
            raise ControlError("membership credential response is invalid")
    return EnrollmentPackage(
        document=dict(document),
        signature=response["signature"],
        site_public_key=response["site_public_key"],
        site_ca_certificate=response["site_ca_certificate"],
        member_certificate=response["member_certificate"],
        comparison_code=comparison_code,
    )


def install_membership(package: EnrollmentPackage) -> EnrollmentResult:
    try:
        identity = install_member_identity(
            package.document,
            package.signature,
            package.site_public_key,
            package.site_ca_certificate,
            package.member_certificate,
        )
    except SiteError as error:
        raise ControlError(str(error)) from error
    return EnrollmentResult(
        identity=identity,
        state=package.state,
        comparison_code=package.comparison_code,
        approval_expires_at_unix=package.approval_expires_at_unix,
    )


def join_site(
    endpoint: str,
    *,
    invite_id: str,
    code: str | None,
    coordinator_certificate_sha256: str,
    member_name: str,
    member_address: str,
) -> EnrollmentResult:
    package = request_membership(
        endpoint,
        invite_id=invite_id,
        code=code,
        coordinator_certificate_sha256=coordinator_certificate_sha256,
        member_name=member_name,
        member_address=member_address,
    )
    return install_membership(package)


def fetch_candidate_membership(
    endpoint: str,
    *,
    package: EnrollmentPackage,
    coordinator_certificate_sha256: str,
) -> dict[str, Any]:
    """Verify a prepared candidate is active before replacing its source site."""
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise ControlError("membership endpoint must be an HTTPS origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ControlError("membership endpoint contains unsupported components")
    if not SHA256_RE.fullmatch(coordinator_certificate_sha256):
        raise ControlError("coordinator certificate fingerprint is invalid")
    with tempfile.TemporaryDirectory(prefix="letsinfer-child-status-") as temporary:
        root = pathlib.Path(temporary)
        ca = root / "site-ca.crt"
        certificate = root / "member.crt"
        ca.write_text(package.site_ca_certificate, encoding="ascii")
        certificate.write_text(package.member_certificate, encoding="ascii")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            context.load_verify_locations(ca)
            context.load_cert_chain(certificate, member_key_path())
        except (OSError, ssl.SSLError) as error:
            raise ControlError("prepared membership credentials are invalid") from error
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or DEFAULT_PORT,
            context=context,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        try:
            connection.connect()
            if connection.sock is None:
                raise ControlError("coordinator TLS connection is unavailable")
            observed = certificate_sha256_der(
                connection.sock.getpeercert(binary_form=True)
            )
            if observed != coordinator_certificate_sha256:
                raise ControlError("coordinator TLS certificate fingerprint changed")
            connection.request(
                "GET", "/node/v1/membership", headers={"Accept": "application/json"}
            )
            response = connection.getresponse()
            raw = response.read(MAX_BODY_BYTES + 1)
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            raise ControlError(f"membership status connection failed: {error}") from error
        finally:
            connection.close()
    if len(raw) > MAX_BODY_BYTES:
        raise ControlError("membership status response is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError("membership status response is not valid JSON") from error
    expected = {
        "protocol",
        "site_id",
        "member_id",
        "state",
        "approval_expires_at_unix",
    }
    if (
        response.status != 200
        or not isinstance(value, dict)
        or set(value) != expected
        or value.get("protocol") != PROTOCOL
        or value.get("site_id") != package.document.get("site_id")
        or value.get("member_id") != package.document.get("member_id")
        or value.get("state") not in {"pending", "active"}
    ):
        raise ControlError("membership status response is invalid")
    return value


def fetch_member_facts(
    endpoint: str,
    *,
    expected_member_id: str,
    expected_certificate_sha256: str,
) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise ControlError("child control endpoint must be an HTTPS origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ControlError("child control endpoint contains unsupported components")
    if not ID_RE.fullmatch(expected_member_id) or not SHA256_RE.fullmatch(
        expected_certificate_sha256
    ):
        raise ControlError("expected member identity is invalid")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(site_ca_certificate_path())
    context.load_cert_chain(member_certificate_path(), member_key_path())
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or DEFAULT_PORT,
        context=context,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    try:
        connection.connect()
        if connection.sock is None:
            raise ControlError("member TLS connection is unavailable")
        observed = certificate_sha256_der(connection.sock.getpeercert(binary_form=True))
        if observed != expected_certificate_sha256:
            raise ControlError("member TLS certificate fingerprint changed")
        peer = connection.sock.getpeercert()
        if _member_id_from_certificate(peer) != expected_member_id:
            raise ControlError("member TLS identity does not match the enrolled member")
        connection.request("GET", "/node/v1/facts", headers={"Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read(MAX_BODY_BYTES + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise ControlError(f"child control connection failed: {error}") from error
    finally:
        connection.close()
    if len(raw) > MAX_BODY_BYTES:
        raise ControlError("member facts response is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError("member facts response is not valid JSON") from error
    if response.status != 200 or not isinstance(value, dict):
        detail = value.get("error") if isinstance(value, dict) else None
        raise ControlError(str(detail or "member facts request was rejected"))
    if set(value) != {"protocol", "facts", "signature"} or value.get("protocol") != PROTOCOL:
        raise ControlError("member facts response schema is invalid")
    try:
        facts = validate_member_facts(value["facts"])
    except ValueError as error:
        raise ControlError(str(error)) from error
    if facts["member_id"] != expected_member_id or not isinstance(value["signature"], str):
        raise ControlError("member facts identity is invalid")
    return {"facts": facts, "signature": value["signature"]}


def post_member_facts(
    endpoint: str,
    *,
    identity: SiteIdentity,
    document: Mapping[str, Any],
) -> None:
    """Publish one signed inventory update to the authenticated coordinator."""
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ControlError("member facts coordinator endpoint must be an HTTPS origin")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(site_ca_certificate_path())
    context.load_cert_chain(member_certificate_path(), member_key_path())
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or DEFAULT_PORT,
        context=context,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    payload = json.dumps(dict(document), separators=(",", ":")).encode("utf-8")
    try:
        connection.connect()
        if connection.sock is None:
            raise ControlError("member facts TLS connection is unavailable")
        if _member_id_from_certificate(connection.sock.getpeercert()) != identity.coordinator_id:
            raise ControlError("member facts TLS peer is not the site coordinator")
        connection.request(
            "POST",
            "/node/v1/facts",
            body=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        response = connection.getresponse()
        raw = response.read(MAX_BODY_BYTES + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise ControlError(f"member facts publication failed: {error}") from error
    finally:
        connection.close()
    if len(raw) > MAX_BODY_BYTES:
        raise ControlError("member facts publication response is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError("member facts publication response is invalid") from error
    if response.status != 200 or value != {"protocol": PROTOCOL, "accepted": True}:
        detail = value.get("error") if isinstance(value, dict) else None
        raise ControlError(str(detail or "member facts publication was rejected"))


class FactsPublisher:
    """Bounded ten-second inventory publication for one configured member."""

    def __init__(
        self,
        identity: SiteIdentity,
        document_provider: Callable[[], Mapping[str, Any]],
        *,
        local_accept: Callable[[Mapping[str, Any], str], None] | None = None,
        endpoint: str | None = None,
    ) -> None:
        if (local_accept is None) == (endpoint is None):
            raise ControlError("facts publisher requires exactly one destination")
        self.identity = identity
        self.document_provider = document_provider
        self.local_accept = local_accept
        self.endpoint = endpoint
        self.stop_event = threading.Event()
        self.last_error: str | None = None
        self.thread = threading.Thread(
            target=self._run, name="letsinfer-node-facts", daemon=True
        )

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                document = dict(self.document_provider())
                if self.local_accept is not None:
                    self.local_accept(document, self.identity.member_id)
                else:
                    post_member_facts(
                        str(self.endpoint), identity=self.identity, document=document
                    )
                self.last_error = None
            except ControlError as error:
                self.last_error = str(error)[:256]
            self.stop_event.wait(max(0.1, 10.0 - (time.monotonic() - started)))

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=REQUEST_TIMEOUT_SECONDS + 1)


def probe_member_link(
    endpoint: str,
    *,
    identity: SiteIdentity,
    expected_member_id: str,
    expected_certificate_sha256: str,
    interface: str,
    kind: str,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Perform one mutually authenticated, nonce-bound physical-link probe."""
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise ControlError("link probe endpoint must be an HTTPS origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ControlError("link probe endpoint contains unsupported components")
    if not ID_RE.fullmatch(expected_member_id) or not SHA256_RE.fullmatch(
        expected_certificate_sha256
    ):
        raise ControlError("link probe peer identity is invalid")
    challenge_nonce = nonce or secrets.token_hex(32)
    if not SHA256_RE.fullmatch(challenge_nonce):
        raise ControlError("link probe nonce is invalid")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(site_ca_certificate_path())
    context.load_cert_chain(member_certificate_path(), member_key_path())
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or DEFAULT_PORT,
        context=context,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    try:
        connection.connect()
        if connection.sock is None:
            raise ControlError("link probe TLS connection is unavailable")
        observed = certificate_sha256_der(connection.sock.getpeercert(binary_form=True))
        if observed != expected_certificate_sha256:
            raise ControlError("link probe certificate fingerprint changed")
        if _member_id_from_certificate(connection.sock.getpeercert()) != expected_member_id:
            raise ControlError("link probe TLS identity does not match the peer member")
        peer_address = str(connection.sock.getpeername()[0])
        try:
            interface_proof = verify_direct_peer_interface(
                interface, peer_address, kind=kind
            )
        except InventoryError as error:
            raise ControlError(str(error)) from error
        payload = json.dumps(
            {
                "protocol": LINK_PROTOCOL,
                "nonce": challenge_nonce,
                "requester_member_id": identity.member_id,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        connection.request(
            "POST",
            "/node/v1/link-challenge",
            body=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        response = connection.getresponse()
        raw = response.read(MAX_BODY_BYTES + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise ControlError(f"member link probe failed: {error}") from error
    finally:
        connection.close()
    if len(raw) > MAX_BODY_BYTES:
        raise ControlError("member link proof is too large")
    try:
        challenge = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError("member link proof is not valid JSON") from error
    if response.status != 200 or not isinstance(challenge, dict):
        detail = challenge.get("error") if isinstance(challenge, dict) else None
        raise ControlError(str(detail or "member link probe was rejected"))
    try:
        return link_from_proof(
            member_id=identity.member_id,
            peer_member_id=expected_member_id,
            peer_certificate_sha256=expected_certificate_sha256,
            interface_proof=interface_proof,
            challenge=challenge,
        )
    except LinkError as error:
        raise ControlError(str(error)) from error


def request_member_link_probe(
    endpoint: str,
    *,
    expected_member_id: str,
    expected_certificate_sha256: str,
    peer_endpoint: str,
    peer_member_id: str,
    peer_certificate_sha256: str,
    interface: str,
    kind: str,
) -> dict[str, Any]:
    """Ask one member, as coordinator, to prove its route to another member."""
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise ControlError("member link-control endpoint must be an HTTPS origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ControlError("member link-control endpoint contains unsupported components")
    peer_parsed = urllib.parse.urlsplit(peer_endpoint)
    if (
        peer_parsed.scheme != "https"
        or not peer_parsed.hostname
        or peer_parsed.path not in {"", "/"}
        or peer_parsed.username
        or peer_parsed.password
        or peer_parsed.query
        or peer_parsed.fragment
    ):
        raise ControlError("peer link endpoint must be an HTTPS origin")
    if (
        not ID_RE.fullmatch(expected_member_id)
        or not SHA256_RE.fullmatch(expected_certificate_sha256)
        or not ID_RE.fullmatch(peer_member_id)
        or not SHA256_RE.fullmatch(peer_certificate_sha256)
        or expected_member_id == peer_member_id
    ):
        raise ControlError("member link-control identity is invalid")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(site_ca_certificate_path())
    context.load_cert_chain(member_certificate_path(), member_key_path())
    connection = http.client.HTTPSConnection(
        parsed.hostname, parsed.port or DEFAULT_PORT, context=context,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    request = {
        "protocol": LINK_PROTOCOL,
        "peer_endpoint": peer_endpoint,
        "peer_member_id": peer_member_id,
        "peer_certificate_sha256": peer_certificate_sha256,
        "interface": interface,
        "kind": kind,
        "nonce": secrets.token_hex(32),
    }
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    try:
        connection.connect()
        if connection.sock is None:
            raise ControlError("member link-control TLS connection is unavailable")
        if certificate_sha256_der(connection.sock.getpeercert(binary_form=True)) != expected_certificate_sha256:
            raise ControlError("member link-control certificate fingerprint changed")
        if _member_id_from_certificate(connection.sock.getpeercert()) != expected_member_id:
            raise ControlError("member link-control identity changed")
        connection.request(
            "POST", "/node/v1/link-probe", body=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        response = connection.getresponse()
        raw = response.read(MAX_BODY_BYTES + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise ControlError(f"member link-control request failed: {error}") from error
    finally:
        connection.close()
    if len(raw) > MAX_BODY_BYTES:
        raise ControlError("member link-control response is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError("member link-control response is not valid JSON") from error
    if response.status != 200 or not isinstance(value, dict):
        detail = value.get("error") if isinstance(value, dict) else None
        raise ControlError(str(detail or "member link-control request was rejected"))
    if set(value) != {"protocol", "link"} or value.get("protocol") != LINK_PROTOCOL:
        raise ControlError("member link-control response schema is invalid")
    try:
        return validate_link(value["link"], member_id=expected_member_id)
    except LinkError as error:
        raise ControlError(str(error)) from error


def _member_control_request(
    endpoint: str,
    *,
    expected_member_id: str,
    expected_certificate_sha256: str,
    method: str,
    path: str,
    body: Mapping[str, Any] | None = None,
    engine_credential: str | None = None,
) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or method not in {"GET", "POST"}
        or not path.startswith("/node/v1/")
    ):
        raise ControlError("child control request is invalid")
    if not ID_RE.fullmatch(expected_member_id) or not SHA256_RE.fullmatch(expected_certificate_sha256):
        raise ControlError("child control identity is invalid")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(site_ca_certificate_path())
    context.load_cert_chain(member_certificate_path(), member_key_path())
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or DEFAULT_PORT,
        context=context,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    if payload is not None and len(payload) > MAX_BODY_BYTES:
        raise ControlError("child control request is too large")
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if engine_credential is not None:
        if path != "/node/v1/group-job" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", engine_credential):
            raise ControlError("engine-group credential is invalid")
        headers["X-Letsinfer-Engine-Credential"] = engine_credential
    try:
        connection.connect()
        if connection.sock is None:
            raise ControlError("child control TLS connection is unavailable")
        if certificate_sha256_der(connection.sock.getpeercert(binary_form=True)) != expected_certificate_sha256:
            raise ControlError("child control certificate fingerprint changed")
        if _member_id_from_certificate(connection.sock.getpeercert()) != expected_member_id:
            raise ControlError("child control TLS identity changed")
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_BODY_BYTES + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise ControlError(f"child control request failed: {error}") from error
    finally:
        connection.close()
    if len(raw) > MAX_BODY_BYTES:
        raise ControlError("child control response is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError("child control response is not valid JSON") from error
    if response.status != 200 or not isinstance(value, dict):
        detail = value.get("error") if isinstance(value, dict) else None
        raise ControlError(str(detail or "child control request was rejected"))
    return value


def submit_member_group_job(
    endpoint: str,
    *,
    expected_member_id: str,
    expected_certificate_sha256: str,
    job: Mapping[str, Any],
    engine_credential: str | None = None,
) -> dict[str, Any]:
    """Submit one bounded immutable lifecycle job as the site coordinator."""
    value = _member_control_request(
        endpoint,
        expected_member_id=expected_member_id,
        expected_certificate_sha256=expected_certificate_sha256,
        method="POST",
        path="/node/v1/group-job",
        body=job,
        engine_credential=engine_credential,
    )
    if (
        value.get("protocol") != GROUP_JOB_PROTOCOL
        or value.get("operation_id") != job.get("operation_id")
        or set(value) != {
            "protocol", "operation_id", "replayed", "state", "result"
        }
        or value.get("state") not in {"running", "succeeded"}
        or (value["state"] == "running" and value["result"] is not None)
        or (value["state"] == "succeeded" and not isinstance(value["result"], dict))
    ):
        raise ControlError("member group-job response schema is invalid")
    return value


def fetch_member_job_status(
    endpoint: str,
    *,
    expected_member_id: str,
    expected_certificate_sha256: str,
    operation_id: str,
) -> dict[str, Any]:
    if not ID_RE.fullmatch(operation_id):
        raise ControlError("engine-group operation identity is invalid")
    value = _member_control_request(
        endpoint,
        expected_member_id=expected_member_id,
        expected_certificate_sha256=expected_certificate_sha256,
        method="GET",
        path=f"/node/v1/jobs/{operation_id}",
    )
    if value.get("protocol") != GROUP_JOB_PROTOCOL or set(value) != {"protocol", "job"}:
        raise ControlError("member job-status response schema is invalid")
    job = value["job"]
    if job is not None and (
        not isinstance(job, dict)
        or set(job) != {
            "operation_id", "group_id", "action", "state", "result", "error",
            "received_at_unix", "finished_at_unix",
        }
        or job.get("operation_id") != operation_id
        or job.get("state") not in {"running", "succeeded", "failed"}
    ):
        raise ControlError("member job-status payload is invalid")
    return value


def fetch_member_group_status(
    endpoint: str,
    *,
    expected_member_id: str,
    expected_certificate_sha256: str,
    group_id: str,
) -> dict[str, Any]:
    if not ID_RE.fullmatch(group_id):
        raise ControlError("engine-group identity is invalid")
    value = _member_control_request(
        endpoint,
        expected_member_id=expected_member_id,
        expected_certificate_sha256=expected_certificate_sha256,
        method="GET",
        path=f"/node/v1/groups/{group_id}",
    )
    if value.get("protocol") != GROUP_JOB_PROTOCOL or set(value) != {"protocol", "group"}:
        raise ControlError("member group-status response schema is invalid")
    return value


def _server_tls_context() -> ssl.SSLContext:
    if not getattr(ssl, "HAS_TLSv1_3", False):
        raise ControlError("site control requires TLS 1.3 support")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(member_certificate_path(), member_key_path())
    context.load_verify_locations(site_ca_certificate_path())
    context.verify_mode = ssl.CERT_OPTIONAL
    return context


class SiteControlState:
    def __init__(
        self,
        identity: SiteIdentity,
        *,
        facts_provider: Callable[[], Mapping[str, Any]],
        link_store: LinkStore | None = None,
        telemetry: TelemetryAggregator | None = None,
        member_agent: MemberAgent | None = None,
        adoption_provider: Callable[[Mapping[str, Any]], Mapping[str, Any]]
        | None = None,
        adoption_completed_provider: Callable[[Mapping[str, Any]], None]
        | None = None,
    ) -> None:
        self.identity = identity
        self.facts_provider = facts_provider
        self.link_store = link_store
        self.telemetry_aggregator = telemetry
        self.member_agent = member_agent
        self.adoption_provider = adoption_provider
        self.adoption_completed_provider = adoption_completed_provider
        self.certificate_sha256 = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(
                member_certificate_path().read_text(encoding="ascii")
            )
        ).hexdigest()

    def discovery(self) -> dict[str, Any]:
        direct_connectx = False
        adoption: dict[str, Any] | None = None
        try:
            select_direct_connectx_interface()
            direct_connectx = True
        except InventoryError:
            pass
        if self.identity.role == "main" and direct_connectx:
            try:
                with SiteStore(identity=self.identity) as store:
                    adoption = store.adoption()
            except SiteError as error:
                raise ControlError(str(error)) from error
        adoptable = bool(adoption and adoption["eligible"])
        return {
            "protocol": PROTOCOL,
            "display_name": self.identity.display_name,
            "site_id": self.identity.site_id,
            "member_id": self.identity.member_id,
            "role": self.identity.role,
            "claimed_state": "adoptable" if adoptable else "configured",
            "public_key_sha256": self.identity.member_public_key_sha256,
            "certificate_sha256": self.certificate_sha256,
            "direct_connectx": direct_connectx,
            "adoption_nonce": adoption["nonce"] if adoptable else None,
            "adoption_expires_at_unix": (
                adoption["expires_at_unix"] if adoptable else None
            ),
        }

    def challenge(
        self, invite_id: str, *, peer_address: str | None = None
    ) -> dict[str, Any]:
        if self.identity.role != "main":
            raise ControlError("child enrollment is main-only")
        try:
            with SiteStore(identity=self.identity) as store:
                invite = store.public_invite(invite_id)
        except SiteError as error:
            raise ControlError(str(error)) from error
        if invite["mode"] == "connectx":
            if peer_address is None:
                raise ControlError("ConnectX enrollment requires a direct peer address")
            try:
                verify_direct_connectx_peer(invite["direct_interface"], peer_address)
            except InventoryError as error:
                raise ControlError(str(error)) from error
        return {
            "protocol": PROTOCOL,
            "site_id": self.identity.site_id,
            "invite_id": invite["invite_id"],
            "nonce": invite["nonce"],
            "mode": invite["mode"],
            "expires_at_unix": invite["expires_at_unix"],
            "coordinator_id": self.identity.coordinator_id,
            "coordinator_address": self.identity.coordinator_address,
            "site_public_key_sha256": self.identity.site_public_key_sha256,
            "coordinator_certificate_sha256": self.certificate_sha256,
        }

    def enroll(
        self, payload: Mapping[str, Any], *, peer_address: str | None = None
    ) -> dict[str, Any]:
        required = {
            "protocol", "invite_id", "code", "member_id", "member_name",
            "member_address", "member_public_key", "installation_id",
            "installation_created_at_unix", "proof_signature",
        }
        if set(payload) != required or payload.get("protocol") != PROTOCOL:
            raise ControlError("membership enrollment request schema is invalid")
        if self.identity.role != "main":
            raise ControlError("child enrollment is main-only")
        try:
            with SiteStore(identity=self.identity) as store:
                invite = store.public_invite(str(payload["invite_id"]))
                if invite["mode"] == "connectx":
                    if peer_address is None:
                        raise ControlError(
                            "ConnectX enrollment requires a direct peer address"
                        )
                    verify_direct_connectx_peer(
                        invite["direct_interface"], peer_address
                    )
                response = store.enroll_member(
                    invite_id=str(payload["invite_id"]),
                    code=payload["code"] if isinstance(payload["code"], str) else None,
                    member_id=str(payload["member_id"]),
                    member_name=str(payload["member_name"]),
                    member_address=str(payload["member_address"]),
                    member_public_key=str(payload["member_public_key"]),
                    installation_id=str(payload["installation_id"]),
                    installation_created_at_unix=payload["installation_created_at_unix"],
                    proof_signature=str(payload["proof_signature"]),
                )
        except (InventoryError, SiteError) as error:
            raise ControlError(str(error)) from error
        return {"protocol": PROTOCOL, **response}

    def adopt(
        self, payload: Mapping[str, Any], *, peer_address: str
    ) -> dict[str, Any]:
        """Authenticate and execute one fresh-site direct-link adoption."""
        if self.identity.role != "main" or self.adoption_provider is None:
            raise ControlError("fresh-site adoption is unavailable")
        from .adoption import AdoptionError, validate_adoption_request

        try:
            direct = select_direct_connectx_interface()
            document = validate_adoption_request(
                self.identity,
                payload,
                peer_address=peer_address,
                direct_interface=direct["interface"],
            )
            result = self.adoption_provider(document)
        except (InventoryError, AdoptionError, SiteError) as error:
            raise ControlError(str(error)) from error
        expected = {
            "protocol", "state", "source_site_id", "destination_site_id",
            "member_id", "move_id",
        }
        if (
            not isinstance(result, Mapping)
            or set(result) != expected
            or result.get("protocol") != "letsinfer-node-adoption-v1"
            or result.get("state") != "committed"
            or result.get("source_site_id") != self.identity.site_id
            or result.get("destination_site_id")
            != document.get("destination_site_id")
            or result.get("member_id") != self.identity.member_id
            or not isinstance(result.get("move_id"), str)
            or not ID_RE.fullmatch(result["move_id"])
        ):
            raise ControlError("fresh-site adoption returned an invalid result")
        return dict(result)

    def adoption_completed(self, result: Mapping[str, Any]) -> None:
        if self.adoption_completed_provider is not None:
            self.adoption_completed_provider(result)

    def facts(self) -> dict[str, Any]:
        try:
            facts = validate_member_facts(dict(self.facts_provider()))
            signature = member_proof(facts)
        except (SiteError, ValueError) as error:
            raise ControlError(str(error)) from error
        return {"protocol": PROTOCOL, "facts": facts, "signature": signature}

    def membership(self, requester_member_id: str) -> dict[str, Any]:
        """Return only the authenticated caller's coordinator membership state."""
        if self.identity.role != "main":
            raise ControlError("child status is main-only")
        try:
            with SiteStore(identity=self.identity) as store:
                rows = [
                    row
                    for row in store.members(include_removed=True)
                    if row["member_id"] == requester_member_id
                ]
        except SiteError as error:
            raise ControlError(str(error)) from error
        if len(rows) != 1:
            raise ControlError("member is not enrolled in this site")
        row = rows[0]
        return {
            "protocol": PROTOCOL,
            "site_id": self.identity.site_id,
            "member_id": requester_member_id,
            "state": row["state"],
            "approval_expires_at_unix": row["approval_expires_at_unix"],
        }

    def accept_facts(
        self,
        payload: Mapping[str, Any],
        *,
        requester_member_id: str,
    ) -> dict[str, Any]:
        if self.identity.role != "main":
            raise ControlError("child fact aggregation is main-only")
        if set(payload) != {"protocol", "facts", "signature"} or payload.get("protocol") != PROTOCOL:
            raise ControlError("member facts publication schema is invalid")
        try:
            facts = validate_member_facts(payload["facts"])
        except ValueError as error:
            raise ControlError(str(error)) from error
        if facts["member_id"] != requester_member_id or not isinstance(payload["signature"], str):
            raise ControlError("member facts publication identity is invalid")
        try:
            with SiteStore(identity=self.identity) as store:
                store.update_member_facts(
                    requester_member_id,
                    facts,
                    payload["signature"],
                    actor_type="member",
                    origin_interface="member-push",
                )
        except SiteError as error:
            raise ControlError(str(error)) from error
        return {"protocol": PROTOCOL, "accepted": True}

    def link_challenge(
        self, payload: Mapping[str, Any], *, requester_member_id: str
    ) -> dict[str, Any]:
        if set(payload) != {"protocol", "nonce", "requester_member_id"}:
            raise ControlError("member link challenge schema is invalid")
        if payload.get("protocol") != LINK_PROTOCOL:
            raise ControlError("member link challenge protocol is invalid")
        if payload.get("requester_member_id") != requester_member_id:
            raise ControlError("member link challenge requester identity changed")
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not SHA256_RE.fullmatch(nonce):
            raise ControlError("member link challenge nonce is invalid")
        return {
            "protocol": LINK_PROTOCOL,
            "member_id": self.identity.member_id,
            "requester_member_id": requester_member_id,
            "nonce": nonce,
            "observed_at_unix": int(time.time()),
        }

    def probe_link(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "protocol", "peer_endpoint", "peer_member_id",
            "peer_certificate_sha256", "interface", "kind", "nonce",
        }
        if set(payload) != required or payload.get("protocol") != LINK_PROTOCOL:
            raise ControlError("member link probe schema is invalid")
        if self.link_store is None:
            raise ControlError("member link storage is unavailable")
        link = probe_member_link(
            str(payload["peer_endpoint"]),
            identity=self.identity,
            expected_member_id=str(payload["peer_member_id"]),
            expected_certificate_sha256=str(payload["peer_certificate_sha256"]),
            interface=str(payload["interface"]),
            kind=str(payload["kind"]),
            nonce=str(payload["nonce"]),
        )
        try:
            stored = self.link_store.upsert(link)
        except LinkError as error:
            raise ControlError(str(error)) from error
        return {"protocol": LINK_PROTOCOL, "link": stored}

    def accept_telemetry(
        self,
        payload: Mapping[str, Any],
        *,
        requester_member_id: str,
    ) -> dict[str, Any]:
        if self.identity.role != "main" or self.telemetry_aggregator is None:
            raise ControlError("node telemetry aggregation is main-only")
        if set(payload) != {"protocol", "sample", "signature"} or payload.get("protocol") != TELEMETRY_PROTOCOL:
            raise ControlError("member telemetry schema is invalid")
        try:
            sample = validate_sample(payload["sample"])
        except TelemetryError as error:
            raise ControlError(str(error)) from error
        if sample["member_id"] != requester_member_id or not isinstance(payload["signature"], str):
            raise ControlError("member telemetry identity is invalid")
        statement = {"protocol": TELEMETRY_PROTOCOL, "sample": sample}
        try:
            with SiteStore(identity=self.identity) as store:
                store.verify_active_member_statement(
                    requester_member_id, statement, payload["signature"]
                )
            self.telemetry_aggregator.update(sample)
        except (SiteError, TelemetryError) as error:
            raise ControlError(str(error)) from error
        return {"protocol": TELEMETRY_PROTOCOL, "accepted": True}

    def accept_local_telemetry(
        self,
        payload: Mapping[str, Any],
        *,
        requester_member_id: str,
    ) -> dict[str, Any]:
        """Accept this main node's in-process Watchdog sample without signing."""

        if self.identity.role != "main" or self.telemetry_aggregator is None:
            raise ControlError("node telemetry aggregation is main-only")
        if requester_member_id != self.identity.member_id:
            raise ControlError("local telemetry requester identity is invalid")
        try:
            sample = validate_sample(payload)
            if sample["member_id"] != self.identity.member_id:
                raise ControlError("local telemetry sample identity is invalid")
            self.telemetry_aggregator.update(sample)
        except TelemetryError as error:
            raise ControlError(str(error)) from error
        return {"protocol": TELEMETRY_PROTOCOL, "accepted": True}

    def execute_group_job(
        self,
        payload: Mapping[str, Any],
        *,
        engine_credential: str | None = None,
    ) -> dict[str, Any]:
        if self.member_agent is None:
            raise ControlError("engine-group lifecycle is unavailable on this member")
        try:
            return self.member_agent.submit(
                payload, engine_credential=engine_credential
            )
        except MemberJobError as error:
            raise ControlError(str(error)) from error

    def group_status(self, group_id: str) -> dict[str, Any]:
        if self.member_agent is None:
            raise ControlError("engine-group lifecycle is unavailable on this member")
        try:
            return self.member_agent.status(group_id)
        except MemberJobError as error:
            raise ControlError(str(error)) from error

    def job_status(self, operation_id: str) -> dict[str, Any]:
        if self.member_agent is None:
            raise ControlError("engine-group lifecycle is unavailable on this member")
        try:
            return self.member_agent.job_status(operation_id)
        except MemberJobError as error:
            raise ControlError(str(error)) from error


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "LetsInferSite/1"
    sys_version = ""

    def log_message(self, _format: str, *_arguments: Any) -> None:
        return

    @property
    def state(self) -> SiteControlState:
        return self.server.control_state  # type: ignore[attr-defined]

    def _respond(self, status: int, value: Mapping[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _require_coordinator(self) -> None:
        certificate = self.connection.getpeercert()  # type: ignore[attr-defined]
        if not certificate:
            raise ControlError("child control requires a client certificate")
        if _member_id_from_certificate(certificate) != self.state.identity.coordinator_id:
            raise ControlError("child control is main-only")

    def _require_site_member(self) -> str:
        certificate = self.connection.getpeercert()  # type: ignore[attr-defined]
        if not certificate:
            raise ControlError("member link proof requires a client certificate")
        return _member_id_from_certificate(certificate)

    def _require_enrollment_capacity(self) -> None:
        peer = str(self.client_address[0])
        if not self.server.enrollment_limiter.allow(peer):  # type: ignore[attr-defined]
            raise RateLimitError("membership enrollment rate limit exceeded")

    def do_GET(self) -> None:
        try:
            if self.path == "/node/v1/discovery":
                self._respond(200, self.state.discovery())
                return
            prefix = "/node/v1/enroll/"
            if self.path.startswith(prefix):
                self._require_enrollment_capacity()
                invite_id = self.path.removeprefix(prefix)
                if not ID_RE.fullmatch(invite_id):
                    raise ControlError("membership invite identity is invalid")
                self._respond(
                    200,
                    self.state.challenge(
                        invite_id, peer_address=str(self.client_address[0])
                    ),
                )
                return
            if self.path == "/node/v1/facts":
                self._require_coordinator()
                self._respond(200, self.state.facts())
                return
            if self.path == "/node/v1/membership":
                self._respond(
                    200,
                    self.state.membership(self._require_site_member()),
                )
                return
            group_prefix = "/node/v1/groups/"
            if self.path.startswith(group_prefix):
                self._require_coordinator()
                group_id = self.path.removeprefix(group_prefix)
                if not ID_RE.fullmatch(group_id):
                    raise ControlError("engine-group identity is invalid")
                self._respond(200, self.state.group_status(group_id))
                return
            job_prefix = "/node/v1/jobs/"
            if self.path.startswith(job_prefix):
                self._require_coordinator()
                operation_id = self.path.removeprefix(job_prefix)
                if not ID_RE.fullmatch(operation_id):
                    raise ControlError("engine-group operation identity is invalid")
                self._respond(200, self.state.job_status(operation_id))
                return
            self._respond(404, {"error": "not found"})
        except RateLimitError as error:
            self._respond(429, {"error": str(error)})
        except ControlError as error:
            self._respond(403, {"error": str(error)})

    def do_POST(self) -> None:
        if self.path not in {
            "/node/v1/enroll", "/node/v1/link-challenge", "/node/v1/link-probe",
            "/node/v1/telemetry", "/node/v1/facts", "/node/v1/group-job",
            "/node/v1/adopt",
        }:
            self._respond(404, {"error": "not found"})
            return
        try:
            if self.path in {"/node/v1/enroll", "/node/v1/adopt"}:
                self._require_enrollment_capacity()
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise ControlError("membership request content type is invalid")
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 2 or length > MAX_BODY_BYTES:
                raise ControlError("membership request size is invalid")
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise ControlError("membership request is invalid")
            if self.path == "/node/v1/enroll":
                response = self.state.enroll(
                    value, peer_address=str(self.client_address[0])
                )
            elif self.path == "/node/v1/adopt":
                response = self.state.adopt(
                    value, peer_address=str(self.client_address[0])
                )
            elif self.path == "/node/v1/link-challenge":
                response = self.state.link_challenge(
                    value, requester_member_id=self._require_site_member()
                )
            elif self.path == "/node/v1/link-probe":
                self._require_coordinator()
                response = self.state.probe_link(value)
            elif self.path == "/node/v1/facts":
                response = self.state.accept_facts(
                    value, requester_member_id=self._require_site_member()
                )
            elif self.path == "/node/v1/group-job":
                self._require_coordinator()
                response = self.state.execute_group_job(
                    value,
                    engine_credential=self.headers.get(
                        "X-Letsinfer-Engine-Credential"
                    ),
                )
            else:
                response = self.state.accept_telemetry(
                    value, requester_member_id=self._require_site_member()
                )
            self._respond(200, response)
            if self.path == "/node/v1/adopt":
                try:
                    self.state.adoption_completed(response)
                except Exception:
                    # The move transaction schedules a bounded fallback restart
                    # before local authority changes. Never corrupt the committed
                    # HTTP response if the immediate post-response activation fails.
                    pass
        except RateLimitError as error:
            self._respond(429, {"error": str(error)})
        except (ControlError, json.JSONDecodeError, ValueError, OSError) as error:
            self._respond(403, {"error": str(error)})


class SiteControlServer(http.server.HTTPServer):
    allow_reuse_address = True
    request_queue_size = 8

    def __init__(
        self,
        address: tuple[str, int],
        state: SiteControlState,
    ) -> None:
        super().__init__(address, _Handler, bind_and_activate=False)
        self.control_state = state
        self.enrollment_limiter = PeerRateLimiter()
        self.socket = _server_tls_context().wrap_socket(self.socket, server_side=True)
        self.server_bind()
        self.server_activate()

    def get_request(self) -> tuple[ssl.SSLSocket, Any]:
        connection, address = super().get_request()
        connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        return connection, address


def serve_in_thread(server: SiteControlServer) -> threading.Thread:
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return worker
