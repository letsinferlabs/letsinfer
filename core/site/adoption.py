#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""One-click adoption of a fresh single-member site over verified ConnectX."""

from __future__ import annotations

import pathlib
import re
import socket
import tempfile
import time
import urllib.parse
import ipaddress
from collections.abc import Mapping
from typing import Any

from .control import DEFAULT_PORT, PinnedHTTPS
from .inventory import InventoryError, verify_direct_connectx_peer
from .state import (
    SiteError,
    SiteIdentity,
    SiteStore,
    member_public_key_fingerprint,
    sign_site_document,
    site_public_key_path,
    verify_site_document,
)


PROTOCOL = "letsinfer-node-adoption-v1"
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ADOPTION_SECONDS = 180


class AdoptionError(RuntimeError):
    """A direct-link adoption request failed closed."""


def _origin(endpoint: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise AdoptionError("adoption endpoint must be an HTTPS origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AdoptionError("adoption endpoint contains unsupported components")
    return parsed.hostname, parsed.port or DEFAULT_PORT


def resolve_direct_peer(endpoint: str, interface: str) -> str:
    """Resolve exactly one address whose kernel route is the approved direct link."""
    host, port = _origin(endpoint)
    try:
        addresses = {
            str(item[4][0])
            for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        }
    except OSError as error:
        raise AdoptionError("adoption candidate address cannot be resolved") from error
    direct: list[str] = []
    for address in sorted(addresses):
        try:
            verify_direct_connectx_peer(interface, address)
            direct.append(address)
        except InventoryError:
            continue
    if not direct:
        raise AdoptionError("adoption candidate is not reachable over direct ConnectX")
    if len(direct) != 1:
        raise AdoptionError("adoption candidate direct address is ambiguous")
    return direct[0]


def request_adoption(
    *,
    source_endpoint: str,
    source_site_id: str,
    source_member_id: str,
    source_public_key_sha256: str,
    source_certificate_sha256: str,
    destination: SiteIdentity,
    invite: Mapping[str, Any],
    source_member_address: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Send one destination-signed, direct-link adoption request to a fresh site."""
    if (
        not ID_RE.fullmatch(source_site_id)
        or not ID_RE.fullmatch(source_member_id)
        or not SHA256_RE.fullmatch(source_public_key_sha256)
        or not SHA256_RE.fullmatch(source_certificate_sha256)
    ):
        raise AdoptionError("adoption candidate identity is invalid")
    _host, port = _origin(source_endpoint)
    try:
        source_member_address = str(ipaddress.ip_address(source_member_address))
    except ValueError as error:
        raise AdoptionError("adoption candidate direct address is invalid") from error
    client = PinnedHTTPS(source_member_address, port, source_certificate_sha256)
    discovery = client.request("GET", "/node/v1/discovery")
    expected_discovery = {
        "protocol",
        "display_name",
        "site_id",
        "member_id",
        "role",
        "claimed_state",
        "public_key_sha256",
        "certificate_sha256",
        "direct_connectx",
        "adoption_nonce",
        "adoption_expires_at_unix",
    }
    if (
        set(discovery) != expected_discovery
        or discovery.get("protocol") != "letsinfer-node-control-v1"
        or discovery.get("site_id") != source_site_id
        or discovery.get("member_id") != source_member_id
        or discovery.get("role") != "main"
        or discovery.get("claimed_state") != "adoptable"
        or discovery.get("public_key_sha256") != source_public_key_sha256
        or discovery.get("certificate_sha256") != source_certificate_sha256
        or discovery.get("direct_connectx") is not True
        or not isinstance(discovery.get("adoption_nonce"), str)
        or not SHA256_RE.fullmatch(discovery["adoption_nonce"])
        or not isinstance(discovery.get("adoption_expires_at_unix"), int)
        or isinstance(discovery.get("adoption_expires_at_unix"), bool)
    ):
        raise AdoptionError("adoption candidate discovery identity is invalid")
    required_invite = {
        "invite_id",
        "endpoint",
        "coordinator_certificate_sha256",
        "candidate_public_key_sha256",
        "mode",
        "expires_at_unix",
    }
    if (
        any(key not in invite for key in required_invite)
        or invite.get("mode") != "connectx"
        or invite.get("candidate_public_key_sha256") != source_public_key_sha256
        or not ID_RE.fullmatch(str(invite.get("invite_id", "")))
        or not isinstance(invite.get("expires_at_unix"), int)
        or isinstance(invite.get("expires_at_unix"), bool)
        or not SHA256_RE.fullmatch(
            str(invite.get("coordinator_certificate_sha256", ""))
        )
    ):
        raise AdoptionError("destination adoption invite is invalid")
    _origin(str(invite["endpoint"]))
    now = int(time.time()) if now_unix is None else now_unix
    expires = min(
        now + MAX_ADOPTION_SECONDS,
        int(discovery["adoption_expires_at_unix"]),
        int(invite["expires_at_unix"]),
    )
    if expires <= now:
        raise AdoptionError("adoption authorization already expired")
    document = {
        "schema_version": 1,
        "source_site_id": source_site_id,
        "source_member_id": source_member_id,
        "source_public_key_sha256": source_public_key_sha256,
        "source_member_address": source_member_address,
        "source_adoption_nonce": discovery["adoption_nonce"],
        "destination_site_id": destination.site_id,
        "destination_coordinator_id": destination.coordinator_id,
        "destination_site_public_key_sha256": destination.site_public_key_sha256,
        "destination_endpoint": invite["endpoint"],
        "destination_invite_id": invite["invite_id"],
        "destination_coordinator_certificate_sha256": invite[
            "coordinator_certificate_sha256"
        ],
        "issued_at_unix": now,
        "expires_at_unix": expires,
    }
    try:
        signature = sign_site_document(document)
        public_key = site_public_key_path().read_text(encoding="ascii")
    except (SiteError, OSError, UnicodeError) as error:
        raise AdoptionError("destination site signing identity is unavailable") from error
    response = client.request(
        "POST",
        "/node/v1/adopt",
        {
            "protocol": PROTOCOL,
            "document": document,
            "signature": signature,
            "destination_site_public_key": public_key,
        },
    )
    expected_response = {
        "protocol", "state", "source_site_id", "destination_site_id", "member_id",
        "move_id",
    }
    if (
        set(response) != expected_response
        or response.get("protocol") != PROTOCOL
        or response.get("state") != "committed"
        or response.get("source_site_id") != source_site_id
        or response.get("destination_site_id") != destination.site_id
        or response.get("member_id") != source_member_id
        or not isinstance(response.get("move_id"), str)
        or not ID_RE.fullmatch(response["move_id"])
    ):
        raise AdoptionError("adoption candidate returned an invalid result")
    return response


def validate_adoption_request(
    identity: SiteIdentity,
    payload: Mapping[str, Any],
    *,
    peer_address: str,
    direct_interface: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Authenticate a destination-signed request on the source's direct link."""
    if set(payload) != {
        "protocol", "document", "signature", "destination_site_public_key"
    } or payload.get("protocol") != PROTOCOL:
        raise AdoptionError("adoption request schema is invalid")
    document = payload.get("document")
    signature = payload.get("signature")
    public_key = payload.get("destination_site_public_key")
    expected = {
        "schema_version",
        "source_site_id",
        "source_member_id",
        "source_public_key_sha256",
        "source_member_address",
        "source_adoption_nonce",
        "destination_site_id",
        "destination_coordinator_id",
        "destination_site_public_key_sha256",
        "destination_endpoint",
        "destination_invite_id",
        "destination_coordinator_certificate_sha256",
        "issued_at_unix",
        "expires_at_unix",
    }
    if (
        not isinstance(document, Mapping)
        or set(document) != expected
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
        or not isinstance(signature, str)
        or not isinstance(public_key, str)
    ):
        raise AdoptionError("adoption document schema is invalid")
    now = int(time.time()) if now_unix is None else now_unix
    if (
        document.get("source_site_id") != identity.site_id
        or document.get("source_member_id") != identity.member_id
        or document.get("source_public_key_sha256")
        != identity.member_public_key_sha256
        or document.get("destination_site_id") == identity.site_id
        or not isinstance(document.get("issued_at_unix"), int)
        or isinstance(document.get("issued_at_unix"), bool)
        or not isinstance(document.get("expires_at_unix"), int)
        or isinstance(document.get("expires_at_unix"), bool)
        or document["issued_at_unix"] > now + 5
        or document["expires_at_unix"] < now
        or document["expires_at_unix"] - document["issued_at_unix"]
        > MAX_ADOPTION_SECONDS
    ):
        raise AdoptionError("adoption document identity or lifetime is invalid")
    try:
        direct = verify_direct_connectx_peer(direct_interface, peer_address)
    except InventoryError as error:
        raise AdoptionError(str(error)) from error
    if direct.get("peer_address") != peer_address:
        raise AdoptionError("adoption destination peer address changed")
    try:
        with SiteStore(identity=identity) as store:
            adoption = store.adoption(now_unix=now)
    except SiteError as error:
        raise AdoptionError(str(error)) from error
    if (
        not adoption["eligible"]
        or document.get("source_adoption_nonce") != adoption["nonce"]
    ):
        raise AdoptionError("fresh-site adoption is unavailable")
    try:
        fingerprint = member_public_key_fingerprint(public_key)
    except SiteError as error:
        raise AdoptionError("destination site public key is invalid") from error
    if fingerprint != document.get("destination_site_public_key_sha256"):
        raise AdoptionError("destination site public key fingerprint changed")
    with tempfile.TemporaryDirectory(prefix="letsinfer-adoption-proof-") as temporary:
        path = pathlib.Path(temporary) / "site.pub"
        path.write_text(public_key, encoding="ascii")
        path.chmod(0o600)
        try:
            verify_site_document(document, signature, path)
        except SiteError as error:
            raise AdoptionError("destination adoption signature is invalid") from error
    for field, pattern in (
        ("destination_site_id", ID_RE),
        ("destination_coordinator_id", ID_RE),
        ("destination_invite_id", ID_RE),
        ("destination_coordinator_certificate_sha256", SHA256_RE),
    ):
        if not isinstance(document.get(field), str) or not pattern.fullmatch(
            document[field]
        ):
            raise AdoptionError(f"adoption {field} is invalid")
    try:
        source_member_address = str(
            ipaddress.ip_address(str(document.get("source_member_address", "")))
        )
    except ValueError as error:
        raise AdoptionError("adoption source member address is invalid") from error
    if source_member_address != document["source_member_address"]:
        raise AdoptionError("adoption source member address is not canonical")
    _origin(str(document.get("destination_endpoint", "")))
    return dict(document)
