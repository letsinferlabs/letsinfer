#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Persistent, authenticated physical-link observations for one member."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
from collections.abc import Mapping
from typing import Any

from .state import SiteError, SiteIdentity, _atomic_private, _private_file, data_root


ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$")
MAX_LINKS = 64
MAX_LINK_AGE_SECONDS = 30


class LinkError(RuntimeError):
    """A physical-link observation is incomplete, stale, or unsafe."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def validate_link(value: Any, *, member_id: str | None = None) -> dict[str, Any]:
    required = {
        "schema_version",
        "peer_member_id",
        "interface",
        "kind",
        "speed_mbps",
        "mtu",
        "rdma",
        "verified",
        "observed_at_unix",
        "peer_certificate_sha256",
        "proof_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
    ):
        raise LinkError("member link has an unsupported schema")
    peer = value.get("peer_member_id")
    if not isinstance(peer, str) or not ID_RE.fullmatch(peer) or peer == member_id:
        raise LinkError("member link peer identity is invalid")
    interface = value.get("interface")
    if not isinstance(interface, str) or not INTERFACE_RE.fullmatch(interface):
        raise LinkError("member link interface is invalid")
    if value.get("kind") not in {"connectx", "ethernet", "wifi", "other"}:
        raise LinkError("member link kind is invalid")
    for field, minimum in (("speed_mbps", 1), ("mtu", 576), ("observed_at_unix", 1)):
        amount = value.get(field)
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < minimum:
            raise LinkError(f"member link {field} is invalid")
    if value.get("verified") is not True or not isinstance(value.get("rdma"), bool):
        raise LinkError("member link verification flags are invalid")
    for field in ("peer_certificate_sha256", "proof_sha256"):
        digest = value.get(field)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise LinkError(f"member link {field} is invalid")
    return value


def link_from_proof(
    *,
    member_id: str,
    peer_member_id: str,
    peer_certificate_sha256: str,
    interface_proof: Mapping[str, Any],
    challenge: Mapping[str, Any],
) -> dict[str, Any]:
    peer_observed = challenge.get("observed_at_unix")
    if (
        challenge.get("protocol") != "letsinfer-node-link-v1"
        or challenge.get("member_id") != peer_member_id
        or challenge.get("requester_member_id") != member_id
        or not isinstance(challenge.get("nonce"), str)
        or not SHA256_RE.fullmatch(challenge["nonce"])
        or not isinstance(peer_observed, int)
        or isinstance(peer_observed, bool)
    ):
        raise LinkError("member link challenge is invalid")
    result = {
        "schema_version": 1,
        "peer_member_id": peer_member_id,
        "interface": interface_proof["interface"],
        "kind": interface_proof["kind"],
        "speed_mbps": interface_proof["speed_mbps"],
        "mtu": interface_proof["mtu"],
        "rdma": interface_proof["rdma"],
        "verified": True,
        # Freshness is measured on the member that owns this record. The
        # peer's clock remains nonce-bound inside proof_sha256 but cannot make
        # a locally fresh physical observation appear stale or future-dated.
        "observed_at_unix": int(time.time()),
        "peer_certificate_sha256": peer_certificate_sha256,
        "proof_sha256": hashlib.sha256(canonical_bytes(dict(challenge))).hexdigest(),
    }
    return validate_link(result, member_id=member_id)


class LinkStore:
    def __init__(
        self,
        identity: SiteIdentity,
        path: pathlib.Path | None = None,
    ) -> None:
        self.identity = identity
        self.path = path or data_root() / "site-links.json"

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            value = json.loads(_private_file(self.path, minimum_bytes=32))
        except (UnicodeDecodeError, json.JSONDecodeError, SiteError) as error:
            raise LinkError(f"cannot read member link state: {error}") from error
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "member_id", "links"}
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or value.get("member_id") != self.identity.member_id
            or not isinstance(value.get("links"), list)
            or len(value["links"]) > MAX_LINKS
        ):
            raise LinkError("member link state is invalid")
        links = [validate_link(item, member_id=self.identity.member_id) for item in value["links"]]
        peers = [item["peer_member_id"] for item in links]
        if len(peers) != len(set(peers)):
            raise LinkError("member link state contains duplicate peers")
        return links

    def records(self, *, now_unix: int | None = None) -> list[dict[str, Any]]:
        now = now_unix or int(time.time())
        return [
            item
            for item in self._read()
            if 0 <= now - item["observed_at_unix"] <= MAX_LINK_AGE_SECONDS
        ]

    def facts(self, *, now_unix: int | None = None) -> list[dict[str, Any]]:
        # Publish configured observations even after their proof expires. The
        # topology graph rejects stale proofs, while the coordinator retains
        # the peer/interface metadata needed to renew them after a restart.
        return [
            {key: value for key, value in item.items() if key != "schema_version"}
            for item in self._read()
        ]

    def upsert(self, value: Mapping[str, Any]) -> dict[str, Any]:
        link = validate_link(dict(value), member_id=self.identity.member_id)
        links = [
            item for item in self._read() if item["peer_member_id"] != link["peer_member_id"]
        ]
        links.append(link)
        links.sort(key=lambda item: item["peer_member_id"])
        if len(links) > MAX_LINKS:
            raise LinkError("member link limit exceeded")
        try:
            _atomic_private(
                self.path,
                canonical_bytes(
                    {
                        "schema_version": 1,
                        "member_id": self.identity.member_id,
                        "links": links,
                    }
                ),
            )
        except SiteError as error:
            raise LinkError(str(error)) from error
        return link
