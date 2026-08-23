# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import hashlib
import json
import time

from core.site import state, topology


def routing_facts(
    member_id: str,
    *,
    temperature_c: float = 55.0,
    health_state: str = "healthy",
    memory_pressure: bool = False,
    protection_trip: bool = False,
    observed_at_unix: int | None = None,
    address: str = "192.0.2.10",
    links: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": 1,
        "member_id": member_id,
        "observed_at_unix": observed_at_unix or int(time.time()),
        "platform": "linux/arm64",
        "accelerator": {
            "vendor": "nvidia",
            "architecture": "sm_121",
            "count": 1,
            "partitioning": "full-device",
            "minimum_memory_gib": 128,
            "devices": [f"GPU-{member_id[:8]}"],
        },
        "memory": {
            "topology": "unified",
            "total_gib": 128,
            "available_gib": 100,
        },
        "storage": {
            "total_gib": 1000,
            "available_gib": 700,
            "cache_available_gib": 600,
        },
        "network": {
            "interfaces": [
                {
                    "name": "eth0",
                    "addresses": [address],
                    "mtu": 9000,
                    "speed_mbps": 200_000,
                    "rdma": True,
                }
            ],
            "links": links or [],
        },
        "software": {
            "driver": "fixture",
            "container_runtime": "fixture",
            "letsinfer_version": "0.11.0-rc.2",
        },
        "health": {
            "state": health_state,
            "memory_pressure": memory_pressure,
            "protection_trip": protection_trip,
            "max_temperature_c": temperature_c,
        },
    }


def routing_link(
    peer_member_id: str,
    *,
    peer_certificate_sha256: str,
    observed_at_unix: int | None = None,
) -> dict:
    return {
        "peer_member_id": peer_member_id,
        "interface": "eth0",
        "kind": "connectx",
        "speed_mbps": 200_000,
        "mtu": 9000,
        "rdma": True,
        "verified": True,
        "observed_at_unix": observed_at_unix or int(time.time()),
        "peer_certificate_sha256": peer_certificate_sha256,
        "proof_sha256": hashlib.sha256(
            (peer_member_id + "-link-proof").encode()
        ).hexdigest(),
    }


def set_member_facts(store: state.SiteStore, member_id: str, facts: dict) -> None:
    store.connection.execute(
        "UPDATE members SET facts_json=?,facts_sha256=? WHERE member_id=?",
        (
            json.dumps(facts, sort_keys=True, separators=(",", ":")),
            topology.facts_sha256(facts),
            member_id,
        ),
    )


def insert_member(store: state.SiteStore, member_id: str, *, facts: dict | None = None) -> None:
    now = int(time.time())
    value = facts or routing_facts(member_id)
    store.connection.execute(
        """INSERT INTO members
           (member_id,display_name,role,address,public_key_sha256,public_key_pem,
            certificate_sha256,certificate_pem,state,approval_code_hash,
            approval_expires_at_unix,facts_json,facts_signature_base64,
            facts_sha256,joined_at_unix,updated_at_unix)
           VALUES(?,?,'child',?,?,?,?,?,'active',NULL,NULL,?,NULL,?,?,?)""",
        (
            member_id,
            "Synthetic member",
            "member.local",
            hashlib.sha256((member_id + "-key").encode()).hexdigest(),
            "synthetic-public-key",
            hashlib.sha256((member_id + "-certificate").encode()).hexdigest(),
            "synthetic-certificate",
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            topology.facts_sha256(value),
            now,
            now,
        ),
    )
