# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

from core.site.links import LinkError, LinkStore, link_from_proof
from core.site.state import SiteIdentity


MEMBER = "1" * 32
PEER = "2" * 32


def identity() -> SiteIdentity:
    return SiteIdentity(
        site_id="3" * 32,
        member_id=MEMBER,
        installation_id="4" * 64,
        display_name="Fixture",
        role="child",
        coordinator_id="5" * 32,
        coordinator_address="coordinator.local",
        site_public_key_sha256="6" * 64,
        member_public_key_sha256="7" * 64,
        created_at_unix=1_700_000_000,
    )


def link(observed_at_unix: int = 1_700_000_000) -> dict:
    return {
        "schema_version": 1,
        "peer_member_id": PEER,
        "interface": "enp1s0",
        "kind": "connectx",
        "speed_mbps": 200_000,
        "mtu": 9000,
        "rdma": True,
        "verified": True,
        "observed_at_unix": observed_at_unix,
        "peer_certificate_sha256": "8" * 64,
        "proof_sha256": "9" * 64,
    }


class LinkStoreTests(unittest.TestCase):
    def test_boolean_schema_and_timestamps_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LinkStore(identity(), pathlib.Path(directory) / "links.json")
            for field in ("schema_version", "observed_at_unix"):
                invalid = link()
                invalid[field] = True
                with self.subTest(field=field):
                    with self.assertRaisesRegex(LinkError, "schema|observed_at_unix"):
                        store.upsert(invalid)

    def test_store_is_private_member_bound_and_retains_renewal_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "links.json"
            store = LinkStore(identity(), path)
            self.assertEqual(store.upsert(link()), link())
            self.assertEqual(store.facts(now_unix=1_700_000_030)[0]["peer_member_id"], PEER)
            self.assertEqual(store.records(now_unix=1_700_000_031), [])
            self.assertEqual(store.facts(now_unix=1_700_000_031)[0]["peer_member_id"], PEER)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            document = json.loads(path.read_text(encoding="utf-8"))
            document["member_id"] = "a" * 32
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(LinkError, "invalid"):
                store.records(now_unix=1_700_000_000)

    def test_new_proof_replaces_only_the_same_peer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LinkStore(identity(), pathlib.Path(directory) / "links.json")
            store.upsert(link())
            replacement = link(1_700_000_001)
            replacement["interface"] = "enp2s0"
            store.upsert(replacement)
            self.assertEqual(store.records(now_unix=1_700_000_001), [replacement])

    def test_proof_uses_local_freshness_and_binds_peer_challenge(self) -> None:
        challenge = {
            "protocol": "letsinfer-node-link-v1",
            "member_id": PEER,
            "requester_member_id": MEMBER,
            "nonce": "a" * 64,
            "observed_at_unix": 1,
        }
        interface = {
            "interface": "enp1s0",
            "kind": "connectx",
            "speed_mbps": 200_000,
            "mtu": 9000,
            "rdma": True,
        }
        with mock.patch("core.site.links.time.time", return_value=1_700_000_000):
            result = link_from_proof(
                member_id=MEMBER,
                peer_member_id=PEER,
                peer_certificate_sha256="8" * 64,
                interface_proof=interface,
                challenge=challenge,
            )
        self.assertEqual(result["observed_at_unix"], 1_700_000_000)
        self.assertNotEqual(result["proof_sha256"], challenge["nonce"])
        changed = dict(challenge, requester_member_id="f" * 32)
        with self.assertRaisesRegex(LinkError, "challenge"):
            link_from_proof(
                member_id=MEMBER,
                peer_member_id=PEER,
                peer_certificate_sha256="8" * 64,
                interface_proof=interface,
                challenge=changed,
            )


if __name__ == "__main__":
    unittest.main()
