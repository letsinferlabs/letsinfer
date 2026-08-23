# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import os
import pathlib
import tempfile
import time
import unittest
from unittest import mock

from core.site import adoption, state


class FreshSiteAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.source_environment = {
            "LETSINFER_HOME": str(root / "source"),
        }
        self.destination_environment = {
            "LETSINFER_HOME": str(root / "destination"),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _signed_request(self) -> tuple[state.SiteIdentity, dict]:
        with mock.patch.dict(os.environ, self.source_environment):
            source = state.setup_site("Fresh Spark", "192.0.2.20")
            with state.SiteStore(identity=source) as store:
                window = store.adoption()
        now = int(time.time())
        with mock.patch.dict(os.environ, self.destination_environment):
            destination = state.setup_site("Home", "192.0.2.10")
            document = {
                "schema_version": 1,
                "source_site_id": source.site_id,
                "source_member_id": source.member_id,
                "source_public_key_sha256": source.member_public_key_sha256,
                "source_member_address": "192.0.2.20",
                "source_adoption_nonce": window["nonce"],
                "destination_site_id": destination.site_id,
                "destination_coordinator_id": destination.coordinator_id,
                "destination_site_public_key_sha256": (
                    destination.site_public_key_sha256
                ),
                "destination_endpoint": "https://192.0.2.10:9770",
                "destination_invite_id": "a" * 32,
                "destination_coordinator_certificate_sha256": "b" * 64,
                "issued_at_unix": now,
                "expires_at_unix": now + 120,
            }
            payload = {
                "protocol": adoption.PROTOCOL,
                "document": document,
                "signature": state.sign_site_document(document),
                "destination_site_public_key": state.site_public_key_path().read_text(
                    encoding="ascii"
                ),
            }
        return source, payload

    def test_signed_request_is_bound_to_fresh_window_and_direct_peer(self) -> None:
        source, payload = self._signed_request()
        with (
            mock.patch.dict(os.environ, self.source_environment),
            mock.patch.object(
                adoption,
                "verify_direct_connectx_peer",
                return_value={"peer_address": "192.0.2.10"},
            ) as verify,
        ):
            document = adoption.validate_adoption_request(
                source,
                payload,
                peer_address="192.0.2.10",
                direct_interface="enp1s0",
            )
            self.assertEqual(document["source_member_address"], "192.0.2.20")
            verify.assert_called_once_with("enp1s0", "192.0.2.10")
            with state.SiteStore(identity=source) as store:
                store.connection.execute(
                    "UPDATE adoption_window SET expires_at_unix=0 WHERE singleton=1"
                )
            with self.assertRaisesRegex(adoption.AdoptionError, "unavailable"):
                adoption.validate_adoption_request(
                    source,
                    payload,
                    peer_address="192.0.2.10",
                    direct_interface="enp1s0",
                )

    def test_destination_signature_cannot_be_changed(self) -> None:
        source, payload = self._signed_request()
        payload["document"]["destination_site_id"] = "f" * 32
        with (
            mock.patch.dict(os.environ, self.source_environment),
            mock.patch.object(
                adoption,
                "verify_direct_connectx_peer",
                return_value={"peer_address": "192.0.2.10"},
            ),
            self.assertRaisesRegex(adoption.AdoptionError, "signature"),
        ):
            adoption.validate_adoption_request(
                source,
                payload,
                peer_address="192.0.2.10",
                direct_interface="enp1s0",
            )

    def test_destination_connects_to_exact_direct_address_and_pins_source(self) -> None:
        with mock.patch.dict(os.environ, self.source_environment):
            source = state.setup_site("Fresh", "192.0.2.20")
            with state.SiteStore(identity=source) as store:
                window = store.adoption()
        with mock.patch.dict(os.environ, self.destination_environment):
            destination = state.setup_site("Home", "192.0.2.10")
            now = int(time.time())
            invite = {
                "invite_id": "a" * 32,
                "endpoint": "https://192.0.2.10:9770",
                "coordinator_certificate_sha256": "b" * 64,
                "candidate_public_key_sha256": source.member_public_key_sha256,
                "mode": "connectx",
                "expires_at_unix": now + 180,
            }
            response = {
                "protocol": adoption.PROTOCOL,
                "state": "committed",
                "source_site_id": source.site_id,
                "destination_site_id": destination.site_id,
                "member_id": source.member_id,
                "move_id": "c" * 32,
            }
            client = mock.Mock()
            client.request.side_effect = [
                {
                    "protocol": "letsinfer-node-control-v1",
                    "display_name": "Fresh",
                    "site_id": source.site_id,
                    "member_id": source.member_id,
                    "role": "main",
                    "claimed_state": "adoptable",
                    "public_key_sha256": source.member_public_key_sha256,
                    "certificate_sha256": "d" * 64,
                    "direct_connectx": True,
                    "adoption_nonce": window["nonce"],
                    "adoption_expires_at_unix": window["expires_at_unix"],
                },
                response,
            ]
            with mock.patch.object(
                adoption, "PinnedHTTPS", return_value=client
            ) as pinned:
                result = adoption.request_adoption(
                    source_endpoint="https://fresh.local:9770",
                    source_site_id=source.site_id,
                    source_member_id=source.member_id,
                    source_public_key_sha256=source.member_public_key_sha256,
                    source_certificate_sha256="d" * 64,
                    destination=destination,
                    invite=invite,
                    source_member_address="192.0.2.20",
                    now_unix=now,
                )
        self.assertEqual(result, response)
        pinned.assert_called_once_with("192.0.2.20", 9770, "d" * 64)
        posted = client.request.call_args_list[1].args[2]
        self.assertEqual(posted["document"]["source_member_address"], "192.0.2.20")


if __name__ == "__main__":
    unittest.main()
