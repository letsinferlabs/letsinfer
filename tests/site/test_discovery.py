# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import unittest
from unittest import mock

from core.site import discovery
from core.site.state import SiteIdentity


def identity() -> SiteIdentity:
    return SiteIdentity(
        site_id="1" * 32,
        member_id="2" * 32,
        installation_id="3" * 64,
        display_name="Home",
        role="main",
        coordinator_id="2" * 32,
        coordinator_address="home.local",
        site_public_key_sha256="4" * 64,
        member_public_key_sha256="5" * 64,
        created_at_unix=1_700_000_000,
    )


class DiscoveryTests(unittest.TestCase):
    def test_boolean_port_is_rejected(self) -> None:
        with self.assertRaisesRegex(discovery.ControlError, "port"):
            discovery.advertisement(
                identity(), port=True, certificate_sha256="6" * 64
            )

    def test_publisher_refuses_extra_or_malformed_public_hints(self) -> None:
        record = discovery.advertisement(
            identity(), port=9770, certificate_sha256="6" * 64
        )
        record["txt"]["credential"] = "must-not-publish"
        with self.assertRaisesRegex(discovery.ControlError, "fields"):
            discovery.publisher_command(record)

        with self.assertRaisesRegex(discovery.ControlError, "certificate"):
            discovery.advertisement(
                identity(), port=9770, certificate_sha256="not-a-digest"
            )
        with self.assertRaisesRegex(discovery.ControlError, "ConnectX"):
            discovery.advertisement(
                identity(),
                port=9770,
                certificate_sha256="6" * 64,
                adoptable=True,
            )

    def test_advertisement_contains_only_public_identity_hints(self) -> None:
        record = discovery.advertisement(
            identity(), port=9770, certificate_sha256="6" * 64
        )
        self.assertEqual(record["service_type"], "_letsinfer._tcp")
        self.assertEqual(
            set(record["txt"]),
            {
                "protocol", "node", "machine", "role", "state", "key", "tls",
                "control", "inference", "inference_port",
            },
        )
        self.assertEqual(record["txt"]["inference"], "http")
        self.assertEqual(record["txt"]["inference_port"], "8000")
        serialized = repr(record).lower()
        for forbidden in ("model", "telemetry", "credential", "api_key", "private"):
            self.assertNotIn(forbidden, serialized)

    def test_linux_and_macos_publishers_receive_the_same_sorted_txt(self) -> None:
        record = discovery.advertisement(
            identity(), port=9770, certificate_sha256="6" * 64
        )
        with mock.patch.object(
            discovery.shutil,
            "which",
            side_effect=lambda name, path=None: "/usr/bin/avahi-publish-service"
            if name == "avahi-publish-service"
            else None,
        ):
            linux = discovery.publisher_command(record)
        self.assertEqual(linux[:4], [
            "/usr/bin/avahi-publish-service", "Let's Infer — Home",
            "_letsinfer._tcp", "9770",
        ])
        self.assertEqual(linux[4:], sorted(linux[4:]))
        with mock.patch.object(
            discovery.shutil,
            "which",
            side_effect=lambda name, path=None: "/usr/bin/dns-sd" if name == "dns-sd" else None,
        ):
            macos = discovery.publisher_command(record)
        self.assertEqual(macos[:6], [
            "/usr/bin/dns-sd", "-R", "Let's Infer — Home",
            "_letsinfer._tcp", "local", "9770",
        ])
        self.assertEqual(macos[6:], linux[4:])

    def test_direct_connectx_hint_contains_no_interface_or_peer_details(self) -> None:
        record = discovery.advertisement(
            identity(),
            port=9770,
            certificate_sha256="6" * 64,
            direct_connectx=True,
        )
        self.assertEqual(record["txt"]["direct"], "connectx")
        self.assertNotIn("interface", repr(record).lower())
        adoptable = discovery.advertisement(
            identity(),
            port=9770,
            certificate_sha256="6" * 64,
            direct_connectx=True,
            adoptable=True,
        )
        self.assertEqual(adoptable["txt"]["state"], "adoptable")


if __name__ == "__main__":
    unittest.main()
