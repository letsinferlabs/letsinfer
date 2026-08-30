#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import pathlib
import shutil
import re
import sys
import tempfile
import unittest


APP_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = APP_ROOT.parents[1]
sys.path.insert(0, str(APP_ROOT))

import release_metadata  # noqa: E402


class MacOSReleaseContractTests(unittest.TestCase):
    def test_version_is_app_owned_and_consistent(self) -> None:
        metadata = release_metadata.release_metadata(APP_ROOT)
        self.assertRegex(metadata["version"], release_metadata.VERSION_RE)
        self.assertRegex(metadata["build"], release_metadata.BUILD_RE)
        self.assertEqual(
            metadata["tag"],
            f'macos-v{metadata["version"]}-build.{metadata["build"]}',
        )
        self.assertFalse(metadata["tag"].startswith("v"))

    def test_generated_project_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "LetsInfer.xcodeproj").mkdir()
            (root / "LetsInfer").mkdir()
            shutil.copy2(APP_ROOT / "project.yml", root / "project.yml")
            shutil.copy2(
                APP_ROOT / "LetsInfer/Info.plist", root / "LetsInfer/Info.plist"
            )
            generated = (
                APP_ROOT / "LetsInfer.xcodeproj/project.pbxproj"
            ).read_text(encoding="utf-8")
            current = release_metadata.release_metadata(APP_ROOT)["version"]
            (root / "LetsInfer.xcodeproj/project.pbxproj").write_text(
                generated.replace(
                    f"MARKETING_VERSION = {current};", "MARKETING_VERSION = 9.9.9;", 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                release_metadata.MacOSReleaseError, "generated Xcode project version"
            ):
                release_metadata.release_metadata(root)

    def test_watchdog_protocol_contract_matches_native_source(self) -> None:
        client = (
            APP_ROOT / "LetsInfer/DataSources/Watchdog/WatchdogTLSClient.swift"
        ).read_text(encoding="utf-8")
        decoder = (
            APP_ROOT / "LetsInfer/DataSources/Watchdog/WatchdogProtocol.swift"
        ).read_text(encoding="utf-8")
        proto = (
            REPOSITORY_ROOT / "schemas/watchdog/li_watchdog_protocol_v1.proto"
        ).read_text(
            encoding="utf-8"
        )
        self.assertIn("static let supportedProtocolVersion: UInt32 = 3", client)
        fields = {
            25: ("active_requests", "activeRequests"),
            26: ("queued_requests", "queuedRequests"),
            27: ("requests_received", "requestsReceived"),
            28: ("requests_admitted", "requestsAdmitted"),
            29: ("requests_completed", "requestsCompleted"),
            30: ("requests_failed", "requestsFailed"),
            31: ("requests_cancelled", "requestsCancelled"),
            32: ("requests_retried", "requestsRetried"),
            33: ("input_tokens", "inputTokens"),
            34: ("output_tokens", "outputTokens"),
            35: ("cached_tokens", "cachedTokens"),
            36: ("queue_milliseconds", "queueMilliseconds"),
            37: ("ttft_milliseconds", "ttftMilliseconds"),
            38: ("decode_milliseconds", "decodeMilliseconds"),
            39: ("exact_token_requests", "exactTokenRequests"),
            40: ("prefix_cache_hits", "prefixCacheHits"),
            41: ("usage_records_dropped", "usageRecordsDropped"),
            42: ("usage_write_errors", "usageWriteErrors"),
        }
        for number, (proto_name, swift_name) in fields.items():
            self.assertRegex(proto, rf"(?:uint32|uint64) {proto_name} = {number};")
            self.assertIn(f"case ({number}, 0): sample.{swift_name} =", decoder)

    def test_controller_key_and_discovery_contracts_remain_bounded(self) -> None:
        pairing = (APP_ROOT / "LetsInfer/Pairing/ControllerPairing.swift").read_text(
            encoding="utf-8"
        )
        discovery = (
            APP_ROOT / "LetsInfer/Discovery/BonjourDiscovery.swift"
        ).read_text(encoding="utf-8")
        info = (APP_ROOT / "LetsInfer/Info.plist").read_text(encoding="utf-8")
        self.assertIn("kSecAttrTokenIDSecureEnclave", pairing)
        self.assertIn("kSecAttrIsExtractable as String: false", pairing)
        self.assertIn("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", pairing)
        self.assertIn(
            'private static let siteControlProtocol = "letsinfer-node-control-v1"',
            discovery,
        )
        self.assertIn('text["control"] == Self.siteControlProtocol', discovery)
        self.assertIn("<string>_letsinfer._tcp</string>", info)
        self.assertNotIn("<string>_watchdog._tcp</string>", info)
        self.assertNotIn("<string>_ssh._tcp</string>", info)
        self.assertNotIn("LetsInferRelease", info)

    def test_release_workflow_is_independent_and_pinned(self) -> None:
        workflow = (
            REPOSITORY_ROOT / ".github/workflows/release-macos.yml"
        ).read_text(encoding="utf-8")
        core_workflow = (
            REPOSITORY_ROOT / ".github/workflows/release-core.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("environment: production-macos-release", workflow)
        self.assertIn("--latest=false", workflow)
        self.assertIn("branches:\n      - macos-release", workflow)
        self.assertNotIn("Publish macOS release", core_workflow)
        for action in re.findall(r"uses:\s*([^\s]+)", workflow):
            revision = action.rsplit("@", 1)[-1]
            self.assertRegex(revision, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
