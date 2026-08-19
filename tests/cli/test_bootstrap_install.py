#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import base64
import pathlib
import re
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = REPOSITORY_ROOT / "install.sh"
RELEASE_PUBLIC_KEY = REPOSITORY_ROOT / "core/trust/release-public-key.pem"
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/release-core.yml"


class BootstrapInstallTests(unittest.TestCase):
    def test_embedded_release_key_matches_committed_trust_root(self) -> None:
        script = INSTALLER.read_text(encoding="utf-8")
        match = re.search(
            r"<<'LETSINFER_RELEASE_PUBLIC_KEY'\n(.*?)LETSINFER_RELEASE_PUBLIC_KEY\n",
            script,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group(1), RELEASE_PUBLIC_KEY.read_text(encoding="utf-8"))
        pem = "".join(
            line
            for line in match.group(1).splitlines()
            if not line.startswith("-----")
        )
        self.assertEqual(len(base64.b64decode(pem, validate=True)), 44)

    def test_installer_is_executable_and_has_fail_closed_verification_order(self) -> None:
        script = INSTALLER.read_text(encoding="utf-8")
        self.assertTrue(INSTALLER.stat().st_mode & 0o111)
        signature = script.index("openssl pkeyutl -verify")
        checksum = script.index("sha256sum --check")
        extraction = script.index('tar -xzf "$archive"')
        installation = script.index('"$unpacked/letsinfer/bin/letsinfer-install"')
        self.assertLess(signature, checksum)
        self.assertLess(checksum, extraction)
        self.assertLess(extraction, installation)
        self.assertIn('curl_protocols="=https"', script)
        self.assertIn('--proto "$curl_protocols"', script)
        self.assertIn("api.github.com/repos/$repository/releases/latest", script)
        self.assertIn('re.fullmatch(r"v[0-9]+\\.[0-9]+\\.[0-9]+", tag)', script)

    def test_release_workflow_uses_protected_environment_and_pinned_actions(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("branches:\n      - release", workflow)
        self.assertIn("environment: production-release", workflow)
        self.assertIn("LETSINFER_RELEASE_SIGNING_KEY_B64", workflow)
        self.assertIn("cmp \"$RUNNER_TEMP/source-a.tar.gz\"", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertNotIn("Validate macOS", workflow)
        action_refs = re.findall(r"uses:\s*([^\s]+)", workflow)
        self.assertGreaterEqual(len(action_refs), 3)
        for action in action_refs:
            revision = action.rsplit("@", 1)[-1]
            self.assertRegex(revision, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
