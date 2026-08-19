#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import pathlib
import re
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = REPOSITORY_ROOT / "install.sh"
RELEASE_ALLOWED_SIGNERS = REPOSITORY_ROOT / "core/trust/release-allowed-signers"
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/release-core.yml"


class BootstrapInstallTests(unittest.TestCase):
    def test_embedded_release_signer_matches_committed_trust_root(self) -> None:
        script = INSTALLER.read_text(encoding="utf-8")
        match = re.search(
            r"<<'LETSINFER_RELEASE_ALLOWED_SIGNERS'\n"
            r"(.*?)LETSINFER_RELEASE_ALLOWED_SIGNERS\n",
            script,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(
            match.group(1), RELEASE_ALLOWED_SIGNERS.read_text(encoding="utf-8")
        )

    def test_installer_is_executable_and_has_fail_closed_verification_order(self) -> None:
        script = INSTALLER.read_text(encoding="utf-8")
        self.assertTrue(INSTALLER.stat().st_mode & 0o111)
        signature = script.index("ssh-keygen -Y verify")
        checksum = script.index('python3 - "$checksums" "$archive_name" "$archive"')
        extraction = script.index('tar -xzf "$archive"')
        installation = script.index('"$unpacked/letsinfer/bin/letsinfer-install"')
        self.assertLess(signature, checksum)
        self.assertLess(checksum, extraction)
        self.assertLess(extraction, installation)
        self.assertIn('curl_protocols="=https"', script)
        self.assertIn('--proto "$curl_protocols"', script)
        self.assertIn("api.github.com/repos/$repository/releases/latest", script)
        self.assertIn('re.fullmatch(r"v[0-9]+\\.[0-9]+\\.[0-9]+", tag)', script)
        self.assertIn('archive_name="letsinfer-$platform_os-$platform_arch.tar.gz"', script)
        self.assertIn('"$command_path" setup', script)
        self.assertIn('prefix="/opt/letsinfer"', script)
        self.assertIn('launcher_dir="/usr/local/bin"', script)
        self.assertIn('for setup_command in docker cmake ctest cc openssl', script)
        self.assertIn('launchctl print "gui/$(id -u)"', script)

    def test_release_workflow_uses_protected_environment_and_pinned_actions(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("branches:\n      - release", workflow)
        self.assertIn("environment: production-release", workflow)
        self.assertIn("LETSINFER_RELEASE_SIGNING_KEY_B64", workflow)
        self.assertIn("cmp \"$RUNNER_TEMP/source-a.tar.gz\"", workflow)
        self.assertIn("python3 -m tools.sshsig prepare", workflow)
        self.assertIn("ssh-keygen -Y verify", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertIn("name: Validate macOS core", workflow)
        self.assertNotIn("xcodebuild", workflow)
        action_refs = re.findall(r"uses:\s*([^\s]+)", workflow)
        self.assertGreaterEqual(len(action_refs), 3)
        for action in action_refs:
            revision = action.rsplit("@", 1)[-1]
            self.assertRegex(revision, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
