#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import pathlib
import re
import subprocess
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = REPOSITORY_ROOT / "install.sh"
RELEASE_ALLOWED_SIGNERS = REPOSITORY_ROOT / "core/trust/release-allowed-signers"
RELEASE_WORKFLOW = REPOSITORY_ROOT / ".github/workflows/release-core.yml"
SERVICE_MANAGER = (
    REPOSITORY_ROOT
    / "installer/src/li_installer_service_manager.rs"
)
CORE_SETUP_PROCESS = (
    REPOSITORY_ROOT
    / "core/application/src/li_core_setup_process.rs"
)


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

    def test_bootstrap_verifies_then_executes_one_native_installer(self) -> None:
        script = INSTALLER.read_text(encoding="utf-8")
        signature = script.index('"$ssh_keygen_command" -Y verify')
        download = script.index(
            'download "$release_base/$installer_archive_name" "$installer_archive"',
            signature,
        )
        checksum = script.index("verify_native_checksum", download)
        preparation = script.index("extract_native_installer\n", checksum)
        inventory = script.index("verify_native_archive")
        extraction = script.index(
            '"$tar_command" -xzf "$installer_archive"', inventory
        )
        execution = script.index('exec "$installer_binary"', preparation)
        self.assertLess(signature, download)
        self.assertLess(download, checksum)
        self.assertLess(checksum, preparation)
        self.assertLess(inventory, extraction)
        self.assertLess(preparation, execution)
        self.assertIn(
            'installer_archive_name="li_installer_${platform_os}_${platform_arch}.tar.gz"',
            script,
        )
        self.assertIn('--selected-platform "$selected_platform"', script)
        self.assertIn('--control-address "$control_address"', script)
        self.assertIn('--temporary-root "$temporary"', script)
        self.assertIn('--release-allowed-signers-file "$allowed_signers"', script)
        self.assertNotIn('download "$release_base/$core_archive_name"', script)
        self.assertNotIn("core-setup --json", script)
        self.assertNotIn("ensure_platform_docker", script)
        self.assertNotIn("ensure_platform_mdns", script)
        self.assertNotIn("route get", script)
        self.assertNotIn("python", script.lower())

    def test_bootstrap_supports_only_released_native_targets(self) -> None:
        script = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("linux/arm64|linux/x86_64|macos/arm64", script)
        self.assertIn(
            'a native installer is unavailable for $platform_os/$platform_arch',
            script,
        )

    def test_native_installer_delegates_atomic_service_readiness_to_core_setup(self) -> None:
        source = SERVICE_MANAGER.read_text(encoding="utf-8")
        self.assertIn("CoreSetupCommand::new(core.setup_command.clone()", source)
        self.assertIn("Command::new(&command.executable)", source)
        self.assertIn("run_core_setup_protocol(", source)
        self.assertIn("decode_setup_summary(&output.stdout, expected)", source)
        self.assertIn("struct CoreSetupResultDocument", source)
        self.assertIn("#[serde(deny_unknown_fields)]", source)
        self.assertNotIn("verify_services", source)
        self.assertNotIn('"li_node.service"', source)
        self.assertNotIn('"li_gateway.service"', source)
        self.assertNotIn('"li_watchdog.service"', source)
        self.assertNotIn('"ai.letsinfer.node"', source)
        self.assertNotIn('"ai.letsinfer.gateway"', source)
        self.assertIn('"entropy_source": "/dev/urandom"', source)
        self.assertIn('"timeout_milliseconds": 5000', source)
        self.assertIn('"maximum_response_bytes": 1048576', source)
        self.assertNotIn('"letsinfer-node.service"', source)
        self.assertNotIn('"letsinfer-gateway.service"', source)

    # Keeps the separately compiled installer and Core on one exact machine exit contract.
    def test_native_installer_matches_core_setup_machine_exit_classes(self) -> None:
        pattern = re.compile(r"const (CORE_SETUP_EXIT_[A-Z_]+): i32 = (\d+);")
        installer_classes = dict(
            pattern.findall(SERVICE_MANAGER.read_text(encoding="utf-8"))
        )
        core_classes = dict(
            pattern.findall(CORE_SETUP_PROCESS.read_text(encoding="utf-8"))
        )
        expected = {
            "CORE_SETUP_EXIT_COMMITTED": "0",
            "CORE_SETUP_EXIT_SAFE_TO_ROLLBACK": "2",
            "CORE_SETUP_EXIT_RECOVERY_REQUIRED": "3",
        }
        self.assertEqual(installer_classes, expected)
        self.assertEqual(core_classes, expected)

    def test_bootstrap_help_does_not_require_network_or_native_assets(self) -> None:
        result = subprocess.run(
            ["/bin/sh", str(INSTALLER), "--help"],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("native Let's Infer installer", result.stdout)

    def test_release_workflow_uses_protected_environment_and_pinned_actions(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("branches:\n      - release", workflow)
        self.assertIn("environment: production-release", workflow)
        self.assertIn("LETSINFER_RELEASE_SIGNING_KEY_B64", workflow)
        self.assertIn("build-native-installer:", workflow)
        self.assertIn("dist/li_installer_linux_arm64.tar.gz", workflow)
        self.assertIn("dist/li_installer_linux_x86_64.tar.gz", workflow)
        self.assertIn("dist/li_installer_macos_arm64.tar.gz", workflow)
        action_refs = re.findall(r"uses:\s*([^\s]+)", workflow)
        self.assertGreaterEqual(len(action_refs), 3)
        for action in action_refs:
            self.assertRegex(action.rsplit("@", 1)[-1], r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
