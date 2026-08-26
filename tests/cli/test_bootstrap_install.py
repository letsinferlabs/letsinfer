#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import pathlib
import re
import subprocess
import tempfile
import unittest

from core.platform import dgx_spark
from core.platform.network import NetworkPlan, apply_network_plan


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = REPOSITORY_ROOT / "install.sh"
RELEASE_ALLOWED_SIGNERS = REPOSITORY_ROOT / "core/trust/release-allowed-signers"
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/release-core.yml"


class BootstrapInstallTests(unittest.TestCase):
    def test_spark_network_provider_isolated_from_generic_setup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            etc = root / "etc"
            sys_class = root / "sys/class"
            etc.mkdir(parents=True)
            (etc / "dgx-release").write_text(
                "DGX_PLATFORM=GX10\n", encoding="ascii"
            )
            for name in dgx_spark.CONNECTX_INTERFACES:
                interface = sys_class / "net" / name
                interface.mkdir(parents=True)
                (interface / "carrier").write_text("1\n", encoding="ascii")
            plan = dgx_spark.network_plan(
                etc_root=etc,
                sys_class=sys_class,
                addresses={},
            )
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.provider, "nvidia-dgx-spark-connectx-v1")
        self.assertEqual(plan.backend, "networkmanager")
        self.assertEqual(dict(plan.settings)["ipv4.method"], "link-local")

    def test_generic_network_applier_preserves_external_ownership(self) -> None:
        plan = dgx_spark.network_plan(
            etc_root=pathlib.Path("/missing"),
            sys_class=pathlib.Path("/missing"),
        )
        self.assertIsNone(plan)

        value = NetworkPlan(
            provider="fixture-network-v1",
            backend="networkmanager",
            interfaces=("eth9",),
            settings=(
                ("ipv4.method", "link-local"),
                ("ipv6.method", "disabled"),
            ),
        )
        identifier = "11111111-2222-3333-4444-555555555555"

        def runner(command):
            output = (
                identifier + "\n"
                if command[1:5] == ("-t", "-f", "UUID", "connection")
                else "eth9\nmanual\nauto\n"
            )
            return subprocess.CompletedProcess(command, 0, output, "")

        result = apply_network_plan(value, runner=runner)
        self.assertEqual(result["state"], "externally-managed")

    def test_generic_network_applier_runs_only_bounded_backend_commands(self) -> None:
        plan = NetworkPlan(
            provider="fixture-network-v1",
            backend="networkmanager",
            interfaces=("eth9",),
            settings=(
                ("ipv4.method", "link-local"),
                ("ipv6.method", "disabled"),
            ),
        )
        commands: list[tuple[str, ...]] = []
        identifier = "11111111-2222-3333-4444-555555555555"

        def runner(command):
            commands.append(tuple(command))
            output = (
                identifier + "\n"
                if command[1:5] == ("-t", "-f", "UUID", "connection")
                else "eth9\nauto\nauto\n"
                if command[1:3] == ("-g", "connection.interface-name,ipv4.method,ipv6.method")
                else ""
            )
            return subprocess.CompletedProcess(
                command,
                0,
                output,
                "",
            )

        with tempfile.TemporaryDirectory() as directory:
            sys_class = pathlib.Path(directory) / "sys/class"
            carrier = sys_class / "net/eth9/carrier"
            carrier.parent.mkdir(parents=True)
            carrier.write_text("1\n", encoding="ascii")
            result = apply_network_plan(
                plan,
                runner=runner,
                sys_class=sys_class,
            )
        self.assertEqual(result["state"], "configured")
        self.assertEqual(
            commands[-1],
            ("sudo", "nmcli", "connection", "up", identifier, "ifname", "eth9"),
        )

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
        public_install_umask = script.index("umask 022", extraction)
        private_setup_umask = script.index("umask 077", public_install_umask)
        setup = script.index('"$command_path" core-setup')
        network = script.index("python3 -m core.platform.network apply-if-detected")
        self.assertLess(signature, checksum)
        self.assertLess(checksum, extraction)
        self.assertLess(extraction, installation)
        self.assertLess(extraction, network)
        self.assertLess(network, installation)
        self.assertLess(public_install_umask, installation)
        self.assertLess(installation, private_setup_umask)
        self.assertLess(private_setup_umask, setup)
        self.assertIn('curl_protocols="=https"', script)
        self.assertIn('--proto "$curl_protocols"', script)
        self.assertIn(
            "api.github.com/repos/$repository/releases?per_page=30", script
        )
        self.assertIn('(?:-rc\\.([0-9]+))?', script)
        self.assertIn('release.get("draft") is not False', script)
        self.assertIn('archive_name="letsinfer-$platform_os-$platform_arch.tar.gz"', script)
        self.assertIn('"$command_path" core-setup', script)
        self.assertIn('letsinfer_home="$HOME/.local/share/letsinfer"', script)
        self.assertIn('--home "$LETSINFER_HOME"', script)
        self.assertIn('$LETSINFER_HOME/core/current/bin/$launcher_name', script)
        self.assertIn('launcher_dir="/usr/local/bin"', script)
        self.assertIn('prefix="$HOME/.local"', script)
        self.assertIn(
            'for setup_command in docker loginctl systemctl systemd-run stat',
            script,
        )
        self.assertIn('preflight_linux_docker "$operator"', script)
        self.assertIn("preflight_linux_docker_service", script)
        self.assertIn("Preparing platform networking", script)
        self.assertIn('sudo usermod -aG "$socket_group" "$operator"', script)
        self.assertIn('sudo systemctl restart "user@$(id -u).service"', script)
        self.assertIn("openssl_development_ready", script)
        self.assertIn("build-essential cmake openssl libssl-dev", script)
        self.assertIn("gcc gcc-c++ make cmake openssl openssl-devel", script)
        self.assertIn('launchctl print "gui/$(id -u)"', script)
        self.assertIn('progress 5 "Resolving release"', script)
        self.assertIn('progress 80 "Initializing services"', script)
        self.assertIn('finish_progress', script)
        self.assertIn(
            '"$command_path" core-setup --json >"$setup_json" 2>"$setup_log"',
            script,
        )
        self.assertLess(
            script.index('json.loads(pathlib.Path(sys.argv[1])'),
            script.index("finish_progress\n"),
        )

    def test_watchdog_build_is_quiet_unless_a_command_fails(self) -> None:
        source = (REPOSITORY_ROOT / "core/cli.py").read_text(encoding="utf-8")
        start = source.index("def install_watchdog_runtime(")
        end = source.index("\ndef core_watchdog_source_identity", start)
        installer = source[start:end]
        self.assertNotIn("run_passthrough(", installer)
        self.assertEqual(installer.count("        run(\n"), 3)

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
