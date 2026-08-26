#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

from core.platform import dgx_spark
from core.platform.network import NetworkPlan, apply_network_plan


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = REPOSITORY_ROOT / "install.sh"
RELEASE_ALLOWED_SIGNERS = REPOSITORY_ROOT / "core/trust/release-allowed-signers"
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/release-core.yml"


def _write_executable(path: pathlib.Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def _docker_installer_harness(
    *,
    distribution: str = "ubuntu",
    platform: str = "linux",
    docker_present: bool = False,
    docker_version_exit: int = 0,
    docker_info_exit: int = 0,
    package_install_exit: int = 0,
    include_preflight: bool = True,
    include_mdns: bool = False,
    mdns_present: bool = False,
) -> tuple[subprocess.CompletedProcess[str], str]:
    script = INSTALLER.read_text(encoding="utf-8")
    function_prefix, marker, _remainder = script.partition('\nwhile [ "$#" -gt 0 ]; do')
    if not marker:
        raise AssertionError("installer function boundary is missing")

    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        command_log = root / "commands.log"
        mdns_service_marker = root / "mdns-service-active"
        os_release = root / "os-release"
        os_release.write_text(f'ID="{distribution}"\n', encoding="utf-8")
        (fake_bin / "python3").symlink_to(sys.executable)

        docker_template = root / "docker-template"
        _write_executable(
            docker_template,
            """#!/bin/sh
case "$1" in
    --version) exit "${FAKE_DOCKER_VERSION_EXIT:-0}" ;;
    info) exit "${FAKE_DOCKER_INFO_EXIT:-0}" ;;
    *) exit 0 ;;
esac
""",
        )
        if docker_present:
            (fake_bin / "docker").write_bytes(docker_template.read_bytes())
            (fake_bin / "docker").chmod(0o755)

        avahi_publish_template = root / "avahi-publish-template"
        avahi_browse_template = root / "avahi-browse-template"
        _write_executable(avahi_publish_template, "#!/bin/sh\nexit 0\n")
        _write_executable(avahi_browse_template, "#!/bin/sh\nexit 0\n")
        if mdns_present:
            (fake_bin / "avahi-publish-service").write_bytes(
                avahi_publish_template.read_bytes()
            )
            (fake_bin / "avahi-publish-service").chmod(0o755)
            (fake_bin / "avahi-browse").write_bytes(
                avahi_browse_template.read_bytes()
            )
            (fake_bin / "avahi-browse").chmod(0o755)

        _write_executable(
            fake_bin / "sudo",
            """#!/bin/sh
printf 'sudo %s\n' "$*" >>"$FAKE_COMMAND_LOG"
if [ "$1" = "env" ]; then
    shift
    exec /usr/bin/env "$@"
fi
exec "$@"
""",
        )
        _write_executable(
            fake_bin / "systemctl",
            """#!/bin/sh
printf 'systemctl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
if [ "$*" = "is-active --quiet avahi-daemon.service" ]; then
    [ -f "$FAKE_MDNS_SERVICE_MARKER" ]
    exit
fi
if [ "$*" = "enable --now avahi-daemon.service" ]; then
    : >"$FAKE_MDNS_SERVICE_MARKER"
fi
exit "${FAKE_SYSTEMCTL_EXIT:-0}"
""",
        )
        for manager in ("apt-get", "dnf", "zypper", "pacman"):
            _write_executable(
                fake_bin / manager,
                f"""#!/bin/sh
printf '{manager} %s\n' "$*" >>"$FAKE_COMMAND_LOG"
if [ "{manager}" = "apt-get" ] && [ "$1" = "update" ]; then
    exit 0
fi
[ "${{FAKE_PACKAGE_INSTALL_EXIT:-0}}" -eq 0 ] || exit "$FAKE_PACKAGE_INSTALL_EXIT"
case " $* " in
    *" avahi "*|*" avahi-daemon "*|*" avahi-utils "*|*" avahi-tools "*)
        /bin/cp "$FAKE_AVAHI_PUBLISH_TEMPLATE" "$FAKE_BIN/avahi-publish-service"
        /bin/cp "$FAKE_AVAHI_BROWSE_TEMPLATE" "$FAKE_BIN/avahi-browse"
        /bin/chmod 0755 "$FAKE_BIN/avahi-publish-service" "$FAKE_BIN/avahi-browse"
        ;;
    *)
        /bin/cp "$FAKE_DOCKER_TEMPLATE" "$FAKE_BIN/docker"
        /bin/chmod 0755 "$FAKE_BIN/docker"
        ;;
esac
exit 0
""",
            )

        preflight = 'preflight_linux_docker "fixture-operator"' if include_preflight else ":"
        mdns = 'ensure_platform_mdns "$1" "$2"' if include_mdns else ":"
        harness = (
            function_prefix
            + "\npython_command=python3\n"
            + '\nensure_platform_docker "$1" "$2"\n'
            + mdns
            + "\n"
            + preflight
            + "\n"
        )
        environment = {
            "PATH": str(fake_bin),
            "HOME": str(root),
            "TERM": "dumb",
            "FAKE_BIN": str(fake_bin),
            "FAKE_COMMAND_LOG": str(command_log),
            "FAKE_DOCKER_TEMPLATE": str(docker_template),
            "FAKE_AVAHI_PUBLISH_TEMPLATE": str(avahi_publish_template),
            "FAKE_AVAHI_BROWSE_TEMPLATE": str(avahi_browse_template),
            "FAKE_MDNS_SERVICE_MARKER": str(mdns_service_marker),
            "FAKE_DOCKER_VERSION_EXIT": str(docker_version_exit),
            "FAKE_DOCKER_INFO_EXIT": str(docker_info_exit),
            "FAKE_PACKAGE_INSTALL_EXIT": str(package_install_exit),
        }
        result = subprocess.run(
            ["/bin/sh", "-c", harness, "docker-installer-test", platform, str(os_release)],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        log = command_log.read_text(encoding="utf-8") if command_log.exists() else ""
        return result, log


class BootstrapInstallTests(unittest.TestCase):
    def test_existing_usable_docker_is_left_unchanged(self) -> None:
        result, log = _docker_installer_harness(docker_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log, "")

    def test_missing_docker_uses_supported_ubuntu_packages_and_starts_daemon(
        self,
    ) -> None:
        result, log = _docker_installer_harness()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Docker is not installed; installing it with sudo", result.stderr)
        self.assertIn("sudo apt-get update", log)
        self.assertIn(
            "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io",
            log,
        )
        self.assertIn("sudo systemctl enable --now docker.service", log)
        self.assertIn("sudo docker info", log)

    def test_non_linux_platform_does_not_inspect_or_install_docker(self) -> None:
        result, log = _docker_installer_harness(
            platform="macos",
            include_preflight=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log, "")

    def test_missing_ubuntu_avahi_is_installed_and_started(self) -> None:
        result, log = _docker_installer_harness(
            include_preflight=False,
            include_mdns=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("apt-get install -y avahi-daemon avahi-utils", log)
        self.assertIn("systemctl enable --now avahi-daemon.service", log)

    def test_supported_distributions_use_native_avahi_packages(self) -> None:
        scenarios = {
            "debian": "apt-get install -y avahi-daemon avahi-utils",
            "fedora": "dnf install -y avahi avahi-tools",
            "opensuse-leap": "zypper --non-interactive install avahi avahi-utils",
            "arch": "pacman --sync --needed --noconfirm avahi",
        }
        for distribution, package_command in scenarios.items():
            with self.subTest(distribution=distribution):
                result, log = _docker_installer_harness(
                    distribution=distribution,
                    include_preflight=False,
                    include_mdns=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(package_command, log)

    def test_supported_distributions_use_declared_native_packages(self) -> None:
        scenarios = {
            "debian": "apt-get install -y docker.io",
            "fedora": "dnf install -y moby-engine",
            "opensuse-leap": "zypper --non-interactive install docker",
            "arch": "pacman --sync --needed --noconfirm docker",
        }
        for distribution, package_command in scenarios.items():
            with self.subTest(distribution=distribution):
                result, log = _docker_installer_harness(
                    distribution=distribution,
                    include_preflight=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(package_command, log)
                self.assertIn("systemctl enable --now docker.service", log)

    def test_missing_docker_fails_closed_on_unsupported_distribution(self) -> None:
        result, log = _docker_installer_harness(
            distribution="alpine",
            include_preflight=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "automatic Docker installation is unsupported on Linux distribution: alpine",
            result.stderr,
        )
        self.assertNotIn("install", log)

    def test_docker_package_installation_failure_is_explicit(self) -> None:
        result, log = _docker_installer_harness(
            package_install_exit=9,
            include_preflight=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("apt could not install Docker", result.stderr)
        self.assertIn("apt-get install -y docker.io", log)
        self.assertNotIn("systemctl enable --now docker.service", log)

    def test_installed_cli_with_unhealthy_daemon_is_not_reinstalled(self) -> None:
        result, log = _docker_installer_harness(
            docker_present=True,
            docker_info_exit=1,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("the Docker daemon is unavailable or unhealthy", result.stderr)
        self.assertNotIn("apt-get", log)

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
        checksum = script.index(
            '"$python_command" - "$checksums" "$archive_name" "$archive"'
        )
        extraction = script.index('tar -xzf "$archive"')
        installation = script.index('"$unpacked/letsinfer/bin/letsinfer-install"')
        public_install_umask = script.index("umask 022", extraction)
        private_setup_umask = script.index("umask 077", public_install_umask)
        setup = script.index('"$command_path" core-setup')
        network = script.index(
            '"$python_command" -m core.platform.network apply-if-detected'
        )
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
            'for setup_command in loginctl systemctl systemd-run stat',
            script,
        )
        self.assertIn('ensure_platform_docker "$platform_os"', script)
        self.assertIn('ensure_platform_mdns "$platform_os"', script)
        self.assertIn(
            "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io",
            script,
        )
        self.assertIn("sudo dnf install -y moby-engine", script)
        self.assertIn("sudo zypper --non-interactive install docker", script)
        self.assertIn("sudo pacman --sync --needed --noconfirm docker", script)
        self.assertNotIn("get.docker.com", script)
        self.assertIn("avahi-daemon avahi-utils", script)
        self.assertIn("avahi avahi-tools", script)
        self.assertIn('preflight_linux_docker "$operator"', script)
        self.assertIn("preflight_linux_docker_service", script)
        self.assertIn("Preparing platform networking", script)
        self.assertIn('sudo usermod -aG "$socket_group" "$operator"', script)
        self.assertIn('sudo systemctl restart "user@$(id -u).service"', script)
        self.assertIn("openssl_development_ready", script)
        self.assertIn("build-essential cmake openssl libssl-dev", script)
        self.assertIn("gcc gcc-c++ make cmake openssl openssl-devel", script)
        self.assertIn('launchctl print "gui/$(id -u)"', script)
        self.assertIn("select_macos_python", script)
        self.assertIn("import plistlib", script)
        self.assertIn('sqlite3.connect(":memory:").close()', script)
        self.assertIn('export LETSINFER_PYTHON=$python_command', script)
        self.assertIn('--python "$python_command"', script)
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
