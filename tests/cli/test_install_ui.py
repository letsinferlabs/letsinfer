#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import errno
import hashlib
import json
import os
import pathlib
import pty
import subprocess
import tarfile
import tempfile
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = REPOSITORY_ROOT / "install.sh"


class InstallerUITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.fake_bin = self.root / "bin"
        self.release = self.root / "release"
        self.source = self.root / "source" / "letsinfer"
        self.fake_bin.mkdir()
        self.release.mkdir()
        (self.source / "bin").mkdir(parents=True)
        (self.source / "tools").mkdir()

        self._executable(
            self.fake_bin / "uname",
            """#!/bin/sh
case "$1" in
    -s) printf '%s\\n' "$FAKE_UNAME_S" ;;
    -m) printf '%s\\n' "$FAKE_UNAME_M" ;;
    *) exit 2 ;;
esac
""",
        )
        self._executable(
            self.fake_bin / "id",
            """#!/bin/sh
case "$1" in
    -u) printf '%s\\n' 501 ;;
    -un) printf '%s\\n' operator ;;
    -G)
        if [ "$#" -eq 1 ]; then
            printf '%s\\n' "${FAKE_CURRENT_GIDS:-20}"
        elif [ "${FAKE_ACCOUNT_HAS_DOCKER:-0}" = 1 ] || [ -f "$FAKE_DOCKER_GROUP_MARKER" ]; then
            printf '%s\\n' '20 999'
        else
            printf '%s\\n' 20
        fi
        ;;
    *) exit 2 ;;
esac
""",
        )
        self._executable(self.fake_bin / "ssh-keygen", "#!/bin/sh\nexit 0\n")
        self._executable(self.fake_bin / "launchctl", "#!/bin/sh\nexit 0\n")
        self._executable(
            self.fake_bin / "sg",
            """#!/bin/sh
[ "$#" -eq 3 ] || exit 2
[ "$2" = "-c" ] || exit 2
FAKE_DOCKER_AS_ROOT=1
export FAKE_DOCKER_AS_ROOT
exec /bin/sh -c "$3"
""",
        )
        self._executable(
            self.fake_bin / "docker",
            """#!/bin/sh
[ "$1" = "--version" ] && exit 0
case "${FAKE_DOCKER_MODE:-allowed}" in
    allowed) exit 0 ;;
    denied) [ "${FAKE_DOCKER_AS_ROOT:-0}" = 1 ] ;;
    daemon-down) exit 1 ;;
    *) exit 2 ;;
esac
""",
        )
        self._executable(
            self.fake_bin / "loginctl",
            """#!/bin/sh
case "$1" in
    show-user) printf '%s\\n' yes ;;
    enable-linger) exit 0 ;;
    *) exit 2 ;;
esac
""",
        )
        self._executable(self.fake_bin / "systemctl", "#!/bin/sh\nexit 0\n")
        self._executable(
            self.fake_bin / "systemd-run",
            """#!/bin/sh
if [ "${FAKE_DOCKER_SERVICE_STALE:-0}" = 1 ] && [ ! -f "$FAKE_USER_MANAGER_RESTARTED" ]; then
    exit 1
fi
exit 0
""",
        )
        self._executable(
            self.fake_bin / "sudo",
            """#!/bin/sh
case "$1" in
    -v) exit 0 ;;
    docker) FAKE_DOCKER_AS_ROOT=1 "$@" ;;
    usermod) touch "$FAKE_DOCKER_GROUP_MARKER" ;;
    systemctl) touch "$FAKE_USER_MANAGER_RESTARTED" ;;
    *) "$@" ;;
esac
""",
        )
        self._executable(
            self.fake_bin / "stat",
            "#!/bin/sh\nprintf '%s\\n' '999:docker'\n",
        )
        for command in ("cmake", "ctest", "cc", "openssl", "usermod"):
            self._executable(self.fake_bin / command, "#!/bin/sh\nexit 0\n")
        self._executable(
            self.fake_bin / "curl",
            """#!/bin/sh
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) output=$2; shift 2 ;;
        --proto) shift 2 ;;
        --fail|--location|--silent|--show-error|--tlsv1.2) shift ;;
        *) url=$1; shift ;;
    esac
done
case "$url" in
    file://*) cp "${url#file://}" "$output" ;;
    *) exit 2 ;;
esac
""",
        )
        self._executable(
            self.source / "bin" / "letsinfer-install",
            """#!/bin/sh
launcher_root=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --home) shift 2 ;;
        --launcher-root) launcher_root=$2; shift 2 ;;
        --python) printf '%s\n' "$2" >"$FAKE_PYTHON_PATH_FILE"; shift 2 ;;
        *) exit 2 ;;
    esac
done
test -n "$launcher_root"
mkdir -p "$launcher_root"
cp "$(dirname "$0")/letsinfer" "$launcher_root/letsinfer"
chmod 0755 "$launcher_root/letsinfer"
""",
        )
        self._executable(
            self.source / "bin" / "letsinfer",
            """#!/bin/sh
printf '%s\\n' "$*" >"$FAKE_SETUP_ARGS_FILE"
printf '%s' "$FAKE_SETUP_STDOUT"
printf '%s' "${FAKE_SETUP_STDERR:-}" >&2
exit "${FAKE_SETUP_STATUS:-0}"
""",
        )
        (self.source / "tools" / "__init__.py").write_text("", encoding="utf-8")
        (self.source / "tools" / "source_archive.py").write_text(
            "raise SystemExit(0)\n", encoding="utf-8"
        )

        checksum_lines = []
        for archive_name in (
            "letsinfer-macos-arm64.tar.gz",
            "letsinfer-linux-arm64.tar.gz",
        ):
            archive = self.release / archive_name
            with tarfile.open(archive, "w:gz") as handle:
                handle.add(self.source, arcname="letsinfer")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            checksum_lines.append(f"{digest}  {archive.name}\n")
        (self.release / "SHA256SUMS").write_text(
            "".join(checksum_lines), encoding="ascii"
        )
        (self.release / "SHA256SUMS.sig").write_text("test\n", encoding="ascii")
        self.signers = self.root / "allowed-signers"
        self.signers.write_text("test\n", encoding="ascii")
        self.run_number = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _executable(path: pathlib.Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def _environment(self, **updates: str) -> dict[str, str]:
        self.run_number += 1
        run_root = self.root / f"run-{self.run_number}"
        run_root.mkdir()
        setup_args = run_root / "setup-args"
        python_path = run_root / "python-path"
        environment = os.environ.copy()
        environment.pop("NO_COLOR", None)
        environment.update(
            {
                "FAKE_SETUP_ARGS_FILE": str(setup_args),
                "FAKE_PYTHON_PATH_FILE": str(python_path),
                "FAKE_SETUP_STDOUT": json.dumps(
                    {
                        "display_name": "Home",
                        "inference_endpoint": "http://home.local:8000/v1",
                        "api_key_file": "/private/key",
                    }
                )
                + "\n",
                "FAKE_DOCKER_GROUP_MARKER": str(run_root / "docker-group-added"),
                "FAKE_UNAME_M": "arm64",
                "FAKE_UNAME_S": "Darwin",
                "FAKE_USER_MANAGER_RESTARTED": str(
                    run_root / "user-manager-restarted"
                ),
                "HOME": str(run_root / "home"),
                "LANG": "en_US.UTF-8",
                "LETSINFER_ALLOW_INSECURE_RELEASE_URL": "1",
                "LETSINFER_HOME": str(run_root / "letsinfer-home"),
                "LETSINFER_RELEASE_ALLOWED_SIGNERS_PATH": str(self.signers),
                "PATH": f"{self.fake_bin}:{environment.get('PATH', '')}",
                "TERM": "xterm-256color",
            }
        )
        environment.update(updates)
        environment["TEST_PREFIX"] = str(run_root / "prefix")
        return environment

    def _command(self, environment: dict[str, str], *extra: str) -> list[str]:
        return [
            "/bin/sh",
            str(INSTALLER),
            "--version",
            "1.2.3",
            "--base-url",
            f"file://{self.release}",
            "--prefix",
            environment["TEST_PREFIX"],
            *extra,
        ]

    def _run_pipe(
        self, environment: dict[str, str], *extra: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self._command(environment, *extra),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

    def _run_tty(self, environment: dict[str, str], *extra: str) -> tuple[int, str]:
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen(
                self._command(environment, *extra),
                stdout=subprocess.DEVNULL,
                stderr=slave,
                env=environment,
            )
        finally:
            os.close(slave)
        chunks = []
        while True:
            try:
                block = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not block:
                break
            chunks.append(block)
        os.close(master)
        return process.wait(), b"".join(chunks).decode("utf-8", errors="replace")

    def test_non_tty_is_plain_and_setup_stderr_does_not_corrupt_json(self) -> None:
        environment = self._environment(FAKE_SETUP_STDERR="hidden diagnostic\n")
        result = self._run_pipe(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("\033", result.stderr)
        self.assertNotIn("hidden diagnostic", result.stderr)
        self.assertIn(
            "Let's Infer 1.2.3 installed and initialized for macos/arm64.",
            result.stderr,
        )
        self.assertIn("   Node      Home", result.stderr)
        self.assertIn("   API       http://home.local:8000/v1", result.stderr)
        self.assertEqual(
            pathlib.Path(environment["FAKE_SETUP_ARGS_FILE"]).read_text(
                encoding="utf-8"
            ),
            "core-setup --json\n",
        )

    def test_term_dumb_disables_progress_even_on_a_tty(self) -> None:
        environment = self._environment(TERM="dumb")
        status, output = self._run_tty(environment)

        self.assertEqual(status, 0, output)
        self.assertNotIn("\033", output)
        self.assertNotIn("INSTALL", output)
        self.assertIn(
            "Let's Infer 1.2.3 installed and initialized for macos/arm64.", output
        )

    def test_macos_persists_a_compatible_python(self) -> None:
        environment = self._environment()
        result = self._run_pipe(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        selected = pathlib.Path(environment["FAKE_PYTHON_PATH_FILE"]).read_text(
            encoding="utf-8"
        ).strip()
        self.assertTrue(pathlib.Path(selected).is_absolute())
        verified = subprocess.run(
            [
                selected,
                "-c",
                (
                    "import hashlib,http.server,plistlib,sqlite3,ssl,urllib.request;"
                    "hashlib.sha256(b'letsinfer').digest();"
                    "sqlite3.connect(':memory:').close();"
                    "plistlib.dumps({'letsinfer':True});"
                    "raise SystemExit(not ssl.HAS_TLSv1_3)"
                ),
            ],
            check=False,
        )
        self.assertEqual(verified.returncode, 0)

    def test_macos_rejects_an_explicit_incompatible_python_before_mutation(self) -> None:
        incompatible = self.root / "incompatible-python"
        self._executable(incompatible, "#!/bin/sh\nexit 1\n")
        environment = self._environment(LETSINFER_PYTHON=str(incompatible))

        result = self._run_pipe(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "working Python 3.9 or newer with TLS 1.3 support", result.stderr
        )
        self.assertFalse(pathlib.Path(environment["LETSINFER_HOME"]).exists())

    def test_no_color_keeps_progress_but_emits_no_color_sequences(self) -> None:
        environment = self._environment(NO_COLOR="1")
        status, output = self._run_tty(environment)

        self.assertEqual(status, 0, output)
        self.assertIn("LET'S INFER", output)
        self.assertIn("INSTALL", output)
        self.assertIn("100%", output)
        self.assertNotIn("38;2", output)
        self.assertNotIn("\033[0m", output)

    def test_no_progress_still_has_a_polished_final_result(self) -> None:
        environment = self._environment()
        status, output = self._run_tty(environment, "--no-progress")

        self.assertEqual(status, 0, output)
        self.assertNotIn("  5%", output)
        self.assertIn("LET'S INFER", output)
        self.assertIn("\033[1;38;2;97;187;70m", output)

    def test_invalid_setup_json_fails_before_success_is_announced(self) -> None:
        environment = self._environment(FAKE_SETUP_STDOUT="not-json\n")
        result = self._run_pipe(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("site initialization result is invalid", result.stderr)
        self.assertNotIn("installed and initialized", result.stderr)

    def test_setup_failure_is_bounded_to_the_last_eighty_diagnostic_lines(self) -> None:
        diagnostics = "".join(f"line-{number}\n" for number in range(100))
        environment = self._environment(
            FAKE_SETUP_STATUS="7", FAKE_SETUP_STDERR=diagnostics
        )
        result = self._run_pipe(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("line-0\n", result.stderr)
        self.assertIn("line-99\n", result.stderr)
        self.assertIn("site initialization failed", result.stderr)

    def test_interactive_failure_survives_exit_cleanup(self) -> None:
        environment = self._environment(
            FAKE_SETUP_STATUS="7", FAKE_SETUP_STDERR="setup detail\n"
        )
        status, output = self._run_tty(environment)

        self.assertNotEqual(status, 0)
        self.assertIn("setup detail", output)
        self.assertIn("Installation failed", output)
        self.assertIn("site initialization failed", output)
        self.assertTrue(output.rstrip().endswith("site initialization failed"), output)

    def test_linux_fails_before_download_when_docker_daemon_is_unhealthy(self) -> None:
        environment = self._environment(
            FAKE_DOCKER_MODE="daemon-down", FAKE_UNAME_S="Linux"
        )

        result = self._run_pipe(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Docker daemon is unavailable or unhealthy", result.stderr)
        self.assertFalse(pathlib.Path(environment["LETSINFER_HOME"]).exists())

    def test_linux_no_setup_does_not_require_docker_access(self) -> None:
        environment = self._environment(
            FAKE_DOCKER_MODE="daemon-down", FAKE_UNAME_S="Linux"
        )

        result = self._run_pipe(environment, "--no-setup")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "Let's Infer 1.2.3 installed for linux/arm64.", result.stderr
        )
        self.assertFalse(
            pathlib.Path(environment["FAKE_SETUP_ARGS_FILE"]).exists()
        )
        self.assertFalse(
            pathlib.Path(environment["FAKE_PYTHON_PATH_FILE"]).exists()
        )

    def test_linux_requires_explicit_approval_for_docker_group_enrollment(self) -> None:
        environment = self._environment(
            FAKE_DOCKER_MODE="denied", FAKE_UNAME_S="Linux"
        )

        result = self._run_pipe(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rerun with --repair-docker-access", result.stderr)
        self.assertFalse(
            pathlib.Path(environment["FAKE_DOCKER_GROUP_MARKER"]).exists()
        )

    def test_linux_enrolls_docker_group_and_continues_in_refreshed_group(self) -> None:
        environment = self._environment(
            FAKE_DOCKER_MODE="denied", FAKE_UNAME_S="Linux"
        )

        result = self._run_pipe(environment, "--repair-docker-access")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "using refreshed docker group access for this installation",
            result.stderr,
        )
        self.assertTrue(
            pathlib.Path(environment["FAKE_DOCKER_GROUP_MARKER"]).exists()
        )
        self.assertEqual(
            pathlib.Path(environment["FAKE_SETUP_ARGS_FILE"]).read_text(
                encoding="utf-8"
            ),
            "core-setup --json\n",
        )

    def test_linux_uses_existing_account_group_without_readding_it(self) -> None:
        environment = self._environment(
            FAKE_ACCOUNT_HAS_DOCKER="1",
            FAKE_DOCKER_MODE="denied",
            FAKE_UNAME_S="Linux",
        )

        result = self._run_pipe(environment, "--repair-docker-access")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "using refreshed docker group access for this installation",
            result.stderr,
        )
        self.assertFalse(
            pathlib.Path(environment["FAKE_DOCKER_GROUP_MARKER"]).exists()
        )
        self.assertEqual(
            pathlib.Path(environment["FAKE_SETUP_ARGS_FILE"]).read_text(
                encoding="utf-8"
            ),
            "core-setup --json\n",
        )

    def test_linux_repairs_a_stale_user_manager_before_setup(self) -> None:
        environment = self._environment(
            FAKE_DOCKER_SERVICE_STALE="1", FAKE_UNAME_S="Linux"
        )

        result = self._run_pipe(environment, "--repair-docker-access")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            pathlib.Path(environment["FAKE_USER_MANAGER_RESTARTED"]).exists()
        )
        self.assertEqual(
            pathlib.Path(environment["FAKE_SETUP_ARGS_FILE"]).read_text(
                encoding="utf-8"
            ),
            "core-setup --json\n",
        )


if __name__ == "__main__":
    unittest.main()
