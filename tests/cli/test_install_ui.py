#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import errno
import hashlib
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
        self.fake_bin.mkdir()
        self.release.mkdir()

        self._executable(
            self.fake_bin / "uname",
            """#!/bin/sh
case "$1" in
    -s) printf '%s\n' "$FAKE_UNAME_S" ;;
    -m) printf '%s\n' "$FAKE_UNAME_M" ;;
    *) exit 2 ;;
esac
""",
        )
        self._executable(
            self.fake_bin / "id",
            """#!/bin/sh
case "$1" in
    -u) printf '501\n' ;;
    -un) printf 'operator\n' ;;
    *) exit 2 ;;
esac
""",
        )
        self._executable(
            self.fake_bin / "ssh-keygen",
            '#!/bin/sh\nexit "${FAKE_SIGNATURE_EXIT:-0}"\n',
        )
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

        macos_source = self._native_source("macos")
        linux_source = self._native_source("linux")
        self._executable(
            macos_source / "bin/li_installer_macos_probe",
            "#!/bin/sh\nexit 0\n",
        )
        checksums = []
        for identity, source in (
            ("macos_arm64", macos_source),
            ("linux_arm64", linux_source),
        ):
            archive = self.release / f"li_installer_{identity}.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                handle.add(source, arcname="installer")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            checksums.append(f"{digest}  {archive.name}\n")
        (self.release / "SHA256SUMS").write_text(
            "".join(checksums), encoding="ascii"
        )
        (self.release / "SHA256SUMS.sig").write_text("fixture\n", encoding="ascii")
        self.signers = self.root / "allowed_signers"
        self.signers.write_text("fixture\n", encoding="ascii")
        self.run_number = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    # Creates one exact native archive root with a fake Rust lifecycle owner.
    def _native_source(self, platform: str) -> pathlib.Path:
        root = self.root / f"native_{platform}" / "installer"
        (root / "bin").mkdir(parents=True)
        (root / "schemas").mkdir()
        self._executable(
            root / "bin/li_installer",
            """#!/bin/sh
printf '%s\n' "$@" >"$FAKE_HANDOFF_FILE"
platform=
version=
launcher_root=
run_setup=
progress=
temporary_root=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --selected-platform) platform=$2 ;;
        --release-version) version=$2 ;;
        --launcher-root) launcher_root=$2 ;;
        --run-setup) run_setup=$2 ;;
        --progress-enabled) progress=$2 ;;
        --temporary-root) temporary_root=$2 ;;
    esac
    shift 2
done
if [ "${FAKE_NATIVE_STATUS:-0}" -ne 0 ]; then
    printf '%s\n' "${FAKE_NATIVE_ERROR:-native failure}" >&2
    exit "$FAKE_NATIVE_STATUS"
fi
mkdir -p "$launcher_root"
printf '#!/bin/sh\nexit 0\n' >"$launcher_root/letsinfer"
chmod 0755 "$launcher_root/letsinfer"
if [ "$run_setup" = true ]; then
    : >"$FAKE_SETUP_MARKER"
    printf "Let's Infer %s installed and initialized for %s.\n" "$version" "$platform" >&2
else
    printf "Let's Infer %s installed for %s.\n" "$version" "$platform" >&2
fi
printf 'progress=%s\n' "$progress" >>"$FAKE_HANDOFF_FILE"
rm -rf -- "$temporary_root"
""",
        )
        (root / "schemas/li_installer_installation_probe_v1.schema.json").write_text(
            "{}\n", encoding="utf-8"
        )
        return root

    # Writes one deterministic executable fixture.
    @staticmethod
    def _executable(path: pathlib.Path, source: str) -> None:
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    # Returns one isolated bootstrap environment and its durable observations.
    def _environment(self, **updates: str) -> dict[str, str]:
        self.run_number += 1
        run_root = self.root / f"run_{self.run_number}"
        run_root.mkdir()
        environment = os.environ.copy()
        environment.pop("NO_COLOR", None)
        environment.update(
            {
                "FAKE_HANDOFF_FILE": str(run_root / "handoff"),
                "FAKE_SETUP_MARKER": str(run_root / "setup"),
                "FAKE_UNAME_M": "arm64",
                "FAKE_UNAME_S": "Darwin",
                "HOME": str(run_root / "home"),
                "LANG": "en_US.UTF-8",
                "LETSINFER_ALLOW_INSECURE_RELEASE_URL": "1",
                "LETSINFER_HOME": str(run_root / "letsinfer_home"),
                "LETSINFER_RELEASE_ALLOWED_SIGNERS_PATH": str(self.signers),
                "PATH": f"{self.fake_bin}:{environment.get('PATH', '')}",
                "TERM": "xterm-256color",
                "TEST_PREFIX": str(run_root / "prefix"),
            }
        )
        environment.update(updates)
        return environment

    # Returns one exact local release bootstrap command.
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

    # Runs the bootstrap through ordinary redirected streams.
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

    # Runs the bootstrap with a real terminal attached to stderr.
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

    def test_bootstrap_executes_native_installer_with_complete_handoff(self) -> None:
        environment = self._environment()
        result = self._run_pipe(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        handoff = pathlib.Path(environment["FAKE_HANDOFF_FILE"]).read_text(
            encoding="utf-8"
        )
        self.assertIn("--selected-platform\nmacos-arm64\n", handoff)
        self.assertIn("--core-archive-name\nletsinfer-macos-arm64.tar.gz\n", handoff)
        self.assertRegex(
            handoff,
            r"--release-allowed-signers-file\n"
            r"/tmp/letsinfer-install\.[^/\n]+/release-allowed-signers\n",
        )
        self.assertIn("--run-setup\ntrue\n", handoff)
        self.assertIn("--control-address\nauto\n", handoff)
        self.assertTrue(pathlib.Path(environment["FAKE_SETUP_MARKER"]).is_file())
        self.assertIn(
            "Let's Infer 1.2.3 installed and initialized for macos-arm64.",
            result.stderr,
        )

    def test_linux_selects_linux_native_archive_and_preserves_no_setup(self) -> None:
        environment = self._environment(FAKE_UNAME_S="Linux")
        result = self._run_pipe(environment, "--no-setup")

        self.assertEqual(result.returncode, 0, result.stderr)
        handoff = pathlib.Path(environment["FAKE_HANDOFF_FILE"]).read_text(
            encoding="utf-8"
        )
        self.assertIn("--selected-platform\nlinux-arm64\n", handoff)
        self.assertIn("--run-setup\nfalse\n", handoff)
        self.assertFalse(pathlib.Path(environment["FAKE_SETUP_MARKER"]).exists())

    # Proves the shell only forwards an explicit address for native validation and setup.
    def test_control_address_override_is_forwarded_to_the_native_installer(self) -> None:
        environment = self._environment()
        result = self._run_pipe(
            environment,
            "--control-address",
            "192.168.1.66",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        handoff = pathlib.Path(environment["FAKE_HANDOFF_FILE"]).read_text(
            encoding="utf-8"
        )
        self.assertIn("--control-address\n192.168.1.66\n", handoff)

    def test_signature_failure_precedes_native_archive_download(self) -> None:
        (self.release / "li_installer_macos_arm64.tar.gz").unlink()
        environment = self._environment(FAKE_SIGNATURE_EXIT="9")
        result = self._run_pipe(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release checksum signature is invalid", result.stderr)
        self.assertNotIn("native installer archive download failed", result.stderr)

    def test_missing_platform_archive_fails_before_native_execution(self) -> None:
        (self.release / "li_installer_macos_arm64.tar.gz").unlink()
        environment = self._environment()
        result = self._run_pipe(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native installer archive download failed", result.stderr)
        self.assertFalse(pathlib.Path(environment["FAKE_HANDOFF_FILE"]).exists())

    def test_native_checksum_failure_precedes_native_execution(self) -> None:
        (self.release / "li_installer_macos_arm64.tar.gz").write_bytes(b"corrupt")
        environment = self._environment()
        result = self._run_pipe(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native installer archive checksum is invalid", result.stderr)
        self.assertFalse(pathlib.Path(environment["FAKE_HANDOFF_FILE"]).exists())

    def test_native_archive_inventory_rejects_an_extra_file(self) -> None:
        source = self.root / "native_macos/installer"
        (source / "unexpected").write_text("unexpected\n", encoding="utf-8")
        archive = self.release / "li_installer_macos_arm64.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(source, arcname="installer")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksums = self.release / "SHA256SUMS"
        records = checksums.read_text(encoding="ascii").splitlines()
        checksums.write_text(
            "\n".join(
                f"{digest}  {archive.name}"
                if line.endswith(f"  {archive.name}")
                else line
                for line in records
            )
            + "\n",
            encoding="ascii",
        )
        environment = self._environment()
        result = self._run_pipe(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native installer archive inventory is invalid", result.stderr)
        self.assertFalse(pathlib.Path(environment["FAKE_HANDOFF_FILE"]).exists())

    def test_exec_propagates_native_failure_without_shell_resuming(self) -> None:
        environment = self._environment(
            FAKE_NATIVE_STATUS="7", FAKE_NATIVE_ERROR="native setup failed"
        )
        result = self._run_pipe(environment)

        self.assertEqual(result.returncode, 7)
        self.assertIn("native setup failed", result.stderr)
        self.assertNotIn("Installation failed", result.stderr)

    def test_no_progress_is_forwarded_to_native_installer(self) -> None:
        environment = self._environment()
        status, output = self._run_tty(environment, "--no-progress", "--no-setup")

        self.assertEqual(status, 0, output)
        handoff = pathlib.Path(environment["FAKE_HANDOFF_FILE"]).read_text(
            encoding="utf-8"
        )
        self.assertIn("--progress-enabled\nfalse\n", handoff)
        self.assertNotIn("  5%", output)

    def test_no_color_preserves_bootstrap_progress_without_color_sequences(self) -> None:
        environment = self._environment(NO_COLOR="1")
        status, output = self._run_tty(environment, "--no-setup")

        self.assertEqual(status, 0, output)
        self.assertIn("INSTALL", output)
        self.assertNotIn("38;2", output)

    def test_bootstrap_does_not_require_or_forward_python(self) -> None:
        environment = self._environment()
        result = self._run_pipe(environment, "--no-setup")

        self.assertEqual(result.returncode, 0, result.stderr)
        handoff = pathlib.Path(environment["FAKE_HANDOFF_FILE"]).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("--python-command", handoff)
        self.assertNotIn("python", INSTALLER.read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    unittest.main()
