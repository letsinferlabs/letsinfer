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
    -s) printf '%s\\n' Darwin ;;
    -m) printf '%s\\n' arm64 ;;
    *) exit 2 ;;
esac
""",
        )
        self._executable(self.fake_bin / "ssh-keygen", "#!/bin/sh\nexit 0\n")
        self._executable(self.fake_bin / "launchctl", "#!/bin/sh\nexit 0\n")
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

        archive = self.release / "letsinfer-macos-arm64.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(self.source, arcname="letsinfer")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.release / "SHA256SUMS").write_text(
            f"{digest}  {archive.name}\n", encoding="ascii"
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
        environment = os.environ.copy()
        environment.pop("NO_COLOR", None)
        environment.update(
            {
                "FAKE_SETUP_ARGS_FILE": str(setup_args),
                "FAKE_SETUP_STDOUT": json.dumps(
                    {
                        "display_name": "Home",
                        "inference_endpoint": "http://home.local:8000/v1",
                        "api_key_file": "/private/key",
                    }
                )
                + "\n",
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
            "setup --json\n",
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


if __name__ == "__main__":
    unittest.main()
