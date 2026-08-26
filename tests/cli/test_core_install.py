#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from tools.install_core import CoreInstallError, install
from tests.runtime_fixture import runtime_candidate


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]


class CoreInstallTests(unittest.TestCase):
    def _restore_directory_modes(self, root: pathlib.Path) -> None:
        if not root.exists():
            return
        for path in root.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)

    def test_install_is_immutable_idempotent_and_exposes_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prefix = pathlib.Path(temporary) / "prefix"
            home = prefix / "share/letsinfer"
            launchers = prefix / "bin"
            self.addCleanup(self._restore_directory_modes, prefix)
            python = pathlib.Path(sys.executable).resolve()
            first = install(
                REPOSITORY_ROOT,
                home,
                launcher_root=launchers,
                python_executable=python,
            )
            second = install(
                REPOSITORY_ROOT,
                home,
                launcher_root=launchers,
                python_executable=python,
            )
            self.assertEqual(first, second)
            source = pathlib.Path(first["source_root"])
            self.assertTrue((launchers / "letsinfer").is_symlink())
            self.assertEqual((launchers / "letsinfer").resolve(), source / "bin/letsinfer")
            self.assertEqual((home / "core/current").resolve(), source)
            self.assertTrue((home / "core/python").is_symlink())
            self.assertEqual((home / "core/python").resolve(), python)
            completed = subprocess.run(
                [str(launchers / "letsinfer"), "--help"],
                check=False,
                capture_output=True,
                text=True,
                env={
                    key: value
                    for key, value in {
                        **os.environ,
                        "LETSINFER_HOME": str(home),
                    }.items()
                    if key != "LETSINFER_PYTHON"
                },
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Let's Infer", completed.stdout)
            self.assertEqual(
                json.loads((source / "SOURCE-MANIFEST.json").read_bytes())["product"],
                "letsinfer",
            )
            self.assertEqual(source.stat().st_mode & 0o777, 0o555)
            self.assertTrue((source / "bin/letsinfer-uninstall-core").is_file())
            self.assertTrue((source / "bin/letsinfer-prune-core").is_file())
            self.assertTrue((source / "tools/uninstall_core.py").is_file())
            self.assertTrue((source / "tools/prune_core.py").is_file())
            self.assertFalse((source / "AGENTS.md").exists())
            self.assertFalse((source / "letsinfer.md").exists())
            self.assertFalse((source / "context").exists())
            self.assertFalse((source / "scratchpad").exists())

    def test_invalid_python_fails_before_installation_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "share/letsinfer"
            with self.assertRaisesRegex(CoreInstallError, "absolute path"):
                install(
                    REPOSITORY_ROOT,
                    home,
                    python_executable=pathlib.Path("python3"),
                )
            self.assertFalse(home.exists())

    def test_existing_regular_launcher_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prefix = pathlib.Path(temporary) / "prefix"
            self.addCleanup(self._restore_directory_modes, prefix)
            launcher = prefix / "bin/letsinfer"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("user file\n", encoding="utf-8")
            with self.assertRaisesRegex(CoreInstallError, "non-symlink"):
                install(
                    REPOSITORY_ROOT,
                    prefix / "share/letsinfer",
                    launcher_root=prefix / "bin",
                )
            self.assertEqual(launcher.read_text(encoding="utf-8"), "user file\n")

    def test_installed_cli_preserves_the_callers_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            prefix = root / "prefix"
            home = prefix / "share/letsinfer"
            self.addCleanup(self._restore_directory_modes, prefix)
            install(REPOSITORY_ROOT, home, launcher_root=prefix / "bin")
            work = root / "work"
            work.mkdir()

            completed = subprocess.run(
                [str(prefix / "bin/letsinfer"), "--help"],
                cwd=work,
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "LETSINFER_HOME": str(root / "home"),
                },
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("letsinfer", completed.stdout)


if __name__ == "__main__":
    unittest.main()
