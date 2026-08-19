#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from tools.install_core import CoreInstallError, install


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
            self.addCleanup(self._restore_directory_modes, prefix)
            first = install(REPOSITORY_ROOT, prefix)
            second = install(REPOSITORY_ROOT, prefix)
            self.assertEqual(first, second)
            source = pathlib.Path(first["source_root"])
            self.assertTrue((prefix / "bin/letsinfer").is_symlink())
            self.assertEqual((prefix / "bin/letsinfer").resolve(), source / "bin/letsinfer")
            completed = subprocess.run(
                [str(prefix / "bin/letsinfer"), "--help"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Let's Infer", completed.stdout)
            self.assertEqual(
                json.loads((source / "SOURCE-MANIFEST.json").read_bytes())["product"],
                "letsinfer",
            )
            self.assertEqual(source.stat().st_mode & 0o777, 0o555)
            self.assertFalse((source / "AGENTS.md").exists())
            self.assertFalse((source / "letsinfer.md").exists())
            self.assertFalse((source / "context").exists())
            self.assertFalse((source / "scratchpad").exists())

    def test_existing_regular_launcher_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prefix = pathlib.Path(temporary) / "prefix"
            self.addCleanup(self._restore_directory_modes, prefix)
            launcher = prefix / "bin/letsinfer"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("user file\n", encoding="utf-8")
            with self.assertRaisesRegex(CoreInstallError, "non-symlink launcher"):
                install(REPOSITORY_ROOT, prefix)
            self.assertEqual(launcher.read_text(encoding="utf-8"), "user file\n")

    def test_installed_cli_preserves_the_callers_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            prefix = root / "prefix"
            self.addCleanup(self._restore_directory_modes, prefix)
            install(REPOSITORY_ROOT, prefix)
            runtime = root / "work" / "runtime"
            runtime.mkdir(parents=True)
            (runtime / "runtime.json").write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "name": "fixture/engine/target",
                        "version": "1.0.0",
                        "model": "fixture",
                        "engine": "engine",
                        "target": "target",
                        "status": "candidate",
                        "release_manifest": "release.json",
                        "core_compatibility": {"api": 2},
                    }
                ),
                encoding="utf-8",
            )
            (runtime / "release.json").write_text("{}\n", encoding="utf-8")
            output = root / "runtime.letsinfer"

            completed = subprocess.run(
                [str(prefix / "bin/letsinfer"), "pack", "runtime", "--output", str(output)],
                cwd=runtime.parent,
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "LETSINFER_CONFIG_HOME": str(root / "config"),
                    "LETSINFER_DATA_HOME": str(root / "data"),
                },
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
