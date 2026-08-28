#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from tools.li_installer_core import install
from tools.prune_core import CorePruneError, plan, prune


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _identity(version_root: pathlib.Path, marker: str) -> pathlib.Path:
    payload = (
        json.dumps(
            {"files": [], "marker": marker, "product": "letsinfer"},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    identity = hashlib.sha256(payload).hexdigest()
    root = version_root / identity
    root.mkdir(parents=True)
    manifest = root / "SOURCE-MANIFEST.json"
    manifest.write_bytes(payload)
    manifest.chmod(0o444)
    root.chmod(0o555)
    return root


class CorePruneTests(unittest.TestCase):
    def test_installed_cli_dry_run_then_prunes_after_confirmation_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            operator = pathlib.Path(temporary) / "operator"
            home = operator / "letsinfer-home"
            installed = install(
                REPOSITORY_ROOT,
                home,
                launcher_root=operator / ".local/bin",
            )
            old = _identity(home / "core/versions/0.10.0", "old")
            completed = subprocess.run(
                [installed["command"], "core-prune", "--dry-run", "--json"],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "HOME": str(operator),
                    "LETSINFER_HOME": str(home),
                },
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertTrue(payload["dry_run"])
            self.assertEqual(payload["core_identities"], [str(old.resolve())])
            self.assertTrue(old.is_dir())

            applied = subprocess.run(
                [installed["command"], "core-prune", "--json"],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "HOME": str(operator),
                    "LETSINFER_HOME": str(home),
                },
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertFalse(old.exists())
            self.assertTrue(pathlib.Path(installed["source_root"]).is_dir())

    def test_dry_run_lists_old_identities_without_deleting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "letsinfer-home"
            product = home / "core/versions"
            old = _identity(product / "1.0.0", "old")
            active = _identity(product / "1.1.0", "active")
            (home / "core/current").symlink_to(active)

            result = prune(active, letsinfer_home=home, dry_run=True)

            self.assertEqual(result["remove"], [str(old.resolve())])
            self.assertEqual(result["removed"], [])
            self.assertTrue(old.is_dir())
            self.assertTrue(active.is_dir())

    def test_prune_removes_old_identities_and_empty_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "letsinfer-home"
            product = home / "core/versions"
            old_version = product / "1.0.0"
            old = _identity(old_version, "old")
            active = _identity(product / "1.1.0", "active")
            (home / "core/current").symlink_to(active)

            result = prune(active, letsinfer_home=home)

            self.assertEqual(result["removed"], [str(old.resolve(strict=False))])
            self.assertFalse(old.exists())
            self.assertFalse(old_version.exists())
            self.assertTrue(active.is_dir())

    def test_plan_fails_closed_on_unexpected_store_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "letsinfer-home"
            product = home / "core/versions"
            active = _identity(product / "1.1.0", "active")
            (home / "core/current").symlink_to(active)
            (product / "manual-backup").mkdir()

            with self.assertRaisesRegex(CorePruneError, "unexpected core version"):
                plan(active, letsinfer_home=home)


if __name__ == "__main__":
    unittest.main()
