#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""CI and documentation cannot drift away from the canonical suite."""

from __future__ import annotations

import pathlib
import re
import unittest

from tools import core_regression


ROOT = pathlib.Path(__file__).resolve().parents[2]


class SuiteContractTests(unittest.TestCase):
    def test_every_test_module_is_registered(self) -> None:
        core_regression.validate_inventory(ROOT)
        self.assertEqual(core_regression.unregistered_test_modules(ROOT), ())
        self.assertGreaterEqual(sum(map(len, core_regression.test_modules(ROOT).values())), 20)

    def test_pull_requests_and_branch_pushes_run_one_named_regression_gate(self) -> None:
        workflow = (ROOT / ".github/workflows/core-regression.yml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            workflow,
            r"push:\s*\n\s*branches:\s*\n\s*- main\s*\n\s*- release",
        )
        self.assertRegex(workflow, r"pull_request:\s*\n\s*branches:")
        self.assertIn("- main", workflow)
        self.assertIn("- release", workflow)
        self.assertIn("name: Core regression suite", workflow)
        self.assertIn("python3 -m tools.core_regression", workflow)
        self.assertIn("sh tests/li_installer/li_installer_run.sh", workflow)
        self.assertIn("cargo test --manifest-path core/Cargo.toml", workflow)
        self.assertNotIn("cmake -S watchdog", workflow)
        self.assertNotIn("ctest --test-dir", workflow)
        for used in re.findall(r"uses:\s*([^\s]+)", workflow):
            self.assertRegex(used.rsplit("@", 1)[-1], r"^[0-9a-f]{40}$")

    def test_release_validation_uses_the_same_runner(self) -> None:
        workflow = (ROOT / ".github/workflows/release-core.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("python3 -m tools.core_regression", workflow)
        self.assertIn("cargo test --manifest-path core/Cargo.toml", workflow)
        self.assertNotIn("cmake -S watchdog", workflow)
        self.assertNotIn("ctest --test-dir", workflow)
        self.assertNotIn("for suite in cli benchmarks gateway orchestration site", workflow)


if __name__ == "__main__":
    unittest.main()
