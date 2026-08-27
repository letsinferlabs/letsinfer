#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import pathlib
import tempfile
import unittest

from core.orchestration.credentials import (
    PlacementGroupCredentialError,
    credential_sha256,
    derive_placement_group_credential,
    ensure_master,
)


class GroupCredentialTests(unittest.TestCase):
    def test_master_is_private_and_derivation_is_stable_and_group_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "config" / "group.key"
            master = ensure_master(path)
            self.assertEqual(master, ensure_master(path))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            first = derive_placement_group_credential("1" * 32, master=master)
            self.assertEqual(first, derive_placement_group_credential("1" * 32, master=master))
            self.assertNotEqual(first, derive_placement_group_credential("2" * 32, master=master))
            self.assertRegex(credential_sha256(first), r"^[0-9a-f]{64}$")

    def test_invalid_master_fails_closed(self) -> None:
        with self.assertRaisesRegex(PlacementGroupCredentialError, "master"):
            derive_placement_group_credential("1" * 32, master=b"short")


if __name__ == "__main__":
    unittest.main()
