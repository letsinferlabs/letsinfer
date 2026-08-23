#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Signed revocation-ledger and active-catalog regressions."""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

from core import revocations
from tests.cli.test_catalog import CANDIDATE, catalog


class RevocationTests(unittest.TestCase):
    def ledger(self, source_digest: str, consensus: str) -> dict:
        return {
            "schema_version": 1,
            "sequence": 1,
            "generated_at_unix": 1_787_465_000,
            "revocations": [
                {
                    "runtime_oci_digest": source_digest,
                    "consensus_sha256": consensus,
                    "actor": {
                        "github_login": "letsinferlabs",
                        "github_id": 317451145,
                        "github_type": "Organization",
                    },
                    "revoked_at_unix": 1_787_465_000,
                    "reason_code": "structurally-invalid-evidence",
                    "verification_ids": ["7" * 64],
                    "replacement": None,
                }
            ],
        }

    def test_revoked_release_is_removed_from_active_selection_view(self) -> None:
        document = catalog()
        release = document["models"]["qwen3.8-27b"]["targets"]["dgx-spark"][
            "candidates"
        ][CANDIDATE]["releases"]["0.1.0-rc.12"]
        consensus = "8" * 64
        release["verification"] = {
            "method": "community-consensus-v1",
            "consensus_path": f"{CANDIDATE}/benchmark.consensus.json",
            "consensus_sha256": consensus,
            "verifiers": [],
        }
        digest = release["source"].rsplit("@", 1)[-1]
        active = revocations.apply_to_catalog(
            document, self.ledger(digest, consensus)
        )
        target = active["models"]["qwen3.8-27b"]["targets"]["dgx-spark"]
        self.assertEqual(target["candidates"], {})
        self.assertIsNone(target["recommended"])

    def test_signed_ledger_round_trip_uses_catalog_trust_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            private = root / "private.pem"
            public = root / "public.pem"
            document = root / "revocations.json"
            signature_path = root / "revocations.json.sig"
            document.write_bytes(revocations.canonical_bytes(revocations.empty_ledger()))
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(private)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                check=True,
                capture_output=True,
            )
            raw = root / "raw.sig"
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign", "-inkey", str(private),
                    "-rawin", "-in", str(document), "-out", str(raw),
                ],
                check=True,
                capture_output=True,
            )
            public_der = subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"],
                check=True,
                capture_output=True,
            ).stdout
            signature_path.write_bytes(
                revocations.canonical_bytes(
                    {
                        "schema_version": 1,
                        "algorithm": "ed25519",
                        "key_id_sha256": hashlib.sha256(public_der).hexdigest(),
                        "document_kind": "letsinfer.revocations",
                        "document_sha256": hashlib.sha256(document.read_bytes()).hexdigest(),
                        "signature_base64": base64.b64encode(raw.read_bytes()).decode(),
                    }
                )
            )
            loaded, _data, signature = revocations.load_ledger(
                str(document), public_key=public
            )
        self.assertEqual(loaded, revocations.empty_ledger())
        self.assertIsNotNone(signature)

    def test_ledger_rejects_duplicate_release_identity(self) -> None:
        ledger = self.ledger("sha256:" + "1" * 64, "2" * 64)
        ledger["revocations"].append(dict(ledger["revocations"][0]))
        with self.assertRaisesRegex(revocations.RevocationError, "repeats"):
            revocations.validate_ledger(ledger)


if __name__ == "__main__":
    unittest.main()
