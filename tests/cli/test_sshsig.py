#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest

from tools.sshsig import allowed_signers, envelope, signed_payload


class SSHSignatureTests(unittest.TestCase):
    def test_openssl_ed25519_signature_verifies_as_sshsig(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            private_key = root / "key.pem"
            public_key = root / "key.pub.pem"
            message = b"signed release checksums\n"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", private_key],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    private_key,
                    "-pubout",
                    "-out",
                    public_key,
                ],
                check=True,
                capture_output=True,
            )
            payload = root / "payload"
            payload.write_bytes(signed_payload(message))
            completed = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    private_key,
                    "-rawin",
                    "-in",
                    payload,
                ],
                check=True,
                capture_output=True,
            )
            signature = root / "message.sig"
            signers = root / "allowed_signers"
            signature.write_bytes(envelope(public_key, completed.stdout))
            signers.write_bytes(allowed_signers(public_key))
            verified = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    signers,
                    "-I",
                    "letsinfer-release",
                    "-n",
                    "letsinfer-release",
                    "-s",
                    signature,
                ],
                input=message,
                check=False,
                capture_output=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr.decode())

    def test_wrong_message_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            private_key = root / "key.pem"
            public_key = root / "key.pub.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", private_key],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key],
                check=True,
                capture_output=True,
            )
            payload = root / "payload"
            payload.write_bytes(signed_payload(b"expected\n"))
            raw = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    private_key,
                    "-rawin",
                    "-in",
                    payload,
                ],
                check=True,
                capture_output=True,
            ).stdout
            signature = root / "message.sig"
            signers = root / "allowed_signers"
            signature.write_bytes(envelope(public_key, raw))
            signers.write_bytes(allowed_signers(public_key))
            verified = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    signers,
                    "-I",
                    "letsinfer-release",
                    "-n",
                    "letsinfer-release",
                    "-s",
                    signature,
                ],
                input=b"tampered\n",
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(verified.returncode, 0)
