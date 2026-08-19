#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import base64
import hashlib
import pathlib
import subprocess
import tempfile
import unittest

from tools.sshsig import allowed_signers, envelope, signed_payload


MESSAGE = b"signed release checksums\n"
PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAF+yDlF/byhKEB7MKqs5WzMvDC3PsPZbu6jWFu2/yH8A=
-----END PUBLIC KEY-----
"""
RAW_SIGNATURE = base64.b64decode(
    b"NPfggC/vduLSJmjmQ/7ilvRF3M7wrDHt6JW8jdKs16EtLIGYOIJ9D4E4qZzR7xJc"
    b"3Qlra9CG/QCVm1SIXnaMDA==",
    validate=True,
)


class SSHSignatureTests(unittest.TestCase):
    def test_public_ed25519_vector_verifies_as_sshsig(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public_key = root / "key.pub.pem"
            public_key.write_bytes(PUBLIC_KEY)
            self.assertEqual(
                hashlib.sha256(signed_payload(MESSAGE)).hexdigest(),
                "82e653e1a43f2018ed2b88074658753d1da65451ac68cc6255ad77a0a064122c",
            )
            signature = root / "message.sig"
            signers = root / "allowed_signers"
            signature.write_bytes(envelope(public_key, RAW_SIGNATURE))
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
                input=MESSAGE,
                check=False,
                capture_output=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr.decode())

    def test_wrong_message_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public_key = root / "key.pub.pem"
            public_key.write_bytes(PUBLIC_KEY)
            signature = root / "message.sig"
            signers = root / "allowed_signers"
            signature.write_bytes(envelope(public_key, RAW_SIGNATURE))
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
