#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Create deterministic OpenSSH SSHSIG envelopes around OpenSSL signatures."""

from __future__ import annotations

import argparse
import base64
import hashlib
import pathlib
import struct
import subprocess
from collections.abc import Sequence


MAGIC = b"SSHSIG"
VERSION = 1
NAMESPACE = b"letsinfer-release"
HASH_ALGORITHM = b"sha512"
ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")


class SSHSignatureError(RuntimeError):
    """The release signature cannot be serialized safely."""


def _string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def signed_payload(message: bytes) -> bytes:
    return (
        MAGIC
        + _string(NAMESPACE)
        + _string(b"")
        + _string(HASH_ALGORITHM)
        + _string(hashlib.sha512(message).digest())
    )


def public_key_blob(public_key: pathlib.Path) -> bytes:
    completed = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise SSHSignatureError("release public key is unreadable")
    der = completed.stdout
    if not der.startswith(ED25519_DER_PREFIX) or len(der) != len(ED25519_DER_PREFIX) + 32:
        raise SSHSignatureError("release public key is not an Ed25519 key")
    return _string(b"ssh-ed25519") + _string(der[len(ED25519_DER_PREFIX) :])


def allowed_signers(public_key: pathlib.Path) -> bytes:
    encoded = base64.b64encode(public_key_blob(public_key)).decode("ascii")
    return f"letsinfer-release ssh-ed25519 {encoded}\n".encode()


def envelope(public_key: pathlib.Path, raw_signature: bytes) -> bytes:
    if len(raw_signature) != 64:
        raise SSHSignatureError("raw Ed25519 signature must be exactly 64 bytes")
    signature_blob = _string(b"ssh-ed25519") + _string(raw_signature)
    binary = (
        MAGIC
        + struct.pack(">I", VERSION)
        + _string(public_key_blob(public_key))
        + _string(NAMESPACE)
        + _string(b"")
        + _string(HASH_ALGORITHM)
        + _string(signature_blob)
    )
    body = base64.b64encode(binary).decode("ascii")
    lines = [body[index : index + 70] for index in range(0, len(body), 70)]
    return (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(lines)
        + "\n-----END SSH SIGNATURE-----\n"
    ).encode()


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--message", type=pathlib.Path, required=True)
    prepare.add_argument("--output", type=pathlib.Path, required=True)
    wrap = commands.add_parser("wrap")
    wrap.add_argument("--public-key", type=pathlib.Path, required=True)
    wrap.add_argument("--signature", type=pathlib.Path, required=True)
    wrap.add_argument("--output", type=pathlib.Path, required=True)
    signers = commands.add_parser("allowed-signers")
    signers.add_argument("--public-key", type=pathlib.Path, required=True)
    signers.add_argument("--output", type=pathlib.Path, required=True)
    parsed = parser.parse_args(arguments)
    if parsed.command == "prepare":
        value = signed_payload(parsed.message.read_bytes())
    elif parsed.command == "wrap":
        value = envelope(parsed.public_key, parsed.signature.read_bytes())
    else:
        value = allowed_signers(parsed.public_key)
    parsed.output.write_bytes(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
