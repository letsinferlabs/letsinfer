#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import gzip
import hashlib
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

from tools.source_archive import (
    LOCAL_ONLY_PATHS,
    PUBLIC_DIRECTORIES,
    PUBLIC_ROOT_FILES,
    RUST_TOOLCHAIN_CONTENT,
    RUST_TOOLCHAIN_NAME,
    SourceArchiveError,
    build_archive,
    verify_archive,
)


class SourceArchiveTests(unittest.TestCase):
    def _source(self, root: pathlib.Path) -> None:
        for name in PUBLIC_ROOT_FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            content = (
                RUST_TOOLCHAIN_CONTENT
                if name == RUST_TOOLCHAIN_NAME
                else f"{name}\n".encode()
            )
            path.write_bytes(content)
        for name in PUBLIC_DIRECTORIES:
            path = root / name
            path.mkdir(parents=True, exist_ok=True)
            (path / "source.txt").write_text(f"{name}\n", encoding="utf-8")

    def _write_custom_archive(
        self,
        output: pathlib.Path,
        relative: str,
        content: bytes,
        *,
        schema_version: object = 1,
        uname: str = "",
        canonical_manifest: bool = True,
        include_toolchain: bool = True,
    ) -> None:
        payloads = {relative: content}
        if include_toolchain and relative != RUST_TOOLCHAIN_NAME:
            payloads[RUST_TOOLCHAIN_NAME] = RUST_TOOLCHAIN_CONTENT
        records = [
            {
                "path": name,
                "bytes": len(payload),
                "mode": 0o644,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for name, payload in sorted(payloads.items())
        ]
        document = {
            "schema_version": schema_version,
            "product": "letsinfer",
            "files": records,
        }
        manifest = (
            json.dumps(document, sort_keys=True, separators=(",", ":"))
            if canonical_manifest
            else json.dumps(document, indent=2, sort_keys=True)
        ).encode() + b"\n"
        memory = io.BytesIO()
        with tarfile.open(fileobj=memory, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            directories = {"letsinfer"}
            for relative_path in payloads:
                parent = pathlib.PurePosixPath("letsinfer", relative_path).parent
                while parent.as_posix() != "letsinfer":
                    directories.add(parent.as_posix())
                    parent = parent.parent
            for name in sorted(set(directories), key=lambda item: (item.count("/"), item)):
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.mtime = 0
                archive.addfile(info)
            archive_payloads = {"SOURCE-MANIFEST.json": manifest, **payloads}
            for name, payload in archive_payloads.items():
                info = tarfile.TarInfo(f"letsinfer/{name}")
                info.mode = 0o644
                info.size = len(payload)
                info.mtime = 0
                info.uname = uname
                archive.addfile(info, io.BytesIO(payload))
        with output.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                compressed.write(memory.getvalue())

    def test_archive_is_deterministic_manifested_and_excludes_local_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self._source(root)
            for name in LOCAL_ONLY_PATHS:
                path = root / name
                if "." in name:
                    path.write_text("private\n", encoding="utf-8")
                else:
                    path.mkdir()
                    (path / "private.txt").write_text("private\n", encoding="utf-8")
            app = root / "apps" / "macos"
            app.mkdir(parents=True)
            (app / "source.swift").write_text("app\n", encoding="utf-8")
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"
            result = build_archive(root, first)
            self.assertEqual(result, build_archive(root, second))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first, "r:gz") as archive:
                names = {member.name for member in archive.getmembers()}
                toolchain = archive.extractfile(f"letsinfer/{RUST_TOOLCHAIN_NAME}")
                self.assertIsNotNone(toolchain)
                assert toolchain is not None
                self.assertEqual(toolchain.read(), RUST_TOOLCHAIN_CONTENT)
            for name in LOCAL_ONLY_PATHS:
                self.assertFalse(any(item == f"letsinfer/{name}" or item.startswith(f"letsinfer/{name}/") for item in names))
            self.assertFalse(
                any(item == "letsinfer/apps" or item.startswith("letsinfer/apps/") for item in names)
            )

    # Binds source creation and verification to one exact compiler declaration.
    def test_rust_toolchain_declaration_is_required_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self._source(root)
            (root / RUST_TOOLCHAIN_NAME).write_text(
                '[toolchain]\nchannel = "stable"\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                SourceArchiveError, "toolchain declaration is invalid"
            ):
                build_archive(root, root / "source.tar.gz")

            archive = root / "missing-toolchain.tar.gz"
            self._write_custom_archive(
                archive,
                "core/source.txt",
                b"safe\n",
                include_toolchain=False,
            )
            with self.assertRaisesRegex(
                SourceArchiveError, "toolchain declaration is missing"
            ):
                verify_archive(archive)

            self._write_custom_archive(
                archive,
                RUST_TOOLCHAIN_NAME,
                b'[toolchain]\nchannel = "1.97.0"\n',
            )
            with self.assertRaisesRegex(
                SourceArchiveError, "toolchain declaration is invalid"
            ):
                verify_archive(archive)

    def test_symlink_in_public_source_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self._source(root)
            (root / PUBLIC_DIRECTORIES[0] / "link").symlink_to("source.txt")
            with self.assertRaisesRegex(SourceArchiveError, "symlinks"):
                build_archive(root, root / "source.tar.gz")

    def test_sensitive_file_and_private_key_material_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self._source(root)
            sensitive = root / PUBLIC_DIRECTORIES[0] / "credential.pem"
            sensitive.write_text("fixture\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceArchiveError, "sensitive file"):
                build_archive(root, root / "source.tar.gz")
            sensitive.unlink()
            (root / PUBLIC_DIRECTORIES[0] / "source.txt").write_text(
                "-----BEGIN " + "PRIVATE KEY-----\nfixture\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(SourceArchiveError, "private key material"):
                build_archive(root, root / "source.tar.gz")

    def test_exact_public_trust_paths_are_the_only_pem_exceptions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self._source(root)
            trust = root / "core" / "trust"
            trust.mkdir()
            for name in ("catalog-public-key.pem", "release-public-key.pem"):
                (trust / name).write_text(
                    "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n",
                    encoding="utf-8",
                )
            build_archive(root, root / "source.tar.gz")

            (trust / "release-public-key.pem").write_text(
                "-----BEGIN " + "PRIVATE KEY-----\nfixture\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SourceArchiveError, "private key material"):
                build_archive(root, root / "source.tar.gz")

    def test_tampered_archive_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self._source(root)
            archive = root / "source.tar.gz"
            build_archive(root, archive)
            content = bytearray(archive.read_bytes())
            content[len(content) // 2] ^= 0x01
            archive.write_bytes(content)
            with self.assertRaises((SourceArchiveError, EOFError)):
                verify_archive(archive)

    def test_verifier_rejects_paths_outside_the_public_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "source.tar.gz"
            self._write_custom_archive(archive, "context/private.txt", b"private\n")
            with self.assertRaisesRegex(SourceArchiveError, "outside the allowlist"):
                verify_archive(archive)

    def test_verifier_rejects_the_retired_in_tree_skills_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "source.tar.gz"
            self._write_custom_archive(
                archive, "skills/legacy/SKILL.md", b"legacy\n"
            )
            with self.assertRaisesRegex(SourceArchiveError, "outside the allowlist"):
                verify_archive(archive)

    def test_verifier_rejects_boolean_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "source.tar.gz"
            self._write_custom_archive(
                archive,
                "core/source.txt",
                b"safe\n",
                schema_version=True,
            )
            with self.assertRaisesRegex(SourceArchiveError, "manifest identity"):
                verify_archive(archive)

    # Rejects semantic JSON aliases so the reported manifest digest names exact archived bytes.
    def test_verifier_rejects_noncanonical_manifest_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "source.tar.gz"
            self._write_custom_archive(
                archive,
                "core/source.txt",
                b"safe\n",
                canonical_manifest=False,
            )
            with self.assertRaisesRegex(SourceArchiveError, "not canonical JSON"):
                verify_archive(archive)

    def test_verifier_bounds_manifest_and_payload_before_unbounded_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "source.tar.gz"
            self._write_custom_archive(archive, "core/source.txt", b"payload\n")
            with mock.patch("tools.source_archive.MAX_PUBLIC_BYTES", 4):
                with self.assertRaisesRegex(SourceArchiveError, "byte limit"):
                    verify_archive(archive)
            with mock.patch("tools.source_archive.MAX_MANIFEST_BYTES", 8):
                with self.assertRaisesRegex(SourceArchiveError, "manifest exceeds"):
                    verify_archive(archive)

    def test_verifier_rejects_sensitive_content_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "source.tar.gz"
            self._write_custom_archive(
                archive,
                "core/source.txt",
                b"-----BEGIN " + b"PRIVATE KEY-----\nfixture\n",
            )
            with self.assertRaisesRegex(SourceArchiveError, "private key material"):
                verify_archive(archive)
            self._write_custom_archive(
                archive, "core/source.txt", b"safe\n", uname="unexpected-owner"
            )
            with self.assertRaisesRegex(SourceArchiveError, "metadata is not normalized"):
                verify_archive(archive)


if __name__ == "__main__":
    unittest.main()
