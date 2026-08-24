#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Community runtime-verification identities, evidence, and GitHub transport.

This module deliberately keeps GitHub credentials outside runtime processes.
Every GitHub operation is delegated to the authenticated ``gh`` executable;
Let's Infer never reads, copies, or persists its token.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import gzip
import hashlib
import io
import json
import math
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Collection, Mapping, Sequence
from typing import Any, BinaryIO

from benchmarks.benchmark_record import BenchmarkRecordError, validate_record

from .paths import ensure_private_directory, secrets_root
from .runtime_packs import PACK_MEDIA_TYPE, canonical_bytes


SCHEMA_VERSION = 1
COMMENT_LIMIT_BYTES = 60_000
MAX_EXPANDED_EVIDENCE_BYTES = 4 << 20
MIN_GH_VERSION = (2, 97, 0)
REPOSITORY = "letsinferlabs/runtimes"
FINALIZER_CERT_IDENTITY = (
    "https://github.com/letsinferlabs/runtimes/"
    ".github/workflows/finalize-verifier.yml@refs/heads/main"
)
COMMENT_MARKER = "letsinfer-verification:v1"
KIND = "letsinfer.runtime-verification"
FAILURE_CATEGORIES = {
    "crash",
    "out_of_memory",
    "protection_trip",
    "output_validation",
    "incomplete_workload",
    "restoration",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
OCI_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
OCI_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
OCI_INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
OCI_CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
OCI_GZIP_LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
OCI_TAR_LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar",
}
MAX_ENGINE_LAYOUT_BYTES = 16 << 30
MAX_ENGINE_ROOTFS_BYTES = 64 << 30
MAX_GHCR_LAYER_BYTES = 10_000_000_000
PR_URL_RE = re.compile(
    r"https://github\.com/letsinferlabs/runtimes/pull/([1-9][0-9]*)(?:/)?"
)
CANDIDATE_RE = re.compile(
    r"[a-z0-9][a-z0-9._-]*--[a-z0-9][a-z0-9._-]*--"
    r"[a-z0-9][a-z0-9._-]*--[a-z0-9][a-z0-9._-]*"
)


class VerificationError(RuntimeError):
    """A verification precondition, identity, or evidence contract failed."""


@dataclasses.dataclass(frozen=True)
class GitHubIdentity:
    login: str
    numeric_id: int
    account_type: str

    def document(self) -> dict[str, Any]:
        return {
            "github_login": self.login,
            "github_id": self.numeric_id,
            "github_type": self.account_type,
        }


@dataclasses.dataclass(frozen=True)
class PullRequest:
    number: int
    url: str
    state: str
    base_ref: str
    base_sha: str
    head_sha: str
    author: GitHubIdentity
    files: tuple[str, ...]
    labels: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    key_id: str
    public_key_pem: str
    private_key: pathlib.Path


@dataclasses.dataclass(frozen=True)
class VerifierBundle:
    root: pathlib.Path
    document: dict[str, Any]
    runtime_pack: pathlib.Path
    engine_archive: pathlib.Path | None
    engine_config_digest: str | None
    engine_tag: str | None

    @property
    def subject(self) -> dict[str, Any]:
        return dict(self.document["subject"])


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def parse_pr_url(value: str) -> int:
    match = PR_URL_RE.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        raise VerificationError(
            "verification requires an open https://github.com/"
            "letsinferlabs/runtimes/pull/NUMBER URL"
        )
    return int(match[1])


def _run(
    command: Sequence[str],
    *,
    input_bytes: bytes | None = None,
    check: bool = True,
    limit: int = 4 << 20,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(command),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=None if environment is None else dict(environment),
        )
    except OSError as error:
        raise VerificationError(f"cannot run {command[0]}: {error}") from error
    if len(result.stdout) > limit or len(result.stderr) > limit:
        raise VerificationError(f"{command[0]} output exceeded its bounded limit")
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise VerificationError(
            f"{' '.join(command[:3])} failed"
            + (f": {detail}" if detail else "")
        )
    return result


def _json_output(command: Sequence[str]) -> dict[str, Any]:
    result = _run(command)
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{command[0]} returned invalid JSON") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{command[0]} returned a non-object response")
    return value


def gh_version(executable: str = "gh") -> tuple[int, int, int] | None:
    path = shutil.which(executable)
    if path is None:
        return None
    result = _run([path, "--version"], check=False, limit=64 << 10)
    if result.returncode != 0:
        return None
    match = re.search(rb"gh version ([0-9]+)\.([0-9]+)\.([0-9]+)", result.stdout)
    return tuple(map(int, match.groups())) if match is not None else None


def gh_install_command() -> list[str] | None:
    """Return one allowlisted system-package command, never a curl pipeline."""

    if platform.system() == "Darwin" and shutil.which("brew"):
        return ["brew", "install", "gh"]
    if platform.system() != "Linux":
        return None
    choices = (
        ("apt-get", ["sudo", "apt-get", "install", "-y", "gh"]),
        ("dnf", ["sudo", "dnf", "install", "-y", "gh"]),
        ("zypper", ["sudo", "zypper", "--non-interactive", "install", "gh"]),
        ("pacman", ["sudo", "pacman", "--noconfirm", "-S", "github-cli"]),
    )
    return next((command for binary, command in choices if shutil.which(binary)), None)


def ensure_gh(*, interactive: bool, install: bool = False) -> str:
    version = gh_version()
    if version is None:
        command = gh_install_command()
        instruction = (
            " ".join(command)
            if command is not None
            else "install GitHub CLI from https://cli.github.com/"
        )
        if not interactive or not install or command is None:
            raise VerificationError(
                f"GitHub CLI is required; run `{instruction}` and retry"
            )
        _run(command)
        version = gh_version()
    if version is None or version < MIN_GH_VERSION:
        required = ".".join(map(str, MIN_GH_VERSION))
        actual = "unavailable" if version is None else ".".join(map(str, version))
        raise VerificationError(
            f"GitHub CLI {required} or newer is required (found {actual})"
        )
    path = shutil.which("gh")
    if path is None:
        raise VerificationError("GitHub CLI disappeared after validation")
    return path


def github_identity(
    *, interactive: bool, install_gh: bool = False, authenticate: bool = False
) -> GitHubIdentity:
    gh = ensure_gh(interactive=interactive, install=install_gh)
    status = _run([gh, "auth", "status", "--hostname", "github.com"], check=False)
    if status.returncode != 0:
        if not interactive or not authenticate:
            raise VerificationError(
                "GitHub CLI is not authenticated; run `gh auth login --hostname "
                "github.com --git-protocol https --web` and retry"
            )
        # The GitHub CLI owns browser/device-code UX and its credential store.
        _run(
            [
                gh,
                "auth",
                "login",
                "--hostname",
                "github.com",
                "--git-protocol",
                "https",
                "--web",
            ]
        )
        _run([gh, "auth", "status", "--hostname", "github.com"])
    value = _json_output([gh, "api", "user"])
    login, numeric_id, account_type = (
        value.get("login"),
        value.get("id"),
        value.get("type"),
    )
    if (
        not isinstance(login, str)
        or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", login) is None
        or not isinstance(numeric_id, int)
        or isinstance(numeric_id, bool)
        or numeric_id <= 0
        or account_type != "User"
    ):
        raise VerificationError("authenticated GitHub identity is not a user account")
    return GitHubIdentity(login, numeric_id, account_type)


def pull_request(url: str, *, gh: str | None = None) -> PullRequest:
    number = parse_pr_url(url)
    executable = gh or ensure_gh(interactive=False)
    value = _json_output(
        [
            executable,
            "pr",
            "view",
            url,
            "--repo",
            REPOSITORY,
            "--json",
            "number,url,state,baseRefName,baseRefOid,headRefOid,author,files,labels",
        ]
    )
    author = value.get("author")
    files = value.get("files")
    if (
        value.get("number") != number
        or value.get("url") != f"https://github.com/{REPOSITORY}/pull/{number}"
        or value.get("state") != "OPEN"
        or value.get("baseRefName") != "main"
        or not isinstance(value.get("baseRefOid"), str)
        or re.fullmatch(r"[0-9a-f]{40}", value["baseRefOid"]) is None
        or not isinstance(value.get("headRefOid"), str)
        or re.fullmatch(r"[0-9a-f]{40}", value["headRefOid"]) is None
        or not isinstance(author, dict)
        or not isinstance(files, list)
    ):
        raise VerificationError("pull request is closed, deleted, or has invalid identity")
    author_login = author.get("login")
    if not isinstance(author_login, str) or not author_login:
        raise VerificationError("pull-request author identity is unavailable")
    resolved_author = _json_output([executable, "api", f"users/{author_login}"])
    author_identity = GitHubIdentity(
        str(resolved_author.get("login")),
        (
            int(resolved_author["id"])
            if isinstance(resolved_author.get("id"), int)
            else -1
        ),
        str(resolved_author.get("type")),
    )
    if (
        author_identity.numeric_id <= 0
        or author_identity.account_type not in {"User", "Organization"}
    ):
        raise VerificationError("pull-request author identity is invalid")
    names: list[str] = []
    for item in files:
        name = item.get("path") if isinstance(item, dict) else None
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 1024:
            raise VerificationError("pull request contains an invalid file path")
        names.append(name)
    return PullRequest(
        number,
        value["url"],
        value["state"],
        value["baseRefName"],
        value["baseRefOid"],
        value["headRefOid"],
        author_identity,
        tuple(names),
        tuple(sorted(
            str(item["name"])
            for item in value.get("labels", [])
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )),
    )


def changed_candidates(pr: PullRequest) -> tuple[str, ...]:
    candidates = {
        name.split("/", 1)[0]
        for name in pr.files
        if "/" in name and not name.startswith((".", "tools/", "tests/"))
    }
    invalid = sorted(name for name in candidates if CANDIDATE_RE.fullmatch(name) is None)
    if invalid:
        raise VerificationError(
            f"pull request changes a non-candidate top-level path: {invalid[0]}"
        )
    return tuple(sorted(candidates))


def select_candidate(pr: PullRequest, requested: str | None) -> str:
    values = changed_candidates(pr)
    if requested is not None:
        if requested not in values:
            raise VerificationError("--candidate is not changed by this pull request")
        return requested
    if len(values) != 1:
        choices = ", ".join(values) if values else "none"
        raise VerificationError(
            f"pull request candidate is ambiguous ({choices}); use --candidate"
        )
    return values[0]


def _safe_tar_member(name: str) -> pathlib.PurePosixPath:
    value = pathlib.PurePosixPath(name)
    if value.is_absolute() or any(part in {"", ".", ".."} for part in value.parts):
        raise VerificationError(f"pull-request archive contains unsafe path: {name}")
    return value


def extract_repository_archive(
    archive: BinaryIO, destination: pathlib.Path
) -> pathlib.Path:
    """Extract a GitHub tarball without links, devices, or path traversal."""

    ensure_private_directory(destination)
    try:
        source = tarfile.open(fileobj=archive, mode="r|gz")
    except tarfile.TarError as error:
        raise VerificationError("pull-request archive is invalid") from error
    roots: set[str] = set()
    count = 0
    expanded = 0
    try:
        for member in source:
            count += 1
            if count > 100_000:
                raise VerificationError("pull-request archive has too many entries")
            relative = _safe_tar_member(member.name)
            roots.add(relative.parts[0])
            if len(roots) != 1:
                raise VerificationError("pull-request archive has multiple roots")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise VerificationError("pull-request archive contains a special file")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(mode=0o700, exist_ok=True)
                continue
            if not member.isfile() or member.size < 0:
                raise VerificationError("pull-request archive contains an unsupported entry")
            expanded += member.size
            if expanded > (8 << 30):
                raise VerificationError("pull-request archive exceeds 8 GiB")
            extracted = source.extractfile(member)
            if extracted is None:
                raise VerificationError("pull-request archive entry is unreadable")
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                shutil.copyfileobj(extracted, output, length=1024 * 1024)
    except (OSError, tarfile.TarError) as error:
        raise VerificationError(f"cannot extract pull-request archive: {error}") from error
    if not roots:
        raise VerificationError("pull-request archive is empty")
    return destination / next(iter(roots))


def fetch_pull_request(pr: PullRequest, destination: pathlib.Path, *, gh: str) -> pathlib.Path:
    archive = destination / "source.tar.gz"
    ensure_private_directory(destination)
    descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            result = subprocess.run(
                [gh, "api", f"repos/{REPOSITORY}/tarball/{pr.head_sha}"],
                stdout=output,
                stderr=subprocess.PIPE,
                check=False,
            )
        if result.returncode != 0:
            raise VerificationError(
                "cannot download the exact pull-request head: "
                + result.stderr.decode("utf-8", errors="replace").strip()
            )
        with archive.open("rb") as handle:
            root = extract_repository_archive(handle, destination / "source")
    finally:
        archive.unlink(missing_ok=True)
    return root


def _download_api_file(gh: str, endpoint: str, destination: pathlib.Path) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            result = subprocess.run(
                [gh, "api", endpoint],
                stdout=output,
                stderr=subprocess.PIPE,
                check=False,
            )
        if result.returncode != 0:
            raise VerificationError(
                "cannot download the exact verifier artifact: "
                + result.stderr.decode("utf-8", errors="replace").strip()
            )
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def extract_verifier_artifact(archive: pathlib.Path, destination: pathlib.Path) -> None:
    """Extract a GitHub artifact zip with an exact flat, regular file surface."""

    ensure_private_directory(destination)
    total = 0
    seen: set[str] = set()
    try:
        source = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as error:
        raise VerificationError("verifier artifact is not a valid zip archive") from error
    with source:
        records = source.infolist()
        if not records or len(records) > 32:
            raise VerificationError("verifier artifact file count is invalid")
        for record in records:
            path = pathlib.PurePosixPath(record.filename)
            if (
                path.is_absolute()
                or len(path.parts) != 1
                or any(part in {"", ".", ".."} for part in path.parts)
                or record.is_dir()
            ):
                raise VerificationError("verifier artifact contains an unsafe path")
            mode = record.external_attr >> 16
            if mode and not stat.S_ISREG(mode):
                raise VerificationError("verifier artifact contains a special file")
            if record.filename in seen:
                raise VerificationError("verifier artifact contains duplicate files")
            seen.add(record.filename)
            total += record.file_size
            if total > (20 << 30) or record.compress_size > (20 << 30):
                raise VerificationError("verifier artifact exceeds the 20 GiB limit")
            target = destination / record.filename
            with source.open(record) as incoming, target.open("xb") as output:
                shutil.copyfileobj(incoming, output, 1024 * 1024)
            target.chmod(0o600)


def verify_bundle_attestations(root: pathlib.Path, *, gh: str) -> None:
    """Require provenance from the trusted main-branch finalizer for every file."""

    paths = sorted(root.iterdir(), key=lambda value: value.name)
    if not paths or any(path.is_symlink() or not path.is_file() for path in paths):
        raise VerificationError("verifier artifact contains a non-regular entry")
    environment = None
    attestation_token = os.environ.get("LETSINFER_ATTESTATION_TOKEN")
    if attestation_token:
        environment = dict(os.environ)
        environment["GH_TOKEN"] = attestation_token
    for path in paths:
        _run(
            [
                gh,
                "attestation",
                "verify",
                str(path),
                "--repo",
                REPOSITORY,
                "--cert-identity",
                FINALIZER_CERT_IDENTITY,
            ],
            environment=environment,
        )


def _bundle_object(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"verifier artifact {path.name} is invalid") from error
    if not isinstance(value, dict):
        raise VerificationError(f"verifier artifact {path.name} must be an object")
    return value


def _oci_descriptor(value: Any, where: str) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or not isinstance(value.get("mediaType"), str)
        or OCI_DIGEST_RE.fullmatch(str(value.get("digest"))) is None
        or not isinstance(value.get("size"), int)
        or isinstance(value.get("size"), bool)
        or value["size"] < 0
    ):
        raise VerificationError(f"verifier Engine {where} descriptor is invalid")
    return dict(value)


def _oci_object(data: bytes, where: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"verifier Engine {where} is invalid JSON") from error
    if not isinstance(value, dict):
        raise VerificationError(f"verifier Engine {where} must contain an object")
    return value


def _extract_engine_layout(archive: pathlib.Path, destination: pathlib.Path) -> None:
    total = 0
    seen: set[str] = set()
    try:
        source = tarfile.open(archive, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise VerificationError("verifier Engine OCI layout is invalid") from error
    with source:
        try:
            for count, member in enumerate(source, start=1):
                if count > 100_000:
                    raise VerificationError("verifier Engine OCI layout has too many entries")
                path = pathlib.PurePosixPath(member.name)
                if path.is_absolute() or any(
                    part in {"", ".", ".."} for part in path.parts
                ):
                    raise VerificationError("verifier Engine OCI layout has an unsafe path")
                name = path.as_posix()
                if name in seen:
                    raise VerificationError("verifier Engine OCI layout has duplicate entries")
                seen.add(name)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise VerificationError("verifier Engine OCI layout has a special entry")
                target = destination.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                if not member.isfile() or member.size < 0:
                    raise VerificationError("verifier Engine OCI layout entry is unsupported")
                total += member.size
                if total > MAX_ENGINE_LAYOUT_BYTES:
                    raise VerificationError("verifier Engine OCI layout exceeds 16 GiB")
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                incoming = source.extractfile(member)
                if incoming is None:
                    raise VerificationError("verifier Engine OCI layout entry is unreadable")
                with target.open("xb") as output:
                    shutil.copyfileobj(incoming, output, 1024 * 1024)
                target.chmod(0o600)
        except (OSError, tarfile.TarError) as error:
            raise VerificationError(
                f"cannot extract verifier Engine OCI layout: {error}"
            ) from error


def _oci_blob(
    root: pathlib.Path, descriptor: Mapping[str, Any], where: str, *, limit: int | None = None
) -> tuple[pathlib.Path, bytes | None]:
    item = _oci_descriptor(descriptor, where)
    path = root / "blobs" / "sha256" / str(item["digest"]).removeprefix("sha256:")
    if path.is_symlink() or not path.is_file() or path.stat().st_size != item["size"]:
        raise VerificationError(f"verifier Engine {where} blob is unavailable")
    if "sha256:" + sha256_file(path) != item["digest"]:
        raise VerificationError(f"verifier Engine {where} blob digest differs")
    if limit is not None:
        if item["size"] > limit:
            raise VerificationError(f"verifier Engine {where} blob is too large")
        return path, path.read_bytes()
    return path, None


def _inspect_engine_layout(
    root: pathlib.Path, expected_platform: str
) -> tuple[dict[str, Any], bytes, tuple[dict[str, Any], ...], tuple[str, ...]]:
    try:
        expected_os, expected_architecture = expected_platform.split("/", 1)
    except ValueError as error:
        raise VerificationError("verifier Engine platform is invalid") from error
    if not expected_os or not expected_architecture:
        raise VerificationError("verifier Engine platform is invalid")
    try:
        layout_data = (root / "oci-layout").read_bytes()
        index_data = (root / "index.json").read_bytes()
    except OSError as error:
        raise VerificationError("verifier Engine OCI metadata is unavailable") from error
    if _oci_object(layout_data, "OCI layout") != {"imageLayoutVersion": "1.0.0"}:
        raise VerificationError("verifier Engine OCI layout version is unsupported")
    index = _oci_object(index_data, "OCI index")
    manifests = index.get("manifests")
    if index.get("schemaVersion") != 2 or not isinstance(manifests, list):
        raise VerificationError("verifier Engine OCI index is invalid")

    def select(values: Sequence[Any], where: str) -> dict[str, Any]:
        selected = []
        for offset, raw in enumerate(values):
            item = _oci_descriptor(raw, f"{where} manifest {offset}")
            item_platform = item.get("platform")
            if isinstance(item_platform, Mapping) and (
                item_platform.get("os"), item_platform.get("architecture")
            ) == (expected_os, expected_architecture):
                selected.append(item)
            elif (
                len(values) == 1
                and not isinstance(item_platform, Mapping)
                and item["mediaType"] in OCI_MANIFEST_MEDIA_TYPES
            ):
                selected.append(item)
        if len(selected) != 1:
            raise VerificationError(
                "verifier Engine OCI layout does not contain exactly one target platform"
            )
        return selected[0]

    manifest_descriptor = select(manifests, "index")
    _manifest_path, manifest_data = _oci_blob(
        root, manifest_descriptor, "platform object", limit=4 << 20
    )
    assert manifest_data is not None
    if manifest_descriptor["mediaType"] in OCI_INDEX_MEDIA_TYPES:
        nested = _oci_object(manifest_data, "nested OCI index")
        nested_manifests = nested.get("manifests")
        if nested.get("schemaVersion") != 2 or not isinstance(nested_manifests, list):
            raise VerificationError("verifier Engine nested OCI index is invalid")
        manifest_descriptor = select(nested_manifests, "nested index")
        _manifest_path, manifest_data = _oci_blob(
            root, manifest_descriptor, "platform manifest", limit=4 << 20
        )
        assert manifest_data is not None
    if manifest_descriptor["mediaType"] not in OCI_MANIFEST_MEDIA_TYPES:
        raise VerificationError("verifier Engine platform object is not an image manifest")
    manifest = _oci_object(manifest_data, "image manifest")
    config_descriptor = _oci_descriptor(manifest.get("config"), "configuration")
    layers = manifest.get("layers")
    if (
        manifest.get("schemaVersion") != 2
        or config_descriptor["mediaType"] not in OCI_CONFIG_MEDIA_TYPES
        or not isinstance(layers, list)
        or not layers
    ):
        raise VerificationError("verifier Engine image manifest is invalid")
    _config_path, config_data = _oci_blob(
        root, config_descriptor, "configuration", limit=4 << 20
    )
    assert config_data is not None
    config = _oci_object(config_data, "configuration")
    if (config.get("os"), config.get("architecture")) != (
        expected_os,
        expected_architecture,
    ):
        raise VerificationError("verifier Engine configuration platform differs")
    rootfs = config.get("rootfs")
    diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, Mapping) else None
    if (
        not isinstance(rootfs, Mapping)
        or rootfs.get("type") != "layers"
        or not isinstance(diff_ids, list)
        or len(diff_ids) != len(layers)
        or any(OCI_DIGEST_RE.fullmatch(str(value)) is None for value in diff_ids)
    ):
        raise VerificationError("verifier Engine rootfs identity is invalid")
    layer_descriptors: list[dict[str, Any]] = []
    for offset, raw in enumerate(layers):
        layer = _oci_descriptor(raw, f"layer {offset}")
        if layer["mediaType"] not in OCI_GZIP_LAYER_MEDIA_TYPES | OCI_TAR_LAYER_MEDIA_TYPES:
            raise VerificationError("verifier Engine layer compression is unsupported")
        if layer["size"] > MAX_GHCR_LAYER_BYTES:
            raise VerificationError("verifier Engine layer exceeds GHCR's 10 GB limit")
        _oci_blob(root, layer, f"layer {offset}")
        layer_descriptors.append(layer)
    identity = {
        "platform": expected_platform,
        "manifest_digest": manifest_descriptor["digest"],
        "manifest_bytes": len(manifest_data),
        "config_digest": config_descriptor["digest"],
        "layer_digests": [value["digest"] for value in layer_descriptors],
    }
    return identity, config_data, tuple(layer_descriptors), tuple(map(str, diff_ids))


def _oci_archive_identity(
    archive: pathlib.Path,
    *,
    expected_manifest: str,
    expected_config: str,
    expected_platform: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="letsinfer-engine-oci-") as temporary:
        root = pathlib.Path(temporary)
        _extract_engine_layout(archive, root)
        identity, _config, _layers, _diff_ids = _inspect_engine_layout(
            root, expected_platform
        )
    if (
        identity["manifest_digest"] != expected_manifest
        or identity["config_digest"] != expected_config
    ):
        raise VerificationError("verifier Engine OCI identity differs")
    return identity


def _tar_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int = 0o600) -> None:
    item = tarfile.TarInfo(name)
    item.size = len(data)
    item.mode = mode
    item.mtime = 0
    archive.addfile(item, io.BytesIO(data))


def _docker_archive_from_oci(
    source_archive: pathlib.Path,
    destination: pathlib.Path,
    *,
    expected_manifest: str,
    expected_config: str,
    expected_platform: str,
    tag: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="letsinfer-engine-convert-") as temporary:
        root = pathlib.Path(temporary)
        _extract_engine_layout(source_archive, root)
        identity, config_data, layers, diff_ids = _inspect_engine_layout(
            root, expected_platform
        )
        if (
            identity["manifest_digest"] != expected_manifest
            or identity["config_digest"] != expected_config
        ):
            raise VerificationError("verifier Engine OCI identity changed before import")
        layer_names: list[str] = []
        expanded = 0
        try:
            with tarfile.open(destination, "x") as output:
                config_name = expected_config.removeprefix("sha256:") + ".json"
                _tar_bytes(output, config_name, config_data)
                for offset, (layer, diff_id) in enumerate(zip(layers, diff_ids)):
                    blob = root / "blobs" / "sha256" / str(layer["digest"]).removeprefix("sha256:")
                    expanded_layer = root / f"docker-layer-{offset}.tar"
                    hasher = hashlib.sha256()
                    opener = gzip.open if layer["mediaType"] in OCI_GZIP_LAYER_MEDIA_TYPES else open
                    with opener(blob, "rb") as incoming, expanded_layer.open("xb") as layer_output:
                        while True:
                            chunk = incoming.read(1024 * 1024)
                            if not chunk:
                                break
                            expanded += len(chunk)
                            if expanded > MAX_ENGINE_ROOTFS_BYTES:
                                raise VerificationError(
                                    "verifier Engine rootfs exceeds the 64 GiB conversion limit"
                                )
                            hasher.update(chunk)
                            layer_output.write(chunk)
                    if "sha256:" + hasher.hexdigest() != diff_id:
                        raise VerificationError(
                            f"verifier Engine layer {offset} differs from its rootfs identity"
                        )
                    layer_name = f"{offset}/layer.tar"
                    layer_names.append(layer_name)
                    info = output.gettarinfo(str(expanded_layer), arcname=layer_name)
                    info.mode = 0o600
                    info.mtime = 0
                    with expanded_layer.open("rb") as layer_input:
                        output.addfile(info, layer_input)
                    expanded_layer.unlink()
                manifest = canonical_bytes(
                    [{"Config": config_name, "RepoTags": [tag], "Layers": layer_names}]
                )
                _tar_bytes(output, "manifest.json", manifest)
        except (OSError, tarfile.TarError, gzip.BadGzipFile) as error:
            destination.unlink(missing_ok=True)
            raise VerificationError(
                f"cannot convert verifier Engine OCI layout for Docker: {error}"
            ) from error


def validate_verifier_bundle(
    root: pathlib.Path, *, pr: PullRequest, candidate: str
) -> VerifierBundle:
    document = _bundle_object(root / "bundle.json")
    proposal_base = document.get("proposal_base_sha")
    build_workflow = document.get("build_workflow")
    finalizer_workflow = document.get("finalizer_workflow")
    if (
        document.get("schema_version") != 1
        or document.get("repository") != REPOSITORY
        or document.get("pull_request") != pr.number
        or document.get("proposal_head_sha") != pr.head_sha
        or document.get("candidate") != candidate
        or document.get("artifact_name")
        != f"verification-bundle-pr-{pr.number}-{pr.head_sha}"
        or proposal_base != pr.base_sha
        or not isinstance(build_workflow, dict)
        or build_workflow.get("path") != ".github/workflows/build-verifier.yml"
        or not isinstance(build_workflow.get("run_id"), int)
        or build_workflow["run_id"] <= 0
        or build_workflow.get("workflow_sha") != proposal_base
        or not isinstance(finalizer_workflow, dict)
        or finalizer_workflow.get("path")
        != ".github/workflows/finalize-verifier.yml"
        or not isinstance(finalizer_workflow.get("run_id"), int)
        or finalizer_workflow["run_id"] <= 0
        or re.fullmatch(
            r"[0-9a-f]{40}", str(finalizer_workflow.get("workflow_sha"))
        )
        is None
    ):
        raise VerificationError("verifier artifact does not identify the current proposal")
    authors = document.get("runtime_authors")
    if not isinstance(authors, list) or not authors:
        raise VerificationError("verifier artifact runtime authors are unavailable")
    author_ids: set[int] = set()
    for author in authors:
        if (
            not isinstance(author, dict)
            or set(author) != {"github_login", "github_id", "github_type"}
            or not isinstance(author.get("github_login"), str)
            or not author["github_login"]
            or not isinstance(author.get("github_id"), int)
            or isinstance(author.get("github_id"), bool)
            or author["github_id"] <= 0
            or author.get("github_type") not in {"User", "Organization"}
            or author["github_id"] in author_ids
        ):
            raise VerificationError("verifier artifact runtime author identity is invalid")
        author_ids.add(author["github_id"])
    mode = document.get("mode")
    basic = {
        "runtime.letsinfer",
        "runtime-plan.json",
        "candidate-audit.json",
        "runtime.spdx.json",
        "provenance.json",
    }
    engine_files = {"engine.oci.tar", "engine.spdx.json"}
    expected = basic | (engine_files if mode == "build-engine" else set())
    if mode not in {"reuse-engine", "build-engine"}:
        raise VerificationError("verifier artifact Engine mode is invalid")
    entries = list(root.iterdir())
    if any(
        path.is_symlink()
        or not path.is_file()
        or not stat.S_ISREG(path.lstat().st_mode)
        for path in entries
    ):
        raise VerificationError("verifier artifact contains a non-regular entry")
    actual = {path.name for path in entries}
    if actual != expected | {"bundle.json", "checksums.json"}:
        raise VerificationError("verifier artifact file set differs")
    checksums_path = root / "checksums.json"
    if sha256_file(checksums_path) != document.get("checksums_sha256"):
        raise VerificationError("verifier artifact checksum manifest differs")
    checksums = _bundle_object(checksums_path)
    if set(checksums) != expected:
        raise VerificationError("verifier artifact checksum file set differs")
    for name, record in checksums.items():
        path = root / name
        if (
            not isinstance(record, dict)
            or set(record) != {"sha256", "bytes"}
            or record.get("bytes") != path.stat().st_size
            or record.get("sha256") != sha256_file(path)
        ):
            raise VerificationError(f"verifier artifact payload differs: {name}")
    subject = document.get("subject")
    if not isinstance(subject, dict):
        raise VerificationError("verifier artifact execution subject is invalid")
    subject_without_id = dict(subject)
    execution = subject_without_id.pop("execution_sha256", None)
    if execution != sha256_bytes(canonical_bytes(subject_without_id)):
        raise VerificationError("verifier artifact execution identity differs")
    if any(
        subject.get(key) != expected_value
        for key, expected_value in (
            ("repository", REPOSITORY),
            ("pull_request", pr.number),
            ("proposal_head_sha", pr.head_sha),
            ("proposal_base_sha", proposal_base),
            ("candidate_id", candidate),
            ("engine_mode", mode),
        )
    ):
        raise VerificationError("verifier artifact subject differs from the proposal")
    runtime_pack = root / "runtime.letsinfer"
    plan = _bundle_object(root / "runtime-plan.json")
    if (
        document.get("runtime") != plan
        or plan.get("layer_digest") != "sha256:" + sha256_file(runtime_pack)
        or plan.get("layer_bytes") != runtime_pack.stat().st_size
        or subject.get("runtime_pack_sha256") != sha256_file(runtime_pack)
        or subject.get("runtime_oci_manifest_digest") != plan.get("manifest_digest")
    ):
        raise VerificationError("verifier artifact runtime plan differs")
    from .runtime_packs import RuntimePackError, materialize

    try:
        with materialize(runtime_pack) as pack:
            if pack.runtime.get("id") != candidate:
                raise VerificationError("verifier runtime pack candidate differs")
            calculated = execution_subject(
                pack.runtime,
                pack_sha256=sha256_file(runtime_pack),
                pack_bytes=runtime_pack.stat().st_size,
            )
            for key, value in calculated.items():
                if key != "execution_sha256" and subject.get(key) != value:
                    raise VerificationError("verifier runtime execution subject differs")
            runtime_engine = pack.runtime["engine"]["oci"]
            runtime_platform = pack.runtime["target"]["platform"]
    except RuntimePackError as error:
        raise VerificationError(f"verifier runtime pack is invalid: {error}") from error
    engine = document.get("engine")
    if (
        not isinstance(engine, dict)
        or engine.get("reference") != runtime_engine["reference"]
        or engine.get("config_digest") != runtime_engine["immutable_id"]
    ):
        raise VerificationError("verifier Engine identity differs from runtime.json")
    engine_archive = None
    engine_config = None
    engine_tag = None
    if mode == "build-engine":
        if (
            engine.get("manifest_digest") != str(engine["reference"]).rsplit("@", 1)[-1]
            or engine.get("config_digest") != runtime_engine["immutable_id"]
            or engine.get("platform") != runtime_platform
        ):
            raise VerificationError("verifier built Engine identity differs")
        engine_archive = root / "engine.oci.tar"
        engine_config = str(engine["config_digest"])
        identity = _oci_archive_identity(
            engine_archive,
            expected_manifest=str(engine["manifest_digest"]),
            expected_config=engine_config,
            expected_platform=runtime_platform,
        )
        if any(engine.get(key) != value for key, value in identity.items()):
            raise VerificationError("verifier Engine OCI metadata differs")
        engine_tag = f"letsinfer-verifier/{candidate}:{pr.head_sha[:12]}"
    provenance = _bundle_object(root / "provenance.json")
    if provenance.get("subject") != subject or provenance.get("engine") != engine:
        raise VerificationError("verifier artifact provenance differs")
    return VerifierBundle(
        root=root,
        document=document,
        runtime_pack=runtime_pack,
        engine_archive=engine_archive,
        engine_config_digest=engine_config,
        engine_tag=engine_tag,
    )


def download_verifier_bundle(
    pr: PullRequest, candidate: str, destination: pathlib.Path, *, gh: str
) -> VerifierBundle:
    """Download the sole trusted-finalizer artifact for the current PR head."""

    name = f"verification-bundle-pr-{pr.number}-{pr.head_sha}"
    artifacts = _json_output(
        [
            gh,
            "api",
            f"repos/{REPOSITORY}/actions/artifacts?name={name}&per_page=100",
        ]
    ).get("artifacts")
    if not isinstance(artifacts, list):
        raise VerificationError("GitHub verifier artifact response is invalid")
    exact = [
        item
        for item in artifacts
        if isinstance(item, dict)
        and item.get("name") == name
        and item.get("expired") is False
        and isinstance(item.get("id"), int)
    ]
    if len(exact) != 1:
        raise VerificationError("exact verifier artifact is unavailable or ambiguous")
    artifact = exact[0]
    workflow = artifact.get("workflow_run")
    run_id = workflow.get("id") if isinstance(workflow, dict) else None
    if not isinstance(run_id, int):
        raise VerificationError("verifier artifact workflow identity is unavailable")
    finalizer = _json_output([gh, "api", f"repos/{REPOSITORY}/actions/runs/{run_id}"])
    if (
        finalizer.get("event") != "workflow_run"
        or finalizer.get("path") != ".github/workflows/finalize-verifier.yml"
        or finalizer.get("conclusion") != "success"
        or finalizer.get("head_branch") != "main"
    ):
        raise VerificationError("verifier artifact was not produced by the trusted finalizer")
    ensure_private_directory(destination)
    archive = destination / "artifact.zip"
    _download_api_file(
        gh,
        f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip",
        archive,
    )
    root = destination / "bundle"
    try:
        extract_verifier_artifact(archive, root)
    finally:
        archive.unlink(missing_ok=True)
    bundle = validate_verifier_bundle(root, pr=pr, candidate=candidate)
    finalizer_identity = bundle.document.get("finalizer_workflow")
    if (
        not isinstance(finalizer_identity, dict)
        or finalizer_identity.get("run_id") != run_id
        or finalizer_identity.get("path") != ".github/workflows/finalize-verifier.yml"
        or finalizer_identity.get("workflow_sha") != finalizer.get("head_sha")
    ):
        raise VerificationError("verifier artifact finalizer identity differs")
    build_identity = bundle.document.get("build_workflow")
    build_id = build_identity.get("run_id") if isinstance(build_identity, dict) else None
    if not isinstance(build_id, int):
        raise VerificationError("verifier artifact build identity is unavailable")
    build = _json_output([gh, "api", f"repos/{REPOSITORY}/actions/runs/{build_id}"])
    if (
        build.get("event") != "workflow_run"
        or build.get("path") != ".github/workflows/build-verifier.yml"
        or build.get("conclusion") != "success"
        or build.get("head_branch") != "main"
        or build.get("head_sha") != pr.base_sha
        or build_identity.get("workflow_sha") != pr.base_sha
    ):
        raise VerificationError("verifier artifact untrusted build identity differs")
    verify_bundle_attestations(root, gh=gh)
    return bundle


def local_engine_receipt_path(output: pathlib.Path) -> pathlib.Path:
    return output / "local-engine-image.json"


def _write_local_engine_receipt(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _docker_image_id(docker: str, reference: str) -> str | None:
    result = _run(
        [docker, "image", "inspect", reference, "--format", "{{.Id}}"],
        check=False,
        limit=64 << 10,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.decode("utf-8", errors="replace").strip()
    return value if OCI_DIGEST_RE.fullmatch(value) else None


def load_local_engine(
    bundle: VerifierBundle, output: pathlib.Path, *, docker: str = "docker"
) -> dict[str, Any] | None:
    """Load the exact bundled image and persist enough state for crash cleanup."""

    if bundle.engine_archive is None or bundle.engine_config_digest is None:
        return None
    config = bundle.engine_config_digest
    preexisting = _docker_image_id(docker, config) == config
    receipt = {
        "schema_version": 1,
        "config_digest": config,
        "tag": bundle.engine_tag,
        "preexisting": preexisting,
        "loaded": False,
        "cleaned": False,
    }
    path = local_engine_receipt_path(output)
    _write_local_engine_receipt(path, receipt)
    if not preexisting:
        if bundle.engine_tag is None:
            raise VerificationError("bundled Engine local tag is unavailable")
        docker_archive = output / "engine.docker.tar"
        receipt["loaded"] = True
        _write_local_engine_receipt(path, receipt)
        try:
            _docker_archive_from_oci(
                bundle.engine_archive,
                docker_archive,
                expected_manifest=str(bundle.document["engine"]["manifest_digest"]),
                expected_config=config,
                expected_platform=str(bundle.document["engine"]["platform"]),
                tag=bundle.engine_tag,
            )
            result = _run(
                [docker, "load", "--input", str(docker_archive)],
                check=False,
                limit=1 << 20,
            )
        finally:
            docker_archive.unlink(missing_ok=True)
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise VerificationError(f"cannot load bundled Engine image: {detail}")
    if _docker_image_id(docker, config) != config:
        raise VerificationError("loaded Engine image configuration identity differs")
    if (
        not preexisting
        and bundle.engine_tag is not None
        and _docker_image_id(docker, bundle.engine_tag) != config
    ):
        raise VerificationError("loaded Engine image tag identifies different bytes")
    receipt["loaded"] = True
    _write_local_engine_receipt(path, receipt)
    return receipt


def cleanup_local_engine(output: pathlib.Path, *, docker: str = "docker") -> None:
    """Remove only an image introduced by verification; preserve prior images."""

    path = local_engine_receipt_path(output)
    if not path.is_file() or path.is_symlink():
        return
    receipt = _bundle_object(path)
    if (
        receipt.get("schema_version") != 1
        or not isinstance(receipt.get("config_digest"), str)
        or type(receipt.get("preexisting")) is not bool
        or type(receipt.get("loaded")) is not bool
        or type(receipt.get("cleaned")) is not bool
    ):
        raise VerificationError("local Engine cleanup receipt is invalid")
    if receipt["cleaned"] or receipt["preexisting"] or not receipt["loaded"]:
        receipt["cleaned"] = True
        _write_local_engine_receipt(path, receipt)
        return
    config = receipt["config_digest"]
    tag = receipt.get("tag")
    for reference in (tag, config):
        if isinstance(reference, str) and _docker_image_id(docker, reference) is not None:
            result = _run(
                [docker, "image", "rm", reference],
                check=False,
                limit=1 << 20,
            )
            if result.returncode != 0:
                detail = result.stderr.decode("utf-8", errors="replace").strip()
                raise VerificationError(
                    f"cannot remove verifier Engine image {reference}: {detail}"
                )
    if _docker_image_id(docker, config) is not None:
        raise VerificationError("verifier Engine image remains after cleanup")
    receipt["cleaned"] = True
    _write_local_engine_receipt(path, receipt)


def runtime_oci_manifest_digest(
    *, candidate: str, version: str, pack_sha256: str, pack_bytes: int
) -> str:
    """Calculate the exact deterministic OCI manifest digest without publishing."""

    if (
        CANDIDATE_RE.fullmatch(candidate) is None
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", version)
        is None
        or SHA256_RE.fullmatch(pack_sha256) is None
        or not isinstance(pack_bytes, int)
        or isinstance(pack_bytes, bool)
        or pack_bytes <= 0
    ):
        raise VerificationError("runtime OCI inputs are invalid")
    compact = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    config = compact(
        {
            "candidate": candidate,
            "media_type": PACK_MEDIA_TYPE,
            "schema_version": 1,
            "version": version,
        }
    )
    config_digest = "sha256:" + sha256_bytes(config)
    manifest = compact(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.letsinfer.runtime.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": PACK_MEDIA_TYPE,
                    "digest": "sha256:" + pack_sha256,
                    "size": pack_bytes,
                    "annotations": {
                        "org.opencontainers.image.title": "runtime.letsinfer"
                    },
                }
            ],
            "annotations": {
                "ai.letsinfer.candidate": candidate,
                "ai.letsinfer.version": version,
                "org.opencontainers.image.source": (
                    "https://github.com/letsinferlabs/runtimes"
                ),
            },
        }
    )
    return "sha256:" + sha256_bytes(manifest)


def execution_subject(
    runtime: Mapping[str, Any], *, pack_sha256: str, pack_bytes: int
) -> dict[str, Any]:
    target = runtime.get("target")
    artifacts = runtime.get("artifacts")
    engine = runtime.get("engine")
    benchmark = runtime.get("benchmark")
    if not all(isinstance(value, Mapping) for value in (target, engine, benchmark)):
        raise VerificationError("runtime execution identity is incomplete")
    if not isinstance(artifacts, list) or not artifacts:
        raise VerificationError("runtime model revision set is unavailable")
    revisions = []
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            raise VerificationError("runtime artifact identity is invalid")
        name = artifact.get("name")
        uri = artifact.get("uri")
        revision = artifact.get("revision")
        artifact_sha = artifact.get("sha256")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name) is None
            or not isinstance(uri, str)
            or re.fullmatch(r"hf://[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", uri) is None
            or not isinstance(revision, str)
            or re.fullmatch(r"[0-9a-f]{40}", revision) is None
            or (artifact_sha is not None and not SHA256_RE.fullmatch(str(artifact_sha)))
        ):
            raise VerificationError("runtime artifact identity is invalid")
        revisions.append(
            {
                "name": name,
                "uri": uri,
                "revision": revision,
                "sha256": artifact_sha,
            }
        )
    candidate = runtime.get("id")
    version = runtime.get("version")
    engine_oci = engine.get("oci")
    if not isinstance(engine_oci, Mapping) or not isinstance(
        benchmark.get("contract"), Mapping
    ):
        raise VerificationError("runtime Engine OCI identity is unavailable")
    subject = {
        "candidate_id": candidate,
        "runtime_version": version,
        "runtime_pack_sha256": pack_sha256,
        "runtime_oci_manifest_digest": runtime_oci_manifest_digest(
            candidate=str(candidate),
            version=str(version),
            pack_sha256=pack_sha256,
            pack_bytes=pack_bytes,
        ),
        "engine_oci_manifest_digest": str(engine_oci.get("reference", "")).rsplit(
            "@", 1
        )[-1],
        "model_revisions": sorted(revisions, key=lambda item: str(item["name"])),
        "benchmark_contract_sha256": sha256_bytes(
            canonical_bytes(benchmark.get("contract"))
        ),
        "target_contract_sha256": sha256_bytes(canonical_bytes(target)),
    }
    if (
        CANDIDATE_RE.fullmatch(str(subject["candidate_id"])) is None
        or not SHA256_RE.fullmatch(str(subject["runtime_pack_sha256"]))
        or not OCI_DIGEST_RE.fullmatch(str(subject["runtime_oci_manifest_digest"]))
        or not OCI_DIGEST_RE.fullmatch(str(subject["engine_oci_manifest_digest"]))
    ):
        raise VerificationError("runtime execution identity is invalid")
    return subject | {"execution_sha256": sha256_bytes(canonical_bytes(subject))}


def _identity_root() -> pathlib.Path:
    return secrets_root() / "benchmark-verification"


def device_identity(root: pathlib.Path | None = None) -> DeviceIdentity:
    directory = ensure_private_directory(root or _identity_root())
    private = directory / "device-ed25519.key"
    public = directory / "device-ed25519.pub"
    if private.exists() != public.exists():
        raise VerificationError("benchmark device identity is incomplete")
    if not private.exists():
        _run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)])
        _run(
            ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)]
        )
        private.chmod(0o600)
        public.chmod(0o600)
    for path in (private, public):
        details = path.stat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) & 0o077
        ):
            raise VerificationError("benchmark device identity is not private")
    public_pem = public.read_text(encoding="ascii")
    public_der = _run(
        ["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"]
    ).stdout
    identity = sha256_bytes(public_der)
    return DeviceIdentity(identity, identity, public_pem, private)


def sign(private_key: pathlib.Path, value: bytes) -> str:
    with tempfile.TemporaryDirectory() as temporary:
        message = pathlib.Path(temporary) / "message.bin"
        message.write_bytes(value)
        result = _run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key),
                "-rawin",
                "-in",
                str(message),
            ],
            limit=64 << 10,
        )
    return base64.urlsafe_b64encode(result.stdout).rstrip(b"=").decode("ascii")


def public_key_id(public_key_pem: str) -> str:
    if (
        not isinstance(public_key_pem, str)
        or len(public_key_pem.encode("ascii", errors="ignore")) > 16 << 10
    ):
        raise VerificationError("verification public key is invalid")
    with tempfile.TemporaryDirectory() as temporary:
        public = pathlib.Path(temporary) / "public.pem"
        try:
            public.write_text(public_key_pem, encoding="ascii")
        except (OSError, UnicodeEncodeError) as error:
            raise VerificationError("verification public key is invalid") from error
        result = _run(
            ["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"],
            check=False,
            limit=16 << 10,
        )
    if result.returncode != 0 or not result.stdout:
        raise VerificationError("verification public key is invalid")
    return sha256_bytes(result.stdout)


def verify_signature(public_key_pem: str, value: bytes, signature: str) -> bool:
    padding = "=" * (-len(signature) % 4)
    try:
        raw_signature = base64.urlsafe_b64decode(signature + padding)
    except (ValueError, binascii.Error):
        return False
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        public = root / "public.pem"
        signature_path = root / "signature.bin"
        message = root / "message.bin"
        public.write_text(public_key_pem, encoding="ascii")
        signature_path.write_bytes(raw_signature)
        message.write_bytes(value)
        result = _run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public),
                "-sigfile",
                str(signature_path),
                "-rawin",
                "-in",
                str(message),
            ],
            check=False,
            limit=64 << 10,
        )
    return result.returncode == 0


def _zstd(data: bytes, *, decompress: bool = False) -> bytes:
    executable = shutil.which("zstd")
    if executable is None:
        raise VerificationError(
            "Zstandard is required for verification evidence; install the `zstd` "
            "system package and retry"
        )
    command = [executable, "--stdout", "--no-progress"]
    if decompress:
        # Verification evidence is always emitted with a declared frame size.
        # Inspect that bounded declaration before allowing decompression.
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary) / "evidence.zst"
            source.write_bytes(data)
            listing = _run([executable, "--list", "--verbose", str(source)])
            match = re.search(
                rb"Decompressed Size:.*?\(([0-9,]+) B\)|"
                rb"Decompressed Size:\s*([0-9,]+) B",
                listing.stdout,
            )
            if match is None:
                raise VerificationError("verification evidence has no declared size")
            declared_value = match.group(1) or match.group(2)
            declared = int(declared_value.replace(b",", b""))
            if declared <= 0 or declared > MAX_EXPANDED_EVIDENCE_BYTES:
                raise VerificationError("verification evidence declared size is invalid")
            return _run(
                [
                    executable,
                    "--decompress",
                    "--stdout",
                    "--no-progress",
                    f"--memory={MAX_EXPANDED_EVIDENCE_BYTES // 1024}KiB",
                    str(source),
                ],
                limit=MAX_EXPANDED_EVIDENCE_BYTES,
            ).stdout
    else:
        command.extend(["-19", "--threads=1", f"--stream-size={len(data)}"])
    return _run(
        command,
        input_bytes=data,
        limit=COMMENT_LIMIT_BYTES,
    ).stdout


def aggregate_score(record: Mapping[str, Any]) -> dict[str, Any]:
    """Build deterministic per-domain and overall aggregate-throughput scores."""

    candidate = record.get("candidate")
    baseline = record.get("baseline")
    if not isinstance(candidate, Mapping):
        raise VerificationError("verification candidate benchmark is unavailable")

    def grouped(value: Mapping[str, Any]) -> dict[str, list[float]]:
        output: dict[str, list[float]] = {}
        results = value.get("results")
        if not isinstance(results, list) or not results:
            raise VerificationError("verification benchmark results are unavailable")
        for result in results:
            if not isinstance(result, Mapping) or result.get("is_prefix_cached") is not False:
                continue
            domain, throughput = result.get("prompt_domain"), result.get("aggregate_tps")
            if (
                domain not in {"code", "prose"}
                or isinstance(throughput, bool)
                or not isinstance(throughput, (int, float))
                or not math.isfinite(float(throughput))
                or float(throughput) <= 0
            ):
                raise VerificationError("verification benchmark contains invalid throughput")
            output.setdefault(str(domain), []).append(float(throughput))
        if set(output) != {"code", "prose"}:
            raise VerificationError("verification benchmark must include code and prose")
        return output

    def geomean(values: Sequence[float]) -> float:
        return math.exp(sum(math.log(item) for item in values) / len(values))

    candidate_values = grouped(candidate)
    baseline_values = grouped(baseline) if isinstance(baseline, Mapping) else None
    domains: dict[str, Any] = {}
    for domain in ("code", "prose"):
        value = geomean(candidate_values[domain])
        reference = (
            geomean(baseline_values[domain]) if baseline_values is not None else None
        )
        domains[domain] = {
            "aggregate_tps_geomean": value,
            "baseline_aggregate_tps_geomean": reference,
            "change_percent": (
                None if reference is None else ((value / reference) - 1.0) * 100.0
            ),
        }
    overall_values = [*candidate_values["code"], *candidate_values["prose"]]
    baseline_overall = (
        None
        if baseline_values is None
        else geomean([*baseline_values["code"], *baseline_values["prose"]])
    )
    overall = geomean(overall_values)
    return {
        "policy": "letsinfer-throughput-geomean-v1",
        "domains": domains,
        "overall": {
            "aggregate_tps_geomean": overall,
            "baseline_aggregate_tps_geomean": baseline_overall,
            "change_percent": (
                None
                if baseline_overall is None
                else ((overall / baseline_overall) - 1.0) * 100.0
            ),
        },
    }


def verification_identity(record: Mapping[str, Any]) -> str:
    candidate = record.get("candidate")
    subject = record.get("subject")
    verifier = record.get("verifier")
    if not isinstance(subject, Mapping) or not isinstance(verifier, Mapping):
        raise VerificationError("verification identity material is incomplete")
    identity_material = {
        "candidate_benchmark_id": (
            candidate.get("id") if isinstance(candidate, Mapping) else None
        ),
        "device_id": record.get("device_id"),
        "execution_sha256": subject.get("execution_sha256"),
        "failure": record.get("failure"),
        "github_id": verifier.get("github_id"),
        "observed_head_sha": record.get("observed_head_sha"),
        "pull_request": record.get("pull_request"),
    }
    return sha256_bytes(canonical_bytes(identity_material))


def verification_record(
    *,
    pr: PullRequest,
    verifier: GitHubIdentity,
    device: DeviceIdentity,
    subject: Mapping[str, Any],
    candidate_benchmark: Mapping[str, Any] | None,
    baseline_benchmark: Mapping[str, Any] | None,
    restoration: Mapping[str, Any],
    failure: Mapping[str, Any] | None = None,
    runtime_author_ids: Collection[int] = (),
) -> dict[str, Any]:
    failure_document: dict[str, Any] | None = None
    if failure is None:
        if candidate_benchmark is None:
            raise VerificationError("successful verification has no candidate benchmark")
        if restoration.get("passed") is not True:
            raise VerificationError("successful verification did not restore resident state")
    else:
        failure_document = dict(failure)
        if (
            set(failure_document) != {"category", "phase", "message"}
            or failure_document.get("category") not in FAILURE_CATEGORIES
            or not isinstance(failure_document.get("phase"), str)
            or not failure_document["phase"]
            or len(failure_document["phase"]) > 128
            or not isinstance(failure_document.get("message"), str)
            or not failure_document["message"]
            or len(failure_document["message"]) > 500
        ):
            raise VerificationError("verification failure evidence is invalid")
    category = None if failure_document is None else failure_document["category"]
    correctness_passed = category not in {"output_validation", "incomplete_workload"}
    safety_passed = category not in {
        "crash",
        "out_of_memory",
        "protection_trip",
        "output_validation",
    }
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "repository": REPOSITORY,
        "pull_request": pr.number,
        "pull_request_url": pr.url,
        "observed_head_sha": pr.head_sha,
        "submitted_at_unix": int(time.time()),
        "verifier": verifier.document(),
        "device_id": device.device_id,
        "subject": dict(subject),
        "candidate": (
            None if candidate_benchmark is None else dict(candidate_benchmark)
        ),
        "baseline": None if baseline_benchmark is None else dict(baseline_benchmark),
        "run_order": ["baseline", "candidate"],
        "correctness": {
            "passed": correctness_passed,
            "failures": 0 if correctness_passed else 1,
        },
        "safety": {
            "passed": safety_passed,
            "crashes": int(category == "crash"),
            "out_of_memory": int(category == "out_of_memory"),
            "protection_trips": int(category == "protection_trip"),
            "output_validation_failures": int(category == "output_validation"),
        },
        "restoration": dict(restoration),
        "failure": failure_document,
        "counts_toward_consensus": (
            verifier.numeric_id != pr.author.numeric_id
            and verifier.numeric_id not in runtime_author_ids
        ),
    }
    record["run_score"] = (
        aggregate_score(record) if failure_document is None else None
    )
    record["verification_id"] = verification_identity(record)
    return record


def _visible_summary(record: Mapping[str, Any]) -> str:
    verifier = record["verifier"]
    score = record["run_score"]
    subject = record["subject"]
    candidate = record["candidate"]
    failure = record.get("failure")
    if isinstance(failure, Mapping):
        return "\n".join(
            [
                "## Let’s Infer runtime verification",
                "",
                f"**Verifier:** @{verifier['github_login']} (`{verifier['github_id']}`)",
                f"**Runtime:** `{subject['candidate_id']}@{subject['runtime_version']}`",
                f"**Execution:** `{subject['execution_sha256']}`",
                "**Result:** blocking failure",
                f"**Failure:** `{failure['category']}` during `{failure['phase']}`",
                f"**Restoration:** {'pass' if record['restoration'].get('passed') else 'fail'}",
                f"**Verification ID:** `{record['verification_id']}`",
            ]
        )
    if not isinstance(candidate, Mapping) or not isinstance(score, Mapping):
        raise VerificationError("successful verification summary is incomplete")
    lines = [
        "## Let’s Infer runtime verification",
        "",
        f"**Verifier:** @{verifier['github_login']} (`{verifier['github_id']}`)",
        f"**Runtime:** `{subject['candidate_id']}@{subject['runtime_version']}`",
        f"**Execution:** `{subject['execution_sha256']}`",
        f"**Target:** `{candidate['subject']['target']}`",
        f"**Benchmark:** `{candidate['id']}` · {len(candidate['results'])} workloads",
        "",
        "| Prompt | Aggregate tok/s | Baseline | Change |",
        "|---|---:|---:|---:|",
    ]
    for domain in ("code", "prose"):
        value = score["domains"][domain]
        baseline = value["baseline_aggregate_tps_geomean"]
        change = value["change_percent"]
        lines.append(
            f"| {domain.title()} | {value['aggregate_tps_geomean']:.3f} | "
            f"{'—' if baseline is None else f'{baseline:.3f}'} | "
            f"{'—' if change is None else f'{change:+.2f}%'} |"
        )
    lines.extend(
        [
            "",
            "**Correctness:** pass · **Safety:** pass · **Restoration:** pass",
            f"**Verification ID:** `{record['verification_id']}`",
        ]
    )
    return "\n".join(lines)


def build_comment(record: Mapping[str, Any], device: DeviceIdentity) -> str:
    evidence = canonical_bytes(record)
    if len(evidence) > MAX_EXPANDED_EVIDENCE_BYTES:
        raise VerificationError("benchmark evidence exceeds the expanded-size limit")
    compressed = _zstd(evidence)
    payload = base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")
    envelope: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "verification_id": record["verification_id"],
        "repository": record["repository"],
        "pull_request": record["pull_request"],
        "observed_head_sha": record["observed_head_sha"],
        "execution_sha256": record["subject"]["execution_sha256"],
        "runtime_oci_manifest_digest": record["subject"][
            "runtime_oci_manifest_digest"
        ],
        "benchmark_contract_sha256": record["subject"][
            "benchmark_contract_sha256"
        ],
        "github_login": record["verifier"]["github_login"],
        "github_id": record["verifier"]["github_id"],
        "github_type": record["verifier"]["github_type"],
        "device_id": record["device_id"],
        "device_public_key_pem": device.public_key_pem,
        "summary": {
            "candidate_benchmark_id": (
                None if record["candidate"] is None else record["candidate"]["id"]
            ),
            "baseline_benchmark_id": (
                None if record["baseline"] is None else record["baseline"]["id"]
            ),
            "workloads": (
                0 if record["candidate"] is None else len(record["candidate"]["results"])
            ),
            "correctness_passed": record["correctness"]["passed"],
            "safety_passed": record["safety"]["passed"],
            "score_sha256": sha256_bytes(canonical_bytes(record["run_score"])),
        },
        "evidence": {
            "media_type": "application/vnd.letsinfer.verification-benchmark.v1+json",
            "encoding": "zstd-19+base64url",
            "uncompressed_sha256": sha256_bytes(evidence),
            "uncompressed_bytes": len(evidence),
            "compressed_sha256": sha256_bytes(compressed),
            "compressed_bytes": len(compressed),
            "payload": payload,
        },
        "signature": {
            "algorithm": "ed25519",
            "key_id": device.key_id,
            "value": "",
        },
    }
    unsigned = canonical_bytes(envelope)
    envelope["signature"]["value"] = sign(device.private_key, unsigned)
    body = (
        _visible_summary(record)
        + f"\n\n<!-- {COMMENT_MARKER}\n"
        + canonical_bytes(envelope).decode("utf-8").rstrip("\n")
        + "\n-->\n"
    )
    if len(body.encode("utf-8")) > COMMENT_LIMIT_BYTES:
        raise VerificationError(
            f"verification comment exceeds {COMMENT_LIMIT_BYTES} bytes; "
            "evidence remains local and was not posted"
        )
    return body


def parse_comment(body: str) -> tuple[dict[str, Any], dict[str, Any]]:
    prefix = f"<!-- {COMMENT_MARKER}\n"
    start = body.find(prefix)
    if start < 0 or not body.endswith("\n-->\n"):
        raise VerificationError("verification comment envelope is missing")
    raw = body[start + len(prefix) : -len("\n-->\n")]
    if len(raw.encode("utf-8")) > COMMENT_LIMIT_BYTES:
        raise VerificationError("verification envelope exceeds its size limit")
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as error:
        raise VerificationError("verification envelope is invalid JSON") from error
    envelope_fields = {
        "schema_version",
        "kind",
        "verification_id",
        "repository",
        "pull_request",
        "observed_head_sha",
        "execution_sha256",
        "runtime_oci_manifest_digest",
        "benchmark_contract_sha256",
        "github_login",
        "github_id",
        "github_type",
        "device_id",
        "device_public_key_pem",
        "summary",
        "evidence",
        "signature",
    }
    if (
        not isinstance(envelope, dict)
        or set(envelope) != envelope_fields
        or envelope.get("schema_version") != SCHEMA_VERSION
        or envelope.get("kind") != KIND
        or envelope.get("repository") != REPOSITORY
    ):
        raise VerificationError("verification envelope kind is invalid")
    signature = envelope.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm",
        "key_id",
        "value",
    }:
        raise VerificationError("verification signature is invalid")
    signed = json.loads(json.dumps(envelope))
    signed["signature"]["value"] = ""
    public_key = envelope.get("device_public_key_pem")
    if (
        signature.get("algorithm") != "ed25519"
        or signature.get("key_id") != envelope.get("device_id")
        or public_key_id(str(public_key)) != envelope.get("device_id")
        or not verify_signature(
            str(public_key),
            canonical_bytes(signed),
            str(signature.get("value", "")),
        )
    ):
        raise VerificationError("verification signature does not match its device")
    evidence = envelope.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {
        "media_type",
        "encoding",
        "uncompressed_sha256",
        "uncompressed_bytes",
        "compressed_sha256",
        "compressed_bytes",
        "payload",
    }:
        raise VerificationError("verification evidence descriptor is invalid")
    if (
        evidence.get("media_type")
        != "application/vnd.letsinfer.verification-benchmark.v1+json"
        or evidence.get("encoding") != "zstd-19+base64url"
    ):
        raise VerificationError("verification evidence encoding is invalid")
    payload = evidence.get("payload")
    if not isinstance(payload, str) or len(payload.encode("ascii", errors="ignore")) > COMMENT_LIMIT_BYTES:
        raise VerificationError("verification evidence payload is invalid")
    try:
        compressed = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    except (ValueError, binascii.Error) as error:
        raise VerificationError("verification evidence base64url is invalid") from error
    if (
        len(compressed) != evidence.get("compressed_bytes")
        or sha256_bytes(compressed) != evidence.get("compressed_sha256")
    ):
        raise VerificationError("verification compressed evidence identity differs")
    expanded = _zstd(compressed, decompress=True)
    if (
        len(expanded) != evidence.get("uncompressed_bytes")
        or len(expanded) > MAX_EXPANDED_EVIDENCE_BYTES
        or sha256_bytes(expanded) != evidence.get("uncompressed_sha256")
    ):
        raise VerificationError("verification expanded evidence identity differs")
    try:
        record = json.loads(expanded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("verification evidence JSON is invalid") from error
    record_fields = {
        "schema_version",
        "kind",
        "repository",
        "pull_request",
        "pull_request_url",
        "observed_head_sha",
        "submitted_at_unix",
        "verifier",
        "device_id",
        "subject",
        "candidate",
        "baseline",
        "run_order",
        "correctness",
        "safety",
        "restoration",
        "failure",
        "counts_toward_consensus",
        "run_score",
        "verification_id",
    }
    if (
        not isinstance(record, dict)
        or set(record) != record_fields
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("kind") != KIND
        or record.get("repository") != REPOSITORY
        or record.get("verification_id") != envelope.get("verification_id")
        or verification_identity(record) != record.get("verification_id")
    ):
        raise VerificationError("verification record identity differs")
    try:
        if record.get("candidate") is not None:
            validate_record(record["candidate"])
        if record.get("baseline") is not None:
            validate_record(record["baseline"])
    except BenchmarkRecordError as error:
        raise VerificationError(
            f"verification benchmark record is invalid: {error}"
        ) from error
    verifier = record.get("verifier")
    subject = record.get("subject")
    summary = envelope.get("summary")
    candidate = record.get("candidate")
    baseline = record.get("baseline")
    failure = record.get("failure")
    failed = any(
        isinstance(record.get(name), Mapping)
        and record[name].get("passed") is False
        for name in ("correctness", "safety", "restoration")
    )
    if (
        not isinstance(verifier, Mapping)
        or set(verifier) != {"github_login", "github_id", "github_type"}
        or verifier.get("github_type") != "User"
        or not isinstance(subject, Mapping)
        or not isinstance(summary, Mapping)
        or (candidate is not None and not isinstance(candidate, Mapping))
        or (baseline is not None and not isinstance(baseline, Mapping))
        or record.get("run_order") != ["baseline", "candidate"]
        or (
            failure is not None
            and (
                not isinstance(failure, Mapping)
                or set(failure) != {"category", "phase", "message"}
                or failure.get("category") not in FAILURE_CATEGORIES
                or not isinstance(failure.get("phase"), str)
                or not failure["phase"]
                or len(failure["phase"]) > 128
                or not isinstance(failure.get("message"), str)
                or not failure["message"]
                or len(failure["message"]) > 500
            )
        )
        or failed is not (failure is not None)
        or (failure is None and (candidate is None or baseline is None))
        or record.get("device_id") != envelope.get("device_id")
        or record.get("pull_request") != envelope.get("pull_request")
        or record.get("observed_head_sha") != envelope.get("observed_head_sha")
        or subject.get("execution_sha256") != envelope.get("execution_sha256")
        or subject.get("runtime_oci_manifest_digest")
        != envelope.get("runtime_oci_manifest_digest")
        or subject.get("benchmark_contract_sha256")
        != envelope.get("benchmark_contract_sha256")
        or verifier.get("github_login") != envelope.get("github_login")
        or verifier.get("github_id") != envelope.get("github_id")
        or verifier.get("github_type") != envelope.get("github_type")
    ):
        raise VerificationError("verification envelope and evidence differ")
    subject_without_identity = dict(subject)
    execution_sha = subject_without_identity.pop("execution_sha256", None)
    if sha256_bytes(canonical_bytes(subject_without_identity)) != execution_sha:
        raise VerificationError("verification execution subject identity differs")
    if (
        set(summary)
        != {
            "candidate_benchmark_id",
            "baseline_benchmark_id",
            "workloads",
            "correctness_passed",
            "safety_passed",
            "score_sha256",
        }
        or summary.get("candidate_benchmark_id")
        != (None if candidate is None else candidate.get("id"))
        or summary.get("baseline_benchmark_id")
        != (None if baseline is None else baseline.get("id"))
        or summary.get("workloads")
        != (0 if candidate is None else len(candidate.get("results", [])))
        or not isinstance(record.get("correctness"), Mapping)
        or not isinstance(record.get("safety"), Mapping)
        or summary.get("correctness_passed") != record["correctness"].get("passed")
        or summary.get("safety_passed") != record["safety"].get("passed")
        or summary.get("score_sha256")
        != sha256_bytes(canonical_bytes(record.get("run_score")))
        or record.get("run_score")
        != (None if record.get("failure") is not None else aggregate_score(record))
    ):
        raise VerificationError("verification summary differs from its evidence")
    visible = body[:start]
    if visible != _visible_summary(record) + "\n\n":
        raise VerificationError("verification visible summary differs from evidence")
    return envelope, record


def post_comment(pr: PullRequest, body: str, *, gh: str) -> str:
    # ``gh api`` returns an array for the comments endpoint, so keep its bounded
    # decoding here instead of weakening the object-only helper.
    listing = _run(
        [
            gh,
            "api",
            "--paginate",
            "--slurp",
            f"repos/{REPOSITORY}/issues/{pr.number}/comments?per_page=100",
        ]
    )
    try:
        comments = json.loads(listing.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("GitHub comments response is invalid") from error
    if not isinstance(comments, list) or any(
        not isinstance(page, list) for page in comments
    ):
        raise VerificationError("GitHub comments response is not an array")
    _envelope, record = parse_comment(body)
    verification_id = record["verification_id"]
    marker = f'"verification_id":"{verification_id}"'
    for comment in (item for page in comments for item in page):
        existing_body = comment.get("body") if isinstance(comment, dict) else None
        if not isinstance(existing_body, str) or marker not in existing_body:
            continue
        if existing_body == body:
            return str(comment.get("html_url"))
        raise VerificationError(
            "verification ID already exists with different comment content"
        )
    payload = canonical_bytes({"body": body})
    posted = _run(
        [
            gh,
            "api",
            "--method",
            "POST",
            f"repos/{REPOSITORY}/issues/{pr.number}/comments",
            "--input",
            "-",
        ],
        input_bytes=payload,
    )
    try:
        response = json.loads(posted.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("GitHub comment response is invalid") from error
    url = response.get("html_url") if isinstance(response, dict) else None
    if not isinstance(url, str) or not url.startswith(pr.url + "#issuecomment-"):
        raise VerificationError("GitHub did not return the canonical comment URL")
    return url
