#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build one deterministic platform-native Let's Infer Core archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from typing import Any


ARCHIVE_ROOT = "letsinfer"
MANIFEST_NAME = "li_core_release_manifest_v1.json"
MANIFEST_SCHEMA_NAME = "li_core_release_manifest"
MANIFEST_SCHEMA_VERSION = 1
SUPPORTED_TARGETS = {
    ("linux", "arm64"),
    ("linux", "x86_64"),
    ("macos", "arm64"),
}
ARCHITECTURE_ALIASES = {
    "aarch64": "arm64",
    "amd64": "x86_64",
    "arm64": "arm64",
    "x86_64": "x86_64",
}
OPERATING_SYSTEM_ALIASES = {
    "darwin": "macos",
    "linux": "linux",
}
APPLICATION_RUST_BINARIES = (
    "li_core_setup",
    "li_gateway",
    "li_letsinfer",
    "li_node",
    "li_watchdog",
)
BENCHMARK_WORKER_BINARY = "li_benchmark_worker"
COMMON_RUST_BINARIES = (
    BENCHMARK_WORKER_BINARY,
    *tuple(name for name in APPLICATION_RUST_BINARIES if name != "li_watchdog"),
)
LINUX_BINARIES = (*COMMON_RUST_BINARIES, "li_watchdog")
MACOS_BINARIES = (*COMMON_RUST_BINARIES, "li_hardware_macos_probe")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAXIMUM_ARCHIVE_BYTES = 256 * 1024 * 1024
REPRODUCIBLE_SOURCE_ROOT = "/usr/src/letsinfer"
REPRODUCIBLE_CARGO_HOME = "/usr/local/cargo"
RUST_FLAG_SEPARATOR = "\x1f"


class CoreReleaseBuildError(RuntimeError):
    """The native Core archive cannot be built or verified safely."""


# Returns the one release identity owned by the Rust workspace manifest.
def rust_core_version(root: pathlib.Path) -> str:
    manifest = root / "core" / "Cargo.toml"
    try:
        text = manifest.read_text(encoding="utf-8")
    except OSError as error:
        raise CoreReleaseBuildError("Rust Core workspace manifest is unavailable") from error
    match = re.search(
        r"^\[workspace\.package\]\s*$"
        r"(?P<body>.*?)(?=^\[|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    versions = () if match is None else tuple(
        re.findall(r'^version\s*=\s*"([^"]+)"\s*$', match.group("body"), re.MULTILINE)
    )
    if len(versions) != 1 or VERSION_PATTERN.fullmatch(versions[0]) is None:
        raise CoreReleaseBuildError("Rust Core workspace version is unavailable or invalid")
    return versions[0]


# Returns one absolute executable supplied by the release composition.
def executable_path(value: pathlib.Path, name: str) -> pathlib.Path:
    if not value.is_absolute():
        raise CoreReleaseBuildError(f"{name} must be an absolute path")
    try:
        details = value.stat()
    except OSError as error:
        raise CoreReleaseBuildError(f"{name} is unavailable: {value}") from error
    if not stat.S_ISREG(details.st_mode) or not os.access(value, os.X_OK):
        raise CoreReleaseBuildError(f"{name} is not an executable file: {value}")
    return value


# Returns the canonical platform identity of the active build host.
def host_target() -> tuple[str, str]:
    operating_system = OPERATING_SYSTEM_ALIASES.get(platform.system().lower())
    architecture = ARCHITECTURE_ALIASES.get(platform.machine().lower())
    if operating_system is None or architecture is None:
        raise CoreReleaseBuildError("Core build host platform is unsupported")
    return operating_system, architecture


# Requires one supported target that exactly matches the native build host.
def validate_target(operating_system: str, architecture: str) -> None:
    requested = (operating_system, architecture)
    if requested not in SUPPORTED_TARGETS:
        raise CoreReleaseBuildError(
            f"Core target is unsupported: {operating_system}-{architecture}"
        )
    observed = host_target()
    if requested != observed:
        raise CoreReleaseBuildError(
            "Core binaries must be built natively: "
            f"requested {operating_system}-{architecture}, "
            f"observed {observed[0]}-{observed[1]}"
        )


# Returns the exact released binary names for one supported platform.
def binary_names(operating_system: str) -> tuple[str, ...]:
    if operating_system == "linux":
        return tuple(sorted(LINUX_BINARIES))
    if operating_system == "macos":
        return tuple(sorted(MACOS_BINARIES))
    raise CoreReleaseBuildError(f"Core operating system is unsupported: {operating_system}")


# Runs one exact native compiler command without a shell.
def run_command(arguments: Sequence[str], environment: Mapping[str, str] | None = None) -> None:
    result = subprocess.run(
        arguments,
        check=False,
        env=None if environment is None else dict(environment),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 0:
        return
    detail = result.stderr.strip() or "native compiler failed"
    detail = detail[-8192:]
    raise CoreReleaseBuildError(detail)


# Returns the closed compiler environment that removes machine-local paths from Rust outputs.
def rust_release_environment(root: pathlib.Path) -> dict[str, str]:
    source = root.resolve(strict=False)
    environment = os.environ.copy()
    cargo_home = pathlib.Path(
        environment.get("CARGO_HOME", pathlib.Path.home() / ".cargo")
    )
    if not cargo_home.is_absolute():
        cargo_home = pathlib.Path.cwd() / cargo_home
    cargo_home = cargo_home.resolve(strict=False)
    environment["CARGO_HOME"] = str(cargo_home)
    environment.pop("RUSTFLAGS", None)
    environment["CARGO_ENCODED_RUSTFLAGS"] = RUST_FLAG_SEPARATOR.join(
        (
            "-D",
            "warnings",
            f"--remap-path-prefix={cargo_home}={REPRODUCIBLE_CARGO_HOME}",
            f"--remap-path-prefix={source}={REPRODUCIBLE_SOURCE_ROOT}",
        )
    )
    return environment


# Builds every Rust Core executable required by one platform release.
def build_rust_binaries(
    root: pathlib.Path,
    cargo: pathlib.Path,
    target_root: pathlib.Path,
    operating_system: str,
) -> dict[str, pathlib.Path]:
    rust_names = tuple(
        name for name in binary_names(operating_system) if name != "li_hardware_macos_probe"
    )
    application_names = tuple(
        name for name in rust_names if name in APPLICATION_RUST_BINARIES
    )
    if BENCHMARK_WORKER_BINARY not in rust_names or len(application_names) + 1 != len(rust_names):
        raise CoreReleaseBuildError("Core release Rust binary ownership is invalid")
    environment = rust_release_environment(root)
    common = [
        str(cargo),
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        str(root / "core" / "Cargo.toml"),
        "--target-dir",
        str(target_root),
    ]
    application_command = [*common, "--package", "li_core_application"]
    for name in application_names:
        application_command.extend(("--bin", name))
    run_command(application_command, environment)
    run_command(
        [
            *common,
            "--package",
            "li_benchmark_worker",
            "--bin",
            BENCHMARK_WORKER_BINARY,
        ],
        environment,
    )
    return {name: target_root / "release" / name for name in rust_names}


# Builds the persistent Swift and Metal hardware probe for one macOS release.
def build_macos_hardware_probe(
    root: pathlib.Path,
    swiftc: pathlib.Path,
    output: pathlib.Path,
) -> pathlib.Path:
    module_cache = output.parent / "swift_module_cache"
    module_cache.mkdir(mode=0o700)
    environment = os.environ.copy()
    environment["CLANG_MODULE_CACHE_PATH"] = str(module_cache)
    environment["SWIFT_MODULECACHE_PATH"] = str(module_cache)
    run_command(
        [
            str(swiftc),
            "-O",
            "-warnings-as-errors",
            "-file-prefix-map",
            f"{root.resolve(strict=False)}={REPRODUCIBLE_SOURCE_ROOT}",
            "-debug-prefix-map",
            f"{root.resolve(strict=False)}={REPRODUCIBLE_SOURCE_ROOT}",
            "-framework",
            "Metal",
            str(root / "core" / "hardware" / "macos" / "li_hardware_macos_probe.swift"),
            "-o",
            str(output),
        ],
        environment,
    )
    return output


# Reads one executable build output without following an alias or accepting a special file.
def executable_bytes(path: pathlib.Path) -> bytes:
    try:
        details = path.lstat()
        content = path.read_bytes()
    except OSError as error:
        raise CoreReleaseBuildError(f"Core binary is unavailable: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(details.st_mode) or not content:
        raise CoreReleaseBuildError(f"Core binary is invalid: {path}")
    if not details.st_mode & 0o111:
        raise CoreReleaseBuildError(f"Core binary is not executable: {path}")
    return content


# Returns one lowercase SHA-256 identity for exact bytes.
def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


# Returns canonical compact JSON bytes with one trailing newline.
def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


# Builds the closed manifest and exact archive file payloads in stable path order.
def release_payloads(
    operating_system: str,
    architecture: str,
    version: str,
    binaries: Mapping[str, pathlib.Path],
) -> tuple[bytes, dict[str, bytes]]:
    if (operating_system, architecture) not in SUPPORTED_TARGETS:
        raise CoreReleaseBuildError("Core release platform is unsupported")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise CoreReleaseBuildError("Core release version is invalid")
    expected = binary_names(operating_system)
    if tuple(sorted(binaries)) != expected:
        raise CoreReleaseBuildError("Core release binary set is incomplete or contains extras")
    payloads = {
        f"bin/{name}": executable_bytes(binaries[name])
        for name in expected
    }
    files = [
        {
            "path": path,
            "bytes": len(payloads[path]),
            "mode": 0o755,
            "sha256": sha256_bytes(payloads[path]),
        }
        for path in sorted(payloads)
    ]
    manifest = {
        "schema": {"name": MANIFEST_SCHEMA_NAME, "version": MANIFEST_SCHEMA_VERSION},
        "release": {"version": version},
        "platform": {"os": operating_system, "architecture": architecture},
        "files": files,
    }
    return canonical_json(manifest), payloads


# Returns one normalized deterministic directory or regular-file tar record.
def tar_record(name: str, mode: int, content: bytes | None = None) -> tarfile.TarInfo:
    record = tarfile.TarInfo(name)
    record.uid = 0
    record.gid = 0
    record.uname = ""
    record.gname = ""
    record.mtime = 0
    record.mode = mode
    if content is None:
        record.type = tarfile.DIRTYPE
        record.size = 0
    else:
        record.type = tarfile.REGTYPE
        record.size = len(content)
    return record


# Writes one deterministic archive atomically from its already-verified native inputs.
def write_archive(
    output: pathlib.Path,
    manifest: bytes,
    payloads: Mapping[str, bytes],
) -> None:
    memory = io.BytesIO()
    with tarfile.open(fileobj=memory, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(tar_record(ARCHIVE_ROOT, 0o755))
        archive.addfile(tar_record(f"{ARCHIVE_ROOT}/bin", 0o755))
        archive.addfile(
            tar_record(f"{ARCHIVE_ROOT}/{MANIFEST_NAME}", 0o644, manifest),
            io.BytesIO(manifest),
        )
        for path in sorted(payloads):
            content = payloads[path]
            archive.addfile(
                tar_record(f"{ARCHIVE_ROOT}/{path}", 0o755, content),
                io.BytesIO(content),
            )
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise CoreReleaseBuildError(f"Core archive output path is invalid: {output}")
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as destination:
            with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
                compressed.write(memory.getvalue())
            destination.flush()
            os.fsync(destination.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


# Reads one bounded regular archive member exactly once.
def member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile() or member.size <= 0 or member.size > MAXIMUM_ARCHIVE_BYTES:
        raise CoreReleaseBuildError(f"Core archive member is invalid: {member.name}")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise CoreReleaseBuildError(f"Core archive member is unavailable: {member.name}")
    content = extracted.read(MAXIMUM_ARCHIVE_BYTES + 1)
    if len(content) != member.size:
        raise CoreReleaseBuildError(f"Core archive member size is invalid: {member.name}")
    return content


# Requires one decoded object to contain exactly the declared fields.
def exact_fields(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CoreReleaseBuildError(f"Core release {name} is invalid")
    return value


# Returns whether one JSON number is exactly an integer rather than a Boolean or float alias.
def is_exact_integer(value: Any) -> bool:
    return type(value) is int


# Verifies the complete closed archive, manifest, platform, and payload identity contract.
def verify_archive(
    path: pathlib.Path,
    operating_system: str,
    architecture: str,
    version: str,
) -> dict[str, Any]:
    if (operating_system, architecture) not in SUPPORTED_TARGETS:
        raise CoreReleaseBuildError("Core release platform is unsupported")
    expected_names = binary_names(operating_system)
    expected_members = [
        ARCHIVE_ROOT,
        f"{ARCHIVE_ROOT}/bin",
        f"{ARCHIVE_ROOT}/{MANIFEST_NAME}",
        *(f"{ARCHIVE_ROOT}/bin/{name}" for name in expected_names),
    ]
    try:
        details = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(details.st_mode):
            raise CoreReleaseBuildError("Core archive is not a regular file")
        handle = tarfile.open(path, mode="r:gz")
    except (OSError, tarfile.TarError) as error:
        raise CoreReleaseBuildError(f"Core archive cannot be opened: {error}") from error
    with handle:
        members = handle.getmembers()
        if [member.name for member in members] != expected_members:
            raise CoreReleaseBuildError("Core archive member set or order is invalid")
        if sum(member.size for member in members if member.isfile()) > MAXIMUM_ARCHIVE_BYTES:
            raise CoreReleaseBuildError("Core archive exceeds its byte limit")
        if any(member.issym() or member.islnk() for member in members):
            raise CoreReleaseBuildError("Core archive contains links")
        for member in members[:2]:
            if not member.isdir() or member.mode != 0o755 or member.size != 0:
                raise CoreReleaseBuildError(f"Core archive directory is invalid: {member.name}")
        manifest_member = members[2]
        if manifest_member.mode != 0o644:
            raise CoreReleaseBuildError("Core release manifest mode is invalid")
        manifest_bytes = member_bytes(handle, manifest_member)
        try:
            manifest_value = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CoreReleaseBuildError("Core release manifest is invalid JSON") from error
        if canonical_json(manifest_value) != manifest_bytes:
            raise CoreReleaseBuildError("Core release manifest is not canonical JSON")
        manifest = exact_fields(
            manifest_value,
            {"schema", "release", "platform", "files"},
            "manifest",
        )
        schema = exact_fields(manifest["schema"], {"name", "version"}, "schema")
        release = exact_fields(manifest["release"], {"version"}, "release")
        target = exact_fields(
            manifest["platform"], {"os", "architecture"}, "platform"
        )
        if (
            schema["name"] != MANIFEST_SCHEMA_NAME
            or not is_exact_integer(schema["version"])
            or schema["version"] != MANIFEST_SCHEMA_VERSION
        ):
            raise CoreReleaseBuildError("Core release schema identity is unsupported")
        if release != {"version": version} or VERSION_PATTERN.fullmatch(version) is None:
            raise CoreReleaseBuildError("Core release version does not match")
        if target != {"os": operating_system, "architecture": architecture}:
            raise CoreReleaseBuildError("Core release platform does not match")
        files = manifest["files"]
        if not isinstance(files, list) or len(files) != len(expected_names):
            raise CoreReleaseBuildError("Core release file set is invalid")
        observed_paths: list[str] = []
        for record, member in zip(files, members[3:]):
            record = exact_fields(record, {"path", "bytes", "mode", "sha256"}, "file")
            path_value = record["path"]
            if not isinstance(path_value, str) or member.name != f"{ARCHIVE_ROOT}/{path_value}":
                raise CoreReleaseBuildError("Core release file path does not match")
            content = member_bytes(handle, member)
            if (
                member.mode != 0o755
                or not is_exact_integer(record["mode"])
                or record["mode"] != 0o755
                or not is_exact_integer(record["bytes"])
                or record["bytes"] != len(content)
                or not isinstance(record["sha256"], str)
                or SHA256_PATTERN.fullmatch(record["sha256"]) is None
                or record["sha256"] != sha256_bytes(content)
            ):
                raise CoreReleaseBuildError(f"Core release file identity is invalid: {path_value}")
            observed_paths.append(path_value)
        expected_paths = [f"bin/{name}" for name in expected_names]
        if observed_paths != expected_paths:
            raise CoreReleaseBuildError("Core release file order is invalid")
        return manifest


# Builds, packages, and independently verifies one native Core archive.
def build_archive(
    root: pathlib.Path,
    operating_system: str,
    architecture: str,
    version: str,
    cargo: pathlib.Path,
    output: pathlib.Path,
    swiftc: pathlib.Path | None,
) -> dict[str, Any]:
    validate_target(operating_system, architecture)
    if version != rust_core_version(root):
        raise CoreReleaseBuildError("Core archive version differs from the Rust workspace")
    expected_name = f"letsinfer-{operating_system}-{architecture}.tar.gz"
    if output.name != expected_name:
        raise CoreReleaseBuildError(f"Core archive name must be {expected_name}")
    with tempfile.TemporaryDirectory(prefix="li_core_release_build_") as temporary_value:
        temporary = pathlib.Path(temporary_value)
        binaries = build_rust_binaries(
            root,
            executable_path(cargo, "Cargo"),
            temporary / "target",
            operating_system,
        )
        if operating_system == "macos":
            if swiftc is None:
                raise CoreReleaseBuildError("Swift compiler is required for macOS")
            binaries["li_hardware_macos_probe"] = build_macos_hardware_probe(
                root,
                executable_path(swiftc, "Swift compiler"),
                temporary / "li_hardware_macos_probe",
            )
        manifest, payloads = release_payloads(
            operating_system,
            architecture,
            version,
            binaries,
        )
        write_archive(output, manifest, payloads)
    return verify_archive(output, operating_system, architecture, version)


# Parses the native release build contract and returns one process exit status.
def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operating-system", choices=("linux", "macos"), required=True)
    parser.add_argument("--architecture", choices=("arm64", "x86_64"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--cargo-command", type=pathlib.Path, required=True)
    parser.add_argument("--swiftc-command", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parsed = parser.parse_args(arguments)
    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        build_archive(
            root,
            parsed.operating_system,
            parsed.architecture,
            parsed.version,
            parsed.cargo_command,
            parsed.output.resolve(strict=False),
            parsed.swiftc_command,
        )
    except CoreReleaseBuildError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
