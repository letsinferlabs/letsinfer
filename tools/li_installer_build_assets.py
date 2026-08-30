#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build or verify one deterministic native Let's Infer installer archive."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import pathlib
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Sequence


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
REPRODUCIBLE_SOURCE_ROOT = "/usr/src/letsinfer"
REPRODUCIBLE_CARGO_HOME = "/usr/local/cargo"
RUST_FLAG_SEPARATOR = "\x1f"
MAXIMUM_ARCHIVE_BYTES = 256 * 1024 * 1024
MAXIMUM_INSTALLER_BYTES = 128 * 1024 * 1024
MAXIMUM_MACOS_PROBE_BYTES = 32 * 1024 * 1024
MAXIMUM_SCHEMA_BYTES = 1024 * 1024
EXECUTABLE_HEADER_BYTES = 24
ARCHIVE_READ_BYTES = 1024 * 1024
ELF_MACHINE_BY_ARCHITECTURE = {
    "arm64": 183,
    "x86_64": 62,
}
MACHO_ARM64_CPU_TYPE = 0x0100000C
MACHO_EXECUTABLE_FILE_TYPE = 2
MACHO_64_MAGIC = 0xFEEDFACF


class InstallerBuildError(RuntimeError):
    """The native installer archive cannot be built safely."""


# Returns one absolute executable supplied by the build composition.
def executable_path(value: pathlib.Path, name: str) -> pathlib.Path:
    if not value.is_absolute():
        raise InstallerBuildError(f"{name} must be an absolute path")
    try:
        details = value.stat()
    except OSError as error:
        raise InstallerBuildError(f"{name} is unavailable: {value}") from error
    if not stat.S_ISREG(details.st_mode) or not os.access(value, os.X_OK):
        raise InstallerBuildError(f"{name} is not an executable file: {value}")
    return value


# Returns the canonical platform identity of the active build host.
def host_target() -> tuple[str, str]:
    operating_system = OPERATING_SYSTEM_ALIASES.get(platform.system().lower())
    architecture = ARCHITECTURE_ALIASES.get(platform.machine().lower())
    if operating_system is None or architecture is None:
        raise InstallerBuildError("build host platform is unsupported")
    return operating_system, architecture


# Requires the requested target to equal one supported native build host.
def validate_target(operating_system: str, architecture: str) -> None:
    requested = (operating_system, architecture)
    if requested not in SUPPORTED_TARGETS:
        raise InstallerBuildError(
            f"installer target is unsupported: {operating_system}_{architecture}"
        )
    observed = host_target()
    if requested != observed:
        raise InstallerBuildError(
            "installer assets must be built natively: "
            f"requested {operating_system}_{architecture}, "
            f"observed {observed[0]}_{observed[1]}"
        )


# Runs one exact compiler command without a shell.
def run_command(arguments: Sequence[str], environment: dict[str, str] | None = None) -> None:
    result = subprocess.run(
        arguments,
        check=False,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 0:
        return
    detail = next(
        (line.strip() for line in result.stderr.splitlines() if line.strip()),
        "native compiler failed",
    )
    raise InstallerBuildError(detail)


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


# Builds the one native Rust installer lifecycle owner.
def build_rust_installer(
    root: pathlib.Path,
    cargo: pathlib.Path,
    target_root: pathlib.Path,
) -> pathlib.Path:
    command = [
        str(cargo),
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        str(root / "installer" / "Cargo.toml"),
        "--target-dir",
        str(target_root),
        "--bin",
        "li_installer",
    ]
    environment = rust_release_environment(root)
    run_command(command, environment)
    return target_root / "release" / "li_installer"


# Builds the Swift Metal probe for the native macOS target.
def build_macos_probe(
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
            str(
                root
                / "installer"
                / "macos"
                / "li_installer_macos_probe.swift"
            ),
            "-o",
            str(output),
        ],
        environment,
    )
    return output


# Copies one verified native build into the bounded archive staging root.
def stage_file(source: pathlib.Path, destination: pathlib.Path, mode: int) -> None:
    if source.is_symlink() or not source.is_file():
        raise InstallerBuildError(f"installer input is unavailable: {source}")
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


# Returns one normalized tar record for a staged directory or regular file.
def tar_record(path: pathlib.Path, relative: pathlib.PurePosixPath) -> tarfile.TarInfo:
    details = path.stat()
    record = tarfile.TarInfo(relative.as_posix())
    record.uid = 0
    record.gid = 0
    record.uname = "root"
    record.gname = "root"
    record.mtime = 0
    if path.is_dir():
        record.type = tarfile.DIRTYPE
        record.mode = 0o755
        record.size = 0
    elif path.is_file() and not path.is_symlink():
        record.type = tarfile.REGTYPE
        record.mode = stat.S_IMODE(details.st_mode)
        record.size = details.st_size
    else:
        raise InstallerBuildError(f"installer staging path is invalid: {path}")
    return record


# Writes one deterministic gzip-compressed tar archive from staged inputs.
def write_archive(staging: pathlib.Path, output: pathlib.Path) -> None:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.PAX_FORMAT) as handle:
        paths = [staging, *sorted(staging.rglob("*"), key=lambda item: item.as_posix())]
        for path in paths:
            relative = pathlib.PurePosixPath("installer")
            if path != staging:
                relative /= pathlib.PurePosixPath(path.relative_to(staging).as_posix())
            record = tar_record(path, relative)
            if record.isfile():
                with path.open("rb") as source:
                    handle.addfile(record, source)
            else:
                handle.addfile(record)
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with output.open("wb") as destination:
        with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
            compressed.write(archive.getvalue())


# Returns the closed ordered member contract for one native installer target.
def archive_members(
    operating_system: str,
    architecture: str,
) -> tuple[tuple[str, bytes, int, int], ...]:
    if (operating_system, architecture) not in SUPPORTED_TARGETS:
        raise InstallerBuildError(
            f"installer target is unsupported: {operating_system}_{architecture}"
        )
    members = [
        ("installer", tarfile.DIRTYPE, 0o755, 0),
        ("installer/bin", tarfile.DIRTYPE, 0o755, 0),
        (
            "installer/bin/li_installer",
            tarfile.REGTYPE,
            0o755,
            MAXIMUM_INSTALLER_BYTES,
        ),
    ]
    if operating_system == "macos":
        members.append(
            (
                "installer/bin/li_installer_macos_probe",
                tarfile.REGTYPE,
                0o755,
                MAXIMUM_MACOS_PROBE_BYTES,
            )
        )
    members.extend(
        (
            ("installer/schemas", tarfile.DIRTYPE, 0o755, 0),
            (
                "installer/schemas/li_installer_installation_probe_v1.schema.json",
                tarfile.REGTYPE,
                0o644,
                MAXIMUM_SCHEMA_BYTES,
            ),
        )
    )
    return tuple(members)


# Verifies one released executable header against its exact native architecture.
def verify_executable_header(
    header: bytes,
    operating_system: str,
    architecture: str,
    name: str,
) -> None:
    if len(header) < EXECUTABLE_HEADER_BYTES:
        raise InstallerBuildError(f"installer executable header is truncated: {name}")
    if operating_system == "linux":
        expected_machine = ELF_MACHINE_BY_ARCHITECTURE[architecture]
        if (
            header[:4] != b"\x7fELF"
            or header[4] != 2
            or header[5] != 1
            or header[6] != 1
            or int.from_bytes(header[16:18], "little") not in (2, 3)
            or int.from_bytes(header[18:20], "little") != expected_machine
            or int.from_bytes(header[20:24], "little") != 1
        ):
            raise InstallerBuildError(
                f"installer ELF architecture is invalid: {name}"
            )
        return
    if (
        int.from_bytes(header[:4], "little") != MACHO_64_MAGIC
        or int.from_bytes(header[4:8], "little") != MACHO_ARM64_CPU_TYPE
        or int.from_bytes(header[12:16], "little") != MACHO_EXECUTABLE_FILE_TYPE
    ):
        raise InstallerBuildError(
            f"installer Mach-O architecture is invalid: {name}"
        )


# Reads one declared archive member exactly while retaining only its bounded header.
def read_member(
    handle: tarfile.TarFile,
    member: tarfile.TarInfo,
) -> bytes:
    source = handle.extractfile(member)
    if source is None:
        raise InstallerBuildError(
            f"installer archive member is unreadable: {member.name}"
        )
    header = source.read(min(member.size, EXECUTABLE_HEADER_BYTES))
    if len(header) != min(member.size, EXECUTABLE_HEADER_BYTES):
        raise InstallerBuildError(
            f"installer archive member is truncated: {member.name}"
        )
    remaining = member.size - len(header)
    while remaining:
        content = source.read(min(remaining, ARCHIVE_READ_BYTES))
        if not content:
            raise InstallerBuildError(
                f"installer archive member is truncated: {member.name}"
            )
        remaining -= len(content)
    return header


# Verifies one archive against the complete bounded native installer contract.
def verify_archive(
    archive: pathlib.Path,
    operating_system: str,
    architecture: str,
) -> None:
    expected = archive_members(operating_system, architecture)
    expected_name = f"li_installer_{operating_system}_{architecture}.tar.gz"
    if archive.name != expected_name:
        raise InstallerBuildError(f"installer archive name must be {expected_name}")
    try:
        details = archive.lstat()
    except OSError as error:
        raise InstallerBuildError(f"installer archive is unavailable: {archive}") from error
    if not stat.S_ISREG(details.st_mode):
        raise InstallerBuildError(f"installer archive is not a regular file: {archive}")
    if details.st_size <= 0 or details.st_size > MAXIMUM_ARCHIVE_BYTES:
        raise InstallerBuildError("installer archive size is outside the supported bound")

    observed = 0
    expanded_bytes = 0
    try:
        with tarfile.open(archive, mode="r|gz") as handle:
            for index, member in enumerate(handle):
                if index >= len(expected):
                    raise InstallerBuildError("installer archive contains an extra member")
                name, member_type, mode, maximum_bytes = expected[index]
                if member.name != name:
                    raise InstallerBuildError(
                        f"installer archive member {index} must be {name}"
                    )
                if member.issym() or member.islnk():
                    raise InstallerBuildError(
                        f"installer archive links are forbidden: {member.name}"
                    )
                if member.type != member_type:
                    raise InstallerBuildError(
                        f"installer archive member type is invalid: {member.name}"
                    )
                if member.mode != mode:
                    raise InstallerBuildError(
                        f"installer archive member mode is invalid: {member.name}"
                    )
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.mtime != 0
                    or member.pax_headers
                ):
                    raise InstallerBuildError(
                        f"installer archive metadata is invalid: {member.name}"
                    )
                if member_type == tarfile.DIRTYPE:
                    if member.size != 0:
                        raise InstallerBuildError(
                            f"installer archive directory size is invalid: {member.name}"
                        )
                elif member.size <= 0 or member.size > maximum_bytes:
                    raise InstallerBuildError(
                        f"installer archive member size is invalid: {member.name}"
                    )
                else:
                    header = read_member(handle, member)
                    if member.name.startswith("installer/bin/"):
                        verify_executable_header(
                            header,
                            operating_system,
                            architecture,
                            member.name,
                        )
                    expanded_bytes += member.size
                    if expanded_bytes > MAXIMUM_ARCHIVE_BYTES:
                        raise InstallerBuildError(
                            "installer archive expanded size exceeds the supported bound"
                        )
                observed += 1
    except InstallerBuildError:
        raise
    except (OSError, EOFError, tarfile.TarError) as error:
        raise InstallerBuildError("installer archive is corrupt") from error
    if observed != len(expected):
        raise InstallerBuildError("installer archive is missing a required member")


# Builds and packages one native installer target from exact repository inputs.
def build_archive(
    root: pathlib.Path,
    operating_system: str,
    architecture: str,
    cargo: pathlib.Path,
    output: pathlib.Path,
    swiftc: pathlib.Path | None,
) -> None:
    validate_target(operating_system, architecture)
    cargo = executable_path(cargo, "Cargo")
    expected_name = f"li_installer_{operating_system}_{architecture}.tar.gz"
    if output.name != expected_name:
        raise InstallerBuildError(f"installer archive name must be {expected_name}")
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise InstallerBuildError(f"installer output path is invalid: {output}")

    with tempfile.TemporaryDirectory(prefix="li_installer_build_") as temporary_value:
        temporary = pathlib.Path(temporary_value)
        staging = temporary / "staging"
        installer = build_rust_installer(
            root,
            cargo,
            temporary / "target",
        )
        stage_file(installer, staging / "bin" / "li_installer", 0o755)
        if operating_system == "macos":
            if swiftc is None:
                raise InstallerBuildError("Swift compiler is required for macOS")
            macos_probe = build_macos_probe(
                root,
                executable_path(swiftc, "Swift compiler"),
                temporary / "li_installer_macos_probe",
            )
            stage_file(
                macos_probe,
                staging / "bin" / "li_installer_macos_probe",
                0o755,
            )
        stage_file(
            root / "schemas" / "li_installer_installation_probe_v1.schema.json",
            staging / "schemas" / "li_installer_installation_probe_v1.schema.json",
            0o644,
        )
        write_archive(staging, output)
        verify_archive(output, operating_system, architecture)


# Parses the native build contract and returns a process exit status.
def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operating-system", choices=("linux", "macos"), required=True)
    parser.add_argument("--architecture", choices=("arm64", "x86_64"), required=True)
    parser.add_argument("--cargo-command", type=pathlib.Path)
    parser.add_argument("--swiftc-command", type=pathlib.Path)
    parser.add_argument("--verify-archive", action="store_true")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parsed = parser.parse_args(arguments)
    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        output = parsed.output.resolve(strict=False)
        if parsed.verify_archive:
            verify_archive(
                output,
                parsed.operating_system,
                parsed.architecture,
            )
        else:
            if parsed.cargo_command is None:
                raise InstallerBuildError("Cargo is required to build an installer archive")
            build_archive(
                root,
                parsed.operating_system,
                parsed.architecture,
                parsed.cargo_command,
                output,
                parsed.swiftc_command,
            )
    except InstallerBuildError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
