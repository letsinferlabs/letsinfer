#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build one deterministic native Let's Infer installer archive."""

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


# Builds the shared Rust dependency manager and selected Rust probe.
def build_rust_components(
    root: pathlib.Path,
    cargo: pathlib.Path,
    target_root: pathlib.Path,
    include_probe: bool,
) -> dict[str, pathlib.Path]:
    binaries = ["li_installer_dependency_manager"]
    if include_probe:
        binaries.append("li_installer_installation_probe")
    command = [
        str(cargo),
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        str(root / "li_installer" / "Cargo.toml"),
        "--target-dir",
        str(target_root),
    ]
    for binary in binaries:
        command.extend(("--bin", binary))
    environment = os.environ.copy()
    environment["RUSTFLAGS"] = "-D warnings"
    run_command(command, environment)
    return {binary: target_root / "release" / binary for binary in binaries}


# Builds the Swift Metal probe for the native macOS target.
def build_macos_probe(
    root: pathlib.Path,
    swiftc: pathlib.Path,
    output: pathlib.Path,
) -> pathlib.Path:
    run_command(
        [
            str(swiftc),
            "-O",
            "-warnings-as-errors",
            "-framework",
            "Metal",
            str(
                root
                / "li_installer"
                / "macos"
                / "li_installer_installation_probe.swift"
            ),
            "-o",
            str(output),
        ]
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
            relative = pathlib.PurePosixPath("li_installer")
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
        binaries = build_rust_components(
            root,
            cargo,
            temporary / "target",
            include_probe=operating_system == "linux",
        )
        dependency_manager = binaries["li_installer_dependency_manager"]
        if operating_system == "linux":
            installation_probe = binaries["li_installer_installation_probe"]
        else:
            if swiftc is None:
                raise InstallerBuildError("Swift compiler is required for macOS")
            installation_probe = build_macos_probe(
                root,
                executable_path(swiftc, "Swift compiler"),
                temporary / "li_installer_installation_probe",
            )
        stage_file(
            installation_probe,
            staging / "bin" / "li_installer_installation_probe",
            0o755,
        )
        stage_file(
            dependency_manager,
            staging / "bin" / "li_installer_dependency_manager",
            0o755,
        )
        stage_file(
            root / "schemas" / "li_installer_installation_probe_v1.schema.json",
            staging / "schemas" / "li_installer_installation_probe_v1.schema.json",
            0o644,
        )
        write_archive(staging, output)


# Parses the native build contract and returns a process exit status.
def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operating-system", choices=("linux", "macos"), required=True)
    parser.add_argument("--architecture", choices=("arm64", "x86_64"), required=True)
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
            parsed.cargo_command,
            parsed.output.resolve(strict=False),
            parsed.swiftc_command,
        )
    except InstallerBuildError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
