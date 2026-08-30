#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Audit Rust Core ownership, naming, comments, and test registration."""

from __future__ import annotations

import argparse
import pathlib
import re
from collections.abc import Sequence


FUNCTION_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*"
)
PACKAGE_RE = re.compile(r'^name\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
LIB_PATH_RE = re.compile(r'^path\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
MANAGER_DECLARATION_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z][A-Za-z0-9_]*Manager)\b",
    re.MULTILINE,
)
PRODUCTION_DATABASE_OPEN_RE = re.compile(r"\bDatabaseManager\s*::\s*open\s*\(")
TEST_MODULE_RE = re.compile(
    r"^#\[cfg\(test\)\]\s*\n\s*mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{",
    re.MULTILINE,
)
TEST_MODULE_END_RE = re.compile(r"^}\s*$", re.MULTILINE)
RUSQLITE_RE = re.compile(r"\brusqlite\b")
METADATA_DATABASE_RE = re.compile(r"\bmetadata\.sqlite3\b")
MEMBERS_RE = re.compile(r"members\s*=\s*\[(.*?)\]", re.DOTALL)
QUOTED_RE = re.compile(r'"([^"]+)"')
RELEASE_VERSION_RE = re.compile(r'^version\s*=\s*"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?"\s*$', re.MULTILINE)
WORKSPACE_VERSION_RE = re.compile(r"^version\.workspace\s*=\s*true\s*$", re.MULTILINE)
SPDX_LINE = "// SPDX-License-Identifier: AGPL-3.0-only"

MANAGER_CORE_MEMBERS = frozenset(
    {
        "audit",
        "authentication",
        "benchmark",
        "database",
        "gateway",
        "hardware",
        "node",
        "pairing",
        "placement",
        "runtime",
        "update",
        "watchdog",
    }
)
EXPECTED_MANAGER_TYPES = frozenset(
    {
        "AuditManager",
        "AuthenticationManager",
        "BenchmarkManager",
        "CoreUpdateManager",
        "DatabaseManager",
        "GatewayManager",
        "HardwareManager",
        "NodeManager",
        "PairingManager",
        "PlacementManager",
        "RuntimeManager",
        "WatchdogManager",
    }
)
APPLICATION_DATABASE_OPEN_OWNERS = frozenset(
    {
        "li_core_node_process.rs",
        "li_core_setup_identity.rs",
    }
)
RESIDENT_DATABASE_ISOLATED_MEMBERS = frozenset({"gateway", "watchdog"})


class CoreAuditError(RuntimeError):
    """The Rust Core workspace violates an ownership or regression contract."""


# Returns the exact workspace members declared by the Core composition root.
def workspace_members(core_root: pathlib.Path) -> tuple[str, ...]:
    manifest = core_root / "Cargo.toml"
    try:
        text = manifest.read_text(encoding="utf-8")
    except OSError as error:
        raise CoreAuditError("core/Cargo.toml is unavailable") from error
    match = MEMBERS_RE.search(text)
    if match is None:
        raise CoreAuditError("Core workspace members are unavailable")
    members = tuple(QUOTED_RE.findall(match.group(1)))
    if not members or len(members) != len(set(members)) or tuple(sorted(members)) != members:
        raise CoreAuditError("Core workspace members must be unique and sorted")
    if RELEASE_VERSION_RE.search(manifest_section(text, "workspace.package")) is None:
        raise CoreAuditError("Core workspace release version is unavailable or invalid")
    return members


# Returns one manifest section without requiring a host TOML dependency.
def manifest_section(text: str, name: str) -> str:
    marker = f"[{name}]"
    start = text.find(marker)
    if start < 0:
        raise CoreAuditError(f"Cargo manifest is missing [{name}]")
    body = text[start + len(marker) :]
    next_section = re.search(r"^\[", body, re.MULTILINE)
    return body if next_section is None else body[: next_section.start()]


# Returns resident Rust text with each explicit test-only module removed.
def resident_production_rust_source(text: str) -> str:
    retained = []
    cursor = 0
    while True:
        test_module = TEST_MODULE_RE.search(text, cursor)
        if test_module is None:
            retained.append(text[cursor:])
            return "".join(retained)
        retained.append(text[cursor : test_module.start()])
        module_end = TEST_MODULE_END_RE.search(text, test_module.end())
        if module_end is None:
            raise CoreAuditError("Rust test-only module is unterminated")
        cursor = module_end.end()


# Requires every named Rust function to carry one concise leading comment.
def validate_function_comments(path: pathlib.Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if FUNCTION_RE.match(line) is None:
            continue
        previous = index - 1
        while previous >= 0 and lines[previous].lstrip().startswith("#["):
            previous -= 1
        if previous < 0 or not lines[previous].lstrip().startswith("//"):
            raise CoreAuditError(
                f"Rust function lacks a leading comment: {path}:{index + 1}"
            )


# Audits one Rust Core member and returns its package identity.
def validate_member(core_root: pathlib.Path, member_name: str) -> str:
    if member_name.startswith("li_") or "/" in member_name or "\\" in member_name:
        raise CoreAuditError(f"Core directory must use its plain domain name: {member_name}")
    member = core_root / member_name
    manifest = member / "Cargo.toml"
    if not member.is_dir() or not manifest.is_file():
        raise CoreAuditError(f"Core workspace member is unavailable: {member_name}")
    text = manifest.read_text(encoding="utf-8")
    package = manifest_section(text, "package")
    package_match = PACKAGE_RE.search(package)
    lib_match = LIB_PATH_RE.search(manifest_section(text, "lib"))
    if package_match is None or not package_match.group(1).startswith("li_"):
        raise CoreAuditError(f"Core package lacks li_ namespace: {member_name}")
    if WORKSPACE_VERSION_RE.search(package) is None:
        raise CoreAuditError(f"Core package does not inherit the workspace version: {member_name}")
    if lib_match is None:
        raise CoreAuditError(f"Core library path is unavailable: {member_name}")
    library = pathlib.PurePosixPath(lib_match.group(1))
    if library.parent.as_posix() != "src" or not library.name.startswith("li_"):
        raise CoreAuditError(f"Core library lacks li_ namespace: {member_name}")
    if (member / "Cargo.lock").exists():
        raise CoreAuditError(f"Core member carries a duplicate Cargo.lock: {member_name}")
    readmes = tuple(member.glob("li_*_readme.md"))
    if len(readmes) != 1:
        raise CoreAuditError(f"Core member requires one li_ readme: {member_name}")
    tests = tuple(sorted((member / "tests").glob("li_*.rs")))
    if not tests:
        raise CoreAuditError(f"Core member has no li_ contract tests: {member_name}")
    rust_files = tuple(sorted((member / "src").rglob("*.rs"))) + tests
    for path in rust_files:
        if not path.name.startswith("li_"):
            raise CoreAuditError(f"Rust source lacks li_ namespace: {path}")
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines or lines[0] != SPDX_LINE:
            raise CoreAuditError(f"Rust source lacks SPDX identity: {path}")
        validate_function_comments(path)
    return package_match.group(1)


# Requires the complete Core workspace to expose exactly its twelve agreed lifecycle owners.
def validate_manager_ownership(core_root: pathlib.Path, members: Sequence[str]) -> None:
    if not MANAGER_CORE_MEMBERS.issubset(members):
        return
    declarations: dict[str, pathlib.Path] = {}
    duplicates: set[str] = set()
    for member_name in members:
        for path in sorted((core_root / member_name / "src").rglob("*.rs")):
            for manager_name in MANAGER_DECLARATION_RE.findall(
                path.read_text(encoding="utf-8")
            ):
                if manager_name in declarations:
                    duplicates.add(manager_name)
                declarations[manager_name] = path
    observed = frozenset(declarations)
    missing = sorted(EXPECTED_MANAGER_TYPES - observed)
    unexpected = sorted(observed - EXPECTED_MANAGER_TYPES)
    if missing or unexpected or duplicates:
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected: {', '.join(unexpected)}")
        if duplicates:
            details.append(f"duplicated: {', '.join(sorted(duplicates))}")
        raise CoreAuditError(
            "Core manager ownership must remain the exact twelve types ("
            + "; ".join(details)
            + ")"
        )


# Restricts production database lifecycle ownership to Node and closed setup bootstrap work.
def validate_application_database_ownership(
    core_root: pathlib.Path, members: Sequence[str]
) -> None:
    if "application" not in members or not MANAGER_CORE_MEMBERS.issubset(members):
        return
    violations = []
    for path in sorted((core_root / "application/src").rglob("*.rs")):
        production = resident_production_rust_source(
            path.read_text(encoding="utf-8")
        )
        if (
            PRODUCTION_DATABASE_OPEN_RE.search(production) is not None
            and path.name not in APPLICATION_DATABASE_OPEN_OWNERS
        ):
            violations.append(path.relative_to(core_root).as_posix())
    if violations:
        raise CoreAuditError(
            "production database open bypasses Node ownership: "
            + ", ".join(violations)
        )


# Keeps resident Gateway and Watchdog crates outside the writable database boundary.
def validate_resident_database_isolation(
    core_root: pathlib.Path, members: Sequence[str]
) -> None:
    violations = []
    for member_name in sorted(RESIDENT_DATABASE_ISOLATED_MEMBERS.intersection(members)):
        member = core_root / member_name
        manifest = member / "Cargo.toml"
        manifest_text = "\n".join(
            line
            for line in manifest.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        if RUSQLITE_RE.search(manifest_text) is not None:
            violations.append(f"{member_name}/Cargo.toml (rusqlite dependency)")
        for path in sorted((member / "src").rglob("*.rs")):
            production = resident_production_rust_source(
                path.read_text(encoding="utf-8")
            )
            markers = []
            if RUSQLITE_RE.search(production) is not None:
                markers.append("rusqlite")
            if METADATA_DATABASE_RE.search(production) is not None:
                markers.append("metadata.sqlite3")
            if PRODUCTION_DATABASE_OPEN_RE.search(production) is not None:
                markers.append("DatabaseManager::open")
            if markers:
                relative = path.relative_to(core_root).as_posix()
                violations.append(f"{relative} ({', '.join(markers)})")
    if violations:
        raise CoreAuditError(
            "resident database boundary violation: " + ", ".join(violations)
        )


# Audits the complete Rust Core workspace and returns its package identities.
def audit_core(core_root: pathlib.Path) -> tuple[str, ...]:
    core_root = core_root.resolve(strict=True)
    if not (core_root / "Cargo.lock").is_file():
        raise CoreAuditError("Core workspace Cargo.lock is unavailable")
    members = workspace_members(core_root)
    packages = tuple(validate_member(core_root, member) for member in members)
    if len(packages) != len(set(packages)):
        raise CoreAuditError("Core package identities are duplicated")
    validate_manager_ownership(core_root, members)
    validate_application_database_ownership(core_root, members)
    validate_resident_database_isolation(core_root, members)
    return packages


# Parses the audit command and returns one process exit status.
def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parsed = parser.parse_args(arguments)
    try:
        packages = audit_core(parsed.root)
    except (CoreAuditError, OSError) as error:
        parser.error(str(error))
    print(f"Rust Core audit: PASS ({len(packages)} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
