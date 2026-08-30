#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import pathlib
import tempfile
import unittest

from tools.li_core_audit import (
    EXPECTED_MANAGER_TYPES,
    MANAGER_CORE_MEMBERS,
    CoreAuditError,
    audit_core,
    validate_application_database_ownership,
    validate_manager_ownership,
    validate_resident_database_isolation,
)


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]


class CoreAuditTests(unittest.TestCase):
    # Accepts the complete checked-in Rust Core workspace.
    def test_accepts_current_workspace(self) -> None:
        packages = audit_core(REPOSITORY_ROOT / "core")
        self.assertIn("li_core_interface", packages)
        self.assertIn("li_database", packages)
        self.assertIn("li_node_manager", packages)
        self.assertIn("li_authentication_manager", packages)

    # Rejects a source file that drops the li_ ownership namespace.
    def test_rejects_source_without_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_value:
            core = self._fixture(pathlib.Path(temporary_value))
            (core / "fixture/src/plain.rs").write_text(
                SPDX_LINE + "\n\n// Runs one fixture.\nfn run() {}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CoreAuditError, "lacks li_ namespace"):
                audit_core(core)

    # Rejects a Rust function without its required responsibility comment.
    def test_rejects_function_without_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_value:
            core = self._fixture(pathlib.Path(temporary_value))
            source = core / "fixture/src/li_fixture.rs"
            source.write_text(SPDX_LINE + "\n\nfn run() {}\n", encoding="utf-8")
            with self.assertRaisesRegex(CoreAuditError, "lacks a leading comment"):
                audit_core(core)

    # Rejects an independently versioned crate so every native binary shares one Core identity.
    def test_rejects_package_version_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_value:
            core = self._fixture(pathlib.Path(temporary_value))
            manifest = core / "fixture/Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    "version.workspace = true", 'version = "9.9.9"'
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CoreAuditError, "does not inherit"):
                audit_core(core)

    # Applies namespace, license, and responsibility-comment checks to nested Rust binaries.
    def test_rejects_invalid_nested_binary_matrix(self) -> None:
        mutations = {
            "namespace": (
                "plain.rs",
                SPDX_LINE + "\n\n// Runs one fixture.\nfn run() {}\n",
                "lacks li_ namespace",
            ),
            "license": (
                "li_fixture_tool.rs",
                "// Runs one fixture.\nfn run() {}\n",
                "lacks SPDX identity",
            ),
            "comment": (
                "li_fixture_tool.rs",
                SPDX_LINE + "\n\nfn run() {}\n",
                "lacks a leading comment",
            ),
        }
        for mutation, (filename, source, expected) in mutations.items():
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary_value:
                core = self._fixture(pathlib.Path(temporary_value))
                binary = core / "fixture/src/bin" / filename
                binary.parent.mkdir()
                binary.write_text(source, encoding="utf-8")
                with self.assertRaisesRegex(CoreAuditError, expected):
                    audit_core(core)

    # Rejects missing, duplicated, or helper-promoted lifecycle ownership.
    def test_rejects_manager_ownership_drift(self) -> None:
        mutations = {
            "missing": ("AuditManager", "", "missing: AuditManager"),
            "unexpected": ("", "pub struct OperationManager {}\n", "unexpected: OperationManager"),
            "duplicated": (
                "",
                "pub struct NodeManager {}\n",
                "duplicated: NodeManager",
            ),
        }
        for name, (omitted, addition, expected) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_value:
                core = pathlib.Path(temporary_value) / "core"
                for member in MANAGER_CORE_MEMBERS:
                    (core / member / "src").mkdir(parents=True)
                declarations = "\n".join(
                    f"pub struct {manager} {{}}"
                    for manager in sorted(EXPECTED_MANAGER_TYPES)
                    if manager != omitted
                )
                (core / "node/src/li_node_manager.rs").write_text(
                    declarations,
                    encoding="utf-8",
                )
                (core / "audit/src/li_manager_mutation.rs").write_text(
                    addition,
                    encoding="utf-8",
                )

                with self.assertRaisesRegex(CoreAuditError, expected):
                    validate_manager_ownership(core, tuple(sorted(MANAGER_CORE_MEMBERS)))

    # Rejects a resident or CLI that takes a second production database lifecycle.
    def test_rejects_application_database_ownership_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_value:
            core = pathlib.Path(temporary_value) / "core"
            source = core / "application/src/li_core_gateway_process.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                "#[cfg(test)]\nmod tests {\n"
                "    fn fixture() { DatabaseManager::open(temporary); }\n"
                "}\n",
                encoding="utf-8",
            )
            members = tuple(sorted(MANAGER_CORE_MEMBERS | {"application"}))
            validate_application_database_ownership(core, members)
            source.write_text(
                source.read_text(encoding="utf-8")
                + "\nfn compose() { DatabaseManager::open(configuration); }\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                CoreAuditError,
                "application/src/li_core_gateway_process.rs",
            ):
                validate_application_database_ownership(core, members)

    # Rejects every resident dependency or production-source database bypass.
    def test_rejects_resident_database_boundary_mutation_matrix(self) -> None:
        mutations = {
            "cargo dependency": (
                "watchdog/Cargo.toml",
                "\n[dev-dependencies]\nrusqlite = \"0.32\"\n",
                "watchdog/Cargo.toml (rusqlite dependency)",
            ),
            "rusqlite import": (
                "gateway/src/li_gateway_manager.rs",
                "\n#[cfg(test)]\nmod tests {\n"
                "    use rusqlite::Connection;\n"
                "}\n"
                "use rusqlite::Connection;\n",
                "gateway/src/li_gateway_manager.rs (rusqlite)",
            ),
            "metadata database": (
                "watchdog/src/li_watchdog_manager.rs",
                '\nconst PATH: &str = "metadata.sqlite3";\n',
                "watchdog/src/li_watchdog_manager.rs (metadata.sqlite3)",
            ),
            "database open": (
                "gateway/src/li_gateway_manager.rs",
                "\n// Opens one forbidden resident database.\n"
                "fn open() { DatabaseManager :: open(configuration); }\n",
                "gateway/src/li_gateway_manager.rs (DatabaseManager::open)",
            ),
        }
        for name, (relative, addition, expected) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_value:
                core = self._resident_fixture(pathlib.Path(temporary_value))
                path = core / relative
                path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
                with self.assertRaises(CoreAuditError) as raised:
                    validate_resident_database_isolation(core, ("gateway", "watchdog"))
                self.assertIn(expected, str(raised.exception))

    # Allows database vocabulary only inside a resident source's test-only module.
    def test_resident_database_boundary_ignores_test_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_value:
            core = self._resident_fixture(pathlib.Path(temporary_value))
            source = core / "watchdog/src/li_watchdog_manager.rs"
            source.write_text(
                source.read_text(encoding="utf-8")
                + "\n#[cfg(test)]\nmod tests {\n"
                + "    use rusqlite::Connection;\n"
                + '    const PATH: &str = "metadata.sqlite3";\n'
                + "    fn open() { DatabaseManager::open(temporary); }\n"
                + "}\n",
                encoding="utf-8",
            )
            validate_resident_database_isolation(core, ("gateway", "watchdog"))

    # Creates minimal resident crate inputs for the database-isolation audit.
    def _resident_fixture(self, root: pathlib.Path) -> pathlib.Path:
        core = root / "core"
        for member in ("gateway", "watchdog"):
            source = core / member / "src" / f"li_{member}_manager.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                SPDX_LINE + "\n\n// Runs one resident fixture.\nfn run() {}\n",
                encoding="utf-8",
            )
            (core / member / "Cargo.toml").write_text(
                f'[package]\nname = "li_{member}_manager"\n\n[dependencies]\n',
                encoding="utf-8",
            )
        return core

    # Creates one minimal valid Rust Core workspace fixture.
    def _fixture(self, root: pathlib.Path) -> pathlib.Path:
        core = root / "core"
        member = core / "fixture"
        (member / "src").mkdir(parents=True)
        (member / "tests").mkdir()
        (core / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["fixture"]\nresolver = "2"\n\n'
            '[workspace.package]\nversion = "1.2.3-rc.4"\n',
            encoding="utf-8",
        )
        (core / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (member / "Cargo.toml").write_text(
            '[package]\nname = "li_fixture"\nversion.workspace = true\n'
            'edition = "2021"\n\n[lib]\npath = "src/li_fixture.rs"\n',
            encoding="utf-8",
        )
        (member / "li_fixture_readme.md").write_text("# Fixture\n", encoding="utf-8")
        source = SPDX_LINE + "\n\n// Runs one fixture.\nfn run() {}\n"
        (member / "src/li_fixture.rs").write_text(source, encoding="utf-8")
        (member / "tests/li_fixture.rs").write_text(source, encoding="utf-8")
        return core


SPDX_LINE = "// SPDX-License-Identifier: AGPL-3.0-only"


if __name__ == "__main__":
    unittest.main()
