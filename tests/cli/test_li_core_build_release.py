#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

from tools.li_core_build_release import (
    ARCHIVE_ROOT,
    MANIFEST_NAME,
    REPRODUCIBLE_CARGO_HOME,
    REPRODUCIBLE_SOURCE_ROOT,
    CoreReleaseBuildError,
    binary_names,
    build_archive,
    build_rust_binaries,
    canonical_json,
    release_payloads,
    rust_core_version,
    verify_archive,
    write_archive,
)
from tools.li_installer_build_assets import (
    MAXIMUM_SCHEMA_BYTES,
    REPRODUCIBLE_CARGO_HOME as INSTALLER_REPRODUCIBLE_CARGO_HOME,
    REPRODUCIBLE_SOURCE_ROOT as INSTALLER_REPRODUCIBLE_SOURCE_ROOT,
    InstallerBuildError,
    build_archive as build_installer_archive,
    build_macos_probe as build_installer_macos_probe,
    build_rust_installer,
    main as installer_build_main,
    verify_archive as verify_installer_archive,
    write_archive as write_installer_archive,
)

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]


class CoreReleaseBuildTests(unittest.TestCase):
    # Builds byte-identical Linux and macOS archives with each exact platform file set.
    def test_archives_are_deterministic_and_platform_closed(self) -> None:
        for operating_system, architecture in (
            ("linux", "x86_64"),
            ("macos", "arm64"),
        ):
            with self.subTest(operating_system=operating_system), tempfile.TemporaryDirectory() as value:
                root = pathlib.Path(value)
                binaries = self._binaries(root, operating_system)
                manifest, payloads = release_payloads(
                    operating_system,
                    architecture,
                    "1.2.3-rc.4",
                    binaries,
                )
                first = root / "first.tar.gz"
                second = root / "second.tar.gz"
                write_archive(first, manifest, payloads)
                write_archive(second, manifest, payloads)
                self.assertEqual(first.read_bytes(), second.read_bytes())
                observed = verify_archive(
                    first,
                    operating_system,
                    architecture,
                    "1.2.3-rc.4",
                )
                self.assertEqual(
                    observed["files"],
                    [
                        {
                            "path": f"bin/{name}",
                            "bytes": len(f"native-{name}".encode()),
                            "mode": 0o755,
                            "sha256": observed["files"][index]["sha256"],
                        }
                        for index, name in enumerate(binary_names(operating_system))
                    ],
                )
                paths = [record["path"] for record in observed["files"]]
                self.assertEqual(paths, [f"bin/{name}" for name in binary_names(operating_system)])
                self.assertEqual("bin/li_watchdog" in paths, operating_system == "linux")
                self.assertEqual(
                    "bin/li_hardware_macos_probe" in paths,
                    operating_system == "macos",
                )

    # Rejects every structural or semantic mutation of a previously valid release archive.
    def test_archive_mutation_matrix_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            binaries = {
                name: self._executable(root / name, b"x")
                for name in binary_names("linux")
            }
            manifest, payloads = release_payloads(
                "linux", "x86_64", "1.2.3", binaries
            )
            valid = root / "valid.tar.gz"
            write_archive(valid, manifest, payloads)
            for mutation in (
                "extra_member",
                "link",
                "binary_mode",
                "manifest_extra",
                "manifest_digest",
                "manifest_noncanonical",
                "schema_version_boolean",
                "file_bytes_boolean",
                "file_bytes_float",
                "file_mode_boolean",
                "file_mode_float",
            ):
                with self.subTest(mutation=mutation):
                    changed = root / f"{mutation}.tar.gz"
                    self._mutated_archive(valid, changed, mutation)
                    with self.assertRaises(CoreReleaseBuildError):
                        verify_archive(changed, "linux", "x86_64", "1.2.3")
            for operating_system, architecture, version in (
                ("macos", "arm64", "1.2.3"),
                ("linux", "arm64", "1.2.3"),
                ("macos", "x86_64", "1.2.3"),
                ("linux", "x86_64", "1.2.4"),
            ):
                with self.subTest(
                    operating_system=operating_system,
                    architecture=architecture,
                    version=version,
                ), self.assertRaises(CoreReleaseBuildError):
                    verify_archive(valid, operating_system, architecture, version)

    # Drives the injected native compiler boundary and packages every macOS output exactly once.
    def test_native_build_composition_uses_exact_rust_and_swift_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            repository = root / "repository"
            (repository / "core/hardware/macos").mkdir(parents=True)
            (repository / "core/Cargo.toml").write_text(
                '[workspace]\n\n[workspace.package]\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            (repository / "core/hardware/macos/li_hardware_macos_probe.swift").write_text(
                "// fixture\n", encoding="utf-8"
            )
            output = root / "letsinfer-macos-arm64.tar.gz"
            calls: list[list[str]] = []

            # Materializes deterministic fake compiler outputs at the exact requested paths.
            def run(arguments: list[str], _environment: object = None) -> None:
                calls.append(arguments)
                if arguments[0].endswith("true") and "cargo" not in arguments[0]:
                    if "--target-dir" in arguments:
                        target = pathlib.Path(arguments[arguments.index("--target-dir") + 1])
                        names = [
                            arguments[index + 1]
                            for index, value in enumerate(arguments)
                            if value == "--bin"
                        ]
                        for name in names:
                            self._executable(target / "release" / name, f"native-{name}".encode())
                        return
                    swift_output = pathlib.Path(arguments[arguments.index("-o") + 1])
                    self._executable(swift_output, b"native-li_hardware_macos_probe")
                    return
                self.fail("unexpected compiler command")

            with mock.patch(
                "tools.li_core_build_release.host_target", return_value=("macos", "arm64")
            ), mock.patch("tools.li_core_build_release.run_command", side_effect=run):
                observed = build_archive(
                    repository,
                    "macos",
                    "arm64",
                    "1.2.3",
                    pathlib.Path("/usr/bin/true"),
                    output,
                    pathlib.Path("/usr/bin/true"),
                )
            self.assertEqual(len(calls), 3)
            self.assertIn("--locked", calls[0])
            self.assertNotIn("li_watchdog", calls[0])
            self.assertEqual(
                calls[0][calls[0].index("--package") + 1],
                "li_core_application",
            )
            self.assertNotIn("li_benchmark_worker", calls[0])
            self.assertEqual(
                calls[1][calls[1].index("--package") + 1],
                "li_benchmark_worker",
            )
            self.assertEqual(calls[1][-2:], ["--bin", "li_benchmark_worker"])
            self.assertIn("-warnings-as-errors", calls[2])
            self.assertIn("-file-prefix-map", calls[2])
            self.assertIn(
                f"{repository.resolve()}={REPRODUCIBLE_SOURCE_ROOT}", calls[2]
            )
            self.assertIn("-debug-prefix-map", calls[2])
            self.assertEqual(
                [record["path"] for record in observed["files"]],
                [f"bin/{name}" for name in binary_names("macos")],
            )

    # Builds each Rust binary only through its owning package on every released platform.
    def test_rust_binary_commands_preserve_package_ownership(self) -> None:
        for operating_system in ("linux", "macos"):
            with self.subTest(operating_system=operating_system), tempfile.TemporaryDirectory() as value:
                root = pathlib.Path(value)
                repository = root / "repository"
                (repository / "core").mkdir(parents=True)
                cargo_home = (root / "cargo-home").resolve()
                calls: list[list[str]] = []

                # Materializes only the exact outputs named by each package-owned command.
                def run(arguments: list[str], environment: object = None) -> None:
                    calls.append(arguments)
                    self.assertNotIn("RUSTFLAGS", environment)
                    self.assertEqual(environment["CARGO_HOME"], str(cargo_home))
                    self.assertEqual(
                        environment["CARGO_ENCODED_RUSTFLAGS"],
                        "\x1f".join(
                            (
                                "-D",
                                "warnings",
                                f"--remap-path-prefix={cargo_home}={REPRODUCIBLE_CARGO_HOME}",
                                f"--remap-path-prefix={repository.resolve()}={REPRODUCIBLE_SOURCE_ROOT}",
                            )
                        ),
                    )
                    target = pathlib.Path(arguments[arguments.index("--target-dir") + 1])
                    for index, value in enumerate(arguments):
                        if value == "--bin":
                            name = arguments[index + 1]
                            self._executable(target / "release" / name, f"native-{name}".encode())

                with mock.patch.dict(os.environ, {"CARGO_HOME": str(cargo_home)}), mock.patch(
                    "tools.li_core_build_release.run_command", side_effect=run
                ):
                    outputs = build_rust_binaries(
                        repository,
                        pathlib.Path("/usr/bin/cargo"),
                        root / "target",
                        operating_system,
                    )
                self.assertEqual(len(calls), 2)
                self.assertTrue(all("--locked" in call for call in calls))
                application, worker = calls
                self.assertEqual(
                    application[application.index("--package") + 1],
                    "li_core_application",
                )
                application_bins = [
                    application[index + 1]
                    for index, value in enumerate(application)
                    if value == "--bin"
                ]
                self.assertNotIn("li_benchmark_worker", application_bins)
                self.assertEqual(
                    worker[worker.index("--package") + 1],
                    "li_benchmark_worker",
                )
                self.assertEqual(worker[-2:], ["--bin", "li_benchmark_worker"])
                expected = {
                    name
                    for name in binary_names(operating_system)
                    if name != "li_hardware_macos_probe"
                }
                self.assertEqual(set(outputs), expected)
                self.assertEqual(set(application_bins) | {"li_benchmark_worker"}, expected)

    # Removes each distinct installer checkout path from the native Rust payload identity.
    def test_installer_rust_build_remaps_the_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            repository = root / "different source root"
            repository.mkdir()
            target = root / "target"
            cargo_home = (root / "different cargo home").resolve()

            # Materializes the requested installer after verifying the exact compiler environment.
            def run(arguments: list[str], environment: object = None) -> None:
                self.assertNotIn("RUSTFLAGS", environment)
                self.assertEqual(environment["CARGO_HOME"], str(cargo_home))
                self.assertEqual(
                    environment["CARGO_ENCODED_RUSTFLAGS"],
                    "\x1f".join(
                        (
                            "-D",
                            "warnings",
                            f"--remap-path-prefix={cargo_home}={INSTALLER_REPRODUCIBLE_CARGO_HOME}",
                            f"--remap-path-prefix={repository.resolve()}={INSTALLER_REPRODUCIBLE_SOURCE_ROOT}",
                        )
                    ),
                )
                output = pathlib.Path(arguments[arguments.index("--target-dir") + 1])
                self._executable(output / "release/li_installer", b"native-installer")

            with mock.patch.dict(os.environ, {"CARGO_HOME": str(cargo_home)}), mock.patch(
                "tools.li_installer_build_assets.run_command", side_effect=run
            ):
                output = build_rust_installer(
                    repository,
                    pathlib.Path("/usr/bin/cargo"),
                    target,
                )
            self.assertEqual(output.read_bytes(), b"native-installer")

    # Accepts each closed native installer layout and rejects every structural mutation.
    def test_installer_archive_mutation_matrix_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            valid_archives = {}
            for operating_system, architecture in (
                ("linux", "arm64"),
                ("linux", "x86_64"),
                ("macos", "arm64"),
            ):
                with self.subTest(
                    operating_system=operating_system,
                    mutation="valid",
                ):
                    archive = self._installer_archive(
                        root / f"{operating_system}_{architecture}",
                        operating_system,
                        architecture,
                    )
                    valid_archives[(operating_system, architecture)] = archive
                    verify_installer_archive(
                        archive,
                        operating_system,
                        architecture,
                    )

            for mutation in (
                "path",
                "order",
                "type",
                "mode",
                "size",
                "bound",
                "link",
                "corruption",
                "extra",
                "missing",
                "wrong_elf_architecture",
                "malformed_elf_header",
            ):
                with self.subTest(mutation=mutation):
                    changed = root / mutation / "li_installer_linux_x86_64.tar.gz"
                    self._mutated_installer_archive(
                        valid_archives[("linux", "x86_64")],
                        changed,
                        mutation,
                    )
                    with self.assertRaises(InstallerBuildError):
                        verify_installer_archive(changed, "linux", "x86_64")
            for mutation in (
                "wrong_macho_architecture",
                "wrong_macho_probe_architecture",
                "malformed_macho_header",
            ):
                with self.subTest(mutation=mutation):
                    changed = root / mutation / "li_installer_macos_arm64.tar.gz"
                    self._mutated_installer_archive(
                        valid_archives[("macos", "arm64")],
                        changed,
                        mutation,
                    )
                    with self.assertRaises(InstallerBuildError):
                        verify_installer_archive(changed, "macos", "arm64")

    # Verifies each completed native build before the builder reports success.
    def test_installer_builder_verifies_each_completed_archive(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            repository = root / "repository"
            schema = (
                repository
                / "schemas/li_installer_installation_probe_v1.schema.json"
            )
            schema.parent.mkdir(parents=True)
            schema.write_text("{}\n", encoding="utf-8")
            installer = self._executable(root / "li_installer", b"native-installer")
            output = root / "li_installer_linux_x86_64.tar.gz"
            events: list[str] = []

            # Records the archive publication boundary without compiling native artifacts.
            def write(_staging: pathlib.Path, _output: pathlib.Path) -> None:
                events.append("write")

            # Records the required post-publication verification boundary.
            def verify(
                _archive: pathlib.Path,
                _operating_system: str,
                _architecture: str,
            ) -> None:
                events.append("verify")

            with mock.patch(
                "tools.li_installer_build_assets.validate_target"
            ), mock.patch(
                "tools.li_installer_build_assets.build_rust_installer",
                return_value=installer,
            ), mock.patch(
                "tools.li_installer_build_assets.write_archive",
                side_effect=write,
            ), mock.patch(
                "tools.li_installer_build_assets.verify_archive",
                side_effect=verify,
            ):
                build_installer_archive(
                    repository,
                    "linux",
                    "x86_64",
                    pathlib.Path("/usr/bin/true"),
                    output,
                    None,
                )
            self.assertEqual(events, ["write", "verify"])

    # Drives verifier-only CLI dispatch and rejects an otherwise valid misnamed archive.
    def test_installer_verify_cli_enforces_the_output_name(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            archive = self._installer_archive(root / "valid", "linux", "arm64")
            arguments = [
                "--verify-archive",
                "--operating-system",
                "linux",
                "--architecture",
                "arm64",
                "--output",
                str(archive),
            ]
            self.assertEqual(installer_build_main(arguments), 0)
            wrong_name = root / "wrong-name.tar.gz"
            wrong_name.write_bytes(archive.read_bytes())
            arguments[-1] = str(wrong_name)
            with mock.patch("sys.stderr", io.StringIO()), self.assertRaisesRegex(
                SystemExit,
                "2",
            ):
                installer_build_main(arguments)

    # Gives every macOS installer probe build one private output-local module cache.
    def test_installer_macos_probe_isolates_swift_module_caches(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            calls: list[tuple[list[str], dict[str, str]]] = []

            # Captures each exact Swift compiler environment without executing the compiler.
            def run(arguments: list[str], environment: dict[str, str]) -> None:
                calls.append((arguments, environment.copy()))

            with mock.patch.dict(
                os.environ,
                {
                    "CLANG_MODULE_CACHE_PATH": "/shared/clang",
                    "SWIFT_MODULECACHE_PATH": "/shared/swift",
                },
            ), mock.patch(
                "tools.li_installer_build_assets.run_command",
                side_effect=run,
            ):
                for name in ("first", "second"):
                    output = root / name / "li_installer_macos_probe"
                    output.parent.mkdir()
                    build_installer_macos_probe(
                        root,
                        pathlib.Path("/usr/bin/swiftc"),
                        output,
                    )

            self.assertEqual(len(calls), 2)
            caches = []
            for arguments, environment in calls:
                output = pathlib.Path(arguments[arguments.index("-o") + 1])
                cache = output.parent / "swift_module_cache"
                caches.append(cache)
                self.assertEqual(environment["CLANG_MODULE_CACHE_PATH"], str(cache))
                self.assertEqual(environment["SWIFT_MODULECACHE_PATH"], str(cache))
                self.assertEqual(stat.S_IMODE(cache.stat().st_mode), 0o700)
            self.assertNotEqual(caches[0], caches[1])

    # Binds release tooling to the exact shared Rust package version before compiler execution.
    def test_native_build_rejects_workspace_version_drift(self) -> None:
        self.assertEqual(rust_core_version(REPOSITORY_ROOT), "0.11.0-rc.114")
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            (root / "core").mkdir()
            (root / "core/Cargo.toml").write_text(
                '[workspace]\n\n[workspace.package]\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            with mock.patch(
                "tools.li_core_build_release.host_target", return_value=("linux", "x86_64")
            ), self.assertRaisesRegex(CoreReleaseBuildError, "differs"):
                build_archive(
                    root,
                    "linux",
                    "x86_64",
                    "1.2.4",
                    pathlib.Path("/usr/bin/true"),
                    root / "letsinfer-linux-x86_64.tar.gz",
                    None,
                )

    # Requires every released platform to build and upload one native Core archive.
    def test_release_workflow_uses_the_native_core_matrix(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/release-core.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('source="$RUNNER_TEMP/native-source/letsinfer"', workflow)
        self.assertEqual(
            workflow.count('python3 "$source/tools/li_core_build_release.py"'),
            1,
        )
        self.assertEqual(
            workflow.count('python3 "$source/tools/li_installer_build_assets.py"'),
            2,
        )
        self.assertNotIn("native-source-first", workflow)
        self.assertNotIn("native-source-second", workflow)
        self.assertNotIn("li_core_first", workflow)
        self.assertNotIn("li_core_second", workflow)
        self.assertEqual(workflow.count("--verify-archive"), 1)
        self.assertIn('--version "$version"', workflow)
        self.assertIn('--manifest-path "$source/core/Cargo.toml"', workflow)
        self.assertNotIn("from core import PRODUCT_VERSION", workflow)
        self.assertIn("runner: ubuntu-24.04-arm", workflow)
        self.assertIn("runner: ubuntu-24.04", workflow)
        self.assertIn("runner: macos-14", workflow)
        self.assertIn("name: letsinfer_${{ matrix.identity }}", workflow)
        self.assertIn("pattern: letsinfer_*", workflow)
        self.assertNotIn(
            'cp "$RUNNER_TEMP/source-a.tar.gz" "dist/letsinfer-$platform.tar.gz"',
            workflow,
        )

    # Builds a release push once from the exact source already validated by its promotion PR.
    def test_release_workflow_builds_the_promoted_source_without_retesting(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/release-core.yml").read_text(
            encoding="utf-8"
        )
        freeze_start = workflow.index("  freeze-source:\n")
        build_start = workflow.index("  build-native-installer:\n")
        publish_start = workflow.index("  publish:\n")
        freeze = workflow[freeze_start:build_start]
        build = workflow[build_start:publish_start]

        self.assertIn("if: github.event_name == 'pull_request'", workflow)
        self.assertNotIn("needs:\n      - validate-linux", freeze)
        self.assertIn("name: li_core_frozen_source", freeze)
        self.assertNotIn("name: letsinfer_core_frozen_source", workflow)
        self.assertIn(
            "path: ${{ runner.temp }}/frozen-source/letsinfer-source.tar.gz",
            freeze,
        )
        self.assertIn("needs:\n      - freeze-source", build)
        self.assertIn("name: li_core_frozen_source", build)
        self.assertIn(
            'frozen_source="$RUNNER_TEMP/frozen-source/letsinfer-source.tar.gz"',
            build,
        )
        self.assertEqual(build.count('tar -xzf "$frozen_source"'), 1)
        self.assertNotIn("tools.source_archive build", build)
        self.assertEqual(freeze.count("tools.source_archive build"), 1)
        self.assertNotIn("cmp \\\n", freeze)
        publish = workflow[publish_start:]
        self.assertNotIn("validate-linux", publish)
        self.assertNotIn("validate-macos", publish)

    # Proves standalone installer CI also compares builds from distinct source roots.
    def test_installer_workflow_compares_independent_source_roots(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/li_installer.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('first_source="$RUNNER_TEMP/native-source-first/letsinfer"', workflow)
        self.assertIn('second_source="$RUNNER_TEMP/native-source-second/letsinfer"', workflow)
        self.assertIn('CARGO_HOME="$RUNNER_TEMP/cargo-home-first"', workflow)
        self.assertIn('CARGO_HOME="$RUNNER_TEMP/cargo-home-second"', workflow)
        self.assertIn('python3 "$first_source/tools/li_installer_build_assets.py"', workflow)
        self.assertIn('python3 "$second_source/tools/li_installer_build_assets.py"', workflow)
        self.assertIn("cmp \\\n", workflow)
        self.assertEqual(workflow.count("--verify-archive"), 1)
        self.assertNotIn("tar -tzf", workflow)

    # Keeps native builds responsive to owned inputs without following the separate Mac app.
    def test_native_workflow_triggers_are_bounded_to_owned_inputs(self) -> None:
        release_trigger = (
            REPOSITORY_ROOT / ".github/workflows/release-core.yml"
        ).read_text(encoding="utf-8").partition("\nconcurrency:\n")[0]
        installer_trigger = (
            REPOSITORY_ROOT / ".github/workflows/li_installer.yml"
        ).read_text(encoding="utf-8").partition("\nconcurrency:\n")[0]

        self.assertEqual(release_trigger.count("    paths-ignore:\n"), 2)
        for path in (
            '      - "apps/macos/**"',
            '      - ".github/workflows/release-macos.yml"',
            '      - "documentation/operations/macos-release.md"',
        ):
            self.assertEqual(release_trigger.count(path), 2, path)
        for path in (
            '      - "rust-toolchain.toml"',
            '      - "tools/source_archive.py"',
        ):
            self.assertEqual(installer_trigger.count(path), 2, path)

    # Binds every Rust CI process to the repository's exact compiler and native host.
    def test_rust_workflows_select_and_verify_the_exact_native_toolchain(self) -> None:
        declaration = (
            '[toolchain]\n'
            'channel = "1.97.1"\n'
            'components = ["rustfmt"]\n'
            'profile = "minimal"\n'
        )
        self.assertEqual(
            (REPOSITORY_ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"),
            declaration,
        )
        expected_workflows = {
            "core-regression.yml",
            "li_installer.yml",
            "release-core.yml",
        }
        observed_workflows = set()
        for path in sorted((REPOSITORY_ROOT / ".github/workflows").glob("*.yml")):
            workflow = path.read_text(encoding="utf-8")
            jobs = workflow.partition("\njobs:\n")[2]
            if re.search(r"\b(?:cargo|rustc)\b", jobs) is None:
                continue
            observed_workflows.add(path.name)
            starts = list(
                re.finditer(r"^  ([a-z][a-z0-9-]+):\n", jobs, re.MULTILINE)
            )
            for index, start in enumerate(starts):
                end = (
                    starts[index + 1].start()
                    if index + 1 < len(starts)
                    else len(jobs)
                )
                job = jobs[start.start() : end]
                if re.search(r"\b(?:cargo|rustc)\b", job) is not None:
                    self.assertEqual(
                        job.count("- name: Select and verify exact Rust toolchain"),
                        1,
                        f"{path.name}:{start.group(1)}",
                    )
        self.assertEqual(observed_workflows, expected_workflows)

        for name, selection_count, hosts in (
            ("core-regression.yml", 1, ("x86_64-unknown-linux-gnu",)),
            (
                "li_installer.yml",
                1,
                (
                    "aarch64-unknown-linux-gnu",
                    "x86_64-unknown-linux-gnu",
                    "aarch64-apple-darwin",
                ),
            ),
            (
                "release-core.yml",
                4,
                (
                    "aarch64-unknown-linux-gnu",
                    "x86_64-unknown-linux-gnu",
                    "aarch64-apple-darwin",
                ),
            ),
        ):
            with self.subTest(workflow=name):
                workflow = (
                    REPOSITORY_ROOT / ".github/workflows" / name
                ).read_text(encoding="utf-8")
                self.assertIn('LI_RUST_VERSION: "1.97.1"', workflow)
                self.assertEqual(
                    workflow.count("- name: Select and verify exact Rust toolchain"),
                    selection_count,
                )
                self.assertEqual(
                    workflow.count(
                        'rustup toolchain install "$toolchain" --profile minimal --component rustfmt'
                    ),
                    selection_count,
                )
                self.assertEqual(
                    workflow.count("rustc --version --verbose"),
                    selection_count * 2,
                )
                self.assertEqual(
                    workflow.count("cargo --version"),
                    selection_count,
                )
                self.assertEqual(
                    workflow.count(
                        "printf 'RUSTUP_TOOLCHAIN=%s\\n' \"$toolchain\" >> \"$GITHUB_ENV\""
                    ),
                    selection_count,
                )
                for host in hosts:
                    self.assertIn(host, workflow)
                self.assertNotIn("XCODE_VERSION", workflow)
                self.assertNotIn("xcode-select", workflow)

    # Requires the native updater to accept the exact ordered payload emitted by the builder.
    def test_core_update_inventory_matches_release_builder(self) -> None:
        source = (
            REPOSITORY_ROOT / "core/update/src/li_core_update_artifact_provider.rs"
        ).read_text(encoding="utf-8")
        start = source.index("fn file_paths(self)")
        end = source.index("// Stores one fully validated native Core release manifest.", start)
        inventory = source[start:end]
        for operating_system, arm in (
            ("linux", "Self::LinuxArm64 | Self::LinuxX86_64"),
            ("macos", "Self::MacosArm64"),
        ):
            with self.subTest(operating_system=operating_system):
                match = re.search(
                    rf"{re.escape(arm)}\s*=>\s*&\[(?P<paths>.*?)\]",
                    inventory,
                    re.DOTALL,
                )
                self.assertIsNotNone(match)
                observed = re.findall(
                    r'"(bin/li_[a-z0-9_]+)"',
                    match.group("paths"),
                )
                self.assertEqual(
                    observed,
                    [f"bin/{name}" for name in binary_names(operating_system)],
                )

    # Creates every executable fixture required by one platform release.
    def _binaries(self, root: pathlib.Path, operating_system: str) -> dict[str, pathlib.Path]:
        return {
            name: self._executable(root / name, f"native-{name}".encode())
            for name in binary_names(operating_system)
        }

    # Creates one non-empty owner-executable fixture file.
    def _executable(self, path: pathlib.Path, content: bytes) -> pathlib.Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o755)
        return path

    # Writes one minimal valid installer archive for a requested platform.
    def _installer_archive(
        self,
        root: pathlib.Path,
        operating_system: str,
        architecture: str,
    ) -> pathlib.Path:
        staging = root / "staging"
        self._executable(
            staging / "bin/li_installer",
            self._installer_executable_header(operating_system, architecture),
        )
        if operating_system == "macos":
            self._executable(
                staging / "bin/li_installer_macos_probe",
                self._installer_executable_header(operating_system, architecture),
            )
        schema = staging / "schemas/li_installer_installation_probe_v1.schema.json"
        schema.parent.mkdir(parents=True)
        schema.write_text("{}\n", encoding="utf-8")
        archive = root / f"li_installer_{operating_system}_{architecture}.tar.gz"
        write_installer_archive(staging, archive)
        return archive

    # Returns one minimal valid native executable header for an installer fixture.
    def _installer_executable_header(
        self,
        operating_system: str,
        architecture: str,
    ) -> bytes:
        if operating_system == "linux":
            machine = 183 if architecture == "arm64" else 62
            header = bytearray(64)
            header[:4] = b"\x7fELF"
            header[4:7] = bytes((2, 1, 1))
            header[16:18] = (3).to_bytes(2, "little")
            header[18:20] = machine.to_bytes(2, "little")
            header[20:24] = (1).to_bytes(4, "little")
            return bytes(header)
        header = bytearray(32)
        header[:4] = (0xFEEDFACF).to_bytes(4, "little")
        header[4:8] = (0x0100000C).to_bytes(4, "little")
        header[12:16] = (2).to_bytes(4, "little")
        return bytes(header)

    # Rewrites one valid installer archive with one exact hostile mutation.
    def _mutated_installer_archive(
        self,
        source: pathlib.Path,
        destination: pathlib.Path,
        mutation: str,
    ) -> None:
        destination.parent.mkdir(parents=True)
        if mutation == "corruption":
            content = source.read_bytes()
            destination.write_bytes(content[: max(1, len(content) // 2)])
            return
        with tarfile.open(source, "r:gz") as archive:
            records = []
            for member in archive.getmembers():
                content = archive.extractfile(member).read() if member.isfile() else None
                records.append((member, content))
        binary_index = next(
            index
            for index, (member, _content) in enumerate(records)
            if member.name == "installer/bin/li_installer"
        )
        probe_index = next(
            (
                index
                for index, (member, _content) in enumerate(records)
                if member.name == "installer/bin/li_installer_macos_probe"
            ),
            None,
        )
        schema_index = next(
            index
            for index, (member, _content) in enumerate(records)
            if member.name.endswith("installation_probe_v1.schema.json")
        )
        if mutation == "path":
            records[0][0].name = "../installer"
        elif mutation == "order":
            records[1], records[2] = records[2], records[1]
        elif mutation == "type":
            member, _content = records[1]
            member.type = tarfile.REGTYPE
            member.size = 1
            records[1] = (member, b"x")
        elif mutation == "mode":
            records[binary_index][0].mode = 0o644
        elif mutation == "size":
            member, _content = records[binary_index]
            member.size = 0
            records[binary_index] = (member, b"")
        elif mutation == "bound":
            member, _content = records[schema_index]
            content = b"x" * (MAXIMUM_SCHEMA_BYTES + 1)
            member.size = len(content)
            records[schema_index] = (member, content)
        elif mutation == "link":
            member, _content = records[binary_index]
            member.type = tarfile.SYMTYPE
            member.linkname = "li_installer"
            member.size = 0
            records[binary_index] = (member, None)
        elif mutation == "extra":
            extra = tarfile.TarInfo("installer/extra")
            extra.type = tarfile.REGTYPE
            extra.mode = 0o644
            extra.uid = 0
            extra.gid = 0
            extra.uname = "root"
            extra.gname = "root"
            extra.mtime = 0
            extra.size = 1
            records.append((extra, b"x"))
        elif mutation == "missing":
            records.pop(schema_index)
        elif mutation == "wrong_elf_architecture":
            member, content = records[binary_index]
            changed = bytearray(content)
            changed[18:20] = (183).to_bytes(2, "little")
            records[binary_index] = (member, bytes(changed))
        elif mutation == "malformed_elf_header":
            member, content = records[binary_index]
            changed = bytearray(content)
            changed[:4] = b"ELF!"
            records[binary_index] = (member, bytes(changed))
        elif mutation == "wrong_macho_architecture":
            member, content = records[binary_index]
            changed = bytearray(content)
            changed[4:8] = (0x01000007).to_bytes(4, "little")
            records[binary_index] = (member, bytes(changed))
        elif mutation == "wrong_macho_probe_architecture":
            if probe_index is None:
                self.fail("macOS probe mutation requires a macOS archive")
            member, content = records[probe_index]
            changed = bytearray(content)
            changed[4:8] = (0x01000007).to_bytes(4, "little")
            records[probe_index] = (member, bytes(changed))
        elif mutation == "malformed_macho_header":
            member, content = records[binary_index]
            changed = bytearray(content)
            changed[:4] = b"MACH"
            records[binary_index] = (member, bytes(changed))
        memory = io.BytesIO()
        with tarfile.open(
            fileobj=memory,
            mode="w:gz",
            format=tarfile.PAX_FORMAT,
        ) as archive:
            for member, content in records:
                archive.addfile(member, None if content is None else io.BytesIO(content))
        destination.write_bytes(memory.getvalue())

    # Rewrites one valid archive with one exact hostile mutation.
    def _mutated_archive(
        self,
        source: pathlib.Path,
        destination: pathlib.Path,
        mutation: str,
    ) -> None:
        with tarfile.open(source, "r:gz") as archive:
            records = []
            for member in archive.getmembers():
                content = archive.extractfile(member).read() if member.isfile() else None
                records.append((member, content))
        manifest_index = next(
            index
            for index, (member, _content) in enumerate(records)
            if member.name == f"{ARCHIVE_ROOT}/{MANIFEST_NAME}"
        )
        binary_index = manifest_index + 1
        if mutation in {
            "manifest_extra",
            "manifest_digest",
            "manifest_noncanonical",
            "schema_version_boolean",
            "file_bytes_boolean",
            "file_bytes_float",
            "file_mode_boolean",
            "file_mode_float",
        }:
            member, content = records[manifest_index]
            manifest = json.loads(content)
            if mutation == "manifest_extra":
                manifest["extra"] = True
            elif mutation == "manifest_digest":
                manifest["files"][0]["sha256"] = "0" * 64
            elif mutation == "schema_version_boolean":
                manifest["schema"]["version"] = True
            elif mutation == "file_bytes_boolean":
                manifest["files"][0]["bytes"] = True
            elif mutation == "file_bytes_float":
                manifest["files"][0]["bytes"] = float(manifest["files"][0]["bytes"])
            elif mutation == "file_mode_boolean":
                manifest["files"][0]["mode"] = True
            elif mutation == "file_mode_float":
                manifest["files"][0]["mode"] = float(manifest["files"][0]["mode"])
            content = canonical_json(manifest)
            if mutation == "manifest_noncanonical":
                content = json.dumps(manifest, indent=2).encode()
            member.size = len(content)
            records[manifest_index] = (member, content)
        elif mutation == "link":
            member, _content = records[binary_index]
            member.type = tarfile.SYMTYPE
            member.linkname = "li_node"
            member.size = 0
            records[binary_index] = (member, None)
        elif mutation == "binary_mode":
            records[binary_index][0].mode = 0o644
        elif mutation == "extra_member":
            extra = tarfile.TarInfo(f"{ARCHIVE_ROOT}/bin/li_extra")
            extra.type = tarfile.REGTYPE
            extra.mode = 0o755
            extra.size = 5
            records.append((extra, b"extra"))
        memory = io.BytesIO()
        with tarfile.open(fileobj=memory, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for member, content in records:
                archive.addfile(member, None if content is None else io.BytesIO(content))
        destination.write_bytes(memory.getvalue())


if __name__ == "__main__":
    unittest.main()
