#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Clean-break CLI integration tests for immutable runtime candidates."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from core import cli
from core.engine_protocol import artifact_storage_slug
from core.runtime_packs import RuntimePackError, candidate_id, validate_runtime_config
from tests.runtime_fixture import runtime_candidate


class RuntimeCandidateCliTests(unittest.TestCase):
    def test_benchmark_placement_borrows_only_overlapping_group_devices(self) -> None:
        member_id = "a" * 32
        group_id = "b" * 32
        identity = types.SimpleNamespace(
            site_id="c" * 32,
            coordinator_id=member_id,
        )
        graph = mock.Mock()
        graph.members = {member_id: {"member_id": member_id}}
        graph.resolve.side_effect = cli.TopologyError("device is allocated")
        placement = types.SimpleNamespace(
            strategy="single",
            member_ids=(member_id,),
            device_uuids={member_id: ("GPU-0",)},
            topology_sha256="d" * 64,
        )
        unallocated = mock.Mock()
        unallocated.resolve.return_value = placement
        store = mock.Mock()
        store.device_allocations.return_value = [
            {
                "group_id": group_id,
                "member_id": member_id,
                "device_uuid": "GPU-0",
            },
            {
                "group_id": "e" * 32,
                "member_id": member_id,
                "device_uuid": "GPU-1",
            },
        ]
        store.engine_groups.return_value = [
            {
                "group_id": group_id,
                "state": "running",
                "desired_state": "running",
            }
        ]
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        manifest = cli.runtime_execution_manifest(
            runtime_candidate(), qualified=False
        )
        with (
            mock.patch.object(
                cli, "_fresh_site_topology", return_value=(identity, graph)
            ),
            mock.patch.object(cli, "TopologyGraph", return_value=unallocated) as topology,
            mock.patch.object(cli, "_site_store", return_value=store_context),
        ):
            resolved, groups = cli.resolve_benchmark_service_placement(
                manifest, "f" * 64
            )

        self.assertEqual(groups, (group_id,))
        graph.resolve.assert_called_once()
        self.assertEqual(resolved["placement_members"], [member_id])
        self.assertEqual(
            topology.call_args.kwargs["allocated_devices"], {member_id: ()}
        )

    def test_benchmark_placement_prefers_an_unallocated_device(self) -> None:
        member_id = "a" * 32
        identity = types.SimpleNamespace(
            site_id="b" * 32,
            coordinator_id=member_id,
        )
        placement = types.SimpleNamespace(
            strategy="single",
            member_ids=(member_id,),
            device_uuids={member_id: ("GPU-1",)},
            topology_sha256="c" * 64,
        )
        graph = mock.Mock()
        graph.members = {member_id: {"member_id": member_id}}
        graph.resolve.return_value = placement
        store = mock.Mock()
        store.device_allocations.return_value = [
            {
                "group_id": "d" * 32,
                "member_id": member_id,
                "device_uuid": "GPU-0",
            }
        ]
        store.engine_groups.return_value = []
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        manifest = cli.runtime_execution_manifest(
            runtime_candidate(), qualified=False
        )
        with (
            mock.patch.object(
                cli, "_fresh_site_topology", return_value=(identity, graph)
            ),
            mock.patch.object(cli, "TopologyGraph") as topology,
            mock.patch.object(cli, "_site_store", return_value=store_context),
        ):
            _resolved, groups = cli.resolve_benchmark_service_placement(
                manifest, "e" * 64
            )

        self.assertEqual(groups, ())
        topology.assert_not_called()

    def test_benchmark_isolation_restores_running_group_on_success_and_failure(
        self,
    ) -> None:
        group_id = "a" * 32
        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                events: list[str] = []

                def benchmark(command: list[str], **_: object) -> None:
                    events.append("benchmark")
                    if failure:
                        raise cli.LetsInferError("fixture benchmark failed")

                with (
                    mock.patch.object(
                        cli,
                        "qualification_service_config_path",
                        return_value=pathlib.Path(directory) / "missing.json",
                    ),
                    mock.patch.object(cli, "protection_trip_latched", return_value=False),
                    mock.patch.object(
                        cli,
                        "_unit_enabled_active",
                        return_value=("disabled", "inactive"),
                    ),
                    mock.patch.object(
                        cli,
                        "_benchmark_engine_group_intents",
                        return_value={group_id: True},
                    ),
                    mock.patch.object(
                        cli,
                        "_stop_engine_group_by_id",
                        side_effect=lambda _group_id: events.append("stop"),
                    ),
                    mock.patch.object(
                        cli,
                        "_start_engine_group_by_id",
                        side_effect=lambda _group_id: events.append("start"),
                    ),
                    mock.patch.object(
                        cli,
                        "_gateway_is_idle",
                        side_effect=lambda: events.append("idle"),
                    ),
                    mock.patch.object(cli, "run_passthrough", side_effect=benchmark),
                ):
                    if failure:
                        with self.assertRaisesRegex(
                            cli.LetsInferError, "fixture benchmark failed"
                        ):
                            cli._run_benchmark_with_service_isolation(
                                ["matrix"], resident_group_ids=(group_id,)
                            )
                    else:
                        cli._run_benchmark_with_service_isolation(
                            ["matrix"], resident_group_ids=(group_id,)
                        )
                self.assertEqual(events, ["idle", "stop", "benchmark", "start"])

    def test_benchmark_isolation_restores_group_when_stop_fails(self) -> None:
        group_id = "a" * 32
        events: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            def fail_stop(_group_id: str) -> None:
                events.append("stop")
                raise cli.LetsInferError("fixture stop failed")

            with (
                mock.patch.object(
                    cli,
                    "qualification_service_config_path",
                    return_value=pathlib.Path(directory) / "missing.json",
                ),
                mock.patch.object(cli, "protection_trip_latched", return_value=False),
                mock.patch.object(
                    cli,
                    "_unit_enabled_active",
                    return_value=("disabled", "inactive"),
                ),
                mock.patch.object(
                    cli,
                    "_benchmark_engine_group_intents",
                    return_value={group_id: True},
                ),
                mock.patch.object(
                    cli,
                    "_gateway_is_idle",
                    side_effect=lambda: events.append("idle"),
                ),
                mock.patch.object(
                    cli,
                    "_stop_engine_group_by_id",
                    side_effect=fail_stop,
                ),
                mock.patch.object(
                    cli,
                    "_start_engine_group_by_id",
                    side_effect=lambda _group_id: events.append("start"),
                ),
            ):
                with self.assertRaisesRegex(cli.LetsInferError, "fixture stop failed"):
                    cli._run_benchmark_with_service_isolation(
                        ["matrix"], resident_group_ids=(group_id,)
                    )
        self.assertEqual(events, ["idle", "stop", "start"])

    def test_benchmark_stop_allows_resident_group_restoration(self) -> None:
        with mock.patch.object(
            cli.benchmark_jobs,
            "read_state",
            return_value={
                "metadata": {"resident_group_ids": ["a" * 32]},
            },
        ):
            self.assertEqual(cli._benchmark_stop_timeout_seconds(), 3_600)

    def test_detached_benchmark_binds_resident_groups_into_worker_command(self) -> None:
        arguments = cli.parser().parse_args(["benchmark", "model", "--c1"])
        command = cli._benchmark_self_command(
            arguments,
            pathlib.Path("/core/bin/letsinfer"),
            pathlib.Path("/evidence"),
            ("a" * 32,),
        )
        self.assertEqual(command[-2:], ["--resident-group", "a" * 32])

    def test_control_bundle_install_accepts_concurrent_exact_publisher(self) -> None:
        manifest = {"release": "fixture-release"}
        adapter = types.SimpleNamespace(name="fixture-engine")
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)

            def collide(source: pathlib.Path, destination: pathlib.Path) -> None:
                self.assertTrue(source.name.startswith("."))
                destination.mkdir(mode=0o700)
                (destination / "runtime-execution.json").write_bytes(
                    cli.canonical_bytes(manifest)
                )
                raise OSError(errno.ENOTEMPTY, "Directory not empty")

            with (
                mock.patch.object(
                    cli,
                    "_core_release",
                    return_value=([], {"schema_version": 1}, "a" * 64),
                ),
                mock.patch.object(
                    cli,
                    "validate_control_bundle",
                    side_effect=lambda _root, path, _sha, **_kwargs: (path, manifest),
                ) as validate,
                mock.patch.object(cli, "adapter_for", return_value=adapter),
                mock.patch.object(
                    pathlib.Path,
                    "replace",
                    autospec=True,
                    side_effect=collide,
                ),
            ):
                root, runtime_manifest = cli.install_control_bundle(
                    pathlib.Path("/runtime-execution.json"),
                    manifest,
                    control_parent=parent,
                )

            self.assertTrue(root.is_dir())
            self.assertEqual(runtime_manifest, root / "runtime-execution.json")
            self.assertEqual(validate.call_count, 2)
            self.assertFalse(any(parent.glob(".*.install-*")))

    def test_control_bundle_validation_uses_its_recorded_source_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            source_content = b"historical source\n"
            source_manifest = {
                "schema_version": 1,
                "product": "letsinfer",
                "files": [
                    {
                        "path": "legacy/removed.py",
                        "bytes": len(source_content),
                        "mode": 0o644,
                        "sha256": hashlib.sha256(source_content).hexdigest(),
                    }
                ],
            }
            source_manifest_data = cli.canonical_bytes(source_manifest)
            runtime_manifest_data = b"{}\n"
            runtime_manifest_sha = hashlib.sha256(runtime_manifest_data).hexdigest()
            core_identity = hashlib.sha256(source_manifest_data).hexdigest()
            bundle_identity = cli._control_bundle_identity(
                core_identity, runtime_manifest_sha
            )
            root = parent / bundle_identity
            legacy = root / "legacy"
            legacy.mkdir(parents=True, mode=0o700)
            root.chmod(0o700)
            legacy.chmod(0o700)
            source = legacy / "removed.py"
            source.write_bytes(source_content)
            source.chmod(0o400)
            core_manifest = root / cli.CORE_SOURCE_MANIFEST
            core_manifest.write_bytes(source_manifest_data)
            core_manifest.chmod(0o400)
            runtime_manifest = root / "runtime-execution.json"
            runtime_manifest.write_bytes(runtime_manifest_data)
            runtime_manifest.chmod(0o400)

            with (
                mock.patch.object(cli, "validate_manifest"),
                mock.patch.object(cli, "verify_runtime_sources"),
                mock.patch.object(
                    cli,
                    "_core_release",
                    side_effect=AssertionError(
                        "control validation must not apply the current source policy"
                    ),
                ),
            ):
                installed_path, installed = cli.validate_control_bundle(
                    root, runtime_manifest, runtime_manifest_sha
                )
                self.assertEqual(installed_path, runtime_manifest.resolve())
                self.assertEqual(installed, {})

                unexpected = root / "unexpected.py"
                unexpected.write_text("unexpected\n", encoding="utf-8")
                unexpected.chmod(0o400)
                with self.assertRaisesRegex(
                    cli.LetsInferError, "source file set mismatch"
                ):
                    cli.validate_control_bundle(
                        root, runtime_manifest, runtime_manifest_sha
                    )

    def test_node_agent_memory_envelope_supports_runtime_staging(self) -> None:
        unit = cli.render_node_service(pathlib.Path("/opt/letsinfer"))
        self.assertIn("MemoryHigh=134217728\n", unit)
        self.assertIn("MemoryMax=201326592\n", unit)

    def test_startup_oom_has_a_concise_engine_error(self) -> None:
        inspection = {
            "State": {
                "Running": False,
                "OOMKilled": True,
                "ExitCode": 137,
                "Error": "",
            }
        }
        with (
            mock.patch.object(cli, "container_inspect", return_value=inspection),
            self.assertRaisesRegex(
                cli.LetsInferError, "Engine container was OOM-killed during startup"
            ),
        ):
            cli.wait_for_ready(
                "engine",
                18000,
                1,
                pathlib.Path("/tmp/server.crt"),
                {},
            )

    def test_service_commits_runtime_selection_before_engine_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            events: list[str] = []
            config = {
                "name": "letsinfer-example",
                "source_root": str(root),
                "protection_root": str(root / "protection"),
            }
            manifest = {"container": {"startup_timeout_seconds": 30}}
            receipt = {"logical_model": "example-model"}
            completed = mock.Mock(returncode=0, stdout="", stderr="")

            def start(command: list[str]) -> None:
                if command[-1] == cli.ENGINE_SERVICE_NAME:
                    self.assertIn("selection", events)
                events.append(command[-1])

            with (
                mock.patch.object(
                    cli, "_unit_enabled_active", return_value=("disabled", "inactive")
                ),
                mock.patch.object(cli, "selections", return_value=[]),
                mock.patch.object(
                    cli, "write_selection", side_effect=lambda _receipt: events.append("selection")
                ),
                mock.patch.object(cli, "run", return_value=completed),
                mock.patch.object(cli, "run_passthrough", side_effect=start),
                mock.patch.object(
                    cli, "_service_state", return_value=("enabled", "active", 1024)
                ),
                mock.patch.object(cli, "wait_for_core_plane_ready"),
                mock.patch.object(cli, "render_engine_service", return_value="unit\n"),
                mock.patch.object(cli, "render_gateway_service", return_value="unit\n"),
                mock.patch.object(cli, "render_user_service", return_value="unit\n"),
                mock.patch.object(cli, "render_node_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_timer", return_value="unit\n"),
            ):
                cli.install_user_service(
                    root / "service.json",
                    config,
                    manifest,
                    no_start=False,
                    runtime_receipt=receipt,
                    unit_dir=root / "units",
                )

            self.assertLess(events.index("selection"), events.index(cli.ENGINE_SERVICE_NAME))

    def test_failed_service_activation_restores_runtime_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            events: list[str] = []
            config = {
                "name": "letsinfer-example",
                "source_root": str(root),
                "protection_root": str(root / "protection"),
            }
            manifest = {"container": {"startup_timeout_seconds": 30}}
            receipt = {"logical_model": "example-model"}
            completed = mock.Mock(returncode=0, stdout="", stderr="")

            def start(command: list[str]) -> None:
                if command[-1] == cli.ENGINE_SERVICE_NAME:
                    raise cli.LetsInferError("synthetic engine failure")

            with (
                mock.patch.object(
                    cli, "_unit_enabled_active", return_value=("disabled", "inactive")
                ),
                mock.patch.object(cli, "selections", return_value=[]),
                mock.patch.object(
                    cli, "write_selection", side_effect=lambda _receipt: events.append("selection")
                ),
                mock.patch.object(
                    cli,
                    "restore_selection",
                    side_effect=lambda _replacement, _previous: events.append("restore"),
                ),
                mock.patch.object(cli, "run", return_value=completed),
                mock.patch.object(cli, "run_passthrough", side_effect=start),
                mock.patch.object(
                    cli, "_service_state", return_value=("enabled", "active", 1024)
                ),
                mock.patch.object(cli, "wait_for_core_plane_ready"),
                mock.patch.object(cli, "container_inspect", return_value=None),
                mock.patch.object(cli, "render_engine_service", return_value="unit\n"),
                mock.patch.object(cli, "render_gateway_service", return_value="unit\n"),
                mock.patch.object(cli, "render_user_service", return_value="unit\n"),
                mock.patch.object(cli, "render_node_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_service", return_value="unit\n"),
                mock.patch.object(cli, "render_recovery_timer", return_value="unit\n"),
                self.assertRaisesRegex(cli.LetsInferError, "previous installation restored"),
            ):
                cli.install_user_service(
                    root / "service.json",
                    config,
                    manifest,
                    no_start=False,
                    runtime_receipt=receipt,
                    unit_dir=root / "units",
                )

            self.assertEqual(events, ["selection", "restore"])

    def test_service_placement_uses_gateway_runtime_contract(self) -> None:
        identity = types.SimpleNamespace(
            site_id="0" * 32,
            member_id="1" * 32,
        )
        adapter = types.SimpleNamespace(
            name="example-engine",
            token_count_path="/v1/count_tokens",
            token_count_protocol="engine-rendered-chat-count-v1",
        )
        config = {
            "placement_id": "2" * 32,
            "placement_strategy": "single",
            "placement_members": [identity.member_id],
            "topology_sha256": "3" * 64,
            "runtime_version": "1.2.3",
            "runtime_digest": "4" * 64,
            "engine_port": 18000,
            "engine_api_key_file": "/secrets/engine.key",
            "tls_cert_file": "/config/server.crt",
            "release": "runtime-release",
            "manifest_sha256": "5" * 64,
        }
        manifest = {
            "model": {"alias": "example-model"},
            "serving": {
                "max_connections": 16,
                "max_active_requests": 8,
                "max_context_tokens": 65536,
            },
        }
        with (
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(cli, "adapter_for", return_value=adapter),
            mock.patch.object(
                cli, "target_contract", return_value={"id": "fixture-target"}
            ),
        ):
            placement = cli.service_placement_document(config, manifest, "running")

        self.assertEqual(
            placement["runtime"],
            "example-model/example-engine/fixture-target@1.2.3@sha256:" + "4" * 64,
        )

    def test_core_prune_retains_installed_runtime_and_rollback_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            control = root / "control"
            current = control / ("1" * 64)
            previous = control / ("2" * 64)
            receipt = {
                "control_root": str(current),
                "history": [{"control_root": str(previous)}],
            }
            with (
                mock.patch.object(cli, "default_control_parent", return_value=control),
                mock.patch.object(
                    cli, "default_service_config_path", return_value=root / "service.json"
                ),
                mock.patch.object(
                    cli,
                    "qualification_service_config_path",
                    return_value=root / "qualification.json",
                ),
                mock.patch.object(
                    cli, "default_engine_group_root", return_value=root / "groups"
                ),
                mock.patch.object(cli, "selections", return_value=[receipt]),
                mock.patch.object(
                    cli, "core_watchdog_source_identity", return_value="3" * 64
                ),
            ):
                controls, watchdogs = cli._core_artifact_references()

            self.assertEqual(
                controls,
                {current.resolve(strict=False), previous.resolve(strict=False)},
            )
            self.assertEqual(watchdogs, {"3" * 64})

    def test_tls_generation_supports_split_config_and_secret_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            certificate = root / "config" / "tls" / "server.crt"
            private_key = root / "secrets" / "tls" / "server.key"

            def generate(command: list[str], **_: object) -> mock.Mock:
                pathlib.Path(command[command.index("-out") + 1]).write_text(
                    "certificate", encoding="ascii"
                )
                pathlib.Path(command[command.index("-keyout") + 1]).write_text(
                    "private-key", encoding="ascii"
                )
                return mock.Mock(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(cli, "run", side_effect=generate),
                mock.patch.object(cli, "validate_tls_material"),
                mock.patch.object(cli, "_certificate_names", return_value=["localhost"]),
            ):
                cli.ensure_tls_material(certificate, private_key)

            self.assertEqual(certificate.read_text(encoding="ascii"), "certificate")
            self.assertEqual(private_key.read_text(encoding="ascii"), "private-key")
            self.assertEqual(private_key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(certificate.stat().st_mode & 0o777, 0o644)

    def test_watchdog_tls_generation_supports_split_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / "config" / "watchdog"
            secrets = root / "secrets" / "watchdog"
            paths = (
                config / "server.crt",
                secrets / "server.key",
                config / "controller-ca.crt",
                secrets / "controller-ca.key",
                config / "local-controller.crt",
                secrets / "local-controller.key",
            )

            def generate(command: list[str], **_: object) -> mock.Mock:
                for option in ("-out", "-keyout"):
                    if option in command:
                        pathlib.Path(command[command.index(option) + 1]).write_text(
                            option, encoding="ascii"
                        )
                return mock.Mock(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(cli, "run", side_effect=generate),
                mock.patch.object(cli, "validate_watchdog_tls_material"),
                mock.patch.object(cli, "_validate_watchdog_controller_material"),
                mock.patch.object(cli, "_certificate_names", return_value=["localhost"]),
            ):
                cli.ensure_watchdog_tls_material(*paths)

            for path in paths:
                self.assertTrue(path.is_file())
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_first_runtime_can_create_a_qualification_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest_path = root / "runtime.json"
            manifest_path.write_text("{}\n", encoding="ascii")
            runtime = runtime_candidate()
            manifest = cli.runtime_execution_manifest(runtime, qualified=False)
            receipt = {
                "candidate_id": runtime["id"],
                "version": runtime["version"],
                "digest": "5" * 64,
                "policy": "local",
            }
            with (
                mock.patch.object(
                    cli, "default_service_config_path", return_value=root / "missing.json"
                ),
                mock.patch.object(
                    cli,
                    "_qualification_core_plane_config",
                    return_value={"watchdog_data_root": str(root / "watchdog")},
                ),
                mock.patch.object(
                    cli,
                    "install_control_bundle",
                    return_value=(root / "control", manifest_path),
                ),
                mock.patch.object(
                    cli,
                    "resolve_service_placement",
                    return_value={
                        "placement_id": "6" * 32,
                        "placement_strategy": "single",
                        "placement_members": ["7" * 32],
                        "topology_sha256": "8" * 64,
                    },
                ),
            ):
                config = cli._qualification_config(
                    manifest_path=manifest_path,
                    manifest=manifest,
                    release_root=root,
                    manifest_sha256="9" * 64,
                    name="letsinfer-example",
                    port=18000,
                    model_cache=root / "models",
                    store_root=root / "store",
                    runtime_cache_root=root / "cache",
                    api_key_file=root / "engine.key",
                    tls_cert_file=root / "server.crt",
                    tls_key_file=root / "server.key",
                    evidence_dir=root / "evidence",
                    runtime_receipt=receipt,
                )

            self.assertTrue(config["qualification_mode"])
            self.assertEqual(config["runtime_name"], runtime["id"])
            self.assertEqual(
                config["protection_root"],
                str(
                    (root / "watchdog").resolve()
                    / cli.PROTECTION_ROOT_NAME
                    / ("6" * 32)
                ),
            )

    def test_qualification_core_plane_uses_the_managed_engine_key(self) -> None:
        with (
            mock.patch.object(
                cli,
                "verify_active_core_watchdog",
                return_value=(pathlib.Path("/watchdog"), "1" * 64),
            ),
            mock.patch.object(cli, "core_watchdog_source_identity", return_value="2" * 64),
            mock.patch.object(
                cli,
                "ensure_installation_identity",
                return_value={"installation_id": "3" * 64},
            ),
            mock.patch.object(
                cli,
                "default_engine_api_key_path",
                return_value=pathlib.Path("/secrets/engine/api-key"),
            ),
        ):
            config = cli._qualification_core_plane_config()

        self.assertEqual(config["engine_api_key_file"], "/secrets/engine/api-key")

    def test_legacy_commands_are_not_registered(self) -> None:
        parser = cli.parser()
        for command in ("derive", "engines", "releases"):
            with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args([command])

    def test_install_selects_runtime_not_engine(self) -> None:
        arguments = cli.parser().parse_args(
            [
                "install",
                "example-model",
                "--runtime",
                "example-engine--example--model--test-target",
            ]
        )
        self.assertEqual(arguments.model, "example-model")
        self.assertEqual(
            arguments.runtime,
            "example-engine--example--model--test-target",
        )
        self.assertFalse(hasattr(arguments, "engine"))

    def test_engine_identity_is_opaque_to_core(self) -> None:
        runtime = runtime_candidate()
        runtime["engine"]["id"] = "future-engine"
        runtime["id"] = candidate_id(
            "future-engine", runtime["model"]["uri"], runtime["target"]["id"]
        )
        validated = validate_runtime_config(runtime)
        execution = cli.runtime_execution_manifest(validated, qualified=False)
        self.assertEqual(execution["engine"]["name"], "future-engine")
        self.assertEqual(execution["image"]["reference"], runtime["engine"]["oci"]["reference"])

    def test_model_store_mirrors_exact_hugging_face_identity_and_revision(self) -> None:
        execution = cli.runtime_execution_manifest(runtime_candidate(), qualified=False)
        artifact = execution["artifacts"][0]
        self.assertEqual(artifact_storage_slug(artifact), "example--model")
        root = pathlib.Path("/letsinfer/models")
        self.assertEqual(
            cli.artifact_snapshot_path(
                {**artifact, "storage_slug": artifact_storage_slug(artifact)}, root
            ),
            root / "example--model" / ("4" * 40),
        )

    def test_runtime_validation_rejects_an_unpinned_model_revision(self) -> None:
        runtime = runtime_candidate()
        runtime["artifacts"][0]["revision"] = "main"
        with self.assertRaisesRegex(RuntimePackError, "full commit SHA"):
            validate_runtime_config(runtime)

    def test_resolve_model_only_considers_installed_runtime_receipts(self) -> None:
        runtime = runtime_candidate()
        execution = cli.runtime_execution_manifest(runtime, qualified=False)
        manifest_path = pathlib.Path("/installed/runtime-execution.json")
        receipt = {
            "candidate_id": runtime["id"],
            "logical_model": runtime["logical_model"],
            "engine": runtime["engine"]["id"],
            "target": runtime["target"]["id"],
            "version": runtime["version"],
            "installed_at": "2026-08-21T00:00:00Z",
        }
        with mock.patch.object(
            cli,
            "installed_runtime_manifests",
            return_value=[(manifest_path, execution, receipt)],
        ):
            selected, selected_manifest = cli.resolve_model("example-model")
        self.assertEqual(selected, manifest_path)
        self.assertIs(selected_manifest, execution)

    def test_unknown_source_tree_is_not_runtime_discovery_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, "release.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(cli, "installed_runtime_manifests", return_value=[]):
                with self.assertRaisesRegex(cli.LetsInferError, "unknown model"):
                    cli.resolve_model(directory)


if __name__ == "__main__":
    unittest.main()
