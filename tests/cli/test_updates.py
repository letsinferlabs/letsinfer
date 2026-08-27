#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Update state is transactional, identity-bound, and invisible to machines."""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import pathlib
import sqlite3
import tempfile
import threading
import types
import unittest
from unittest import mock

from core import cli, runtime_packs, ui
from core.runtime_packs import target_contract_sha256
from core.updates.manager import (
    Component,
    UpdateError,
    UpdateManager,
    UpdatePoller,
    UpdateRecord,
    UpdateSnapshot,
    _Candidate,
    _github_candidate,
    compare_versions,
)


RUNTIME_DIGEST = "1" * 64
NEXT_RUNTIME_DIGEST = "2" * 64
TARGET_DIGEST = "3" * 64
CANDIDATE = "sglang--radixark--qwen3.8-27b-nvfp4--dgx-spark"
ENGINE_DIGEST = "4" * 64
BENCHMARK_ID = "5" * 64


def components(*, core_identity: str = "core-a", runtime_policy: str = "recommended"):
    return (
        Component("core", "core", "0.11.0-rc.29", core_identity),
        Component(
            "runtime",
            "qwen3.8-27b",
            "0.1.0-rc.10",
            RUNTIME_DIGEST,
            policy=runtime_policy,
            model="qwen3.8-27b",
            runtime=CANDIDATE,
            engine="sglang",
            target="dgx-spark",
            target_contract_sha256=target_contract_sha256(
                catalog()["targets"]["dgx-spark"]["match"]
            ),
            installed_source="ghcr.io/letsinferlabs/runtimes/qwen@sha256:"
            + RUNTIME_DIGEST,
        ),
    )


def catalog(version: str = "0.1.0-rc.11", digest: str = NEXT_RUNTIME_DIGEST):
    return {
        "schema_version": runtime_packs.CATALOG_SCHEMA_VERSION,
        "recommendation_policy": {
            "id": "letsinfer-throughput-geomean-v1",
            "benchmark_suite": "letsinfer-code-prose-v1",
            "metric": "aggregate_tps",
            "cache": "uncached",
            "tie_breakers": ["score", "version", "candidate"],
        },
        "targets": {
            "dgx-spark": {
                "match": {
                    "id": "dgx-spark",
                    "platform": "linux/arm64",
                    "accelerator": {
                        "vendor": "nvidia",
                        "architecture": "sm121",
                        "count": 1,
                        "partitioning": "full-device",
                    },
                    "memory": {"topology": "unified", "minimum_total_gib": 100},
                    "placement": {
                        "strategy": "single",
                        "node_count": 1,
                        "interconnect": {
                            "kind": "any",
                            "rdma_required": False,
                            "minimum_speed_mbps": 0,
                            "minimum_mtu": 0,
                        },
                    },
                }
            }
        },
        "models": {
            "qwen3.8-27b": {
                "targets": {
                    "dgx-spark": {
                        "recommended": {
                            "candidate": CANDIDATE,
                            "version": version,
                        },
                        "candidates": {
                            CANDIDATE: {
                                "latest": version,
                                "releases": {
                                    version: {
                                        "authors": ["MiaAI-Lab", "Letsinfer"],
                                        "license": "AGPL-3.0-only",
                                        "source": "ghcr.io/letsinferlabs/runtimes/qwen"
                                        f"@sha256:{digest}",
                                        "qualified": True,
                                        "revoked": False,
                                        "engine": "sglang",
                                        "engine_oci": "ghcr.io/letsinferlabs/engines/sglang"
                                        f"@sha256:{ENGINE_DIGEST}",
                                        "model_uri": "hf://RadixArk/Qwen3.8-27B-NVFP4",
                                        "benchmark": {
                                            "id": BENCHMARK_ID,
                                            "suite": "letsinfer-code-prose-v1",
                                            "score": 1.0,
                                            "evidence": "ghcr.io/letsinferlabs/benchmarks/qwen"
                                            "@sha256:" + "6" * 64,
                                        },
                                    }
                                },
                            }
                        },
                    }
                }
            }
        },
    }


class TTY(io.StringIO):
    def isatty(self):
        return True


class UpdateManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = pathlib.Path(self.temporary.name) / "data" / "updates.sqlite3"
        self.now = 1_800_000_000
        self.core_calls = 0
        self.catalog_calls = 0

    def manager(self, *, installed=components(), runtime_catalog=None, core_error=None):
        def core_candidate(_version):
            self.core_calls += 1
            if core_error is not None:
                raise core_error
            return _Candidate(
                "0.11.0-rc.30", "github-release:30", "https://github.com/letsinferlabs/letsinfer/releases/tag/v0.11.0-rc.30"
            )

        def catalog_loader(_location):
            self.catalog_calls += 1
            if isinstance(runtime_catalog, BaseException):
                raise runtime_catalog
            return runtime_catalog or catalog()

        return UpdateManager(
            lambda: installed,
            database=self.database,
            catalog_location=lambda: "catalog.json",
            core_candidate=core_candidate,
            catalog_loader=catalog_loader,
            clock=lambda: self.now,
        )

    def test_source_checkout_identity_is_stable_without_generated_manifest(self):
        root = pathlib.Path(self.temporary.name) / "checkout"
        for relative, content in (
            ("core/__init__.py", "PRODUCT_VERSION = 'test'\n"),
            ("core/cli.py", "# cli\n"),
            ("core/updates/manager.py", "# manager\n"),
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        with mock.patch.object(cli, "source_root", return_value=root):
            first = cli._core_update_identity()
            second = cli._core_update_identity()
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, second)

    def test_update_components_use_placement_group_releases_without_service_json(self):
        identity_path = pathlib.Path(self.temporary.name) / "site.json"
        identity_path.write_text("{}\n", encoding="utf-8")
        placement_id = "a" * 32
        release = {
            "logical_model": "qwen3.8-27b",
            "candidate_id": CANDIDATE,
            "target_id": "dgx-spark",
            "target_contract_sha256": TARGET_DIGEST,
            "version": "0.1.0-rc.10",
            "runtime_digest": RUNTIME_DIGEST,
            "source": (
                "ghcr.io/letsinferlabs/runtime-artifacts/qwen@sha256:"
                + RUNTIME_DIGEST
            ),
        }
        store = mock.MagicMock()
        store.placements.return_value = [
            {
                "placement_id": placement_id,
                "model": release["logical_model"],
            }
        ]
        store.placement_groups.return_value = [
            {
                "model": release["logical_model"],
                "state": "running",
                "desired_state": "running",
                "plan": {"release": release},
            },
            {
                "model": release["logical_model"],
                "state": "stopped",
                "desired_state": "stopped",
                "plan": {"release": release},
            },
        ]
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        missing = pathlib.Path(self.temporary.name) / "missing-service.json"
        with (
            mock.patch.object(cli, "site_identity_path", return_value=identity_path),
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(role="main"),
            ),
            mock.patch.object(cli, "SiteStore", return_value=store_context),
            mock.patch.object(cli, "_core_update_identity", return_value="core-a"),
            mock.patch.object(
                cli, "qualification_service_config_path", return_value=missing
            ),
            mock.patch.object(cli, "default_service_config_path", return_value=missing),
            mock.patch.object(cli, "read_service_config") as legacy_config,
        ):
            installed = cli._update_components()

        legacy_config.assert_not_called()
        self.assertEqual(len(installed), 2)
        runtime = installed[1]
        self.assertEqual(runtime.subject, release["logical_model"])
        self.assertEqual(runtime.model, release["logical_model"])
        self.assertEqual(runtime.runtime, release["candidate_id"])
        self.assertEqual(runtime.installed_identity, release["runtime_digest"])
        self.assertEqual(runtime.installed_source, release["source"])

    def test_update_components_keep_mixed_group_releases_distinct(self):
        identity_path = pathlib.Path(self.temporary.name) / "site.json"
        identity_path.write_text("{}\n", encoding="utf-8")
        model = "qwen3.8-27b"
        releases = []
        groups = []
        placements = []
        for index, version in enumerate(("0.1.0-rc.9", "0.1.0-rc.10"), start=1):
            digest = str(index) * 64
            placement_id = str(index + 2) * 32
            release = {
                "logical_model": model,
                "candidate_id": CANDIDATE,
                "target_id": "dgx-spark",
                "target_contract_sha256": TARGET_DIGEST,
                "version": version,
                "runtime_digest": digest,
                "source": "registry.example/runtime@sha256:" + digest,
            }
            releases.append(release)
            placements.append({"placement_id": placement_id, "model": model})
            groups.append(
                {
                    "model": model,
                    "state": "running",
                    "desired_state": "running",
                    "plan": {"release": release},
                }
            )
        store = mock.MagicMock()
        store.placements.return_value = placements
        store.placement_groups.return_value = groups
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        missing = pathlib.Path(self.temporary.name) / "missing-service.json"
        with (
            mock.patch.object(cli, "site_identity_path", return_value=identity_path),
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(role="main"),
            ),
            mock.patch.object(cli, "SiteStore", return_value=store_context),
            mock.patch.object(cli, "_core_update_identity", return_value="core-a"),
            mock.patch.object(
                cli, "qualification_service_config_path", return_value=missing
            ),
            mock.patch.object(cli, "default_service_config_path", return_value=missing),
        ):
            runtimes = cli._update_components()[1:]

        self.assertEqual(len(runtimes), 2)
        self.assertEqual(len({runtime.subject for runtime in runtimes}), 2)
        self.assertEqual({runtime.apply_subject for runtime in runtimes}, {model})
        self.assertTrue(all(runtime.display_subject.startswith(model) for runtime in runtimes))

    def test_child_update_components_use_the_local_group_plan(self):
        identity_path = pathlib.Path(self.temporary.name) / "site.json"
        identity_path.write_text("{}\n", encoding="utf-8")
        group_root = pathlib.Path(self.temporary.name) / "groups" / ("a" * 32)
        group_root.mkdir(parents=True)
        group_file = group_root / "placement-group.json"
        group_file.write_text(
            json.dumps({"padding": "x" * 64}) + "\n", encoding="utf-8"
        )
        group_file.chmod(0o600)
        release = {
            "logical_model": "qwen3.8-27b",
            "candidate_id": CANDIDATE,
            "target_id": "dgx-spark",
            "target_contract_sha256": TARGET_DIGEST,
            "version": "0.1.0-rc.10",
            "runtime_digest": RUNTIME_DIGEST,
            "source": "registry.example/runtime@sha256:" + RUNTIME_DIGEST,
        }
        missing = pathlib.Path(self.temporary.name) / "missing-service.json"
        with (
            mock.patch.object(cli, "site_identity_path", return_value=identity_path),
            mock.patch.object(
                cli,
                "read_site_identity",
                return_value=types.SimpleNamespace(role="child"),
            ),
            mock.patch.object(
                cli,
                "default_placement_group_root",
                return_value=group_root.parent,
            ),
            mock.patch.object(
                cli, "validate_placement_group_document", return_value={"release": release}
            ),
            mock.patch.object(cli, "_core_update_identity", return_value="core-a"),
            mock.patch.object(
                cli, "qualification_service_config_path", return_value=missing
            ),
            mock.patch.object(cli, "default_service_config_path", return_value=missing),
        ):
            installed = cli._update_components()

        self.assertEqual(installed[1].model, release["logical_model"])
        self.assertEqual(installed[1].installed_identity, release["runtime_digest"])

    def test_version_order_covers_rc_and_stable(self):
        self.assertLess(compare_versions("0.11.0-rc.9", "0.11.0-rc.10"), 0)
        self.assertLess(compare_versions("0.11.0-rc.30", "0.11.0"), 0)
        self.assertGreater(compare_versions("0.12.0-rc.1", "0.11.9"), 0)
        self.assertLess(compare_versions("1.0.0-beta.11", "1.0.0-rc.1"), 0)
        self.assertLess(compare_versions("1.0.0-alpha.1", "1.0.0-alpha.beta"), 0)
        self.assertEqual(compare_versions("1.0.0+build.1", "1.0.0+build.2"), 0)
        with self.assertRaises(UpdateError):
            compare_versions("latest", "0.11.0")
        with self.assertRaises(UpdateError):
            compare_versions("1.0.0-rc.01", "1.0.0-rc.1")

    def test_core_release_channel_advances_rc_but_not_stable_to_prerelease(self):
        releases = [
            {
                "id": 31,
                "tag_name": "v0.12.0-rc.1",
                "draft": False,
                "prerelease": True,
                "html_url": "https://github.com/letsinferlabs/letsinfer/releases/tag/v0.12.0-rc.1",
            },
            {
                "id": 30,
                "tag_name": "v0.11.0",
                "draft": False,
                "prerelease": False,
                "html_url": "https://github.com/letsinferlabs/letsinfer/releases/tag/v0.11.0",
            },
        ]

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_arguments):
                return False

            def read(self, _limit):
                return json.dumps(releases).encode("utf-8")

        opener = lambda *_arguments, **_keywords: Response()
        self.assertEqual(
            _github_candidate("0.11.0-rc.29", opener=opener).version,
            "0.12.0-rc.1",
        )
        self.assertEqual(
            _github_candidate("0.10.0", opener=opener).version,
            "0.11.0",
        )

    def test_core_release_channel_rejects_mismatched_prerelease_metadata(self):
        releases = [
            {
                "id": 31,
                "tag_name": "v0.12.0-rc.1",
                "draft": False,
                "prerelease": False,
                "html_url": "https://github.com/letsinferlabs/letsinfer/releases/tag/v0.12.0-rc.1",
            },
            {
                "id": 30,
                "tag_name": "v0.11.0-rc.30",
                "draft": False,
                "prerelease": True,
                "html_url": "https://github.com/letsinferlabs/letsinfer/releases/tag/v0.11.0-rc.30",
            },
        ]

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_arguments):
                return False

            def read(self, _limit):
                return json.dumps(releases).encode("utf-8")

        self.assertEqual(
            _github_candidate(
                "0.11.0-rc.29", opener=lambda *_args, **_kwargs: Response()
            ).version,
            "0.11.0-rc.30",
        )

    def test_refresh_publishes_core_and_runtime_in_one_snapshot(self):
        manager = self.manager()
        snapshot = manager.refresh()
        self.assertEqual(
            [(record.kind, record.status) for record in snapshot.records],
            [("core", "available"), ("runtime", "available")],
        )
        self.assertEqual(manager.cached(), snapshot)
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)

    def test_cached_records_restore_runtime_display_and_apply_subjects(self):
        core, runtime = components()
        runtime = dataclasses.replace(
            runtime,
            subject="runtime-component-id",
            display_subject="Qwen · DGX Spark",
            apply_subject="qwen3.8-27b",
        )
        manager = self.manager(installed=(core, runtime))
        refreshed = manager.refresh()
        cached = manager.cached()
        self.assertEqual(cached, refreshed)
        record = next(item for item in cached.records if item.kind == "runtime")
        self.assertEqual(record.label, "Qwen · DGX Spark")
        self.assertEqual(record.apply, "qwen3.8-27b")

    def test_cached_never_creates_storage_or_calls_network(self):
        manager = self.manager()
        self.assertEqual(manager.cached().records, ())
        self.assertFalse(self.database.exists())
        self.assertEqual((self.core_calls, self.catalog_calls), (0, 0))

    def test_transient_failure_retains_exact_verified_availability(self):
        manager = self.manager()
        first = manager.refresh()
        self.now += 60
        failed = self.manager(
            runtime_catalog=OSError("offline"), core_error=OSError("offline")
        ).refresh()
        self.assertEqual(
            [record.available_version for record in failed.records],
            [record.available_version for record in first.records],
        )
        self.assertTrue(all(record.error_code == "network_unavailable" for record in failed.records))
        self.assertTrue(all(record.verified_at_unix == self.now - 60 for record in failed.records))

    def test_installed_identity_change_hides_old_advice_immediately(self):
        self.manager().refresh()
        changed = self.manager(installed=components(core_identity="core-b"))
        cached = changed.cached()
        self.assertEqual([record.kind for record in cached.records], ["runtime"])

    def test_same_runtime_version_with_different_digest_fails_closed(self):
        snapshot = self.manager(
            runtime_catalog=catalog("0.1.0-rc.10", NEXT_RUNTIME_DIGEST)
        ).refresh()
        runtime = next(record for record in snapshot.records if record.kind == "runtime")
        self.assertEqual(runtime.status, "integrity_error")
        self.assertEqual(runtime.error_code, "same_version_identity_changed")
        self.assertFalse(runtime.available)

    def test_new_runtime_version_cannot_reuse_the_installed_oci_identity(self):
        snapshot = self.manager(
            runtime_catalog=catalog("0.1.0-rc.11", RUNTIME_DIGEST)
        ).refresh()
        runtime = next(record for record in snapshot.records if record.kind == "runtime")
        self.assertEqual(runtime.status, "integrity_error")
        self.assertEqual(runtime.error_code, "new_version_reused_identity")
        self.assertFalse(runtime.available)

    def test_pinned_runtime_does_not_consult_catalog(self):
        snapshot = self.manager(
            installed=components(runtime_policy="pinned")
        ).refresh()
        runtime = next(record for record in snapshot.records if record.kind == "runtime")
        self.assertEqual(runtime.status, "pinned")
        self.assertEqual(self.catalog_calls, 0)

    def test_cross_process_lease_returns_cached_busy_snapshot(self):
        manager = self.manager()
        manager.refresh()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO refresh_lease VALUES (1, 'other', ?)",
                (self.now + 30,),
            )
        calls = self.core_calls
        snapshot = manager.refresh()
        self.assertTrue(snapshot.busy)
        self.assertEqual(self.core_calls, calls)
        self.assertTrue(snapshot.available)

    def test_concurrent_refreshes_collapse_before_network_io(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def core_candidate(_version):
            calls.append("core")
            entered.set()
            self.assertTrue(release.wait(2))
            return _Candidate(
                "0.11.0-rc.30",
                "github-release:30",
                "https://github.com/letsinferlabs/letsinfer/releases/tag/v0.11.0-rc.30",
            )

        installed = (components()[0],)
        first = UpdateManager(
            lambda: installed,
            database=self.database,
            core_candidate=core_candidate,
            clock=lambda: self.now,
        )
        second = UpdateManager(
            lambda: installed,
            database=self.database,
            core_candidate=core_candidate,
            clock=lambda: self.now,
        )
        result = []
        worker = threading.Thread(target=lambda: result.append(first.refresh()))
        worker.start()
        self.assertTrue(entered.wait(2))
        competing = second.refresh()
        self.assertTrue(competing.busy)
        self.assertEqual(calls, ["core"])
        release.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertTrue(result[0].available)

    def test_expired_lease_is_recovered(self):
        manager = self.manager()
        manager.refresh()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO refresh_lease VALUES (1, 'dead', ?)",
                (self.now - 1,),
            )
        self.now += 1
        self.assertFalse(manager.refresh().busy)

    def test_corrupt_cache_is_invisible_to_normal_commands(self):
        self.database.parent.mkdir(parents=True)
        self.database.write_text("not sqlite", encoding="utf-8")
        self.assertEqual(self.manager().cached().records, ())

    def test_symlink_storage_is_rejected_on_refresh(self):
        target = pathlib.Path(self.temporary.name) / "real"
        target.mkdir()
        self.database.parent.parent.mkdir(exist_ok=True)
        self.database.parent.symlink_to(target)
        with self.assertRaises(UpdateError):
            self.manager().refresh()

    def test_non_private_existing_database_is_rejected_on_refresh(self):
        self.database.parent.mkdir(parents=True)
        self.database.touch(mode=0o644)
        self.database.chmod(0o644)
        with self.assertRaisesRegex(UpdateError, "private and user-owned"):
            self.manager().refresh()

    def test_poller_stops_and_tolerates_source_failure(self):
        stop = threading.Event()
        manager = self.manager(core_error=OSError("offline"), runtime_catalog=OSError("offline"))
        poller = UpdatePoller(manager, stop=stop, interval_seconds=1, jitter_seconds=0)
        poller.start()
        for _ in range(100):
            if self.database.exists():
                break
            threading.Event().wait(0.01)
        stop.set()
        poller.join(2)
        self.assertFalse(poller.thread.is_alive())


class UpdateNoticeTests(unittest.TestCase):
    def test_interactive_notice_is_compact(self):
        stream = TTY()
        records = (
            types.SimpleNamespace(
                kind="core", subject="core", available_version="0.11.0-rc.30"
            ),
            types.SimpleNamespace(
                kind="runtime",
                subject="qwen3.8-27b",
                available_version="0.1.0-rc.11",
            ),
        )
        ui.update_notice(records, stream=stream, environ={"TERM": "xterm", "NO_COLOR": "1"})
        rendered = stream.getvalue()
        self.assertIn("Update available", rendered)
        self.assertIn("Core 0.11.0-rc.30", rendered)
        self.assertIn("qwen3.8-27b 0.1.0-rc.11", rendered)
        self.assertIn("┌", rendered)
        self.assertIn("└", rendered)
        self.assertTrue(rendered.endswith("\n\n"))

    def test_non_tty_notice_is_byte_silent(self):
        stream = io.StringIO()
        ui.update_notice((mock.sentinel.record,), stream=stream)
        self.assertEqual(stream.getvalue(), "")

    def test_interactive_notice_accepts_one_pass_record_iterables(self):
        stream = TTY()
        records = (
            record
            for record in (
                types.SimpleNamespace(
                    kind="core",
                    subject="core",
                    available_version="0.11.0-rc.30",
                ),
            )
        )
        ui.update_notice(
            records,
            stream=stream,
            environ={"TERM": "xterm", "NO_COLOR": "1"},
        )
        self.assertIn("Update available · Core 0.11.0-rc.30", stream.getvalue())

    def test_cleared_notice_corrects_stale_interactive_advice(self):
        stream = TTY()
        ui.update_notice(
            (),
            stream=stream,
            environ={"TERM": "xterm", "NO_COLOR": "1"},
            cleared=True,
        )
        self.assertIn("installed components are current", stream.getvalue())

    def test_unresolved_refresh_never_claims_components_are_current(self):
        stream = TTY()
        ui.update_notice(
            (),
            stream=stream,
            environ={"TERM": "xterm", "NO_COLOR": "1"},
            attention=True,
        )
        rendered = stream.getvalue()
        self.assertIn("verification needs attention", rendered)
        self.assertNotIn("components are current", rendered)


class UpdateCommandTests(unittest.TestCase):
    def snapshot(self, *, status="available", busy=False):
        return UpdateSnapshot(
            (
                UpdateRecord(
                    "core",
                    "core",
                    "0.11.0-rc.29",
                    "core-a",
                    "0.11.0-rc.30" if status == "available" else None,
                    "github-release:30" if status == "available" else None,
                    "https://github.com/letsinferlabs/letsinfer/releases/tag/v0.11.0-rc.30"
                    if status == "available"
                    else None,
                    status,
                    1_800_000_000,
                    1_800_000_000 if status in {"available", "current"} else None,
                    "same_version_identity_changed"
                    if status == "integrity_error"
                    else None,
                ),
            ),
            busy=busy,
        )

    def test_parser_preserves_core_update_and_adds_explicit_check(self):
        parser = cli.parser()
        applying = parser.parse_args(["update", "core", "0.11.0-rc.30"])
        checking = parser.parse_args(["update", "check", "--json"])
        self.assertIs(applying.action, cli.update_core_command)
        self.assertEqual(applying.version, "0.11.0-rc.30")
        self.assertIs(checking.action, cli.check_updates)
        self.assertTrue(checking.json)

    def test_json_check_is_structured_and_machine_clean(self):
        manager = mock.Mock()
        manager.refresh.return_value = self.snapshot()
        output = io.StringIO()
        arguments = types.SimpleNamespace(catalog="catalog.json", json=True)
        with (
            mock.patch.object(cli, "_update_manager", return_value=manager) as factory,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.check_updates(arguments), 0)
        factory.assert_called_once_with("catalog.json")
        document = json.loads(output.getvalue())
        self.assertTrue(document["updates_available"])
        self.assertEqual(document["components"][0]["available_version"], "0.11.0-rc.30")
        self.assertEqual(output.getvalue().count("\n"), 1)

    def test_integrity_error_is_visible_and_returns_failure(self):
        manager = mock.Mock()
        manager.refresh.return_value = self.snapshot(status="integrity_error")
        output = io.StringIO()
        arguments = types.SimpleNamespace(catalog=None, json=False)
        with (
            mock.patch.object(cli, "_update_manager", return_value=manager),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.check_updates(arguments), 1)
        self.assertIn("same_version_identity_changed", output.getvalue())

    def test_busy_check_without_verified_state_returns_failure(self):
        manager = mock.Mock()
        manager.refresh.return_value = UpdateSnapshot((), busy=True)
        output = io.StringIO()
        arguments = types.SimpleNamespace(catalog=None, json=False)
        with (
            mock.patch.object(cli, "_update_manager", return_value=manager),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.check_updates(arguments), 1)
        self.assertIn("Another update check is already running", output.getvalue())


if __name__ == "__main__":
    unittest.main()
