#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from core import cli
from core.storage_usage import (
    RuntimeStorageReference,
    StorageUsageError,
    cleanup_candidate,
    cleanup_plan,
    container_runtime_usage,
    execute_cleanup,
    managed_container_running,
    usage_report,
)


def _write(path: pathlib.Path, size: int) -> pathlib.Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    return path


class NodeUsageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = pathlib.Path(self.temporary.name) / "letsinfer"
        self.home.mkdir(mode=0o700)
        self.environment = {"LETSINFER_HOME": str(self.home)}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _fixtures(self) -> tuple[list[RuntimeStorageReference], dict[str, pathlib.Path]]:
        paths = {
            "active_model": _write(
                self.home / "models/owner--active/rev/model.bin", 8192
            ).parent,
            "stopped_model": _write(
                self.home / "models/owner--stopped/rev/model.bin", 12288
            ).parent,
            "orphan_model": _write(
                self.home / "models/owner--orphan/rev/model.bin", 4096
            ).parent,
            "active_cache": _write(
                self.home / "cache/runtime/active/cache.bin", 4096
            ).parent,
            "stopped_cache": _write(
                self.home / "cache/runtime/stopped/cache.bin", 4096
            ).parent,
            "benchmarks": _write(
                self.home / "benchmarks/run/result.json", 2048
            ).parents[1],
            "benchmark_job": _write(
                self.home / "state/benchmark-job/benchmark.log", 1024
            ).parent,
        }
        references = [
            RuntimeStorageReference(
                model="active-model",
                model_paths=(paths["active_model"],),
                cache_paths=(paths["active_cache"],),
                active=True,
            ),
            RuntimeStorageReference(
                model="stopped-model",
                model_paths=(paths["stopped_model"],),
                cache_paths=(paths["stopped_cache"],),
                active=False,
            ),
        ]
        return references, paths

    def test_plan_protects_running_data_and_marks_stopped_model_for_download(self) -> None:
        references, paths = self._fixtures()
        candidates = cleanup_plan(
            self.home,
            references,
            benchmark_roots=(paths["benchmarks"], paths["benchmark_job"]),
            benchmark_active=False,
        )
        targets = {item.path for item in candidates}
        self.assertNotIn(paths["active_model"], targets)
        self.assertNotIn(paths["active_cache"], targets)
        self.assertIn(paths["stopped_model"], targets)
        self.assertIn(paths["orphan_model"], targets)
        self.assertIn(paths["stopped_cache"], targets)
        stopped = next(item for item in candidates if item.path == paths["stopped_model"])
        self.assertEqual(stopped.models, ("stopped-model",))
        self.assertIn("downloaded again", stopped.reason)
        report = usage_report(self.home, candidates)
        self.assertGreater(report["total_allocated_bytes"], 0)
        self.assertGreater(report["total_reclaimable_bytes"], 0)
        self.assertFalse(report["container_runtime"]["included"])

    def test_active_benchmark_is_never_reclaimable(self) -> None:
        references, paths = self._fixtures()
        candidates = cleanup_plan(
            self.home,
            references,
            benchmark_roots=(paths["benchmarks"], paths["benchmark_job"]),
            benchmark_active=True,
        )
        self.assertFalse(any(item.category == "benchmarks" for item in candidates))

    def test_shared_snapshot_is_protected_when_any_consumer_is_running(self) -> None:
        shared = _write(
            self.home / "models/owner--shared/rev/model.bin", 4096
        ).parent
        references = [
            RuntimeStorageReference(
                model="running-replica",
                model_paths=(shared,),
                cache_paths=(),
                active=True,
            ),
            RuntimeStorageReference(
                model="stopped-replica",
                model_paths=(shared,),
                cache_paths=(),
                active=False,
            ),
        ]
        candidates = cleanup_plan(
            self.home,
            references,
            benchmark_roots=(),
            benchmark_active=False,
        )
        self.assertNotIn(shared, {item.path for item in candidates})

    def test_cleanup_revalidates_inode_and_writes_a_durable_receipt(self) -> None:
        target = _write(self.home / "models/owner--model/rev/model.bin", 4096).parent
        candidate = cleanup_candidate(
            category="models",
            path=target,
            allowed_root=self.home / "models",
            reason="inactive",
            models=("model",),
        )
        result = execute_cleanup(self.home, (candidate,))
        self.assertFalse(target.exists())
        self.assertEqual(result["models_to_download_again"], ["model"])
        receipt = pathlib.Path(result["receipt"])
        document = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(document["state"], "completed")
        self.assertEqual(len(document["removed"]), 1)

    def test_cleanup_rejects_symlink_and_changed_target(self) -> None:
        real = _write(self.home / "models/owner--real/rev/model.bin", 1).parent
        linked = self.home / "models/owner--linked/rev"
        linked.parent.mkdir(parents=True)
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(StorageUsageError, "symlink"):
            cleanup_candidate(
                category="models",
                path=linked,
                allowed_root=self.home / "models",
                reason="unsafe",
            )

        candidate = cleanup_candidate(
            category="models",
            path=real,
            allowed_root=self.home / "models",
            reason="inactive",
        )
        moved = real.with_name("old")
        real.replace(moved)
        real.mkdir()
        with self.assertRaisesRegex(StorageUsageError, "changed after review"):
            execute_cleanup(self.home, (candidate,))

    def test_json_cleanup_removes_only_selected_category(self) -> None:
        references, paths = self._fixtures()
        arguments = argparse.Namespace(
            clean=True,
            category=["models"],
            yes=True,
            json=True,
        )
        output = io.StringIO()
        with (
            mock.patch.dict(os.environ, self.environment),
            mock.patch.object(cli, "_group_storage_references", return_value=references),
            mock.patch.object(cli, "_service_storage_references", return_value=[]),
            mock.patch.object(cli.benchmark_jobs, "active_state", return_value=None),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.node_usage_command(arguments), 0)
        document = json.loads(output.getvalue())
        self.assertEqual(
            document["cleanup"]["models_to_download_again"], ["stopped-model"]
        )
        self.assertTrue(paths["active_model"].exists())
        self.assertFalse(paths["stopped_model"].exists())
        self.assertFalse(paths["orphan_model"].exists())
        self.assertTrue(paths["stopped_cache"].exists())
        self.assertTrue(paths["benchmarks"].exists())

    def test_cleanup_requires_yes_without_a_terminal(self) -> None:
        references, _paths = self._fixtures()
        arguments = argparse.Namespace(
            clean=True,
            category=["models"],
            yes=False,
            json=True,
        )
        with (
            mock.patch.dict(os.environ, self.environment),
            mock.patch.object(cli, "_group_storage_references", return_value=references),
            mock.patch.object(cli, "_service_storage_references", return_value=[]),
            mock.patch.object(cli.benchmark_jobs, "active_state", return_value=None),
        ):
            with self.assertRaisesRegex(cli.LetsInferError, "requires --yes"):
                cli.node_usage_command(arguments)

    def test_cleanup_rejects_a_plan_that_changes_after_review(self) -> None:
        target = _write(
            self.home / "models/owner--model/rev/model.bin", 4096
        ).parent
        first = cleanup_candidate(
            category="models",
            path=target,
            allowed_root=self.home / "models",
            reason="inactive",
        )
        first_report = usage_report(self.home, (first,))
        _write(target / "extra.bin", 4096)
        second = cleanup_candidate(
            category="models",
            path=target,
            allowed_root=self.home / "models",
            reason="inactive",
        )
        second_report = usage_report(self.home, (second,))
        arguments = argparse.Namespace(
            clean=True,
            category=["models"],
            yes=True,
            json=True,
        )
        with (
            mock.patch.dict(os.environ, self.environment),
            mock.patch.object(
                cli,
                "_node_usage_plan",
                side_effect=[
                    (first_report, (first,), False),
                    (second_report, (second,), False),
                ],
            ),
        ):
            with self.assertRaisesRegex(cli.LetsInferError, "changed after review"):
                cli.node_usage_command(arguments)
        self.assertTrue(target.exists())

    def test_clean_is_blocked_while_a_benchmark_is_active(self) -> None:
        arguments = argparse.Namespace(
            clean=True,
            category=None,
            yes=True,
            json=True,
        )
        with (
            mock.patch.dict(os.environ, self.environment),
            mock.patch.object(cli, "_group_storage_references", return_value=[]),
            mock.patch.object(cli, "_service_storage_references", return_value=[]),
            mock.patch.object(
                cli.benchmark_jobs,
                "active_state",
                return_value={"job_id": "active"},
            ),
        ):
            with self.assertRaisesRegex(cli.LetsInferError, "benchmark is active"):
                cli.node_usage_command(arguments)

    def test_missing_exact_model_is_downloaded_again_before_start(self) -> None:
        manifest = {
            "artifacts": [
                {
                    "name": "primary",
                    "repository": "owner/model",
                    "revision": "a" * 40,
                    "uri": "hf://owner/model@" + "a" * 40,
                }
            ]
        }
        with (
            mock.patch.object(
                cli,
                "verify_model_snapshot",
                side_effect=cli.LetsInferError("snapshot missing"),
            ),
            mock.patch.object(cli, "acquire_model_snapshot") as acquire,
            mock.patch.object(cli, "ensure_image") as image,
        ):
            downloaded = cli.ensure_install_dependencies(
                manifest,
                model_cache=self.home / "models",
                runtime_artifact_root=self.home / "runtimes/object",
                download=True,
                build_image=False,
            )
        self.assertEqual(downloaded, ("owner/model@" + "a" * 40,))
        acquire.assert_called_once()
        self.assertTrue(image.call_args.kwargs["pull"])

    def test_failed_automatic_model_download_is_explicit(self) -> None:
        manifest = {
            "artifacts": [
                {
                    "name": "primary",
                    "repository": "owner/model",
                    "revision": "b" * 40,
                    "uri": "hf://owner/model@" + "b" * 40,
                }
            ]
        }
        with (
            mock.patch.object(
                cli,
                "verify_model_snapshot",
                side_effect=cli.LetsInferError("snapshot missing"),
            ),
            mock.patch.object(
                cli,
                "acquire_model_snapshot",
                side_effect=cli.LetsInferError("network unavailable"),
            ),
        ):
            with self.assertRaisesRegex(
                cli.LetsInferError,
                "automatic re-download failed: network unavailable",
            ):
                cli.ensure_install_dependencies(
                    manifest,
                    model_cache=self.home / "models",
                    runtime_artifact_root=self.home / "runtimes/object",
                    download=True,
                    build_image=False,
                )

    def test_container_usage_counts_unique_images_and_writable_layers(self) -> None:
        image = "sha256:" + "a" * 64
        responses = iter(
            (
                subprocess.CompletedProcess([], 0, "abc123def456\ndef456abc123\n", ""),
                subprocess.CompletedProcess(
                    [],
                    0,
                    json.dumps(
                        [
                            {
                                "Config": {"Labels": {cli.MANAGED_LABEL: "true"}},
                                "SizeRw": 100,
                                "Image": image,
                            },
                            {
                                "Config": {"Labels": {cli.MANAGED_LABEL: "true"}},
                                "SizeRw": 200,
                                "Image": image,
                            },
                        ]
                    ),
                    "",
                ),
                subprocess.CompletedProcess(
                    [], 0, json.dumps([{"Size": 1000}]), ""
                ),
            )
        )
        run = mock.Mock(side_effect=lambda *_args, **_kwargs: next(responses))
        result = container_runtime_usage(run, managed_label=cli.MANAGED_LABEL)
        self.assertTrue(result["available"])
        self.assertEqual(result["managed_containers"], 2)
        self.assertEqual(result["writable_bytes"], 300)
        self.assertEqual(result["image_logical_bytes"], 1000)
        self.assertFalse(result["included_in_total"])

    def test_unknown_container_authority_disables_cleanup(self) -> None:
        unavailable = mock.Mock(
            return_value=subprocess.CompletedProcess(
                [], 1, "", "Cannot connect to the Docker daemon"
            )
        )
        with self.assertRaisesRegex(StorageUsageError, "cleanup is disabled"):
            managed_container_running(
                unavailable,
                "letsinfer-group",
                managed_label=cli.MANAGED_LABEL,
            )

        absent = mock.Mock(
            return_value=subprocess.CompletedProcess(
                [], 1, "", "Error: No such container: letsinfer-group"
            )
        )
        self.assertFalse(
            managed_container_running(
                absent,
                "letsinfer-group",
                managed_label=cli.MANAGED_LABEL,
            )
        )


if __name__ == "__main__":
    unittest.main()
