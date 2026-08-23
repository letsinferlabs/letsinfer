#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

from core import benchmark_jobs
from core import cli
from core import paths
from tools.uninstall_core import CoreUninstallError, remove
from tests.runtime_fixture import runtime_candidate


class HomeContractTests(unittest.TestCase):
    def test_one_home_owns_every_default_product_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "letsinfer"
            with mock.patch.dict(
                os.environ,
                {
                    "LETSINFER_HOME": str(home),
                    "LETSINFER_CONFIG_HOME": "",
                    "LETSINFER_DATA_HOME": "",
                    "LETSINFER_RUNTIME_HOME": "",
                    "LETSINFER_MODELS_HOME": "",
                },
                clear=False,
            ):
                for name in (
                    "LETSINFER_CONFIG_HOME",
                    "LETSINFER_DATA_HOME",
                    "LETSINFER_RUNTIME_HOME",
                    "LETSINFER_MODELS_HOME",
                ):
                    os.environ.pop(name)
                self.assertEqual(paths.config_root(), home / "config")
                self.assertEqual(paths.data_root(), home / "state")
                self.assertEqual(paths.runtime_root(), home / "runtimes")
                self.assertEqual(paths.models_root(), home / "models")
                self.assertEqual(paths.benchmarks_root(), home / "benchmarks")
                paths.ensure_home()
                for root in paths.managed_roots():
                    self.assertTrue(root.is_dir())
                    self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_home_rejects_a_broad_root(self) -> None:
        with mock.patch.dict(os.environ, {"LETSINFER_HOME": "/"}):
            with self.assertRaisesRegex(paths.PathContractError, "too broad"):
                paths.home_root()


class BenchmarkCleanTests(unittest.TestCase):
    def test_clean_removes_local_evidence_but_not_runtime_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            with mock.patch.dict(os.environ, {"LETSINFER_HOME": str(home)}):
                local = paths.benchmarks_root() / "fixture-run"
                local.mkdir(parents=True)
                (local / "benchmark.json").write_text("local\n", encoding="utf-8")
                job = benchmark_jobs.root()
                job.mkdir(parents=True)
                (job / "benchmark.log").write_text("done\n", encoding="utf-8")
                sealed = paths.runtime_root() / "objects" / "digest" / "benchmark.json"
                sealed.parent.mkdir(parents=True)
                sealed.write_text("sealed\n", encoding="utf-8")
                output = io.StringIO()
                with mock.patch.object(benchmark_jobs, "active_state", return_value=None):
                    with contextlib.redirect_stdout(output):
                        result = cli._benchmark_clean(assume_yes=True)
                self.assertEqual(result, 0)
                self.assertFalse(paths.benchmarks_root().exists())
                self.assertFalse(job.exists())
                self.assertEqual(sealed.read_text(encoding="utf-8"), "sealed\n")
                self.assertIn("sealed runtime results preserved", output.getvalue())


class ManagedHomeRemovalTests(unittest.TestCase):
    def _layout(self, temporary: str) -> tuple[pathlib.Path, pathlib.Path]:
        root = pathlib.Path(temporary)
        home = root / "operator" / ".local/share/letsinfer"
        models = home / "models"
        models.mkdir(parents=True)
        (models / "weights").write_text("model\n", encoding="utf-8")
        for name in ("config", "state", "runtimes", "benchmarks", "cache", "logs"):
            directory = home / name
            directory.mkdir()
            (directory / "owned").write_text(name, encoding="utf-8")
        return home, models

    def test_keep_models_leaves_only_models(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home, models = self._layout(temporary)
            operator = pathlib.Path(temporary) / "operator"
            with mock.patch.dict(os.environ, {"LETSINFER_HOME": str(home)}):
                with mock.patch.object(pathlib.Path, "home", return_value=operator):
                    cli._remove_managed_home(
                        keep_models=True,
                        configured_model_cache=models,
                    )
            self.assertEqual([path.name for path in home.iterdir()], ["models"])
            self.assertEqual((models / "weights").read_text(encoding="utf-8"), "model\n")

    def test_default_removes_the_complete_home(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home, models = self._layout(temporary)
            operator = pathlib.Path(temporary) / "operator"
            with mock.patch.dict(os.environ, {"LETSINFER_HOME": str(home)}):
                with mock.patch.object(pathlib.Path, "home", return_value=operator):
                    cli._remove_managed_home(
                        keep_models=False,
                        configured_model_cache=models,
                    )
            self.assertFalse(home.exists())

    def test_removal_refuses_the_operator_home(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            operator = pathlib.Path(temporary)
            with mock.patch.object(pathlib.Path, "home", return_value=operator):
                with self.assertRaisesRegex(cli.LetsInferError, "overly broad"):
                    cli._remove_user_tree(operator, label="configured model cache")


class RuntimeImageRemovalTests(unittest.TestCase):
    def test_collects_only_images_from_validated_runtime_objects(self) -> None:
        runtime = runtime_candidate()
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            valid = home / "runtimes/.objects/valid"
            valid.mkdir(parents=True)
            (valid / "runtime.json").write_text(
                json.dumps(runtime),
                encoding="utf-8",
            )
            corrupt = home / "runtimes/.objects/corrupt"
            corrupt.mkdir()
            (corrupt / "runtime.json").write_text(
                json.dumps(
                    {
                        "engine": {"oci": {"reference": "unrelated:latest"}}
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"LETSINFER_HOME": str(home)}):
                references = cli._installed_runtime_image_references()

        self.assertIn(runtime["engine"]["oci"]["reference"], references)
        self.assertIn(runtime["engine"]["oci"]["immutable_id"], references)
        self.assertIn(runtime["model"]["acquisition"]["image"], references)
        self.assertNotIn("unrelated:latest", references)


class UninstallFlowTests(unittest.TestCase):
    def test_uninstall_disables_exact_public_exposure(self) -> None:
        store = mock.MagicMock()
        store.__enter__.return_value.exposure.return_value = {
            "state": "enabled",
            "provider": "tailscale-funnel",
            "configuration_sha256": "a" * 64,
        }
        with (
            mock.patch.object(cli, "site_identity_path") as identity_path,
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(cli, "disable_tailscale") as disable,
        ):
            identity_path.return_value.is_file.return_value = True
            cli._remove_public_exposure()
        disable.assert_called_once_with("a" * 64)

    def test_cleanup_of_home_and_core_is_deferred_until_after_audit(self) -> None:
        arguments = mock.Mock(config=None, keep_models=True)
        with (
            mock.patch.object(cli, "_uninstall_service_config", return_value=(None, None)),
            mock.patch.object(cli, "_confirmed", return_value=True),
            mock.patch.object(
                cli, "_installed_runtime_image_references", return_value={"fixture@sha256:x"}
            ),
            mock.patch.object(cli.benchmark_jobs, "active_state", return_value=None),
            mock.patch.object(cli, "site_identity_path", return_value=pathlib.Path("/absent")),
            mock.patch.object(cli, "_retire_qualification_candidate"),
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli, "_remove_linux_services"),
            mock.patch.object(cli, "_remove_managed_containers", return_value=(2, 3)) as remove_containers,
            mock.patch.object(cli, "_remove_managed_home") as remove_home,
            mock.patch.object(cli, "_remove_installed_core", return_value=True) as remove_core,
        ):
            self.assertEqual(cli.uninstall(arguments), 0)
            remove_home.assert_not_called()
            remove_core.assert_not_called()
            remove_containers.assert_called_once_with({"fixture@sha256:x"})
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(arguments.after_audit(), 0)
            remove_home.assert_called_once_with(
                keep_models=True,
                configured_model_cache=None,
            )
            remove_core.assert_called_once_with()

    def test_progress_begins_only_after_confirmation_and_covers_final_removal(self) -> None:
        arguments = mock.Mock(config=None, keep_models=False)
        events: list[str] = []

        def confirmed(*_args: object, **_kwargs: object) -> bool:
            events.append("confirmed")
            return True

        def activity(message: str, **_kwargs: object) -> contextlib.AbstractContextManager[None]:
            events.append(f"progress:{message}")
            return contextlib.nullcontext()

        with (
            mock.patch.object(cli, "_uninstall_service_config", return_value=(None, None)),
            mock.patch.object(cli, "_confirmed", side_effect=confirmed),
            mock.patch.object(cli.ui, "progress", side_effect=activity),
            mock.patch.object(
                cli.ui, "protect_stdout", side_effect=lambda _owner: contextlib.nullcontext()
            ),
            mock.patch.object(cli, "_human_presenter", return_value=None),
            mock.patch.object(cli, "_installed_runtime_image_references", return_value=set()),
            mock.patch.object(cli.benchmark_jobs, "active_state", return_value=None),
            mock.patch.object(cli, "site_identity_path", return_value=pathlib.Path("/absent")),
            mock.patch.object(cli, "_retire_qualification_candidate"),
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli, "_remove_linux_services"),
            mock.patch.object(cli, "_remove_managed_containers", return_value=(0, 0)),
            mock.patch.object(cli, "_remove_managed_home"),
            mock.patch.object(cli, "_remove_installed_core", return_value=True),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cli.uninstall(arguments), 0)
            self.assertEqual(
                events,
                [
                    "confirmed",
                    "progress:Stopping services and removing runtime data",
                ],
            )
            self.assertEqual(arguments.after_audit(), 0)
        self.assertEqual(
            events,
            [
                "confirmed",
                "progress:Stopping services and removing runtime data",
                "progress:Removing the core and managed data",
            ],
        )

    def test_declining_confirmation_does_not_begin_cleanup(self) -> None:
        arguments = mock.Mock(config=None, keep_models=False)
        with (
            mock.patch.object(cli, "_uninstall_service_config", return_value=(None, None)),
            mock.patch.object(cli, "_confirmed", return_value=False),
            mock.patch.object(cli, "_installed_runtime_image_references") as images,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cli.uninstall(arguments), 0)
        images.assert_not_called()


class CoreRemovalTests(unittest.TestCase):
    def test_removes_only_the_validated_install_store_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            operator = root / "operator"
            prefix = operator / ".local"
            home = prefix / "share/letsinfer"
            source = home / "core/versions/1.0.0/identity"
            source.mkdir(parents=True)
            (source / "SOURCE-MANIFEST.json").write_text(
                json.dumps({"product": "letsinfer"}), encoding="utf-8"
            )
            launcher = prefix / "bin/letsinfer"
            launcher.parent.mkdir(parents=True)
            launcher.symlink_to(source / "bin/letsinfer")
            (home / "core/current").symlink_to(source)
            unrelated = prefix / "lib/unrelated"
            unrelated.mkdir(parents=True)

            result = remove(
                source,
                launcher_directory=prefix / "bin",
                letsinfer_home=home,
            )

            self.assertFalse((prefix / "lib/letsinfer").exists())
            self.assertFalse((home / "core").exists())
            self.assertFalse(launcher.exists())
            self.assertTrue(unrelated.is_dir())
            self.assertEqual(
                pathlib.Path(result["removed_store"]),
                (home / "core").resolve(strict=False),
            )

    def test_refuses_a_source_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(CoreUninstallError, "immutable"):
                remove(
                    root,
                    launcher_directory=root / "bin",
                    letsinfer_home=root / "home",
                )


if __name__ == "__main__":
    unittest.main()
