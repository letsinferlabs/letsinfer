#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import pathlib
import tempfile
import types
import unittest
from unittest import mock

from core import benchmark_jobs


class BenchmarkJobTests(unittest.TestCase):
    def test_start_records_one_detached_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = pathlib.Path(temporary)
            process = types.SimpleNamespace(pid=4321)
            with (
                mock.patch.object(benchmark_jobs, "data_root", return_value=data),
                mock.patch.object(benchmark_jobs, "active_state", return_value=None),
                mock.patch.object(
                    benchmark_jobs.subprocess, "Popen", return_value=process
                ) as launch,
            ):
                state = benchmark_jobs.start(
                    ["/opt/letsinfer/bin/letsinfer", "benchmark", "model"],
                    runtime="model",
                    output_directory="/evidence/model",
                )
                self.assertEqual(state["pid"], 4321)
                self.assertEqual(state["state"], "starting")
                command = launch.call_args.args[0]
                self.assertEqual(command[-3:-1], ["--job-worker", "--job-id"])
                self.assertEqual(command[-1], state["job_id"])
                self.assertTrue(launch.call_args.kwargs["start_new_session"])
                self.assertEqual(benchmark_jobs.read_state(), state)

    def test_active_state_binds_pid_to_job_identity(self) -> None:
        state = {
            "schema_version": 1,
            "state": "running",
            "pid": 123,
            "job_id": "job-identity",
        }
        with (
            mock.patch.object(benchmark_jobs.os, "kill"),
            mock.patch.object(
                benchmark_jobs,
                "_process_command",
                return_value="letsinfer benchmark model --job-worker --job-id job-identity",
            ),
        ):
            self.assertTrue(benchmark_jobs.is_alive(state))
        with (
            mock.patch.object(benchmark_jobs.os, "kill"),
            mock.patch.object(
                benchmark_jobs,
                "_process_command",
                return_value="unrelated process",
            ),
        ):
            self.assertFalse(benchmark_jobs.is_alive(state))

    def test_stop_targets_only_the_recorded_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = pathlib.Path(temporary)
            state = {
                "schema_version": 1,
                "state": "running",
                "pid": 987,
                "job_id": "job-stop",
                "runtime": "model",
            }
            with (
                mock.patch.object(benchmark_jobs, "data_root", return_value=data),
                mock.patch.object(
                    benchmark_jobs, "active_state", return_value=dict(state)
                ),
                mock.patch.object(benchmark_jobs.os, "kill") as kill,
            ):
                stopped = benchmark_jobs.request_stop()
                self.assertEqual(stopped["state"], "stopping")
                kill.assert_called_once_with(987, benchmark_jobs.signal.SIGTERM)
                self.assertEqual(benchmark_jobs.read_state()["state"], "stopping")


if __name__ == "__main__":
    unittest.main()
