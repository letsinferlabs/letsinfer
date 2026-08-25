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
    @staticmethod
    def _live_metrics(cell: str | None = "32k-code-c1") -> dict:
        return {
            "schema_version": 1,
            "sample_unix_ms": 1_700_000_000_000,
            "fresh": True,
            "performance_cell": cell,
            "active_requests": 1,
            "queued_requests": 0,
            "rates": {
                "aggregate_tokens_per_second": 58.9,
                "decode_tokens_per_second": 27.1,
                "prefill_tokens_per_second": 219.4,
                "average_ttft_milliseconds": 420.0,
            },
            "temperatures": {
                "gpu_temp_deci_c": 390,
                "system_temp_deci_c": 430,
                "nvme_temp_deci_c": 380,
            },
            "system": {
                "gpu_percent": 80,
                "cpu_percent": 20,
                "memory_percent": 70,
                "memory_used_mib": 1000,
                "memory_total_mib": 2000,
                "disk_percent": 10,
                "disk_read_kib_s": 12,
                "disk_write_kib_s": 34,
                "power_deci_w": 500,
            },
        }

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

    def test_live_metrics_merge_preserves_worker_progress_and_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = pathlib.Path(temporary)
            state = {
                "schema_version": 1,
                "state": "running",
                "pid": 123,
                "job_id": "job-live",
                "runtime": "model",
            }
            with mock.patch.object(benchmark_jobs, "data_root", return_value=data):
                benchmark_jobs._write_json(benchmark_jobs.state_path(), state)
                benchmark_jobs.update_progress(
                    "job-live",
                    {
                        "phase": "workload:32k-code-c1:measuring",
                        "message": "Measuring 32k-code-c1",
                        "current_cell": "32k-code-c1",
                    },
                )
                merged = benchmark_jobs.merge_progress(
                    "job-live",
                    {
                        "live_metrics": self._live_metrics(),
                        "preparation": {
                            "schema_version": 1,
                            "state": "measuring",
                            "detail": "Measuring the current workload",
                            "updated_unix_ms": 1_700_000_000_000,
                        },
                    },
                )
                self.assertEqual(
                    merged["phase"], "workload:32k-code-c1:measuring"
                )
                self.assertEqual(
                    benchmark_jobs.read_progress()["live_metrics"],
                    self._live_metrics(),
                )

                invalid = self._live_metrics()
                invalid["temperatures"] = {"gpu_temp_deci_c": -1}
                with self.assertRaisesRegex(
                    benchmark_jobs.BenchmarkJobError, "live metrics"
                ):
                    benchmark_jobs.merge_progress(
                        "job-live", {"live_metrics": invalid}
                    )


if __name__ == "__main__":
    unittest.main()
