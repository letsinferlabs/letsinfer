# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import threading
import time
import unittest
from unittest import mock

from core import cli as letsinfer
from core import status_ui, topology_ui, ui
from core.actions import ACTIONS, AuditPolicy, CommandScope, MutationClass
from core.ui_contracts import ProgressKind, UI_CONTRACTS


class FakeStream(io.StringIO):
    def __init__(self, *, tty: bool, encoding: str = "utf-8") -> None:
        super().__init__()
        self._tty = tty
        self._encoding = encoding

    def isatty(self) -> bool:
        return self._tty

    @property
    def encoding(self) -> str:
        return self._encoding


class TerminalTests(unittest.TestCase):
    def test_tty_status_uses_the_logo_motif_and_color(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        terminal.status("Resolving runtime")
        terminal.success("Ready")
        self.assertTrue(terminal.interactive)
        self.assertTrue(terminal.color)
        self.assertEqual(terminal.mark, "ϟ")
        self.assertIn("\033[", stream.getvalue())
        self.assertIn("Resolving runtime", stream.getvalue())
        self.assertIn("Ready", stream.getvalue())

    def test_logo_highlights_the_lockup_as_a_light_badge(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        rendered = terminal.logo()
        self.assertIn(
            ui.BOLD
            + ui.DARK
            + ui.LIGHT_BACKGROUND
            + " ϟ  LET'S INFER "
            + ui.RESET,
            rendered,
        )

    def test_no_color_keeps_interaction_without_escape_styling(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(
            stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        terminal.warning("Memory pressure")
        self.assertTrue(terminal.interactive)
        self.assertFalse(terminal.color)
        self.assertNotIn("\033[", stream.getvalue())
        self.assertEqual(stream.getvalue(), "! Memory pressure\n")

    def test_non_tty_and_dumb_terminal_use_plain_fallback(self) -> None:
        for stream, environ in (
            (FakeStream(tty=False), {"TERM": "xterm-256color"}),
            (FakeStream(tty=True), {"TERM": "dumb"}),
        ):
            with self.subTest(tty=stream.isatty(), term=environ["TERM"]):
                terminal = ui.Terminal(stream, environ=environ)
                terminal.error("Unavailable")
                self.assertFalse(terminal.interactive)
                self.assertFalse(terminal.color)
                self.assertEqual(stream.getvalue(), "ERROR Unavailable\n")

    def test_spinner_cleans_its_line_and_finishes_once(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        spinner = ui.Spinner(
            terminal,
            "Installing runtime",
            done="Runtime installed",
            delay=0,
            interval=0.01,
        )
        with spinner:
            time.sleep(0.035)
        rendered = stream.getvalue()
        self.assertIn("Installing runtime", rendered)
        self.assertIn(ui.CLEAR_LINE, rendered)
        self.assertEqual(rendered.count("Runtime installed"), 1)
        self.assertTrue(rendered.endswith("Runtime installed\n"))
        self.assertIsNotNone(spinner._thread)
        self.assertFalse(spinner._thread.is_alive())

    def test_disabled_spinner_is_silent(self) -> None:
        stream = FakeStream(tty=False)
        with ui.progress("Working", done="Done", stream=stream):
            pass
        self.assertEqual(stream.getvalue(), "")

    def test_external_output_stops_the_current_spinner(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        spinner = ui.Spinner(
            terminal,
            "Downloading image",
            done="Image ready",
            delay=0,
            interval=0.01,
        )
        with spinner, ui.protect_stdout(spinner):
            time.sleep(0.02)
            ui.before_external_output()
            self.assertTrue(spinner._stop.is_set())
        self.assertIn(ui.CLEAR_LINE, stream.getvalue())
        self.assertIn("Image ready", stream.getvalue())

    def test_spinner_cleans_up_without_success_on_failure(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        spinner = ui.Spinner(
            terminal,
            "Starting inference",
            done="Inference ready",
            delay=0,
            interval=0.01,
        )
        with self.assertRaisesRegex(RuntimeError, "failed"):
            with spinner:
                time.sleep(0.02)
                raise RuntimeError("failed")
        rendered = stream.getvalue()
        self.assertIn(ui.CLEAR_LINE, rendered)
        self.assertNotIn("Inference ready", rendered)
        self.assertIsNotNone(spinner._thread)
        self.assertFalse(spinner._thread.is_alive())

    def test_step_progress_marks_completed_current_and_upcoming_rows(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(
            stream, environ={"TERM": "xterm-256color", "NO_COLOR": "1"}
        )
        with ui.StepProgress(
            terminal,
            ("Install core", "Rebind runtime", "Verify update"),
            section="update",
            interval=1,
        ) as progress:
            progress.advance()
            progress.advance()
            progress.advance()
        rendered = stream.getvalue()
        self.assertIn("LET'S INFER  /  UPDATE", rendered)
        self.assertIn("✓  Install core", rendered)
        self.assertIn("✓  Rebind runtime", rendered)
        self.assertIn("✓  Verify update", rendered)
        self.assertIn("○  Verify update", rendered)

    def test_step_progress_failure_marks_only_the_active_row(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(
            stream, environ={"TERM": "xterm-256color", "NO_COLOR": "1"}
        )
        with self.assertRaisesRegex(RuntimeError, "broken"):
            with ui.StepProgress(
                terminal,
                ("Install core", "Rebind runtime", "Verify update"),
                section="update",
                interval=1,
            ) as progress:
                progress.advance()
                raise RuntimeError("broken")
        rendered = stream.getvalue()
        self.assertIn("✗  Rebind runtime  Failed", rendered)
        self.assertIn("○  Verify update", rendered)

    def test_step_progress_is_silent_for_non_tty_output(self) -> None:
        stream = FakeStream(tty=False)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        with ui.StepProgress(
            terminal, ("Install", "Verify"), section="update"
        ) as progress:
            progress.advance()
            progress.advance()
        self.assertEqual(stream.getvalue(), "")

    def test_runtime_status_is_a_compact_branded_health_card(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "node_active": "active",
                "recovery_timer_active": "active",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
                "within_memory_limit": True,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "deepseek-v4-flash",
                "engine": "dwarfstar",
                "target": "dgx-spark",
                "runtime_version": "0.11.0-rc.3",
                "capacity": {
                    "max_context_tokens": 557056,
                    "max_active_requests": 128,
                },
            },
            "protection": {"armed": True, "trip_latched": False},
            "telemetry": {
                "active_requests": 2,
                "connected_clients": 3,
                "queued_requests": 1,
                "rates": {
                    "output_tokens_per_second": 58.9,
                    "decode_tokens_per_second": 27.1,
                    "prefill_tokens_per_second": 219.4,
                },
            },
        }
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color"},
        )
        rendered = stream.getvalue()
        self.assertIn("LET'S INFER", rendered)
        self.assertIn("SERVING", rendered)
        self.assertIn("deepseek-v4-flash", rendered)
        self.assertIn("dwarfstar", rendered)
        self.assertIn("dgx-spark", rendered)
        self.assertIn("0.11.0-rc.3", rendered)
        self.assertIn("557K context", rendered)
        self.assertIn("homeai.local:8000/v1", rendered)
        self.assertIn("19.0 / 30 M", rendered)
        self.assertIn("Request path", rendered)
        self.assertNotIn("Scheduler", rendered)
        self.assertIn("Performance", rendered)
        self.assertIn("58.9 tok/s", rendered)
        self.assertIn("CLIENT    3 connected", ui.ANSI.sub("", rendered))
        self.assertIn("Allocation", rendered)
        self.assertIn("\033[", rendered)
        plain = ui.ANSI.sub("", rendered)
        self.assertIn("deepseek-v4-flash 557K context", plain)
        request_path = plain.partition("Request path")[2].partition("Performance")[0]
        self.assertNotIn("homeai.local", request_path)
        self.assertNotIn("deepseek-v4-flash", request_path)
        self.assertNotIn("dgx-spark", request_path)
        header = next(line for line in plain.splitlines() if "LET'S INFER" in line)
        self.assertRegex(header, r"Home\s+✓\s+Uptime —\s+ϟ\s+LET'S INFER")
        self.assertGreater(header.index("LET'S INFER"), header.index("Uptime"))
        summary = rendered.partition("Request path")[0]
        self.assertNotIn("LIVE", summary)
        self.assertIn("dgx-spark", summary)
        self.assertNotIn("runtime pack", summary)
        self.assertNotIn("candidate control plane active", summary)
        self.assertNotIn("candidate guarded", summary)

    def test_runtime_status_calls_out_a_protection_trip(self) -> None:
        stream = FakeStream(tty=True)
        ui.runtime_status(
            {
                "service": {
                    "active": "active",
                    "engine_active": "active",
                    "gateway_active": "active",
                    "gateway_health": True,
                    "gateway_auth_required": True,
                    "gateway_authenticated": True,
                    "gateway_model_identity": True,
                    "node_active": "active",
                    "recovery_timer_active": "active",
                    "memory_current_bytes": 1,
                    "memory_limit_bytes": 2,
                    "within_memory_limit": True,
                },
                "container": {
                    "state": "running",
                    "healthy": True,
                    "docker_health": "healthy",
                    "model_identity": True,
                },
                "protection": {"armed": False, "trip_latched": True},
            },
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("FAILED", rendered)
        self.assertIn("Blocked", rendered)
        self.assertNotIn("\033[", rendered)

    def test_runtime_status_keeps_verified_update_context_in_live_panel(self) -> None:
        stream = FakeStream(tty=True)
        ui.runtime_status(
            {
                "service": {},
                "container": {},
                "protection": {},
                "updates": [
                    {"kind": "core", "subject": "core", "version": "0.11.0-rc.30"},
                    {
                        "kind": "runtime",
                        "subject": "qwen3.8-27b",
                        "version": "0.1.0-rc.11",
                    },
                ],
            },
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("Update available", rendered)
        self.assertIn("Core 0.11.0-rc.30", rendered)
        self.assertIn("qwen3.8-27b 0.1.0-rc.11", rendered)

    def test_status_history_uses_the_exact_six_color_design_palette(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        payload = {
            "service": {
                "memory_current_bytes": 15 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
            },
            "telemetry": {
                "history": [
                    {
                        "aggregate": {
                            "active_requests": 1,
                            "rates": {"aggregate_tokens_per_second": 1.0},
                        }
                    },
                    {
                        "aggregate": {
                            "active_requests": 2,
                            "rates": {"aggregate_tokens_per_second": 2.0},
                        }
                    },
                ],
                "system": {
                    "gpu_percent": 1,
                    "memory_percent": 2,
                    "cpu_percent": 3,
                    "disk_percent": 4,
                    "power_deci_w": 50,
                    "network_rx_kib_s": 3,
                    "network_tx_kib_s": 3,
                },
            }
        }
        rendered = "\n".join(
            status_ui.dashboard_lines(
                payload,
                terminal,
                session_history={
                    "gpu": [1, 2],
                    "memory": [2, 3],
                    "cpu": [3, 4],
                    "nvme": [4, 5],
                    "power": [4, 5],
                    "network": [5, 6],
                },
            )
        )
        self.assertEqual(
            ui.HISTORY_CHART_COLORS,
            (
                "\033[38;2;0;156;223m",
                "\033[38;2;151;57;153m",
                "\033[38;2;97;187;70m",
                "\033[38;2;255;185;0m",
                "\033[38;2;247;130;0m",
                "\033[38;2;226;56;56m",
            ),
        )
        for color in ui.HISTORY_CHART_COLORS[2:]:
            self.assertIn(color, rendered)
            self.assertNotIn(ui.DIM + color, rendered)
        performance = rendered.partition("Performance")[2].partition("System")[0]
        system = rendered.partition("System")[2].partition("Temperature")[0]
        self.assertIn("Requests", performance)
        self.assertIn("Watchdog", performance)
        self.assertNotIn(ui.HISTORY_CHART_COLORS[0], performance)
        self.assertNotIn(ui.HISTORY_CHART_COLORS[1], performance)
        self.assertIn("Unified mem", system)
        self.assertIn("Power", system)
        self.assertIn("Network", system)
        self.assertNotIn("Tokens", system)
        self.assertNotIn("Requests", system)

    def test_status_utilization_history_uses_an_absolute_percent_scale(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        rendered = "\n".join(
            status_ui.dashboard_lines(
                {
                    "telemetry": {
                        "system": {
                            "gpu_percent": 2,
                            "memory_percent": 27,
                            "cpu_percent": 10,
                            "disk_percent": 20,
                        }
                    }
                },
                terminal,
                session_history={
                    "gpu": [2] * 24,
                    "memory": [27] * 24,
                    "cpu": [10] * 24,
                    "nvme": [20] * 24,
                },
            )
        )
        history = ui.ANSI.sub("", rendered).partition("System")[2].partition("Temperature")[0]
        rows = {
            fields[0]: fields[-1]
            for line in history.splitlines()
            if (fields := line.strip(" │").split())
        }
        self.assertEqual(rows["GPU"], "▁" * 24)
        self.assertEqual(rows["Unified"], "▃" * 24)
        self.assertEqual(rows["CPU"], "▂" * 24)
        self.assertEqual(rows["NVMe"], "▂" * 24)

    def test_status_system_temperatures_are_bold_without_bolding_details(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        rendered = "\n".join(
            status_ui.dashboard_lines(
                {
                    "telemetry": {
                        "system": {
                            "gpu_temp_deci_c": 410,
                            "gpu_clock_mhz": 2460,
                            "system_temp_deci_c": 550,
                            "cpu_clock_mhz": 3900,
                            "nvme_temp_deci_c": 430,
                            "disk_read_kib_s": 10,
                            "disk_write_kib_s": 20,
                        }
                    }
                },
                terminal,
            )
        )
        for temperature in ("41°C", "55°C", "43°C"):
            self.assertIn(ui.BOLD + temperature, rendered)
        temperature = rendered.partition("Temperature")[2]
        self.assertNotIn("2.46G", temperature)
        self.assertNotIn("R10/W20", temperature)

    def test_status_scales_units_and_mutes_bold_secondary_values(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        rendered = "\n".join(
            status_ui.dashboard_lines(
                {
                    "telemetry": {
                        "fresh": True,
                        "system": {
                            "gpu_percent": 6,
                            "gpu_clock_mhz": 900,
                            "memory_percent": 8,
                            "memory_used_mib": 9 * 1024,
                            "memory_total_mib": 122 * 1024,
                            "cpu_percent": 7,
                            "cpu_clock_mhz": 2460,
                            "disk_percent": 16,
                            "disk_read_kib_s": 10,
                            "disk_write_kib_s": 2048,
                            "power_deci_w": 50,
                            "network_rx_kib_s": 1024,
                            "network_tx_kib_s": 1024,
                        },
                    }
                },
                terminal,
            )
        )
        plain = ui.ANSI.sub("", rendered)
        self.assertIn("6% 900 MHz", plain)
        self.assertIn("7% 2.46 GHz", plain)
        self.assertIn("8% 9 G / 122 G", plain)
        self.assertIn("↑10 K/s ↓2 M/s", plain)
        self.assertIn("2 M/s", plain)
        self.assertIn(ui.BOLD + ui.DIM + " 900 MHz" + ui.RESET, rendered)
        self.assertIn(ui.BOLD + ui.DIM + " 2.46 GHz" + ui.RESET, rendered)

    def test_status_separates_discrete_vram_from_installed_system_ram(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        rendered = "\n".join(
            status_ui.dashboard_lines(
                {
                    "hardware": {
                        "accelerator": {"minimum_memory_gib": 32},
                        "memory": {"topology": "discrete", "total_gib": 96},
                    },
                    "telemetry": {
                        "system": {
                            "gpu_memory_percent": 3,
                            "memory_percent": 5,
                            "memory_used_mib": 4608,
                            "memory_total_mib": 94 * 1024,
                        }
                    },
                },
                terminal,
                session_history={"vram": [2, 3], "memory": [4, 5]},
            )
        )
        plain = ui.ANSI.sub("", rendered)
        system = plain.partition("System")[2].partition("Temperature")[0]
        self.assertIn("VRAM", system)
        self.assertIn("3%", system)
        self.assertIn("32 G", system)
        self.assertIn("System RAM", system)
        self.assertIn("4.5 G / 96 G", system)
        self.assertNotIn("Unified mem", system)

    def test_status_system_trends_compare_consecutive_fresh_samples(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        payload = {
            "telemetry": {
                "fresh": True,
                "system": {
                    "gpu_percent": 20,
                    "memory_percent": 20,
                    "cpu_percent": 20,
                    "disk_percent": 20,
                    "power_deci_w": 200,
                },
            }
        }
        rendered = "\n".join(
            status_ui.dashboard_lines(
                payload,
                terminal,
                session_history={
                    "gpu": [10, 20],
                    "memory": [30, 20],
                    "cpu": [20, 20],
                    "nvme": [10, 20],
                    "power": [30, 20],
                },
            )
        )
        system = rendered.partition("System")[2].partition("Temperature")[0]
        self.assertEqual(system.count(ui.BOLD + ui.RED + "↑" + ui.RESET), 2)
        self.assertEqual(system.count(ui.BOLD + ui.GREEN + "↓" + ui.RESET), 2)
        gpu_line = ui.ANSI.sub(
            "", next(line for line in system.splitlines() if "GPU" in line)
        )
        self.assertRegex(gpu_line, r"GPU\s+20% ↑")
        cpu_line = next(line for line in system.splitlines() if "CPU" in line)
        self.assertNotIn("↑", ui.ANSI.sub("", cpu_line))
        self.assertNotIn("↓", ui.ANSI.sub("", cpu_line))

        payload["telemetry"]["display_state"] = "reconnecting"
        stale = "\n".join(
            status_ui.dashboard_lines(
                payload,
                terminal,
                session_history={"gpu": [10, 20]},
            )
        )
        stale_system = ui.ANSI.sub("", stale).partition("System")[2].partition("Temperature")[0]
        self.assertNotIn("↑", stale_system)
        self.assertNotIn("↓", stale_system)

    def test_status_history_headers_and_charts_share_the_right_edge(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        rendered = "\n".join(
            status_ui.dashboard_lines(
                {
                    "telemetry": {
                        "fresh": True,
                        "system": {
                            "gpu_percent": 20,
                            "gpu_temp_deci_c": 400,
                        },
                    }
                },
                terminal,
                session_history={
                    "gpu": [10, 20],
                    "gpu_temp": [35, 40],
                },
            )
        )
        plain_rendered = ui.ANSI.sub("", rendered)
        system = plain_rendered.partition("System")[2].partition("Temperature")[0]
        temperature = plain_rendered.partition("Temperature")[2]
        system_header = next(
            line for line in plain_rendered.splitlines() if "System" in line
        )
        temperature_header = next(
            line for line in plain_rendered.splitlines() if "Temperature" in line
        )
        self.assertTrue(system_header.rstrip(" │").endswith("last 5 min"))
        self.assertTrue(temperature_header.rstrip(" │").endswith("last 5 min"))
        self.assertNotIn("1 sec", plain_rendered)
        system_gpu = next(line for line in system.splitlines() if "GPU" in line)
        temperature_gpu = next(
            line for line in temperature.splitlines() if "GPU" in line
        )
        chart = re.compile(r"[▁▂▃▄▅▆▇█]")
        self.assertEqual(
            chart.search(system_gpu).start(),
            chart.search(temperature_gpu).start(),
        )

    def test_status_temperature_history_uses_a_fixed_120_degree_scale(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        rendered = "\n".join(
            status_ui.dashboard_lines(
                {
                    "telemetry": {
                        "system": {
                            "gpu_temp_deci_c": 600,
                            "system_temp_deci_c": 1200,
                        }
                    }
                },
                terminal,
                session_history={
                    "gpu_temp": [60.0] * 24,
                    "cpu_temp": [120.0] * 24,
                },
            )
        )
        temperature = ui.ANSI.sub("", rendered).partition("Temperature")[2]
        rows = {
            fields[0]: fields[-1]
            for line in temperature.splitlines()
            if (fields := line.strip(" │").split())
        }
        self.assertEqual(rows["GPU"], "▅" * 24)
        self.assertEqual(rows["CPU"], "█" * 24)

    def test_runtime_status_renders_startup_as_a_transition(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "activating",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": False,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "node_active": "active",
                "recovery_timer_active": "active",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
                "within_memory_limit": True,
            },
            "container": {
                "state": "running",
                "healthy": False,
                "docker_health": "starting",
                "model_identity": False,
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "0.1.0-rc.3",
            },
            "protection": {
                "phase": "starting",
                "armed": False,
                "trip_latched": False,
            },
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        self.assertEqual(payload["lifecycle"]["state"], "starting")
        self.assertTrue(payload["lifecycle"]["transitional"])

        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("STARTING", rendered)
        self.assertIn("Starting", rendered)
        self.assertIn("Arming", rendered)
        self.assertIn("GATEWAY   STARTING", rendered)
        self.assertIn("RUNTIME   STARTING", rendered)
        self.assertNotIn("UNAVAILABLE", rendered)
        self.assertNotIn("RUNTIME   STOPPED", rendered)
        self.assertNotIn("ATTENTION", rendered)
        self.assertNotIn("Unavailable", rendered)

    def test_runtime_status_labels_a_healthy_candidate_without_false_service_failures(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "inactive",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "node_active": "active",
                "recovery_timer_active": "inactive",
                "runtime_mode": "qualification",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
                "within_memory_limit": True,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "0.1.0-rc.5",
                "qualification_mode": True,
                "capacity": {
                    "max_context_tokens": 262144,
                    "max_active_requests": 8,
                },
            },
            "protection": {"armed": True, "trip_latched": False},
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("SERVING", rendered)
        self.assertIn("sglang", rendered)
        self.assertIn("dgx-spark", rendered)
        self.assertIn("0.1.0-rc.5", rendered)
        self.assertIn("262K context", rendered)
        self.assertNotIn("Services", rendered)
        self.assertNotIn("candidate control plane active", rendered)
        self.assertIn("State        ✓  SERVING", rendered)
        self.assertIn("API          ✓  homeai.local:8000/v1", rendered)
        self.assertRegex(rendered, r"Guard\s+✓")
        self.assertNotIn("Armed", rendered)
        self.assertNotIn("FAILED", rendered)
        self.assertNotIn("unit(s) need attention", rendered)

    def test_runtime_status_keeps_a_saturated_verified_candidate_serving(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "inactive",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "node_active": "active",
                "recovery_timer_active": "inactive",
                "runtime_mode": "qualification",
            },
            "container": {
                "state": "running",
                "healthy": False,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "0.1.0-rc.7",
            },
            "protection": {
                "phase": "armed",
                "armed": True,
                "trip_latched": False,
            },
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        self.assertEqual(payload["lifecycle"]["state"], "ready")
        self.assertTrue(payload["lifecycle"]["runtime_ready"])

        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("State        ✓  SERVING", rendered)
        self.assertIn("RUNTIME   SERVING", rendered)
        self.assertIn("TARGET    READY", rendered)
        self.assertNotIn("STOPPED", rendered)
        self.assertNotIn("WAITING", rendered)

    def test_runtime_status_labels_an_intentionally_stopped_candidate(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "inactive",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": False,
                "node_active": "active",
                "runtime_mode": "qualification",
            },
            "container": {
                "state": "exited",
                "healthy": False,
                "docker_health": "unhealthy",
                "model_identity": False,
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "0.1.0-rc.5",
            },
            "protection": {
                "phase": "disarmed",
                "armed": False,
                "trip_latched": False,
            },
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        self.assertEqual(payload["lifecycle"]["state"], "stopped")
        self.assertEqual(payload["lifecycle"]["reason"], "runtime-stopped")
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("STOPPED", rendered)
        self.assertIn("Disarmed", rendered)
        self.assertIn("intentional stop · no trip", rendered)
        self.assertNotIn("FAILED", rendered)
        self.assertNotIn("Blocked", rendered)

    def test_memory_headroom_is_telemetry_not_a_runtime_state(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "inactive",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "node_active": "active",
                "recovery_timer_active": "inactive",
                "runtime_mode": "qualification",
                "memory_pressure": True,
                "memory_available_bytes": 3_800_000_000,
                "memory_pressure_floor_bytes": 4 * 1024**3,
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "0.1.0-rc.5",
                "capacity": {
                    "max_connections": 128,
                    "max_active_requests": 10,
                    "max_context_tokens": 262144,
                },
            },
            "protection": {"armed": True, "trip_latched": False},
            "telemetry": {"active_requests": 0, "queued_requests": 1},
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        self.assertEqual(payload["lifecycle"]["reason"], "all-components-ready")
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("SERVING", rendered)
        self.assertIn("API          ✓  homeai.local:8000/v1", rendered)
        self.assertRegex(rendered, r"Guard\s+✓")
        self.assertNotIn("Armed", rendered)
        self.assertIn("1 queued", rendered)
        self.assertIn("RUNTIME   SERVING", rendered)
        self.assertIn("GATEWAY   API Ready", rendered)
        performance = rendered.split("Performance", 1)[1].split("System", 1)[0]
        self.assertIn("Requests     0 active · 1 queued", performance)
        self.assertNotIn("PRESSURE", rendered)
        self.assertNotIn("Queuing", rendered)
        self.assertNotIn("GiB available", rendered)
        self.assertNotIn("floor", rendered)
        self.assertNotIn("✓ API ready", rendered)
        self.assertNotIn("✓ Runtime serving", rendered)
        self.assertNotIn("✓ Protection armed", rendered)

    def test_live_runtime_status_refreshes_until_control_c(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "node_active": "active",
                "recovery_timer_active": "active",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "fixture-model",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "1.0.0",
            },
            "protection": {"armed": True, "trip_latched": False},
            "hardware": {
                "accelerator": {"minimum_memory_gib": 32},
                "memory": {"topology": "discrete", "total_gib": 96},
            },
            "lifecycle": {
                "state": "ready",
                "ready_services": 5,
                "total_services": 5,
            },
            "telemetry": {
                "fresh": True,
                "sample_sequence": 1,
                "system": {"gpu_memory_percent": 42},
            },
        }
        with (
            mock.patch.object(ui.sys, "stdout", stream),
            mock.patch.object(ui.time, "sleep", side_effect=KeyboardInterrupt),
        ):
            self.assertEqual(ui.live_runtime_status(lambda: payload), 0)
        rendered = stream.getvalue()
        self.assertIn("\033[?25l", rendered)
        self.assertIn("\033[?25h", rendered)
        self.assertIn("\033[?1049h", rendered)
        self.assertIn("\033[?1049l", rendered)
        self.assertNotIn("\033[H\033[J", rendered)
        self.assertIn("fixture-model", rendered)
        self.assertIn("42%", rendered)

    def test_live_topology_animates_traffic_until_control_c(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "topology_sha256": "a" * 64,
            "nodes": [
                {
                    "member_id": "1" * 32,
                    "name": "homeai",
                    "role": "main",
                    "health": "healthy",
                    "traffic": {"rx_kib_s": 1, "tx_kib_s": 2, "fresh": True},
                },
                {
                    "member_id": "2" * 32,
                    "name": "homeai-node-2",
                    "role": "child",
                    "health": "healthy",
                    "traffic": {"rx_kib_s": 3, "tx_kib_s": 4, "fresh": True},
                },
            ],
            "links": [
                {
                    "nodes": ["1" * 32, "2" * 32],
                    "kind": "connectx",
                    "speed_mbps": 200000,
                    "mtu": 9000,
                    "rdma": True,
                    "age_seconds": 0,
                }
            ],
        }
        with (
            mock.patch.dict(
                os.environ,
                {"TERM": "xterm-256color", "COLUMNS": "80"},
                clear=True,
            ),
            mock.patch.object(topology_ui.sys, "stdout", stream),
            mock.patch.object(topology_ui.time, "sleep", side_effect=KeyboardInterrupt),
        ):
            self.assertEqual(topology_ui.live_topology(lambda: payload), 0)
        rendered = stream.getvalue()
        self.assertIn("\033[?1049h", rendered)
        self.assertIn("\033[?1049l", rendered)
        self.assertNotIn("Direct links", rendered)
        self.assertIn("[ConnectX]", rendered)
        self.assertIn("200 Gbit/s", rendered)
        self.assertIn("RDMA · MTU 9000", rendered)

    def test_topology_link_pulse_uses_the_reduced_speed(self) -> None:
        self.assertEqual(
            topology_ui.PULSE_STEP_SECONDS,
            topology_ui.REFRESH_SECONDS * 2.5,
        )

    def test_topology_node_header_uses_independent_semantic_colors(self) -> None:
        terminal = ui.Terminal(
            FakeStream(tty=True),
            environ={"TERM": "xterm-256color", "COLUMNS": "80"},
        )
        rendered = topology_ui._node_header(
            terminal,
            {
                "member_id": "1" * 32,
                "name": "homeai",
                "role": "main",
                "state": "active",
                "online": True,
            },
            "⠋",
            70,
        )
        self.assertIn(terminal.paint("⠋", ui.BOLD, ui.BLUE), rendered)
        self.assertIn(terminal.paint("homeai", ui.BOLD, ui.LIGHT), rendered)
        self.assertIn(terminal.paint(" · MAIN", ui.DIM), rendered)
        self.assertIn(terminal.paint("ONLINE", ui.BOLD, ui.GREEN), rendered)

    def test_slow_topology_poll_never_blocks_animation_reads(self) -> None:
        started = threading.Event()
        release = threading.Event()

        def slow_snapshot() -> dict[str, int]:
            started.set()
            release.wait(1)
            return {"revision": 2}

        with mock.patch.object(topology_ui, "SNAPSHOT_SECONDS", 0.01):
            worker = topology_ui._TopologySnapshotWorker(
                slow_snapshot,
                {"revision": 1},
            )
            worker.start()
            try:
                self.assertTrue(started.wait(1))
                before = time.monotonic()
                revisions = [worker.current()["revision"] for _ in range(20)]
                elapsed = time.monotonic() - before
                self.assertEqual(revisions, [1] * 20)
                self.assertLess(elapsed, 0.05)
                release.set()
                deadline = time.monotonic() + 1
                while worker.current()["revision"] != 2:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
            finally:
                release.set()
                worker.close()

    def test_topology_omits_redundant_per_node_link_absence(self) -> None:
        node = {
            "member_id": "1" * 32,
            "name": "homeai",
            "role": "main",
            "health": "healthy",
            "models": [],
            "traffic": {"fresh": False},
        }
        one = topology_ui.topology_text(
            {"nodes": [node], "links": []},
            stream=FakeStream(tty=True),
            environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
        )
        self.assertNotIn("verified direct node link", one.casefold())
        two = topology_ui.topology_text(
            {
                "nodes": [
                    node,
                    {
                        **node,
                        "member_id": "2" * 32,
                        "name": "homeai-node-2",
                        "role": "child",
                        "state": "active",
                        "online": True,
                        "connection": "Ethernet",
                    },
                ],
                "links": [],
            },
            stream=FakeStream(tty=True),
            environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
        )
        self.assertNotIn("verified direct node link", two.casefold())
        self.assertIn("homeai-node-2 · ONLINE", two)
        self.assertIn("[Ethernet]", two)
        self.assertNotIn("Direct links", two)

    def test_topology_marks_only_the_affected_model_paused(self) -> None:
        rendered = topology_ui.topology_text(
            {
                "nodes": [
                    {
                        "member_id": "1" * 32,
                        "name": "homeai",
                        "role": "main",
                        "health": "healthy",
                        "models": [
                            {"model": "local-model", "state": "running"},
                            {"model": "distributed-model", "state": "stopped"},
                        ],
                        "traffic": {"fresh": False},
                    }
                ],
                "links": [],
            },
            stream=FakeStream(tty=True),
            environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
        )
        self.assertIn("1 model running", rendered)
        self.assertIn("local-model", rendered)
        self.assertIn("distributed-model · PAUSED", rendered)

    def test_topology_reflects_online_offline_membership_and_transport_changes(self) -> None:
        main = {
            "member_id": "1" * 32,
            "name": "homeai",
            "role": "main",
            "state": "active",
            "online": True,
            "health": "healthy",
            "models": [],
            "traffic": {"fresh": False},
        }
        child = {
            "member_id": "2" * 32,
            "name": "node-2",
            "role": "child",
            "state": "offline",
            "online": False,
            "health": "offline",
            "connection": "Wireless",
            "models": [],
            "traffic": {"fresh": False},
        }
        wireless = topology_ui.topology_text(
            {"nodes": [main, child], "links": []},
            stream=FakeStream(tty=True),
            environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
        )
        self.assertIn("homeai · MAIN · ONLINE", wireless)
        self.assertIn("node-2 · OFFLINE", wireless)
        self.assertIn("[Wireless]", wireless)
        ethernet = topology_ui.topology_text(
            {"nodes": [main, {**child, "connection": "Ethernet"}], "links": []},
            stream=FakeStream(tty=True),
            environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
        )
        self.assertIn("[Ethernet]", ethernet)
        removed = topology_ui.topology_text(
            {"nodes": [main], "links": []},
            stream=FakeStream(tty=True),
            environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
        )
        self.assertIn("1 node", removed)
        self.assertNotIn("node-2", removed)

    def test_topology_uses_one_continuous_sequential_child_trunk(self) -> None:
        main = {
            "member_id": "1" * 32,
            "name": "homeai",
            "role": "main",
            "online": True,
            "models": [],
        }
        children = [
            {
                "member_id": member * 32,
                "name": name,
                "role": "child",
                "online": True,
                "connection": connection,
                "models": [],
            }
            for member, name, connection in (
                ("2", "homeai-node-2", "ConnectX"),
                ("3", "t.inference.server", "Ethernet"),
            )
        ]
        calls: list[tuple[int, int]] = []

        def pulse(
            _terminal: ui.Terminal,
            value: str,
            *,
            frame: int,
            segment: int,
            segments: int = 4,
        ) -> str:
            del frame
            calls.append((segment, segments))
            return value

        with mock.patch.object(topology_ui, "_tree_pulse", side_effect=pulse):
            rendered = topology_ui.topology_text(
                {"nodes": [main, *children], "links": []},
                stream=FakeStream(tty=True),
                environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
            )

        self.assertIn("│ [ConnectX]", rendered)
        self.assertIn("│ [Ethernet]", rendered)
        self.assertIn("│   accelerator unknown", rendered)
        self.assertTrue(all(segments == 8 for _segment, segments in calls))
        self.assertEqual({segment for segment, _segments in calls}, set(range(8)))

    def test_topology_discrete_node_shows_vram_and_system_ram(self) -> None:
        rendered = topology_ui.topology_text(
            {
                "nodes": [
                    {
                        "member_id": "1" * 32,
                        "name": "t.inference.server",
                        "role": "main",
                        "online": True,
                        "accelerator": "NVIDIA GeForce RTX 5090",
                        "memory_topology": "discrete",
                        "accelerator_memory_gib": 32,
                        "system_memory_gib": 96,
                        "models": [],
                    }
                ],
                "links": [],
            },
            stream=FakeStream(tty=True),
            environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
        )
        self.assertIn("NVIDIA GeForce RTX 5090 · 32 G VRAM · 96 G RAM", rendered)

    def test_live_runtime_status_refreshes_request_performance_and_allocation(self) -> None:
        stream = FakeStream(tty=True)
        base = {
            "service": {
                "active": "active",
                "engine_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "model_identity": True,
                "model": "fixture-model",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "1.0.0",
                "capacity": {
                    "max_active_requests": 128,
                    "max_context_tokens": 4096,
                },
            },
            "protection": {"armed": True, "trip_latched": False},
            "lifecycle": {"state": "ready", "runtime_ready": True},
        }
        payloads = [
            {
                **base,
                "telemetry": {
                    "fresh": True,
                    "sample_sequence": 1,
                    "active_requests": 0,
                    "connected_clients": 0,
                    "queued_requests": 0,
                    "rates": {"aggregate_tokens_per_second": 1.0},
                },
            },
            {
                **base,
                "telemetry": {
                    "fresh": True,
                    "sample_sequence": 2,
                    "active_requests": 1,
                    "connected_clients": 1,
                    "queued_requests": 0,
                    "rates": {
                        "aggregate_tokens_per_second": 25.0,
                        "decode_tokens_per_second": 20.0,
                        "prefill_tokens_per_second": 100.0,
                    },
                },
            },
        ]
        with (
            mock.patch.object(ui.sys, "stdout", stream),
            mock.patch.object(
                ui.time, "sleep", side_effect=[None, KeyboardInterrupt]
            ),
        ):
            self.assertEqual(ui.live_runtime_status(lambda: payloads.pop(0)), 0)
        plain = ui.ANSI.sub("", stream.getvalue())
        self.assertIn("1 tok/s", plain)
        self.assertIn("25 tok/s", plain)
        self.assertIn("Allocation   1 / 128", plain)
        self.assertIn("CLIENT    1 connected", plain)

    def test_live_runtime_status_refreshes_without_an_installed_runtime(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "identity": {"display_name": "Home", "role": "main"},
            "endpoint": "http://homeai.local:8000/v1",
            "services": {
                "node_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
            },
            "runtime": None,
        }
        snapshots = mock.Mock(return_value=payload)
        with (
            mock.patch.object(ui.sys, "stdout", stream),
            mock.patch.object(ui.time, "sleep", side_effect=[None, KeyboardInterrupt]),
        ):
            self.assertEqual(ui.live_runtime_status(snapshots), 0)
        rendered = stream.getvalue()
        self.assertEqual(snapshots.call_count, 2)
        self.assertGreaterEqual(rendered.count("Not installed"), 2)
        self.assertIn("\033[?25l", rendered)
        self.assertIn("\033[?25h", rendered)
        self.assertIn("\033[?1049h", rendered)
        self.assertIn("\033[?1049l", rendered)

    def test_live_node_status_keeps_the_detailed_runtime_dashboard(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "identity": {"display_name": "Home", "role": "main"},
            "endpoint": "http://homeai.local:8000/v1",
            "services": {
                "node_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
            },
            "service": {
                "runtime_installed": True,
                "gateway_expected": True,
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": False,
                "gateway_endpoint": "http://homeai.local:8000/v1",
            },
            "container": {
                "state": "running",
                "healthy": True,
                "model_identity": True,
                "model": "qwen3.8-flash-next",
                "engine": "sglang",
                "target": "dgx-spark-connectx-2",
                "runtime_version": "0.1.0-rc.2",
                "capacity": {
                    "max_active_requests": 4,
                    "max_context_tokens": 65536,
                },
            },
            "protection": {"armed": True, "trip_latched": False},
            "lifecycle": {"state": "ready", "runtime_ready": True},
            "telemetry": {
                "fresh": True,
                "sample_sequence": 1,
                "system": {
                    "gpu_memory_percent": 80,
                    "memory_percent": 80,
                },
            },
            "models": [
                {
                    "model": "qwen3.8-flash-next",
                    "state": "running",
                    "replicas": 1,
                }
            ],
        }
        with (
            mock.patch.object(ui.sys, "stdout", stream),
            mock.patch.object(ui.time, "sleep", side_effect=KeyboardInterrupt),
        ):
            self.assertEqual(ui.live_runtime_status(lambda: payload), 0)

        rendered = stream.getvalue()
        self.assertIn("Model", rendered)
        self.assertIn("qwen3.8-flash-next", rendered)
        self.assertIn("sglang", rendered)
        self.assertIn("dgx-spark-connectx-2", rendered)
        self.assertIn("0.1.0-rc.2", rendered)
        self.assertIn("Performance", rendered)
        self.assertNotIn("TOPOLOGY", rendered)
        self.assertNotIn("Not installed", rendered)

    def test_live_runtime_status_transitions_from_node_to_runtime(self) -> None:
        stream = FakeStream(tty=True)
        payloads = [
            {
                "identity": {"display_name": "Home", "role": "main"},
                "endpoint": "http://homeai.local:8000/v1",
                "services": {"node_active": "active"},
                "runtime": None,
            },
            {
                "service": {
                    "active": "active",
                    "engine_active": "active",
                    "gateway_active": "active",
                    "gateway_health": True,
                },
                "container": {
                    "state": "running",
                    "healthy": True,
                    "model": "fixture-model",
                    "engine": "sglang",
                    "target": "dgx-spark",
                    "runtime_version": "1.0.0",
                },
                "protection": {"armed": True, "trip_latched": False},
                "lifecycle": {"state": "ready", "runtime_ready": True},
            },
        ]
        with (
            mock.patch.object(ui.sys, "stdout", stream),
            mock.patch.object(ui.time, "sleep", side_effect=[None, KeyboardInterrupt]),
        ):
            self.assertEqual(ui.live_runtime_status(lambda: payloads.pop(0)), 0)
        rendered = stream.getvalue()
        self.assertIn("Not installed", rendered)
        self.assertIn("fixture-model", rendered)
        self.assertEqual(rendered.count("\033[?1049h"), 1)

    def test_live_runtime_status_keeps_last_good_telemetry_during_reconnect(self) -> None:
        stream = FakeStream(tty=True)
        base = {
            "service": {
                "active": "active",
                "engine_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "node_active": "active",
                "recovery_timer_active": "active",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "fixture-model",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "1.0.0",
            },
            "protection": {"armed": True, "trip_latched": False},
            "lifecycle": {"state": "ready", "runtime_ready": True},
        }
        payloads = [
            {
                **base,
                "telemetry": {
                    "active_requests": 1,
                    "queued_requests": 0,
                    "sample_sequence": 7,
                    "system": {"gpu_percent": 73},
                },
            },
            {**base, "telemetry": None},
        ]
        with (
            mock.patch.object(ui.sys, "stdout", stream),
            mock.patch.object(ui.time, "sleep", side_effect=[None, KeyboardInterrupt]),
        ):
            self.assertEqual(ui.live_runtime_status(lambda: payloads.pop(0)), 0)
        rendered = stream.getvalue()
        self.assertGreaterEqual(rendered.count("73%"), 2)
        self.assertIn("reconnecting · last good", rendered)
        self.assertNotIn("\033[H\033[J", rendered)

    def test_live_runtime_status_keeps_local_sample_when_site_member_is_stale(self) -> None:
        stream = FakeStream(tty=True)
        base = {
            "service": {
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
            },
            "container": {"model": "fixture-model"},
            "lifecycle": {"state": "ready", "runtime_ready": True},
        }
        payloads = [
            {
                **base,
                "telemetry": {
                    "fresh": True,
                    "active_requests": 1,
                    "queued_requests": 0,
                    "sample_sequence": 7,
                    "system": {"gpu_percent": 73},
                },
            },
            {
                **base,
                "telemetry": {
                    "fresh": False,
                    "active_requests": 2,
                    "queued_requests": 1,
                },
            },
        ]
        with (
            mock.patch.object(ui.sys, "stdout", stream),
            mock.patch.object(ui.time, "sleep", side_effect=[None, KeyboardInterrupt]),
        ):
            self.assertEqual(ui.live_runtime_status(lambda: payloads.pop(0)), 0)
        rendered = stream.getvalue()
        self.assertGreaterEqual(rendered.count("73%"), 2)
        self.assertIn("2 active · 1 queued", rendered)
        self.assertIn("reconnecting · last good", rendered)

    def test_runtime_status_labels_missing_telemetry_without_fake_zeroes(self) -> None:
        stream = FakeStream(tty=True)
        ui.runtime_status(
            {
                "service": {
                    "memory_current_bytes": 19 * 1024 * 1024,
                    "memory_limit_bytes": 30 * 1024 * 1024,
                },
                "telemetry": {"display_state": "unavailable"},
            },
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("telemetry unavailable", rendered)
        self.assertRegex(rendered, r"Requests\s+—")
        self.assertRegex(rendered, r"Network\s+—")
        self.assertNotIn("0K/s", rendered)

    def test_runtime_status_does_not_call_a_reachable_api_unavailable(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "runtime_metadata_ready": False,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "node_active": "active",
                "recovery_timer_active": "active",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
                "within_memory_limit": True,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "0.1.0-rc.2",
            },
            "protection": {"armed": True, "trip_latched": False},
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("API          ✓  homeai.local:8000/v1", rendered)
        self.assertIn("ATTENTION", rendered)
        self.assertNotIn("API          Unavailable", rendered)

    def test_node_status_is_branded_without_claiming_a_runtime(self) -> None:
        stream = FakeStream(tty=True)
        ui.node_status(
            {
                "identity": {
                    "display_name": "Home",
                    "role": "main",
                    "machine_id": "homeai",
                },
                "endpoint": "http://homeai.local:8000/v1",
                "services": {
                    "node_active": "active",
                    "gateway_active": "active",
                    "gateway_health": True,
                    "gateway_auth_required": True,
                    "gateway_authenticated": True,
                },
                "runtime": None,
                "updates": [
                    {"kind": "core", "subject": "core", "version": "0.11.0-rc.30"}
                ],
            },
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("LET'S INFER", rendered)
        self.assertIn("ONLINE", rendered)
        self.assertIn("Home", rendered)
        self.assertIn("Not installed", rendered)
        self.assertIn("http://homeai.local:8000/v1", rendered)
        self.assertIn("Update available", rendered)
        self.assertIn("Core 0.11.0-rc.30", rendered)
        self.assertNotIn("\033[", rendered)

    def test_node_status_shows_all_models_nodes_and_verified_links(self) -> None:
        stream = FakeStream(tty=True)
        ui.node_status(
            {
                "identity": {"display_name": "Home", "role": "main"},
                "services": {
                    "node_active": "active",
                    "gateway_active": "active",
                    "gateway_health": True,
                    "gateway_auth_required": True,
                    "gateway_authenticated": True,
                },
                "nodes": [
                    {"state": "active"},
                    {"state": "paused"},
                ],
                "links": [{"verified": True}],
                "models": [
                    {"model": "ling-3-flash", "state": "running", "replicas": 2},
                    {"model": "qwen3.8-27b", "state": "failed", "replicas": 1},
                ],
            },
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("2 node(s)", rendered)
        self.assertIn("1/1 verified", rendered)
        self.assertIn("ling-3-flash · 2 replica(s)", rendered)
        self.assertIn("qwen3.8-27b · 1 replica(s)", rendered)
        self.assertNotIn("Not installed", rendered)

    def test_no_runtime_dashboard_keeps_device_and_monitoring_visible(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "node_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "runtime_installed": False,
                "gateway_expected": True,
                "memory_current_bytes": 18 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
            },
            "container": {},
            "protection": None,
            "runtime": None,
            "node": {
                "display_name": "Home",
                "hostname": "homeai",
                "hardware_name": "NVIDIA DGX Spark",
                "role": "main",
                "uptime_seconds": 3720,
            },
            "telemetry": {
                "fresh": True,
                "system": {
                    "gpu_percent": 73,
                    "memory_percent": 41,
                    "cpu_percent": 8,
                    "disk_percent": 20,
                    "gpu_temp_deci_c": 420,
                    "system_temp_deci_c": 510,
                    "nvme_temp_deci_c": 390,
                },
            },
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("State        ✓  READY", rendered)
        self.assertIn("NVIDIA DGX Spark · homeai · main", rendered)
        self.assertIn("Runtime      Not installed", rendered)
        self.assertIn("RUNTIME   NOT INSTALLED", rendered)
        self.assertIn("Monitoring", rendered)
        self.assertIn("Watchdog", rendered)
        self.assertIn("System", rendered)
        self.assertIn("Temperature", rendered)
        self.assertIn("73%", rendered)
        self.assertNotIn("Scheduler", rendered)
        self.assertNotIn("Tokens", rendered)

    def test_no_runtime_worker_ignores_an_unused_gateway_failure(self) -> None:
        lifecycle = letsinfer.runtime_lifecycle(
            {
                "service": {
                    "active": "active",
                    "node_active": "active",
                    "gateway_active": "failed",
                    "gateway_expected": False,
                    "runtime_installed": False,
                }
            }
        )
        self.assertEqual(lifecycle["state"], "ready")
        self.assertEqual(lifecycle["reason"], "runtime-not-installed")
        self.assertFalse(lifecycle["runtime_ready"])

    def test_no_runtime_darwin_main_does_not_require_watchdog(self) -> None:
        lifecycle = letsinfer.runtime_lifecycle(
            {
                "service": {
                    "active": "inactive",
                    "watchdog_expected": False,
                    "node_active": "active",
                    "gateway_active": "active",
                    "gateway_health": True,
                    "gateway_auth_required": True,
                    "gateway_authenticated": True,
                    "gateway_expected": True,
                    "runtime_installed": False,
                }
            }
        )
        self.assertEqual(lifecycle["state"], "ready")
        self.assertEqual(lifecycle["ready_services"], 2)
        self.assertEqual(lifecycle["total_services"], 2)

    def test_no_runtime_darwin_worker_only_requires_node_agent(self) -> None:
        lifecycle = letsinfer.runtime_lifecycle(
            {
                "service": {
                    "active": "inactive",
                    "watchdog_expected": False,
                    "node_active": "active",
                    "gateway_active": "inactive",
                    "gateway_expected": False,
                    "runtime_installed": False,
                }
            }
        )
        self.assertEqual(lifecycle["state"], "ready")
        self.assertEqual(lifecycle["ready_services"], 1)
        self.assertEqual(lifecycle["total_services"], 1)

    def test_no_runtime_darwin_dashboard_omits_linux_watchdog_rows(self) -> None:
        payload = {
            "service": {
                "active": "inactive",
                "watchdog_expected": False,
                "node_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_endpoint": "http://mac.local:8000/v1",
                "gateway_expected": True,
                "runtime_installed": False,
            },
            "node": {
                "display_name": "Mac",
                "hostname": "mac.local",
                "hardware_name": "Apple silicon",
                "role": "main",
            },
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        stream = FakeStream(tty=True)
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("State        ✓  READY", rendered)
        self.assertIn("Runtime      Not installed", rendered)
        self.assertNotIn("Guard", rendered)
        self.assertNotIn("Watchdog", rendered)

    def test_runtime_status_fits_an_eighty_column_terminal(self) -> None:
        stream = FakeStream(tty=True)
        ui.runtime_status(
            {
                "service": {
                    "active": "active",
                    "engine_active": "active",
                    "gateway_active": "active",
                    "gateway_health": True,
                    "gateway_auth_required": True,
                    "gateway_authenticated": True,
                    "gateway_model_identity": True,
                    "node_active": "active",
                    "recovery_timer_active": "active",
                    "memory_current_bytes": 19 * 1024 * 1024,
                    "memory_limit_bytes": 30 * 1024 * 1024,
                    "within_memory_limit": True,
                },
                "container": {
                    "state": "running",
                    "healthy": True,
                    "docker_health": "healthy",
                    "model_identity": True,
                    "model": "a-model-name-that-is-deliberately-long-enough-to-need-bounding",
                    "engine": "dwarfstar",
                    "target": "a-deliberately-long-target-name-for-terminal-rendering",
                    "runtime_version": "0.11.0-release-candidate-with-a-long-suffix",
                    "capacity": {
                        "max_context_tokens": 557056,
                        "max_active_requests": 128,
                    },
                },
                "protection": {"armed": True, "trip_latched": False},
            },
            stream=stream,
            environ={"TERM": "xterm-256color", "COLUMNS": "80"},
        )
        rendered = stream.getvalue()
        plain = re.sub(r"\x1b\[[0-9;]*m", "", rendered)
        self.assertTrue(all(len(line) <= 80 for line in plain.splitlines()))
        self.assertNotIn("Services", plain)


class HelpTests(unittest.TestCase):
    def test_root_without_a_command_shows_the_action_first_home(self) -> None:
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main([])
        self.assertEqual(result, 0)
        self.assertIn("LET'S INFER", stdout.getvalue())
        self.assertIn("Your inference node is ready", stdout.getvalue())
        self.assertIn("letsinfer model install <model>", stdout.getvalue())
        self.assertNotIn("Usage:", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_tty_help_is_branded_and_colored(self) -> None:
        stream = FakeStream(tty=True)
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True),
            contextlib.redirect_stdout(stream),
        ):
            value = letsinfer.parser().format_help()
        self.assertIn("ϟ", value)
        self.assertIn("LET'S INFER", value)
        self.assertIn("\033[", value)
        self.assertIn("Usage:", value)
        self.assertIn("Commands:", value)
        self.assertIn("letsinfer [-h] COMMAND", value)

    def test_subcommand_help_keeps_function_left_and_brand_right(self) -> None:
        stream = FakeStream(tty=False)
        with contextlib.redirect_stdout(stream):
            root = letsinfer.parser()
            subparsers = next(
                action
                for action in root._actions
                if isinstance(action, argparse._SubParsersAction)
            )
            model = subparsers.choices["model"]
            model_subparsers = next(
                action
                for action in model._actions
                if isinstance(action, argparse._SubParsersAction)
            )
            value = model_subparsers.choices["install"].format_help()
        first = value.splitlines()[0]
        self.assertTrue(first.startswith("Model Install"))
        self.assertTrue(first.endswith(" >  LET'S INFER "))
        self.assertNotIn("\033[", value)
        self.assertIn("Arguments:", value)
        self.assertNotIn("Commands:\n  model", value)

    def test_piped_help_is_branded_but_has_no_terminal_escapes(self) -> None:
        stream = FakeStream(tty=False)
        with contextlib.redirect_stdout(stream):
            value = letsinfer.parser().format_help()
        self.assertIn("LET'S INFER", value)
        self.assertNotIn("\033[", value)
        self.assertIn("Usage:", value)

    def test_root_without_a_tty_keeps_the_plain_help_contract(self) -> None:
        stdout = FakeStream(tty=False)
        with contextlib.redirect_stdout(stdout):
            result = letsinfer.main([])
        self.assertEqual(result, 0)
        self.assertIn("Usage:", stdout.getvalue())
        self.assertNotIn("\033[", stdout.getvalue())


class MainOutputTests(unittest.TestCase):
    def _metadata(self, name: str = "node.info") -> object:
        return argparse.Namespace(
            name=name,
            scope=CommandScope.MAIN,
            mutation=MutationClass.NODE,
            audit=AuditPolicy.NONE,
        )

    def test_json_mode_keeps_stdout_and_stderr_byte_clean(self) -> None:
        payload = {"installation_id": "a" * 64, "state": "ready"}

        def action(_arguments: argparse.Namespace) -> int:
            print(json.dumps(payload, separators=(",", ":")))
            return 0

        arguments = argparse.Namespace(
            command="node",
            action=action,
            action_id="node.info",
            json=True,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata(), None),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["node", "info", "--json"])
        self.assertEqual(result, 0)
        self.assertEqual(
            stdout.getvalue(),
            json.dumps(payload, separators=(",", ":")) + "\n",
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_control_c_is_quiet_cancellation_not_failure(self) -> None:
        def action(_arguments: argparse.Namespace) -> int:
            raise KeyboardInterrupt

        arguments = argparse.Namespace(
            command="node",
            action=action,
            action_id="node.info",
            json=False,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.dict(
                os.environ,
                {"TERM": "xterm-256color", "NO_COLOR": "1"},
                clear=True,
            ),
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata(), None),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["node", "info"])
        self.assertEqual(result, 130)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Cancelled", stderr.getvalue())
        self.assertNotIn("FAILED", stderr.getvalue())

    def test_peer_denial_is_muted_message_not_failure(self) -> None:
        def action(_arguments: argparse.Namespace) -> int:
            raise letsinfer.CommandDenied("homeai-node-2 denied the request")

        arguments = argparse.Namespace(
            command="node",
            action=action,
            action_id="node.add",
            json=False,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.dict(
                os.environ,
                {"TERM": "xterm-256color"},
                clear=True,
            ),
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata("node.add"), None),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["node", "add"])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        rendered = stderr.getvalue()
        self.assertIn(
            ui.DIM + "homeai-node-2 denied the request" + ui.RESET,
            rendered,
        )
        self.assertNotIn("FAILED", rendered)

    def test_control_transport_error_is_bounded_without_traceback(self) -> None:
        def action(_arguments: argparse.Namespace) -> int:
            raise letsinfer.ControlError("membership connection failed: closed")

        arguments = argparse.Namespace(
            command="node",
            action=action,
            action_id="node.add",
            json=False,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stderr = FakeStream(tty=True)
        with (
            mock.patch.dict(
                os.environ,
                {"TERM": "xterm-256color", "NO_COLOR": "1"},
                clear=True,
            ),
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata("node.add"), None),
            ),
            contextlib.redirect_stdout(FakeStream(tty=True)),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["node", "add"])
        rendered = stderr.getvalue()
        self.assertEqual(result, 1)
        self.assertIn("FAILED", rendered)
        self.assertIn("membership connection failed: closed", rendered)
        self.assertNotIn("Traceback", rendered)

    def test_every_bounded_progress_contract_has_activity_language(self) -> None:
        mutations = {
            name
            for name, presentation in UI_CONTRACTS.items()
            if presentation.progress in {ProgressKind.SPINNER, ProgressKind.STEPS}
            and ACTIONS[name].mutation is not MutationClass.INTERNAL
        }
        language = set(letsinfer.ACTION_PROGRESS) | set(letsinfer.READ_PROGRESS)
        self.assertEqual(mutations, language & mutations)
        self.assertNotIn("auth.key.list", mutations)
        self.assertNotIn("auth.key.show", mutations)

    def test_key_secret_and_warning_keep_their_stream_contracts(self) -> None:
        token = "li_once_secret"

        def action(_arguments: argparse.Namespace) -> int:
            print("KEY app id=fixture", file=os.sys.stderr)
            print(token)
            print("This token is shown once. Store it now.", file=os.sys.stderr)
            return 0

        arguments = argparse.Namespace(
            command="auth",
            action=action,
            action_id="auth.key.create",
            json=False,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True),
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata("auth.key.create"), None),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["auth", "key", "create", "app"])
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), f"{token}\n")
        self.assertIn("KEY app id=fixture", stderr.getvalue())
        self.assertIn("This token is shown once. Store it now.", stderr.getvalue())
        self.assertIn("API key created", stderr.getvalue())
        self.assertIn("LET'S INFER", stderr.getvalue())
        self.assertIn("Create API Key", ui.ANSI.sub("", stderr.getvalue()))
        self.assertNotIn(token, stderr.getvalue())

    def test_read_result_is_unadorned_and_non_tty_mutation_is_byte_stable(self) -> None:
        for name, output in (
            ("auth.key.list", "fixture\tactive\n"),
            ("node.pause", "PAUSED fixture\n"),
        ):
            with self.subTest(name=name):
                arguments = argparse.Namespace(
                    command=name.split(".")[0],
                    action=lambda _arguments, value=output: print(value, end="") or 0,
                    action_id=name,
                    json=False,
                    port=1,
                    engine_port=None,
                    tail=0,
                )
                parser = mock.Mock()
                parser.parse_args.return_value = arguments
                stdout = FakeStream(tty=False)
                stderr = FakeStream(tty=False)
                with (
                    mock.patch.object(letsinfer, "parser", return_value=parser),
                    mock.patch.object(
                        letsinfer,
                        "_authorize_command",
                        return_value=(self._metadata(name), None),
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = letsinfer.main([name.split(".")[0]])
                self.assertEqual(result, 0)
                self.assertEqual(stdout.getvalue(), output)
                self.assertEqual(stderr.getvalue(), "")

    def test_human_tty_action_animates_without_changing_its_result(self) -> None:
        def action(_arguments: argparse.Namespace) -> int:
            time.sleep(0.22)
            print("INSTALLED RUNTIME fixture")
            return 0

        arguments = argparse.Namespace(
            command="model",
            action=action,
            action_id="model.install",
            json=False,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True),
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata("model.install"), None),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["model", "install", "fixture"])
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "INSTALLED RUNTIME fixture\n")
        self.assertIn("Installing models", stderr.getvalue())
        header = ui.ANSI.sub("", stderr.getvalue()).splitlines()[0]
        self.assertIn("Install Model", header)
        self.assertIn("LET'S INFER", header)
        self.assertIn("Models installed", stderr.getvalue())
        self.assertIn(ui.CLEAR_LINE, stderr.getvalue())

    def test_update_leaves_the_installer_as_the_only_interactive_progress_owner(self) -> None:
        arguments = argparse.Namespace(
            command="update",
            action=lambda _arguments: 0,
            action_id="update.core",
            json=False,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        progress = mock.Mock(return_value=contextlib.nullcontext())
        with (
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata("update.core"), None),
            ),
            mock.patch.object(ui, "progress", progress),
            mock.patch.object(
                ui, "protect_stdout", return_value=contextlib.nullcontext()
            ),
        ):
            self.assertEqual(letsinfer.main(["update", "core"]), 0)
        progress.assert_not_called()

    def test_non_tty_error_contract_is_unchanged(self) -> None:
        arguments = argparse.Namespace(
            command="node",
            action=lambda _arguments: 0,
            action_id="node.info",
            json=False,
            port=0,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stderr = FakeStream(tty=False)
        with (
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata(), None),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["node", "info"])
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "FATAL: port must be between 1 and 65535\n")

    def test_tty_error_uses_the_bounded_failure_state(self) -> None:
        stream = FakeStream(tty=True)
        with mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True):
            ui.fatal("runtime is unavailable", stream=stream)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", stream.getvalue())
        self.assertIn("FAILED", plain)
        self.assertIn("runtime is unavailable", plain)
        self.assertNotIn("FATAL:", plain)
        self.assertIn("\033[38;2;226;56;56m", stream.getvalue())

    def test_non_tty_parser_snapshots_help_width_without_terminal_syscalls(self) -> None:
        previous_key = ui.HelpFormatter._width_key
        previous_width = ui.HelpFormatter._cached_width
        stream = FakeStream(tty=False)
        try:
            ui.HelpFormatter._width_key = None
            with (
                contextlib.redirect_stdout(stream),
                mock.patch.object(os, "get_terminal_size", wraps=os.get_terminal_size) as size,
            ):
                letsinfer.parser()
            self.assertEqual(size.call_count, 0)
        finally:
            ui.HelpFormatter._width_key = previous_key
            ui.HelpFormatter._cached_width = previous_width


if __name__ == "__main__":
    unittest.main()
