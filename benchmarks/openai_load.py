#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run crash-safe, resumable OpenAI-v1 load and soak qualification.

The workload and evidence contract are engine-neutral. Engine-specific cache,
scheduler, and speculative-decoding claims still require separate supplements.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import ssl
import stat
import sys
import threading
import time
from typing import Any


BENCHMARK_DIR = pathlib.Path(__file__).resolve().parent
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))
import openai_matrix as common  # pylint: disable=wrong-import-position


class LoadError(common.QualificationError):
    """The load/soak contract was invalid or did not complete safely."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--release-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--plan", type=pathlib.Path, required=True)
    parser.add_argument("--fixture-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--output-directory", type=pathlib.Path, required=True)
    parser.add_argument("--api-key-file", type=pathlib.Path, required=True)
    parser.add_argument("--ca-cert-file", type=pathlib.Path, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--measured-commit", required=True)
    parser.add_argument("--server-command-file", type=pathlib.Path, required=True)
    parser.add_argument("--source-attestation", type=pathlib.Path)
    parser.add_argument(
        "--watchdog-trip-file",
        type=pathlib.Path,
        default=pathlib.Path.home()
        / ".local/share/letsinfer/watchdog/data/protection-trip.json",
        help="latched Watchdog protection-trip file",
    )
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument(
        "--task",
        action="append",
        default=[],
        help=(
            "run only this named task from the committed plan; repeat to select "
            "multiple tasks"
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="resume the exact interrupted run without replacing completed waves",
    )
    return parser.parse_args()


def select_tasks(plan: dict[str, Any], names: list[str]) -> dict[str, Any]:
    """Select complete plan tasks without changing their committed order."""
    if not names:
        return plan
    if len(names) != len(set(names)):
        raise LoadError("--task names must not be repeated")
    available = {task["name"] for task in plan["tasks"]}
    unknown = sorted(set(names) - available)
    if unknown:
        raise LoadError(f"unknown --task name(s): {', '.join(unknown)}")
    selected = set(names)
    return {**plan, "tasks": [task for task in plan["tasks"] if task["name"] in selected]}


def _nonnegative_int(mapping: dict[str, Any], key: str, where: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise LoadError(f"{where}.{key} must be a non-negative integer")
    return value


def load_plan(
    path: pathlib.Path,
    *,
    fixture_path: pathlib.Path,
    engine_name: str,
    model_id: str,
    model_revision: str,
) -> tuple[dict[str, Any], pathlib.Path, dict[str, dict[str, Any]], dict[str, Any]]:
    plan = common.read_json_object(path, "load plan")
    if type(plan.get("schema_version")) is not int or plan.get("schema_version") != 1:
        raise LoadError("load plan schema_version must be 1")
    if "fixture_manifest" in plan:
        raise LoadError(
            "load plan must not bind an engine fixture; use --fixture-manifest"
        )
    if fixture_path.is_symlink() or not fixture_path.is_file():
        raise LoadError("fixture manifest must be a regular non-symlink file")
    _, cells, tokenizer = common.load_fixture_contract(
        fixture_path,
        engine_name=engine_name,
        model_id=model_id,
        model_revision=model_revision,
    )
    cells_by_name = {cell["name"]: cell for cell in cells}
    sample_interval = plan.get("sample_interval_seconds", 5)
    if (
        not isinstance(sample_interval, int)
        or isinstance(sample_interval, bool)
        or not 1 <= sample_interval <= 60
    ):
        raise LoadError("load plan.sample_interval_seconds must be from 1 through 60")
    cache_requirements = plan.get(
        "cache_requirements",
        {"warmup": "unconstrained", "measured": "unconstrained"},
    )
    if not isinstance(cache_requirements, dict) or set(cache_requirements) - {
        "warmup",
        "measured",
        "minimum_hit_tokens",
    }:
        raise LoadError("load plan.cache_requirements has invalid fields")
    cache_requirements = dict(cache_requirements)
    for phase in ("warmup", "measured"):
        mode = cache_requirements.get(phase, "unconstrained")
        if mode not in {"unconstrained", "miss", "hit"}:
            raise LoadError(
                f"load plan.cache_requirements.{phase} must be "
                "unconstrained, miss, or hit"
            )
        cache_requirements[phase] = mode
    minimum_hit_tokens = cache_requirements.get("minimum_hit_tokens", 1)
    if (
        not isinstance(minimum_hit_tokens, int)
        or isinstance(minimum_hit_tokens, bool)
        or minimum_hit_tokens <= 0
    ):
        raise LoadError(
            "load plan.cache_requirements.minimum_hit_tokens must be positive"
        )
    cache_requirements["minimum_hit_tokens"] = minimum_hit_tokens
    rows = plan.get("tasks")
    if not isinstance(rows, list) or not rows:
        raise LoadError("load plan.tasks must be a non-empty array")
    tasks: list[dict[str, Any]] = []
    names: set[str] = set()
    allocated_cells: set[str] = set()
    for index, row in enumerate(rows):
        where = f"load plan.tasks[{index}]"
        if not isinstance(row, dict):
            raise LoadError(f"{where} must be an object")
        name = common.require_string(row, "name", where)
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name):
            raise LoadError(f"{where}.name must be a safe lowercase evidence name")
        if name in names:
            raise LoadError(f"duplicate task name: {name}")
        names.add(name)
        cell_name = common.require_string(row, "cell", where)
        if cell_name not in cells_by_name:
            raise LoadError(f"{where}.cell names unknown cell {cell_name!r}")
        if cell_name in allocated_cells:
            raise LoadError(
                f"load tasks must use disjoint cells; repeated cell: {cell_name}"
            )
        allocated_cells.add(cell_name)
        warmup_waves = _nonnegative_int(row, "warmup_waves", where)
        measured_waves = common.require_positive_int(row, "measured_waves", where)
        cooldown = _nonnegative_int(row, "cooldown_seconds", where)
        equality = row.get("require_output_equality")
        if not isinstance(equality, bool):
            raise LoadError(f"{where}.require_output_equality must be boolean")
        tasks.append(
            {
                "name": name,
                "cell": cell_name,
                "warmup_waves": warmup_waves,
                "measured_waves": measured_waves,
                "cooldown_seconds": cooldown,
                "require_output_equality": equality,
                "streams": len(cells_by_name[cell_name]["fixtures"]),
            }
        )
    public = {
        "schema_version": 1,
        "sample_interval_seconds": sample_interval,
        "cache_requirements": cache_requirements,
        "tasks": tasks,
    }
    return public, fixture_path, cells_by_name, tokenizer


def expected_waves(plan: dict[str, Any]) -> list[dict[str, Any]]:
    waves: list[dict[str, Any]] = []
    for task in plan["tasks"]:
        for phase, count in (
            ("warmup", task["warmup_waves"]),
            ("measured", task["measured_waves"]),
        ):
            for index in range(1, count + 1):
                relative = f"waves/{task['name']}/{phase}-{index:04d}.json"
                waves.append(
                    {
                        "task": task["name"],
                        "cell": task["cell"],
                        "streams": task["streams"],
                        "phase": phase,
                        "index": index,
                        "relative_path": relative,
                    }
                )
    return waves


def validate_workload_capacity(
    manifest: dict[str, Any],
    plan: dict[str, Any],
    cells: dict[str, dict[str, Any]],
) -> dict[str, int]:
    try:
        connection_capacity = manifest["serving"]["max_connections"]
        active_capacity = manifest["serving"]["max_active_requests"]
        context_capacity = manifest["serving"]["max_context_tokens"]
    except (KeyError, TypeError) as error:
        raise LoadError("release omits its serving capacity") from error
    if (
        not isinstance(connection_capacity, int)
        or isinstance(connection_capacity, bool)
        or connection_capacity <= 0
        or not isinstance(active_capacity, int)
        or isinstance(active_capacity, bool)
        or active_capacity <= 0
        or not isinstance(context_capacity, int)
        or isinstance(context_capacity, bool)
        or context_capacity <= 0
    ):
        raise LoadError("release has invalid engine workload capacity")
    for task in plan["tasks"]:
        cell = cells[task["cell"]]
        if task["streams"] > connection_capacity:
            raise LoadError(
                f"task {task['name']} requests {task['streams']} streams, but "
                f"the serving contract admits {connection_capacity} connections"
            )
        for fixture in cell["fixtures"]:
            demand = fixture["expected_prompt_tokens"] + cell["max_tokens"]
            if demand > context_capacity:
                raise LoadError(
                    f"task {task['name']} fixture {fixture['name']} requires "
                    f"{demand} tokens, above the {context_capacity}-token context"
                )
    return {
        "max_connections": connection_capacity,
        "max_active_requests": active_capacity,
        "max_context_tokens": context_capacity,
    }


def run_identity(inputs: dict[str, Any]) -> str:
    canonical = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    return common.sha256_bytes(canonical)


def result_envelope(
    inputs: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    """Build load-v3 evidence without allowing input schema metadata to win."""
    return {
        **inputs,
        **payload,
        "schema_version": 1,
        "contract": "letsinfer-openai-v1-load-v1",
    }


def initialize_state(
    output: pathlib.Path,
    *,
    inputs: dict[str, Any],
    plan: dict[str, Any],
    resume: bool,
) -> dict[str, Any]:
    identity = run_identity(inputs)
    state_path = output / "state.json"
    if output.exists():
        if not resume:
            raise LoadError(f"refusing existing output directory: {output}")
        if output.is_symlink() or not output.is_dir():
            raise LoadError("output directory must be a real directory, not a symlink")
        for path, name in (
            (output / "inputs.json", "saved run inputs"),
            (output / "plan.json", "saved load plan"),
            (state_path, "run state"),
        ):
            if path.is_symlink() or not path.is_file():
                raise LoadError(f"{name} must be a regular non-symlink file")
        saved_inputs = common.read_json_object(output / "inputs.json", "saved run inputs")
        saved_plan = common.read_json_object(output / "plan.json", "saved load plan")
        if saved_inputs != inputs or saved_plan != plan:
            raise LoadError("saved inputs or plan do not match the exact requested run")
        state = common.read_json_object(state_path, "run state")
        if (
            type(state.get("schema_version")) is not int
            or state.get("schema_version") != 1
            or state.get("run_identity") != identity
        ):
            raise LoadError("existing state does not match the exact requested run")
        if state.get("status") not in {"pending", "running", "failed", "complete"}:
            raise LoadError("run state has an invalid status")
        if not isinstance(state.get("tasks"), dict) or set(state["tasks"]) != {
            task["name"] for task in plan["tasks"]
        }:
            raise LoadError("run state tasks do not match the exact requested run")
        if (
            not isinstance(state.get("resume_count"), int)
            or isinstance(state.get("resume_count"), bool)
            or state["resume_count"] < 0
        ):
            raise LoadError("run state has an invalid resume count")
        history = state.setdefault("failure_history", [])
        if not isinstance(history, list):
            raise LoadError("run state failure_history must be an array")
        failures = output / "failures"
        if failures.exists() and (failures.is_symlink() or not failures.is_dir()):
            raise LoadError("failure evidence path must be a real directory")
        failures.mkdir(exist_ok=True)
        attempts = output / "attempts"
        if attempts.exists() and (attempts.is_symlink() or not attempts.is_dir()):
            raise LoadError("attempt evidence path must be a real directory")
        attempts.mkdir(exist_ok=True)
        return state
    if resume:
        raise LoadError(f"cannot resume missing output directory: {output}")
    (output / "waves").mkdir(parents=True)
    (output / "failures").mkdir()
    (output / "attempts").mkdir()
    common.write_json_atomic(output / "inputs.json", inputs)
    common.write_json_atomic(output / "plan.json", plan)
    state = {
        "schema_version": 1,
        "run_identity": identity,
        "status": "pending",
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "completed_waves": [],
        "tasks": {task["name"]: "pending" for task in plan["tasks"]},
        "resume_count": 0,
        "failure_history": [],
    }
    common.write_json_atomic(state_path, state)
    return state


def save_state(output: pathlib.Path, state: dict[str, Any]) -> None:
    state["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    common.write_json_atomic(output / "state.json", state)


def reconcile_waves(
    output: pathlib.Path,
    state: dict[str, Any],
    expected: list[dict[str, Any]],
) -> None:
    def validate_document(relative: str, document: dict[str, Any]) -> None:
        wave = expected_by_path[relative]
        expected_values = {
            "task": wave["task"],
            "phase": wave["phase"],
            "wave_index": wave["index"],
        }
        if any(document.get(key) != value for key, value in expected_values.items()):
            raise LoadError(f"wave identity mismatch: {relative}")
        result = document.get("result")
        if not isinstance(result, dict):
            raise LoadError(f"wave result is missing or invalid: {relative}")
        if (
            result.get("cell") != wave["cell"]
            or result.get("phase") != wave["phase"]
            or result.get("streams") != wave["streams"]
        ):
            raise LoadError(f"wave result contract mismatch: {relative}")
        requests = result.get("requests")
        if not isinstance(requests, list) or len(requests) != wave["streams"]:
            raise LoadError(f"wave request count mismatch: {relative}")

    expected_by_path = {wave["relative_path"]: wave for wave in expected}
    completed: dict[str, dict[str, Any]] = {}
    rows = state.get("completed_waves")
    if not isinstance(rows, list):
        raise LoadError("run state completed_waves must be an array")
    for row in rows:
        if not isinstance(row, dict):
            raise LoadError("run state has an invalid completed wave")
        relative = row.get("relative_path")
        if relative not in expected_by_path or relative in completed:
            raise LoadError("run state has an unknown or duplicate completed wave")
        path = output / relative
        if not path.is_file() or path.is_symlink():
            raise LoadError(f"completed wave is missing or unsafe: {relative}")
        if common.sha256_file(path) != row.get("sha256"):
            raise LoadError(f"completed wave hash mismatch: {relative}")
        validate_document(relative, common.read_json_object(path, "completed wave"))
        completed[relative] = row
    observed = {
        str(path.relative_to(output))
        for path in (output / "waves").glob("*/*.json")
        if path.is_file()
    }
    unknown = sorted(observed - expected_by_path.keys())
    if unknown:
        raise LoadError(f"unexpected wave evidence exists: {', '.join(unknown)}")
    recovered = False
    for relative in sorted(observed - completed.keys()):
        document = common.read_json_object(output / relative, "orphan wave")
        validate_document(relative, document)
        state["completed_waves"].append(
            {"relative_path": relative, "sha256": common.sha256_file(output / relative)}
        )
        recovered = True
    if recovered:
        save_state(output, state)


def reconcile_results(output: pathlib.Path, state: dict[str, Any]) -> bool:
    """Finish an atomic result write interrupted before state finalization."""
    results_path = output / "results.json"
    checksum_path = output / "results.sha256"
    if not results_path.exists() and not checksum_path.exists():
        if state.get("status") == "complete":
            raise LoadError("complete run state has no result evidence")
        return False
    if results_path.is_symlink() or not results_path.is_file():
        raise LoadError("result evidence must be a regular non-symlink file")
    document = common.read_json_object(results_path, "load results")
    if (
        document.get("run_identity") != state["run_identity"]
        or document.get("qualification_passed") is not True
    ):
        raise LoadError("result evidence does not match the completed run")
    results_sha = common.sha256_file(results_path)
    expected_line = f"{results_sha}  results.json\n"
    if checksum_path.exists():
        if checksum_path.is_symlink() or not checksum_path.is_file():
            raise LoadError("result checksum must be a regular non-symlink file")
        if checksum_path.read_text(encoding="utf-8") != expected_line:
            raise LoadError("result checksum does not match result evidence")
    else:
        common.write_text_atomic(checksum_path, expected_line)
    recorded_sha = state.get("results_sha256")
    if recorded_sha is not None and recorded_sha != results_sha:
        raise LoadError("run state result hash does not match result evidence")
    state["status"] = "complete"
    state["results_sha256"] = results_sha
    state.pop("error", None)
    save_state(output, state)
    return True


def reconcile_failures(output: pathlib.Path, state: dict[str, Any]) -> None:
    failures = output / "failures"
    recorded: dict[str, dict[str, Any]] = {}
    for row in state["failure_history"]:
        if not isinstance(row, dict):
            raise LoadError("run state has invalid failure evidence")
        relative = row.get("relative_path")
        if (
            not isinstance(relative, str)
            or not re.fullmatch(r"failures/attempt-[0-9]{4}\.json", relative)
            or relative in recorded
        ):
            raise LoadError("run state has unknown or duplicate failure evidence")
        path = output / relative
        if path.is_symlink() or not path.is_file():
            raise LoadError(f"failure evidence is missing or unsafe: {relative}")
        if common.sha256_file(path) != row.get("sha256"):
            raise LoadError(f"failure evidence hash mismatch: {relative}")
        recorded[relative] = row
    observed = {
        str(path.relative_to(output))
        for path in failures.glob("attempt-*.json")
        if path.is_file() and not path.is_symlink()
    }
    recovered = False
    for relative in sorted(observed - recorded.keys()):
        document = common.read_json_object(output / relative, "orphan failure evidence")
        match = re.fullmatch(r"failures/attempt-([0-9]{4})\.json", relative)
        if (
            match is None
            or document.get("run_identity") != state["run_identity"]
            or document.get("attempt") != int(match.group(1))
        ):
            raise LoadError(f"orphan failure evidence identity mismatch: {relative}")
        state["failure_history"].append(
            {"relative_path": relative, "sha256": common.sha256_file(output / relative)}
        )
        recovered = True
    unsafe_or_unknown = {
        str(path.relative_to(output))
        for path in failures.iterdir()
        if path.name not in {pathlib.Path(item).name for item in observed}
    }
    if unsafe_or_unknown:
        raise LoadError(
            "unexpected failure evidence exists: " + ", ".join(sorted(unsafe_or_unknown))
        )
    if recovered:
        save_state(output, state)


def record_failure(
    output: pathlib.Path, state: dict[str, Any], error: BaseException
) -> None:
    attempt = state["resume_count"]
    relative = f"failures/attempt-{attempt:04d}.json"
    path = output / relative
    if path.exists():
        raise LoadError(f"refusing to overwrite failure evidence: {relative}")
    common.write_json_atomic(
        path,
        {
            "schema_version": 1,
            "run_identity": state["run_identity"],
            "attempt": attempt,
            "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "error_type": type(error).__name__,
            "error": str(error),
        },
    )
    state["failure_history"].append(
        {"relative_path": relative, "sha256": common.sha256_file(path)}
    )
    save_state(output, state)


def collect_attempt_evidence(output: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    attempts = output / "attempts"
    for directory in sorted(attempts.iterdir()):
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or not re.fullmatch(r"attempt-[0-9]{4}", directory.name)
        ):
            raise LoadError(f"unexpected attempt evidence path: {directory.name}")
        files: list[dict[str, str]] = []
        for path in sorted(directory.iterdir()):
            if path.is_symlink() or not path.is_file():
                raise LoadError(f"unsafe attempt evidence path: {path}")
            if path.name not in {
                "container-before.json",
                "container-after.json",
                "telemetry.jsonl",
            }:
                raise LoadError(f"unexpected attempt evidence file: {path}")
            files.append(
                {
                    "relative_path": str(path.relative_to(output)),
                    "sha256": common.sha256_file(path),
                }
            )
        rows.append({"attempt": int(directory.name[-4:]), "files": files})
    return rows


def _meminfo_summary() -> dict[str, int]:
    wanted = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    result: dict[str, int] = {}
    for line in pathlib.Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        key, _, rest = line.partition(":")
        if key in wanted:
            fields = rest.split()
            if fields and fields[0].isdigit():
                result[f"{key}_kib"] = int(fields[0])
    return result


def _read_text(path: pathlib.Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None


def _cpu_summary() -> dict[str, Any]:
    stat = _read_text(pathlib.Path("/proc/stat")) or ""
    cpu_line = next((line for line in stat.splitlines() if line.startswith("cpu ")), "")
    fields = cpu_line.split()
    counters = [int(value) for value in fields[1:] if value.isdigit()]
    loadavg = (_read_text(pathlib.Path("/proc/loadavg")) or "").split()
    return {
        "jiffies": counters,
        "load_1m": float(loadavg[0]) if len(loadavg) >= 1 else None,
        "load_5m": float(loadavg[1]) if len(loadavg) >= 2 else None,
        "load_15m": float(loadavg[2]) if len(loadavg) >= 3 else None,
    }


def _thermal_summary() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for zone in sorted(pathlib.Path("/sys/class/thermal").glob("thermal_zone*")):
        raw = _read_text(zone / "temp")
        if raw is None or not re.fullmatch(r"-?[0-9]+", raw):
            continue
        rows.append(
            {
                "sensor": zone.name,
                "type": _read_text(zone / "type"),
                "temperature_millicelsius": int(raw),
            }
        )
    for sensor in sorted(pathlib.Path("/sys/class/nvme").glob("nvme*/device/hwmon/hwmon*")):
        for path in sorted(sensor.glob("temp*_input")):
            raw = _read_text(path)
            if raw is None or not re.fullmatch(r"-?[0-9]+", raw):
                continue
            stem = path.name.removesuffix("_input")
            rows.append(
                {
                    "sensor": str(path),
                    "type": _read_text(sensor / f"{stem}_label") or "nvme",
                    "temperature_millicelsius": int(raw),
                }
            )
    return rows


def _nvme_summary() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for device in sorted(pathlib.Path("/sys/block").glob("nvme*n*")):
        fields = (_read_text(device / "stat") or "").split()
        if len(fields) < 11 or not all(value.isdigit() for value in fields[:11]):
            continue
        values = [int(value) for value in fields]
        rows.append(
            {
                "device": device.name,
                "reads_completed": values[0],
                "sectors_read": values[2],
                "read_milliseconds": values[3],
                "writes_completed": values[4],
                "sectors_written": values[6],
                "write_milliseconds": values[7],
                "io_in_progress": values[8],
                "io_milliseconds": values[9],
                "weighted_io_milliseconds": values[10],
            }
        )
    return rows


def telemetry_sample(container: str) -> dict[str, Any]:
    captured = dt.datetime.now(dt.timezone.utc).isoformat()
    inspection = common.docker_inspect(container)
    state = inspection.get("State") or {}
    nvidia = common.run_command(
        [
            "nvidia-smi",
            "--query-gpu=uuid,temperature.gpu,power.draw,utilization.gpu,utilization.memory,memory.used,memory.total,memory.free",
            "--format=csv,noheader,nounits",
        ]
    )
    if nvidia.returncode != 0 or not nvidia.stdout.strip():
        raise LoadError("nvidia-smi telemetry failed during load")
    watchdog = common.run_command(
        [
            "systemctl",
            "--user",
            "show",
            "letsinfer.service",
            "--property=ActiveState,MainPID,MemoryCurrent,MemoryPeak",
        ]
    )
    docker_stats = common.run_command(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}", container]
    )
    docker_payload: dict[str, Any] | None = None
    if docker_stats.returncode == 0 and docker_stats.stdout.strip():
        try:
            decoded = json.loads(docker_stats.stdout)
            if isinstance(decoded, dict):
                docker_payload = decoded
        except json.JSONDecodeError:
            docker_payload = None
    return {
        "captured_at": captured,
        "host": _meminfo_summary(),
        "cpu": _cpu_summary(),
        "thermals": _thermal_summary(),
        "nvme": _nvme_summary(),
        "gpu_csv": nvidia.stdout.strip().splitlines(),
        "docker_stats": {
            "exit_code": docker_stats.returncode,
            "values": docker_payload,
            "stderr": docker_stats.stderr.strip(),
        },
        "container": {
            "id": inspection.get("Id"),
            "running": state.get("Running"),
            "status": state.get("Status"),
            "health": (state.get("Health") or {}).get("Status"),
            "oom_killed": state.get("OOMKilled"),
            "restart_count": inspection.get("RestartCount"),
            "started_at": state.get("StartedAt"),
        },
        "watchdog_systemd": {
            "exit_code": watchdog.returncode,
            "properties": watchdog.stdout.strip().splitlines(),
            "stderr": watchdog.stderr.strip(),
        },
    }


def protection_trip(path: pathlib.Path) -> dict[str, Any] | None:
    """Return a validated latched Watchdog trip, if one exists."""
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise LoadError(f"unsafe Watchdog protection-trip path: {path}")
    details = path.stat()
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise LoadError(f"Watchdog protection trip must be private and user-owned: {path}")
    document = common.read_json_object(path, "Watchdog protection trip")
    if (
        type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
        or document.get("action") not in {"stop", "kill"}
        or not isinstance(document.get("reason"), str)
        or not document["reason"]
    ):
        raise LoadError(f"invalid Watchdog protection trip: {path}")
    return document


class TelemetryMonitor:
    def __init__(
        self,
        path: pathlib.Path,
        container: str,
        interval: int,
        runtime_min_available_gib: int,
        protection_trip_path: pathlib.Path,
    ) -> None:
        self.path = path
        self.container = container
        self.interval = interval
        self.runtime_min_available_gib = runtime_min_available_gib
        self.protection_trip_path = protection_trip_path
        self.stop_event = threading.Event()
        self.fault_event = threading.Event()
        self.errors: list[str] = []
        self.thread = threading.Thread(target=self._run, name="letsinfer-load-monitor")
        self.thread_started = False

    def _append(self, value: dict[str, Any]) -> None:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())

    def _record_error(self, message: str, key: str = "telemetry_error") -> None:
        self.errors.append(message)
        self.fault_event.set()
        try:
            self._append(
                {
                    "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    key: message,
                }
            )
        except Exception as append_error:  # the in-memory error still fails the run
            self.errors.append(
                f"telemetry evidence write failed: {type(append_error).__name__}: "
                f"{append_error}"
            )

    def _stop_for_safety(self, message: str) -> bool:
        self._record_error(message, "safety_stop")
        for command in (
            ["docker", "update", "--restart", "no", self.container],
            ["docker", "stop", "--time", "10", self.container],
        ):
            result = common.run_command(command)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip()
                self._record_error(
                    f"safety command failed ({' '.join(command)}): {detail}"
                )
        return False

    def _capture_once(self) -> bool:
        try:
            trip = protection_trip(self.protection_trip_path)
            if trip is not None:
                return self._stop_for_safety(
                    "Watchdog protection trip latched: "
                    f"action={trip['action']} reason={trip['reason']}"
                )
            sample = telemetry_sample(self.container)
            self._append(sample)
            container = sample.get("container")
            if isinstance(container, dict) and (
                container.get("running") is not True
                or container.get("status") != "running"
                or container.get("health") != "healthy"
                or container.get("oom_killed") is True
            ):
                self._record_error(
                    "runtime container became unhealthy during load: "
                    f"running={container.get('running')} "
                    f"status={container.get('status')} "
                    f"health={container.get('health')} "
                    f"oom_killed={container.get('oom_killed')}",
                    "container_fault",
                )
                return False
            available_kib = sample["host"].get("MemAvailable_kib")
            if (
                isinstance(available_kib, int)
                and available_kib < self.runtime_min_available_gib * 1048576
            ):
                message = (
                    "runtime unified-memory reserve fell below "
                    f"{self.runtime_min_available_gib} GiB"
                )
                return self._stop_for_safety(message)
            return True
        except Exception as error:  # preserve failure evidence, then fail the run
            self._record_error(f"{type(error).__name__}: {error}")
            return False

    def _run(self) -> None:
        while not self.stop_event.wait(self.interval):
            if not self._capture_once():
                return

    def __enter__(self) -> "TelemetryMonitor":
        if self._capture_once():
            self.thread.start()
            self.thread_started = True
        return self

    def __exit__(self, *_: object) -> None:
        self.stop_event.set()
        if self.thread_started:
            self.thread.join(timeout=self.interval + 5)
        if self.thread_started and self.thread.is_alive():
            self.errors.append("telemetry monitor did not stop")
        try:
            trip = protection_trip(self.protection_trip_path)
            if trip is not None:
                message = (
                    "Watchdog protection trip latched: "
                    f"action={trip['action']} reason={trip['reason']}"
                )
                if message not in self.errors:
                    self._record_error(message, "safety_stop")
        except Exception as error:
            self._record_error(f"{type(error).__name__}: {error}")


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def metric_summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "min": min(values) if values else None,
        "p50": percentile(values, 0.50),
        "p90": percentile(values, 0.90),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values) if values else None,
        "mean": sum(values) / len(values) if values else None,
    }


def phase_summary(waves: list[dict[str, Any]]) -> dict[str, Any]:
    requests = [request for wave in waves for request in wave["result"]["requests"]]

    def floats(key: str) -> list[float]:
        return [
            float(row[key])
            for row in requests
            if isinstance(row.get(key), (int, float))
            and not isinstance(row.get(key), bool)
        ]

    return {
        "waves": len(waves),
        "requests": len(requests),
        "completion_tokens": sum(row["completion_tokens"] for row in requests),
        "cached_prompt_tokens": metric_summary(floats("cached_prompt_tokens")),
        "cache_write_tokens": metric_summary(floats("cache_write_tokens")),
        "ttft_ms": metric_summary(floats("ttft_ms")),
        "wall_ms": metric_summary(floats("wall_ms")),
        "decode_tokens_per_second": metric_summary(
            floats("decode_tokens_per_second")
        ),
        "batch_wall_ms": metric_summary(
            [float(wave["result"]["batch_wall_ms"]) for wave in waves]
        ),
        "job_completion_tokens_per_second": metric_summary(
            [
                float(wave["result"]["job_completion_tokens_per_second"])
                for wave in waves
            ]
        ),
    }


def enforce_cache_requirement(
    task_name: str,
    phase: str,
    mode: str,
    waves: list[dict[str, Any]],
    minimum_hit_tokens: int,
) -> None:
    if mode == "unconstrained":
        return
    requests = [request for wave in waves for request in wave["result"]["requests"]]
    if not requests:
        raise LoadError(
            f"task {task_name} requires a {phase} cache {mode}, but has no waves"
        )
    for request in requests:
        cached = request.get("cached_prompt_tokens")
        if not isinstance(cached, int) or isinstance(cached, bool):
            raise LoadError(
                f"task {task_name} {phase} lacks engine-reported cached prompt tokens"
            )
        if mode == "miss" and cached != 0:
            raise LoadError(
                f"task {task_name} {phase} expected a cache miss, reported {cached} tokens"
            )
        if mode == "hit" and cached < minimum_hit_tokens:
            raise LoadError(
                f"task {task_name} {phase} expected at least "
                f"{minimum_hit_tokens} cached prompt token(s), reported {cached}"
            )


def task_results(
    output: pathlib.Path,
    task: dict[str, Any],
    expected: list[dict[str, Any]],
    cache_requirements: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    phases: dict[str, list[dict[str, Any]]] = {"warmup": [], "measured": []}
    for wave in expected:
        if wave["task"] == task["name"]:
            phases[wave["phase"]].append(
                common.read_json_object(output / wave["relative_path"], "wave")
            )
    if len(phases["warmup"]) != task["warmup_waves"]:
        raise LoadError(f"task {task['name']} has incomplete warmup evidence")
    if len(phases["measured"]) != task["measured_waves"]:
        raise LoadError(f"task {task['name']} has incomplete measured evidence")
    waves = phases["warmup"] + phases["measured"]
    equal = len(waves) >= 2 and all(
        common.assert_pair_equal(waves[0]["result"], row["result"])
        for row in waves[1:]
    )
    if task["require_output_equality"]:
        if len(waves) < 2:
            raise LoadError(
                f"task {task['name']} requires output equality but has fewer than two waves"
            )
        if not equal:
            raise LoadError(f"cold/warm output divergence in task {task['name']}")
    minimum_hit_tokens = cache_requirements["minimum_hit_tokens"]
    for phase in ("warmup", "measured"):
        enforce_cache_requirement(
            task["name"],
            phase,
            cache_requirements[phase],
            phases[phase],
            minimum_hit_tokens,
        )
    measured = phase_summary(phases["measured"])
    summary = {
        "name": task["name"],
        "cell": task["cell"],
        "streams": task["streams"],
        "warmup_waves": task["warmup_waves"],
        "measured_waves": task["measured_waves"],
        "requests": measured["requests"],
        "completion_tokens": measured["completion_tokens"],
        "outputs_equal": equal,
        "cache_requirements": cache_requirements,
        "phases": {
            "warmup": phase_summary(phases["warmup"]),
            "measured": measured,
        },
        "ttft_ms": measured["ttft_ms"],
        "wall_ms": measured["wall_ms"],
        "decode_tokens_per_second": measured["decode_tokens_per_second"],
        "batch_wall_ms": measured["batch_wall_ms"],
        "job_completion_tokens_per_second": measured[
            "job_completion_tokens_per_second"
        ],
    }
    return waves, summary


def main() -> int:
    arguments = parse_arguments()
    if arguments.timeout <= 0:
        raise LoadError("--timeout must be positive")
    base_url = common.validate_base_url(arguments.base_url)
    manifest = common.read_json_object(arguments.release_manifest, "release manifest")
    release, engine_name, model_id = common.validate_release_manifest(manifest)
    source_root = pathlib.Path(__file__).resolve().parents[1]
    common.verify_letsinfer_release_sources(manifest, source_root)
    model_revision = common.model_revision(manifest)
    plan, fixture_path, cells, tokenizer = load_plan(
        arguments.plan,
        fixture_path=arguments.fixture_manifest,
        engine_name=engine_name,
        model_id=model_id,
        model_revision=model_revision,
    )
    plan = select_tasks(plan, arguments.task)
    workload_capacity = validate_workload_capacity(
        manifest, plan, cells
    )
    source = common.source_identity(
        source_root, arguments.measured_commit, arguments.source_attestation
    )
    api_key = common.read_private_file(arguments.api_key_file, "API-key file")
    if arguments.ca_cert_file.is_symlink() or not arguments.ca_cert_file.is_file():
        raise LoadError("CA certificate must be a regular non-symlink file")
    tls_context = ssl.create_default_context(cafile=str(arguments.ca_cert_file))
    server_command = arguments.server_command_file.read_text(encoding="utf-8").strip()
    if not server_command or api_key in server_command:
        raise LoadError("server command is empty or contains the API-key value")
    before_inspection = common.docker_inspect(arguments.container)
    before = common.validate_container(
        before_inspection, manifest
    )
    inputs = {
        "schema_version": 1,
        "release": release,
        "engine": engine_name,
        "model_id": model_id,
        "model_revision": model_revision,
        "serving": manifest["serving"],
        "container": arguments.container,
        "base_url": base_url,
        "measured_commit": arguments.measured_commit,
        "release_manifest_sha256": common.sha256_file(arguments.release_manifest),
        "plan_sha256": common.sha256_file(arguments.plan),
        "selected_tasks": [task["name"] for task in plan["tasks"]],
        "fixture_manifest_sha256": common.sha256_file(fixture_path),
        "workload_capacity": workload_capacity,
        "server_command_sha256": common.sha256_text(server_command),
        "runner_sha256": common.sha256_file(pathlib.Path(__file__).resolve()),
        "source_identity": source,
        "container_identity": {
            "id": before["id"],
            "image": before["image"],
            "started_at": before["started_at"],
            "restart_count": before["restart_count"],
        },
    }
    state = initialize_state(
        arguments.output_directory, inputs=inputs, plan=plan, resume=arguments.resume
    )
    expected = expected_waves(plan)
    reconcile_waves(arguments.output_directory, state, expected)
    reconcile_failures(arguments.output_directory, state)
    finalized = reconcile_results(arguments.output_directory, state)
    if finalized or state["status"] == "complete":
        if arguments.resume:
            print(
                f"COMPLETE {release} engine={engine_name} "
                f"results_sha256={state.get('results_sha256', 'unknown')}"
            )
            return 0
        raise LoadError("run is already complete")
    if arguments.resume:
        state["resume_count"] += 1
        state.pop("error", None)
    state["status"] = "running"
    save_state(arguments.output_directory, state)
    attempt_number = state["resume_count"]
    attempt_directory = (
        arguments.output_directory / "attempts" / f"attempt-{attempt_number:04d}"
    )
    if attempt_directory.exists():
        raise LoadError(f"refusing to overwrite attempt evidence: {attempt_directory}")
    attempt_directory.mkdir()
    common.write_json_atomic(attempt_directory / "container-before.json", before_inspection)
    completed_paths = {row["relative_path"] for row in state["completed_waves"]}
    failure: BaseException | None = None
    preflight: dict[str, Any] | None = None
    monitor = TelemetryMonitor(
        attempt_directory / "telemetry.jsonl",
        arguments.container,
        plan["sample_interval_seconds"],
        manifest["container"].get("runtime_min_available_gib", 16),
        arguments.watchdog_trip_file,
    )
    started = time.monotonic()
    try:
        with monitor:
            if monitor.errors:
                raise LoadError(f"telemetry monitoring failed: {monitor.errors[0]}")
            preflight = common.preflight(
                base_url, tls_context, min(arguments.timeout, 30), api_key, model_id
            )
            if monitor.errors:
                raise LoadError(f"telemetry monitoring failed: {monitor.errors[0]}")
            tasks_by_name = {task["name"]: task for task in plan["tasks"]}
            for wave in expected:
                task = tasks_by_name[wave["task"]]
                if wave["relative_path"] in completed_paths:
                    continue
                state["tasks"][task["name"]] = "running"
                save_state(arguments.output_directory, state)
                print(
                    f"{task['name']} {wave['phase']} {wave['index']}",
                    file=sys.stderr,
                    flush=True,
                )
                inspection = common.docker_inspect(arguments.container)
                current = common.validate_container(
                    inspection, manifest
                )
                if (
                    current["id"] != before["id"]
                    or current["started_at"] != before["started_at"]
                    or current["restart_count"] != before["restart_count"]
                ):
                    raise LoadError("container changed or restarted before a wave")
                result = common.run_cell(
                    cell=cells[task["cell"]],
                    phase=wave["phase"],
                    base_url=base_url,
                    context=tls_context,
                    api_key=api_key,
                    model_id=model_id,
                    timeout=arguments.timeout,
                )
                if monitor.errors:
                    raise LoadError(f"telemetry monitoring failed: {monitor.errors[0]}")
                document = {
                    "schema_version": 1,
                    "task": task["name"],
                    "phase": wave["phase"],
                    "wave_index": wave["index"],
                    "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "result": result,
                }
                path = arguments.output_directory / wave["relative_path"]
                common.write_json_atomic(path, document)
                state["completed_waves"].append(
                    {
                        "relative_path": wave["relative_path"],
                        "sha256": common.sha256_file(path),
                    }
                )
                completed_paths.add(wave["relative_path"])
                save_state(arguments.output_directory, state)
                if task["cooldown_seconds"]:
                    if monitor.fault_event.wait(task["cooldown_seconds"]):
                        raise LoadError(
                            f"telemetry monitoring failed: {monitor.errors[0]}"
                        )
            for task in plan["tasks"]:
                state["tasks"][task["name"]] = "complete"
            save_state(arguments.output_directory, state)
    except BaseException as error:
        failure = error
    after_inspection: dict[str, Any] | None = None
    try:
        after_inspection = common.docker_inspect(arguments.container)
        common.write_json_atomic(
            attempt_directory / "container-after.json", after_inspection
        )
    except BaseException as error:
        if failure is None:
            failure = error
    try:
        if after_inspection is None:
            assert failure is not None
            raise failure
        try:
            after = common.validate_container(
                after_inspection, manifest
            )
        except BaseException as postcondition_error:
            if failure is not None:
                raise LoadError(
                    f"load attempt failed ({type(failure).__name__}: {failure}); "
                    f"container postcondition failed "
                    f"({type(postcondition_error).__name__}: {postcondition_error})"
                ) from failure
            raise
        if (
            after["id"] != before["id"]
            or after["started_at"] != before["started_at"]
            or after["restart_count"] != before["restart_count"]
        ):
            raise LoadError("container changed or restarted during the load run")
        if monitor.errors:
            raise LoadError(f"telemetry monitoring failed: {monitor.errors[0]}")
        if failure is not None:
            raise failure
        if preflight is None:
            raise LoadError("load preflight did not complete")
        summaries: list[dict[str, Any]] = []
        for task in plan["tasks"]:
            _, summary = task_results(
                arguments.output_directory,
                task,
                expected,
                plan["cache_requirements"],
            )
            summaries.append(summary)
        document = result_envelope(
            inputs,
            {
                "run_identity": state["run_identity"],
                "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "duration_seconds": time.monotonic() - started,
                "tokenizer_identity": tokenizer,
                "server_command": server_command,
                "preflight": preflight,
                "container_before": before,
                "container_after": after,
                "plan": plan,
                "tasks": summaries,
                "attempt_evidence": collect_attempt_evidence(
                    arguments.output_directory
                ),
                "resume_count": state["resume_count"],
                "failure_history": state["failure_history"],
                "qualification_passed": True,
                "scope_note": (
                    "This engine-neutral load contract does not claim engine-specific "
                    "cache, scheduler, or speculative-decoding behavior."
                ),
            },
        )
        results_path = arguments.output_directory / "results.json"
        if results_path.exists() or (arguments.output_directory / "results.sha256").exists():
            raise LoadError("refusing to overwrite existing result evidence")
        common.write_json_atomic(results_path, document)
        results_sha = common.sha256_file(results_path)
        common.write_text_atomic(
            arguments.output_directory / "results.sha256",
            f"{results_sha}  results.json\n",
        )
        state["status"] = "complete"
        state["results_sha256"] = results_sha
        save_state(arguments.output_directory, state)
        print(
            f"PASS {release} engine={engine_name} "
            f"tasks={len(summaries)} results_sha256={results_sha}"
        )
        return 0
    except BaseException as error:
        state["status"] = "failed"
        state["error"] = {"type": type(error).__name__, "message": str(error)}
        save_state(arguments.output_directory, state)
        record_failure(arguments.output_directory, state, error)
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except common.QualificationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
