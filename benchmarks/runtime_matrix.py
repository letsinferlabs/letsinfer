#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Benchmark a sealed Let's Infer runtime across context and concurrency cells.

The runtime manifest owns every engine and serving setting. The installed
runtime declares a standard workload; this runner materializes fixed canonical
code/prose prompts and records exact adapter token counts, starts simultaneous OpenAI
requests, and records results and safety telemetry. It deliberately has no
engine-argument surface.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import pathlib
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any


BENCHMARK_DIR = pathlib.Path(__file__).resolve().parent
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))
CONTROL_ROOT = BENCHMARK_DIR.parent
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))
import openai_load as load  # pylint: disable=wrong-import-position
import openai_matrix as common  # pylint: disable=wrong-import-position
import benchmark_record  # pylint: disable=wrong-import-position
import prompt_generator  # pylint: disable=wrong-import-position
import watchdog_client  # pylint: disable=wrong-import-position
from core import ui  # pylint: disable=wrong-import-position
from core.exact_tokens import (  # pylint: disable=wrong-import-position
    TokenCountError,
    parse_token_count_response,
    prepare_token_count_request,
)
from core.runtime_packs import (  # pylint: disable=wrong-import-position
    RuntimePackError,
    benchmark_model_sha256,
)


CONCURRENCIES = (1, 2, 4, 8, 16)
CONTEXTS = ("32k", "64k", "128k", "256k")
SAFE_CELL = re.compile(
    r"(?:32k|64k|128k|256k)-(?:code|prose)-c(?:1|2|4|8|16)"
)
_PROGRESS_FILE: pathlib.Path | None = None
_PROGRESS_STARTED_UNIX_NS: int | None = None
_EXPECTED_MINUTES: tuple[int, int] | None = None
_SELECTED_CELLS: tuple[str, ...] = ()
_COMPLETED_CELLS: list[str] = []
_CURRENT_CELL: str | None = None


class RuntimeMatrixError(common.QualificationError):
    """The runtime matrix contract was invalid or failed."""


def _write_benchmark_progress(phase: str, message: str, state: str) -> None:
    if _PROGRESS_FILE is None:
        return
    common.write_json_atomic(
        _PROGRESS_FILE,
        {
            "schema_version": 1,
            "state": state,
            "phase": phase,
            "message": message,
            "started_unix_ns": _PROGRESS_STARTED_UNIX_NS,
            "updated_unix_ns": time.time_ns(),
            "expected_minutes": (
                list(_EXPECTED_MINUTES) if _EXPECTED_MINUTES is not None else None
            ),
            "selected_cells": list(_SELECTED_CELLS),
            "completed_cells": list(_COMPLETED_CELLS),
            "current_cell": _CURRENT_CELL,
        },
    )


@contextlib.contextmanager
def benchmark_activity(message: str, *, done: str, phase: str) -> Any:
    """Keep long benchmark phases visible without changing result stdout."""
    _write_benchmark_progress(phase, message, "running")
    terminal = ui.Terminal(sys.stderr)
    started = time.monotonic()
    if terminal.interactive:
        with ui.progress(message, done=done, stream=sys.stderr):
            yield
        return
    print(f"BENCHMARK {message}", file=sys.stderr, flush=True)
    try:
        yield
    except BaseException:
        _write_benchmark_progress(phase, message, "failed")
        elapsed = time.monotonic() - started
        print(
            f"BENCHMARK FAILED {message} elapsed={elapsed:.1f}s",
            file=sys.stderr,
            flush=True,
        )
        raise
    _write_benchmark_progress(phase, done, "running")
    elapsed = time.monotonic() - started
    print(
        f"BENCHMARK {done} elapsed={elapsed:.1f}s",
        file=sys.stderr,
        flush=True,
    )


def benchmark_state(message: str, *, phase: str) -> None:
    """Write one compact, colored benchmark state to the activity stream."""
    _write_benchmark_progress(phase, message, "running")
    ui.Terminal(sys.stderr).status(message)


def expected_duration_range(
    selected: list[dict[str, Any]], *, includes_materializer: bool
) -> tuple[int, int]:
    """Return a deliberately broad first-run estimate in whole minutes."""
    launches = len(selected) + (1 if includes_materializer else 0)
    prompt_tokens = sum(
        value
        for cell in selected
        for fixture in cell["fixtures"]
        for value in (fixture.get("expected_prompt_tokens", 0),)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
    )
    lower_seconds = launches * 150 + prompt_tokens / 1500
    upper_seconds = launches * 240 + prompt_tokens / 500
    lower_minutes = max(1, int((lower_seconds + 59) // 60))
    upper_minutes = max(lower_minutes, int((upper_seconds + 59) // 60))
    return lower_minutes, upper_minutes


def capture_container_logs(container: str, output: pathlib.Path) -> None:
    """Preserve engine logs before the isolated container is removed."""
    try:
        logs = common.run_command(
            ["docker", "container", "logs", "--timestamps", container]
        )
        common.write_text_atomic(output / "container-stdout.log", logs.stdout)
        common.write_text_atomic(output / "container-stderr.log", logs.stderr)
        common.write_json_atomic(
            output / "container-logs.json",
            {
                "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "returncode": logs.returncode,
                "stderr_sha256": common.sha256_file(output / "container-stderr.log"),
                "stdout_sha256": common.sha256_file(output / "container-stdout.log"),
            },
        )
    except BaseException as error:
        common.write_json_atomic(
            output / "container-logs.json",
            {
                "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "capture_error": f"{type(error).__name__}: {error}",
            },
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime",
        required=True,
        help=(
            "installed Let's Infer runtime name or private runtime-execution path; "
            "it is the only serving config"
        ),
    )
    parser.add_argument(
        "--prompt-plan",
        type=pathlib.Path,
        help="explicit materialized prompt plan (benchmark-development use only)",
    )
    parser.add_argument("--runtime-config", type=pathlib.Path)
    parser.add_argument("--token-count-path", help=argparse.SUPPRESS)
    parser.add_argument("--token-count-protocol", help=argparse.SUPPRESS)
    parser.add_argument("--token-count-base-url", help=argparse.SUPPRESS)
    parser.add_argument(
        "--token-count-api-key-file", type=pathlib.Path, help=argparse.SUPPRESS
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--engine-port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--output-directory", type=pathlib.Path)
    parser.add_argument(
        "--api-key-file",
        type=pathlib.Path,
        default=pathlib.Path.home() / ".config/letsinfer/api-key",
    )
    parser.add_argument(
        "--ca-cert-file",
        type=pathlib.Path,
        default=pathlib.Path.home() / ".config/letsinfer/tls/server.crt",
    )
    parser.add_argument(
        "--container",
        default="letsinfer-benchmark",
        help="temporary managed container name (default: letsinfer-benchmark)",
    )
    parser.add_argument(
        "--letsinfer-bin",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1] / "bin/letsinfer",
        help="Let's Infer CLI used to resolve, launch, and stop the runtime",
    )
    parser.add_argument(
        "--store-root",
        type=pathlib.Path,
        help="fresh per-cell store parent (default: OUTPUT_DIRECTORY/stores)",
    )
    parser.add_argument(
        "--launch-directory",
        type=pathlib.Path,
        help="per-cell launch evidence parent (default: OUTPUT_DIRECTORY/launches)",
    )
    parser.add_argument("--measured-commit")
    parser.add_argument("--installation-id", help=argparse.SUPPRESS)
    parser.add_argument("--benchmark-timestamp-unix-ns", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--benchmark-contract-sha256", help=argparse.SUPPRESS)
    parser.add_argument("--progress-file", type=pathlib.Path, help=argparse.SUPPRESS)
    parser.add_argument("--watchdog-port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--watchdog-ca-file", type=pathlib.Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--watchdog-controller-cert-file", type=pathlib.Path, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--watchdog-controller-key-file", type=pathlib.Path, help=argparse.SUPPRESS
    )
    parser.add_argument("--source-attestation", type=pathlib.Path)
    parser.add_argument(
        "--watchdog-trip-file",
        type=pathlib.Path,
        default=pathlib.Path.home()
        / ".local/share/letsinfer/watchdog/data-v2/protection-trip.json",
    )
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument(
        "--sample-interval-seconds",
        type=int,
        help="must match the interval sealed by the prompt plan",
    )
    for concurrency in CONCURRENCIES:
        parser.add_argument(
            f"--c{concurrency}",
            action="store_true",
            help=f"select concurrency {concurrency}",
        )
    for context in CONTEXTS:
        parser.add_argument(
            f"--{context}",
            action="store_true",
            dest=f"context_{context}",
            help=f"select the {context.upper()} context",
        )
    parser.add_argument(
        "--list",
        action="store_true",
        help="validate inputs and print selected cells without running inference",
    )
    parser.add_argument(
        "--active-container", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--prompt-domain", choices=prompt_generator.DOMAINS, help=argparse.SUPPRESS
    )
    return parser.parse_args()


def _command_output(command: list[str], what: str) -> str:
    result = common.run_command(command)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeMatrixError(f"{what} failed: {detail}")
    return result.stdout


def resolve_runtime(
    value: str, letsinfer_bin: pathlib.Path
) -> tuple[pathlib.Path, str]:
    """Resolve a manifest path and an exact selector accepted by `letsinfer serve`."""
    candidate = pathlib.Path(value).expanduser()
    if candidate.is_file():
        manifest_path = candidate.resolve()
        manifest = common.read_json_object(manifest_path, "runtime manifest")
        return manifest_path, common.require_string(manifest, "release", "runtime")

    output = _command_output(
        [str(letsinfer_bin), "inspect", value, "--json"],
        f"resolving runtime {value!r}",
    )
    try:
        inspection = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeMatrixError(
            f"Let's Infer returned invalid runtime JSON: {error}"
        ) from error
    if not isinstance(inspection, dict):
        raise RuntimeMatrixError("Let's Infer runtime inspection must be a JSON object")
    receipt = inspection.get("runtime")
    if isinstance(receipt, dict):
        manifest_value = receipt.get("manifest_path")
        selector = receipt.get("name")
        if (
            isinstance(manifest_value, str)
            and manifest_value
            and isinstance(selector, str)
            and selector
        ):
            manifest_path = pathlib.Path(manifest_value).expanduser().resolve()
            if not manifest_path.is_file():
                raise RuntimeMatrixError(
                    f"installed runtime manifest is missing: {manifest_path}"
                )
            return manifest_path, selector
    release = inspection.get("release")
    if not isinstance(release, str) or not release:
        raise RuntimeMatrixError("Let's Infer runtime inspection has no exact selector")
    raise RuntimeMatrixError(
        f"runtime {release!r} is not an installed runtime pack; install it first"
    )


def selected_axes(arguments: argparse.Namespace) -> tuple[list[int], list[str]]:
    concurrencies = [
        value for value in CONCURRENCIES if getattr(arguments, f"c{value}")
    ]
    contexts = [
        value for value in CONTEXTS if getattr(arguments, f"context_{value}")
    ]
    return concurrencies or list(CONCURRENCIES), contexts or list(CONTEXTS)


def load_benchmark_contract(
    path: pathlib.Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    runtime = common.read_json_object(path, "runtime config")
    benchmark = runtime.get("benchmark")
    contract = benchmark.get("contract") if isinstance(benchmark, dict) else None
    try:
        prompt_generator.validate_benchmark_contract(contract)
    except ValueError as error:
        raise RuntimeMatrixError(str(error)) from error
    assert isinstance(contract, dict)
    cases = contract["cases"]
    if [row["id"] for row in cases] != list(CONTEXTS):
        raise RuntimeMatrixError(
            "runtime benchmark cases must be ordered 32k, 64k, 128k, and 256k"
        )
    if any(row["concurrencies"] != list(CONCURRENCIES) for row in cases):
        raise RuntimeMatrixError(
            "runtime benchmark cases must declare c1, c2, c4, c8, and c16"
        )
    tokenizer = contract["tokenizer"]
    try:
        model_sha = benchmark_model_sha256(manifest)
    except RuntimePackError as error:
        raise RuntimeMatrixError(str(error)) from error
    image_id = manifest.get("image", {}).get("immutable_id", "")
    image_sha = image_id.removeprefix("sha256:")
    if tokenizer["model_sha256"] != model_sha:
        raise RuntimeMatrixError(
            "runtime benchmark tokenizer model identity does not match the release"
        )
    if tokenizer["engine_image_sha256"] != image_sha:
        raise RuntimeMatrixError(
            "runtime benchmark tokenizer engine identity does not match the release"
        )
    return contract


def contract_cells(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build selection/capacity rows before prompt bytes are materialized."""
    request = contract["request"]
    cells: dict[str, dict[str, Any]] = {}
    for case in contract["cases"]:
        for concurrency in case["concurrencies"]:
            for domain in prompt_generator.DOMAINS:
                name = f"{case['id']}-{domain}-c{concurrency}"
                cells[name] = {
                    "name": name,
                    "prompt_domain": domain,
                    "prompt_suite": prompt_generator.BENCHMARK_SUITE,
                    "target_prompt_tokens": case["prompt_tokens"],
                    "fixtures": [
                        {"expected_prompt_tokens": case["prompt_tokens"]}
                        for _ in range(concurrency)
                    ],
                    "max_tokens": request["output_tokens"],
                }
    return cells


def token_count_client(
    *,
    base_url: str,
    path: str,
    protocol: str,
    api_key: str,
    tls_context: ssl.SSLContext,
    model_id: str,
    timeout: int,
) -> Any:
    """Return the standard authenticated rendered-chat token-count operation."""
    if not path.startswith("/") or "://" in path:
        raise RuntimeMatrixError("engine adapter token-count path is invalid")
    endpoint = base_url.rstrip("/") + path

    def count(text: str) -> int:
        openai_body = json.dumps(
            {
                "model": model_id,
                "messages": [{"role": "user", "content": text}],
                "max_tokens": 1,
                "temperature": 0,
            },
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        try:
            body = prepare_token_count_request(protocol, model_id, openai_body)
        except TokenCountError as error:
            raise RuntimeMatrixError(
                f"engine token-count request cannot be represented exactly: {error}"
            ) from error
        request = urllib.request.Request(
            endpoint,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(
                request, context=tls_context, timeout=timeout
            ) as response:
                payload = response.read()
        except OSError as error:
            raise RuntimeMatrixError(f"engine token-count request failed: {error}") from error
        try:
            return parse_token_count_response(protocol, model_id, payload)
        except TokenCountError as error:
            raise RuntimeMatrixError(f"engine token-count response is invalid: {error}") from error

    return count


def prompt_set_sha256(rows: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item["relative_path"]):
        digest.update(row["relative_path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(row["sha256"].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def bind_sample_interval(requested: int | None, plan: dict[str, Any]) -> int:
    declared = common.require_positive_int(
        plan, "sample_interval_seconds", "prompt plan"
    )
    if declared > 60:
        raise RuntimeMatrixError(
            "prompt plan.sample_interval_seconds must be from 1 through 60"
        )
    if requested is not None and requested != declared:
        raise RuntimeMatrixError(
            f"--sample-interval-seconds must match the sealed plan ({declared})"
        )
    return declared


def _number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeMatrixError(f"{where} must be a number")
    result = float(value)
    if result <= 0:
        raise RuntimeMatrixError(f"{where} must be positive")
    return result


def host_mem_available_bytes(
    meminfo: pathlib.Path = pathlib.Path("/proc/meminfo"),
) -> int:
    """Read the kernel's unified-memory admission signal."""
    for line in meminfo.read_text(encoding="utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            fields = line.split()
            if len(fields) != 3 or fields[2] != "kB":
                break
            try:
                available_kib = int(fields[1])
            except ValueError as error:
                raise RuntimeMatrixError(
                    f"invalid MemAvailable value in {meminfo}: {fields[1]!r}"
                ) from error
            if available_kib <= 0:
                break
            return available_kib * 1024
    raise RuntimeMatrixError(f"cannot read MemAvailable from {meminfo}")


def require_post_load_warning_headroom(
    manifest: dict[str, Any],
    *,
    samples: int = 3,
    interval_seconds: float = 1.0,
) -> dict[str, Any]:
    """Require a stable post-load baseline above the release warning line."""
    protection = manifest.get("watchdog", {}).get("protection", {})
    warning = protection.get("warning_available_bytes")
    if isinstance(warning, bool) or not isinstance(warning, int) or warning <= 0:
        raise RuntimeMatrixError(
            "runtime manifest watchdog.protection.warning_available_bytes "
            "must be a positive integer"
        )
    if samples <= 0:
        raise RuntimeMatrixError("post-load memory sample count must be positive")
    observed: list[int] = []
    for index in range(samples):
        observed.append(host_mem_available_bytes())
        if index + 1 < samples:
            time.sleep(interval_seconds)
    minimum = min(observed)
    result = {
        "warning_available_bytes": warning,
        "observed_available_bytes": observed,
        "minimum_available_bytes": minimum,
        "passed": minimum >= warning,
    }
    if minimum < warning:
        raise RuntimeMatrixError(
            "post-load host memory is below the manifest warning line: "
            f"minimum {minimum} bytes < required {warning} bytes; "
            "do not start benchmark traffic from this host state"
        )
    return result


def load_prompt_plan(
    path: pathlib.Path, manifest: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    plan = common.read_json_object(path, "runtime matrix prompt plan")
    if type(plan.get("schema_version")) is not int or plan.get("schema_version") != 2:
        raise RuntimeMatrixError("runtime matrix schema_version must be 2")
    prompt_suite = plan.get("prompt_suite")
    if prompt_suite != prompt_generator.BENCHMARK_SUITE:
        raise RuntimeMatrixError("prompt plan suite is unsupported")
    expected_identity = {
        "model_id": common._manifest_value(manifest, "model.id"),
        "model_revision": common.model_revision(manifest),
    }
    for key, value in expected_identity.items():
        if plan.get(key) != value:
            raise RuntimeMatrixError(
                f"prompt plan {key} must be {value!r}, got {plan.get(key)!r}"
            )
    tokenizer = plan.get("tokenizer_identity")
    if not isinstance(tokenizer, dict) or not tokenizer:
        raise RuntimeMatrixError("prompt plan tokenizer_identity must be an object")
    request = plan.get("request")
    if not isinstance(request, dict):
        raise RuntimeMatrixError("prompt plan request must be an object")
    max_tokens = common.require_positive_int(request, "max_tokens", "prompt plan.request")
    minimum = common.require_positive_int(
        request, "min_completion_tokens", "prompt plan.request"
    )
    if minimum > max_tokens:
        raise RuntimeMatrixError("minimum completion tokens exceed max_tokens")
    natural_stop = request.get("require_natural_stop")
    if not isinstance(natural_stop, bool):
        raise RuntimeMatrixError("prompt plan.request.require_natural_stop must be boolean")
    options = common.validate_request_options(
        request.get("options"), "prompt plan.request.options"
    )
    temperature = common.validate_temperature(
        request.get("temperature", 0), "prompt plan.request.temperature"
    )

    fixture_rows = plan.get("fixtures")
    if not isinstance(fixture_rows, list) or not fixture_rows:
        raise RuntimeMatrixError("prompt plan fixtures must be a non-empty array")
    fixtures: dict[str, dict[str, Any]] = {}
    public_files: list[dict[str, Any]] = []
    for index, row in enumerate(fixture_rows):
        where = f"prompt plan.fixtures[{index}]"
        if not isinstance(row, dict):
            raise RuntimeMatrixError(f"{where} must be an object")
        name = common.require_string(row, "name", where)
        if name in fixtures:
            raise RuntimeMatrixError(f"duplicate prompt fixture: {name}")
        message, public = common.load_fixture_message(
            path.parent, row, where, default_role="user"
        )
        expected_tokens = common.require_positive_int(
            row, "expected_prompt_tokens", where
        )
        prompt_domain = common.require_string(row, "prompt_domain", where)
        if prompt_domain not in prompt_generator.DOMAINS:
            raise RuntimeMatrixError(f"{where}.prompt_domain is unsupported")
        fixtures[name] = {
            "name": name,
            "sha256": public["sha256"],
            "messages": [message],
            "message_files": [public],
            "expected_prompt_tokens": expected_tokens,
            "prompt_domain": prompt_domain,
        }
        public_files.append(
            {
                "relative_path": public["path"],
                "sha256": public["sha256"],
                "expected_prompt_tokens": expected_tokens,
            }
        )
    expected_set_sha = common.require_string(
        plan, "prompt_set_sha256", "prompt plan"
    )
    actual_set_sha = prompt_set_sha256(public_files)
    if actual_set_sha != expected_set_sha:
        raise RuntimeMatrixError(
            f"prompt set SHA-256 is {actual_set_sha}, expected {expected_set_sha}"
        )

    context_rows = plan.get("contexts")
    if not isinstance(context_rows, list) or not context_rows:
        raise RuntimeMatrixError("prompt plan contexts must be a non-empty array")
    if len(context_rows) > len(CONTEXTS):
        raise RuntimeMatrixError("prompt plan defines too many contexts")
    cells: dict[str, dict[str, Any]] = {}
    public_contexts: list[dict[str, Any]] = []
    allocated: set[str] = set()
    previous_context_index = -1
    for index, row in enumerate(context_rows):
        where = f"prompt plan.contexts[{index}]"
        if not isinstance(row, dict):
            raise RuntimeMatrixError(f"{where} must be an object")
        context = common.require_string(row, "name", where)
        if context not in CONTEXTS:
            raise RuntimeMatrixError(f"{where}.name is not a standard context")
        context_index = CONTEXTS.index(context)
        if context_index <= previous_context_index:
            raise RuntimeMatrixError(
                "prompt plan contexts must be unique and in standard order"
            )
        previous_context_index = context_index
        target_prompt_tokens = common.require_positive_int(
            row, "target_prompt_tokens", where
        )
        mappings = row.get("cells")
        if not isinstance(mappings, dict) or not mappings:
            raise RuntimeMatrixError(f"{where}.cells must be a non-empty object")
        known_keys = {
            f"{domain}-c{concurrency}"
            for domain in prompt_generator.DOMAINS
            for concurrency in CONCURRENCIES
        }
        unknown_keys = sorted(set(mappings) - known_keys)
        if unknown_keys:
            raise RuntimeMatrixError(
                f"{where}.cells contains unknown cells: {', '.join(unknown_keys)}"
            )
        public_cells: dict[str, list[str]] = {}
        for concurrency in CONCURRENCIES:
            for domain in prompt_generator.DOMAINS:
                key = f"{domain}-c{concurrency}"
                if key not in mappings:
                    continue
                names = mappings.get(key)
                if (
                    not isinstance(names, list)
                    or len(names) != concurrency
                    or not all(isinstance(name, str) and name for name in names)
                ):
                    raise RuntimeMatrixError(
                        f"{where}.cells.{key} must contain {concurrency} fixture names"
                    )
                if len(names) != len(set(names)):
                    raise RuntimeMatrixError(f"{where}.cells.{key} contains duplicates")
                missing = sorted(set(names) - fixtures.keys())
                if missing:
                    raise RuntimeMatrixError(
                        f"{where}.cells.{key} names unknown fixtures: {', '.join(missing)}"
                    )
                if any(fixtures[name]["prompt_domain"] != domain for name in names):
                    raise RuntimeMatrixError(
                        f"{where}.cells.{key} mixes prompt domains"
                    )
                allocated.update(names)
                cell_name = f"{context}-{key}"
                selected_rows = [
                    {
                        "relative_path": fixtures[name]["message_files"][0]["path"],
                        "sha256": fixtures[name]["sha256"],
                    }
                    for name in names
                ]
                cells[cell_name] = {
                    "name": cell_name,
                    "prompt_domain": domain,
                    "prompt_suite": prompt_suite,
                    "prompt_set_sha256": prompt_set_sha256(selected_rows),
                    "target_prompt_tokens": target_prompt_tokens,
                    "fixtures": [fixtures[name] for name in names],
                    "max_tokens": max_tokens,
                    "min_completion_tokens": minimum,
                    "require_natural_stop": natural_stop,
                    "request_options": options,
                    "temperature": temperature,
                }
                public_cells[key] = names
        sealed = row.get("sealed_c1")
        if sealed is not None:
            if not isinstance(sealed, dict):
                raise RuntimeMatrixError(f"{where}.sealed_c1 must be an object")
            sealed = {
                "decode_tokens_per_second": _number(
                    sealed.get("decode_tokens_per_second"),
                    f"{where}.sealed_c1.decode_tokens_per_second",
                ),
                "ttft_ms": _number(
                    sealed.get("ttft_ms"), f"{where}.sealed_c1.ttft_ms"
                ),
                "evidence": common.require_string(
                    sealed, "evidence", f"{where}.sealed_c1"
                ),
            }
        public_contexts.append(
            {
                "name": context,
                "target_prompt_tokens": target_prompt_tokens,
                "cells": public_cells,
                "sealed_c1": sealed,
            }
        )
    if set(fixtures) != allocated:
        unused = sorted(set(fixtures) - allocated)
        raise RuntimeMatrixError("prompt plan has unused fixtures: " + ", ".join(unused))
    public_plan = {
        "schema_version": 2,
        "prompt_suite": prompt_suite,
        "model_id": plan["model_id"],
        "model_revision": plan["model_revision"],
        "tokenizer_identity": tokenizer,
        "sample_interval_seconds": bind_sample_interval(None, plan),
        "request": {
            "max_tokens": max_tokens,
            "min_completion_tokens": minimum,
            "require_natural_stop": natural_stop,
            "temperature": temperature,
            "options": options,
        },
        "prompt_set_sha256": actual_set_sha,
        "contexts": public_contexts,
    }
    materialization = plan.get("materialization")
    if materialization is not None:
        if not isinstance(materialization, dict):
            raise RuntimeMatrixError("prompt plan materialization must be an object")
        public_plan["materialization"] = materialization
    return public_plan, cells


def select_cells(
    cells: dict[str, dict[str, Any]],
    concurrencies: list[int],
    contexts: list[str],
    prompt_domain: str | None = None,
) -> list[dict[str, Any]]:
    # C1 is intentionally completed before higher concurrency so sealed parity
    # is known before the expensive load cells begin.
    names = [
        f"{context}-{domain}-c{concurrency}"
        for concurrency in concurrencies
        for context in contexts
        for domain in prompt_generator.DOMAINS
        if prompt_domain is None or domain == prompt_domain
    ]
    missing = [name for name in names if name not in cells]
    if missing:
        raise RuntimeMatrixError(
            "prompt plan does not define selected cell(s): " + ", ".join(missing)
        )
    return [cells[name] for name in names]


def discover_container(release: str) -> str:
    result = common.run_command(
        [
            "docker",
            "ps",
            "--filter",
            f"label=io.letsinfer.release={release}",
            "--format",
            "{{.Names}}",
        ]
    )
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0 or len(names) != 1:
        raise RuntimeMatrixError(
            f"expected one running container for release {release}, found {len(names)}"
        )
    return names[0]


def resolved_container_command(inspection: dict[str, Any]) -> str:
    config = inspection.get("Config")
    if not isinstance(config, dict):
        raise RuntimeMatrixError("container inspection has no Config")
    parts = config.get("Entrypoint") or []
    command = config.get("Cmd") or []
    if not isinstance(parts, list) or not isinstance(command, list):
        raise RuntimeMatrixError("container entrypoint/command is invalid")
    value = json.dumps(parts + command, separators=(",", ":"))
    if not parts and not command:
        raise RuntimeMatrixError("container has no resolved command")
    return value


def validate_capacity(
    manifest: dict[str, Any], selected: list[dict[str, Any]]
) -> dict[str, int]:
    serving = manifest.get("serving")
    if not isinstance(serving, dict):
        raise RuntimeMatrixError("runtime serving contract is missing")
    max_connections = common.require_positive_int(
        serving, "max_connections", "runtime.serving"
    )
    max_active = common.require_positive_int(
        serving, "max_active_requests", "runtime.serving"
    )
    max_context = common.require_positive_int(
        serving, "max_context_tokens", "runtime.serving"
    )
    requested = max(len(cell["fixtures"]) for cell in selected)
    # Client concurrency is bounded by accepted connections.  The engine's
    # active ceiling is a scheduler limit: excess accepted requests queue.
    if requested > max_connections:
        raise RuntimeMatrixError(
            f"selected c{requested} exceeds runtime connection ceiling "
            f"({max_connections})"
        )
    for cell in selected:
        for fixture in cell["fixtures"]:
            required = fixture["expected_prompt_tokens"] + cell["max_tokens"]
            if required > max_context:
                raise RuntimeMatrixError(
                    f"{cell['name']} requires {required} tokens, runtime allows {max_context}"
                )
    return {
        "runtime_max_connections": max_connections,
        "runtime_max_active_requests": max_active,
        "runtime_max_context_tokens": max_context,
        "selected_max_concurrency": requested,
    }


def summarize(cell: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    requests = result["requests"]

    def values(key: str) -> list[float]:
        return [
            float(row[key])
            for row in requests
            if isinstance(row.get(key), (int, float))
            and not isinstance(row.get(key), bool)
        ]

    return {
        "cell": cell["name"],
        "concurrency": len(requests),
        "prompt_tokens": [row["prompt_tokens"] for row in requests],
        "completion_tokens": sum(row["completion_tokens"] for row in requests),
        "decode_tokens_per_second": load.metric_summary(
            values("decode_tokens_per_second")
        ),
        "ttft_ms": load.metric_summary(values("ttft_ms")),
        "wall_ms": load.metric_summary(values("wall_ms")),
        "cached_prompt_tokens": load.metric_summary(
            [
                0.0 if row.get("cached_prompt_tokens") is None
                else float(row["cached_prompt_tokens"])
                for row in requests
            ]
        ),
        "batch_wall_ms": result["batch_wall_ms"],
        "aggregate_completion_tokens_per_second": result[
            "job_completion_tokens_per_second"
        ],
    }


def public_benchmark_result(
    cell: dict[str, Any],
    summary: dict[str, Any],
    watchdog_samples: list[dict[str, int]],
) -> dict[str, Any]:
    prompt_tokens = summary.get("prompt_tokens")
    concurrency = summary.get("concurrency")
    if (
        not isinstance(prompt_tokens, list)
        or not prompt_tokens
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in prompt_tokens
        )
        or not isinstance(concurrency, int)
        or isinstance(concurrency, bool)
        or concurrency <= 0
    ):
        raise RuntimeMatrixError("matrix summary cannot identify one public workload")
    decode = summary.get("decode_tokens_per_second")
    ttft = summary.get("ttft_ms")
    cached = summary.get("cached_prompt_tokens")
    if not all(isinstance(value, dict) for value in (decode, ttft, cached)):
        raise RuntimeMatrixError("matrix summary is missing public metrics")
    decode_mean = decode.get("mean")
    cached_max = cached.get("max")
    if not isinstance(decode_mean, (int, float)) or isinstance(decode_mean, bool):
        raise RuntimeMatrixError("matrix summary has no decode throughput")
    if not isinstance(cached_max, (int, float)) or isinstance(cached_max, bool):
        raise RuntimeMatrixError("matrix summary has no cache observation")
    statistic = "single" if concurrency == 1 else "p50"
    ttft_ms = ttft.get("mean" if concurrency == 1 else "p50")
    ttft_p95_ms = None if concurrency == 1 else ttft.get("p95")
    if not isinstance(ttft_ms, (int, float)) or isinstance(ttft_ms, bool):
        raise RuntimeMatrixError("matrix summary has no TTFT")
    if ttft_p95_ms is not None and (
        not isinstance(ttft_p95_ms, (int, float)) or isinstance(ttft_p95_ms, bool)
    ):
        raise RuntimeMatrixError("matrix summary has invalid TTFT p95")
    measurement_started = summary.get("measurement_started_unix_ms")
    if not isinstance(measurement_started, int) or isinstance(
        measurement_started, bool
    ):
        raise RuntimeMatrixError("matrix summary has no measurement start time")
    try:
        telemetry = benchmark_record.watchdog_summary(
            watchdog_samples, measurement_started
        )
    except benchmark_record.BenchmarkRecordError as error:
        raise RuntimeMatrixError(str(error)) from error
    result = {
        "workload": (
            f"pp{cell['target_prompt_tokens']},tg{cell['max_tokens']},c{concurrency}"
        ),
        "prompt_domain": cell["prompt_domain"],
        "prompt_suite": cell["prompt_suite"],
        "prompt_set_sha256": cell["prompt_set_sha256"],
        "actual_prompt_tokens": prompt_tokens,
        "aggregate_tps": summary["aggregate_completion_tokens_per_second"],
        "decode_tps": decode_mean,
        "ttft_seconds": float(ttft_ms) / 1000.0,
        "ttft_statistic": statistic,
        "ttft_p95_seconds": (
            float(ttft_p95_ms) / 1000.0 if ttft_p95_ms is not None else None
        ),
        "is_prefix_cached": float(cached_max) > 0,
        **telemetry,
    }
    return result


def attach_sealed_comparison(
    summary: dict[str, Any], plan: dict[str, Any]
) -> None:
    if summary["concurrency"] != 1:
        return
    context = summary["cell"].split("-", 1)[0]
    row = next(item for item in plan["contexts"] if item["name"] == context)
    sealed = row["sealed_c1"]
    if sealed is None:
        summary["sealed_comparison"] = None
        return
    current_tps = summary["decode_tokens_per_second"]["mean"]
    current_ttft = summary["ttft_ms"]["mean"]
    assert isinstance(current_tps, float) and isinstance(current_ttft, float)
    tps_change = (current_tps / sealed["decode_tokens_per_second"] - 1.0) * 100.0
    ttft_change = (current_ttft / sealed["ttft_ms"] - 1.0) * 100.0
    summary["sealed_comparison"] = {
        "reference": sealed,
        "decode_percent_change": tps_change,
        "ttft_percent_change": ttft_change,
        "plain_result": (
            f"TPS is {'higher' if tps_change >= 0 else 'lower'} by {abs(tps_change):.3f}%; "
            f"TTFT is {'slower' if ttft_change >= 0 else 'faster'} by {abs(ttft_change):.3f}%"
        ),
    }


def resolve_measured_commit(
    requested: str | None, manifest: dict[str, Any]
) -> str:
    """Use the runtime's sealed benchmark commit unless explicitly supplied."""
    gate = manifest.get("serving", {}).get("gate", {})
    sealed = gate.get("measured_commit") if isinstance(gate, dict) else None
    measured = requested or sealed
    if not isinstance(measured, str) or not re.fullmatch(r"[0-9a-f]{40}", measured):
        raise RuntimeMatrixError(
            "--measured-commit is required when the runtime has no full sealed commit"
        )
    return measured


def verified_source_identity(
    source_root: pathlib.Path,
    manifest_path: pathlib.Path,
    manifest: dict[str, Any],
    measured_commit: str,
    attestation_path: pathlib.Path | None,
) -> dict[str, Any]:
    """Identify either a clean checkout or its verified immutable control bundle."""
    if (source_root / ".git").exists() or attestation_path is not None:
        return common.source_identity(
            source_root, measured_commit, attestation_path
        )

    manifest_sha256 = common.sha256_file(manifest_path)
    try:
        relative_manifest = manifest_path.resolve(strict=True).relative_to(
            source_root.resolve(strict=True)
        )
    except (OSError, ValueError) as error:
        raise RuntimeMatrixError(
            "deployment tree is not a hash-addressed control bundle; "
            "--source-attestation is required"
        ) from error
    if relative_manifest.as_posix() != "runtime-execution.json":
        raise RuntimeMatrixError(
            "control bundle must contain exactly runtime-execution.json"
        )
    try:
        from tools.source_archive import (  # pylint: disable=import-outside-toplevel
            SourceArchiveError,
            public_files,
            source_manifest,
        )

        generated_core_manifest = source_manifest(public_files(source_root))
        recorded_core_manifest = common.read_json_object(
            source_root / "SOURCE-MANIFEST.json", "core source manifest"
        )
    except (OSError, SourceArchiveError, common.QualificationError) as error:
        raise RuntimeMatrixError(f"control-bundle core source is invalid: {error}") from error
    if recorded_core_manifest != generated_core_manifest:
        raise RuntimeMatrixError("control-bundle core source manifest mismatch")
    core_identity = hashlib.sha256(
        benchmark_record.canonical_bytes(generated_core_manifest)
    ).hexdigest()
    bundle_identity = hashlib.sha256(
        benchmark_record.canonical_bytes(
            {
                "schema_version": 1,
                "core_source_sha256": core_identity,
                "runtime_manifest_sha256": manifest_sha256,
            }
        )
    ).hexdigest()
    if source_root.name != bundle_identity:
        raise RuntimeMatrixError(
            "deployment tree is not a hash-addressed control bundle; "
            "--source-attestation is required"
        )
    sealed_commit = manifest.get("serving", {}).get("gate", {}).get(
        "measured_commit"
    )
    if measured_commit != sealed_commit:
        raise RuntimeMatrixError(
            "a verified control bundle must use its sealed measured commit"
        )
    return {
        "kind": "verified-control-bundle",
        "commit": measured_commit,
        "core_source_sha256": core_identity,
        "execution_manifest_sha256": manifest_sha256,
    }


def print_summary(summary: dict[str, Any]) -> None:
    decode = summary["decode_tokens_per_second"]
    ttft = summary["ttft_ms"]
    message = (
        f"DONE {summary['cell']} prompt={summary['prompt_tokens']} "
        f"mean_tps={decode['mean']:.6f} aggregate_tps="
        f"{summary['aggregate_completion_tokens_per_second']:.6f} "
        f"ttft_p50={ttft['p50'] / 1000.0:.3f}s "
        f"ttft_p95={ttft['p95'] / 1000.0:.3f}s"
    )
    comparison = summary.get("sealed_comparison")
    if isinstance(comparison, dict):
        message += " | " + comparison["plain_result"]
    print(message, flush=True)


def validate_isolated_cache_evidence(cell: dict[str, Any], result: dict[str, Any]) -> None:
    """Validate cache evidence without rejecting same-cell prefix sharing.

    Every matrix cell already receives a fresh engine process and store.  A
    positive cache count can therefore only be reuse admitted among requests
    in this cell, which is legitimate engine behavior and is retained in the
    public ``is_prefix_cached`` field.
    """
    requests = result.get("requests")
    if not isinstance(requests, list) or len(requests) != len(cell["fixtures"]):
        raise RuntimeMatrixError(
            f"{cell['name']} returned an invalid request count"
        )
    invalid = [
        index
        for index, row in enumerate(requests)
        if (
            not isinstance(row, dict)
            or (
                row.get("cached_prompt_tokens") is not None
                and (
                    not isinstance(row.get("cached_prompt_tokens"), int)
                    or isinstance(row.get("cached_prompt_tokens"), bool)
                    or row["cached_prompt_tokens"] < 0
                )
            )
        )
    ]
    if invalid:
        raise RuntimeMatrixError(
            f"{cell['name']} returned invalid cache evidence for request(s) "
            + ", ".join(str(index) for index in invalid)
        )


def _require_container_absent(name: str) -> None:
    result = common.run_command(["docker", "container", "inspect", name])
    if result.returncode == 0:
        raise RuntimeMatrixError(
            f"temporary benchmark container already exists: {name}; "
            "stop it explicitly"
        )
    detail = (result.stderr or result.stdout).lower()
    if "no such" not in detail:
        raise RuntimeMatrixError(f"cannot establish container absence: {detail.strip()}")


def _worker_command(
    arguments: argparse.Namespace,
    manifest_path: pathlib.Path,
    plan_path: pathlib.Path,
    cell: dict[str, Any],
    output: pathlib.Path,
) -> list[str]:
    context, domain, concurrency_value = cell["name"].split("-", 2)
    concurrency = concurrency_value.removeprefix("c")
    worker_api_key = (
        getattr(arguments, "token_count_api_key_file", None) or arguments.api_key_file
    )
    command = [
        sys.executable,
        str(pathlib.Path(__file__).resolve()),
        "--runtime",
        str(manifest_path),
        "--prompt-plan",
        str(plan_path),
        "--base-url",
        f"https://127.0.0.1:{arguments.engine_port}",
        "--output-directory",
        str(output),
        "--api-key-file",
        str(worker_api_key),
        "--ca-cert-file",
        str(arguments.ca_cert_file),
        "--container",
        arguments.container,
        "--measured-commit",
        arguments.measured_commit,
        "--watchdog-trip-file",
        str(arguments.watchdog_trip_file),
        "--timeout",
        str(arguments.timeout),
        "--sample-interval-seconds",
        str(arguments.sample_interval_seconds),
        f"--{context}",
        f"--c{concurrency}",
        "--prompt-domain",
        domain,
        "--active-container",
    ]
    if arguments.source_attestation is not None:
        command.extend(["--source-attestation", str(arguments.source_attestation)])
    return command


def _serve_command(
    arguments: argparse.Namespace,
    runtime_selector: str,
    store_root: pathlib.Path,
    evidence_directory: pathlib.Path,
) -> list[str]:
    """Launch every isolated materializer/cell on the service's backend port."""
    return [
        str(arguments.letsinfer_bin),
        "serve",
        runtime_selector,
        "--port",
        str(arguments.engine_port),
        "--name",
        arguments.container,
        "--store-root",
        str(store_root),
        "--evidence-dir",
        str(evidence_directory),
        "--qualification-mode",
    ]


def run_isolated_matrix(
    arguments: argparse.Namespace,
    manifest_path: pathlib.Path,
    runtime_selector: str,
    manifest: dict[str, Any],
    plan_path: pathlib.Path | None,
    selected: list[dict[str, Any]],
    source: dict[str, Any],
    benchmark_contract: dict[str, Any] | None = None,
) -> int:
    if (
        not isinstance(arguments.engine_port, int)
        or isinstance(arguments.engine_port, bool)
        or not 1 <= arguments.engine_port <= 65_535
    ):
        raise RuntimeMatrixError("isolated benchmark requires a valid engine port")
    output = arguments.output_directory
    assert output is not None
    if output.exists():
        raise RuntimeMatrixError(f"refusing existing output directory: {output}")
    # ``letsinfer serve --qualification-mode`` owns the single candidate-slot
    # replacement transaction.  Do not reject its currently active container
    # here: the outer benchmark lifecycle records whether inference was active
    # and restores the final isolated candidate after the matrix exits.
    output.mkdir(parents=True)
    results_root = output / "cells"
    stores_root = arguments.store_root or output / "stores"
    launches_root = arguments.launch_directory or output / "launches"
    results_root.mkdir()
    stores_root.mkdir(parents=True, exist_ok=True)
    launches_root.mkdir(parents=True, exist_ok=True)

    model = manifest.get("model")
    model_name = (
        model.get("alias")
        if isinstance(model, dict) and isinstance(model.get("alias"), str)
        else runtime_selector
    )
    expected_low, expected_high = expected_duration_range(
        selected, includes_materializer=benchmark_contract is not None
    )
    global _COMPLETED_CELLS, _CURRENT_CELL, _EXPECTED_MINUTES, _SELECTED_CELLS
    _EXPECTED_MINUTES = (expected_low, expected_high)
    _SELECTED_CELLS = tuple(cell["name"] for cell in selected)
    _COMPLETED_CELLS = []
    _CURRENT_CELL = None
    benchmark_state(
        f"Benchmarking {model_name} · {len(selected)} workload(s)",
        phase="starting",
    )
    benchmark_state(
        f"Expected {expected_low}–{expected_high} min · elapsed time follows live",
        phase="starting",
    )

    if benchmark_contract is not None:
        if plan_path is not None:
            raise RuntimeMatrixError(
                "generated benchmark contract cannot be combined with a prompt plan"
            )
        if not arguments.token_count_path or not arguments.token_count_protocol:
            raise RuntimeMatrixError(
                "selected engine adapter does not expose exact rendered-chat token counting"
            )
        if (
            not arguments.token_count_base_url
            or arguments.token_count_api_key_file is None
        ):
            raise RuntimeMatrixError(
                "isolated benchmark requires the private engine token-count endpoint"
            )
        materialization_store = stores_root / "materialization"
        materialization_launch = launches_root / "materialization"
        materialization_started = False
        materialization_error: BaseException | None = None
        try:
            materialization_started = True
            with benchmark_activity(
                "Preparing prompts · loading tokenizer runtime",
                done="Tokenizer runtime ready",
                phase="preparing-prompts",
            ):
                launch_output = _command_output(
                    _serve_command(
                        arguments,
                        runtime_selector,
                        materialization_store,
                        materialization_launch,
                    ),
                    "launching benchmark prompt materializer",
                )
            if launch_output.strip():
                print(launch_output.strip(), flush=True)
            token_count_api_key = common.read_private_file(
                arguments.token_count_api_key_file,
                "engine token-count API-key file",
            )
            if (
                arguments.ca_cert_file.is_symlink()
                or not arguments.ca_cert_file.is_file()
            ):
                raise RuntimeMatrixError(
                    "CA certificate must be a regular non-symlink file"
                )
            tls_context = ssl.create_default_context(cafile=str(arguments.ca_cert_file))
            counter = token_count_client(
                base_url=common.validate_base_url(arguments.token_count_base_url),
                path=arguments.token_count_path,
                protocol=arguments.token_count_protocol,
                api_key=token_count_api_key,
                tls_context=tls_context,
                model_id=model_name,
                timeout=arguments.timeout,
            )
            with benchmark_activity(
                "Preparing canonical code/prose prompts · counting rendered tokens",
                done="Canonical prompts ready",
                phase="materializing-prompts",
            ):
                plan_path = prompt_generator.materialize(
                    benchmark_contract,
                    output / "inputs",
                    counter,
                    model_id=manifest["model"]["id"],
                model_revision=common.model_revision(manifest),
                    selected_cells=(cell["name"] for cell in selected),
                )
        except BaseException as error:
            materialization_error = error
        stop_error: BaseException | None = None
        if materialization_started:
            try:
                stop_output = _command_output(
                    [
                        str(arguments.letsinfer_bin),
                        "stop",
                        "--container-only",
                        "--name",
                        arguments.container,
                    ],
                    "stopping benchmark prompt materializer",
                )
                if stop_output.strip():
                    print(stop_output.strip(), flush=True)
            except BaseException as error:
                stop_error = error
        if materialization_error is not None:
            if stop_error is not None:
                raise RuntimeMatrixError(
                    f"{materialization_error}; materializer cleanup also failed: {stop_error}"
                ) from materialization_error
            raise materialization_error
        if stop_error is not None:
            raise stop_error
        assert plan_path is not None
        _, materialized_cells = load_prompt_plan(plan_path, manifest)
        requested_names = [cell["name"] for cell in selected]
        selected = [materialized_cells[name] for name in requested_names]
        validate_capacity(manifest, selected)

    if plan_path is None:
        raise RuntimeMatrixError("benchmark prompt plan was not materialized")

    rows: list[dict[str, Any]] = []
    container_ids: set[str] = set()
    for cell_index, cell in enumerate(selected, start=1):
        name = cell["name"]
        _CURRENT_CELL = name
        cell_output = results_root / name
        cell_store = stores_root / name
        cell_launch = launches_root / name
        for path, label in (
            (cell_output, "result"),
            (cell_store, "store"),
            (cell_launch, "launch evidence"),
        ):
            if path.exists():
                raise RuntimeMatrixError(
                    f"refusing existing {label} path for {name}: {path}"
                )

        benchmark_state(
            f"Workload {cell_index}/{len(selected)} · {name} · "
            f"{len(selected) - cell_index} remaining",
            phase=f"workload:{name}:starting",
        )
        launch_attempted = False
        cell_error: BaseException | None = None
        try:
            launch_attempted = True
            with benchmark_activity(
                f"Loading runtime for {name}",
                done=f"Runtime ready for {name}",
                phase=f"workload:{name}:loading",
            ):
                launch_output = _command_output(
                    _serve_command(
                        arguments,
                        runtime_selector,
                        cell_store,
                        cell_launch,
                    ),
                    f"launching {name}",
                )
            if launch_output.strip():
                print(launch_output.strip(), flush=True)
            with benchmark_activity(
                f"Measuring {name}",
                done=f"Measurement complete for {name}",
                phase=f"workload:{name}:measuring",
            ):
                worker = common.run_command(
                    _worker_command(
                        arguments, manifest_path, plan_path, cell, cell_output
                    )
                )
            if worker.stdout.strip():
                print(worker.stdout.strip(), flush=True)
            if worker.returncode != 0:
                raise RuntimeMatrixError(
                    f"{name} worker failed: {(worker.stderr or worker.stdout).strip()}"
                )
        except BaseException as error:
            cell_error = error

        stop_error: BaseException | None = None
        if launch_attempted:
            try:
                stop_output = _command_output(
                    [
                        str(arguments.letsinfer_bin),
                        "stop",
                        "--container-only",
                        "--name",
                        arguments.container,
                    ],
                    f"stopping {name}",
                )
                if stop_output.strip():
                    print(stop_output.strip(), flush=True)
            except BaseException as error:
                stop_error = error
        if cell_error is not None:
            if stop_error is not None:
                raise RuntimeMatrixError(
                    f"{cell_error}; cleanup also failed: {stop_error}"
                ) from cell_error
            raise cell_error
        if stop_error is not None:
            raise stop_error

        result_path = cell_output / "results.json"
        result = common.read_json_object(result_path, f"{name} result")
        summaries = result.get("summaries")
        if (
            result.get("qualification_passed") is not True
            or result.get("selected_cells") != [name]
            or not isinstance(summaries, list)
            or len(summaries) != 1
        ):
            raise RuntimeMatrixError(f"{name} worker evidence is incomplete")
        before = result.get("container_before")
        container_id = before.get("id") if isinstance(before, dict) else None
        if not isinstance(container_id, str) or not container_id:
            raise RuntimeMatrixError(f"{name} evidence has no container identity")
        if container_id in container_ids:
            raise RuntimeMatrixError(f"{name} reused a prior container process")
        container_ids.add(container_id)
        measurement_started = summaries[0].get("measurement_started_unix_ms")
        measurement_ended = summaries[0].get("measurement_ended_unix_ms")
        if (
            not isinstance(measurement_started, int)
            or isinstance(measurement_started, bool)
            or not isinstance(measurement_ended, int)
            or isinstance(measurement_ended, bool)
            or measurement_ended < measurement_started
        ):
            raise RuntimeMatrixError(f"{name} evidence has no valid measurement range")
        assert arguments.watchdog_port is not None
        assert arguments.watchdog_ca_file is not None
        assert arguments.watchdog_controller_cert_file is not None
        assert arguments.watchdog_controller_key_file is not None
        try:
            watchdog_samples = watchdog_client.query_range(
                start_unix_ms=measurement_started,
                end_unix_ms=measurement_ended,
                port=arguments.watchdog_port,
                ca_file=arguments.watchdog_ca_file,
                controller_cert_file=arguments.watchdog_controller_cert_file,
                controller_key_file=arguments.watchdog_controller_key_file,
                timeout=min(arguments.timeout, 30),
            )
        except watchdog_client.WatchdogClientError as error:
            raise RuntimeMatrixError(str(error)) from error
        watchdog_path = cell_output / "watchdog-telemetry.json"
        common.write_json_atomic(
            watchdog_path,
            {
                "schema_version": 1,
                "source": "letsinfer-watchdog-raw-1-second",
                "measurement_started_unix_ms": measurement_started,
                "measurement_ended_unix_ms": measurement_ended,
                "samples": watchdog_samples,
            },
        )
        rows.append(
            {
                "cell": name,
                "container_id": container_id,
                "result_directory": str(cell_output),
                "results_sha256": common.sha256_file(result_path),
                "store_root": str(cell_store),
                "launch_directory": str(cell_launch),
                "summary": summaries[0],
                "watchdog_telemetry": str(watchdog_path),
                "watchdog_telemetry_sha256": common.sha256_file(watchdog_path),
            }
        )
        _COMPLETED_CELLS.append(name)
        benchmark_state(
            f"Completed workload {cell_index}/{len(selected)} · {name}",
            phase=f"workload:{name}:completed",
        )

    cells_by_name = {cell["name"]: cell for cell in selected}
    public_results = [
        public_benchmark_result(
            cells_by_name[row["cell"]],
            row["summary"],
            common.read_json_object(
                pathlib.Path(row["watchdog_telemetry"]), "Watchdog telemetry"
            )["samples"],
        )
        for row in rows
    ]
    assert arguments.installation_id is not None
    assert arguments.benchmark_timestamp_unix_ns is not None
    assert arguments.benchmark_contract_sha256 is not None
    if arguments.runtime_config is None:
        raise RuntimeMatrixError("--runtime-config is required for benchmark identity")
    runtime_source = common.read_json_object(
        arguments.runtime_config, "runtime configuration"
    )
    model = runtime_source.get("model")
    artifacts = runtime_source.get("artifacts")
    engine = runtime_source.get("engine")
    target = runtime_source.get("target")
    if not all(isinstance(item, dict) for item in (model, engine, target)) or not isinstance(
        artifacts, list
    ):
        raise RuntimeMatrixError("runtime configuration cannot produce a benchmark subject")
    primary = next(
        (
            artifact
            for artifact in artifacts
            if isinstance(artifact, dict) and artifact.get("name") == model.get("artifact")
        ),
        None,
    )
    engine_oci = engine.get("oci")
    if not isinstance(primary, dict) or not isinstance(engine_oci, dict):
        raise RuntimeMatrixError("runtime primary artifact or Engine OCI is unavailable")
    subject = {
        "candidate_id": runtime_source.get("id"),
        "runtime_version": runtime_source.get("version"),
        "model_uri": model.get("uri"),
        "model_revision": primary.get("revision"),
        "engine_oci": engine_oci.get("reference"),
        "target": target.get("id"),
        "target_contract_sha256": hashlib.sha256(
            benchmark_record.canonical_bytes(target)
        ).hexdigest(),
    }
    try:
        benchmark_record.validate_subject(subject)
    except benchmark_record.BenchmarkRecordError as error:
        raise RuntimeMatrixError(str(error)) from error
    public_results_sha = benchmark_record.results_sha256(public_results)
    public_record = {
        "schema_version": benchmark_record.SCHEMA_VERSION,
        "id": benchmark_record.benchmark_id(
            arguments.installation_id,
            arguments.benchmark_timestamp_unix_ns,
            subject,
            arguments.benchmark_contract_sha256,
            public_results_sha,
        ),
        "installation_id": arguments.installation_id,
        "timestamp": arguments.benchmark_timestamp_unix_ns // 1_000_000_000,
        "timestamp_unix_ns": arguments.benchmark_timestamp_unix_ns,
        "subject": subject,
        "benchmark_contract_sha256": arguments.benchmark_contract_sha256,
        "results_sha256": public_results_sha,
        "results": public_results,
    }
    try:
        benchmark_record.validate_record(public_record)
    except benchmark_record.BenchmarkRecordError as error:
        raise RuntimeMatrixError(str(error)) from error
    benchmark_path = output / "benchmark.json"
    common.write_json_atomic(benchmark_path, public_record)
    try:
        benchmark_record.read_record(benchmark_path)
    except benchmark_record.BenchmarkRecordError as error:
        raise RuntimeMatrixError(str(error)) from error
    benchmark_sha = common.sha256_file(benchmark_path)
    common.write_text_atomic(
        output / "benchmark.sha256", f"{benchmark_sha}  benchmark.json\n"
    )

    index = {
        "schema_version": 1,
        "contract": "letsinfer-isolated-runtime-matrix",
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "benchmark_id": public_record["id"],
        "installation_id": arguments.installation_id,
        "benchmark_timestamp_unix_ns": arguments.benchmark_timestamp_unix_ns,
        "benchmark_contract_sha256": arguments.benchmark_contract_sha256,
        "benchmark_record_sha256": benchmark_sha,
        "release": manifest["release"],
        "runtime_selector": runtime_selector,
        "runtime_manifest": str(manifest_path),
        "runtime_manifest_sha256": common.sha256_file(manifest_path),
        "measured_commit": arguments.measured_commit,
        "source_identity": source,
        "runner_sha256": common.sha256_file(pathlib.Path(__file__).resolve()),
        "prompt_plan": str(plan_path),
        "prompt_plan_sha256": common.sha256_file(plan_path),
        "prompt_materialization_sha256": (
            common.sha256_file(plan_path.parent / "materialization.json")
            if (plan_path.parent / "materialization.json").is_file()
            else None
        ),
        "selected_cells": [cell["name"] for cell in selected],
        "fresh_process_per_cell": True,
        "fresh_store_per_cell": True,
        "cells": rows,
        "qualification_passed": True,
    }
    index_path = output / "matrix-index.json"
    common.write_json_atomic(index_path, index)
    index_sha = common.sha256_file(index_path)
    common.write_text_atomic(
        output / "matrix-index.sha256", f"{index_sha}  matrix-index.json\n"
    )
    print(
        f"ISOLATED MATRIX PASS cells={len(rows)} index_sha256={index_sha} "
        f"evidence={output}",
        flush=True,
    )
    _CURRENT_CELL = None
    _write_benchmark_progress(
        "completed", f"Completed {len(rows)}/{len(selected)} workloads", "completed"
    )
    return 0


def main() -> int:
    global _PROGRESS_FILE, _PROGRESS_STARTED_UNIX_NS
    arguments = parse_arguments()
    _PROGRESS_FILE = arguments.progress_file
    _PROGRESS_STARTED_UNIX_NS = time.time_ns()
    if arguments.timeout <= 0:
        raise RuntimeMatrixError("--timeout must be positive")
    manifest_path, runtime_selector = resolve_runtime(
        arguments.runtime, arguments.letsinfer_bin
    )
    manifest = common.read_json_object(manifest_path, "runtime manifest")
    release, engine, model_id = common.validate_release_manifest(manifest)
    served_model = common.served_model_name(manifest)
    plan_path = arguments.prompt_plan
    benchmark_contract: dict[str, Any] | None = None
    if plan_path is not None:
        plan, cells = load_prompt_plan(plan_path, manifest)
        arguments.sample_interval_seconds = bind_sample_interval(
            arguments.sample_interval_seconds, plan
        )
    else:
        if arguments.runtime_config is None:
            raise RuntimeMatrixError(
                "--runtime-config is required when no materialized prompt plan is supplied"
            )
        benchmark_contract = load_benchmark_contract(
            arguments.runtime_config, manifest
        )
        cells = contract_cells(benchmark_contract)
        arguments.sample_interval_seconds = bind_sample_interval(
            arguments.sample_interval_seconds,
            {
                "sample_interval_seconds": benchmark_contract[
                    "sample_interval_seconds"
                ]
            },
        )
    concurrencies, contexts = selected_axes(arguments)
    selected = select_cells(
        cells, concurrencies, contexts, arguments.prompt_domain
    )
    capacity = validate_capacity(manifest, selected)
    if arguments.list:
        for cell in selected:
            print(cell["name"])
        return 0
    if arguments.output_directory is None:
        raise RuntimeMatrixError("--output-directory is required unless --list is used")
    if not arguments.active_container:
        required_identity = {
            "--installation-id": arguments.installation_id,
            "--benchmark-timestamp-unix-ns": arguments.benchmark_timestamp_unix_ns,
            "--benchmark-contract-sha256": arguments.benchmark_contract_sha256,
            "--watchdog-port": arguments.watchdog_port,
            "--watchdog-ca-file": arguments.watchdog_ca_file,
            "--watchdog-controller-cert-file": arguments.watchdog_controller_cert_file,
            "--watchdog-controller-key-file": arguments.watchdog_controller_key_file,
        }
        missing_identity = [
            flag for flag, value in required_identity.items() if value is None
        ]
        if missing_identity:
            raise RuntimeMatrixError(
                "benchmark identity is incomplete: " + ", ".join(missing_identity)
            )
        if benchmark_contract is not None:
            actual_contract_sha = hashlib.sha256(
                benchmark_record.canonical_bytes(benchmark_contract)
            ).hexdigest()
        else:
            assert plan_path is not None
            actual_contract_sha = common.sha256_file(plan_path)
        if arguments.benchmark_contract_sha256 != actual_contract_sha:
            raise RuntimeMatrixError("benchmark contract identity does not match its input")
        try:
            benchmark_record.benchmark_id(
                arguments.installation_id,
                arguments.benchmark_timestamp_unix_ns,
                {
                    "candidate_id": "placeholder--placeholder--placeholder--placeholder",
                    "runtime_version": "0.0.0",
                    "model_uri": "hf://placeholder/placeholder",
                    "model_revision": "0" * 40,
                    "engine_oci": "example.invalid/engine@sha256:" + "0" * 64,
                    "target": "placeholder",
                    "target_contract_sha256": "0" * 64,
                },
                arguments.benchmark_contract_sha256,
                "0" * 64,
            )
        except benchmark_record.BenchmarkRecordError as error:
            raise RuntimeMatrixError(str(error)) from error
    arguments.measured_commit = resolve_measured_commit(
        arguments.measured_commit, manifest
    )
    base_url = common.validate_base_url(arguments.base_url)
    source_root = pathlib.Path(__file__).resolve().parents[1]
    common.verify_letsinfer_release_sources(manifest, source_root)
    source = verified_source_identity(
        source_root,
        manifest_path,
        manifest,
        arguments.measured_commit,
        arguments.source_attestation,
    )
    if not arguments.active_container:
        return run_isolated_matrix(
            arguments,
            manifest_path,
            runtime_selector,
            manifest,
            plan_path,
            selected,
            source,
            benchmark_contract,
        )
    if plan_path is None:
        raise RuntimeMatrixError("active benchmark worker requires --prompt-plan")
    if arguments.output_directory.exists():
        raise RuntimeMatrixError(
            f"refusing existing output directory: {arguments.output_directory}"
        )
    api_key = common.read_private_file(arguments.api_key_file, "API-key file")
    if arguments.ca_cert_file.is_symlink() or not arguments.ca_cert_file.is_file():
        raise RuntimeMatrixError("CA certificate must be a regular non-symlink file")
    tls_context = ssl.create_default_context(cafile=str(arguments.ca_cert_file))
    container = arguments.container or discover_container(release)
    before_inspection = common.docker_inspect(container)
    before = common.validate_container(before_inspection, manifest)
    server_command = resolved_container_command(before_inspection)
    output = arguments.output_directory
    raw = output / "cells"
    raw.mkdir(parents=True)
    common.write_json_atomic(output / "container-before.json", before_inspection)
    preflight = common.preflight(
        base_url, tls_context, min(arguments.timeout, 30), api_key, served_model
    )
    preflight["post_load_memory"] = require_post_load_warning_headroom(manifest)
    monitor = load.TelemetryMonitor(
        output / "telemetry.jsonl",
        container,
        arguments.sample_interval_seconds,
        manifest["container"].get("runtime_min_available_gib", 16),
        arguments.watchdog_trip_file,
    )
    results: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    started = time.monotonic()
    failure: BaseException | None = None
    try:
        with monitor:
            if monitor.errors:
                raise RuntimeMatrixError(monitor.errors[0])
            for cell in selected:
                if not SAFE_CELL.fullmatch(cell["name"]):
                    raise RuntimeMatrixError(f"unsafe cell name: {cell['name']}")
                print(f"RUN {cell['name']}", flush=True)
                current = common.validate_container(
                    common.docker_inspect(container), manifest
                )
                if (
                    current["id"] != before["id"]
                    or current["started_at"] != before["started_at"]
                    or current["restart_count"] != before["restart_count"]
                ):
                    raise RuntimeMatrixError("runtime container changed before a cell")
                measurement_started_unix_ms = time.time_ns() // 1_000_000
                result = common.run_cell(
                    cell=cell,
                    phase="matrix",
                    base_url=base_url,
                    context=tls_context,
                    api_key=api_key,
                    model_id=served_model,
                    timeout=arguments.timeout,
                    stream_directory=raw / f"{cell['name']}-streams",
                )
                measurement_ended_unix_ms = time.time_ns() // 1_000_000
                validate_isolated_cache_evidence(cell, result)
                if monitor.errors:
                    raise RuntimeMatrixError(monitor.errors[0])
                summary = summarize(cell, result)
                summary["measurement_started_unix_ms"] = (
                    measurement_started_unix_ms
                )
                summary["measurement_ended_unix_ms"] = measurement_ended_unix_ms
                attach_sealed_comparison(summary, plan)
                common.write_json_atomic(raw / f"{cell['name']}.json", result)
                results.append(result)
                summaries.append(summary)
                print_summary(summary)
    except BaseException as error:
        failure = error
    after_inspection = common.docker_inspect(container)
    common.write_json_atomic(output / "container-after.json", after_inspection)
    if failure is not None:
        capture_container_logs(container, output)
    after: dict[str, Any] | None = None
    postcondition_error: BaseException | None = None
    try:
        after = common.validate_container(after_inspection, manifest)
    except BaseException as error:
        postcondition_error = error
    try:
        if postcondition_error is not None:
            if failure is not None:
                raise RuntimeMatrixError(
                    f"matrix failed ({type(failure).__name__}: {failure}); "
                    "container postcondition failed "
                    f"({type(postcondition_error).__name__}: {postcondition_error})"
                ) from failure
            raise postcondition_error
        assert after is not None
        if (
            after["id"] != before["id"]
            or after["started_at"] != before["started_at"]
            or after["restart_count"] != before["restart_count"]
        ):
            raise RuntimeMatrixError("runtime container changed during the matrix")
        if monitor.errors:
            raise RuntimeMatrixError(monitor.errors[0])
        if failure is not None:
            raise failure
    except BaseException as error:
        common.write_json_atomic(
            output / "failure.json",
            {
                "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "error_type": type(error).__name__,
                "error": str(error),
                "completed_cells": [row["cell"] for row in summaries],
            },
        )
        raise
    document = {
        "schema_version": 1,
        "contract": "letsinfer-sealed-runtime-matrix",
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "duration_seconds": time.monotonic() - started,
        "release": release,
        "runtime_manifest_sha256": common.sha256_file(manifest_path),
        "engine": engine,
        "model_id": model_id,
        "model_revision": common.model_revision(manifest),
        "target": common._manifest_value(manifest, "target.id"),
        "serving": manifest["serving"],
        "capacity": capacity,
        "source_identity": source,
        "measured_commit": arguments.measured_commit,
        "runner_sha256": common.sha256_file(pathlib.Path(__file__).resolve()),
        "prompt_plan_sha256": common.sha256_file(plan_path),
        "prompt_plan": plan,
        "selected_cells": [cell["name"] for cell in selected],
        "server_command": server_command,
        "server_command_sha256": common.sha256_text(server_command),
        "preflight": preflight,
        "container_before": before,
        "container_after": after,
        "summaries": summaries,
        "results": results,
        "qualification_passed": True,
        "evidence_directory": str(output),
    }
    results_path = output / "results.json"
    common.write_json_atomic(results_path, document)
    result_sha = common.sha256_file(results_path)
    common.write_text_atomic(output / "results.sha256", f"{result_sha}  results.json\n")
    block = (
        f"## `{arguments.measured_commit}` — {release} runtime matrix\n\n"
        f"- Cells: {len(summaries)}/{len(selected)} passed\n"
        f"- Runtime manifest SHA-256: `{common.sha256_file(manifest_path)}`\n"
        f"- Prompt plan SHA-256: `{common.sha256_file(plan_path)}`\n"
        f"- Results SHA-256: `{result_sha}`\n"
        f"- Evidence: `{output}`\n"
    )
    common.write_text_atomic(output / "bench-block.md", block)
    print(block)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeMatrixError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
