#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run Let's Infer's engine-neutral OpenAI-v1 qualification matrix.

The runner deliberately uses only the shared OpenAI API surface. Engine-
specific cache, scheduler, and speculative-decoding counters belong in
supplemental evidence; they are not guessed or silently omitted here.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, TextIO


PROTECTED_REQUEST_KEYS = {
    "max_completion_tokens",
    "max_tokens",
    "messages",
    "model",
    "n",
    "stream",
    "stream_options",
    "temperature",
}
EXPECTED_LABELS = {
    "io.letsinfer.managed": "true",
    "io.letsinfer.release": "release",
    "io.letsinfer.model": "model.alias",
    "io.letsinfer.engine": "engine.name",
}
BENCHMARK_MESSAGE_ROLES = {"system", "user"}


class QualificationError(RuntimeError):
    """The common qualification contract was not satisfied."""


def verify_letsinfer_release_sources(
    manifest: dict[str, Any], source_root: pathlib.Path
) -> None:
    """Verify immutable source bytes without importing product lifecycle code."""
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    try:
        from benchmarks.li_runtime_source_validation import (
            RuntimeSourceValidationError,
            verify_runtime_sources,
        )
    except ImportError as error:
        raise QualificationError(
            f"cannot import Let's Infer release validation: {error}"
        ) from error
    try:
        verify_runtime_sources(manifest, source_root)
    except RuntimeSourceValidationError as error:
        raise QualificationError(f"Let's Infer release verification failed: {error}") from error


def validate_release_sources(
    manifest: dict[str, Any], source_root: pathlib.Path
) -> tuple[str, str, str]:
    """Validate closed release semantics before touching immutable source bytes."""
    release = validate_release_manifest(manifest)
    verify_letsinfer_release_sources(manifest, source_root)
    return release


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Let's Infer OpenAI-compatible endpoint.",
    )
    parser.add_argument("--release-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--fixture-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--output-directory", type=pathlib.Path, required=True)
    parser.add_argument("--api-key-file", type=pathlib.Path, required=True)
    parser.add_argument("--ca-cert-file", type=pathlib.Path, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--measured-commit", required=True)
    parser.add_argument("--server-command-file", type=pathlib.Path, required=True)
    parser.add_argument(
        "--source-attestation",
        type=pathlib.Path,
        help=(
            "Clean-source JSON for deployment trees without .git. Required when "
            "the repository Git metadata is unavailable."
        ),
    )
    parser.add_argument("--timeout", type=int, default=3600)
    return parser.parse_args()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_text_atomic(path: pathlib.Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(value, encoding="utf-8")
    os.replace(temporary, path)


def write_json_atomic(path: pathlib.Path, value: object) -> None:
    write_text_atomic(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_json_object(path: pathlib.Path, name: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"cannot read {name} {path}: {error}") from error
    if not isinstance(value, dict):
        raise QualificationError(f"{name} must be a JSON object: {path}")
    return value


def require_string(mapping: dict[str, Any], key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise QualificationError(f"{where}.{key} must be a non-empty string")
    return value


def require_positive_int(mapping: dict[str, Any], key: str, where: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise QualificationError(f"{where}.{key} must be a positive integer")
    return value


def _manifest_value(manifest: dict[str, Any], path: str) -> str:
    value: Any = manifest
    for component in path.split("."):
        if not isinstance(value, dict):
            raise QualificationError(f"release manifest has no {path}")
        value = value.get(component)
    if not isinstance(value, str) or not value:
        raise QualificationError(f"release manifest has no {path}")
    return value


def model_artifact(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the exact artifact selected as the served model."""
    model = manifest.get("model")
    artifacts = manifest.get("artifacts")
    if not isinstance(model, dict) or not isinstance(artifacts, list):
        raise QualificationError("release manifest has no model artifact contract")
    name = require_string(model, "artifact", "release manifest.model")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("name") == name
    ]
    if len(matches) != 1:
        raise QualificationError("release manifest model artifact is ambiguous")
    return matches[0]


def model_revision(manifest: dict[str, Any]) -> str:
    return require_string(
        model_artifact(manifest), "revision", "release manifest model artifact"
    )


def validate_release_manifest(manifest: dict[str, Any]) -> tuple[str, str, str]:
    if type(manifest.get("schema_version")) is not int or manifest.get("schema_version") != 1:
        raise QualificationError("release manifest schema_version must be 1")
    release = require_string(manifest, "release", "release manifest")
    engine = manifest.get("engine")
    model = manifest.get("model")
    serving = manifest.get("serving")
    image = manifest.get("image")
    if not isinstance(engine, dict) or engine.get("api_protocol") != "openai-v1":
        raise QualificationError("release engine must declare api_protocol=openai-v1")
    if not isinstance(model, dict) or not isinstance(serving, dict):
        raise QualificationError("release manifest model/serving must be objects")
    if not isinstance(image, dict):
        raise QualificationError("release manifest image must be an object")
    engine_name = require_string(engine, "name", "release manifest.engine")
    model_id = require_string(model, "id", "release manifest.model")
    require_string(model, "alias", "release manifest.model")
    model_revision(manifest)
    require_string(image, "immutable_id", "release manifest.image")
    return release, engine_name, model_id


def served_model_name(manifest: dict[str, Any]) -> str:
    model = manifest.get("model")
    if not isinstance(model, dict):
        raise QualificationError("release manifest model must be an object")
    return require_string(model, "alias", "release manifest.model")


def contained_fixture(root: pathlib.Path, relative_text: str) -> pathlib.Path:
    relative = pathlib.Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise QualificationError(f"fixture path escapes its directory: {relative}")
    root_resolved = root.resolve(strict=True)
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise QualificationError(f"fixture must be a regular non-symlink file: {path}")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as error:
        raise QualificationError(f"fixture escapes its directory: {path}") from error
    return resolved


def validate_request_options(options: Any, where: str) -> dict[str, Any]:
    if options is None:
        return {}
    if not isinstance(options, dict):
        raise QualificationError(f"{where} must be an object")
    protected = sorted(PROTECTED_REQUEST_KEYS.intersection(options))
    if protected:
        raise QualificationError(
            f"{where} cannot override protected keys: {', '.join(protected)}"
        )
    return options


def validate_temperature(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise QualificationError(f"{where} must be a number")
    temperature = float(value)
    if not math.isfinite(temperature) or not 0.0 <= temperature <= 2.0:
        raise QualificationError(f"{where} must be from 0 through 2")
    return temperature


def load_fixture_message(
    root: pathlib.Path,
    row: dict[str, Any],
    where: str,
    *,
    default_role: str | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    role = default_role if default_role is not None else require_string(row, "role", where)
    if role not in BENCHMARK_MESSAGE_ROLES:
        raise QualificationError(
            f"{where}.role must be one of: {', '.join(sorted(BENCHMARK_MESSAGE_ROLES))}"
        )
    relative = require_string(row, "path", where)
    expected_sha = require_string(row, "sha256", where)
    if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
        raise QualificationError(f"{where}.sha256 must be lowercase SHA-256")
    fixture_path = contained_fixture(root, relative)
    actual_sha = sha256_file(fixture_path)
    if actual_sha != expected_sha:
        raise QualificationError(
            f"fixture message {relative} SHA-256 is {actual_sha}, expected {expected_sha}"
        )
    content = fixture_path.read_text(encoding="utf-8")
    if not content:
        raise QualificationError(f"fixture message is empty: {relative}")
    return (
        {"role": role, "content": content},
        {"role": role, "path": relative, "sha256": actual_sha},
    )


def load_fixture_contract(
    path: pathlib.Path,
    *,
    engine_name: str,
    model_id: str,
    model_revision: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    contract = read_json_object(path, "fixture manifest")
    schema_version = contract.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise QualificationError("fixture manifest schema_version must be 1")
    expected = {
        "engine": engine_name,
        "model_id": model_id,
        "model_revision": model_revision,
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            raise QualificationError(
                f"fixture manifest {key} must be {value!r}, got {contract.get(key)!r}"
            )
    tokenizer_identity = contract.get("tokenizer_identity")
    if not isinstance(tokenizer_identity, dict) or not tokenizer_identity:
        raise QualificationError("fixture manifest tokenizer_identity must be an object")
    default_options = validate_request_options(
        contract.get("request_options"), "fixture manifest.request_options"
    )
    default_temperature = validate_temperature(
        contract.get("temperature", 0), "fixture manifest.temperature"
    )
    fixture_rows = contract.get("fixtures")
    cell_rows = contract.get("cells")
    if not isinstance(fixture_rows, list) or not fixture_rows:
        raise QualificationError("fixture manifest fixtures must be a non-empty array")
    if not isinstance(cell_rows, list) or not cell_rows:
        raise QualificationError("fixture manifest cells must be a non-empty array")

    fixtures: list[dict[str, Any]] = []
    fixtures_by_name: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(fixture_rows):
        where = f"fixture manifest.fixtures[{index}]"
        if not isinstance(row, dict):
            raise QualificationError(f"{where} must be an object")
        name = require_string(row, "name", where)
        if name in fixtures_by_name:
            raise QualificationError(f"duplicate fixture name: {name}")
        message_rows = row.get("messages")
        if message_rows is None:
            message, public_message = load_fixture_message(
                path.parent, row, where, default_role="user"
            )
            messages = [message]
            public_messages = [public_message]
            fixture_sha = public_message["sha256"]
        else:
            if "path" in row or "sha256" in row:
                raise QualificationError(
                    f"{where} cannot combine messages with path or sha256"
                )
            if not isinstance(message_rows, list) or not message_rows:
                raise QualificationError(f"{where}.messages must be a non-empty array")
            messages = []
            public_messages = []
            for message_index, message_row in enumerate(message_rows):
                message_where = f"{where}.messages[{message_index}]"
                if not isinstance(message_row, dict):
                    raise QualificationError(f"{message_where} must be an object")
                message, public_message = load_fixture_message(
                    path.parent, message_row, message_where
                )
                messages.append(message)
                public_messages.append(public_message)
            if not any(message["role"] == "user" for message in messages):
                raise QualificationError(f"{where}.messages must contain a user message")
            fixture_sha = sha256_text(
                json.dumps(public_messages, sort_keys=True, separators=(",", ":"))
            )
        fixture = {
            "name": name,
            "sha256": fixture_sha,
            "messages": messages,
            "message_files": public_messages,
            "expected_prompt_tokens": require_positive_int(
                row, "expected_prompt_tokens", where
            ),
        }
        fixtures.append(fixture)
        fixtures_by_name[name] = fixture

    cells: list[dict[str, Any]] = []
    cell_names: set[str] = set()
    allocated_fixtures: set[str] = set()
    for index, row in enumerate(cell_rows):
        where = f"fixture manifest.cells[{index}]"
        if not isinstance(row, dict):
            raise QualificationError(f"{where} must be an object")
        name = require_string(row, "name", where)
        if name in cell_names:
            raise QualificationError(f"duplicate cell name: {name}")
        cell_names.add(name)
        names = row.get("fixtures")
        if not isinstance(names, list) or not names or not all(
            isinstance(item, str) and item for item in names
        ):
            raise QualificationError(f"{where}.fixtures must be a non-empty string array")
        if len(names) != len(set(names)):
            raise QualificationError(f"{where}.fixtures contains duplicates")
        missing = sorted(set(names) - fixtures_by_name.keys())
        if missing:
            raise QualificationError(f"{where} names unknown fixtures: {', '.join(missing)}")
        reused = sorted(set(names).intersection(allocated_fixtures))
        if reused:
            raise QualificationError(
                f"fixtures must be globally disjoint across cells: {', '.join(reused)}"
            )
        allocated_fixtures.update(names)
        natural_stop = row.get("require_natural_stop")
        if not isinstance(natural_stop, bool):
            raise QualificationError(f"{where}.require_natural_stop must be boolean")
        options = dict(default_options)
        options.update(validate_request_options(row.get("request_options"), f"{where}.request_options"))
        temperature = validate_temperature(
            row.get("temperature", default_temperature), f"{where}.temperature"
        )
        cells.append(
            {
                "name": name,
                "fixtures": [fixtures_by_name[item] for item in names],
                "max_tokens": require_positive_int(row, "max_tokens", where),
                "min_completion_tokens": require_positive_int(
                    row, "min_completion_tokens", where
                ),
                "require_natural_stop": natural_stop,
                "request_options": options,
                "temperature": temperature,
            }
        )
    return fixtures, cells, tokenizer_identity


def read_private_file(path: pathlib.Path, name: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise QualificationError(f"{name} must be a regular non-symlink file: {path}")
    if path.stat().st_mode & 0o077:
        raise QualificationError(f"{name} permissions must be 0600 or stricter: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise QualificationError(f"{name} is empty: {path}")
    return value


def validate_base_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.query or parsed.fragment:
        raise QualificationError("base URL must be a plain http(s):// host[:port] URL")
    if parsed.path not in {"", "/"}:
        raise QualificationError("base URL cannot contain a path")
    return value.rstrip("/")


def request_json(
    *,
    url: str,
    context: ssl.SSLContext,
    timeout: int,
    api_key: str | None,
) -> tuple[int, Any]:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key is not None else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read()
            try:
                payload = json.loads(body.decode("utf-8")) if body else None
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = None
            return response.status, payload
    except urllib.error.HTTPError as error:
        body = error.read()
        try:
            payload = json.loads(body.decode("utf-8")) if body else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        return error.code, payload


def inference_auth_status(
    base_url: str,
    context: ssl.SSLContext,
    timeout: int,
    api_key: str | None,
) -> int:
    """Probe chat auth before validation without invoking model generation."""
    headers = {"Content-Type": "application/json"}
    if api_key is not None:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        f"{base_url}/v1/chat/completions",
        data=b"{}",
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def preflight(
    base_url: str,
    context: ssl.SSLContext,
    timeout: int,
    api_key: str,
    model_id: str,
) -> dict[str, Any]:
    health_status, _ = request_json(
        url=f"{base_url}/health", context=context, timeout=timeout, api_key=None
    )
    anonymous_inference_status = inference_auth_status(
        base_url, context, timeout, None
    )
    authenticated_inference_status = inference_auth_status(
        base_url, context, timeout, api_key
    )
    authenticated_status, models = request_json(
        url=f"{base_url}/v1/models", context=context, timeout=timeout, api_key=api_key
    )
    data = models.get("data") if isinstance(models, dict) else None
    exact_model = isinstance(data, list) and any(
        isinstance(item, dict) and item.get("id") == model_id for item in data
    )
    if health_status != 200:
        raise QualificationError(f"health endpoint returned HTTP {health_status}")
    if anonymous_inference_status != 401:
        raise QualificationError(
            "anonymous inference probe returned HTTP "
            f"{anonymous_inference_status}, expected 401"
        )
    if authenticated_inference_status not in {400, 422}:
        raise QualificationError(
            "authenticated inference probe returned HTTP "
            f"{authenticated_inference_status}, expected request validation"
        )
    if authenticated_status != 200 or not exact_model:
        raise QualificationError("authenticated /v1/models did not return the exact model")
    return {
        "health_status": health_status,
        "anonymous_inference_status": anonymous_inference_status,
        "authenticated_inference_probe_status": authenticated_inference_status,
        "authenticated_models_status": authenticated_status,
        "exact_model_identity": exact_model,
    }


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, check=False, text=True, capture_output=True)
    except FileNotFoundError as error:
        raise QualificationError(f"required command is unavailable: {command[0]}") from error


def docker_inspect(container: str) -> dict[str, Any]:
    result = run_command(["docker", "container", "inspect", container])
    if result.returncode != 0:
        raise QualificationError(
            f"cannot inspect container {container}: {(result.stderr or result.stdout).strip()}"
        )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise QualificationError(f"invalid Docker inspection: {error}") from error
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise QualificationError("Docker inspection did not return one object")
    return value[0]


def validate_container(
    inspection: dict[str, Any],
    manifest: dict[str, Any],
    *,
    require_docker_health: bool = True,
) -> dict[str, Any]:
    state = inspection.get("State")
    config = inspection.get("Config")
    if not isinstance(state, dict) or not isinstance(config, dict):
        raise QualificationError("Docker inspection omits State or Config")
    labels = config.get("Labels") or {}
    expected = {
        label: "true" if path == "true" else _manifest_value(manifest, path)
        for label, path in EXPECTED_LABELS.items()
    }
    mismatches = [key for key, value in expected.items() if labels.get(key) != value]
    if mismatches:
        raise QualificationError(
            f"container identity mismatch: {', '.join(sorted(mismatches))}"
        )
    if inspection.get("Image") != manifest["image"]["immutable_id"]:
        raise QualificationError("container image differs from release immutable_id")
    health = state.get("Health") or {}
    summary = {
        "id": inspection.get("Id"),
        "image": inspection.get("Image"),
        "running": state.get("Running") is True,
        "status": state.get("Status"),
        "health": health.get("Status"),
        "oom_killed": state.get("OOMKilled") is True,
        "restart_count": inspection.get("RestartCount"),
        "started_at": state.get("StartedAt"),
        "labels": {key: labels.get(key) for key in sorted(expected)},
    }
    if not summary["running"] or (
        require_docker_health and summary["health"] != "healthy"
    ):
        raise QualificationError("container is not running and healthy")
    if summary["oom_killed"]:
        raise QualificationError("container reports OOMKilled")
    if not isinstance(summary["restart_count"], int) or isinstance(
        summary["restart_count"], bool
    ):
        raise QualificationError("container restart count is unavailable")
    return summary


def source_identity(
    source_root: pathlib.Path,
    measured_commit: str,
    attestation_path: pathlib.Path | None,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", measured_commit):
        raise QualificationError("measured commit must be a full 40-hex Git identity")
    git_directory = source_root / ".git"
    if git_directory.exists():
        head = run_command(["git", "-C", str(source_root), "rev-parse", "HEAD"])
        commit = run_command(
            ["git", "-C", str(source_root), "rev-parse", f"{measured_commit}^{{commit}}"]
        )
        status = run_command(
            ["git", "-C", str(source_root), "status", "--porcelain", "--untracked-files=all"]
        )
        if head.returncode or commit.returncode or status.returncode:
            raise QualificationError("could not verify the source Git identity")
        if head.stdout.strip() != commit.stdout.strip():
            raise QualificationError("measured commit is not the current HEAD")
        if status.stdout:
            raise QualificationError("source tree is not clean; refusing performance evidence")
        tree = run_command(["git", "-C", str(source_root), "rev-parse", "HEAD^{tree}"])
        if tree.returncode:
            raise QualificationError("could not resolve the source tree identity")
        return {
            "kind": "live-clean-git",
            "commit": head.stdout.strip(),
            "tree": tree.stdout.strip(),
        }
    if attestation_path is None:
        raise QualificationError(
            "deployment tree has no .git; --source-attestation is required"
        )
    attestation = read_json_object(attestation_path, "source attestation")
    if (
        type(attestation.get("schema_version")) is not int
        or attestation.get("schema_version") != 1
        or attestation.get("clean") is not True
    ):
        raise QualificationError("source attestation must be schema 1 and clean=true")
    if attestation.get("commit") != measured_commit:
        raise QualificationError("source attestation commit does not match --measured-commit")
    require_string(attestation, "tree", "source attestation")
    return {
        "kind": "deployment-attestation",
        "commit": measured_commit,
        "tree": attestation["tree"],
        "attestation_sha256": sha256_file(attestation_path),
    }


def _write_stream_journal(
    journal: TextIO | None, record: dict[str, Any]
) -> None:
    if journal is None:
        return
    journal.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    journal.flush()


def _measure_stream(
    *,
    base_url: str,
    context: ssl.SSLContext,
    api_key: str,
    model_id: str,
    fixture: dict[str, Any],
    max_tokens: int,
    min_completion_tokens: int,
    require_natural_stop: bool,
    request_options: dict[str, Any],
    temperature: float,
    timeout: int,
    barrier: threading.Barrier,
    journal: TextIO | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model_id,
        "messages": fixture["messages"],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    payload.update(request_options)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/v1/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    barrier.wait(timeout=30)
    started_wall = dt.datetime.now(dt.timezone.utc).isoformat()
    started = time.perf_counter()
    events: list[dict[str, Any]] = []
    output_parts: list[str] = []
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    output_arrivals: list[float] = []
    usage: dict[str, Any] | None = None
    finish_reasons: list[str] = []
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            if response.status != 200:
                raise QualificationError(f"chat completion returned HTTP {response.status}")
            for raw_line in response:
                elapsed = time.perf_counter() - started
                line = raw_line.decode("utf-8", errors="strict").strip()
                _write_stream_journal(
                    journal,
                    {
                        "arrival_ms": elapsed * 1000.0,
                        "kind": "response-line",
                        "line": line,
                    },
                )
                if not line.startswith("data:"):
                    continue
                text = line[5:].strip()
                if not text or text == "[DONE]":
                    continue
                try:
                    event = json.loads(text)
                except json.JSONDecodeError as error:
                    raise QualificationError(f"invalid SSE JSON: {error}") from error
                if not isinstance(event, dict):
                    raise QualificationError("SSE event must be a JSON object")
                events.append({"arrival_ms": elapsed * 1000.0, "event": event})
                if isinstance(event.get("usage"), dict):
                    usage = event["usage"]
                choices = event.get("choices") or []
                if not isinstance(choices, list):
                    raise QualificationError("SSE choices must be an array")
                for choice in choices:
                    if not isinstance(choice, dict):
                        continue
                    finish = choice.get("finish_reason")
                    if isinstance(finish, str):
                        finish_reasons.append(finish)
                    delta = choice.get("delta") or {}
                    if not isinstance(delta, dict):
                        continue
                    for key, destination in (
                        ("reasoning_content", reasoning_parts),
                        ("content", content_parts),
                    ):
                        part = delta.get(key)
                        if isinstance(part, str) and part:
                            destination.append(part)
                            output_parts.append(part)
                            output_arrivals.append(elapsed)
            _write_stream_journal(
                journal,
                {
                    "arrival_ms": (time.perf_counter() - started) * 1000.0,
                    "kind": "response-eof",
                },
            )
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise QualificationError(
            f"chat completion returned HTTP {error.code}: {detail}"
        ) from error
    completed = time.perf_counter()
    if not output_parts or not output_arrivals:
        raise QualificationError("stream returned no output text")
    if usage is None:
        raise QualificationError("stream returned no OpenAI usage object")
    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    if (
        not isinstance(prompt_tokens, int)
        or isinstance(prompt_tokens, bool)
        or prompt_tokens != fixture["expected_prompt_tokens"]
    ):
        raise QualificationError(
            f"fixture {fixture['name']} prompt token drift: {prompt_tokens!r} "
            f"!= {fixture['expected_prompt_tokens']}"
        )
    if (
        not isinstance(completion_tokens, int)
        or isinstance(completion_tokens, bool)
        or completion_tokens < min_completion_tokens
    ):
        raise QualificationError(
            f"fixture {fixture['name']} completion token count {completion_tokens!r} "
            f"is below {min_completion_tokens}"
        )
    if completion_tokens > max_tokens:
        raise QualificationError("completion token count exceeds max_tokens")
    if require_natural_stop and "length" in finish_reasons:
        raise QualificationError(f"fixture {fixture['name']} stopped at the token limit")
    ttft = output_arrivals[0]
    last_output = output_arrivals[-1]
    decode_seconds = last_output - ttft
    decode_rate = (
        (completion_tokens - 1) / decode_seconds
        if completion_tokens > 1 and decode_seconds > 0
        else None
    )
    output = "".join(output_parts)
    prompt_details = usage.get("prompt_tokens_details")
    if not isinstance(prompt_details, dict):
        prompt_details = {}
    cached_tokens = prompt_details.get("cached_tokens")
    cache_write_tokens = prompt_details.get("cache_write_tokens")
    return {
        "fixture": fixture["name"],
        "fixture_sha256": fixture["sha256"],
        "fixture_messages": fixture["message_files"],
        "started_at": started_wall,
        "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "wall_ms": (completed - started) * 1000.0,
        "ttft_ms": ttft * 1000.0,
        "last_output_ms": last_output * 1000.0,
        "decode_tokens_per_second": decode_rate,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "cached_prompt_tokens": (
            cached_tokens
            if isinstance(cached_tokens, int)
            and not isinstance(cached_tokens, bool)
            and cached_tokens >= 0
            else None
        ),
        "cache_write_tokens": (
            cache_write_tokens
            if isinstance(cache_write_tokens, int)
            and not isinstance(cache_write_tokens, bool)
            and cache_write_tokens >= 0
            else None
        ),
        "usage": usage,
        "finish_reasons": finish_reasons,
        "output_sha256": sha256_text(output),
        "output_bytes": len(output.encode("utf-8")),
        "output": output,
        "content": "".join(content_parts),
        "reasoning_content": "".join(reasoning_parts),
        "events": events,
    }


def measure_stream(
    *,
    base_url: str,
    context: ssl.SSLContext,
    api_key: str,
    model_id: str,
    fixture: dict[str, Any],
    max_tokens: int,
    min_completion_tokens: int,
    require_natural_stop: bool,
    request_options: dict[str, Any],
    temperature: float,
    timeout: int,
    barrier: threading.Barrier,
    stream_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    journal = None
    try:
        if stream_path is not None:
            journal = stream_path.open("x", encoding="utf-8", buffering=1)
            _write_stream_journal(
                journal,
                {
                    "fixture": fixture["name"],
                    "fixture_sha256": fixture["sha256"],
                    "kind": "request",
                    "max_tokens": max_tokens,
                    "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                },
            )
        result = _measure_stream(
            base_url=base_url,
            context=context,
            api_key=api_key,
            model_id=model_id,
            fixture=fixture,
            max_tokens=max_tokens,
            min_completion_tokens=min_completion_tokens,
            require_natural_stop=require_natural_stop,
            request_options=request_options,
            temperature=temperature,
            timeout=timeout,
            barrier=barrier,
            journal=journal,
        )
        _write_stream_journal(
            journal,
            {
                "completed_at": result["completed_at"],
                "kind": "accepted",
                "output_sha256": result["output_sha256"],
                "usage": result["usage"],
            },
        )
        return result
    except BaseException as error:
        _write_stream_journal(
            journal,
            {
                "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "error": str(error),
                "error_type": type(error).__name__,
                "kind": "error",
            },
        )
        raise
    finally:
        if journal is not None:
            journal.close()


def run_cell(
    *,
    cell: dict[str, Any],
    phase: str,
    base_url: str,
    context: ssl.SSLContext,
    api_key: str,
    model_id: str,
    timeout: int,
    stream_directory: pathlib.Path | None = None,
) -> dict[str, Any]:
    fixtures = cell["fixtures"]
    if stream_directory is not None:
        stream_directory.mkdir(parents=True, exist_ok=False)
    barrier = threading.Barrier(len(fixtures))
    batch_started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fixtures)) as pool:
        futures = [
            pool.submit(
                measure_stream,
                base_url=base_url,
                context=context,
                api_key=api_key,
                model_id=model_id,
                fixture=fixture,
                max_tokens=cell["max_tokens"],
                min_completion_tokens=cell["min_completion_tokens"],
                require_natural_stop=cell["require_natural_stop"],
                request_options=cell["request_options"],
                temperature=cell["temperature"],
                timeout=timeout,
                barrier=barrier,
                stream_path=(
                    stream_directory / f"{index:02d}.jsonl"
                    if stream_directory is not None
                    else None
                ),
            )
            for index, fixture in enumerate(fixtures)
        ]
        rows = [future.result() for future in futures]
    wall_seconds = time.perf_counter() - batch_started
    total_tokens = sum(row["completion_tokens"] for row in rows)
    return {
        "cell": cell["name"],
        "phase": phase,
        "streams": len(rows),
        "max_tokens": cell["max_tokens"],
        "min_completion_tokens": cell["min_completion_tokens"],
        "require_natural_stop": cell["require_natural_stop"],
        "request_options": cell["request_options"],
        "temperature": cell["temperature"],
        "batch_wall_ms": wall_seconds * 1000.0,
        "job_completion_tokens_per_second": (
            total_tokens / wall_seconds if wall_seconds > 0 else None
        ),
        "completion_tokens": total_tokens,
        "requests": rows,
    }


def public_cell(cell: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": cell["name"],
        "fixtures": [fixture["name"] for fixture in cell["fixtures"]],
        "max_tokens": cell["max_tokens"],
        "min_completion_tokens": cell["min_completion_tokens"],
        "require_natural_stop": cell["require_natural_stop"],
        "request_options": cell["request_options"],
        "temperature": cell["temperature"],
    }


def assert_pair_equal(first: dict[str, Any], repeat: dict[str, Any]) -> bool:
    first_rows = {row["fixture"]: row for row in first["requests"]}
    repeat_rows = {row["fixture"]: row for row in repeat["requests"]}
    return first_rows.keys() == repeat_rows.keys() and all(
        first_rows[name]["output"] == repeat_rows[name]["output"]
        and first_rows[name]["completion_tokens"] == repeat_rows[name]["completion_tokens"]
        and first_rows[name]["finish_reasons"] == repeat_rows[name]["finish_reasons"]
        for name in first_rows
    )


def main() -> int:
    arguments = parse_arguments()
    if arguments.timeout <= 0:
        raise QualificationError("--timeout must be positive")
    if arguments.output_directory.exists():
        raise QualificationError(
            f"refusing existing output directory: {arguments.output_directory}"
        )
    base_url = validate_base_url(arguments.base_url)
    manifest = read_json_object(arguments.release_manifest, "release manifest")
    source_root = pathlib.Path(__file__).resolve().parents[1]
    release, engine_name, model_id = validate_release_sources(manifest, source_root)
    served_model = served_model_name(manifest)
    model_revision_value = model_revision(manifest)
    _, cells, tokenizer_identity = load_fixture_contract(
        arguments.fixture_manifest,
        engine_name=engine_name,
        model_id=model_id,
        model_revision=model_revision_value,
    )
    api_key = read_private_file(arguments.api_key_file, "API-key file")
    if arguments.ca_cert_file.is_symlink() or not arguments.ca_cert_file.is_file():
        raise QualificationError("CA certificate must be a regular non-symlink file")
    tls_context = ssl.create_default_context(cafile=str(arguments.ca_cert_file))
    server_command = arguments.server_command_file.read_text(encoding="utf-8").strip()
    if not server_command:
        raise QualificationError("server command file is empty")
    if api_key in server_command:
        raise QualificationError("server command file contains the API-key value")
    source = source_identity(
        source_root, arguments.measured_commit, arguments.source_attestation
    )

    raw_directory = arguments.output_directory / "raw"
    raw_directory.mkdir(parents=True)
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    before_inspection = docker_inspect(arguments.container)
    before = validate_container(before_inspection, manifest)
    write_json_atomic(raw_directory / "container-before.json", before_inspection)
    preflight_result = preflight(
        base_url, tls_context, min(arguments.timeout, 30), api_key, served_model
    )
    results: list[dict[str, Any]] = []
    pair_equality: dict[str, bool] = {}
    try:
        for cell in cells:
            phases: dict[str, dict[str, Any]] = {}
            for phase in ("first", "immediate-repeat"):
                print(f"{cell['name']} {phase}", file=sys.stderr, flush=True)
                row = run_cell(
                    cell=cell,
                    phase=phase,
                    base_url=base_url,
                    context=tls_context,
                    api_key=api_key,
                    model_id=served_model,
                    timeout=arguments.timeout,
                    stream_directory=(
                        raw_directory / f"{cell['name']}-{phase}-streams"
                    ),
                )
                phases[phase] = row
                write_json_atomic(
                    raw_directory / f"{cell['name']}-{phase}.json", row
                )
                results.append(row)
            equal = assert_pair_equal(phases["first"], phases["immediate-repeat"])
            pair_equality[cell["name"]] = equal
            if not equal:
                raise QualificationError(
                    f"first/immediate-repeat output divergence in {cell['name']}"
                )
    except BaseException as error:
        write_json_atomic(
            arguments.output_directory / "failure.json",
            {
                "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "error_type": type(error).__name__,
                "error": str(error),
            },
        )
        raise
    finally:
        after_inspection = docker_inspect(arguments.container)
        write_json_atomic(raw_directory / "container-after.json", after_inspection)

    after = validate_container(after_inspection, manifest)
    if after["restart_count"] != before["restart_count"]:
        raise QualificationError("container restart count changed during the matrix")
    if after["id"] != before["id"] or after["started_at"] != before["started_at"]:
        raise QualificationError("container identity/start time changed during the matrix")
    nvidia = run_command(
        [
            "nvidia-smi",
            "--query-gpu=timestamp,name,temperature.gpu,memory.used,memory.total",
            "--format=csv,noheader,nounits",
        ]
    )
    write_text_atomic(
        raw_directory / "nvidia-smi.txt", (nvidia.stdout or "") + (nvidia.stderr or "")
    )
    if nvidia.returncode != 0 or not nvidia.stdout.strip():
        raise QualificationError("nvidia-smi telemetry failed")
    meminfo = pathlib.Path("/proc/meminfo").read_text(encoding="utf-8")
    write_text_atomic(raw_directory / "meminfo.txt", meminfo)
    runner_path = pathlib.Path(__file__).resolve()
    document = {
        "schema_version": 1,
        "contract": "letsinfer-openai-v1-common",
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "started_at": started_at,
        "release": release,
        "release_manifest_sha256": sha256_file(arguments.release_manifest),
        "engine": engine_name,
        "model_id": model_id,
        "model_revision": model_revision,
        "serving": manifest["serving"],
        "serving_was_qualified": manifest["serving"].get("qualified"),
        "measured_commit": arguments.measured_commit,
        "source_identity": source,
        "runner_sha256": sha256_file(runner_path),
        "fixture_manifest_sha256": sha256_file(arguments.fixture_manifest),
        "tokenizer_identity": tokenizer_identity,
        "server_command": server_command,
        "server_command_sha256": sha256_text(server_command),
        "preflight": preflight_result,
        "container_before": before,
        "container_after": after,
        "nvidia_smi_exit_code": nvidia.returncode,
        "cells": [public_cell(cell) for cell in cells],
        "first_repeat_equal": pair_equality,
        "results": results,
        "qualification_passed": all(pair_equality.values()),
        "scope_note": (
            "This common OpenAI-v1 gate does not claim engine-specific cache reuse, "
            "scheduler, or speculative-decoding behavior. Supplemental engine evidence "
            "is required by the release serving contract."
        ),
        "evidence_directory": str(arguments.output_directory),
    }
    results_path = arguments.output_directory / "results.json"
    write_json_atomic(results_path, document)
    results_sha = sha256_file(results_path)
    write_text_atomic(
        arguments.output_directory / "results.sha256", f"{results_sha}  results.json\n"
    )
    block = (
        f"## `{arguments.measured_commit}` — {release}\n\n"
        f"- Engine: `{engine_name}`\n"
        f"- Common OpenAI-v1 cells: {len(cells)} passed\n"
        f"- First/immediate-repeat equality: {sum(pair_equality.values())}/{len(cells)}\n"
        f"- Results SHA-256: `{results_sha}`\n"
        f"- Evidence: `{arguments.output_directory}`\n"
    )
    write_text_atomic(arguments.output_directory / "bench-block.md", block)
    print(block)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except QualificationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
