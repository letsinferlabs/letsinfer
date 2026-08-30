#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate li_-namespaced benchmark JSON Schemas against active Core contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import re
import unittest
from typing import Any

from benchmarks import benchmark_record
from benchmarks import li_benchmark_contract as runtime_packs


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "schemas" / "benchmark"
SCHEMA_FILES = {
    "common": "li_benchmark_common_v1.schema.json",
    "contract": "li_benchmark_contract_v8.schema.json",
    "result": "li_benchmark_result_v1.schema.json",
    "telemetry": "li_benchmark_telemetry_v1.schema.json",
    "record_oci": "li_benchmark_record_v7.schema.json",
    "record_native": "li_benchmark_record_v8.schema.json",
    "community_verification": "li_benchmark_community_verification_v1.schema.json",
}


class SchemaValidationError(ValueError):
    """A fixture violates the supported JSON Schema contract subset."""


# Loads one exact checked-in benchmark schema.
def load_schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMA_ROOT / SCHEMA_FILES[name]).read_text(encoding="utf-8"))


# Resolves one local or same-directory external JSON pointer.
def resolve_reference(reference: str, current: pathlib.Path) -> tuple[dict[str, Any], pathlib.Path]:
    path_value, separator, fragment = reference.partition("#")
    path = current if not path_value else (current.parent / path_value).resolve(strict=True)
    value: Any = json.loads(path.read_text(encoding="utf-8"))
    if separator and fragment:
        if not fragment.startswith("/"):
            raise SchemaValidationError("schema reference fragment is not a JSON pointer")
        for component in fragment[1:].split("/"):
            key = component.replace("~1", "/").replace("~0", "~")
            if not isinstance(value, dict) or key not in value:
                raise SchemaValidationError("schema reference is unresolved")
            value = value[key]
    if not isinstance(value, dict):
        raise SchemaValidationError("schema reference does not resolve to an object")
    return value, path


# Returns whether one Python value has the exact JSON type requested by a schema.
def has_type(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }[expected]


# Validates the strict JSON Schema subset used by the checked-in benchmark schemas.
def validate_schema(
    value: Any,
    schema: dict[str, Any],
    schema_path: pathlib.Path,
    where: str = "$",
) -> None:
    if "$ref" in schema:
        resolved, resolved_path = resolve_reference(str(schema["$ref"]), schema_path)
        validate_schema(value, resolved, resolved_path, where)
    for item in schema.get("allOf", []):
        validate_schema(value, item, schema_path, where)
    if "anyOf" in schema:
        for item in schema["anyOf"]:
            try:
                validate_schema(value, item, schema_path, where)
                break
            except SchemaValidationError:
                continue
        else:
            raise SchemaValidationError(f"{where} must match at least one schema")
    if "oneOf" in schema:
        matches = 0
        for item in schema["oneOf"]:
            try:
                validate_schema(value, item, schema_path, where)
            except SchemaValidationError:
                continue
            matches += 1
        if matches != 1:
            raise SchemaValidationError(f"{where} must match exactly one schema")
    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{where} differs from its constant")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError(f"{where} is outside its enum")
    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not has_type(value, expected_type):
        raise SchemaValidationError(f"{where} is not {expected_type}")
    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [name for name in required if name not in value]
        if missing:
            raise SchemaValidationError(f"{where} is missing {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise SchemaValidationError(f"{where} has unsupported fields {sorted(extra)}")
        for name, item in value.items():
            if name in properties:
                validate_schema(item, properties[name], schema_path, f"{where}.{name}")
    if isinstance(value, list):
        if len(value) < int(schema.get("minItems", 0)):
            raise SchemaValidationError(f"{where} has too few items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise SchemaValidationError(f"{where} has too many items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(encoded) != len(set(encoded)):
                raise SchemaValidationError(f"{where} contains duplicates")
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                validate_schema(item, schema["items"], schema_path, f"{where}[{index}]")
    if isinstance(value, str) and "pattern" in schema:
        if re.fullmatch(str(schema["pattern"]), value) is None:
            raise SchemaValidationError(f"{where} does not match its pattern")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaValidationError(f"{where} is below its minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaValidationError(f"{where} exceeds its maximum")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            raise SchemaValidationError(f"{where} is below its exclusive minimum")


# Returns one active schema-8 benchmark contract fixture.
def contract_fixture() -> dict[str, Any]:
    request = {
        "output_tokens": 128,
        "min_completion_tokens": 128,
        "require_natural_stop": False,
        "temperature": 0,
        "seed": 42042,
    }
    return {
        "schema_version": 8,
        "suite": "letsinfer-code-prose-v1",
        "generator": {"id": "letsinfer-code-prose", "version": 8},
        "domains": ["code"],
        "execution": {
            "isolation": "fresh-matrix",
            "prefix_state": "shared",
            "samples_per_cell": 1,
            "stream_prefix": "shared-body",
        },
        "tokenizer": {
            "capability": "engine-rendered-chat-count-v1",
            "model_sha256": "1" * 64,
            "engine_payload_sha256": "2" * 64,
            "render_contract": "openai-chat-user-v1",
        },
        "request": request,
        "short": {
            "domains": ["code", "prose"],
            "prompt_tokens": 256,
            "concurrencies": [1, 2, 4],
            "request": {
                **request,
                "output_tokens": 512,
                "min_completion_tokens": 512,
            },
        },
        "ttft_cache": {
            "prompt_tokens": 64000,
            "prompt_domain": "code",
            "repetitions": 2,
            "request": {
                **request,
                "output_tokens": 1,
                "min_completion_tokens": 1,
            },
        },
        "sample_interval_seconds": 5,
        "cases": [{"id": "32k", "prompt_tokens": 32768, "concurrencies": [1]}],
    }


# Returns one empty explicit telemetry timeline.
def telemetry_fixture() -> dict[str, Any]:
    return {
        "interval_seconds": None,
        "columns": list(benchmark_record.TELEMETRY_COLUMNS),
        "samples": [],
    }


# Returns one ordinary benchmark result whose declared maxima match its empty timeline.
def result_fixture() -> dict[str, Any]:
    return {
        "workload": "pp32768,tg128,c1",
        "prompt_domain": "code",
        "prompt_suite": "letsinfer-code-prose-v1",
        "prompt_set_sha256": "3" * 64,
        "actual_prompt_tokens": [32768],
        "aggregate_tps": 1.0,
        "decode_tps": 1.0,
        "ttft_seconds": 1.0,
        "ttft_statistic": "single",
        "ttft_p95_seconds": None,
        "is_prefix_cached": False,
        "max_gpu_usage_percent": None,
        "max_gpu_temperature_c": None,
        "max_cpu_temperature_c": None,
        "max_cpu_usage_percent": None,
        "max_cpu_clock_mhz": -1,
        "max_gpu_clock_mhz": -1,
        "max_vram_clock_mhz": -1,
        "max_system_ram_clock_mhz": -1,
        "max_nvme_usage_percent": -1,
        "max_nvme_temperature_c": -1,
        "max_nvme_read_kib_per_second": -1,
        "max_nvme_write_kib_per_second": -1,
        "telemetry": telemetry_fixture(),
    }


# Returns one hash-bound benchmark record for OCI or native execution payloads.
def record_fixture(native: bool) -> dict[str, Any]:
    contract = contract_fixture()
    results = [result_fixture()]
    contract_sha = hashlib.sha256(benchmark_record.canonical_bytes(contract)).hexdigest()
    results_sha = benchmark_record.results_sha256(results)
    subject = {
        "candidate_id": "fixture--owner--model--target",
        "runtime_version": "1.0.0",
        "model_uri": "hf://FixtureOrg/FixtureModel",
        "model_revision": "4" * 40,
        "engine_payload_sha256": "5" * 64,
        ("measured_engine_kind" if native else "measured_engine_oci"): (
            "native-archive"
            if native
            else f"ghcr.io/letsinferlabs/engine@sha256:{'6' * 64}"
        ),
        "target": "target",
        "target_contract_sha256": "7" * 64,
    }
    installation_id = "8" * 64
    timestamp_unix_ns = 1_000_000_000
    return {
        "schema_version": 8 if native else 7,
        "id": benchmark_record.benchmark_id(
            installation_id,
            timestamp_unix_ns,
            subject,
            contract_sha,
            results_sha,
        ),
        "installation_id": installation_id,
        "timestamp": 1,
        "timestamp_unix_ns": timestamp_unix_ns,
        "subject": subject,
        "benchmark_contract_sha256": contract_sha,
        "results_sha256": results_sha,
        "results": results,
        "benchmark_contract": contract,
    }


# Returns one closed blocking community-verification record fixture.
def community_verification_fixture() -> dict[str, Any]:
    subject = {
        "artifact_schema_version": 1,
        "repository": "letsinferlabs/runtimes",
        "pull_request": 41,
        "proposal_head_sha": "a" * 40,
        "proposal_base_sha": "b" * 40,
        "proposal_tree_sha256": "8" * 64,
        "candidate_id": "fixture--owner--model--target",
        "engine_mode": "reuse-engine",
        "build_workflow_run_id": 11,
        "runtime_version": "1.0.0",
        "runtime_pack_sha256": "1" * 64,
        "runtime_oci_manifest_digest": "sha256:" + "2" * 64,
        "engine_oci_manifest_digest": "sha256:" + "3" * 64,
        "model_revisions": [],
        "benchmark_contract_sha256": hashlib.sha256(
            benchmark_record.canonical_bytes(contract_fixture())
        ).hexdigest(),
        "target_contract_sha256": "4" * 64,
    }
    subject["execution_sha256"] = hashlib.sha256(
        benchmark_record.canonical_bytes(subject)
    ).hexdigest()
    return {
        "schema_version": 1,
        "kind": "letsinfer.runtime-verification",
        "repository": "letsinferlabs/runtimes",
        "pull_request": 41,
        "pull_request_url": "https://github.com/letsinferlabs/runtimes/pull/41",
        "observed_head_sha": "a" * 40,
        "submitted_at_unix": 1_787_465_000,
        "verifier": {
            "github_login": "Verifier",
            "github_id": 73,
            "github_type": "User",
        },
        "device_id": "5" * 64,
        "subject": subject,
        "candidate": None,
        "baseline": record_fixture(False),
        "run_order": ["baseline", "candidate"],
        "correctness": {"passed": True, "failures": 0},
        "safety": {
            "passed": False,
            "crashes": 1,
            "out_of_memory": 0,
            "protection_trips": 0,
            "output_validation_failures": 0,
        },
        "restoration": {"passed": True, "receipt_id": "6" * 64},
        "failure": {
            "category": "crash",
            "phase": "candidate",
            "message": "candidate failed",
        },
        "counts_toward_consensus": True,
        "run_score": None,
        "verification_id": "7" * 64,
    }


class BenchmarkSchemaTests(unittest.TestCase):
    """Keep checked-in JSON Schemas aligned with active semantic validators."""

    # Requires one closed li_-namespaced schema inventory with stable public IDs.
    def test_schema_inventory_is_closed_and_namespaced(self) -> None:
        actual = {path.name for path in SCHEMA_ROOT.glob("*.schema.json")}
        self.assertEqual(actual, set(SCHEMA_FILES.values()))
        for filename in sorted(actual):
            self.assertTrue(filename.startswith("li_benchmark_"))
            value = json.loads((SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
            self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(
                value["$id"],
                f"https://letsinfer.ai/schemas/benchmark/{filename}",
            )

    # Validates the active contract through both structural and semantic owners.
    def test_contract_schema_matches_active_schema_8_validator(self) -> None:
        value = contract_fixture()
        validate_schema(value, load_schema("contract"), SCHEMA_ROOT / SCHEMA_FILES["contract"])
        self.assertEqual(runtime_packs.validate_benchmark_contract(copy.deepcopy(value)), value)

    # Rejects every structural contract boundary in both schema and Core validator.
    def test_contract_mutation_matrix_fails_closed(self) -> None:
        mutations = (
            lambda value: value.pop("cases"),
            lambda value: value.__setitem__("unknown", True),
            lambda value: value.__setitem__("schema_version", 7),
            lambda value: value["generator"].__setitem__("version", 7),
            lambda value: value["tokenizer"].__setitem__("engine_payload_sha256", "bad"),
            lambda value: value["execution"].__setitem__("prefix_state", "private"),
            lambda value: value["short"].__setitem__("concurrencies", [1]),
            lambda value: value["ttft_cache"].__setitem__("prompt_tokens", 1),
            lambda value: value["cases"][0].__setitem__("concurrencies", [0]),
        )
        for mutate in mutations:
            value = contract_fixture()
            mutate(value)
            with self.assertRaises(SchemaValidationError):
                validate_schema(
                    value,
                    load_schema("contract"),
                    SCHEMA_ROOT / SCHEMA_FILES["contract"],
                )
            with self.assertRaises(runtime_packs.BenchmarkContractError):
                runtime_packs.validate_benchmark_contract(value)

    # Validates reusable result and telemetry shapes plus both current record unions.
    def test_result_telemetry_and_record_schemas_match_semantic_validator(self) -> None:
        validate_schema(
            telemetry_fixture(),
            load_schema("telemetry"),
            SCHEMA_ROOT / SCHEMA_FILES["telemetry"],
        )
        validate_schema(
            result_fixture(),
            load_schema("result"),
            SCHEMA_ROOT / SCHEMA_FILES["result"],
        )
        for name, native in (("record_oci", False), ("record_native", True)):
            value = record_fixture(native)
            validate_schema(value, load_schema(name), SCHEMA_ROOT / SCHEMA_FILES[name])
            self.assertEqual(benchmark_record.validate_record(copy.deepcopy(value)), value)

        verification = community_verification_fixture()
        validate_schema(
            verification,
            load_schema("community_verification"),
            SCHEMA_ROOT / SCHEMA_FILES["community_verification"],
        )

    # Rejects record subject, result, telemetry, and envelope mutations structurally.
    def test_record_mutation_matrix_fails_closed(self) -> None:
        mutations = (
            lambda value: value.pop("results"),
            lambda value: value.__setitem__("unknown", True),
            lambda value: value["subject"].__setitem__("measured_engine_kind", "oci"),
            lambda value: value["results"][0].__setitem__("aggregate_tps", 0),
            lambda value: value["results"][0]["telemetry"].__setitem__("columns", []),
            lambda value: value["results"][0].__setitem__("max_nvme_usage_percent", -2),
        )
        for mutate in mutations:
            value = record_fixture(True)
            mutate(value)
            with self.assertRaises(SchemaValidationError):
                validate_schema(
                    value,
                    load_schema("record_native"),
                    SCHEMA_ROOT / SCHEMA_FILES["record_native"],
                )
            with self.assertRaises(benchmark_record.BenchmarkRecordError):
                benchmark_record.validate_record(value)

    # Rejects public verification identity, failure, and restoration shape drift structurally.
    def test_community_verification_mutation_matrix_fails_closed(self) -> None:
        mutations = (
            lambda value: value.pop("observed_head_sha"),
            lambda value: value.__setitem__("unknown", True),
            lambda value: value.__setitem__("repository", "other/repository"),
            lambda value: value["verifier"].__setitem__("github_id", 0),
            lambda value: value["subject"].__setitem__("execution_sha256", "bad"),
            lambda value: value["failure"].__setitem__("category", "slow"),
            lambda value: value["restoration"].__setitem__("receipt_id", "bad"),
        )
        for mutate in mutations:
            value = community_verification_fixture()
            mutate(value)
            with self.assertRaises(SchemaValidationError):
                validate_schema(
                    value,
                    load_schema("community_verification"),
                    SCHEMA_ROOT / SCHEMA_FILES["community_verification"],
                )


if __name__ == "__main__":
    unittest.main()
