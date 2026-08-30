// SPDX-License-Identifier: AGPL-3.0-only

use li_benchmark_manager::{
    decode_benchmark_telemetry_state, encode_benchmark_telemetry_state, BenchmarkError,
    BenchmarkGitRevision, BenchmarkKind, BenchmarkProgress, BenchmarkRecordSchema,
    BenchmarkRequest, BenchmarkRunPlan, BenchmarkScope, BenchmarkSubject, BenchmarkTelemetryState,
    BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES,
};
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use serde_json::{json, Value};

// Parses one deterministic SHA-256 fixture identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Parses one deterministic operation identity.
fn operation(character: char) -> OperationId {
    OperationId::parse(&character.to_string().repeat(32)).expect("operation")
}

// Creates one exact immutable benchmark subject.
fn subject() -> BenchmarkSubject {
    BenchmarkSubject::new(
        InstallationId::parse(&"1".repeat(64)).expect("installation"),
        RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime installation"),
        LogicalModelName::parse("qwen-test").expect("model"),
        PlacementGroupId::parse(&"3".repeat(32)).expect("placement group"),
        digest('4'),
        digest('5'),
        digest('6'),
    )
}

// Creates one local diagnostic request whose ordered scope must survive serialization.
fn local_request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::selected(vec![
            TechnicalName::parse("32k-code-c1").expect("cell"),
            TechnicalName::parse("32k-prose-c4").expect("cell"),
        ])
        .expect("scope"),
        subject(),
    )
    .expect("request")
}

// Creates one complete community-verification request with every optional identity populated.
fn verification_request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::verification(
            42,
            BenchmarkGitRevision::parse(&"7".repeat(40)).expect("revision"),
            RuntimeCandidateId::parse("engine--owner--model--target").expect("candidate"),
            OperationId::parse(&"a".repeat(32)).expect("transaction"),
            digest('b'),
            digest('c'),
            73,
            digest('8'),
            Some(digest('9')),
        )
        .expect("verification"),
        BenchmarkScope::Complete,
        subject(),
    )
    .expect("request")
}

// Creates one exact plan from the supplied request and selected record shape.
fn plan(
    request: &BenchmarkRequest,
    record_schema: BenchmarkRecordSchema,
    total_cells: u32,
) -> BenchmarkRunPlan {
    BenchmarkRunPlan::new(request, record_schema, total_cells, 60_000, 5_000, 1_000).expect("plan")
}

// Creates one unsealed local timeline with exact progress and fixed sample windows.
fn local_state() -> BenchmarkTelemetryState {
    let plan = plan(
        &local_request(),
        BenchmarkRecordSchema::NativeExecutionPayloadV8,
        2,
    );
    BenchmarkTelemetryState::new(
        operation('a'),
        plan,
        digest('b'),
        digest('c'),
        UnixMilliseconds::new(10_000),
        Some(UnixMilliseconds::new(12_000)),
        2,
        digest('d'),
        Some(
            BenchmarkProgress::new(TechnicalName::parse("measuring").expect("phase"), 1, 2)
                .expect("progress"),
        ),
        None,
        None,
    )
    .expect("telemetry state")
}

// Creates one sealed verification timeline to exercise complete-scope and terminal fields.
fn sealed_verification_state() -> BenchmarkTelemetryState {
    let plan = plan(
        &verification_request(),
        BenchmarkRecordSchema::OciExecutionPayloadV7,
        4,
    );
    BenchmarkTelemetryState::new(
        operation('e'),
        plan,
        digest('f'),
        digest('0'),
        UnixMilliseconds::new(20_000),
        Some(UnixMilliseconds::new(24_000)),
        4,
        digest('1'),
        Some(
            BenchmarkProgress::new(TechnicalName::parse("complete").expect("phase"), 4, 4)
                .expect("progress"),
        ),
        Some(UnixMilliseconds::new(24_999)),
        Some(digest('2')),
    )
    .expect("telemetry state")
}

// Encodes one state and exposes its closed JSON value for targeted mutations.
fn document_value(state: &BenchmarkTelemetryState) -> Value {
    serde_json::from_slice(&encode_benchmark_telemetry_state(state).expect("encode")).expect("JSON")
}

// Replaces one string value addressed by an exact JSON pointer.
fn replace_string(document: &mut Value, pointer: &str, value: &str) {
    *document.pointer_mut(pointer).expect("pointer") = Value::String(value.to_string());
}

// Asserts that one structurally valid JSON mutation fails at the codec boundary.
fn assert_rejected(label: &str, document: Value) {
    let bytes = serde_json::to_vec(&document).expect("JSON");
    assert_eq!(
        decode_benchmark_telemetry_state(&bytes),
        Err(BenchmarkError::InvalidContract {
            reason: "benchmark telemetry document is invalid",
        }),
        "{label}"
    );
}

// Proves deterministic local-state round trips retain the complete request, scope, and progress.
#[test]
fn local_state_round_trip_is_deterministic_and_exact() {
    let state = local_state();
    let first = encode_benchmark_telemetry_state(&state).expect("first encoding");
    let second = encode_benchmark_telemetry_state(&state).expect("second encoding");
    assert_eq!(first, second);
    assert!(first.len() < BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES);

    let value: Value = serde_json::from_slice(&first).expect("JSON");
    assert_eq!(
        value["schema"],
        json!({"name": "li_benchmark_telemetry_state", "version": 1})
    );
    assert_eq!(value["state"]["plan"]["request"]["kind"]["mode"], "local");
    assert_eq!(
        value["state"]["plan"]["request"]["scope"],
        json!({"mode": "selected", "cells": ["32k-code-c1", "32k-prose-c4"]})
    );
    assert_eq!(
        decode_benchmark_telemetry_state(&first).expect("decode"),
        state
    );
    assert_eq!(
        encode_benchmark_telemetry_state(
            &decode_benchmark_telemetry_state(&first).expect("decode")
        )
        .expect("re-encode"),
        first
    );
}

// Proves the verification alternative, complete scope, optional baseline, and seal survive exactly.
#[test]
fn sealed_verification_state_round_trip_preserves_every_alternative() {
    let state = sealed_verification_state();
    let document = encode_benchmark_telemetry_state(&state).expect("encode");
    let value: Value = serde_json::from_slice(&document).expect("JSON");
    assert_eq!(
        value["state"]["plan"]["request"]["kind"],
        json!({
            "mode": "verification",
            "pull_request": 42,
            "proposal_head": "7".repeat(40),
            "candidate": "engine--owner--model--target",
            "transaction_id": "a".repeat(32),
            "verifier_bundle_sha256": "b".repeat(64),
            "candidate_subject_sha256": "c".repeat(64),
            "verifier_numeric_id": 73,
            "device_id": "8".repeat(64),
            "baseline_execution_sha256": "9".repeat(64),
        })
    );
    assert_eq!(
        value["state"]["plan"]["request"]["scope"],
        json!({"mode": "complete"})
    );
    assert_eq!(value["state"]["sealed_at_unix_milliseconds"], 24_999);
    assert_eq!(value["state"]["sealed_receipt_id"], "2".repeat(64));
    assert_eq!(
        decode_benchmark_telemetry_state(&document).expect("decode"),
        state
    );
}

// Proves every closed object boundary rejects fields outside the declared public contract.
#[test]
fn unknown_fields_are_rejected_at_every_object_boundary() {
    let ordinary = document_value(&local_state());
    for (label, pointer) in [
        ("root", ""),
        ("schema", "/schema"),
        ("state", "/state"),
        ("plan", "/state/plan"),
        ("request", "/state/plan/request"),
        ("kind", "/state/plan/request/kind"),
        ("scope", "/state/plan/request/scope"),
        ("subject", "/state/plan/request/subject"),
        ("progress", "/state/progress"),
    ] {
        let mut mutated = ordinary.clone();
        mutated
            .pointer_mut(pointer)
            .expect("pointer")
            .as_object_mut()
            .expect("object")
            .insert("future_field".to_string(), json!(true));
        assert_rejected(label, mutated);
    }
}

// Proves schema, identity, plan, request, progress, and timeline corruption fail closed.
#[test]
fn semantic_corruption_matrix_reapplies_domain_invariants() {
    let ordinary = document_value(&local_state());
    let mut mutations = Vec::new();

    let mut schema_name = ordinary.clone();
    replace_string(&mut schema_name, "/schema/name", "li_other_state");
    mutations.push(("schema name", schema_name));

    let mut schema_version = ordinary.clone();
    schema_version["schema"]["version"] = json!(2);
    mutations.push(("schema version", schema_version));

    let mut job_id = ordinary.clone();
    replace_string(&mut job_id, "/state/job_id", "not-an-operation");
    mutations.push(("job identity", job_id));

    let mut installation = ordinary.clone();
    replace_string(
        &mut installation,
        "/state/plan/request/subject/installation_id",
        &"a".repeat(32),
    );
    mutations.push(("installation identity", installation));

    let mut duplicate_cells = ordinary.clone();
    duplicate_cells["state"]["plan"]["request"]["scope"]["cells"] =
        json!(["32k-code-c1", "32k-code-c1"]);
    mutations.push(("duplicate cells", duplicate_cells));

    let mut total_cells = ordinary.clone();
    total_cells["state"]["plan"]["total_cells"] = json!(1);
    mutations.push(("plan cell count", total_cells));

    for field in [
        "plan_sha256",
        "request_sha256",
        "benchmark_contract_sha256",
        "execution_sha256",
        "target_contract_sha256",
    ] {
        let mut digest_binding = ordinary.clone();
        replace_string(
            &mut digest_binding,
            &format!("/state/plan/{field}"),
            &"f".repeat(64),
        );
        mutations.push((field, digest_binding));
    }

    let mut record_schema = ordinary.clone();
    replace_string(
        &mut record_schema,
        "/state/plan/record_schema",
        "future_schema_v9",
    );
    mutations.push(("record schema", record_schema));

    let mut progress = ordinary.clone();
    progress["state"]["progress"]["total_cells"] = json!(3);
    mutations.push(("progress total", progress));

    let mut sample_time = ordinary.clone();
    sample_time["state"]["last_sample_at_unix_milliseconds"] = json!(12_001);
    mutations.push(("sample timeline", sample_time));

    let mut sample_digest = ordinary.clone();
    replace_string(&mut sample_digest, "/state/samples_sha256", "not-a-digest");
    mutations.push(("sample digest", sample_digest));

    let mut incomplete_seal = ordinary.clone();
    incomplete_seal["state"]["sealed_at_unix_milliseconds"] = json!(12_000);
    mutations.push(("incomplete seal", incomplete_seal));

    for (label, mutation) in mutations {
        assert_rejected(label, mutation);
    }
}

// Proves empty, oversized, duplicate-key, and non-JSON input never reaches domain reconstruction.
#[test]
fn malformed_or_unbounded_documents_fail_before_reconstruction() {
    for (label, document) in [
        ("empty", Vec::new()),
        ("non-JSON", b"not JSON".to_vec()),
        (
            "duplicate root field",
            br#"{"schema":{"name":"li_benchmark_telemetry_state","version":1},"schema":{"name":"li_benchmark_telemetry_state","version":1},"state":{}}"#.to_vec(),
        ),
        (
            "oversized",
            vec![b' '; BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES + 1],
        ),
    ] {
        assert_eq!(
            decode_benchmark_telemetry_state(&document),
            Err(BenchmarkError::InvalidContract {
                reason: "benchmark telemetry document is invalid",
            }),
            "{label}"
        );
    }
}
