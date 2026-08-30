// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_benchmark_worker::{
    run_native_benchmark_controlled, BenchmarkWorkerError, NativeBenchmarkClock,
    NativeBenchmarkStreamMeasurement, NativeBenchmarkStreamRequest, NativeBenchmarkTelemetrySource,
    NativeBenchmarkTransport, NativeBenchmarkWorkerInput,
};
use li_watchdog_manager::{WatchdogSample, WatchdogSampleTelemetry};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// Returns compact canonical JSON with one trailing newline.
fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("JSON");
    bytes.push(b'\n');
    bytes
}

// Hashes exact bytes into lowercase SHA-256 text.
fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

// Returns one complete active native schema-8 benchmark contract.
fn contract() -> Value {
    json!({
        "schema_version": 8,
        "suite": "letsinfer-code-prose-v1",
        "generator": {"id": "letsinfer-code-prose", "version": 8},
        "domains": ["code", "prose"],
        "execution": {
            "isolation": "fresh-context",
            "prefix_state": "shared",
            "samples_per_cell": 1,
            "stream_prefix": "shared-body"
        },
        "tokenizer": {
            "capability": "engine-rendered-chat-count-v1",
            "model_sha256": "1".repeat(64),
            "engine_payload_sha256": "2".repeat(64),
            "render_contract": "openai-chat-user-v1"
        },
        "request": {
            "output_tokens": 8,
            "min_completion_tokens": 1,
            "require_natural_stop": true,
            "temperature": 0,
            "seed": 7
        },
        "short": {
            "domains": ["code", "prose"],
            "prompt_tokens": 256,
            "concurrencies": [1, 2, 4],
            "request": {
                "output_tokens": 8,
                "min_completion_tokens": 1,
                "require_natural_stop": true,
                "temperature": 0,
                "seed": 7
            }
        },
        "ttft_cache": {
            "prompt_tokens": 64000,
            "prompt_domain": "code",
            "repetitions": 2,
            "request": {
                "output_tokens": 1,
                "min_completion_tokens": 1,
                "require_natural_stop": false,
                "temperature": 0,
                "seed": 7
            }
        },
        "sample_interval_seconds": 1,
        "cases": [
            {"id": "32k", "prompt_tokens": 32768, "concurrencies": [1, 2, 4]},
            {"id": "64k", "prompt_tokens": 64000, "concurrencies": [1, 2, 4]}
        ]
    })
}

// Returns one exact sealed worker input with a closed native subject.
fn input_value() -> Value {
    let contract = contract();
    json!({
        "schema_name": "li-benchmark-worker-input",
        "schema_version": 1,
        "job_id": "a".repeat(32),
        "plan_sha256": "b".repeat(64),
        "installation_id": "c".repeat(64),
        "benchmark_contract_sha256": sha256(&canonical(&contract)),
        "execution_sha256": "d".repeat(64),
        "target_contract_sha256": "e".repeat(64),
        "record_schema_version": 8,
        "timestamp_unix_ns": 2_000_000_000_u64,
        "model": "deepseek-r1",
        "route": {
            "placement_group_id": "4".repeat(32),
            "endpoint_node_id": "5".repeat(32),
            "host": "127.0.0.1",
            "port": 8443,
            "owner_user_id": 501,
            "bearer_file": "/private/tmp/li-benchmark/bearer",
            "ca_file": "/private/tmp/li-benchmark/ca.pem",
            "token_count_path": "/v1/letsinfer/token-count",
            "max_active_requests": 8,
            "max_context_tokens": 131072
        },
        "watchdog": {
            "host": "127.0.0.1",
            "port": 9443,
            "server_name": "localhost",
            "ca_file": "/private/tmp/li-benchmark/watchdog-ca.pem",
            "controller_cert_file": "/private/tmp/li-benchmark/watchdog-controller.pem",
            "controller_key_file": "/private/tmp/li-benchmark/watchdog-controller.key",
            "timeout_milliseconds": 30000
        },
        "output_file": "/private/tmp/li-benchmark/evidence.json",
        "status_file": "/private/tmp/li-benchmark/status.json",
        "cancellation_file": "/private/tmp/li-benchmark/cancel",
        "rotation_file": "/private/tmp/li-benchmark/rotation.json",
        "subject": {
            "candidate_id": "engine--owner--model--target",
            "runtime_version": "1.0.0",
            "model_uri": "hf://owner/model",
            "model_revision": "3".repeat(40),
            "engine_payload_sha256": "2".repeat(64),
            "measured_engine_kind": "native-archive",
            "target": "target",
            "target_contract_sha256": "e".repeat(64)
        },
        "benchmark_contract": contract,
        "selected_cells": []
    })
}

// Supplies stable increasing wall-clock windows without sleeping.
struct MockClock {
    next: std::sync::atomic::AtomicU64,
}

impl MockClock {
    // Creates one clock whose cell windows are always three seconds wide.
    fn new() -> Self {
        Self {
            next: std::sync::atomic::AtomicU64::new(1_000_000),
        }
    }
}

impl NativeBenchmarkClock for MockClock {
    // Advances every observation by exactly three seconds.
    fn unix_milliseconds(&self) -> Result<u64, BenchmarkWorkerError> {
        Ok(self.next.fetch_add(3_000, Ordering::SeqCst))
    }

    // Makes settlement deterministic without consuming CI wall time.
    fn wait_until(&self, _unix_milliseconds: u64) -> Result<(), BenchmarkWorkerError> {
        Ok(())
    }
}

// Supplies complete deterministic one-second Watchdog samples for every cell interval.
struct MockTelemetrySource;

impl NativeBenchmarkTelemetrySource for MockTelemetrySource {
    // Returns one consecutive sample for every inclusive second in the requested interval.
    fn query_range(
        &self,
        start_unix_milliseconds: u64,
        end_unix_milliseconds: u64,
    ) -> Result<Vec<WatchdogSample>, BenchmarkWorkerError> {
        let mut samples = Vec::new();
        for (offset, milliseconds) in (start_unix_milliseconds..=end_unix_milliseconds)
            .step_by(1_000)
            .enumerate()
        {
            let mut telemetry = WatchdogSampleTelemetry {
                cpu_percent: 42,
                gpu_percent: 81,
                disk_percent: 12,
                system_temp_deci_c: 505,
                gpu_temp_deci_c: 620,
                nvme_temp_deci_c: 410,
                disk_read_kib_s: 100,
                disk_write_kib_s: 50,
                cpu_clock_mhz: 3_200,
                gpu_clock_mhz: 1_500,
                vram_clock_mhz: 2_000,
                system_ram_clock_mhz: 4_800,
                ..WatchdogSampleTelemetry::default()
            };
            telemetry.gpu_percent = telemetry.gpu_percent.saturating_add(offset as u8);
            samples.push(
                WatchdogSample::with_telemetry(
                    offset as u64 + 1,
                    milliseconds,
                    offset as u64 + 1,
                    telemetry,
                )
                .map_err(|_| BenchmarkWorkerError::invalid("mock telemetry is invalid"))?,
            );
        }
        Ok(samples)
    }
}

// Tracks concurrency and returns stable complete Engine-like measurements.
struct MockTransport {
    active: AtomicUsize,
    maximum_active: AtomicUsize,
    execute_calls: AtomicUsize,
    fail_at: Option<usize>,
    natural_stop: bool,
}

impl MockTransport {
    // Creates one deterministic transport with optional execution failure.
    fn new(fail_at: Option<usize>, natural_stop: bool) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum_active: AtomicUsize::new(0),
            execute_calls: AtomicUsize::new(0),
            fail_at,
            natural_stop,
        }
    }
}

impl NativeBenchmarkTransport for MockTransport {
    // Uses byte length as one deterministic positive Engine token count.
    fn count_tokens(&self, _model: &str, prompt: &str) -> Result<u64, BenchmarkWorkerError> {
        u64::try_from(prompt.len())
            .map_err(|_| BenchmarkWorkerError::invalid("mock prompt is too large"))
    }

    // Returns stable usage while recording simultaneous stream admission.
    fn execute(
        &self,
        request: &NativeBenchmarkStreamRequest,
    ) -> Result<NativeBenchmarkStreamMeasurement, BenchmarkWorkerError> {
        let call = self.execute_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_at == Some(call) {
            return Err(BenchmarkWorkerError::invalid("mock transport failed"));
        }
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum_active.fetch_max(active, Ordering::SeqCst);
        std::thread::yield_now();
        self.active.fetch_sub(1, Ordering::SeqCst);
        let cached = match request.cell() {
            "ttftwarm-code-c1" => request.prompt_tokens(),
            _ => 0,
        };
        NativeBenchmarkStreamMeasurement::new(
            request.generation().output_tokens,
            cached,
            2.0,
            if request.cell() == "ttftwarm-code-c1" {
                0.5
            } else {
                1.0
            },
            self.natural_stop,
        )
    }
}

// Runs one in-process test execution with explicit successful context-rotation acknowledgments.
fn run_benchmark(
    input: &NativeBenchmarkWorkerInput,
    transport: Arc<dyn NativeBenchmarkTransport>,
) -> Result<li_benchmark_worker::NativeBenchmarkWorkerOutput, BenchmarkWorkerError> {
    run_native_benchmark_controlled(
        input,
        transport,
        Arc::new(MockTelemetrySource),
        Arc::new(MockClock::new()),
        &|| false,
        &|_, _, _, _, _| Ok(()),
        &|_, _| Ok(()),
    )
}

// Runs local/native schema-8 evidence deterministically and binds every published hash.
#[test]
fn native_execution_emits_hash_bound_schema_8_record() {
    let input = NativeBenchmarkWorkerInput::parse(&canonical(&input_value())).expect("input");
    let transport = Arc::new(MockTransport::new(None, true));
    let first = run_benchmark(&input, transport.clone()).expect("first run");
    let second = run_benchmark(&input, transport.clone()).expect("replay");
    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.raw_evidence_sha256(), sha256(first.bytes()));
    assert_eq!(first.completed_cells(), 20);
    let value: Value = serde_json::from_slice(first.bytes()).expect("record");
    assert_eq!(value["schema_version"], 8);
    assert_eq!(
        value["benchmark_contract_sha256"],
        input_value()["benchmark_contract_sha256"]
    );
    assert_eq!(value["results"].as_array().map(Vec::len), Some(18));
    assert_eq!(value["ttft_cache"]["cold_cached_prompt_tokens"], 0);
    assert!(value["ttft_cache"]["warm_cached_prompt_tokens"]
        .as_u64()
        .is_some_and(|value| value > 0));
    let result_material = json!({
        "results": value["results"].clone(),
        "ttft_cache": value["ttft_cache"].clone()
    });
    assert_eq!(
        value["results_sha256"],
        sha256(&canonical(&result_material))
    );
    assert!(transport.maximum_active.load(Ordering::SeqCst) >= 2);
    assert_eq!(value["results"][0]["telemetry"]["interval_seconds"], 1);
    assert_eq!(
        value["results"][0]["telemetry"]["samples"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    assert_eq!(value["results"][0]["max_gpu_usage_percent"], 84.0);
}

// Reports every completed cell in order and fails closed when durable progress cannot advance.
#[test]
fn native_execution_progress_is_exact_and_provider_failure_is_terminal() {
    let input = NativeBenchmarkWorkerInput::parse(&canonical(&input_value())).expect("input");
    let progress = Mutex::new(Vec::new());
    let rotations = Mutex::new(Vec::new());
    run_native_benchmark_controlled(
        &input,
        Arc::new(MockTransport::new(None, true)),
        Arc::new(MockTelemetrySource),
        Arc::new(MockClock::new()),
        &|| false,
        &|context, index, count, completed, total| {
            rotations
                .lock()
                .expect("rotations")
                .push((context, index, count, completed, total));
            Ok(())
        },
        &|completed, total| {
            progress.lock().expect("progress").push((completed, total));
            Ok(())
        },
    )
    .expect("execution");
    assert_eq!(
        progress.into_inner().expect("progress"),
        (1..=20)
            .map(|completed| (completed, 20))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        rotations.into_inner().expect("rotations"),
        vec![
            ("short".to_string(), 1, 4, 0, 20),
            ("32k".to_string(), 2, 4, 6, 20),
            ("64k".to_string(), 3, 4, 12, 20),
            ("ttft".to_string(), 4, 4, 18, 20),
        ]
    );

    let calls = AtomicUsize::new(0);
    let error = run_native_benchmark_controlled(
        &input,
        Arc::new(MockTransport::new(None, true)),
        Arc::new(MockTelemetrySource),
        Arc::new(MockClock::new()),
        &|| false,
        &|_, _, _, _, _| Ok(()),
        &|_, _| {
            let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == 3 {
                return Err(BenchmarkWorkerError::invalid(
                    "mock progress persistence failed",
                ));
            }
            Ok(())
        },
    )
    .expect_err("progress failure");
    assert_eq!(error.reason(), "mock progress persistence failed");
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    let transport = Arc::new(MockTransport::new(None, true));
    let error = run_native_benchmark_controlled(
        &input,
        transport.clone(),
        Arc::new(MockTelemetrySource),
        Arc::new(MockClock::new()),
        &|| false,
        &|_, _, _, _, _| {
            Err(BenchmarkWorkerError::invalid(
                "mock context rotation failed",
            ))
        },
        &|_, _| Ok(()),
    )
    .expect_err("rotation failure");
    assert_eq!(error.reason(), "mock context rotation failed");
    assert_eq!(transport.execute_calls.load(Ordering::SeqCst), 0);
}

// Stops between groups without rotating or executing any cell from the next context tier.
#[test]
fn native_execution_cancellation_contains_the_next_group() {
    let input = NativeBenchmarkWorkerInput::parse(&canonical(&input_value())).expect("input");
    let cancelled = AtomicUsize::new(0);
    let rotations = Mutex::new(Vec::new());
    let error = run_native_benchmark_controlled(
        &input,
        Arc::new(MockTransport::new(None, true)),
        Arc::new(MockTelemetrySource),
        Arc::new(MockClock::new()),
        &|| cancelled.load(Ordering::SeqCst) == 1,
        &|context, _, _, _, _| {
            rotations.lock().expect("rotations").push(context);
            Ok(())
        },
        &|completed, _| {
            if completed == 6 {
                cancelled.store(1, Ordering::SeqCst);
            }
            Ok(())
        },
    )
    .expect_err("cancellation");
    assert!(error.is_cancelled());
    assert_eq!(
        rotations.into_inner().expect("rotations"),
        ["short".to_string()]
    );
}

// Rejects input, subject, contract, target, and replay identity drift before transport use.
#[test]
fn native_execution_rejects_input_identity_mutation_matrix() {
    let mutations: [fn(&mut Value); 9] = [
        |value| value["schema_name"] = json!("other"),
        |value| value["job_id"] = json!("bad"),
        |value| value["plan_sha256"] = json!("bad"),
        |value| value["benchmark_contract_sha256"] = json!("f".repeat(64)),
        |value| value["target_contract_sha256"] = json!("f".repeat(64)),
        |value| value["subject"]["engine_payload_sha256"] = json!("bad"),
        |value| value["record_schema_version"] = json!(9),
        |value| value["watchdog"]["host"] = json!("watchdog.local"),
        |value| value["unknown"] = json!(true),
    ];
    for mutate in mutations {
        let mut value = input_value();
        mutate(&mut value);
        assert!(NativeBenchmarkWorkerInput::parse(&canonical(&value)).is_err());
    }
}

// Propagates one stream failure without publishing partial evidence.
#[test]
fn native_execution_fails_closed_on_transport_or_completion_failure() {
    let input = NativeBenchmarkWorkerInput::parse(&canonical(&input_value())).expect("input");
    assert!(run_benchmark(&input, Arc::new(MockTransport::new(Some(3), true))).is_err());
    assert!(run_benchmark(&input, Arc::new(MockTransport::new(None, false))).is_err());
}

// Refuses partial TTFT selection and records no fabricated cache evidence.
#[test]
fn native_execution_refuses_partial_ttft_cache_phase() {
    let mut value = input_value();
    value["selected_cells"] = json!(["short-code-c1", "ttftcold-code-c1"]);
    let input = NativeBenchmarkWorkerInput::parse(&canonical(&value)).expect("input");
    let transport = Arc::new(MockTransport::new(None, true));
    assert!(run_benchmark(&input, transport.clone()).is_err());
    assert_eq!(transport.execute_calls.load(Ordering::SeqCst), 0);
}

// Keeps a declared fresh-matrix contract to one reset without inventing context isolation.
#[test]
fn native_execution_respects_one_declared_matrix_group() {
    let mut value = input_value();
    value["benchmark_contract"]["execution"]["isolation"] = json!("fresh-matrix");
    value["benchmark_contract_sha256"] = json!(sha256(&canonical(&value["benchmark_contract"])));
    value["selected_cells"] = json!([
        "short-code-c1",
        "32k-code-c1",
        "ttftcold-code-c1",
        "ttftwarm-code-c1"
    ]);
    let input = NativeBenchmarkWorkerInput::parse(&canonical(&value)).expect("input");
    let rotations = Mutex::new(Vec::new());
    run_native_benchmark_controlled(
        &input,
        Arc::new(MockTransport::new(None, true)),
        Arc::new(MockTelemetrySource),
        Arc::new(MockClock::new()),
        &|| false,
        &|context, index, count, completed, total| {
            rotations
                .lock()
                .expect("rotations")
                .push((context, index, count, completed, total));
            Ok(())
        },
        &|_, _| Ok(()),
    )
    .expect("matrix execution");
    assert_eq!(
        rotations.into_inner().expect("rotations"),
        [("matrix".to_string(), 1, 1, 0, 4)]
    );
}
