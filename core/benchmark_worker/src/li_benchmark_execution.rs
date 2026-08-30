// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::path::{Component, Path};
use std::sync::{Arc, Barrier};
use std::thread;

use li_benchmark_manager::{canonical_benchmark_json_bytes, validate_benchmark_record_bytes};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::li_benchmark_watchdog::{collect_cell_telemetry, NativeBenchmarkTelemetrySummary};
use crate::{
    materialize_native_benchmark, BenchmarkWorkerError, NativeBenchmarkCell, NativeBenchmarkClock,
    NativeBenchmarkRequest, NativeBenchmarkTelemetrySource, NativeBenchmarkWatchdogInput,
};

// Carries one exact stream request without Engine-specific flags.
#[derive(Clone, Debug, PartialEq)]
pub struct NativeBenchmarkStreamRequest {
    request_id: String,
    model: String,
    cell: String,
    prompt: String,
    prompt_tokens: u64,
    generation: NativeBenchmarkRequest,
}

impl NativeBenchmarkStreamRequest {
    // Returns the deterministic request identity.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    // Returns the selected logical model name.
    pub fn model(&self) -> &str {
        &self.model
    }

    // Returns the canonical benchmark cell identity.
    pub fn cell(&self) -> &str {
        &self.cell
    }

    // Returns canonical prompt text.
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    // Returns the exact Engine-rendered prompt count observed before launch.
    pub const fn prompt_tokens(&self) -> u64 {
        self.prompt_tokens
    }

    // Returns the exact generation contract.
    pub const fn generation(&self) -> &NativeBenchmarkRequest {
        &self.generation
    }
}

// Carries one complete exact native stream measurement.
#[derive(Clone, Debug, PartialEq)]
pub struct NativeBenchmarkStreamMeasurement {
    output_tokens: u64,
    cached_prompt_tokens: u64,
    elapsed_seconds: f64,
    ttft_seconds: f64,
    natural_stop: bool,
}

impl NativeBenchmarkStreamMeasurement {
    // Creates one finite positive stream result after exact Engine usage parsing.
    pub fn new(
        output_tokens: u64,
        cached_prompt_tokens: u64,
        elapsed_seconds: f64,
        ttft_seconds: f64,
        natural_stop: bool,
    ) -> Result<Self, BenchmarkWorkerError> {
        if output_tokens == 0
            || !elapsed_seconds.is_finite()
            || !ttft_seconds.is_finite()
            || elapsed_seconds <= 0.0
            || ttft_seconds <= 0.0
            || ttft_seconds > elapsed_seconds
        {
            return Err(BenchmarkWorkerError::invalid(
                "benchmark stream measurement is invalid",
            ));
        }
        Ok(Self {
            output_tokens,
            cached_prompt_tokens,
            elapsed_seconds,
            ttft_seconds,
            natural_stop,
        })
    }
}

// Counts and executes exact OpenAI requests through one native transport implementation.
pub trait NativeBenchmarkTransport: Send + Sync {
    // Counts exact Engine-rendered chat tokens for one canonical prompt.
    fn count_tokens(&self, model: &str, prompt: &str) -> Result<u64, BenchmarkWorkerError>;

    // Executes one exact stream and returns complete usage and timing evidence.
    fn execute(
        &self,
        request: &NativeBenchmarkStreamRequest,
    ) -> Result<NativeBenchmarkStreamMeasurement, BenchmarkWorkerError>;
}

// Stores one exact local Engine route and its private credential references.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBenchmarkRouteInput {
    pub(crate) placement_group_id: String,
    pub(crate) endpoint_node_id: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) owner_user_id: u32,
    pub(crate) bearer_file: String,
    pub(crate) ca_file: String,
    pub(crate) token_count_path: String,
    pub(crate) max_active_requests: u32,
    pub(crate) max_context_tokens: u64,
}

// Stores one closed native worker input received from the Node-owned task adapter.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBenchmarkWorkerInput {
    schema_name: String,
    schema_version: u64,
    job_id: String,
    plan_sha256: String,
    installation_id: String,
    benchmark_contract_sha256: String,
    execution_sha256: String,
    target_contract_sha256: String,
    record_schema_version: u64,
    timestamp_unix_ns: u64,
    model: String,
    route: NativeBenchmarkRouteInput,
    watchdog: NativeBenchmarkWatchdogInput,
    output_file: String,
    status_file: String,
    cancellation_file: String,
    rotation_file: String,
    subject: Value,
    benchmark_contract: Value,
    #[serde(default)]
    selected_cells: Vec<String>,
}

impl NativeBenchmarkWorkerInput {
    // Parses one closed input and verifies every immutable identity before HTTP work.
    pub fn parse(bytes: &[u8]) -> Result<Self, BenchmarkWorkerError> {
        if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
            return Err(BenchmarkWorkerError::invalid(
                "benchmark worker input size is invalid",
            ));
        }
        let input: Self = serde_json::from_slice(bytes)
            .map_err(|_| BenchmarkWorkerError::invalid("benchmark worker input is invalid"))?;
        input.validate()?;
        Ok(input)
    }

    // Returns the deterministic operation identity.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    // Returns the deterministic plan identity.
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    // Returns the exact PlacementManager group whose process and store must be rotated.
    pub fn placement_group_id(&self) -> &str {
        &self.route.placement_group_id
    }

    // Returns the exact local Engine route consumed by the native transport.
    pub const fn route(&self) -> &NativeBenchmarkRouteInput {
        &self.route
    }

    // Returns the explicit authenticated Watchdog endpoint and credential references.
    pub const fn watchdog(&self) -> &NativeBenchmarkWatchdogInput {
        &self.watchdog
    }

    // Returns the user identity that must own every private worker input.
    pub const fn owner_user_id(&self) -> u32 {
        self.route.owner_user_id
    }

    // Returns the absolute owner-only evidence destination selected by the task adapter.
    pub fn output_file(&self) -> &Path {
        Path::new(&self.output_file)
    }

    // Returns the owner-only restart polling status selected by the task adapter.
    pub fn status_file(&self) -> &Path {
        Path::new(&self.status_file)
    }

    // Returns the exact owner-only cancellation marker selected by the task adapter.
    pub fn cancellation_file(&self) -> &Path {
        Path::new(&self.cancellation_file)
    }

    // Returns the owner-only manager acknowledgment file for context-process rotation.
    pub fn rotation_file(&self) -> &Path {
        Path::new(&self.rotation_file)
    }

    // Returns the exact logical model selected by the Node-owned task adapter.
    pub fn model(&self) -> &str {
        &self.model
    }

    // Verifies the closed schema, contract digest, subject identity, and selection bounds.
    fn validate(&self) -> Result<(), BenchmarkWorkerError> {
        let contract = canonical(&self.benchmark_contract)?;
        let subject = self
            .subject
            .as_object()
            .ok_or_else(|| BenchmarkWorkerError::invalid("benchmark subject is invalid"))?;
        let measured = match self.record_schema_version {
            7 => "measured_engine_oci",
            8 => "measured_engine_kind",
            _ => {
                return Err(BenchmarkWorkerError::invalid(
                    "benchmark record schema is unsupported",
                ))
            }
        };
        let expected_subject = [
            "candidate_id",
            "runtime_version",
            "model_uri",
            "model_revision",
            "engine_payload_sha256",
            measured,
            "target",
            "target_contract_sha256",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if self.schema_name != "li-benchmark-worker-input"
            || self.schema_version != 1
            || !is_lower_hex(&self.job_id, 32)
            || !is_lower_hex(&self.plan_sha256, 64)
            || !is_lower_hex(&self.installation_id, 64)
            || !is_lower_hex(&self.benchmark_contract_sha256, 64)
            || !is_lower_hex(&self.execution_sha256, 64)
            || !is_lower_hex(&self.target_contract_sha256, 64)
            || self.timestamp_unix_ns == 0
            || !safe_name(&self.model)
            || self.route.validate().is_err()
            || self.watchdog.validate().is_err()
            || !safe_absolute_file(Path::new(&self.output_file))
            || !safe_absolute_file(Path::new(&self.status_file))
            || !safe_absolute_file(Path::new(&self.cancellation_file))
            || !safe_absolute_file(Path::new(&self.rotation_file))
            || self.output_file == self.status_file
            || self.output_file == self.cancellation_file
            || self.output_file == self.rotation_file
            || self.status_file == self.cancellation_file
            || self.status_file == self.rotation_file
            || self.cancellation_file == self.rotation_file
            || sha256(&contract) != self.benchmark_contract_sha256
            || subject.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_subject
            || subject
                .get("target_contract_sha256")
                .and_then(Value::as_str)
                != Some(self.target_contract_sha256.as_str())
            || subject
                .get("engine_payload_sha256")
                .and_then(Value::as_str)
                .is_none_or(|value| !is_lower_hex(value, 64))
            || self.selected_cells.len() > 128
        {
            return Err(BenchmarkWorkerError::invalid(
                "benchmark worker input identity is invalid",
            ));
        }
        Ok(())
    }

    // Creates one private test-only identity fixture for receipt validation without HTTP work.
    #[cfg(test)]
    pub(crate) fn rotation_fixture() -> Self {
        Self {
            schema_name: "li-benchmark-worker-input".to_string(),
            schema_version: 1,
            job_id: "a".repeat(32),
            plan_sha256: "b".repeat(64),
            installation_id: "c".repeat(64),
            benchmark_contract_sha256: "d".repeat(64),
            execution_sha256: "e".repeat(64),
            target_contract_sha256: "f".repeat(64),
            record_schema_version: 8,
            timestamp_unix_ns: 1,
            model: "model".to_string(),
            route: NativeBenchmarkRouteInput {
                placement_group_id: "1".repeat(32),
                endpoint_node_id: "2".repeat(32),
                host: "127.0.0.1".to_string(),
                port: 8443,
                owner_user_id: 501,
                bearer_file: "/private/tmp/bearer".to_string(),
                ca_file: "/private/tmp/ca".to_string(),
                token_count_path: "/v1/letsinfer/token-count".to_string(),
                max_active_requests: 1,
                max_context_tokens: 1,
            },
            watchdog: NativeBenchmarkWatchdogInput {
                host: "127.0.0.1".to_string(),
                port: 9443,
                server_name: "localhost".to_string(),
                ca_file: "/private/tmp/watchdog-ca".to_string(),
                controller_cert_file: "/private/tmp/watchdog-cert".to_string(),
                controller_key_file: "/private/tmp/watchdog-key".to_string(),
                timeout_milliseconds: 1_000,
            },
            output_file: "/private/tmp/output".to_string(),
            status_file: "/private/tmp/status".to_string(),
            cancellation_file: "/private/tmp/cancel".to_string(),
            rotation_file: "/private/tmp/rotation".to_string(),
            subject: Value::Null,
            benchmark_contract: Value::Null,
            selected_cells: Vec::new(),
        }
    }
}

impl NativeBenchmarkRouteInput {
    // Validates local HTTPS, identity, capacity, and private absolute file references.
    fn validate(&self) -> Result<(), BenchmarkWorkerError> {
        if !is_lower_hex(&self.placement_group_id, 32)
            || !is_lower_hex(&self.endpoint_node_id, 32)
            || self.host.is_empty()
            || self.host.len() > 255
            || self.host.chars().any(char::is_whitespace)
            || self.port == 0
            || self.owner_user_id == u32::MAX
            || !safe_absolute_file(Path::new(&self.bearer_file))
            || !safe_absolute_file(Path::new(&self.ca_file))
            || self.bearer_file == self.ca_file
            || !self.token_count_path.starts_with('/')
            || self.token_count_path.contains("://")
            || self.token_count_path.chars().any(char::is_whitespace)
            || self.max_active_requests == 0
            || self.max_context_tokens == 0
        {
            return Err(BenchmarkWorkerError::invalid(
                "benchmark native route is invalid",
            ));
        }
        Ok(())
    }
}

// Carries canonical successful evidence and scheduler artifact identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBenchmarkWorkerOutput {
    bytes: Vec<u8>,
    raw_evidence_sha256: String,
    results_sha256: String,
    completed_cells: u32,
}

// Binds one contiguous set of cells to exactly one fresh process/store generation.
struct NativeBenchmarkExecutionGroup<'a> {
    name: String,
    cells: &'a [NativeBenchmarkCell],
}

impl NativeBenchmarkWorkerOutput {
    // Returns canonical newline-terminated public record bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    // Returns the exact raw evidence identity.
    pub fn raw_evidence_sha256(&self) -> &str {
        &self.raw_evidence_sha256
    }

    // Returns the exact schema-owned result-material identity.
    pub fn results_sha256(&self) -> &str {
        &self.results_sha256
    }

    // Returns the exact number of completed declared cells.
    pub const fn completed_cells(&self) -> u32 {
        self.completed_cells
    }
}

// Runs one benchmark with manager-owned context rotation, cancellation, and progress callbacks.
pub fn run_native_benchmark_controlled(
    input: &NativeBenchmarkWorkerInput,
    transport: Arc<dyn NativeBenchmarkTransport>,
    telemetry: Arc<dyn NativeBenchmarkTelemetrySource>,
    clock: Arc<dyn NativeBenchmarkClock>,
    cancelled: &dyn Fn() -> bool,
    rotate: &dyn Fn(String, u32, u32, u32, u32) -> Result<(), BenchmarkWorkerError>,
    progress: &dyn Fn(u32, u32) -> Result<(), BenchmarkWorkerError>,
) -> Result<NativeBenchmarkWorkerOutput, BenchmarkWorkerError> {
    input.validate()?;
    if cancelled() {
        return Err(BenchmarkWorkerError::cancelled());
    }
    let contract_bytes = canonical(&input.benchmark_contract)?;
    let mut count = |prompt: &str| transport.count_tokens(&input.model, prompt);
    let materialized =
        materialize_native_benchmark(&contract_bytes, &input.selected_cells, &mut count)?;
    let groups =
        benchmark_execution_groups(materialized.cells(), materialized.execution_isolation())?;
    let mut results = Vec::new();
    let mut ttft = Vec::new();
    let total_cells = u32::try_from(materialized.cells().len())
        .map_err(|_| BenchmarkWorkerError::invalid("benchmark cell count overflowed"))?;
    let group_count = u32::try_from(groups.len())
        .map_err(|_| BenchmarkWorkerError::invalid("benchmark group count overflowed"))?;
    let mut completed_cells = 0_u32;
    for (group_offset, group) in groups.iter().enumerate() {
        if cancelled() {
            return Err(BenchmarkWorkerError::cancelled());
        }
        let group_index = u32::try_from(group_offset + 1)
            .map_err(|_| BenchmarkWorkerError::invalid("benchmark group count overflowed"))?;
        rotate(
            group.name.clone(),
            group_index,
            group_count,
            completed_cells,
            total_cells,
        )?;
        for cell in group.cells {
            if cancelled() {
                return Err(BenchmarkWorkerError::cancelled());
            }
            let measurement_started = clock.unix_milliseconds()?;
            let measurements = run_cell(input, cell, transport.clone())?;
            let measurement_ended = clock.unix_milliseconds()?;
            let telemetry = collect_cell_telemetry(
                clock.as_ref(),
                telemetry.as_ref(),
                measurement_started,
                measurement_ended,
            )?;
            if cell.is_ttft() {
                ttft.push((cell, measurements));
            } else {
                results.push(result_value(
                    cell,
                    &measurements,
                    materialized.prompt_set_sha256(),
                    &telemetry,
                )?);
            }
            completed_cells = completed_cells
                .checked_add(1)
                .ok_or_else(|| BenchmarkWorkerError::invalid("benchmark cell count overflowed"))?;
            progress(completed_cells, total_cells)?;
        }
    }
    let ttft_cache = ttft_value(&ttft)?;
    let result_material = if input.record_schema_version == 8 {
        json!({"results": results, "ttft_cache": ttft_cache})
    } else {
        Value::Array(results.clone())
    };
    let results_sha256 = sha256(&canonical(&result_material)?);
    let identity = json!({
        "benchmark_contract_sha256": input.benchmark_contract_sha256,
        "contract": "letsinfer-benchmark-identity-v2",
        "installation_id": input.installation_id,
        "results_sha256": results_sha256,
        "subject": input.subject,
        "timestamp_unix_ns": input.timestamp_unix_ns
    });
    let evidence_id = sha256(&canonical(&identity)?);
    let mut record = json!({
        "schema_version": input.record_schema_version,
        "id": evidence_id,
        "installation_id": input.installation_id,
        "timestamp": input.timestamp_unix_ns / 1_000_000_000,
        "timestamp_unix_ns": input.timestamp_unix_ns,
        "subject": input.subject,
        "benchmark_contract_sha256": input.benchmark_contract_sha256,
        "results_sha256": results_sha256,
        "results": results,
        "benchmark_contract": input.benchmark_contract
    });
    if input.record_schema_version == 8 {
        record["ttft_cache"] = ttft_cache;
    }
    let bytes = canonical(&record)?;
    let receipt = validate_benchmark_record_bytes(&bytes)
        .map_err(|_| BenchmarkWorkerError::invalid("benchmark record validation failed"))?;
    if receipt.evidence_id().as_str() != evidence_id
        || receipt.results_sha256().as_str() != results_sha256
        || u64::from(receipt.schema().version()) != input.record_schema_version
        || receipt.byte_count() != bytes.len() as u64
    {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark record validation failed",
        ));
    }
    Ok(NativeBenchmarkWorkerOutput {
        raw_evidence_sha256: sha256(&bytes),
        results_sha256,
        completed_cells: total_cells,
        bytes,
    })
}

// Returns the exact schema-8 process/store isolation group for one canonical cell name.
fn benchmark_context(cell: &str) -> &str {
    let context = cell.split_once('-').map_or(cell, |(context, _)| context);
    match context {
        "ttftcold" | "ttftwarm" => "ttft",
        value => value,
    }
}

// Resolves and validates every process/store group before the first runtime reset occurs.
fn benchmark_execution_groups<'a>(
    cells: &'a [NativeBenchmarkCell],
    isolation: &str,
) -> Result<Vec<NativeBenchmarkExecutionGroup<'a>>, BenchmarkWorkerError> {
    if cells.is_empty() {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark context selection is empty",
        ));
    }
    let ttft = cells
        .iter()
        .filter(|cell| cell.is_ttft())
        .map(|cell| cell.name())
        .collect::<Vec<_>>();
    if !ttft.is_empty() || cells.iter().all(NativeBenchmarkCell::is_ttft) {
        if ttft != ["ttftcold-code-c1", "ttftwarm-code-c1"] {
            return Err(BenchmarkWorkerError::invalid(
                "TTFT cache benchmark phases are incomplete or drifted",
            ));
        }
    }
    if cells.iter().all(NativeBenchmarkCell::is_ttft) {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark selection has no result-producing cell",
        ));
    }
    if isolation == "fresh-matrix" {
        return Ok(vec![NativeBenchmarkExecutionGroup {
            name: "matrix".to_string(),
            cells,
        }]);
    }
    if isolation != "fresh-context" {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark isolation policy is unsupported",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut groups = Vec::new();
    let mut start = 0_usize;
    while start < cells.len() {
        let context = benchmark_context(cells[start].name());
        let mut end = start + 1;
        while end < cells.len() && benchmark_context(cells[end].name()) == context {
            end += 1;
        }
        if !seen.insert(context.to_string()) {
            return Err(BenchmarkWorkerError::invalid(
                "benchmark context ordering is invalid",
            ));
        }
        groups.push(NativeBenchmarkExecutionGroup {
            name: context.to_string(),
            cells: &cells[start..end],
        });
        start = end;
    }
    Ok(groups)
}

// Executes all streams in one cell behind a common launch barrier.
fn run_cell(
    input: &NativeBenchmarkWorkerInput,
    cell: &NativeBenchmarkCell,
    transport: Arc<dyn NativeBenchmarkTransport>,
) -> Result<Vec<NativeBenchmarkStreamMeasurement>, BenchmarkWorkerError> {
    let barrier = Arc::new(Barrier::new(cell.fixtures().len()));
    let outcomes = thread::scope(|scope| {
        let mut handles = Vec::new();
        for fixture in cell.fixtures() {
            let transport = transport.clone();
            let barrier = barrier.clone();
            let request_id = framed_sha256(&[
                "li-benchmark-native-request-v1",
                &input.job_id,
                &input.plan_sha256,
                cell.name(),
                fixture.name(),
                fixture.sha256(),
            ]);
            let request = NativeBenchmarkStreamRequest {
                request_id,
                model: input.model.clone(),
                cell: cell.name().to_string(),
                prompt: fixture.content().to_string(),
                prompt_tokens: fixture.prompt_tokens(),
                generation: cell.request().clone(),
            };
            handles.push(scope.spawn(move || {
                barrier.wait();
                transport.execute(&request)
            }));
        }
        handles
            .into_iter()
            .map(|handle| {
                handle.join().map_err(|_| {
                    BenchmarkWorkerError::invalid("benchmark stream worker panicked")
                })?
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    if outcomes
        .iter()
        .zip(cell.fixtures())
        .any(|(measurement, fixture)| {
            measurement.cached_prompt_tokens > fixture.prompt_tokens()
                || (cell.request().require_natural_stop && !measurement.natural_stop)
        })
    {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark stream violates cache or completion contract",
        ));
    }
    Ok(outcomes)
}

// Builds one schema-owned ordinary benchmark result from exact concurrent streams.
fn result_value(
    cell: &NativeBenchmarkCell,
    measurements: &[NativeBenchmarkStreamMeasurement],
    prompt_set_sha256: &str,
    telemetry: &NativeBenchmarkTelemetrySummary,
) -> Result<Value, BenchmarkWorkerError> {
    let elapsed = measurements
        .iter()
        .map(|value| value.elapsed_seconds)
        .fold(0.0_f64, f64::max);
    let output_tokens = measurements
        .iter()
        .map(|value| value.output_tokens)
        .sum::<u64>();
    let mut decode = measurements
        .iter()
        .map(|value| {
            value.output_tokens as f64 / (value.elapsed_seconds - value.ttft_seconds).max(1e-9)
        })
        .collect::<Vec<_>>();
    let mut ttft = measurements
        .iter()
        .map(|value| value.ttft_seconds)
        .collect::<Vec<_>>();
    decode.sort_by(f64::total_cmp);
    ttft.sort_by(f64::total_cmp);
    let single = measurements.len() == 1;
    let ttft_value = if single {
        ttft[0]
    } else {
        percentile(&ttft, 0.50)
    };
    let p95 = (!single).then(|| percentile(&ttft, 0.95));
    let aggregate = output_tokens as f64 / elapsed;
    let decode_value = if single {
        decode.iter().sum::<f64>() / decode.len() as f64
    } else {
        percentile(&decode, 0.50)
    };
    if !aggregate.is_finite()
        || !decode_value.is_finite()
        || aggregate <= 0.0
        || decode_value <= 0.0
    {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark throughput calculation is invalid",
        ));
    }
    let mut result = json!({
        "workload": format!("pp{},tg{},c{}", cell.target_prompt_tokens(), cell.request().output_tokens, cell.concurrency()),
        "prompt_domain": cell.domain(),
        "prompt_suite": "letsinfer-code-prose-v1",
        "prompt_set_sha256": prompt_set_sha256,
        "actual_prompt_tokens": cell.fixtures().iter().map(|fixture| fixture.prompt_tokens()).collect::<Vec<_>>(),
        "aggregate_tps": aggregate,
        "decode_tps": decode_value,
        "ttft_seconds": ttft_value,
        "ttft_statistic": if single {"single"} else {"p50"},
        "ttft_p95_seconds": p95,
        "is_prefix_cached": measurements.iter().any(|value| value.cached_prompt_tokens > 0)
    });
    telemetry.apply(
        result
            .as_object_mut()
            .ok_or_else(|| BenchmarkWorkerError::invalid("benchmark result is invalid"))?,
    );
    Ok(result)
}

// Builds exact cold/warm TTFT cache evidence when both dedicated phases ran.
fn ttft_value(
    values: &[(&NativeBenchmarkCell, Vec<NativeBenchmarkStreamMeasurement>)],
) -> Result<Value, BenchmarkWorkerError> {
    if values.is_empty() {
        return Ok(Value::Null);
    }
    if values.len() != 2
        || values[0].0.name() != "ttftcold-code-c1"
        || values[1].0.name() != "ttftwarm-code-c1"
        || values[0].0.fixtures()[0].sha256() != values[1].0.fixtures()[0].sha256()
    {
        return Err(BenchmarkWorkerError::invalid(
            "TTFT cache benchmark phases are incomplete or drifted",
        ));
    }
    let cold = &values[0].1[0];
    let warm = &values[1].1[0];
    let tokens = values[0].0.fixtures()[0].prompt_tokens();
    if cold.cached_prompt_tokens > tokens
        || warm.cached_prompt_tokens > tokens
        || warm.cached_prompt_tokens <= cold.cached_prompt_tokens
    {
        return Err(BenchmarkWorkerError::invalid(
            "TTFT cache reuse was not observed exactly",
        ));
    }
    Ok(json!({
        "workload": "pp64000,tg1,c1",
        "prompt_domain": "code",
        "prompt_suite": "letsinfer-code-prose-v1",
        "prompt_sha256": values[0].0.fixtures()[0].sha256(),
        "actual_prompt_tokens": tokens,
        "cold_ttft_seconds": cold.ttft_seconds,
        "warm_ttft_seconds": warm.ttft_seconds,
        "cold_cached_prompt_tokens": cold.cached_prompt_tokens,
        "warm_cached_prompt_tokens": warm.cached_prompt_tokens,
        "ttft_speedup_ratio": cold.ttft_seconds / warm.ttft_seconds,
        "ttft_reduction_percent": (cold.ttft_seconds - warm.ttft_seconds) * 100.0 / cold.ttft_seconds
    }))
}

// Returns one linearly interpolated percentile over non-empty sorted finite values.
fn percentile(values: &[f64], fraction: f64) -> f64 {
    let index = fraction * (values.len() - 1) as f64;
    let lower = index.floor() as usize;
    let upper = index.ceil() as usize;
    values[lower] + (values[upper] - values[lower]) * (index - lower as f64)
}

// Encodes compact deterministic JSON with one trailing newline.
fn canonical(value: &Value) -> Result<Vec<u8>, BenchmarkWorkerError> {
    canonical_benchmark_json_bytes(value)
        .map_err(|_| BenchmarkWorkerError::invalid("benchmark JSON encoding failed"))
}

// Hashes exact bytes into lowercase SHA-256 text.
fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

// Hashes ordered identity fields with unambiguous length framing.
fn framed_sha256(fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

// Returns whether one identity is exact lowercase hexadecimal text.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Returns whether one logical model uses the shared technical-name alphabet.
fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

// Returns whether one absolute file reference has no parent traversal component.
fn safe_absolute_file(value: &Path) -> bool {
    value.is_absolute()
        && value
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && value.file_name().is_some()
}
