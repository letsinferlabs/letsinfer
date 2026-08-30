// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::BenchmarkError;

const TELEMETRY_COLUMNS: [&str; 13] = [
    "elapsed_seconds",
    "gpu_usage_percent",
    "gpu_temperature_c",
    "cpu_usage_percent",
    "cpu_temperature_c",
    "cpu_clock_mhz",
    "gpu_clock_mhz",
    "vram_clock_mhz",
    "system_ram_clock_mhz",
    "nvme_usage_percent",
    "nvme_temperature_c",
    "nvme_read_kib_per_second",
    "nvme_write_kib_per_second",
];

const RESULT_FIELDS: [&str; 24] = [
    "workload",
    "prompt_domain",
    "prompt_suite",
    "prompt_set_sha256",
    "actual_prompt_tokens",
    "aggregate_tps",
    "decode_tps",
    "ttft_seconds",
    "ttft_statistic",
    "ttft_p95_seconds",
    "is_prefix_cached",
    "max_gpu_usage_percent",
    "max_gpu_temperature_c",
    "max_cpu_temperature_c",
    "max_cpu_usage_percent",
    "max_cpu_clock_mhz",
    "max_gpu_clock_mhz",
    "max_vram_clock_mhz",
    "max_system_ram_clock_mhz",
    "max_nvme_usage_percent",
    "max_nvme_temperature_c",
    "max_nvme_read_kib_per_second",
    "max_nvme_write_kib_per_second",
    "telemetry",
];

const MAXIMUM_FIELDS: [&str; 12] = [
    "max_gpu_usage_percent",
    "max_gpu_temperature_c",
    "max_cpu_usage_percent",
    "max_cpu_temperature_c",
    "max_cpu_clock_mhz",
    "max_gpu_clock_mhz",
    "max_vram_clock_mhz",
    "max_system_ram_clock_mhz",
    "max_nvme_usage_percent",
    "max_nvme_temperature_c",
    "max_nvme_read_kib_per_second",
    "max_nvme_write_kib_per_second",
];

// Validates the complete active schema-8 benchmark contract without accepting extensions.
pub(crate) fn validate_benchmark_contract(
    value: &Map<String, Value>,
) -> Result<(), BenchmarkError> {
    require_fields(
        value,
        &[
            "schema_version",
            "suite",
            "generator",
            "domains",
            "execution",
            "tokenizer",
            "request",
            "short",
            "ttft_cache",
            "sample_interval_seconds",
            "cases",
        ],
    )?;
    require_integer(value.get("schema_version"), 8, 8)?;
    require_exact_string(value.get("suite"), "letsinfer-code-prose-v1")?;

    let generator = object(value.get("generator"))?;
    require_fields(generator, &["id", "version"])?;
    require_exact_string(generator.get("id"), "letsinfer-code-prose")?;
    require_integer(generator.get("version"), 8, 8)?;

    let domains = array(value.get("domains"))?;
    if !matches_string_list(domains, &["code"])
        && !matches_string_list(domains, &["prose"])
        && !matches_string_list(domains, &["code", "prose"])
    {
        return rejected();
    }

    let execution = object(value.get("execution"))?;
    require_fields(
        execution,
        &[
            "isolation",
            "prefix_state",
            "samples_per_cell",
            "stream_prefix",
        ],
    )?;
    require_string_member(
        execution.get("isolation"),
        &["fresh-context", "fresh-matrix"],
    )?;
    require_exact_string(execution.get("prefix_state"), "shared")?;
    require_integer(execution.get("samples_per_cell"), 1, 1)?;
    require_exact_string(execution.get("stream_prefix"), "shared-body")?;

    let tokenizer = object(value.get("tokenizer"))?;
    require_fields(
        tokenizer,
        &[
            "capability",
            "model_sha256",
            "engine_payload_sha256",
            "render_contract",
        ],
    )?;
    require_exact_string(tokenizer.get("capability"), "engine-rendered-chat-count-v1")?;
    require_sha256(tokenizer.get("model_sha256"))?;
    require_sha256(tokenizer.get("engine_payload_sha256"))?;
    require_exact_string(tokenizer.get("render_contract"), "openai-chat-user-v1")?;

    validate_request(object(value.get("request"))?)?;
    validate_short(object(value.get("short"))?)?;
    validate_ttft_contract(object(value.get("ttft_cache"))?)?;
    require_integer(value.get("sample_interval_seconds"), 1, 60)?;
    validate_cases(array(value.get("cases"))?)
}

// Validates every schema-7 or schema-8 result plus optional cache evidence semantics.
pub(crate) fn validate_benchmark_results(
    results: &[Value],
    ttft_cache: Option<&Value>,
) -> Result<(), BenchmarkError> {
    if results.is_empty() {
        return rejected();
    }
    let mut identities = BTreeSet::new();
    for result in results {
        let result = object(Some(result))?;
        require_fields(result, &RESULT_FIELDS)?;
        let workload = string(result.get("workload"))?;
        let concurrency = parse_workload(workload)?;
        let domain = string(result.get("prompt_domain"))?;
        if !matches!(domain, "code" | "prose")
            || !identities.insert((workload.to_string(), domain.to_string()))
        {
            return rejected();
        }
        require_exact_string(result.get("prompt_suite"), "letsinfer-code-prose-v1")?;
        require_sha256(result.get("prompt_set_sha256"))?;
        let tokens = array(result.get("actual_prompt_tokens"))?;
        if tokens.len() != concurrency
            || tokens
                .iter()
                .any(|token| positive_integer(Some(token)).is_err())
        {
            return rejected();
        }
        positive_number(result.get("aggregate_tps"))?;
        nullable_positive_number(result.get("decode_tps"))?;
        let ttft = positive_number(result.get("ttft_seconds"))?;
        let statistic = string(result.get("ttft_statistic"))?;
        if !matches!(statistic, "single" | "mean" | "p50") {
            return rejected();
        }
        let p95 = nullable_positive_number(result.get("ttft_p95_seconds"))?;
        if (statistic == "p50" && p95.is_none_or(|value| value < ttft))
            || (statistic != "p50" && p95.is_some())
        {
            return rejected();
        }
        if result
            .get("is_prefix_cached")
            .and_then(Value::as_bool)
            .is_none()
        {
            return rejected();
        }
        nullable_range(result.get("max_gpu_usage_percent"), 0.0, 100.0)?;
        nullable_range(result.get("max_cpu_usage_percent"), 0.0, 100.0)?;
        nullable_range(result.get("max_gpu_temperature_c"), -100.0, 250.0)?;
        nullable_range(result.get("max_cpu_temperature_c"), -100.0, 250.0)?;
        for field in [
            "max_cpu_clock_mhz",
            "max_gpu_clock_mhz",
            "max_vram_clock_mhz",
            "max_system_ram_clock_mhz",
        ] {
            unknown_or_positive(result.get(field))?;
        }
        unknown_or_range(result.get("max_nvme_usage_percent"), 0.0, 100.0)?;
        unknown_or_range(result.get("max_nvme_temperature_c"), -100.0, 250.0)?;
        unknown_or_nonnegative(result.get("max_nvme_read_kib_per_second"))?;
        unknown_or_nonnegative(result.get("max_nvme_write_kib_per_second"))?;
        validate_telemetry(result)?;
    }
    if let Some(value) = ttft_cache {
        validate_ttft_result(object(Some(value))?)?;
    }
    Ok(())
}

// Validates one closed ordinary or short request contract.
fn validate_request(value: &Map<String, Value>) -> Result<(), BenchmarkError> {
    require_fields(
        value,
        &[
            "output_tokens",
            "min_completion_tokens",
            "require_natural_stop",
            "temperature",
            "seed",
        ],
    )?;
    let output = positive_integer(value.get("output_tokens"))?;
    let minimum = positive_integer(value.get("min_completion_tokens"))?;
    if minimum > output
        || value
            .get("require_natural_stop")
            .and_then(Value::as_bool)
            .is_none()
    {
        return rejected();
    }
    nonnegative_number(value.get("temperature"))?;
    nonnegative_integer(value.get("seed"))?;
    Ok(())
}

// Validates the exact schema-8 short-workload projection.
fn validate_short(value: &Map<String, Value>) -> Result<(), BenchmarkError> {
    require_fields(
        value,
        &["domains", "prompt_tokens", "concurrencies", "request"],
    )?;
    if !matches_string_list(array(value.get("domains"))?, &["code", "prose"])
        || !matches_integer_list(array(value.get("concurrencies"))?, &[1, 2, 4])
    {
        return rejected();
    }
    positive_integer(value.get("prompt_tokens"))?;
    validate_request(object(value.get("request"))?)
}

// Validates the exact schema-8 dedicated cache request projection.
fn validate_ttft_contract(value: &Map<String, Value>) -> Result<(), BenchmarkError> {
    require_fields(
        value,
        &["prompt_tokens", "prompt_domain", "repetitions", "request"],
    )?;
    require_integer(value.get("prompt_tokens"), 64_000, 64_000)?;
    require_exact_string(value.get("prompt_domain"), "code")?;
    require_integer(value.get("repetitions"), 2, 2)?;
    let request = object(value.get("request"))?;
    validate_request(request)?;
    require_integer(request.get("output_tokens"), 1, 1)?;
    require_integer(request.get("min_completion_tokens"), 1, 1)?;
    if request.get("require_natural_stop") != Some(&Value::Bool(false))
        || number(request.get("temperature"))? != 0.0
    {
        return rejected();
    }
    Ok(())
}

// Validates ordered unique schema-8 matrix cases.
fn validate_cases(values: &[Value]) -> Result<(), BenchmarkError> {
    if values.is_empty() {
        return rejected();
    }
    let mut identities = BTreeSet::new();
    for value in values {
        let value = object(Some(value))?;
        require_fields(value, &["id", "prompt_tokens", "concurrencies"])?;
        let identity = string(value.get("id"))?;
        if !safe_name(identity) || !identities.insert(identity.to_string()) {
            return rejected();
        }
        positive_integer(value.get("prompt_tokens"))?;
        let concurrencies = array(value.get("concurrencies"))?;
        if concurrencies.is_empty() {
            return rejected();
        }
        let mut previous = 0_u64;
        for concurrency in concurrencies {
            let concurrency = integer(Some(concurrency))?;
            if !(1..=128).contains(&concurrency) || concurrency <= previous {
                return rejected();
            }
            previous = concurrency;
        }
    }
    Ok(())
}

// Validates one result's exact timeline and every declared maximum projection.
fn validate_telemetry(result: &Map<String, Value>) -> Result<(), BenchmarkError> {
    let telemetry = object(result.get("telemetry"))?;
    require_fields(telemetry, &["interval_seconds", "columns", "samples"])?;
    if !matches_string_list(array(telemetry.get("columns"))?, &TELEMETRY_COLUMNS) {
        return rejected();
    }
    let samples = array(telemetry.get("samples"))?;
    if (samples.is_empty()
        && !telemetry
            .get("interval_seconds")
            .is_some_and(Value::is_null))
        || (!samples.is_empty() && integer(telemetry.get("interval_seconds")).ok() != Some(1))
    {
        return rejected();
    }
    let mut maxima: [Option<f64>; 12] = [None; 12];
    let mut previous_elapsed = -1.0_f64;
    for sample in samples {
        let fields = string(Some(sample))?.split(',').collect::<Vec<_>>();
        if fields.len() != TELEMETRY_COLUMNS.len() {
            return rejected();
        }
        let elapsed = parse_finite(fields[0])?;
        if elapsed < 0.0 || elapsed <= previous_elapsed {
            return rejected();
        }
        previous_elapsed = elapsed;
        let parsed = [
            timeline_number(fields[1], TimelineKind::Percent)?,
            timeline_number(fields[2], TimelineKind::Temperature)?,
            timeline_number(fields[3], TimelineKind::Percent)?,
            timeline_number(fields[4], TimelineKind::Temperature)?,
            timeline_number(fields[5], TimelineKind::Clock)?,
            timeline_number(fields[6], TimelineKind::Clock)?,
            timeline_number(fields[7], TimelineKind::Clock)?,
            timeline_number(fields[8], TimelineKind::Clock)?,
            timeline_number(fields[9], TimelineKind::UnknownPercent)?,
            timeline_number(fields[10], TimelineKind::UnknownTemperature)?,
            timeline_number(fields[11], TimelineKind::UnknownRate)?,
            timeline_number(fields[12], TimelineKind::UnknownRate)?,
        ];
        for (maximum, observed) in maxima.iter_mut().zip(parsed) {
            if let Some(observed) = observed {
                *maximum = Some(maximum.map_or(observed, |current| current.max(observed)));
            }
        }
    }
    for (index, field) in MAXIMUM_FIELDS.iter().enumerate() {
        let expected = maxima[index].or_else(|| {
            (field.ends_with("_clock_mhz") || field.starts_with("max_nvme_")).then_some(-1.0)
        });
        if !matches_optional_number(result.get(*field), expected) {
            return rejected();
        }
    }
    Ok(())
}

// Distinguishes the fixed numeric policies of each compact timeline column.
#[derive(Clone, Copy)]
enum TimelineKind {
    Percent,
    Temperature,
    Clock,
    UnknownPercent,
    UnknownTemperature,
    UnknownRate,
}

// Parses one optional compact timeline field through its exact column policy.
fn timeline_number(raw: &str, kind: TimelineKind) -> Result<Option<f64>, BenchmarkError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let value = parse_finite(raw)?;
    if matches!(
        kind,
        TimelineKind::UnknownPercent | TimelineKind::UnknownTemperature | TimelineKind::UnknownRate
    ) && value == -1.0
    {
        return Ok(Some(value));
    }
    let valid = match kind {
        TimelineKind::Percent | TimelineKind::UnknownPercent => (0.0..=100.0).contains(&value),
        TimelineKind::Temperature | TimelineKind::UnknownTemperature => {
            (-100.0..=250.0).contains(&value)
        }
        TimelineKind::Clock => value == -1.0 || value > 0.0,
        TimelineKind::UnknownRate => value >= 0.0,
    };
    if !valid {
        return rejected();
    }
    Ok(Some(value))
}

// Validates the exact optional schema-owned cold/warm cache evidence.
fn validate_ttft_result(value: &Map<String, Value>) -> Result<(), BenchmarkError> {
    require_fields(
        value,
        &[
            "workload",
            "prompt_domain",
            "prompt_suite",
            "prompt_sha256",
            "actual_prompt_tokens",
            "cold_ttft_seconds",
            "warm_ttft_seconds",
            "cold_cached_prompt_tokens",
            "warm_cached_prompt_tokens",
            "ttft_speedup_ratio",
            "ttft_reduction_percent",
        ],
    )?;
    require_exact_string(value.get("workload"), "pp64000,tg1,c1")?;
    require_exact_string(value.get("prompt_domain"), "code")?;
    require_exact_string(value.get("prompt_suite"), "letsinfer-code-prose-v1")?;
    require_sha256(value.get("prompt_sha256"))?;
    let prompt_tokens = positive_integer(value.get("actual_prompt_tokens"))?;
    let cold = positive_number(value.get("cold_ttft_seconds"))?;
    let warm = positive_number(value.get("warm_ttft_seconds"))?;
    let cold_cached = integer(value.get("cold_cached_prompt_tokens"))?;
    let warm_cached = integer(value.get("warm_cached_prompt_tokens"))?;
    if cold_cached > prompt_tokens || warm_cached > prompt_tokens || warm_cached <= cold_cached {
        return rejected();
    }
    let speedup = positive_number(value.get("ttft_speedup_ratio"))?;
    let reduction = number(value.get("ttft_reduction_percent"))?;
    if !close(speedup, cold / warm, 1e-9, 1e-12)
        || !close(reduction, (cold - warm) * 100.0 / cold, 1e-9, 1e-9)
    {
        return rejected();
    }
    Ok(())
}

// Parses one canonical workload identity and returns its stream concurrency.
fn parse_workload(value: &str) -> Result<usize, BenchmarkError> {
    let Some((prompt, remainder)) = value
        .strip_prefix("pp")
        .and_then(|value| value.split_once(",tg"))
    else {
        return rejected();
    };
    let Some((generation, concurrency)) = remainder.split_once(",c") else {
        return rejected();
    };
    if !positive_decimal(prompt) || !positive_decimal(generation) || !positive_decimal(concurrency)
    {
        return rejected();
    }
    concurrency
        .parse::<usize>()
        .map_err(|_| BenchmarkError::EvidenceRejected)
}

// Requires one closed JSON object field inventory.
fn require_fields(value: &Map<String, Value>, expected: &[&str]) -> Result<(), BenchmarkError> {
    if value.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != expected.iter().copied().collect::<BTreeSet<_>>()
    {
        return rejected();
    }
    Ok(())
}

// Returns one required JSON object.
fn object(value: Option<&Value>) -> Result<&Map<String, Value>, BenchmarkError> {
    value
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Returns one required JSON array.
fn array(value: Option<&Value>) -> Result<&[Value], BenchmarkError> {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Returns one required JSON string.
fn string(value: Option<&Value>) -> Result<&str, BenchmarkError> {
    value
        .and_then(Value::as_str)
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Requires one exact string value.
fn require_exact_string(value: Option<&Value>, expected: &str) -> Result<(), BenchmarkError> {
    if string(value)? != expected {
        return rejected();
    }
    Ok(())
}

// Requires one string from a closed set.
fn require_string_member(value: Option<&Value>, expected: &[&str]) -> Result<(), BenchmarkError> {
    if !expected.contains(&string(value)?) {
        return rejected();
    }
    Ok(())
}

// Requires one exact ordered string list.
fn matches_string_list(value: &[Value], expected: &[&str]) -> bool {
    value.len() == expected.len()
        && value
            .iter()
            .zip(expected)
            .all(|(observed, expected)| observed.as_str() == Some(*expected))
}

// Requires one exact ordered integer list.
fn matches_integer_list(value: &[Value], expected: &[u64]) -> bool {
    value.len() == expected.len()
        && value
            .iter()
            .zip(expected)
            .all(|(observed, expected)| observed.as_u64() == Some(*expected))
}

// Returns one required unsigned JSON integer.
fn integer(value: Option<&Value>) -> Result<u64, BenchmarkError> {
    value
        .and_then(Value::as_u64)
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Returns one required positive JSON integer.
fn positive_integer(value: Option<&Value>) -> Result<u64, BenchmarkError> {
    integer(value).and_then(|value| {
        (value > 0)
            .then_some(value)
            .ok_or(BenchmarkError::EvidenceRejected)
    })
}

// Returns one required nonnegative JSON integer.
fn nonnegative_integer(value: Option<&Value>) -> Result<u64, BenchmarkError> {
    integer(value)
}

// Requires one integer within inclusive bounds.
fn require_integer(
    value: Option<&Value>,
    minimum: u64,
    maximum: u64,
) -> Result<(), BenchmarkError> {
    if !(minimum..=maximum).contains(&integer(value)?) {
        return rejected();
    }
    Ok(())
}

// Returns one required finite JSON number.
fn number(value: Option<&Value>) -> Result<f64, BenchmarkError> {
    value
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Returns one required positive finite JSON number.
fn positive_number(value: Option<&Value>) -> Result<f64, BenchmarkError> {
    number(value).and_then(|value| {
        (value > 0.0)
            .then_some(value)
            .ok_or(BenchmarkError::EvidenceRejected)
    })
}

// Returns one required nonnegative finite JSON number.
fn nonnegative_number(value: Option<&Value>) -> Result<f64, BenchmarkError> {
    number(value).and_then(|value| {
        (value >= 0.0)
            .then_some(value)
            .ok_or(BenchmarkError::EvidenceRejected)
    })
}

// Returns null or one positive finite JSON number.
fn nullable_positive_number(value: Option<&Value>) -> Result<Option<f64>, BenchmarkError> {
    match value {
        Some(Value::Null) => Ok(None),
        _ => positive_number(value).map(Some),
    }
}

// Requires null or a finite number inside inclusive bounds.
fn nullable_range(value: Option<&Value>, minimum: f64, maximum: f64) -> Result<(), BenchmarkError> {
    if value.is_some_and(Value::is_null) {
        return Ok(());
    }
    if !(minimum..=maximum).contains(&number(value)?) {
        return rejected();
    }
    Ok(())
}

// Requires -1 or one positive finite number.
fn unknown_or_positive(value: Option<&Value>) -> Result<(), BenchmarkError> {
    let value = number(value)?;
    if value != -1.0 && value <= 0.0 {
        return rejected();
    }
    Ok(())
}

// Requires -1 or a finite number inside inclusive bounds.
fn unknown_or_range(
    value: Option<&Value>,
    minimum: f64,
    maximum: f64,
) -> Result<(), BenchmarkError> {
    let value = number(value)?;
    if value != -1.0 && !(minimum..=maximum).contains(&value) {
        return rejected();
    }
    Ok(())
}

// Requires -1 or one nonnegative finite number.
fn unknown_or_nonnegative(value: Option<&Value>) -> Result<(), BenchmarkError> {
    let value = number(value)?;
    if value != -1.0 && value < 0.0 {
        return rejected();
    }
    Ok(())
}

// Requires one lowercase hexadecimal SHA-256 identity.
fn require_sha256(value: Option<&Value>) -> Result<(), BenchmarkError> {
    let value = string(value)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return rejected();
    }
    Ok(())
}

// Requires one lowercase safe technical name.
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

// Requires one canonical positive decimal without leading zero.
fn positive_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_digit()
        && value.as_bytes()[0] != b'0'
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

// Parses one finite compact timeline number with Python-compatible outer whitespace.
fn parse_finite(value: &str) -> Result<f64, BenchmarkError> {
    value
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Compares one declared JSON number with an optional computed projection.
fn matches_optional_number(value: Option<&Value>, expected: Option<f64>) -> bool {
    match expected {
        Some(expected) => number(value).is_ok_and(|value| value == expected),
        None => value.is_some_and(Value::is_null),
    }
}

// Implements Python math.isclose for one schema-owned arithmetic projection.
fn close(left: f64, right: f64, relative: f64, absolute: f64) -> bool {
    (left - right).abs() <= absolute.max(relative * left.abs().max(right.abs()))
}

// Returns one stable semantic rejection.
fn rejected<T>() -> Result<T, BenchmarkError> {
    Err(BenchmarkError::EvidenceRejected)
}
