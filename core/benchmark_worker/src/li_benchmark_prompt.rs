// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::BenchmarkWorkerError;

const SUITE: &str = "letsinfer-code-prose-v1";
const SOURCE_WORDS_PER_TARGET_TOKEN: f64 = 0.87;
const NODES: [&str; 8] = [
    "amber", "blue", "calm", "green", "north", "plain", "silver", "west",
];
const ITEMS: [&str; 8] = [
    "batch", "event", "item", "key", "record", "signal", "task", "value",
];
const STATES: [&str; 8] = [
    "clean", "final", "open", "ready", "safe", "stable", "valid", "warm",
];
const ACTIONS: [&str; 8] = [
    "checked", "joined", "kept", "moved", "read", "saved", "sorted", "wrote",
];
const CHECKS: [&str; 8] = [
    "boundary", "order", "range", "retry", "state", "time", "type", "value",
];
const CODE_SHARED_TEMPLATE: &str = include_str!("../../../benchmarks/prompts/code-shared.md");
const PROSE_SHARED_TEMPLATE: &str = include_str!("../../../benchmarks/prompts/prose-shared.md");
const SHORT_CODE_TEMPLATE: &str = include_str!("../../../benchmarks/prompts/short-code.md");
const SHORT_PROSE_TEMPLATE: &str = include_str!("../../../benchmarks/prompts/short-prose.md");

// Stores one closed schema-8 generation request.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeBenchmarkRequest {
    pub output_tokens: u64,
    pub min_completion_tokens: u64,
    pub require_natural_stop: bool,
    pub temperature: f64,
    pub seed: u64,
}

// Stores the exact native prompt generator identity.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeBenchmarkGenerator {
    id: String,
    version: u64,
}

// Stores the exact shared-prefix isolation vocabulary.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeBenchmarkExecution {
    isolation: String,
    prefix_state: String,
    samples_per_cell: u64,
    stream_prefix: String,
}

// Stores immutable tokenizer and Engine payload identities.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeBenchmarkTokenizer {
    capability: String,
    model_sha256: String,
    engine_payload_sha256: String,
    render_contract: String,
}

// Stores the fixed short-workload matrix.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeBenchmarkShort {
    domains: Vec<String>,
    prompt_tokens: u64,
    concurrencies: Vec<u16>,
    request: NativeBenchmarkRequest,
}

// Stores the fixed cold/warm TTFT cache workload.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeBenchmarkTtft {
    prompt_tokens: u64,
    prompt_domain: String,
    repetitions: u64,
    request: NativeBenchmarkRequest,
}

// Stores one ordered context and concurrency lane.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeBenchmarkCase {
    id: String,
    prompt_tokens: u64,
    concurrencies: Vec<u16>,
}

// Stores the complete active schema-8 benchmark contract.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeBenchmarkContract {
    schema_version: u64,
    suite: String,
    generator: NativeBenchmarkGenerator,
    domains: Vec<String>,
    execution: NativeBenchmarkExecution,
    tokenizer: NativeBenchmarkTokenizer,
    pub request: NativeBenchmarkRequest,
    short: NativeBenchmarkShort,
    ttft_cache: NativeBenchmarkTtft,
    sample_interval_seconds: u64,
    cases: Vec<NativeBenchmarkCase>,
}

// Carries one canonical generated prompt and exact Engine-rendered token count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBenchmarkFixture {
    name: String,
    relative_path: String,
    content: String,
    sha256: String,
    prompt_tokens: u64,
}

impl NativeBenchmarkFixture {
    // Returns the stable prompt fixture identity.
    pub fn name(&self) -> &str {
        &self.name
    }

    // Returns canonical UTF-8 prompt bytes.
    pub fn content(&self) -> &str {
        &self.content
    }

    // Returns the exact Engine-rendered prompt-token count.
    pub const fn prompt_tokens(&self) -> u64 {
        self.prompt_tokens
    }

    // Returns the prompt content identity.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

// Carries one exact workload cell and its ordered stream fixtures.
#[derive(Clone, Debug, PartialEq)]
pub struct NativeBenchmarkCell {
    name: String,
    context: String,
    domain: String,
    target_prompt_tokens: u64,
    concurrency: u16,
    request: NativeBenchmarkRequest,
    fixtures: Vec<NativeBenchmarkFixture>,
}

impl NativeBenchmarkCell {
    // Returns the canonical cell name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // Returns whether this is a cold or warm TTFT cache cell.
    pub fn is_ttft(&self) -> bool {
        matches!(self.context.as_str(), "ttftcold" | "ttftwarm")
    }

    // Returns the prompt domain.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    // Returns the nominal context size declared by the contract.
    pub const fn target_prompt_tokens(&self) -> u64 {
        self.target_prompt_tokens
    }

    // Returns the simultaneous stream count.
    pub const fn concurrency(&self) -> u16 {
        self.concurrency
    }

    // Returns the exact generation request.
    pub const fn request(&self) -> &NativeBenchmarkRequest {
        &self.request
    }

    // Returns the ordered canonical stream fixtures.
    pub fn fixtures(&self) -> &[NativeBenchmarkFixture] {
        &self.fixtures
    }
}

// Carries all selected cells and their selected prompt-set identity.
#[derive(Clone, Debug, PartialEq)]
pub struct NativeBenchmarkMaterialization {
    contract: NativeBenchmarkContract,
    cells: Vec<NativeBenchmarkCell>,
    prompt_set_sha256: String,
}

impl NativeBenchmarkMaterialization {
    // Returns the strictly parsed schema-8 contract.
    pub const fn contract(&self) -> &NativeBenchmarkContract {
        &self.contract
    }

    // Returns selected cells in canonical contract order.
    pub fn cells(&self) -> &[NativeBenchmarkCell] {
        &self.cells
    }

    // Returns the selected canonical prompt-set identity.
    pub fn prompt_set_sha256(&self) -> &str {
        &self.prompt_set_sha256
    }

    // Returns the declared process/store isolation policy consumed by the native worker.
    pub(crate) fn execution_isolation(&self) -> &str {
        &self.contract.execution.isolation
    }
}

// Parses, validates, and materializes schema-8 prompts using exact Engine token counts.
pub fn materialize_native_benchmark(
    contract_bytes: &[u8],
    selected_cells: &[String],
    count_tokens: &mut dyn FnMut(&str) -> Result<u64, BenchmarkWorkerError>,
) -> Result<NativeBenchmarkMaterialization, BenchmarkWorkerError> {
    let contract: NativeBenchmarkContract = serde_json::from_slice(contract_bytes)
        .map_err(|_| BenchmarkWorkerError::invalid("benchmark contract JSON is invalid"))?;
    validate_contract(&contract)?;
    let definitions = cell_definitions(&contract);
    let known = definitions
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    let selection = if selected_cells.is_empty() {
        known.clone()
    } else {
        let selection = selected_cells.iter().cloned().collect::<BTreeSet<_>>();
        if selection.len() != selected_cells.len()
            || selection.iter().any(|name| !known.contains(name))
        {
            return Err(BenchmarkWorkerError::invalid(
                "benchmark cell selection is unknown or contains duplicates",
            ));
        }
        selection
    };
    let mut fixture_cache: BTreeMap<(String, String, u16), NativeBenchmarkFixture> =
        BTreeMap::new();
    let mut cells = Vec::new();
    for (name, definition) in definitions {
        if !selection.contains(&name) {
            continue;
        }
        let mut fixtures = Vec::with_capacity(usize::from(definition.concurrency));
        for slot in 0..definition.concurrency {
            let key = (definition.context.clone(), definition.domain.clone(), slot);
            let fixture = if let Some(fixture) = fixture_cache.get(&key) {
                fixture.clone()
            } else {
                let fixture = materialize_fixture(&definition, slot, count_tokens)?;
                fixture_cache.insert(key, fixture.clone());
                fixture
            };
            fixtures.push(fixture);
        }
        cells.push(NativeBenchmarkCell {
            name,
            context: definition.context,
            domain: definition.domain,
            target_prompt_tokens: definition.target_prompt_tokens,
            concurrency: definition.concurrency,
            request: definition.request,
            fixtures,
        });
    }
    if cells.is_empty() {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark cell selection is empty",
        ));
    }
    let mut rows = cells
        .iter()
        .flat_map(|cell| cell.fixtures.iter())
        .map(|fixture| (fixture.relative_path.clone(), fixture.sha256.clone()))
        .collect::<Vec<_>>();
    rows.sort();
    rows.dedup();
    let mut digest = Sha256::new();
    for (path, sha256) in rows {
        digest.update(path.as_bytes());
        digest.update([0]);
        digest.update(sha256.as_bytes());
        digest.update(b"\n");
    }
    Ok(NativeBenchmarkMaterialization {
        contract,
        cells,
        prompt_set_sha256: format!("{:x}", digest.finalize()),
    })
}

// Stores one internal materialization lane before stream fixtures exist.
#[derive(Clone)]
struct CellDefinition {
    context: String,
    domain: String,
    target_prompt_tokens: u64,
    concurrency: u16,
    request: NativeBenchmarkRequest,
    short: bool,
    ttft: bool,
}

// Enumerates schema-8 cells in the Python oracle's stable insertion order.
fn cell_definitions(contract: &NativeBenchmarkContract) -> Vec<(String, CellDefinition)> {
    let mut cells = Vec::new();
    for concurrency in &contract.short.concurrencies {
        for domain in &contract.short.domains {
            cells.push((
                format!("short-{domain}-c{concurrency}"),
                CellDefinition {
                    context: "short".to_string(),
                    domain: domain.clone(),
                    target_prompt_tokens: contract.short.prompt_tokens,
                    concurrency: *concurrency,
                    request: contract.short.request.clone(),
                    short: true,
                    ttft: false,
                },
            ));
        }
    }
    for case in &contract.cases {
        for concurrency in &case.concurrencies {
            for domain in &contract.domains {
                cells.push((
                    format!("{}-{domain}-c{concurrency}", case.id),
                    CellDefinition {
                        context: case.id.clone(),
                        domain: domain.clone(),
                        target_prompt_tokens: case.prompt_tokens,
                        concurrency: *concurrency,
                        request: contract.request.clone(),
                        short: false,
                        ttft: false,
                    },
                ));
            }
        }
    }
    for phase in ["ttftcold", "ttftwarm"] {
        cells.push((
            format!("{phase}-code-c1"),
            CellDefinition {
                context: phase.to_string(),
                domain: "code".to_string(),
                target_prompt_tokens: contract.ttft_cache.prompt_tokens,
                concurrency: 1,
                request: contract.ttft_cache.request.clone(),
                short: false,
                ttft: true,
            },
        ));
    }
    cells
}

// Materializes one fixture exactly once through the schema-8 generator algorithm.
fn materialize_fixture(
    definition: &CellDefinition,
    slot: u16,
    count_tokens: &mut dyn FnMut(&str) -> Result<u64, BenchmarkWorkerError>,
) -> Result<NativeBenchmarkFixture, BenchmarkWorkerError> {
    let fixture_id = format!("{}-{}-s{slot:02}", definition.context, definition.domain);
    let seed_context = if definition.ttft {
        "ttft64k"
    } else {
        &definition.context
    };
    let content_fixture_id = if definition.ttft {
        format!("ttft64k-{}-s{slot:02}", definition.domain)
    } else {
        fixture_id.clone()
    };
    let seed_material = format!("{SUITE}\0{seed_context}\0{slot}");
    let marker = format!(
        "LETSINFER-{}",
        hex_upper(&Sha256::digest(seed_material.as_bytes()))[..24].to_string()
    );
    let body_seed_material = format!("{SUITE}\0{seed_context}\0shared-body");
    let body_digest = Sha256::digest(body_seed_material.as_bytes());
    let body_seed = u32::from_be_bytes(body_digest[..4].try_into().expect("fixed digest prefix"));
    let template = template(&definition.domain, definition.short)?;
    let content = if definition.short {
        template.trim_end_matches('\n').to_string()
    } else {
        render_template(
            template,
            &content_fixture_id,
            &marker,
            slot,
            &source_text(body_seed, definition.target_prompt_tokens),
        )?
    };
    let prompt_tokens = count_tokens(&content)?;
    if prompt_tokens == 0 {
        return Err(BenchmarkWorkerError::invalid(
            "Engine token counter returned zero",
        ));
    }
    Ok(NativeBenchmarkFixture {
        name: fixture_id.clone(),
        relative_path: format!("prompts/{fixture_id}.md"),
        sha256: sha256(content.as_bytes()),
        content,
        prompt_tokens,
    })
}

// Returns the only schema-8 embedded prompt template for one domain and lane.
fn template(domain: &str, short: bool) -> Result<&'static str, BenchmarkWorkerError> {
    match (domain, short) {
        ("code", false) => Ok(CODE_SHARED_TEMPLATE),
        ("prose", false) => Ok(PROSE_SHARED_TEMPLATE),
        ("code", true) => Ok(SHORT_CODE_TEMPLATE),
        ("prose", true) => Ok(SHORT_PROSE_TEMPLATE),
        _ => Err(BenchmarkWorkerError::invalid(
            "benchmark prompt domain is unsupported",
        )),
    }
}

// Creates the deterministic event ledger without consulting a tokenizer.
fn source_text(seed: u32, target_prompt_tokens: u64) -> String {
    let scaled = (target_prompt_tokens as f64 * SOURCE_WORDS_PER_TARGET_TOKEN) as usize;
    let word_budget = scaled.max(256);
    let mut state = if seed == 0 { 0x9e37_79b9 } else { seed };
    let mut words = Vec::with_capacity(word_budget);
    while words.len() < word_budget {
        let tables = [
            &NODES[..],
            &ITEMS[..],
            &STATES[..],
            &ACTIONS[..],
            &CHECKS[..],
            &NODES[..],
            &ITEMS[..],
            &STATES[..],
        ];
        let mut chosen = Vec::with_capacity(tables.len());
        for values in tables {
            state = next_state(state);
            chosen.push(values[state as usize % values.len()]);
        }
        let sentence = format!(
            "The {} node {} the {} after the {} check and kept the {} in the {} state while the {} node recorded the result.",
            chosen[0], chosen[3], chosen[1], chosen[4], chosen[6], chosen[7], chosen[5]
        );
        for word in sentence.split_whitespace() {
            if words.len() == word_budget {
                break;
            }
            words.push(word.to_string());
        }
    }
    let mut lines = words
        .chunks(24)
        .map(|line| line.join(" "))
        .collect::<Vec<_>>()
        .join(".\n");
    lines.push_str(".\n");
    lines
}

// Advances one canonical xorshift32 generator state.
fn next_state(mut state: u32) -> u32 {
    state ^= state.wrapping_shl(13);
    state ^= state >> 17;
    state ^= state.wrapping_shl(5);
    state
}

// Replaces every template placeholder and rejects unresolved template syntax.
fn render_template(
    template: &str,
    fixture_id: &str,
    marker: &str,
    slot: u16,
    body: &str,
) -> Result<String, BenchmarkWorkerError> {
    let value = template
        .replace("{{FIXTURE_ID}}", fixture_id)
        .replace("{{MARKER}}", marker)
        .replace("{{SLOT}}", &slot.to_string())
        .replace("{{BODY}}", body);
    if value.contains("{{") || value.contains("}}") {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark template contains an unresolved placeholder",
        ));
    }
    Ok(value)
}

// Validates the closed schema-8 contract independently at the worker boundary.
fn validate_contract(contract: &NativeBenchmarkContract) -> Result<(), BenchmarkWorkerError> {
    let domains = contract.domains.as_slice();
    let valid_domains = domains == ["code"] || domains == ["prose"] || domains == ["code", "prose"];
    let tokenizer = &contract.tokenizer;
    if contract.schema_version != 8
        || contract.suite != SUITE
        || contract.generator.id != "letsinfer-code-prose"
        || contract.generator.version != 8
        || !valid_domains
        || !matches!(
            contract.execution.isolation.as_str(),
            "fresh-context" | "fresh-matrix"
        )
        || contract.execution.prefix_state != "shared"
        || contract.execution.samples_per_cell != 1
        || contract.execution.stream_prefix != "shared-body"
        || tokenizer.capability != "engine-rendered-chat-count-v1"
        || !is_digest(&tokenizer.model_sha256)
        || !is_digest(&tokenizer.engine_payload_sha256)
        || tokenizer.render_contract != "openai-chat-user-v1"
        || contract.short.domains != ["code", "prose"]
        || contract.short.prompt_tokens == 0
        || contract.short.concurrencies != [1, 2, 4]
        || contract.ttft_cache.prompt_tokens != 64_000
        || contract.ttft_cache.prompt_domain != "code"
        || contract.ttft_cache.repetitions != 2
        || !(1..=60).contains(&contract.sample_interval_seconds)
        || contract.cases.is_empty()
    {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark contract is not supported schema 8",
        ));
    }
    validate_request(&contract.request, false)?;
    validate_request(&contract.short.request, false)?;
    validate_request(&contract.ttft_cache.request, true)?;
    let mut prior = BTreeSet::new();
    for case in &contract.cases {
        if !safe_name(&case.id)
            || matches!(case.id.as_str(), "short" | "ttft" | "ttftcold" | "ttftwarm")
            || !prior.insert(case.id.clone())
            || case.prompt_tokens == 0
            || case.concurrencies.is_empty()
            || case
                .concurrencies
                .iter()
                .any(|value| !(1..=128).contains(value))
            || case
                .concurrencies
                .windows(2)
                .any(|values| values[0] >= values[1])
        {
            return Err(BenchmarkWorkerError::invalid(
                "benchmark case matrix is invalid",
            ));
        }
    }
    Ok(())
}

// Validates one bounded schema-8 generation request.
fn validate_request(
    request: &NativeBenchmarkRequest,
    ttft: bool,
) -> Result<(), BenchmarkWorkerError> {
    if request.output_tokens == 0
        || request.min_completion_tokens == 0
        || request.min_completion_tokens > request.output_tokens
        || !request.temperature.is_finite()
        || request.temperature < 0.0
        || (ttft
            && (request.output_tokens != 1
                || request.min_completion_tokens != 1
                || request.require_natural_stop
                || request.temperature != 0.0))
    {
        return Err(BenchmarkWorkerError::invalid(
            "benchmark generation request is invalid",
        ));
    }
    Ok(())
}

// Returns whether one value is a canonical SHA-256 identity.
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Returns whether one case identity uses the shared technical-name alphabet.
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

// Hashes bytes into lowercase SHA-256 text.
fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

// Renders bytes as uppercase hexadecimal marker text.
fn hex_upper(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02X}")).collect()
}
