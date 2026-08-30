// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use li_benchmark_manager::{
    canonical_benchmark_json_bytes, validate_benchmark_record_bytes, BenchmarkError,
    BenchmarkExecutionOutcome, BenchmarkFailureCategory, BenchmarkGitRevision, BenchmarkKind,
    BenchmarkPublication, BenchmarkPublicationProvider, BenchmarkPublicationRequest,
    BenchmarkRecordSchema,
};
use li_core_interface::{RuntimeCandidateId, RuntimeVersion, Sha256Digest};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const REPOSITORY: &str = "letsinferlabs/runtimes";
const KIND: &str = "letsinfer.runtime-verification";
const COMMENT_MARKER: &str = "letsinfer-verification:v1";
const EVIDENCE_MEDIA_TYPE: &str = "application/vnd.letsinfer.verification-benchmark.v1+json";
const EVIDENCE_ENCODING: &str = "zstd-19+base64url";
const COMMENT_LIMIT_BYTES: usize = 60_000;
const MAXIMUM_EXPANDED_EVIDENCE_BYTES: usize = 4 << 20;
const MAXIMUM_GITHUB_OUTPUT_BYTES: usize = 4 << 20;
const MAXIMUM_GITHUB_PAGES: usize = 100;
const MAXIMUM_GITHUB_COMMENTS: usize = 10_000;
const GITHUB_TIMEOUT: Duration = Duration::from_secs(60);
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[cfg_attr(target_os = "linux", link(name = "m"))]
unsafe extern "C" {
    // Computes the same platform-libm logarithm used by Python's `math.log`.
    #[link_name = "log"]
    fn python_log(value: f64) -> f64;
    // Computes the same platform-libm exponent used by Python's `math.exp`.
    #[link_name = "exp"]
    fn python_exp(value: f64) -> f64;
}

// Carries the public verifier account identity used by visible and signed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreBenchmarkVerificationGitHubIdentity {
    login: String,
    numeric_id: u64,
    account_type: String,
}

impl CoreBenchmarkVerificationGitHubIdentity {
    // Creates one exact authenticated human GitHub identity without accepting aliases.
    pub fn new(login: &str, numeric_id: u64, account_type: &str) -> Result<Self, BenchmarkError> {
        if !valid_github_login(login) || numeric_id == 0 || account_type != "User" {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(Self {
            login: login.to_string(),
            numeric_id,
            account_type: account_type.to_string(),
        })
    }

    // Returns the immutable public login used in the visible summary.
    pub fn login(&self) -> &str {
        &self.login
    }

    // Returns GitHub's immutable numeric account identity.
    pub const fn numeric_id(&self) -> u64 {
        self.numeric_id
    }

    // Returns the closed account type accepted by verification consensus.
    pub fn account_type(&self) -> &str {
        &self.account_type
    }
}

// Supplies every parent-orchestrated paired-run input without GitHub credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreBenchmarkVerificationPublicationMaterial {
    pull_request_url: String,
    observed_head_sha: BenchmarkGitRevision,
    proposal_base_sha: BenchmarkGitRevision,
    engine_mode: String,
    verifier: CoreBenchmarkVerificationGitHubIdentity,
    pull_request_author_numeric_id: u64,
    runtime_author_numeric_ids: Vec<u64>,
    execution_subject_json: Vec<u8>,
    candidate_benchmark_json: Option<Vec<u8>>,
    baseline_benchmark_json: Vec<u8>,
    restoration_passed: bool,
    submitted_at_unix_seconds: u64,
}

impl CoreBenchmarkVerificationPublicationMaterial {
    // Creates one bounded parent-owned paired-run closure before JSON interpretation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pull_request_url: String,
        observed_head_sha: BenchmarkGitRevision,
        proposal_base_sha: BenchmarkGitRevision,
        engine_mode: String,
        verifier: CoreBenchmarkVerificationGitHubIdentity,
        pull_request_author_numeric_id: u64,
        runtime_author_numeric_ids: Vec<u64>,
        execution_subject_json: Vec<u8>,
        candidate_benchmark_json: Option<Vec<u8>>,
        baseline_benchmark_json: Vec<u8>,
        restoration_passed: bool,
        submitted_at_unix_seconds: u64,
    ) -> Result<Self, BenchmarkError> {
        let unique = runtime_author_numeric_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if pull_request_url.len() > 512
            || !matches!(
                engine_mode.as_str(),
                "reuse-engine" | "build-engine" | "build-native-engine"
            )
            || pull_request_author_numeric_id == 0
            || runtime_author_numeric_ids.len() > 64
            || unique.len() != runtime_author_numeric_ids.len()
            || unique.contains(&0)
            || execution_subject_json.is_empty()
            || execution_subject_json.len() > 128 * 1024
            || candidate_benchmark_json.as_ref().is_some_and(|bytes| {
                bytes.is_empty() || bytes.len() > MAXIMUM_EXPANDED_EVIDENCE_BYTES
            })
            || baseline_benchmark_json.is_empty()
            || baseline_benchmark_json.len() > MAXIMUM_EXPANDED_EVIDENCE_BYTES
            || submitted_at_unix_seconds == 0
        {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(Self {
            pull_request_url,
            observed_head_sha,
            proposal_base_sha,
            engine_mode,
            verifier,
            pull_request_author_numeric_id,
            runtime_author_numeric_ids,
            execution_subject_json,
            candidate_benchmark_json,
            baseline_benchmark_json,
            restoration_passed,
            submitted_at_unix_seconds,
        })
    }
}

// Resolves paired-run publication material by exact durable benchmark operation.
pub trait CoreBenchmarkVerificationPublicationMaterialPort: Send + Sync {
    // Returns one immutable paired result or fails without posting partial evidence.
    fn material(
        &self,
        request: &CoreBenchmarkVerificationRecordRequest<'_>,
    ) -> Result<CoreBenchmarkVerificationPublicationMaterial, BenchmarkError>;
}

// Presents terminal verification state before evidence identity and signature exist.
pub struct CoreBenchmarkVerificationRecordRequest<'a> {
    job_id: &'a li_core_interface::OperationId,
    request: &'a li_benchmark_manager::BenchmarkRequest,
    outcome: &'a BenchmarkExecutionOutcome,
    restoration: &'a li_benchmark_manager::BenchmarkRestoration,
}

impl<'a> CoreBenchmarkVerificationRecordRequest<'a> {
    // Creates one borrowed record-construction view without fabricating sealed evidence.
    pub const fn new(
        job_id: &'a li_core_interface::OperationId,
        request: &'a li_benchmark_manager::BenchmarkRequest,
        outcome: &'a BenchmarkExecutionOutcome,
        restoration: &'a li_benchmark_manager::BenchmarkRestoration,
    ) -> Self {
        Self {
            job_id,
            request,
            outcome,
            restoration,
        }
    }

    // Returns the durable outer verification job identity.
    pub const fn job_id(&self) -> &li_core_interface::OperationId {
        self.job_id
    }

    // Returns the exact typed verification request.
    pub const fn request(&self) -> &li_benchmark_manager::BenchmarkRequest {
        self.request
    }

    // Returns the terminal paired outcome before publication.
    pub const fn outcome(&self) -> &BenchmarkExecutionOutcome {
        self.outcome
    }

    // Returns the exact baseline-restoration receipt.
    pub const fn restoration(&self) -> &li_benchmark_manager::BenchmarkRestoration {
        self.restoration
    }
}

// Returns exact persisted outer-record bytes by their already-sealed evidence identity.
pub trait CoreBenchmarkVerificationRecordReader: Send + Sync {
    // Reads one bounded record and never reconstructs it from mutable external state.
    fn record(&self, request: &BenchmarkPublicationRequest<'_>) -> Result<Vec<u8>, BenchmarkError>;
}

// Carries one exact DER-identified Ed25519 verifier device identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreBenchmarkVerificationDeviceIdentity {
    device_id: Sha256Digest,
    key_id: Sha256Digest,
    public_key_spki: Vec<u8>,
}

impl CoreBenchmarkVerificationDeviceIdentity {
    // Creates one bounded identity only when device and signature-key identities agree.
    pub fn new(
        device_id: Sha256Digest,
        key_id: Sha256Digest,
        public_key_spki: Vec<u8>,
    ) -> Result<Self, BenchmarkError> {
        if device_id != key_id
            || public_key_spki.len() != ED25519_SPKI_PREFIX.len() + 32
            || !public_key_spki.starts_with(ED25519_SPKI_PREFIX)
            || digest(&public_key_spki)? != device_id
        {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(Self {
            device_id,
            key_id,
            public_key_spki,
        })
    }
}

// Signs one canonical envelope through the setup-issued device identity.
pub trait CoreBenchmarkVerificationDeviceSigner: Send + Sync {
    // Returns the exact DER public key identity without private material.
    fn identity(&self) -> Result<CoreBenchmarkVerificationDeviceIdentity, BenchmarkError>;

    // Returns one raw Ed25519 signature over exact canonical bytes.
    fn sign(&self, unsigned_envelope: &[u8]) -> Result<Vec<u8>, BenchmarkError>;
}

// Carries canonical CommunityVerificationV1 bytes and every publication identity derived from them.
#[derive(Clone)]
pub struct CoreBenchmarkVerificationRecord {
    bytes: Vec<u8>,
    value: Value,
    pull_request: u64,
    proposal_head: BenchmarkGitRevision,
    candidate: RuntimeCandidateId,
    verification_id: Sha256Digest,
    record_sha256: Sha256Digest,
    candidate_benchmark_id: Option<Sha256Digest>,
    baseline_benchmark_id: Option<Sha256Digest>,
    score_sha256: Sha256Digest,
    device_id: Sha256Digest,
    signature_key_id: Sha256Digest,
    visible_summary: String,
}

impl CoreBenchmarkVerificationRecord {
    // Returns exact Python-compatible canonical bytes for atomic evidence persistence.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    // Returns the canonical expanded-record SHA-256 used as evidence identity.
    pub const fn record_sha256(&self) -> &Sha256Digest {
        &self.record_sha256
    }
}

// Builds one outer verification record before BenchmarkManager signs its evidence receipt.
pub struct CoreBenchmarkVerificationRecordBuilder {
    material: Arc<dyn CoreBenchmarkVerificationPublicationMaterialPort>,
    signer: Arc<dyn CoreBenchmarkVerificationDeviceSigner>,
}

impl CoreBenchmarkVerificationRecordBuilder {
    // Creates one record builder from exact paired material and device identity capabilities.
    pub const fn new(
        material: Arc<dyn CoreBenchmarkVerificationPublicationMaterialPort>,
        signer: Arc<dyn CoreBenchmarkVerificationDeviceSigner>,
    ) -> Self {
        Self { material, signer }
    }

    // Materializes one canonical record without creating an envelope or external side effect.
    pub fn record(
        &self,
        request: &CoreBenchmarkVerificationRecordRequest<'_>,
    ) -> Result<CoreBenchmarkVerificationRecord, BenchmarkError> {
        let material = self.material.material(request)?;
        let identity = self.signer.identity()?;
        build_record(request, &material, &identity)
    }
}

// Carries one bounded shell-free GitHub CLI process result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreBenchmarkVerificationGitHubCommandOutput {
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CoreBenchmarkVerificationGitHubCommandOutput {
    // Creates one exact result without interpreting its response bytes.
    pub const fn new(status: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            status,
            stdout,
            stderr,
        }
    }

    // Returns the native process exit status or -1 after signal termination.
    pub const fn status(&self) -> i32 {
        self.status
    }

    // Returns the bounded stdout consumed only by the closed GitHub parser.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    // Returns bounded diagnostics only for stable failure classification.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

// Executes exact GitHub CLI argv with optional bounded canonical stdin.
pub trait CoreBenchmarkVerificationGitHubCommandRunner: Send + Sync {
    // Runs one shell-free command under one hard time and combined-output bound.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        input: Option<&[u8]>,
        timeout: Duration,
        maximum_output_bytes: usize,
    ) -> Result<CoreBenchmarkVerificationGitHubCommandOutput, BenchmarkError>;
}

// Runs GitHub CLI without a shell while preserving its existing credential environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreBenchmarkVerificationGitHubCommandRunner;

impl CoreBenchmarkVerificationGitHubCommandRunner
    for SystemCoreBenchmarkVerificationGitHubCommandRunner
{
    // Executes one exact argv, writes optional stdin, and kills a process crossing its bound.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        input: Option<&[u8]>,
        timeout: Duration,
        maximum_output_bytes: usize,
    ) -> Result<CoreBenchmarkVerificationGitHubCommandOutput, BenchmarkError> {
        run_github_command(executable, arguments, input, timeout, maximum_output_bytes)
    }
}

// Builds, posts, reads back, and verifies one exact signed verification comment.
pub struct CoreBenchmarkVerificationPublicationProvider {
    github_cli: PathBuf,
    records: Arc<dyn CoreBenchmarkVerificationRecordReader>,
    signer: Arc<dyn CoreBenchmarkVerificationDeviceSigner>,
    runner: Arc<dyn CoreBenchmarkVerificationGitHubCommandRunner>,
}

impl CoreBenchmarkVerificationPublicationProvider {
    // Creates one publisher from explicit credential-free composition authorities.
    pub fn new(
        github_cli: PathBuf,
        records: Arc<dyn CoreBenchmarkVerificationRecordReader>,
        signer: Arc<dyn CoreBenchmarkVerificationDeviceSigner>,
        runner: Arc<dyn CoreBenchmarkVerificationGitHubCommandRunner>,
    ) -> Result<Self, BenchmarkError> {
        if !absolute_normal(&github_cli) {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(Self {
            github_cli,
            records,
            signer,
            runner,
        })
    }

    // Publishes one verification and requires exact signed readback before returning a receipt.
    fn publish_verification(
        &self,
        request: &BenchmarkPublicationRequest<'_>,
    ) -> Result<BenchmarkPublication, BenchmarkError> {
        let record = self.records.record(request)?;
        let built = build_publication(request, &record, self.signer.as_ref())?;
        let comment = self.publish_comment(&built)?;
        BenchmarkPublication::new(
            built.verification_id,
            built.record_sha256,
            built.body_sha256,
            built.pull_request,
            built.proposal_head,
            built.candidate,
            built.candidate_benchmark_id,
            built.baseline_benchmark_id,
            built.score_sha256,
            request.restoration().receipt_id().clone(),
            request.sealed().evidence().evidence_id().clone(),
            built.device_id,
            built.signature_key_id,
            comment.id,
            comment.url,
        )
    }

    // Finds an exact replay or posts and then mandatorily re-reads the expected comment.
    fn publish_comment(&self, built: &BuiltPublication) -> Result<GitHubComment, BenchmarkError> {
        match self.lookup_comment(built)? {
            Some(comment) => return Ok(comment),
            None => {}
        }
        let input = canonical_json(&json!({"body": built.body}))?;
        let arguments = vec![
            "api".to_string(),
            "--method".to_string(),
            "POST".to_string(),
            format!("repos/{REPOSITORY}/issues/{}/comments", built.pull_request),
            "--input".to_string(),
            "-".to_string(),
        ];
        let posted = self.runner.run(
            &self.github_cli,
            &arguments,
            Some(&input),
            GITHUB_TIMEOUT,
            MAXIMUM_GITHUB_OUTPUT_BYTES,
        );
        if posted.as_ref().is_ok_and(|output| output.status() == 0) {
            // The response is deliberately not authority; lookup/readback below owns success.
        }
        self.lookup_comment(built)?
            .ok_or(BenchmarkError::PublicationRejected)
    }

    // Lists every bounded page and returns only exact replay after full parse/readback equality.
    fn lookup_comment(
        &self,
        built: &BuiltPublication,
    ) -> Result<Option<GitHubComment>, BenchmarkError> {
        let arguments = vec![
            "api".to_string(),
            "--paginate".to_string(),
            "--slurp".to_string(),
            format!(
                "repos/{REPOSITORY}/issues/{}/comments?per_page=100",
                built.pull_request
            ),
        ];
        let output = self.runner.run(
            &self.github_cli,
            &arguments,
            None,
            GITHUB_TIMEOUT,
            MAXIMUM_GITHUB_OUTPUT_BYTES,
        )?;
        if output.status() != 0 {
            return Err(BenchmarkError::PublicationRejected);
        }
        let pages: Value = serde_json::from_slice(output.stdout())
            .map_err(|_| BenchmarkError::PublicationRejected)?;
        let pages = pages
            .as_array()
            .ok_or(BenchmarkError::PublicationRejected)?;
        if pages.len() > MAXIMUM_GITHUB_PAGES {
            return Err(BenchmarkError::PublicationRejected);
        }
        let marker = format!("\"verification_id\":\"{}\"", built.verification_id.as_str());
        let mut observed = None;
        let mut count = 0_usize;
        for page in pages {
            let comments = page.as_array().ok_or(BenchmarkError::PublicationRejected)?;
            if comments.len() > 100 {
                return Err(BenchmarkError::PublicationRejected);
            }
            for value in comments {
                count += 1;
                if count > MAXIMUM_GITHUB_COMMENTS {
                    return Err(BenchmarkError::PublicationRejected);
                }
                let object = value
                    .as_object()
                    .ok_or(BenchmarkError::PublicationRejected)?;
                let Some(body) = object.get("body").and_then(Value::as_str) else {
                    continue;
                };
                if !body.contains(&marker) {
                    continue;
                }
                if body != built.body {
                    return Err(BenchmarkError::PublicationRejected);
                }
                parse_comment(body, built)?;
                let id = object
                    .get("id")
                    .and_then(Value::as_u64)
                    .filter(|id| *id > 0)
                    .ok_or(BenchmarkError::PublicationRejected)?;
                let url = object
                    .get("html_url")
                    .and_then(Value::as_str)
                    .ok_or(BenchmarkError::PublicationRejected)?;
                require_comment_url(url, built.pull_request, id)?;
                let comment = GitHubComment {
                    id,
                    url: url.to_string(),
                };
                if observed.replace(comment.clone()).is_some() {
                    return Err(BenchmarkError::PublicationRejected);
                }
            }
        }
        Ok(observed)
    }
}

impl BenchmarkPublicationProvider for CoreBenchmarkVerificationPublicationProvider {
    // Publishes only community verification; local evidence deliberately has no external receipt.
    fn publish(
        &self,
        request: &BenchmarkPublicationRequest<'_>,
    ) -> Result<Option<BenchmarkPublication>, BenchmarkError> {
        if !request.request().kind().is_verification() {
            return Ok(None);
        }
        match request.sealed().evidence().schema() {
            BenchmarkRecordSchema::CommunityVerificationV1 => {
                self.publish_verification(request).map(Some)
            }
            BenchmarkRecordSchema::CoreLocalFailureV1 => Ok(None),
            BenchmarkRecordSchema::OciExecutionPayloadV7
            | BenchmarkRecordSchema::NativeExecutionPayloadV8 => {
                Err(BenchmarkError::PublicationRejected)
            }
        }
    }
}

// Retains every independently verified comment and record identity until receipt construction.
struct BuiltPublication {
    pull_request: u64,
    proposal_head: BenchmarkGitRevision,
    candidate: RuntimeCandidateId,
    verification_id: Sha256Digest,
    record_sha256: Sha256Digest,
    body_sha256: Sha256Digest,
    candidate_benchmark_id: Option<Sha256Digest>,
    baseline_benchmark_id: Option<Sha256Digest>,
    score_sha256: Sha256Digest,
    device_id: Sha256Digest,
    signature_key_id: Sha256Digest,
    record: Value,
    envelope: Value,
    visible_summary: String,
    body: String,
}

// Returns one immutable GitHub comment readback receipt.
#[derive(Clone)]
struct GitHubComment {
    id: u64,
    url: String,
}

// Retains one schema-validated benchmark record and its score/method projection.
struct ValidatedBenchmark {
    value: Value,
    id: Sha256Digest,
    target: String,
    score_values: [Vec<f64>; 2],
    method: Vec<Value>,
}

// Builds one exact Python-compatible verification record before evidence signing.
fn build_record(
    request: &CoreBenchmarkVerificationRecordRequest<'_>,
    material: &CoreBenchmarkVerificationPublicationMaterial,
    identity: &CoreBenchmarkVerificationDeviceIdentity,
) -> Result<CoreBenchmarkVerificationRecord, BenchmarkError> {
    let BenchmarkKind::Verification {
        pull_request,
        proposal_head,
        candidate,
        candidate_subject_sha256,
        verifier_numeric_id,
        device_id,
        ..
    } = request.request().kind()
    else {
        return Err(BenchmarkError::PublicationRejected);
    };
    let expected_url = format!("https://github.com/{REPOSITORY}/pull/{pull_request}");
    if material.pull_request_url != expected_url
        || material.observed_head_sha != *proposal_head
        || material.verifier.numeric_id() != *verifier_numeric_id
        || &identity.device_id != device_id
        || identity.device_id != identity.key_id
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let subject = validated_execution_subject(
        &material.execution_subject_json,
        candidate,
        *pull_request,
        proposal_head,
        &material.proposal_base_sha,
        &material.engine_mode,
        candidate_subject_sha256,
        request.request().subject().benchmark_contract_sha256(),
        request.request().subject().target_contract_sha256(),
    )?;
    let baseline = validated_benchmark(
        &material.baseline_benchmark_json,
        None,
        request.request().subject().benchmark_contract_sha256(),
    )?;
    let candidate_benchmark = material
        .candidate_benchmark_json
        .as_deref()
        .map(|bytes| {
            validated_benchmark(
                bytes,
                Some(candidate),
                request.request().subject().benchmark_contract_sha256(),
            )
        })
        .transpose()?;
    if candidate_benchmark
        .as_ref()
        .is_some_and(|value| value.target != baseline.target || value.method != baseline.method)
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let failure = verification_failure(request.outcome());
    if failure.is_none() && candidate_benchmark.is_none() {
        return Err(BenchmarkError::PublicationRejected);
    }
    let category = failure
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|value| value.get("category"))
        .and_then(Value::as_str);
    if material.restoration_passed != (category != Some("restoration")) {
        return Err(BenchmarkError::PublicationRejected);
    }
    let correctness_passed = !matches!(category, Some("output_validation" | "incomplete_workload"));
    let safety_passed = !matches!(
        category,
        Some("crash" | "out_of_memory" | "protection_trip" | "output_validation")
    );
    if failure.is_some() && category != Some("restoration") && candidate_benchmark.is_some() {
        return Err(BenchmarkError::PublicationRejected);
    }
    let score = if failure.is_none() {
        candidate_benchmark
            .as_ref()
            .map(|candidate| aggregate_score(candidate, &baseline))
            .transpose()?
    } else {
        None
    };
    let counts_toward_consensus = material.verifier.numeric_id()
        != material.pull_request_author_numeric_id
        && !material
            .runtime_author_numeric_ids
            .contains(&material.verifier.numeric_id());
    let restoration = json!({
        "passed": material.restoration_passed,
        "receipt_id": request.restoration().receipt_id().as_str(),
    });
    let candidate_value = candidate_benchmark
        .as_ref()
        .map(|value| value.value.clone());
    let baseline_value = baseline.value.clone();
    let record = json!({
        "schema_version": 1,
        "kind": KIND,
        "repository": REPOSITORY,
        "pull_request": pull_request,
        "pull_request_url": material.pull_request_url,
        "observed_head_sha": proposal_head.as_str(),
        "submitted_at_unix": material.submitted_at_unix_seconds,
        "verifier": {
            "github_login": material.verifier.login(),
            "github_id": material.verifier.numeric_id(),
            "github_type": material.verifier.account_type(),
        },
        "device_id": identity.device_id.as_str(),
        "subject": subject,
        "candidate": candidate_value,
        "baseline": baseline_value,
        "run_order": ["baseline", "candidate"],
        "correctness": {
            "passed": correctness_passed,
            "failures": if correctness_passed { 0 } else { 1 },
        },
        "safety": {
            "passed": safety_passed,
            "crashes": usize::from(category == Some("crash")),
            "out_of_memory": usize::from(category == Some("out_of_memory")),
            "protection_trips": usize::from(category == Some("protection_trip")),
            "output_validation_failures": usize::from(category == Some("output_validation")),
        },
        "restoration": restoration,
        "failure": failure,
        "counts_toward_consensus": counts_toward_consensus,
        "run_score": score,
        "verification_id": Value::Null,
    });
    let record_bytes = canonical_json(&record)?;
    let mut record: Value =
        serde_json::from_slice(&record_bytes).map_err(|_| BenchmarkError::PublicationRejected)?;
    if failure.is_none() {
        let normalized_baseline = validated_benchmark(
            &canonical_json(&record["baseline"])?,
            None,
            request.request().subject().benchmark_contract_sha256(),
        )?;
        let normalized_candidate = validated_benchmark(
            &canonical_json(&record["candidate"])?,
            Some(candidate),
            request.request().subject().benchmark_contract_sha256(),
        )?;
        let normalized_score = aggregate_score(&normalized_candidate, &normalized_baseline)?;
        record["run_score"] = normalized_score;
    }
    record["verification_id"] = Value::Null;
    let verification_id = verification_identity(&record)?;
    record["verification_id"] = Value::String(verification_id.as_str().to_string());
    let record_bytes = canonical_json(&record)?;
    let record: Value =
        serde_json::from_slice(&record_bytes).map_err(|_| BenchmarkError::PublicationRejected)?;
    let record_sha256 = digest(&record_bytes)?;
    let score_sha256 = digest(&canonical_json(&record["run_score"])?)?;
    let visible_summary = visible_summary(&record)?;
    Ok(CoreBenchmarkVerificationRecord {
        bytes: record_bytes,
        value: record,
        pull_request: *pull_request,
        proposal_head: proposal_head.clone(),
        candidate: candidate.clone(),
        verification_id,
        record_sha256,
        candidate_benchmark_id: candidate_benchmark.map(|value| value.id),
        baseline_benchmark_id: Some(baseline.id),
        score_sha256,
        device_id: identity.device_id.clone(),
        signature_key_id: identity.key_id.clone(),
        visible_summary,
    })
}

// Parses persisted record bytes and binds them back to the signed manager publication request.
fn validated_record(
    publication: &BenchmarkPublicationRequest<'_>,
    bytes: &[u8],
    identity: &CoreBenchmarkVerificationDeviceIdentity,
) -> Result<CoreBenchmarkVerificationRecord, BenchmarkError> {
    if bytes.is_empty()
        || bytes.len() > MAXIMUM_EXPANDED_EVIDENCE_BYTES
        || publication.sealed().evidence().schema()
            != BenchmarkRecordSchema::CommunityVerificationV1
        || publication.sealed().evidence().byte_count() != bytes.len() as u64
        || publication.sealed().evidence().evidence_id() != &digest(bytes)?
        || publication.sealed().signature().key_id() != &identity.key_id
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| BenchmarkError::PublicationRejected)?;
    let object = value
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    require_fields(
        object,
        &[
            "schema_version",
            "kind",
            "repository",
            "pull_request",
            "pull_request_url",
            "observed_head_sha",
            "submitted_at_unix",
            "verifier",
            "device_id",
            "subject",
            "candidate",
            "baseline",
            "run_order",
            "correctness",
            "safety",
            "restoration",
            "failure",
            "counts_toward_consensus",
            "run_score",
            "verification_id",
        ],
    )?;
    let BenchmarkKind::Verification {
        pull_request,
        proposal_head,
        candidate,
        candidate_subject_sha256,
        verifier_numeric_id,
        device_id,
        ..
    } = publication.request().kind()
    else {
        return Err(BenchmarkError::PublicationRejected);
    };
    if unsigned(object, "schema_version")? != 1
        || text(object, "kind")? != KIND
        || text(object, "repository")? != REPOSITORY
        || unsigned(object, "pull_request")? != *pull_request
        || unsigned(object, "submitted_at_unix")? == 0
        || text(object, "pull_request_url")?
            != format!("https://github.com/{REPOSITORY}/pull/{pull_request}")
        || text(object, "observed_head_sha")? != proposal_head.as_str()
        || text(object, "device_id")? != device_id.as_str()
        || device_id != &identity.device_id
        || object.get("run_order") != Some(&json!(["baseline", "candidate"]))
        || !object
            .get("counts_toward_consensus")
            .is_some_and(Value::is_boolean)
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let verifier = object
        .get("verifier")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::PublicationRejected)?;
    require_fields(verifier, &["github_login", "github_id", "github_type"])?;
    if unsigned(verifier, "github_id")? != *verifier_numeric_id
        || text(verifier, "github_type")? != "User"
        || !valid_github_login(text(verifier, "github_login")?)
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let subject = object
        .get("subject")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::PublicationRejected)?;
    let proposal_base = BenchmarkGitRevision::parse(text(subject, "proposal_base_sha")?)
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    let engine_mode = text(subject, "engine_mode")?;
    let subject_bytes = canonical_json(&Value::Object(subject.clone()))?;
    validated_execution_subject(
        &subject_bytes,
        candidate,
        *pull_request,
        proposal_head,
        &proposal_base,
        engine_mode,
        candidate_subject_sha256,
        publication.request().subject().benchmark_contract_sha256(),
        publication.request().subject().target_contract_sha256(),
    )?;
    let baseline_bytes = canonical_json(
        object
            .get("baseline")
            .ok_or(BenchmarkError::PublicationRejected)?,
    )?;
    let baseline = validated_benchmark(
        &baseline_bytes,
        None,
        publication.request().subject().benchmark_contract_sha256(),
    )?;
    let candidate_benchmark = object
        .get("candidate")
        .filter(|value| !value.is_null())
        .map(canonical_json)
        .transpose()?
        .as_deref()
        .map(|bytes| {
            validated_benchmark(
                bytes,
                Some(candidate),
                publication.request().subject().benchmark_contract_sha256(),
            )
        })
        .transpose()?;
    if candidate_benchmark
        .as_ref()
        .is_some_and(|value| value.target != baseline.target || value.method != baseline.method)
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let expected_failure = verification_failure(publication.outcome());
    if object.get("failure") != Some(expected_failure.as_ref().unwrap_or(&Value::Null))
        || (expected_failure.is_none() && candidate_benchmark.is_none())
        || (expected_failure.is_some()
            && expected_failure
                .as_ref()
                .and_then(Value::as_object)
                .and_then(|value| value.get("category"))
                .and_then(Value::as_str)
                != Some("restoration")
            && candidate_benchmark.is_some())
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let category = expected_failure
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|value| value.get("category"))
        .and_then(Value::as_str);
    let correctness_passed = !matches!(category, Some("output_validation" | "incomplete_workload"));
    let safety_passed = !matches!(
        category,
        Some("crash" | "out_of_memory" | "protection_trip" | "output_validation")
    );
    let correctness = object
        .get("correctness")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::PublicationRejected)?;
    require_fields(correctness, &["passed", "failures"])?;
    let safety = object
        .get("safety")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::PublicationRejected)?;
    require_fields(
        safety,
        &[
            "passed",
            "crashes",
            "out_of_memory",
            "protection_trips",
            "output_validation_failures",
        ],
    )?;
    if correctness.get("passed").and_then(Value::as_bool) != Some(correctness_passed)
        || unsigned(correctness, "failures")? != u64::from(!correctness_passed)
        || safety.get("passed").and_then(Value::as_bool) != Some(safety_passed)
        || unsigned(safety, "crashes")? != u64::from(category == Some("crash"))
        || unsigned(safety, "out_of_memory")? != u64::from(category == Some("out_of_memory"))
        || unsigned(safety, "protection_trips")? != u64::from(category == Some("protection_trip"))
        || unsigned(safety, "output_validation_failures")?
            != u64::from(category == Some("output_validation"))
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let expected_score = if expected_failure.is_none() {
        candidate_benchmark
            .as_ref()
            .map(|candidate| aggregate_score(candidate, &baseline))
            .transpose()?
    } else {
        None
    };
    if object.get("run_score") != Some(expected_score.as_ref().unwrap_or(&Value::Null)) {
        return Err(BenchmarkError::PublicationRejected);
    }
    let restoration = object
        .get("restoration")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::PublicationRejected)?;
    require_fields(restoration, &["passed", "receipt_id"])?;
    if restoration.get("passed").and_then(Value::as_bool) != Some(category != Some("restoration"))
        || text(restoration, "receipt_id")? != publication.restoration().receipt_id().as_str()
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let verification_id = verification_identity(&value)?;
    if text(object, "verification_id")? != verification_id.as_str() {
        return Err(BenchmarkError::PublicationRejected);
    }
    let score_sha256 = digest(&canonical_json(&value["run_score"])?)?;
    let visible_summary = visible_summary(&value)?;
    Ok(CoreBenchmarkVerificationRecord {
        bytes: bytes.to_vec(),
        value,
        pull_request: *pull_request,
        proposal_head: proposal_head.clone(),
        candidate: candidate.clone(),
        verification_id,
        record_sha256: publication.sealed().evidence().evidence_id().clone(),
        candidate_benchmark_id: candidate_benchmark.map(|value| value.id),
        baseline_benchmark_id: Some(baseline.id),
        score_sha256,
        device_id: identity.device_id.clone(),
        signature_key_id: identity.key_id.clone(),
        visible_summary,
    })
}

// Builds and self-verifies a signed envelope around exact already-persisted record bytes.
fn build_publication(
    publication: &BenchmarkPublicationRequest<'_>,
    record_bytes: &[u8],
    signer: &dyn CoreBenchmarkVerificationDeviceSigner,
) -> Result<BuiltPublication, BenchmarkError> {
    let identity = signer.identity()?;
    let record = validated_record(publication, record_bytes, &identity)?;
    let compressed = zstd::stream::encode_all(Cursor::new(&record_bytes), 19)
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    if compressed.is_empty() || compressed.len() > COMMENT_LIMIT_BYTES {
        return Err(BenchmarkError::PublicationRejected);
    }
    let summary = json!({
        "candidate_benchmark_id": record.candidate_benchmark_id.as_ref().map(Sha256Digest::as_str),
        "baseline_benchmark_id": record.baseline_benchmark_id.as_ref().map(Sha256Digest::as_str),
        "workloads": record.value["candidate"].as_object().map_or(0, |value| {
            value.get("results").and_then(Value::as_array).map_or(0, Vec::len)
        }),
        "correctness_passed": record.value["correctness"]["passed"],
        "safety_passed": record.value["safety"]["passed"],
        "score_sha256": record.score_sha256.as_str(),
    });
    let evidence_descriptor = json!({
        "media_type": EVIDENCE_MEDIA_TYPE,
        "encoding": EVIDENCE_ENCODING,
        "uncompressed_sha256": record.record_sha256.as_str(),
        "uncompressed_bytes": record.bytes.len(),
        "compressed_sha256": digest(&compressed)?.as_str(),
        "compressed_bytes": compressed.len(),
        "payload": URL_SAFE_NO_PAD.encode(&compressed),
    });
    let public_key_pem = public_key_pem(&identity.public_key_spki);
    let mut envelope = json!({
        "schema_version": 1,
        "kind": KIND,
        "verification_id": record.verification_id.as_str(),
        "repository": REPOSITORY,
        "pull_request": record.pull_request,
        "observed_head_sha": record.proposal_head.as_str(),
        "execution_sha256": record.value["subject"]["execution_sha256"],
        "runtime_oci_manifest_digest": record.value["subject"]["runtime_oci_manifest_digest"],
        "benchmark_contract_sha256": publication.request().subject().benchmark_contract_sha256().as_str(),
        "github_login": record.value["verifier"]["github_login"],
        "github_id": record.value["verifier"]["github_id"],
        "github_type": record.value["verifier"]["github_type"],
        "device_id": identity.device_id.as_str(),
        "device_public_key_pem": public_key_pem,
        "summary": summary,
        "evidence": evidence_descriptor,
        "signature": {
            "algorithm": "ed25519",
            "key_id": identity.key_id.as_str(),
            "value": "",
        },
    });
    let unsigned = canonical_json(&envelope)?;
    let signature = signer.sign(&unsigned)?;
    if signature.len() != 64
        || UnparsedPublicKey::new(
            &ED25519,
            &identity.public_key_spki[ED25519_SPKI_PREFIX.len()..],
        )
        .verify(&unsigned, &signature)
        .is_err()
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    envelope["signature"]["value"] = Value::String(URL_SAFE_NO_PAD.encode(signature));
    let body = format!(
        "{}\n\n<!-- {COMMENT_MARKER}\n{}\n-->\n",
        record.visible_summary,
        String::from_utf8(canonical_json(&envelope)?)
            .map_err(|_| BenchmarkError::PublicationRejected)?
            .trim_end()
    );
    if body.len() > COMMENT_LIMIT_BYTES {
        return Err(BenchmarkError::PublicationRejected);
    }
    let body_sha256 = digest(body.as_bytes())?;
    let built = BuiltPublication {
        pull_request: record.pull_request,
        proposal_head: record.proposal_head,
        candidate: record.candidate,
        verification_id: record.verification_id,
        record_sha256: record.record_sha256,
        body_sha256,
        candidate_benchmark_id: record.candidate_benchmark_id,
        baseline_benchmark_id: record.baseline_benchmark_id,
        score_sha256: record.score_sha256,
        device_id: record.device_id,
        signature_key_id: record.signature_key_id,
        record: record.value,
        envelope,
        visible_summary: record.visible_summary,
        body,
    };
    parse_comment(&built.body, &built)?;
    Ok(built)
}

// Parses and validates one exact execution subject against manager-owned typed identities.
fn validated_execution_subject(
    bytes: &[u8],
    candidate: &RuntimeCandidateId,
    pull_request: u64,
    proposal_head: &BenchmarkGitRevision,
    proposal_base: &BenchmarkGitRevision,
    engine_mode: &str,
    execution_sha256: &Sha256Digest,
    benchmark_contract_sha256: &Sha256Digest,
    target_contract_sha256: &Sha256Digest,
) -> Result<Value, BenchmarkError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| BenchmarkError::PublicationRejected)?;
    if canonical_json(&value)? != bytes {
        return Err(BenchmarkError::PublicationRejected);
    }
    let object = value
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let required = BTreeSet::from([
        "candidate_id",
        "runtime_version",
        "runtime_pack_sha256",
        "runtime_oci_manifest_digest",
        "model_revisions",
        "benchmark_contract_sha256",
        "target_contract_sha256",
        "artifact_schema_version",
        "repository",
        "pull_request",
        "proposal_head_sha",
        "proposal_base_sha",
        "proposal_tree_sha256",
        "engine_mode",
        "build_workflow_run_id",
        "execution_sha256",
    ]);
    let allowed = required
        .iter()
        .copied()
        .chain(["engine_payload_sha256", "engine_oci_manifest_digest"])
        .collect::<BTreeSet<_>>();
    let fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if !required.is_subset(&fields)
        || !fields.is_subset(&allowed)
        || text(object, "candidate_id")? != candidate.as_str()
        || unsigned(object, "artifact_schema_version")? != 1
        || text(object, "repository")? != REPOSITORY
        || unsigned(object, "pull_request")? != pull_request
        || text(object, "proposal_head_sha")? != proposal_head.as_str()
        || text(object, "proposal_base_sha")? != proposal_base.as_str()
        || text(object, "engine_mode")? != engine_mode
        || !lower_hex(text(object, "proposal_tree_sha256")?, 64)
        || unsigned(object, "build_workflow_run_id")? == 0
        || !matches!(
            engine_mode,
            "reuse-engine" | "build-engine" | "build-native-engine"
        )
        || RuntimeVersion::parse(text(object, "runtime_version")?).is_err()
        || text(object, "execution_sha256")? != execution_sha256.as_str()
        || text(object, "benchmark_contract_sha256")? != benchmark_contract_sha256.as_str()
        || text(object, "target_contract_sha256")? != target_contract_sha256.as_str()
        || !lower_hex(text(object, "runtime_pack_sha256")?, 64)
        || !oci_digest(text(object, "runtime_oci_manifest_digest")?)
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let mut identity = object.clone();
    identity.remove("execution_sha256");
    if digest(&canonical_json(&Value::Object(identity))?)? != *execution_sha256 {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(value)
}

// Validates one complete public benchmark and extracts exact paired-comparison inputs.
fn validated_benchmark(
    bytes: &[u8],
    candidate: Option<&RuntimeCandidateId>,
    benchmark_contract_sha256: &Sha256Digest,
) -> Result<ValidatedBenchmark, BenchmarkError> {
    validate_benchmark_record_bytes(bytes).map_err(|_| BenchmarkError::PublicationRejected)?;
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| BenchmarkError::PublicationRejected)?;
    if canonical_json(&value)? != bytes {
        return Err(BenchmarkError::PublicationRejected);
    }
    let object = value
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let id = Sha256Digest::parse(text(object, "id")?)
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    if text(object, "benchmark_contract_sha256")? != benchmark_contract_sha256.as_str() {
        return Err(BenchmarkError::PublicationRejected);
    }
    let subject = object
        .get("subject")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::PublicationRejected)?;
    if candidate
        .is_some_and(|candidate| text(subject, "candidate_id").ok() != Some(candidate.as_str()))
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let target = text(subject, "target")?.to_string();
    let results = object
        .get("results")
        .and_then(Value::as_array)
        .filter(|value| !value.is_empty())
        .ok_or(BenchmarkError::PublicationRejected)?;
    let mut score_values = [Vec::new(), Vec::new()];
    let mut method = Vec::with_capacity(results.len());
    for row in results {
        let row = row.as_object().ok_or(BenchmarkError::PublicationRejected)?;
        method.push(json!({
            "workload": text(row, "workload")?,
            "prompt_domain": text(row, "prompt_domain")?,
            "prompt_suite": text(row, "prompt_suite")?,
            "prompt_set_sha256": text(row, "prompt_set_sha256")?,
            "actual_prompt_tokens": row.get("actual_prompt_tokens").ok_or(BenchmarkError::PublicationRejected)?,
            "is_prefix_cached": row.get("is_prefix_cached").ok_or(BenchmarkError::PublicationRejected)?,
        }));
        if row.get("is_prefix_cached").and_then(Value::as_bool) != Some(false) {
            continue;
        }
        let index = match text(row, "prompt_domain")? {
            "code" => 0,
            "prose" => 1,
            _ => return Err(BenchmarkError::PublicationRejected),
        };
        let throughput = row
            .get("aggregate_tps")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite() && *value > 0.0)
            .ok_or(BenchmarkError::PublicationRejected)?;
        score_values[index].push(throughput);
    }
    if score_values.iter().any(Vec::is_empty) {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(ValidatedBenchmark {
        value,
        id,
        target,
        score_values,
        method,
    })
}

// Builds the exact per-domain and overall geometric-mean throughput score.
fn aggregate_score(
    candidate: &ValidatedBenchmark,
    baseline: &ValidatedBenchmark,
) -> Result<Value, BenchmarkError> {
    let mut domains = Map::new();
    let mut candidate_all = Vec::new();
    let mut baseline_all = Vec::new();
    for (index, name) in ["code", "prose"].into_iter().enumerate() {
        let measured = geometric_mean(&candidate.score_values[index])?;
        let reference = geometric_mean(&baseline.score_values[index])?;
        candidate_all.extend(candidate.score_values[index].iter().copied());
        baseline_all.extend(baseline.score_values[index].iter().copied());
        domains.insert(
            name.to_string(),
            json!({
                "aggregate_tps_geomean": measured,
                "baseline_aggregate_tps_geomean": reference,
                "change_percent": ((measured / reference) - 1.0) * 100.0,
            }),
        );
    }
    let measured = geometric_mean(&candidate_all)?;
    let reference = geometric_mean(&baseline_all)?;
    Ok(json!({
        "policy": "letsinfer-throughput-geomean-v1",
        "domains": domains,
        "overall": {
            "aggregate_tps_geomean": measured,
            "baseline_aggregate_tps_geomean": reference,
            "change_percent": ((measured / reference) - 1.0) * 100.0,
        },
    }))
}

// Computes one finite positive geometric mean without accumulating product overflow.
fn geometric_mean(values: &[f64]) -> Result<f64, BenchmarkError> {
    if values.is_empty()
        || values
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let logarithms = values
        .iter()
        .map(|value| {
            // SAFETY: every input was checked finite and strictly positive above.
            unsafe { python_log(*value) }
        })
        .sum::<f64>();
    let exponent = logarithms / values.len() as f64;
    // SAFETY: `exp` accepts every finite input and is checked for finite positive output below.
    let value = unsafe { python_exp(exponent) };
    if !value.is_finite() || value <= 0.0 {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(value)
}

// Converts one exact terminal outcome into the closed public blocking-failure vocabulary.
fn verification_failure(outcome: &BenchmarkExecutionOutcome) -> Option<Value> {
    match outcome {
        BenchmarkExecutionOutcome::Succeeded { .. } => None,
        BenchmarkExecutionOutcome::Failed { failure, .. } => Some(json!({
            "category": failure.category().as_str(),
            "phase": failure.phase().as_str(),
            "message": failure.description().message(),
        })),
        BenchmarkExecutionOutcome::Cancelled { .. } => Some(json!({
            "category": BenchmarkFailureCategory::IncompleteWorkload.as_str(),
            "phase": "cancelled",
            "message": "verification was cancelled before the complete workload finished",
        })),
    }
}

// Derives the stable public verification identity from the Python contract's exact subset.
fn verification_identity(record: &Value) -> Result<Sha256Digest, BenchmarkError> {
    let object = record
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let subject = object
        .get("subject")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::PublicationRejected)?;
    let verifier = object
        .get("verifier")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::PublicationRejected)?;
    let candidate_benchmark_id = object
        .get("candidate")
        .and_then(Value::as_object)
        .and_then(|candidate| candidate.get("id"))
        .cloned()
        .unwrap_or(Value::Null);
    let identity = json!({
        "candidate_benchmark_id": candidate_benchmark_id,
        "device_id": object.get("device_id").ok_or(BenchmarkError::PublicationRejected)?,
        "execution_sha256": subject.get("execution_sha256").ok_or(BenchmarkError::PublicationRejected)?,
        "failure": object.get("failure").ok_or(BenchmarkError::PublicationRejected)?,
        "github_id": verifier.get("github_id").ok_or(BenchmarkError::PublicationRejected)?,
        "observed_head_sha": object.get("observed_head_sha").ok_or(BenchmarkError::PublicationRejected)?,
        "pull_request": object.get("pull_request").ok_or(BenchmarkError::PublicationRejected)?,
    });
    digest(&canonical_json(&identity)?)
}

// Renders the exact human-visible summary that is independently checked during readback.
fn visible_summary(record: &Value) -> Result<String, BenchmarkError> {
    let object = record
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let verifier = object["verifier"]
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let subject = object["subject"]
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let verification_id = object["verification_id"]
        .as_str()
        .ok_or(BenchmarkError::PublicationRejected)?;
    if let Some(failure) = object["failure"].as_object() {
        let restoration = object["restoration"]
            .as_object()
            .and_then(|value| value.get("passed"))
            .and_then(Value::as_bool)
            .ok_or(BenchmarkError::PublicationRejected)?;
        return Ok([
            "## Let’s Infer runtime verification".to_string(),
            String::new(),
            format!(
                "**Verifier:** @{} (`{}`)",
                text(verifier, "github_login")?,
                unsigned(verifier, "github_id")?
            ),
            format!(
                "**Runtime:** `{}@{}`",
                text(subject, "candidate_id")?,
                text(subject, "runtime_version")?
            ),
            format!("**Execution:** `{}`", text(subject, "execution_sha256")?),
            "**Result:** blocking failure".to_string(),
            format!(
                "**Failure:** `{}` during `{}`",
                text(failure, "category")?,
                text(failure, "phase")?
            ),
            format!(
                "**Restoration:** {}",
                if restoration { "pass" } else { "fail" }
            ),
            format!("**Verification ID:** `{verification_id}`"),
        ]
        .join("\n"));
    }
    let candidate = object["candidate"]
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let score = object["run_score"]
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let mut lines = vec![
        "## Let’s Infer runtime verification".to_string(),
        String::new(),
        format!(
            "**Verifier:** @{} (`{}`)",
            text(verifier, "github_login")?,
            unsigned(verifier, "github_id")?
        ),
        format!(
            "**Runtime:** `{}@{}`",
            text(subject, "candidate_id")?,
            text(subject, "runtime_version")?
        ),
        format!("**Execution:** `{}`", text(subject, "execution_sha256")?),
        format!(
            "**Target:** `{}`",
            candidate
                .get("subject")
                .and_then(Value::as_object)
                .ok_or(BenchmarkError::PublicationRejected)
                .and_then(|subject| text(subject, "target"))?
        ),
        format!(
            "**Benchmark:** `{}` · {} workloads",
            text(candidate, "id")?,
            candidate
                .get("results")
                .and_then(Value::as_array)
                .ok_or(BenchmarkError::PublicationRejected)?
                .len()
        ),
        String::new(),
        "| Prompt | Aggregate tok/s | Baseline | Change |".to_string(),
        "|---|---:|---:|---:|".to_string(),
    ];
    let domains = score["domains"]
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    for name in ["code", "prose"] {
        let domain = domains[name]
            .as_object()
            .ok_or(BenchmarkError::PublicationRejected)?;
        let measured = number(domain, "aggregate_tps_geomean")?;
        let baseline = number(domain, "baseline_aggregate_tps_geomean")?;
        let change = number(domain, "change_percent")?;
        let title = if name == "code" { "Code" } else { "Prose" };
        lines.push(format!(
            "| {title} | {measured:.3} | {baseline:.3} | {change:+.2}% |"
        ));
    }
    lines.extend([
        String::new(),
        "**Correctness:** pass · **Safety:** pass · **Restoration:** pass".to_string(),
        format!("**Verification ID:** `{verification_id}`"),
    ]);
    Ok(lines.join("\n"))
}

// Independently parses, verifies, decompresses, and compares one exact posted comment.
fn parse_comment(body: &str, expected: &BuiltPublication) -> Result<(), BenchmarkError> {
    if body.len() > COMMENT_LIMIT_BYTES || digest(body.as_bytes())? != expected.body_sha256 {
        return Err(BenchmarkError::PublicationRejected);
    }
    let prefix = format!("<!-- {COMMENT_MARKER}\n");
    let start = body
        .find(&prefix)
        .ok_or(BenchmarkError::PublicationRejected)?;
    if !body.ends_with("\n-->\n")
        || body[..start].strip_suffix("\n\n") != Some(expected.visible_summary.as_str())
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let raw = &body[start + prefix.len()..body.len() - "\n-->\n".len()];
    let envelope: Value =
        serde_json::from_str(raw).map_err(|_| BenchmarkError::PublicationRejected)?;
    if canonical_json(&envelope)?
        .strip_suffix(&[b'\n'])
        .ok_or(BenchmarkError::PublicationRejected)?
        != raw.as_bytes()
        || envelope != expected.envelope
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let object = envelope
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    require_fields(
        object,
        &[
            "schema_version",
            "kind",
            "verification_id",
            "repository",
            "pull_request",
            "observed_head_sha",
            "execution_sha256",
            "runtime_oci_manifest_digest",
            "benchmark_contract_sha256",
            "github_login",
            "github_id",
            "github_type",
            "device_id",
            "device_public_key_pem",
            "summary",
            "evidence",
            "signature",
        ],
    )?;
    let signature = object["signature"]
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    require_fields(signature, &["algorithm", "key_id", "value"])?;
    if text(signature, "algorithm")? != "ed25519"
        || text(signature, "key_id")? != text(object, "device_id")?
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let public_der = parse_public_key_pem(text(object, "device_public_key_pem")?)?;
    if digest(&public_der)?.as_str() != text(object, "device_id")? {
        return Err(BenchmarkError::PublicationRejected);
    }
    let raw_signature = URL_SAFE_NO_PAD
        .decode(text(signature, "value")?)
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    let mut unsigned_envelope = envelope.clone();
    unsigned_envelope["signature"]["value"] = Value::String(String::new());
    if raw_signature.len() != 64
        || UnparsedPublicKey::new(&ED25519, &public_der[ED25519_SPKI_PREFIX.len()..])
            .verify(&canonical_json(&unsigned_envelope)?, &raw_signature)
            .is_err()
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let evidence = object["evidence"]
        .as_object()
        .ok_or(BenchmarkError::PublicationRejected)?;
    require_fields(
        evidence,
        &[
            "media_type",
            "encoding",
            "uncompressed_sha256",
            "uncompressed_bytes",
            "compressed_sha256",
            "compressed_bytes",
            "payload",
        ],
    )?;
    if text(evidence, "media_type")? != EVIDENCE_MEDIA_TYPE
        || text(evidence, "encoding")? != EVIDENCE_ENCODING
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let compressed = URL_SAFE_NO_PAD
        .decode(text(evidence, "payload")?)
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    if compressed.len() as u64 != unsigned(evidence, "compressed_bytes")?
        || digest(&compressed)?.as_str() != text(evidence, "compressed_sha256")?
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let decoder = zstd::stream::read::Decoder::new(Cursor::new(&compressed))
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    let mut expanded = Vec::new();
    decoder
        .take(MAXIMUM_EXPANDED_EVIDENCE_BYTES as u64 + 1)
        .read_to_end(&mut expanded)
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    if expanded.len() > MAXIMUM_EXPANDED_EVIDENCE_BYTES
        || expanded.len() as u64 != unsigned(evidence, "uncompressed_bytes")?
        || digest(&expanded)?.as_str() != text(evidence, "uncompressed_sha256")?
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let record: Value =
        serde_json::from_slice(&expanded).map_err(|_| BenchmarkError::PublicationRejected)?;
    if record != expected.record {
        return Err(BenchmarkError::PublicationRejected);
    }
    if verification_identity(&record)? != expected.verification_id {
        return Err(BenchmarkError::PublicationRejected);
    }
    if visible_summary(&record)? != expected.visible_summary {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(())
}

// Serializes one value through the shared sorted compact UTF-8 plus newline contract.
fn canonical_json(value: &Value) -> Result<Vec<u8>, BenchmarkError> {
    canonical_benchmark_json_bytes(value).map_err(|_| BenchmarkError::PublicationRejected)
}

// Computes one canonical lowercase SHA-256 identity.
fn digest(bytes: &[u8]) -> Result<Sha256Digest, BenchmarkError> {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| BenchmarkError::PublicationRejected)
}

// Returns one required string field without copying rejected content into an error.
fn text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, BenchmarkError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(BenchmarkError::PublicationRejected)
}

// Returns one required unsigned integer field.
fn unsigned(object: &Map<String, Value>, field: &str) -> Result<u64, BenchmarkError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(BenchmarkError::PublicationRejected)
}

// Returns one required finite JSON number field.
fn number(object: &Map<String, Value>, field: &str) -> Result<f64, BenchmarkError> {
    object
        .get(field)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or(BenchmarkError::PublicationRejected)
}

// Requires one closed object field set without accepting aliases or future silent widening.
fn require_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<(), BenchmarkError> {
    let expected = fields.iter().copied().collect::<BTreeSet<_>>();
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(())
}

// Returns whether one login follows GitHub's bounded public account-name grammar.
fn valid_github_login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 39
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

// Returns whether one string is exact lowercase hexadecimal at a fixed length.
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Returns whether one OCI identity is a canonical SHA-256 digest.
fn oci_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|value| lower_hex(value, 64))
}

// Encodes a public SPKI as PEM without embedding a marker literal in source.
fn public_key_pem(spki: &[u8]) -> String {
    let begin = ["-----BEGIN ", "PUBLIC KEY-----"].concat();
    let end = ["-----END ", "PUBLIC KEY-----"].concat();
    let encoded = STANDARD.encode(spki);
    let lines = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{begin}\n{lines}\n{end}\n")
}

// Parses exactly one dynamically constructed Ed25519 public-key PEM envelope.
fn parse_public_key_pem(value: &str) -> Result<Vec<u8>, BenchmarkError> {
    if value.len() > 16 * 1024 || !value.is_ascii() {
        return Err(BenchmarkError::PublicationRejected);
    }
    let begin = ["-----BEGIN ", "PUBLIC KEY-----"].concat();
    let end = ["-----END ", "PUBLIC KEY-----"].concat();
    let mut lines = value.lines();
    if lines.next() != Some(begin.as_str()) {
        return Err(BenchmarkError::PublicationRejected);
    }
    let mut encoded = String::new();
    loop {
        let line = lines.next().ok_or(BenchmarkError::PublicationRejected)?;
        if line == end {
            break;
        }
        if line.is_empty() || line.len() > 64 {
            return Err(BenchmarkError::PublicationRejected);
        }
        encoded.push_str(line);
    }
    if lines.next().is_some() {
        return Err(BenchmarkError::PublicationRejected);
    }
    let der = STANDARD
        .decode(encoded)
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    if der.len() != ED25519_SPKI_PREFIX.len() + 32 || !der.starts_with(ED25519_SPKI_PREFIX) {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(der)
}

// Requires the one canonical immutable runtimes pull-request comment URL.
fn require_comment_url(
    url: &str,
    pull_request: u64,
    comment_id: u64,
) -> Result<(), BenchmarkError> {
    let expected =
        format!("https://github.com/{REPOSITORY}/pull/{pull_request}#issuecomment-{comment_id}");
    if url != expected {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(())
}

// Returns whether one native executable path is normal, absolute, and non-root.
fn absolute_normal(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Executes one bounded GitHub CLI process while preserving its credential environment.
fn run_github_command(
    executable: &Path,
    arguments: &[String],
    input: Option<&[u8]>,
    timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<CoreBenchmarkVerificationGitHubCommandOutput, BenchmarkError> {
    if !absolute_normal(executable)
        || arguments.is_empty()
        || arguments.len() > 32
        || arguments.iter().any(|argument| {
            argument.is_empty() || argument.len() > 4_096 || argument.bytes().any(|byte| byte == 0)
        })
        || input.is_some_and(|value| value.is_empty() || value.len() > COMMENT_LIMIT_BYTES + 64)
        || timeout.is_zero()
        || timeout > GITHUB_TIMEOUT
        || maximum_output_bytes == 0
        || maximum_output_bytes > MAXIMUM_GITHUB_OUTPUT_BYTES
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .current_dir("/")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(BenchmarkError::PublicationRejected)?;
    let stdout_reader = bounded_reader(stdout, maximum_output_bytes);
    let stderr_reader = bounded_reader(stderr, maximum_output_bytes);
    if let Some(input) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or(BenchmarkError::PublicationRejected)?;
        stdin
            .write_all(input)
            .map_err(|_| BenchmarkError::PublicationRejected)?;
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(BenchmarkError::PublicationRejected)?;
    let status = loop {
        match child
            .try_wait()
            .map_err(|_| BenchmarkError::PublicationRejected)?
        {
            Some(status) => break status.code().unwrap_or(-1),
            None if Instant::now() < deadline => std::thread::sleep(COMMAND_POLL_INTERVAL),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BenchmarkError::PublicationRejected);
            }
        }
    };
    let stdout = join_reader(stdout_reader, maximum_output_bytes)?;
    let stderr = join_reader(stderr_reader, maximum_output_bytes)?;
    if stdout
        .len()
        .checked_add(stderr.len())
        .is_none_or(|bytes| bytes > maximum_output_bytes)
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(CoreBenchmarkVerificationGitHubCommandOutput::new(
        status, stdout, stderr,
    ))
}

// Reads one process stream while retaining at most one byte beyond its bound.
fn bounded_reader<R: Read + Send + 'static>(
    reader: R,
    maximum: usize,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

// Joins one bounded reader without retaining platform diagnostics.
fn join_reader(
    reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    maximum: usize,
) -> Result<Vec<u8>, BenchmarkError> {
    let bytes = reader
        .join()
        .map_err(|_| BenchmarkError::PublicationRejected)?
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    if bytes.len() > maximum {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use li_benchmark_manager::{
        BenchmarkEvidence, BenchmarkFailure, BenchmarkFailureCategory, BenchmarkRecordSchema,
        BenchmarkRequest, BenchmarkRestoration, BenchmarkScope, BenchmarkSignature,
        BenchmarkSubject, SealedBenchmarkEvidence,
    };
    use li_core_interface::{
        InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeInstallationId,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    // Signs envelopes with one in-memory Ed25519 identity and no native command.
    struct Signer(Ed25519KeyPair);

    impl Signer {
        // Creates one cryptographically valid test device identity.
        fn new() -> Self {
            let document =
                Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).expect("key");
            Self(Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("pair"))
        }

        // Returns the exact DER device identity used by request and sealed evidence fixtures.
        fn device_id(&self) -> Sha256Digest {
            self.identity().expect("identity").device_id
        }
    }

    impl CoreBenchmarkVerificationDeviceSigner for Signer {
        // Returns one canonical Ed25519 SPKI identity.
        fn identity(&self) -> Result<CoreBenchmarkVerificationDeviceIdentity, BenchmarkError> {
            let mut spki = ED25519_SPKI_PREFIX.to_vec();
            spki.extend_from_slice(self.0.public_key().as_ref());
            let identity = digest(&spki)?;
            CoreBenchmarkVerificationDeviceIdentity::new(identity.clone(), identity, spki)
        }

        // Signs exact canonical envelope bytes.
        fn sign(&self, unsigned_envelope: &[u8]) -> Result<Vec<u8>, BenchmarkError> {
            Ok(self.0.sign(unsigned_envelope).as_ref().to_vec())
        }
    }

    // Returns one immutable publication material closure.
    struct Material(CoreBenchmarkVerificationPublicationMaterial);

    impl CoreBenchmarkVerificationPublicationMaterialPort for Material {
        // Returns the retained exact paired-run material.
        fn material(
            &self,
            _request: &CoreBenchmarkVerificationRecordRequest<'_>,
        ) -> Result<CoreBenchmarkVerificationPublicationMaterial, BenchmarkError> {
            Ok(self.0.clone())
        }
    }

    // Returns one exact persisted record without reconstructing publication material.
    struct Record(Vec<u8>);

    impl CoreBenchmarkVerificationRecordReader for Record {
        // Returns the fixture's already-canonical record bytes.
        fn record(
            &self,
            _request: &BenchmarkPublicationRequest<'_>,
        ) -> Result<Vec<u8>, BenchmarkError> {
            Ok(self.0.clone())
        }
    }

    // Queues bounded GitHub command outcomes and records every argv/input boundary.
    #[derive(Default)]
    struct Runner {
        outputs:
            Mutex<VecDeque<Result<CoreBenchmarkVerificationGitHubCommandOutput, BenchmarkError>>>,
        calls: Mutex<Vec<(Vec<String>, Option<Vec<u8>>)>>,
    }

    impl Runner {
        // Adds one successful JSON stdout result.
        fn output(&self, value: Value) {
            self.outputs.lock().expect("outputs").push_back(Ok(
                CoreBenchmarkVerificationGitHubCommandOutput::new(
                    0,
                    serde_json::to_vec(&value).expect("JSON"),
                    Vec::new(),
                ),
            ));
        }

        // Adds one command-layer failure, including simulated POST response loss.
        fn fail(&self) {
            self.outputs
                .lock()
                .expect("outputs")
                .push_back(Err(BenchmarkError::PublicationRejected));
        }
    }

    impl CoreBenchmarkVerificationGitHubCommandRunner for Runner {
        // Returns the next exact mock result without external state.
        fn run(
            &self,
            _executable: &Path,
            arguments: &[String],
            input: Option<&[u8]>,
            _timeout: Duration,
            _maximum_output_bytes: usize,
        ) -> Result<CoreBenchmarkVerificationGitHubCommandOutput, BenchmarkError> {
            self.calls
                .lock()
                .expect("calls")
                .push((arguments.to_vec(), input.map(<[u8]>::to_vec)));
            self.outputs
                .lock()
                .expect("outputs")
                .pop_front()
                .expect("mock output")
        }
    }

    // Owns every borrowed value needed by a manager publication request.
    #[allow(dead_code)]
    pub(crate) struct Fixture {
        job_id: OperationId,
        request: BenchmarkRequest,
        outcome: BenchmarkExecutionOutcome,
        restoration: BenchmarkRestoration,
        material: CoreBenchmarkVerificationPublicationMaterial,
        signer: Arc<Signer>,
        bundle_json: Vec<u8>,
    }

    #[allow(dead_code)]
    impl Fixture {
        // Returns the exact outer job identity for cross-module production composition tests.
        pub(crate) const fn job_id(&self) -> &OperationId {
            &self.job_id
        }

        // Returns the complete typed verification request.
        pub(crate) const fn request(&self) -> &BenchmarkRequest {
            &self.request
        }

        // Returns the terminal paired outcome used to construct outer evidence.
        pub(crate) const fn outcome(&self) -> &BenchmarkExecutionOutcome {
            &self.outcome
        }

        // Returns the exact baseline-restoration receipt.
        pub(crate) const fn restoration(&self) -> &BenchmarkRestoration {
            &self.restoration
        }

        // Returns the signer behind its narrow production trait.
        pub(crate) fn signer(&self) -> Arc<dyn CoreBenchmarkVerificationDeviceSigner> {
            self.signer.clone()
        }

        // Returns the shared device/signature-key identity for a sealed outer evidence receipt.
        pub(crate) fn signature_key_id(&self) -> Sha256Digest {
            self.signer.device_id()
        }

        // Returns canonical trusted bundle bytes whose digest is in the request.
        pub(crate) fn bundle_json(&self) -> &[u8] {
            &self.bundle_json
        }

        // Returns canonical full finalizer subject bytes.
        pub(crate) fn subject_json(&self) -> &[u8] {
            &self.material.execution_subject_json
        }

        // Returns the complete successful baseline benchmark bytes.
        pub(crate) fn baseline_json(&self) -> &[u8] {
            &self.material.baseline_benchmark_json
        }

        // Returns the complete successful candidate benchmark bytes.
        pub(crate) fn candidate_json(&self) -> &[u8] {
            self.material
                .candidate_benchmark_json
                .as_deref()
                .expect("successful fixture candidate")
        }

        // Builds canonical record bytes, seals their identity, then creates the signed comment.
        fn publication(&self) -> (SealedBenchmarkEvidence, BuiltPublication) {
            let device_id = self.signer.device_id();
            let record_request = CoreBenchmarkVerificationRecordRequest::new(
                &self.job_id,
                &self.request,
                &self.outcome,
                &self.restoration,
            );
            let builder = CoreBenchmarkVerificationRecordBuilder::new(
                Arc::new(Material(self.material.clone())),
                self.signer.clone(),
            );
            let record = builder.record(&record_request).expect("record");
            let sealed = SealedBenchmarkEvidence::new(
                BenchmarkEvidence::new(
                    record.record_sha256.clone(),
                    digest(&[1]).expect("results"),
                    BenchmarkRecordSchema::CommunityVerificationV1,
                    record.bytes.len() as u64,
                )
                .expect("evidence"),
                BenchmarkSignature::new(device_id, "c2lnbmF0dXJl").expect("signature"),
            );
            let publication_request = BenchmarkPublicationRequest::new(
                &self.job_id,
                &self.request,
                &self.outcome,
                &self.restoration,
                &sealed,
            );
            let built =
                build_publication(&publication_request, record.bytes(), self.signer.as_ref())
                    .expect("built publication");
            (sealed, built)
        }
    }

    // Returns one complete paired verification fixture using real schema-8 benchmark validation.
    pub(crate) fn fixture() -> Fixture {
        let signer = Arc::new(Signer::new());
        let candidate =
            RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate");
        let target_contract = repeated_digest('2');
        let contract = benchmark_contract();
        let contract_sha = digest(&canonical_json(&contract).expect("contract")).expect("digest");
        let baseline_candidate =
            RuntimeCandidateId::parse("baseline--owner--model--target").expect("baseline");
        let baseline = benchmark_record(&baseline_candidate, &contract, &contract_sha, 1.0, 2);
        let measured = benchmark_record(&candidate, &contract, &contract_sha, 1.1, 3);
        let mut subject = json!({
            "artifact_schema_version": 1,
            "repository": REPOSITORY,
            "pull_request": 123,
            "proposal_head_sha": "a".repeat(40),
            "proposal_base_sha": "b".repeat(40),
            "proposal_tree_sha256": "c".repeat(64),
            "engine_mode": "reuse-engine",
            "build_workflow_run_id": 11,
            "candidate_id": candidate.as_str(),
            "runtime_version": "1.2.3",
            "runtime_pack_sha256": repeated_digest('1').as_str(),
            "runtime_oci_manifest_digest": format!("sha256:{}", "2".repeat(64)),
            "model_revisions": [],
            "benchmark_contract_sha256": contract_sha.as_str(),
            "target_contract_sha256": target_contract.as_str(),
        });
        let execution = digest(&canonical_json(&subject).expect("subject")).expect("execution");
        subject["execution_sha256"] = Value::String(execution.as_str().to_string());
        let bundle_json = canonical_json(&json!({
            "subject": subject.clone(),
            "proposal_base_sha": "b".repeat(40),
            "mode": "reuse-engine",
            "runtime_authors": [
                {"github_login": "RuntimeAuthor", "github_id": 42, "github_type": "User"}
            ],
        }))
        .expect("bundle");
        let bundle_sha256 = digest(&bundle_json).expect("bundle digest");
        let request = BenchmarkRequest::new(
            BenchmarkKind::verification(
                123,
                li_benchmark_manager::BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
                candidate,
                OperationId::parse(&"d".repeat(32)).expect("transaction"),
                bundle_sha256,
                execution.clone(),
                99,
                signer.device_id(),
                Some(repeated_digest('b')),
            )
            .expect("kind"),
            BenchmarkScope::Complete,
            BenchmarkSubject::new(
                InstallationId::parse(&"1".repeat(64)).expect("installation"),
                RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime"),
                LogicalModelName::parse("qwen3.8").expect("model"),
                PlacementGroupId::parse(&"3".repeat(32)).expect("group"),
                repeated_digest('8'),
                contract_sha,
                target_contract,
            ),
        )
        .expect("request");
        Fixture {
            job_id: OperationId::parse(&"4".repeat(32)).expect("job"),
            request,
            outcome: BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256: repeated_digest('5'),
                results_sha256: repeated_digest('6'),
                record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
            },
            restoration: BenchmarkRestoration::new(repeated_digest('7')),
            material: CoreBenchmarkVerificationPublicationMaterial::new(
                "https://github.com/letsinferlabs/runtimes/pull/123".to_string(),
                BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
                BenchmarkGitRevision::parse(&"b".repeat(40)).expect("base"),
                "reuse-engine".to_string(),
                CoreBenchmarkVerificationGitHubIdentity::new("Verifier", 99, "User")
                    .expect("verifier"),
                41,
                vec![42],
                canonical_json(&subject).expect("subject"),
                Some(measured),
                baseline,
                true,
                1_787_465_000,
            )
            .expect("material"),
            signer,
            bundle_json,
        }
    }

    // Returns one schema-8 benchmark contract accepted by the production record validator.
    fn benchmark_contract() -> Value {
        json!({
            "schema_version": 8,
            "suite": "letsinfer-code-prose-v1",
            "generator": {"id": "letsinfer-code-prose", "version": 8},
            "domains": ["code", "prose"],
            "execution": {
                "isolation": "fresh-matrix", "prefix_state": "shared",
                "samples_per_cell": 1, "stream_prefix": "shared-body"
            },
            "tokenizer": {
                "capability": "engine-rendered-chat-count-v1",
                "model_sha256": repeated_digest('c').as_str(),
                "engine_payload_sha256": repeated_digest('3').as_str(),
                "render_contract": "openai-chat-user-v1"
            },
            "request": {
                "output_tokens": 128, "min_completion_tokens": 128,
                "require_natural_stop": false, "temperature": 0, "seed": 42042
            },
            "short": {
                "domains": ["code", "prose"], "prompt_tokens": 256,
                "concurrencies": [1, 2, 4],
                "request": {
                    "output_tokens": 512, "min_completion_tokens": 512,
                    "require_natural_stop": false, "temperature": 0, "seed": 42042
                }
            },
            "ttft_cache": {
                "prompt_tokens": 64000, "prompt_domain": "code", "repetitions": 2,
                "request": {
                    "output_tokens": 1, "min_completion_tokens": 1,
                    "require_natural_stop": false, "temperature": 0, "seed": 42042
                }
            },
            "sample_interval_seconds": 5,
            "cases": [{"id": "32k", "prompt_tokens": 32768, "concurrencies": [1]}]
        })
    }

    // Returns one canonical native benchmark record with code and prose score rows.
    fn benchmark_record(
        candidate: &RuntimeCandidateId,
        contract: &Value,
        contract_sha: &Sha256Digest,
        multiplier: f64,
        timestamp: u64,
    ) -> Vec<u8> {
        let results = ["code", "prose"]
            .into_iter()
            .enumerate()
            .map(|(index, domain)| benchmark_row(domain, (index as f64 + 1.0) * 30.0 * multiplier))
            .collect::<Vec<_>>();
        let ttft_cache = json!({
            "workload": "pp64000,tg1,c1", "prompt_domain": "code",
            "prompt_suite": "letsinfer-code-prose-v1", "prompt_sha256": repeated_digest('e').as_str(),
            "actual_prompt_tokens": 64000, "cold_ttft_seconds": 2.0,
            "warm_ttft_seconds": 1.0, "cold_cached_prompt_tokens": 0,
            "warm_cached_prompt_tokens": 64000, "ttft_speedup_ratio": 2.0,
            "ttft_reduction_percent": 50.0
        });
        let result_material = json!({"results": results, "ttft_cache": ttft_cache});
        let results_sha =
            digest(&canonical_json(&result_material).expect("results")).expect("digest");
        let subject = json!({
            "candidate_id": candidate.as_str(),
            "engine_payload_sha256": repeated_digest('3').as_str(),
            "measured_engine_kind": "native-archive",
            "model_revision": "5".repeat(40),
            "model_uri": "hf://owner/model",
            "runtime_version": "1.2.3",
            "target": "dgx-spark",
            "target_contract_sha256": repeated_digest('2').as_str()
        });
        let timestamp_ns = timestamp * 1_000_000_000;
        let installation = repeated_digest('1');
        let identity = json!({
            "benchmark_contract_sha256": contract_sha.as_str(),
            "contract": "letsinfer-benchmark-identity-v2",
            "installation_id": installation.as_str(),
            "results_sha256": results_sha.as_str(),
            "subject": subject,
            "timestamp_unix_ns": timestamp_ns
        });
        let id = digest(&canonical_json(&identity).expect("identity")).expect("id");
        let mut record = json!({
            "schema_version": 8,
            "id": id.as_str(), "installation_id": installation.as_str(),
            "timestamp": timestamp, "timestamp_unix_ns": timestamp_ns,
            "subject": identity["subject"].clone(),
            "benchmark_contract_sha256": contract_sha.as_str(),
            "results_sha256": results_sha.as_str(),
            "results": result_material["results"].clone(),
            "benchmark_contract": contract,
            "ttft_cache": result_material["ttft_cache"].clone()
        });
        let bytes = canonical_json(&record).expect("record");
        validate_benchmark_record_bytes(&bytes).expect("valid benchmark record");
        record = serde_json::from_slice(&bytes).expect("record");
        canonical_json(&record).expect("canonical record")
    }

    // Returns one complete result row under the public schema.
    fn benchmark_row(domain: &str, throughput: f64) -> Value {
        json!({
            "workload": "pp32768,tg128,c1", "prompt_domain": domain,
            "prompt_suite": "letsinfer-code-prose-v1", "prompt_set_sha256": repeated_digest('d').as_str(),
            "actual_prompt_tokens": [32768], "aggregate_tps": throughput,
            "decode_tps": throughput, "ttft_seconds": 1.0, "ttft_statistic": "single",
            "ttft_p95_seconds": null, "is_prefix_cached": false,
            "max_gpu_usage_percent": null, "max_gpu_temperature_c": null,
            "max_cpu_temperature_c": null, "max_cpu_usage_percent": null,
            "max_cpu_clock_mhz": -1, "max_gpu_clock_mhz": -1,
            "max_vram_clock_mhz": -1, "max_system_ram_clock_mhz": -1,
            "max_nvme_usage_percent": -1, "max_nvme_temperature_c": -1,
            "max_nvme_read_kib_per_second": -1, "max_nvme_write_kib_per_second": -1,
            "telemetry": {
                "interval_seconds": null,
                "columns": [
                    "elapsed_seconds", "gpu_usage_percent", "gpu_temperature_c",
                    "cpu_usage_percent", "cpu_temperature_c", "cpu_clock_mhz",
                    "gpu_clock_mhz", "vram_clock_mhz", "system_ram_clock_mhz",
                    "nvme_usage_percent", "nvme_temperature_c",
                    "nvme_read_kib_per_second", "nvme_write_kib_per_second"
                ],
                "samples": []
            }
        })
    }

    // Returns one repeated canonical SHA-256 test identity.
    fn repeated_digest(character: char) -> Sha256Digest {
        Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
    }

    // Returns one canonical GitHub comment object for the built publication.
    fn comment(built: &BuiltPublication, id: u64, url: Option<String>) -> Value {
        json!({
            "id": id,
            "html_url": url.unwrap_or_else(|| format!(
                "https://github.com/letsinferlabs/runtimes/pull/123#issuecomment-{id}"
            )),
            "body": built.body,
        })
    }

    // Returns one record reader over the exact bytes used by a built fixture.
    fn record_reader(built: &BuiltPublication) -> Arc<Record> {
        Arc::new(Record(canonical_json(&built.record).expect("record")))
    }

    // Publishes, reads back, and returns one completely bound receipt.
    #[test]
    fn publication_posts_then_requires_exact_readback() {
        let fixture = fixture();
        let (sealed, built) = fixture.publication();
        let runner = Arc::new(Runner::default());
        runner.output(json!([[]]));
        runner.output(json!({"id": 11, "html_url": "ignored"}));
        runner.output(json!([[comment(&built, 11, None)]]));
        let provider = CoreBenchmarkVerificationPublicationProvider::new(
            PathBuf::from("/usr/bin/gh"),
            record_reader(&built),
            fixture.signer.clone(),
            runner.clone(),
        )
        .expect("provider");
        let request = BenchmarkPublicationRequest::new(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.restoration,
            &sealed,
        );
        let receipt = provider
            .publish(&request)
            .expect("publication")
            .expect("receipt");
        assert_eq!(receipt.verification_id(), &built.verification_id);
        assert_eq!(receipt.comment_id(), 11);
        assert_eq!(receipt.comment_body_sha256(), &built.body_sha256);
        let calls = runner.calls.lock().expect("calls");
        assert_eq!(calls.len(), 3);
        assert!(calls[0].0.contains(&"--paginate".to_string()));
        assert_eq!(calls[1].0[1..3], ["--method", "POST"]);
        assert!(calls[1].1.is_some());
    }

    // Replays an existing exact comment without posting and rejects divergent collision content.
    #[test]
    fn publication_replays_exact_comment_and_rejects_divergent_collision() {
        let fixture = fixture();
        let (sealed, built) = fixture.publication();
        for divergent in [false, true] {
            let runner = Arc::new(Runner::default());
            let mut value = comment(&built, 12, None);
            if divergent {
                value["body"] = Value::String(value["body"].as_str().expect("body").replacen(
                    "runtime verification",
                    "runtime verification changed",
                    1,
                ));
            }
            runner.output(json!([[value]]));
            let provider = CoreBenchmarkVerificationPublicationProvider::new(
                PathBuf::from("/usr/bin/gh"),
                record_reader(&built),
                fixture.signer.clone(),
                runner.clone(),
            )
            .expect("provider");
            let request = BenchmarkPublicationRequest::new(
                &fixture.job_id,
                &fixture.request,
                &fixture.outcome,
                &fixture.restoration,
                &sealed,
            );
            let result = provider.publish(&request);
            if divergent {
                assert_eq!(result, Err(BenchmarkError::PublicationRejected));
            } else {
                assert_eq!(result.expect("replay").expect("receipt").comment_id(), 12);
            }
            assert_eq!(runner.calls.lock().expect("calls").len(), 1);
        }
    }

    // Recovers a lost POST response only through mandatory exact lookup/readback.
    #[test]
    fn publication_recovers_post_response_loss_by_exact_lookup() {
        let fixture = fixture();
        let (sealed, built) = fixture.publication();
        let runner = Arc::new(Runner::default());
        runner.output(json!([[]]));
        runner.fail();
        runner.output(json!([[comment(&built, 13, None)]]));
        let provider = CoreBenchmarkVerificationPublicationProvider::new(
            PathBuf::from("/usr/bin/gh"),
            record_reader(&built),
            fixture.signer.clone(),
            runner,
        )
        .expect("provider");
        let request = BenchmarkPublicationRequest::new(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.restoration,
            &sealed,
        );
        assert_eq!(
            provider
                .publish(&request)
                .expect("recovered")
                .expect("receipt")
                .comment_id(),
            13
        );
    }

    // Rejects API/page/URL and sealed-evidence identity drift without claiming publication.
    #[test]
    fn publication_failure_matrix_is_retryable_and_fail_closed() {
        let fixture = fixture();
        let (sealed, built) = fixture.publication();
        let cases = [
            None,
            Some(json!({"not": "pages"})),
            Some(json!([[comment(
                &built,
                14,
                Some("https://example.invalid/comment".to_string())
            )]])),
        ];
        for listing in cases {
            let runner = Arc::new(Runner::default());
            match listing {
                Some(value) => runner.output(value),
                None => runner.fail(),
            }
            let provider = CoreBenchmarkVerificationPublicationProvider::new(
                PathBuf::from("/usr/bin/gh"),
                record_reader(&built),
                fixture.signer.clone(),
                runner,
            )
            .expect("provider");
            let request = BenchmarkPublicationRequest::new(
                &fixture.job_id,
                &fixture.request,
                &fixture.outcome,
                &fixture.restoration,
                &sealed,
            );
            assert_eq!(
                provider.publish(&request),
                Err(BenchmarkError::PublicationRejected)
            );
        }

        let wrong = SealedBenchmarkEvidence::new(
            BenchmarkEvidence::new(
                repeated_digest('f'),
                repeated_digest('1'),
                BenchmarkRecordSchema::CommunityVerificationV1,
                sealed.evidence().byte_count(),
            )
            .expect("evidence"),
            sealed.signature().clone(),
        );
        let request = BenchmarkPublicationRequest::new(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.restoration,
            &wrong,
        );
        assert!(matches!(
            build_publication(
                &request,
                &canonical_json(&built.record).expect("record"),
                fixture.signer.as_ref()
            ),
            Err(BenchmarkError::PublicationRejected)
        ));
    }

    // Rejects signature, envelope, evidence, visible summary, and expanded-size drift in a table.
    #[test]
    fn comment_parser_rejects_every_signed_or_visible_drift_class() {
        let fixture = fixture();
        let (_sealed, built) = fixture.publication();
        let marker = format!("<!-- {COMMENT_MARKER}\n");
        let start = built.body.find(&marker).expect("marker") + marker.len();
        let end = built.body.len() - "\n-->\n".len();
        let envelope: Value = serde_json::from_str(&built.body[start..end]).expect("envelope");
        let mut mutations = Vec::new();
        for pointer in [
            "/device_id",
            "/observed_head_sha",
            "/execution_sha256",
            "/summary/score_sha256",
            "/evidence/uncompressed_sha256",
            "/signature/key_id",
            "/signature/value",
        ] {
            let mut value = envelope.clone();
            *value.pointer_mut(pointer).expect("pointer") = Value::String("f".repeat(64));
            mutations.push(value);
        }
        for value in mutations {
            let body = format!(
                "{}{}\n-->\n",
                &built.body[..start],
                String::from_utf8(canonical_json(&value).expect("canonical"))
                    .expect("UTF-8")
                    .trim_end()
            );
            assert_eq!(
                parse_comment(&body, &built),
                Err(BenchmarkError::PublicationRejected)
            );
        }
        let visible = built
            .body
            .replacen("Aggregate tok/s", "Aggregate tokens", 1);
        assert_eq!(
            parse_comment(&visible, &built),
            Err(BenchmarkError::PublicationRejected)
        );
    }

    // Rejects every manager/material identity drift and both expanded-input size ceilings.
    #[test]
    fn publication_rejects_identity_and_size_drift_table() {
        let fixture = fixture();
        let (sealed, built) = fixture.publication();
        let record_request = CoreBenchmarkVerificationRecordRequest::new(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.restoration,
        );
        let identity = fixture.signer.identity().expect("identity");
        let independent = build_record(&record_request, &fixture.material, &identity)
            .expect("independent record");
        assert_eq!(
            independent.value["counts_toward_consensus"],
            Value::Bool(true)
        );
        let mut pull_request_author = fixture.material.clone();
        pull_request_author.pull_request_author_numeric_id = 99;
        let mut runtime_author = fixture.material.clone();
        runtime_author.runtime_author_numeric_ids = vec![99];
        for informational in [pull_request_author, runtime_author] {
            let record = build_record(&record_request, &informational, &identity)
                .expect("informational record");
            assert_eq!(record.value["counts_toward_consensus"], Value::Bool(false));
        }
        let mut materials = Vec::new();
        let mut wrong_pull_request = fixture.material.clone();
        wrong_pull_request.pull_request_url =
            "https://github.com/letsinferlabs/runtimes/pull/124".to_string();
        materials.push(wrong_pull_request);
        let mut wrong_head = fixture.material.clone();
        wrong_head.observed_head_sha = BenchmarkGitRevision::parse(&"b".repeat(40)).expect("head");
        materials.push(wrong_head);
        let mut wrong_candidate = fixture.material.clone();
        let mut subject: Value =
            serde_json::from_slice(&wrong_candidate.execution_subject_json).expect("subject");
        subject["candidate_id"] = Value::String("engine--owner--other--target".to_string());
        wrong_candidate.execution_subject_json = canonical_json(&subject).expect("subject");
        materials.push(wrong_candidate);
        let mut wrong_execution = fixture.material.clone();
        let mut subject: Value =
            serde_json::from_slice(&wrong_execution.execution_subject_json).expect("subject");
        subject["execution_sha256"] = Value::String(repeated_digest('0').as_str().to_string());
        wrong_execution.execution_subject_json = canonical_json(&subject).expect("subject");
        materials.push(wrong_execution);
        for material in materials {
            assert!(matches!(
                build_record(&record_request, &material, &identity),
                Err(BenchmarkError::PublicationRejected)
            ));
        }

        let other_signer = Signer::new();
        assert!(matches!(
            build_record(
                &record_request,
                &fixture.material,
                &other_signer.identity().expect("identity")
            ),
            Err(BenchmarkError::PublicationRejected)
        ));
        let wrong_restoration = BenchmarkRestoration::new(repeated_digest('0'));
        let wrong_restoration_request = BenchmarkPublicationRequest::new(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &wrong_restoration,
            &sealed,
        );
        assert!(matches!(
            build_publication(
                &wrong_restoration_request,
                &canonical_json(&built.record).expect("record"),
                fixture.signer.as_ref()
            ),
            Err(BenchmarkError::PublicationRejected)
        ));
        let wrong_signature = SealedBenchmarkEvidence::new(
            sealed.evidence().clone(),
            BenchmarkSignature::new(repeated_digest('f'), "c2lnbmF0dXJl").expect("signature"),
        );
        let wrong_signature_request = BenchmarkPublicationRequest::new(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.restoration,
            &wrong_signature,
        );
        assert!(matches!(
            build_publication(
                &wrong_signature_request,
                &canonical_json(&built.record).expect("record"),
                fixture.signer.as_ref()
            ),
            Err(BenchmarkError::PublicationRejected)
        ));

        for (subject, candidate) in [
            (
                vec![b' '; 128 * 1024 + 1],
                fixture.material.candidate_benchmark_json.clone(),
            ),
            (
                fixture.material.execution_subject_json.clone(),
                Some(vec![b' '; MAXIMUM_EXPANDED_EVIDENCE_BYTES + 1]),
            ),
        ] {
            assert!(matches!(
                CoreBenchmarkVerificationPublicationMaterial::new(
                    fixture.material.pull_request_url.clone(),
                    fixture.material.observed_head_sha.clone(),
                    fixture.material.proposal_base_sha.clone(),
                    fixture.material.engine_mode.clone(),
                    fixture.material.verifier.clone(),
                    fixture.material.pull_request_author_numeric_id,
                    fixture.material.runtime_author_numeric_ids.clone(),
                    subject,
                    candidate,
                    fixture.material.baseline_benchmark_json.clone(),
                    fixture.material.restoration_passed,
                    fixture.material.submitted_at_unix_seconds,
                ),
                Err(BenchmarkError::PublicationRejected)
            ));
        }
    }

    // Builds a blocking failure without a candidate score while preserving baseline evidence.
    #[test]
    fn publication_builds_closed_blocking_failure_record() {
        let mut output_failure = fixture();
        output_failure.outcome = BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256: Some(repeated_digest('8')),
            failure: BenchmarkFailure::new(
                BenchmarkFailureCategory::OutputValidation,
                "candidate",
                "candidate output failed validation",
            )
            .expect("failure"),
        };
        output_failure.material.candidate_benchmark_json = None;
        let (_sealed, built) = output_failure.publication();
        assert!(built.record["candidate"].is_null());
        assert!(built.record["run_score"].is_null());
        assert_eq!(built.record["correctness"]["passed"], Value::Bool(false));
        assert_eq!(built.record["safety"]["passed"], Value::Bool(false));
        assert_eq!(
            built.record["failure"]["category"],
            Value::String("output_validation".to_string())
        );
        parse_comment(&built.body, &built).expect("failure readback");

        let mut restoration = fixture();
        restoration.outcome = BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256: Some(repeated_digest('8')),
            failure: BenchmarkFailure::new(
                BenchmarkFailureCategory::Restoration,
                "restore",
                "resident baseline restoration requires intervention",
            )
            .expect("failure"),
        };
        restoration.material.restoration_passed = false;
        let (_sealed, built) = restoration.publication();
        assert!(built.record["candidate"].is_object());
        assert!(built.record["run_score"].is_null());
        assert_eq!(built.record["restoration"]["passed"], Value::Bool(false));
        assert_eq!(
            built.record["failure"]["category"],
            Value::String("restoration".to_string())
        );
        parse_comment(&built.body, &built).expect("restoration failure readback");
    }
}
