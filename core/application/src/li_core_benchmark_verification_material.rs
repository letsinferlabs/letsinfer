// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use li_benchmark_manager::{
    canonical_benchmark_json_bytes, validate_benchmark_evidence_bytes,
    BenchmarkCommunityVerificationDocument, BenchmarkCommunityVerificationDocumentProvider,
    BenchmarkError, BenchmarkExecutionOutcome, BenchmarkGitRevision, BenchmarkKind,
    BenchmarkPublicationProvider, BenchmarkPublicationRequest, BenchmarkRecordSchema,
    PairedBenchmarkVerificationExecutionProvider,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    ApplicationCoreBenchmarkVerificationPublicationFactory,
    ApplicationCoreBenchmarkVerificationTerminalProviders, CoreBenchmarkVerificationDeviceSigner,
    CoreBenchmarkVerificationGitHubCommandRunner, CoreBenchmarkVerificationGitHubIdentity,
    CoreBenchmarkVerificationPublicationMaterial, CoreBenchmarkVerificationPublicationMaterialPort,
    CoreBenchmarkVerificationPublicationProvider, CoreBenchmarkVerificationRecordBuilder,
    CoreBenchmarkVerificationRecordReader, CoreBenchmarkVerificationRecordRequest,
};

const REPOSITORY: &str = "letsinferlabs/runtimes";
const MAXIMUM_DOCUMENT_BYTES: usize = 4 << 20;
const GITHUB_TIMEOUT: Duration = Duration::from_secs(60);

// Builds one terminal publisher after binding it to the exact paired parent result source.
pub struct SystemCoreBenchmarkVerificationPublicationFactory {
    github_cli: PathBuf,
    verifier_root: PathBuf,
    evidence_root: PathBuf,
    owner_user_id: u32,
    signer: Arc<dyn CoreBenchmarkVerificationDeviceSigner>,
    runner: Arc<dyn CoreBenchmarkVerificationGitHubCommandRunner>,
}

impl SystemCoreBenchmarkVerificationPublicationFactory {
    // Creates one factory from explicit owner-private roots and credential-owning GitHub CLI port.
    pub fn new(
        github_cli: PathBuf,
        verifier_root: PathBuf,
        evidence_root: PathBuf,
        owner_user_id: u32,
        signer: Arc<dyn CoreBenchmarkVerificationDeviceSigner>,
        runner: Arc<dyn CoreBenchmarkVerificationGitHubCommandRunner>,
    ) -> Result<Self, BenchmarkError> {
        if !absolute_normal(&github_cli)
            || !absolute_normal(&verifier_root)
            || !absolute_normal(&evidence_root)
            || verifier_root == evidence_root
        {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(Self {
            github_cli,
            verifier_root,
            evidence_root,
            owner_user_id,
            signer,
            runner,
        })
    }
}

impl ApplicationCoreBenchmarkVerificationPublicationFactory
    for SystemCoreBenchmarkVerificationPublicationFactory
{
    // Binds one record builder to atomic evidence persistence and exact GitHub publication.
    fn terminal_providers(
        &self,
        results: Arc<PairedBenchmarkVerificationExecutionProvider>,
    ) -> Result<ApplicationCoreBenchmarkVerificationTerminalProviders, BenchmarkError> {
        let material = Arc::new(ApplicationCoreBenchmarkVerificationMaterial {
            github_cli: self.github_cli.clone(),
            verifier_root: self.verifier_root.clone(),
            evidence_root: self.evidence_root.clone(),
            owner_user_id: self.owner_user_id,
            results: results.clone(),
            runner: self.runner.clone(),
        });
        let builder = Arc::new(CoreBenchmarkVerificationRecordBuilder::new(
            material,
            self.signer.clone(),
        ));
        let evidence: Arc<dyn BenchmarkCommunityVerificationDocumentProvider> = Arc::new(
            ApplicationCoreBenchmarkVerificationDocumentProvider::new(builder, results),
        );
        let records: Arc<dyn CoreBenchmarkVerificationRecordReader> =
            Arc::new(FilesystemCoreBenchmarkVerificationRecordReader::new(
                self.evidence_root.clone(),
                self.owner_user_id,
            )?);
        let publication = CoreBenchmarkVerificationPublicationProvider::new(
            self.github_cli.clone(),
            records,
            self.signer.clone(),
            self.runner.clone(),
        )
        .map(|provider| Arc::new(provider) as Arc<dyn BenchmarkPublicationProvider>)?;
        Ok(ApplicationCoreBenchmarkVerificationTerminalProviders::new(
            evidence,
            publication,
        ))
    }
}

// Materializes community evidence only after the durable candidate-start boundary.
struct ApplicationCoreBenchmarkVerificationDocumentProvider {
    builder: Arc<CoreBenchmarkVerificationRecordBuilder>,
    results: Arc<PairedBenchmarkVerificationExecutionProvider>,
}

impl ApplicationCoreBenchmarkVerificationDocumentProvider {
    // Creates one outer evidence provider from the exact parent state and pure record builder.
    const fn new(
        builder: Arc<CoreBenchmarkVerificationRecordBuilder>,
        results: Arc<PairedBenchmarkVerificationExecutionProvider>,
    ) -> Self {
        Self { builder, results }
    }
}

impl BenchmarkCommunityVerificationDocumentProvider
    for ApplicationCoreBenchmarkVerificationDocumentProvider
{
    // Keeps pre-candidate failures local and materializes all later terminal evidence publicly.
    fn document(
        &self,
        job_id: &li_core_interface::OperationId,
        request: &li_benchmark_manager::BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        _telemetry: &li_benchmark_manager::BenchmarkTelemetryReceipt,
        restoration: &li_benchmark_manager::BenchmarkRestoration,
    ) -> Result<BenchmarkCommunityVerificationDocument, BenchmarkError> {
        if !request.kind().is_verification() {
            return Err(BenchmarkError::EvidenceRejected);
        }
        if !matches!(outcome, BenchmarkExecutionOutcome::Succeeded { .. })
            && !self.results.candidate_execution_started(job_id)?
        {
            return Ok(BenchmarkCommunityVerificationDocument::LocalFailure);
        }
        let request =
            CoreBenchmarkVerificationRecordRequest::new(job_id, request, outcome, restoration);
        let record = self.builder.record(&request)?;
        Ok(BenchmarkCommunityVerificationDocument::Community(
            record.bytes().to_vec(),
        ))
    }
}

// Reads exact already-sealed outer records from owner-private evidence storage.
struct FilesystemCoreBenchmarkVerificationRecordReader {
    evidence_root: PathBuf,
    owner_user_id: u32,
}

impl FilesystemCoreBenchmarkVerificationRecordReader {
    // Creates one reader from an explicit absolute owner-private evidence root.
    fn new(evidence_root: PathBuf, owner_user_id: u32) -> Result<Self, BenchmarkError> {
        if !absolute_normal(&evidence_root) {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(Self {
            evidence_root,
            owner_user_id,
        })
    }
}

impl CoreBenchmarkVerificationRecordReader for FilesystemCoreBenchmarkVerificationRecordReader {
    // Reads and content-binds one persisted CommunityVerificationV1 record before publication.
    fn record(&self, request: &BenchmarkPublicationRequest<'_>) -> Result<Vec<u8>, BenchmarkError> {
        if request.sealed().evidence().schema() != BenchmarkRecordSchema::CommunityVerificationV1 {
            return Err(BenchmarkError::PublicationRejected);
        }
        let bytes = read_private_file(
            &self.evidence_root.join(format!(
                "{}.json",
                request.sealed().evidence().evidence_id().as_str()
            )),
            MAXIMUM_DOCUMENT_BYTES,
            self.owner_user_id,
        )?;
        if bytes.len() as u64 != request.sealed().evidence().byte_count()
            || format!("{:x}", Sha256::digest(&bytes))
                != request.sealed().evidence().evidence_id().as_str()
        {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(bytes)
    }
}

// Resolves exact paired evidence, trusted bundle subject, and current immutable GitHub identities.
struct ApplicationCoreBenchmarkVerificationMaterial {
    github_cli: PathBuf,
    verifier_root: PathBuf,
    evidence_root: PathBuf,
    owner_user_id: u32,
    results: Arc<PairedBenchmarkVerificationExecutionProvider>,
    runner: Arc<dyn CoreBenchmarkVerificationGitHubCommandRunner>,
}

impl CoreBenchmarkVerificationPublicationMaterialPort
    for ApplicationCoreBenchmarkVerificationMaterial
{
    // Reconstructs one exact publication closure after paired terminal state is durably committed.
    fn material(
        &self,
        request: &CoreBenchmarkVerificationRecordRequest<'_>,
    ) -> Result<CoreBenchmarkVerificationPublicationMaterial, BenchmarkError> {
        let BenchmarkKind::Verification {
            pull_request,
            proposal_head,
            verifier_numeric_id,
            verifier_bundle_sha256,
            candidate_subject_sha256,
            ..
        } = request.request().kind()
        else {
            return Err(BenchmarkError::PublicationRejected);
        };
        let (baseline, candidate) = self.results.results(request.job_id())?;
        let (baseline_request, candidate_request) =
            self.results.child_requests(request.job_id())?;
        let baseline_bytes =
            self.read_evidence(baseline.evidence().evidence().evidence_id().as_str())?;
        if validate_benchmark_evidence_bytes(&baseline_request, baseline.outcome(), &baseline_bytes)
            .map_err(|_| BenchmarkError::PublicationRejected)?
            != *baseline.evidence().evidence()
        {
            return Err(BenchmarkError::PublicationRejected);
        }
        let candidate_bytes = match candidate.outcome() {
            BenchmarkExecutionOutcome::Succeeded { .. } => {
                let bytes =
                    self.read_evidence(candidate.evidence().evidence().evidence_id().as_str())?;
                if validate_benchmark_evidence_bytes(
                    &candidate_request,
                    candidate.outcome(),
                    &bytes,
                )
                .map_err(|_| BenchmarkError::PublicationRejected)?
                    != *candidate.evidence().evidence()
                {
                    return Err(BenchmarkError::PublicationRejected);
                }
                Some(bytes)
            }
            BenchmarkExecutionOutcome::Failed { .. }
            | BenchmarkExecutionOutcome::Cancelled { .. } => {
                let bytes =
                    self.read_evidence(candidate.evidence().evidence().evidence_id().as_str())?;
                if validate_benchmark_evidence_bytes(
                    &candidate_request,
                    candidate.outcome(),
                    &bytes,
                )
                .map_err(|_| BenchmarkError::PublicationRejected)?
                    != *candidate.evidence().evidence()
                {
                    return Err(BenchmarkError::PublicationRejected);
                }
                None
            }
        };
        let bundle = self.read_bundle(verifier_bundle_sha256.as_str())?;
        let subject = bundle
            .get("subject")
            .and_then(Value::as_object)
            .ok_or(BenchmarkError::PublicationRejected)?;
        if text(subject, "execution_sha256")? != candidate_subject_sha256.as_str() {
            return Err(BenchmarkError::PublicationRejected);
        }
        let execution_subject_json =
            canonical_benchmark_json_bytes(&Value::Object(subject.clone()))?;
        let proposal_base_sha = BenchmarkGitRevision::parse(text(&bundle, "proposal_base_sha")?)
            .map_err(|_| BenchmarkError::PublicationRejected)?;
        let engine_mode = text(&bundle, "mode")?.to_string();
        let runtime_author_numeric_ids = runtime_authors(&bundle)?;
        let pull_request_url = format!("https://github.com/{REPOSITORY}/pull/{pull_request}");
        let verifier = self.verifier_identity(*verifier_numeric_id)?;
        let pull_request_author_numeric_id =
            self.pull_request_author(&pull_request_url, proposal_head.as_str())?;
        CoreBenchmarkVerificationPublicationMaterial::new(
            pull_request_url,
            proposal_head.clone(),
            proposal_base_sha,
            engine_mode,
            verifier,
            pull_request_author_numeric_id,
            runtime_author_numeric_ids,
            execution_subject_json,
            candidate_bytes,
            baseline_bytes,
            self.results.restoration_passed(request.job_id())?,
            self.results.submitted_at_unix_seconds(request.job_id())?,
        )
    }
}

impl ApplicationCoreBenchmarkVerificationMaterial {
    // Reads one immutable child evidence record from its exact evidence identity.
    fn read_evidence(&self, evidence_id: &str) -> Result<Vec<u8>, BenchmarkError> {
        if evidence_id.len() != 64 {
            return Err(BenchmarkError::PublicationRejected);
        }
        read_private_file(
            &self.evidence_root.join(format!("{evidence_id}.json")),
            MAXIMUM_DOCUMENT_BYTES,
            self.owner_user_id,
        )
    }

    // Reads one retained trusted-finalizer bundle document by its exact bundle identity.
    fn read_bundle(&self, bundle_sha256: &str) -> Result<Map<String, Value>, BenchmarkError> {
        let root = self.verifier_root.join(format!("bundle-{bundle_sha256}"));
        let metadata =
            fs::symlink_metadata(&root).map_err(|_| BenchmarkError::PublicationRejected)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != self.owner_user_id
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(BenchmarkError::PublicationRejected);
        }
        let bytes = read_private_file(
            &root.join("bundle.json"),
            MAXIMUM_DOCUMENT_BYTES,
            self.owner_user_id,
        )?;
        if format!("{:x}", Sha256::digest(&bytes)) != bundle_sha256 {
            return Err(BenchmarkError::PublicationRejected);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| BenchmarkError::PublicationRejected)?;
        value
            .as_object()
            .cloned()
            .ok_or(BenchmarkError::PublicationRejected)
    }

    // Re-resolves the authenticated GitHub account and binds its immutable numeric identity.
    fn verifier_identity(
        &self,
        expected_numeric_id: u64,
    ) -> Result<CoreBenchmarkVerificationGitHubIdentity, BenchmarkError> {
        let value = self.github_json(vec!["api".to_string(), "user".to_string()])?;
        let object = value
            .as_object()
            .ok_or(BenchmarkError::PublicationRejected)?;
        let login = text(object, "login")?;
        let numeric_id = number(object, "id")?;
        let account_type = text(object, "type")?;
        if numeric_id != expected_numeric_id {
            return Err(BenchmarkError::PublicationRejected);
        }
        CoreBenchmarkVerificationGitHubIdentity::new(login, numeric_id, account_type)
    }

    // Re-resolves the exact open PR head and its immutable author numeric identity.
    fn pull_request_author(
        &self,
        pull_request_url: &str,
        expected_head: &str,
    ) -> Result<u64, BenchmarkError> {
        let value = self.github_json(vec![
            "pr".to_string(),
            "view".to_string(),
            pull_request_url.to_string(),
            "--repo".to_string(),
            REPOSITORY.to_string(),
            "--json".to_string(),
            "url,state,headRefOid,author".to_string(),
        ])?;
        let object = value
            .as_object()
            .ok_or(BenchmarkError::PublicationRejected)?;
        if text(object, "url")? != pull_request_url
            || text(object, "state")? != "OPEN"
            || text(object, "headRefOid")? != expected_head
        {
            return Err(BenchmarkError::PublicationRejected);
        }
        let author = object
            .get("author")
            .and_then(Value::as_object)
            .ok_or(BenchmarkError::PublicationRejected)?;
        let login = text(author, "login")?;
        let identity = self.github_json(vec!["api".to_string(), format!("users/{login}")])?;
        let identity = identity
            .as_object()
            .ok_or(BenchmarkError::PublicationRejected)?;
        let kind = text(identity, "type")?;
        let numeric_id = number(identity, "id")?;
        if numeric_id == 0 || !matches!(kind, "User" | "Organization") {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(numeric_id)
    }

    // Executes one bounded GitHub CLI JSON request without accepting stderr or non-object output.
    fn github_json(&self, arguments: Vec<String>) -> Result<Value, BenchmarkError> {
        let output = self.runner.run(
            &self.github_cli,
            &arguments,
            None,
            GITHUB_TIMEOUT,
            MAXIMUM_DOCUMENT_BYTES,
        )?;
        if output.status() != 0 || !output.stderr().is_empty() {
            return Err(BenchmarkError::PublicationRejected);
        }
        let value: Value = serde_json::from_slice(output.stdout())
            .map_err(|_| BenchmarkError::PublicationRejected)?;
        if !value.is_object() {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(value)
    }
}

// Returns unique sorted runtime author identities from the trusted finalizer bundle.
fn runtime_authors(bundle: &Map<String, Value>) -> Result<Vec<u64>, BenchmarkError> {
    let authors = bundle
        .get("runtime_authors")
        .and_then(Value::as_array)
        .ok_or(BenchmarkError::PublicationRejected)?;
    let mut values = authors
        .iter()
        .map(|author| {
            author
                .as_object()
                .and_then(|author| author.get("github_id"))
                .and_then(Value::as_u64)
                .filter(|identity| *identity > 0)
                .ok_or(BenchmarkError::PublicationRejected)
        })
        .collect::<Result<Vec<_>, _>>()?;
    values.sort_unstable();
    values.dedup();
    if values.len() != authors.len() || values.is_empty() {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(values)
}

// Reads one owner-private single-link regular file without following its final path.
fn read_private_file(
    path: &Path,
    maximum_bytes: usize,
    owner_user_id: u32,
) -> Result<Vec<u8>, BenchmarkError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    let metadata = file
        .metadata()
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > maximum_bytes as u64
    {
        return Err(BenchmarkError::PublicationRejected);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BenchmarkError::PublicationRejected)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(BenchmarkError::PublicationRejected);
    }
    Ok(bytes)
}

// Returns one required string field.
fn text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, BenchmarkError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(BenchmarkError::PublicationRejected)
}

// Returns one required positive numeric field.
fn number(object: &Map<String, Value>, field: &str) -> Result<u64, BenchmarkError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(BenchmarkError::PublicationRejected)
}

// Returns whether one path is absolute, normal, and non-root.
fn absolute_normal(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use li_benchmark_manager::{
        validate_benchmark_evidence_bytes, validate_benchmark_record_bytes, BenchmarkAuthorization,
        BenchmarkEvidenceProvider, BenchmarkExecutionObservation, BenchmarkExecutionProvider,
        BenchmarkRecordSchema, BenchmarkRestoration, BenchmarkSignature, BenchmarkTelemetryReceipt,
        BenchmarkVerificationArm, BenchmarkVerificationChildObservation,
        BenchmarkVerificationChildProvider, BenchmarkVerificationChildResult,
        BenchmarkVerificationClock, DatabaseBenchmarkVerificationStore,
        FilesystemBenchmarkEvidenceProvider, PreparedBenchmark, RoutedBenchmarkEvidenceProvider,
        RunningBenchmark, SealedBenchmarkEvidence, SystemBenchmarkEvidenceNativeIo,
    };
    use li_core_interface::{OperationId, PlacementGroupState, Sha256Digest, UnixMilliseconds};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use crate::li_benchmark_candidate_handoff_fixture::BenchmarkCandidateHandoffFixture;
    use crate::li_core_benchmark_verification_publication::tests::fixture;
    use crate::ApplicationCoreBenchmarkVerificationHandoff;

    use super::*;

    // Returns one deterministic terminal child result for each real parent arm.
    struct TerminalChildren {
        baseline: BenchmarkVerificationChildResult,
        candidate: BenchmarkVerificationChildResult,
    }

    impl BenchmarkVerificationChildProvider for TerminalChildren {
        // Returns one arm-specific deterministic preparation receipt.
        fn prepare(
            &self,
            _job_id: &OperationId,
            arm: BenchmarkVerificationArm,
            _request: &li_benchmark_manager::BenchmarkRequest,
        ) -> Result<PreparedBenchmark, BenchmarkError> {
            Ok(PreparedBenchmark::new(digest(match arm {
                BenchmarkVerificationArm::Baseline => b"baseline prepared",
                BenchmarkVerificationArm::Candidate => b"candidate prepared",
            })))
        }

        // Returns one arm-specific deterministic running receipt.
        fn start(
            &self,
            _job_id: &OperationId,
            arm: BenchmarkVerificationArm,
            _request: &li_benchmark_manager::BenchmarkRequest,
            _prepared: &PreparedBenchmark,
        ) -> Result<RunningBenchmark, BenchmarkError> {
            Ok(RunningBenchmark::new(digest(match arm {
                BenchmarkVerificationArm::Baseline => b"baseline running",
                BenchmarkVerificationArm::Candidate => b"candidate running",
            })))
        }

        // Returns the exact already-sealed terminal result for one active arm.
        fn observe(
            &self,
            _job_id: &OperationId,
            arm: BenchmarkVerificationArm,
            _request: &li_benchmark_manager::BenchmarkRequest,
            _prepared: &PreparedBenchmark,
            _running: &RunningBenchmark,
        ) -> Result<BenchmarkVerificationChildObservation, BenchmarkError> {
            Ok(BenchmarkVerificationChildObservation::Terminal(match arm {
                BenchmarkVerificationArm::Baseline => self.baseline.clone(),
                BenchmarkVerificationArm::Candidate => self.candidate.clone(),
            }))
        }

        // Accepts an idempotent stop if the outer manager ever requests cancellation.
        fn request_stop(
            &self,
            _job_id: &OperationId,
            _arm: BenchmarkVerificationArm,
            _running: &RunningBenchmark,
        ) -> Result<(), BenchmarkError> {
            Ok(())
        }

        // Accepts idempotent child cleanup after real baseline restoration.
        fn cleanup(
            &self,
            _job_id: &OperationId,
            _arm: BenchmarkVerificationArm,
        ) -> Result<(), BenchmarkError> {
            Ok(())
        }
    }

    // Supplies deterministic increasing times for real parent phase commits.
    struct ParentClock(std::sync::atomic::AtomicU64);

    impl BenchmarkVerificationClock for ParentClock {
        // Returns one unique terminal-adjacent parent transition time.
        fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
            Ok(UnixMilliseconds::new(
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            ))
        }
    }

    // Captures the first posted comment and serves it back for mandatory readback and restart replay.
    #[derive(Default)]
    struct GitHubRunner {
        body: Mutex<Option<String>>,
        posts: Mutex<u64>,
    }

    impl GitHubRunner {
        // Returns the number of actual comment mutations across both finalization attempts.
        fn post_count(&self) -> u64 {
            *self.posts.lock().expect("posts")
        }
    }

    impl CoreBenchmarkVerificationGitHubCommandRunner for GitHubRunner {
        // Implements the exact bounded GitHub identity, PR, post, and readback calls.
        fn run(
            &self,
            _executable: &Path,
            arguments: &[String],
            input: Option<&[u8]>,
            _timeout: Duration,
            _maximum_output_bytes: usize,
        ) -> Result<crate::CoreBenchmarkVerificationGitHubCommandOutput, BenchmarkError> {
            let value = if arguments == ["api", "user"] {
                json!({"login": "Verifier", "id": 99, "type": "User"})
            } else if arguments.first().map(String::as_str) == Some("pr") {
                json!({
                    "url": "https://github.com/letsinferlabs/runtimes/pull/123",
                    "state": "OPEN",
                    "headRefOid": "a".repeat(40),
                    "author": {"login": "PullAuthor"},
                })
            } else if arguments == ["api", "users/PullAuthor"] {
                json!({"id": 41, "type": "User"})
            } else if arguments.iter().any(|value| value == "--paginate") {
                match self.body.lock().expect("body").clone() {
                    Some(body) => json!([[{
                        "id": 11,
                        "html_url": "https://github.com/letsinferlabs/runtimes/pull/123#issuecomment-11",
                        "body": body,
                    }]]),
                    None => json!([[]]),
                }
            } else if arguments.iter().any(|value| value == "POST") {
                let document: Value =
                    serde_json::from_slice(input.ok_or(BenchmarkError::PublicationRejected)?)
                        .map_err(|_| BenchmarkError::PublicationRejected)?;
                let body = document
                    .get("body")
                    .and_then(Value::as_str)
                    .ok_or(BenchmarkError::PublicationRejected)?
                    .to_string();
                *self.body.lock().expect("body") = Some(body.clone());
                *self.posts.lock().expect("posts") += 1;
                json!({
                    "id": 11,
                    "html_url": "https://github.com/letsinferlabs/runtimes/pull/123#issuecomment-11",
                    "body": body,
                })
            } else {
                return Err(BenchmarkError::PublicationRejected);
            };
            Ok(crate::CoreBenchmarkVerificationGitHubCommandOutput::new(
                0,
                canonical_benchmark_json_bytes(&value)?,
                Vec::new(),
            ))
        }
    }

    // Returns one lowercase SHA-256 identity for exact bytes.
    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
    }

    // Creates one owner-private directory required by production filesystem providers.
    fn private_directory(path: &Path) {
        fs::create_dir_all(path).expect("directory");
        fs::set_permissions(path, Permissions::from_mode(0o700)).expect("directory mode");
    }

    // Writes one exact owner-private immutable fixture file.
    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("file");
        fs::set_permissions(path, Permissions::from_mode(0o600)).expect("file mode");
    }

    // Returns one successful child result and proves its request/outcome evidence binding first.
    fn child_result(
        request: &li_benchmark_manager::BenchmarkRequest,
        bytes: &[u8],
        key_id: &Sha256Digest,
        character: char,
    ) -> BenchmarkVerificationChildResult {
        let receipt = validate_benchmark_record_bytes(bytes).expect("record");
        let outcome = BenchmarkExecutionOutcome::Succeeded {
            raw_evidence_sha256: digest(bytes),
            results_sha256: receipt.results_sha256().clone(),
            record_schema: receipt.schema(),
        };
        assert_eq!(
            validate_benchmark_evidence_bytes(request, &outcome, bytes).expect("binding"),
            receipt
        );
        BenchmarkVerificationChildResult::new(
            outcome,
            BenchmarkTelemetryReceipt::new(digest(&[character as u8]), 2),
            BenchmarkRestoration::new(digest(&[character as u8, 1])),
            SealedBenchmarkEvidence::new(
                receipt,
                BenchmarkSignature::new(key_id.clone(), "c2lnbmF0dXJl").expect("signature"),
            ),
            2,
        )
        .expect("child result")
    }

    // Rebinds one canonical child record to the real Leaf-A Core installation identity.
    fn rebound_record(bytes: &[u8], subject: &li_benchmark_manager::BenchmarkSubject) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(bytes).expect("record");
        value["installation_id"] = Value::String(subject.installation_id().as_str().to_string());
        let identity = json!({
            "benchmark_contract_sha256": value["benchmark_contract_sha256"].clone(),
            "contract": "letsinfer-benchmark-identity-v2",
            "installation_id": value["installation_id"].clone(),
            "results_sha256": value["results_sha256"].clone(),
            "subject": value["subject"].clone(),
            "timestamp_unix_ns": value["timestamp_unix_ns"].clone(),
        });
        value["id"] = Value::String(
            digest(&canonical_benchmark_json_bytes(&identity).expect("identity"))
                .as_str()
                .to_string(),
        );
        canonical_benchmark_json_bytes(&value).expect("record")
    }

    // Retains one real paired lifecycle plus the shared Leaf-A providers needed for restart.
    struct PairedRun {
        provider: Arc<PairedBenchmarkVerificationExecutionProvider>,
        request: li_benchmark_manager::BenchmarkRequest,
        outcome: BenchmarkExecutionOutcome,
        restoration: BenchmarkRestoration,
        baseline: BenchmarkVerificationChildResult,
        candidate: BenchmarkVerificationChildResult,
        leaf: BenchmarkCandidateHandoffFixture,
    }

    // Runs the real DB-backed parent through Leaf-A, both child arms, and baseline restoration.
    fn paired_parent(
        publication: &crate::li_core_benchmark_verification_publication::tests::Fixture,
        evidence_root: &Path,
    ) -> PairedRun {
        let benchmark_contract = publication
            .request()
            .subject()
            .benchmark_contract_sha256()
            .clone();
        let target_contract = publication
            .request()
            .subject()
            .target_contract_sha256()
            .clone();
        let leaf = BenchmarkCandidateHandoffFixture::new_with_contracts(
            PlacementGroupState::Running,
            benchmark_contract,
            target_contract,
        );
        let coordinator = Arc::new(leaf.coordinator());
        let node_request = leaf.request('d');
        coordinator.prepare(node_request).expect("Leaf-A prepare");
        let transaction_id = OperationId::parse(&"d".repeat(32)).expect("transaction");
        let candidate_subject = coordinator
            .prepared_subject(&transaction_id)
            .expect("prepared subject");
        let BenchmarkKind::Verification {
            pull_request,
            proposal_head,
            candidate,
            verifier_bundle_sha256,
            candidate_subject_sha256,
            verifier_numeric_id,
            device_id,
            ..
        } = publication.request().kind()
        else {
            panic!("verification request");
        };
        let candidate_request = li_benchmark_manager::BenchmarkRequest::new(
            BenchmarkKind::verification(
                *pull_request,
                proposal_head.clone(),
                candidate.clone(),
                transaction_id,
                verifier_bundle_sha256.clone(),
                candidate_subject_sha256.clone(),
                *verifier_numeric_id,
                device_id.clone(),
                Some(leaf.baseline_subject.execution_sha256().clone()),
            )
            .expect("verification kind"),
            li_benchmark_manager::BenchmarkScope::Complete,
            candidate_subject,
        )
        .expect("candidate request");
        let baseline_request = li_benchmark_manager::BenchmarkRequest::new(
            BenchmarkKind::Local,
            li_benchmark_manager::BenchmarkScope::Complete,
            leaf.baseline_subject.clone(),
        )
        .expect("baseline request");
        let baseline_bytes = rebound_record(publication.baseline_json(), &leaf.baseline_subject);
        let candidate_bytes =
            rebound_record(publication.candidate_json(), candidate_request.subject());
        let key_id = publication.signature_key_id();
        let baseline = child_result(&baseline_request, &baseline_bytes, &key_id, 'b');
        let candidate = child_result(&candidate_request, &candidate_bytes, &key_id, 'c');
        for (result, bytes) in [
            (&baseline, baseline_bytes.as_slice()),
            (&candidate, candidate_bytes.as_slice()),
        ] {
            private_file(
                &evidence_root.join(format!(
                    "{}.json",
                    result.evidence().evidence().evidence_id().as_str()
                )),
                bytes,
            );
        }
        let store = Arc::new(DatabaseBenchmarkVerificationStore::new(
            leaf.database.clone(),
        ));
        let handoff = Arc::new(ApplicationCoreBenchmarkVerificationHandoff::new(
            coordinator,
        ));
        let children = Arc::new(TerminalChildren {
            baseline: baseline.clone(),
            candidate: candidate.clone(),
        });
        let provider = Arc::new(PairedBenchmarkVerificationExecutionProvider::new(
            store,
            handoff,
            children,
            Arc::new(ParentClock(std::sync::atomic::AtomicU64::new(
                1_787_465_000_000,
            ))),
        ));
        let prepared = provider
            .prepare(
                publication.job_id(),
                &candidate_request,
                &BenchmarkAuthorization::new(digest(b"authorization")),
            )
            .expect("parent prepare");
        let running = provider
            .start(publication.job_id(), &candidate_request, &prepared)
            .expect("parent start");
        let BenchmarkExecutionObservation::Terminal(outcome) = provider
            .observe(publication.job_id(), &running)
            .expect("paired terminal")
        else {
            panic!("terminal observation");
        };
        let restoration = provider
            .restore(
                publication.job_id(),
                &candidate_request,
                &prepared,
                Some(&running),
                &outcome,
            )
            .expect("parent restoration");
        PairedRun {
            provider,
            request: candidate_request,
            outcome,
            restoration,
            baseline,
            candidate,
            leaf,
        }
    }

    // Reopens the same DB parent and real Leaf-A coordinator after the simulated process restart.
    fn restarted_parent(run: &PairedRun) -> Arc<PairedBenchmarkVerificationExecutionProvider> {
        Arc::new(PairedBenchmarkVerificationExecutionProvider::new(
            Arc::new(DatabaseBenchmarkVerificationStore::new(
                run.leaf.database.clone(),
            )),
            Arc::new(ApplicationCoreBenchmarkVerificationHandoff::new(Arc::new(
                run.leaf.coordinator(),
            ))),
            Arc::new(TerminalChildren {
                baseline: run.baseline.clone(),
                candidate: run.candidate.clone(),
            }),
            Arc::new(ParentClock(std::sync::atomic::AtomicU64::new(
                1_787_465_001_000,
            ))),
        ))
    }

    #[test]
    // Runs production material, persistence, signature identity, GitHub readback, and restart replay.
    fn production_material_factory_persists_posts_reads_back_and_replays_after_restart() {
        let publication_fixture = fixture();
        let directory = tempfile::tempdir().expect("directory");
        let task_root = directory.path().join("tasks");
        let evidence_root = directory.path().join("evidence");
        let verifier_root = directory.path().join("verifier");
        let source_root = directory.path().join("source");
        for path in [&task_root, &evidence_root, &verifier_root, &source_root] {
            private_directory(path);
        }
        let run = paired_parent(&publication_fixture, &evidence_root);
        let BenchmarkKind::Verification {
            verifier_bundle_sha256,
            ..
        } = run.request.kind()
        else {
            panic!("verification");
        };
        let bundle_root = verifier_root.join(format!("bundle-{}", verifier_bundle_sha256.as_str()));
        private_directory(&bundle_root);
        private_file(
            &bundle_root.join("bundle.json"),
            publication_fixture.bundle_json(),
        );
        let runner = Arc::new(GitHubRunner::default());
        // SAFETY: this reads only the effective identity of the current test process.
        let owner_user_id = unsafe { libc::geteuid() };
        let factory = SystemCoreBenchmarkVerificationPublicationFactory::new(
            PathBuf::from("/usr/bin/gh"),
            verifier_root.clone(),
            evidence_root.clone(),
            owner_user_id,
            publication_fixture.signer(),
            runner.clone(),
        )
        .expect("factory");
        let (documents, publication) = factory
            .terminal_providers(run.provider.clone())
            .expect("terminal providers")
            .into_parts();
        let native_io = Arc::new(SystemBenchmarkEvidenceNativeIo);
        let ordinary = Arc::new(
            FilesystemBenchmarkEvidenceProvider::new(
                source_root.clone(),
                evidence_root.clone(),
                owner_user_id,
                native_io,
            )
            .expect("ordinary evidence"),
        );
        let routed = RoutedBenchmarkEvidenceProvider::new(ordinary.clone(), ordinary, documents);
        let telemetry = BenchmarkTelemetryReceipt::new(digest(b"outer telemetry"), 4);
        let evidence = routed
            .finalize(
                publication_fixture.job_id(),
                &run.request,
                &run.outcome,
                &telemetry,
                &run.restoration,
            )
            .expect("outer evidence");
        routed
            .verify(&run.request, &run.outcome, &evidence)
            .expect("outer verification");
        assert_eq!(
            evidence.schema(),
            BenchmarkRecordSchema::CommunityVerificationV1
        );
        let sealed = SealedBenchmarkEvidence::new(
            evidence.clone(),
            BenchmarkSignature::new(publication_fixture.signature_key_id(), "c2lnbmF0dXJl")
                .expect("outer signature"),
        );
        let publication_request = li_benchmark_manager::BenchmarkPublicationRequest::new(
            publication_fixture.job_id(),
            &run.request,
            &run.outcome,
            &run.restoration,
            &sealed,
        );
        let first = publication
            .publish(&publication_request)
            .expect("publish")
            .expect("receipt");
        assert_eq!(runner.post_count(), 1);

        let restarted_parent = restarted_parent(&run);
        let restarted_factory = SystemCoreBenchmarkVerificationPublicationFactory::new(
            PathBuf::from("/usr/bin/gh"),
            verifier_root,
            evidence_root.clone(),
            owner_user_id,
            publication_fixture.signer(),
            runner.clone(),
        )
        .expect("restart factory");
        let (restart_documents, restart_publication) = restarted_factory
            .terminal_providers(restarted_parent)
            .expect("restart providers")
            .into_parts();
        let restart_ordinary = Arc::new(
            FilesystemBenchmarkEvidenceProvider::new(
                source_root,
                evidence_root,
                owner_user_id,
                Arc::new(SystemBenchmarkEvidenceNativeIo),
            )
            .expect("restart evidence"),
        );
        let restart_routed = RoutedBenchmarkEvidenceProvider::new(
            restart_ordinary.clone(),
            restart_ordinary,
            restart_documents,
        );
        let replayed_evidence = restart_routed
            .finalize(
                publication_fixture.job_id(),
                &run.request,
                &run.outcome,
                &telemetry,
                &run.restoration,
            )
            .expect("restart evidence replay");
        assert_eq!(replayed_evidence, evidence);
        let replayed_sealed = SealedBenchmarkEvidence::new(
            replayed_evidence,
            BenchmarkSignature::new(publication_fixture.signature_key_id(), "c2lnbmF0dXJl")
                .expect("restart signature"),
        );
        let replay_request = li_benchmark_manager::BenchmarkPublicationRequest::new(
            publication_fixture.job_id(),
            &run.request,
            &run.outcome,
            &run.restoration,
            &replayed_sealed,
        );
        let replay = restart_publication
            .publish(&replay_request)
            .expect("restart publication")
            .expect("restart receipt");
        assert_eq!(replay, first);
        assert_eq!(runner.post_count(), 1);
    }
}
