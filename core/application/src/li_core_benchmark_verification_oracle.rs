// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use li_benchmark_manager::BenchmarkGitRevision;
use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, ByteCount, CpuArchitecture, EngineDistribution,
    EntityTimestamps, EvidenceLabel, GgufFileIdentity, LogicalModelName, MemoryTopology,
    ModelArtifact, ModelArtifactFormat, NativeEngineKind, NodeId, OperatingSystem,
    PlatformIdentity, RuntimeCandidateId, RuntimeIdentity, RuntimeInstallation,
    RuntimeInstallationId, RuntimeInstallationState, RuntimeSource, RuntimeVersion, Sha256Digest,
    TargetId, TechnicalName, UnixMilliseconds,
};
use li_runtime_manager::{
    FilesystemRuntimeExecutionManifestProvider, RuntimeAcceleratorVendor, RuntimeBearerToken,
    RuntimeCandidate, RuntimeExecutionManifestIo, RuntimeExecutionManifestProvider,
    RuntimeHttpClient, RuntimeHttpRequest, RuntimeInstallationProvider, RuntimePackArtifactIo,
    RuntimeTarget, SystemRuntimePackArtifactIo,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    CoreBenchmarkVerificationOracle, CoreBenchmarkVerificationPreparationError,
    CoreBenchmarkVerificationProposal,
};

const REPOSITORY: &str = "letsinferlabs/runtimes";
const BENCHMARK_READY_LABEL: &str = "benchmark-ready";
const FINALIZER_PATH: &str = ".github/workflows/finalize-verifier.yml";
const BUILD_PATH: &str = ".github/workflows/build-verifier.yml";
const FINALIZER_CERTIFICATE_IDENTITY: &str =
    "https://github.com/letsinferlabs/runtimes/.github/workflows/finalize-verifier.yml@refs/heads/main";
const MINIMUM_GH_VERSION: (u64, u64, u64) = (2, 97, 0);
const MAXIMUM_COMMAND_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_COMMAND_ARGUMENTS: usize = 128;
const MAXIMUM_COMMAND_ARGUMENT_BYTES: usize = 4 * 1024;
const MAXIMUM_ARTIFACT_FILES: usize = 32;
const MAXIMUM_ARTIFACT_BYTES: u64 = 20_u64 << 30;
const MAXIMUM_DOCUMENT_BYTES: u64 = 4 << 20;
const MAXIMUM_RUNTIME_PACK_BYTES: u64 = 1 << 30;
const MAXIMUM_ENGINE_LAYOUT_BYTES: u64 = 16_u64 << 30;
const MAXIMUM_ENGINE_DOCUMENT_BYTES: u64 = 4 << 20;
const MAXIMUM_ENGINE_LAYER_BYTES: u64 = 10_000_000_000;
const MAXIMUM_ENGINE_ENTRIES: usize = 100_000;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const PACK_MEDIA_TYPE: &str = "application/vnd.letsinfer.runtime.v6+tar";

// Identifies how one trusted verifier candidate's Engine bytes must be staged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreBenchmarkVerificationEngineArtifact {
    Reuse,
    BuiltOci {
        archive_file: PathBuf,
        config_digest: Sha256Digest,
        local_tag: String,
    },
    BuiltNative,
}

// Carries one fully verified resident-only candidate closure; no field crosses the private API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreBenchmarkVerificationCandidate {
    runtime: RuntimeCandidate,
    runtime_pack_file: PathBuf,
    engine: CoreBenchmarkVerificationEngineArtifact,
    bundle_sha256: Sha256Digest,
    execution_sha256: Sha256Digest,
    runtime_author_numeric_ids: Vec<u64>,
    proposal_base: BenchmarkGitRevision,
}

impl CoreBenchmarkVerificationCandidate {
    // Creates one already verified resident-only closure for production or deterministic mocks.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: RuntimeCandidate,
        runtime_pack_file: PathBuf,
        engine: CoreBenchmarkVerificationEngineArtifact,
        bundle_sha256: Sha256Digest,
        execution_sha256: Sha256Digest,
        runtime_author_numeric_ids: Vec<u64>,
        proposal_base: BenchmarkGitRevision,
    ) -> Result<Self, CoreBenchmarkVerificationOracleError> {
        let mut authors = runtime_author_numeric_ids.clone();
        authors.sort_unstable();
        authors.dedup();
        let engine_valid = match &engine {
            CoreBenchmarkVerificationEngineArtifact::Reuse
            | CoreBenchmarkVerificationEngineArtifact::BuiltNative => true,
            CoreBenchmarkVerificationEngineArtifact::BuiltOci {
                archive_file,
                local_tag,
                ..
            } => {
                absolute_normal(archive_file)
                    && !local_tag.is_empty()
                    && local_tag.len() <= 255
                    && !local_tag.chars().any(char::is_whitespace)
            }
        };
        if !absolute_normal(&runtime_pack_file)
            || !engine_valid
            || runtime_author_numeric_ids.is_empty()
            || runtime_author_numeric_ids
                .iter()
                .any(|identity| *identity == 0)
            || authors.len() != runtime_author_numeric_ids.len()
        {
            return Err(CoreBenchmarkVerificationOracleError::InvalidConfiguration);
        }
        Ok(Self {
            runtime,
            runtime_pack_file,
            engine,
            bundle_sha256,
            execution_sha256,
            runtime_author_numeric_ids,
            proposal_base,
        })
    }

    // Returns the exact typed runtime candidate reconstructed by the production Runtime parser.
    pub const fn runtime(&self) -> &RuntimeCandidate {
        &self.runtime
    }

    // Returns the retained verified runtime pack inside the owner-private bundle root.
    pub fn runtime_pack_file(&self) -> &Path {
        &self.runtime_pack_file
    }

    // Returns the exact reuse, local OCI, or native Engine staging identity.
    pub const fn engine(&self) -> &CoreBenchmarkVerificationEngineArtifact {
        &self.engine
    }

    // Returns the aggregate trusted-finalizer bundle identity.
    pub const fn bundle_sha256(&self) -> &Sha256Digest {
        &self.bundle_sha256
    }

    // Returns the canonical verifier execution subject identity.
    pub const fn execution_sha256(&self) -> &Sha256Digest {
        &self.execution_sha256
    }

    // Returns immutable GitHub numeric identities declared as runtime authors.
    pub fn runtime_author_numeric_ids(&self) -> &[u64] {
        &self.runtime_author_numeric_ids
    }

    // Returns the exact trusted base revision whose workflow built the candidate.
    pub const fn proposal_base(&self) -> &BenchmarkGitRevision {
        &self.proposal_base
    }
}

// Names one exact production-oracle failure without exposing credentials or response bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreBenchmarkVerificationOracleError {
    InvalidConfiguration,
    CommandUnavailable,
    CommandFailed,
    ResponseInvalid,
    ProposalInvalid,
    ArtifactInvalid,
    BundleInvalid,
    FilesystemUnavailable,
}

impl fmt::Display for CoreBenchmarkVerificationOracleError {
    // Presents one bounded provider failure without repository credentials or native paths.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("benchmark verification oracle failed")
    }
}

impl Error for CoreBenchmarkVerificationOracleError {}

// Names one bounded shell-free command failure before any response is trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreBenchmarkVerificationCommandError {
    InvalidCommand,
    Unavailable,
    TimedOut,
    OutputExceeded,
}

impl fmt::Display for CoreBenchmarkVerificationCommandError {
    // Presents one credential-free process boundary failure.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("benchmark verification command failed")
    }
}

impl Error for CoreBenchmarkVerificationCommandError {}

// Carries one exact bounded process exit result for production and deterministic mocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreBenchmarkVerificationCommandOutput {
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CoreBenchmarkVerificationCommandOutput {
    // Creates one exact command result without interpreting its status or bytes.
    pub const fn new(status: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            status,
            stdout,
            stderr,
        }
    }

    // Returns the native exit status or -1 after signal termination.
    pub const fn status(&self) -> i32 {
        self.status
    }

    // Returns bounded stdout for the closed response parser.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    // Returns bounded stderr only for stable failure classification.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

// Defines every GitHub CLI process interaction behind one deterministic shell-free boundary.
pub trait CoreBenchmarkVerificationCommandRunner: Send + Sync {
    // Runs one exact argv and returns at most the requested combined output bytes.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout: Duration,
        maximum_output_bytes: usize,
        use_attestation_token: bool,
    ) -> Result<CoreBenchmarkVerificationCommandOutput, CoreBenchmarkVerificationCommandError>;

    // Streams one exact command stdout into a new private file under a strict byte limit.
    fn download(
        &self,
        executable: &Path,
        arguments: &[String],
        destination: &Path,
        timeout: Duration,
        maximum_bytes: u64,
    ) -> Result<CoreBenchmarkVerificationCommandOutput, CoreBenchmarkVerificationCommandError>;
}

// Executes GitHub CLI operations without a shell and kills commands that cross fixed bounds.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreBenchmarkVerificationCommandRunner;

impl CoreBenchmarkVerificationCommandRunner for SystemCoreBenchmarkVerificationCommandRunner {
    // Runs one explicit executable and argv with bounded concurrent stdout and stderr reads.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout: Duration,
        maximum_output_bytes: usize,
        use_attestation_token: bool,
    ) -> Result<CoreBenchmarkVerificationCommandOutput, CoreBenchmarkVerificationCommandError> {
        validate_command(executable, arguments, timeout, maximum_output_bytes)?;
        let mut command = command(executable, arguments, use_attestation_token);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(CoreBenchmarkVerificationCommandError::Unavailable)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(CoreBenchmarkVerificationCommandError::Unavailable)?;
        let stdout_reader = bounded_reader(stdout, maximum_output_bytes);
        let stderr_reader = bounded_reader(stderr, maximum_output_bytes);
        let status = wait_for_child(&mut child, timeout, None)?;
        let stdout = join_reader(stdout_reader)?;
        let stderr = join_reader(stderr_reader)?;
        if stdout
            .len()
            .checked_add(stderr.len())
            .is_none_or(|bytes| bytes > maximum_output_bytes)
        {
            return Err(CoreBenchmarkVerificationCommandError::OutputExceeded);
        }
        Ok(CoreBenchmarkVerificationCommandOutput::new(
            status, stdout, stderr,
        ))
    }

    // Streams artifact bytes to one no-follow create-new file and observes growth while waiting.
    fn download(
        &self,
        executable: &Path,
        arguments: &[String],
        destination: &Path,
        timeout: Duration,
        maximum_bytes: u64,
    ) -> Result<CoreBenchmarkVerificationCommandOutput, CoreBenchmarkVerificationCommandError> {
        validate_command(executable, arguments, timeout, MAXIMUM_COMMAND_OUTPUT_BYTES)?;
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_ARTIFACT_BYTES {
            return Err(CoreBenchmarkVerificationCommandError::InvalidCommand);
        }
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(destination)
            .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
        let output = file
            .try_clone()
            .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
        let mut command = command(executable, arguments, false);
        command.stdout(Stdio::from(output)).stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(CoreBenchmarkVerificationCommandError::Unavailable)?;
        let stderr_reader = bounded_reader(stderr, MAXIMUM_COMMAND_OUTPUT_BYTES);
        let status = wait_for_child(&mut child, timeout, Some((destination, maximum_bytes)))?;
        let stderr = join_reader(stderr_reader)?;
        file.sync_all()
            .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() == 0
            || metadata.len() > maximum_bytes
        {
            return Err(CoreBenchmarkVerificationCommandError::OutputExceeded);
        }
        Ok(CoreBenchmarkVerificationCommandOutput::new(
            status,
            Vec::new(),
            stderr,
        ))
    }
}

// Resolves one exact proposal through authenticated GitHub CLI and trusted finalized artifacts.
pub struct SystemCoreBenchmarkVerificationOracle {
    github_cli: PathBuf,
    workspace_root: PathBuf,
    owner_user_id: u32,
    device_id: Sha256Digest,
    runner: Arc<dyn CoreBenchmarkVerificationCommandRunner>,
    registry_http: Arc<dyn RuntimeHttpClient>,
    sequence: AtomicU64,
}

impl SystemCoreBenchmarkVerificationOracle {
    // Creates one production oracle from explicit executable, private workspace, and device identity.
    pub fn new(
        github_cli: PathBuf,
        workspace_root: PathBuf,
        owner_user_id: u32,
        device_id: Sha256Digest,
        runner: Arc<dyn CoreBenchmarkVerificationCommandRunner>,
        registry_http: Arc<dyn RuntimeHttpClient>,
    ) -> Result<Self, CoreBenchmarkVerificationOracleError> {
        if !absolute_normal(&github_cli)
            || !absolute_normal(&workspace_root)
            || github_cli == workspace_root
            || owner_user_id == u32::MAX
        {
            return Err(CoreBenchmarkVerificationOracleError::InvalidConfiguration);
        }
        validate_private_directory(&workspace_root, owner_user_id)?;
        Ok(Self {
            github_cli,
            workspace_root,
            owner_user_id,
            device_id,
            runner,
            registry_http,
            sequence: AtomicU64::new(0),
        })
    }

    // Resolves one unambiguous changed candidate with no caller-selected override.
    pub fn resolve_verified(
        &self,
        pull_request_url: &str,
    ) -> Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationOracleError> {
        self.resolve_candidate(pull_request_url, None)
    }

    // Resolves one optional exact changed candidate and verifies its complete finalized bundle.
    pub fn resolve_candidate(
        &self,
        pull_request_url: &str,
        requested_candidate: Option<&RuntimeCandidateId>,
    ) -> Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationOracleError> {
        let pull_request_number = parse_pull_request_url(pull_request_url)?;
        self.require_github_cli_version()?;
        self.require_authenticated_session()?;
        let verifier = self.authenticated_user()?;
        let pull_request = self.pull_request(pull_request_url, pull_request_number)?;
        let candidate = select_candidate(&pull_request, requested_candidate)?;
        let workspace = self.create_workspace()?;
        let result =
            self.resolve_bundle(&pull_request, &candidate, verifier.numeric_id, &workspace);
        let cleanup = remove_workspace(&workspace, &self.workspace_root);
        match (result, cleanup) {
            (Ok(proposal), Ok(())) => Ok(proposal),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    // Requires GitHub CLI 2.97.0 or newer before any authenticated API operation.
    fn require_github_cli_version(&self) -> Result<(), CoreBenchmarkVerificationOracleError> {
        let output = self.run(&["--version"], false)?;
        let text = std::str::from_utf8(output.stdout())
            .map_err(|_| CoreBenchmarkVerificationOracleError::ResponseInvalid)?;
        let version = parse_github_cli_version(text)
            .ok_or(CoreBenchmarkVerificationOracleError::ResponseInvalid)?;
        if version < MINIMUM_GH_VERSION {
            return Err(CoreBenchmarkVerificationOracleError::ProposalInvalid);
        }
        Ok(())
    }

    // Requires an already authenticated GitHub session without starting interactive login.
    fn require_authenticated_session(&self) -> Result<(), CoreBenchmarkVerificationOracleError> {
        self.run(&["auth", "status", "--hostname", "github.com"], false)?;
        Ok(())
    }

    // Resolves the exact authenticated human GitHub account without retaining credentials.
    fn authenticated_user(&self) -> Result<GitHubIdentity, CoreBenchmarkVerificationOracleError> {
        let value = self.json(&["api", "user"])?;
        github_identity(&value, &BTreeSet::from(["User"]))
    }

    // Resolves and closes one canonical open main-based pull request and its author identity.
    fn pull_request(
        &self,
        url: &str,
        number: u64,
    ) -> Result<PullRequest, CoreBenchmarkVerificationOracleError> {
        let fields = "number,url,state,baseRefName,baseRefOid,headRefOid,author,files,labels";
        let value = self.json(&["pr", "view", url, "--repo", REPOSITORY, "--json", fields])?;
        let document = object(
            &value,
            CoreBenchmarkVerificationOracleError::ProposalInvalid,
        )?;
        if unsigned(document, "number")? != number
            || string(document, "url")? != format!("https://github.com/{REPOSITORY}/pull/{number}")
            || string(document, "state")? != "OPEN"
            || string(document, "baseRefName")? != "main"
        {
            return Err(CoreBenchmarkVerificationOracleError::ProposalInvalid);
        }
        let base_sha = git_revision(string(document, "baseRefOid")?)?;
        let head_sha = git_revision(string(document, "headRefOid")?)?;
        let author = object(
            document
                .get("author")
                .ok_or(CoreBenchmarkVerificationOracleError::ProposalInvalid)?,
            CoreBenchmarkVerificationOracleError::ProposalInvalid,
        )?;
        let author_login = string(author, "login")?;
        if !valid_github_login(author_login) {
            return Err(CoreBenchmarkVerificationOracleError::ProposalInvalid);
        }
        let author_value = self.json(&["api", &format!("users/{author_login}")])?;
        let author = github_identity(&author_value, &BTreeSet::from(["User", "Organization"]))?;
        let files = array(document, "files")?;
        let mut names = Vec::with_capacity(files.len());
        for value in files {
            let value = object(value, CoreBenchmarkVerificationOracleError::ProposalInvalid)?;
            let path = string(value, "path")?;
            if path.is_empty()
                || path.len() > 1_024
                || path.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(CoreBenchmarkVerificationOracleError::ProposalInvalid);
            }
            names.push(path.to_string());
        }
        let labels = array(document, "labels")?
            .iter()
            .map(|value| {
                object(value, CoreBenchmarkVerificationOracleError::ProposalInvalid)
                    .and_then(|value| string(value, "name"))
                    .map(str::to_string)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if !labels.contains(BENCHMARK_READY_LABEL) {
            return Err(CoreBenchmarkVerificationOracleError::ProposalInvalid);
        }
        Ok(PullRequest {
            number,
            base_sha,
            head_sha,
            author,
            files: names,
        })
    }

    // Downloads, attests, validates, and workflow-binds the sole exact finalized artifact.
    fn resolve_bundle(
        &self,
        pull_request: &PullRequest,
        candidate: &RuntimeCandidateId,
        verifier_numeric_id: u64,
        workspace: &Path,
    ) -> Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationOracleError> {
        let artifact_name = format!(
            "verification-bundle-pr-{}-{}",
            pull_request.number,
            pull_request.head_sha.as_str()
        );
        let response = self.json(&[
            "api",
            &format!("repos/{REPOSITORY}/actions/artifacts?name={artifact_name}&per_page=100"),
        ])?;
        let artifacts = array(
            object(
                &response,
                CoreBenchmarkVerificationOracleError::ArtifactInvalid,
            )?,
            "artifacts",
        )?;
        let exact = artifacts
            .iter()
            .filter_map(|value| value.as_object())
            .filter(|value| {
                value.get("name").and_then(Value::as_str) == Some(artifact_name.as_str())
                    && value.get("expired").and_then(Value::as_bool) == Some(false)
                    && value.get("id").and_then(Value::as_u64).is_some()
            })
            .collect::<Vec<_>>();
        let [artifact] = exact.as_slice() else {
            return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
        };
        let artifact_id = unsigned(artifact, "id")?;
        let workflow = object(
            artifact
                .get("workflow_run")
                .ok_or(CoreBenchmarkVerificationOracleError::ArtifactInvalid)?,
            CoreBenchmarkVerificationOracleError::ArtifactInvalid,
        )?;
        let finalizer_run_id = unsigned(workflow, "id")?;
        let finalizer = self.workflow_run(finalizer_run_id)?;
        require_finalizer(&finalizer)?;
        let archive = workspace.join("artifact.zip");
        self.download(
            &[
                "api",
                &format!("repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"),
            ],
            &archive,
        )?;
        let bundle_root = workspace.join("bundle");
        extract_artifact(&archive, &bundle_root, self.owner_user_id)?;
        fs::remove_file(&archive)
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
        let paths = regular_bundle_paths(&bundle_root)?;
        for path in &paths {
            self.run_owned(
                vec![
                    "attestation".to_string(),
                    "verify".to_string(),
                    path.to_string_lossy().into_owned(),
                    "--repo".to_string(),
                    REPOSITORY.to_string(),
                    "--cert-identity".to_string(),
                    FINALIZER_CERTIFICATE_IDENTITY.to_string(),
                ],
                true,
                ATTESTATION_TIMEOUT,
            )?;
        }
        let bundle = validate_bundle(
            &bundle_root,
            pull_request,
            candidate,
            self.registry_http.as_ref(),
        )?;
        validate_finalizer_binding(&bundle.document, finalizer_run_id, &finalizer)?;
        let build_identity = child_object(&bundle.document, "build_workflow")?;
        let build_run_id = unsigned(build_identity, "run_id")?;
        let build = self.workflow_run(build_run_id)?;
        validate_build_binding(build_identity, &build, &pull_request.base_sha)?;
        let trusted_candidate = self.retain_verified_bundle(&bundle_root, &bundle)?;
        Ok(CoreBenchmarkVerificationProposal::new(
            pull_request.number,
            pull_request.head_sha.clone(),
            candidate.clone(),
            verifier_numeric_id,
            self.device_id.clone(),
            None,
            bundle.bundle_sha256,
            true,
            true,
            true,
        )
        .with_trusted_candidate(trusted_candidate))
    }

    // Atomically retains one verified flat bundle by digest and returns its typed staging closure.
    fn retain_verified_bundle(
        &self,
        source: &Path,
        bundle: &VerifiedBundle,
    ) -> Result<CoreBenchmarkVerificationCandidate, CoreBenchmarkVerificationOracleError> {
        let destination = self
            .workspace_root
            .join(format!("bundle-{}", bundle.bundle_sha256.as_str()));
        match fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || metadata.uid() != self.owner_user_id
                    || metadata.mode() & 0o777 != 0o700
                    || !same_flat_bundle(source, &destination)?
                {
                    return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
                }
                remove_workspace(
                    source,
                    source
                        .parent()
                        .ok_or(CoreBenchmarkVerificationOracleError::ArtifactInvalid)?,
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::rename(source, &destination)
                    .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
            }
            Err(_) => return Err(CoreBenchmarkVerificationOracleError::FilesystemUnavailable),
        }
        let engine = match bundle.engine_mode.as_str() {
            "reuse-engine" => CoreBenchmarkVerificationEngineArtifact::Reuse,
            "build-native-engine" => CoreBenchmarkVerificationEngineArtifact::BuiltNative,
            "build-engine" => CoreBenchmarkVerificationEngineArtifact::BuiltOci {
                archive_file: destination.join("engine.oci.tar"),
                config_digest: bundle
                    .engine_config_digest
                    .clone()
                    .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?,
                local_tag: bundle
                    .engine_local_tag
                    .clone()
                    .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?,
            },
            _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
        };
        CoreBenchmarkVerificationCandidate::new(
            bundle.runtime_candidate.clone(),
            destination.join("runtime.letsinfer"),
            engine,
            bundle.bundle_sha256.clone(),
            bundle.execution_sha256.clone(),
            bundle.runtime_author_numeric_ids.clone(),
            bundle.proposal_base.clone(),
        )
    }

    // Returns one closed Actions workflow-run document.
    fn workflow_run(&self, run_id: u64) -> Result<Value, CoreBenchmarkVerificationOracleError> {
        if run_id == 0 {
            return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
        }
        self.json(&["api", &format!("repos/{REPOSITORY}/actions/runs/{run_id}")])
    }

    // Creates one collision-resistant owner-private workspace beneath the configured root.
    fn create_workspace(&self) -> Result<PathBuf, CoreBenchmarkVerificationOracleError> {
        validate_private_directory(&self.workspace_root, self.owner_user_id)?;
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let path = self
            .workspace_root
            .join(format!(".verification-{}-{sequence}", std::process::id()));
        fs::create_dir(&path)
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
        validate_private_directory(&path, self.owner_user_id)?;
        Ok(path)
    }

    // Runs one borrowed static argv with ordinary metadata bounds.
    fn run(
        &self,
        arguments: &[&str],
        use_attestation_token: bool,
    ) -> Result<CoreBenchmarkVerificationCommandOutput, CoreBenchmarkVerificationOracleError> {
        self.run_owned(
            arguments.iter().map(|value| (*value).to_string()).collect(),
            use_attestation_token,
            COMMAND_TIMEOUT,
        )
    }

    // Runs one owned argv and accepts only a successful bounded process result.
    fn run_owned(
        &self,
        arguments: Vec<String>,
        use_attestation_token: bool,
        timeout: Duration,
    ) -> Result<CoreBenchmarkVerificationCommandOutput, CoreBenchmarkVerificationOracleError> {
        let output = self
            .runner
            .run(
                &self.github_cli,
                &arguments,
                timeout,
                MAXIMUM_COMMAND_OUTPUT_BYTES,
                use_attestation_token,
            )
            .map_err(map_command_error)?;
        if output.status() != 0 {
            return Err(CoreBenchmarkVerificationOracleError::CommandFailed);
        }
        Ok(output)
    }

    // Parses one successful command stdout as a JSON object.
    fn json(&self, arguments: &[&str]) -> Result<Value, CoreBenchmarkVerificationOracleError> {
        let output = self.run(arguments, false)?;
        let value: Value = serde_json::from_slice(output.stdout())
            .map_err(|_| CoreBenchmarkVerificationOracleError::ResponseInvalid)?;
        if !value.is_object() {
            return Err(CoreBenchmarkVerificationOracleError::ResponseInvalid);
        }
        Ok(value)
    }

    // Streams one successful GitHub API response into an exact private file.
    fn download(
        &self,
        arguments: &[&str],
        destination: &Path,
    ) -> Result<(), CoreBenchmarkVerificationOracleError> {
        let arguments = arguments
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        let output = self
            .runner
            .download(
                &self.github_cli,
                &arguments,
                destination,
                DOWNLOAD_TIMEOUT,
                MAXIMUM_ARTIFACT_BYTES,
            )
            .map_err(map_command_error)?;
        if output.status() != 0 {
            return Err(CoreBenchmarkVerificationOracleError::CommandFailed);
        }
        Ok(())
    }
}

impl CoreBenchmarkVerificationOracle for SystemCoreBenchmarkVerificationOracle {
    // Maps typed production failures into the credential-free preparation boundary.
    fn resolve(
        &self,
        pull_request_url: &str,
    ) -> Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationPreparationError> {
        self.resolve_verified(pull_request_url)
            .map_err(map_oracle_error)
    }

    // Preserves the explicit candidate selector through the same complete trust chain.
    fn resolve_candidate(
        &self,
        pull_request_url: &str,
        requested_candidate: Option<&RuntimeCandidateId>,
    ) -> Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationPreparationError> {
        SystemCoreBenchmarkVerificationOracle::resolve_candidate(
            self,
            pull_request_url,
            requested_candidate,
        )
        .map_err(map_oracle_error)
    }
}

// Maps typed oracle failures into the credential-free preparation categories.
fn map_oracle_error(
    error: CoreBenchmarkVerificationOracleError,
) -> CoreBenchmarkVerificationPreparationError {
    match error {
        CoreBenchmarkVerificationOracleError::InvalidConfiguration => {
            CoreBenchmarkVerificationPreparationError::InvalidInput
        }
        CoreBenchmarkVerificationOracleError::CommandUnavailable
        | CoreBenchmarkVerificationOracleError::CommandFailed
        | CoreBenchmarkVerificationOracleError::FilesystemUnavailable => {
            CoreBenchmarkVerificationPreparationError::Unavailable
        }
        CoreBenchmarkVerificationOracleError::ResponseInvalid
        | CoreBenchmarkVerificationOracleError::ProposalInvalid
        | CoreBenchmarkVerificationOracleError::ArtifactInvalid
        | CoreBenchmarkVerificationOracleError::BundleInvalid => {
            CoreBenchmarkVerificationPreparationError::InvalidAuthority
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GitHubIdentity {
    login: String,
    numeric_id: u64,
    account_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PullRequest {
    number: u64,
    base_sha: BenchmarkGitRevision,
    head_sha: BenchmarkGitRevision,
    author: GitHubIdentity,
    files: Vec<String>,
}

struct VerifiedBundle {
    document: Map<String, Value>,
    bundle_sha256: Sha256Digest,
    runtime_candidate: RuntimeCandidate,
    execution_sha256: Sha256Digest,
    runtime_author_numeric_ids: Vec<u64>,
    proposal_base: BenchmarkGitRevision,
    engine_mode: String,
    engine_config_digest: Option<Sha256Digest>,
    engine_local_tag: Option<String>,
}

// Builds one shell-free process while preserving GitHub CLI's existing credential store.
fn command(executable: &Path, arguments: &[String], use_attestation_token: bool) -> Command {
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .current_dir("/")
        .stdin(Stdio::null());
    if use_attestation_token {
        if let Some(token) = std::env::var_os("LETSINFER_ATTESTATION_TOKEN") {
            command.env("GH_TOKEN", token);
        }
    }
    command
}

// Validates executable, argv, deadline, and output bounds before process creation.
fn validate_command(
    executable: &Path,
    arguments: &[String],
    timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<(), CoreBenchmarkVerificationCommandError> {
    if !absolute_normal(executable)
        || arguments.is_empty()
        || arguments.len() > MAXIMUM_COMMAND_ARGUMENTS
        || arguments.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > MAXIMUM_COMMAND_ARGUMENT_BYTES
                || argument.bytes().any(|byte| byte == 0)
        })
        || timeout.is_zero()
        || timeout > DOWNLOAD_TIMEOUT
        || maximum_output_bytes == 0
        || maximum_output_bytes > MAXIMUM_COMMAND_OUTPUT_BYTES
    {
        return Err(CoreBenchmarkVerificationCommandError::InvalidCommand);
    }
    let metadata =
        fs::metadata(executable).map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(CoreBenchmarkVerificationCommandError::InvalidCommand);
    }
    Ok(())
}

// Reads one process stream concurrently and retains at most one byte beyond its bound.
fn bounded_reader<R: Read + Send + 'static>(
    stream: R,
    maximum_bytes: usize,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stream
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

// Joins one bounded stream reader and classifies I/O, panic, and size failures.
fn join_reader(
    reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
) -> Result<Vec<u8>, CoreBenchmarkVerificationCommandError> {
    let bytes = reader
        .join()
        .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?
        .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
    if bytes.len() > MAXIMUM_COMMAND_OUTPUT_BYTES {
        return Err(CoreBenchmarkVerificationCommandError::OutputExceeded);
    }
    Ok(bytes)
}

// Waits for one child while enforcing its deadline and optional streamed-file byte ceiling.
fn wait_for_child(
    child: &mut std::process::Child,
    timeout: Duration,
    output: Option<(&Path, u64)>,
) -> Result<i32, CoreBenchmarkVerificationCommandError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(CoreBenchmarkVerificationCommandError::InvalidCommand)?;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?
        {
            return Ok(status.code().unwrap_or(-1));
        }
        if output.is_some_and(|(path, maximum)| {
            fs::metadata(path)
                .ok()
                .is_some_and(|metadata| metadata.len() > maximum)
        }) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CoreBenchmarkVerificationCommandError::OutputExceeded);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CoreBenchmarkVerificationCommandError::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// Maps the process boundary into the oracle's stable provider categories.
fn map_command_error(
    error: CoreBenchmarkVerificationCommandError,
) -> CoreBenchmarkVerificationOracleError {
    match error {
        CoreBenchmarkVerificationCommandError::InvalidCommand => {
            CoreBenchmarkVerificationOracleError::InvalidConfiguration
        }
        CoreBenchmarkVerificationCommandError::Unavailable
        | CoreBenchmarkVerificationCommandError::TimedOut
        | CoreBenchmarkVerificationCommandError::OutputExceeded => {
            CoreBenchmarkVerificationOracleError::CommandUnavailable
        }
    }
}

// Parses the first exact `gh version MAJOR.MINOR.PATCH` line from bounded output.
fn parse_github_cli_version(value: &str) -> Option<(u64, u64, u64)> {
    value.lines().find_map(|line| {
        let value = line
            .strip_prefix("gh version ")?
            .split_whitespace()
            .next()?;
        let mut parts = value.split('.');
        let version = (
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        );
        parts.next().is_none().then_some(version)
    })
}

// Parses only the canonical public runtimes pull-request URL with one positive number.
fn parse_pull_request_url(value: &str) -> Result<u64, CoreBenchmarkVerificationOracleError> {
    let prefix = "https://github.com/letsinferlabs/runtimes/pull/";
    value
        .strip_prefix(prefix)
        .filter(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 20
                && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
        .and_then(|suffix| suffix.parse::<u64>().ok())
        .filter(|number| *number > 0)
        .ok_or(CoreBenchmarkVerificationOracleError::ProposalInvalid)
}

// Parses one canonical forty-character lowercase Git revision.
fn git_revision(value: &str) -> Result<BenchmarkGitRevision, CoreBenchmarkVerificationOracleError> {
    BenchmarkGitRevision::parse(value)
        .map_err(|_| CoreBenchmarkVerificationOracleError::ProposalInvalid)
}

// Parses one exact GitHub account document with an allowlisted account kind.
fn github_identity(
    value: &Value,
    allowed_types: &BTreeSet<&str>,
) -> Result<GitHubIdentity, CoreBenchmarkVerificationOracleError> {
    let object = object(value, CoreBenchmarkVerificationOracleError::ProposalInvalid)?;
    let login = string(object, "login")?;
    let numeric_id = unsigned(object, "id")?;
    let account_type = string(object, "type")?;
    if !valid_github_login(login) || numeric_id == 0 || !allowed_types.contains(account_type) {
        return Err(CoreBenchmarkVerificationOracleError::ProposalInvalid);
    }
    Ok(GitHubIdentity {
        login: login.to_string(),
        numeric_id,
        account_type: account_type.to_string(),
    })
}

// Accepts GitHub's bounded account-login alphabet without normalizing its case.
fn valid_github_login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 39
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_alphanumeric() || (index > 0 && byte == b'-'))
}

// Selects one exact changed candidate and rejects invalid candidate-like top-level paths.
fn select_candidate(
    pull_request: &PullRequest,
    requested: Option<&RuntimeCandidateId>,
) -> Result<RuntimeCandidateId, CoreBenchmarkVerificationOracleError> {
    let mut candidates = BTreeSet::new();
    for path in &pull_request.files {
        let Some((top, _)) = path.split_once('/') else {
            continue;
        };
        if top.starts_with('.') || matches!(top, "tools" | "tests") {
            continue;
        }
        let candidate = RuntimeCandidateId::parse(top)
            .map_err(|_| CoreBenchmarkVerificationOracleError::ProposalInvalid)?;
        if candidate.as_str().split("--").count() != 4 {
            return Err(CoreBenchmarkVerificationOracleError::ProposalInvalid);
        }
        candidates.insert(candidate);
    }
    if let Some(requested) = requested {
        if candidates.contains(requested) {
            return Ok(requested.clone());
        }
        return Err(CoreBenchmarkVerificationOracleError::ProposalInvalid);
    }
    if candidates.len() != 1 {
        return Err(CoreBenchmarkVerificationOracleError::ProposalInvalid);
    }
    candidates
        .into_iter()
        .next()
        .ok_or(CoreBenchmarkVerificationOracleError::ProposalInvalid)
}

// Requires the trusted main-branch workflow-run finalizer to have completed successfully.
fn require_finalizer(value: &Value) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let value = object(value, CoreBenchmarkVerificationOracleError::ArtifactInvalid)?;
    if string(value, "event")? != "workflow_run"
        || string(value, "path")? != FINALIZER_PATH
        || string(value, "conclusion")? != "success"
        || string(value, "head_branch")? != "main"
        || BenchmarkGitRevision::parse(string(value, "head_sha")?).is_err()
    {
        return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
    }
    Ok(())
}

// Extracts one flat artifact ZIP with no links, traversal, duplicates, or unbounded expansion.
fn extract_artifact(
    archive: &Path,
    destination: &Path,
    owner_user_id: u32,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    fs::create_dir(destination)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    validate_private_directory(destination, owner_user_id)?;
    let file = open_regular(archive, MAXIMUM_ARTIFACT_BYTES)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|_| CoreBenchmarkVerificationOracleError::ArtifactInvalid)?;
    if archive.is_empty() || archive.len() > MAXIMUM_ARTIFACT_FILES {
        return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
    }
    let mut seen = HashSet::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| CoreBenchmarkVerificationOracleError::ArtifactInvalid)?;
        let enclosed = entry
            .enclosed_name()
            .ok_or(CoreBenchmarkVerificationOracleError::ArtifactInvalid)?;
        if enclosed.components().count() != 1
            || entry.is_dir()
            || !entry.is_file()
            || entry.is_symlink()
            || entry.encrypted()
            || entry.compressed_size() > MAXIMUM_ARTIFACT_BYTES
            || !seen.insert(enclosed.clone())
        {
            return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
        }
        if entry.unix_mode().is_some_and(|mode| {
            let file_type = mode & libc::S_IFMT as u32;
            file_type != 0 && file_type != libc::S_IFREG as u32
        }) {
            return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
        }
        total = total
            .checked_add(entry.size())
            .filter(|bytes| *bytes <= MAXIMUM_ARTIFACT_BYTES)
            .ok_or(CoreBenchmarkVerificationOracleError::ArtifactInvalid)?;
        let target = destination.join(&enclosed);
        let mut output = create_private_file(&target)?;
        let copied = std::io::copy(&mut entry, &mut output)
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
        if copied != entry.size() {
            return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
        }
        output
            .sync_all()
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    }
    Ok(())
}

// Returns a stable sorted regular-file surface for exact attestation verification.
fn regular_bundle_paths(root: &Path) -> Result<Vec<PathBuf>, CoreBenchmarkVerificationOracleError> {
    let mut paths = root
        .read_dir()
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    if paths.is_empty() {
        return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
    }
    for path in &paths {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
        }
    }
    Ok(paths)
}

// Requires two owner-private flat bundle roots to contain the same exact names and bytes.
fn same_flat_bundle(
    left: &Path,
    right: &Path,
) -> Result<bool, CoreBenchmarkVerificationOracleError> {
    let project = |root: &Path| {
        regular_bundle_paths(root).and_then(|paths| {
            paths
                .into_iter()
                .map(|path| {
                    let name = path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .ok_or(CoreBenchmarkVerificationOracleError::ArtifactInvalid)?
                        .to_string();
                    Ok((name, sha256_file(&path, MAXIMUM_ARTIFACT_BYTES)?))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()
        })
    };
    Ok(project(left)? == project(right)?)
}

// Verifies the complete bundle inventory, hashes, runtime pack, Engine, and provenance closure.
fn validate_bundle(
    root: &Path,
    pull_request: &PullRequest,
    candidate: &RuntimeCandidateId,
    registry_http: &dyn RuntimeHttpClient,
) -> Result<VerifiedBundle, CoreBenchmarkVerificationOracleError> {
    let document_bytes = read_regular(&root.join("bundle.json"), MAXIMUM_DOCUMENT_BYTES)?;
    let document_value = parse_json_object(&document_bytes)?;
    let document = document_value
        .as_object()
        .cloned()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let proposal_base = string(&document, "proposal_base_sha")?;
    let build_workflow = child_object(&document, "build_workflow")?;
    let finalizer_workflow = child_object(&document, "finalizer_workflow")?;
    let expected_artifact = format!(
        "verification-bundle-pr-{}-{}",
        pull_request.number,
        pull_request.head_sha.as_str()
    );
    if unsigned(&document, "schema_version")? != 1
        || string(&document, "repository")? != REPOSITORY
        || unsigned(&document, "pull_request")? != pull_request.number
        || string(&document, "proposal_head_sha")? != pull_request.head_sha.as_str()
        || proposal_base != pull_request.base_sha.as_str()
        || string(&document, "candidate")? != candidate.as_str()
        || string(&document, "artifact_name")? != expected_artifact
        || string(build_workflow, "path")? != BUILD_PATH
        || unsigned(build_workflow, "run_id")? == 0
        || string(build_workflow, "workflow_sha")? != proposal_base
        || string(finalizer_workflow, "path")? != FINALIZER_PATH
        || unsigned(finalizer_workflow, "run_id")? == 0
        || BenchmarkGitRevision::parse(string(finalizer_workflow, "workflow_sha")?).is_err()
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let runtime_author_numeric_ids = validate_runtime_authors(&document)?;
    let mode = string(&document, "mode")?.to_string();
    let mut expected = BTreeSet::from([
        "runtime.letsinfer",
        "runtime-plan.json",
        "candidate-audit.json",
        "runtime.spdx.json",
        "provenance.json",
    ]);
    match mode.as_str() {
        "reuse-engine" | "build-native-engine" => {}
        "build-engine" => {
            expected.insert("engine.oci.tar");
            expected.insert("engine.spdx.json");
        }
        _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
    }
    let actual = regular_bundle_paths(root)?
        .into_iter()
        .map(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .map(str::to_string)
                .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut complete = expected
        .iter()
        .map(|value| (*value).to_string())
        .collect::<BTreeSet<_>>();
    complete.insert("bundle.json".to_string());
    complete.insert("checksums.json".to_string());
    if actual != complete {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    validate_checksums(root, &document, &expected)?;
    let subject = child_object(&document, "subject")?;
    validate_subject_identity(subject, pull_request, candidate, &mode)?;
    let runtime_pack = root.join("runtime.letsinfer");
    let pack_metadata = fs::symlink_metadata(&runtime_pack)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    if !pack_metadata.is_file()
        || pack_metadata.len() == 0
        || pack_metadata.len() > MAXIMUM_RUNTIME_PACK_BYTES
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let pack_sha256 = sha256_file(&runtime_pack, MAXIMUM_RUNTIME_PACK_BYTES)?;
    let plan = parse_file_object(&root.join("runtime-plan.json"))?;
    let runtime_document = document
        .get("runtime")
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if runtime_document != &Value::Object(plan.clone())
        || string(&plan, "layer_digest")? != format!("sha256:{pack_sha256}")
        || unsigned(&plan, "layer_bytes")? != pack_metadata.len()
        || string(subject, "runtime_pack_sha256")? != pack_sha256
        || string(subject, "runtime_oci_manifest_digest")? != string(&plan, "manifest_digest")?
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let (runtime, runtime_candidate) =
        validate_runtime_pack(root, &runtime_pack, candidate, &pack_sha256)?;
    let calculated = execution_subject(&runtime, &pack_sha256, pack_metadata.len())?;
    for (key, value) in &calculated {
        if key != "execution_sha256" && subject.get(key) != Some(value) {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
    }
    let engine = child_object(&document, "engine")?;
    validate_engine(
        root,
        &mode,
        &runtime,
        engine,
        candidate,
        pull_request,
        registry_http,
    )?;
    let provenance = parse_file_object(&root.join("provenance.json"))?;
    if provenance.get("subject") != Some(&Value::Object(subject.clone()))
        || provenance.get("engine") != Some(&Value::Object(engine.clone()))
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let execution_sha256 = Sha256Digest::parse(string(subject, "execution_sha256")?)
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let engine_config_digest = engine
        .get("config_digest")
        .and_then(Value::as_str)
        .map(prefixed_digest)
        .transpose()?;
    let engine_local_tag = (mode == "build-engine").then(|| {
        format!(
            "letsinfer-verifier/{}:{}",
            candidate.as_str(),
            &pull_request.head_sha.as_str()[..12]
        )
    });
    Ok(VerifiedBundle {
        document,
        bundle_sha256: Sha256Digest::parse(&sha256_bytes(&document_bytes))
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
        runtime_candidate,
        execution_sha256,
        runtime_author_numeric_ids,
        proposal_base: pull_request.base_sha.clone(),
        engine_mode: mode,
        engine_config_digest,
        engine_local_tag,
    })
}

// Requires one non-empty unique set of bounded human or organization runtime authors.
fn validate_runtime_authors(
    document: &Map<String, Value>,
) -> Result<Vec<u64>, CoreBenchmarkVerificationOracleError> {
    let authors = array(document, "runtime_authors")?;
    if authors.is_empty() || authors.len() > 64 {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let mut ids = HashSet::new();
    for author in authors {
        let author = object(author, CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        exact_fields(author, &["github_login", "github_id", "github_type"])?;
        let login = string(author, "github_login")?;
        let id = unsigned(author, "github_id")?;
        let kind = string(author, "github_type")?;
        if !valid_github_login(login)
            || id == 0
            || !matches!(kind, "User" | "Organization")
            || !ids.insert(id)
        {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
    }
    let mut ids = ids.into_iter().collect::<Vec<_>>();
    ids.sort_unstable();
    Ok(ids)
}

// Verifies the attested checksum manifest and exact byte identity of every payload file.
fn validate_checksums(
    root: &Path,
    document: &Map<String, Value>,
    expected: &BTreeSet<&str>,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let path = root.join("checksums.json");
    let bytes = read_regular(&path, MAXIMUM_DOCUMENT_BYTES)?;
    if sha256_bytes(&bytes) != string(document, "checksums_sha256")? {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let checksums = parse_json_object(&bytes)?;
    let checksums = checksums
        .as_object()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if checksums
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != *expected
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    for (name, record) in checksums {
        let record = object(record, CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        exact_fields(record, &["sha256", "bytes"])?;
        let payload = root.join(name);
        let metadata = fs::symlink_metadata(&payload)
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != unsigned(record, "bytes")?
            || sha256_file(&payload, MAXIMUM_ARTIFACT_BYTES)? != string(record, "sha256")?
        {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
    }
    Ok(())
}

// Requires one self-hashed execution subject bound to the current proposal and Engine mode.
fn validate_subject_identity(
    subject: &Map<String, Value>,
    pull_request: &PullRequest,
    candidate: &RuntimeCandidateId,
    mode: &str,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let mut material = subject.clone();
    let execution = material
        .remove("execution_sha256")
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if execution != sha256_bytes(&canonical_json(&Value::Object(material))?)
        || string(subject, "repository")? != REPOSITORY
        || unsigned(subject, "pull_request")? != pull_request.number
        || string(subject, "proposal_head_sha")? != pull_request.head_sha.as_str()
        || string(subject, "proposal_base_sha")? != pull_request.base_sha.as_str()
        || string(subject, "candidate_id")? != candidate.as_str()
        || string(subject, "engine_mode")? != mode
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(())
}

// Extracts and validates one complete schema-6 runtime pack through RuntimeManager's native parser.
fn validate_runtime_pack(
    bundle_root: &Path,
    archive: &Path,
    candidate: &RuntimeCandidateId,
    pack_sha256: &str,
) -> Result<(Value, RuntimeCandidate), CoreBenchmarkVerificationOracleError> {
    let destination = bundle_root.join(".runtime-pack");
    fs::create_dir(&destination)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    let io = SystemRuntimePackArtifactIo;
    let result = io
        .extract_archive(archive, &destination)
        .and_then(|_| io.verified_documents(&destination))
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)
        .and_then(|documents| {
            let runtime = parse_json_object(documents.runtime())?;
            let root = runtime
                .as_object()
                .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
            if string(root, "id")? != candidate.as_str()
                || unsigned(root, "schema_version")? != 6
                || root
                    .get("serving")
                    .and_then(Value::as_object)
                    .is_none_or(|serving| {
                        serving.contains_key("qualified") || serving.contains_key("blocked_by")
                    })
            {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            }
            let candidate = validate_complete_runtime_document(
                documents.descriptor_digest().clone(),
                documents.runtime(),
                &runtime,
                pack_sha256,
            )?;
            Ok((runtime, candidate))
        });
    let cleanup = remove_workspace(&destination, bundle_root);
    match (result, cleanup) {
        (Ok(runtime), Ok(())) => Ok(runtime),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

// Reuses the production typed execution parser so the verifier cannot accept a partial runtime.
fn validate_complete_runtime_document(
    descriptor_digest: Sha256Digest,
    runtime_bytes: &[u8],
    runtime: &Value,
    pack_sha256: &str,
) -> Result<RuntimeCandidate, CoreBenchmarkVerificationOracleError> {
    let root = object(runtime, CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let distribution = parse_engine_distribution(child_object(root, "engine")?, root)?;
    let artifacts = parse_model_artifacts(array(root, "artifacts")?)?;
    let orchestration = root
        .get("orchestration")
        .cloned()
        .unwrap_or_else(|| json!({"contract": "letsinfer-single-task-v1"}));
    let runtime_identity = RuntimeIdentity::new(
        RuntimeCandidateId::parse(string(root, "id")?)
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
        RuntimeVersion::parse(string(root, "version")?)
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
        TargetId::parse(string(child_object(root, "target")?, "id")?)
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/verifier-runtime@sha256:{pack_sha256}"
        ))
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
        distribution,
        descriptor_digest,
        digest(runtime_bytes)?,
        digest(&canonical_json(&orchestration)?)?,
    )
    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let logical_model = LogicalModelName::parse(string(root, "logical_model")?)
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let target = parse_runtime_target(child_object(root, "target")?)?;
    let installation = RuntimeInstallation::new(
        RuntimeInstallationId::parse(&"0".repeat(32))
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
        NodeId::parse(&"0".repeat(32))
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
        logical_model.clone(),
        runtime_identity.clone(),
        artifacts.clone(),
        EvidenceLabel::Unknown,
        RuntimeInstallationState::Available,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(0), UnixMilliseconds::new(0))
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
    )
    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let provider = FilesystemRuntimeExecutionManifestProvider::new(
        PathBuf::from("/li_verifier/runtime"),
        PathBuf::from("/li_verifier/cache"),
        Arc::new(SingleRuntimeInstallationProvider(installation.clone())),
        Arc::new(FixedRuntimeManifestIo(runtime_bytes.to_vec())),
    )
    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let manifest = provider
        .manifest(installation.installation_id())
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if manifest.benchmark().is_none() {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    RuntimeCandidate::new(
        logical_model,
        runtime_identity,
        artifacts,
        target,
        EvidenceLabel::Unqualified,
        2,
        false,
        false,
    )
    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)
}

// Parses the exact static runtime target used by RuntimeManager compatibility judgment.
fn parse_runtime_target(
    target: &Map<String, Value>,
) -> Result<RuntimeTarget, CoreBenchmarkVerificationOracleError> {
    let platform = string(target, "platform")?;
    let (operating_system, architecture) = platform
        .split_once('/')
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let operating_system = match operating_system {
        "linux" => OperatingSystem::Linux,
        "macos" => OperatingSystem::Macos,
        _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
    };
    let architecture = match architecture {
        "arm64" => CpuArchitecture::Arm64,
        "x86_64" => CpuArchitecture::X86_64,
        _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
    };
    let accelerator = child_object(target, "accelerator")?;
    let vendor = match string(accelerator, "vendor")? {
        "nvidia" => RuntimeAcceleratorVendor::Nvidia,
        "apple" => RuntimeAcceleratorVendor::Apple,
        value => RuntimeAcceleratorVendor::Other(
            TechnicalName::parse(value)
                .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
        ),
    };
    let count = u16::try_from(unsigned(accelerator, "count")?)
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let memory = child_object(target, "memory")?;
    let topology = match string(memory, "topology")? {
        "unified" => MemoryTopology::Unified,
        "discrete" => MemoryTopology::Discrete,
        _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
    };
    let gibibytes = |value: u64| {
        value
            .checked_mul(1 << 30)
            .and_then(|bytes| ByteCount::new(bytes).ok())
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
    };
    let minimum_framebuffer = accelerator
        .get("minimum_memory_gib")
        .and_then(Value::as_u64)
        .map(gibibytes)
        .transpose()?;
    RuntimeTarget::new(
        operating_system,
        architecture,
        vendor,
        TechnicalName::parse(string(accelerator, "architecture")?)
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
        count,
        topology,
        minimum_framebuffer,
        gibibytes(unsigned(memory, "minimum_total_gib")?)?,
    )
    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)
}

struct SingleRuntimeInstallationProvider(RuntimeInstallation);

impl RuntimeInstallationProvider for SingleRuntimeInstallationProvider {
    // Returns only the one exact verifier reconstruction identity.
    fn installation(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<RuntimeInstallation>, li_runtime_manager::RuntimeError> {
        Ok((self.0.installation_id() == installation_id).then(|| self.0.clone()))
    }
}

struct FixedRuntimeManifestIo(Vec<u8>);

impl RuntimeExecutionManifestIo for FixedRuntimeManifestIo {
    // Returns the already bounded verified runtime bytes without consulting caller paths.
    fn read(
        &self,
        _path: &Path,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, li_runtime_manager::RuntimeError> {
        if self.0.is_empty() || self.0.len() > maximum_bytes {
            return Err(li_runtime_manager::RuntimeError::ExecutionManifestUnavailable);
        }
        Ok(self.0.clone())
    }
}

// Parses one exact immutable Engine distribution into the shared typed identity.
fn parse_engine_distribution(
    engine: &Map<String, Value>,
    runtime: &Map<String, Value>,
) -> Result<EngineDistribution, CoreBenchmarkVerificationOracleError> {
    let distribution = child_object(engine, "distribution")?;
    let kind = string(distribution, "kind")?;
    if kind == "oci-container" {
        let allowed = BTreeSet::from(["kind", "reference", "immutable_id"]);
        let mut actual = distribution
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        actual.remove("base");
        actual.remove("payload_id");
        if actual != allowed {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        let reference = RuntimeSource::parse(string(distribution, "reference")?)
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        let immutable = prefixed_digest(string(distribution, "immutable_id")?)?;
        let base = distribution
            .get("base")
            .map(|value| {
                value
                    .as_str()
                    .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
                    .and_then(|value| {
                        RuntimeSource::parse(value)
                            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)
                    })
            })
            .transpose()?;
        let payload = distribution
            .get("payload_id")
            .map(|value| {
                value
                    .as_str()
                    .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
                    .and_then(prefixed_digest)
            })
            .transpose()?;
        return Ok(EngineDistribution::oci(reference, immutable, base, payload));
    }
    let target_platform = string(child_object(runtime, "target")?, "platform")?;
    let platform_value = string(distribution, "platform")?;
    if platform_value != target_platform {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let (operating_system, architecture) = platform_value
        .split_once('/')
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let operating_system = match operating_system {
        "linux" => OperatingSystem::Linux,
        "macos" => OperatingSystem::Macos,
        _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
    };
    let architecture = match architecture {
        "arm64" => CpuArchitecture::Arm64,
        "x86_64" => CpuArchitecture::X86_64,
        _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
    };
    let platform = PlatformIdentity::new(operating_system, architecture);
    let native_kind = match kind {
        "native-archive" => NativeEngineKind::NativeArchive,
        "python-standalone" => NativeEngineKind::PythonStandalone,
        "embedded-application" => NativeEngineKind::EmbeddedApplication,
        _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
    };
    validate_native_distribution(distribution, native_kind)?;
    Ok(EngineDistribution::native(
        native_kind,
        platform,
        prefixed_digest(string(distribution, "payload_id")?)?,
        ArtifactRevision::parse(string(distribution, "source_revision")?)
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
    ))
}

// Requires the complete closed native distribution shape for its declared delivery kind.
fn validate_native_distribution(
    value: &Map<String, Value>,
    kind: NativeEngineKind,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let mut expected = BTreeSet::from([
        "kind",
        "platform",
        "payload_id",
        "source_revision",
        "entrypoint",
        "port_count",
    ]);
    match kind {
        NativeEngineKind::NativeArchive => {
            expected.extend(["archive", "upstream_executable"]);
        }
        NativeEngineKind::PythonStandalone => {
            expected.extend(["python", "requirements_lock"]);
        }
        NativeEngineKind::EmbeddedApplication => {
            expected.extend([
                "bundle_id",
                "signing_policy",
                "minimum_version",
                "embedded_engine",
            ]);
        }
    }
    if value.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected
        || prefixed_digest(string(value, "payload_id")?).is_err()
        || ArtifactRevision::parse(string(value, "source_revision")?).is_err()
        || !safe_relative_text(string(value, "entrypoint")?)
        || !(1..=4).contains(&unsigned(value, "port_count")?)
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(())
}

// Parses every exact immutable model artifact for the production runtime parser.
fn parse_model_artifacts(
    values: &[Value],
) -> Result<Vec<ModelArtifact>, CoreBenchmarkVerificationOracleError> {
    if values.is_empty() || values.len() > 64 {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    values
        .iter()
        .map(|value| {
            let value = object(value, CoreBenchmarkVerificationOracleError::BundleInvalid)?;
            let format = match string(value, "format")? {
                "huggingface-snapshot" => ModelArtifactFormat::HuggingFaceSnapshot,
                "gguf-file" => ModelArtifactFormat::GgufFile(
                    GgufFileIdentity::new(
                        string(value, "filename")?,
                        Sha256Digest::parse(string(value, "sha256")?)
                            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
                        value.get("bytes").and_then(Value::as_u64),
                    )
                    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
                ),
                _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
            };
            Ok(ModelArtifact::new(
                ArtifactName::parse(string(value, "name")?)
                    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
                ArtifactUri::parse(string(value, "uri")?)
                    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
                ArtifactRevision::parse(string(value, "revision")?)
                    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
                format,
            ))
        })
        .collect()
}

// Computes the exact public execution-subject projection from one verified runtime pack.
fn execution_subject(
    runtime: &Value,
    pack_sha256: &str,
    pack_bytes: u64,
) -> Result<Map<String, Value>, CoreBenchmarkVerificationOracleError> {
    let root = object(runtime, CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let target = child_object(root, "target")?;
    let engine = child_object(root, "engine")?;
    let distribution = child_object(engine, "distribution")?;
    let benchmark = child_object(root, "benchmark")?;
    let contract = benchmark
        .get("contract")
        .filter(|value| value.is_object())
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let mut revisions = array(root, "artifacts")?
        .iter()
        .map(|artifact| {
            let artifact = object(
                artifact,
                CoreBenchmarkVerificationOracleError::BundleInvalid,
            )?;
            let name = string(artifact, "name")?;
            let uri = string(artifact, "uri")?;
            let revision = string(artifact, "revision")?;
            if ArtifactName::parse(name).is_err()
                || ArtifactUri::parse(uri).is_err()
                || ArtifactRevision::parse(revision).is_err()
            {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            }
            let sha256 = artifact.get("sha256").cloned().unwrap_or(Value::Null);
            if !sha256.is_null()
                && sha256
                    .as_str()
                    .is_none_or(|value| Sha256Digest::parse(value).is_err())
            {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            }
            Ok(json!({
                "name": name,
                "uri": uri,
                "revision": revision,
                "sha256": sha256,
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    revisions.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });
    let candidate = string(root, "id")?;
    let version = string(root, "version")?;
    let runtime_manifest =
        runtime_oci_manifest_digest(candidate, version, pack_sha256, pack_bytes)?;
    let mut subject = Map::new();
    subject.insert(
        "candidate_id".to_string(),
        Value::String(candidate.to_string()),
    );
    subject.insert(
        "runtime_version".to_string(),
        Value::String(version.to_string()),
    );
    subject.insert(
        "runtime_pack_sha256".to_string(),
        Value::String(pack_sha256.to_string()),
    );
    subject.insert(
        "runtime_oci_manifest_digest".to_string(),
        Value::String(runtime_manifest),
    );
    if let Some(payload) = distribution.get("payload_id").and_then(Value::as_str) {
        subject.insert(
            "engine_payload_sha256".to_string(),
            Value::String(prefixed_digest(payload)?.as_str().to_string()),
        );
    } else {
        let reference = string(distribution, "reference")?;
        let digest = reference
            .rsplit_once("@sha256:")
            .map(|(_, digest)| format!("sha256:{digest}"))
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        subject.insert(
            "engine_oci_manifest_digest".to_string(),
            Value::String(digest),
        );
    }
    subject.insert("model_revisions".to_string(), Value::Array(revisions));
    subject.insert(
        "benchmark_contract_sha256".to_string(),
        Value::String(sha256_bytes(&canonical_json(contract)?)),
    );
    subject.insert(
        "target_contract_sha256".to_string(),
        Value::String(sha256_bytes(&canonical_json(&Value::Object(
            target.clone(),
        ))?)),
    );
    let execution = sha256_bytes(&canonical_json(&Value::Object(subject.clone()))?);
    subject.insert("execution_sha256".to_string(), Value::String(execution));
    Ok(subject)
}

// Computes the deterministic OCI manifest digest used by runtime publication.
fn runtime_oci_manifest_digest(
    candidate: &str,
    version: &str,
    pack_sha256: &str,
    pack_bytes: u64,
) -> Result<String, CoreBenchmarkVerificationOracleError> {
    if RuntimeCandidateId::parse(candidate).is_err()
        || RuntimeVersion::parse(version).is_err()
        || Sha256Digest::parse(pack_sha256).is_err()
        || pack_bytes == 0
        || pack_bytes > MAXIMUM_RUNTIME_PACK_BYTES
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let config = compact_json(&json!({
        "candidate": candidate,
        "media_type": PACK_MEDIA_TYPE,
        "schema_version": 1,
        "version": version,
    }))?;
    let config_digest = format!("sha256:{}", sha256_bytes(&config));
    let manifest = compact_json(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.letsinfer.runtime.config.v1+json",
            "digest": config_digest,
            "size": config.len(),
        },
        "layers": [{
            "mediaType": PACK_MEDIA_TYPE,
            "digest": format!("sha256:{pack_sha256}"),
            "size": pack_bytes,
            "annotations": {"org.opencontainers.image.title": "runtime.letsinfer"},
        }],
        "annotations": {
            "ai.letsinfer.candidate": candidate,
            "ai.letsinfer.version": version,
            "org.opencontainers.image.source": "https://github.com/letsinferlabs/runtimes",
        },
    }))?;
    Ok(format!("sha256:{}", sha256_bytes(&manifest)))
}

// Verifies the bundle Engine projection against the runtime and its selected build mode.
fn validate_engine(
    root: &Path,
    mode: &str,
    runtime: &Value,
    engine: &Map<String, Value>,
    candidate: &RuntimeCandidateId,
    pull_request: &PullRequest,
    registry_http: &dyn RuntimeHttpClient,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let runtime = object(runtime, CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let distribution = child_object(child_object(runtime, "engine")?, "distribution")?;
    let target_platform = string(child_object(runtime, "target")?, "platform")?;
    let kind = string(distribution, "kind")?;
    if string(engine, "kind")? != kind {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    if kind == "oci-container"
        && (string(engine, "reference")? != string(distribution, "reference")?
            || string(engine, "config_digest")? != string(distribution, "immutable_id")?)
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    if let Some(payload) = distribution.get("payload_id").and_then(Value::as_str) {
        if engine.get("payload_digest").and_then(Value::as_str) != Some(payload) {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
    }
    match mode {
        "reuse-engine" => {
            if root.join("engine.oci.tar").exists() {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            }
        }
        "build-native-engine" => {
            if kind == "oci-container"
                || string(engine, "platform")? != target_platform
                || string(engine, "source_revision")? != string(distribution, "source_revision")?
                || string(engine, "payload_digest")? != string(distribution, "payload_id")?
            {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            }
        }
        "build-engine" => {
            if kind != "oci-container"
                || string(engine, "platform")? != target_platform
                || string(engine, "manifest_digest")?
                    != string(engine, "reference")?
                        .rsplit_once('@')
                        .map(|(_, digest)| digest)
                        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?
            {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            }
            let identity = inspect_engine_archive(
                &root.join("engine.oci.tar"),
                string(engine, "manifest_digest")?,
                string(engine, "config_digest")?,
                target_platform,
                string(engine, "reference")?,
                registry_http,
            )?;
            for (key, value) in identity {
                if engine.get(&key) != Some(&value) {
                    return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
                }
            }
            let tag = format!(
                "letsinfer-verifier/{}:{}",
                candidate.as_str(),
                &pull_request.head_sha.as_str()[..12]
            );
            if tag.len() > 255 {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            }
        }
        _ => return Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
    }
    Ok(())
}

// Extracts and inspects one complete OCI Engine archive without trusting tar paths or metadata.
fn inspect_engine_archive(
    archive: &Path,
    expected_manifest: &str,
    expected_config: &str,
    expected_platform: &str,
    expected_reference: &str,
    registry_http: &dyn RuntimeHttpClient,
) -> Result<Map<String, Value>, CoreBenchmarkVerificationOracleError> {
    if !valid_prefixed_digest(expected_manifest)
        || !valid_prefixed_digest(expected_config)
        || !valid_platform(expected_platform)
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let parent = archive
        .parent()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let layout_root = parent.join(".engine-layout");
    fs::create_dir(&layout_root)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    fs::set_permissions(&layout_root, fs::Permissions::from_mode(0o700))
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    let result = extract_engine_layout(archive, &layout_root).and_then(|_| {
        inspect_engine_layout(
            &layout_root,
            expected_manifest,
            expected_config,
            expected_platform,
            expected_reference,
            registry_http,
        )
    });
    let cleanup = remove_workspace(&layout_root, parent);
    match (result, cleanup) {
        (Ok(identity), Ok(())) => Ok(identity),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

// Extracts one bounded OCI tar or tar.gz with regular files and directories only.
fn extract_engine_layout(
    archive: &Path,
    destination: &Path,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let mut file = open_regular(archive, MAXIMUM_ARTIFACT_BYTES)?;
    let mut magic = [0_u8; 2];
    file.read_exact(&mut magic)
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    let reader: Box<dyn Read> = if magic == [0x1f, 0x8b] {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let mut seen = HashSet::new();
    let mut total = 0_u64;
    let mut count = 0_usize;
    for entry in entries {
        let mut entry = entry.map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        count += 1;
        if count > MAXIMUM_ENGINE_ENTRIES {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        let relative = safe_relative_path(
            entry
                .path()
                .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?
                .as_ref(),
        )?;
        if !seen.insert(relative.clone()) {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        let target = destination.join(&relative);
        if entry.header().entry_type().is_dir() {
            create_private_directories(destination, &relative)?;
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        let bytes = entry
            .header()
            .size()
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        total = total
            .checked_add(bytes)
            .filter(|value| *value <= MAXIMUM_ENGINE_LAYOUT_BYTES)
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        if let Some(parent) = relative
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            create_private_directories(destination, parent)?;
        }
        let mut output = create_private_file(&target)?;
        let copied = std::io::copy(&mut entry, &mut output)
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
        if copied != bytes {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        output
            .sync_all()
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    }
    if count == 0 {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(())
}

// Verifies one exact platform manifest, configuration, layer closure, and payload identity.
fn inspect_engine_layout(
    root: &Path,
    expected_manifest: &str,
    expected_config: &str,
    expected_platform: &str,
    expected_reference: &str,
    registry_http: &dyn RuntimeHttpClient,
) -> Result<Map<String, Value>, CoreBenchmarkVerificationOracleError> {
    let layout = parse_file_object(&root.join("oci-layout"))?;
    if layout
        != json!({"imageLayoutVersion": "1.0.0"})
            .as_object()
            .unwrap()
            .clone()
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let (expected_os, expected_architecture) = expected_platform
        .split_once('/')
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let index = parse_file_object(&root.join("index.json"))?;
    if unsigned(&index, "schemaVersion")? != 2 {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let descriptor = select_platform_descriptor(
        array(&index, "manifests")?,
        expected_os,
        expected_architecture,
    )?;
    let descriptor_digest = string(&descriptor, "digest")?.to_string();
    let mut manifest_bytes = oci_blob(root, &descriptor, MAXIMUM_ENGINE_DOCUMENT_BYTES)?;
    let mut manifest = parse_json_object(&manifest_bytes)?;
    let mut manifest = manifest
        .as_object_mut()
        .cloned()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let media_type = string(&descriptor, "mediaType")?;
    if is_index_media_type(media_type) {
        let nested = select_platform_descriptor(
            array(&manifest, "manifests")?,
            expected_os,
            expected_architecture,
        )?;
        let nested_bytes = oci_blob(root, &nested, MAXIMUM_ENGINE_DOCUMENT_BYTES)?;
        manifest = parse_json_object(&nested_bytes)?
            .as_object()
            .cloned()
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        if string(&nested, "digest")? != expected_manifest {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        manifest_bytes = nested_bytes;
    } else if descriptor_digest != expected_manifest {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    if unsigned(&manifest, "schemaVersion")? != 2
        || !is_manifest_media_type(string(&manifest, "mediaType")?)
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let config_descriptor = child_object(&manifest, "config")?.clone();
    if string(&config_descriptor, "digest")? != expected_config
        || !is_config_media_type(string(&config_descriptor, "mediaType")?)
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let config_bytes = oci_blob(root, &config_descriptor, MAXIMUM_ENGINE_DOCUMENT_BYTES)?;
    let config = parse_json_object(&config_bytes)?;
    let config = config
        .as_object()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if string(config, "os")? != expected_os
        || string(config, "architecture")? != expected_architecture
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let rootfs = child_object(config, "rootfs")?;
    let diff_ids = array(rootfs, "diff_ids")?;
    let layers = array(&manifest, "layers")?;
    if string(rootfs, "type")? != "layers" || layers.is_empty() || layers.len() != diff_ids.len() {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let mut layer_descriptors = Vec::new();
    let mut rootfs_digests = Vec::new();
    for (index, layer) in layers.iter().enumerate() {
        let layer = object(layer, CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        let media_type = string(layer, "mediaType")?;
        if !is_layer_media_type(media_type) || unsigned(layer, "size")? > MAXIMUM_ENGINE_LAYER_BYTES
        {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        validate_oci_descriptor(layer)?;
        layer_descriptors.push(layer.clone());
        let diff_id = diff_ids[index]
            .as_str()
            .filter(|value| valid_prefixed_digest(value))
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        rootfs_digests.push(diff_id.to_string());
    }
    let external = external_engine_layers(
        root,
        expected_manifest,
        &layer_descriptors,
        &rootfs_digests,
        expected_platform,
        expected_reference,
        registry_http,
    )?;
    let external_indices = external
        .as_ref()
        .map(|external| external.indices.clone())
        .unwrap_or_default();
    for (index, layer) in layer_descriptors.iter().enumerate() {
        if !external_indices.contains(&index) {
            oci_blob(root, layer, MAXIMUM_ENGINE_LAYER_BYTES)?;
        }
    }
    let payload = if let Some(external) = &external {
        engine_overlay_payload_digest(
            expected_platform,
            config,
            &external.source_reference,
            &normalized_engine_overlay_digest(root, &layer_descriptors, &external.indices)?,
        )?
    } else {
        engine_payload_digest(expected_platform, config, &rootfs_digests)?
    };
    let layer_digests = layer_descriptors
        .iter()
        .map(|layer| string(layer, "digest").map(|digest| Value::String(digest.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    let mut identity = Map::new();
    identity.insert(
        "platform".to_string(),
        Value::String(expected_platform.to_string()),
    );
    identity.insert(
        "manifest_digest".to_string(),
        Value::String(expected_manifest.to_string()),
    );
    identity.insert(
        "manifest_bytes".to_string(),
        Value::Number((manifest_bytes.len() as u64).into()),
    );
    identity.insert(
        "config_digest".to_string(),
        Value::String(expected_config.to_string()),
    );
    identity.insert("payload_digest".to_string(), Value::String(payload));
    identity.insert("layer_digests".to_string(), Value::Array(layer_digests));
    identity.insert(
        "local_layer_count".to_string(),
        Value::Number(((layers.len() - external_indices.len()) as u64).into()),
    );
    identity.insert(
        "external_layer_count".to_string(),
        Value::Number((external_indices.len() as u64).into()),
    );
    if let Some(external) = external {
        identity.insert(
            "external_reference".to_string(),
            Value::String(external.source_reference),
        );
    }
    Ok(identity)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExternalEngineLayers {
    source_reference: String,
    indices: BTreeSet<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemoteEngineImage {
    layers: Vec<Map<String, Value>>,
    diff_ids: Vec<String>,
}

// Verifies one optional thin-layout inventory against its immutable public base image.
#[allow(clippy::too_many_arguments)]
fn external_engine_layers(
    root: &Path,
    manifest_digest: &str,
    layers: &[Map<String, Value>],
    diff_ids: &[String],
    expected_platform: &str,
    expected_reference: &str,
    registry_http: &dyn RuntimeHttpClient,
) -> Result<Option<ExternalEngineLayers>, CoreBenchmarkVerificationOracleError> {
    let path = root.join("letsinfer-external-blobs.json");
    if !path.exists() {
        return Ok(None);
    }
    let inventory = parse_file_object(&path)?;
    exact_fields(
        &inventory,
        &[
            "schema_version",
            "source_reference",
            "target_repository",
            "manifest_digest",
            "layers",
        ],
    )?;
    let source_reference = string(&inventory, "source_reference")?;
    let source = parse_oci_reference(source_reference)?;
    let expected = parse_oci_reference(expected_reference)?;
    if unsigned(&inventory, "schema_version")? != 1
        || string(&inventory, "manifest_digest")? != manifest_digest
        || expected.digest != manifest_digest
        || string(&inventory, "target_repository")?
            != format!("{}/{}", expected.original_registry, expected.repository)
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let remote = remote_engine_image(registry_http, &source, expected_platform)?;
    let remote_records = remote
        .layers
        .iter()
        .enumerate()
        .map(|(index, layer)| {
            Ok((
                string(layer, "digest")?.to_string(),
                unsigned(layer, "size")?,
                remote.diff_ids[index].clone(),
            ))
        })
        .collect::<Result<HashSet<_>, CoreBenchmarkVerificationOracleError>>()?;
    let records = array(&inventory, "layers")?;
    let mut indices = BTreeSet::new();
    let mut descriptors = BTreeMap::new();
    for record in records {
        let record = object(record, CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        exact_fields(record, &["index", "digest", "size", "mediaType", "diff_id"])?;
        let index = usize::try_from(unsigned(record, "index")?)
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        if index >= layers.len() || !indices.insert(index) {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        let layer = &layers[index];
        if string(record, "digest")? != string(layer, "digest")?
            || unsigned(record, "size")? != unsigned(layer, "size")?
            || string(record, "mediaType")? != string(layer, "mediaType")?
            || string(record, "diff_id")? != diff_ids[index]
            || !remote_records.contains(&(
                string(layer, "digest")?.to_string(),
                unsigned(layer, "size")?,
                diff_ids[index].clone(),
            ))
        {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        let blob = engine_blob_path(root, string(layer, "digest")?)?;
        if blob.exists() || blob.is_symlink() {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        descriptors.insert(string(layer, "digest")?.to_string(), layer.clone());
    }
    if indices.is_empty() {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    for (index, layer) in layers.iter().enumerate() {
        if !indices.contains(&index) {
            oci_blob(root, layer, MAXIMUM_ENGINE_LAYER_BYTES)?;
        }
    }
    for descriptor in descriptors.values() {
        probe_registry_blob(registry_http, &source, descriptor)?;
    }
    Ok(Some(ExternalEngineLayers {
        source_reference: source_reference.to_string(),
        indices,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OciReference {
    original_registry: String,
    registry: String,
    repository: String,
    digest: String,
}

// Parses one immutable registry/repository reference without paths that escape its repository.
fn parse_oci_reference(value: &str) -> Result<OciReference, CoreBenchmarkVerificationOracleError> {
    if value.len() > 2_048 || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let (location, digest) = value
        .rsplit_once('@')
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if !valid_prefixed_digest(digest) {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let (registry, repository) = location
        .split_once('/')
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if !valid_registry(registry)
        || repository.is_empty()
        || repository
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | "..") || !safe_registry_part(part))
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(OciReference {
        original_registry: registry.to_string(),
        registry: if registry == "docker.io" {
            "registry-1.docker.io".to_string()
        } else {
            registry.to_string()
        },
        repository: repository.to_string(),
        digest: digest.to_string(),
    })
}

// Returns whether one registry hostname and optional numeric port are canonical.
fn valid_registry(value: &str) -> bool {
    let mut parts = value.split(':');
    let host = parts.next().unwrap_or_default();
    let port = parts.next();
    !host.is_empty()
        && parts.next().is_none()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && port.is_none_or(|port| {
            !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().ok().is_some_and(|port| port > 0)
        })
}

// Returns whether one repository path component uses the registry-safe alphabet.
fn safe_registry_part(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

// Resolves one immutable public base image and validates its exact platform rootfs identity.
fn remote_engine_image(
    client: &dyn RuntimeHttpClient,
    reference: &OciReference,
    expected_platform: &str,
) -> Result<RemoteEngineImage, CoreBenchmarkVerificationOracleError> {
    let accept = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json";
    let mut manifest = registry_get(
        client,
        reference,
        &format!("manifests/{}", reference.digest),
        accept,
        MAXIMUM_ENGINE_DOCUMENT_BYTES,
    )?;
    if format!("sha256:{}", sha256_bytes(&manifest)) != reference.digest {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let mut document = parse_json_object(&manifest)?
        .as_object()
        .cloned()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if document.contains_key("manifests") && !document.contains_key("config") {
        let (expected_os, expected_architecture) = expected_platform
            .split_once('/')
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        let descriptor = select_platform_descriptor(
            array(&document, "manifests")?,
            expected_os,
            expected_architecture,
        )?;
        manifest = registry_get(
            client,
            reference,
            &format!("manifests/{}", string(&descriptor, "digest")?),
            "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
            MAXIMUM_ENGINE_DOCUMENT_BYTES,
        )?;
        if format!("sha256:{}", sha256_bytes(&manifest)) != string(&descriptor, "digest")? {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        }
        document = parse_json_object(&manifest)?
            .as_object()
            .cloned()
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    }
    if unsigned(&document, "schemaVersion")? != 2
        || !is_manifest_media_type(string(&document, "mediaType")?)
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let config_descriptor = child_object(&document, "config")?;
    if !is_config_media_type(string(config_descriptor, "mediaType")?) {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let config = registry_get(
        client,
        reference,
        &format!("blobs/{}", string(config_descriptor, "digest")?),
        string(config_descriptor, "mediaType")?,
        MAXIMUM_ENGINE_DOCUMENT_BYTES,
    )?;
    if config.len() as u64 != unsigned(config_descriptor, "size")?
        || format!("sha256:{}", sha256_bytes(&config)) != string(config_descriptor, "digest")?
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let config = parse_json_object(&config)?;
    let config = config
        .as_object()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let (expected_os, expected_architecture) = expected_platform
        .split_once('/')
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if string(config, "os")? != expected_os
        || string(config, "architecture")? != expected_architecture
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let layers = array(&document, "layers")?
        .iter()
        .map(|layer| {
            let layer = object(layer, CoreBenchmarkVerificationOracleError::BundleInvalid)?;
            validate_oci_descriptor(layer)?;
            if !is_layer_media_type(string(layer, "mediaType")?)
                || unsigned(layer, "size")? > MAXIMUM_ENGINE_LAYER_BYTES
            {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            }
            Ok(layer.clone())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let rootfs = child_object(config, "rootfs")?;
    let diff_ids = array(rootfs, "diff_ids")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| valid_prefixed_digest(value))
                .map(str::to_string)
                .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if string(rootfs, "type")? != "layers" || layers.is_empty() || layers.len() != diff_ids.len() {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(RemoteEngineImage { layers, diff_ids })
}

// Reads one registry object anonymously or through a bounded public bearer challenge.
fn registry_get(
    client: &dyn RuntimeHttpClient,
    reference: &OciReference,
    path: &str,
    accept: &str,
    maximum_bytes: u64,
) -> Result<Vec<u8>, CoreBenchmarkVerificationOracleError> {
    let url = format!(
        "https://{}/v2/{}/{}",
        reference.registry, reference.repository, path
    );
    let request = RuntimeHttpRequest::https(&url, Some(accept.to_string()))
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let mut response = client
        .get(&request, maximum_bytes)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    if matches!(response.status(), 401 | 403) {
        let challenge = response
            .header("www-authenticate")
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        let token = registry_token(client, challenge, &reference.repository)?;
        let request =
            RuntimeHttpRequest::new(&url, Some(accept.to_string()), Some(token), false, 3_600)
                .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        response = client
            .get(&request, maximum_bytes)
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    }
    if response.status() != 200 || !response.final_url().starts_with("https://") {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(response.body().to_vec())
}

// Resolves one public registry bearer token from a strict RFC-6750 challenge.
fn registry_token(
    client: &dyn RuntimeHttpClient,
    challenge: &str,
    repository: &str,
) -> Result<RuntimeBearerToken, CoreBenchmarkVerificationOracleError> {
    let attributes = challenge
        .strip_prefix("Bearer ")
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?
        .split(',')
        .map(|part| {
            let (key, value) = part
                .trim()
                .split_once('=')
                .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
            Ok((key, value))
        })
        .collect::<Result<BTreeMap<_, _>, CoreBenchmarkVerificationOracleError>>()?;
    let realm = attributes
        .get("realm")
        .filter(|realm| realm.starts_with("https://"))
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let separator = if realm.contains('?') { '&' } else { '?' };
    let mut url = format!("{realm}{separator}scope=repository:{repository}:pull");
    if let Some(service) = attributes.get("service") {
        url.push_str("&service=");
        url.push_str(&percent_encode(service));
    }
    let request =
        RuntimeHttpRequest::new(&url, Some("application/json".to_string()), None, false, 60)
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let response = client
        .get(&request, 64 * 1024)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    if response.status() != 200 {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let value = parse_json_object(response.body())?;
    let token = value
        .as_object()
        .and_then(|value| value.get("token").or_else(|| value.get("access_token")))
        .and_then(Value::as_str)
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    RuntimeBearerToken::new(token).map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)
}

// Probes one exact external blob descriptor through the authenticated public registry path.
fn probe_registry_blob(
    client: &dyn RuntimeHttpClient,
    reference: &OciReference,
    descriptor: &Map<String, Value>,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let url = format!(
        "https://{}/v2/{}/blobs/{}",
        reference.registry,
        reference.repository,
        string(descriptor, "digest")?
    );
    let request = RuntimeHttpRequest::https(&url, None)
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let mut response = client
        .head(&request)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    if matches!(response.status(), 401 | 403) {
        let challenge = response
            .header("www-authenticate")
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        let token = registry_token(client, challenge, &reference.repository)?;
        let request = RuntimeHttpRequest::new(&url, None, Some(token), false, 3_600)
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        response = client
            .head(&request)
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    }
    if response.status() != 200
        || !response.final_url().starts_with("https://")
        || response.header("content-length").is_some_and(|value| {
            value.parse::<u64>().ok() != Some(unsigned(descriptor, "size").unwrap_or(u64::MAX))
        })
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(())
}

// Percent-encodes one public token-service value using the RFC-3986 unreserved alphabet.
fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

// Returns the exact contained OCI blob path for one canonical digest.
fn engine_blob_path(
    root: &Path,
    digest: &str,
) -> Result<PathBuf, CoreBenchmarkVerificationOracleError> {
    Ok(root.join("blobs/sha256").join(
        digest
            .strip_prefix("sha256:")
            .filter(|value| Sha256Digest::parse(value).is_ok())
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?,
    ))
}

// Selects exactly one descriptor for the expected operating-system and architecture pair.
fn select_platform_descriptor(
    values: &[Value],
    expected_os: &str,
    expected_architecture: &str,
) -> Result<Map<String, Value>, CoreBenchmarkVerificationOracleError> {
    let selected = values
        .iter()
        .filter_map(Value::as_object)
        .filter(|descriptor| {
            descriptor
                .get("platform")
                .and_then(Value::as_object)
                .is_some_and(|platform| {
                    platform.get("os").and_then(Value::as_str) == Some(expected_os)
                        && platform.get("architecture").and_then(Value::as_str)
                            == Some(expected_architecture)
                })
                || (values.len() == 1
                    && descriptor.get("platform").is_none()
                    && descriptor
                        .get("mediaType")
                        .and_then(Value::as_str)
                        .is_some_and(is_manifest_media_type))
        })
        .cloned()
        .collect::<Vec<_>>();
    let [descriptor] = selected.as_slice() else {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    };
    validate_oci_descriptor(descriptor)?;
    Ok(descriptor.clone())
}

// Reads and digest-verifies one exact OCI blob under its declared bound.
fn oci_blob(
    root: &Path,
    descriptor: &Map<String, Value>,
    maximum_bytes: u64,
) -> Result<Vec<u8>, CoreBenchmarkVerificationOracleError> {
    validate_oci_descriptor(descriptor)?;
    let digest = string(descriptor, "digest")?;
    let path = root.join("blobs/sha256").join(
        digest
            .strip_prefix("sha256:")
            .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?,
    );
    let bytes = read_regular(&path, maximum_bytes)?;
    if bytes.len() as u64 != unsigned(descriptor, "size")?
        || format!("sha256:{}", sha256_bytes(&bytes)) != digest
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(bytes)
}

// Requires one ordinary OCI descriptor with a canonical digest and bounded size.
fn validate_oci_descriptor(
    descriptor: &Map<String, Value>,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    if string(descriptor, "mediaType")?.is_empty()
        || !valid_prefixed_digest(string(descriptor, "digest")?)
        || descriptor.get("size").and_then(Value::as_u64).is_none()
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(())
}

// Computes the exact schema-1 Engine execution payload digest for a complete local OCI image.
fn engine_payload_digest(
    platform: &str,
    config: &Map<String, Value>,
    diff_ids: &[String],
) -> Result<String, CoreBenchmarkVerificationOracleError> {
    if !valid_platform(platform)
        || diff_ids.is_empty()
        || diff_ids.iter().any(|value| !valid_prefixed_digest(value))
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let runtime = config
        .get("config")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let runtime = runtime
        .as_object()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let fields = [
        "ArgsEscaped",
        "Cmd",
        "Entrypoint",
        "Env",
        "ExposedPorts",
        "Healthcheck",
        "OnBuild",
        "Shell",
        "StopSignal",
        "User",
        "Volumes",
        "WorkingDir",
    ];
    let runtime_config = fields
        .iter()
        .filter_map(|field| {
            runtime
                .get(*field)
                .cloned()
                .map(|value| ((*field).to_string(), value))
        })
        .collect::<Map<_, _>>();
    let material = json!({
        "schema_version": 1,
        "platform": platform,
        "rootfs_diff_ids": diff_ids,
        "runtime_config": runtime_config,
    });
    Ok(format!(
        "sha256:{}",
        sha256_bytes(&canonical_json(&material)?)
    ))
}

// Computes the exact schema-2 Engine payload identity for a verified base plus local overlay.
fn engine_overlay_payload_digest(
    platform: &str,
    config: &Map<String, Value>,
    base_reference: &str,
    overlay_digest: &str,
) -> Result<String, CoreBenchmarkVerificationOracleError> {
    parse_oci_reference(base_reference)?;
    if !valid_platform(platform) || !valid_prefixed_digest(overlay_digest) {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    let runtime = config
        .get("config")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let runtime = runtime
        .as_object()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    let fields = [
        "ArgsEscaped",
        "Cmd",
        "Entrypoint",
        "Env",
        "ExposedPorts",
        "Healthcheck",
        "OnBuild",
        "Shell",
        "StopSignal",
        "User",
        "Volumes",
        "WorkingDir",
    ];
    let runtime_config = fields
        .iter()
        .filter_map(|field| {
            runtime
                .get(*field)
                .cloned()
                .map(|value| ((*field).to_string(), value))
        })
        .collect::<Map<_, _>>();
    let material = json!({
        "schema_version": 2,
        "platform": platform,
        "base_reference": base_reference,
        "overlay_digest": overlay_digest,
        "runtime_config": runtime_config,
    });
    Ok(format!(
        "sha256:{}",
        sha256_bytes(&canonical_json(&material)?)
    ))
}

// Computes the normalized overlay tree after applying local OCI layers and whiteouts in order.
fn normalized_engine_overlay_digest(
    root: &Path,
    layers: &[Map<String, Value>],
    external_indices: &BTreeSet<usize>,
) -> Result<String, CoreBenchmarkVerificationOracleError> {
    let mut state = BTreeMap::<String, Value>::new();
    for (layer_index, descriptor) in layers.iter().enumerate() {
        if external_indices.contains(&layer_index) {
            continue;
        }
        let bytes = oci_blob(root, descriptor, MAXIMUM_ENGINE_LAYER_BYTES)?;
        let media_type = string(descriptor, "mediaType")?;
        let reader: Box<dyn Read> = if matches!(
            media_type,
            "application/vnd.oci.image.layer.v1.tar+gzip"
                | "application/vnd.docker.image.rootfs.diff.tar.gzip"
        ) {
            Box::new(GzDecoder::new(CursorReader::new(bytes)))
        } else {
            Box::new(CursorReader::new(bytes))
        };
        let mut archive = tar::Archive::new(reader);
        let entries = archive
            .entries()
            .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
        let mut count = 0_usize;
        for entry in entries {
            let mut entry =
                entry.map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
            count += 1;
            if count > MAXIMUM_ENGINE_ENTRIES {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            }
            let path = safe_relative_path(
                entry
                    .path()
                    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?
                    .as_ref(),
            )?;
            let name = path
                .to_str()
                .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?
                .to_string();
            let parent = path
                .parent()
                .and_then(Path::to_str)
                .filter(|value| !value.is_empty())
                .unwrap_or(".");
            let basename = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?;
            if basename == ".wh..wh..opq" {
                let prefix = if parent == "." {
                    String::new()
                } else {
                    format!("{parent}/")
                };
                state.retain(|key, _| key != parent && !key.starts_with(&prefix));
                continue;
            }
            if let Some(target) = basename.strip_prefix(".wh.") {
                let target = if parent == "." {
                    target.to_string()
                } else {
                    format!("{parent}/{target}")
                };
                let prefix = format!("{target}/");
                state.retain(|key, _| key != &target && !key.starts_with(&prefix));
                continue;
            }
            let entry_type = entry.header().entry_type();
            let kind = if entry_type.is_file() {
                "file"
            } else if entry_type.is_dir() {
                "directory"
            } else if entry_type.is_symlink() {
                "symlink"
            } else if entry_type.is_hard_link() {
                "hardlink"
            } else {
                return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
            };
            let content_sha256 = if entry_type.is_file() {
                let mut digest = Sha256::new();
                std::io::copy(&mut entry, &mut digest)
                    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
                Value::String(format!("{:x}", digest.finalize()))
            } else {
                Value::Null
            };
            if !entry_type.is_dir() {
                let prefix = format!("{name}/");
                state.retain(|key, _| !key.starts_with(&prefix));
            }
            let linkname = if entry_type.is_symlink() || entry_type.is_hard_link() {
                entry
                    .link_name()
                    .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?
                    .and_then(|value| value.to_str().map(str::to_string))
                    .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)?
            } else {
                String::new()
            };
            let xattrs = entry
                .pax_extensions()
                .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?
                .map(|extensions| {
                    extensions
                        .filter_map(|extension| extension.ok())
                        .filter_map(|extension| {
                            let key = extension.key().ok()?;
                            key.starts_with("SCHILY.xattr.").then(|| {
                                extension.value().ok().map(|value| {
                                    (key.to_string(), Value::String(value.to_string()))
                                })
                            })?
                        })
                        .collect::<Map<String, Value>>()
                })
                .unwrap_or_default();
            state.insert(
                name.clone(),
                json!({
                    "path": name,
                    "type": kind,
                    "mode": entry.header().mode().map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)? & 0o7777,
                    "uid": entry.header().uid().map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
                    "gid": entry.header().gid().map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?,
                    "linkname": linkname,
                    "content_sha256": content_sha256,
                    "xattrs": xattrs,
                }),
            );
        }
    }
    let normalized = Value::Array(state.into_values().collect());
    Ok(format!(
        "sha256:{}",
        sha256_bytes(&canonical_json(&normalized)?)
    ))
}

struct CursorReader {
    value: std::io::Cursor<Vec<u8>>,
}

impl CursorReader {
    // Creates one owned byte reader for nested archive decompression.
    fn new(value: Vec<u8>) -> Self {
        Self {
            value: std::io::Cursor::new(value),
        }
    }
}

impl Read for CursorReader {
    // Delegates bounded reads to the owned in-memory cursor.
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.value.read(buffer)
    }
}

// Returns whether one media type is an accepted OCI or Docker image manifest.
fn is_manifest_media_type(value: &str) -> bool {
    matches!(
        value,
        "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
    )
}

// Returns whether one media type is an accepted OCI or Docker platform index.
fn is_index_media_type(value: &str) -> bool {
    matches!(
        value,
        "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
    )
}

// Returns whether one media type is an accepted OCI or Docker image configuration.
fn is_config_media_type(value: &str) -> bool {
    matches!(
        value,
        "application/vnd.oci.image.config.v1+json"
            | "application/vnd.docker.container.image.v1+json"
    )
}

// Returns whether one layer uses an accepted OCI or Docker tar representation.
fn is_layer_media_type(value: &str) -> bool {
    matches!(
        value,
        "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip"
            | "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.docker.image.rootfs.diff.tar"
    )
}

// Binds the attested document to the exact trusted finalizer run and workflow revision.
fn validate_finalizer_binding(
    document: &Map<String, Value>,
    run_id: u64,
    finalizer: &Value,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let identity = child_object(document, "finalizer_workflow")?;
    let finalizer = object(
        finalizer,
        CoreBenchmarkVerificationOracleError::ArtifactInvalid,
    )?;
    if unsigned(identity, "run_id")? != run_id
        || string(identity, "path")? != FINALIZER_PATH
        || string(identity, "workflow_sha")? != string(finalizer, "head_sha")?
    {
        return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
    }
    Ok(())
}

// Binds the untrusted builder to the exact main workflow at the proposal base revision.
fn validate_build_binding(
    identity: &Map<String, Value>,
    build: &Value,
    proposal_base: &BenchmarkGitRevision,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let build = object(build, CoreBenchmarkVerificationOracleError::ArtifactInvalid)?;
    if string(build, "event")? != "workflow_run"
        || string(build, "path")? != BUILD_PATH
        || string(build, "conclusion")? != "success"
        || string(build, "head_branch")? != "main"
        || string(build, "head_sha")? != proposal_base.as_str()
        || string(identity, "workflow_sha")? != proposal_base.as_str()
    {
        return Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid);
    }
    Ok(())
}

// Parses one exact JSON object file beneath the verifier's regular-file boundary.
fn parse_file_object(
    path: &Path,
) -> Result<Map<String, Value>, CoreBenchmarkVerificationOracleError> {
    parse_json_object(&read_regular(path, MAXIMUM_DOCUMENT_BYTES)?)?
        .as_object()
        .cloned()
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
}

// Parses one bounded UTF-8 JSON document without accepting trailing data.
fn parse_json_object(bytes: &[u8]) -> Result<Value, CoreBenchmarkVerificationOracleError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = Value::deserialize(&mut deserializer)
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    deserializer
        .end()
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)?;
    if !value.is_object() {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(value)
}

// Serializes one canonical sorted compact JSON value with the public trailing newline.
fn canonical_json(value: &Value) -> Result<Vec<u8>, CoreBenchmarkVerificationOracleError> {
    let mut bytes = compact_json(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// Serializes one sorted compact JSON value without the public trailing newline.
fn compact_json(value: &Value) -> Result<Vec<u8>, CoreBenchmarkVerificationOracleError> {
    serde_json::to_vec(value).map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)
}

// Returns the lowercase SHA-256 identity of exact bytes.
fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

// Reads and hashes one bounded regular file without following its final path.
fn sha256_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<String, CoreBenchmarkVerificationOracleError> {
    let mut file = open_regular(path, maximum_bytes)?;
    let mut digest = Sha256::new();
    let copied = std::io::copy(&mut file, &mut digest)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    if copied == 0 || copied > maximum_bytes {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(format!("{:x}", digest.finalize()))
}

// Converts exact bytes into the shared unprefixed SHA-256 value type.
fn digest(value: &[u8]) -> Result<Sha256Digest, CoreBenchmarkVerificationOracleError> {
    Sha256Digest::parse(&sha256_bytes(value))
        .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)
}

// Parses one exact `sha256:` value into the shared unprefixed digest type.
fn prefixed_digest(value: &str) -> Result<Sha256Digest, CoreBenchmarkVerificationOracleError> {
    value
        .strip_prefix("sha256:")
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
        .and_then(|value| {
            Sha256Digest::parse(value)
                .map_err(|_| CoreBenchmarkVerificationOracleError::BundleInvalid)
        })
}

// Returns whether one value is exactly a lowercase prefixed SHA-256 identity.
fn valid_prefixed_digest(value: &str) -> bool {
    prefixed_digest(value).is_ok()
}

// Returns whether one platform is a supported operating-system and CPU architecture pair.
fn valid_platform(value: &str) -> bool {
    matches!(value, "linux/arm64" | "linux/x86_64" | "macos/arm64")
}

// Returns whether one relative executable or archive path is normalized and contained.
fn safe_relative_text(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

// Parses one safe normalized relative filesystem path.
fn safe_relative_path(value: &Path) -> Result<PathBuf, CoreBenchmarkVerificationOracleError> {
    if value.as_os_str().is_empty()
        || value.is_absolute()
        || value
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(value.to_path_buf())
}

// Returns whether one caller path is absolute and contains only root and normal components.
fn absolute_normal(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Requires one owner-private real directory before writing any verification artifact beneath it.
fn validate_private_directory(
    path: &Path,
    owner_user_id: u32,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    if !absolute_normal(path)
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(CoreBenchmarkVerificationOracleError::InvalidConfiguration);
    }
    Ok(())
}

// Opens one no-follow bounded regular file and verifies its stable owner-only metadata.
fn open_regular(
    path: &Path,
    maximum_bytes: u64,
) -> Result<File, CoreBenchmarkVerificationOracleError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(file)
}

// Reads one entire already-bounded regular file.
fn read_regular(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Vec<u8>, CoreBenchmarkVerificationOracleError> {
    let mut file = open_regular(path, maximum_bytes)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(bytes)
}

// Creates one new owner-private regular file without following its final path.
fn create_private_file(path: &Path) -> Result<File, CoreBenchmarkVerificationOracleError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)
}

// Creates every contained private directory in one normalized relative path.
fn create_private_directories(
    root: &Path,
    relative: &Path,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let relative = safe_relative_path(relative)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
        };
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
                .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&current)
                    .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
                }
            }
            Err(_) => return Err(CoreBenchmarkVerificationOracleError::FilesystemUnavailable),
        }
    }
    Ok(())
}

// Removes one contained workspace recursively without ever traversing a symbolic link.
fn remove_workspace(
    path: &Path,
    parent: &Path,
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    if path.parent() != Some(parent) || path == parent {
        return Err(CoreBenchmarkVerificationOracleError::InvalidConfiguration);
    }
    remove_entry(path)
}

// Removes one exact regular file, symbolic link, or recursively validated directory.
fn remove_entry(path: &Path) -> Result<(), CoreBenchmarkVerificationOracleError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?;
    if metadata.file_type().is_symlink() || metadata.is_file() {
        return fs::remove_file(path)
            .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable);
    }
    if !metadata.is_dir() {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    for entry in path
        .read_dir()
        .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?
    {
        remove_entry(
            &entry
                .map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)?
                .path(),
        )?;
    }
    fs::remove_dir(path).map_err(|_| CoreBenchmarkVerificationOracleError::FilesystemUnavailable)
}

// Returns one JSON object or the caller-selected stable rejection category.
fn object(
    value: &Value,
    error: CoreBenchmarkVerificationOracleError,
) -> Result<&Map<String, Value>, CoreBenchmarkVerificationOracleError> {
    value.as_object().ok_or(error)
}

// Returns one required child object.
fn child_object<'a>(
    value: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Map<String, Value>, CoreBenchmarkVerificationOracleError> {
    value
        .get(name)
        .and_then(Value::as_object)
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
}

// Returns one required string field.
fn string<'a>(
    value: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, CoreBenchmarkVerificationOracleError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
}

// Returns one required unsigned integer without accepting a floating or negative value.
fn unsigned(
    value: &Map<String, Value>,
    name: &str,
) -> Result<u64, CoreBenchmarkVerificationOracleError> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
}

// Returns one required JSON array.
fn array<'a>(
    value: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a [Value], CoreBenchmarkVerificationOracleError> {
    value
        .get(name)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(CoreBenchmarkVerificationOracleError::BundleInvalid)
}

// Requires one object to contain exactly the declared field set.
fn exact_fields(
    value: &Map<String, Value>,
    fields: &[&str],
) -> Result<(), CoreBenchmarkVerificationOracleError> {
    if value.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != fields.iter().copied().collect::<BTreeSet<_>>()
    {
        return Err(CoreBenchmarkVerificationOracleError::BundleInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Mutex;

    use li_runtime_manager::{RuntimeHttpDownload, RuntimeHttpResponse};
    use tempfile::{tempdir, TempDir};
    use zip::write::SimpleFileOptions;

    use super::*;

    struct RejectHttpClient;

    impl RuntimeHttpClient for RejectHttpClient {
        // Refuses unexpected registry traffic from fixtures with complete local Engine layers.
        fn get(
            &self,
            _request: &RuntimeHttpRequest,
            _maximum_body_bytes: u64,
        ) -> Result<RuntimeHttpResponse, li_runtime_manager::RuntimeError> {
            Err(li_runtime_manager::RuntimeError::DownloadUnavailable)
        }

        // Refuses unexpected streamed registry downloads from complete local fixtures.
        fn download(
            &self,
            _request: &RuntimeHttpRequest,
            _destination: &Path,
            _maximum_body_bytes: u64,
        ) -> Result<RuntimeHttpDownload, li_runtime_manager::RuntimeError> {
            Err(li_runtime_manager::RuntimeError::DownloadUnavailable)
        }
    }

    struct MockHttpClient {
        gets: Mutex<BTreeMap<String, RuntimeHttpResponse>>,
        heads: Mutex<BTreeMap<String, RuntimeHttpResponse>>,
    }

    impl RuntimeHttpClient for MockHttpClient {
        // Returns one exact immutable registry body by requested HTTPS URL.
        fn get(
            &self,
            request: &RuntimeHttpRequest,
            _maximum_body_bytes: u64,
        ) -> Result<RuntimeHttpResponse, li_runtime_manager::RuntimeError> {
            self.gets
                .lock()
                .expect("gets")
                .remove(request.url())
                .ok_or(li_runtime_manager::RuntimeError::DownloadUnavailable)
        }

        // Returns one exact immutable registry blob probe by requested HTTPS URL.
        fn head(
            &self,
            request: &RuntimeHttpRequest,
        ) -> Result<RuntimeHttpResponse, li_runtime_manager::RuntimeError> {
            self.heads
                .lock()
                .expect("heads")
                .remove(request.url())
                .ok_or(li_runtime_manager::RuntimeError::DownloadUnavailable)
        }

        // Refuses streamed downloads because the external verifier uses bounded metadata reads.
        fn download(
            &self,
            _request: &RuntimeHttpRequest,
            _destination: &Path,
            _maximum_body_bytes: u64,
        ) -> Result<RuntimeHttpDownload, li_runtime_manager::RuntimeError> {
            Err(li_runtime_manager::RuntimeError::DownloadUnavailable)
        }
    }

    // Records exact shell-free requests and returns one deterministic GitHub transcript.
    struct MockCommandRunner {
        responses: Mutex<BTreeMap<Vec<String>, CoreBenchmarkVerificationCommandOutput>>,
        artifact: Vec<u8>,
        attestation_status: i32,
        calls: Mutex<Vec<Vec<String>>>,
        downloads: Mutex<Vec<Vec<String>>>,
    }

    impl MockCommandRunner {
        // Creates one mock from exact argv-to-output mappings and one artifact ZIP.
        fn new(
            responses: BTreeMap<Vec<String>, CoreBenchmarkVerificationCommandOutput>,
            artifact: Vec<u8>,
        ) -> Self {
            Self {
                responses: Mutex::new(responses),
                artifact,
                attestation_status: 0,
                calls: Mutex::new(Vec::new()),
                downloads: Mutex::new(Vec::new()),
            }
        }

        // Selects one deterministic per-file attestation exit status.
        fn with_attestation_status(mut self, status: i32) -> Self {
            self.attestation_status = status;
            self
        }
    }

    impl CoreBenchmarkVerificationCommandRunner for MockCommandRunner {
        // Returns the exact response or accepts one per-file attestation command.
        fn run(
            &self,
            _executable: &Path,
            arguments: &[String],
            _timeout: Duration,
            _maximum_output_bytes: usize,
            use_attestation_token: bool,
        ) -> Result<CoreBenchmarkVerificationCommandOutput, CoreBenchmarkVerificationCommandError>
        {
            self.calls.lock().expect("calls").push(arguments.to_vec());
            if arguments.starts_with(&["attestation".to_string(), "verify".to_string()]) {
                assert!(use_attestation_token);
                return Ok(CoreBenchmarkVerificationCommandOutput::new(
                    self.attestation_status,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            self.responses
                .lock()
                .expect("responses")
                .remove(arguments)
                .ok_or(CoreBenchmarkVerificationCommandError::Unavailable)
        }

        // Writes the deterministic artifact with production-equivalent owner-only mode.
        fn download(
            &self,
            _executable: &Path,
            arguments: &[String],
            destination: &Path,
            _timeout: Duration,
            _maximum_bytes: u64,
        ) -> Result<CoreBenchmarkVerificationCommandOutput, CoreBenchmarkVerificationCommandError>
        {
            self.downloads
                .lock()
                .expect("downloads")
                .push(arguments.to_vec());
            fs::write(destination, &self.artifact)
                .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o600))
                .map_err(|_| CoreBenchmarkVerificationCommandError::Unavailable)?;
            Ok(CoreBenchmarkVerificationCommandOutput::new(
                0,
                Vec::new(),
                Vec::new(),
            ))
        }
    }

    struct BundleFixture {
        _temporary: TempDir,
        root: PathBuf,
        pull_request: PullRequest,
        candidate: RuntimeCandidateId,
    }

    // Returns one complete current schema-6 runtime with a schema-8 benchmark contract.
    fn runtime_value() -> Value {
        json!({
            "schema_version": 6,
            "id": "sglang--radixark--qwen3.8--dgx-spark",
            "version": "1.0.0",
            "logical_model": "qwen3.8",
            "target": {
                "id": "dgx-spark",
                "platform": "linux/arm64",
                "accelerator": {
                    "vendor": "nvidia",
                    "architecture": "sm_121",
                    "count": 1,
                    "partitioning": "full-device"
                },
                "memory": {"topology": "unified", "minimum_total_gib": 64},
                "placement": {
                    "strategy": "single",
                    "node_count": 1,
                    "interconnect": {
                        "kind": "any",
                        "rdma_required": false,
                        "minimum_speed_mbps": 0,
                        "minimum_mtu": 0
                    }
                }
            },
            "engine": {
                "id": "sglang",
                "protocol": {"version": 2},
                "distribution": {
                    "kind": "oci-container",
                    "reference": format!("ghcr.io/letsinferlabs/engine-images@sha256:{}", "3".repeat(64)),
                    "immutable_id": format!("sha256:{}", "4".repeat(64))
                },
                "model_format": "huggingface-snapshot",
                "cache_provider": "fixture-prefix-v1",
                "arguments": ["--context-length", "32768"],
                "environment": {"FIXTURE_MODE": "deterministic"}
            },
            "model": {
                "uri": "hf://RadixArk/Qwen3.8",
                "artifact": "model",
                "acquisition": {
                    "kind": "oci-container",
                    "image": format!("ghcr.io/letsinferlabs/engine-images@sha256:{}", "3".repeat(64))
                }
            },
            "artifacts": [{
                "name": "model",
                "uri": "hf://RadixArk/Qwen3.8",
                "format": "huggingface-snapshot",
                "revision": "7".repeat(40)
            }],
            "container": {
                "memory_bytes": 68719476736_u64,
                "shm_bytes": 8589934592_u64,
                "min_available_gib": 64,
                "runtime_min_available_gib": 4,
                "startup_timeout_seconds": 900,
                "cpuset_cpus": "0-7"
            },
            "cache": {
                "provider": "fixture-prefix-v1",
                "persistent": true,
                "prewarm": true,
                "replay_output_policy": "restored-repeat-exact",
                "config": {"ttl_seconds": 60}
            },
            "serving": {
                "max_connections": 128,
                "max_active_requests": 8,
                "max_context_tokens": 32768,
                "gate": null
            },
            "benchmark": {"contract": {
                "schema_version": 8,
                "suite": "letsinfer-code-prose-v1",
                "generator": {"id": "letsinfer-code-prose", "version": 8},
                "domains": ["code"],
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
                    "require_natural_stop": false,
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
                        "require_natural_stop": false,
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
                    {"id": "64k", "prompt_tokens": 65536, "concurrencies": [1, 2]}
                ]
            }}
        })
    }

    // Builds one exact schema-6 runtime archive with a self-describing file inventory.
    fn runtime_pack(runtime: &Value) -> Vec<u8> {
        let runtime_bytes = canonical_json(runtime).expect("runtime bytes");
        let root = runtime.as_object().expect("runtime object");
        let descriptor = json!({
            "artifact_schema_version": 6,
            "media_type": PACK_MEDIA_TYPE,
            "runtime_sha256": sha256_bytes(&runtime_bytes),
            "candidate": {
                "id": string(root, "id").expect("id"),
                "version": string(root, "version").expect("version"),
                "logical_model": string(root, "logical_model").expect("model"),
                "engine": string(child_object(root, "engine").expect("engine"), "id").expect("engine id"),
                "target": string(child_object(root, "target").expect("target"), "id").expect("target id")
            },
            "files": [{
                "path": "runtime.json",
                "bytes": runtime_bytes.len(),
                "mode": 0o644,
                "sha256": sha256_bytes(&runtime_bytes)
            }]
        });
        let descriptor = canonical_json(&descriptor).expect("descriptor");
        let mut archive = tar::Builder::new(Vec::new());
        append_tar_file(&mut archive, "letsinfer-runtime.json", &descriptor, 0o644);
        append_tar_file(&mut archive, "runtime.json", &runtime_bytes, 0o644);
        archive.finish().expect("finish pack");
        archive.into_inner().expect("pack")
    }

    // Appends one deterministic regular tar entry.
    fn append_tar_file(archive: &mut tar::Builder<Vec<u8>>, name: &str, bytes: &[u8], mode: u32) {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).expect("path");
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        archive
            .append(&header, Cursor::new(bytes))
            .expect("append file");
    }

    // Writes one complete reuse-Engine verifier bundle and its current proposal identity.
    fn bundle_fixture() -> BundleFixture {
        let temporary = tempdir().expect("temporary");
        let root = temporary.path().join("bundle");
        fs::create_dir(&root).expect("bundle root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
        let runtime = runtime_value();
        let pack = runtime_pack(&runtime);
        let pack_sha = sha256_bytes(&pack);
        let candidate =
            RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate");
        let mut subject =
            execution_subject(&runtime, &pack_sha, pack.len() as u64).expect("subject");
        subject.remove("execution_sha256");
        subject.extend([
            ("artifact_schema_version".to_string(), json!(1)),
            ("repository".to_string(), json!(REPOSITORY)),
            ("pull_request".to_string(), json!(123)),
            ("proposal_head_sha".to_string(), json!("a".repeat(40))),
            ("proposal_base_sha".to_string(), json!("b".repeat(40))),
            ("proposal_tree_sha256".to_string(), json!("8".repeat(64))),
            ("engine_mode".to_string(), json!("reuse-engine")),
            ("build_workflow_run_id".to_string(), json!(11)),
        ]);
        let execution =
            sha256_bytes(&canonical_json(&Value::Object(subject.clone())).expect("subject bytes"));
        subject.insert("execution_sha256".to_string(), json!(execution));
        let runtime_root = runtime.as_object().expect("runtime");
        let distribution = child_object(
            child_object(runtime_root, "engine").expect("engine"),
            "distribution",
        )
        .expect("distribution");
        let manifest_digest =
            runtime_oci_manifest_digest(candidate.as_str(), "1.0.0", &pack_sha, pack.len() as u64)
                .expect("manifest");
        let plan = json!({
            "candidate": candidate.as_str(),
            "version": "1.0.0",
            "tag": format!("ghcr.io/letsinferlabs/runtimes/{}:1.0.0", candidate.as_str()),
            "source": format!("ghcr.io/letsinferlabs/runtimes/{}@{}", candidate.as_str(), manifest_digest),
            "manifest_digest": manifest_digest,
            "manifest_bytes": 0,
            "config_digest": format!("sha256:{}", "9".repeat(64)),
            "layer_digest": format!("sha256:{pack_sha}"),
            "layer_bytes": pack.len()
        });
        let engine = json!({
            "mode": "reuse-engine",
            "kind": "oci-container",
            "reference": string(distribution, "reference").expect("reference"),
            "config_digest": string(distribution, "immutable_id").expect("immutable")
        });
        write_private(&root.join("runtime.letsinfer"), &pack);
        write_private(
            &root.join("runtime-plan.json"),
            &canonical_json(&plan).expect("plan"),
        );
        write_private(&root.join("candidate-audit.json"), b"{}\n");
        write_private(&root.join("runtime.spdx.json"), b"{}\n");
        write_private(
            &root.join("provenance.json"),
            &canonical_json(&json!({"subject": subject, "engine": engine})).expect("provenance"),
        );
        let payload_names = [
            "runtime.letsinfer",
            "runtime-plan.json",
            "candidate-audit.json",
            "runtime.spdx.json",
            "provenance.json",
        ];
        let checksums = payload_names
            .iter()
            .map(|name| {
                let bytes = fs::read(root.join(name)).expect("payload");
                (
                    (*name).to_string(),
                    json!({"sha256": sha256_bytes(&bytes), "bytes": bytes.len()}),
                )
            })
            .collect::<Map<_, _>>();
        let checksums = canonical_json(&Value::Object(checksums)).expect("checksums");
        write_private(&root.join("checksums.json"), &checksums);
        let document = json!({
            "schema_version": 1,
            "repository": REPOSITORY,
            "pull_request": 123,
            "proposal_head_sha": "a".repeat(40),
            "proposal_base_sha": "b".repeat(40),
            "proposal_tree_sha256": "8".repeat(64),
            "candidate": candidate.as_str(),
            "runtime_authors": [{"github_login": "Author", "github_id": 41, "github_type": "User"}],
            "mode": "reuse-engine",
            "artifact_name": format!("verification-bundle-pr-123-{}", "a".repeat(40)),
            "build_workflow": {"path": BUILD_PATH, "run_id": 11, "workflow_sha": "b".repeat(40)},
            "finalizer_workflow": {"path": FINALIZER_PATH, "run_id": 12, "workflow_sha": "c".repeat(40)},
            "subject": subject,
            "engine": engine,
            "runtime": plan,
            "checksums_sha256": sha256_bytes(&checksums)
        });
        write_private(
            &root.join("bundle.json"),
            &canonical_json(&document).expect("bundle"),
        );
        BundleFixture {
            _temporary: temporary,
            root,
            pull_request: PullRequest {
                number: 123,
                base_sha: BenchmarkGitRevision::parse(&"b".repeat(40)).expect("base"),
                head_sha: BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
                author: GitHubIdentity {
                    login: "Author".to_string(),
                    numeric_id: 41,
                    account_type: "User".to_string(),
                },
                files: vec![format!("{}/runtime.json", candidate.as_str())],
            },
            candidate,
        }
    }

    // Writes one exact owner-only fixture file.
    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    }

    // Creates a flat regular ZIP from the complete fixture bundle.
    fn bundle_zip(root: &Path) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut archive = zip::ZipWriter::new(cursor);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o600);
        let mut paths = regular_bundle_paths(root).expect("paths");
        paths.sort();
        for path in paths {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .expect("name");
            archive.start_file(name, options).expect("start");
            std::io::copy(&mut File::open(path).expect("source"), &mut archive).expect("copy");
        }
        archive.finish().expect("finish").into_inner()
    }

    // Builds one minimal complete OCI image archive and its derived immutable identities.
    fn engine_archive(path: &Path) -> (String, String, String) {
        let layer = b"exact engine layer".to_vec();
        let layer_digest = format!("sha256:{}", sha256_bytes(&layer));
        let diff_id = layer_digest.clone();
        let config_value = json!({
            "architecture": "arm64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [diff_id]},
            "config": {"Env": ["A=1"], "Cmd": ["/engine"]}
        });
        let config = compact_json(&config_value).expect("config");
        let config_digest = format!("sha256:{}", sha256_bytes(&config));
        let manifest_value = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config.len()
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": layer.len()
            }]
        });
        let manifest = compact_json(&manifest_value).expect("manifest");
        let manifest_digest = format!("sha256:{}", sha256_bytes(&manifest));
        let index = compact_json(&json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": manifest.len(),
                "platform": {"os": "linux", "architecture": "arm64"}
            }]
        }))
        .expect("index");
        let layout = compact_json(&json!({"imageLayoutVersion": "1.0.0"})).expect("layout");
        let mut archive = tar::Builder::new(File::create(path).expect("engine archive"));
        append_file_archive(&mut archive, "oci-layout", &layout);
        append_file_archive(&mut archive, "index.json", &index);
        append_file_archive(
            &mut archive,
            &format!(
                "blobs/sha256/{}",
                config_digest.trim_start_matches("sha256:")
            ),
            &config,
        );
        append_file_archive(
            &mut archive,
            &format!(
                "blobs/sha256/{}",
                manifest_digest.trim_start_matches("sha256:")
            ),
            &manifest,
        );
        append_file_archive(
            &mut archive,
            &format!(
                "blobs/sha256/{}",
                layer_digest.trim_start_matches("sha256:")
            ),
            &layer,
        );
        archive.finish().expect("finish engine");
        let config_object = config_value.as_object().expect("config object");
        let payload =
            engine_payload_digest("linux/arm64", config_object, &[diff_id]).expect("payload");
        (manifest_digest, config_digest, payload)
    }

    // Builds one thin OCI overlay plus exact public-registry responses for its external base.
    fn thin_engine_archive(path: &Path) -> (String, String, String, Arc<MockHttpClient>) {
        let base_layer = b"base layer".to_vec();
        let base_digest = format!("sha256:{}", sha256_bytes(&base_layer));
        let base_diff = base_digest.clone();
        let mut patch_archive = tar::Builder::new(Vec::new());
        append_tar_file(
            &mut patch_archive,
            "opt/letsinfer/engine",
            b"overlay",
            0o755,
        );
        patch_archive.finish().expect("finish patch");
        let patch_layer = patch_archive.into_inner().expect("patch");
        let patch_digest = format!("sha256:{}", sha256_bytes(&patch_layer));
        let patch_diff = patch_digest.clone();
        let base_config = compact_json(&json!({
            "architecture": "arm64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [base_diff]}
        }))
        .expect("base config");
        let base_config_digest = format!("sha256:{}", sha256_bytes(&base_config));
        let base_manifest = compact_json(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": base_config_digest,
                "size": base_config.len()
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": base_digest,
                "size": base_layer.len()
            }]
        }))
        .expect("base manifest");
        let base_manifest_digest = format!("sha256:{}", sha256_bytes(&base_manifest));
        let source_reference = format!("registry.example/base@{base_manifest_digest}");
        let target_config = compact_json(&json!({
            "architecture": "arm64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [base_diff, patch_diff]},
            "config": {"Cmd": ["/opt/letsinfer/engine"]}
        }))
        .expect("target config");
        let target_config_digest = format!("sha256:{}", sha256_bytes(&target_config));
        let target_manifest = compact_json(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": target_config_digest,
                "size": target_config.len()
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": base_digest,
                    "size": base_layer.len()
                },
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": patch_digest,
                    "size": patch_layer.len()
                }
            ]
        }))
        .expect("target manifest");
        let target_manifest_digest = format!("sha256:{}", sha256_bytes(&target_manifest));
        let target_reference = format!("registry.example/target@{target_manifest_digest}");
        let index = compact_json(&json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": target_manifest_digest,
                "size": target_manifest.len(),
                "platform": {"os": "linux", "architecture": "arm64"}
            }]
        }))
        .expect("index");
        let inventory = canonical_json(&json!({
            "schema_version": 1,
            "source_reference": source_reference,
            "target_repository": "registry.example/target",
            "manifest_digest": target_manifest_digest,
            "layers": [{
                "index": 0,
                "digest": base_digest,
                "size": base_layer.len(),
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "diff_id": base_diff
            }]
        }))
        .expect("inventory");
        let layout = compact_json(&json!({"imageLayoutVersion": "1.0.0"})).expect("layout");
        let mut archive = tar::Builder::new(File::create(path).expect("archive"));
        append_file_archive(&mut archive, "oci-layout", &layout);
        append_file_archive(&mut archive, "index.json", &index);
        append_file_archive(
            &mut archive,
            &format!(
                "blobs/sha256/{}",
                target_config_digest.trim_start_matches("sha256:")
            ),
            &target_config,
        );
        append_file_archive(
            &mut archive,
            &format!(
                "blobs/sha256/{}",
                target_manifest_digest.trim_start_matches("sha256:")
            ),
            &target_manifest,
        );
        append_file_archive(
            &mut archive,
            &format!(
                "blobs/sha256/{}",
                patch_digest.trim_start_matches("sha256:")
            ),
            &patch_layer,
        );
        append_file_archive(&mut archive, "letsinfer-external-blobs.json", &inventory);
        archive.finish().expect("finish");
        let registry = "https://registry.example/v2/base";
        let gets = BTreeMap::from([
            (
                format!("{registry}/manifests/{base_manifest_digest}"),
                http_response(
                    &format!("{registry}/manifests/{base_manifest_digest}"),
                    base_manifest,
                ),
            ),
            (
                format!("{registry}/blobs/{base_config_digest}"),
                http_response(
                    &format!("{registry}/blobs/{base_config_digest}"),
                    base_config,
                ),
            ),
        ]);
        let blob_url = format!("{registry}/blobs/{base_digest}");
        let heads = BTreeMap::from([(
            blob_url.clone(),
            RuntimeHttpResponse::new(
                200,
                blob_url,
                BTreeMap::from([("content-length".to_string(), base_layer.len().to_string())]),
                Vec::new(),
                false,
            )
            .expect("HEAD"),
        )]);
        (
            target_manifest_digest,
            target_config_digest,
            target_reference,
            Arc::new(MockHttpClient {
                gets: Mutex::new(gets),
                heads: Mutex::new(heads),
            }),
        )
    }

    // Returns one successful bounded HTTPS registry response.
    fn http_response(url: &str, body: Vec<u8>) -> RuntimeHttpResponse {
        RuntimeHttpResponse::new(200, url.to_string(), BTreeMap::new(), body, false)
            .expect("response")
    }

    // Appends one deterministic regular entry to a file-backed tar archive.
    fn append_file_archive(archive: &mut tar::Builder<File>, name: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).expect("path");
        header.set_mode(0o600);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        archive.append(&header, Cursor::new(bytes)).expect("append");
    }

    // Returns one exact successful GitHub CLI response.
    fn output(value: Value) -> CoreBenchmarkVerificationCommandOutput {
        CoreBenchmarkVerificationCommandOutput::new(
            0,
            serde_json::to_vec(&value).expect("JSON"),
            Vec::new(),
        )
    }

    // Returns the complete successful GitHub transcript for one proposal.
    fn github_responses() -> BTreeMap<Vec<String>, CoreBenchmarkVerificationCommandOutput> {
        let mut responses = BTreeMap::new();
        responses.insert(
            vec!["--version".to_string()],
            CoreBenchmarkVerificationCommandOutput::new(
                0,
                b"gh version 2.97.0 (test)\n".to_vec(),
                Vec::new(),
            ),
        );
        responses.insert(
            vec!["auth", "status", "--hostname", "github.com"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            CoreBenchmarkVerificationCommandOutput::new(0, Vec::new(), Vec::new()),
        );
        responses.insert(
            vec!["api", "user"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            output(json!({"login": "Verifier", "id": 99, "type": "User"})),
        );
        let fields = "number,url,state,baseRefName,baseRefOid,headRefOid,author,files,labels";
        responses.insert(
            vec![
                "pr".to_string(),
                "view".to_string(),
                "https://github.com/letsinferlabs/runtimes/pull/123".to_string(),
                "--repo".to_string(),
                REPOSITORY.to_string(),
                "--json".to_string(),
                fields.to_string(),
            ],
            output(json!({
                "number": 123,
                "url": "https://github.com/letsinferlabs/runtimes/pull/123",
                "state": "OPEN",
                "baseRefName": "main",
                "baseRefOid": "b".repeat(40),
                "headRefOid": "a".repeat(40),
                "author": {"login": "Author"},
                "files": [{"path": "sglang--radixark--qwen3.8--dgx-spark/runtime.json"}],
                "labels": [{"name": BENCHMARK_READY_LABEL}]
            })),
        );
        responses.insert(
            vec!["api", "users/Author"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            output(json!({"login": "Author", "id": 41, "type": "User"})),
        );
        let artifact_name = format!("verification-bundle-pr-123-{}", "a".repeat(40));
        responses.insert(
            vec![
                "api".to_string(),
                format!("repos/{REPOSITORY}/actions/artifacts?name={artifact_name}&per_page=100"),
            ],
            output(json!({"artifacts": [{
                "name": artifact_name,
                "expired": false,
                "id": 44,
                "workflow_run": {"id": 12}
            }]})),
        );
        responses.insert(
            vec![
                "api".to_string(),
                format!("repos/{REPOSITORY}/actions/runs/12"),
            ],
            output(json!({
                "event": "workflow_run",
                "path": FINALIZER_PATH,
                "conclusion": "success",
                "head_branch": "main",
                "head_sha": "c".repeat(40)
            })),
        );
        responses.insert(
            vec![
                "api".to_string(),
                format!("repos/{REPOSITORY}/actions/runs/11"),
            ],
            output(json!({
                "event": "workflow_run",
                "path": BUILD_PATH,
                "conclusion": "success",
                "head_branch": "main",
                "head_sha": "b".repeat(40)
            })),
        );
        responses
    }

    // Returns the exact pull-request query argv used by the production oracle.
    fn pull_request_arguments() -> Vec<String> {
        vec![
            "pr".to_string(),
            "view".to_string(),
            "https://github.com/letsinferlabs/runtimes/pull/123".to_string(),
            "--repo".to_string(),
            REPOSITORY.to_string(),
            "--json".to_string(),
            "number,url,state,baseRefName,baseRefOid,headRefOid,author,files,labels".to_string(),
        ]
    }

    // Returns one exact valid pull-request response for independent field mutation.
    fn pull_request_response() -> Value {
        json!({
            "number": 123,
            "url": "https://github.com/letsinferlabs/runtimes/pull/123",
            "state": "OPEN",
            "baseRefName": "main",
            "baseRefOid": "b".repeat(40),
            "headRefOid": "a".repeat(40),
            "author": {"login": "Author"},
            "files": [{"path": "sglang--radixark--qwen3.8--dgx-spark/runtime.json"}],
            "labels": [{"name": BENCHMARK_READY_LABEL}]
        })
    }

    // Creates one production oracle over a deterministic command runner and private root.
    fn oracle(runner: Arc<MockCommandRunner>) -> (TempDir, SystemCoreBenchmarkVerificationOracle) {
        let temporary = tempdir().expect("temporary");
        let root = temporary.path().join("oracle");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
        let owner = fs::symlink_metadata(&root).expect("metadata").uid();
        let oracle = SystemCoreBenchmarkVerificationOracle::new(
            PathBuf::from("/usr/bin/gh"),
            root,
            owner,
            Sha256Digest::parse(&"d".repeat(64)).expect("device"),
            runner,
            Arc::new(RejectHttpClient),
        )
        .expect("oracle");
        (temporary, oracle)
    }

    #[test]
    // Resolves the exact ready PR through every GitHub, attestation, bundle, and workflow gate.
    fn production_oracle_accepts_one_complete_trusted_finalizer_bundle() {
        let fixture = bundle_fixture();
        let runner = Arc::new(MockCommandRunner::new(
            github_responses(),
            bundle_zip(&fixture.root),
        ));
        let (_temporary, oracle) = oracle(runner.clone());
        let proposal = oracle
            .resolve_verified("https://github.com/letsinferlabs/runtimes/pull/123")
            .expect("proposal");
        assert_eq!(proposal.pull_request(), 123);
        assert_eq!(proposal.candidate(), &fixture.candidate);
        assert_eq!(proposal.verifier_numeric_id(), 99);
        assert!(proposal.is_ready());
        let calls = runner.calls.lock().expect("calls");
        assert_eq!(
            calls
                .iter()
                .filter(|arguments| arguments
                    .first()
                    .is_some_and(|value| value == "attestation"))
                .count(),
            7
        );
        assert_eq!(runner.downloads.lock().expect("downloads").len(), 1);
    }

    #[test]
    // Rejects a GitHub CLI predating the attestation security fix before any API request.
    fn production_oracle_rejects_github_cli_before_minimum_version() {
        let fixture = bundle_fixture();
        let mut responses = github_responses();
        responses.insert(
            vec!["--version".to_string()],
            CoreBenchmarkVerificationCommandOutput::new(
                0,
                b"gh version 2.96.0 (test)\n".to_vec(),
                Vec::new(),
            ),
        );
        let runner = Arc::new(MockCommandRunner::new(responses, bundle_zip(&fixture.root)));
        let (_temporary, oracle) = oracle(runner.clone());
        assert_eq!(
            oracle.resolve_verified("https://github.com/letsinferlabs/runtimes/pull/123"),
            Err(CoreBenchmarkVerificationOracleError::ProposalInvalid)
        );
        assert_eq!(runner.calls.lock().expect("calls").len(), 1);
    }

    #[test]
    // Rejects PR state, base, head, author, file, and readiness-label drift before artifact lookup.
    fn production_oracle_rejects_each_pull_request_identity_boundary() {
        let fixture = bundle_fixture();
        let mutations = [
            ("state", json!("CLOSED")),
            ("baseRefName", json!("release")),
            ("baseRefOid", json!("B".repeat(40))),
            ("headRefOid", json!("short")),
            ("author", json!({"login": ""})),
            ("files", json!([{"path": "bad\npath/runtime.json"}])),
            ("labels", json!([])),
        ];
        for (field, value) in mutations {
            let mut response = pull_request_response();
            response[field] = value;
            let mut responses = github_responses();
            responses.insert(pull_request_arguments(), output(response));
            let runner = Arc::new(MockCommandRunner::new(responses, bundle_zip(&fixture.root)));
            let (_temporary, oracle) = oracle(runner);
            assert_eq!(
                oracle.resolve_verified("https://github.com/letsinferlabs/runtimes/pull/123"),
                Err(CoreBenchmarkVerificationOracleError::ProposalInvalid),
                "{field}"
            );
        }
    }

    #[test]
    // Rejects absent or duplicate exact artifacts and an untrusted finalizer before extraction.
    fn production_oracle_rejects_artifact_ambiguity_and_finalizer_drift() {
        let fixture = bundle_fixture();
        let artifact_name = format!("verification-bundle-pr-123-{}", "a".repeat(40));
        let artifact_arguments = vec![
            "api".to_string(),
            format!("repos/{REPOSITORY}/actions/artifacts?name={artifact_name}&per_page=100"),
        ];
        for artifacts in [
            json!([]),
            json!([
                {"name": artifact_name, "expired": false, "id": 44, "workflow_run": {"id": 12}},
                {"name": artifact_name, "expired": false, "id": 45, "workflow_run": {"id": 13}}
            ]),
        ] {
            let mut responses = github_responses();
            responses.insert(
                artifact_arguments.clone(),
                output(json!({"artifacts": artifacts})),
            );
            let runner = Arc::new(MockCommandRunner::new(responses, bundle_zip(&fixture.root)));
            let (_temporary, oracle) = oracle(runner);
            assert_eq!(
                oracle.resolve_verified("https://github.com/letsinferlabs/runtimes/pull/123"),
                Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid)
            );
        }
        let mut responses = github_responses();
        responses.insert(
            vec![
                "api".to_string(),
                format!("repos/{REPOSITORY}/actions/runs/12"),
            ],
            output(json!({
                "event": "pull_request",
                "path": FINALIZER_PATH,
                "conclusion": "success",
                "head_branch": "main",
                "head_sha": "c".repeat(40)
            })),
        );
        let runner = Arc::new(MockCommandRunner::new(responses, bundle_zip(&fixture.root)));
        let (_temporary, oracle) = oracle(runner);
        assert_eq!(
            oracle.resolve_verified("https://github.com/letsinferlabs/runtimes/pull/123"),
            Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid)
        );
    }

    #[test]
    // Rejects the complete bundle when any required finalizer-certificate attestation fails.
    fn production_oracle_requires_each_file_attestation() {
        let fixture = bundle_fixture();
        let runner = Arc::new(
            MockCommandRunner::new(github_responses(), bundle_zip(&fixture.root))
                .with_attestation_status(1),
        );
        let (_temporary, oracle) = oracle(runner.clone());
        assert_eq!(
            oracle.resolve_verified("https://github.com/letsinferlabs/runtimes/pull/123"),
            Err(CoreBenchmarkVerificationOracleError::CommandFailed)
        );
        let calls = runner.calls.lock().expect("calls");
        let attestation = calls
            .iter()
            .find(|arguments| {
                arguments
                    .first()
                    .is_some_and(|value| value == "attestation")
            })
            .expect("attestation");
        assert!(attestation
            .windows(2)
            .any(|values| { values == ["--cert-identity", FINALIZER_CERTIFICATE_IDENTITY] }));
    }

    #[test]
    // Rejects missing readiness, invalid candidate paths, and ambiguous candidate changes.
    fn pull_request_candidate_and_label_gates_fail_closed() {
        let pull_request = PullRequest {
            number: 123,
            base_sha: BenchmarkGitRevision::parse(&"b".repeat(40)).expect("base"),
            head_sha: BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
            author: GitHubIdentity {
                login: "Author".to_string(),
                numeric_id: 41,
                account_type: "User".to_string(),
            },
            files: vec!["invalid-top/runtime.json".to_string()],
        };
        assert_eq!(
            select_candidate(&pull_request, None),
            Err(CoreBenchmarkVerificationOracleError::ProposalInvalid)
        );
        let mut ambiguous = pull_request;
        ambiguous.files = vec![
            "a--b--c--d/runtime.json".to_string(),
            "e--f--g--h/runtime.json".to_string(),
        ];
        assert_eq!(
            select_candidate(&ambiguous, None),
            Err(CoreBenchmarkVerificationOracleError::ProposalInvalid)
        );
    }

    #[test]
    // Rejects payload tampering independently at checksum, runtime-plan, provenance, and Engine gates.
    fn complete_bundle_is_tamper_evident_at_each_semantic_boundary() {
        let fixture = bundle_fixture();
        validate_bundle(
            &fixture.root,
            &fixture.pull_request,
            &fixture.candidate,
            &RejectHttpClient,
        )
        .expect("valid bundle");
        for name in [
            "candidate-audit.json",
            "runtime-plan.json",
            "provenance.json",
            "runtime.letsinfer",
        ] {
            let fixture = bundle_fixture();
            write_private(&fixture.root.join(name), b"{\"tampered\":true}\n");
            assert_eq!(
                validate_bundle(
                    &fixture.root,
                    &fixture.pull_request,
                    &fixture.candidate,
                    &RejectHttpClient,
                )
                .map(|_| ()),
                Err(CoreBenchmarkVerificationOracleError::BundleInvalid),
                "{name}"
            );
        }
        let fixture = bundle_fixture();
        let mut bundle = parse_file_object(&fixture.root.join("bundle.json")).expect("bundle");
        bundle["engine"] = json!({"kind": "oci-container", "reference": "changed"});
        write_private(
            &fixture.root.join("bundle.json"),
            &canonical_json(&Value::Object(bundle)).expect("bundle bytes"),
        );
        assert_eq!(
            validate_bundle(
                &fixture.root,
                &fixture.pull_request,
                &fixture.candidate,
                &RejectHttpClient,
            )
            .map(|_| ()),
            Err(CoreBenchmarkVerificationOracleError::BundleInvalid)
        );
    }

    #[test]
    // Rejects nested artifact paths before writing any attacker-selected destination.
    fn artifact_extraction_rejects_non_flat_paths() {
        let temporary = tempdir().expect("temporary");
        let archive_path = temporary.path().join("artifact.zip");
        let mut archive = zip::ZipWriter::new(File::create(&archive_path).expect("archive"));
        archive
            .start_file("nested/bundle.json", SimpleFileOptions::default())
            .expect("entry");
        std::io::Write::write_all(&mut archive, b"{}\n").expect("write");
        archive.finish().expect("finish");
        let destination = temporary.path().join("bundle");
        let owner = fs::symlink_metadata(temporary.path())
            .expect("metadata")
            .uid();
        assert_eq!(
            extract_artifact(&archive_path, &destination, owner),
            Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid)
        );
    }

    #[test]
    // Requires exact trusted-finalizer and untrusted-builder run bindings.
    fn workflow_run_bindings_reject_path_head_and_event_drift() {
        let base = BenchmarkGitRevision::parse(&"b".repeat(40)).expect("base");
        let identity = json!({"workflow_sha": "b".repeat(40)})
            .as_object()
            .expect("identity")
            .clone();
        let valid = json!({
            "event": "workflow_run",
            "path": BUILD_PATH,
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": "b".repeat(40)
        });
        validate_build_binding(&identity, &valid, &base).expect("valid build");
        for (field, value) in [
            ("event", json!("pull_request")),
            ("path", json!(".github/workflows/other.yml")),
            ("head_sha", json!("a".repeat(40))),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert_eq!(
                validate_build_binding(&identity, &changed, &base),
                Err(CoreBenchmarkVerificationOracleError::ArtifactInvalid)
            );
        }
    }

    #[test]
    // Derives and verifies exact OCI manifest, configuration, layer, platform, and payload identity.
    fn built_engine_archive_is_verified_from_its_complete_oci_closure() {
        let temporary = tempdir().expect("temporary");
        let archive = temporary.path().join("engine.oci.tar");
        let (manifest, config, payload) = engine_archive(&archive);
        let reference = format!("ghcr.io/letsinferlabs/engine@{manifest}");
        let identity = inspect_engine_archive(
            &archive,
            &manifest,
            &config,
            "linux/arm64",
            &reference,
            &RejectHttpClient,
        )
        .expect("identity");
        assert_eq!(identity.get("manifest_digest"), Some(&json!(manifest)));
        assert_eq!(identity.get("config_digest"), Some(&json!(config)));
        assert_eq!(identity.get("payload_digest"), Some(&json!(payload)));
        assert_eq!(identity.get("local_layer_count"), Some(&json!(1)));
        assert_eq!(
            inspect_engine_archive(
                &archive,
                &format!("sha256:{}", "0".repeat(64)),
                &config,
                "linux/arm64",
                &reference,
                &RejectHttpClient,
            ),
            Err(CoreBenchmarkVerificationOracleError::BundleInvalid)
        );
    }

    #[test]
    // Verifies thin OCI external layers against their immutable registry source and local overlay.
    fn thin_engine_archive_binds_external_base_and_normalized_overlay() {
        let temporary = tempdir().expect("temporary");
        let archive = temporary.path().join("engine.oci.tar");
        let (manifest, config, reference, http) = thin_engine_archive(&archive);
        let identity = inspect_engine_archive(
            &archive,
            &manifest,
            &config,
            "linux/arm64",
            &reference,
            http.as_ref(),
        )
        .expect("identity");
        assert_eq!(identity.get("external_layer_count"), Some(&json!(1)));
        assert_eq!(identity.get("local_layer_count"), Some(&json!(1)));
        assert!(identity
            .get("external_reference")
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with("registry.example/base@sha256:")));
        assert!(identity
            .get("payload_digest")
            .and_then(Value::as_str)
            .is_some_and(valid_prefixed_digest));
    }

    #[test]
    // Accepts only a native Engine bundle whose platform, source revision, and payload all match.
    fn native_engine_identity_is_bound_without_an_oci_archive() {
        let temporary = tempdir().expect("temporary");
        let candidate =
            RuntimeCandidateId::parse("llamacpp--qwen--qwen3--macos-apple").expect("candidate");
        let pull_request = PullRequest {
            number: 123,
            base_sha: BenchmarkGitRevision::parse(&"b".repeat(40)).expect("base"),
            head_sha: BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
            author: GitHubIdentity {
                login: "Author".to_string(),
                numeric_id: 41,
                account_type: "User".to_string(),
            },
            files: Vec::new(),
        };
        let runtime = json!({
            "target": {"platform": "macos/arm64"},
            "engine": {"distribution": {
                "kind": "native-archive",
                "platform": "macos/arm64",
                "payload_id": format!("sha256:{}", "8".repeat(64)),
                "source_revision": "9".repeat(40)
            }}
        });
        let engine = json!({
            "kind": "native-archive",
            "platform": "macos/arm64",
            "payload_digest": format!("sha256:{}", "8".repeat(64)),
            "source_revision": "9".repeat(40)
        });
        validate_engine(
            temporary.path(),
            "build-native-engine",
            &runtime,
            engine.as_object().expect("engine"),
            &candidate,
            &pull_request,
            &RejectHttpClient,
        )
        .expect("native identity");
        let mut changed = engine;
        changed["source_revision"] = json!("7".repeat(40));
        assert_eq!(
            validate_engine(
                temporary.path(),
                "build-native-engine",
                &runtime,
                changed.as_object().expect("engine"),
                &candidate,
                &pull_request,
                &RejectHttpClient,
            ),
            Err(CoreBenchmarkVerificationOracleError::BundleInvalid)
        );
    }
}
