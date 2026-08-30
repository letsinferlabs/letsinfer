// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use li_benchmark_manager::{
    BenchmarkGitRevision, BenchmarkKind, BenchmarkRequest, BenchmarkScope, BenchmarkSubject,
};
use li_core_interface::{OperationId, RuntimeCandidateId, Sha256Digest};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::CoreBenchmarkVerificationCandidate;

const AUTHORITY_LIFETIME_MILLISECONDS: u64 = 15 * 60 * 1_000;
const MAXIMUM_PULL_REQUEST_URL_BYTES: usize = 512;

// Describes one stable preparation failure without repository credentials or provider details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreBenchmarkVerificationPreparationError {
    InvalidInput,
    Unavailable,
    Conflict,
    InvalidAuthority,
}

impl fmt::Display for CoreBenchmarkVerificationPreparationError {
    // Presents one bounded failure without URL, account, filesystem, or signature material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("benchmark verification preparation failed")
    }
}

impl Error for CoreBenchmarkVerificationPreparationError {}

// Carries the closed result of the credential-owning trusted-finalizer oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreBenchmarkVerificationProposal {
    pull_request: u64,
    proposal_head: BenchmarkGitRevision,
    candidate: RuntimeCandidateId,
    verifier_numeric_id: u64,
    device_id: Sha256Digest,
    baseline_execution_sha256: Option<Sha256Digest>,
    verifier_bundle_sha256: Sha256Digest,
    open: bool,
    benchmark_ready: bool,
    verifier_bundle_verified: bool,
    trusted_candidate: Option<CoreBenchmarkVerificationCandidate>,
}

impl CoreBenchmarkVerificationProposal {
    // Creates one closed oracle result after external finalizer and account verification.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        pull_request: u64,
        proposal_head: BenchmarkGitRevision,
        candidate: RuntimeCandidateId,
        verifier_numeric_id: u64,
        device_id: Sha256Digest,
        baseline_execution_sha256: Option<Sha256Digest>,
        verifier_bundle_sha256: Sha256Digest,
        open: bool,
        benchmark_ready: bool,
        verifier_bundle_verified: bool,
    ) -> Self {
        Self {
            pull_request,
            proposal_head,
            candidate,
            verifier_numeric_id,
            device_id,
            baseline_execution_sha256,
            verifier_bundle_sha256,
            open,
            benchmark_ready,
            verifier_bundle_verified,
            trusted_candidate: None,
        }
    }

    // Attaches the fully verified resident-only candidate closure after durable bundle retention.
    pub fn with_trusted_candidate(mut self, candidate: CoreBenchmarkVerificationCandidate) -> Self {
        self.trusted_candidate = Some(candidate);
        self
    }

    // Returns the verified candidate closure without exposing it to wire serialization.
    pub const fn trusted_candidate(&self) -> Option<&CoreBenchmarkVerificationCandidate> {
        self.trusted_candidate.as_ref()
    }

    // Returns the exact public pull-request number resolved by the oracle.
    pub const fn pull_request(&self) -> u64 {
        self.pull_request
    }

    // Returns the immutable proposal head revision bound by the trusted finalizer.
    pub const fn proposal_head(&self) -> &BenchmarkGitRevision {
        &self.proposal_head
    }

    // Returns the one exact changed runtime candidate selected for verification.
    pub const fn candidate(&self) -> &RuntimeCandidateId {
        &self.candidate
    }

    // Returns the authenticated verifier's immutable numeric GitHub identity.
    pub const fn verifier_numeric_id(&self) -> u64 {
        self.verifier_numeric_id
    }

    // Returns the local verifier device's public stable digest identity.
    pub const fn device_id(&self) -> &Sha256Digest {
        &self.device_id
    }

    // Returns the attested bundle document's exact SHA-256 identity.
    pub const fn verifier_bundle_sha256(&self) -> &Sha256Digest {
        &self.verifier_bundle_sha256
    }

    // Returns whether the complete source, label, artifact, and workflow authority is ready.
    pub const fn is_ready(&self) -> bool {
        self.open && self.benchmark_ready && self.verifier_bundle_verified
    }
}

// Resolves one exact public PR through a credential-owning boundary outside BenchmarkManager.
pub trait CoreBenchmarkVerificationOracle: Send + Sync {
    // Returns only closed verified identities and never a token, header, or network client.
    fn resolve(
        &self,
        pull_request_url: &str,
    ) -> Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationPreparationError>;

    // Resolves an optional exact changed candidate or preserves the unambiguous default behavior.
    fn resolve_candidate(
        &self,
        pull_request_url: &str,
        requested_candidate: Option<&RuntimeCandidateId>,
    ) -> Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationPreparationError> {
        if requested_candidate.is_some() {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidInput);
        }
        self.resolve(pull_request_url)
    }
}

// Resolves the exact installed runtime subject selected by the finalized candidate.
pub trait CoreBenchmarkVerificationSubjectResolver: Send + Sync {
    // Returns one immutable local subject only when candidate and target match this node.
    fn resolve(
        &self,
        candidate: &RuntimeCandidateId,
    ) -> Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError>;
}

// Signs exact authority payload bytes without exposing private-key material.
pub trait CoreBenchmarkVerificationSnapshotSigner: Send + Sync {
    // Returns the pinned public-key digest and raw Ed25519 signature.
    fn sign(
        &self,
        payload: &[u8],
    ) -> Result<(Sha256Digest, Vec<u8>), CoreBenchmarkVerificationPreparationError>;
}

// Atomically publishes one request-addressed authority snapshot.
pub trait CoreBenchmarkVerificationSnapshotPublisher: Send + Sync {
    // Creates or exactly replaces one bounded snapshot without following caller paths.
    fn publish(
        &self,
        request_sha256: &Sha256Digest,
        document: &[u8],
    ) -> Result<PathBuf, CoreBenchmarkVerificationPreparationError>;
}

// Publishes owner-private authority snapshots beneath one explicit safe root.
pub struct SystemCoreBenchmarkVerificationSnapshotPublisher {
    root: PathBuf,
    owner_user_id: u32,
}

impl SystemCoreBenchmarkVerificationSnapshotPublisher {
    // Creates one publisher rooted at an absolute normal directory.
    pub fn new(
        root: PathBuf,
        owner_user_id: u32,
    ) -> Result<Self, CoreBenchmarkVerificationPreparationError> {
        if !safe_root(&root) || owner_user_id == u32::MAX {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidInput);
        }
        validate_private_root(&root, owner_user_id)?;
        Ok(Self {
            root,
            owner_user_id,
        })
    }
}

impl CoreBenchmarkVerificationSnapshotPublisher
    for SystemCoreBenchmarkVerificationSnapshotPublisher
{
    // Writes, syncs, and renames one private temporary file into its deterministic identity.
    fn publish(
        &self,
        request_sha256: &Sha256Digest,
        document: &[u8],
    ) -> Result<PathBuf, CoreBenchmarkVerificationPreparationError> {
        if document.is_empty() || document.len() > 128 * 1024 {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority);
        }
        validate_private_root(&self.root, self.owner_user_id)?;
        let destination = self
            .root
            .join(format!("{}.authority.json", request_sha256.as_str()));
        let temporary = self.root.join(format!(
            ".{}.{}.authority.tmp",
            request_sha256.as_str(),
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(&temporary)
            .map_err(|_| CoreBenchmarkVerificationPreparationError::Unavailable)?;
        file.write_all(document)
            .and_then(|_| file.sync_all())
            .map_err(|_| CoreBenchmarkVerificationPreparationError::Unavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| CoreBenchmarkVerificationPreparationError::Unavailable)?;
        if !metadata.is_file()
            || metadata.uid() != self.owner_user_id
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() != document.len() as u64
        {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority);
        }
        fs::rename(&temporary, &destination)
            .map_err(|_| CoreBenchmarkVerificationPreparationError::Unavailable)?;
        Ok(destination)
    }
}

// Carries one exact request and its published credential-free authority snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCoreBenchmarkVerification {
    request: BenchmarkRequest,
    authority_file: PathBuf,
    candidate: CoreBenchmarkVerificationCandidate,
}

impl PreparedCoreBenchmarkVerification {
    // Returns the exact complete verification request ready for Node admission.
    pub const fn request(&self) -> &BenchmarkRequest {
        &self.request
    }
    // Returns the deterministic authority snapshot consumed during admission.
    pub fn authority_file(&self) -> &Path {
        &self.authority_file
    }

    // Returns the resident-only candidate bytes and typed Runtime closure verified by the oracle.
    pub const fn candidate(&self) -> &CoreBenchmarkVerificationCandidate {
        &self.candidate
    }

    // Creates one prepared fixture only inside this crate's deterministic test builds.
    #[cfg(test)]
    pub(crate) fn test_fixture(
        request: BenchmarkRequest,
        candidate: CoreBenchmarkVerificationCandidate,
    ) -> Self {
        Self {
            request,
            authority_file: PathBuf::from("/test/authority.json"),
            candidate,
        }
    }
}

// Carries one closed proposal and retained trusted candidate before Node-owned handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedCoreBenchmarkVerification {
    proposal: CoreBenchmarkVerificationProposal,
}

impl ResolvedCoreBenchmarkVerification {
    // Creates one resolved fixture only inside this crate's deterministic test builds.
    #[cfg(test)]
    pub(crate) const fn test_fixture(proposal: CoreBenchmarkVerificationProposal) -> Self {
        Self { proposal }
    }
    // Returns the fully verified resident-only candidate closure for Node handoff.
    pub fn candidate(&self) -> &CoreBenchmarkVerificationCandidate {
        self.proposal
            .trusted_candidate()
            .expect("resolved verification always contains a trusted candidate")
    }

    // Returns the exact public pull-request number.
    pub const fn pull_request(&self) -> u64 {
        self.proposal.pull_request
    }

    // Returns the immutable proposal head revision.
    pub const fn proposal_head(&self) -> &BenchmarkGitRevision {
        &self.proposal.proposal_head
    }

    // Returns the selected runtime candidate identity.
    pub const fn candidate_id(&self) -> &RuntimeCandidateId {
        &self.proposal.candidate
    }

    // Derives the Node-owned handoff transaction from proposal, bundle, and exact baseline.
    pub fn transaction_id(
        &self,
        baseline: &BenchmarkSubject,
    ) -> Result<OperationId, CoreBenchmarkVerificationPreparationError> {
        let mut digest = Sha256::new();
        let pull_request = self.proposal.pull_request.to_string();
        for value in [
            "li-core-benchmark-verification-transaction-v1",
            pull_request.as_str(),
            self.proposal.proposal_head.as_str(),
            self.proposal.candidate.as_str(),
            self.proposal.verifier_bundle_sha256.as_str(),
            baseline.installation_id().as_str(),
            baseline.runtime_installation_id().as_str(),
            baseline.placement_group_id().as_str(),
            baseline.execution_sha256().as_str(),
            baseline.benchmark_contract_sha256().as_str(),
            baseline.target_contract_sha256().as_str(),
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        let value = format!("{:x}", digest.finalize());
        OperationId::parse(&value[..32])
            .map_err(|_| CoreBenchmarkVerificationPreparationError::InvalidAuthority)
    }
}

// Resolves, binds, signs, and atomically publishes one exact community verification request.
pub struct CoreBenchmarkVerificationPreparation {
    oracle: Arc<dyn CoreBenchmarkVerificationOracle>,
    subject: Arc<dyn CoreBenchmarkVerificationSubjectResolver>,
    signer: Arc<dyn CoreBenchmarkVerificationSnapshotSigner>,
    publisher: Arc<dyn CoreBenchmarkVerificationSnapshotPublisher>,
}

impl CoreBenchmarkVerificationPreparation {
    // Creates one shell-free capability from explicit credential, subject, signing, and storage ports.
    pub const fn new(
        oracle: Arc<dyn CoreBenchmarkVerificationOracle>,
        subject: Arc<dyn CoreBenchmarkVerificationSubjectResolver>,
        signer: Arc<dyn CoreBenchmarkVerificationSnapshotSigner>,
        publisher: Arc<dyn CoreBenchmarkVerificationSnapshotPublisher>,
    ) -> Self {
        Self {
            oracle,
            subject,
            signer,
            publisher,
        }
    }

    // Prepares one URL-selected proposal at an injected trusted wall-clock instant.
    pub fn prepare(
        &self,
        pull_request_url: &str,
        issued_at_unix_milliseconds: u64,
    ) -> Result<PreparedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError> {
        self.prepare_candidate(pull_request_url, None, issued_at_unix_milliseconds)
    }

    // Prepares one URL-selected proposal with an optional exact changed-candidate identity.
    pub fn prepare_candidate(
        &self,
        pull_request_url: &str,
        requested_candidate: Option<&RuntimeCandidateId>,
        issued_at_unix_milliseconds: u64,
    ) -> Result<PreparedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError> {
        let resolved = self.resolve_candidate(pull_request_url, requested_candidate)?;
        let subject = self.subject.resolve(resolved.candidate_id())?;
        self.authorize(
            resolved,
            subject.clone(),
            &subject,
            issued_at_unix_milliseconds,
        )
    }

    // Resolves and verifies one candidate bundle before any Runtime or Placement mutation.
    pub fn resolve_candidate(
        &self,
        pull_request_url: &str,
        requested_candidate: Option<&RuntimeCandidateId>,
    ) -> Result<ResolvedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError> {
        let requested_pull_request = validate_pull_request_url(pull_request_url)?;
        let proposal = self
            .oracle
            .resolve_candidate(pull_request_url, requested_candidate)?;
        if proposal.pull_request != requested_pull_request
            || proposal.verifier_numeric_id == 0
            || !proposal.open
            || !proposal.benchmark_ready
            || !proposal.verifier_bundle_verified
            || requested_candidate.is_some_and(|candidate| candidate != &proposal.candidate)
        {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority);
        }
        let trusted_candidate = proposal
            .trusted_candidate
            .clone()
            .ok_or(CoreBenchmarkVerificationPreparationError::InvalidAuthority)?;
        if trusted_candidate.runtime().runtime().candidate_id() != &proposal.candidate
            || trusted_candidate.bundle_sha256() != &proposal.verifier_bundle_sha256
        {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority);
        }
        Ok(ResolvedCoreBenchmarkVerification { proposal })
    }

    // Binds one Node-handoff candidate subject, signs its authority, and atomically publishes it.
    pub fn authorize(
        &self,
        resolved: ResolvedCoreBenchmarkVerification,
        subject: BenchmarkSubject,
        baseline: &BenchmarkSubject,
        issued_at_unix_milliseconds: u64,
    ) -> Result<PreparedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError> {
        if issued_at_unix_milliseconds == 0 {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidInput);
        }
        let transaction_id = resolved.transaction_id(baseline)?;
        let proposal = resolved.proposal;
        let trusted_candidate = proposal
            .trusted_candidate
            .clone()
            .ok_or(CoreBenchmarkVerificationPreparationError::InvalidAuthority)?;
        if trusted_candidate.runtime().runtime().candidate_id() != &proposal.candidate
            || trusted_candidate.bundle_sha256() != &proposal.verifier_bundle_sha256
            || subject.model() != trusted_candidate.runtime().logical_model()
            || subject.execution_sha256()
                != trusted_candidate
                    .runtime()
                    .runtime()
                    .execution_contract_digest()
        {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority);
        }
        let request = BenchmarkRequest::new(
            BenchmarkKind::verification(
                proposal.pull_request,
                proposal.proposal_head.clone(),
                proposal.candidate.clone(),
                transaction_id,
                proposal.verifier_bundle_sha256.clone(),
                trusted_candidate.execution_sha256().clone(),
                proposal.verifier_numeric_id,
                proposal.device_id.clone(),
                Some(baseline.execution_sha256().clone()),
            )
            .map_err(|_| CoreBenchmarkVerificationPreparationError::InvalidAuthority)?,
            BenchmarkScope::Complete,
            subject,
        )
        .map_err(|_| CoreBenchmarkVerificationPreparationError::InvalidAuthority)?;
        let request_sha256 = request
            .sha256()
            .map_err(|_| CoreBenchmarkVerificationPreparationError::InvalidAuthority)?;
        let expires = issued_at_unix_milliseconds
            .checked_add(AUTHORITY_LIFETIME_MILLISECONDS)
            .ok_or(CoreBenchmarkVerificationPreparationError::InvalidInput)?;
        let payload = AuthorityPayload::from_request(
            &request,
            &proposal,
            &request_sha256,
            issued_at_unix_milliseconds,
            expires,
        )?;
        let payload = serde_json::to_vec(&payload)
            .map_err(|_| CoreBenchmarkVerificationPreparationError::InvalidAuthority)?;
        let (key_sha256, signature) = self.signer.sign(&payload)?;
        if signature.len() != 64 {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority);
        }
        let envelope = AuthorityEnvelope {
            schema_name: "li-benchmark-community-authority-envelope",
            schema_version: 1,
            payload_base64: STANDARD.encode(&payload),
            payload_sha256: hex_digest(&payload),
            signature_algorithm: "ed25519",
            signing_key_sha256: key_sha256.as_str(),
            signature_base64: STANDARD.encode(signature),
        };
        let document = serde_json::to_vec(&envelope)
            .map_err(|_| CoreBenchmarkVerificationPreparationError::InvalidAuthority)?;
        let authority_file = self.publisher.publish(&request_sha256, &document)?;
        Ok(PreparedCoreBenchmarkVerification {
            request,
            authority_file,
            candidate: trusted_candidate,
        })
    }
}

#[derive(Serialize)]
struct AuthorityEnvelope<'a> {
    schema_name: &'a str,
    schema_version: u32,
    payload_base64: String,
    payload_sha256: String,
    signature_algorithm: &'a str,
    signing_key_sha256: &'a str,
    signature_base64: String,
}

#[derive(Serialize)]
struct AuthorityPayload<'a> {
    schema_name: &'a str,
    schema_version: u32,
    repository: &'a str,
    request_sha256: &'a str,
    pull_request: u64,
    proposal_head: &'a str,
    candidate_id: &'a str,
    candidate_subject_sha256: &'a str,
    transaction_id: &'a str,
    verifier_numeric_id: u64,
    device_id: &'a str,
    baseline_execution_sha256: Option<&'a str>,
    verifier_bundle_sha256: &'a str,
    model: &'a str,
    runtime_execution_sha256: &'a str,
    benchmark_contract_sha256: &'a str,
    target_contract_sha256: &'a str,
    benchmark_ready: bool,
    verifier_bundle_verified: bool,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
}

impl<'a> AuthorityPayload<'a> {
    // Projects the exact closed request into the authority verifier's signed wire identity.
    fn from_request(
        request: &'a BenchmarkRequest,
        proposal: &'a CoreBenchmarkVerificationProposal,
        request_sha256: &'a Sha256Digest,
        issued: u64,
        expires: u64,
    ) -> Result<Self, CoreBenchmarkVerificationPreparationError> {
        let BenchmarkKind::Verification {
            pull_request,
            proposal_head,
            candidate,
            transaction_id,
            verifier_bundle_sha256,
            candidate_subject_sha256,
            verifier_numeric_id,
            device_id,
            baseline_execution_sha256,
        } = request.kind()
        else {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority);
        };
        let subject = request.subject();
        Ok(Self {
            schema_name: "li-benchmark-community-authority",
            schema_version: 1,
            repository: "letsinferlabs/runtimes",
            request_sha256: request_sha256.as_str(),
            pull_request: *pull_request,
            proposal_head: proposal_head.as_str(),
            candidate_id: candidate.as_str(),
            candidate_subject_sha256: candidate_subject_sha256.as_str(),
            transaction_id: transaction_id.as_str(),
            verifier_numeric_id: *verifier_numeric_id,
            device_id: device_id.as_str(),
            baseline_execution_sha256: baseline_execution_sha256.as_ref().map(Sha256Digest::as_str),
            verifier_bundle_sha256: verifier_bundle_sha256.as_str(),
            model: subject.model().as_str(),
            runtime_execution_sha256: subject.execution_sha256().as_str(),
            benchmark_contract_sha256: subject.benchmark_contract_sha256().as_str(),
            target_contract_sha256: subject.target_contract_sha256().as_str(),
            benchmark_ready: proposal.benchmark_ready,
            verifier_bundle_verified: proposal.verifier_bundle_verified,
            issued_at_unix_milliseconds: issued,
            expires_at_unix_milliseconds: expires,
        })
    }
}

// Accepts only the documented canonical runtimes pull-request URL shape.
fn validate_pull_request_url(
    value: &str,
) -> Result<u64, CoreBenchmarkVerificationPreparationError> {
    let prefix = "https://github.com/letsinferlabs/runtimes/pull/";
    let number = value
        .strip_prefix(prefix)
        .filter(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 20
                && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
        .and_then(|suffix| suffix.parse::<u64>().ok())
        .filter(|number| *number > 0);
    if value.len() > MAXIMUM_PULL_REQUEST_URL_BYTES {
        return Err(CoreBenchmarkVerificationPreparationError::InvalidInput);
    }
    number.ok_or(CoreBenchmarkVerificationPreparationError::InvalidInput)
}

// Returns whether one publisher root is absolute, normal, and never the filesystem root.
fn safe_root(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Requires one pre-created owner-private directory without following its final component.
fn validate_private_root(
    path: &Path,
    owner_user_id: u32,
) -> Result<(), CoreBenchmarkVerificationPreparationError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CoreBenchmarkVerificationPreparationError::Unavailable)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o700
        || metadata.nlink() < 1
    {
        return Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority);
    }
    Ok(())
}

// Returns the lowercase SHA-256 identity of exact bytes.
fn hex_digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use li_core_interface::{
        ArtifactName, ArtifactRevision, ArtifactUri, ByteCount, CpuArchitecture,
        EngineDistribution, EvidenceLabel, InstallationId, LogicalModelName, MemoryTopology,
        ModelArtifact, ModelArtifactFormat, OperatingSystem, PlacementGroupId, RuntimeIdentity,
        RuntimeInstallationId, RuntimeSource, RuntimeVersion, TargetId, TechnicalName,
    };
    use li_runtime_manager::{RuntimeAcceleratorVendor, RuntimeCandidate, RuntimeTarget};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::tempdir;

    use super::*;

    struct FixedOracle(
        Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationPreparationError>,
    );
    impl CoreBenchmarkVerificationOracle for FixedOracle {
        // Returns one injected credential-free proposal result.
        fn resolve(
            &self,
            _url: &str,
        ) -> Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationPreparationError>
        {
            self.0.clone()
        }

        // Preserves one exact candidate selector in the deterministic oracle mock.
        fn resolve_candidate(
            &self,
            _url: &str,
            requested_candidate: Option<&RuntimeCandidateId>,
        ) -> Result<CoreBenchmarkVerificationProposal, CoreBenchmarkVerificationPreparationError>
        {
            let proposal = self.0.clone()?;
            if requested_candidate.is_some_and(|candidate| candidate != proposal.candidate()) {
                return Err(CoreBenchmarkVerificationPreparationError::InvalidInput);
            }
            Ok(proposal)
        }
    }

    struct FixedSubject(Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError>);
    impl CoreBenchmarkVerificationSubjectResolver for FixedSubject {
        // Returns one injected installed-runtime resolution.
        fn resolve(
            &self,
            _candidate: &RuntimeCandidateId,
        ) -> Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError> {
            self.0.clone()
        }
    }

    struct TestSigner {
        pair: Ed25519KeyPair,
        failure: bool,
    }
    impl CoreBenchmarkVerificationSnapshotSigner for TestSigner {
        // Signs exact bytes or returns one injected provider failure.
        fn sign(
            &self,
            payload: &[u8],
        ) -> Result<(Sha256Digest, Vec<u8>), CoreBenchmarkVerificationPreparationError> {
            if self.failure {
                return Err(CoreBenchmarkVerificationPreparationError::Unavailable);
            }
            Ok((
                Sha256Digest::parse(&hex_digest(self.pair.public_key().as_ref()))
                    .expect("key digest"),
                self.pair.sign(payload).as_ref().to_vec(),
            ))
        }
    }

    struct CapturingPublisher {
        document: Mutex<Option<Vec<u8>>>,
        failure: bool,
    }
    impl CoreBenchmarkVerificationSnapshotPublisher for CapturingPublisher {
        // Captures exact bytes or returns one injected atomic-publication failure.
        fn publish(
            &self,
            request: &Sha256Digest,
            document: &[u8],
        ) -> Result<PathBuf, CoreBenchmarkVerificationPreparationError> {
            if self.failure {
                return Err(CoreBenchmarkVerificationPreparationError::Unavailable);
            }
            *self.document.lock().expect("publisher") = Some(document.to_vec());
            Ok(PathBuf::from(format!(
                "/authority/{}.authority.json",
                request.as_str()
            )))
        }
    }

    // Returns one exact lowercase digest fixture.
    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
    }

    // Returns one complete externally verified proposal fixture.
    fn proposal(ready: bool) -> CoreBenchmarkVerificationProposal {
        CoreBenchmarkVerificationProposal::new(
            41,
            BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
            RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
            73,
            digest('b'),
            Some(digest('c')),
            digest('d'),
            true,
            ready,
            true,
        )
        .with_trusted_candidate(trusted_candidate())
    }

    // Returns one exact resident-only candidate closure matching the subject fixture.
    fn trusted_candidate() -> CoreBenchmarkVerificationCandidate {
        let candidate_id =
            RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate");
        let distribution = EngineDistribution::oci(
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/engine@sha256:{}",
                "8".repeat(64)
            ))
            .expect("Engine source"),
            digest('9'),
            None,
            None,
        );
        let runtime = RuntimeIdentity::new(
            candidate_id,
            RuntimeVersion::parse("1.0.0").expect("version"),
            TargetId::parse("spark").expect("target"),
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/runtime@sha256:{}",
                "7".repeat(64)
            ))
            .expect("runtime source"),
            distribution,
            digest('6'),
            digest('5'),
            digest('4'),
        )
        .expect("runtime");
        let artifact = ModelArtifact::new(
            ArtifactName::parse("model").expect("artifact"),
            ArtifactUri::parse("hf://owner/model").expect("URI"),
            ArtifactRevision::parse(&"1".repeat(40)).expect("revision"),
            ModelArtifactFormat::HuggingFaceSnapshot,
        );
        let target = RuntimeTarget::new(
            OperatingSystem::Linux,
            CpuArchitecture::Arm64,
            RuntimeAcceleratorVendor::Nvidia,
            TechnicalName::parse("sm_121").expect("compute"),
            1,
            MemoryTopology::Unified,
            None,
            ByteCount::new(1 << 30).expect("memory"),
        )
        .expect("target");
        CoreBenchmarkVerificationCandidate::new(
            RuntimeCandidate::new(
                LogicalModelName::parse("model").expect("model"),
                runtime,
                vec![artifact],
                target,
                EvidenceLabel::Unqualified,
                2,
                false,
                false,
            )
            .expect("candidate"),
            PathBuf::from("/authority/runtime.letsinfer"),
            crate::CoreBenchmarkVerificationEngineArtifact::Reuse,
            digest('d'),
            digest('4'),
            vec![41],
            BenchmarkGitRevision::parse(&"b".repeat(40)).expect("base"),
        )
        .expect("trusted candidate")
    }

    // Returns one exact installed runtime subject fixture.
    fn subject() -> BenchmarkSubject {
        BenchmarkSubject::new(
            InstallationId::parse(&"1".repeat(64)).expect("installation"),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime"),
            LogicalModelName::parse("model").expect("model"),
            PlacementGroupId::parse(&"3".repeat(32)).expect("group"),
            digest('4'),
            digest('5'),
            digest('6'),
        )
    }

    // Creates one capability and exposes its captured atomic publisher.
    fn capability(
        oracle: Result<
            CoreBenchmarkVerificationProposal,
            CoreBenchmarkVerificationPreparationError,
        >,
        subject: Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError>,
        signer_failure: bool,
        publisher_failure: bool,
    ) -> (
        CoreBenchmarkVerificationPreparation,
        Arc<CapturingPublisher>,
    ) {
        let publisher = Arc::new(CapturingPublisher {
            document: Mutex::new(None),
            failure: publisher_failure,
        });
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("key");
        (
            CoreBenchmarkVerificationPreparation::new(
                Arc::new(FixedOracle(oracle)),
                Arc::new(FixedSubject(subject)),
                Arc::new(TestSigner {
                    pair,
                    failure: signer_failure,
                }),
                publisher.clone(),
            ),
            publisher,
        )
    }

    #[test]
    // Publishes only beneath an existing owner-private real directory and rejects a symlink root.
    fn system_publisher_enforces_its_private_root() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempdir().expect("directory");
        let root = directory.path().join("authority");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("permissions");
        let owner = fs::symlink_metadata(&root).expect("metadata").uid();
        let publisher = SystemCoreBenchmarkVerificationSnapshotPublisher::new(root.clone(), owner)
            .expect("publisher");
        let path = publisher.publish(&digest('e'), b"{}").expect("publish");
        assert_eq!(fs::read(path).expect("document"), b"{}");
        let link = directory.path().join("authority-link");
        symlink(&root, &link).expect("link");
        assert!(SystemCoreBenchmarkVerificationSnapshotPublisher::new(link, owner).is_err());
    }

    #[test]
    // Resolves, signs, and publishes one exact complete request without credential fields.
    fn valid_proposal_produces_a_consumable_closed_snapshot() {
        let (capability, publisher) = capability(Ok(proposal(true)), Ok(subject()), false, false);
        let prepared = capability
            .prepare("https://github.com/letsinferlabs/runtimes/pull/41", 1_000)
            .expect("prepared");
        assert!(prepared.request().kind().is_verification());
        assert!(prepared.authority_file().ends_with(format!(
            "{}.authority.json",
            prepared.request().sha256().expect("digest").as_str()
        )));
        let document = publisher
            .document
            .lock()
            .expect("publisher")
            .clone()
            .expect("document");
        let text = String::from_utf8(document).expect("UTF-8");
        assert!(
            !text.contains("token")
                && !text.contains("authorization")
                && !text.contains("github_pat")
        );
    }

    #[test]
    // Preserves one explicit changed-candidate selector through oracle resolution and signing.
    fn explicit_candidate_is_bound_before_authority_publication() {
        let expected = RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate");
        let (capability, _) = capability(Ok(proposal(true)), Ok(subject()), false, false);
        let prepared = capability
            .prepare_candidate(
                "https://github.com/letsinferlabs/runtimes/pull/41",
                Some(&expected),
                1_000,
            )
            .expect("prepared");
        let BenchmarkKind::Verification { candidate, .. } = prepared.request().kind() else {
            panic!("verification kind");
        };
        assert_eq!(candidate, &expected);
    }

    #[test]
    // Rejects malformed URLs and every non-finalized or unavailable resolution boundary.
    fn invalid_url_unready_or_unavailable_authority_fails_before_publication() {
        let (invalid_url_capability, _) =
            capability(Ok(proposal(true)), Ok(subject()), false, false);
        assert_eq!(
            invalid_url_capability
                .prepare("http://github.com/letsinferlabs/runtimes/pull/41", 1_000),
            Err(CoreBenchmarkVerificationPreparationError::InvalidInput)
        );
        let (unready_capability, _) = capability(Ok(proposal(false)), Ok(subject()), false, false);
        assert_eq!(
            unready_capability.prepare("https://github.com/letsinferlabs/runtimes/pull/41", 1_000),
            Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority)
        );
        let (unavailable_capability, _) = capability(
            Err(CoreBenchmarkVerificationPreparationError::Unavailable),
            Ok(subject()),
            false,
            false,
        );
        assert_eq!(
            unavailable_capability
                .prepare("https://github.com/letsinferlabs/runtimes/pull/41", 1_000),
            Err(CoreBenchmarkVerificationPreparationError::Unavailable)
        );
    }

    #[test]
    // Propagates subject, signing, and atomic-publication failures without partial success.
    fn local_identity_signing_and_publication_fail_closed() {
        for (subject_result, signer_failure, publisher_failure, expected) in [
            (
                Err(CoreBenchmarkVerificationPreparationError::Conflict),
                false,
                false,
                CoreBenchmarkVerificationPreparationError::Conflict,
            ),
            (
                Ok(subject()),
                true,
                false,
                CoreBenchmarkVerificationPreparationError::Unavailable,
            ),
            (
                Ok(subject()),
                false,
                true,
                CoreBenchmarkVerificationPreparationError::Unavailable,
            ),
        ] {
            let (capability, _) = capability(
                Ok(proposal(true)),
                subject_result,
                signer_failure,
                publisher_failure,
            );
            assert_eq!(
                capability.prepare("https://github.com/letsinferlabs/runtimes/pull/41", 1_000),
                Err(expected)
            );
        }
    }
}
