// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{OperationId, RuntimeCandidateId, Sha256Digest, TechnicalName};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::li_benchmark_failure_evidence::{
    local_failure_evidence, local_outcome_value, parsed_local_failure_evidence,
};
use crate::li_benchmark_record::{validate_benchmark_contract, validate_benchmark_results};
use crate::{
    BenchmarkCommunityVerificationDocument, BenchmarkCommunityVerificationDocumentProvider,
    BenchmarkError, BenchmarkEvidence, BenchmarkEvidenceProvider, BenchmarkExecutionOutcome,
    BenchmarkRecordSchema, BenchmarkRequest, BenchmarkRestoration, BenchmarkTelemetryReceipt,
};

pub(crate) const MAXIMUM_BENCHMARK_EVIDENCE_BYTES: usize = 64 << 20;
const BENCHMARK_RECORD_NAME: &str = "benchmark.json";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

// Identifies one final filesystem entry without following a symbolic link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkEvidenceEntryKind {
    Directory,
    RegularFile,
    SymbolicLink,
    Other,
}

// Describes one no-follow filesystem entry at the native evidence boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchmarkEvidenceFileMetadata {
    kind: BenchmarkEvidenceEntryKind,
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    byte_count: u64,
}

impl BenchmarkEvidenceFileMetadata {
    // Creates one explicit metadata snapshot for production or deterministic mocks.
    pub const fn new(
        kind: BenchmarkEvidenceEntryKind,
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        byte_count: u64,
    ) -> Self {
        Self {
            kind,
            owner_user_id,
            mode,
            link_count,
            byte_count,
        }
    }

    // Returns the no-follow final entry kind.
    pub const fn kind(&self) -> BenchmarkEvidenceEntryKind {
        self.kind
    }

    // Returns the native owner user identity.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    // Returns permission bits without file-type flags.
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    // Returns the native hard-link count.
    pub const fn link_count(&self) -> u64 {
        self.link_count
    }

    // Returns the exact observed byte count.
    pub const fn byte_count(&self) -> u64 {
        self.byte_count
    }
}

// Describes one redacted native evidence I/O failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkEvidenceIoError {
    AlreadyExists,
    Unavailable,
}

// Distinguishes a new atomic publication from an existing destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkEvidencePublishDisposition {
    Published,
    Existing,
}

// Isolates owner-bound no-follow filesystem operations from evidence policy.
pub trait BenchmarkEvidenceNativeIo: Send + Sync {
    // Returns one final entry snapshot without following a symbolic link.
    fn metadata(
        &self,
        path: &Path,
    ) -> Result<Option<BenchmarkEvidenceFileMetadata>, BenchmarkEvidenceIoError>;

    // Reads one bounded regular file through a no-follow descriptor.
    fn read_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, BenchmarkEvidenceIoError>;

    // Creates one owner-only, single-link temporary file and synchronizes its contents.
    fn write_private_file(&self, path: &Path, bytes: &[u8])
        -> Result<(), BenchmarkEvidenceIoError>;

    // Publishes one complete temporary file without replacing an existing identity.
    fn publish_file(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<BenchmarkEvidencePublishDisposition, BenchmarkEvidenceIoError>;

    // Removes one exact private regular file without following links.
    fn remove_private_file(&self, path: &Path) -> Result<(), BenchmarkEvidenceIoError>;

    // Synchronizes one owner-bound evidence directory after a namespace mutation.
    fn sync_directory(&self, path: &Path) -> Result<(), BenchmarkEvidenceIoError>;
}

// Performs benchmark evidence filesystem operations on Unix hosts.
#[derive(Default)]
pub struct SystemBenchmarkEvidenceNativeIo;

impl BenchmarkEvidenceNativeIo for SystemBenchmarkEvidenceNativeIo {
    // Returns lstat metadata while preserving absence as an ordinary state.
    fn metadata(
        &self,
        path: &Path,
    ) -> Result<Option<BenchmarkEvidenceFileMetadata>, BenchmarkEvidenceIoError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                let kind = if metadata.file_type().is_symlink() {
                    BenchmarkEvidenceEntryKind::SymbolicLink
                } else if metadata.is_dir() {
                    BenchmarkEvidenceEntryKind::Directory
                } else if metadata.is_file() {
                    BenchmarkEvidenceEntryKind::RegularFile
                } else {
                    BenchmarkEvidenceEntryKind::Other
                };
                Ok(Some(BenchmarkEvidenceFileMetadata::new(
                    kind,
                    metadata.uid(),
                    metadata.mode() & 0o777,
                    metadata.nlink(),
                    metadata.len(),
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(BenchmarkEvidenceIoError::Unavailable),
        }
    }

    // Reads through O_NOFOLLOW and rejects bytes beyond the supplied exact ceiling.
    fn read_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, BenchmarkEvidenceIoError> {
        if maximum_bytes == 0 {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
        let descriptor = file
            .metadata()
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
        if !descriptor.is_file()
            || descriptor.mode() & 0o777 != PRIVATE_FILE_MODE
            || descriptor.nlink() != 1
            || descriptor.len() == 0
            || descriptor.len() > maximum_bytes as u64
        {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
        file.take((maximum_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
        if bytes.len() > maximum_bytes || bytes.len() as u64 != descriptor.len() {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        Ok(bytes)
    }

    // Writes one new owner-only file and durably flushes its complete bytes.
    fn write_private_file(
        &self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), BenchmarkEvidenceIoError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    BenchmarkEvidenceIoError::AlreadyExists
                } else {
                    BenchmarkEvidenceIoError::Unavailable
                }
            })?;
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)
    }

    // Links one complete file into place and removes the temporary link before returning.
    fn publish_file(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<BenchmarkEvidencePublishDisposition, BenchmarkEvidenceIoError> {
        match fs::hard_link(temporary, destination) {
            Ok(()) => {
                if fs::remove_file(temporary).is_err() {
                    let _ = fs::remove_file(destination);
                    return Err(BenchmarkEvidenceIoError::Unavailable);
                }
                Ok(BenchmarkEvidencePublishDisposition::Published)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Ok(BenchmarkEvidencePublishDisposition::Existing)
            }
            Err(_) => Err(BenchmarkEvidenceIoError::Unavailable),
        }
    }

    // Removes only one ordinary regular file after the provider validates its metadata.
    fn remove_private_file(&self, path: &Path) -> Result<(), BenchmarkEvidenceIoError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(BenchmarkEvidenceIoError::Unavailable),
        }
    }

    // Opens and synchronizes one directory without following its final component.
    fn sync_directory(&self, path: &Path) -> Result<(), BenchmarkEvidenceIoError> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
        directory
            .sync_all()
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)
    }
}

// Materializes canonical benchmark records into one immutable local evidence namespace.
pub struct FilesystemBenchmarkEvidenceProvider {
    source_root: PathBuf,
    evidence_root: PathBuf,
    owner_user_id: u32,
    native_io: Arc<dyn BenchmarkEvidenceNativeIo>,
}

impl FilesystemBenchmarkEvidenceProvider {
    // Creates one provider from explicit source, destination, owner, and native I/O inputs.
    pub fn new(
        source_root: PathBuf,
        evidence_root: PathBuf,
        owner_user_id: u32,
        native_io: Arc<dyn BenchmarkEvidenceNativeIo>,
    ) -> Result<Self, BenchmarkError> {
        require_absolute_normal_path(&source_root)?;
        require_absolute_normal_path(&evidence_root)?;
        if source_root == evidence_root {
            return Err(evidence_provider_error("evidence roots are invalid"));
        }
        Ok(Self {
            source_root,
            evidence_root,
            owner_user_id,
            native_io,
        })
    }

    // Verifies immutable source and destination roots before benchmark state can mutate.
    pub fn preflight(&self) -> Result<(), BenchmarkError> {
        require_directory(
            self.native_io.as_ref(),
            &self.source_root,
            self.owner_user_id,
        )?;
        require_directory(
            self.native_io.as_ref(),
            &self.evidence_root,
            self.owner_user_id,
        )
    }

    // Resolves one execution-owned canonical source record path.
    fn source_path(&self, job_id: &OperationId) -> PathBuf {
        self.source_root
            .join(job_id.as_str())
            .join(BENCHMARK_RECORD_NAME)
    }

    // Resolves one immutable destination from the schema-owned benchmark identity.
    pub(crate) fn evidence_path(&self, evidence_id: &Sha256Digest) -> PathBuf {
        self.evidence_root
            .join(format!("{}.json", evidence_id.as_str()))
    }

    // Resolves one deterministic private staging file for replay-safe publication.
    fn temporary_path(&self, job_id: &OperationId) -> PathBuf {
        self.evidence_root
            .join(format!(".li_benchmark_{}.tmp", job_id.as_str()))
    }

    // Requires the fixed source and destination directory chain to remain private.
    fn require_directories(&self, job_id: &OperationId) -> Result<(), BenchmarkError> {
        self.preflight()?;
        require_directory(
            self.native_io.as_ref(),
            &self.source_root.join(job_id.as_str()),
            self.owner_user_id,
        )
    }

    // Removes one safe provider-owned file before or after a failed publication attempt.
    fn cleanup_owned_file(&self, path: &Path) -> Result<(), BenchmarkError> {
        let Some(metadata) = self
            .native_io
            .metadata(path)
            .map_err(|_| evidence_cleanup_error())?
        else {
            return Ok(());
        };
        require_private_file_metadata(&metadata, self.owner_user_id, None)
            .map_err(|_| evidence_cleanup_error())?;
        self.native_io
            .remove_private_file(path)
            .map_err(|_| evidence_cleanup_error())?;
        self.native_io
            .sync_directory(&self.evidence_root)
            .map_err(|_| evidence_cleanup_error())
    }

    // Returns an existing exact publication or rejects a conflicting immutable identity.
    fn existing_evidence(
        &self,
        path: &Path,
        expected_bytes: &[u8],
        expected: &BenchmarkEvidence,
    ) -> Result<BenchmarkEvidence, BenchmarkError> {
        let observed = read_private_file(
            self.native_io.as_ref(),
            path,
            self.owner_user_id,
            MAXIMUM_BENCHMARK_EVIDENCE_BYTES,
        )?;
        if observed != expected_bytes {
            return Err(BenchmarkError::EvidenceRejected);
        }
        let parsed = parsed_evidence(&observed)?;
        if &parsed.receipt != expected {
            return Err(BenchmarkError::EvidenceRejected);
        }
        Ok(parsed.receipt)
    }

    // Publishes complete bytes or rolls back only this attempt's temporary state.
    fn publish(
        &self,
        job_id: &OperationId,
        bytes: &[u8],
        receipt: &BenchmarkEvidence,
    ) -> Result<BenchmarkEvidence, BenchmarkError> {
        let temporary = self.temporary_path(job_id);
        let destination = self.evidence_path(receipt.evidence_id());
        self.cleanup_owned_file(&temporary)?;
        if self
            .native_io
            .metadata(&destination)
            .map_err(|_| evidence_provider_error("evidence inspection failed"))?
            .is_some()
        {
            return self.existing_evidence(&destination, bytes, receipt);
        }
        if self
            .native_io
            .write_private_file(&temporary, bytes)
            .is_err()
        {
            self.cleanup_owned_file(&temporary)?;
            return Err(evidence_provider_error("evidence staging failed"));
        }
        let staged = read_private_file(
            self.native_io.as_ref(),
            &temporary,
            self.owner_user_id,
            MAXIMUM_BENCHMARK_EVIDENCE_BYTES,
        );
        if staged.as_deref() != Ok(bytes) {
            self.cleanup_owned_file(&temporary)?;
            return Err(evidence_provider_error("evidence staging failed"));
        }
        let disposition = self.native_io.publish_file(&temporary, &destination);
        match disposition {
            Ok(BenchmarkEvidencePublishDisposition::Published) => {
                let published = match self.existing_evidence(&destination, bytes, receipt) {
                    Ok(published) => published,
                    Err(error) => {
                        self.cleanup_owned_file(&destination)?;
                        return Err(error);
                    }
                };
                if self.native_io.sync_directory(&self.evidence_root).is_err() {
                    self.cleanup_owned_file(&destination)?;
                    return Err(evidence_provider_error("evidence publication failed"));
                }
                Ok(published)
            }
            Ok(BenchmarkEvidencePublishDisposition::Existing) => {
                self.cleanup_owned_file(&temporary)?;
                self.existing_evidence(&destination, bytes, receipt)
            }
            Err(_) => {
                self.cleanup_owned_file(&temporary)?;
                Err(evidence_provider_error("evidence publication failed"))
            }
        }
    }
}

impl BenchmarkEvidenceProvider for FilesystemBenchmarkEvidenceProvider {
    // Publishes one successful public record or distinct Core-local terminal record.
    fn finalize(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        telemetry: &BenchmarkTelemetryReceipt,
        restoration: &BenchmarkRestoration,
    ) -> Result<BenchmarkEvidence, BenchmarkError> {
        match outcome {
            BenchmarkExecutionOutcome::Succeeded { .. } => {
                self.require_directories(job_id)?;
                let bytes = read_private_file(
                    self.native_io.as_ref(),
                    &self.source_path(job_id),
                    self.owner_user_id,
                    MAXIMUM_BENCHMARK_EVIDENCE_BYTES,
                )?;
                let parsed = parsed_evidence(&bytes)?;
                require_evidence_binding(request, outcome, &bytes, &parsed)?;
                self.publish(job_id, &bytes, &parsed.receipt)
            }
            BenchmarkExecutionOutcome::Failed { .. }
            | BenchmarkExecutionOutcome::Cancelled { .. } => {
                require_directory(
                    self.native_io.as_ref(),
                    &self.evidence_root,
                    self.owner_user_id,
                )?;
                let (bytes, receipt) =
                    local_failure_evidence(job_id, request, outcome, telemetry, restoration)?;
                self.publish(job_id, &bytes, &receipt)
            }
        }
    }

    // Re-reads immutable bytes and independently verifies their request and outcome binding.
    fn verify(
        &self,
        request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        evidence: &BenchmarkEvidence,
    ) -> Result<(), BenchmarkError> {
        require_directory(
            self.native_io.as_ref(),
            &self.evidence_root,
            self.owner_user_id,
        )?;
        let bytes = read_private_file(
            self.native_io.as_ref(),
            &self.evidence_path(evidence.evidence_id()),
            self.owner_user_id,
            MAXIMUM_BENCHMARK_EVIDENCE_BYTES,
        )?;
        let parsed = parsed_evidence(&bytes)?;
        if &parsed.receipt != evidence {
            return Err(BenchmarkError::EvidenceRejected);
        }
        require_evidence_binding(request, outcome, &bytes, &parsed)
    }
}

// Routes ordinary evidence unchanged and persists paired verification records without an outer worker file.
pub struct RoutedBenchmarkEvidenceProvider {
    ordinary: Arc<dyn BenchmarkEvidenceProvider>,
    filesystem: Arc<FilesystemBenchmarkEvidenceProvider>,
    community: Arc<dyn BenchmarkCommunityVerificationDocumentProvider>,
}

impl RoutedBenchmarkEvidenceProvider {
    // Creates one routing boundary from the established filesystem owner and a typed record builder.
    pub const fn new(
        ordinary: Arc<dyn BenchmarkEvidenceProvider>,
        filesystem: Arc<FilesystemBenchmarkEvidenceProvider>,
        community: Arc<dyn BenchmarkCommunityVerificationDocumentProvider>,
    ) -> Self {
        Self {
            ordinary,
            filesystem,
            community,
        }
    }

    // Replays one exact community document without passing it through ordinary record parsing.
    fn existing_community(
        &self,
        path: &Path,
        expected_bytes: &[u8],
        expected: &BenchmarkEvidence,
    ) -> Result<BenchmarkEvidence, BenchmarkError> {
        let observed = read_private_file(
            self.filesystem.native_io.as_ref(),
            path,
            self.filesystem.owner_user_id,
            MAXIMUM_BENCHMARK_EVIDENCE_BYTES,
        )?;
        if observed != expected_bytes
            || digest_bytes(&observed) != *expected.evidence_id()
            || observed.len() as u64 != expected.byte_count()
        {
            return Err(BenchmarkError::EvidenceRejected);
        }
        Ok(expected.clone())
    }

    // Publishes community bytes through the same atomic owner-private filesystem contract.
    fn publish_community(
        &self,
        job_id: &OperationId,
        bytes: &[u8],
        receipt: &BenchmarkEvidence,
    ) -> Result<BenchmarkEvidence, BenchmarkError> {
        let temporary = self.filesystem.temporary_path(job_id);
        let destination = self.filesystem.evidence_path(receipt.evidence_id());
        self.filesystem.cleanup_owned_file(&temporary)?;
        if self
            .filesystem
            .native_io
            .metadata(&destination)
            .map_err(|_| evidence_provider_error("evidence inspection failed"))?
            .is_some()
        {
            return self.existing_community(&destination, bytes, receipt);
        }
        if self
            .filesystem
            .native_io
            .write_private_file(&temporary, bytes)
            .is_err()
        {
            self.filesystem.cleanup_owned_file(&temporary)?;
            return Err(evidence_provider_error("evidence staging failed"));
        }
        if read_private_file(
            self.filesystem.native_io.as_ref(),
            &temporary,
            self.filesystem.owner_user_id,
            MAXIMUM_BENCHMARK_EVIDENCE_BYTES,
        )
        .as_deref()
            != Ok(bytes)
        {
            self.filesystem.cleanup_owned_file(&temporary)?;
            return Err(evidence_provider_error("evidence staging failed"));
        }
        match self
            .filesystem
            .native_io
            .publish_file(&temporary, &destination)
        {
            Ok(BenchmarkEvidencePublishDisposition::Published) => {
                let published = match self.existing_community(&destination, bytes, receipt) {
                    Ok(published) => published,
                    Err(error) => {
                        self.filesystem.cleanup_owned_file(&destination)?;
                        return Err(error);
                    }
                };
                if self
                    .filesystem
                    .native_io
                    .sync_directory(&self.filesystem.evidence_root)
                    .is_err()
                {
                    self.filesystem.cleanup_owned_file(&destination)?;
                    return Err(evidence_provider_error("evidence publication failed"));
                }
                Ok(published)
            }
            Ok(BenchmarkEvidencePublishDisposition::Existing) => {
                self.filesystem.cleanup_owned_file(&temporary)?;
                self.existing_community(&destination, bytes, receipt)
            }
            Err(_) => {
                self.filesystem.cleanup_owned_file(&temporary)?;
                Err(evidence_provider_error("evidence publication failed"))
            }
        }
    }

    // Persists one canonical CommunityVerificationV1 document under its exact content identity.
    fn finalize_community(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        bytes: &[u8],
    ) -> Result<BenchmarkEvidence, BenchmarkError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_BENCHMARK_EVIDENCE_BYTES {
            return Err(BenchmarkError::EvidenceRejected);
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| BenchmarkError::EvidenceRejected)?;
        if canonical_json_bytes(&value)? != bytes
            || value.get("schema_version").and_then(Value::as_u64) != Some(1)
            || value.get("kind").and_then(Value::as_str) != Some("letsinfer.runtime-verification")
            || !request.kind().is_verification()
        {
            return Err(BenchmarkError::EvidenceRejected);
        }
        let evidence_id = digest_bytes(bytes);
        let results_sha256 = match outcome {
            BenchmarkExecutionOutcome::Succeeded {
                results_sha256,
                record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
                ..
            } => results_sha256.clone(),
            BenchmarkExecutionOutcome::Failed { .. }
            | BenchmarkExecutionOutcome::Cancelled { .. } => evidence_id.clone(),
            BenchmarkExecutionOutcome::Succeeded { .. } => {
                return Err(BenchmarkError::EvidenceRejected)
            }
        };
        let receipt = BenchmarkEvidence::new(
            evidence_id,
            results_sha256,
            BenchmarkRecordSchema::CommunityVerificationV1,
            bytes.len() as u64,
        )?;
        require_directory(
            self.filesystem.native_io.as_ref(),
            &self.filesystem.evidence_root,
            self.filesystem.owner_user_id,
        )?;
        self.publish_community(job_id, bytes, &receipt)
    }

    // Re-reads exact community bytes and verifies their canonical content-addressed receipt.
    fn verify_community(
        &self,
        outcome: &BenchmarkExecutionOutcome,
        evidence: &BenchmarkEvidence,
    ) -> Result<(), BenchmarkError> {
        if evidence.schema() != BenchmarkRecordSchema::CommunityVerificationV1 {
            return Err(BenchmarkError::EvidenceRejected);
        }
        let bytes = read_private_file(
            self.filesystem.native_io.as_ref(),
            &self.filesystem.evidence_path(evidence.evidence_id()),
            self.filesystem.owner_user_id,
            MAXIMUM_BENCHMARK_EVIDENCE_BYTES,
        )?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| BenchmarkError::EvidenceRejected)?;
        let expected_results = match outcome {
            BenchmarkExecutionOutcome::Succeeded {
                results_sha256,
                record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
                ..
            } => results_sha256,
            BenchmarkExecutionOutcome::Failed { .. }
            | BenchmarkExecutionOutcome::Cancelled { .. } => evidence.evidence_id(),
            BenchmarkExecutionOutcome::Succeeded { .. } => {
                return Err(BenchmarkError::EvidenceRejected)
            }
        };
        if canonical_json_bytes(&value)? != bytes
            || digest_bytes(&bytes) != *evidence.evidence_id()
            || evidence.byte_count() != bytes.len() as u64
            || evidence.results_sha256() != expected_results
        {
            return Err(BenchmarkError::EvidenceRejected);
        }
        Ok(())
    }
}

impl BenchmarkEvidenceProvider for RoutedBenchmarkEvidenceProvider {
    // Routes local jobs and pre-candidate failures through the unchanged ordinary evidence path.
    fn finalize(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        telemetry: &BenchmarkTelemetryReceipt,
        restoration: &BenchmarkRestoration,
    ) -> Result<BenchmarkEvidence, BenchmarkError> {
        if !request.kind().is_verification() {
            return self
                .ordinary
                .finalize(job_id, request, outcome, telemetry, restoration);
        }
        match self
            .community
            .document(job_id, request, outcome, telemetry, restoration)?
        {
            BenchmarkCommunityVerificationDocument::Community(bytes) => {
                self.finalize_community(job_id, request, outcome, &bytes)
            }
            BenchmarkCommunityVerificationDocument::LocalFailure => {
                if matches!(outcome, BenchmarkExecutionOutcome::Succeeded { .. }) {
                    return Err(BenchmarkError::EvidenceRejected);
                }
                self.ordinary
                    .finalize(job_id, request, outcome, telemetry, restoration)
            }
        }
    }

    // Revalidates community bytes locally or delegates the established ordinary record contract.
    fn verify(
        &self,
        request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        evidence: &BenchmarkEvidence,
    ) -> Result<(), BenchmarkError> {
        if evidence.schema() == BenchmarkRecordSchema::CommunityVerificationV1 {
            if !request.kind().is_verification() {
                return Err(BenchmarkError::EvidenceRejected);
            }
            self.verify_community(outcome, evidence)
        } else {
            self.ordinary.verify(request, outcome, evidence)
        }
    }
}

// Stores one parsed public record together with its exact receipt bindings.
pub(crate) struct ParsedBenchmarkEvidence {
    pub(crate) receipt: BenchmarkEvidence,
    binding: ParsedBenchmarkEvidenceBinding,
}

// Distinguishes successful publication evidence from Core-local terminal evidence.
enum ParsedBenchmarkEvidenceBinding {
    Successful {
        installation_id: Sha256Digest,
        benchmark_contract_sha256: Sha256Digest,
        target_contract_sha256: Sha256Digest,
    },
    CoreLocalFailure {
        request_sha256: Sha256Digest,
        outcome: Value,
    },
}

// Parses one canonical schema-7 or schema-8 record and verifies its hash identities.
pub(crate) fn parsed_evidence(bytes: &[u8]) -> Result<ParsedBenchmarkEvidence, BenchmarkError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_BENCHMARK_EVIDENCE_BYTES {
        return Err(BenchmarkError::EvidenceRejected);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| BenchmarkError::EvidenceRejected)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err(BenchmarkError::EvidenceRejected);
    }
    let object = value.as_object().ok_or(BenchmarkError::EvidenceRejected)?;
    if let Some(local) = parsed_local_failure_evidence(object, bytes)? {
        return Ok(ParsedBenchmarkEvidence {
            receipt: local.receipt,
            binding: ParsedBenchmarkEvidenceBinding::CoreLocalFailure {
                request_sha256: local.request_sha256,
                outcome: local.outcome,
            },
        });
    }
    require_record_fields(object)?;
    let schema_version = positive_u64(object, "schema_version")?;
    let schema = match schema_version {
        7 => BenchmarkRecordSchema::OciExecutionPayloadV7,
        8 => BenchmarkRecordSchema::NativeExecutionPayloadV8,
        _ => return Err(BenchmarkError::EvidenceRejected),
    };
    let evidence_id = digest_field(object, "id")?;
    let installation_id = digest_field(object, "installation_id")?;
    let benchmark_contract_sha256 = digest_field(object, "benchmark_contract_sha256")?;
    let results_sha256 = digest_field(object, "results_sha256")?;
    let timestamp_unix_ns = positive_u64(object, "timestamp_unix_ns")?;
    let timestamp = positive_u64(object, "timestamp")?;
    if timestamp != timestamp_unix_ns / 1_000_000_000 {
        return Err(BenchmarkError::EvidenceRejected);
    }
    let contract = object
        .get("benchmark_contract")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::EvidenceRejected)?;
    if positive_u64(contract, "schema_version")? != 8 {
        return Err(BenchmarkError::EvidenceRejected);
    }
    validate_benchmark_contract(contract)?;
    if digest_bytes(&canonical_json_bytes(&Value::Object(contract.clone()))?)
        != benchmark_contract_sha256
    {
        return Err(BenchmarkError::EvidenceRejected);
    }
    let results = object
        .get("results")
        .and_then(Value::as_array)
        .filter(|results| !results.is_empty())
        .ok_or(BenchmarkError::EvidenceRejected)?;
    validate_benchmark_results(results, object.get("ttft_cache"))?;
    let result_material = match object.get("ttft_cache") {
        Some(ttft_cache) if ttft_cache.is_object() => {
            let mut material = Map::new();
            material.insert("results".to_string(), Value::Array(results.clone()));
            material.insert("ttft_cache".to_string(), ttft_cache.clone());
            Value::Object(material)
        }
        Some(_) => return Err(BenchmarkError::EvidenceRejected),
        None => Value::Array(results.clone()),
    };
    if digest_bytes(&canonical_json_bytes(&result_material)?) != results_sha256 {
        return Err(BenchmarkError::EvidenceRejected);
    }
    let subject = object
        .get("subject")
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::EvidenceRejected)?;
    let target_contract_sha256 = validate_subject(subject, schema)?;
    let mut identity = Map::new();
    identity.insert(
        "benchmark_contract_sha256".to_string(),
        Value::String(benchmark_contract_sha256.as_str().to_string()),
    );
    identity.insert(
        "contract".to_string(),
        Value::String("letsinfer-benchmark-identity-v2".to_string()),
    );
    identity.insert(
        "installation_id".to_string(),
        Value::String(installation_id.as_str().to_string()),
    );
    identity.insert(
        "results_sha256".to_string(),
        Value::String(results_sha256.as_str().to_string()),
    );
    identity.insert("subject".to_string(), Value::Object(subject.clone()));
    identity.insert(
        "timestamp_unix_ns".to_string(),
        Value::Number(timestamp_unix_ns.into()),
    );
    if digest_bytes(&canonical_json_bytes(&Value::Object(identity))?) != evidence_id {
        return Err(BenchmarkError::EvidenceRejected);
    }
    let receipt = BenchmarkEvidence::new(evidence_id, results_sha256, schema, bytes.len() as u64)
        .map_err(|_| BenchmarkError::EvidenceRejected)?;
    Ok(ParsedBenchmarkEvidence {
        receipt,
        binding: ParsedBenchmarkEvidenceBinding::Successful {
            installation_id,
            benchmark_contract_sha256,
            target_contract_sha256,
        },
    })
}

// Requires one parsed record to bind the manager's immutable request and raw evidence bytes.
fn require_evidence_binding(
    request: &BenchmarkRequest,
    outcome: &BenchmarkExecutionOutcome,
    bytes: &[u8],
    parsed: &ParsedBenchmarkEvidence,
) -> Result<(), BenchmarkError> {
    match &parsed.binding {
        ParsedBenchmarkEvidenceBinding::Successful {
            installation_id,
            benchmark_contract_sha256,
            target_contract_sha256,
        } => {
            let BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256,
                results_sha256,
                record_schema,
            } = outcome
            else {
                return Err(BenchmarkError::EvidenceRejected);
            };
            if &digest_bytes(bytes) != raw_evidence_sha256
                || parsed.receipt.results_sha256() != results_sha256
                || parsed.receipt.schema() != *record_schema
                || installation_id.as_str() != request.subject().installation_id().as_str()
                || benchmark_contract_sha256 != request.subject().benchmark_contract_sha256()
                || target_contract_sha256 != request.subject().target_contract_sha256()
            {
                return Err(BenchmarkError::EvidenceRejected);
            }
        }
        ParsedBenchmarkEvidenceBinding::CoreLocalFailure {
            request_sha256,
            outcome: recorded_outcome,
        } => {
            if request_sha256 != &request.sha256()?
                || recorded_outcome != &local_outcome_value(outcome)?
            {
                return Err(BenchmarkError::EvidenceRejected);
            }
        }
    }
    Ok(())
}

// Requires the exact closed root fields shared by record schemas 7 and 8.
fn require_record_fields(object: &Map<String, Value>) -> Result<(), BenchmarkError> {
    let expected = BTreeSet::from([
        "benchmark_contract",
        "benchmark_contract_sha256",
        "id",
        "installation_id",
        "results",
        "results_sha256",
        "schema_version",
        "subject",
        "timestamp",
        "timestamp_unix_ns",
    ]);
    let observed: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let with_ttft_cache = observed
        == expected
            .iter()
            .copied()
            .chain(std::iter::once("ttft_cache"))
            .collect();
    if observed != expected && !with_ttft_cache {
        return Err(BenchmarkError::EvidenceRejected);
    }
    Ok(())
}

// Validates the schema-specific subject shape and returns its target contract identity.
fn validate_subject(
    subject: &Map<String, Value>,
    schema: BenchmarkRecordSchema,
) -> Result<Sha256Digest, BenchmarkError> {
    let measured_field = match schema {
        BenchmarkRecordSchema::OciExecutionPayloadV7 => "measured_engine_oci",
        BenchmarkRecordSchema::NativeExecutionPayloadV8 => "measured_engine_kind",
        BenchmarkRecordSchema::CommunityVerificationV1 => {
            return Err(BenchmarkError::EvidenceRejected)
        }
        BenchmarkRecordSchema::CoreLocalFailureV1 => return Err(BenchmarkError::EvidenceRejected),
    };
    let expected = BTreeSet::from([
        "candidate_id",
        "engine_payload_sha256",
        measured_field,
        "model_revision",
        "model_uri",
        "runtime_version",
        "target",
        "target_contract_sha256",
    ]);
    if subject.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(BenchmarkError::EvidenceRejected);
    }
    RuntimeCandidateId::parse(string_field(subject, "candidate_id")?)
        .map_err(|_| BenchmarkError::EvidenceRejected)?;
    require_runtime_version(string_field(subject, "runtime_version")?)?;
    require_model_uri(string_field(subject, "model_uri")?)?;
    require_lower_hex(string_field(subject, "model_revision")?, 40)?;
    digest_field(subject, "engine_payload_sha256")?;
    TechnicalName::parse(string_field(subject, "target")?)
        .map_err(|_| BenchmarkError::EvidenceRejected)?;
    match schema {
        BenchmarkRecordSchema::OciExecutionPayloadV7 => {
            require_digest_pinned_oci(string_field(subject, measured_field)?)?;
        }
        BenchmarkRecordSchema::NativeExecutionPayloadV8 => {
            if !matches!(
                string_field(subject, measured_field)?,
                "native-archive" | "python-standalone" | "embedded-application"
            ) {
                return Err(BenchmarkError::EvidenceRejected);
            }
        }
        BenchmarkRecordSchema::CoreLocalFailureV1 => {
            return Err(BenchmarkError::EvidenceRejected);
        }
        BenchmarkRecordSchema::CommunityVerificationV1 => {
            return Err(BenchmarkError::EvidenceRejected);
        }
    }
    digest_field(subject, "target_contract_sha256")
}

// Serializes one JSON value through the established sorted compact UTF-8 contract.
pub(crate) fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, BenchmarkError> {
    let mut bytes = Vec::new();
    write_canonical_json(value, &mut bytes)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// Serializes public benchmark JSON through the exact Python-compatible canonical byte contract.
pub fn canonical_benchmark_json_bytes(value: &Value) -> Result<Vec<u8>, BenchmarkError> {
    canonical_json_bytes(value)
}

// Validates one complete public benchmark record and returns its immutable evidence receipt.
pub fn validate_benchmark_record_bytes(bytes: &[u8]) -> Result<BenchmarkEvidence, BenchmarkError> {
    let parsed = parsed_evidence(bytes)?;
    if !matches!(
        parsed.binding,
        ParsedBenchmarkEvidenceBinding::Successful { .. }
    ) {
        return Err(BenchmarkError::EvidenceRejected);
    }
    Ok(parsed.receipt)
}

// Validates exact public or Core-local evidence bytes against one typed request and outcome.
pub fn validate_benchmark_evidence_bytes(
    request: &BenchmarkRequest,
    outcome: &BenchmarkExecutionOutcome,
    bytes: &[u8],
) -> Result<BenchmarkEvidence, BenchmarkError> {
    let parsed = parsed_evidence(bytes)?;
    require_evidence_binding(request, outcome, bytes, &parsed)?;
    Ok(parsed.receipt)
}

// Writes one JSON value with Python's sorted compact ensure_ascii-false number contract.
fn write_canonical_json(value: &Value, bytes: &mut Vec<u8>) -> Result<(), BenchmarkError> {
    match value {
        Value::Null => bytes.extend_from_slice(b"null"),
        Value::Bool(true) => bytes.extend_from_slice(b"true"),
        Value::Bool(false) => bytes.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                bytes.extend_from_slice(value.to_string().as_bytes());
            } else if let Some(value) = number.as_u64() {
                bytes.extend_from_slice(value.to_string().as_bytes());
            } else {
                let value = number
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .ok_or(BenchmarkError::EvidenceRejected)?;
                bytes.extend_from_slice(python_float(value)?.as_bytes());
            }
        }
        Value::String(value) => bytes.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|_| BenchmarkError::EvidenceRejected)?
                .as_bytes(),
        ),
        Value::Array(values) => {
            bytes.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                write_canonical_json(value, bytes)?;
            }
            bytes.push(b']');
        }
        Value::Object(values) => {
            bytes.push(b'{');
            let mut fields = values.iter().collect::<Vec<_>>();
            fields.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (field, value)) in fields.into_iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                bytes.extend_from_slice(
                    serde_json::to_string(field)
                        .map_err(|_| BenchmarkError::EvidenceRejected)?
                        .as_bytes(),
                );
                bytes.push(b':');
                write_canonical_json(value, bytes)?;
            }
            bytes.push(b'}');
        }
    }
    Ok(())
}

// Formats one finite binary float exactly like Python's JSON encoder.
fn python_float(value: f64) -> Result<String, BenchmarkError> {
    let rendered = serde_json::to_string(&value).map_err(|_| BenchmarkError::EvidenceRejected)?;
    if let Some((coefficient, exponent)) = rendered.split_once('e') {
        let exponent = exponent
            .parse::<i32>()
            .map_err(|_| BenchmarkError::EvidenceRejected)?;
        return Ok(format_python_exponent(coefficient, exponent));
    }
    let unsigned = rendered.strip_prefix('-').unwrap_or(&rendered);
    let Some(nonzero) = unsigned
        .bytes()
        .position(|byte| byte.is_ascii_digit() && byte != b'0')
    else {
        return Ok(rendered);
    };
    let decimal = unsigned.find('.').unwrap_or(unsigned.len());
    let exponent = if nonzero < decimal {
        decimal as i32 - nonzero as i32 - 1
    } else {
        decimal as i32 - nonzero as i32
    };
    if exponent >= -4 {
        return Ok(rendered);
    }
    let negative = rendered.starts_with('-');
    let digits = unsigned
        .bytes()
        .filter(|byte| byte.is_ascii_digit())
        .skip_while(|byte| *byte == b'0')
        .map(char::from)
        .collect::<String>();
    let coefficient = if digits.len() == 1 {
        digits
    } else {
        format!("{}.{}", &digits[..1], &digits[1..])
    };
    Ok(format_python_exponent(
        &if negative {
            format!("-{coefficient}")
        } else {
            coefficient
        },
        exponent,
    ))
}

// Writes one Python-style signed exponent with at least two decimal digits.
fn format_python_exponent(coefficient: &str, exponent: i32) -> String {
    let sign = if exponent < 0 { '-' } else { '+' };
    format!("{coefficient}e{sign}{:02}", exponent.unsigned_abs())
}

// Returns one SHA-256 identity for exact bytes.
pub(crate) fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is canonical")
}

// Reads one owner-only, single-link regular file after no-follow metadata checks.
pub(crate) fn read_private_file(
    native_io: &dyn BenchmarkEvidenceNativeIo,
    path: &Path,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<Vec<u8>, BenchmarkError> {
    let metadata = native_io
        .metadata(path)
        .map_err(|_| evidence_provider_error("evidence inspection failed"))?
        .ok_or_else(|| evidence_provider_error("evidence is unavailable"))?;
    require_private_file_metadata(&metadata, owner_user_id, Some(maximum_bytes))?;
    let bytes = native_io
        .read_file(path, maximum_bytes)
        .map_err(|_| evidence_provider_error("evidence read failed"))?;
    if bytes.len() as u64 != metadata.byte_count() {
        return Err(evidence_provider_error("evidence changed while reading"));
    }
    Ok(bytes)
}

// Requires one exact private directory.
pub(crate) fn require_directory(
    native_io: &dyn BenchmarkEvidenceNativeIo,
    path: &Path,
    owner_user_id: u32,
) -> Result<(), BenchmarkError> {
    let metadata = native_io
        .metadata(path)
        .map_err(|_| evidence_provider_error("evidence directory inspection failed"))?
        .ok_or_else(|| evidence_provider_error("evidence directory is unavailable"))?;
    if metadata.kind() != BenchmarkEvidenceEntryKind::Directory
        || metadata.owner_user_id() != owner_user_id
        || metadata.mode() != PRIVATE_DIRECTORY_MODE
        || metadata.link_count() < 1
    {
        return Err(evidence_provider_error("evidence directory is unsafe"));
    }
    Ok(())
}

// Requires one owner-only regular file with exactly one native link.
pub(crate) fn require_private_file_metadata(
    metadata: &BenchmarkEvidenceFileMetadata,
    owner_user_id: u32,
    maximum_bytes: Option<usize>,
) -> Result<(), BenchmarkError> {
    if metadata.kind() != BenchmarkEvidenceEntryKind::RegularFile
        || metadata.owner_user_id() != owner_user_id
        || metadata.mode() != PRIVATE_FILE_MODE
        || metadata.link_count() != 1
        || maximum_bytes.is_some_and(|maximum| {
            metadata.byte_count() == 0 || metadata.byte_count() > maximum as u64
        })
    {
        return Err(evidence_provider_error("evidence file is unsafe"));
    }
    Ok(())
}

// Validates one absolute normalized path before any native I/O.
pub(crate) fn require_absolute_normal_path(path: &Path) -> Result<(), BenchmarkError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(evidence_provider_error("evidence path is invalid"));
    }
    Ok(())
}

// Returns one required string field from a closed JSON object.
fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, BenchmarkError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Returns one required canonical SHA-256 field.
fn digest_field(object: &Map<String, Value>, field: &str) -> Result<Sha256Digest, BenchmarkError> {
    Sha256Digest::parse(string_field(object, field)?).map_err(|_| BenchmarkError::EvidenceRejected)
}

// Returns one positive integer field without accepting booleans or floating values.
fn positive_u64(object: &Map<String, Value>, field: &str) -> Result<u64, BenchmarkError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Requires one lowercase hexadecimal identity of an exact byte length.
fn require_lower_hex(value: &str, length: usize) -> Result<(), BenchmarkError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BenchmarkError::EvidenceRejected);
    }
    Ok(())
}

// Requires one bounded semantic-version-shaped runtime release identity.
fn require_runtime_version(value: &str) -> Result<(), BenchmarkError> {
    let (core, suffix) = value
        .split_once(['-', '+'])
        .map_or((value, None), |(core, suffix)| (core, Some(suffix)));
    let numeric = core.split('.').collect::<Vec<_>>();
    let valid = numeric.len() == 3
        && numeric
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && suffix.is_none_or(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        });
    if !valid || value.len() > 128 {
        return Err(BenchmarkError::EvidenceRejected);
    }
    Ok(())
}

// Requires one bounded Hugging Face repository URI.
fn require_model_uri(value: &str) -> Result<(), BenchmarkError> {
    let Some(repository) = value.strip_prefix("hf://") else {
        return Err(BenchmarkError::EvidenceRejected);
    };
    let parts = repository.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(BenchmarkError::EvidenceRejected);
    }
    Ok(())
}

// Requires one digest-pinned OCI reference without whitespace or a second separator.
fn require_digest_pinned_oci(value: &str) -> Result<(), BenchmarkError> {
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        return Err(BenchmarkError::EvidenceRejected);
    };
    if repository.is_empty()
        || repository.chars().any(char::is_whitespace)
        || repository.contains('@')
    {
        return Err(BenchmarkError::EvidenceRejected);
    }
    require_lower_hex(digest, 64)
}

// Converts one fixed provider failure into redacted benchmark language.
fn evidence_provider_error(reason: &'static str) -> BenchmarkError {
    BenchmarkError::provider("evidence", reason)
}

// Returns one stable cleanup failure without exposing a native path.
fn evidence_cleanup_error() -> BenchmarkError {
    evidence_provider_error("evidence cleanup failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Preserves Python's exponent thresholds, padding, sorting, and unescaped Unicode contract.
    #[test]
    fn canonical_json_matches_established_python_bytes() {
        let value: Value = serde_json::from_str(
            r#"{"score":46.669047558312116,"small":1e-5,"tiny":1e-7,"large":1e16,"fixed":1e15,"unicode":"é"}"#,
        )
        .expect("JSON");
        assert_eq!(
            canonical_json_bytes(&value).expect("canonical JSON"),
            "{\"fixed\":1000000000000000.0,\"large\":1e+16,\"score\":46.669047558312116,\"small\":1e-05,\"tiny\":1e-07,\"unicode\":\"é\"}\n".as_bytes()
        );
    }
}
