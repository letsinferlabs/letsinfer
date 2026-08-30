// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, CpuArchitecture, EngineDistribution,
    EntityTimestamps, EvidenceLabel, FailureDescription, GgufFileIdentity, LogicalModelName,
    ModelArtifact, ModelArtifactFormat, NativeEngineKind, NodeId, OperatingSystem,
    PlatformIdentity, RuntimeCandidateId, RuntimeIdentity, RuntimeInstallation,
    RuntimeInstallationId, RuntimeInstallationState, RuntimeSource, RuntimeVersion, Sha256Digest,
    TargetId, TechnicalName, UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use li_runtime_manager::{RuntimeError, RuntimeInstallationStore, VersionedRuntimeInstallation};
use serde::{Deserialize, Serialize};

// Stores one exact model artifact in the private runtime record.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ArtifactDatabaseRecord {
    name: String,
    uri: String,
    revision: String,
    format: String,
    filename: Option<String>,
    digest: Option<String>,
    bytes: Option<u64>,
}

// Stores one closed Engine distribution projection in private persistence.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) enum EngineDatabaseRecord {
    Oci {
        reference: String,
        immutable_id: String,
        base: Option<String>,
        payload_id: Option<String>,
    },
    Native {
        kind: String,
        operating_system: String,
        architecture: String,
        payload_id: String,
        source_revision: String,
    },
}

// Stores one runtime installation through DatabaseManager's private schema.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RuntimeInstallationDatabaseRecord {
    installation_id: String,
    node_id: String,
    logical_model: String,
    candidate_id: String,
    version: String,
    target_id: String,
    source: String,
    engine: EngineDatabaseRecord,
    runtime_digest: String,
    manifest_digest: String,
    execution_contract_digest: String,
    artifacts: Vec<ArtifactDatabaseRecord>,
    evidence_label: String,
    state: String,
    failure_code: Option<String>,
    failure_message: Option<String>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

impl DatabaseRecord for RuntimeInstallationDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::RuntimeInstallations;

    // Returns the exact runtime-installation identity.
    fn identifier(&self) -> &str {
        &self.installation_id
    }
}

// Adapts RuntimeManager's narrow store contract to DatabaseManager.
pub struct DatabaseRuntimeInstallationStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseRuntimeInstallationStore {
    // Creates one adapter without transferring database lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }
}

impl RuntimeInstallationStore for DatabaseRuntimeInstallationStore {
    // Returns one validated installation when it exists.
    fn read(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
        match self
            .database
            .read(DatabaseQuery::<RuntimeInstallationDatabaseRecord>::record(
                installation_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some(VersionedRuntimeInstallation::new(
                runtime_installation(stored.value)?,
                stored.revision,
            ))),
            Ok(DatabaseResult::Records(_)) => Err(RuntimeError::StoreUnavailable),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(runtime_store_error(error)),
        }
    }

    // Returns every validated installation in identity order.
    fn all(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
        match self
            .database
            .read(DatabaseQuery::<RuntimeInstallationDatabaseRecord>::all())
        {
            Ok(DatabaseResult::Records(records)) => records
                .into_iter()
                .map(|stored| {
                    Ok(VersionedRuntimeInstallation::new(
                        runtime_installation(stored.value)?,
                        stored.revision,
                    ))
                })
                .collect(),
            Ok(DatabaseResult::Record(_)) => Err(RuntimeError::StoreUnavailable),
            Err(error) => Err(runtime_store_error(error)),
        }
    }

    // Creates one staging installation and rejects replay as a conflict.
    fn create(
        &self,
        installation: RuntimeInstallation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        let identity = installation.installation_id().clone();
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!("runtime:create:{}", identity.as_str()),
                runtime_installation_record(&installation),
                DatabaseRevision::Missing,
            ))
            .map_err(runtime_store_error)?;
        require_applied(result.disposition())?;
        Ok(VersionedRuntimeInstallation::new(
            installation,
            result.commit().revision,
        ))
    }

    // Replaces one exact installation revision.
    fn replace(
        &self,
        installation: RuntimeInstallation,
        expected_revision: u64,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        let identity = installation.installation_id().clone();
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!("runtime:replace:{}:{expected_revision}", identity.as_str()),
                runtime_installation_record(&installation),
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(runtime_store_error)?;
        require_applied(result.disposition())?;
        Ok(VersionedRuntimeInstallation::new(
            installation,
            result.commit().revision,
        ))
    }

    // Deletes one exact removed installation revision.
    fn delete(
        &self,
        installation_id: &RuntimeInstallationId,
        expected_revision: u64,
    ) -> Result<(), RuntimeError> {
        let result = self
            .database
            .write(
                DatabaseCommand::<RuntimeInstallationDatabaseRecord>::delete(
                    format!(
                        "runtime:delete:{}:{expected_revision}",
                        installation_id.as_str()
                    ),
                    installation_id.as_str(),
                    DatabaseRevision::Exact(expected_revision),
                ),
            )
            .map_err(runtime_store_error)?;
        require_applied(result.disposition())
    }
}

// Projects one installation into private persistence fields.
pub(crate) fn runtime_installation_record(
    installation: &RuntimeInstallation,
) -> RuntimeInstallationDatabaseRecord {
    RuntimeInstallationDatabaseRecord {
        installation_id: installation.installation_id().as_str().to_string(),
        node_id: installation.node_id().as_str().to_string(),
        logical_model: installation.logical_model().as_str().to_string(),
        candidate_id: installation.runtime().candidate_id().as_str().to_string(),
        version: installation.runtime().version().as_str().to_string(),
        target_id: installation.runtime().target_id().as_str().to_string(),
        source: installation.runtime().source().as_str().to_string(),
        engine: engine_record(installation.runtime().engine_distribution()),
        runtime_digest: installation.runtime().runtime_digest().as_str().to_string(),
        manifest_digest: installation
            .runtime()
            .manifest_digest()
            .as_str()
            .to_string(),
        execution_contract_digest: installation
            .runtime()
            .execution_contract_digest()
            .as_str()
            .to_string(),
        artifacts: installation
            .artifacts()
            .iter()
            .map(|artifact| ArtifactDatabaseRecord {
                name: artifact.name().as_str().to_string(),
                uri: artifact.uri().as_str().to_string(),
                revision: artifact.revision().as_str().to_string(),
                format: artifact_format_name(artifact.format()).to_string(),
                filename: gguf(artifact.format()).map(|value| value.filename().to_string()),
                digest: gguf(artifact.format()).map(|value| value.digest().as_str().to_string()),
                bytes: gguf(artifact.format()).and_then(GgufFileIdentity::bytes),
            })
            .collect(),
        evidence_label: evidence_name(installation.evidence_label()).to_string(),
        state: state_name(installation.state()).to_string(),
        failure_code: installation
            .last_failure()
            .map(|failure| failure.code().as_str().to_string()),
        failure_message: installation
            .last_failure()
            .map(|failure| failure.message().to_string()),
        created_at_unix_milliseconds: installation.timestamps().created_at().value(),
        updated_at_unix_milliseconds: installation.timestamps().updated_at().value(),
    }
}

// Reconstructs one validated installation from private persistence.
pub(crate) fn runtime_installation(
    record: RuntimeInstallationDatabaseRecord,
) -> Result<RuntimeInstallation, RuntimeError> {
    let artifacts = record
        .artifacts
        .into_iter()
        .map(|artifact| {
            let format = artifact_format(&artifact)?;
            Ok(ModelArtifact::new(
                ArtifactName::parse(&artifact.name).map_err(|_| RuntimeError::StoreUnavailable)?,
                ArtifactUri::parse(&artifact.uri).map_err(|_| RuntimeError::StoreUnavailable)?,
                ArtifactRevision::parse(&artifact.revision)
                    .map_err(|_| RuntimeError::StoreUnavailable)?,
                format,
            ))
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    let failure = match (record.failure_code, record.failure_message) {
        (Some(code), Some(message)) => Some(
            FailureDescription::new(
                TechnicalName::parse(&code).map_err(|_| RuntimeError::StoreUnavailable)?,
                &message,
            )
            .map_err(|_| RuntimeError::StoreUnavailable)?,
        ),
        (None, None) => None,
        _ => return Err(RuntimeError::StoreUnavailable),
    };
    RuntimeInstallation::new(
        RuntimeInstallationId::parse(&record.installation_id)
            .map_err(|_| RuntimeError::StoreUnavailable)?,
        NodeId::parse(&record.node_id).map_err(|_| RuntimeError::StoreUnavailable)?,
        LogicalModelName::parse(&record.logical_model)
            .map_err(|_| RuntimeError::StoreUnavailable)?,
        RuntimeIdentity::new(
            RuntimeCandidateId::parse(&record.candidate_id)
                .map_err(|_| RuntimeError::StoreUnavailable)?,
            RuntimeVersion::parse(&record.version).map_err(|_| RuntimeError::StoreUnavailable)?,
            TargetId::parse(&record.target_id).map_err(|_| RuntimeError::StoreUnavailable)?,
            RuntimeSource::parse(&record.source).map_err(|_| RuntimeError::StoreUnavailable)?,
            engine_distribution(record.engine)?,
            Sha256Digest::parse(&record.runtime_digest)
                .map_err(|_| RuntimeError::StoreUnavailable)?,
            Sha256Digest::parse(&record.manifest_digest)
                .map_err(|_| RuntimeError::StoreUnavailable)?,
            Sha256Digest::parse(&record.execution_contract_digest)
                .map_err(|_| RuntimeError::StoreUnavailable)?,
        )
        .map_err(|_| RuntimeError::StoreUnavailable)?,
        artifacts,
        evidence(&record.evidence_label)?,
        state(&record.state)?,
        failure,
        EntityTimestamps::new(
            UnixMilliseconds::new(record.created_at_unix_milliseconds),
            UnixMilliseconds::new(record.updated_at_unix_milliseconds),
        )
        .map_err(|_| RuntimeError::StoreUnavailable)?,
    )
    .map_err(|_| RuntimeError::StoreUnavailable)
}

// Projects one Engine distribution into private persistence fields.
pub(crate) fn engine_record(engine: &EngineDistribution) -> EngineDatabaseRecord {
    match engine {
        EngineDistribution::Oci {
            reference,
            immutable_id,
            base,
            payload_id,
        } => EngineDatabaseRecord::Oci {
            reference: reference.as_str().to_string(),
            immutable_id: immutable_id.as_str().to_string(),
            base: base.as_ref().map(|value| value.as_str().to_string()),
            payload_id: payload_id.as_ref().map(|value| value.as_str().to_string()),
        },
        EngineDistribution::Native {
            kind,
            platform,
            payload_id,
            source_revision,
        } => EngineDatabaseRecord::Native {
            kind: native_kind_name(*kind).to_string(),
            operating_system: operating_system_name(platform.operating_system()).to_string(),
            architecture: architecture_name(platform.architecture()).to_string(),
            payload_id: payload_id.as_str().to_string(),
            source_revision: source_revision.as_str().to_string(),
        },
    }
}

// Reconstructs one Engine distribution from private persistence fields.
pub(crate) fn engine_distribution(
    record: EngineDatabaseRecord,
) -> Result<EngineDistribution, RuntimeError> {
    match record {
        EngineDatabaseRecord::Oci {
            reference,
            immutable_id,
            base,
            payload_id,
        } => Ok(EngineDistribution::oci(
            RuntimeSource::parse(&reference).map_err(|_| RuntimeError::StoreUnavailable)?,
            Sha256Digest::parse(&immutable_id).map_err(|_| RuntimeError::StoreUnavailable)?,
            base.map(|value| RuntimeSource::parse(&value))
                .transpose()
                .map_err(|_| RuntimeError::StoreUnavailable)?,
            payload_id
                .map(|value| Sha256Digest::parse(&value))
                .transpose()
                .map_err(|_| RuntimeError::StoreUnavailable)?,
        )),
        EngineDatabaseRecord::Native {
            kind,
            operating_system,
            architecture,
            payload_id,
            source_revision,
        } => Ok(EngineDistribution::native(
            native_kind(&kind)?,
            PlatformIdentity::new(
                operating_system_value(&operating_system)?,
                architecture_value(&architecture)?,
            ),
            Sha256Digest::parse(&payload_id).map_err(|_| RuntimeError::StoreUnavailable)?,
            ArtifactRevision::parse(&source_revision)
                .map_err(|_| RuntimeError::StoreUnavailable)?,
        )),
    }
}

// Returns the private persistence name for one model artifact format.
fn artifact_format_name(value: &ModelArtifactFormat) -> &'static str {
    match value {
        ModelArtifactFormat::HuggingFaceSnapshot => "huggingface_snapshot",
        ModelArtifactFormat::GgufFile(_) => "gguf_file",
    }
}

// Returns GGUF details only for an exact-file artifact.
fn gguf(value: &ModelArtifactFormat) -> Option<&GgufFileIdentity> {
    match value {
        ModelArtifactFormat::HuggingFaceSnapshot => None,
        ModelArtifactFormat::GgufFile(value) => Some(value),
    }
}

// Reconstructs one closed model artifact format from private persistence.
fn artifact_format(record: &ArtifactDatabaseRecord) -> Result<ModelArtifactFormat, RuntimeError> {
    match record.format.as_str() {
        "huggingface_snapshot"
            if record.filename.is_none() && record.digest.is_none() && record.bytes.is_none() =>
        {
            Ok(ModelArtifactFormat::HuggingFaceSnapshot)
        }
        "gguf_file" => Ok(ModelArtifactFormat::GgufFile(
            GgufFileIdentity::new(
                record
                    .filename
                    .as_deref()
                    .ok_or(RuntimeError::StoreUnavailable)?,
                Sha256Digest::parse(
                    record
                        .digest
                        .as_deref()
                        .ok_or(RuntimeError::StoreUnavailable)?,
                )
                .map_err(|_| RuntimeError::StoreUnavailable)?,
                record.bytes,
            )
            .map_err(|_| RuntimeError::StoreUnavailable)?,
        )),
        _ => Err(RuntimeError::StoreUnavailable),
    }
}

// Returns the private persistence name for one evidence label.
fn evidence_name(value: EvidenceLabel) -> &'static str {
    match value {
        EvidenceLabel::Qualified => "qualified",
        EvidenceLabel::Unqualified => "unqualified",
        EvidenceLabel::Unknown => "unknown",
    }
}

// Parses one private evidence-label value.
fn evidence(value: &str) -> Result<EvidenceLabel, RuntimeError> {
    match value {
        "qualified" => Ok(EvidenceLabel::Qualified),
        "unqualified" => Ok(EvidenceLabel::Unqualified),
        "unknown" => Ok(EvidenceLabel::Unknown),
        _ => Err(RuntimeError::StoreUnavailable),
    }
}

// Returns the private persistence name for one installation state.
fn state_name(value: RuntimeInstallationState) -> &'static str {
    match value {
        RuntimeInstallationState::Staging => "staging",
        RuntimeInstallationState::Available => "available",
        RuntimeInstallationState::Removing => "removing",
        RuntimeInstallationState::Removed => "removed",
        RuntimeInstallationState::Failed => "failed",
    }
}

// Parses one private installation-state value.
fn state(value: &str) -> Result<RuntimeInstallationState, RuntimeError> {
    match value {
        "staging" => Ok(RuntimeInstallationState::Staging),
        "available" => Ok(RuntimeInstallationState::Available),
        "removing" => Ok(RuntimeInstallationState::Removing),
        "removed" => Ok(RuntimeInstallationState::Removed),
        "failed" => Ok(RuntimeInstallationState::Failed),
        _ => Err(RuntimeError::StoreUnavailable),
    }
}

// Converts DatabaseManager failures to RuntimeInstallationStore's narrow surface.
fn runtime_store_error(error: DatabaseError) -> RuntimeError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            RuntimeError::StoreConflict
        }
        DatabaseError::NotFound { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::Corrupt { .. }
        | DatabaseError::Unavailable { .. }
        | DatabaseError::Closed => RuntimeError::StoreUnavailable,
    }
}

// Requires a store mutation to be newly applied rather than replayed.
fn require_applied(disposition: DatabaseCommitDisposition) -> Result<(), RuntimeError> {
    match disposition {
        DatabaseCommitDisposition::Applied => Ok(()),
        DatabaseCommitDisposition::Replayed => Err(RuntimeError::StoreConflict),
    }
}

// Returns the private persistence name for one native Engine kind.
fn native_kind_name(value: NativeEngineKind) -> &'static str {
    match value {
        NativeEngineKind::NativeArchive => "native_archive",
        NativeEngineKind::PythonStandalone => "python_standalone",
        NativeEngineKind::EmbeddedApplication => "embedded_application",
    }
}

// Parses one private native Engine kind.
fn native_kind(value: &str) -> Result<NativeEngineKind, RuntimeError> {
    match value {
        "native_archive" => Ok(NativeEngineKind::NativeArchive),
        "python_standalone" => Ok(NativeEngineKind::PythonStandalone),
        "embedded_application" => Ok(NativeEngineKind::EmbeddedApplication),
        _ => Err(RuntimeError::StoreUnavailable),
    }
}

// Returns the private persistence name for one operating system.
fn operating_system_name(value: OperatingSystem) -> &'static str {
    match value {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
    }
}

// Parses one private operating-system value.
fn operating_system_value(value: &str) -> Result<OperatingSystem, RuntimeError> {
    match value {
        "linux" => Ok(OperatingSystem::Linux),
        "macos" => Ok(OperatingSystem::Macos),
        _ => Err(RuntimeError::StoreUnavailable),
    }
}

// Returns the private persistence name for one CPU architecture.
fn architecture_name(value: CpuArchitecture) -> &'static str {
    match value {
        CpuArchitecture::Arm64 => "arm64",
        CpuArchitecture::X86_64 => "x86_64",
    }
}

// Parses one private CPU-architecture value.
fn architecture_value(value: &str) -> Result<CpuArchitecture, RuntimeError> {
    match value {
        "arm64" => Ok(CpuArchitecture::Arm64),
        "x86_64" => Ok(CpuArchitecture::X86_64),
        _ => Err(RuntimeError::StoreUnavailable),
    }
}
