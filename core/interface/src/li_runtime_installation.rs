// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use crate::{
    ArtifactName, ArtifactRevision, ArtifactUri, EngineDistribution, EntityTimestamps,
    EvidenceLabel, FailureDescription, InterfaceError, LogicalModelName, NodeId,
    RuntimeCandidateId, RuntimeInstallationId, RuntimeSource, RuntimeVersion, Sha256Digest,
    TargetId,
};

const MAX_MODEL_ARTIFACTS: usize = 64;

// Binds one runtime candidate to its exact immutable execution identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeIdentity {
    candidate_id: RuntimeCandidateId,
    version: RuntimeVersion,
    target_id: TargetId,
    source: RuntimeSource,
    engine_distribution: EngineDistribution,
    runtime_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    execution_contract_digest: Sha256Digest,
}

impl RuntimeIdentity {
    // Creates one sealed runtime identity and verifies local-object consistency.
    pub fn new(
        candidate_id: RuntimeCandidateId,
        version: RuntimeVersion,
        target_id: TargetId,
        source: RuntimeSource,
        engine_distribution: EngineDistribution,
        runtime_digest: Sha256Digest,
        manifest_digest: Sha256Digest,
        execution_contract_digest: Sha256Digest,
    ) -> Result<Self, InterfaceError> {
        if let Some(source_digest) = source.as_str().strip_prefix("letsinfer-object:sha256:") {
            if source_digest != runtime_digest.as_str() {
                return Err(InterfaceError::new(
                    "runtime identity",
                    "local source digest differs from the runtime digest",
                ));
            }
        }
        Ok(Self {
            candidate_id,
            version,
            target_id,
            source,
            engine_distribution,
            runtime_digest,
            manifest_digest,
            execution_contract_digest,
        })
    }

    // Returns the exact runtime candidate identity.
    pub const fn candidate_id(&self) -> &RuntimeCandidateId {
        &self.candidate_id
    }

    // Returns the exact runtime version.
    pub const fn version(&self) -> &RuntimeVersion {
        &self.version
    }

    // Returns the exact target identity.
    pub const fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    // Returns the immutable runtime distribution source.
    pub const fn source(&self) -> &RuntimeSource {
        &self.source
    }

    // Returns the exact immutable Engine distribution.
    pub const fn engine_distribution(&self) -> &EngineDistribution {
        &self.engine_distribution
    }

    // Returns the runtime-pack digest.
    pub const fn runtime_digest(&self) -> &Sha256Digest {
        &self.runtime_digest
    }

    // Returns the runtime manifest digest.
    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    // Returns the opaque execution-contract digest.
    pub const fn execution_contract_digest(&self) -> &Sha256Digest {
        &self.execution_contract_digest
    }
}

// Describes one exact GGUF file within a Hugging Face revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GgufFileIdentity {
    filename: String,
    digest: Sha256Digest,
    bytes: Option<u64>,
}

impl GgufFileIdentity {
    // Creates one contained GGUF identity with optional declared size.
    pub fn new(
        filename: &str,
        digest: Sha256Digest,
        bytes: Option<u64>,
    ) -> Result<Self, InterfaceError> {
        if !filename.ends_with(".gguf")
            || filename.contains('/')
            || filename.contains('\\')
            || filename.len() > 255
            || bytes == Some(0)
        {
            return Err(InterfaceError::new(
                "GGUF file identity",
                "filename or byte count is invalid",
            ));
        }
        Ok(Self {
            filename: filename.to_string(),
            digest,
            bytes,
        })
    }

    // Returns the contained GGUF filename.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    // Returns the exact GGUF SHA-256.
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    // Returns the optional declared file size.
    pub const fn bytes(&self) -> Option<u64> {
        self.bytes
    }
}

// Selects complete-revision or exact-file Hugging Face acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelArtifactFormat {
    HuggingFaceSnapshot,
    GgufFile(GgufFileIdentity),
}

// Identifies one exact upstream model artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelArtifact {
    name: ArtifactName,
    uri: ArtifactUri,
    revision: ArtifactRevision,
    format: ModelArtifactFormat,
}

impl ModelArtifact {
    // Creates one exact model artifact identity without acquiring it.
    pub const fn new(
        name: ArtifactName,
        uri: ArtifactUri,
        revision: ArtifactRevision,
        format: ModelArtifactFormat,
    ) -> Self {
        Self {
            name,
            uri,
            revision,
            format,
        }
    }

    // Returns the artifact's role within the runtime.
    pub const fn name(&self) -> &ArtifactName {
        &self.name
    }

    // Returns the upstream repository identity.
    pub const fn uri(&self) -> &ArtifactUri {
        &self.uri
    }

    // Returns the exact upstream revision.
    pub const fn revision(&self) -> &ArtifactRevision {
        &self.revision
    }

    // Returns complete-snapshot or exact-GGUF acquisition identity.
    pub const fn format(&self) -> &ModelArtifactFormat {
        &self.format
    }
}

// Describes the latest observed materialization state on one node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeInstallationState {
    Staging,
    Available,
    Removing,
    Removed,
    Failed,
}

// Describes one immutable host-local model and runtime installation snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeInstallation {
    installation_id: RuntimeInstallationId,
    node_id: NodeId,
    logical_model: LogicalModelName,
    runtime: RuntimeIdentity,
    artifacts: Vec<ModelArtifact>,
    evidence_label: EvidenceLabel,
    state: RuntimeInstallationState,
    last_failure: Option<FailureDescription>,
    timestamps: EntityTimestamps,
}

impl RuntimeInstallation {
    // Creates one bounded installation snapshot without applying evidence policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: RuntimeInstallationId,
        node_id: NodeId,
        logical_model: LogicalModelName,
        runtime: RuntimeIdentity,
        artifacts: Vec<ModelArtifact>,
        evidence_label: EvidenceLabel,
        state: RuntimeInstallationState,
        last_failure: Option<FailureDescription>,
        timestamps: EntityTimestamps,
    ) -> Result<Self, InterfaceError> {
        let artifact_names: HashSet<&ArtifactName> =
            artifacts.iter().map(ModelArtifact::name).collect();
        if artifacts.is_empty()
            || artifacts.len() > MAX_MODEL_ARTIFACTS
            || artifact_names.len() != artifacts.len()
        {
            return Err(InterfaceError::new(
                "runtime installation",
                "artifact identities must be non-empty, unique, and bounded",
            ));
        }
        if state == RuntimeInstallationState::Failed && last_failure.is_none() {
            return Err(InterfaceError::new(
                "runtime installation",
                "failed state requires a failure description",
            ));
        }
        Ok(Self {
            installation_id,
            node_id,
            logical_model,
            runtime,
            artifacts,
            evidence_label,
            state,
            last_failure,
            timestamps,
        })
    }

    // Returns the host-local installation identity.
    pub const fn installation_id(&self) -> &RuntimeInstallationId {
        &self.installation_id
    }

    // Returns the node that owns the installed bytes.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the user-facing logical model identity.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the sealed runtime identity.
    pub const fn runtime(&self) -> &RuntimeIdentity {
        &self.runtime
    }

    // Returns every exact model artifact required by the runtime.
    pub fn artifacts(&self) -> &[ModelArtifact] {
        &self.artifacts
    }

    // Returns the descriptive evidence label without interpreting it as admission.
    pub const fn evidence_label(&self) -> EvidenceLabel {
        self.evidence_label
    }

    // Returns the latest observed installation state.
    pub const fn state(&self) -> RuntimeInstallationState {
        self.state
    }

    // Returns the most recent bounded failure when one exists.
    pub const fn last_failure(&self) -> Option<&FailureDescription> {
        self.last_failure.as_ref()
    }

    // Returns the installation snapshot timestamps.
    pub const fn timestamps(&self) -> EntityTimestamps {
        self.timestamps
    }
}
