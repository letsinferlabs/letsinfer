// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use li_core_interface::{
    ArtifactRevision, LogicalModelName, RuntimeCandidateId, RuntimeInstallationId, RuntimeVersion,
    Sha256Digest, TargetId, TechnicalName,
};
use serde_json::Value;

use crate::{RuntimeError, RuntimeExecutionDistribution, RuntimeExecutionManifest};

const MAX_APPLICATION_HANDLE_BYTES: usize = 512;

// Describes the exact independently supervised application content required by one runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEmbeddedApplicationAcquisitionRequest {
    candidate_id: RuntimeCandidateId,
    version: RuntimeVersion,
    logical_model: LogicalModelName,
    target_id: TargetId,
    runtime_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    payload_id: Sha256Digest,
    source_revision: ArtifactRevision,
    bundle_id: String,
    embedded_engine: TechnicalName,
    minimum_version: RuntimeVersion,
    entrypoint: PathBuf,
    port_count: u16,
}

impl RuntimeEmbeddedApplicationAcquisitionRequest {
    // Creates one request only after the runtime distribution has been structurally validated.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        candidate_id: RuntimeCandidateId,
        version: RuntimeVersion,
        logical_model: LogicalModelName,
        target_id: TargetId,
        runtime_digest: Sha256Digest,
        manifest_digest: Sha256Digest,
        payload_id: Sha256Digest,
        source_revision: ArtifactRevision,
        bundle_id: String,
        embedded_engine: TechnicalName,
        minimum_version: RuntimeVersion,
        entrypoint: PathBuf,
        port_count: u16,
    ) -> Result<Self, RuntimeError> {
        if !is_bundle_id(&bundle_id)
            || entrypoint.as_os_str().is_empty()
            || entrypoint.is_absolute()
            || port_count == 0
            || port_count > 4
        {
            return Err(RuntimeError::EmbeddedApplicationInvalid);
        }
        Ok(Self {
            candidate_id,
            version,
            logical_model,
            target_id,
            runtime_digest,
            manifest_digest,
            payload_id,
            source_revision,
            bundle_id,
            embedded_engine,
            minimum_version,
            entrypoint,
            port_count,
        })
    }

    // Returns the exact runtime candidate requesting application ownership.
    pub const fn candidate_id(&self) -> &RuntimeCandidateId {
        &self.candidate_id
    }

    // Returns the exact runtime release requesting application ownership.
    pub const fn version(&self) -> &RuntimeVersion {
        &self.version
    }

    // Returns the user-facing logical model bound to the runtime.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the exact runtime target identity.
    pub const fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    // Returns the immutable runtime-pack digest.
    pub const fn runtime_digest(&self) -> &Sha256Digest {
        &self.runtime_digest
    }

    // Returns the immutable runtime manifest digest.
    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    // Returns the exact embedded Engine payload identity.
    pub const fn payload_id(&self) -> &Sha256Digest {
        &self.payload_id
    }

    // Returns the source revision which produced the embedded Engine.
    pub const fn source_revision(&self) -> &ArtifactRevision {
        &self.source_revision
    }

    // Returns the application bundle identifier which must own execution.
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    // Returns the app-internal Engine identity.
    pub const fn embedded_engine(&self) -> &TechnicalName {
        &self.embedded_engine
    }

    // Returns the minimum acceptable application version.
    pub const fn minimum_version(&self) -> &RuntimeVersion {
        &self.minimum_version
    }

    // Returns the runtime-owned adapter entry point consumed by the application.
    pub fn entrypoint(&self) -> &Path {
        &self.entrypoint
    }

    // Returns the exact number of ports owned by the embedded Engine.
    pub const fn port_count(&self) -> u16 {
        self.port_count
    }

    // Encodes the complete request identity for one private acquisition receipt.
    pub(crate) fn receipt_value(
        &self,
        application_version: &RuntimeVersion,
    ) -> Result<Value, RuntimeError> {
        Ok(serde_json::json!({
            "schema": {"name": "li_runtime_embedded_application_receipt", "version": 1},
            "candidate_id": self.candidate_id.as_str(),
            "version": self.version.as_str(),
            "logical_model": self.logical_model.as_str(),
            "target_id": self.target_id.as_str(),
            "runtime_digest": self.runtime_digest.as_str(),
            "manifest_digest": self.manifest_digest.as_str(),
            "payload_id": self.payload_id.as_str(),
            "source_revision": self.source_revision.as_str(),
            "bundle_id": self.bundle_id,
            "embedded_engine": self.embedded_engine.as_str(),
            "minimum_version": self.minimum_version.as_str(),
            "application_version": application_version.as_str(),
            "entrypoint": path_string(&self.entrypoint)?,
            "port_count": self.port_count
        }))
    }
}

// Confirms that the independently supervised application owns the exact requested payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEmbeddedApplicationAcquisition {
    bundle_id: String,
    embedded_engine: TechnicalName,
    payload_id: Sha256Digest,
    application_version: RuntimeVersion,
}

impl RuntimeEmbeddedApplicationAcquisition {
    // Creates one app-owned acquisition result without weakening any requested identity.
    pub fn new(
        bundle_id: String,
        embedded_engine: TechnicalName,
        payload_id: Sha256Digest,
        application_version: RuntimeVersion,
    ) -> Result<Self, RuntimeError> {
        if !is_bundle_id(&bundle_id) {
            return Err(RuntimeError::EmbeddedApplicationInvalid);
        }
        Ok(Self {
            bundle_id,
            embedded_engine,
            payload_id,
            application_version,
        })
    }

    // Requires the application result to match every app-owned immutable request field.
    pub(crate) fn validate(
        &self,
        request: &RuntimeEmbeddedApplicationAcquisitionRequest,
    ) -> Result<(), RuntimeError> {
        if self.bundle_id != request.bundle_id
            || self.embedded_engine != request.embedded_engine
            || self.payload_id != request.payload_id
            || !version_at_least(&self.application_version, &request.minimum_version)?
        {
            return Err(RuntimeError::EmbeddedApplicationInvalid);
        }
        Ok(())
    }

    // Returns the exact installed application version for the durable receipt.
    pub const fn application_version(&self) -> &RuntimeVersion {
        &self.application_version
    }
}

// Describes one exact execution ownership transfer to the supervised application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEmbeddedApplicationExecutionRequest {
    installation_id: RuntimeInstallationId,
    logical_model: LogicalModelName,
    bundle_id: String,
    embedded_engine: TechnicalName,
    payload_id: Sha256Digest,
    source_revision: ArtifactRevision,
    minimum_version: RuntimeVersion,
    entrypoint: PathBuf,
    port_count: u16,
}

impl RuntimeEmbeddedApplicationExecutionRequest {
    // Projects one already-verified embedded execution manifest into the app boundary.
    pub(crate) fn from_manifest(manifest: &RuntimeExecutionManifest) -> Result<Self, RuntimeError> {
        let RuntimeExecutionDistribution::EmbeddedApplication {
            bundle_id,
            embedded_engine,
            payload_id,
            source_revision,
            minimum_version,
            entrypoint,
            port_count,
        } = manifest.distribution()
        else {
            return Err(RuntimeError::EmbeddedApplicationInvalid);
        };
        Ok(Self {
            installation_id: manifest.installation_id().clone(),
            logical_model: manifest.logical_model().clone(),
            bundle_id: bundle_id.clone(),
            embedded_engine: TechnicalName::parse(embedded_engine)
                .map_err(|_| RuntimeError::EmbeddedApplicationInvalid)?,
            payload_id: payload_id.clone(),
            source_revision: source_revision.clone(),
            minimum_version: minimum_version.clone(),
            entrypoint: entrypoint.clone(),
            port_count: *port_count,
        })
    }

    // Returns the exact installation whose execution is being transferred.
    pub const fn installation_id(&self) -> &RuntimeInstallationId {
        &self.installation_id
    }

    // Returns the logical model exposed by the app-owned execution.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the application bundle which must accept the handoff.
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    // Returns the app-internal Engine identity.
    pub const fn embedded_engine(&self) -> &TechnicalName {
        &self.embedded_engine
    }

    // Returns the exact app-owned payload which must accept the execution.
    pub const fn payload_id(&self) -> &Sha256Digest {
        &self.payload_id
    }

    // Returns the exact source revision which produced the app-owned payload.
    pub const fn source_revision(&self) -> &ArtifactRevision {
        &self.source_revision
    }

    // Returns the minimum supervised application version accepted by the runtime.
    pub const fn minimum_version(&self) -> &RuntimeVersion {
        &self.minimum_version
    }

    // Returns the contained runtime adapter entry point consumed by the application.
    pub fn entrypoint(&self) -> &Path {
        &self.entrypoint
    }

    // Returns the exact number of ports transferred to the application.
    pub const fn port_count(&self) -> u16 {
        self.port_count
    }
}

// Confirms that one supervised application accepted an exact execution handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEmbeddedApplicationExecution {
    installation_id: RuntimeInstallationId,
    bundle_id: String,
    embedded_engine: TechnicalName,
    payload_id: Sha256Digest,
    application_version: RuntimeVersion,
    application_handle: String,
}

impl RuntimeEmbeddedApplicationExecution {
    // Creates one opaque app-owned handle bound to the exact requested execution identity.
    pub fn new(
        installation_id: RuntimeInstallationId,
        bundle_id: String,
        embedded_engine: TechnicalName,
        payload_id: Sha256Digest,
        application_version: RuntimeVersion,
        application_handle: String,
    ) -> Result<Self, RuntimeError> {
        if !is_bundle_id(&bundle_id)
            || application_handle.is_empty()
            || application_handle.len() > MAX_APPLICATION_HANDLE_BYTES
            || application_handle.chars().any(char::is_control)
        {
            return Err(RuntimeError::EmbeddedApplicationInvalid);
        }
        Ok(Self {
            installation_id,
            bundle_id,
            embedded_engine,
            payload_id,
            application_version,
            application_handle,
        })
    }

    // Requires the application result to preserve the complete handoff identity.
    pub(crate) fn validate(
        &self,
        request: &RuntimeEmbeddedApplicationExecutionRequest,
    ) -> Result<(), RuntimeError> {
        if self.installation_id != request.installation_id
            || self.bundle_id != request.bundle_id
            || self.embedded_engine != request.embedded_engine
            || self.payload_id != request.payload_id
            || !version_at_least(&self.application_version, &request.minimum_version)?
        {
            return Err(RuntimeError::EmbeddedApplicationInvalid);
        }
        Ok(())
    }

    // Returns the exact installation accepted by the application.
    pub const fn installation_id(&self) -> &RuntimeInstallationId {
        &self.installation_id
    }

    // Returns the supervised application version which accepted the execution.
    pub const fn application_version(&self) -> &RuntimeVersion {
        &self.application_version
    }

    // Returns the opaque app-owned execution handle without interpreting it in Core.
    pub fn application_handle(&self) -> &str {
        &self.application_handle
    }
}

// Defines the only acquisition and execution boundary for embedded application Engines.
pub trait RuntimeEmbeddedApplicationProvider: Send + Sync {
    // Verifies or acquires the exact embedded payload without host materialization fallback.
    fn acquire(
        &self,
        request: &RuntimeEmbeddedApplicationAcquisitionRequest,
    ) -> Result<RuntimeEmbeddedApplicationAcquisition, RuntimeError>;

    // Accepts one exact execution handoff inside the independently supervised application.
    fn execute(
        &self,
        request: &RuntimeEmbeddedApplicationExecutionRequest,
    ) -> Result<RuntimeEmbeddedApplicationExecution, RuntimeError>;
}

// Compares normalized semantic versions without accepting build metadata or partial versions.
pub(crate) fn version_at_least(
    observed: &RuntimeVersion,
    minimum: &RuntimeVersion,
) -> Result<bool, RuntimeError> {
    let (observed_core, observed_prerelease) = version_key(observed.as_str())?;
    let (minimum_core, minimum_prerelease) = version_key(minimum.as_str())?;
    if observed_core != minimum_core {
        return Ok(observed_core > minimum_core);
    }
    Ok(match (observed_prerelease, minimum_prerelease) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(observed), Some(minimum)) => {
            compare_prerelease(&observed, &minimum)? != Ordering::Less
        }
    })
}

// Converts one validated runtime version into a stable precedence key.
fn version_key(value: &str) -> Result<((u64, u64, u64), Option<String>), RuntimeError> {
    let (core, prerelease) = value
        .split_once('-')
        .map_or((value, None), |(core, value)| {
            (core, Some(value.to_string()))
        });
    let mut values = core.split('.');
    let major = values
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or(RuntimeError::EmbeddedApplicationInvalid)?;
    let minor = values
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or(RuntimeError::EmbeddedApplicationInvalid)?;
    let patch = values
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or(RuntimeError::EmbeddedApplicationInvalid)?;
    if values.next().is_some() {
        return Err(RuntimeError::EmbeddedApplicationInvalid);
    }
    Ok(((major, minor, patch), prerelease))
}

// Compares dot-separated prerelease identifiers using semantic-version precedence.
fn compare_prerelease(left: &str, right: &str) -> Result<Ordering, RuntimeError> {
    let mut left = left.split('.');
    let mut right = right.split('.');
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Ok(Ordering::Equal),
            (None, Some(_)) => return Ok(Ordering::Less),
            (Some(_), None) => return Ok(Ordering::Greater),
            (Some(left), Some(right)) => {
                let ordering = match (
                    left.bytes().all(|byte| byte.is_ascii_digit()),
                    right.bytes().all(|byte| byte.is_ascii_digit()),
                ) {
                    (true, true) => left
                        .parse::<u64>()
                        .map_err(|_| RuntimeError::EmbeddedApplicationInvalid)?
                        .cmp(
                            &right
                                .parse::<u64>()
                                .map_err(|_| RuntimeError::EmbeddedApplicationInvalid)?,
                        ),
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => left.cmp(right),
                };
                if ordering != Ordering::Equal {
                    return Ok(ordering);
                }
            }
        }
    }
}

// Returns whether one value is a canonical reverse-domain application identifier.
fn is_bundle_id(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() >= 2
        && value.len() <= 255
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

// Converts one contained UTF-8 path into receipt text without normalization.
fn path_string(path: &Path) -> Result<&str, RuntimeError> {
    path.to_str()
        .ok_or(RuntimeError::EmbeddedApplicationInvalid)
}
