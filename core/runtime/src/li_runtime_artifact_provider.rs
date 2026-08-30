// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use li_core_interface::{
    ModelArtifact, ModelArtifactFormat, RuntimeInstallation, RuntimeInstallationId, RuntimeSource,
    Sha256Digest,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{RuntimeArtifactProvider, RuntimeCandidate, RuntimeError};
use crate::{
    RuntimeExactCandidateArtifacts, RuntimeExactEngineArtifact, RuntimeExactEngineCleanup,
    RuntimeExactEngineOwnership, RuntimePackArtifactIo, SystemRuntimePackArtifactIo,
};

const EXACT_ENGINE_MARKER_SCHEMA: &str = "li-runtime-exact-engine-cleanup";
const EXACT_ENGINE_MARKER_VERSION: u32 = 1;
const MAXIMUM_EXACT_ENGINE_MARKER_BYTES: u64 = 16 * 1024;
const MAXIMUM_RETAINED_MODEL_MARKER_BYTES: u64 = 512;
const MAXIMUM_RETAINED_MODEL_ENTRIES: usize = 200_000;
const RETAINED_MODEL_PREFIX: &str = ".retained-models-";

// Fetches each immutable artifact class into an exact staging destination.
pub trait RuntimeArtifactFetcher: Send + Sync {
    // Fetches and verifies one runtime pack source and digest.
    fn fetch_runtime_pack(
        &self,
        source: &RuntimeSource,
        digest: &Sha256Digest,
        destination: &Path,
    ) -> Result<(), RuntimeError>;

    // Fetches one exact upstream model artifact snapshot.
    fn fetch_model_artifact(
        &self,
        artifact: &ModelArtifact,
        destination: &Path,
    ) -> Result<(), RuntimeError>;

    // Fetches one exact OCI or native Engine distribution.
    fn fetch_engine_distribution(
        &self,
        candidate: &RuntimeCandidate,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<(), RuntimeError>;

    // Observes exact built-Engine ownership before any mutation begins.
    fn prepare_exact_engine_distribution(
        &self,
        _cleanup: &RuntimeExactEngineCleanup,
    ) -> Result<RuntimeExactEngineOwnership, RuntimeError> {
        Err(RuntimeError::EngineAcquisitionUnavailable)
    }

    // Acquires one exact prepared Engine artifact without falling back to public source selection.
    fn fetch_exact_engine_distribution(
        &self,
        candidate: &RuntimeCandidate,
        artifacts: &RuntimeExactCandidateArtifacts,
        ownership: Option<&RuntimeExactEngineOwnership>,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<Option<RuntimeExactEngineOwnership>, RuntimeError> {
        match artifacts.engine() {
            RuntimeExactEngineArtifact::Reuse | RuntimeExactEngineArtifact::BuiltNative => {
                if ownership.is_some() {
                    return Err(RuntimeError::EngineAcquisitionInvalid);
                }
                self.fetch_engine_distribution(candidate, runtime_root, destination)?;
                Ok(None)
            }
            RuntimeExactEngineArtifact::BuiltOci { .. } => {
                Err(RuntimeError::EngineAcquisitionUnavailable)
            }
        }
    }

    // Revalidates a completed exact Engine acquisition without mutation.
    fn verify_exact_engine_distribution(
        &self,
        _ownership: &RuntimeExactEngineOwnership,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::EngineAcquisitionUnavailable)
    }

    // Removes one built verifier Engine identity without touching ordinary shared images.
    fn remove_exact_engine_distribution(
        &self,
        _ownership: &RuntimeExactEngineOwnership,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::EngineAcquisitionUnavailable)
    }
}

// Fetches one immutable runtime-pack artifact class.
pub trait RuntimePackArtifactFetcher: Send + Sync {
    // Fetches and verifies one runtime pack source and descriptor digest.
    fn fetch(
        &self,
        source: &RuntimeSource,
        digest: &Sha256Digest,
        destination: &Path,
    ) -> Result<(), RuntimeError>;
}

// Fetches one exact upstream model artifact class.
pub trait RuntimeModelArtifactFetcher: Send + Sync {
    // Fetches one exact model artifact into an empty private destination.
    fn fetch(&self, artifact: &ModelArtifact, destination: &Path) -> Result<(), RuntimeError>;
}

// Fetches one immutable OCI or native Engine artifact class.
pub trait RuntimeEngineArtifactFetcher: Send + Sync {
    // Fetches one exact Engine distribution into an empty private destination.
    fn fetch(
        &self,
        candidate: &RuntimeCandidate,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<(), RuntimeError>;

    // Observes exact built-Engine ownership before any mutation begins.
    fn prepare_exact(
        &self,
        _cleanup: &RuntimeExactEngineCleanup,
    ) -> Result<RuntimeExactEngineOwnership, RuntimeError> {
        Err(RuntimeError::EngineAcquisitionUnavailable)
    }

    // Acquires a trusted prepared Engine closure or rejects unsupported local materialization.
    fn fetch_exact(
        &self,
        candidate: &RuntimeCandidate,
        artifacts: &RuntimeExactCandidateArtifacts,
        ownership: Option<&RuntimeExactEngineOwnership>,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<Option<RuntimeExactEngineOwnership>, RuntimeError> {
        match artifacts.engine() {
            RuntimeExactEngineArtifact::Reuse | RuntimeExactEngineArtifact::BuiltNative => {
                if ownership.is_some() {
                    return Err(RuntimeError::EngineAcquisitionInvalid);
                }
                self.fetch(candidate, runtime_root, destination)?;
                Ok(None)
            }
            RuntimeExactEngineArtifact::BuiltOci { .. } => {
                Err(RuntimeError::EngineAcquisitionUnavailable)
            }
        }
    }

    // Revalidates a completed exact Engine acquisition without mutation.
    fn verify_exact(&self, _ownership: &RuntimeExactEngineOwnership) -> Result<(), RuntimeError> {
        Err(RuntimeError::EngineAcquisitionUnavailable)
    }

    // Removes one exact built verifier Engine identity without a broad image-prune operation.
    fn remove_exact(&self, _ownership: &RuntimeExactEngineOwnership) -> Result<(), RuntimeError> {
        Err(RuntimeError::EngineAcquisitionUnavailable)
    }
}

// Composes the three independently testable immutable artifact mechanisms.
pub struct ComposedRuntimeArtifactFetcher {
    runtime_packs: Arc<dyn RuntimePackArtifactFetcher>,
    models: Arc<dyn RuntimeModelArtifactFetcher>,
    engines: Arc<dyn RuntimeEngineArtifactFetcher>,
}

// Selects OCI or native Engine materialization from the candidate's closed distribution union.
pub struct ComposedRuntimeEngineFetcher {
    oci: Arc<dyn RuntimeEngineArtifactFetcher>,
    native: Arc<dyn RuntimeEngineArtifactFetcher>,
}

impl ComposedRuntimeEngineFetcher {
    // Creates one Engine provider from independently testable OCI and native mechanisms.
    pub const fn new(
        oci: Arc<dyn RuntimeEngineArtifactFetcher>,
        native: Arc<dyn RuntimeEngineArtifactFetcher>,
    ) -> Self {
        Self { oci, native }
    }
}

impl RuntimeEngineArtifactFetcher for ComposedRuntimeEngineFetcher {
    // Delegates one exact closed distribution without fallback between mechanisms.
    fn fetch(
        &self,
        candidate: &RuntimeCandidate,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        match candidate.runtime().engine_distribution() {
            li_core_interface::EngineDistribution::Oci { .. } => {
                self.oci.fetch(candidate, runtime_root, destination)
            }
            li_core_interface::EngineDistribution::Native { .. } => {
                self.native.fetch(candidate, runtime_root, destination)
            }
        }
    }

    // Routes one preparation-bound acquisition through the candidate's exact distribution kind.
    fn fetch_exact(
        &self,
        candidate: &RuntimeCandidate,
        artifacts: &RuntimeExactCandidateArtifacts,
        ownership: Option<&RuntimeExactEngineOwnership>,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<Option<RuntimeExactEngineOwnership>, RuntimeError> {
        match candidate.runtime().engine_distribution() {
            li_core_interface::EngineDistribution::Oci { .. } => {
                self.oci
                    .fetch_exact(candidate, artifacts, ownership, runtime_root, destination)
            }
            li_core_interface::EngineDistribution::Native { .. } => {
                self.native
                    .fetch_exact(candidate, artifacts, ownership, runtime_root, destination)
            }
        }
    }

    // Routes built verifier OCI observation only to the OCI Engine provider.
    fn prepare_exact(
        &self,
        cleanup: &RuntimeExactEngineCleanup,
    ) -> Result<RuntimeExactEngineOwnership, RuntimeError> {
        self.oci.prepare_exact(cleanup)
    }

    // Revalidates completed built verifier OCI ownership through the OCI provider.
    fn verify_exact(&self, ownership: &RuntimeExactEngineOwnership) -> Result<(), RuntimeError> {
        self.oci.verify_exact(ownership)
    }

    // Routes built verifier OCI cleanup only to the OCI Engine provider.
    fn remove_exact(&self, ownership: &RuntimeExactEngineOwnership) -> Result<(), RuntimeError> {
        self.oci.remove_exact(ownership)
    }
}

impl ComposedRuntimeArtifactFetcher {
    // Creates one fetcher without transferring lifecycle ownership to its providers.
    pub const fn new(
        runtime_packs: Arc<dyn RuntimePackArtifactFetcher>,
        models: Arc<dyn RuntimeModelArtifactFetcher>,
        engines: Arc<dyn RuntimeEngineArtifactFetcher>,
    ) -> Self {
        Self {
            runtime_packs,
            models,
            engines,
        }
    }
}

impl RuntimeArtifactFetcher for ComposedRuntimeArtifactFetcher {
    // Delegates runtime-pack acquisition to its exact mechanism owner.
    fn fetch_runtime_pack(
        &self,
        source: &RuntimeSource,
        digest: &Sha256Digest,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.runtime_packs.fetch(source, digest, destination)
    }

    // Delegates model acquisition to its exact mechanism owner.
    fn fetch_model_artifact(
        &self,
        artifact: &ModelArtifact,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.models.fetch(artifact, destination)
    }

    // Delegates Engine acquisition to its exact mechanism owner.
    fn fetch_engine_distribution(
        &self,
        candidate: &RuntimeCandidate,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.engines.fetch(candidate, runtime_root, destination)
    }

    // Delegates pre-mutation exact Engine ownership observation.
    fn prepare_exact_engine_distribution(
        &self,
        cleanup: &RuntimeExactEngineCleanup,
    ) -> Result<RuntimeExactEngineOwnership, RuntimeError> {
        self.engines.prepare_exact(cleanup)
    }

    // Delegates the preparation-bound Engine closure without public fallback for built OCI bytes.
    fn fetch_exact_engine_distribution(
        &self,
        candidate: &RuntimeCandidate,
        artifacts: &RuntimeExactCandidateArtifacts,
        ownership: Option<&RuntimeExactEngineOwnership>,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<Option<RuntimeExactEngineOwnership>, RuntimeError> {
        self.engines
            .fetch_exact(candidate, artifacts, ownership, runtime_root, destination)
    }

    // Delegates completed exact Engine ownership verification.
    fn verify_exact_engine_distribution(
        &self,
        ownership: &RuntimeExactEngineOwnership,
    ) -> Result<(), RuntimeError> {
        self.engines.verify_exact(ownership)
    }

    // Delegates exact built-Engine cleanup to the composed Engine provider.
    fn remove_exact_engine_distribution(
        &self,
        ownership: &RuntimeExactEngineOwnership,
    ) -> Result<(), RuntimeError> {
        self.engines.remove_exact(ownership)
    }
}

// Verifies the complete staged or installed artifact closure.
pub trait RuntimeArtifactVerifier: Send + Sync {
    // Verifies an exact retained model closure without requiring runtime or Engine bytes.
    fn verify_models(
        &self,
        _artifacts: &[ModelArtifact],
        _root: &Path,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Requires runtime pack, model artifacts, and Engine distribution to match the candidate.
    fn verify(&self, candidate: &RuntimeCandidate, root: &Path) -> Result<(), RuntimeError>;
}

// Owns private staging, atomic activation, verification, and exact cleanup.
pub struct FilesystemRuntimeArtifactProvider {
    root: PathBuf,
    fetcher: Arc<dyn RuntimeArtifactFetcher>,
    verifier: Arc<dyn RuntimeArtifactVerifier>,
}

impl FilesystemRuntimeArtifactProvider {
    // Creates one provider rooted at an explicit absolute managed directory.
    pub fn new(
        root: PathBuf,
        fetcher: Arc<dyn RuntimeArtifactFetcher>,
        verifier: Arc<dyn RuntimeArtifactVerifier>,
    ) -> Result<Self, RuntimeError> {
        if !root.is_absolute() {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        Ok(Self {
            root,
            fetcher,
            verifier,
        })
    }

    // Returns the exact managed root for one installation identity.
    fn installation_root(&self, installation_id: &RuntimeInstallationId) -> PathBuf {
        self.root.join(installation_id.as_str())
    }

    // Returns the exact private staging root for one installation identity.
    fn staging_root(&self, installation_id: &RuntimeInstallationId) -> PathBuf {
        self.root
            .join(format!(".{}.incoming", installation_id.as_str()))
    }

    // Returns the durable removal root used after retained models leave an installation.
    fn removal_root(&self, installation_id: &RuntimeInstallationId) -> PathBuf {
        self.root
            .join(format!(".{}.removing", installation_id.as_str()))
    }

    // Returns the durable private built-Engine cleanup marker for one exact installation.
    fn exact_engine_marker(&self, installation_id: &RuntimeInstallationId) -> PathBuf {
        self.root
            .join(format!(".{}.exact-engine.json", installation_id.as_str()))
    }

    // Returns the durable source marker for one in-progress retained-model consumption.
    fn retained_model_consumption_marker(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> PathBuf {
        self.root.join(format!(
            ".{}.retained-model-source",
            installation_id.as_str()
        ))
    }

    // Returns one collision-free retained-model root bound to exact artifacts and installation.
    fn retained_model_root(
        &self,
        artifacts: &[ModelArtifact],
        installation_id: &RuntimeInstallationId,
    ) -> PathBuf {
        self.root.join(format!(
            "{RETAINED_MODEL_PREFIX}{}-{}",
            model_closure_identity(artifacts),
            installation_id.as_str()
        ))
    }

    // Returns verified retained model roots for one exact artifact closure in stable order.
    fn retained_model_roots(
        &self,
        artifacts: &[ModelArtifact],
    ) -> Result<Vec<PathBuf>, RuntimeError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        validate_private_directory(&self.root)?;
        let prefix = format!(
            "{RETAINED_MODEL_PREFIX}{}-",
            model_closure_identity(artifacts)
        );
        let mut roots = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| RuntimeError::ArtifactUnavailable)? {
            let path = entry.map_err(|_| RuntimeError::ArtifactUnavailable)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(identity) = name.strip_prefix(&prefix) else {
                continue;
            };
            if RuntimeInstallationId::parse(identity).is_err() {
                continue;
            }
            validate_private_directory(&path)?;
            roots.push(path);
        }
        roots.sort();
        Ok(roots)
    }

    // Returns retained closures owned by one exact installation identity in stable order.
    fn installation_retained_model_roots(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Vec<PathBuf>, RuntimeError> {
        let suffix = format!("-{}", installation_id.as_str());
        let mut roots = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| RuntimeError::ArtifactUnavailable)? {
            let path = entry.map_err(|_| RuntimeError::ArtifactUnavailable)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with(RETAINED_MODEL_PREFIX) && name.ends_with(&suffix) {
                validate_private_directory(&path)?;
                roots.push(path);
            }
        }
        roots.sort();
        Ok(roots)
    }

    // Atomically consumes the first verified retained closure into one empty staging root.
    fn restore_retained_models(
        &self,
        candidate: &RuntimeCandidate,
        installation_id: &RuntimeInstallationId,
        destination: &Path,
    ) -> Result<Option<PathBuf>, RuntimeError> {
        for retained in self.retained_model_roots(candidate.artifacts())? {
            if let Err(error) = validate_retained_model_tree(&retained) {
                if !retained.exists() && !retained.is_symlink() {
                    continue;
                }
                return Err(error);
            }
            if self
                .verifier
                .verify_models(candidate.artifacts(), &retained)
                .is_err()
            {
                if retained.exists() || retained.is_symlink() {
                    remove_private_root(&retained)?;
                }
                continue;
            }
            let marker = self.retained_model_consumption_marker(installation_id);
            write_retained_model_marker(&marker, &retained)?;
            remove_private_root(destination)?;
            if activate_no_replace(&retained, destination).is_err() {
                fs::remove_file(&marker).map_err(|_| RuntimeError::ArtifactUnavailable)?;
                create_private_directory(destination)?;
                if retained.exists() || retained.is_symlink() {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
                continue;
            }
            return Ok(Some(retained));
        }
        Ok(None)
    }

    // Restores crash-interrupted retained models before stale staging cleanup.
    fn recover_retained_models(
        &self,
        candidate: &RuntimeCandidate,
        installation_id: &RuntimeInstallationId,
        staging: &Path,
    ) -> Result<(), RuntimeError> {
        let marker = self.retained_model_consumption_marker(installation_id);
        if !marker.exists() && !marker.is_symlink() {
            if staging.exists() {
                remove_private_root(staging)?;
            }
            return Ok(());
        }
        let retained = read_retained_model_marker(&marker, &self.root, candidate.artifacts())?;
        if retained.exists() || retained.is_symlink() {
            validate_private_directory(&retained)?;
            validate_retained_model_tree(&retained)?;
            self.verifier
                .verify_models(candidate.artifacts(), &retained)?;
        } else {
            let models = staging.join("models");
            validate_retained_model_tree(&models)?;
            self.verifier
                .verify_models(candidate.artifacts(), &models)?;
            activate_no_replace(&models, &retained)?;
        }
        if staging.exists() {
            remove_private_root(staging)?;
        }
        fs::remove_file(marker).map_err(|_| RuntimeError::ArtifactUnavailable)
    }
}

impl RuntimeArtifactProvider for FilesystemRuntimeArtifactProvider {
    // Fetches all immutable inputs and atomically activates one complete root.
    fn acquire(
        &self,
        candidate: &RuntimeCandidate,
        installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError> {
        prepare_managed_root(&self.root)?;
        let _lock = acquire_installation_lock(&self.root, installation_id)?;
        let destination = self.installation_root(installation_id);
        if destination.is_symlink() {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        if destination.exists() {
            validate_private_directory(&destination)?;
            self.verifier.verify(candidate, &destination)?;
            let marker = self.retained_model_consumption_marker(installation_id);
            if marker.exists()
                && validate_private_file(&marker, MAXIMUM_RETAINED_MODEL_MARKER_BYTES).is_ok()
            {
                let _ = fs::remove_file(marker);
            }
            return Ok(());
        }
        let staging = self.staging_root(installation_id);
        self.recover_retained_models(candidate, installation_id, &staging)?;
        create_private_directory(&staging)?;
        let mut restored_models = None;
        let result = (|| {
            let runtime_root = staging.join("runtime");
            let model_root = staging.join("models");
            let engine_root = staging.join("engine");
            create_private_directory(&runtime_root)?;
            create_private_directory(&model_root)?;
            create_private_directory(&engine_root)?;
            self.fetcher.fetch_runtime_pack(
                candidate.runtime().source(),
                candidate.runtime().runtime_digest(),
                &runtime_root,
            )?;
            restored_models =
                self.restore_retained_models(candidate, installation_id, &model_root)?;
            if restored_models.is_none() {
                for artifact in candidate.artifacts() {
                    let artifact_root = model_root.join(artifact.name().as_str());
                    create_private_directory(&artifact_root)?;
                    self.fetcher
                        .fetch_model_artifact(artifact, &artifact_root)?;
                }
            }
            self.fetcher
                .fetch_engine_distribution(candidate, &runtime_root, &engine_root)?;
            self.verifier.verify(candidate, &staging)?;
            activate_no_replace(&staging, &destination)
        })();
        if result.is_err() {
            if let Some(retained) = restored_models.as_ref() {
                let model_root = staging.join("models");
                if model_root.exists() && activate_no_replace(&model_root, &retained).is_err() {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
                let marker = self.retained_model_consumption_marker(installation_id);
                fs::remove_file(marker).map_err(|_| RuntimeError::ArtifactUnavailable)?;
            }
            if staging.exists() {
                let _ = remove_private_root(&staging);
            }
        } else if restored_models.is_some() {
            let marker = self.retained_model_consumption_marker(installation_id);
            let _ = fs::remove_file(marker);
        }
        result
    }

    // Materializes one retained trusted runtime pack and exact Engine closure atomically.
    fn acquire_exact(
        &self,
        candidate: &RuntimeCandidate,
        artifacts: &RuntimeExactCandidateArtifacts,
        installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError> {
        prepare_managed_root(&self.root)?;
        let _lock = acquire_installation_lock(&self.root, installation_id)?;
        let marker = self.exact_engine_marker(installation_id);
        let cleanup = exact_engine_cleanup(candidate, artifacts)?;
        let mut ownership = match cleanup {
            Some(cleanup) if marker.exists() || marker.is_symlink() => {
                let ownership = read_exact_engine_marker(&marker, installation_id)?;
                if ownership.cleanup() != &cleanup {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
                Some(ownership)
            }
            Some(cleanup) => {
                let ownership = self.fetcher.prepare_exact_engine_distribution(&cleanup)?;
                if ownership.cleanup() != &cleanup || ownership.is_acquired() {
                    return Err(RuntimeError::EngineAcquisitionInvalid);
                }
                write_new_exact_engine_marker(&marker, installation_id, &ownership)?;
                Some(ownership)
            }
            None if marker.exists() || marker.is_symlink() => {
                return Err(RuntimeError::ArtifactUnavailable);
            }
            None => None,
        };
        let destination = self.installation_root(installation_id);
        if destination.is_symlink() {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        if destination.exists() {
            validate_private_directory(&destination)?;
            if let Some(ownership) = ownership.as_ref() {
                if !ownership.is_acquired() {
                    return Err(RuntimeError::EngineAcquisitionInvalid);
                }
                self.fetcher.verify_exact_engine_distribution(ownership)?;
            }
            return self.verifier.verify(candidate, &destination);
        }
        let staging = self.staging_root(installation_id);
        if staging.exists() {
            remove_private_root(&staging)?;
        }
        create_private_directory(&staging)?;
        let result = (|| {
            let runtime_root = staging.join("runtime");
            let model_root = staging.join("models");
            let engine_root = staging.join("engine");
            create_private_directory(&runtime_root)?;
            create_private_directory(&model_root)?;
            create_private_directory(&engine_root)?;
            let runtime_packs = SystemRuntimePackArtifactIo;
            runtime_packs.prepare_destination(&runtime_root)?;
            runtime_packs.extract_archive(artifacts.runtime_pack_file(), &runtime_root)?;
            runtime_packs.verify_descriptor(&runtime_root, candidate.runtime().runtime_digest())?;
            for artifact in candidate.artifacts() {
                let artifact_root = model_root.join(artifact.name().as_str());
                create_private_directory(&artifact_root)?;
                self.fetcher
                    .fetch_model_artifact(artifact, &artifact_root)?;
            }
            let acquired = self.fetcher.fetch_exact_engine_distribution(
                candidate,
                artifacts,
                ownership.as_ref(),
                &runtime_root,
                &engine_root,
            )?;
            match (ownership.as_ref(), acquired) {
                (Some(prepared), Some(acquired)) => {
                    if !acquired.is_acquired() || acquired.cleanup() != prepared.cleanup() {
                        return Err(RuntimeError::EngineAcquisitionInvalid);
                    }
                    replace_exact_engine_marker(&marker, installation_id, prepared, &acquired)?;
                    ownership = Some(acquired);
                }
                (None, None) => {}
                _ => return Err(RuntimeError::EngineAcquisitionInvalid),
            }
            self.verifier.verify(candidate, &staging)?;
            activate_no_replace(&staging, &destination)
        })();
        if result.is_err() && staging.exists() {
            let _ = remove_private_root(&staging);
        }
        result
    }

    // Revalidates one activated installation root without mutation.
    fn verify(
        &self,
        candidate: &RuntimeCandidate,
        installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError> {
        let root = self.installation_root(installation_id);
        validate_private_directory(&root)?;
        self.verifier.verify(candidate, &root)
    }

    // Removes only one exact managed installation and staging root.
    fn remove(&self, installation_id: &RuntimeInstallationId) -> Result<(), RuntimeError> {
        if !self.root.exists() {
            if self.root.is_symlink() {
                return Err(RuntimeError::ArtifactUnavailable);
            }
            return Ok(());
        }
        validate_private_directory(&self.root)?;
        let _lock = acquire_installation_lock(&self.root, installation_id)?;
        let marker = self.exact_engine_marker(installation_id);
        if marker.exists() || marker.is_symlink() {
            let ownership = read_exact_engine_marker(&marker, installation_id)?;
            self.fetcher.remove_exact_engine_distribution(&ownership)?;
            fs::remove_file(&marker).map_err(|_| RuntimeError::ArtifactUnavailable)?;
        }
        let destination = self.installation_root(installation_id);
        let staging = self.staging_root(installation_id);
        let removal = self.removal_root(installation_id);
        if destination.exists() {
            remove_private_root(&destination)?;
        }
        if staging.exists() {
            remove_private_root(&staging)?;
        }
        if removal.exists() {
            remove_private_root(&removal)?;
        }
        for retained in self.installation_retained_model_roots(installation_id)? {
            remove_private_root(&retained)?;
        }
        let consumption_marker = self.retained_model_consumption_marker(installation_id);
        if consumption_marker.exists() || consumption_marker.is_symlink() {
            validate_private_file(&consumption_marker, MAXIMUM_RETAINED_MODEL_MARKER_BYTES)?;
            fs::remove_file(consumption_marker).map_err(|_| RuntimeError::ArtifactUnavailable)?;
        }
        Ok(())
    }

    // Moves only verified model bytes into the retained cache before exact closure cleanup.
    fn remove_preserving_models(
        &self,
        installation: &RuntimeInstallation,
    ) -> Result<(), RuntimeError> {
        if !self.root.exists() {
            if self.root.is_symlink() {
                return Err(RuntimeError::ArtifactUnavailable);
            }
            return Ok(());
        }
        validate_private_directory(&self.root)?;
        let installation_id = installation.installation_id();
        let _lock = acquire_installation_lock(&self.root, installation_id)?;
        let destination = self.installation_root(installation_id);
        let retained = self.retained_model_root(installation.artifacts(), installation_id);
        let removal = self.removal_root(installation_id);
        let marker = self.exact_engine_marker(installation_id);
        let exact_engine_ownership = if marker.exists() || marker.is_symlink() {
            Some(read_exact_engine_marker(&marker, installation_id)?)
        } else {
            None
        };
        if destination.exists() {
            if removal.exists() || removal.is_symlink() {
                return Err(RuntimeError::ArtifactUnavailable);
            }
            if retained.exists() {
                validate_removal_root(&destination)?;
                validate_private_directory(&retained)?;
                validate_retained_model_tree(&retained)?;
                self.verifier
                    .verify_models(installation.artifacts(), &retained)?;
            } else {
                if retained.is_symlink() {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
                validate_preservable_installation(&destination)?;
                let model_root = destination.join("models");
                self.verifier
                    .verify_models(installation.artifacts(), &model_root)?;
                activate_no_replace(&model_root, &retained)?;
            }
            if activate_no_replace(&destination, &removal).is_err() {
                let model_root = destination.join("models");
                if !model_root.exists() {
                    activate_no_replace(&retained, &model_root)?;
                }
                return Err(RuntimeError::ArtifactUnavailable);
            }
        } else {
            if retained.exists() {
                validate_private_directory(&retained)?;
                validate_retained_model_tree(&retained)?;
                self.verifier
                    .verify_models(installation.artifacts(), &retained)?;
            } else {
                return Err(RuntimeError::ArtifactUnavailable);
            }
            if removal.exists() {
                validate_removal_root(&removal)?;
            } else if removal.is_symlink() {
                return Err(RuntimeError::ArtifactUnavailable);
            }
        }
        if let Some(ownership) = exact_engine_ownership {
            self.fetcher.remove_exact_engine_distribution(&ownership)?;
            fs::remove_file(&marker).map_err(|_| RuntimeError::ArtifactUnavailable)?;
        }
        if removal.exists() {
            remove_private_root(&removal)?;
        }
        let staging = self.staging_root(installation_id);
        if staging.exists() {
            remove_private_root(&staging)?;
        }
        Ok(())
    }

    // Closes the managed root to retained caches only or removes it completely by policy.
    fn finalize_cleanup(
        &self,
        installations: &[RuntimeInstallation],
        preserve_models: bool,
    ) -> Result<(), RuntimeError> {
        if !self.root.exists() {
            return if self.root.is_symlink() {
                Err(RuntimeError::ArtifactUnavailable)
            } else {
                Ok(())
            };
        }
        validate_private_directory(&self.root)?;
        let known = installations
            .iter()
            .map(|installation| (installation.installation_id().as_str(), installation))
            .collect::<HashMap<_, _>>();
        let mut retained_roots = Vec::new();
        let mut locks = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| RuntimeError::ArtifactUnavailable)? {
            let path = entry.map_err(|_| RuntimeError::ArtifactUnavailable)?.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(RuntimeError::ArtifactUnavailable)?;
            if let Some((closure, installation_id)) = retained_model_root_identity(name)? {
                validate_retained_model_tree(&path)?;
                if let Some(installation) = known.get(installation_id.as_str()) {
                    if closure.as_str() != model_closure_identity(installation.artifacts()) {
                        return Err(RuntimeError::ArtifactUnavailable);
                    }
                    self.verifier
                        .verify_models(installation.artifacts(), &path)?;
                }
                retained_roots.push(path);
                continue;
            }
            if let Some(installation_id) = installation_lock_identity(name)? {
                let file = acquire_cleanup_lock(&path)?;
                locks.push((installation_id, path, file));
                continue;
            }
            return Err(RuntimeError::ArtifactUnavailable);
        }
        retained_roots.sort();
        locks.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        if !preserve_models {
            for retained in retained_roots {
                remove_private_root(&retained)?;
            }
        }
        for (_, path, _lock) in &locks {
            fs::remove_file(path).map_err(|_| RuntimeError::ArtifactUnavailable)?;
        }
        if fs::read_dir(&self.root)
            .map_err(|_| RuntimeError::ArtifactUnavailable)?
            .next()
            .is_none()
        {
            fs::remove_dir(&self.root).map_err(|_| RuntimeError::ArtifactUnavailable)?;
        }
        Ok(())
    }
}

// Parses one closed retained-cache basename without accepting aliases or extra suffixes.
fn retained_model_root_identity(
    name: &str,
) -> Result<Option<(Sha256Digest, RuntimeInstallationId)>, RuntimeError> {
    let Some(remainder) = name.strip_prefix(RETAINED_MODEL_PREFIX) else {
        return Ok(None);
    };
    let Some((closure, installation_id)) = remainder.split_once('-') else {
        return Err(RuntimeError::ArtifactUnavailable);
    };
    if installation_id.contains('-') {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    let closure = Sha256Digest::parse(closure).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let installation_id = RuntimeInstallationId::parse(installation_id)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    Ok(Some((closure, installation_id)))
}

// Parses one persistent installation-lock basename without accepting unrelated hidden files.
fn installation_lock_identity(name: &str) -> Result<Option<RuntimeInstallationId>, RuntimeError> {
    let Some(identity) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".lock"))
    else {
        return Ok(None);
    };
    RuntimeInstallationId::parse(identity)
        .map(Some)
        .map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Persists one owner-private retained-model source name before cache consumption.
fn write_retained_model_marker(marker: &Path, retained: &Path) -> Result<(), RuntimeError> {
    let name = retained
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(RuntimeError::ArtifactUnavailable)?;
    let incoming = marker.with_extension("retained-model-source.incoming");
    if incoming.exists() || incoming.is_symlink() {
        validate_private_temporary_file(&incoming, MAXIMUM_RETAINED_MODEL_MARKER_BYTES)?;
        fs::remove_file(&incoming).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(&incoming)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    file.write_all(name.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    validate_private_file(&incoming, MAXIMUM_RETAINED_MODEL_MARKER_BYTES)?;
    activate_no_replace(&incoming, marker)
}

// Reads one closed retained-model marker bound to exact artifact and installation syntax.
fn read_retained_model_marker(
    marker: &Path,
    root: &Path,
    artifacts: &[ModelArtifact],
) -> Result<PathBuf, RuntimeError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(marker)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    validate_private_file_metadata(&metadata, MAXIMUM_RETAINED_MODEL_MARKER_BYTES)?;
    let expected_bytes = metadata.len();
    let mut bytes = Vec::new();
    file.take(MAXIMUM_RETAINED_MODEL_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if bytes.len() as u64 != expected_bytes {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    let name = std::str::from_utf8(&bytes).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let prefix = format!(
        "{RETAINED_MODEL_PREFIX}{}-",
        model_closure_identity(artifacts)
    );
    let identity = name
        .strip_prefix(&prefix)
        .ok_or(RuntimeError::ArtifactUnavailable)?;
    RuntimeInstallationId::parse(identity).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    Ok(root.join(name))
}

// Requires a bounded owner-private cache tree before content corruption may be removed as a miss.
fn validate_retained_model_tree(root: &Path) -> Result<(), RuntimeError> {
    let mut entries = 0;
    validate_retained_model_tree_at(root, &mut entries)
}

// Walks one retained cache without following links or accepting unsafe modes and aliases.
fn validate_retained_model_tree_at(path: &Path, entries: &mut usize) -> Result<(), RuntimeError> {
    validate_private_directory(path)?;
    for entry in fs::read_dir(path).map_err(|_| RuntimeError::ArtifactUnavailable)? {
        *entries = entries
            .checked_add(1)
            .ok_or(RuntimeError::ArtifactUnavailable)?;
        if *entries > MAXIMUM_RETAINED_MODEL_ENTRIES {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        let path = entry.map_err(|_| RuntimeError::ArtifactUnavailable)?.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| RuntimeError::ArtifactUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        if metadata.is_dir() {
            validate_retained_model_tree_at(&path, entries)?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};

                if metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.nlink() != 1
                    || metadata.permissions().mode() & 0o7777 != 0o600
                {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
            }
        } else {
            return Err(RuntimeError::ArtifactUnavailable);
        }
    }
    Ok(())
}

// Requires a durable post-model removal root to contain no names beyond runtime and Engine.
fn validate_removal_root(root: &Path) -> Result<(), RuntimeError> {
    validate_private_directory(root)?;
    let mut names = fs::read_dir(root)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?
        .map(|entry| {
            entry
                .map_err(|_| RuntimeError::ArtifactUnavailable)?
                .file_name()
                .into_string()
                .map_err(|_| RuntimeError::ArtifactUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    if names
        .iter()
        .any(|name| name != "engine" && name != "runtime")
    {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    for name in names {
        validate_private_directory(&root.join(name))?;
    }
    Ok(())
}

// Requires the exact activated three-directory closure before selective retention begins.
fn validate_preservable_installation(root: &Path) -> Result<(), RuntimeError> {
    validate_private_directory(root)?;
    let mut names = fs::read_dir(root)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?
        .map(|entry| {
            entry
                .map_err(|_| RuntimeError::ArtifactUnavailable)?
                .file_name()
                .into_string()
                .map_err(|_| RuntimeError::ArtifactUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    if names != ["engine", "models", "runtime"] {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    for name in names {
        validate_private_directory(&root.join(name))?;
    }
    Ok(())
}

// Computes one unambiguous SHA-256 identity over exact ordered model artifact fields.
fn model_closure_identity(artifacts: &[ModelArtifact]) -> String {
    let mut digest = Sha256::new();
    for artifact in artifacts {
        update_identity_field(&mut digest, artifact.name().as_str().as_bytes());
        update_identity_field(&mut digest, artifact.uri().as_str().as_bytes());
        update_identity_field(&mut digest, artifact.revision().as_str().as_bytes());
        match artifact.format() {
            ModelArtifactFormat::HuggingFaceSnapshot => update_identity_field(&mut digest, b"hf"),
            ModelArtifactFormat::GgufFile(file) => {
                update_identity_field(&mut digest, b"gguf");
                update_identity_field(&mut digest, file.filename().as_bytes());
                update_identity_field(&mut digest, file.digest().as_str().as_bytes());
                update_identity_field(
                    &mut digest,
                    &file.bytes().map_or(u64::MAX, |bytes| bytes).to_be_bytes(),
                );
            }
        }
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// Adds one length-delimited field to a retained-model closure identity.
fn update_identity_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

// Projects a built verifier OCI mode into durable cleanup identity without artifact paths.
fn exact_engine_cleanup(
    candidate: &RuntimeCandidate,
    artifacts: &RuntimeExactCandidateArtifacts,
) -> Result<Option<RuntimeExactEngineCleanup>, RuntimeError> {
    let RuntimeExactEngineArtifact::BuiltOci {
        config_digest,
        local_tag,
        ..
    } = artifacts.engine()
    else {
        return Ok(None);
    };
    let li_core_interface::EngineDistribution::Oci {
        reference,
        immutable_id,
        ..
    } = candidate.runtime().engine_distribution()
    else {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    };
    if immutable_id != config_digest {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    RuntimeExactEngineCleanup::new(
        reference.as_str().to_string(),
        local_tag.clone(),
        config_digest.clone(),
    )
    .map(Some)
}

// Returns one installation-bound local OCI config only from a completed exact ownership marker.
pub(crate) fn exact_engine_execution_config(
    installation_root: &Path,
    installation_id: &RuntimeInstallationId,
    expected_config_digest: &Sha256Digest,
) -> Result<Option<Sha256Digest>, RuntimeError> {
    let marker = installation_root.join(format!(".{}.exact-engine.json", installation_id.as_str()));
    if !marker.exists() {
        return if marker.is_symlink() {
            Err(RuntimeError::ExecutionManifestInvalid)
        } else {
            Ok(None)
        };
    }
    let ownership = read_exact_engine_marker(&marker, installation_id)
        .map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
    if !ownership.is_acquired() || ownership.cleanup().config_digest() != expected_config_digest {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(Some(expected_config_digest.clone()))
}

// Atomically creates one owner-only prepared built-Engine ownership marker.
fn write_new_exact_engine_marker(
    path: &Path,
    installation_id: &RuntimeInstallationId,
    ownership: &RuntimeExactEngineOwnership,
) -> Result<(), RuntimeError> {
    if path.exists() || path.is_symlink() {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    let bytes = exact_engine_marker_bytes(installation_id, ownership)?;
    let incoming = write_exact_engine_marker_temporary(path, &bytes)?;
    activate_no_replace(&incoming, path)
}

// Atomically advances one exact prepared marker to its completed acquisition receipt.
fn replace_exact_engine_marker(
    path: &Path,
    installation_id: &RuntimeInstallationId,
    expected: &RuntimeExactEngineOwnership,
    replacement: &RuntimeExactEngineOwnership,
) -> Result<(), RuntimeError> {
    if read_exact_engine_marker(path, installation_id)? != *expected {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    let bytes = exact_engine_marker_bytes(installation_id, replacement)?;
    let incoming = write_exact_engine_marker_temporary(path, &bytes)?;
    fs::rename(&incoming, path).map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Returns the closed canonical marker bytes for one ownership phase.
fn exact_engine_marker_bytes(
    installation_id: &RuntimeInstallationId,
    ownership: &RuntimeExactEngineOwnership,
) -> Result<Vec<u8>, RuntimeError> {
    let cleanup = ownership.cleanup();
    let document = json!({
        "schema_name": EXACT_ENGINE_MARKER_SCHEMA,
        "schema_version": EXACT_ENGINE_MARKER_VERSION,
        "installation_id": installation_id.as_str(),
        "reference": cleanup.reference(),
        "local_tag": cleanup.local_tag(),
        "config_digest": cleanup.config_digest().as_str(),
        "preexisting_config": ownership.preexisting_config(),
        "preexisting_reference": ownership.preexisting_reference(),
        "preexisting_local_tag": ownership.preexisting_local_tag(),
        "created_config": ownership.created_config(),
        "created_reference": ownership.created_reference(),
        "created_local_tag": ownership.created_local_tag(),
        "acquired": ownership.is_acquired(),
    });
    serde_json::to_vec(&document).map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Writes one synced owner-only marker temporary beside its final destination.
fn write_exact_engine_marker_temporary(path: &Path, bytes: &[u8]) -> Result<PathBuf, RuntimeError> {
    let incoming = path.with_extension("json.incoming");
    if incoming.exists() || incoming.is_symlink() {
        validate_private_file(&incoming, MAXIMUM_EXACT_ENGINE_MARKER_BYTES)?;
        fs::remove_file(&incoming).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(&incoming)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    validate_private_file(&incoming, MAXIMUM_EXACT_ENGINE_MARKER_BYTES)?;
    Ok(incoming)
}

// Reads one closed built-Engine cleanup marker without following links or accepting drift.
fn read_exact_engine_marker(
    path: &Path,
    expected_installation_id: &RuntimeInstallationId,
) -> Result<RuntimeExactEngineOwnership, RuntimeError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    validate_private_file_metadata(&metadata, MAXIMUM_EXACT_ENGINE_MARKER_BYTES)?;
    let expected_bytes = metadata.len();
    let mut bytes = Vec::new();
    file.take(MAXIMUM_EXACT_ENGINE_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if bytes.len() as u64 != expected_bytes {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    let marker: Value =
        serde_json::from_slice(&bytes).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let marker = marker
        .as_object()
        .ok_or(RuntimeError::ArtifactUnavailable)?;
    let expected = [
        "schema_name",
        "schema_version",
        "installation_id",
        "reference",
        "local_tag",
        "config_digest",
        "preexisting_config",
        "preexisting_reference",
        "preexisting_local_tag",
        "created_config",
        "created_reference",
        "created_local_tag",
        "acquired",
    ];
    if marker.len() != expected.len()
        || expected.iter().any(|field| !marker.contains_key(*field))
        || marker.get("schema_name").and_then(Value::as_str) != Some(EXACT_ENGINE_MARKER_SCHEMA)
        || marker.get("schema_version").and_then(Value::as_u64)
            != Some(u64::from(EXACT_ENGINE_MARKER_VERSION))
        || marker.get("installation_id").and_then(Value::as_str)
            != Some(expected_installation_id.as_str())
    {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    let cleanup = RuntimeExactEngineCleanup::new(
        marker
            .get("reference")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::ArtifactUnavailable)?
            .to_string(),
        marker
            .get("local_tag")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::ArtifactUnavailable)?
            .to_string(),
        Sha256Digest::parse(
            marker
                .get("config_digest")
                .and_then(Value::as_str)
                .ok_or(RuntimeError::ArtifactUnavailable)?,
        )
        .map_err(|_| RuntimeError::ArtifactUnavailable)?,
    )?;
    RuntimeExactEngineOwnership::restore(
        cleanup,
        marker_boolean(marker, "preexisting_config")?,
        marker_boolean(marker, "preexisting_reference")?,
        marker_boolean(marker, "preexisting_local_tag")?,
        marker_boolean(marker, "created_config")?,
        marker_boolean(marker, "created_reference")?,
        marker_boolean(marker, "created_local_tag")?,
        marker_boolean(marker, "acquired")?,
    )
    .map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Returns one required exact boolean from the closed ownership marker.
fn marker_boolean(
    marker: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<bool, RuntimeError> {
    marker
        .get(name)
        .and_then(Value::as_bool)
        .ok_or(RuntimeError::ArtifactUnavailable)
}

// Requires one bounded owner-only, single-link regular marker file.
fn validate_private_file(path: &Path, maximum_bytes: u64) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if metadata.file_type().is_symlink() {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    validate_private_file_metadata(&metadata, maximum_bytes)
}

// Requires one owner-only regular temporary while accepting a crash-left empty write.
fn validate_private_temporary_file(path: &Path, maximum_bytes: u64) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
    }
    Ok(())
}

// Requires one opened or no-follow observed marker to retain exact private file properties.
fn validate_private_file_metadata(
    metadata: &fs::Metadata,
    maximum_bytes: u64,
) -> Result<(), RuntimeError> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
    }
    Ok(())
}

// Acquires one existing zero-byte private lock nonblockingly before final unlink.
#[cfg(unix)]
fn acquire_cleanup_lock(path: &Path) -> Result<File, RuntimeError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.len() != 0
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
        || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    Ok(file)
}

// Opens one existing lock on future non-Unix providers before exact final unlink.
#[cfg(not(unix))]
fn acquire_cleanup_lock(path: &Path) -> Result<File, RuntimeError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Holds one cross-process installation lock until its guarded operation completes.
#[cfg(unix)]
fn acquire_installation_lock(
    root: &Path,
    installation_id: &RuntimeInstallationId,
) -> Result<File, RuntimeError> {
    let path = root.join(format!(".{}.lock", installation_id.as_str()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0
    {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    Ok(file)
}

// Opens one best-effort installation lock on future non-Unix providers.
#[cfg(not(unix))]
fn acquire_installation_lock(
    root: &Path,
    installation_id: &RuntimeInstallationId,
) -> Result<File, RuntimeError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(root.join(format!(".{}.lock", installation_id.as_str())))
        .map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Creates or validates the private managed artifact root.
fn prepare_managed_root(root: &Path) -> Result<(), RuntimeError> {
    if root.exists() {
        return validate_private_directory(root);
    }
    if root.is_symlink() {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    create_private_directory(root)
}

// Creates one exact owner-private directory without exposing a public-mode race window.
#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => validate_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_private_directory(path)
        }
        Err(_) => Err(RuntimeError::ArtifactUnavailable),
    }
}

// Creates one exact private directory on future non-Unix providers.
#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), RuntimeError> {
    match fs::create_dir(path) {
        Ok(()) => validate_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_private_directory(path)
        }
        Err(_) => Err(RuntimeError::ArtifactUnavailable),
    }
}

// Removes one exact non-symlink managed directory.
fn remove_private_root(path: &Path) -> Result<(), RuntimeError> {
    validate_private_directory(path)?;
    fs::remove_dir_all(path).map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Requires one managed directory to remain owner-only and free of aliasing.
fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
    }
    Ok(())
}

// Activates one staged directory without replacing state created concurrently.
#[cfg(target_os = "linux")]
fn activate_no_replace(staging: &Path, destination: &Path) -> Result<(), RuntimeError> {
    let staging = path_c_string(staging)?;
    let destination = path_c_string(destination)?;
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            staging.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(RuntimeError::ArtifactUnavailable)
    }
}

// Activates one staged directory without replacing state created concurrently.
#[cfg(target_os = "macos")]
fn activate_no_replace(staging: &Path, destination: &Path) -> Result<(), RuntimeError> {
    let staging = path_c_string(staging)?;
    let destination = path_c_string(destination)?;
    let status =
        unsafe { libc::renamex_np(staging.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
    if status == 0 {
        Ok(())
    } else {
        Err(RuntimeError::ArtifactUnavailable)
    }
}

// Declines activation on unsupported Unix hosts lacking an atomic no-replace primitive.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn activate_no_replace(_staging: &Path, _destination: &Path) -> Result<(), RuntimeError> {
    Err(RuntimeError::ArtifactUnavailable)
}

// Activates one staging directory on the future non-Unix provider boundary.
#[cfg(not(unix))]
fn activate_no_replace(staging: &Path, destination: &Path) -> Result<(), RuntimeError> {
    if destination.exists() {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    fs::rename(staging, destination).map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Converts one native path without lossy encoding before an atomic rename.
#[cfg(unix)]
fn path_c_string(path: &Path) -> Result<CString, RuntimeError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| RuntimeError::ArtifactUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proves prepared/acquired ownership survives restart and rejects semantic or shape drift.
    #[test]
    fn exact_engine_cleanup_marker_round_trips_and_fails_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let installation_id = RuntimeInstallationId::parse(&"a".repeat(32)).expect("installation");
        let other_installation =
            RuntimeInstallationId::parse(&"b".repeat(32)).expect("other installation");
        let marker = directory
            .path()
            .join(format!(".{}.exact-engine.json", installation_id.as_str()));
        let cleanup = RuntimeExactEngineCleanup::new(
            format!("ghcr.io/engine@sha256:{}", "1".repeat(64)),
            "li-verifier/candidate:fixture".to_string(),
            Sha256Digest::parse(&"2".repeat(64)).expect("config"),
        )
        .expect("cleanup");
        let prepared = RuntimeExactEngineOwnership::prepared(cleanup, false, false, false)
            .expect("prepared ownership");
        write_new_exact_engine_marker(&marker, &installation_id, &prepared).expect("write marker");
        assert_eq!(
            read_exact_engine_marker(&marker, &installation_id).expect("read marker"),
            prepared
        );
        assert!(read_exact_engine_marker(&marker, &other_installation).is_err());
        assert!(write_new_exact_engine_marker(&marker, &installation_id, &prepared).is_err());
        let acquired = prepared.acquired(true, true, true).expect("acquired");
        replace_exact_engine_marker(&marker, &installation_id, &prepared, &acquired)
            .expect("replace marker");
        assert_eq!(
            read_exact_engine_marker(&marker, &installation_id).expect("read acquired marker"),
            acquired
        );
        assert!(
            replace_exact_engine_marker(&marker, &installation_id, &prepared, &acquired).is_err()
        );
        assert_eq!(
            exact_engine_execution_config(
                directory.path(),
                &installation_id,
                acquired.cleanup().config_digest(),
            )
            .expect("execution config"),
            Some(acquired.cleanup().config_digest().clone())
        );
        assert!(exact_engine_execution_config(
            directory.path(),
            &installation_id,
            &Sha256Digest::parse(&"c".repeat(64)).expect("wrong config"),
        )
        .is_err());
        let mut changed: Value = serde_json::from_slice(
            &exact_engine_marker_bytes(&installation_id, &acquired).expect("marker bytes"),
        )
        .expect("marker JSON");
        changed
            .as_object_mut()
            .expect("marker object")
            .insert("extra".to_string(), Value::Bool(true));
        fs::write(
            &marker,
            serde_json::to_vec(&changed).expect("mutated marker"),
        )
        .expect("mutate marker");
        assert!(read_exact_engine_marker(&marker, &installation_id).is_err());
    }
}
