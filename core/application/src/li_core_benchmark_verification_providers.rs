// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::OpenOptions;
use std::io::{Cursor, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_benchmark_manager::BenchmarkError;
use li_benchmark_manager::BenchmarkSubject;
use li_core_interface::{
    ModelServiceDesiredState, RuntimeCandidateId, RuntimeInstallationState, Sha256Digest,
};
use li_node_manager::NodeManager;
use li_placement_manager::PlacementStore;
use li_runtime_manager::{RuntimeInstallationStore, RuntimeManager};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

use crate::{
    CoreBenchmarkVerificationBaselinePort, CoreBenchmarkVerificationCandidate,
    CoreBenchmarkVerificationDeviceIdentity, CoreBenchmarkVerificationDeviceSigner,
    CoreBenchmarkVerificationPreparationError, CoreBenchmarkVerificationSnapshotSigner,
    CoreBenchmarkVerificationSubjectResolver,
};

const MAXIMUM_PRIVATE_KEY_BYTES: u64 = 16 * 1024;
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

// Resolves one finalized candidate to exactly one available local installed placement.
pub struct ManagerCoreBenchmarkVerificationSubjectResolver {
    node: Arc<NodeManager>,
    runtime: Arc<RuntimeManager>,
    runtime_store: Arc<dyn RuntimeInstallationStore>,
    placement_store: Arc<dyn PlacementStore>,
}

impl ManagerCoreBenchmarkVerificationSubjectResolver {
    // Creates one resolver from existing manager-owned read boundaries.
    pub const fn new(
        node: Arc<NodeManager>,
        runtime: Arc<RuntimeManager>,
        runtime_store: Arc<dyn RuntimeInstallationStore>,
        placement_store: Arc<dyn PlacementStore>,
    ) -> Self {
        Self {
            node,
            runtime,
            runtime_store,
            placement_store,
        }
    }

    // Resolves one exact available local installation and active group under a caller predicate.
    fn resolve_matching(
        &self,
        matches_installation: impl Fn(&li_core_interface::RuntimeInstallation) -> bool,
    ) -> Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError> {
        let local = self.node.local_node().map_err(|_| unavailable())?;
        let installations = self.runtime_store.all().map_err(|_| unavailable())?;
        let mut matches = installations
            .iter()
            .map(|value| value.installation())
            .filter(|installation| {
                matches_installation(installation)
                    && installation.node_id() == local.identity().node_id()
                    && installation.state() == RuntimeInstallationState::Available
            });
        let installation = matches
            .next()
            .ok_or(CoreBenchmarkVerificationPreparationError::Conflict)?;
        if matches.next().is_some() {
            return Err(CoreBenchmarkVerificationPreparationError::Conflict);
        }
        let services = self.node.model_services().map_err(|_| unavailable())?;
        let mut matched_groups = Vec::new();
        for service in services.iter().filter(|service| {
            service.desired_state() != ModelServiceDesiredState::Removed
                && service.logical_model() == installation.logical_model()
        }) {
            for group_id in service.placement_group_ids() {
                let group = self
                    .placement_store
                    .read(group_id)
                    .map_err(|_| unavailable())?;
                if group.as_ref().is_some_and(|record| {
                    record.record().placements().iter().any(|placement| {
                        placement.assignment().runtime_installation_id()
                            == installation.installation_id()
                    })
                }) {
                    matched_groups.push(group_id.clone());
                }
            }
        }
        let [group_id] = matched_groups.as_slice() else {
            return Err(CoreBenchmarkVerificationPreparationError::Conflict);
        };
        let manifest = self
            .runtime
            .execution_manifest(installation.installation_id())
            .map_err(|_| unavailable())?;
        let benchmark = manifest
            .benchmark()
            .ok_or(CoreBenchmarkVerificationPreparationError::Conflict)?;
        if manifest.logical_model() != installation.logical_model() {
            return Err(CoreBenchmarkVerificationPreparationError::Conflict);
        }
        Ok(BenchmarkSubject::new(
            local.identity().installation_id().clone(),
            installation.installation_id().clone(),
            installation.logical_model().clone(),
            group_id.clone(),
            installation.runtime().execution_contract_digest().clone(),
            benchmark.contract_sha256().clone(),
            benchmark.target_contract_sha256().clone(),
        ))
    }
}

impl CoreBenchmarkVerificationSubjectResolver for ManagerCoreBenchmarkVerificationSubjectResolver {
    // Requires one unambiguous available local installation and its exact active group.
    fn resolve(
        &self,
        candidate: &RuntimeCandidateId,
    ) -> Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError> {
        self.resolve_matching(|installation| installation.runtime().candidate_id() == candidate)
    }
}

impl CoreBenchmarkVerificationBaselinePort for ManagerCoreBenchmarkVerificationSubjectResolver {
    // Resolves the sole current resident installation for the trusted candidate logical model.
    fn baseline(
        &self,
        candidate: &CoreBenchmarkVerificationCandidate,
    ) -> Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError> {
        self.resolve_matching(|installation| {
            installation.logical_model() == candidate.runtime().logical_model()
        })
    }
}

// Signs authority bytes with the dedicated setup-issued owner-private Ed25519 PKCS#8 key.
pub struct SetupEd25519CoreBenchmarkVerificationSnapshotSigner {
    private_key_file: PathBuf,
    owner_user_id: u32,
}

impl SetupEd25519CoreBenchmarkVerificationSnapshotSigner {
    // Creates one signer from an explicit normal absolute setup-issued key reference.
    pub fn new(
        private_key_file: PathBuf,
        owner_user_id: u32,
    ) -> Result<Self, CoreBenchmarkVerificationPreparationError> {
        if !safe_file(&private_key_file) || owner_user_id == u32::MAX {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidInput);
        }
        Ok(Self {
            private_key_file,
            owner_user_id,
        })
    }

    // Returns the exact public device identity derived from the setup-issued private key.
    pub fn public_key_sha256(
        &self,
    ) -> Result<Sha256Digest, CoreBenchmarkVerificationPreparationError> {
        let mut pem = read_private_key(&self.private_key_file, self.owner_user_id)?;
        let result = (|| {
            let der = rustls_pemfile::private_key(&mut Cursor::new(&pem))
                .map_err(|_| invalid_authority())?
                .ok_or_else(invalid_authority)?;
            let pair = setup_ed25519_key_pair(der.secret_der())?;
            Sha256Digest::parse(&format!("{:x}", Sha256::digest(public_key_spki(&pair))))
                .map_err(|_| invalid_authority())
        })();
        pem.fill(0);
        result
    }
}

impl CoreBenchmarkVerificationSnapshotSigner
    for SetupEd25519CoreBenchmarkVerificationSnapshotSigner
{
    // Loads, signs, and clears the bounded key bytes without invoking a shell or native command.
    fn sign(
        &self,
        payload: &[u8],
    ) -> Result<(Sha256Digest, Vec<u8>), CoreBenchmarkVerificationPreparationError> {
        if payload.is_empty() || payload.len() > 64 * 1024 {
            return Err(CoreBenchmarkVerificationPreparationError::InvalidInput);
        }
        let mut pem = read_private_key(&self.private_key_file, self.owner_user_id)?;
        let result = (|| {
            let der = rustls_pemfile::private_key(&mut Cursor::new(&pem))
                .map_err(|_| invalid_authority())?
                .ok_or_else(invalid_authority)?;
            let pair = setup_ed25519_key_pair(der.secret_der())?;
            let digest =
                Sha256Digest::parse(&format!("{:x}", Sha256::digest(public_key_spki(&pair))))
                    .map_err(|_| invalid_authority())?;
            Ok((digest, pair.sign(payload).as_ref().to_vec()))
        })();
        pem.fill(0);
        result
    }
}

impl CoreBenchmarkVerificationDeviceSigner for SetupEd25519CoreBenchmarkVerificationSnapshotSigner {
    // Returns the Python-compatible SHA-256 identity of exact Ed25519 SPKI DER.
    fn identity(&self) -> Result<CoreBenchmarkVerificationDeviceIdentity, BenchmarkError> {
        let mut pem = read_private_key(&self.private_key_file, self.owner_user_id)
            .map_err(|_| BenchmarkError::PublicationRejected)?;
        let result = (|| {
            let der = rustls_pemfile::private_key(&mut Cursor::new(&pem))
                .map_err(|_| BenchmarkError::PublicationRejected)?
                .ok_or(BenchmarkError::PublicationRejected)?;
            let pair = setup_ed25519_key_pair(der.secret_der())
                .map_err(|_| BenchmarkError::PublicationRejected)?;
            let spki = public_key_spki(&pair);
            let identity = Sha256Digest::parse(&format!("{:x}", Sha256::digest(&spki)))
                .map_err(|_| BenchmarkError::PublicationRejected)?;
            CoreBenchmarkVerificationDeviceIdentity::new(identity.clone(), identity, spki)
        })();
        pem.fill(0);
        result
    }

    // Signs one bounded canonical envelope without exposing or retaining private material.
    fn sign(&self, unsigned_envelope: &[u8]) -> Result<Vec<u8>, BenchmarkError> {
        if unsigned_envelope.is_empty() || unsigned_envelope.len() > 128 * 1024 {
            return Err(BenchmarkError::PublicationRejected);
        }
        let mut pem = read_private_key(&self.private_key_file, self.owner_user_id)
            .map_err(|_| BenchmarkError::PublicationRejected)?;
        let result = (|| {
            let der = rustls_pemfile::private_key(&mut Cursor::new(&pem))
                .map_err(|_| BenchmarkError::PublicationRejected)?
                .ok_or(BenchmarkError::PublicationRejected)?;
            let pair = setup_ed25519_key_pair(der.secret_der())
                .map_err(|_| BenchmarkError::PublicationRejected)?;
            Ok(pair.sign(unsigned_envelope).as_ref().to_vec())
        })();
        pem.fill(0);
        result
    }
}

// Loads the OpenSSL-issued PKCS#8 v1 key while retaining ring's strict v2 checks when present.
fn setup_ed25519_key_pair(
    private_key_der: &[u8],
) -> Result<Ed25519KeyPair, CoreBenchmarkVerificationPreparationError> {
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(private_key_der).map_err(|_| invalid_authority())
}

// Builds one canonical Ed25519 SubjectPublicKeyInfo DER document.
fn public_key_spki(pair: &Ed25519KeyPair) -> Vec<u8> {
    let mut spki = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + pair.public_key().as_ref().len());
    spki.extend_from_slice(ED25519_SPKI_PREFIX);
    spki.extend_from_slice(pair.public_key().as_ref());
    spki
}

// Reads one exact single-link owner-private key without following its final path.
fn read_private_key(
    path: &Path,
    owner: u32,
) -> Result<Vec<u8>, CoreBenchmarkVerificationPreparationError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| unavailable())?;
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_PRIVATE_KEY_BYTES
    {
        return Err(invalid_authority());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|_| unavailable())?;
    if bytes.len() as u64 != metadata.len() {
        bytes.fill(0);
        return Err(unavailable());
    }
    Ok(bytes)
}

// Returns whether one key reference is absolute, normal, and bounded.
fn safe_file(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4_096
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.file_name().is_some()
}

// Returns one redacted provider-unavailable failure.
const fn unavailable() -> CoreBenchmarkVerificationPreparationError {
    CoreBenchmarkVerificationPreparationError::Unavailable
}

// Returns one redacted key or signed-authority failure.
const fn invalid_authority() -> CoreBenchmarkVerificationPreparationError {
    CoreBenchmarkVerificationPreparationError::InvalidAuthority
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use ring::signature::{UnparsedPublicKey, ED25519};
    use tempfile::tempdir;

    use super::*;

    // Creates one setup-shaped Ed25519 PKCS#8 PEM and its exact public key.
    fn private_key_pem() -> (Vec<u8>, Vec<u8>) {
        let document =
            Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).expect("PKCS8");
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("pair");
        let begin = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
        let end = ["-----END ", "PRIVATE KEY-----"].concat();
        let pem = format!("{begin}\n{}\n{end}\n", STANDARD.encode(document.as_ref())).into_bytes();
        (pem, pair.public_key().as_ref().to_vec())
    }

    #[test]
    // Signs exact bytes with the setup-issued PEM and returns its matching public identity.
    fn setup_signer_produces_a_verifiable_ed25519_signature() {
        let directory = tempdir().expect("directory");
        let key_file = directory.path().join("benchmark-signing-private.pem");
        let (pem, public_key) = private_key_pem();
        std::fs::write(&key_file, pem).expect("key");
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("permissions");
        let owner = std::fs::symlink_metadata(&key_file)
            .expect("metadata")
            .uid();
        let signer = SetupEd25519CoreBenchmarkVerificationSnapshotSigner::new(key_file, owner)
            .expect("signer");
        let (public_sha256, signature) =
            CoreBenchmarkVerificationSnapshotSigner::sign(&signer, b"authority")
                .expect("signature");
        let mut public_spki = ED25519_SPKI_PREFIX.to_vec();
        public_spki.extend_from_slice(&public_key);
        assert_eq!(
            public_sha256.as_str(),
            format!("{:x}", Sha256::digest(&public_spki))
        );
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(b"authority", &signature)
            .expect("verified");
    }

    #[test]
    // Rejects a symlinked key before reading or retaining any private material.
    fn setup_signer_does_not_follow_a_private_key_symlink() {
        let directory = tempdir().expect("directory");
        let key_file = directory.path().join("key.pem");
        let link = directory.path().join("key-link.pem");
        let (pem, _) = private_key_pem();
        std::fs::write(&key_file, pem).expect("key");
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("permissions");
        symlink(&key_file, &link).expect("symlink");
        let owner = std::fs::symlink_metadata(&key_file)
            .expect("metadata")
            .uid();
        let signer =
            SetupEd25519CoreBenchmarkVerificationSnapshotSigner::new(link, owner).expect("signer");
        assert_eq!(
            CoreBenchmarkVerificationSnapshotSigner::sign(&signer, b"authority"),
            Err(CoreBenchmarkVerificationPreparationError::Unavailable)
        );
    }
}
