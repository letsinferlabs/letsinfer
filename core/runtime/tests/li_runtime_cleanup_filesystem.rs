// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, ByteCount, CpuArchitecture, EngineDistribution,
    EntityTimestamps, EvidenceLabel, LogicalModelName, MemoryTopology, ModelArtifact,
    ModelArtifactFormat, NodeId, OperatingSystem, RuntimeCandidateId, RuntimeIdentity,
    RuntimeInstallation, RuntimeInstallationId, RuntimeInstallationState, RuntimeSource,
    RuntimeVersion, Sha256Digest, TargetId, TechnicalName, UnixMilliseconds,
};
use li_runtime_manager::{
    FilesystemRuntimeArtifactProvider, RuntimeAcceleratorVendor, RuntimeArtifactFetcher,
    RuntimeArtifactProvider, RuntimeArtifactVerifier, RuntimeCandidate, RuntimeCatalogProvider,
    RuntimeClock, RuntimeError, RuntimeInstallationIdentityProvider, RuntimeInstallationStore,
    RuntimeManager, RuntimeTarget, VersionedRuntimeInstallation,
};
use tempfile::TempDir;

// Returns no candidates because cleanup finalization must not consult the public catalog.
struct EmptyCatalog;

impl RuntimeCatalogProvider for EmptyCatalog {
    // Rejects any accidental selection during filesystem-only finalization.
    fn candidates(&self, _model: &LogicalModelName) -> Result<Vec<RuntimeCandidate>, RuntimeError> {
        Err(RuntimeError::CatalogUnavailable)
    }
}

// Retains one terminal installation while rejecting every unused mutation operation.
struct TerminalStore {
    installation: VersionedRuntimeInstallation,
}

impl RuntimeInstallationStore for TerminalStore {
    // Returns the terminal fixture only for its exact installation identity.
    fn read(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
        Ok(
            (self.installation.installation().installation_id() == installation_id)
                .then(|| self.installation.clone()),
        )
    }

    // Returns the sole terminal fixture consumed by RuntimeManager finalization.
    fn all(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
        Ok(vec![self.installation.clone()])
    }

    // Rejects installation creation outside this finalization-only store contract.
    fn create(
        &self,
        _installation: RuntimeInstallation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        Err(RuntimeError::StoreUnavailable)
    }

    // Rejects installation replacement outside this finalization-only store contract.
    fn replace(
        &self,
        _installation: RuntimeInstallation,
        _expected_revision: u64,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        Err(RuntimeError::StoreUnavailable)
    }

    // Rejects deletion because RuntimeManager finalization must only read terminal state.
    fn delete(
        &self,
        _installation_id: &RuntimeInstallationId,
        _expected_revision: u64,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::StoreUnavailable)
    }
}

// Rejects accidental installation because root finalization never allocates an identity.
struct UnusedIdentity;

impl RuntimeInstallationIdentityProvider for UnusedIdentity {
    // Fails closed if finalization crosses into installation creation.
    fn installation_id(&self) -> Result<RuntimeInstallationId, RuntimeError> {
        Err(RuntimeError::LifecycleUnavailable)
    }
}

// Rejects accidental lifecycle time because root finalization has no state transition.
struct UnusedClock;

impl RuntimeClock for UnusedClock {
    // Fails closed if finalization unexpectedly requests a timestamp.
    fn now(&self) -> Result<UnixMilliseconds, RuntimeError> {
        Err(RuntimeError::LifecycleUnavailable)
    }
}

// Materializes one deterministic marker for each immutable artifact class.
struct PhysicalFetcher;

impl RuntimeArtifactFetcher for PhysicalFetcher {
    // Writes the exact runtime-pack fixture into the provider-owned private directory.
    fn fetch_runtime_pack(
        &self,
        _source: &RuntimeSource,
        _digest: &Sha256Digest,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        write_private_fixture(&destination.join("fixture"), b"runtime")
    }

    // Writes the exact model fixture used by retained-cache verification.
    fn fetch_model_artifact(
        &self,
        _artifact: &ModelArtifact,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        write_private_fixture(&destination.join("fixture"), b"model")
    }

    // Writes the exact Engine fixture into the provider-owned private directory.
    fn fetch_engine_distribution(
        &self,
        _candidate: &RuntimeCandidate,
        _runtime_root: &Path,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        write_private_fixture(&destination.join("fixture"), b"engine")
    }
}

// Verifies real fixture paths and exact model bytes without replacing provider traversal.
struct PhysicalVerifier;

impl RuntimeArtifactVerifier for PhysicalVerifier {
    // Accepts only the exact retained model closure produced by PhysicalFetcher.
    fn verify_models(&self, artifacts: &[ModelArtifact], root: &Path) -> Result<(), RuntimeError> {
        if artifacts.len() != 1
            || artifacts[0].name().as_str() != "model"
            || fs::read(root.join("model/fixture")).ok().as_deref() != Some(b"model")
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        Ok(())
    }

    // Accepts only a complete runtime, model, and Engine fixture closure.
    fn verify(&self, _candidate: &RuntimeCandidate, root: &Path) -> Result<(), RuntimeError> {
        if fs::read(root.join("runtime/fixture")).ok().as_deref() != Some(b"runtime")
            || fs::read(root.join("models/model/fixture")).ok().as_deref() != Some(b"model")
            || fs::read(root.join("engine/fixture")).ok().as_deref() != Some(b"engine")
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        Ok(())
    }
}

// Owns one real retained-cache layout and its RuntimeManager finalization surface.
struct CleanupFixture {
    temporary: TempDir,
    root: PathBuf,
    retained: PathBuf,
    lock: PathBuf,
    manager: RuntimeManager,
}

impl CleanupFixture {
    // Acquires and removes one real installation while preserving its verified model cache.
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("runtime-artifacts");
        let provider = Arc::new(
            FilesystemRuntimeArtifactProvider::new(
                root.clone(),
                Arc::new(PhysicalFetcher),
                Arc::new(PhysicalVerifier),
            )
            .expect("artifact provider"),
        );
        let candidate = candidate();
        let installation_id = RuntimeInstallationId::parse(&"9".repeat(32)).expect("installation");
        provider
            .acquire(&candidate, &installation_id)
            .expect("acquire installation");
        let available = installation(
            &candidate,
            installation_id.clone(),
            RuntimeInstallationState::Available,
        );
        provider
            .remove_preserving_models(&available)
            .expect("preserve models");
        let retained = single_retained_root(&root);
        let lock = root.join(format!(".{}.lock", installation_id.as_str()));
        let removed = installation(
            &candidate,
            installation_id,
            RuntimeInstallationState::Removed,
        );
        let manager = RuntimeManager::with_lifecycle(
            Arc::new(EmptyCatalog),
            provider,
            Arc::new(TerminalStore {
                installation: VersionedRuntimeInstallation::new(removed, 3),
            }),
            Arc::new(UnusedIdentity),
            Arc::new(UnusedClock),
        );
        Self {
            temporary,
            root,
            retained,
            lock,
            manager,
        }
    }

    // Keeps the owning temporary directory observably live for the complete fixture lifetime.
    fn owns_temporary_root(&self) -> bool {
        self.temporary.path().is_dir()
    }
}

// Captures exact path identity and content so a failed finalization cannot hide mutation.
#[derive(Debug, Eq, PartialEq)]
struct PhysicalEntry {
    path: PathBuf,
    kind: &'static str,
    mode: u32,
    device: u64,
    inode: u64,
    content: Vec<u8>,
}

// Returns one exact runtime candidate sufficient to produce a retained model closure.
fn candidate() -> RuntimeCandidate {
    let runtime_digest = "a".repeat(64);
    RuntimeCandidate::new(
        LogicalModelName::parse("qwen3.8").expect("model"),
        RuntimeIdentity::new(
            RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
            RuntimeVersion::parse("1.0.0").expect("version"),
            TargetId::parse("dgx-spark").expect("target"),
            RuntimeSource::parse(&format!("ghcr.io/runtime/qwen@sha256:{runtime_digest}"))
                .expect("runtime source"),
            EngineDistribution::oci(
                RuntimeSource::parse(&format!("ghcr.io/engine/qwen@sha256:{}", "b".repeat(64)))
                    .expect("Engine source"),
                Sha256Digest::parse(&"c".repeat(64)).expect("Engine identity"),
                None,
                None,
            ),
            Sha256Digest::parse(&runtime_digest).expect("runtime digest"),
            Sha256Digest::parse(&"d".repeat(64)).expect("manifest"),
            Sha256Digest::parse(&"e".repeat(64)).expect("execution"),
        )
        .expect("runtime identity"),
        vec![ModelArtifact::new(
            ArtifactName::parse("model").expect("artifact"),
            ArtifactUri::parse("hf://RadixArk/Qwen3.8").expect("artifact URI"),
            ArtifactRevision::parse(&"f".repeat(40)).expect("revision"),
            ModelArtifactFormat::HuggingFaceSnapshot,
        )],
        RuntimeTarget::new(
            OperatingSystem::Linux,
            CpuArchitecture::Arm64,
            RuntimeAcceleratorVendor::Nvidia,
            TechnicalName::parse("sm_121").expect("architecture"),
            1,
            MemoryTopology::Unified,
            None,
            ByteCount::new(64 * 1024 * 1024 * 1024).expect("memory"),
        )
        .expect("runtime target"),
        EvidenceLabel::Qualified,
        2,
        true,
        false,
    )
    .expect("runtime candidate")
}

// Projects one exact candidate into the requested lifecycle state.
fn installation(
    candidate: &RuntimeCandidate,
    installation_id: RuntimeInstallationId,
    state: RuntimeInstallationState,
) -> RuntimeInstallation {
    RuntimeInstallation::new(
        installation_id,
        NodeId::parse(&"1".repeat(32)).expect("node"),
        candidate.logical_model().clone(),
        candidate.runtime().clone(),
        candidate.artifacts().to_vec(),
        candidate.evidence_label(),
        state,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1), UnixMilliseconds::new(2))
            .expect("timestamps"),
    )
    .expect("runtime installation")
}

// Writes one exact owner-private regular fixture file.
fn write_private_fixture(path: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
    fs::write(path, bytes).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Returns the sole retained model cache created by one fixture removal.
fn single_retained_root(root: &Path) -> PathBuf {
    let retained = fs::read_dir(root)
        .expect("artifact root")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".retained-models-"))
        })
        .collect::<Vec<_>>();
    assert_eq!(retained.len(), 1);
    retained.into_iter().next().expect("retained root")
}

// Recursively captures inode, type, mode, target, and regular-file bytes in stable order.
fn physical_inventory(root: &Path) -> Vec<PhysicalEntry> {
    let mut entries = Vec::new();
    capture_entry(root, root, &mut entries);
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

// Adds one no-follow entry and every directory child to the exact physical inventory.
fn capture_entry(root: &Path, path: &Path, entries: &mut Vec<PhysicalEntry>) {
    let metadata = fs::symlink_metadata(path).expect("entry metadata");
    let relative = path
        .strip_prefix(root)
        .expect("relative path")
        .to_path_buf();
    let (kind, content) = if metadata.file_type().is_symlink() {
        (
            "symlink",
            fs::read_link(path)
                .expect("symbolic target")
                .as_os_str()
                .as_encoded_bytes()
                .to_vec(),
        )
    } else if metadata.is_dir() {
        ("directory", Vec::new())
    } else {
        ("file", fs::read(path).expect("file bytes"))
    };
    entries.push(PhysicalEntry {
        path: relative,
        kind,
        mode: metadata.mode(),
        device: metadata.dev(),
        inode: metadata.ino(),
        content,
    });
    if metadata.is_dir() {
        let mut children = fs::read_dir(path)
            .expect("directory entries")
            .map(|entry| entry.expect("directory entry").path())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            capture_entry(root, &child, entries);
        }
    }
}

// Proves keep-model finalization removes every lock and leaves only the verified private cache.
#[test]
fn keep_policy_leaves_only_the_valid_retained_cache() {
    let fixture = CleanupFixture::new();
    assert!(fixture.owns_temporary_root());
    assert!(fixture.lock.is_file());

    fixture
        .manager
        .finalize_cleanup(true)
        .expect("keep cleanup");

    assert!(fixture.root.is_dir());
    assert!(!fixture.lock.exists());
    assert_eq!(single_retained_root(&fixture.root), fixture.retained);
    assert_eq!(
        fs::read(fixture.retained.join("model/fixture")).expect("retained bytes"),
        b"model"
    );
    let names = fs::read_dir(&fixture.root)
        .expect("final root")
        .map(|entry| entry.expect("final entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [fixture.retained.file_name().expect("retained name")]
    );
}

// Proves remove-model finalization deletes the retained cache and then its empty managed root.
#[test]
fn remove_policy_deletes_the_cache_lock_and_root() {
    let fixture = CleanupFixture::new();

    fixture
        .manager
        .finalize_cleanup(false)
        .expect("remove cleanup");

    assert!(!fixture.retained.exists());
    assert!(!fixture.lock.exists());
    assert!(!fixture.root.exists());
}

// Proves one unknown residue rejects finalization before any cache or lock path changes.
#[test]
fn unknown_residue_fails_before_filesystem_mutation() {
    let fixture = CleanupFixture::new();
    write_private_fixture(&fixture.root.join("unknown"), b"foreign").expect("unknown residue");
    let before = physical_inventory(&fixture.root);

    assert_eq!(
        fixture.manager.finalize_cleanup(true),
        Err(RuntimeError::ArtifactUnavailable)
    );

    assert_eq!(physical_inventory(&fixture.root), before);
}

// Proves symbolic and unsafe retained caches fail closed without consuming their exact lock.
#[test]
fn unsafe_retained_cache_matrix_fails_without_mutation() {
    for unsafe_kind in ["symbolic", "public-mode"] {
        let fixture = CleanupFixture::new();
        let external = fixture.temporary.path().join("external-model-cache");
        if unsafe_kind == "symbolic" {
            fs::create_dir(&external).expect("external cache");
            fs::set_permissions(&external, fs::Permissions::from_mode(0o700))
                .expect("external mode");
            write_private_fixture(&external.join("fixture"), b"external").expect("external bytes");
            fs::remove_dir_all(&fixture.retained).expect("replace retained cache");
            symlink(&external, &fixture.retained).expect("retained symlink");
        } else {
            fs::set_permissions(&fixture.retained, fs::Permissions::from_mode(0o755))
                .expect("unsafe retained mode");
        }
        let before = physical_inventory(&fixture.root);
        let external_before = external.exists().then(|| physical_inventory(&external));

        assert_eq!(
            fixture.manager.finalize_cleanup(true),
            Err(RuntimeError::ArtifactUnavailable),
            "kind={unsafe_kind}"
        );

        assert_eq!(
            physical_inventory(&fixture.root),
            before,
            "kind={unsafe_kind}"
        );
        assert_eq!(
            external.exists().then(|| physical_inventory(&external)),
            external_before,
            "kind={unsafe_kind}"
        );
    }
}

// Proves a competing process lock returns unavailable without deleting cache, lock, or root.
#[test]
fn contended_cleanup_lock_returns_unavailable_without_mutation() {
    let fixture = CleanupFixture::new();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&fixture.lock)
        .expect("cleanup lock");
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let before = physical_inventory(&fixture.root);

    assert_eq!(
        fixture.manager.finalize_cleanup(true),
        Err(RuntimeError::ArtifactUnavailable)
    );

    assert_eq!(physical_inventory(&fixture.root), before);
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
}
