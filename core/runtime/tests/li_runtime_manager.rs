// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use li_core_interface::{
    Accelerator, AcceleratorMemory, AcceleratorVendor, ArtifactName, ArtifactRevision, ArtifactUri,
    BootId, ByteCount, ComputeCapability, CpuArchitecture, DisplayName, EngineDistribution,
    EntityTimestamps, EvidenceLabel, HardwareObservation, HardwareObservationId, LogicalModelName,
    MemoryTopology, ModelArtifact, ModelArtifactFormat, NodeId, OperatingSystem, PlatformIdentity,
    ProcessorObservation, RuntimeCandidateId, RuntimeIdentity, RuntimeInstallation,
    RuntimeInstallationId, RuntimeInstallationState, RuntimeSource, RuntimeVersion, Sha256Digest,
    TargetId, TechnicalName, UnixMilliseconds,
};
use li_runtime_manager::{
    FilesystemRuntimeArtifactProvider, RuntimeAcceleratorVendor, RuntimeArtifactFetcher,
    RuntimeArtifactProvider, RuntimeArtifactVerifier, RuntimeCandidate, RuntimeCatalogProvider,
    RuntimeClock, RuntimeError, RuntimeEvent, RuntimeExactCandidateArtifacts,
    RuntimeExactEngineArtifact, RuntimeIncompatibility, RuntimeInstallability,
    RuntimeInstallationIdentityProvider, RuntimeInstallationStore, RuntimeManager, RuntimeTarget,
    RuntimeUpdateDisposition, VersionedRuntimeInstallation,
};

// Returns one Linux NVIDIA observation suitable for static target matching.
fn hardware(memory_bytes: u64) -> HardwareObservation {
    HardwareObservation::new(
        HardwareObservationId::parse(&"1".repeat(32)).expect("observation"),
        NodeId::parse(&"2".repeat(32)).expect("node"),
        BootId::parse("boot-fixture").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("Grace CPU").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(memory_bytes).expect("memory"),
        vec![Accelerator::new(
            li_core_interface::DeviceId::parse("GPU-fixture").expect("device"),
            AcceleratorVendor::Nvidia,
            DisplayName::parse("NVIDIA GB10").expect("GPU"),
            AcceleratorMemory::new(MemoryTopology::Unified, None, None).expect("memory"),
            ComputeCapability::Cuda {
                architecture: TechnicalName::parse("sm_121").expect("architecture"),
                maximum_version: Some(TechnicalName::parse("cuda_13.0").expect("CUDA")),
            },
        )],
        Vec::new(),
        UnixMilliseconds::new(1_000),
    )
    .expect("hardware")
}

// Returns one exact runtime candidate with configurable evidence and selection state.
fn candidate(
    character: char,
    evidence: EvidenceLabel,
    recommended: bool,
    revoked: bool,
    protocol: u16,
) -> RuntimeCandidate {
    candidate_version(character, "1.0.0", evidence, recommended, revoked, protocol)
}

// Returns one exact runtime candidate with a configurable release version.
fn candidate_version(
    character: char,
    version: &str,
    evidence: EvidenceLabel,
    recommended: bool,
    revoked: bool,
    protocol: u16,
) -> RuntimeCandidate {
    let digest = character.to_string().repeat(64);
    RuntimeCandidate::new(
        LogicalModelName::parse("qwen3.8").expect("model"),
        RuntimeIdentity::new(
            RuntimeCandidateId::parse(&format!("sglang--radixark--qwen3.8-{character}--dgx-spark"))
                .expect("candidate"),
            RuntimeVersion::parse(version).expect("version"),
            TargetId::parse("dgx-spark").expect("target"),
            RuntimeSource::parse(&format!("ghcr.io/runtime/qwen@sha256:{digest}")).expect("source"),
            EngineDistribution::oci(
                RuntimeSource::parse(&format!("ghcr.io/engine/qwen@sha256:{}", "e".repeat(64)))
                    .expect("Engine source"),
                Sha256Digest::parse(&"f".repeat(64)).expect("Engine identity"),
                None,
                None,
            ),
            Sha256Digest::parse(&digest).expect("runtime digest"),
            Sha256Digest::parse(&"a".repeat(64)).expect("manifest"),
            Sha256Digest::parse(&"b".repeat(64)).expect("execution"),
        )
        .expect("runtime"),
        vec![ModelArtifact::new(
            ArtifactName::parse("model").expect("artifact"),
            ArtifactUri::parse("hf://RadixArk/Qwen3.8").expect("URI"),
            ArtifactRevision::parse(&"c".repeat(40)).expect("revision"),
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
        .expect("target"),
        evidence,
        protocol,
        recommended,
        revoked,
    )
    .expect("candidate")
}

// Supplies candidates in deterministic signed-catalog preference order.
struct TestCatalog(Vec<RuntimeCandidate>);

impl RuntimeCatalogProvider for TestCatalog {
    // Returns cloned candidates for the one fixture model.
    fn candidates(&self, model: &LogicalModelName) -> Result<Vec<RuntimeCandidate>, RuntimeError> {
        if model.as_str() != "qwen3.8" {
            return Ok(Vec::new());
        }
        Ok(self.0.clone())
    }
}

// Rejects every lookup so exact-candidate tests prove catalog selection is never invoked.
struct RejectCatalog;

impl RuntimeCatalogProvider for RejectCatalog {
    // Fails any accidental mutable catalog lookup.
    fn candidates(&self, _model: &LogicalModelName) -> Result<Vec<RuntimeCandidate>, RuntimeError> {
        Err(RuntimeError::CatalogUnavailable)
    }
}

// Treats every evidence label as installable on identical compatible hardware.
#[test]
fn qualification_is_never_an_installation_gate() {
    let manager = RuntimeManager::new(Arc::new(TestCatalog(Vec::new())));
    for label in [
        EvidenceLabel::Qualified,
        EvidenceLabel::Unqualified,
        EvidenceLabel::Unknown,
    ] {
        assert_eq!(
            manager.assess(
                &candidate('1', label, false, false, 2),
                &hardware(128 * 1024 * 1024 * 1024)
            ),
            RuntimeInstallability::Installable {
                evidence_label: label
            }
        );
    }
}

// Reports every static mismatch together without checking live free resources.
#[test]
fn assessment_reports_complete_static_incompatibility() {
    let manager = RuntimeManager::new(Arc::new(TestCatalog(Vec::new())));
    let result = manager.assess(
        &candidate('1', EvidenceLabel::Qualified, false, false, 1),
        &hardware(32 * 1024 * 1024 * 1024),
    );
    let RuntimeInstallability::Incompatible { reasons } = result else {
        panic!("expected incompatibility");
    };
    assert!(reasons.contains(&RuntimeIncompatibility::HostMemory));
    assert!(reasons.contains(&RuntimeIncompatibility::EngineProtocol));
}

// Prefers the compatible signed recommendation without consulting evidence label.
#[test]
fn automatic_selection_prefers_recommended_compatible_candidate() {
    let first = candidate('1', EvidenceLabel::Qualified, false, false, 2);
    let recommended = candidate('2', EvidenceLabel::Unqualified, true, false, 2);
    let manager = RuntimeManager::new(Arc::new(TestCatalog(vec![first, recommended.clone()])));
    let selected = manager
        .select(
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("selection");
    assert_eq!(
        selected.runtime().candidate_id(),
        recommended.runtime().candidate_id()
    );
}

// Rejects a revoked explicit candidate even when its static target matches.
#[test]
fn explicit_selection_rejects_revocation() {
    let revoked = candidate('1', EvidenceLabel::Qualified, true, true, 2);
    let identity = revoked.runtime().candidate_id().clone();
    let manager = RuntimeManager::new(Arc::new(TestCatalog(vec![revoked])));
    assert_eq!(
        manager
            .select(
                &LogicalModelName::parse("qwen3.8").expect("model"),
                Some(&identity),
                &hardware(128 * 1024 * 1024 * 1024),
            )
            .expect_err("revoked candidate must fail"),
        RuntimeError::CandidateRevoked
    );
}

// Skips incompatible and revoked candidates during automatic selection.
#[test]
fn automatic_selection_requires_one_compatible_nonrevoked_candidate() {
    let revoked = candidate('1', EvidenceLabel::Qualified, true, true, 2);
    let incompatible = candidate('2', EvidenceLabel::Qualified, false, false, 1);
    let manager = RuntimeManager::new(Arc::new(TestCatalog(vec![revoked, incompatible])));
    assert_eq!(
        manager
            .select(
                &LogicalModelName::parse("qwen3.8").expect("model"),
                None,
                &hardware(128 * 1024 * 1024 * 1024),
            )
            .expect_err("selection must fail"),
        RuntimeError::CandidateNotFound
    );
}

// Mocks immutable artifact acquisition and records compensating removal.
#[derive(Default)]
struct MockArtifacts {
    fail_acquire: AtomicBool,
    fail_verify: AtomicBool,
    removed: AtomicBool,
    fail_remove: AtomicBool,
    remove_calls: AtomicUsize,
    preserve_remove_calls: AtomicUsize,
    finalize_calls: AtomicUsize,
    finalized_preserving_models: AtomicBool,
}

impl RuntimeArtifactProvider for MockArtifacts {
    // Returns configured acquisition success or failure.
    fn acquire(
        &self,
        _candidate: &RuntimeCandidate,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError> {
        if self.fail_acquire.load(Ordering::SeqCst) {
            Err(RuntimeError::ArtifactUnavailable)
        } else {
            Ok(())
        }
    }

    // Acquires the injected resident closure through the same deterministic mock boundary.
    fn acquire_exact(
        &self,
        _candidate: &RuntimeCandidate,
        _artifacts: &RuntimeExactCandidateArtifacts,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError> {
        if self.fail_acquire.load(Ordering::SeqCst) {
            Err(RuntimeError::ArtifactUnavailable)
        } else {
            Ok(())
        }
    }

    // Returns configured verification success or failure.
    fn verify(
        &self,
        _candidate: &RuntimeCandidate,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError> {
        if self.fail_verify.load(Ordering::SeqCst) {
            Err(RuntimeError::ArtifactUnavailable)
        } else {
            Ok(())
        }
    }

    // Records exact compensating cleanup.
    fn remove(&self, _installation_id: &RuntimeInstallationId) -> Result<(), RuntimeError> {
        self.remove_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_remove.load(Ordering::SeqCst) {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        self.removed.store(true, Ordering::SeqCst);
        Ok(())
    }

    // Records selective cleanup independently from ordinary failed-installation cleanup.
    fn remove_preserving_models(
        &self,
        _installation: &RuntimeInstallation,
    ) -> Result<(), RuntimeError> {
        self.preserve_remove_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_remove.load(Ordering::SeqCst) {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        self.removed.store(true, Ordering::SeqCst);
        Ok(())
    }

    // Records one terminal root closure only after the lifecycle supplies Removed snapshots.
    fn finalize_cleanup(
        &self,
        installations: &[RuntimeInstallation],
        preserve_models: bool,
    ) -> Result<(), RuntimeError> {
        if installations
            .iter()
            .any(|installation| installation.state() != RuntimeInstallationState::Removed)
        {
            return Err(RuntimeError::InstallationUnavailable);
        }
        self.finalize_calls.fetch_add(1, Ordering::SeqCst);
        self.finalized_preserving_models
            .store(preserve_models, Ordering::SeqCst);
        Ok(())
    }
}

// Mocks optimistic installation persistence through the complete lifecycle.
#[derive(Default)]
struct MockStore {
    value: Mutex<Option<VersionedRuntimeInstallation>>,
    fail_replace: AtomicBool,
}

impl RuntimeInstallationStore for MockStore {
    // Returns one stored installation by identity.
    fn read(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
        let value = self
            .value
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?;
        Ok(value
            .as_ref()
            .filter(|stored| stored.installation().installation_id() == installation_id)
            .cloned())
    }

    // Returns the one stored installation when present.
    fn all(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
        Ok(self
            .value
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?
            .iter()
            .cloned()
            .collect())
    }

    // Creates one staging record at revision one.
    fn create(
        &self,
        installation: RuntimeInstallation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        let mut value = self
            .value
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?;
        if value.is_some() {
            return Err(RuntimeError::StoreConflict);
        }
        let stored = VersionedRuntimeInstallation::new(installation, 1);
        *value = Some(stored.clone());
        Ok(stored)
    }

    // Replaces the expected revision or returns the configured conflict.
    fn replace(
        &self,
        installation: RuntimeInstallation,
        expected_revision: u64,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        if self.fail_replace.load(Ordering::SeqCst) {
            return Err(RuntimeError::StoreConflict);
        }
        let mut value = self
            .value
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?;
        if value.as_ref().map(VersionedRuntimeInstallation::revision) != Some(expected_revision) {
            return Err(RuntimeError::StoreConflict);
        }
        let stored = VersionedRuntimeInstallation::new(installation, expected_revision + 1);
        *value = Some(stored.clone());
        Ok(stored)
    }

    // Deletes one exact removed installation revision.
    fn delete(
        &self,
        installation_id: &RuntimeInstallationId,
        expected_revision: u64,
    ) -> Result<(), RuntimeError> {
        let mut value = self
            .value
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?;
        if value.as_ref().is_none_or(|stored| {
            stored.installation().installation_id() != installation_id
                || stored.revision() != expected_revision
        }) {
            return Err(RuntimeError::StoreConflict);
        }
        *value = None;
        Ok(())
    }
}

// Supplies one deterministic installation identity.
struct MockIdentity;

impl RuntimeInstallationIdentityProvider for MockIdentity {
    // Returns the fixture runtime-installation identity.
    fn installation_id(&self) -> Result<RuntimeInstallationId, RuntimeError> {
        RuntimeInstallationId::parse(&"9".repeat(32))
            .map_err(|_| RuntimeError::LifecycleUnavailable)
    }
}

// Supplies deterministic increasing lifecycle timestamps.
struct MockClock(AtomicU64);

impl RuntimeClock for MockClock {
    // Returns one increasing fixture timestamp.
    fn now(&self) -> Result<UnixMilliseconds, RuntimeError> {
        Ok(UnixMilliseconds::new(self.0.fetch_add(1, Ordering::SeqCst)))
    }
}

// Creates one lifecycle-enabled manager with retained mocks.
fn lifecycle_manager(artifacts: Arc<MockArtifacts>, store: Arc<MockStore>) -> RuntimeManager {
    RuntimeManager::with_lifecycle(
        Arc::new(TestCatalog(vec![candidate(
            '1',
            EvidenceLabel::Unqualified,
            true,
            false,
            2,
        )])),
        artifacts,
        store,
        Arc::new(MockIdentity),
        Arc::new(MockClock(AtomicU64::new(2_000))),
    )
}

// Creates one exact-candidate manager whose catalog rejects every accidental lookup.
fn exact_lifecycle_manager(artifacts: Arc<MockArtifacts>, store: Arc<MockStore>) -> RuntimeManager {
    RuntimeManager::with_lifecycle(
        Arc::new(RejectCatalog),
        artifacts,
        store,
        Arc::new(MockIdentity),
        Arc::new(MockClock(AtomicU64::new(2_000))),
    )
}

// Returns one resident-only artifact closure matching the fixture OCI Engine identity.
fn exact_artifacts() -> RuntimeExactCandidateArtifacts {
    RuntimeExactCandidateArtifacts::new(
        "/private/tmp/runtime.letsinfer".into(),
        RuntimeExactEngineArtifact::Reuse,
        Sha256Digest::parse(&"9".repeat(64)).expect("closure"),
    )
    .expect("artifacts")
}

// Installs one preparation-trusted candidate while preserving revocation and compatibility gates.
#[test]
fn exact_candidate_installation_never_reselects_catalog_and_fails_closed() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MockStore::default());
    let manager = exact_lifecycle_manager(artifacts, store.clone());
    let installed = manager
        .install_exact_candidate(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            RuntimeInstallationId::parse(&"4".repeat(32)).expect("installation"),
            candidate('1', EvidenceLabel::Unqualified, false, false, 2),
            exact_artifacts(),
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("exact install");
    assert_eq!(
        installed.installation().installation().state(),
        RuntimeInstallationState::Available
    );

    let fresh_store = Arc::new(MockStore::default());
    let manager = exact_lifecycle_manager(Arc::new(MockArtifacts::default()), fresh_store.clone());
    for (candidate, expected) in [
        (
            candidate('2', EvidenceLabel::Unknown, false, true, 2),
            RuntimeError::CandidateRevoked,
        ),
        (
            candidate('3', EvidenceLabel::Qualified, false, false, 1),
            RuntimeError::Incompatible {
                reasons: vec![RuntimeIncompatibility::EngineProtocol],
            },
        ),
    ] {
        assert_eq!(
            manager.install_exact_candidate(
                NodeId::parse(&"2".repeat(32)).expect("node"),
                RuntimeInstallationId::parse(&"5".repeat(32)).expect("installation"),
                candidate,
                exact_artifacts(),
                &hardware(128 * 1024 * 1024 * 1024),
            ),
            Err(expected)
        );
        assert!(fresh_store.value.lock().expect("store").is_none());
    }

    let mismatched_engine = RuntimeExactCandidateArtifacts::new(
        "/private/tmp/runtime.letsinfer".into(),
        RuntimeExactEngineArtifact::BuiltOci {
            archive_file: "/private/tmp/engine.oci.tar".into(),
            config_digest: Sha256Digest::parse(&"e".repeat(64)).expect("wrong config"),
            local_tag: "li-verifier/candidate:fixture".to_string(),
        },
        Sha256Digest::parse(&"9".repeat(64)).expect("closure"),
    )
    .expect("mismatched Engine artifacts");
    assert_eq!(
        manager.install_exact_candidate(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            RuntimeInstallationId::parse(&"6".repeat(32)).expect("installation"),
            candidate('4', EvidenceLabel::Qualified, false, false, 2),
            mismatched_engine,
            &hardware(128 * 1024 * 1024 * 1024),
        ),
        Err(RuntimeError::ArtifactUnavailable)
    );
    assert!(fresh_store.value.lock().expect("store").is_none());
}

// Stages, acquires, verifies, and activates one unqualified installation.
#[test]
fn installation_lifecycle_reaches_available_with_mocked_boundaries() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MockStore::default());
    let manager = lifecycle_manager(artifacts, store);
    let result = manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("install");
    assert_eq!(
        result.installation().installation().state(),
        RuntimeInstallationState::Available
    );
    assert!(matches!(
        result.event(),
        RuntimeEvent::InstallationAvailable { .. }
    ));
}

// Persists failure and removes exact artifacts when verification fails.
#[test]
fn installation_lifecycle_compensates_mocked_verification_failure() {
    let artifacts = Arc::new(MockArtifacts::default());
    artifacts.fail_verify.store(true, Ordering::SeqCst);
    let store = Arc::new(MockStore::default());
    let manager = lifecycle_manager(artifacts.clone(), store);
    let result = manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("failed installation record");
    assert_eq!(
        result.installation().installation().state(),
        RuntimeInstallationState::Failed
    );
    assert!(artifacts.removed.load(Ordering::SeqCst));
    assert!(matches!(
        result.event(),
        RuntimeEvent::InstallationFailed { .. }
    ));
}

// Returns store conflict without claiming a completed installation event.
#[test]
fn installation_lifecycle_propagates_mocked_store_conflict() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MockStore::default());
    store.fail_replace.store(true, Ordering::SeqCst);
    let manager = lifecycle_manager(artifacts.clone(), store.clone());
    assert_eq!(
        manager
            .install(
                NodeId::parse(&"2".repeat(32)).expect("node"),
                &LogicalModelName::parse("qwen3.8").expect("model"),
                None,
                &hardware(128 * 1024 * 1024 * 1024),
            )
            .expect_err("store conflict must fail"),
        RuntimeError::StoreConflict
    );
    assert_eq!(
        store
            .value
            .lock()
            .expect("store")
            .as_ref()
            .expect("durable staging")
            .installation()
            .state(),
        RuntimeInstallationState::Staging
    );
    store.fail_replace.store(false, Ordering::SeqCst);
    assert_eq!(
        manager.prune(&HashSet::new()).expect("recover staging"),
        vec![RuntimeInstallationId::parse(&"9".repeat(32)).expect("installation")]
    );
    assert!(store.value.lock().expect("store").is_none());
    assert_eq!(artifacts.remove_calls.load(Ordering::SeqCst), 1);
}

// Moves an available installation through Removing to Removed and cleans artifacts.
#[test]
fn removal_lifecycle_completes_with_mocked_boundaries() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MockStore::default());
    let manager = lifecycle_manager(artifacts.clone(), store);
    let installed = manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("install");
    let removed = manager
        .remove(installed.installation().installation().installation_id())
        .expect("remove");
    assert_eq!(
        removed.installation().installation().state(),
        RuntimeInstallationState::Removed
    );
    assert!(artifacts.removed.load(Ordering::SeqCst));
    assert!(matches!(
        removed.event(),
        RuntimeEvent::InstallationRemoved { .. }
    ));
}

// Retains models only for Available closures and ordinarily removes failed installations.
#[test]
fn selective_removal_requires_an_available_verified_closure() {
    let available_artifacts = Arc::new(MockArtifacts::default());
    let available = lifecycle_manager(available_artifacts.clone(), Arc::new(MockStore::default()));
    let installed = available
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("install");
    available
        .remove_preserving_models(installed.installation().installation().installation_id())
        .expect("selective removal");
    assert_eq!(
        available_artifacts
            .preserve_remove_calls
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(available_artifacts.remove_calls.load(Ordering::SeqCst), 0);

    let failed_artifacts = Arc::new(MockArtifacts::default());
    failed_artifacts.fail_acquire.store(true, Ordering::SeqCst);
    let failed = lifecycle_manager(failed_artifacts.clone(), Arc::new(MockStore::default()));
    let installation = failed
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("failed installation");
    failed
        .remove_preserving_models(installation.installation().installation().installation_id())
        .expect("ordinary cleanup");
    assert_eq!(failed_artifacts.remove_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        failed_artifacts
            .preserve_remove_calls
            .load(Ordering::SeqCst),
        0
    );
}

// Refuses root finalization until every store record is Removed, then binds the exact policy.
#[test]
fn cleanup_finalization_requires_terminal_store_state() {
    let artifacts = Arc::new(MockArtifacts::default());
    let manager = lifecycle_manager(artifacts.clone(), Arc::new(MockStore::default()));
    let installed = manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("install");
    assert_eq!(
        manager.finalize_cleanup(true),
        Err(RuntimeError::InstallationUnavailable)
    );
    assert_eq!(artifacts.finalize_calls.load(Ordering::SeqCst), 0);

    manager
        .remove_preserving_models(installed.installation().installation().installation_id())
        .expect("remove");
    manager.finalize_cleanup(true).expect("finalize");
    assert_eq!(artifacts.finalize_calls.load(Ordering::SeqCst), 1);
    assert!(artifacts.finalized_preserving_models.load(Ordering::SeqCst));
}

// Persists Failed state when mocked artifact removal fails.
#[test]
fn removal_lifecycle_records_mocked_cleanup_failure() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MockStore::default());
    let manager = lifecycle_manager(artifacts.clone(), store);
    let installed = manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("install");
    artifacts.fail_remove.store(true, Ordering::SeqCst);
    let failed = manager
        .remove(installed.installation().installation().installation_id())
        .expect("failed removal state");
    assert_eq!(
        failed.installation().installation().state(),
        RuntimeInstallationState::Failed
    );
    artifacts.fail_remove.store(false, Ordering::SeqCst);
    let recovered = manager
        .remove(installed.installation().installation().installation_id())
        .expect("retry removal");
    assert_eq!(
        recovered.installation().installation().state(),
        RuntimeInstallationState::Removed
    );
    assert_eq!(artifacts.remove_calls.load(Ordering::SeqCst), 2);
}

// Prunes unreferenced installations while retaining active references.
#[test]
fn prune_uses_mocked_store_and_reference_set() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MockStore::default());
    let manager = lifecycle_manager(artifacts, store.clone());
    let installed = manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("install");
    let identity = installed
        .installation()
        .installation()
        .installation_id()
        .clone();
    assert!(manager
        .prune(&HashSet::from([identity.clone()]))
        .expect("retained prune")
        .is_empty());
    assert_eq!(
        manager.prune(&HashSet::new()).expect("prune"),
        vec![identity]
    );
    assert!(store.value.lock().expect("store").is_none());
}

// Retains a durable failed cleanup for a later prune retry without deleting its record early.
#[test]
fn prune_retries_failed_cleanup_before_deleting_state() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MockStore::default());
    let manager = lifecycle_manager(artifacts.clone(), store.clone());
    let installation_id = manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("install")
        .installation()
        .installation()
        .installation_id()
        .clone();
    artifacts.fail_remove.store(true, Ordering::SeqCst);
    assert!(manager
        .prune(&HashSet::new())
        .expect("durable cleanup failure")
        .is_empty());
    assert_eq!(
        store
            .read(&installation_id)
            .expect("read")
            .expect("failed cleanup")
            .installation()
            .state(),
        RuntimeInstallationState::Failed
    );
    artifacts.fail_remove.store(false, Ordering::SeqCst);
    assert_eq!(
        manager.prune(&HashSet::new()).expect("retry"),
        vec![installation_id]
    );
    assert!(store.value.lock().expect("store").is_none());
}

// Rejects an update when signed selection resolves to the installed runtime identity.
#[test]
fn update_reports_already_current_without_mutating_mocked_store() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MockStore::default());
    let manager = lifecycle_manager(artifacts, store);
    let installed = manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("install");
    assert_eq!(
        manager
            .update(
                installed.installation().installation(),
                None,
                &hardware(128 * 1024 * 1024 * 1024),
            )
            .expect_err("current update must fail"),
        RuntimeError::NoUpdateAvailable
    );
}

// Stores multiple installations so update handoff can retain old and replacement snapshots.
#[derive(Default)]
struct MultiStore {
    values: Mutex<BTreeMap<String, VersionedRuntimeInstallation>>,
}

impl RuntimeInstallationStore for MultiStore {
    // Returns one exact installation when present.
    fn read(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?
            .get(installation_id.as_str())
            .cloned())
    }

    // Returns every installation in stable identity order.
    fn all(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?
            .values()
            .cloned()
            .collect())
    }

    // Creates one independently addressed staging installation.
    fn create(
        &self,
        installation: RuntimeInstallation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?;
        let key = installation.installation_id().as_str().to_string();
        if values.contains_key(&key) {
            return Err(RuntimeError::StoreConflict);
        }
        let stored = VersionedRuntimeInstallation::new(installation, 1);
        values.insert(key, stored.clone());
        Ok(stored)
    }

    // Replaces one exact optimistic installation revision.
    fn replace(
        &self,
        installation: RuntimeInstallation,
        expected_revision: u64,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?;
        let key = installation.installation_id().as_str().to_string();
        if values.get(&key).map(VersionedRuntimeInstallation::revision) != Some(expected_revision) {
            return Err(RuntimeError::StoreConflict);
        }
        let stored = VersionedRuntimeInstallation::new(installation, expected_revision + 1);
        values.insert(key, stored.clone());
        Ok(stored)
    }

    // Deletes one exact removed installation revision.
    fn delete(
        &self,
        installation_id: &RuntimeInstallationId,
        expected_revision: u64,
    ) -> Result<(), RuntimeError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| RuntimeError::StoreUnavailable)?;
        if values
            .get(installation_id.as_str())
            .map(VersionedRuntimeInstallation::revision)
            != Some(expected_revision)
        {
            return Err(RuntimeError::StoreConflict);
        }
        values.remove(installation_id.as_str());
        Ok(())
    }
}

// Forces two removal readers to observe the same optimistic store revision.
struct ConcurrentRemovalStore {
    inner: Arc<MultiStore>,
    read_barrier: Barrier,
}

impl RuntimeInstallationStore for ConcurrentRemovalStore {
    // Returns one shared snapshot only after both concurrent removals have read it.
    fn read(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
        let value = self.inner.read(installation_id)?;
        self.read_barrier.wait();
        Ok(value)
    }

    // Returns every shared installation without changing synchronization.
    fn all(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
        self.inner.all()
    }

    // Creates one shared installation for trait completeness.
    fn create(
        &self,
        installation: RuntimeInstallation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        self.inner.create(installation)
    }

    // Replaces one exact shared revision through optimistic concurrency.
    fn replace(
        &self,
        installation: RuntimeInstallation,
        expected_revision: u64,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        self.inner.replace(installation, expected_revision)
    }

    // Deletes one exact shared revision for trait completeness.
    fn delete(
        &self,
        installation_id: &RuntimeInstallationId,
        expected_revision: u64,
    ) -> Result<(), RuntimeError> {
        self.inner.delete(installation_id, expected_revision)
    }
}

// Allows exactly one concurrent removal to mutate artifacts and exposes the loser conflict.
#[test]
fn concurrent_removal_has_one_optimistic_winner() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MultiStore::default());
    let installed = versioned_manager(
        candidate_version('1', "1.0.0", EvidenceLabel::Qualified, true, false, 2),
        artifacts.clone(),
        store.clone(),
        &['8'],
    )
    .install(
        NodeId::parse(&"2".repeat(32)).expect("node"),
        &LogicalModelName::parse("qwen3.8").expect("model"),
        None,
        &hardware(128 * 1024 * 1024 * 1024),
    )
    .expect("install");
    let installation_id = installed
        .installation()
        .installation()
        .installation_id()
        .clone();
    let manager = Arc::new(RuntimeManager::with_lifecycle(
        Arc::new(TestCatalog(Vec::new())),
        artifacts.clone(),
        Arc::new(ConcurrentRemovalStore {
            inner: store.clone(),
            read_barrier: Barrier::new(2),
        }),
        Arc::new(MultiIdentity::new(&[])),
        Arc::new(MockClock(AtomicU64::new(8_000))),
    ));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let manager = manager.clone();
            let installation_id = installation_id.clone();
            thread::spawn(move || manager.remove(&installation_id))
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(RuntimeError::StoreConflict)))
            .count(),
        1
    );
    assert_eq!(artifacts.remove_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .read(&installation_id)
            .expect("read")
            .expect("installation")
            .installation()
            .state(),
        RuntimeInstallationState::Removed
    );
}

// Supplies deterministic distinct installation identities in requested order.
struct MultiIdentity(Mutex<VecDeque<RuntimeInstallationId>>);

impl MultiIdentity {
    // Creates one identity source from canonical repeated-hex fixture values.
    fn new(characters: &[char]) -> Self {
        Self(Mutex::new(
            characters
                .iter()
                .map(|character| {
                    RuntimeInstallationId::parse(&character.to_string().repeat(32))
                        .expect("identity")
                })
                .collect(),
        ))
    }
}

impl RuntimeInstallationIdentityProvider for MultiIdentity {
    // Returns the next deterministic installation identity.
    fn installation_id(&self) -> Result<RuntimeInstallationId, RuntimeError> {
        self.0
            .lock()
            .map_err(|_| RuntimeError::LifecycleUnavailable)?
            .pop_front()
            .ok_or(RuntimeError::LifecycleUnavailable)
    }
}

// Creates one lifecycle manager that can retain multiple installation versions.
fn versioned_manager(
    candidate: RuntimeCandidate,
    artifacts: Arc<MockArtifacts>,
    store: Arc<MultiStore>,
    identities: &[char],
) -> RuntimeManager {
    RuntimeManager::with_lifecycle(
        Arc::new(TestCatalog(vec![candidate])),
        artifacts,
        store,
        Arc::new(MultiIdentity::new(identities)),
        Arc::new(MockClock(AtomicU64::new(4_000))),
    )
}

// Prepares a different-version replacement while leaving the current installation untouched.
#[test]
fn different_version_update_returns_ready_handoff_and_retains_current() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MultiStore::default());
    let current_manager = versioned_manager(
        candidate_version('1', "1.0.0", EvidenceLabel::Qualified, true, false, 2),
        artifacts.clone(),
        store.clone(),
        &['8'],
    );
    let current = current_manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("current")
        .installation()
        .installation()
        .clone();
    let update_manager = versioned_manager(
        candidate_version('2', "2.0.0", EvidenceLabel::Unknown, true, false, 2),
        artifacts,
        store.clone(),
        &['9'],
    );
    let handoff = update_manager
        .prepare_update(&current, None, &hardware(128 * 1024 * 1024 * 1024))
        .expect("handoff");
    assert_eq!(handoff.disposition(), RuntimeUpdateDisposition::Ready);
    assert_eq!(handoff.current_installation_id(), current.installation_id());
    assert_eq!(
        handoff.replacement().installation().installation().state(),
        RuntimeInstallationState::Available
    );
    assert_eq!(
        handoff
            .replacement()
            .installation()
            .installation()
            .runtime()
            .version()
            .as_str(),
        "2.0.0"
    );
    assert_eq!(
        store
            .read(current.installation_id())
            .expect("read current")
            .expect("current retained")
            .installation()
            .state(),
        RuntimeInstallationState::Available
    );
    assert_eq!(store.all().expect("all").len(), 2);
}

// Returns a failed replacement handoff without changing current authority or bytes.
#[test]
fn failed_replacement_handoff_preserves_available_current() {
    let artifacts = Arc::new(MockArtifacts::default());
    let store = Arc::new(MultiStore::default());
    let current_manager = versioned_manager(
        candidate_version('1', "1.0.0", EvidenceLabel::Qualified, true, false, 2),
        artifacts.clone(),
        store.clone(),
        &['8'],
    );
    let current = current_manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("current")
        .installation()
        .installation()
        .clone();
    artifacts.fail_verify.store(true, Ordering::SeqCst);
    let update_manager = versioned_manager(
        candidate_version('2', "2.0.0", EvidenceLabel::Unknown, true, false, 2),
        artifacts,
        store.clone(),
        &['9'],
    );
    let handoff = update_manager
        .prepare_update(&current, None, &hardware(128 * 1024 * 1024 * 1024))
        .expect("failed handoff");
    assert_eq!(handoff.disposition(), RuntimeUpdateDisposition::Failed);
    assert_eq!(
        store
            .read(current.installation_id())
            .expect("read current")
            .expect("current retained")
            .installation()
            .state(),
        RuntimeInstallationState::Available
    );
    assert_eq!(store.all().expect("all").len(), 2);
}

// Rejects replacement from every non-Available current state before selection or mutation.
#[test]
fn update_handoff_requires_available_current_installation() {
    let artifacts = Arc::new(MockArtifacts::default());
    artifacts.fail_verify.store(true, Ordering::SeqCst);
    let store = Arc::new(MultiStore::default());
    let manager = versioned_manager(
        candidate_version('1', "1.0.0", EvidenceLabel::Qualified, true, false, 2),
        artifacts,
        store.clone(),
        &['8'],
    );
    let failed = manager
        .install(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(128 * 1024 * 1024 * 1024),
        )
        .expect("failed installation")
        .installation()
        .installation()
        .clone();
    assert_eq!(
        manager
            .prepare_update(&failed, None, &hardware(128 * 1024 * 1024 * 1024),)
            .expect_err("unavailable current"),
        RuntimeError::InstallationUnavailable
    );
    assert_eq!(store.all().expect("all").len(), 1);
}

// Mocks fetch operations while writing deterministic artifact markers.
#[derive(Default)]
struct MockFetcher {
    fail_step: Mutex<Option<&'static str>>,
    calls: Mutex<Vec<&'static str>>,
}

impl RuntimeArtifactFetcher for MockFetcher {
    // Writes one runtime-pack marker or returns the configured failure.
    fn fetch_runtime_pack(
        &self,
        _source: &RuntimeSource,
        _digest: &Sha256Digest,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.fetch("runtime", destination)
    }

    // Writes one model marker or returns the configured failure.
    fn fetch_model_artifact(
        &self,
        _artifact: &ModelArtifact,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.fetch("model", destination)
    }

    // Writes one Engine marker or returns the configured failure.
    fn fetch_engine_distribution(
        &self,
        _candidate: &RuntimeCandidate,
        _runtime_root: &Path,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.fetch("engine", destination)
    }
}

impl MockFetcher {
    // Records and materializes one mocked immutable artifact class.
    fn fetch(&self, step: &'static str, destination: &Path) -> Result<(), RuntimeError> {
        self.calls
            .lock()
            .map_err(|_| RuntimeError::ArtifactUnavailable)?
            .push(step);
        if self
            .fail_step
            .lock()
            .map_err(|_| RuntimeError::ArtifactUnavailable)?
            .as_ref()
            == Some(&step)
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        let fixture = destination.join("fixture");
        fs::write(&fixture, step).map_err(|_| RuntimeError::ArtifactUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&fixture, fs::Permissions::from_mode(0o600))
                .map_err(|_| RuntimeError::ArtifactUnavailable)?;
        }
        Ok(())
    }
}

// Mocks closure verification over the real staged filesystem layout.
#[derive(Default)]
struct MockVerifier {
    should_fail: AtomicBool,
}

impl RuntimeArtifactVerifier for MockVerifier {
    // Verifies the exact mocked model directory without runtime or Engine markers.
    fn verify_models(&self, artifacts: &[ModelArtifact], root: &Path) -> Result<(), RuntimeError> {
        if artifacts.len() != 1
            || artifacts[0].name().as_str() != "model"
            || !root.join("model/fixture").is_file()
            || fs::read(root.join("model/fixture")).ok().as_deref() != Some(b"model")
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        Ok(())
    }

    // Requires every artifact class marker and optional configured success.
    fn verify(&self, _candidate: &RuntimeCandidate, root: &Path) -> Result<(), RuntimeError> {
        if self.should_fail.load(Ordering::SeqCst)
            || !root.join("runtime/fixture").is_file()
            || !root.join("models/model/fixture").is_file()
            || !root.join("engine/fixture").is_file()
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        Ok(())
    }
}

// Projects one acquired candidate into the exact Available installation passed to removal.
fn acquired_installation(
    candidate: &RuntimeCandidate,
    installation_id: RuntimeInstallationId,
) -> RuntimeInstallation {
    RuntimeInstallation::new(
        installation_id,
        NodeId::parse(&"2".repeat(32)).expect("node"),
        candidate.logical_model().clone(),
        candidate.runtime().clone(),
        candidate.artifacts().to_vec(),
        candidate.evidence_label(),
        RuntimeInstallationState::Available,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("installation")
}

// Creates one empty competing destination after staging verification.
struct CollisionVerifier {
    destination: std::path::PathBuf,
}

impl RuntimeArtifactVerifier for CollisionVerifier {
    // Simulates a concurrent owner winning the activation name without replacing its state.
    fn verify(&self, _candidate: &RuntimeCandidate, root: &Path) -> Result<(), RuntimeError> {
        if !root.join("runtime/fixture").is_file()
            || !root.join("models/model/fixture").is_file()
            || !root.join("engine/fixture").is_file()
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        fs::create_dir(&self.destination).map_err(|_| RuntimeError::ArtifactUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&self.destination, fs::Permissions::from_mode(0o700))
                .map_err(|_| RuntimeError::ArtifactUnavailable)?;
        }
        Ok(())
    }
}

// Atomically stages, verifies, reuses, and removes a complete artifact closure.
#[test]
fn filesystem_artifact_provider_runs_all_mocked_fetch_paths() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let fetcher = Arc::new(MockFetcher::default());
    let provider = FilesystemRuntimeArtifactProvider::new(
        directory.path().join("runtime-artifacts"),
        fetcher.clone(),
        Arc::new(MockVerifier::default()),
    )
    .expect("provider");
    let candidate = candidate('1', EvidenceLabel::Qualified, true, false, 2);
    let identity = RuntimeInstallationId::parse(&"9".repeat(32)).expect("installation");
    provider.acquire(&candidate, &identity).expect("acquire");
    provider.verify(&candidate, &identity).expect("verify");
    assert_eq!(
        fetcher.calls.lock().expect("calls").as_slice(),
        &["runtime", "model", "engine"]
    );
    provider.acquire(&candidate, &identity).expect("reuse");
    assert_eq!(fetcher.calls.lock().expect("calls").len(), 3);
    provider.remove(&identity).expect("remove");
    assert!(!directory
        .path()
        .join("runtime-artifacts")
        .join(identity.as_str())
        .exists());
}

// Physically retains only model bytes, reuses them, and rolls back post-restore Engine failure.
#[test]
fn filesystem_artifact_provider_reuses_retained_models_without_refetch() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path().join("runtime-artifacts");
    let fetcher = Arc::new(MockFetcher::default());
    let provider = FilesystemRuntimeArtifactProvider::new(
        root.clone(),
        fetcher.clone(),
        Arc::new(MockVerifier::default()),
    )
    .expect("provider");
    let candidate = candidate('1', EvidenceLabel::Qualified, true, false, 2);
    let first = RuntimeInstallationId::parse(&"8".repeat(32)).expect("first installation");
    provider.acquire(&candidate, &first).expect("first acquire");
    provider
        .remove_preserving_models(&acquired_installation(&candidate, first.clone()))
        .expect("retain models");
    assert!(!root.join(first.as_str()).exists());
    let retained = fs::read_dir(&root)
        .expect("artifact root")
        .map(|entry| entry.expect("entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".retained-models-"))
        })
        .expect("retained model root");
    assert_eq!(
        fs::read(retained.join("model/fixture")).expect("retained model bytes"),
        b"model"
    );

    *fetcher.fail_step.lock().expect("failure") = Some("engine");
    let second = RuntimeInstallationId::parse(&"7".repeat(32)).expect("second installation");
    assert_eq!(
        provider.acquire(&candidate, &second),
        Err(RuntimeError::ArtifactUnavailable)
    );
    assert_eq!(
        fs::read(retained.join("model/fixture")).expect("rolled back model bytes"),
        b"model"
    );

    *fetcher.fail_step.lock().expect("failure") = None;
    let third = RuntimeInstallationId::parse(&"6".repeat(32)).expect("third installation");
    provider
        .acquire(&candidate, &third)
        .expect("retained acquire");
    assert_eq!(
        fetcher
            .calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|step| **step == "model")
            .count(),
        1
    );
    assert!(!retained.exists());
    assert_eq!(
        fs::read(root.join(third.as_str()).join("models/model/fixture"))
            .expect("reused model bytes"),
        b"model"
    );

    provider
        .remove_preserving_models(&acquired_installation(&candidate, third.clone()))
        .expect("retain reused models");
    let retained = fs::read_dir(&root)
        .expect("artifact root")
        .map(|entry| entry.expect("entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".retained-models-"))
        })
        .expect("second retained root");
    fs::write(retained.join("model/fixture"), b"corrupt").expect("corrupt retained bytes");
    let fourth = RuntimeInstallationId::parse(&"5".repeat(32)).expect("fourth installation");
    provider
        .acquire(&candidate, &fourth)
        .expect("corrupt cache refetch");
    assert_eq!(
        fetcher
            .calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|step| **step == "model")
            .count(),
        2
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        provider
            .remove_preserving_models(&acquired_installation(&candidate, fourth.clone()))
            .expect("retain refetched models");
        let retained = fs::read_dir(&root)
            .expect("artifact root")
            .map(|entry| entry.expect("entry").path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".retained-models-"))
            })
            .expect("unsafe retained root");
        fs::set_permissions(&retained, fs::Permissions::from_mode(0o777)).expect("unsafe mode");
        let fifth = RuntimeInstallationId::parse(&"4".repeat(32)).expect("fifth installation");
        assert_eq!(
            provider.acquire(&candidate, &fifth),
            Err(RuntimeError::ArtifactUnavailable)
        );
        assert!(retained.exists());
    }
}

// Salvages a crash-left consumed cache from staging before ordinary stale-work cleanup.
#[cfg(unix)]
#[test]
fn filesystem_artifact_provider_recovers_retained_consumption_marker() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path().join("runtime-artifacts");
    let fetcher = Arc::new(MockFetcher::default());
    let provider = FilesystemRuntimeArtifactProvider::new(
        root.clone(),
        fetcher.clone(),
        Arc::new(MockVerifier::default()),
    )
    .expect("provider");
    let candidate = candidate('1', EvidenceLabel::Qualified, true, false, 2);
    let first = RuntimeInstallationId::parse(&"3".repeat(32)).expect("first installation");
    provider.acquire(&candidate, &first).expect("first acquire");
    provider
        .remove_preserving_models(&acquired_installation(&candidate, first))
        .expect("retain models");
    let retained = fs::read_dir(&root)
        .expect("artifact root")
        .map(|entry| entry.expect("entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".retained-models-"))
        })
        .expect("retained root");
    let retained_name = retained
        .file_name()
        .and_then(|name| name.to_str())
        .expect("retained name")
        .to_string();
    let second = RuntimeInstallationId::parse(&"2".repeat(32)).expect("second installation");
    let staging = root.join(format!(".{}.incoming", second.as_str()));
    fs::create_dir(&staging).expect("staging");
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).expect("staging mode");
    for name in ["runtime", "engine"] {
        let path = staging.join(name);
        fs::create_dir(&path).expect("staging child");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("child mode");
    }
    fs::rename(&retained, staging.join("models")).expect("consume retained models");
    let marker = root.join(format!(".{}.retained-model-source", second.as_str()));
    fs::write(&marker, retained_name).expect("consumption marker");
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("marker mode");

    provider
        .acquire(&candidate, &second)
        .expect("recover and acquire");
    assert!(!marker.exists());
    assert!(!staging.exists());
    assert_eq!(
        fetcher
            .calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|step| **step == "model")
            .count(),
        1
    );
    assert_eq!(
        fs::read(root.join(second.as_str()).join("models/model/fixture")).expect("recovered model"),
        b"model"
    );
}

// Lets one of two concurrent installations reuse one cache while the other exactly refetches.
#[test]
fn filesystem_artifact_provider_serializes_retained_cache_consumption_by_rename() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path().join("runtime-artifacts");
    let fetcher = Arc::new(MockFetcher::default());
    let provider = Arc::new(
        FilesystemRuntimeArtifactProvider::new(
            root.clone(),
            fetcher.clone(),
            Arc::new(MockVerifier::default()),
        )
        .expect("provider"),
    );
    let candidate = candidate('1', EvidenceLabel::Qualified, true, false, 2);
    let original = RuntimeInstallationId::parse(&"1".repeat(32)).expect("original installation");
    provider
        .acquire(&candidate, &original)
        .expect("original acquire");
    provider
        .remove_preserving_models(&acquired_installation(&candidate, original))
        .expect("retain models");

    let barrier = Arc::new(Barrier::new(2));
    let installations = ['2', '3']
        .into_iter()
        .map(|character| {
            let provider = provider.clone();
            let candidate = candidate.clone();
            let barrier = barrier.clone();
            let installation = RuntimeInstallationId::parse(&character.to_string().repeat(32))
                .expect("installation");
            thread::spawn(move || {
                barrier.wait();
                provider.acquire(&candidate, &installation)
            })
        })
        .collect::<Vec<_>>();
    for installation in installations {
        installation
            .join()
            .expect("acquisition thread")
            .expect("acquisition");
    }
    assert_eq!(
        fetcher
            .calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|step| **step == "model")
            .count(),
        2
    );
    for character in ['2', '3'] {
        assert!(root.join(character.to_string().repeat(32)).is_dir());
    }
}

// Cleans staging for failure at every mocked fetch or verification boundary.
#[test]
fn filesystem_artifact_provider_cleans_every_mocked_failure_path() {
    for step in ["runtime", "model", "engine", "verify"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let fetcher = Arc::new(MockFetcher::default());
        let verifier = Arc::new(MockVerifier::default());
        if step == "verify" {
            verifier.should_fail.store(true, Ordering::SeqCst);
        } else {
            *fetcher.fail_step.lock().expect("failure") = Some(step);
        }
        let provider = FilesystemRuntimeArtifactProvider::new(
            directory.path().join("runtime-artifacts"),
            fetcher,
            verifier,
        )
        .expect("provider");
        let candidate = candidate('1', EvidenceLabel::Qualified, true, false, 2);
        let identity = RuntimeInstallationId::parse(&"9".repeat(32)).expect("installation");
        assert!(
            provider.acquire(&candidate, &identity).is_err(),
            "step={step}"
        );
        assert!(!directory
            .path()
            .join("runtime-artifacts")
            .join(format!(".{}.incoming", identity.as_str()))
            .exists());
    }
}

// Rejects unsafe managed metadata and atomically preserves a concurrent activation winner.
#[test]
fn filesystem_artifact_provider_never_replaces_foreign_or_racing_state() {
    let candidate = candidate('1', EvidenceLabel::Qualified, true, false, 2);
    let identity = RuntimeInstallationId::parse(&"9".repeat(32)).expect("installation");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("runtime-artifacts");
        fs::create_dir(&root).expect("managed root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("public mode");
        let fetcher = Arc::new(MockFetcher::default());
        let provider = FilesystemRuntimeArtifactProvider::new(
            root,
            fetcher.clone(),
            Arc::new(MockVerifier::default()),
        )
        .expect("provider");
        assert_eq!(
            provider
                .acquire(&candidate, &identity)
                .expect_err("public root"),
            RuntimeError::ArtifactUnavailable
        );
        assert!(fetcher.calls.lock().expect("calls").is_empty());
    }

    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path().join("runtime-artifacts");
    let destination = root.join(identity.as_str());
    let provider = FilesystemRuntimeArtifactProvider::new(
        root,
        Arc::new(MockFetcher::default()),
        Arc::new(CollisionVerifier {
            destination: destination.clone(),
        }),
    )
    .expect("provider");
    assert_eq!(
        provider
            .acquire(&candidate, &identity)
            .expect_err("activation collision"),
        RuntimeError::ArtifactUnavailable
    );
    assert!(destination.is_dir());
    assert!(destination
        .read_dir()
        .expect("competing destination")
        .next()
        .is_none());
    assert!(!directory
        .path()
        .join("runtime-artifacts")
        .join(format!(".{}.incoming", identity.as_str()))
        .exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&destination, fs::Permissions::from_mode(0o777))
            .expect("foreign destination mode");
        fs::write(destination.join("foreign"), b"preserve").expect("foreign bytes");
        assert_eq!(
            provider.remove(&identity).expect_err("foreign destination"),
            RuntimeError::ArtifactUnavailable
        );
        assert_eq!(
            fs::read(destination.join("foreign")).expect("preserved bytes"),
            b"preserve"
        );
    }
}

// Serializes same-identity acquisition so concurrent retries share one verified closure.
#[test]
fn filesystem_artifact_provider_concurrent_same_identity_acquisition_is_idempotent() {
    for _ in 0..32 {
        let directory = tempfile::tempdir().expect("temporary directory");
        let fetcher = Arc::new(MockFetcher::default());
        let provider = Arc::new(
            FilesystemRuntimeArtifactProvider::new(
                directory.path().join("runtime-artifacts"),
                fetcher.clone(),
                Arc::new(MockVerifier::default()),
            )
            .expect("provider"),
        );
        let candidate = candidate('1', EvidenceLabel::Qualified, true, false, 2);
        let identity = RuntimeInstallationId::parse(&"9".repeat(32)).expect("installation");
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let provider = provider.clone();
                let candidate = candidate.clone();
                let identity = identity.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    provider.acquire(&candidate, &identity)
                })
            })
            .collect();
        for thread in threads {
            thread
                .join()
                .expect("acquisition thread")
                .expect("acquisition");
        }
        assert_eq!(
            fetcher.calls.lock().expect("calls").as_slice(),
            &["runtime", "model", "engine"]
        );
        provider.verify(&candidate, &identity).expect("closure");
    }
}

// Rejects public, symbolic-link, and hard-link aliases at the acquisition lock boundary.
#[cfg(unix)]
#[test]
fn filesystem_artifact_provider_rejects_unsafe_installation_locks() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let candidate = candidate('1', EvidenceLabel::Qualified, true, false, 2);
    let identity = RuntimeInstallationId::parse(&"9".repeat(32)).expect("installation");
    for kind in ["public", "symlink", "hardlink"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("runtime-artifacts");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let lock = root.join(format!(".{}.lock", identity.as_str()));
        let source = directory.path().join("lock-source");
        fs::write(&source, b"lock").expect("source");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("source mode");
        match kind {
            "public" => {
                fs::write(&lock, b"lock").expect("lock");
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o666)).expect("lock mode");
            }
            "symlink" => symlink(&source, &lock).expect("lock symlink"),
            "hardlink" => fs::hard_link(&source, &lock).expect("lock hard link"),
            _ => unreachable!(),
        }
        let fetcher = Arc::new(MockFetcher::default());
        let provider = FilesystemRuntimeArtifactProvider::new(
            root,
            fetcher.clone(),
            Arc::new(MockVerifier::default()),
        )
        .expect("provider");
        assert_eq!(
            provider
                .acquire(&candidate, &identity)
                .expect_err("unsafe lock"),
            RuntimeError::ArtifactUnavailable,
            "kind={kind}"
        );
        assert!(fetcher.calls.lock().expect("calls").is_empty());
    }
}
