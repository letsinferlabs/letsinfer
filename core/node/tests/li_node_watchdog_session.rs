// SPDX-License-Identifier: AGPL-3.0-only

use std::num::NonZeroU64;
use std::sync::{Arc, Barrier, Mutex};

use li_core_interface::{
    BootId, CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership,
    EndpointScheme, EngineDistribution, EntityTimestamps, InterconnectKind,
    InterconnectRequirement, LogicalModelName, ModelServiceDesiredState, ModelServiceId,
    NetworkPort, NodeAddress, NodeId, Placement, PlacementAssignment, PlacementEndpoint,
    PlacementGroup, PlacementGroupCapacity, PlacementGroupId, PlacementGroupState, PlacementId,
    PlacementResources, PlacementState, PortRange, ResourceIdentity, ResourceLease,
    ResourceLeaseId, ResourceLeaseState, RuntimeCandidateId, RuntimeIdentity,
    RuntimeInstallationId, RuntimeSource, RuntimeVersion, Sha256Digest, TargetId, TaskId,
    TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{
    DatabasePlacementStore, NodeWatchdogControllerId, NodeWatchdogProcessProvider,
    NodeWatchdogProtocolIdentityProvider, NodeWatchdogRuntimeProvider, NodeWatchdogRuntimeStatus,
    NodeWatchdogSession, NodeWatchdogSessionAuthority, NodeWatchdogSessionError,
    NodeWatchdogSessionState, NodeWatchdogTargetError, NodeWatchdogTargetKey,
    NodeWatchdogTargetProvider, PersistedNodeWatchdogTargetProvider,
};
use li_placement_manager::{
    LinuxPlacementProtectedTargetProvider, LinuxPlacementProtectionProvider,
    LinuxProtectedProcessIdentity, PlacementError, PlacementProtectedTarget,
    PlacementProtectionGeneration, PlacementProtectionPhase, PlacementProtectionStatus,
    PlacementRecord, PlacementStore,
};
use li_watchdog_manager::{
    WatchdogControllerBinding, WatchdogControllerSessionProvider, WatchdogProtocolCapabilities,
    WatchdogProtocolDataError, WatchdogProtocolIdentityProvider, WatchdogProtocolResidentStatus,
    WatchdogProtocolSiteStatus,
};

// Stores one deterministic target result that tests may replace between resolutions.
struct MockTargetProvider {
    result: Mutex<Result<PlacementProtectedTarget, NodeWatchdogTargetError>>,
}

impl MockTargetProvider {
    // Creates one target provider with an exact initial result.
    fn new(result: Result<PlacementProtectedTarget, NodeWatchdogTargetError>) -> Self {
        Self {
            result: Mutex::new(result),
        }
    }

    // Replaces the exact current target observation.
    fn set(&self, result: Result<PlacementProtectedTarget, NodeWatchdogTargetError>) {
        *self.result.lock().expect("target result") = result;
    }
}

impl NodeWatchdogTargetProvider for MockTargetProvider {
    // Returns the configured exact target result without inspecting its opaque identity.
    fn active_target(
        &self,
        _target: &NodeWatchdogTargetKey,
    ) -> Result<PlacementProtectedTarget, NodeWatchdogTargetError> {
        self.result.lock().expect("target result").clone()
    }
}

// Opens one real isolated DatabaseManager at a restart-stable path.
fn database(path: &std::path::Path) -> Arc<DatabaseManager> {
    Arc::new(DatabaseManager::open(DatabaseConfiguration::new(path)).expect("database manager"))
}

// Returns one repeated canonical digest.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one exact controller identity.
fn controller(character: char) -> NodeWatchdogControllerId {
    NodeWatchdogControllerId::parse(&character.to_string().repeat(32)).expect("controller")
}

// Returns one exact target in the default placement group.
fn target(character: char) -> NodeWatchdogTargetKey {
    target_in('2', character)
}

// Returns one exact placement-group and placement target key.
fn target_in(group_character: char, placement_character: char) -> NodeWatchdogTargetKey {
    NodeWatchdogTargetKey::new(
        PlacementGroupId::parse(&group_character.to_string().repeat(32)).expect("group"),
        PlacementId::parse(&placement_character.to_string().repeat(32)).expect("placement"),
    )
}

// Returns one complete process-bound target for Watchdog conversion.
fn protected_target(
    generation: char,
    container: char,
    process_id: u32,
) -> PlacementProtectedTarget {
    PlacementProtectedTarget::new(
        PlacementProtectionGeneration::parse(&generation.to_string().repeat(32))
            .expect("generation"),
        PlacementProtectionPhase::Armed,
        LinuxProtectedProcessIdentity::new(
            TechnicalName::parse(&format!("li_placement_{}", "1".repeat(32)))
                .expect("container name"),
            digest(container),
            process_id,
            9_876,
            BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
            "/sys/fs/cgroup/user.slice/user-501.slice/li.scope",
        )
        .expect("process"),
    )
    .expect("protected target")
}

// Returns one exact active session generation.
fn session(
    controller_id: NodeWatchdogControllerId,
    certificate: char,
    generation: u64,
    target: NodeWatchdogTargetKey,
) -> NodeWatchdogSession {
    NodeWatchdogSession::active(
        controller_id,
        digest(certificate),
        NonZeroU64::new(generation).expect("generation"),
        target,
    )
}

// Reconstructs authority after restart and resolves every exact binding field.
#[test]
fn authority_persists_and_resolves_exact_binding_after_restart() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let targets = Arc::new(MockTargetProvider::new(Ok(protected_target(
        '8', '5', 1_234,
    ))));
    let controller_id = controller('1');
    let certificate = digest('a');
    {
        let authority = NodeWatchdogSessionAuthority::new(database(&path), targets.clone());
        let created = authority
            .create(
                "watchdog-create",
                session(controller_id.clone(), 'a', 1, target('1')),
            )
            .expect("create");
        assert_eq!(created.revision(), 1);
        assert!(created.session().protected_target_sha256().is_some());
    }

    let authority = NodeWatchdogSessionAuthority::new(database(&path), targets);
    let binding = authority
        .binding_for_certificate(certificate.as_str())
        .expect("binding");
    assert_eq!(binding.controller_id(), controller_id.as_str());
    assert_eq!(binding.certificate_sha256(), certificate.as_str());
    assert_eq!(binding.session_generation(), 1);
    assert_eq!(binding.target().generation(), &"8".repeat(32));
    assert_eq!(binding.target().container_id(), Some(digest('5').as_str()));
    assert_eq!(binding.target().process_id(), Some(1_234));
    assert_eq!(binding.target().process_start_ticks(), Some(9_876));
    assert_eq!(
        binding.target().boot_id(),
        Some("11111111-2222-3333-4444-555555555555")
    );
}

// Rotates one certificate atomically and terminally revokes its next generation.
#[test]
fn authority_rotation_and_revocation_remove_every_old_authorization_path() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let targets = Arc::new(MockTargetProvider::new(Ok(protected_target(
        '8', '5', 1_234,
    ))));
    let authority = NodeWatchdogSessionAuthority::new(
        database(&directory.path().join("core.sqlite3")),
        targets,
    );
    let controller_id = controller('1');
    authority
        .create(
            "watchdog-create",
            session(controller_id.clone(), 'a', 1, target('1')),
        )
        .expect("create");
    let rotated = authority
        .replace(
            "watchdog-rotate",
            session(controller_id.clone(), 'b', 2, target('1')),
            1,
        )
        .expect("rotate");
    assert_eq!(rotated.revision(), 2);
    assert!(authority
        .binding_for_certificate(digest('a').as_str())
        .is_err());
    assert_eq!(
        authority
            .binding_for_certificate(digest('b').as_str())
            .expect("rotated binding")
            .session_generation(),
        2
    );

    let revoked = authority
        .revoke("watchdog-revoke", &controller_id, 2)
        .expect("revoke");
    assert_eq!(revoked.revision(), 3);
    assert_eq!(revoked.session().state(), NodeWatchdogSessionState::Revoked);
    assert_eq!(revoked.session().session_generation().get(), 3);
    assert_eq!(
        authority
            .revoke("watchdog-revoke", &controller_id, 2)
            .expect("replayed revoke"),
        revoked
    );
    assert!(authority
        .binding_for_certificate(digest('b').as_str())
        .is_err());
}

// Rejects skipped, reused, stale, and conflicting generations while preserving exact replay.
#[test]
fn authority_enforces_generation_replay_and_one_concurrent_winner() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let targets = Arc::new(MockTargetProvider::new(Ok(protected_target(
        '8', '5', 1_234,
    ))));
    let authority = Arc::new(NodeWatchdogSessionAuthority::new(
        database(&directory.path().join("core.sqlite3")),
        targets,
    ));
    let controller_id = controller('1');
    authority
        .create(
            "watchdog-create",
            session(controller_id.clone(), 'a', 1, target('1')),
        )
        .expect("create");
    for generation in [1, 3] {
        assert_eq!(
            authority
                .replace(
                    &format!("invalid-generation-{generation}"),
                    session(controller_id.clone(), 'b', generation, target('1'),),
                    1,
                )
                .expect_err("invalid generation"),
            NodeWatchdogSessionError::Conflict
        );
    }

    let barrier = Arc::new(Barrier::new(3));
    let (first, second) = std::thread::scope(|scope| {
        let run = |certificate: char, idempotency: &'static str| {
            let authority = authority.clone();
            let barrier = barrier.clone();
            let controller_id = controller_id.clone();
            scope.spawn(move || {
                barrier.wait();
                authority.replace(
                    idempotency,
                    session(controller_id, certificate, 2, target('1')),
                    1,
                )
            })
        };
        let first = run('b', "watchdog-first");
        let second = run('c', "watchdog-second");
        barrier.wait();
        (
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        )
    });
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(
        first.err().or_else(|| second.err()).expect("conflict"),
        NodeWatchdogSessionError::Conflict
    );
}

// Fails closed for missing, ambiguous, stopped, and replaced explicit target observations.
#[test]
fn authority_rejects_every_target_resolution_failure_without_persistence() {
    for (index, error) in [
        NodeWatchdogTargetError::Missing,
        NodeWatchdogTargetError::Ambiguous,
        NodeWatchdogTargetError::Inactive,
        NodeWatchdogTargetError::ReplacedProcess,
        NodeWatchdogTargetError::Unavailable,
    ]
    .into_iter()
    .enumerate()
    {
        let directory = tempfile::tempdir().expect("temporary directory");
        let targets = Arc::new(MockTargetProvider::new(Err(error)));
        let authority = NodeWatchdogSessionAuthority::new(
            database(&directory.path().join("core.sqlite3")),
            targets,
        );
        let controller_id = controller(char::from(b'1' + index as u8));
        assert_eq!(
            authority
                .create(
                    &format!("watchdog-target-{index}"),
                    session(controller_id.clone(), 'a', 1, target('1')),
                )
                .expect_err("target failure"),
            NodeWatchdogSessionError::Target(error)
        );
        assert!(authority.read(&controller_id).expect("read").is_none());
    }
}

// Revalidates the live process on every binding rather than trusting creation-time state.
#[test]
fn binding_rejects_stopped_and_replaced_process_after_authority_creation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let targets = Arc::new(MockTargetProvider::new(Ok(protected_target(
        '8', '5', 1_234,
    ))));
    let authority = NodeWatchdogSessionAuthority::new(
        database(&directory.path().join("core.sqlite3")),
        targets.clone(),
    );
    authority
        .create(
            "watchdog-create",
            session(controller('1'), 'a', 1, target('1')),
        )
        .expect("create");
    targets.set(Err(NodeWatchdogTargetError::Inactive));
    assert!(authority
        .binding_for_certificate(digest('a').as_str())
        .is_err());
    targets.set(Err(NodeWatchdogTargetError::ReplacedProcess));
    assert!(authority
        .binding_for_certificate(digest('a').as_str())
        .is_err());
    targets.set(Ok(protected_target('9', '6', 2_345)));
    assert!(authority
        .binding_for_certificate(digest('a').as_str())
        .is_err());
    authority
        .replace(
            "watchdog-rebind",
            session(controller('1'), 'a', 2, target('1')),
            1,
        )
        .expect("explicit rebind");
    let rebound = authority
        .binding_for_certificate(digest('a').as_str())
        .expect("rebound binding");
    assert_eq!(rebound.session_generation(), 2);
    assert_eq!(rebound.target().generation(), &"9".repeat(32));
    assert_eq!(rebound.target().process_id(), Some(2_345));
}

// Stores one replaceable live process result for concrete target resolution.
struct MockProcessProvider {
    result: Mutex<Result<(), NodeWatchdogTargetError>>,
}

impl MockProcessProvider {
    // Creates one process provider from an exact verification result.
    fn new(result: Result<(), NodeWatchdogTargetError>) -> Self {
        Self {
            result: Mutex::new(result),
        }
    }

    // Replaces the live process result between deterministic assertions.
    fn set(&self, result: Result<(), NodeWatchdogTargetError>) {
        *self.result.lock().expect("process result") = result;
    }
}

impl NodeWatchdogProcessProvider for MockProcessProvider {
    // Returns the exact configured process-verification result.
    fn require_running(
        &self,
        _target: &PlacementProtectedTarget,
    ) -> Result<(), NodeWatchdogTargetError> {
        *self.result.lock().expect("process result")
    }
}

// Stores one exact durable protection target for concrete target resolution.
struct MockProtectionProvider(PlacementProtectedTarget);

impl LinuxPlacementProtectedTargetProvider for MockProtectionProvider {
    // Returns the configured exact protected target.
    fn active_target(
        &self,
        _placement: &Placement,
    ) -> Result<Option<PlacementProtectedTarget>, PlacementError> {
        Ok(Some(self.0.clone()))
    }
}

// Returns one exact runtime identity for a persisted placement aggregate.
fn runtime_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("dgx-spark").expect("target"),
        RuntimeSource::parse(&format!("ghcr.io/runtime/qwen@sha256:{}", "a".repeat(64)))
            .expect("runtime source"),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!("ghcr.io/engine/qwen@sha256:{}", "b".repeat(64)))
                .expect("Engine source"),
            digest('c'),
            None,
            Some(digest('d')),
        ),
        digest('a'),
        digest('e'),
        digest('f'),
    )
    .expect("runtime")
}

// Returns one complete running or stopped single-placement aggregate.
fn placement_record(
    group_character: char,
    placement_character: char,
    state: PlacementGroupState,
    port: u16,
    device: &str,
) -> PlacementRecord {
    let placement_group_id =
        PlacementGroupId::parse(&group_character.to_string().repeat(32)).expect("group");
    let placement_id =
        PlacementId::parse(&placement_character.to_string().repeat(32)).expect("placement");
    let node_id = NodeId::parse(&"1".repeat(32)).expect("node");
    let resources = PlacementResources::new(
        PortRange::new(port, 1).expect("ports"),
        vec![DeviceId::parse(device).expect("device")],
        None,
    )
    .expect("resources");
    let placement_state = match state {
        PlacementGroupState::Running => PlacementState::Running,
        PlacementGroupState::Stopped => PlacementState::Stopped,
        _ => panic!("unsupported placement fixture state"),
    };
    let placement = Placement::new(
        placement_id.clone(),
        placement_group_id.clone(),
        PlacementAssignment::new(
            node_id.clone(),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("installation"),
            li_core_interface::HardwareObservationId::parse(&"6".repeat(32))
                .expect("hardware observation"),
            li_core_interface::BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
            UnixMilliseconds::new(900),
            TaskId::parse("task-0").expect("task"),
            NodeAddress::parse("spark.local").expect("address"),
            resources,
            EndpointOwnership::Owner,
        ),
        placement_state,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("placement");
    let endpoint = (state == PlacementGroupState::Running).then(|| {
        PlacementEndpoint::new(
            placement_id.clone(),
            node_id.clone(),
            EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("spark.local").expect("endpoint host"),
                port,
            )
            .expect("endpoint address"),
            CredentialId::parse(&"3".repeat(32)).expect("credential"),
            Some(CredentialId::parse(&"4".repeat(32)).expect("CA")),
            None,
            4,
            4_096,
            EndpointHealth::new(true, false, None, Vec::new()).expect("health"),
        )
        .expect("endpoint")
    });
    let group = PlacementGroup::new(
        placement_group_id,
        ModelServiceId::parse(&"5".repeat(32)).expect("service"),
        runtime_identity(),
        vec![placement_id.clone()],
        placement_id.clone(),
        endpoint,
        PlacementGroupCapacity::new(
            8,
            4,
            4_096,
            InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
        )
        .expect("capacity"),
        if state == PlacementGroupState::Running {
            ModelServiceDesiredState::Running
        } else {
            ModelServiceDesiredState::Stopped
        },
        state,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("group");
    let lease_state = if state == PlacementGroupState::Running {
        ResourceLeaseState::Active
    } else {
        ResourceLeaseState::Reserved
    };
    let leases = [
        ResourceIdentity::Accelerator(DeviceId::parse(device).expect("device")),
        ResourceIdentity::Port(NetworkPort::new(port).expect("port")),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, resource)| {
        ResourceLease::new(
            ResourceLeaseId::parse(&format!("{}{:031x}", group_character, index + 1))
                .expect("lease"),
            placement_id.clone(),
            node_id.clone(),
            resource,
            lease_state,
            EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
                .expect("timestamps"),
        )
    })
    .collect();
    PlacementRecord::new(
        group,
        vec![placement],
        leases,
        vec![vec![placement_id.clone()]],
        vec![(placement_id, digest('9'))],
    )
    .expect("placement record")
}

// Resolves an exact persisted active placement and rejects stopped or replaced live state.
#[test]
fn persisted_target_provider_binds_durable_placement_to_unchanged_live_process() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(DatabasePlacementStore::new(database(
        &directory.path().join("core.sqlite3"),
    )));
    store
        .create(placement_record(
            '2',
            '1',
            PlacementGroupState::Running,
            18_000,
            "GPU-A",
        ))
        .expect("placement create");
    let protected = protected_target('8', '5', 1_234);
    let processes = Arc::new(MockProcessProvider::new(Ok(())));
    let provider = PersistedNodeWatchdogTargetProvider::new(
        NodeId::parse(&"1".repeat(32)).expect("node"),
        store,
        Arc::new(MockProtectionProvider(protected.clone())),
        processes.clone(),
    );
    assert_eq!(
        provider.active_target(&target('1')).expect("target"),
        protected
    );

    processes.set(Err(NodeWatchdogTargetError::Inactive));
    assert_eq!(
        provider.active_target(&target('1')).expect_err("stopped"),
        NodeWatchdogTargetError::Inactive
    );
    processes.set(Err(NodeWatchdogTargetError::ReplacedProcess));
    assert_eq!(
        provider
            .active_target(&target('1'))
            .expect_err("replaced process"),
        NodeWatchdogTargetError::ReplacedProcess
    );
}

// Selects the exact group and rejects a missing placement without scanning other groups.
#[test]
fn persisted_target_provider_uses_explicit_group_and_placement_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(DatabasePlacementStore::new(database(
        &directory.path().join("core.sqlite3"),
    )));
    for record in [
        placement_record('2', '1', PlacementGroupState::Running, 18_000, "GPU-A"),
        placement_record('3', '1', PlacementGroupState::Running, 19_000, "GPU-B"),
    ] {
        store.create(record).expect("placement create");
    }
    let protected = protected_target('8', '5', 1_234);
    let provider = PersistedNodeWatchdogTargetProvider::new(
        NodeId::parse(&"1".repeat(32)).expect("node"),
        store,
        Arc::new(MockProtectionProvider(protected)),
        Arc::new(MockProcessProvider::new(Ok(()))),
    );
    assert_eq!(
        provider.active_target(&target('f')).expect_err("missing"),
        NodeWatchdogTargetError::Missing
    );
    assert_eq!(
        provider.active_target(&target('1')).expect("first group"),
        protected_target('8', '5', 1_234)
    );
    assert_eq!(
        provider
            .active_target(&target_in('3', '1'))
            .expect("second group"),
        protected_target('8', '5', 1_234)
    );
}

// Keeps the checked-in persistence schema aligned with the exact closed record payload.
#[test]
fn checked_in_watchdog_session_schema_owns_exact_identity_and_generation_bounds() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/node/li_node_watchdog_session_record_v1.schema.json"
    ))
    .expect("schema JSON");
    assert_eq!(schema["properties"]["session_generation"]["minimum"], 1);
    assert_eq!(
        schema["properties"]["target_placement_group_id"]["$ref"],
        "#/$defs/hex_32"
    );
    assert_eq!(
        schema["properties"]["protected_target_sha256"]["$ref"],
        "#/$defs/hex_64"
    );
    assert_eq!(schema["oneOf"].as_array().expect("record union").len(), 2);
    assert_eq!(schema["additionalProperties"], false);
}

// Supplies one replaceable verified RuntimeManager status projection.
struct MockWatchdogRuntimeProvider {
    result: Mutex<Result<NodeWatchdogRuntimeStatus, WatchdogProtocolDataError>>,
}

impl MockWatchdogRuntimeProvider {
    // Creates one provider from an exact initial runtime status result.
    fn new(result: Result<NodeWatchdogRuntimeStatus, WatchdogProtocolDataError>) -> Self {
        Self {
            result: Mutex::new(result),
        }
    }

    // Replaces the runtime status result between deterministic assertions.
    fn set(&self, result: Result<NodeWatchdogRuntimeStatus, WatchdogProtocolDataError>) {
        *self.result.lock().expect("runtime status") = result;
    }
}

impl NodeWatchdogRuntimeProvider for MockWatchdogRuntimeProvider {
    // Returns the configured status without interpreting the opaque installation identity.
    fn status(
        &self,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<NodeWatchdogRuntimeStatus, WatchdogProtocolDataError> {
        self.result.lock().expect("runtime status").clone()
    }
}

// Supplies one replaceable current Placement protection observation.
struct MockWatchdogProtectionProvider {
    result: Mutex<Result<PlacementProtectionStatus, PlacementError>>,
}

impl MockWatchdogProtectionProvider {
    // Creates one provider from an exact initial protection status result.
    fn new(result: Result<PlacementProtectionStatus, PlacementError>) -> Self {
        Self {
            result: Mutex::new(result),
        }
    }

    // Replaces the protection status result between deterministic assertions.
    fn set(&self, result: Result<PlacementProtectionStatus, PlacementError>) {
        *self.result.lock().expect("protection status") = result;
    }
}

impl LinuxPlacementProtectionProvider for MockWatchdogProtectionProvider {
    // Rejects mutation because identity projection owns read-only status.
    fn begin(
        &self,
        _placement: &Placement,
    ) -> Result<PlacementProtectionGeneration, PlacementError> {
        Err(PlacementError::ProtectionUnsafe)
    }

    // Rejects mutation because identity projection owns read-only status.
    fn bind_starting(
        &self,
        _placement: &Placement,
        _generation: &PlacementProtectionGeneration,
        _process: &LinuxProtectedProcessIdentity,
    ) -> Result<(), PlacementError> {
        Err(PlacementError::ProtectionUnsafe)
    }

    // Rejects mutation because identity projection owns read-only status.
    fn arm(
        &self,
        _placement: &Placement,
        _generation: &PlacementProtectionGeneration,
        _process: &LinuxProtectedProcessIdentity,
    ) -> Result<(), PlacementError> {
        Err(PlacementError::ProtectionUnsafe)
    }

    // Rejects mutation because identity projection owns read-only status.
    fn disarm(&self, _placement: &Placement) -> Result<PlacementProtectionStatus, PlacementError> {
        Err(PlacementError::ProtectionUnsafe)
    }

    // Returns the exact configured current status.
    fn status(
        &self,
        _placement: &Placement,
        _process: Option<&LinuxProtectedProcessIdentity>,
    ) -> Result<PlacementProtectionStatus, PlacementError> {
        self.result.lock().expect("protection status").clone()
    }

    // Rejects mutation because identity projection owns read-only status.
    fn acknowledge_trip(&self, _placement: &Placement) -> Result<bool, PlacementError> {
        Err(PlacementError::ProtectionUnsafe)
    }

    // Rejects mutation because identity projection owns read-only status.
    fn retire(&self, _placement: &Placement) -> Result<(), PlacementError> {
        Err(PlacementError::ProtectionUnsafe)
    }
}

// Creates one exact RuntimeManager projection whose Engine identity is not candidate-derived.
fn watchdog_runtime_status(runtime: RuntimeIdentity) -> NodeWatchdogRuntimeStatus {
    NodeWatchdogRuntimeStatus::new(
        LogicalModelName::parse("fixture-model").expect("logical model"),
        runtime,
        TechnicalName::parse("verified-engine").expect("Engine identity"),
        "verified-cache",
        true,
    )
    .expect("runtime status")
}

// Creates one target-keyed identity provider over real durable placement and session records.
fn watchdog_identity_fixture(
    state: PlacementGroupState,
) -> (
    NodeWatchdogProtocolIdentityProvider,
    WatchdogControllerBinding,
    Arc<MockWatchdogRuntimeProvider>,
    Arc<MockWatchdogProtectionProvider>,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("core.sqlite3"));
    let placements = Arc::new(DatabasePlacementStore::new(database.clone()));
    placements
        .create(placement_record('2', '1', state, 18_000, "GPU-A"))
        .expect("placement create");
    let targets = Arc::new(MockTargetProvider::new(Ok(protected_target(
        '8', '5', 1_234,
    ))));
    let sessions = Arc::new(NodeWatchdogSessionAuthority::new(database, targets));
    sessions
        .create(
            "watchdog-identity-create",
            session(controller('1'), 'a', 1, target('1')),
        )
        .expect("session create");
    let binding = sessions
        .binding_for_certificate(digest('a').as_str())
        .expect("binding");
    let runtimes = Arc::new(MockWatchdogRuntimeProvider::new(Ok(
        watchdog_runtime_status(runtime_identity()),
    )));
    let protection = Arc::new(MockWatchdogProtectionProvider::new(Ok(
        PlacementProtectionStatus::new(PlacementProtectionPhase::Armed, false),
    )));
    let identity = NodeWatchdogProtocolIdentityProvider::new(
        NodeId::parse(&"9".repeat(32)).expect("node identity"),
        "0.1.0".to_string(),
        digest('6'),
        "7".repeat(64),
        1_000,
        10_000,
        1,
        sessions,
        placements,
        runtimes.clone(),
        protection.clone(),
    )
    .expect("identity provider");
    (identity, binding, runtimes, protection, directory)
}

// Emits exact status from the authenticated target and explicit verified Engine identity.
#[test]
fn protocol_identity_projects_exact_target_without_parsing_runtime_candidate_names() {
    let (identity, binding, _, protection, _directory) =
        watchdog_identity_fixture(PlacementGroupState::Running);
    protection.set(Ok(PlacementProtectionStatus::new(
        PlacementProtectionPhase::Armed,
        true,
    )));
    assert_eq!(
        identity.capabilities().expect("capabilities"),
        WatchdogProtocolCapabilities::new(1_000, 10_000, 1).expect("expected capabilities")
    );
    assert_eq!(
        identity.resident_status().expect("resident status"),
        WatchdogProtocolResidentStatus::ready(
            NodeId::parse(&"9".repeat(32)).expect("node identity"),
            "0.1.0".to_string(),
            digest('6'),
            li_core_interface::InstallationId::parse(&"7".repeat(64))
                .expect("installation identity"),
        )
        .expect("expected resident status")
    );
    assert_eq!(
        identity.site_status(&binding).expect("site status"),
        WatchdogProtocolSiteStatus::new(
            "0.1.0".to_string(),
            "fixture-model".to_string(),
            "verified-engine".to_string(),
            "sglang--radixark--qwen3.8--dgx-spark".to_string(),
            "1.0.0".to_string(),
            "e".repeat(64),
            "verified-cache".to_string(),
            true,
            18_000,
            8,
            4,
            4_096,
            "running".to_string(),
            "running".to_string(),
            "armed".to_string(),
            true,
            true,
            format!("li_placement_{}", "1".repeat(32)),
            "7".repeat(64),
        )
        .expect("expected status")
    );
}

// Denies stale authorization, inactive placement state, and runtime identity disagreement.
#[test]
fn protocol_identity_fails_closed_for_auth_state_and_runtime_disagreement() {
    let (identity, binding, runtimes, _, _directory) =
        watchdog_identity_fixture(PlacementGroupState::Running);
    runtimes.set(Ok(watchdog_runtime_status(
        RuntimeIdentity::new(
            RuntimeCandidateId::parse("opaque--different--runtime--target").expect("candidate"),
            RuntimeVersion::parse("2.0.0").expect("version"),
            TargetId::parse("dgx-spark").expect("target"),
            RuntimeSource::parse(&format!("ghcr.io/runtime/other@sha256:{}", "1".repeat(64)))
                .expect("source"),
            EngineDistribution::oci(
                RuntimeSource::parse(&format!("ghcr.io/engine/other@sha256:{}", "2".repeat(64)))
                    .expect("Engine source"),
                digest('3'),
                None,
                Some(digest('4')),
            ),
            digest('5'),
            digest('6'),
            digest('7'),
        )
        .expect("runtime"),
    )));
    assert_eq!(
        identity
            .site_status(&binding)
            .expect_err("runtime mismatch"),
        WatchdogProtocolDataError::Unavailable
    );

    let (inactive, inactive_binding, _, _, _inactive_directory) =
        watchdog_identity_fixture(PlacementGroupState::Stopped);
    assert_eq!(
        inactive
            .site_status(&inactive_binding)
            .expect_err("inactive placement"),
        WatchdogProtocolDataError::Unavailable
    );
}

// Denies missing RuntimeManager data and any protection phase that changed after authorization.
#[test]
fn protocol_identity_fails_closed_for_provider_and_protection_changes() {
    let (identity, binding, runtimes, protection, _directory) =
        watchdog_identity_fixture(PlacementGroupState::Running);
    runtimes.set(Err(WatchdogProtocolDataError::Unavailable));
    assert_eq!(
        identity.site_status(&binding).expect_err("runtime failure"),
        WatchdogProtocolDataError::Unavailable
    );
    runtimes.set(Ok(watchdog_runtime_status(runtime_identity())));
    protection.set(Ok(PlacementProtectionStatus::new(
        PlacementProtectionPhase::Starting,
        false,
    )));
    assert_eq!(
        identity
            .site_status(&binding)
            .expect_err("protection changed"),
        WatchdogProtocolDataError::Unavailable
    );
    protection.set(Err(PlacementError::ExecutionUnavailable));
    assert_eq!(
        identity
            .site_status(&binding)
            .expect_err("protection failure"),
        WatchdogProtocolDataError::Unavailable
    );
}
