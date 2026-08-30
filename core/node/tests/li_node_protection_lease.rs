// SPDX-License-Identifier: AGPL-3.0-only

use std::num::NonZeroU64;
use std::sync::{Arc, Barrier};
use std::thread;

use li_core_interface::{
    BootId, InstallationId, NodeId, NodeState, PlacementGroupId, PlacementId, Sha256Digest,
    TechnicalName, UnixMilliseconds,
};
use li_gateway_manager::GatewayProtectionAuthority;
use li_node_manager::{
    NodeProtectionLeaseBinding, NodeProtectionLeaseError, NodeProtectionLeaseStore,
    NodeProtectionNodeStatus,
};
use li_placement_manager::{
    LinuxProtectedProcessIdentity, PlacementProtectedTarget, PlacementProtectionGeneration,
    PlacementProtectionPhase,
};
use li_watchdog_manager::{
    WatchdogError, WatchdogManager, WatchdogProcessState, WatchdogProtectedEngine,
    WatchdogProtectionCycle, WatchdogProtectionObservation, WatchdogProtectionProvider,
    WatchdogSafetyAction, WatchdogSafetyEvent, WatchdogSafetyInput, WatchdogSafetyThresholds,
    WatchdogSample, WatchdogSampleProvider, WatchdogStorageProvider,
};

// Returns one exact armed descriptor consumed by the real Watchdog cycle path.
fn descriptor(generation: char) -> String {
    format!(
        "version=1\ngeneration={}\nphase=armed\ncontainer_name=li_engine\ncontainer_id={}\npid=1234\nstart_ticks=5678\nboot_id=12345678-1234-1234-1234-123456789abc\ncgroup=/sys/fs/cgroup/user.slice/li_engine\n",
        identity(generation, 32),
        identity('d', 64),
    )
}

// Supplies one exact sample without consulting host time.
struct SampleMock {
    sequence: u64,
    observed_at: u64,
}

impl WatchdogSampleProvider for SampleMock {
    // Returns the expected sample identity and rejects an unexpected durable head.
    fn sample(&self, sequence: u64) -> Result<WatchdogSample, WatchdogError> {
        if sequence != self.sequence {
            return Err(WatchdogError::provider("sample", "unexpected sequence"));
        }
        WatchdogSample::new(sequence, self.observed_at, sequence)
    }
}

// Returns one exact protection observation without mutating native state.
struct ProtectionMock(WatchdogProtectionObservation);

impl WatchdogProtectionProvider for ProtectionMock {
    // Returns the one deterministic observation.
    fn observations(
        &self,
        _sample: &WatchdogSample,
    ) -> Result<Vec<WatchdogProtectionObservation>, WatchdogError> {
        Ok(vec![self.0.clone()])
    }

    // Accepts an unreachable disarm acknowledgement.
    fn acknowledge_disarmed(&self, _target: &WatchdogProtectedEngine) -> Result<(), WatchdogError> {
        Ok(())
    }

    // Accepts an unreachable trip latch.
    fn latch_trip(
        &self,
        _target: &WatchdogProtectedEngine,
        _action: WatchdogSafetyAction,
        _reason: &'static str,
        _input: WatchdogSafetyInput,
    ) -> Result<(), WatchdogError> {
        Ok(())
    }

    // Reports an unreachable containment as complete.
    fn contain(
        &self,
        _target: &WatchdogProtectedEngine,
        _action: WatchdogSafetyAction,
        _grace_milliseconds: u32,
    ) -> Result<bool, WatchdogError> {
        Ok(true)
    }
}

// Supplies one durable sequence head and accepts deterministic records.
struct StorageMock(u64);

impl WatchdogStorageProvider for StorageMock {
    // Returns the exact next sequence.
    fn next_sequence(&self) -> Result<u64, WatchdogError> {
        Ok(self.0)
    }

    // Accepts the exact sample record.
    fn record_sample(&self, _sample: &WatchdogSample) -> Result<(), WatchdogError> {
        Ok(())
    }

    // Accepts an unreachable safety event.
    fn record_event(&self, _event: &WatchdogSafetyEvent) -> Result<(), WatchdogError> {
        Ok(())
    }

    // Completes the deterministic durability boundary.
    fn flush(&self) -> Result<(), WatchdogError> {
        Ok(())
    }
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical Node identity.
fn node_id(character: char) -> NodeId {
    NodeId::parse(&identity(character, 32)).expect("node")
}

// Returns one canonical placement-group identity.
fn group_id(character: char) -> PlacementGroupId {
    PlacementGroupId::parse(&identity(character, 32)).expect("group")
}

// Returns one canonical placement identity.
fn placement_id(character: char) -> PlacementId {
    PlacementId::parse(&identity(character, 32)).expect("placement")
}

// Returns one canonical SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns one authenticated authority with a monotonic Node-owned generation.
fn authority(node: char, session: char, generation: u64) -> GatewayProtectionAuthority {
    GatewayProtectionAuthority::new(
        node_id(node),
        InstallationId::parse(&identity(node, 64)).expect("Core installation"),
        digest('f'),
        digest(session),
        NonZeroU64::new(generation).expect("session generation"),
    )
}

// Returns one complete real Watchdog cycle for an armed and untripped target.
fn cycle(generation: char, sequence: u64, observed_at: u64) -> WatchdogProtectionCycle {
    let observation = WatchdogProtectionObservation::new(
        WatchdogProtectedEngine::parse(&descriptor(generation)).expect("descriptor"),
        WatchdogProcessState::Running,
        WatchdogSafetyInput {
            available_bytes: 32 << 30,
            ..WatchdogSafetyInput::default()
        },
        false,
    );
    WatchdogManager::new(
        WatchdogSafetyThresholds::new(
            16 << 30,
            8 << 30,
            4 << 30,
            1 << 30,
            500_000,
            100_000,
            3,
            5_000,
        )
        .expect("thresholds"),
        Arc::new(SampleMock {
            sequence,
            observed_at,
        }),
        Arc::new(ProtectionMock(observation)),
        Arc::new(StorageMock(sequence)),
    )
    .expect("Watchdog")
    .tick()
    .expect("tick")
    .protection_cycle()
    .clone()
}

// Returns the Placement-owned target matching one Watchdog descriptor.
fn target(generation: char) -> PlacementProtectedTarget {
    target_with_process(
        generation,
        "li_engine",
        'd',
        1234,
        5678,
        "12345678-1234-1234-1234-123456789abc",
        "/sys/fs/cgroup/user.slice/li_engine",
    )
}

// Returns one Placement-owned target with explicit process identity fields.
#[allow(clippy::too_many_arguments)]
fn target_with_process(
    generation: char,
    container_name: &str,
    container_id: char,
    process_id: u32,
    process_start_ticks: u64,
    boot_id: &str,
    cgroup: &str,
) -> PlacementProtectedTarget {
    PlacementProtectedTarget::new(
        PlacementProtectionGeneration::parse(&identity(generation, 32)).expect("generation"),
        PlacementProtectionPhase::Armed,
        LinuxProtectedProcessIdentity::new(
            TechnicalName::parse(container_name).expect("container"),
            digest(container_id),
            process_id,
            process_start_ticks,
            BootId::parse(boot_id).expect("boot"),
            cgroup,
        )
        .expect("process"),
    )
    .expect("target")
}

// Returns one exact placement binding for a selected Node and group.
fn binding(
    node: char,
    group: char,
    placement: char,
    generation: char,
) -> NodeProtectionLeaseBinding {
    NodeProtectionLeaseBinding::new(
        node_id(node),
        group_id(group),
        placement_id(placement),
        target(generation),
    )
}

// Proves only a completed exact cycle can create a current identity-bound lease.
#[test]
fn complete_cycle_commits_exact_lease_and_replays_idempotently() {
    let store = NodeProtectionLeaseStore::new();
    let authority = authority('1', 'a', 1);
    store
        .begin_watchdog_session(
            authority.clone(),
            UnixMilliseconds::new(900),
            NonZeroU64::new(10).expect("sequence"),
        )
        .expect("session");
    let cycle = cycle('a', 10, 1_000);
    let binding = binding('1', '1', 'a', 'a');
    let first = store
        .commit_protection_cycle(
            authority.node_id(),
            authority.watchdog_session_id(),
            authority.watchdog_session_generation(),
            &cycle,
            std::slice::from_ref(&binding),
            1_000,
        )
        .expect("lease");
    let replay = store
        .commit_protection_cycle(
            authority.node_id(),
            authority.watchdog_session_id(),
            authority.watchdog_session_generation(),
            &cycle,
            &[binding],
            1_000,
        )
        .expect("replay");

    assert_eq!(first, replay);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].sample_sequence().get(), 10);
    assert_eq!(first[0].watchdog_session_generation().get(), 1);
    assert_eq!(
        first[0].core_installation_id(),
        authority.core_installation_id()
    );
    assert_eq!(
        first[0].watchdog_source_identity(),
        authority.watchdog_source_identity()
    );
}

// Proves every exact process field must match the completed Watchdog observation.
#[test]
fn process_identity_mutation_matrix_never_commits_a_lease() {
    let store = NodeProtectionLeaseStore::new();
    let authority = authority('1', 'a', 1);
    store
        .begin_watchdog_session(
            authority.clone(),
            UnixMilliseconds::new(900),
            NonZeroU64::new(10).expect("sequence"),
        )
        .expect("session");
    let cycle = cycle('a', 10, 1_000);
    let mutations = [
        target('b'),
        target_with_process(
            'a',
            "li_engine_other",
            'd',
            1234,
            5678,
            "12345678-1234-1234-1234-123456789abc",
            "/sys/fs/cgroup/user.slice/li_engine",
        ),
        target_with_process(
            'a',
            "li_engine",
            'e',
            1234,
            5678,
            "12345678-1234-1234-1234-123456789abc",
            "/sys/fs/cgroup/user.slice/li_engine",
        ),
        target_with_process(
            'a',
            "li_engine",
            'd',
            1235,
            5678,
            "12345678-1234-1234-1234-123456789abc",
            "/sys/fs/cgroup/user.slice/li_engine",
        ),
        target_with_process(
            'a',
            "li_engine",
            'd',
            1234,
            5679,
            "12345678-1234-1234-1234-123456789abc",
            "/sys/fs/cgroup/user.slice/li_engine",
        ),
        target_with_process(
            'a',
            "li_engine",
            'd',
            1234,
            5678,
            "12345678-1234-1234-1234-123456789abd",
            "/sys/fs/cgroup/user.slice/li_engine",
        ),
        target_with_process(
            'a',
            "li_engine",
            'd',
            1234,
            5678,
            "12345678-1234-1234-1234-123456789abc",
            "/sys/fs/cgroup/user.slice/li_engine_other",
        ),
    ];
    for target in mutations {
        let binding =
            NodeProtectionLeaseBinding::new(node_id('1'), group_id('1'), placement_id('a'), target);
        assert_eq!(
            store.commit_protection_cycle(
                authority.node_id(),
                authority.watchdog_session_id(),
                authority.watchdog_session_generation(),
                &cycle,
                &[binding],
                1_000,
            ),
            Err(NodeProtectionLeaseError::InvalidContract)
        );
    }
    assert!(store
        .placement_group_snapshot(&group_id('1'), &[(placement_id('a'), node_id('1'))])
        .expect("snapshot")
        .expect("connected")
        .leases()
        .is_empty());
}

// Proves Watchdog restart clears leases and rejects the old static-ack cycle receipt.
#[test]
fn restarted_watchdog_requires_one_fresh_cycle_before_reopening() {
    let store = NodeProtectionLeaseStore::new();
    let first = authority('1', 'a', 1);
    store
        .begin_watchdog_session(
            first.clone(),
            UnixMilliseconds::new(900),
            NonZeroU64::new(10).expect("sequence"),
        )
        .expect("first session");
    let old_cycle = cycle('a', 10, 1_000);
    let binding = binding('1', '1', 'a', 'a');
    store
        .commit_protection_cycle(
            first.node_id(),
            first.watchdog_session_id(),
            first.watchdog_session_generation(),
            &old_cycle,
            std::slice::from_ref(&binding),
            1_000,
        )
        .expect("first lease");
    store
        .end_watchdog_session(
            first.node_id(),
            first.watchdog_session_id(),
            first.watchdog_session_generation(),
        )
        .expect("first disconnect");

    let restarted = authority('1', 'b', 2);
    store
        .begin_watchdog_session(
            restarted.clone(),
            UnixMilliseconds::new(2_000),
            NonZeroU64::new(11).expect("sequence"),
        )
        .expect("restart session");
    assert!(store
        .placement_group_snapshot(&group_id('1'), &[(placement_id('a'), node_id('1'))])
        .expect("snapshot")
        .expect("connected snapshot")
        .leases()
        .is_empty());
    assert_eq!(
        store.commit_protection_cycle(
            restarted.node_id(),
            restarted.watchdog_session_id(),
            restarted.watchdog_session_generation(),
            &old_cycle,
            std::slice::from_ref(&binding),
            1_000,
        ),
        Err(NodeProtectionLeaseError::RegressedCycle)
    );

    let fresh = cycle('a', 11, 2_001);
    assert_eq!(
        store
            .commit_protection_cycle(
                restarted.node_id(),
                restarted.watchdog_session_id(),
                restarted.watchdog_session_generation(),
                &fresh,
                &[binding],
                1_000,
            )
            .expect("fresh lease")
            .len(),
        1
    );
}

// Proves lower generations, same-generation substitution, and session reuse fail closed.
#[test]
fn session_generation_matrix_is_monotonic() {
    let store = NodeProtectionLeaseStore::new();
    store
        .begin_watchdog_session(
            authority('1', 'a', 2),
            UnixMilliseconds::new(100),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("session");
    for rejected in [
        authority('1', 'b', 1),
        authority('1', 'b', 2),
        authority('1', 'a', 3),
    ] {
        assert_eq!(
            store.begin_watchdog_session(
                rejected,
                UnixMilliseconds::new(200),
                NonZeroU64::new(2).expect("sequence"),
            ),
            Err(NodeProtectionLeaseError::RegressedCycle)
        );
    }
    store
        .end_watchdog_session(
            &node_id('1'),
            &digest('a'),
            NonZeroU64::new(2).expect("generation"),
        )
        .expect("disconnect");
    assert!(store
        .begin_watchdog_session(
            authority('1', 'b', 3),
            UnixMilliseconds::new(200),
            NonZeroU64::new(2).expect("sequence"),
        )
        .is_ok());
}

// Proves concurrent replacement at one generation has exactly one winning session.
#[test]
fn concurrent_new_session_generation_has_one_winner() {
    let store = Arc::new(NodeProtectionLeaseStore::new());
    store
        .begin_watchdog_session(
            authority('1', 'a', 1),
            UnixMilliseconds::new(100),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("initial");
    store
        .end_watchdog_session(
            &node_id('1'),
            &digest('a'),
            NonZeroU64::new(1).expect("generation"),
        )
        .expect("disconnect");
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for session in ['b', 'c'] {
        let store = store.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            store.begin_watchdog_session(
                authority('1', session, 2),
                UnixMilliseconds::new(200),
                NonZeroU64::new(2).expect("sequence"),
            )
        }));
    }
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(NodeProtectionLeaseError::RegressedCycle))
            .count(),
        1
    );
}

// Proves a restarted Node clears only its leases while a sibling Node remains represented.
#[test]
fn multi_node_restart_preserves_sibling_lease_without_completing_the_group() {
    let store = NodeProtectionLeaseStore::new();
    for (node, session) in [('1', 'a'), ('2', 'b')] {
        let authority = authority(node, session, 1);
        store
            .begin_watchdog_session(
                authority.clone(),
                UnixMilliseconds::new(900),
                NonZeroU64::new(10).expect("sequence"),
            )
            .expect("session");
        store
            .commit_protection_cycle(
                authority.node_id(),
                authority.watchdog_session_id(),
                authority.watchdog_session_generation(),
                &cycle(node, 10, 1_000),
                &[binding(node, '1', node, node)],
                1_000,
            )
            .expect("lease");
    }
    let expected = [
        (placement_id('1'), node_id('1')),
        (placement_id('2'), node_id('2')),
    ];
    assert_eq!(
        store
            .placement_group_snapshot(&group_id('1'), &expected)
            .expect("snapshot")
            .expect("connected")
            .leases()
            .len(),
        2
    );

    store
        .end_watchdog_session(
            &node_id('1'),
            &digest('a'),
            NonZeroU64::new(1).expect("generation"),
        )
        .expect("disconnect");
    store
        .begin_watchdog_session(
            authority('1', 'c', 2),
            UnixMilliseconds::new(2_000),
            NonZeroU64::new(11).expect("sequence"),
        )
        .expect("restart");
    let snapshot = store
        .placement_group_snapshot(&group_id('1'), &expected)
        .expect("snapshot")
        .expect("both sessions connected");
    assert_eq!(snapshot.leases().len(), 1);
    assert_eq!(snapshot.leases()[0].node_id(), &node_id('2'));
}

// Proves stale process leases cannot route through any non-active or replaced Node identity.
#[test]
fn inactive_or_reinstalled_node_never_produces_a_route_snapshot() {
    let store = NodeProtectionLeaseStore::new();
    let authority = authority('1', 'a', 1);
    store
        .begin_watchdog_session(
            authority.clone(),
            UnixMilliseconds::new(900),
            NonZeroU64::new(10).expect("sequence"),
        )
        .expect("session");
    store
        .commit_protection_cycle(
            authority.node_id(),
            authority.watchdog_session_id(),
            authority.watchdog_session_generation(),
            &cycle('a', 10, 1_000),
            &[binding('1', '1', 'a', 'a')],
            1_000,
        )
        .expect("lease");
    let expected = [(placement_id('a'), node_id('1'))];
    let active = NodeProtectionNodeStatus::new(
        node_id('1'),
        authority.core_installation_id().clone(),
        NodeState::Active,
    );
    assert_eq!(
        store
            .placement_group_snapshot_for_nodes(&group_id('1'), &expected, &[active])
            .expect("snapshot")
            .expect("active")
            .leases()
            .len(),
        1
    );

    for state in [
        NodeState::Pending,
        NodeState::Draining,
        NodeState::Offline,
        NodeState::Removed,
    ] {
        assert!(store
            .placement_group_snapshot_for_nodes(
                &group_id('1'),
                &expected,
                &[NodeProtectionNodeStatus::new(
                    node_id('1'),
                    authority.core_installation_id().clone(),
                    state,
                )],
            )
            .expect("snapshot")
            .is_none());
    }
    assert!(store
        .placement_group_snapshot_for_nodes(
            &group_id('1'),
            &expected,
            &[NodeProtectionNodeStatus::new(
                node_id('1'),
                InstallationId::parse(&identity('e', 64)).expect("replacement"),
                NodeState::Active,
            )],
        )
        .expect("snapshot")
        .is_none());
}
