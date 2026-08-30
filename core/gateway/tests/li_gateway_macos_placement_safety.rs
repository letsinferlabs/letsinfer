// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{
    InstallationId, NodeId, PlacementGroupId, PlacementId, Sha256Digest, UnixMilliseconds,
};
use li_gateway_manager::{GatewayMacOsPlacementSafetyLease, GatewayMacOsPlacementSafetySnapshot};

// Returns one repeated lowercase hexadecimal identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical Node identity.
fn node_id() -> NodeId {
    NodeId::parse(&identity('1', 32)).expect("node")
}

// Returns one canonical placement-group identity.
fn group_id(character: char) -> PlacementGroupId {
    PlacementGroupId::parse(&identity(character, 32)).expect("group")
}

// Returns one canonical placement identity.
fn placement_id() -> PlacementId {
    PlacementId::parse(&identity('3', 32)).expect("placement")
}

// Returns one canonical SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns one exact native macOS process-safety proof.
fn lease(
    group: char,
    label: &str,
    process_id: u32,
    process_started_at: u64,
    observed_at: u64,
    expires_at: u64,
) -> Result<GatewayMacOsPlacementSafetyLease, li_gateway_manager::GatewayError> {
    GatewayMacOsPlacementSafetyLease::new(
        node_id(),
        group_id(group),
        placement_id(),
        InstallationId::parse(&identity('4', 64)).expect("installation"),
        digest('5'),
        label,
        digest('6'),
        process_id,
        UnixMilliseconds::new(process_started_at),
        UnixMilliseconds::new(observed_at),
        UnixMilliseconds::new(expires_at),
    )
}

// Proves macOS carries native launchd identity without a synthetic Watchdog authority.
#[test]
fn native_launchd_safety_contract_is_distinct_and_complete() {
    let lease = lease('2', "ai.letsinfer.placement.3", 1234, 900, 1_000, 2_000).expect("lease");
    let snapshot = GatewayMacOsPlacementSafetySnapshot::new(
        group_id('2'),
        vec![(placement_id(), node_id())],
        vec![lease.clone()],
    )
    .expect("snapshot");

    assert_eq!(snapshot.leases(), &[lease]);
    assert_eq!(
        snapshot.leases()[0].launchd_label(),
        "ai.letsinfer.placement.3"
    );
    assert_eq!(snapshot.leases()[0].process_id(), 1234);
    assert_eq!(snapshot.leases()[0].executable_identity(), &digest('5'));
}

// Proves unsafe labels, PID reuse ambiguity, time inversion, and group mismatch fail closed.
#[test]
fn native_launchd_safety_mutation_matrix_is_closed() {
    assert!(lease('2', "invalid label", 1234, 900, 1_000, 2_000).is_err());
    assert!(lease('2', "ai.letsinfer.placement", 1, 900, 1_000, 2_000).is_err());
    assert!(lease('2', "ai.letsinfer.placement", 1234, 1_001, 1_000, 2_000).is_err());
    assert!(lease('2', "ai.letsinfer.placement", 1234, 900, 1_000, 1_000).is_err());
    assert!(lease('2', "ai.letsinfer.placement", 1234, 900, 1_000, 61_001).is_err());
    assert!(GatewayMacOsPlacementSafetySnapshot::new(
        group_id('7'),
        vec![(placement_id(), node_id())],
        vec![lease('2', "ai.letsinfer.placement", 1234, 900, 1_000, 2_000).expect("lease")],
    )
    .is_err());
}
