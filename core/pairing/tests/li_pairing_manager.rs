// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use li_core_interface::{
    DisplayName, InstallationId, MachineId, NetworkInterfaceName, NodeAddress, NodeId,
    NodeIdentity, NodeRole, PairingInviteId, Sha256Digest, UnixMilliseconds,
};
use li_pairing_manager::{
    PairingAdvertisement, PairingCandidate, PairingClock, PairingContext, PairingCredentials,
    PairingDirectLinkProvider, PairingDiscoveryProvider, PairingError, PairingEvent,
    PairingManager, PairingMaterialProvider, PairingMembershipState, PairingMode, PairingRecord,
    PairingReplayOperation, PairingReplayRecord, PairingSetupCodeProvider, PairingStore,
    PairingTrustProvider, PairingWindowRequest, VersionedPairingRecord,
};
use sha2::{Digest, Sha256};

// Supplies deterministic mutable time to pairing tests.
struct TestClock {
    value: AtomicU64,
    fail_next: AtomicBool,
}

impl TestClock {
    // Creates one exact pairing clock.
    fn new(value: u64) -> Self {
        Self {
            value: AtomicU64::new(value),
            fail_next: AtomicBool::new(false),
        }
    }

    // Changes the exact timestamp returned by later calls.
    fn set(&self, value: u64) {
        self.value.store(value, Ordering::SeqCst);
    }

    // Fails exactly the next clock observation without advancing test time.
    fn fail_next(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }
}

impl PairingClock for TestClock {
    // Returns the configured deterministic timestamp.
    fn now(&self) -> Result<UnixMilliseconds, PairingError> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(PairingError::StateUnavailable);
        }
        Ok(UnixMilliseconds::new(self.value.load(Ordering::SeqCst)))
    }
}

// Supplies deterministic unique bytes for invitation fixtures.
struct TestMaterial {
    next_value: AtomicU8,
    fail_next: AtomicBool,
}

impl TestMaterial {
    // Creates deterministic material beginning with one byte.
    fn new(first_value: u8) -> Self {
        Self {
            next_value: AtomicU8::new(first_value),
            fail_next: AtomicBool::new(false),
        }
    }

    // Fails exactly the next entropy request without consuming fixture material.
    fn fail_next(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }
}

impl PairingMaterialProvider for TestMaterial {
    // Fills each destination with the next deterministic byte.
    fn fill(&self, destination: &mut [u8]) -> Result<(), PairingError> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(PairingError::EntropyUnavailable);
        }
        destination.fill(self.next_value.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

// Derives one deterministic code without retaining or persisting plaintext state.
struct TestSetupCode;

impl PairingSetupCodeProvider for TestSetupCode {
    // Returns the exact eight-digit fixture for every installation-bound input set.
    fn derive(
        &self,
        _installation_id: &InstallationId,
        _invite_id: &PairingInviteId,
        _nonce: &Sha256Digest,
        _salt: &[u8; 16],
    ) -> Result<[u8; 8], PairingError> {
        Ok(*b"12345678")
    }
}

// Captures pairing publications and removals without invoking native discovery.
#[derive(Default)]
struct TestDiscovery {
    published: Mutex<Vec<PairingAdvertisement>>,
    unpublished: Mutex<Vec<String>>,
    should_fail: AtomicBool,
}

impl PairingDiscoveryProvider for TestDiscovery {
    // Records one bounded advertisement or returns the configured failure.
    fn publish(&self, advertisement: &PairingAdvertisement) -> Result<(), PairingError> {
        if self.should_fail.load(Ordering::SeqCst) {
            return Err(PairingError::DiscoveryUnavailable);
        }
        self.published
            .lock()
            .map_err(|_| PairingError::StateUnavailable)?
            .push(advertisement.clone());
        Ok(())
    }

    // Records removal of one invitation advertisement.
    fn unpublish(&self, invite_id: &PairingInviteId) {
        if let Ok(mut values) = self.unpublished.lock() {
            values.push(invite_id.as_str().to_string());
        }
    }
}

// Verifies direct-link pairing against one deterministic peer address.
#[derive(Default)]
struct TestDirectLink {
    should_fail: AtomicBool,
}

impl PairingDirectLinkProvider for TestDirectLink {
    // Accepts only the fixture interface and direct peer address.
    fn verify(
        &self,
        interface: &NetworkInterfaceName,
        peer_address: &NodeAddress,
    ) -> Result<(), PairingError> {
        if self.should_fail.load(Ordering::SeqCst)
            || interface.as_str() != "enp1s0"
            || peer_address.as_str() != "192.168.10.2"
        {
            return Err(PairingError::Unauthorized);
        }
        Ok(())
    }
}

// Verifies deterministic proof bytes and issues public fixture credentials.
#[derive(Default)]
struct TestTrust {
    should_fail: AtomicBool,
    membership_should_fail: AtomicBool,
}

// Persists deterministic versioned pairing records for manager lifecycle tests.
#[derive(Default)]
struct TestPairingStore {
    records: Mutex<BTreeMap<String, (PairingRecord, u64)>>,
    replays: Mutex<BTreeMap<String, PairingReplayRecord>>,
    fail_next: AtomicBool,
}

impl TestPairingStore {
    // Fails exactly the next store operation before observing or mutating state.
    fn fail_next(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }

    // Applies one scheduled deterministic store failure.
    fn fail_if_requested(&self) -> Result<(), PairingError> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(PairingError::StoreUnavailable);
        }
        Ok(())
    }
}

impl PairingStore for TestPairingStore {
    // Creates one absent record at revision one.
    fn create(&self, record: PairingRecord) -> Result<VersionedPairingRecord, PairingError> {
        self.fail_if_requested()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?;
        let identity = record.invite_id().as_str().to_string();
        if records.contains_key(&identity) {
            return Err(PairingError::StoreConflict);
        }
        let replay = PairingReplayRecord::open(&record)?;
        self.replays
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?
            .insert(
                replay.identity().idempotency_sha256().as_str().to_string(),
                replay,
            );
        records.insert(identity, (record.clone(), 1));
        VersionedPairingRecord::new(record, 1)
    }

    // Reads one exact record snapshot.
    fn pairing(
        &self,
        invite_id: &PairingInviteId,
    ) -> Result<Option<VersionedPairingRecord>, PairingError> {
        self.fail_if_requested()?;
        self.records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?
            .get(invite_id.as_str())
            .map(|(record, revision)| VersionedPairingRecord::new(record.clone(), *revision))
            .transpose()
    }

    // Resolves one exact open, enroll, or approval replay identity.
    fn replay(
        &self,
        idempotency_sha256: &Sha256Digest,
    ) -> Result<Option<PairingReplayRecord>, PairingError> {
        self.fail_if_requested()?;
        Ok(self
            .replays
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?
            .get(idempotency_sha256.as_str())
            .cloned())
    }

    // Lists only the caller-bounded record set.
    fn pairings(
        &self,
        maximum_results: usize,
    ) -> Result<Vec<VersionedPairingRecord>, PairingError> {
        self.fail_if_requested()?;
        let records = self
            .records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?;
        if records.len() > maximum_results {
            return Err(PairingError::StoreCorrupt);
        }
        records
            .values()
            .map(|(record, revision)| VersionedPairingRecord::new(record.clone(), *revision))
            .collect()
    }

    // Replaces one exact observed revision.
    fn replace(
        &self,
        record: PairingRecord,
        expected_revision: u64,
    ) -> Result<VersionedPairingRecord, PairingError> {
        self.fail_if_requested()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?;
        let identity = record.invite_id().as_str().to_string();
        let (current, revision) = records.get(&identity).ok_or(PairingError::NotFound)?;
        if *revision != expected_revision {
            return Err(PairingError::StoreConflict);
        }
        let replay = if current.approval_replay() != record.approval_replay() {
            record.approval_replay().map(|identity| {
                PairingReplayRecord::operation(
                    identity.clone(),
                    PairingReplayOperation::Approve,
                    record.invite_id().clone(),
                )
            })
        } else if current.enrollment_replay() != record.enrollment_replay() {
            record.enrollment_replay().map(|identity| {
                PairingReplayRecord::operation(
                    identity.clone(),
                    PairingReplayOperation::Enroll,
                    record.invite_id().clone(),
                )
            })
        } else {
            None
        }
        .transpose()?;
        if let Some(replay) = replay {
            self.replays
                .lock()
                .map_err(|_| PairingError::StoreUnavailable)?
                .insert(
                    replay.identity().idempotency_sha256().as_str().to_string(),
                    replay,
                );
        }
        let revision = revision.checked_add(1).ok_or(PairingError::StoreCorrupt)?;
        records.insert(identity, (record.clone(), revision));
        VersionedPairingRecord::new(record, revision)
    }

    // Removes one just-created invitation and replay mapping after publication failure.
    fn rollback_create(
        &self,
        record: &PairingRecord,
        expected_revision: u64,
    ) -> Result<(), PairingError> {
        self.fail_if_requested()?;
        self.delete(record.invite_id(), expected_revision)?;
        self.replays
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?
            .remove(record.open_replay().idempotency_sha256().as_str());
        Ok(())
    }

    // Deletes one exact observed revision.
    fn delete(
        &self,
        invite_id: &PairingInviteId,
        expected_revision: u64,
    ) -> Result<(), PairingError> {
        self.fail_if_requested()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?;
        let (_, revision) = records
            .get(invite_id.as_str())
            .ok_or(PairingError::NotFound)?;
        if *revision != expected_revision {
            return Err(PairingError::StoreConflict);
        }
        records.remove(invite_id.as_str());
        Ok(())
    }
}

impl PairingTrustProvider for TestTrust {
    // Verifies the fixture signature and returns the public-key SHA-256.
    fn verify_candidate(
        &self,
        public_key: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<Sha256Digest, PairingError> {
        if self.should_fail.load(Ordering::SeqCst)
            || signature != b"fixture-signature"
            || transcript.is_empty()
        {
            return Err(PairingError::Unauthorized);
        }
        Sha256Digest::parse(&format!("{:x}", Sha256::digest(public_key)))
            .map_err(|_| PairingError::TrustUnavailable)
    }

    // Returns one bounded public credential fixture.
    fn issue_membership(
        &self,
        _context: &PairingContext,
        _candidate: &PairingCandidate,
        _public_key_fingerprint: &Sha256Digest,
        _state: PairingMembershipState,
        _approval_expires_at: Option<UnixMilliseconds>,
    ) -> Result<PairingCredentials, PairingError> {
        if self.membership_should_fail.swap(false, Ordering::SeqCst) {
            return Err(PairingError::TrustUnavailable);
        }
        PairingCredentials::new(
            b"site-public-key".to_vec(),
            b"site-ca-certificate".to_vec(),
            b"member-certificate".to_vec(),
            b"membership-signature".to_vec(),
            Sha256Digest::parse(&"a".repeat(64)).expect("member leaf"),
            UnixMilliseconds::new(500),
            UnixMilliseconds::new(500_000),
        )
    }
}

// Returns one canonical main or child pairing context.
fn context(role: NodeRole) -> PairingContext {
    PairingContext::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            MachineId::parse(&"2".repeat(32)).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        role,
        DisplayName::parse("Home AI").expect("display name"),
        NodeAddress::parse("homeai.local").expect("address"),
        9_770,
        Sha256Digest::parse(&"4".repeat(64)).expect("public key"),
        Sha256Digest::parse(&"5".repeat(64)).expect("certificate"),
    )
}

// Creates one manager and retains its observable providers.
fn manager(
    role: NodeRole,
) -> (
    Arc<PairingManager>,
    Arc<TestDiscovery>,
    Arc<TestDirectLink>,
    Arc<TestTrust>,
    Arc<TestClock>,
    Arc<TestMaterial>,
    Arc<TestPairingStore>,
) {
    let discovery = Arc::new(TestDiscovery::default());
    let direct = Arc::new(TestDirectLink::default());
    let trust = Arc::new(TestTrust::default());
    let clock = Arc::new(TestClock::new(1_000));
    let material = Arc::new(TestMaterial::new(1));
    let store = Arc::new(TestPairingStore::default());
    let manager = Arc::new(PairingManager::new(
        context(role),
        discovery.clone(),
        direct.clone(),
        trust.clone(),
        material.clone(),
        Arc::new(TestSetupCode),
        clock.clone(),
        store.clone(),
    ));
    (manager, discovery, direct, trust, clock, material, store)
}

// Returns one bounded candidate with an optional setup code.
fn candidate(code: Option<String>, peer_address: &str) -> PairingCandidate {
    PairingCandidate::new(
        NodeIdentity::new(
            NodeId::parse(&"6".repeat(32)).expect("node"),
            MachineId::parse(&"7".repeat(32)).expect("machine"),
            InstallationId::parse(&"8".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Child AI").expect("display name"),
        NodeAddress::parse("child.local").expect("address"),
        vec![9; 128],
        UnixMilliseconds::new(900),
        b"fixture-signature".to_vec(),
        code,
        NodeAddress::parse(peer_address).expect("peer address"),
    )
    .expect("candidate")
}

// Opens one code invitation and returns its identity and presented setup code.
fn code_invitation(manager: &PairingManager, mode: PairingMode) -> (PairingInviteId, String) {
    static NEXT_OPEN_KEY: AtomicU64 = AtomicU64::new(1);
    let idempotency_key = format!("open:{}", NEXT_OPEN_KEY.fetch_add(1, Ordering::SeqCst));
    let mut opened = manager
        .open(
            &idempotency_key,
            PairingWindowRequest::new(mode, 180).expect("window request"),
        )
        .expect("open pairing");
    let invite_id = opened.value().invite_id().clone();
    let code = opened
        .value_mut()
        .setup_code_mut()
        .expect("setup code")
        .take()
        .expect("present code");
    assert!(opened
        .value_mut()
        .setup_code_mut()
        .expect("setup code owner")
        .take()
        .is_none());
    (invite_id, code)
}

// Completes LAN pairing immediately and removes its advertisement.
#[test]
fn manager_completes_lan_pairing_once() {
    let (manager, discovery, _, _, _, _, store) = manager(NodeRole::Main);
    let (invite_id, code) = code_invitation(&manager, PairingMode::Lan);
    let enrolled_candidate = candidate(Some(code), "192.168.1.20");
    assert_eq!(discovery.published.lock().expect("published").len(), 1);
    let challenge = manager
        .challenge(
            &invite_id,
            &NodeAddress::parse("192.168.1.20").expect("peer"),
        )
        .expect("challenge");
    assert_eq!(challenge.invite_id(), &invite_id);
    let paired = manager
        .enroll("enroll:lan", &invite_id, &enrolled_candidate)
        .expect("enroll");
    assert_eq!(paired.value().state(), PairingMembershipState::Active);
    assert!(paired.value().comparison_code().is_none());
    assert!(matches!(paired.event(), PairingEvent::ChildPaired { .. }));
    store
        .replace(
            paired.value().pairing_record().clone(),
            paired.value().expected_pairing_revision(),
        )
        .expect("commit pairing");
    manager.pairing_did_commit(&invite_id);
    assert_eq!(
        discovery
            .unpublished
            .lock()
            .expect("unpublished")
            .as_slice(),
        &[invite_id.as_str().to_string()]
    );
    let replayed = manager
        .enroll("enroll:lan", &invite_id, &enrolled_candidate)
        .expect("exact enrollment replay");
    assert_eq!(replayed.value().state(), PairingMembershipState::Active);
    assert_eq!(replayed.value().credentials(), paired.value().credentials());
    assert_eq!(
        replayed.value().pairing_record(),
        paired.value().pairing_record()
    );
    assert_eq!(
        manager
            .enroll(
                "enroll:wrong-code",
                &invite_id,
                &candidate(Some("00000000".to_string()), "192.168.1.20")
            )
            .expect_err("consumed invitation must fail"),
        PairingError::Consumed
    );
}

// Returns pending remote membership with a separate six-digit comparison code.
#[test]
fn manager_requires_remote_human_comparison() {
    let (manager, _, _, _, _, _, store) = manager(NodeRole::Main);
    let (invite_id, code) = code_invitation(&manager, PairingMode::Remote);
    let paired = manager
        .enroll(
            "enroll:remote",
            &invite_id,
            &candidate(Some(code), "203.0.113.8"),
        )
        .expect("remote enrollment");
    assert_eq!(
        paired.value().state(),
        PairingMembershipState::PendingApproval
    );
    assert_eq!(
        paired
            .value()
            .comparison_code()
            .expect("comparison code")
            .expose()
            .len(),
        6
    );
    assert_eq!(
        paired.value().approval_expires_at(),
        Some(UnixMilliseconds::new(181_000))
    );
    store
        .replace(
            paired.value().pairing_record().clone(),
            paired.value().expected_pairing_revision(),
        )
        .expect("persist pending pairing");
    let approved = manager
        .approve("approve:remote", &invite_id)
        .expect("approve pairing");
    assert_eq!(
        approved.value().enrollment().peer_credential().state(),
        PairingMembershipState::Active
    );
    let committed = store
        .replace(
            approved.value().pairing_record().clone(),
            approved.value().expected_pairing_revision(),
        )
        .expect("commit approval");
    let replayed = manager
        .approve("approve:remote", &invite_id)
        .expect("replay approval");
    assert_eq!(replayed.value().pairing_record(), committed.record());
    assert_eq!(
        replayed.value().expected_pairing_revision(),
        committed.revision()
    );
    assert_eq!(
        manager
            .approve("approve:remote:foreign", &invite_id)
            .expect_err("active pairing cannot be approved again"),
        PairingError::InvalidApproval
    );
}

// Binds ConnectX pairing to preapproved key identity, interface, and peer route.
#[test]
fn manager_enforces_connectx_identity_and_route_without_code() {
    let (manager, _, direct, _, _, _, store) = manager(NodeRole::Main);
    let public_key_fingerprint =
        Sha256Digest::parse(&format!("{:x}", Sha256::digest(vec![9; 128]))).expect("fingerprint");
    let mode = PairingMode::ConnectX {
        candidate_public_key: public_key_fingerprint,
        direct_interface: NetworkInterfaceName::parse("enp1s0").expect("interface"),
    };
    let opened = manager
        .open(
            "open:connectx",
            PairingWindowRequest::new(mode, 180).expect("window request"),
        )
        .expect("open pairing");
    let invite_id = opened.value().invite_id().clone();
    assert!(matches!(
        opened.value().mode(),
        PairingMode::ConnectX { .. }
    ));
    manager
        .challenge(
            &invite_id,
            &NodeAddress::parse("192.168.10.2").expect("peer"),
        )
        .expect("direct challenge");
    let paired = manager
        .enroll(
            "enroll:connectx",
            &invite_id,
            &candidate(None, "192.168.10.2"),
        )
        .expect("direct enrollment");
    assert_eq!(paired.value().state(), PairingMembershipState::Active);
    direct.should_fail.store(true, Ordering::SeqCst);
    assert_eq!(
        manager
            .enroll(
                "enroll:connectx:denied",
                &invite_id,
                &candidate(None, "192.168.10.2"),
            )
            .expect_err("direct-link denial must fail"),
        PairingError::Unauthorized
    );
    assert_eq!(
        store
            .pairing(&invite_id)
            .expect("stored invitation")
            .expect("invitation")
            .record()
            .attempts(),
        1
    );
}

// Exhausts one invitation after five incorrect setup-code attempts.
#[test]
fn manager_bounds_incorrect_code_attempts() {
    let (manager, _, _, _, _, _, _) = manager(NodeRole::Main);
    let (invite_id, _) = code_invitation(&manager, PairingMode::Lan);
    for _ in 0..4 {
        assert_eq!(
            manager
                .enroll(
                    "enroll:attempt-limit",
                    &invite_id,
                    &candidate(Some("99999999".to_string()), "192.168.1.20")
                )
                .expect_err("incorrect code must fail"),
            PairingError::Unauthorized
        );
    }
    assert_eq!(
        manager
            .enroll(
                "enroll:attempt-limit-terminal",
                &invite_id,
                &candidate(Some("99999999".to_string()), "192.168.1.20")
            )
            .expect_err("fifth attempt must close invitation"),
        PairingError::AttemptLimit
    );
    assert_eq!(
        manager
            .challenge(
                &invite_id,
                &NodeAddress::parse("192.168.1.20").expect("peer")
            )
            .expect_err("attempt limit must persist"),
        PairingError::AttemptLimit
    );
}

// Refuses and prunes an invitation at its exact exclusive expiry boundary.
#[test]
fn manager_rejects_and_prunes_invitation_at_exact_expiry() {
    let (manager, discovery, _, _, clock, _, _) = manager(NodeRole::Main);
    let (invite_id, code) = code_invitation(&manager, PairingMode::Lan);
    clock.set(181_000);
    assert_eq!(
        manager
            .enroll(
                "enroll:trust-failure",
                &invite_id,
                &candidate(Some(code), "192.168.1.20"),
            )
            .expect_err("expired invitation must fail"),
        PairingError::Expired
    );
    assert_eq!(
        manager.prune_inactive().expect("prune"),
        vec![invite_id.clone()]
    );
    assert_eq!(
        discovery
            .unpublished
            .lock()
            .expect("unpublished")
            .as_slice(),
        &[invite_id.as_str().to_string()]
    );
}

// Counts invalid proof as an authorization attempt without exposing trust details.
#[test]
fn manager_hides_candidate_proof_failure() {
    let (manager, _, _, trust, _, _, _) = manager(NodeRole::Main);
    let (invite_id, code) = code_invitation(&manager, PairingMode::Lan);
    trust.should_fail.store(true, Ordering::SeqCst);
    assert_eq!(
        manager
            .enroll(
                "enroll:store-failure",
                &invite_id,
                &candidate(Some(code), "192.168.1.20"),
            )
            .expect_err("proof must fail"),
        PairingError::Unauthorized
    );
}

// Rejects a durable invitation rebound to another main identity before any trust mutation.
#[test]
fn manager_rejects_persisted_main_identity_mismatch() {
    let (manager, _, _, _, _, _, store) = manager(NodeRole::Main);
    let (invite_id, code) = code_invitation(&manager, PairingMode::Lan);
    let current = store
        .pairing(&invite_id)
        .expect("store")
        .expect("invitation");
    let mismatched = PairingRecord::restore(
        NodeId::parse(&"f".repeat(32)).expect("foreign main"),
        current.record().invite_id().clone(),
        current.record().mode().clone(),
        current.record().nonce().clone(),
        current.record().open_replay().clone(),
        current.record().enrollment_replay().cloned(),
        current.record().approval_replay().cloned(),
        *current.record().setup_salt(),
        current.record().created_at(),
        current.record().expires_at(),
        current.record().attempts(),
        current.record().state(),
        None,
        None,
        None,
    )
    .expect("mismatched record");
    store
        .replace(mismatched, current.revision())
        .expect("replace record");
    assert_eq!(
        manager
            .enroll(
                "enroll:mismatched-main",
                &invite_id,
                &candidate(Some(code), "192.168.1.20"),
            )
            .expect_err("foreign authority"),
        PairingError::StoreCorrupt
    );
}

// Rejects child-owned and undiscoverable windows without retaining invitation state.
#[test]
fn manager_fails_before_opening_invalid_window() {
    let (child, _, _, _, _, _, _) = manager(NodeRole::Child);
    assert_eq!(
        child
            .open(
                "open:child",
                PairingWindowRequest::new(PairingMode::Lan, 180).expect("request"),
            )
            .expect_err("child invitation must fail"),
        PairingError::MainOnly
    );
    let (main, discovery, _, _, _, _, _) = manager(NodeRole::Main);
    discovery.should_fail.store(true, Ordering::SeqCst);
    assert_eq!(
        main.open(
            "open:discovery-failure",
            PairingWindowRequest::new(PairingMode::Lan, 180).expect("request"),
        )
        .expect_err("discovery failure must fail"),
        PairingError::DiscoveryUnavailable
    );
    discovery.should_fail.store(false, Ordering::SeqCst);
    main.open(
        "open:discovery-failure",
        PairingWindowRequest::new(PairingMode::Lan, 180).expect("request"),
    )
    .expect("retry after rolled-back publication");
}

// Fails clock, entropy, storage, and membership issuance without retaining partial state.
#[test]
fn manager_external_boundary_failures_are_deterministic_and_retryable() {
    let (manager, discovery, _, trust, clock, material, store) = manager(NodeRole::Main);
    let request = PairingWindowRequest::new(PairingMode::Lan, 180).expect("window request");

    clock.fail_next();
    assert_eq!(
        manager
            .open("open:clock-failure", request.clone())
            .expect_err("clock failure must fail"),
        PairingError::StateUnavailable
    );
    material.fail_next();
    assert_eq!(
        manager
            .open("open:entropy-failure", request.clone())
            .expect_err("entropy failure must fail"),
        PairingError::EntropyUnavailable
    );
    store.fail_next();
    assert_eq!(
        manager
            .open("open:store-failure", request)
            .expect_err("store failure must fail"),
        PairingError::StoreUnavailable
    );
    assert!(store.pairings(17).expect("empty store").is_empty());
    assert!(discovery.published.lock().expect("published").is_empty());

    let (invite_id, code) = code_invitation(&manager, PairingMode::Lan);
    trust.membership_should_fail.store(true, Ordering::SeqCst);
    let enrolled_candidate = candidate(Some(code), "192.168.1.20");
    assert_eq!(
        manager
            .enroll("enroll:membership-failure", &invite_id, &enrolled_candidate)
            .expect_err("membership issuance failure must fail"),
        PairingError::TrustUnavailable
    );
    let retained = store
        .pairing(&invite_id)
        .expect("store")
        .expect("open invitation");
    assert_eq!(
        retained.record().state(),
        li_pairing_manager::PairingRecordState::Open
    );
    assert_eq!(retained.record().attempts(), 0);
    assert!(manager
        .enroll("enroll:membership-failure", &invite_id, &enrolled_candidate)
        .is_ok());
}

// Bounds discoverable invitations without retaining the rejected seventeenth window.
#[test]
fn manager_enforces_the_sixteen_invitation_capacity() {
    let (manager, discovery, _, _, _, _, store) = manager(NodeRole::Main);
    let request = PairingWindowRequest::new(PairingMode::Lan, 180).expect("window request");

    for index in 0..16 {
        manager
            .open(&format!("open:capacity:{index}"), request.clone())
            .expect("bounded invitation");
    }
    assert_eq!(
        manager
            .open("open:capacity:overflow", request)
            .expect_err("seventeenth invitation must be rejected"),
        PairingError::StateUnavailable
    );
    assert_eq!(store.pairings(17).expect("stored invitations").len(), 16);
    assert_eq!(discovery.published.lock().expect("published").len(), 16);
}

// Reconstructs the exact open response and rejects semantic reuse of its idempotency identity.
#[test]
fn manager_replays_open_from_derivation_material_and_rejects_conflict() {
    let (manager, discovery, _, _, _, _, _) = manager(NodeRole::Main);
    let request = PairingWindowRequest::new(PairingMode::Lan, 180).expect("request");
    let mut first = manager
        .open("open:durable-replay", request.clone())
        .expect("first open");
    let first_code = first
        .value_mut()
        .setup_code_mut()
        .expect("first setup owner")
        .take()
        .expect("first setup code");
    let mut replayed = manager
        .open("open:durable-replay", request)
        .expect("replayed open");
    let replayed_code = replayed
        .value_mut()
        .setup_code_mut()
        .expect("replay setup owner")
        .take()
        .expect("replay setup code");

    assert_eq!(replayed.value().invite_id(), first.value().invite_id());
    assert_eq!(replayed.value().nonce(), first.value().nonce());
    assert_eq!(replayed.value().expires_at(), first.value().expires_at());
    assert_eq!(replayed_code, first_code);
    assert_eq!(discovery.published.lock().expect("published").len(), 1);
    assert_eq!(
        manager
            .open(
                "open:durable-replay",
                PairingWindowRequest::new(PairingMode::Lan, 181).expect("conflict request"),
            )
            .expect_err("semantic replay conflict"),
        PairingError::StoreConflict
    );
}

// Lets exactly one concurrent candidate consume a one-use invitation.
#[test]
fn manager_serializes_concurrent_enrollment() {
    let (manager, _, _, _, _, _, store) = manager(NodeRole::Main);
    let (invite_id, code) = code_invitation(&manager, PairingMode::Lan);
    let mut workers = Vec::new();
    for worker_index in 0..2 {
        let manager = Arc::clone(&manager);
        let store = Arc::clone(&store);
        let invite_id = invite_id.clone();
        let candidate = candidate(Some(code.clone()), "192.168.1.20");
        workers.push(thread::spawn(move || {
            let paired = manager.enroll(
                &format!("enroll:concurrent:{worker_index}"),
                &invite_id,
                &candidate,
            )?;
            store
                .replace(
                    paired.value().pairing_record().clone(),
                    paired.value().expected_pairing_revision(),
                )
                .map(|_| ())
        }));
    }
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("pairing worker"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
}

// Redacts code, proof, and key material from candidate debug output.
#[test]
fn candidate_debug_redacts_sensitive_pairing_material() {
    let candidate = candidate(Some("12345678".to_string()), "192.168.1.20");
    let debug = format!("{candidate:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("12345678"));
    assert!(!debug.contains("fixture-signature"));
}
