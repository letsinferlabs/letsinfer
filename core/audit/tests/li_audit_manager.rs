// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use li_audit_manager::{
    AuditAction, AuditActor, AuditActorId, AuditActorType, AuditAppendDisposition,
    AuditAppendReceipt, AuditAppendRequest, AuditCheckpoint, AuditCheckpointCryptography,
    AuditCheckpointPolicy, AuditClock, AuditCorrelationId, AuditError, AuditEvent, AuditEventId,
    AuditExportLimit, AuditIdentityProvider, AuditIntegrityError, AuditLedger, AuditLedgerEntry,
    AuditManager, AuditOrigin, AuditOriginInterface, AuditOutcome, AuditReason, AuditReplayId,
    AuditReplayReceipt, AuditStore, AuditStoreError, AuditTarget, AuditUnixNanoseconds,
    AUDIT_GENESIS_HASH,
};
use li_core_interface::{NodeId, Sha256Digest};
use sha2::{Digest, Sha256};

const AUDIT_EXPORT_SCHEMA: &str =
    include_str!("../../../schemas/audit/li_audit_export_v1.schema.json");

// Stores deterministic append-only state and injected failures for manager tests.
#[derive(Default)]
struct MemoryStore {
    state: Mutex<MemoryState>,
    append_calls: AtomicUsize,
    append_barrier: Mutex<Option<Arc<Barrier>>>,
    fail_append: AtomicBool,
}

// Stores the complete mock ledger and replay index under one atomic lock.
#[derive(Default)]
struct MemoryState {
    entries: Vec<AuditLedgerEntry>,
    revision: u64,
    replays: HashMap<String, (Sha256Digest, usize)>,
}

impl MemoryStore {
    // Fails the next store append before any mock state changes.
    fn fail_next_append(&self) {
        self.fail_append.store(true, Ordering::SeqCst);
    }

    // Synchronizes the first two append attempts to force one optimistic conflict.
    fn contest_next_two_appends(&self) {
        self.append_calls.store(0, Ordering::SeqCst);
        *self.append_barrier.lock().expect("append barrier") = Some(Arc::new(Barrier::new(2)));
    }

    // Replaces one entry to emulate owner-level persistence tampering.
    fn tamper(&self, index: usize, entry: AuditLedgerEntry) {
        self.state.lock().expect("memory store").entries[index] = entry;
    }

    // Returns the current mock entry count.
    fn count(&self) -> usize {
        self.state.lock().expect("memory store").entries.len()
    }
}

impl AuditStore for MemoryStore {
    // Returns one coherent cloned ledger snapshot.
    fn ledger(&self) -> Result<AuditLedger, AuditStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        AuditLedger::from_persisted(state.entries.clone(), state.revision)
    }

    // Returns one cloned first-commit replay receipt.
    fn replay(
        &self,
        replay_id: &AuditReplayId,
    ) -> Result<Option<AuditReplayReceipt>, AuditStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        Ok(state
            .replays
            .get(replay_id.as_str())
            .map(|(digest, index)| {
                AuditReplayReceipt::new(
                    digest.clone(),
                    state.entries[*index].clone(),
                    state.revision,
                )
            }))
    }

    // Returns one cloned event by identity.
    fn event(&self, event_id: &AuditEventId) -> Result<Option<AuditEvent>, AuditStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        Ok(state
            .entries
            .iter()
            .find(|entry| entry.event().event_id() == event_id)
            .map(|entry| entry.event().clone()))
    }

    // Commits one exact event and checkpoint together under optimistic revision control.
    fn append(
        &self,
        expected_revision: u64,
        replay_id: &AuditReplayId,
        request_sha256: &Sha256Digest,
        entry: AuditLedgerEntry,
    ) -> Result<AuditAppendReceipt, AuditStoreError> {
        let call = self.append_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call <= 2 {
            let barrier = self
                .append_barrier
                .lock()
                .map_err(|_| AuditStoreError::Unavailable)?
                .clone();
            if let Some(barrier) = barrier {
                barrier.wait();
            }
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        if let Some((stored_digest, index)) = state.replays.get(replay_id.as_str()).cloned() {
            if stored_digest != *request_sha256 {
                return Err(AuditStoreError::ReplayConflict);
            }
            return Ok(AuditAppendReceipt::new(
                stored_digest,
                state.entries[index].clone(),
                AuditAppendDisposition::Replayed,
                state.revision,
            ));
        }
        if state.revision != expected_revision {
            return Err(AuditStoreError::Conflict);
        }
        if self.fail_append.swap(false, Ordering::SeqCst) {
            return Err(AuditStoreError::Unavailable);
        }
        let expected_sequence = state.entries.len() as u64 + 1;
        if entry.event().sequence() != expected_sequence {
            return Err(AuditStoreError::Corrupt);
        }
        let index = state.entries.len();
        state.entries.push(entry.clone());
        state.replays.insert(
            replay_id.as_str().to_string(),
            (request_sha256.clone(), index),
        );
        state.revision += 1;
        Ok(AuditAppendReceipt::new(
            request_sha256.clone(),
            entry,
            AuditAppendDisposition::Applied,
            state.revision,
        ))
    }
}

// Supplies monotonically increasing deterministic timestamps.
struct ClockMock {
    next: AtomicU64,
    calls: AtomicUsize,
    fail: AtomicBool,
}

impl ClockMock {
    // Creates one clock whose first value is exact and subsequent values increment once.
    fn new(first: u64) -> Self {
        Self {
            next: AtomicU64::new(first),
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        }
    }

    // Fails the next timestamp observation before returning any time value.
    fn fail_next(&self) {
        self.fail.store(true, Ordering::SeqCst);
    }
}

impl AuditClock for ClockMock {
    // Returns one deterministic timestamp.
    fn now(&self) -> Result<AuditUnixNanoseconds, AuditError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(AuditError::provider("clock", "mock clock failure"));
        }
        AuditUnixNanoseconds::new(self.next.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies sequential deterministic event identities.
#[derive(Default)]
struct IdentityMock {
    next: AtomicUsize,
    fail: AtomicBool,
}

impl IdentityMock {
    // Fails the next identity allocation before returning any event identity.
    fn fail_next(&self) {
        self.fail.store(true, Ordering::SeqCst);
    }
}

impl AuditIdentityProvider for IdentityMock {
    // Returns the next lowercase 128-bit test identity.
    fn event_id(&self) -> Result<AuditEventId, AuditError> {
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(AuditError::provider("identity", "mock identity failure"));
        }
        let value = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        AuditEventId::parse(&format!("{value:032x}"))
    }
}

// Signs checkpoints with a deterministic keyed digest and supports exact boundary failures.
#[derive(Default)]
struct CryptographyMock {
    fail_sign: AtomicBool,
    fail_verify: AtomicBool,
    sign_calls: AtomicUsize,
    verify_calls: AtomicUsize,
}

impl CryptographyMock {
    // Fails the next signing operation before producing bytes.
    fn fail_next_sign(&self) {
        self.fail_sign.store(true, Ordering::SeqCst);
    }

    // Fails the next verification operation at the provider boundary.
    fn fail_next_verify(&self) {
        self.fail_verify.store(true, Ordering::SeqCst);
    }

    // Returns one deterministic signature for exact test material.
    fn signature(value: &[u8]) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(b"li_audit_test_signing_key\0");
        digest.update(value);
        digest.finalize().to_vec()
    }
}

impl AuditCheckpointCryptography for CryptographyMock {
    // Produces one deterministic signature unless failure is scheduled.
    fn sign(&self, event_hash: &[u8]) -> Result<Vec<u8>, AuditError> {
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_sign.swap(false, Ordering::SeqCst) {
            return Err(AuditError::provider("signing", "mock signing failure"));
        }
        Ok(Self::signature(event_hash))
    }

    // Verifies one deterministic signature unless provider failure is scheduled.
    fn verify(&self, event_hash: &[u8], signature: &[u8]) -> Result<bool, AuditError> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_verify.swap(false, Ordering::SeqCst) {
            return Err(AuditError::provider(
                "verification",
                "mock verification failure",
            ));
        }
        Ok(Self::signature(event_hash) == signature)
    }
}

// Owns one complete deterministic manager fixture.
struct Fixture {
    manager: Arc<AuditManager>,
    store: Arc<MemoryStore>,
    clock: Arc<ClockMock>,
    identities: Arc<IdentityMock>,
    cryptography: Arc<CryptographyMock>,
    node_id: NodeId,
}

// Creates one fixture with an explicit checkpoint interval.
fn fixture(interval: u64) -> Fixture {
    let store = Arc::new(MemoryStore::default());
    let clock = Arc::new(ClockMock::new(1_000_000));
    let identities = Arc::new(IdentityMock::default());
    let cryptography = Arc::new(CryptographyMock::default());
    let node_id = NodeId::parse(&"a".repeat(32)).expect("node identity");
    let manager = Arc::new(AuditManager::new(
        node_id.clone(),
        store.clone(),
        clock.clone(),
        identities.clone(),
        cryptography.clone(),
        AuditCheckpointPolicy::new(interval).expect("checkpoint policy"),
    ));
    Fixture {
        manager,
        store,
        clock,
        identities,
        cryptography,
        node_id,
    }
}

// Creates one ordinary action request with stable deterministic content.
fn request(replay: &str) -> AuditAppendRequest {
    AuditAppendRequest::new(
        AuditReplayId::parse(replay).expect("replay identity"),
        AuditCorrelationId::parse(&"b".repeat(32)).expect("correlation identity"),
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse("alice").expect("actor identity"),
        ),
        AuditOrigin::new(
            NodeId::parse(&"a".repeat(32)).expect("origin node"),
            AuditOriginInterface::Cli,
        ),
        AuditAction::parse("node.setup").expect("action"),
        AuditTarget::parse(&format!("node/{}", "a".repeat(32))).expect("target"),
        None,
        Some(Sha256Digest::parse(&"d".repeat(64)).expect("after digest")),
        AuditOutcome::Success,
        None,
    )
    .expect("append request")
}

// Creates one denied or failed action with a required bounded reason code.
fn unsuccessful_request(replay: &str, outcome: AuditOutcome) -> AuditAppendRequest {
    AuditAppendRequest::new(
        AuditReplayId::parse(replay).expect("replay identity"),
        AuditCorrelationId::parse(&"c".repeat(32)).expect("correlation identity"),
        AuditActor::new(
            AuditActorType::Controller,
            AuditActorId::parse(&"e".repeat(32)).expect("actor identity"),
        ),
        AuditOrigin::new(
            NodeId::parse(&"a".repeat(32)).expect("origin node"),
            AuditOriginInterface::Controller,
        ),
        AuditAction::parse("auth.key.update").expect("action"),
        AuditTarget::parse(&"f".repeat(32)).expect("target"),
        None,
        None,
        outcome,
        Some(AuditReason::parse("permission_denied").expect("reason")),
    )
    .expect("unsuccessful request")
}

// Reconstructs one event with selected persisted chain fields for tamper scenarios.
fn persisted_event(
    event: &AuditEvent,
    target: AuditTarget,
    previous_hash: Sha256Digest,
    event_hash: Sha256Digest,
) -> AuditEvent {
    AuditEvent::from_persisted(
        event.sequence(),
        event.event_id().clone(),
        event.correlation_id().clone(),
        event.timestamp(),
        event.node_id().clone(),
        event.actor().clone(),
        event.origin().clone(),
        event.action().clone(),
        target,
        event.before_sha256().cloned(),
        event.after_sha256().cloned(),
        event.outcome(),
        event.reason().cloned(),
        previous_hash,
        event_hash,
    )
    .expect("persisted event")
}

// Reports whether one checked-in closed object schema accepts its required shallow shape.
fn closed_schema_object_accepts(schema: &serde_json::Value, document: &serde_json::Value) -> bool {
    let Some(properties) = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    let Some(required) = schema.get("required").and_then(serde_json::Value::as_array) else {
        return false;
    };
    let Some(document) = document.as_object() else {
        return false;
    };
    schema.get("additionalProperties") == Some(&serde_json::Value::Bool(false))
        && required.iter().all(|name| {
            name.as_str()
                .is_some_and(|name| document.contains_key(name))
        })
        && document.iter().all(|(name, value)| {
            properties
                .get(name)
                .is_some_and(|property| shallow_schema_value_accepts(property, value))
        })
}

// Applies the direct const, enum, and primitive-type constraints used by shape mutations.
fn shallow_schema_value_accepts(schema: &serde_json::Value, value: &serde_json::Value) -> bool {
    if schema
        .get("const")
        .is_some_and(|expected| expected != value)
    {
        return false;
    }
    if schema
        .get("enum")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| !values.contains(value))
    {
        return false;
    }
    match schema.get("type").and_then(serde_json::Value::as_str) {
        Some("array") => value.is_array(),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.is_i64() || value.is_u64(),
        Some("null") => value.is_null(),
        Some("object") => value.is_object(),
        Some("string") => value.is_string(),
        Some(_) => false,
        None => true,
    }
}

// Proves ordinary append, exact hashing, read paths, verification, and complete export.
#[test]
fn appends_and_reads_one_production_shaped_chain() {
    let fixture = fixture(100);
    let appended = fixture
        .manager
        .append(request("ordinary-1"))
        .expect("append");
    assert_eq!(appended.disposition(), AuditAppendDisposition::Applied);
    assert_eq!(appended.entry().event().sequence(), 1);
    assert_eq!(
        appended.entry().event().event_hash().as_str(),
        "92ca799fd0cba34e2dec4eeebe7a5afd3fade02f41d812006f9ff710e343c8f7"
    );
    assert_eq!(
        fixture.manager.list(100).expect("list"),
        vec![appended.entry().event().clone()]
    );
    assert_eq!(
        fixture
            .manager
            .show(appended.entry().event().event_id())
            .expect("show"),
        *appended.entry().event()
    );
    let verification = fixture.manager.verify().expect("verify");
    assert_eq!(verification.events(), 1);
    assert_eq!(verification.checkpoints(), 0);
    let export = fixture
        .manager
        .export(AuditExportLimit::maximum())
        .expect("export");
    let document: serde_json::Value = serde_json::from_slice(export.bytes()).expect("export JSON");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["events"].as_array().expect("events").len(), 1);
    assert_eq!(document["verification"]["valid"], true);
}

// Binds the public export producer to one closed checked-in schema and its rejection surface.
#[test]
fn checked_in_export_schema_matches_the_producer_and_closes_mutations() {
    let schema: serde_json::Value =
        serde_json::from_str(AUDIT_EXPORT_SCHEMA).expect("audit export schema");
    assert_eq!(
        schema["$id"],
        "https://letsinfer.ai/schemas/audit/li_audit_export_v1.schema.json"
    );
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(schema["properties"]["events"]["maxItems"], 10_000);
    assert_eq!(schema["properties"]["checkpoints"]["maxItems"], 10_000);
    assert_eq!(
        schema["$defs"]["node_identity"]["pattern"],
        "^[0-9a-f]{32}$"
    );
    assert_eq!(schema["$defs"]["sha256"]["pattern"], "^[0-9a-f]{64}$");
    assert_eq!(
        schema["$defs"]["checkpoint"]["properties"]["signature_base64"]["maxLength"],
        5_464
    );

    let fixture = fixture(1);
    fixture
        .manager
        .append(request("schema-export"))
        .expect("schema export event");
    let export = fixture
        .manager
        .export(AuditExportLimit::maximum())
        .expect("schema export");
    let document: serde_json::Value =
        serde_json::from_slice(export.bytes()).expect("schema export JSON");
    let event = document["events"][0].clone();
    let checkpoint = document["checkpoints"][0].clone();
    let verification = document["verification"].clone();
    assert!(closed_schema_object_accepts(&schema, &document));
    assert!(closed_schema_object_accepts(
        &schema["$defs"]["event"],
        &event
    ));
    assert!(closed_schema_object_accepts(
        &schema["$defs"]["checkpoint"],
        &checkpoint
    ));
    assert!(closed_schema_object_accepts(
        &schema["$defs"]["verification"],
        &verification
    ));

    let mut mutations = Vec::new();
    let mut changed = document.clone();
    changed
        .as_object_mut()
        .expect("export object")
        .insert("unknown".to_string(), serde_json::Value::Bool(true));
    mutations.push(("unknown export field", schema.clone(), changed));
    let mut changed = document.clone();
    changed
        .as_object_mut()
        .expect("export object")
        .remove("events");
    mutations.push(("missing export field", schema.clone(), changed));
    let mut changed = document.clone();
    changed["schema_version"] = serde_json::Value::from(2);
    mutations.push(("unsupported export version", schema.clone(), changed));

    let event_schema = schema["$defs"]["event"].clone();
    let mut changed = event.clone();
    changed
        .as_object_mut()
        .expect("event object")
        .remove("event_hash");
    mutations.push(("missing event field", event_schema.clone(), changed));
    let mut changed = event.clone();
    changed["actor_type"] = serde_json::Value::from("foreign");
    mutations.push(("foreign actor type", event_schema.clone(), changed));
    let mut changed = event;
    changed["outcome"] = serde_json::Value::from("unknown");
    mutations.push(("foreign outcome", event_schema, changed));

    let checkpoint_schema = schema["$defs"]["checkpoint"].clone();
    let mut changed = checkpoint.clone();
    changed
        .as_object_mut()
        .expect("checkpoint object")
        .remove("signature_base64");
    mutations.push((
        "missing checkpoint field",
        checkpoint_schema.clone(),
        changed,
    ));
    let mut changed = checkpoint;
    changed["signature_base64"] = serde_json::Value::from(7);
    mutations.push((
        "invalid checkpoint signature type",
        checkpoint_schema,
        changed,
    ));

    let verification_schema = schema["$defs"]["verification"].clone();
    let mut changed = verification.clone();
    changed["valid"] = serde_json::Value::Bool(false);
    mutations.push(("unverified export", verification_schema.clone(), changed));
    let mut changed = verification;
    changed
        .as_object_mut()
        .expect("verification object")
        .insert("unknown".to_string(), serde_json::Value::Bool(true));
    mutations.push(("unknown verification field", verification_schema, changed));

    for (name, mutation_schema, mutation) in mutations {
        assert!(
            !closed_schema_object_accepts(&mutation_schema, &mutation),
            "schema accepted {name}"
        );
    }
}

// Proves denied and failed records while excluding content and secret-shaped values at construction.
#[test]
fn records_unsuccessful_outcomes_without_free_form_content() {
    let fixture = fixture(100);
    let denied = fixture
        .manager
        .append(unsuccessful_request("denied-1", AuditOutcome::Denied))
        .expect("denied append");
    let failed = fixture
        .manager
        .append(unsuccessful_request("failed-1", AuditOutcome::Failed))
        .expect("failed append");
    assert_eq!(denied.entry().event().outcome(), AuditOutcome::Denied);
    assert_eq!(failed.entry().event().outcome(), AuditOutcome::Failed);
    assert_eq!(
        failed.entry().event().reason().expect("reason").as_str(),
        "permission_denied"
    );
    assert!(AuditReason::parse("response body\nsecret").is_err());
    assert!(AuditTarget::parse("Bearer-secret-token").is_err());
    assert!(AuditActorId::parse(&["-----BEGIN ", "PRIVATE KEY-----"].concat()).is_err());
    assert!(AuditReplayId::parse(&"x".repeat(129)).is_err());
    assert!(AuditAppendRequest::new(
        request("invalid-reason").replay_id().clone(),
        request("invalid-reason").correlation_id().clone(),
        request("invalid-reason").actor().clone(),
        request("invalid-reason").origin().clone(),
        request("invalid-reason").action().clone(),
        request("invalid-reason").target().clone(),
        None,
        None,
        AuditOutcome::Denied,
        None,
    )
    .is_err());
}

// Proves periodic signing and complete signature verification over exact event-hash text.
#[test]
fn signs_and_verifies_periodic_checkpoints() {
    let fixture = fixture(2);
    fixture
        .manager
        .append(request("checkpoint-1"))
        .expect("first");
    let second = fixture
        .manager
        .append(request("checkpoint-2"))
        .expect("second");
    let checkpoint = second.entry().checkpoint().expect("checkpoint");
    assert_eq!(checkpoint.sequence(), 2);
    assert_eq!(
        checkpoint.signature(),
        CryptographyMock::signature(checkpoint.event_hash().as_str().as_bytes())
    );
    let verification = fixture.manager.verify().expect("verify");
    assert_eq!(verification.events(), 2);
    assert_eq!(verification.checkpoints(), 1);
    assert!(fixture.cryptography.sign_calls.load(Ordering::SeqCst) >= 1);
    assert!(fixture.cryptography.verify_calls.load(Ordering::SeqCst) >= 1);
    fixture.cryptography.fail_next_verify();
    assert!(matches!(
        fixture.manager.verify(),
        Err(AuditError::Provider {
            capability: "verification",
            ..
        })
    ));
}

// Proves restart replay returns the first commit and rejects a changed action intent.
#[test]
fn replays_idempotently_across_manager_restart() {
    let fixture = fixture(100);
    let first_request = request("restart-1");
    let first = fixture
        .manager
        .append(first_request.clone())
        .expect("first append");
    let restarted = AuditManager::new(
        fixture.node_id.clone(),
        fixture.store.clone(),
        fixture.clock.clone(),
        fixture.identities.clone(),
        fixture.cryptography.clone(),
        AuditCheckpointPolicy::new(100).expect("policy"),
    );
    let replay = restarted.append(first_request).expect("replay");
    assert_eq!(replay.disposition(), AuditAppendDisposition::Replayed);
    assert_eq!(replay.entry(), first.entry());
    assert_eq!(fixture.store.count(), 1);
    let changed = AuditAppendRequest::new(
        AuditReplayId::parse("restart-1").expect("replay identity"),
        AuditCorrelationId::parse(&"b".repeat(32)).expect("correlation"),
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse("alice").expect("actor"),
        ),
        AuditOrigin::new(fixture.node_id.clone(), AuditOriginInterface::Cli),
        AuditAction::parse("node.remove").expect("action"),
        AuditTarget::parse(&format!("node/{}", "a".repeat(32))).expect("target"),
        None,
        Some(Sha256Digest::parse(&"d".repeat(64)).expect("digest")),
        AuditOutcome::Success,
        None,
    )
    .expect("changed request");
    assert_eq!(
        restarted.append(changed),
        Err(AuditError::IdempotencyConflict)
    );
}

// Proves two writers produce one optimistic winner followed by one bounded retry.
#[test]
fn resolves_concurrent_append_with_one_winner_and_retry() {
    let fixture = fixture(100);
    fixture.store.contest_next_two_appends();
    let first_manager = fixture.manager.clone();
    let second_manager = fixture.manager.clone();
    let first = thread::spawn(move || first_manager.append(request("concurrent-1")));
    let second = thread::spawn(move || second_manager.append(request("concurrent-2")));
    let first = first.join().expect("first writer").expect("first append");
    let second = second
        .join()
        .expect("second writer")
        .expect("second append");
    assert_ne!(
        first.entry().event().sequence(),
        second.entry().event().sequence()
    );
    let verification = fixture.manager.verify().expect("verify");
    assert_eq!(verification.events(), 2);
    assert_eq!(fixture.store.count(), 2);
    assert!(fixture.store.append_calls.load(Ordering::SeqCst) >= 3);
}

// Proves event content, previous-link, and checkpoint tampering fail at their exact boundaries.
#[test]
fn rejects_tampered_event_previous_hash_and_checkpoint() {
    let target_fixture = fixture(2);
    target_fixture
        .manager
        .append(request("tamper-target-1"))
        .expect("first");
    target_fixture
        .manager
        .append(request("tamper-target-2"))
        .expect("second");
    let ledger = target_fixture.store.ledger().expect("ledger");
    let first = ledger.entries()[0].event();
    let changed = persisted_event(
        first,
        AuditTarget::parse("node/changed").expect("changed target"),
        first.previous_hash().clone(),
        first.event_hash().clone(),
    );
    target_fixture
        .store
        .tamper(0, AuditLedgerEntry::new(changed, None).expect("entry"));
    assert!(matches!(
        target_fixture.manager.verify(),
        Err(AuditError::Integrity(AuditIntegrityError::EventHash {
            sequence: 1
        }))
    ));

    let previous_fixture = fixture(2);
    previous_fixture
        .manager
        .append(request("tamper-previous-1"))
        .expect("first");
    previous_fixture
        .manager
        .append(request("tamper-previous-2"))
        .expect("second");
    let ledger = previous_fixture.store.ledger().expect("ledger");
    let second_entry = &ledger.entries()[1];
    let second = second_entry.event();
    let changed = persisted_event(
        second,
        second.target().clone(),
        Sha256Digest::parse(&"f".repeat(64)).expect("tampered previous"),
        second.event_hash().clone(),
    );
    previous_fixture.store.tamper(
        1,
        AuditLedgerEntry::new(changed, second_entry.checkpoint().cloned()).expect("entry"),
    );
    assert!(matches!(
        previous_fixture.manager.verify(),
        Err(AuditError::Integrity(AuditIntegrityError::PreviousHash {
            sequence: 2
        }))
    ));

    let checkpoint_fixture = fixture(2);
    checkpoint_fixture
        .manager
        .append(request("tamper-checkpoint-1"))
        .expect("first");
    checkpoint_fixture
        .manager
        .append(request("tamper-checkpoint-2"))
        .expect("second");
    let ledger = checkpoint_fixture.store.ledger().expect("ledger");
    let second = ledger.entries()[1].event().clone();
    let checkpoint = AuditCheckpoint::from_persisted(
        2,
        second.event_hash().clone(),
        vec![0_u8; 32],
        AuditUnixNanoseconds::new(second.timestamp().value() + 1).expect("checkpoint time"),
    )
    .expect("checkpoint");
    checkpoint_fixture.store.tamper(
        1,
        AuditLedgerEntry::new(second, Some(checkpoint)).expect("entry"),
    );
    assert!(matches!(
        checkpoint_fixture.manager.verify(),
        Err(AuditError::Integrity(
            AuditIntegrityError::CheckpointSignature { sequence: 2 }
        ))
    ));
}

// Proves checkpoint signing and atomic-store failures leave no event or partial checkpoint.
#[test]
fn preserves_atomicity_when_signing_or_storage_fails() {
    let fixture = fixture(2);
    fixture.manager.append(request("atomic-1")).expect("first");
    fixture.cryptography.fail_next_sign();
    assert!(matches!(
        fixture.manager.append(request("atomic-signing")),
        Err(AuditError::Provider {
            capability: "signing",
            ..
        })
    ));
    assert_eq!(fixture.store.count(), 1);
    assert_eq!(fixture.manager.verify().expect("verify").checkpoints(), 0);
    fixture.store.fail_next_append();
    assert_eq!(
        fixture.manager.append(request("atomic-store")),
        Err(AuditError::Store(AuditStoreError::Unavailable))
    );
    assert_eq!(fixture.store.count(), 1);
    assert_eq!(fixture.manager.verify().expect("verify").checkpoints(), 0);
}

// Proves identity and clock provider failures leave no event or replay state behind.
#[test]
fn preserves_atomicity_when_identity_or_clock_fails() {
    let fixture = fixture(2);
    fixture.identities.fail_next();
    assert!(matches!(
        fixture.manager.append(request("atomic-identity")),
        Err(AuditError::Provider {
            capability: "identity",
            ..
        })
    ));
    assert_eq!(fixture.store.count(), 0);

    fixture.clock.fail_next();
    assert!(matches!(
        fixture.manager.append(request("atomic-clock")),
        Err(AuditError::Provider {
            capability: "clock",
            ..
        })
    ));
    assert_eq!(fixture.store.count(), 0);

    assert_eq!(
        fixture
            .manager
            .append(request("atomic-recovery"))
            .expect("append after provider recovery")
            .entry()
            .event()
            .sequence(),
        1
    );
}

// Proves export is complete or fails closed at explicit event and byte bounds.
#[test]
fn enforces_complete_export_bounds_without_truncation() {
    let fixture = fixture(100);
    for index in 0..3 {
        fixture
            .manager
            .append(request(&format!("export-{index}")))
            .expect("append");
    }
    assert_eq!(
        fixture
            .manager
            .export(AuditExportLimit::new(2, 16 * 1024 * 1024).expect("event limit")),
        Err(AuditError::ExportLimitExceeded)
    );
    assert_eq!(
        fixture
            .manager
            .export(AuditExportLimit::new(3, 64).expect("byte limit")),
        Err(AuditError::ExportLimitExceeded)
    );
    let export = fixture
        .manager
        .export(AuditExportLimit::new(3, 64 * 1024).expect("export limit"))
        .expect("bounded export");
    assert_eq!(export.events(), 3);
    let document: serde_json::Value = serde_json::from_slice(export.bytes()).expect("export JSON");
    assert_eq!(document["events"].as_array().expect("events").len(), 3);
    assert!(document.get("prompts").is_none());
    assert!(document.get("responses").is_none());
    assert_eq!(document["events"][0]["previous_hash"], AUDIT_GENESIS_HASH);
}
