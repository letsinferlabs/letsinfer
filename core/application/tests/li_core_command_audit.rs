// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use li_audit_manager::{
    AuditActor, AuditActorId, AuditActorType, AuditAppendDisposition, AuditAppendReceipt,
    AuditCheckpointCryptography, AuditCheckpointPolicy, AuditClock, AuditCorrelationId, AuditError,
    AuditEvent, AuditEventId, AuditIdentityProvider, AuditLedger, AuditLedgerEntry, AuditManager,
    AuditOrigin, AuditOriginInterface, AuditReplayId, AuditReplayReceipt, AuditStore,
    AuditStoreError, AuditUnixNanoseconds,
};
use li_core_application::{
    CoreCommandAuditConfigurationError, CoreCommandAuditIdentity, CoreCommandAuditIdentityProvider,
    CoreCommandAuditPort,
};
use li_core_cli::{
    ActionId, AuditPolicy, CommandAuditError, CommandAuditIntent, CommandAuditOutcome,
    CommandAuditPort, CommandAuditResult, CommandAuditTarget, CommandAuditTargetKind,
    CommandContext, LocalRole, MutationClass,
};
use li_core_interface::{NodeId, Sha256Digest};

// Stores one optimistic in-memory audit ledger and replay index for composition tests.
#[derive(Default)]
struct AuditStoreMock {
    entries: Mutex<Vec<AuditLedgerEntry>>,
    replays: Mutex<BTreeMap<String, AuditReplayReceipt>>,
    fail_append: AtomicBool,
}

impl AuditStore for AuditStoreMock {
    // Returns one complete chronological ledger clone.
    fn ledger(&self) -> Result<AuditLedger, AuditStoreError> {
        let entries = self.entries.lock().expect("entries").clone();
        AuditLedger::from_persisted(entries.clone(), entries.len() as u64)
    }

    // Returns one exact prior replay receipt.
    fn replay(
        &self,
        replay_id: &AuditReplayId,
    ) -> Result<Option<AuditReplayReceipt>, AuditStoreError> {
        Ok(self
            .replays
            .lock()
            .expect("replays")
            .get(replay_id.as_str())
            .cloned())
    }

    // Returns one event by its exact stable identity.
    fn event(&self, event_id: &AuditEventId) -> Result<Option<AuditEvent>, AuditStoreError> {
        Ok(self
            .entries
            .lock()
            .expect("entries")
            .iter()
            .find(|entry| entry.event().event_id() == event_id)
            .map(|entry| entry.event().clone()))
    }

    // Appends one entry under exact revision and creates its replay receipt atomically.
    fn append(
        &self,
        expected_revision: u64,
        replay_id: &AuditReplayId,
        request_sha256: &Sha256Digest,
        entry: AuditLedgerEntry,
    ) -> Result<AuditAppendReceipt, AuditStoreError> {
        if self.fail_append.swap(false, Ordering::SeqCst) {
            return Err(AuditStoreError::Unavailable);
        }
        let mut entries = self.entries.lock().expect("entries");
        if entries.len() as u64 != expected_revision {
            return Err(AuditStoreError::Conflict);
        }
        if self
            .replays
            .lock()
            .expect("replays")
            .contains_key(replay_id.as_str())
        {
            return Err(AuditStoreError::ReplayConflict);
        }
        entries.push(entry.clone());
        let revision = entries.len() as u64;
        self.replays.lock().expect("replays").insert(
            replay_id.as_str().to_string(),
            AuditReplayReceipt::new(request_sha256.clone(), entry.clone(), revision),
        );
        Ok(AuditAppendReceipt::new(
            request_sha256.clone(),
            entry,
            AuditAppendDisposition::Applied,
            revision,
        ))
    }
}

// Supplies increasing deterministic timestamps.
struct AuditClockMock(AtomicU64);

impl AuditClock for AuditClockMock {
    // Returns the next positive timestamp.
    fn now(&self) -> Result<AuditUnixNanoseconds, AuditError> {
        AuditUnixNanoseconds::new(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies increasing deterministic event identities.
struct AuditEventIdentityMock(AtomicU64);

impl AuditIdentityProvider for AuditEventIdentityMock {
    // Returns one unique lowercase 128-bit event identity.
    fn event_id(&self) -> Result<AuditEventId, AuditError> {
        AuditEventId::parse(&format!("{:032x}", self.0.fetch_add(1, Ordering::SeqCst)))
    }
}

// Provides deterministic checkpoint signatures for an interval these tests do not reach.
struct AuditCryptographyMock;

impl AuditCheckpointCryptography for AuditCryptographyMock {
    // Copies the event hash as one deterministic signature.
    fn sign(&self, event_hash: &[u8]) -> Result<Vec<u8>, AuditError> {
        Ok(event_hash.to_vec())
    }

    // Requires the deterministic signature to equal its event hash.
    fn verify(&self, event_hash: &[u8], signature: &[u8]) -> Result<bool, AuditError> {
        Ok(event_hash == signature)
    }
}

// Supplies deterministic command marker identities and can intentionally replay one marker.
struct CommandIdentityMock {
    next: AtomicU64,
    repeat_first: AtomicBool,
}

impl CommandIdentityMock {
    // Creates one ordinary unique marker source.
    fn unique() -> Self {
        Self {
            next: AtomicU64::new(1),
            repeat_first: AtomicBool::new(false),
        }
    }

    // Creates one source that returns the same first marker for every call.
    fn repeating() -> Self {
        Self {
            next: AtomicU64::new(1),
            repeat_first: AtomicBool::new(true),
        }
    }
}

impl CoreCommandAuditIdentityProvider for CommandIdentityMock {
    // Returns one action-bound deterministic identity set.
    fn identity(&self, action: ActionId) -> Result<CoreCommandAuditIdentity, CommandAuditError> {
        let value = if self.repeat_first.load(Ordering::SeqCst) {
            1
        } else {
            self.next.fetch_add(1, Ordering::SeqCst)
        };
        let nonce = format!("{value:032x}");
        CoreCommandAuditIdentity::new(
            action,
            &format!("li_cli_audit_{nonce}"),
            AuditCorrelationId::parse(&nonce).expect("correlation"),
            AuditReplayId::parse(&format!("li_cli_{}_{nonce}", action.as_str())).expect("replay"),
        )
        .map_err(|_| CommandAuditError::new("fixture.identity", "fixture identity failed"))
    }
}

// Groups the audit port with its observable manager and persistence mock.
struct TestEnvironment {
    port: CoreCommandAuditPort,
    manager: Arc<AuditManager>,
    store: Arc<AuditStoreMock>,
}

// Creates one deterministic application audit composition.
fn environment(identities: Arc<dyn CoreCommandAuditIdentityProvider>) -> TestEnvironment {
    let node_id = NodeId::parse(&"1".repeat(32)).expect("node");
    let store = Arc::new(AuditStoreMock::default());
    let manager = Arc::new(AuditManager::new(
        node_id.clone(),
        store.clone(),
        Arc::new(AuditClockMock(AtomicU64::new(1_000))),
        Arc::new(AuditEventIdentityMock(AtomicU64::new(1))),
        Arc::new(AuditCryptographyMock),
        AuditCheckpointPolicy::production(),
    ));
    let port = CoreCommandAuditPort::new(
        manager.clone(),
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse("local-user-501").expect("actor"),
        ),
        AuditOrigin::new(node_id, AuditOriginInterface::Cli),
        identities,
    )
    .expect("port");
    TestEnvironment {
        port,
        manager,
        store,
    }
}

// Creates one exact command intent for an explicit audit policy.
fn intent(action: ActionId, policy: AuditPolicy) -> CommandAuditIntent {
    CommandAuditIntent::new(
        action,
        policy,
        MutationClass::Node,
        CommandContext::configured(LocalRole::Main),
    )
}

// Opens and durably completes one successful audited command.
#[test]
fn successful_command_records_one_exact_terminal_event() {
    let mut environment = environment(Arc::new(CommandIdentityMock::unique()));
    let marker = environment
        .port
        .will_execute(
            intent(ActionId::ModelInstall, AuditPolicy::Always).with_target(
                CommandAuditTarget::new(CommandAuditTargetKind::Model, "sha256-target")
                    .expect("target"),
            ),
        )
        .expect("open")
        .expect("marker");
    assert_eq!(environment.port.pending_count(), 1);

    environment
        .port
        .did_execute(
            &marker,
            CommandAuditResult::new(ActionId::ModelInstall, CommandAuditOutcome::Succeeded, None),
        )
        .expect("complete");

    assert_eq!(environment.port.pending_count(), 0);
    let events = environment.manager.list(10).expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action().as_str(), "model.install");
    assert_eq!(events[0].target().as_str(), "model:sha256-target");
    assert_eq!(events[0].outcome().as_str(), "success");
    assert!(events[0].reason().is_none());
}

// Applies Success and Always policy semantics without fabricating failed success-only events.
#[test]
fn audit_policy_selects_the_terminal_outcomes_it_owns() {
    let mut environment = environment(Arc::new(CommandIdentityMock::unique()));
    let success_only = environment
        .port
        .will_execute(intent(ActionId::UpdateCheck, AuditPolicy::Success))
        .expect("open")
        .expect("marker");
    environment
        .port
        .did_execute(
            &success_only,
            CommandAuditResult::new(
                ActionId::UpdateCheck,
                CommandAuditOutcome::Failed,
                Some("network_unavailable"),
            ),
        )
        .expect("complete without append");
    assert!(environment.manager.list(10).expect("events").is_empty());

    let always = environment
        .port
        .will_execute(intent(ActionId::AuthKeyShow, AuditPolicy::SensitiveRead))
        .expect("open")
        .expect("marker");
    environment
        .port
        .did_execute(
            &always,
            CommandAuditResult::new(
                ActionId::AuthKeyShow,
                CommandAuditOutcome::Denied,
                Some("authorization_denied"),
            ),
        )
        .expect("denied append");
    let event = environment.manager.list(10).expect("events").remove(0);
    assert_eq!(event.target().as_str(), "local-node");
    assert_eq!(event.outcome().as_str(), "denied");
    assert_eq!(
        event.reason().expect("reason").as_str(),
        "authorization_denied"
    );
}

// Retains a failed durable completion and rejects an action changed under the same marker.
#[test]
fn failed_append_remains_open_for_explicit_recovery() {
    let mut environment = environment(Arc::new(CommandIdentityMock::unique()));
    let marker = environment
        .port
        .will_execute(intent(ActionId::NodePause, AuditPolicy::Always))
        .expect("open")
        .expect("marker");
    assert!(environment
        .port
        .did_execute(
            &marker,
            CommandAuditResult::new(ActionId::NodeResume, CommandAuditOutcome::Succeeded, None,),
        )
        .is_err());
    environment.store.fail_append.store(true, Ordering::SeqCst);
    assert!(environment
        .port
        .did_execute(
            &marker,
            CommandAuditResult::new(ActionId::NodePause, CommandAuditOutcome::Succeeded, None,),
        )
        .is_err());
    assert_eq!(environment.port.pending_count(), 1);
    assert!(environment.manager.list(10).expect("events").is_empty());
}

// Rejects mismatched ledger ownership and one reused open marker before dispatch.
#[test]
fn composition_rejects_identity_mismatch_and_marker_reuse() {
    let node_id = NodeId::parse(&"1".repeat(32)).expect("node");
    let manager = Arc::new(AuditManager::new(
        node_id,
        Arc::new(AuditStoreMock::default()),
        Arc::new(AuditClockMock(AtomicU64::new(1_000))),
        Arc::new(AuditEventIdentityMock(AtomicU64::new(1))),
        Arc::new(AuditCryptographyMock),
        AuditCheckpointPolicy::production(),
    ));
    let mismatch = CoreCommandAuditPort::new(
        manager,
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse("local-user-501").expect("actor"),
        ),
        AuditOrigin::new(
            NodeId::parse(&"2".repeat(32)).expect("foreign node"),
            AuditOriginInterface::Cli,
        ),
        Arc::new(CommandIdentityMock::unique()),
    );
    assert!(matches!(
        mismatch,
        Err(CoreCommandAuditConfigurationError::NodeIdentityMismatch)
    ));

    let mut environment = environment(Arc::new(CommandIdentityMock::repeating()));
    environment
        .port
        .will_execute(intent(ActionId::ModelRemove, AuditPolicy::Always))
        .expect("first marker");
    assert!(environment
        .port
        .will_execute(intent(ActionId::ModelRemove, AuditPolicy::Always))
        .is_err());
    assert_eq!(environment.port.pending_count(), 1);

    let mismatched_identity = CoreCommandAuditIdentity::new(
        ActionId::ModelRemove,
        "li_cli_audit_00000000000000000000000000000001",
        AuditCorrelationId::parse("00000000000000000000000000000002")
            .expect("mismatched correlation"),
        AuditReplayId::parse("li_cli_model.remove_00000000000000000000000000000001")
            .expect("mismatched replay"),
    );
    assert_eq!(
        mismatched_identity,
        Err(CoreCommandAuditConfigurationError::InvalidIdentity)
    );
}
