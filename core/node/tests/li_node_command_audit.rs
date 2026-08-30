// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use li_audit_manager::{
    AuditActor, AuditActorId, AuditActorType, AuditCheckpointCryptography, AuditCheckpointPolicy,
    AuditClock, AuditError, AuditEventId, AuditIdentityProvider, AuditOrigin, AuditOriginInterface,
    AuditUnixNanoseconds,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    DatabaseAuditStore, DatabaseNodeCommandAuditSessionStore, NodeCommandAuditApiPort,
    NodeCommandAuditCompletionDisposition, NodeCommandAuditCompletionRequest,
    NodeCommandAuditCoordinator, NodeCommandAuditError, NodeCommandAuditIntent,
    NodeCommandAuditMarker, NodeCommandAuditMutation, NodeCommandAuditOpenDisposition,
    NodeCommandAuditOpenRequest, NodeCommandAuditOutcome, NodeCommandAuditPolicy,
    NodeCommandAuditResult, NodeCommandAuditSession, NodeCommandAuditSessionStore,
    NodeCommandAuditTarget, NodeCommandAuditTargetKind, NodeManager,
    VersionedNodeCommandAuditSession,
};

// Supplies deterministic increasing database commit time.
struct DatabaseClockMock(AtomicI64);

impl DatabaseClock for DatabaseClockMock {
    // Returns one unique database commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies deterministic increasing audit time.
struct AuditClockMock(AtomicU64);

impl AuditClock for AuditClockMock {
    // Returns one unique positive audit timestamp.
    fn now(&self) -> Result<AuditUnixNanoseconds, AuditError> {
        AuditUnixNanoseconds::new(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies deterministic unique audit event identities.
struct AuditIdentityMock(AtomicU64);

impl AuditIdentityProvider for AuditIdentityMock {
    // Returns one unique lowercase 128-bit-shaped identity.
    fn event_id(&self) -> Result<AuditEventId, AuditError> {
        AuditEventId::parse(&format!("{:032x}", self.0.fetch_add(1, Ordering::SeqCst)))
    }
}

// Verifies deterministic tests without introducing native key files.
struct CryptographyMock;

impl AuditCheckpointCryptography for CryptographyMock {
    // Returns the exact event hash as its deterministic signature.
    fn sign(&self, event_hash: &[u8]) -> Result<Vec<u8>, AuditError> {
        Ok(event_hash.to_vec())
    }

    // Accepts only the exact deterministic signature.
    fn verify(&self, event_hash: &[u8], signature: &[u8]) -> Result<bool, AuditError> {
        Ok(event_hash == signature)
    }
}

// Injects one crash-shaped failure after the audit append but before session completion.
struct FailCompletedWriteOnce {
    inner: Arc<DatabaseNodeCommandAuditSessionStore>,
    replacements: AtomicU64,
}

impl NodeCommandAuditSessionStore for FailCompletedWriteOnce {
    // Delegates exact reads to real DatabaseManager persistence.
    fn read(
        &self,
        command_id: &Sha256Digest,
    ) -> Result<Option<VersionedNodeCommandAuditSession>, NodeCommandAuditError> {
        self.inner.read(command_id)
    }

    // Delegates session creation to real DatabaseManager persistence.
    fn create(
        &self,
        session: NodeCommandAuditSession,
    ) -> Result<VersionedNodeCommandAuditSession, NodeCommandAuditError> {
        self.inner.create(session)
    }

    // Fails only the second transition, after the completing phase is durable.
    fn replace(
        &self,
        session: NodeCommandAuditSession,
        expected_revision: u64,
    ) -> Result<VersionedNodeCommandAuditSession, NodeCommandAuditError> {
        if self.replacements.fetch_add(1, Ordering::SeqCst) == 1 {
            return Err(NodeCommandAuditError::Unavailable);
        }
        self.inner.replace(session, expected_revision)
    }
}

// Owns one reusable real database and deterministic audit composition.
struct Fixture {
    database: Arc<DatabaseManager>,
    manager: Arc<li_audit_manager::AuditManager>,
    node_id: NodeId,
}

impl Fixture {
    // Opens one real WAL database and initialized active main identity.
    fn open(directory: &tempfile::TempDir) -> Self {
        let database = Arc::new(
            DatabaseManager::open(
                DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                    .with_busy_timeout(Duration::from_secs(1))
                    .with_clock(Arc::new(DatabaseClockMock(AtomicI64::new(10_000)))),
            )
            .expect("database"),
        );
        let node = local_node();
        let node_id = node.identity().node_id().clone();
        let manager = NodeManager::open(database.clone(), node, "initialize-node")
            .expect("node manager")
            .0;
        let audit = manager.audit_manager_with_dependencies(
            Arc::new(AuditClockMock(AtomicU64::new(1_000_000))),
            Arc::new(AuditIdentityMock(AtomicU64::new(1))),
            Arc::new(CryptographyMock),
            AuditCheckpointPolicy::production(),
        );
        Self {
            database,
            manager: Arc::new(audit),
            node_id,
        }
    }

    // Reopens the same persistence with fresh process-local audit dependencies.
    fn restart(&self) -> Self {
        let audit = li_audit_manager::AuditManager::new(
            self.node_id.clone(),
            Arc::new(DatabaseAuditStore::new(self.database.clone())),
            Arc::new(AuditClockMock(AtomicU64::new(2_000_000))),
            Arc::new(AuditIdentityMock(AtomicU64::new(100))),
            Arc::new(CryptographyMock),
            AuditCheckpointPolicy::production(),
        );
        Self {
            database: self.database.clone(),
            manager: Arc::new(audit),
            node_id: self.node_id.clone(),
        }
    }

    // Composes the ordinary durable coordinator over this exact database.
    fn coordinator(&self) -> Arc<NodeCommandAuditCoordinator> {
        self.coordinator_with_store(Arc::new(DatabaseNodeCommandAuditSessionStore::new(
            self.database.clone(),
        )))
    }

    // Composes a coordinator with one injected session persistence boundary.
    fn coordinator_with_store(
        &self,
        store: Arc<dyn NodeCommandAuditSessionStore>,
    ) -> Arc<NodeCommandAuditCoordinator> {
        Arc::new(
            NodeCommandAuditCoordinator::new(
                self.manager.clone(),
                store,
                AuditActor::new(
                    AuditActorType::LocalUser,
                    AuditActorId::parse("local-user-501").expect("actor"),
                ),
                AuditOrigin::new(self.node_id.clone(), AuditOriginInterface::Cli),
            )
            .expect("coordinator"),
        )
    }
}

// Returns one coherent active local main fixture.
fn local_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            MachineId::parse(&"2".repeat(32)).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Home AI").expect("name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1), UnixMilliseconds::new(1))
            .expect("timestamps"),
    )
}

// Returns one canonical digest whose identity is clear at each call site.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one secret-free exact command intent.
fn intent(
    action: &str,
    policy: NodeCommandAuditPolicy,
    mutation: NodeCommandAuditMutation,
) -> NodeCommandAuditIntent {
    NodeCommandAuditIntent::new(
        TechnicalName::parse(action).expect("action"),
        policy,
        mutation,
        NodeRole::Main,
    )
}

// Opens one ordinary action under its exact durable command identity.
fn open(
    coordinator: &NodeCommandAuditCoordinator,
    command_id: Sha256Digest,
    intent: NodeCommandAuditIntent,
) -> li_node_manager::NodeCommandAuditOpenReceipt {
    coordinator
        .open(NodeCommandAuditOpenRequest::new(command_id, intent))
        .expect("open")
}

// Completes one marker using a canonical terminal action and outcome.
fn complete(
    coordinator: &NodeCommandAuditCoordinator,
    marker: &NodeCommandAuditMarker,
    action: &str,
    outcome: NodeCommandAuditOutcome,
    failure_code: Option<&str>,
) -> Result<li_node_manager::NodeCommandAuditCompletionReceipt, NodeCommandAuditError> {
    coordinator.complete(NodeCommandAuditCompletionRequest::new(
        marker.clone(),
        NodeCommandAuditResult::new(
            TechnicalName::parse(action).expect("action"),
            outcome,
            failure_code,
        )?,
    ))
}

// Proves open survives process loss, replays exactly, and rejects a divergent intent binding.
#[test]
fn open_is_durable_restart_safe_and_exactly_bound() {
    let directory = tempfile::tempdir().expect("temporary");
    let fixture = Fixture::open(&directory);
    let command_id = digest('a');
    let command_intent = intent(
        "model.install",
        NodeCommandAuditPolicy::Always,
        NodeCommandAuditMutation::Node,
    )
    .with_target(
        NodeCommandAuditTarget::new(NodeCommandAuditTargetKind::Model, "deepseek_r1")
            .expect("target"),
    );
    let receipt = open(
        &fixture.coordinator(),
        command_id.clone(),
        command_intent.clone(),
    );
    assert_eq!(
        receipt.disposition(),
        NodeCommandAuditOpenDisposition::Opened
    );

    let restarted = fixture.restart();
    let replay = open(&restarted.coordinator(), command_id.clone(), command_intent);
    assert_eq!(
        replay.disposition(),
        NodeCommandAuditOpenDisposition::Replayed
    );
    assert_eq!(replay.marker(), receipt.marker());
    assert_eq!(
        restarted
            .coordinator()
            .open(NodeCommandAuditOpenRequest::new(
                command_id,
                intent(
                    "model.install",
                    NodeCommandAuditPolicy::Always,
                    NodeCommandAuditMutation::Node,
                )
                .with_target(
                    NodeCommandAuditTarget::new(NodeCommandAuditTargetKind::Model, "qwen3_8")
                        .expect("target"),
                ),
            )),
        Err(NodeCommandAuditError::Conflict)
    );
    complete(
        &restarted.coordinator(),
        receipt.marker(),
        "model.install",
        NodeCommandAuditOutcome::Succeeded,
        None,
    )
    .expect("completion");
    let events = restarted.manager.list(1).expect("events");
    assert_eq!(events[0].target().as_str(), "model:deepseek_r1");
}

// Proves concurrent duplicate opens have one creator and one exact replay without two sessions.
#[test]
fn concurrent_duplicate_open_has_one_durable_winner() {
    let directory = tempfile::tempdir().expect("temporary");
    let fixture = Fixture::open(&directory);
    let coordinator = fixture.coordinator();
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _worker in 0..2 {
        let coordinator = coordinator.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            open(
                &coordinator,
                digest('b'),
                intent(
                    "auth.key.rotate",
                    NodeCommandAuditPolicy::Always,
                    NodeCommandAuditMutation::Node,
                ),
            )
        }));
    }
    barrier.wait();
    let dispositions = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker").disposition())
        .collect::<Vec<_>>();
    assert_eq!(
        dispositions
            .iter()
            .filter(|value| **value == NodeCommandAuditOpenDisposition::Opened)
            .count(),
        1
    );
    assert_eq!(
        dispositions
            .iter()
            .filter(|value| **value == NodeCommandAuditOpenDisposition::Replayed)
            .count(),
        1
    );
}

// Proves every policy/outcome pair reaches one exact immutable terminal state.
#[test]
fn policy_and_terminal_outcome_matrix_is_complete_and_replay_safe() {
    let directory = tempfile::tempdir().expect("temporary");
    let fixture = Fixture::open(&directory);
    let coordinator = fixture.coordinator();
    let policies = [
        NodeCommandAuditPolicy::Success,
        NodeCommandAuditPolicy::Always,
        NodeCommandAuditPolicy::SensitiveRead,
    ];
    let outcomes = [
        NodeCommandAuditOutcome::Succeeded,
        NodeCommandAuditOutcome::Failed,
        NodeCommandAuditOutcome::Denied,
        NodeCommandAuditOutcome::Cancelled,
    ];
    let mut next_identity = 1_u8;
    let mut appended = 0_u64;
    for policy in policies {
        for outcome in outcomes {
            let command_id =
                Sha256Digest::parse(&format!("{next_identity:064x}")).expect("command identity");
            next_identity += 1;
            let receipt = open(
                &coordinator,
                command_id,
                intent("model.restart", policy, NodeCommandAuditMutation::Node),
            );
            let failure = if outcome == NodeCommandAuditOutcome::Succeeded {
                None
            } else {
                Some("manager_unavailable")
            };
            let completed = complete(
                &coordinator,
                receipt.marker(),
                "model.restart",
                outcome,
                failure,
            )
            .expect("completion");
            let should_append = policy != NodeCommandAuditPolicy::Success
                || outcome == NodeCommandAuditOutcome::Succeeded;
            assert_eq!(completed.event_id().is_some(), should_append);
            appended += u64::from(should_append);
            let replay = complete(
                &coordinator,
                receipt.marker(),
                "model.restart",
                outcome,
                failure,
            )
            .expect("completion replay");
            assert_eq!(
                replay.disposition(),
                NodeCommandAuditCompletionDisposition::Replayed
            );
            assert_eq!(replay.event_id(), completed.event_id());
            assert_eq!(
                complete(
                    &coordinator,
                    receipt.marker(),
                    "model.restart",
                    if outcome == NodeCommandAuditOutcome::Succeeded {
                        NodeCommandAuditOutcome::Failed
                    } else {
                        NodeCommandAuditOutcome::Succeeded
                    },
                    if outcome == NodeCommandAuditOutcome::Succeeded {
                        Some("manager_unavailable")
                    } else {
                        None
                    },
                ),
                Err(NodeCommandAuditError::Conflict)
            );
        }
    }
    assert_eq!(appended, 9);
    assert_eq!(fixture.manager.verify().expect("ledger").events(), 9);
}

// Proves an interrupted post-append journal write resumes through AuditManager replay after restart.
#[test]
fn crash_after_append_resumes_without_duplicate_event() {
    let directory = tempfile::tempdir().expect("temporary");
    let fixture = Fixture::open(&directory);
    let real_store = Arc::new(DatabaseNodeCommandAuditSessionStore::new(
        fixture.database.clone(),
    ));
    let failing = fixture.coordinator_with_store(Arc::new(FailCompletedWriteOnce {
        inner: real_store,
        replacements: AtomicU64::new(0),
    }));
    let receipt = open(
        &failing,
        digest('c'),
        intent(
            "service.stop",
            NodeCommandAuditPolicy::Always,
            NodeCommandAuditMutation::Local,
        ),
    );
    assert_eq!(
        complete(
            &failing,
            receipt.marker(),
            "service.stop",
            NodeCommandAuditOutcome::Succeeded,
            None,
        ),
        Err(NodeCommandAuditError::Unavailable)
    );
    assert_eq!(fixture.manager.verify().expect("ledger").events(), 1);

    let restarted = fixture.restart();
    let completion = complete(
        &restarted.coordinator(),
        receipt.marker(),
        "service.stop",
        NodeCommandAuditOutcome::Succeeded,
        None,
    )
    .expect("resumed completion");
    assert_eq!(
        completion.disposition(),
        NodeCommandAuditCompletionDisposition::Replayed
    );
    assert_eq!(restarted.manager.verify().expect("ledger").events(), 1);
}

// Proves opaque markers, diagnostics, and real SQLite/WAL bytes never retain supplied secret text.
#[test]
fn secret_shaped_failure_text_is_normalized_and_absent_from_durable_bytes() {
    let directory = tempfile::tempdir().expect("temporary");
    let fixture = Fixture::open(&directory);
    let coordinator = fixture.coordinator();
    let secret = "li_super_secret_bearer_value_that_must_never_persist";
    let receipt = open(
        &coordinator,
        digest('d'),
        intent(
            "auth.key.rotate",
            NodeCommandAuditPolicy::Always,
            NodeCommandAuditMutation::Node,
        ),
    );
    assert_eq!(
        format!("{:?}", receipt.marker()),
        "NodeCommandAuditMarker(<redacted>)"
    );
    let result = NodeCommandAuditResult::new(
        TechnicalName::parse("auth.key.rotate").expect("action"),
        NodeCommandAuditOutcome::Failed,
        Some(secret),
    )
    .expect("normalized result");
    assert_eq!(result.failure_code(), Some("command_failed"));
    assert!(!format!("{result:?}").contains(secret));
    coordinator
        .complete(NodeCommandAuditCompletionRequest::new(
            receipt.marker().clone(),
            result,
        ))
        .expect("completion");
    assert!(!NodeCommandAuditError::Unavailable
        .to_string()
        .contains(secret));

    for name in ["core.sqlite3", "core.sqlite3-wal", "core.sqlite3-shm"] {
        let path = directory.path().join(name);
        if path.exists() {
            let bytes = fs::read(path).expect("database bytes");
            assert!(!bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()));
        }
    }
}
