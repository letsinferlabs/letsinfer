// SPDX-License-Identifier: AGPL-3.0-only

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    CredentialId, DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress,
    NodeId, NodeIdentity, NodeRole, NodeState, PlacementGroupId, Sha256Digest, TokenCountContract,
    TokenCountProtocol, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_gateway_manager::{
    GatewayNativeFile, GatewayNativeFileIo, GatewayNativeIoError, GatewayNativeTarget,
    GatewayRelayAuthorizationProvider,
};
use li_node_manager::{
    DatabaseNodeGatewayRelayTrustStore, NodeGatewayRelayClock,
    NodeGatewayRelayCredentialReferences, NodeGatewayRelayNodeProvider,
    NodeGatewayRelayTargetProvider, NodeGatewayRelayTrust, NodeGatewayRelayTrustError,
    NodeGatewayRelayTrustState, NodeGatewayRelayTrustStore,
    PersistedNodeGatewayRelayAuthorizationProvider, PersistedNodeGatewayRelayTargetProvider,
    VersionedNodeGatewayRelayTrust, LETSINFER_PRIVATE_GATEWAY_PORT,
};
use serde::{Deserialize, Serialize};

// Supplies one independent transaction target for atomic relay-trust rollback tests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RelayTrustTransactionCompanion {
    identifier: String,
    value: String,
}

impl li_database::DatabaseRecord for RelayTrustTransactionCompanion {
    const COLLECTION: li_database::DatabaseCollection =
        li_database::DatabaseCollection::Configuration;

    // Returns the exact independent configuration-record identity.
    fn identifier(&self) -> &str {
        &self.identifier
    }
}

// Returns one canonical identity fixture.
fn identity(character: char) -> String {
    character.to_string().repeat(32)
}

// Returns one canonical installation identity fixture.
fn installation(character: char) -> String {
    character.to_string().repeat(64)
}

// Returns one coherent active node fixture.
fn node(
    node_character: char,
    machine_character: char,
    installation_character: char,
    role: NodeRole,
    state: NodeState,
    address: &str,
) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity(node_character)).expect("node"),
            MachineId::parse(&identity(machine_character)).expect("machine"),
            InstallationId::parse(&installation(installation_character)).expect("installation"),
        ),
        DisplayName::parse(if role == NodeRole::Main {
            "Home AI"
        } else {
            "Home AI Child"
        })
        .expect("display name"),
        role,
        state,
        NodeAddress::parse(address).expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
}

// Returns the ordinary active main fixture.
fn main_node() -> Node {
    node(
        '1',
        '2',
        '3',
        NodeRole::Main,
        NodeState::Active,
        "homeai.local",
    )
}

// Returns the ordinary active child fixture.
fn child_node() -> Node {
    node(
        '4',
        '5',
        '6',
        NodeRole::Child,
        NodeState::Active,
        "homeai-node-2.local",
    )
}

// Returns one reference-only credential fixture with no secret bytes.
fn credentials(seed: char) -> NodeGatewayRelayCredentialReferences {
    NodeGatewayRelayCredentialReferences::new(
        CredentialId::parse(&identity(seed)).expect("relay credential"),
        PathBuf::from(format!("/private/relay/{seed}/li_relay_bearer")),
        CredentialId::parse(&identity(next_character(seed, 1))).expect("CA credential"),
        PathBuf::from(format!("/private/relay/{seed}/li_site_ca.pem")),
        CredentialId::parse(&identity(next_character(seed, 2))).expect("child leaf"),
        PathBuf::from(format!("/private/relay/{seed}/li_child_leaf.pem")),
        Sha256Digest::parse(&next_character(seed, 3).to_string().repeat(64))
            .expect("child leaf digest"),
        CredentialId::parse(&identity(next_character(seed, 4))).expect("main leaf"),
        PathBuf::from(format!("/private/relay/{seed}/li_main_leaf.pem")),
        PathBuf::from(format!("/private/relay/{seed}/li_main_leaf.key")),
    )
    .expect("credentials")
}

// Advances one hexadecimal fixture character by a small deterministic offset.
fn next_character(value: char, offset: u8) -> char {
    char::from_digit(
        value.to_digit(16).expect("hex character") + u32::from(offset),
        16,
    )
    .expect("advanced hexadecimal character")
}

// Returns one complete trust fixture for the supplied identities and lifecycle fields.
#[allow(clippy::too_many_arguments)]
fn trust(
    main: &Node,
    child: &Node,
    address: &str,
    generation: u64,
    issued_at: u64,
    expires_at: u64,
    state: NodeGatewayRelayTrustState,
    credential_seed: char,
) -> NodeGatewayRelayTrust {
    NodeGatewayRelayTrust::new(
        Sha256Digest::parse(&credential_seed.to_string().repeat(64)).expect("receipt"),
        main.identity().clone(),
        child.identity().clone(),
        NodeAddress::parse(address).expect("address"),
        NonZeroU64::new(generation).expect("generation"),
        UnixMilliseconds::new(issued_at),
        UnixMilliseconds::new(expires_at),
        state,
        credentials(credential_seed),
    )
    .expect("trust")
}

// Supplies mutable live Node snapshots through the production provider port.
struct NodeMock {
    local: Mutex<Result<Node, GatewayNativeIoError>>,
    child: Mutex<Result<Option<Node>, GatewayNativeIoError>>,
}

impl NodeGatewayRelayNodeProvider for NodeMock {
    // Returns the configured local snapshot or stable provider failure.
    fn local_node(&self) -> Result<Node, GatewayNativeIoError> {
        self.local.lock().expect("local lock").clone()
    }

    // Returns the configured child only when its requested identity remains exact.
    fn node(&self, node_id: &NodeId) -> Result<Option<Node>, GatewayNativeIoError> {
        self.child
            .lock()
            .expect("child lock")
            .clone()
            .map(|child| child.filter(|candidate| candidate.identity().node_id() == node_id))
    }
}

// Supplies one mutable persisted trust observation or stable store failure.
struct TrustMock {
    value: Mutex<Result<Option<VersionedNodeGatewayRelayTrust>, NodeGatewayRelayTrustError>>,
}

impl NodeGatewayRelayTrustStore for TrustMock {
    // Returns the configured trust only when its child identity matches the lookup.
    fn read(
        &self,
        child_node_id: &NodeId,
    ) -> Result<Option<VersionedNodeGatewayRelayTrust>, NodeGatewayRelayTrustError> {
        self.value.lock().expect("trust lock").clone().map(|value| {
            value.filter(|candidate| candidate.trust().child_identity().node_id() == child_node_id)
        })
    }
}

// Supplies one deterministic relay-validity timestamp.
struct ClockMock(Result<UnixMilliseconds, GatewayNativeIoError>);

impl NodeGatewayRelayClock for ClockMock {
    // Returns the configured timestamp or stable provider failure.
    fn now(&self) -> Result<UnixMilliseconds, GatewayNativeIoError> {
        self.0.clone()
    }
}

// Supplies one exact private bearer observation through the native no-follow boundary.
struct FileMock {
    file: Mutex<GatewayNativeFile>,
}

impl GatewayNativeFileIo for FileMock {
    // Returns the configured bounded metadata observation without reading a real secret path.
    fn read_no_follow(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        Ok(self.file.lock().expect("file lock").clone())
    }
}

// Creates one provider from deterministic live and persisted state.
fn provider(
    main: Node,
    child: Node,
    persisted: Result<Option<VersionedNodeGatewayRelayTrust>, NodeGatewayRelayTrustError>,
    now: u64,
) -> PersistedNodeGatewayRelayTargetProvider {
    PersistedNodeGatewayRelayTargetProvider::new(
        501,
        Arc::new(NodeMock {
            local: Mutex::new(Ok(main)),
            child: Mutex::new(Ok(Some(child))),
        }),
        Arc::new(TrustMock {
            value: Mutex::new(persisted),
        }),
        Arc::new(ClockMock(Ok(UnixMilliseconds::new(now)))),
    )
}

// Creates one inbound authorization provider from exact child, main, trust, and bearer state.
fn authorization_provider(
    main: Node,
    child: Node,
    persisted: NodeGatewayRelayTrust,
    bearer: &[u8],
    mode: u32,
) -> PersistedNodeGatewayRelayAuthorizationProvider {
    PersistedNodeGatewayRelayAuthorizationProvider::new(
        501,
        Arc::new(NodeMock {
            local: Mutex::new(Ok(child)),
            child: Mutex::new(Ok(Some(main))),
        }),
        Arc::new(TrustMock {
            value: Mutex::new(Ok(Some(VersionedNodeGatewayRelayTrust::new(persisted, 1)))),
        }),
        Arc::new(ClockMock(Ok(UnixMilliseconds::new(5_000)))),
        Arc::new(FileMock {
            file: Mutex::new(GatewayNativeFile::new(501, mode, 1, bearer.to_vec()).unwrap()),
        }),
    )
}

// Authenticates exact active child trust and private bearer bytes without leaking mismatch detail.
#[test]
fn persisted_inbound_relay_authorization_fails_closed() {
    let main = main_node();
    let child = child_node();
    let persisted = trust(
        &main,
        &child,
        child.control_address().as_str(),
        1,
        1_000,
        10_000,
        NodeGatewayRelayTrustState::Active,
        '7',
    );
    let bearer = "r".repeat(48);
    let provider = authorization_provider(
        main.clone(),
        child.clone(),
        persisted.clone(),
        bearer.as_bytes(),
        0o600,
    );
    assert_eq!(
        provider.authorize(&bearer).unwrap(),
        *main.identity().node_id()
    );
    assert!(provider.authorize(&format!("{}x", &bearer[..47])).is_err());

    let unsafe_file = authorization_provider(main, child, persisted, bearer.as_bytes(), 0o640);
    assert!(unsafe_file.authorize(&bearer).is_err());
}

// Resolves one relay through exact Node and persisted pairing state with Core's fixed token path.
#[test]
fn persisted_relay_uses_exact_identity_references_and_fixed_core_contract() {
    assert_eq!(LETSINFER_PRIVATE_GATEWAY_PORT, 9_444);
    let main = main_node();
    let child = child_node();
    let persisted = trust(
        &main,
        &child,
        child.control_address().as_str(),
        1,
        1_000,
        10_000,
        NodeGatewayRelayTrustState::Active,
        '7',
    );
    let expected = GatewayNativeTarget::child_relay(
        child.control_address().as_str(),
        LETSINFER_PRIVATE_GATEWAY_PORT,
        501,
        PathBuf::from("/private/relay/7/li_relay_bearer"),
        PathBuf::from("/private/relay/7/li_site_ca.pem"),
        persisted
            .credentials()
            .child_leaf_certificate_sha256()
            .clone(),
        PathBuf::from("/private/relay/7/li_main_leaf.pem"),
        PathBuf::from("/private/relay/7/li_main_leaf.key"),
        Some(
            TokenCountContract::new("/li/token-count", TokenCountProtocol::LetsInferV1)
                .expect("Core token contract"),
        ),
    )
    .expect("native target");
    let provider = provider(
        main,
        child.clone(),
        Ok(Some(VersionedNodeGatewayRelayTrust::new(
            persisted.clone(),
            1,
        ))),
        5_000,
    );

    let target = provider
        .target(
            &PlacementGroupId::parse(&identity('a')).expect("group"),
            child.identity().node_id(),
            child.control_address(),
            Some(
                TokenCountContract::new("/engine/tokenize", TokenCountProtocol::LetsInferV1)
                    .expect("Engine contract"),
            ),
        )
        .expect("relay target");

    assert_eq!(target.native_target(), &expected);
    assert_eq!(target.child_node_id(), child.identity().node_id());
    assert_eq!(target.child_address(), child.control_address());
    assert_eq!(
        target.child_leaf_credential_id(),
        persisted.credentials().child_leaf_credential_id()
    );
    assert_eq!(
        target.child_leaf_certificate_file(),
        PathBuf::from("/private/relay/7/li_child_leaf.pem")
    );
    assert_eq!(
        target.child_leaf_certificate_sha256(),
        persisted.credentials().child_leaf_certificate_sha256()
    );
    let debug = format!("{target:?}");
    assert!(!debug.contains("/private/"));
}

// Proves meaningful stale, replayed, revoked, foreign, and mismatched trust paths fail closed.
#[test]
fn persisted_relay_rejects_trust_and_membership_mismatch_matrix() {
    let main = main_node();
    let child = child_node();
    let ordinary = trust(
        &main,
        &child,
        child.control_address().as_str(),
        1,
        1_000,
        10_000,
        NodeGatewayRelayTrustState::Active,
        '7',
    );
    let group = PlacementGroupId::parse(&identity('a')).expect("group");
    let assert_rejected =
        |provider: PersistedNodeGatewayRelayTargetProvider, child: &Node, address: &str| {
            assert!(provider
                .target(
                    &group,
                    child.identity().node_id(),
                    &NodeAddress::parse(address).expect("route address"),
                    None,
                )
                .is_err());
        };

    assert_rejected(
        provider(main.clone(), child.clone(), Ok(None), 5_000),
        &child,
        child.control_address().as_str(),
    );
    assert_rejected(
        provider(
            main.clone(),
            child.clone(),
            Ok(Some(VersionedNodeGatewayRelayTrust::new(
                ordinary.clone(),
                2,
            ))),
            5_000,
        ),
        &child,
        child.control_address().as_str(),
    );
    let revoked = trust(
        &main,
        &child,
        child.control_address().as_str(),
        1,
        1_000,
        10_000,
        NodeGatewayRelayTrustState::Revoked,
        '7',
    );
    assert_rejected(
        provider(
            main.clone(),
            child.clone(),
            Ok(Some(VersionedNodeGatewayRelayTrust::new(revoked, 1))),
            5_000,
        ),
        &child,
        child.control_address().as_str(),
    );
    assert_rejected(
        provider(
            main.clone(),
            child.clone(),
            Ok(Some(VersionedNodeGatewayRelayTrust::new(
                ordinary.clone(),
                1,
            ))),
            10_000,
        ),
        &child,
        child.control_address().as_str(),
    );
    let foreign_main = node(
        'b',
        'c',
        'd',
        NodeRole::Main,
        NodeState::Active,
        "other-main.local",
    );
    let foreign = trust(
        &foreign_main,
        &child,
        child.control_address().as_str(),
        1,
        1_000,
        10_000,
        NodeGatewayRelayTrustState::Active,
        '7',
    );
    assert_rejected(
        provider(
            main.clone(),
            child.clone(),
            Ok(Some(VersionedNodeGatewayRelayTrust::new(foreign, 1))),
            5_000,
        ),
        &child,
        child.control_address().as_str(),
    );
    let changed_child = node(
        '4',
        '5',
        'e',
        NodeRole::Child,
        NodeState::Active,
        "homeai-node-2.local",
    );
    assert_rejected(
        provider(
            main.clone(),
            changed_child.clone(),
            Ok(Some(VersionedNodeGatewayRelayTrust::new(
                ordinary.clone(),
                1,
            ))),
            5_000,
        ),
        &changed_child,
        changed_child.control_address().as_str(),
    );
    assert_rejected(
        provider(
            main.clone(),
            child.clone(),
            Ok(Some(VersionedNodeGatewayRelayTrust::new(
                ordinary.clone(),
                1,
            ))),
            5_000,
        ),
        &child,
        "changed-child.local",
    );
    let inactive_child = node(
        '4',
        '5',
        '6',
        NodeRole::Child,
        NodeState::Offline,
        "homeai-node-2.local",
    );
    assert_rejected(
        provider(
            main,
            inactive_child.clone(),
            Ok(Some(VersionedNodeGatewayRelayTrust::new(ordinary, 1))),
            5_000,
        ),
        &inactive_child,
        inactive_child.control_address().as_str(),
    );
}

// Persists monotonic trust generations, exact replay, replacement, and terminal revocation.
#[test]
fn database_store_preserves_reference_only_trust_and_rejects_rollback() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1)),
        )
        .expect("database"),
    );
    let store = DatabaseNodeGatewayRelayTrustStore::new(database);
    let main = main_node();
    let child = child_node();
    let first = trust(
        &main,
        &child,
        child.control_address().as_str(),
        1,
        1_000,
        10_000,
        NodeGatewayRelayTrustState::Active,
        '7',
    );

    let created = store.create(first.clone()).expect("create trust");
    let replayed = store.create(first).expect("replay trust");
    assert_eq!(created, replayed);
    assert_eq!(created.revision(), 1);

    let replacement = trust(
        &main,
        &child,
        child.control_address().as_str(),
        2,
        2_000,
        20_000,
        NodeGatewayRelayTrustState::Active,
        '8',
    );
    let replaced = store
        .replace(replacement.clone(), created.revision())
        .expect("replace trust");
    assert_eq!(replaced.revision(), 2);
    assert_eq!(replaced.trust(), &replacement);
    assert_eq!(
        store
            .replace(replacement, 1)
            .expect_err("stale replacement must fail"),
        NodeGatewayRelayTrustError::Conflict
    );

    let revoked = store
        .revoke(child.identity().node_id(), replaced.revision())
        .expect("revoke trust");
    assert_eq!(revoked.revision(), 3);
    assert_eq!(revoked.trust().state(), NodeGatewayRelayTrustState::Revoked);
    assert_eq!(
        store
            .replace(
                trust(
                    &main,
                    &child,
                    child.control_address().as_str(),
                    4,
                    3_000,
                    30_000,
                    NodeGatewayRelayTrustState::Active,
                    '9',
                ),
                revoked.revision(),
            )
            .expect_err("revoked trust must not reactivate"),
        NodeGatewayRelayTrustError::Conflict
    );
    let observed = store
        .read(child.identity().node_id())
        .expect("read trust")
        .expect("persisted trust");
    assert_eq!(observed, revoked);
}

// Composes relay trust into a larger transaction and rolls it back on a later conflict.
#[test]
fn database_store_composes_relay_trust_atomically() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1)),
        )
        .expect("database"),
    );
    let store = DatabaseNodeGatewayRelayTrustStore::new(database.clone());
    let main = main_node();
    let child = child_node();
    let desired = trust(
        &main,
        &child,
        child.control_address().as_str(),
        1,
        1_000,
        10_000,
        NodeGatewayRelayTrustState::Active,
        '7',
    );
    let companion = RelayTrustTransactionCompanion {
        identifier: "relay-trust-transaction-companion".to_string(),
        value: "expected".to_string(),
    };
    database
        .write(li_database::DatabaseCommand::save(
            "relay-trust:companion:create",
            companion.clone(),
            li_database::DatabaseRevision::Missing,
        ))
        .expect("companion");

    let transaction =
        li_database::DatabaseTransaction::new("relay-trust:atomic").expect("transaction");
    let transaction = store
        .creating_transaction(transaction, &desired)
        .expect("relay trust mutation");
    let transaction = transaction
        .save(companion, li_database::DatabaseRevision::Missing)
        .expect("companion mutation");
    assert!(database.write_transaction(transaction).is_err());
    assert!(store
        .read(child.identity().node_id())
        .expect("trust lookup")
        .is_none());

    let transaction =
        li_database::DatabaseTransaction::new("relay-trust:atomic-success").expect("transaction");
    let transaction = store
        .creating_transaction(transaction, &desired)
        .expect("relay trust mutation");
    let applied = database
        .write_transaction(transaction)
        .expect("atomic trust");
    assert_eq!(applied.commit().commits().len(), 1);
    assert_eq!(
        store
            .read(child.identity().node_id())
            .expect("trust lookup")
            .expect("trust")
            .trust(),
        &desired
    );
}

// Rejects aliased credential identities and paths before anything reaches persistence.
#[test]
fn credential_references_reject_ambiguous_or_relative_inputs() {
    let duplicate = CredentialId::parse(&identity('1')).expect("credential");
    assert!(NodeGatewayRelayCredentialReferences::new(
        duplicate.clone(),
        PathBuf::from("/private/relay/bearer"),
        duplicate,
        PathBuf::from("/private/relay/ca.pem"),
        CredentialId::parse(&identity('2')).expect("child"),
        PathBuf::from("/private/relay/child.pem"),
        Sha256Digest::parse(&"3".repeat(64)).expect("digest"),
        CredentialId::parse(&identity('4')).expect("main"),
        PathBuf::from("/private/relay/main.pem"),
        PathBuf::from("/private/relay/main.key"),
    )
    .is_err());
    assert!(NodeGatewayRelayCredentialReferences::new(
        CredentialId::parse(&identity('1')).expect("relay"),
        PathBuf::from("relative/bearer"),
        CredentialId::parse(&identity('2')).expect("CA"),
        PathBuf::from("/private/relay/ca.pem"),
        CredentialId::parse(&identity('3')).expect("child"),
        PathBuf::from("/private/relay/child.pem"),
        Sha256Digest::parse(&"4".repeat(64)).expect("digest"),
        CredentialId::parse(&identity('5')).expect("main"),
        PathBuf::from("/private/relay/main.pem"),
        PathBuf::from("/private/relay/main.key"),
    )
    .is_err());
}
