// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{
    CredentialId, InstallationId, MachineId, Node, NodeAddress, NodeId, NodeIdentity, NodeRole,
    NodeState, PlacementGroupId, Sha256Digest, TokenCountContract, TokenCountProtocol,
    UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision, DatabaseTransaction,
};
use li_gateway_manager::{
    GatewayError, GatewayNativeFileIo, GatewayNativeIoError, GatewayNativeTarget,
    GatewayRelayAuthorizationProvider, LETSINFER_RELAY_TOKEN_COUNT_PATH,
};
use serde::{Deserialize, Serialize};

use crate::{NodeGatewayRelayTargetProvider, NodeManager};

pub const LETSINFER_PRIVATE_GATEWAY_PORT: u16 = 9_444;
const RELAY_TRUST_SCHEMA_NAME: &str = "letsinfer.node-gateway-relay-trust";
const RELAY_TRUST_SCHEMA_VERSION: u32 = 1;
const RELAY_TRUST_RECORD_PREFIX: &str = "li_gateway_relay_trust_v1_";
const MAX_RELAY_BEARER_BYTES: usize = 512;

// Identifies whether one enrolled child trust is usable or terminally revoked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeGatewayRelayTrustState {
    Active,
    Revoked,
}

// Carries only credential identities, file references, and public certificate digests.
#[derive(Clone, Eq, PartialEq)]
pub struct NodeGatewayRelayCredentialReferences {
    relay_credential_id: CredentialId,
    relay_bearer_file: PathBuf,
    site_ca_credential_id: CredentialId,
    site_ca_certificate_file: PathBuf,
    child_leaf_credential_id: CredentialId,
    child_leaf_certificate_file: PathBuf,
    child_leaf_certificate_sha256: Sha256Digest,
    main_leaf_credential_id: CredentialId,
    main_leaf_certificate_file: PathBuf,
    main_leaf_private_key_file: PathBuf,
}

impl NodeGatewayRelayCredentialReferences {
    // Creates one complete reference-only relay credential set without reading secret bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay_credential_id: CredentialId,
        relay_bearer_file: PathBuf,
        site_ca_credential_id: CredentialId,
        site_ca_certificate_file: PathBuf,
        child_leaf_credential_id: CredentialId,
        child_leaf_certificate_file: PathBuf,
        child_leaf_certificate_sha256: Sha256Digest,
        main_leaf_credential_id: CredentialId,
        main_leaf_certificate_file: PathBuf,
        main_leaf_private_key_file: PathBuf,
    ) -> Result<Self, NodeGatewayRelayTrustError> {
        let credential_ids = [
            &relay_credential_id,
            &site_ca_credential_id,
            &child_leaf_credential_id,
            &main_leaf_credential_id,
        ];
        let paths = [
            relay_bearer_file.as_path(),
            site_ca_certificate_file.as_path(),
            child_leaf_certificate_file.as_path(),
            main_leaf_certificate_file.as_path(),
            main_leaf_private_key_file.as_path(),
        ];
        if credential_ids
            .iter()
            .enumerate()
            .any(|(index, value)| credential_ids[..index].contains(value))
            || paths
                .iter()
                .enumerate()
                .any(|(index, value)| paths[..index].contains(value))
            || paths.iter().any(|path| !valid_private_path(path))
        {
            return Err(NodeGatewayRelayTrustError::InvalidContract {
                reason: "relay credential identities or file references are ambiguous",
            });
        }
        Ok(Self {
            relay_credential_id,
            relay_bearer_file,
            site_ca_credential_id,
            site_ca_certificate_file,
            child_leaf_credential_id,
            child_leaf_certificate_file,
            child_leaf_certificate_sha256,
            main_leaf_credential_id,
            main_leaf_certificate_file,
            main_leaf_private_key_file,
        })
    }

    // Returns the bearer credential identity without exposing its secret bytes.
    pub const fn relay_credential_id(&self) -> &CredentialId {
        &self.relay_credential_id
    }

    // Returns the private bearer file reference consumed only by native Gateway I/O.
    pub fn relay_bearer_file(&self) -> &Path {
        &self.relay_bearer_file
    }

    // Returns the site CA credential identity.
    pub const fn site_ca_credential_id(&self) -> &CredentialId {
        &self.site_ca_credential_id
    }

    // Returns the exact site CA certificate reference.
    pub fn site_ca_certificate_file(&self) -> &Path {
        &self.site_ca_certificate_file
    }

    // Returns the enrolled child leaf credential identity.
    pub const fn child_leaf_credential_id(&self) -> &CredentialId {
        &self.child_leaf_credential_id
    }

    // Returns the enrolled child leaf certificate reference for exact server pinning.
    pub fn child_leaf_certificate_file(&self) -> &Path {
        &self.child_leaf_certificate_file
    }

    // Returns the enrolled child leaf certificate digest for exact server pinning.
    pub const fn child_leaf_certificate_sha256(&self) -> &Sha256Digest {
        &self.child_leaf_certificate_sha256
    }

    // Returns the outbound main leaf credential identity.
    pub const fn main_leaf_credential_id(&self) -> &CredentialId {
        &self.main_leaf_credential_id
    }

    // Returns the outbound main leaf certificate reference.
    pub fn main_leaf_certificate_file(&self) -> &Path {
        &self.main_leaf_certificate_file
    }

    // Returns the outbound main leaf private-key reference without reading its bytes.
    pub fn main_leaf_private_key_file(&self) -> &Path {
        &self.main_leaf_private_key_file
    }
}

impl fmt::Debug for NodeGatewayRelayCredentialReferences {
    // Presents reference identities while redacting every credential path.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeGatewayRelayCredentialReferences")
            .field("relay_credential_id", &self.relay_credential_id)
            .field("relay_bearer_file", &"<private-path>")
            .field("site_ca_credential_id", &self.site_ca_credential_id)
            .field("site_ca_certificate_file", &"<private-path>")
            .field("child_leaf_credential_id", &self.child_leaf_credential_id)
            .field("child_leaf_certificate_file", &"<private-path>")
            .field(
                "child_leaf_certificate_sha256",
                &self.child_leaf_certificate_sha256,
            )
            .field("main_leaf_credential_id", &self.main_leaf_credential_id)
            .field("main_leaf_certificate_file", &"<private-path>")
            .field("main_leaf_private_key_file", &"<private-path>")
            .finish()
    }
}

// Binds one pairing receipt to exact main, child, address, validity, and credential references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeGatewayRelayTrust {
    membership_receipt_sha256: Sha256Digest,
    main_identity: NodeIdentity,
    child_identity: NodeIdentity,
    child_address: NodeAddress,
    generation: NonZeroU64,
    issued_at: UnixMilliseconds,
    expires_at: UnixMilliseconds,
    state: NodeGatewayRelayTrustState,
    credentials: NodeGatewayRelayCredentialReferences,
}

impl NodeGatewayRelayTrust {
    // Creates one closed persisted trust projection from a completed pairing lifecycle.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        membership_receipt_sha256: Sha256Digest,
        main_identity: NodeIdentity,
        child_identity: NodeIdentity,
        child_address: NodeAddress,
        generation: NonZeroU64,
        issued_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
        state: NodeGatewayRelayTrustState,
        credentials: NodeGatewayRelayCredentialReferences,
    ) -> Result<Self, NodeGatewayRelayTrustError> {
        if main_identity.node_id() == child_identity.node_id()
            || main_identity.machine_id() == child_identity.machine_id()
            || main_identity.installation_id() == child_identity.installation_id()
            || issued_at.value() >= expires_at.value()
        {
            return Err(NodeGatewayRelayTrustError::InvalidContract {
                reason: "relay trust identities or validity window are incoherent",
            });
        }
        Ok(Self {
            membership_receipt_sha256,
            main_identity,
            child_identity,
            child_address,
            generation,
            issued_at,
            expires_at,
            state,
            credentials,
        })
    }

    // Returns the signed pairing receipt digest that established this trust.
    pub const fn membership_receipt_sha256(&self) -> &Sha256Digest {
        &self.membership_receipt_sha256
    }

    // Returns the exact main installation authorized to relay.
    pub const fn main_identity(&self) -> &NodeIdentity {
        &self.main_identity
    }

    // Returns the exact enrolled child installation accepting the relay.
    pub const fn child_identity(&self) -> &NodeIdentity {
        &self.child_identity
    }

    // Returns the exact private child Gateway address.
    pub const fn child_address(&self) -> &NodeAddress {
        &self.child_address
    }

    // Returns the monotonic trust generation bound to its database revision.
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    // Returns when this pairing trust first becomes usable.
    pub const fn issued_at(&self) -> UnixMilliseconds {
        self.issued_at
    }

    // Returns the exclusive upper validity boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns whether this trust remains active or was terminally revoked.
    pub const fn state(&self) -> NodeGatewayRelayTrustState {
        self.state
    }

    // Returns reference-only credential bindings without secret bytes.
    pub const fn credentials(&self) -> &NodeGatewayRelayCredentialReferences {
        &self.credentials
    }

    // Creates the next terminal revocation while preserving exact membership identity.
    pub fn revoked(&self, generation: NonZeroU64) -> Result<Self, NodeGatewayRelayTrustError> {
        if self.state == NodeGatewayRelayTrustState::Revoked
            || generation.get() != self.generation.get().saturating_add(1)
        {
            return Err(NodeGatewayRelayTrustError::Conflict);
        }
        Ok(Self {
            membership_receipt_sha256: self.membership_receipt_sha256.clone(),
            main_identity: self.main_identity.clone(),
            child_identity: self.child_identity.clone(),
            child_address: self.child_address.clone(),
            generation,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            state: NodeGatewayRelayTrustState::Revoked,
            credentials: self.credentials.clone(),
        })
    }
}

// Carries one validated trust together with its optimistic database revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedNodeGatewayRelayTrust {
    trust: NodeGatewayRelayTrust,
    revision: u64,
}

impl VersionedNodeGatewayRelayTrust {
    // Creates one versioned trust observation for production stores or deterministic mocks.
    pub const fn new(trust: NodeGatewayRelayTrust, revision: u64) -> Self {
        Self { trust, revision }
    }

    // Returns the validated trust value.
    pub const fn trust(&self) -> &NodeGatewayRelayTrust {
        &self.trust
    }

    // Returns the optimistic persistence revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Describes stable trust persistence failures without credential or path disclosure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeGatewayRelayTrustError {
    InvalidContract { reason: &'static str },
    Conflict,
    Corrupt,
    Unavailable,
}

impl fmt::Display for NodeGatewayRelayTrustError {
    // Presents stable redacted relay-trust failure language.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { reason } => {
                write!(formatter, "relay trust is invalid: {reason}")
            }
            Self::Conflict => formatter.write_str("relay trust changed concurrently"),
            Self::Corrupt => formatter.write_str("relay trust state is corrupt"),
            Self::Unavailable => formatter.write_str("relay trust state is unavailable"),
        }
    }
}

impl Error for NodeGatewayRelayTrustError {}

// Reads one authoritative persisted pairing trust without owning routing policy.
pub trait NodeGatewayRelayTrustStore: Send + Sync {
    // Returns the exact current trust generation for one child when present.
    fn read(
        &self,
        child_node_id: &NodeId,
    ) -> Result<Option<VersionedNodeGatewayRelayTrust>, NodeGatewayRelayTrustError>;
}

// Supplies current NodeManager identity and membership state through a narrow read-only port.
pub trait NodeGatewayRelayNodeProvider: Send + Sync {
    // Returns the current local node snapshot.
    fn local_node(&self) -> Result<Node, GatewayNativeIoError>;

    // Returns one current enrolled child snapshot or explicit absence.
    fn node(&self, node_id: &NodeId) -> Result<Option<Node>, GatewayNativeIoError>;
}

impl NodeGatewayRelayNodeProvider for NodeManager {
    // Returns the current local NodeManager snapshot without exposing database mechanics.
    fn local_node(&self) -> Result<Node, GatewayNativeIoError> {
        NodeManager::local_node(self).map_err(|_| relay_target_error())
    }

    // Returns one current enrolled NodeManager snapshot or explicit absence.
    fn node(&self, node_id: &NodeId) -> Result<Option<Node>, GatewayNativeIoError> {
        match NodeManager::node(self, node_id) {
            Ok(change) => Ok(Some(change.value().clone())),
            Err(crate::NodeManagerError::Database(DatabaseError::NotFound { .. })) => Ok(None),
            Err(_) => Err(relay_target_error()),
        }
    }
}

// Supplies current time explicitly for deterministic validity-window checks.
pub trait NodeGatewayRelayClock: Send + Sync {
    // Returns current non-negative Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, GatewayNativeIoError>;
}

// Reads production relay time from the active host.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemNodeGatewayRelayClock;

impl NodeGatewayRelayClock for SystemNodeGatewayRelayClock {
    // Returns current host time without accepting a pre-epoch clock.
    fn now(&self) -> Result<UnixMilliseconds, GatewayNativeIoError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| relay_target_error())?;
        let milliseconds = u64::try_from(duration.as_millis()).map_err(|_| relay_target_error())?;
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Returns one native relay plus the exact child leaf identity required by TLS pinning.
#[derive(Clone, Eq, PartialEq)]
pub struct NodeGatewayRelayTarget {
    native_target: GatewayNativeTarget,
    child_node_id: NodeId,
    child_address: NodeAddress,
    child_leaf_credential_id: CredentialId,
    child_leaf_certificate_file: PathBuf,
    child_leaf_certificate_sha256: Sha256Digest,
}

impl NodeGatewayRelayTarget {
    // Creates one complete relay result after Node, trust, and native references agree.
    pub fn new(
        native_target: GatewayNativeTarget,
        child_node_id: NodeId,
        child_address: NodeAddress,
        child_leaf_credential_id: CredentialId,
        child_leaf_certificate_file: PathBuf,
        child_leaf_certificate_sha256: Sha256Digest,
    ) -> Result<Self, GatewayNativeIoError> {
        if !valid_private_path(&child_leaf_certificate_file) {
            return Err(relay_target_error());
        }
        Ok(Self {
            native_target,
            child_node_id,
            child_address,
            child_leaf_credential_id,
            child_leaf_certificate_file,
            child_leaf_certificate_sha256,
        })
    }

    // Returns the native target carrying the same exact child server-leaf pin.
    pub const fn native_target(&self) -> &GatewayNativeTarget {
        &self.native_target
    }

    // Transfers native target ownership to the Gateway adapter.
    pub fn into_native_target(self) -> GatewayNativeTarget {
        self.native_target
    }

    // Returns the exact child node identity bound by pairing trust.
    pub const fn child_node_id(&self) -> &NodeId {
        &self.child_node_id
    }

    // Returns the exact child address bound by pairing trust.
    pub const fn child_address(&self) -> &NodeAddress {
        &self.child_address
    }

    // Returns the enrolled child leaf credential identity.
    pub const fn child_leaf_credential_id(&self) -> &CredentialId {
        &self.child_leaf_credential_id
    }

    // Returns the enrolled child leaf certificate reference.
    pub fn child_leaf_certificate_file(&self) -> &Path {
        &self.child_leaf_certificate_file
    }

    // Returns the enrolled child leaf digest required for exact TLS pinning.
    pub const fn child_leaf_certificate_sha256(&self) -> &Sha256Digest {
        &self.child_leaf_certificate_sha256
    }
}

impl fmt::Debug for NodeGatewayRelayTarget {
    // Presents child identity and digest while redacting every credential path.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeGatewayRelayTarget")
            .field("native_target", &"<private-references>")
            .field("child_node_id", &self.child_node_id)
            .field("child_address", &self.child_address)
            .field("child_leaf_credential_id", &self.child_leaf_credential_id)
            .field("child_leaf_certificate_file", &"<private-path>")
            .field(
                "child_leaf_certificate_sha256",
                &self.child_leaf_certificate_sha256,
            )
            .finish()
    }
}

// Resolves one child relay only after live Node state and persisted pairing trust agree.
pub struct PersistedNodeGatewayRelayTargetProvider {
    owner_user_id: u32,
    nodes: Arc<dyn NodeGatewayRelayNodeProvider>,
    trust: Arc<dyn NodeGatewayRelayTrustStore>,
    clock: Arc<dyn NodeGatewayRelayClock>,
}

// Authenticates inbound main relays against exact active child trust and private bearer bytes.
pub struct PersistedNodeGatewayRelayAuthorizationProvider {
    owner_user_id: u32,
    nodes: Arc<dyn NodeGatewayRelayNodeProvider>,
    trust: Arc<dyn NodeGatewayRelayTrustStore>,
    clock: Arc<dyn NodeGatewayRelayClock>,
    files: Arc<dyn GatewayNativeFileIo>,
}

impl PersistedNodeGatewayRelayAuthorizationProvider {
    // Creates one inbound relay authority from Node-owned identity and trust references.
    pub const fn new(
        owner_user_id: u32,
        nodes: Arc<dyn NodeGatewayRelayNodeProvider>,
        trust: Arc<dyn NodeGatewayRelayTrustStore>,
        clock: Arc<dyn NodeGatewayRelayClock>,
        files: Arc<dyn GatewayNativeFileIo>,
    ) -> Self {
        Self {
            owner_user_id,
            nodes,
            trust,
            clock,
            files,
        }
    }

    // Resolves one exact active child-to-main trust before reading bearer material.
    fn active_trust(&self) -> Result<NodeGatewayRelayTrust, GatewayError> {
        let child = self.nodes.local_node().map_err(|_| relay_denied())?;
        if child.role() != NodeRole::Child || child.state() != NodeState::Active {
            return Err(relay_denied());
        }
        let versioned = self
            .trust
            .read(child.identity().node_id())
            .map_err(|_| relay_denied())?
            .ok_or_else(relay_denied)?;
        let trust = versioned.trust();
        let main = self
            .nodes
            .node(trust.main_identity().node_id())
            .map_err(|_| relay_denied())?
            .ok_or_else(relay_denied)?;
        let now = self.clock.now().map_err(|_| relay_denied())?;
        if trust.state() != NodeGatewayRelayTrustState::Active
            || trust.generation().get() != versioned.revision()
            || trust.child_identity() != child.identity()
            || trust.main_identity() != main.identity()
            || main.role() != NodeRole::Main
            || main.state() != NodeState::Active
            || now.value() < trust.issued_at().value()
            || now.value() >= trust.expires_at().value()
        {
            return Err(relay_denied());
        }
        Ok(trust.clone())
    }
}

impl GatewayRelayAuthorizationProvider for PersistedNodeGatewayRelayAuthorizationProvider {
    // Verifies one bounded relay credential in constant time and returns its exact main identity.
    fn authorize(&self, relay_credential: &str) -> Result<NodeId, GatewayError> {
        let trust = self.active_trust()?;
        let file = self
            .files
            .read_no_follow(
                trust.credentials().relay_bearer_file(),
                MAX_RELAY_BEARER_BYTES,
            )
            .map_err(|_| relay_denied())?;
        if file.owner_user_id() != self.owner_user_id
            || file.mode() != 0o600
            || file.link_count() != 1
        {
            return Err(relay_denied());
        }
        let stored = std::str::from_utf8(file.bytes())
            .map_err(|_| relay_denied())?
            .trim_end_matches(['\r', '\n']);
        if stored.len() < 32
            || stored.len() > MAX_RELAY_BEARER_BYTES
            || !stored.is_ascii()
            || stored.chars().any(char::is_whitespace)
            || !constant_time_equal(stored.as_bytes(), relay_credential.as_bytes())
        {
            return Err(relay_denied());
        }
        Ok(trust.main_identity().node_id().clone())
    }
}

impl PersistedNodeGatewayRelayTargetProvider {
    // Creates one production relay resolver from explicit Node, trust, and clock owners.
    pub const fn new(
        owner_user_id: u32,
        nodes: Arc<dyn NodeGatewayRelayNodeProvider>,
        trust: Arc<dyn NodeGatewayRelayTrustStore>,
        clock: Arc<dyn NodeGatewayRelayClock>,
    ) -> Self {
        Self {
            owner_user_id,
            nodes,
            trust,
            clock,
        }
    }

    // Requires exact active main and child membership before consulting credential references.
    fn nodes(
        &self,
        child_node_id: &NodeId,
        address: &NodeAddress,
    ) -> Result<(Node, Node), GatewayNativeIoError> {
        let main = self.nodes.local_node()?;
        let child = self
            .nodes
            .node(child_node_id)?
            .ok_or_else(relay_target_error)?;
        if main.role() != NodeRole::Main
            || main.state() != NodeState::Active
            || child.role() != NodeRole::Child
            || child.state() != NodeState::Active
            || child.identity().node_id() != child_node_id
            || child.control_address() != address
        {
            return Err(relay_target_error());
        }
        Ok((main, child))
    }

    // Requires one current non-replayed trust generation bound to exact live membership.
    fn trust(
        &self,
        main: &Node,
        child: &Node,
        address: &NodeAddress,
    ) -> Result<NodeGatewayRelayTrust, GatewayNativeIoError> {
        let versioned = self
            .trust
            .read(child.identity().node_id())
            .map_err(|_| relay_target_error())?
            .ok_or_else(relay_target_error)?;
        let trust = versioned.trust();
        let now = self.clock.now()?;
        if trust.state() != NodeGatewayRelayTrustState::Active
            || trust.generation().get() != versioned.revision()
            || trust.main_identity() != main.identity()
            || trust.child_identity() != child.identity()
            || trust.child_address() != address
            || now.value() < trust.issued_at().value()
            || now.value() >= trust.expires_at().value()
        {
            return Err(relay_target_error());
        }
        Ok(trust.clone())
    }

    // Projects one validated trust into native references and a fixed Core token-count contract.
    fn relay_target(
        &self,
        trust: NodeGatewayRelayTrust,
    ) -> Result<NodeGatewayRelayTarget, GatewayNativeIoError> {
        let credentials = trust.credentials();
        let token_count = TokenCountContract::new(
            LETSINFER_RELAY_TOKEN_COUNT_PATH,
            TokenCountProtocol::LetsInferV1,
        )
        .map_err(|_| relay_target_error())?;
        let native_target = GatewayNativeTarget::child_relay(
            trust.child_address().as_str(),
            LETSINFER_PRIVATE_GATEWAY_PORT,
            self.owner_user_id,
            credentials.relay_bearer_file().to_path_buf(),
            credentials.site_ca_certificate_file().to_path_buf(),
            credentials.child_leaf_certificate_sha256().clone(),
            credentials.main_leaf_certificate_file().to_path_buf(),
            credentials.main_leaf_private_key_file().to_path_buf(),
            Some(token_count),
        )?;
        NodeGatewayRelayTarget::new(
            native_target,
            trust.child_identity().node_id().clone(),
            trust.child_address().clone(),
            credentials.child_leaf_credential_id().clone(),
            credentials.child_leaf_certificate_file().to_path_buf(),
            credentials.child_leaf_certificate_sha256().clone(),
        )
    }
}

impl NodeGatewayRelayTargetProvider for PersistedNodeGatewayRelayTargetProvider {
    // Resolves one relay while deliberately replacing the Engine token path with Core's fixed path.
    fn target(
        &self,
        _placement_group_id: &PlacementGroupId,
        child_node_id: &NodeId,
        address: &NodeAddress,
        _engine_token_count: Option<TokenCountContract>,
    ) -> Result<NodeGatewayRelayTarget, GatewayNativeIoError> {
        let (main, child) = self.nodes(child_node_id, address)?;
        let trust = self.trust(&main, &child, address)?;
        self.relay_target(trust)
    }
}

// Stores one closed reference-only trust projection in DatabaseManager configuration state.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeGatewayRelayTrustDatabaseRecord {
    record_id: String,
    schema_name: String,
    schema_version: u32,
    membership_receipt_sha256: String,
    main_node_id: String,
    main_machine_id: String,
    main_installation_id: String,
    child_node_id: String,
    child_machine_id: String,
    child_installation_id: String,
    child_address: String,
    generation: u64,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    state: String,
    relay_credential_id: String,
    relay_bearer_file: String,
    site_ca_credential_id: String,
    site_ca_certificate_file: String,
    child_leaf_credential_id: String,
    child_leaf_certificate_file: String,
    child_leaf_certificate_sha256: String,
    main_leaf_credential_id: String,
    main_leaf_certificate_file: String,
    main_leaf_private_key_file: String,
}

impl DatabaseRecord for NodeGatewayRelayTrustDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Configuration;

    // Returns the child-scoped singleton trust identity.
    fn identifier(&self) -> &str {
        &self.record_id
    }
}

// Persists pairing trust generations without storing bearer or private-key bytes.
pub struct DatabaseNodeGatewayRelayTrustStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseNodeGatewayRelayTrustStore {
    // Creates one relay-trust adapter without taking DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Appends one active generation-one trust to a caller-owned atomic transaction.
    pub fn creating_transaction(
        &self,
        transaction: DatabaseTransaction,
        trust: &NodeGatewayRelayTrust,
    ) -> Result<DatabaseTransaction, NodeGatewayRelayTrustError> {
        if trust.generation().get() != 1 || trust.state() != NodeGatewayRelayTrustState::Active {
            return Err(NodeGatewayRelayTrustError::InvalidContract {
                reason: "new relay trust must be active generation one",
            });
        }
        transaction
            .save(trust_database_record(trust)?, DatabaseRevision::Missing)
            .map_err(trust_database_error)
    }

    // Creates generation one and treats only an exact database replay as idempotent.
    pub fn create(
        &self,
        trust: NodeGatewayRelayTrust,
    ) -> Result<VersionedNodeGatewayRelayTrust, NodeGatewayRelayTrustError> {
        if trust.generation().get() != 1 || trust.state() != NodeGatewayRelayTrustState::Active {
            return Err(NodeGatewayRelayTrustError::InvalidContract {
                reason: "new relay trust must be active generation one",
            });
        }
        self.write(trust, DatabaseRevision::Missing, "create")
    }

    // Replaces one exact generation while preventing identity changes or revocation rollback.
    pub fn replace(
        &self,
        trust: NodeGatewayRelayTrust,
        expected_revision: u64,
    ) -> Result<VersionedNodeGatewayRelayTrust, NodeGatewayRelayTrustError> {
        let current = self
            .read(trust.child_identity().node_id())?
            .ok_or(NodeGatewayRelayTrustError::Conflict)?;
        if current.revision() != expected_revision
            || trust.generation().get() != expected_revision.saturating_add(1)
            || current.trust().main_identity() != trust.main_identity()
            || current.trust().child_identity() != trust.child_identity()
            || current.trust().state() == NodeGatewayRelayTrustState::Revoked
        {
            return Err(NodeGatewayRelayTrustError::Conflict);
        }
        self.write(trust, DatabaseRevision::Exact(expected_revision), "replace")
    }

    // Commits the next terminal revoked generation for one current active trust.
    pub fn revoke(
        &self,
        child_node_id: &NodeId,
        expected_revision: u64,
    ) -> Result<VersionedNodeGatewayRelayTrust, NodeGatewayRelayTrustError> {
        let current = self
            .read(child_node_id)?
            .ok_or(NodeGatewayRelayTrustError::Conflict)?;
        if current.revision() != expected_revision {
            return Err(NodeGatewayRelayTrustError::Conflict);
        }
        let generation = NonZeroU64::new(expected_revision.saturating_add(1))
            .ok_or(NodeGatewayRelayTrustError::Conflict)?;
        self.replace(current.trust().revoked(generation)?, expected_revision)
    }

    // Writes one validated generation through optimistic and idempotent database semantics.
    fn write(
        &self,
        trust: NodeGatewayRelayTrust,
        expected_revision: DatabaseRevision,
        action: &str,
    ) -> Result<VersionedNodeGatewayRelayTrust, NodeGatewayRelayTrustError> {
        let idempotency_key = format!(
            "gateway-relay-trust:{action}:{}:{}:{}",
            trust.child_identity().node_id().as_str(),
            trust.generation(),
            trust.membership_receipt_sha256().as_str()
        );
        let result = self
            .database
            .write(DatabaseCommand::save(
                idempotency_key,
                trust_database_record(&trust)?,
                expected_revision,
            ))
            .map_err(trust_database_error)?;
        if result.commit().identifier != relay_trust_record_id(trust.child_identity().node_id())
            || result.commit().collection != DatabaseCollection::Configuration
            || result.commit().revision != trust.generation().get()
            || !matches!(
                result.disposition(),
                DatabaseCommitDisposition::Applied | DatabaseCommitDisposition::Replayed
            )
        {
            return Err(NodeGatewayRelayTrustError::Corrupt);
        }
        Ok(VersionedNodeGatewayRelayTrust::new(
            trust,
            result.commit().revision,
        ))
    }
}

impl NodeGatewayRelayTrustStore for DatabaseNodeGatewayRelayTrustStore {
    // Reads and validates one exact child trust while rejecting generation replay.
    fn read(
        &self,
        child_node_id: &NodeId,
    ) -> Result<Option<VersionedNodeGatewayRelayTrust>, NodeGatewayRelayTrustError> {
        match self.database.read(
            DatabaseQuery::<NodeGatewayRelayTrustDatabaseRecord>::record(relay_trust_record_id(
                child_node_id,
            )),
        ) {
            Ok(DatabaseResult::Record(stored)) => {
                let trust = trust_from_database_record(stored.value)?;
                if trust.child_identity().node_id() != child_node_id
                    || trust.generation().get() != stored.revision
                {
                    return Err(NodeGatewayRelayTrustError::Corrupt);
                }
                Ok(Some(VersionedNodeGatewayRelayTrust::new(
                    trust,
                    stored.revision,
                )))
            }
            Ok(DatabaseResult::Records(_)) => Err(NodeGatewayRelayTrustError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(trust_database_error(error)),
        }
    }
}

// Projects one validated trust into closed reference-only database fields.
fn trust_database_record(
    trust: &NodeGatewayRelayTrust,
) -> Result<NodeGatewayRelayTrustDatabaseRecord, NodeGatewayRelayTrustError> {
    let credentials = trust.credentials();
    Ok(NodeGatewayRelayTrustDatabaseRecord {
        record_id: relay_trust_record_id(trust.child_identity().node_id()),
        schema_name: RELAY_TRUST_SCHEMA_NAME.to_string(),
        schema_version: RELAY_TRUST_SCHEMA_VERSION,
        membership_receipt_sha256: trust.membership_receipt_sha256().as_str().to_string(),
        main_node_id: trust.main_identity().node_id().as_str().to_string(),
        main_machine_id: trust.main_identity().machine_id().as_str().to_string(),
        main_installation_id: trust.main_identity().installation_id().as_str().to_string(),
        child_node_id: trust.child_identity().node_id().as_str().to_string(),
        child_machine_id: trust.child_identity().machine_id().as_str().to_string(),
        child_installation_id: trust
            .child_identity()
            .installation_id()
            .as_str()
            .to_string(),
        child_address: trust.child_address().as_str().to_string(),
        generation: trust.generation().get(),
        issued_at_unix_milliseconds: trust.issued_at().value(),
        expires_at_unix_milliseconds: trust.expires_at().value(),
        state: trust_state_name(trust.state()).to_string(),
        relay_credential_id: credentials.relay_credential_id().as_str().to_string(),
        relay_bearer_file: path_text(credentials.relay_bearer_file())?,
        site_ca_credential_id: credentials.site_ca_credential_id().as_str().to_string(),
        site_ca_certificate_file: path_text(credentials.site_ca_certificate_file())?,
        child_leaf_credential_id: credentials.child_leaf_credential_id().as_str().to_string(),
        child_leaf_certificate_file: path_text(credentials.child_leaf_certificate_file())?,
        child_leaf_certificate_sha256: credentials
            .child_leaf_certificate_sha256()
            .as_str()
            .to_string(),
        main_leaf_credential_id: credentials.main_leaf_credential_id().as_str().to_string(),
        main_leaf_certificate_file: path_text(credentials.main_leaf_certificate_file())?,
        main_leaf_private_key_file: path_text(credentials.main_leaf_private_key_file())?,
    })
}

// Reconstructs one validated trust from closed database fields.
fn trust_from_database_record(
    record: NodeGatewayRelayTrustDatabaseRecord,
) -> Result<NodeGatewayRelayTrust, NodeGatewayRelayTrustError> {
    let child_node_id = node_id(&record.child_node_id)?;
    if record.schema_name != RELAY_TRUST_SCHEMA_NAME
        || record.schema_version != RELAY_TRUST_SCHEMA_VERSION
        || record.record_id != relay_trust_record_id(&child_node_id)
    {
        return Err(NodeGatewayRelayTrustError::Corrupt);
    }
    let credentials = NodeGatewayRelayCredentialReferences::new(
        credential_id(&record.relay_credential_id)?,
        PathBuf::from(record.relay_bearer_file),
        credential_id(&record.site_ca_credential_id)?,
        PathBuf::from(record.site_ca_certificate_file),
        credential_id(&record.child_leaf_credential_id)?,
        PathBuf::from(record.child_leaf_certificate_file),
        digest(&record.child_leaf_certificate_sha256)?,
        credential_id(&record.main_leaf_credential_id)?,
        PathBuf::from(record.main_leaf_certificate_file),
        PathBuf::from(record.main_leaf_private_key_file),
    )?;
    NodeGatewayRelayTrust::new(
        digest(&record.membership_receipt_sha256)?,
        NodeIdentity::new(
            node_id(&record.main_node_id)?,
            machine_id(&record.main_machine_id)?,
            installation_id(&record.main_installation_id)?,
        ),
        NodeIdentity::new(
            child_node_id,
            machine_id(&record.child_machine_id)?,
            installation_id(&record.child_installation_id)?,
        ),
        NodeAddress::parse(&record.child_address)
            .map_err(|_| NodeGatewayRelayTrustError::Corrupt)?,
        NonZeroU64::new(record.generation).ok_or(NodeGatewayRelayTrustError::Corrupt)?,
        UnixMilliseconds::new(record.issued_at_unix_milliseconds),
        UnixMilliseconds::new(record.expires_at_unix_milliseconds),
        trust_state(&record.state)?,
        credentials,
    )
    .map_err(|_| NodeGatewayRelayTrustError::Corrupt)
}

// Returns the child-scoped singleton record identity.
fn relay_trust_record_id(child_node_id: &NodeId) -> String {
    format!("{RELAY_TRUST_RECORD_PREFIX}{}", child_node_id.as_str())
}

// Returns the closed persistence spelling for one trust state.
const fn trust_state_name(state: NodeGatewayRelayTrustState) -> &'static str {
    match state {
        NodeGatewayRelayTrustState::Active => "active",
        NodeGatewayRelayTrustState::Revoked => "revoked",
    }
}

// Parses one closed trust-state persistence value.
fn trust_state(value: &str) -> Result<NodeGatewayRelayTrustState, NodeGatewayRelayTrustError> {
    match value {
        "active" => Ok(NodeGatewayRelayTrustState::Active),
        "revoked" => Ok(NodeGatewayRelayTrustState::Revoked),
        _ => Err(NodeGatewayRelayTrustError::Corrupt),
    }
}

// Requires one absolute bounded UTF-8 path without parent traversal.
fn valid_private_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4096
        && path.to_str().is_some()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

// Returns one validated path as private database text.
fn path_text(path: &Path) -> Result<String, NodeGatewayRelayTrustError> {
    if !valid_private_path(path) {
        return Err(NodeGatewayRelayTrustError::InvalidContract {
            reason: "relay credential file reference is invalid",
        });
    }
    path.to_str()
        .map(ToString::to_string)
        .ok_or(NodeGatewayRelayTrustError::Corrupt)
}

// Parses one node identity while mapping external values to closed corruption.
fn node_id(value: &str) -> Result<NodeId, NodeGatewayRelayTrustError> {
    NodeId::parse(value).map_err(|_| NodeGatewayRelayTrustError::Corrupt)
}

// Parses one machine identity while mapping external values to closed corruption.
fn machine_id(value: &str) -> Result<MachineId, NodeGatewayRelayTrustError> {
    MachineId::parse(value).map_err(|_| NodeGatewayRelayTrustError::Corrupt)
}

// Parses one installation identity while mapping external values to closed corruption.
fn installation_id(value: &str) -> Result<InstallationId, NodeGatewayRelayTrustError> {
    InstallationId::parse(value).map_err(|_| NodeGatewayRelayTrustError::Corrupt)
}

// Parses one credential identity while mapping external values to closed corruption.
fn credential_id(value: &str) -> Result<CredentialId, NodeGatewayRelayTrustError> {
    CredentialId::parse(value).map_err(|_| NodeGatewayRelayTrustError::Corrupt)
}

// Parses one SHA-256 identity while mapping external values to closed corruption.
fn digest(value: &str) -> Result<Sha256Digest, NodeGatewayRelayTrustError> {
    Sha256Digest::parse(value).map_err(|_| NodeGatewayRelayTrustError::Corrupt)
}

// Maps DatabaseManager failures without leaking record contents or private paths.
fn trust_database_error(error: DatabaseError) -> NodeGatewayRelayTrustError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            NodeGatewayRelayTrustError::Conflict
        }
        DatabaseError::Corrupt { .. } => NodeGatewayRelayTrustError::Corrupt,
        _ => NodeGatewayRelayTrustError::Unavailable,
    }
}

// Returns one stable redacted relay resolution failure before any response output.
fn relay_target_error() -> GatewayNativeIoError {
    GatewayNativeIoError::terminal_before_head("child relay trust is unavailable or changed")
}

// Compares bounded secret bytes without revealing the first differing position.
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let left_byte = left.get(index).copied().unwrap_or_default();
        let right_byte = right.get(index).copied().unwrap_or_default();
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

// Returns the one indistinguishable relay authorization failure.
fn relay_denied() -> GatewayError {
    GatewayError::RelayDenied
}
