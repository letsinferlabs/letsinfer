// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};

use li_authentication_manager::{
    ApiKey, ApiKeyLimits, ApiKeyModelScope, ApiKeyPolicy, AuthenticationError,
    AuthenticationManager, Controller, ControllerCertificateSource, ControllerError,
    ControllerPublicKey, ControllerRole, ControllerState,
};
use li_core_interface::{
    ApiKeyId, ControllerId, DisplayName, LogicalModelName, Sha256Digest, TechnicalName,
    UnixMilliseconds,
};

// Carries one proof-validated controller candidate without private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeControllerEnrollmentCandidate {
    controller_id: ControllerId,
    name: DisplayName,
    public_key: ControllerPublicKey,
}

impl NodeControllerEnrollmentCandidate {
    // Creates one candidate after an enrollment provider has verified public-key possession.
    pub const fn new(
        controller_id: ControllerId,
        name: DisplayName,
        public_key: ControllerPublicKey,
    ) -> Self {
        Self {
            controller_id,
            name,
            public_key,
        }
    }

    // Returns the stable controller identity asserted by the enrollment proof.
    pub const fn controller_id(&self) -> &ControllerId {
        &self.controller_id
    }

    // Returns the bounded user-facing controller name.
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    // Returns the exact proof-validated public key for certificate issuance.
    pub const fn public_key(&self) -> &ControllerPublicKey {
        &self.public_key
    }
}

// Projects durable controller metadata without certificate or private-key bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeControllerSummary {
    controller_id: ControllerId,
    name: DisplayName,
    role: ControllerRole,
    state: ControllerState,
    certificate_sha256: Sha256Digest,
    public_key_sha256: Sha256Digest,
    certificate_valid_from: UnixMilliseconds,
    certificate_expires_at: UnixMilliseconds,
    issued_at: UnixMilliseconds,
    activated_at: Option<UnixMilliseconds>,
    revoked_at: Option<UnixMilliseconds>,
}

impl NodeControllerSummary {
    // Projects one manager-validated controller without copying its public certificate document.
    pub fn from_controller(controller: &Controller) -> Self {
        Self {
            controller_id: controller.controller_id().clone(),
            name: controller.name().clone(),
            role: controller.role(),
            state: controller.state(),
            certificate_sha256: controller.certificate().certificate_sha256().clone(),
            public_key_sha256: controller.certificate().public_key_sha256().clone(),
            certificate_valid_from: controller.certificate().valid_from(),
            certificate_expires_at: controller.certificate().expires_at(),
            issued_at: controller.issued_at(),
            activated_at: controller.activated_at(),
            revoked_at: controller.revoked_at(),
        }
    }

    // Reconstructs one strict secret-free wire projection after checking lifecycle invariants.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        controller_id: ControllerId,
        name: DisplayName,
        role: ControllerRole,
        state: ControllerState,
        certificate_sha256: Sha256Digest,
        public_key_sha256: Sha256Digest,
        certificate_valid_from: UnixMilliseconds,
        certificate_expires_at: UnixMilliseconds,
        issued_at: UnixMilliseconds,
        activated_at: Option<UnixMilliseconds>,
        revoked_at: Option<UnixMilliseconds>,
    ) -> Result<Self, ControllerError> {
        let lifecycle_valid = match state {
            ControllerState::Issued => activated_at.is_none() && revoked_at.is_none(),
            ControllerState::Active => activated_at.is_some() && revoked_at.is_none(),
            ControllerState::Revoked => revoked_at.is_some(),
        };
        if certificate_expires_at <= certificate_valid_from
            || issued_at < certificate_valid_from
            || issued_at >= certificate_expires_at
            || !lifecycle_valid
            || activated_at.is_some_and(|value| value < issued_at)
            || revoked_at.is_some_and(|value| {
                value < issued_at || activated_at.is_some_and(|activated| value < activated)
            })
        {
            return Err(ControllerError::InvalidRecord {
                reason: "controller summary lifecycle is inconsistent",
            });
        }
        Ok(Self {
            controller_id,
            name,
            role,
            state,
            certificate_sha256,
            public_key_sha256,
            certificate_valid_from,
            certificate_expires_at,
            issued_at,
            activated_at,
            revoked_at,
        })
    }

    // Returns the stable controller identity.
    pub const fn controller_id(&self) -> &ControllerId {
        &self.controller_id
    }

    // Returns the public controller name.
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    // Returns the exact durable authorization role.
    pub const fn role(&self) -> ControllerRole {
        self.role
    }

    // Returns the exact durable lifecycle state.
    pub const fn state(&self) -> ControllerState {
        self.state
    }

    // Returns the public certificate fingerprint without certificate material.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }

    // Returns the public-key fingerprint without key material.
    pub const fn public_key_sha256(&self) -> &Sha256Digest {
        &self.public_key_sha256
    }

    // Returns the inclusive certificate lifetime boundary.
    pub const fn certificate_valid_from(&self) -> UnixMilliseconds {
        self.certificate_valid_from
    }

    // Returns the exclusive certificate lifetime boundary.
    pub const fn certificate_expires_at(&self) -> UnixMilliseconds {
        self.certificate_expires_at
    }

    // Returns when this exact certificate entered durable trust state.
    pub const fn issued_at(&self) -> UnixMilliseconds {
        self.issued_at
    }

    // Returns when this exact certificate became active.
    pub const fn activated_at(&self) -> Option<UnixMilliseconds> {
        self.activated_at
    }

    // Returns when this exact controller was revoked.
    pub const fn revoked_at(&self) -> Option<UnixMilliseconds> {
        self.revoked_at
    }
}

// Returns one durable controller plus exact certificate DER needed by the held TLS session.
#[derive(Clone, Eq, PartialEq)]
pub struct NodeControllerEnrollmentReceipt {
    controller: NodeControllerSummary,
    certificate_public_material: Vec<u8>,
}

// Identifies one active controller entry projected into Watchdog authorization.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeControllerAuthorization {
    controller_id: ControllerId,
    certificate_sha256: Sha256Digest,
}

impl NodeControllerAuthorization {
    // Creates one already-validated active authorization projection value.
    pub const fn new(controller_id: ControllerId, certificate_sha256: Sha256Digest) -> Self {
        Self {
            controller_id,
            certificate_sha256,
        }
    }

    // Projects one active manager controller without copying certificate material.
    fn from_controller(controller: &Controller) -> Result<Self, ControllerError> {
        if controller.state() != ControllerState::Active {
            return Err(ControllerError::InvalidRecord {
                reason: "controller authorization is not active",
            });
        }
        Ok(Self {
            controller_id: controller.controller_id().clone(),
            certificate_sha256: controller.certificate().certificate_sha256().clone(),
        })
    }

    // Returns the stable controller identity carried by the authorization set.
    pub const fn controller_id(&self) -> &ControllerId {
        &self.controller_id
    }

    // Returns the exact canonical certificate DER fingerprint.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }
}

// Reconciles the complete active controller set with Watchdog's live authorization boundary.
pub trait NodeControllerAuthorizationProjectionPort: Send + Sync {
    // Atomically installs and reloads one exact deterministic active-controller set.
    fn reconcile(&self, controllers: &[NodeControllerAuthorization])
        -> Result<(), ControllerError>;
}

impl NodeControllerEnrollmentReceipt {
    // Creates one receipt only from manager-validated active controller state.
    pub fn new(controller: &Controller) -> Result<Self, ControllerError> {
        if controller.state() != ControllerState::Active
            || controller.certificate().public_material().is_empty()
        {
            return Err(ControllerError::InvalidRecord {
                reason: "controller enrollment receipt is invalid",
            });
        }
        Ok(Self {
            controller: NodeControllerSummary::from_controller(controller),
            certificate_public_material: controller.certificate().public_material().to_vec(),
        })
    }

    // Reconstructs one closed-wire receipt after verifying its certificate fingerprint.
    pub fn restore(
        controller: NodeControllerSummary,
        certificate_public_material: Vec<u8>,
    ) -> Result<Self, ControllerError> {
        use sha2::{Digest, Sha256};

        let fingerprint = format!("{:x}", Sha256::digest(&certificate_public_material));
        if certificate_public_material.is_empty()
            || certificate_public_material.len() > 16 * 1024
            || fingerprint != controller.certificate_sha256().as_str()
            || controller.state() != ControllerState::Active
        {
            return Err(ControllerError::InvalidRecord {
                reason: "controller enrollment receipt is invalid",
            });
        }
        Ok(Self {
            controller,
            certificate_public_material,
        })
    }

    // Returns the secret-free durable controller projection.
    pub const fn controller(&self) -> &NodeControllerSummary {
        &self.controller
    }

    // Returns canonical certificate DER only to the transient enrollment response owner.
    pub fn certificate_public_material(&self) -> &[u8] {
        &self.certificate_public_material
    }
}

impl fmt::Debug for NodeControllerEnrollmentReceipt {
    // Redacts certificate bytes while retaining their public fingerprint projection.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeControllerEnrollmentReceipt")
            .field("controller", &self.controller)
            .field(
                "certificate_public_material",
                &format_args!(
                    "<public certificate; {} bytes>",
                    self.certificate_public_material.len()
                ),
            )
            .finish()
    }
}

// Describes only the policy fields supplied by one CLI update request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeApiKeyPolicyUpdate {
    selected_models: Option<Vec<LogicalModelName>>,
    expires_at: Option<UnixMilliseconds>,
    requests_per_minute: Option<NonZeroU32>,
    tokens_per_minute: Option<NonZeroU64>,
    concurrency: Option<NonZeroU32>,
    context_tokens: Option<NonZeroU64>,
    tenant: Option<TechnicalName>,
    application: Option<TechnicalName>,
}

impl NodeApiKeyPolicyUpdate {
    // Creates one partial policy update whose absent fields retain durable values.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        selected_models: Option<Vec<LogicalModelName>>,
        expires_at: Option<UnixMilliseconds>,
        requests_per_minute: Option<NonZeroU32>,
        tokens_per_minute: Option<NonZeroU64>,
        concurrency: Option<NonZeroU32>,
        context_tokens: Option<NonZeroU64>,
        tenant: Option<TechnicalName>,
        application: Option<TechnicalName>,
    ) -> Self {
        Self {
            selected_models,
            expires_at,
            requests_per_minute,
            tokens_per_minute,
            concurrency,
            context_tokens,
            tenant,
            application,
        }
    }

    // Returns the explicitly supplied selected-model scope.
    pub fn selected_models(&self) -> Option<&[LogicalModelName]> {
        self.selected_models.as_deref()
    }

    // Returns the explicitly supplied expiration.
    pub const fn expires_at(&self) -> Option<UnixMilliseconds> {
        self.expires_at
    }

    // Returns the explicitly supplied request-rate limit.
    pub const fn requests_per_minute(&self) -> Option<NonZeroU32> {
        self.requests_per_minute
    }

    // Returns the explicitly supplied token-rate limit.
    pub const fn tokens_per_minute(&self) -> Option<NonZeroU64> {
        self.tokens_per_minute
    }

    // Returns the explicitly supplied concurrency limit.
    pub const fn concurrency(&self) -> Option<NonZeroU32> {
        self.concurrency
    }

    // Returns the explicitly supplied context-token limit.
    pub const fn context_tokens(&self) -> Option<NonZeroU64> {
        self.context_tokens
    }

    // Returns the explicitly supplied tenant label.
    pub const fn tenant(&self) -> Option<&TechnicalName> {
        self.tenant.as_ref()
    }

    // Returns the explicitly supplied application label.
    pub const fn application(&self) -> Option<&TechnicalName> {
        self.application.as_ref()
    }
}

// Owns one bearer token between manager issuance and one CLI presentation.
pub struct NodeIssuedApiKey {
    api_key: ApiKey,
    token: RefCell<Option<String>>,
}

impl NodeIssuedApiKey {
    // Creates one response owner from metadata and an immediately issued bearer token.
    pub fn new(api_key: ApiKey, token: String) -> Self {
        Self {
            api_key,
            token: RefCell::new(Some(token)),
        }
    }

    // Returns the durable non-secret metadata.
    pub const fn api_key(&self) -> &ApiKey {
        &self.api_key
    }

    // Returns the bearer token to its display owner exactly once.
    pub fn take_token(&self) -> Option<String> {
        self.token.borrow_mut().take()
    }

    // Transfers the unconsumed token to one immediate wire encoding.
    pub(crate) fn take_token_for_wire(&self) -> Option<String> {
        self.take_token()
    }
}

impl Clone for NodeIssuedApiKey {
    // Copies only durable public metadata and never duplicates bearer material.
    fn clone(&self) -> Self {
        Self {
            api_key: self.api_key.clone(),
            token: RefCell::new(None),
        }
    }
}

impl fmt::Debug for NodeIssuedApiKey {
    // Redacts bearer material from every debug projection.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeIssuedApiKey")
            .field("api_key", &self.api_key)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl PartialEq for NodeIssuedApiKey {
    // Compares public metadata and only the presence, never the bytes, of one token.
    fn eq(&self, other: &Self) -> bool {
        self.api_key == other.api_key
            && self.token.borrow().is_some() == other.token.borrow().is_some()
    }
}

impl Eq for NodeIssuedApiKey {}

// Defines the narrow AuthenticationManager lifecycle consumed by the private Node API.
pub trait NodeAuthenticationApiPort: Send + Sync {
    // Atomically commits one proof-validated, human-confirmed controller candidate.
    fn add_controller(
        &self,
        candidate: NodeControllerEnrollmentCandidate,
        role: ControllerRole,
    ) -> Result<NodeControllerEnrollmentReceipt, ControllerError>;

    // Returns every secret-free durable controller snapshot.
    fn controllers(&self) -> Result<Vec<NodeControllerSummary>, ControllerError>;

    // Revokes one exact identity or unambiguous public name.
    fn revoke_controller(&self, selector: &str) -> Result<NodeControllerSummary, ControllerError>;

    // Creates one inference key and transfers its token to one response owner.
    fn create(
        &self,
        name: DisplayName,
        policy: ApiKeyPolicy,
    ) -> Result<NodeIssuedApiKey, AuthenticationError>;

    // Returns every non-secret API-key metadata snapshot.
    fn keys(&self) -> Result<Vec<ApiKey>, AuthenticationError>;

    // Resolves one exact identity or unambiguous public name.
    fn key(&self, selector: &str) -> Result<ApiKey, AuthenticationError>;

    // Applies only supplied policy fields while retaining all others.
    fn update(
        &self,
        selector: &str,
        update: NodeApiKeyPolicyUpdate,
    ) -> Result<ApiKey, AuthenticationError>;

    // Replaces one active key secret while preserving its public identity and policy.
    fn rotate(&self, selector: &str) -> Result<NodeIssuedApiKey, AuthenticationError>;

    // Revokes one active key or returns its exact replay state.
    fn revoke(&self, selector: &str) -> Result<ApiKey, AuthenticationError>;
}

// Owns the Node-facing orchestration over one already-composed AuthenticationManager.
pub struct NodeAuthenticationCoordinator {
    manager: Arc<AuthenticationManager>,
    controller_projection: Arc<dyn NodeControllerAuthorizationProjectionPort>,
    controller_mutation: Mutex<()>,
}

impl NodeAuthenticationCoordinator {
    // Creates one Node-owned role that commits only already-confirmed enrollment candidates.
    pub fn new(manager: Arc<AuthenticationManager>) -> Self {
        Self {
            manager,
            controller_projection: Arc::new(UnavailableNodeControllerAuthorizationProjection),
            controller_mutation: Mutex::new(()),
        }
    }

    // Creates one coordinator with the exact live Watchdog authorization projection enabled.
    pub fn new_with_controller_projection(
        manager: Arc<AuthenticationManager>,
        controller_projection: Arc<dyn NodeControllerAuthorizationProjectionPort>,
    ) -> Self {
        Self {
            manager,
            controller_projection,
            controller_mutation: Mutex::new(()),
        }
    }

    // Resolves one key selector without disclosing a secret or store distinction.
    fn resolve_key(&self, selector: &str) -> Result<ApiKey, AuthenticationError> {
        if let Ok(key_id) = ApiKeyId::parse(selector) {
            return self.manager.api_key(&key_id);
        }
        let matches: Vec<ApiKey> = self
            .manager
            .api_keys()?
            .into_iter()
            .filter(|key| key.name().as_str() == selector)
            .collect();
        match matches.as_slice() {
            [key] => Ok(key.clone()),
            _ => Err(AuthenticationError::NotFound),
        }
    }

    // Converts one issued manager value into the sole token-bearing Node response.
    fn issued(
        mut change: li_authentication_manager::AuthenticationChange<
            li_authentication_manager::IssuedApiKey,
        >,
    ) -> Result<NodeIssuedApiKey, AuthenticationError> {
        let api_key = change.value().api_key().clone();
        let token = change
            .value_mut()
            .take_token()
            .ok_or(AuthenticationError::EntropyUnavailable)?;
        Ok(NodeIssuedApiKey::new(api_key, token))
    }

    // Resolves one controller selector without exposing store or certificate material.
    fn resolve_controller(&self, selector: &str) -> Result<Controller, ControllerError> {
        if let Ok(controller_id) = ControllerId::parse(selector) {
            return self.manager.controller(&controller_id);
        }
        let matches = self
            .manager
            .controllers()?
            .into_iter()
            .filter(|controller| controller.name().as_str() == selector)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [controller] => Ok(controller.clone()),
            _ => Err(ControllerError::NotFound),
        }
    }

    // Returns every active controller authorization in stable identity order.
    fn active_controller_authorizations(
        &self,
    ) -> Result<Vec<NodeControllerAuthorization>, ControllerError> {
        self.manager
            .controllers()?
            .iter()
            .filter(|controller| controller.state() == ControllerState::Active)
            .map(NodeControllerAuthorization::from_controller)
            .collect()
    }

    // Restores a prior projection and collapses ambiguous rollback into fail-closed unavailability.
    fn restore_controller_authorizations(
        &self,
        prior: &[NodeControllerAuthorization],
        error: ControllerError,
    ) -> ControllerError {
        match self.controller_projection.reconcile(prior) {
            Ok(()) => error,
            Err(_) => ControllerError::ProviderUnavailable,
        }
    }
}

// Fails controller mutation closed until production supplies its live Watchdog projection.
struct UnavailableNodeControllerAuthorizationProjection;

impl NodeControllerAuthorizationProjectionPort
    for UnavailableNodeControllerAuthorizationProjection
{
    // Rejects mutation while leaving API-key-only coordinator construction usable.
    fn reconcile(
        &self,
        _controllers: &[NodeControllerAuthorization],
    ) -> Result<(), ControllerError> {
        Err(ControllerError::ProviderUnavailable)
    }
}

impl NodeAuthenticationApiPort for NodeAuthenticationCoordinator {
    // Atomically activates one proof-validated candidate after CLI-owned confirmation.
    fn add_controller(
        &self,
        candidate: NodeControllerEnrollmentCandidate,
        role: ControllerRole,
    ) -> Result<NodeControllerEnrollmentReceipt, ControllerError> {
        let _mutation = self
            .controller_mutation
            .lock()
            .map_err(|_| ControllerError::ProviderUnavailable)?;
        let prior = self.active_controller_authorizations()?;
        let issued = match self.manager.controller(candidate.controller_id()) {
            Ok(existing) if existing.state() == ControllerState::Revoked => {
                self.manager.replace_controller(
                    candidate.controller_id(),
                    candidate.name().clone(),
                    role,
                    ControllerCertificateSource::Issue(candidate.public_key().clone()),
                )?
            }
            Ok(_) | Err(ControllerError::NotFound) => self.manager.issue_controller(
                candidate.controller_id().clone(),
                candidate.name().clone(),
                role,
                candidate.public_key().clone(),
            )?,
            Err(error) => return Err(error),
        };
        if issued.value().state() == ControllerState::Active {
            self.controller_projection
                .reconcile(&self.active_controller_authorizations()?)?;
            return NodeControllerEnrollmentReceipt::new(issued.value());
        }
        let mut desired = prior.clone();
        desired.push(NodeControllerAuthorization {
            controller_id: issued.value().controller_id().clone(),
            certificate_sha256: issued.value().certificate().certificate_sha256().clone(),
        });
        desired.sort();
        self.controller_projection.reconcile(&desired)?;
        match self
            .manager
            .activate_controller(issued.value().controller_id())
        {
            Ok(active) => NodeControllerEnrollmentReceipt::new(active.value()),
            Err(error) => Err(self.restore_controller_authorizations(&prior, error)),
        }
    }

    // Returns every manager-validated controller as a secret-free summary.
    fn controllers(&self) -> Result<Vec<NodeControllerSummary>, ControllerError> {
        self.manager.controllers().map(|controllers| {
            controllers
                .iter()
                .map(NodeControllerSummary::from_controller)
                .collect()
        })
    }

    // Revokes one resolved controller through the manager's replay-safe terminal transition.
    fn revoke_controller(&self, selector: &str) -> Result<NodeControllerSummary, ControllerError> {
        let _mutation = self
            .controller_mutation
            .lock()
            .map_err(|_| ControllerError::ProviderUnavailable)?;
        let controller = self.resolve_controller(selector)?;
        let prior = self.active_controller_authorizations()?;
        let desired = prior
            .iter()
            .filter(|entry| entry.controller_id() != controller.controller_id())
            .cloned()
            .collect::<Vec<_>>();
        self.controller_projection.reconcile(&desired)?;
        match self.manager.revoke_controller(controller.controller_id()) {
            Ok(change) => Ok(NodeControllerSummary::from_controller(change.value())),
            Err(error) => Err(self.restore_controller_authorizations(&prior, error)),
        }
    }

    // Creates one key through the ordinary manager lifecycle.
    fn create(
        &self,
        name: DisplayName,
        policy: ApiKeyPolicy,
    ) -> Result<NodeIssuedApiKey, AuthenticationError> {
        Self::issued(self.manager.create(name, policy)?)
    }

    // Returns stable non-secret manager snapshots.
    fn keys(&self) -> Result<Vec<ApiKey>, AuthenticationError> {
        self.manager.api_keys()
    }

    // Resolves one stable identity or public name.
    fn key(&self, selector: &str) -> Result<ApiKey, AuthenticationError> {
        self.resolve_key(selector)
    }

    // Merges supplied fields and commits one complete manager-owned policy.
    fn update(
        &self,
        selector: &str,
        update: NodeApiKeyPolicyUpdate,
    ) -> Result<ApiKey, AuthenticationError> {
        let current = self.resolve_key(selector)?;
        let current_policy = current.policy();
        let model_scope = match update.selected_models {
            Some(models) => ApiKeyModelScope::selected(models)?,
            None => current_policy.model_scope().clone(),
        };
        let current_limits = current_policy.limits();
        let policy = ApiKeyPolicy::new(
            model_scope,
            update.expires_at.or(current_policy.expires_at()),
            ApiKeyLimits::new(
                update
                    .requests_per_minute
                    .or(current_limits.requests_per_minute()),
                update
                    .tokens_per_minute
                    .or(current_limits.tokens_per_minute()),
                update.concurrency.or(current_limits.concurrency()),
                update.context_tokens.or(current_limits.context_tokens()),
            ),
            update.tenant.or_else(|| current_policy.tenant().cloned()),
            update
                .application
                .or_else(|| current_policy.application().cloned()),
        );
        self.manager
            .update_policy(current.key_id(), policy)
            .map(|change| change.value().clone())
    }

    // Rotates one resolved key through identity-preserving manager code.
    fn rotate(&self, selector: &str) -> Result<NodeIssuedApiKey, AuthenticationError> {
        let current = self.resolve_key(selector)?;
        Self::issued(self.manager.rotate_preserving_name(current.key_id())?)
    }

    // Revokes one resolved key through replay-safe manager code.
    fn revoke(&self, selector: &str) -> Result<ApiKey, AuthenticationError> {
        let current = self.resolve_key(selector)?;
        self.manager
            .revoke(current.key_id())
            .map(|change| change.value().clone())
    }
}
