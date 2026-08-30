// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};

use li_core_interface::{
    ApiKeyId, DisplayName, InterfaceError, LogicalModelName, TechnicalName, UnixMilliseconds,
};

use crate::AuthenticationError;

const MAX_MODEL_SCOPES: usize = 128;

// Stores one validated model-scope alternative behind a private representation.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ApiKeyModelScopeValue {
    All,
    Selected(Vec<LogicalModelName>),
}

// Describes which logical models one API key may access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyModelScope(ApiKeyModelScopeValue);

impl ApiKeyModelScope {
    // Creates one unrestricted logical-model scope.
    pub const fn all() -> Self {
        Self(ApiKeyModelScopeValue::All)
    }

    // Creates one non-empty bounded model allowlist.
    pub fn selected(models: Vec<LogicalModelName>) -> Result<Self, AuthenticationError> {
        let unique: HashSet<&LogicalModelName> = models.iter().collect();
        if models.is_empty() || models.len() > MAX_MODEL_SCOPES || unique.len() != models.len() {
            return Err(AuthenticationError::InvalidPolicy {
                reason: "selected model scopes must be non-empty, unique, and bounded",
            });
        }
        Ok(Self(ApiKeyModelScopeValue::Selected(models)))
    }

    // Returns whether this scope permits one exact logical model.
    pub fn permits(&self, model: &LogicalModelName) -> bool {
        match &self.0 {
            ApiKeyModelScopeValue::All => true,
            ApiKeyModelScopeValue::Selected(models) => models.contains(model),
        }
    }

    // Returns the selected models or None for unrestricted scope.
    pub fn selected_models(&self) -> Option<&[LogicalModelName]> {
        match &self.0 {
            ApiKeyModelScopeValue::All => None,
            ApiKeyModelScopeValue::Selected(models) => Some(models),
        }
    }
}

// Describes configured per-key request limits without owning live counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApiKeyLimits {
    requests_per_minute: Option<NonZeroU32>,
    tokens_per_minute: Option<NonZeroU64>,
    concurrency: Option<NonZeroU32>,
    context_tokens: Option<NonZeroU64>,
}

impl ApiKeyLimits {
    // Creates one explicit set of optional positive limits.
    pub const fn new(
        requests_per_minute: Option<NonZeroU32>,
        tokens_per_minute: Option<NonZeroU64>,
        concurrency: Option<NonZeroU32>,
        context_tokens: Option<NonZeroU64>,
    ) -> Self {
        Self {
            requests_per_minute,
            tokens_per_minute,
            concurrency,
            context_tokens,
        }
    }

    // Returns the configured request-rate limit.
    pub const fn requests_per_minute(self) -> Option<NonZeroU32> {
        self.requests_per_minute
    }

    // Returns the configured token-rate limit.
    pub const fn tokens_per_minute(self) -> Option<NonZeroU64> {
        self.tokens_per_minute
    }

    // Returns the configured concurrent-request limit.
    pub const fn concurrency(self) -> Option<NonZeroU32> {
        self.concurrency
    }

    // Returns the configured context-token limit.
    pub const fn context_tokens(self) -> Option<NonZeroU64> {
        self.context_tokens
    }
}

// Describes durable authorization policy for one inference API key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyPolicy {
    model_scope: ApiKeyModelScope,
    expires_at: Option<UnixMilliseconds>,
    limits: ApiKeyLimits,
    tenant: Option<TechnicalName>,
    application: Option<TechnicalName>,
}

impl ApiKeyPolicy {
    // Creates one policy without evaluating live request counters.
    pub const fn new(
        model_scope: ApiKeyModelScope,
        expires_at: Option<UnixMilliseconds>,
        limits: ApiKeyLimits,
        tenant: Option<TechnicalName>,
        application: Option<TechnicalName>,
    ) -> Self {
        Self {
            model_scope,
            expires_at,
            limits,
            tenant,
            application,
        }
    }

    // Returns the configured model scope.
    pub const fn model_scope(&self) -> &ApiKeyModelScope {
        &self.model_scope
    }

    // Returns when the key expires, when bounded.
    pub const fn expires_at(&self) -> Option<UnixMilliseconds> {
        self.expires_at
    }

    // Returns the configured per-key limits for Gateway enforcement.
    pub const fn limits(&self) -> ApiKeyLimits {
        self.limits
    }

    // Returns the optional tenant label.
    pub const fn tenant(&self) -> Option<&TechnicalName> {
        self.tenant.as_ref()
    }

    // Returns the optional application label.
    pub const fn application(&self) -> Option<&TechnicalName> {
        self.application.as_ref()
    }
}

// Describes durable public metadata for one API key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKey {
    key_id: ApiKeyId,
    name: DisplayName,
    policy: ApiKeyPolicy,
    created_at: UnixMilliseconds,
    revoked_at: Option<UnixMilliseconds>,
    rotated_from: Option<ApiKeyId>,
}

impl ApiKey {
    // Creates one coherent API-key metadata snapshot.
    pub fn new(
        key_id: ApiKeyId,
        name: DisplayName,
        policy: ApiKeyPolicy,
        created_at: UnixMilliseconds,
        revoked_at: Option<UnixMilliseconds>,
        rotated_from: Option<ApiKeyId>,
    ) -> Result<Self, AuthenticationError> {
        if policy
            .expires_at()
            .is_some_and(|expires_at| expires_at <= created_at)
        {
            return Err(AuthenticationError::InvalidPolicy {
                reason: "expiration must follow API-key creation",
            });
        }
        if revoked_at.is_some_and(|revoked_at| revoked_at < created_at) {
            return Err(AuthenticationError::InvalidPolicy {
                reason: "revocation cannot precede API-key creation",
            });
        }
        Ok(Self {
            key_id,
            name,
            policy,
            created_at,
            revoked_at,
            rotated_from,
        })
    }

    // Returns the public API-key identity.
    pub const fn key_id(&self) -> &ApiKeyId {
        &self.key_id
    }

    // Returns the user-facing API-key name.
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    // Returns the durable authorization policy.
    pub const fn policy(&self) -> &ApiKeyPolicy {
        &self.policy
    }

    // Returns when the API key was created.
    pub const fn created_at(&self) -> UnixMilliseconds {
        self.created_at
    }

    // Returns when the API key was revoked.
    pub const fn revoked_at(&self) -> Option<UnixMilliseconds> {
        self.revoked_at
    }

    // Returns the prior API-key identity when this key is a rotation.
    pub const fn rotated_from(&self) -> Option<&ApiKeyId> {
        self.rotated_from.as_ref()
    }
}

// Carries the authenticated identity and policy returned to the Gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationPrincipal {
    key_id: ApiKeyId,
    policy: ApiKeyPolicy,
}

impl AuthenticationPrincipal {
    // Creates one authenticated principal from verified durable metadata.
    pub(crate) fn new(api_key: &ApiKey) -> Self {
        Self {
            key_id: api_key.key_id().clone(),
            policy: api_key.policy().clone(),
        }
    }

    // Returns the authenticated API-key identity.
    pub const fn key_id(&self) -> &ApiKeyId {
        &self.key_id
    }

    // Returns the policy the Gateway must enforce for this principal.
    pub const fn policy(&self) -> &ApiKeyPolicy {
        &self.policy
    }
}

// Owns one newly issued secret and clears its bytes when released.
pub struct IssuedApiKey {
    api_key: ApiKey,
    secret: Option<[u8; 32]>,
}

impl IssuedApiKey {
    // Creates one single-presentation API key from generated secret bytes.
    pub(crate) const fn new(api_key: ApiKey, secret: [u8; 32]) -> Self {
        Self {
            api_key,
            secret: Some(secret),
        }
    }

    // Returns the durable public metadata associated with this secret.
    pub const fn api_key(&self) -> &ApiKey {
        &self.api_key
    }

    // Takes the namespaced bearer token exactly once and clears retained secret bytes.
    pub fn take_token(&mut self) -> Option<String> {
        let mut secret = self.secret.take()?;
        let token = format!(
            "li_{}_{}",
            self.api_key.key_id().as_str(),
            hexadecimal(&secret)
        );
        secret.fill(0);
        Some(token)
    }
}

impl fmt::Debug for IssuedApiKey {
    // Redacts secret material from debug presentation.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedApiKey")
            .field("api_key", &self.api_key)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Drop for IssuedApiKey {
    // Clears secret bytes when their single-presentation owner is released.
    fn drop(&mut self) {
        if let Some(secret) = &mut self.secret {
            secret.fill(0);
        }
    }
}

// Converts fixed secret bytes to lowercase hexadecimal presentation.
fn hexadecimal(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

impl From<InterfaceError> for AuthenticationError {
    // Preserves conversion from shared interface validation at the auth boundary.
    fn from(error: InterfaceError) -> Self {
        Self::Interface(error)
    }
}
