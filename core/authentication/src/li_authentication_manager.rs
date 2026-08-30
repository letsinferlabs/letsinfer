// SPDX-License-Identifier: AGPL-3.0-only

mod li_api_key;
mod li_authentication_cryptography;
mod li_authentication_error;
mod li_authentication_event;
mod li_authentication_store;
mod li_controller;
mod li_controller_certificate;
mod li_controller_error;
mod li_controller_lifecycle;
mod li_controller_store;
mod li_peer_credential;

pub use li_api_key::{
    ApiKey, ApiKeyLimits, ApiKeyModelScope, ApiKeyPolicy, AuthenticationPrincipal, IssuedApiKey,
};
pub use li_authentication_cryptography::{ApiKeyMaterialProvider, SystemApiKeyMaterialProvider};
pub use li_authentication_error::{AuthenticationError, AuthenticationStoreError};
pub use li_authentication_event::{AuthenticationChange, AuthenticationEvent};
pub use li_authentication_store::{
    AuthenticationRecord, AuthenticationRotation, AuthenticationStore,
    VersionedAuthenticationRecord,
};
pub use li_controller::{Controller, ControllerPrincipal, ControllerRole, ControllerState};
pub use li_controller_certificate::{
    ControllerCertificate, ControllerCertificateError, ControllerCertificateMaterial,
    ControllerCertificateProvider, ControllerPublicKey,
};
pub use li_controller_error::ControllerError;
pub use li_controller_lifecycle::ControllerCertificateSource;
pub use li_controller_store::{ControllerStore, VersionedController};
pub use li_peer_credential::{
    PeerCredential, PeerCredentialDirection, PeerCredentialError, PeerCredentialPrincipal,
    PeerCredentialState, PeerCredentialStore, VersionedPeerCredential,
    MAX_PEER_CREDENTIAL_LOOKUP_RESULTS,
};

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{
    ApiKeyId, CredentialId, DisplayName, LogicalModelName, Sha256Digest, UnixMilliseconds,
};

use li_authentication_cryptography::{api_key_verifier, verifiers_equal};

const KEY_IDENTIFIER_BYTES: usize = 16;
const KEY_SALT_BYTES: usize = 16;
const KEY_SECRET_BYTES: usize = 32;

// Supplies time explicitly for expiration, revocation, and deterministic tests.
pub trait AuthenticationClock: Send + Sync {
    // Returns the current Unix timestamp in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError>;
}

// Reads production authentication time from the active host.
#[derive(Default)]
pub struct SystemAuthenticationClock;

impl AuthenticationClock for SystemAuthenticationClock {
    // Returns current host time without accepting a pre-epoch clock.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            AuthenticationError::InvalidPolicy {
                reason: "system clock is before the Unix epoch",
            }
        })?;
        let milliseconds = u64::try_from(duration.as_millis()).map_err(|_| {
            AuthenticationError::InvalidPolicy {
                reason: "system clock exceeds the timestamp range",
            }
        })?;
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Owns inference API-key creation, verification, rotation, and revocation.
pub struct AuthenticationManager {
    store: Arc<dyn AuthenticationStore>,
    peer_credential_store: Arc<dyn PeerCredentialStore>,
    controller_store: Arc<dyn ControllerStore>,
    controller_certificates: Arc<dyn ControllerCertificateProvider>,
    material: Arc<dyn ApiKeyMaterialProvider>,
    clock: Arc<dyn AuthenticationClock>,
}

impl AuthenticationManager {
    // Creates one manager from explicit storage, entropy, and clock capabilities.
    pub fn new(
        store: Arc<dyn AuthenticationStore>,
        material: Arc<dyn ApiKeyMaterialProvider>,
        clock: Arc<dyn AuthenticationClock>,
    ) -> Self {
        Self::new_with_peer_credential_store(
            store,
            Arc::new(UnavailablePeerCredentialStore),
            material,
            clock,
        )
    }

    // Creates one manager with the persisted peer-certificate credential capability enabled.
    pub fn new_with_peer_credential_store(
        store: Arc<dyn AuthenticationStore>,
        peer_credential_store: Arc<dyn PeerCredentialStore>,
        material: Arc<dyn ApiKeyMaterialProvider>,
        clock: Arc<dyn AuthenticationClock>,
    ) -> Self {
        Self {
            store,
            peer_credential_store,
            controller_store: Arc::new(UnavailableControllerStore),
            controller_certificates: Arc::new(UnavailableControllerCertificateProvider),
            material,
            clock,
        }
    }

    // Creates one manager with API-key, peer, and controller credential persistence enabled.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_controller_store(
        store: Arc<dyn AuthenticationStore>,
        peer_credential_store: Arc<dyn PeerCredentialStore>,
        controller_store: Arc<dyn ControllerStore>,
        controller_certificates: Arc<dyn ControllerCertificateProvider>,
        material: Arc<dyn ApiKeyMaterialProvider>,
        clock: Arc<dyn AuthenticationClock>,
    ) -> Self {
        Self {
            store,
            peer_credential_store,
            controller_store,
            controller_certificates,
            material,
            clock,
        }
    }

    // Creates one API key and returns its secret through a single owner.
    pub fn create(
        &self,
        name: DisplayName,
        policy: ApiKeyPolicy,
    ) -> Result<AuthenticationChange<IssuedApiKey>, AuthenticationError> {
        let now = self.clock.now()?;
        let material = self.generate_material()?;
        let api_key = ApiKey::new(material.key_id.clone(), name, policy, now, None, None)?;
        let record = AuthenticationRecord::new(
            api_key.clone(),
            material.salt,
            api_key_verifier(&material.salt, &material.secret),
        );
        let stored = self.store.create(record.clone())?;
        require_committed_record(&stored, &record, 0)?;
        Ok(AuthenticationChange::new(
            IssuedApiKey::new(api_key, material.secret),
            Some(AuthenticationEvent::ApiKeyCreated {
                key_id: material.key_id.clone(),
            }),
        ))
    }

    // Returns one API-key metadata snapshot without exposing verifier material.
    pub fn api_key(&self, key_id: &ApiKeyId) -> Result<ApiKey, AuthenticationError> {
        let stored = self
            .store
            .read(key_id)?
            .ok_or(AuthenticationError::NotFound)?;
        require_read_record(&stored, key_id)?;
        Ok(stored.record().api_key().clone())
    }

    // Returns every API-key metadata snapshot in stable identity order.
    pub fn api_keys(&self) -> Result<Vec<ApiKey>, AuthenticationError> {
        let stored = self.store.all()?;
        let unique_ids: HashSet<&ApiKeyId> = stored
            .iter()
            .map(|value| value.record().api_key().key_id())
            .collect();
        let unique_names: HashSet<&DisplayName> = stored
            .iter()
            .map(|value| value.record().api_key().name())
            .collect();
        if unique_ids.len() != stored.len()
            || unique_names.len() != stored.len()
            || stored.iter().any(|value| value.revision() == 0)
        {
            return Err(AuthenticationStoreError::Corrupt.into());
        }
        let mut values: Vec<ApiKey> = stored
            .into_iter()
            .map(|value| value.record().api_key().clone())
            .collect();
        values.sort_by(|left, right| left.key_id().as_str().cmp(right.key_id().as_str()));
        Ok(values)
    }

    // Replaces one active key policy and suppresses duplicate events for an exact replay.
    pub fn update_policy(
        &self,
        key_id: &ApiKeyId,
        policy: ApiKeyPolicy,
    ) -> Result<AuthenticationChange<ApiKey>, AuthenticationError> {
        let current = self
            .store
            .read(key_id)?
            .ok_or(AuthenticationError::NotFound)?;
        require_read_record(&current, key_id)?;
        if current.record().api_key().revoked_at().is_some() {
            return Err(AuthenticationError::NotFound);
        }
        if current.record().api_key().policy() == &policy {
            return Ok(AuthenticationChange::new(
                current.record().api_key().clone(),
                None,
            ));
        }
        let updated = policy_record(current.record(), policy)?;
        match self.store.replace(updated.clone(), current.revision()) {
            Ok(stored) => {
                require_committed_record(&stored, &updated, current.revision())?;
                Ok(AuthenticationChange::new(
                    stored.record().api_key().clone(),
                    Some(AuthenticationEvent::ApiKeyPolicyUpdated {
                        key_id: key_id.clone(),
                    }),
                ))
            }
            Err(AuthenticationStoreError::Conflict) => {
                let observed = self
                    .store
                    .read(key_id)?
                    .ok_or(AuthenticationError::NotFound)?;
                require_read_record(&observed, key_id)?;
                if observed.record().api_key().revoked_at().is_none()
                    && observed.record().api_key().policy() == updated.api_key().policy()
                {
                    Ok(AuthenticationChange::new(
                        observed.record().api_key().clone(),
                        None,
                    ))
                } else {
                    Err(AuthenticationStoreError::Conflict.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    // Rotates one key while preserving its public name and policy on the replacement.
    pub fn rotate_preserving_name(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<AuthenticationChange<IssuedApiKey>, AuthenticationError> {
        let current = self
            .store
            .read(key_id)?
            .ok_or(AuthenticationError::NotFound)?;
        require_read_record(&current, key_id)?;
        if current.record().api_key().revoked_at().is_some() {
            return Err(AuthenticationError::NotFound);
        }
        let replacement_name = current.record().api_key().name().clone();
        let archived_name = archived_rotation_name(current.record().api_key())?;
        self.rotate_record(current, replacement_name, Some(archived_name))
    }

    // Revokes one key and emits no duplicate event when it is already revoked.
    pub fn revoke(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<AuthenticationChange<ApiKey>, AuthenticationError> {
        let now = self.clock.now()?;
        let current = self
            .store
            .read(key_id)?
            .ok_or(AuthenticationError::NotFound)?;
        require_read_record(&current, key_id)?;
        if current.record().api_key().revoked_at().is_some() {
            return Ok(AuthenticationChange::new(
                current.record().api_key().clone(),
                None,
            ));
        }
        let revoked = revoked_record(current.record(), now)?;
        match self.store.replace(revoked.clone(), current.revision()) {
            Ok(stored) => {
                require_committed_record(&stored, &revoked, current.revision())?;
                Ok(AuthenticationChange::new(
                    stored.record().api_key().clone(),
                    Some(AuthenticationEvent::ApiKeyRevoked {
                        key_id: key_id.clone(),
                    }),
                ))
            }
            Err(AuthenticationStoreError::Conflict) => {
                let observed = self
                    .store
                    .read(key_id)?
                    .ok_or(AuthenticationError::NotFound)?;
                require_read_record(&observed, key_id)?;
                if observed.record().api_key().revoked_at().is_some() {
                    Ok(AuthenticationChange::new(
                        observed.record().api_key().clone(),
                        None,
                    ))
                } else {
                    Err(AuthenticationStoreError::Conflict.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    // Atomically revokes one key and returns a new replacement secret.
    pub fn rotate(
        &self,
        key_id: &ApiKeyId,
        replacement_name: DisplayName,
    ) -> Result<AuthenticationChange<IssuedApiKey>, AuthenticationError> {
        let current = self
            .store
            .read(key_id)?
            .ok_or(AuthenticationError::NotFound)?;
        require_read_record(&current, key_id)?;
        if current.record().api_key().revoked_at().is_some() {
            return Err(AuthenticationError::NotFound);
        }
        self.rotate_record(current, replacement_name, None)
    }

    // Commits one atomic rotation after its public and archived names are resolved.
    fn rotate_record(
        &self,
        current: VersionedAuthenticationRecord,
        replacement_name: DisplayName,
        archived_name: Option<DisplayName>,
    ) -> Result<AuthenticationChange<IssuedApiKey>, AuthenticationError> {
        let now = self.clock.now()?;
        let key_id = current.record().api_key().key_id().clone();
        let material = self.generate_material()?;
        let replacement = ApiKey::new(
            material.key_id.clone(),
            replacement_name,
            current.record().api_key().policy().clone(),
            now,
            None,
            Some(key_id.clone()),
        )?;
        let replacement_record = AuthenticationRecord::new(
            replacement.clone(),
            material.salt,
            api_key_verifier(&material.salt, &material.secret),
        );
        let revoked = revoked_record_with_name(current.record(), archived_name, now)?;
        let rotation = self.store.rotate(
            revoked.clone(),
            current.revision(),
            replacement_record.clone(),
        )?;
        require_committed_record(rotation.revoked(), &revoked, current.revision())?;
        require_committed_record(rotation.replacement(), &replacement_record, 0)?;
        Ok(AuthenticationChange::new(
            IssuedApiKey::new(replacement, material.secret),
            Some(AuthenticationEvent::ApiKeyRotated {
                revoked_key_id: key_id,
                replacement_key_id: material.key_id.clone(),
            }),
        ))
    }

    // Authenticates one bearer token and enforces identity, expiry, revocation, and model scope.
    pub fn authenticate(
        &self,
        token: &str,
        model: &LogicalModelName,
    ) -> Result<AuthenticationPrincipal, AuthenticationError> {
        let principal = self.authenticate_identity(token)?;
        if !principal.policy().model_scope().permits(model) {
            return Err(AuthenticationError::Unauthorized);
        }
        Ok(principal)
    }

    // Authenticates bearer identity and durable lifetime before a caller filters model scope.
    pub fn authenticate_identity(
        &self,
        token: &str,
    ) -> Result<AuthenticationPrincipal, AuthenticationError> {
        let parsed = ParsedApiKey::parse(token).ok_or(AuthenticationError::Unauthorized)?;
        let stored = self
            .store
            .read(&parsed.key_id)?
            .ok_or(AuthenticationError::Unauthorized)?;
        require_read_record(&stored, &parsed.key_id)?;
        let api_key = stored.record().api_key();
        let now = self.clock.now()?;
        if api_key.revoked_at().is_some()
            || api_key
                .policy()
                .expires_at()
                .is_some_and(|expiry| expiry <= now)
        {
            return Err(AuthenticationError::Unauthorized);
        }
        let observed = api_key_verifier(stored.record().salt(), &parsed.secret);
        if !verifiers_equal(stored.record().verifier(), &observed) {
            return Err(AuthenticationError::Unauthorized);
        }
        Ok(AuthenticationPrincipal::new(api_key))
    }

    // Resolves one exact active peer leaf without following rotation or another identity.
    pub fn resolve_peer_credential(
        &self,
        peer_leaf_sha256: &Sha256Digest,
    ) -> Result<PeerCredentialPrincipal, PeerCredentialError> {
        let matches = self
            .peer_credential_store
            .matching_peer_credentials(peer_leaf_sha256, MAX_PEER_CREDENTIAL_LOOKUP_RESULTS)?;
        if matches.len() > 1 {
            return Err(PeerCredentialError::Ambiguous);
        }
        let stored = matches.first().ok_or(PeerCredentialError::Unrecognized)?;
        if stored.revision() == 0 || stored.credential().peer_leaf_sha256() != peer_leaf_sha256 {
            return Err(AuthenticationStoreError::Corrupt.into());
        }
        stored.credential().resolve_at(self.clock.now()?)
    }

    // Revalidates one exact resolved peer identity before authorizing a private action.
    pub fn authorize_peer_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<PeerCredentialPrincipal, PeerCredentialError> {
        let matches = self
            .peer_credential_store
            .matching_peer_credential_ids(credential_id, MAX_PEER_CREDENTIAL_LOOKUP_RESULTS)?;
        if matches.is_empty() {
            return Err(PeerCredentialError::Unrecognized);
        }
        if matches.len() != 1 || matches[0].credential().credential_id() != credential_id {
            return Err(PeerCredentialError::Ambiguous);
        }
        matches[0].credential().resolve_at(self.clock.now()?)
    }

    // Generates one key identity, secret, and salt from the injected CSPRNG.
    fn generate_material(&self) -> Result<GeneratedApiKeyMaterial, AuthenticationError> {
        let mut identifier = [0_u8; KEY_IDENTIFIER_BYTES];
        let mut secret = [0_u8; KEY_SECRET_BYTES];
        let mut salt = [0_u8; KEY_SALT_BYTES];
        self.material.fill(&mut identifier)?;
        self.material.fill(&mut secret)?;
        self.material.fill(&mut salt)?;
        let key_id = ApiKeyId::parse(&hexadecimal(&identifier))?;
        Ok(GeneratedApiKeyMaterial {
            key_id,
            secret,
            salt,
        })
    }
}

// Keeps legacy API-key-only construction explicitly unavailable for peer resolution.
struct UnavailablePeerCredentialStore;

impl PeerCredentialStore for UnavailablePeerCredentialStore {
    // Fails closed until application composition supplies the persisted peer store.
    fn matching_peer_credentials(
        &self,
        _peer_leaf_sha256: &Sha256Digest,
        _maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects identity lookup when peer-certificate persistence is not composed.
    fn matching_peer_credential_ids(
        &self,
        _credential_id: &CredentialId,
        _maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Keeps controller lifecycle unavailable until composition supplies both exact authorities.
struct UnavailableControllerStore;

impl ControllerStore for UnavailableControllerStore {
    // Fails closed when controller persistence is not composed.
    fn read(
        &self,
        _controller_id: &li_core_interface::ControllerId,
    ) -> Result<Option<VersionedController>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Fails closed when controller persistence is not composed.
    fn all(&self) -> Result<Vec<VersionedController>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Fails closed when controller persistence is not composed.
    fn create(
        &self,
        _controller: Controller,
    ) -> Result<VersionedController, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Fails closed when controller persistence is not composed.
    fn replace(
        &self,
        _controller: Controller,
        _expected_revision: u64,
    ) -> Result<VersionedController, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Keeps controller certificate issuance unavailable until a platform provider is composed.
struct UnavailableControllerCertificateProvider;

impl ControllerCertificateProvider for UnavailableControllerCertificateProvider {
    // Rejects certificate issuance without a configured trust authority.
    fn issue(
        &self,
        _controller_id: &li_core_interface::ControllerId,
        _public_key: &ControllerPublicKey,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        Err(ControllerCertificateError::Unavailable)
    }

    // Rejects certificate import without a configured validation authority.
    fn import(
        &self,
        _controller_id: &li_core_interface::ControllerId,
        _material: &ControllerCertificateMaterial,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        Err(ControllerCertificateError::Unavailable)
    }
}

// Owns newly generated secret material until issuance completes.
struct GeneratedApiKeyMaterial {
    key_id: ApiKeyId,
    secret: [u8; KEY_SECRET_BYTES],
    salt: [u8; KEY_SALT_BYTES],
}

impl Drop for GeneratedApiKeyMaterial {
    // Clears unissued secret and salt bytes on every exit path.
    fn drop(&mut self) {
        self.secret.fill(0);
        self.salt.fill(0);
    }
}

// Owns parsed bearer secret bytes only for one authentication attempt.
struct ParsedApiKey {
    key_id: ApiKeyId,
    secret: [u8; KEY_SECRET_BYTES],
}

impl ParsedApiKey {
    // Parses the exact `li_<id>_<secret>` bearer-token contract.
    fn parse(token: &str) -> Option<Self> {
        let value = token.strip_prefix("li_")?;
        let (identifier, secret) = value.split_once('_')?;
        if secret.contains('_') {
            return None;
        }
        Some(Self {
            key_id: ApiKeyId::parse(identifier).ok()?,
            secret: decode_hexadecimal::<KEY_SECRET_BYTES>(secret)?,
        })
    }
}

impl Drop for ParsedApiKey {
    // Clears parsed bearer secret bytes after verification.
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

// Returns one revoked copy while preserving its verifier and rotation metadata.
fn revoked_record(
    record: &AuthenticationRecord,
    revoked_at: UnixMilliseconds,
) -> Result<AuthenticationRecord, AuthenticationError> {
    let api_key = record.api_key();
    Ok(AuthenticationRecord::new(
        ApiKey::new(
            api_key.key_id().clone(),
            api_key.name().clone(),
            api_key.policy().clone(),
            api_key.created_at(),
            Some(revoked_at),
            api_key.rotated_from().cloned(),
        )?,
        *record.salt(),
        *record.verifier(),
    ))
}

// Returns one revoked copy with an optional archived name for identity-preserving rotation.
fn revoked_record_with_name(
    record: &AuthenticationRecord,
    archived_name: Option<DisplayName>,
    revoked_at: UnixMilliseconds,
) -> Result<AuthenticationRecord, AuthenticationError> {
    let api_key = record.api_key();
    Ok(AuthenticationRecord::new(
        ApiKey::new(
            api_key.key_id().clone(),
            archived_name.unwrap_or_else(|| api_key.name().clone()),
            api_key.policy().clone(),
            api_key.created_at(),
            Some(revoked_at),
            api_key.rotated_from().cloned(),
        )?,
        *record.salt(),
        *record.verifier(),
    ))
}

// Returns one non-secret archived name that remains unique after preserving the replacement name.
fn archived_rotation_name(api_key: &ApiKey) -> Result<DisplayName, AuthenticationError> {
    const MAX_DISPLAY_NAME_BYTES: usize = 128;
    let suffix = format!("-revoked-{}", api_key.key_id().as_str());
    let maximum_prefix_bytes = MAX_DISPLAY_NAME_BYTES.saturating_sub(suffix.len());
    let mut prefix_end = api_key.name().as_str().len().min(maximum_prefix_bytes);
    while !api_key.name().as_str().is_char_boundary(prefix_end) {
        prefix_end = prefix_end.saturating_sub(1);
    }
    DisplayName::parse(&format!(
        "{}{}",
        &api_key.name().as_str()[..prefix_end],
        suffix
    ))
    .map_err(Into::into)
}

// Returns one metadata-only record with a replacement policy and unchanged verifier material.
fn policy_record(
    record: &AuthenticationRecord,
    policy: ApiKeyPolicy,
) -> Result<AuthenticationRecord, AuthenticationError> {
    let api_key = record.api_key();
    Ok(AuthenticationRecord::new(
        ApiKey::new(
            api_key.key_id().clone(),
            api_key.name().clone(),
            policy,
            api_key.created_at(),
            api_key.revoked_at(),
            api_key.rotated_from().cloned(),
        )?,
        *record.salt(),
        *record.verifier(),
    ))
}

// Requires one store read to preserve its queried identity and a committed revision.
fn require_read_record(
    stored: &VersionedAuthenticationRecord,
    expected_key_id: &ApiKeyId,
) -> Result<(), AuthenticationError> {
    if stored.revision() == 0 || stored.record().api_key().key_id() != expected_key_id {
        return Err(AuthenticationStoreError::Corrupt.into());
    }
    Ok(())
}

// Requires a mutation result to equal the proposed private record at a newer revision.
fn require_committed_record(
    stored: &VersionedAuthenticationRecord,
    expected: &AuthenticationRecord,
    prior_revision: u64,
) -> Result<(), AuthenticationError> {
    if stored.record() != expected || stored.revision() <= prior_revision {
        return Err(AuthenticationStoreError::Corrupt.into());
    }
    Ok(())
}

// Converts fixed bytes to lowercase hexadecimal identity text.
fn hexadecimal(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

// Decodes exact lowercase hexadecimal text into one fixed secret buffer.
fn decode_hexadecimal<const BYTES: usize>(value: &str) -> Option<[u8; BYTES]> {
    if value.len() != BYTES * 2 {
        return None;
    }
    let mut output = [0_u8; BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hexadecimal_nibble(pair[0])? << 4) | hexadecimal_nibble(pair[1])?;
    }
    Some(output)
}

// Returns one lowercase hexadecimal nibble without accepting ambiguous text.
fn hexadecimal_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
