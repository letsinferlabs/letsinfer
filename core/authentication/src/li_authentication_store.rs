// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::ApiKeyId;

use crate::{ApiKey, AuthenticationStoreError};

// Stores one salted verifier and its non-secret API-key metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationRecord {
    api_key: ApiKey,
    salt: [u8; 16],
    verifier: [u8; 32],
}

impl AuthenticationRecord {
    // Creates one private authentication record without plaintext secret material.
    pub const fn new(api_key: ApiKey, salt: [u8; 16], verifier: [u8; 32]) -> Self {
        Self {
            api_key,
            salt,
            verifier,
        }
    }

    // Returns the durable non-secret API-key metadata.
    pub const fn api_key(&self) -> &ApiKey {
        &self.api_key
    }

    // Returns the random salt bound to the verifier.
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    // Returns the fixed verifier used for constant-time authentication.
    pub const fn verifier(&self) -> &[u8; 32] {
        &self.verifier
    }
}

// Returns one authentication record with its optimistic revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedAuthenticationRecord {
    record: AuthenticationRecord,
    revision: u64,
}

impl VersionedAuthenticationRecord {
    // Creates one versioned store result.
    pub const fn new(record: AuthenticationRecord, revision: u64) -> Self {
        Self { record, revision }
    }

    // Returns the stored authentication record.
    pub const fn record(&self) -> &AuthenticationRecord {
        &self.record
    }

    // Returns the revision required by the next mutation.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Returns the two records committed by one atomic rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationRotation {
    revoked: VersionedAuthenticationRecord,
    replacement: VersionedAuthenticationRecord,
}

impl AuthenticationRotation {
    // Creates one atomic rotation result.
    pub const fn new(
        revoked: VersionedAuthenticationRecord,
        replacement: VersionedAuthenticationRecord,
    ) -> Self {
        Self {
            revoked,
            replacement,
        }
    }

    // Returns the newly revoked prior key.
    pub const fn revoked(&self) -> &VersionedAuthenticationRecord {
        &self.revoked
    }

    // Returns the newly created replacement key.
    pub const fn replacement(&self) -> &VersionedAuthenticationRecord {
        &self.replacement
    }
}

// Defines the narrow durable capability required by AuthenticationManager.
pub trait AuthenticationStore: Send + Sync {
    // Returns one API-key record when it exists.
    fn read(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<Option<VersionedAuthenticationRecord>, AuthenticationStoreError>;

    // Returns every API-key record in stable key-identity order.
    fn all(&self) -> Result<Vec<VersionedAuthenticationRecord>, AuthenticationStoreError>;

    // Creates one API-key record only when its identity and name are absent.
    fn create(
        &self,
        record: AuthenticationRecord,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError>;

    // Replaces one exact API-key revision.
    fn replace(
        &self,
        record: AuthenticationRecord,
        expected_revision: u64,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError>;

    // Revokes one key and creates its replacement in one atomic transaction.
    fn rotate(
        &self,
        revoked: AuthenticationRecord,
        expected_revision: u64,
        replacement: AuthenticationRecord,
    ) -> Result<AuthenticationRotation, AuthenticationStoreError>;
}
