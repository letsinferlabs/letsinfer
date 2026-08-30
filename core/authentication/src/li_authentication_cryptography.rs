// SPDX-License-Identifier: AGPL-3.0-only

use getrandom::fill;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::AuthenticationError;

const VERIFIER_DOMAIN: &[u8] = b"letsinfer-api-key-v1\0";

// Supplies cryptographically secure bytes without exposing a platform mechanism.
pub trait ApiKeyMaterialProvider: Send + Sync {
    // Fills the complete destination with cryptographically secure random bytes.
    fn fill(&self, destination: &mut [u8]) -> Result<(), AuthenticationError>;
}

// Uses the active platform random source for production key material.
#[derive(Default)]
pub struct SystemApiKeyMaterialProvider;

impl ApiKeyMaterialProvider for SystemApiKeyMaterialProvider {
    // Fills one destination from the operating system CSPRNG.
    fn fill(&self, destination: &mut [u8]) -> Result<(), AuthenticationError> {
        fill(destination).map_err(|_| AuthenticationError::EntropyUnavailable)
    }
}

// Derives one domain-separated verifier from a random salt and high-entropy secret.
pub(crate) fn api_key_verifier(salt: &[u8; 16], secret: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(VERIFIER_DOMAIN);
    digest.update(salt);
    digest.update(secret);
    digest.finalize().into()
}

// Compares two fixed verifiers without data-dependent early return.
pub(crate) fn verifiers_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}
