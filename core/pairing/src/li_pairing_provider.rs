// SPDX-License-Identifier: AGPL-3.0-only

use getrandom::fill;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    PairingAdvertisement, PairingCandidate, PairingContext, PairingCredentials, PairingError,
    PairingMembershipState,
};
use li_core_interface::{NetworkInterfaceName, NodeAddress, Sha256Digest};

// Supplies current time explicitly for invitation expiry and deterministic tests.
pub trait PairingClock: Send + Sync {
    // Returns the current Unix timestamp in milliseconds.
    fn now(&self) -> Result<li_core_interface::UnixMilliseconds, PairingError>;
}

// Reads production pairing time from the active host.
#[derive(Default)]
pub struct SystemPairingClock;

impl PairingClock for SystemPairingClock {
    // Returns current host time without accepting a pre-epoch clock.
    fn now(&self) -> Result<li_core_interface::UnixMilliseconds, PairingError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PairingError::StateUnavailable)?;
        let milliseconds =
            u64::try_from(duration.as_millis()).map_err(|_| PairingError::StateUnavailable)?;
        Ok(li_core_interface::UnixMilliseconds::new(milliseconds))
    }
}

// Supplies cryptographically secure random pairing material.
pub trait PairingMaterialProvider: Send + Sync {
    // Fills the complete destination with random bytes.
    fn fill(&self, destination: &mut [u8]) -> Result<(), PairingError>;
}

// Uses the active platform CSPRNG for production pairing material.
#[derive(Default)]
pub struct SystemPairingMaterialProvider;

impl PairingMaterialProvider for SystemPairingMaterialProvider {
    // Fills one destination from the operating-system random source.
    fn fill(&self, destination: &mut [u8]) -> Result<(), PairingError> {
        fill(destination).map_err(|_| PairingError::EntropyUnavailable)
    }
}

// Publishes and removes bounded pairing discovery records.
pub trait PairingDiscoveryProvider: Send + Sync {
    // Publishes one invitation without credentials or hardware details.
    fn publish(&self, advertisement: &PairingAdvertisement) -> Result<(), PairingError>;

    // Removes one invitation advertisement after close or consumption.
    fn unpublish(&self, invite_id: &li_core_interface::PairingInviteId);
}

// Verifies direct-link authorization for ConnectX pairing.
pub trait PairingDirectLinkProvider: Send + Sync {
    // Requires the peer address to arrive through the bound direct interface.
    fn verify(
        &self,
        interface: &NetworkInterfaceName,
        peer_address: &NodeAddress,
    ) -> Result<(), PairingError>;
}

// Isolates proof verification, certificate issuance, and membership signing.
pub trait PairingTrustProvider: Send + Sync {
    // Verifies candidate possession and returns its public-key fingerprint.
    fn verify_candidate(
        &self,
        public_key: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<Sha256Digest, PairingError>;

    // Issues public credentials and signs one validated membership result.
    fn issue_membership(
        &self,
        context: &PairingContext,
        candidate: &PairingCandidate,
        public_key_fingerprint: &Sha256Digest,
        state: PairingMembershipState,
        approval_expires_at: Option<li_core_interface::UnixMilliseconds>,
    ) -> Result<PairingCredentials, PairingError>;
}
