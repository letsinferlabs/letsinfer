// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{Sha256Digest, UnixMilliseconds};
use li_node_manager::{
    node_pairing_candidate_offer_transcript, NodeManager, NodePairingCandidateOffer,
    NodePairingCandidateOfferPort, NodePairingTransportError,
};
use li_pairing_manager::{PairingCandidateTrustProvider, PairingClock};

const CANDIDATE_OFFER_LIFETIME_MILLISECONDS: u64 = 30_000;

// Derives short-lived signed candidate offers from NodeManager and existing local key material.
pub struct CorePairingCandidate {
    nodes: Arc<NodeManager>,
    trust: Arc<dyn PairingCandidateTrustProvider>,
    certificate_sha256: Sha256Digest,
    clock: Arc<dyn PairingClock>,
}

impl CorePairingCandidate {
    // Creates one candidate signer from exact Node, trust, certificate, and clock capabilities.
    pub const fn new(
        nodes: Arc<NodeManager>,
        trust: Arc<dyn PairingCandidateTrustProvider>,
        certificate_sha256: Sha256Digest,
        clock: Arc<dyn PairingClock>,
    ) -> Self {
        Self {
            nodes,
            trust,
            certificate_sha256,
            clock,
        }
    }
}

impl NodePairingCandidateOfferPort for CorePairingCandidate {
    // Returns one nonce-bound offer signed by the exact existing local identity.
    fn candidate_offer(
        &self,
        request_nonce: &Sha256Digest,
    ) -> Result<NodePairingCandidateOffer, NodePairingTransportError> {
        let candidate = self
            .nodes
            .local_node()
            .map_err(|_| NodePairingTransportError::Unavailable)?;
        let (public_key, public_key_sha256) = self
            .trust
            .public_key()
            .map_err(|_| NodePairingTransportError::Unavailable)?;
        let issued_at = self
            .clock
            .now()
            .map_err(|_| NodePairingTransportError::Unavailable)?;
        let expires_at = UnixMilliseconds::new(
            issued_at
                .value()
                .checked_add(CANDIDATE_OFFER_LIFETIME_MILLISECONDS)
                .ok_or(NodePairingTransportError::Unavailable)?,
        );
        let transcript = node_pairing_candidate_offer_transcript(
            &candidate,
            &public_key_sha256,
            &self.certificate_sha256,
            request_nonce,
            issued_at,
            expires_at,
        );
        let signature = self
            .trust
            .sign(&transcript)
            .map_err(|_| NodePairingTransportError::Unavailable)?;
        NodePairingCandidateOffer::new(
            candidate,
            public_key,
            public_key_sha256,
            self.certificate_sha256.clone(),
            request_nonce.clone(),
            issued_at,
            expires_at,
            signature,
        )
    }
}
