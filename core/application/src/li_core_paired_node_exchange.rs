// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use li_core_cli::{NodePrivateDocumentExchangeError, NodePrivateDocumentExchangePort};
use li_core_interface::{NodeAddress, Sha256Digest};
use li_node_manager::{
    NodePairingCancellationPort, NodePrivateRemoteClientError, NodePrivateRemoteClientPort,
};

// Adapts one exact paired mTLS endpoint into the existing private Node document client.
pub struct CorePairedNodeDocumentExchange {
    client: Arc<dyn NodePrivateRemoteClientPort>,
    address: NodeAddress,
    port: u16,
    server_certificate_sha256: Sha256Digest,
    cancellation: Arc<dyn NodePairingCancellationPort>,
}

impl CorePairedNodeDocumentExchange {
    // Creates one endpoint-fixed exchange without discovery, public fallback, or retry policy.
    pub const fn new(
        client: Arc<dyn NodePrivateRemoteClientPort>,
        address: NodeAddress,
        port: u16,
        server_certificate_sha256: Sha256Digest,
        cancellation: Arc<dyn NodePairingCancellationPort>,
    ) -> Self {
        Self {
            client,
            address,
            port,
            server_certificate_sha256,
            cancellation,
        }
    }
}

impl NodePrivateDocumentExchangePort for CorePairedNodeDocumentExchange {
    // Preserves exact private transport bounds while redacting every native TLS diagnostic.
    fn exchange(
        &mut self,
        request: &[u8],
        timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
        self.client
            .exchange(
                &self.address,
                self.port,
                &self.server_certificate_sha256,
                request,
                timeout,
                maximum_response_bytes,
                self.cancellation.as_ref(),
            )
            .map_err(exchange_error)
    }
}

// Converts one closed paired transport failure into the existing CLI client vocabulary.
fn exchange_error(error: NodePrivateRemoteClientError) -> NodePrivateDocumentExchangeError {
    match error {
        NodePrivateRemoteClientError::TimedOut => NodePrivateDocumentExchangeError::TimedOut,
        NodePrivateRemoteClientError::RequestTooLarge => {
            NodePrivateDocumentExchangeError::RequestTooLarge
        }
        NodePrivateRemoteClientError::ResponseTooLarge => {
            NodePrivateDocumentExchangeError::ResponseTooLarge
        }
        NodePrivateRemoteClientError::MalformedResponse => {
            NodePrivateDocumentExchangeError::MalformedResponse
        }
        NodePrivateRemoteClientError::InvalidConfiguration
        | NodePrivateRemoteClientError::UnsafeFile
        | NodePrivateRemoteClientError::MalformedCertificate
        | NodePrivateRemoteClientError::MalformedPrivateKey
        | NodePrivateRemoteClientError::Unavailable
        | NodePrivateRemoteClientError::Cancelled
        | NodePrivateRemoteClientError::UntrustedPeer => {
            NodePrivateDocumentExchangeError::Unavailable
        }
    }
}
