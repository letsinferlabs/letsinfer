// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::CorePairedNodeDocumentExchange;
use li_core_cli::{NodePrivateDocumentExchangeError, NodePrivateDocumentExchangePort};
use li_core_interface::{NodeAddress, Sha256Digest};
use li_node_manager::{
    NodePairingCancellationPort, NodePrivateRemoteClientError, NodePrivateRemoteClientPort,
};

// Records one exact paired-client exchange without performing network work.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedExchange {
    address: NodeAddress,
    port: u16,
    certificate_sha256: Sha256Digest,
    request: Vec<u8>,
    timeout: Duration,
    maximum_response_bytes: usize,
    cancelled: bool,
}

// Returns one deterministic remote result and retains the complete bounded call.
struct RemoteClientMock {
    result: Result<Vec<u8>, NodePrivateRemoteClientError>,
    calls: Mutex<Vec<ObservedExchange>>,
}

impl NodePrivateRemoteClientPort for RemoteClientMock {
    // Records every request field before returning the configured closed result.
    fn exchange(
        &self,
        address: &NodeAddress,
        port: u16,
        expected_server_certificate_sha256: &Sha256Digest,
        request: &[u8],
        timeout: Duration,
        maximum_response_bytes: usize,
        cancellation: &dyn NodePairingCancellationPort,
    ) -> Result<Vec<u8>, NodePrivateRemoteClientError> {
        self.calls.lock().expect("calls").push(ObservedExchange {
            address: address.clone(),
            port,
            certificate_sha256: expected_server_certificate_sha256.clone(),
            request: request.to_vec(),
            timeout,
            maximum_response_bytes,
            cancelled: cancellation.is_cancelled(),
        });
        self.result.clone()
    }
}

// Supplies one deterministic cancellation state to the paired exchange.
struct Cancellation(bool);

impl NodePairingCancellationPort for Cancellation {
    // Returns the configured workflow cancellation state.
    fn is_cancelled(&self) -> bool {
        self.0
    }
}

// Forwards one private document only to the exact configured paired endpoint and bounds.
#[test]
fn paired_exchange_forwards_exact_endpoint_identity_and_bounds() {
    let client = Arc::new(RemoteClientMock {
        result: Ok(b"response".to_vec()),
        calls: Mutex::new(Vec::new()),
    });
    let mut exchange = CorePairedNodeDocumentExchange::new(
        client.clone(),
        NodeAddress::parse("main.local").expect("address"),
        9_770,
        digest('a'),
        Arc::new(Cancellation(false)),
    );

    assert_eq!(
        exchange.exchange(b"request", Duration::from_secs(7), 16_384),
        Ok(b"response".to_vec())
    );
    assert_eq!(
        *client.calls.lock().expect("calls"),
        [ObservedExchange {
            address: NodeAddress::parse("main.local").expect("address"),
            port: 9_770,
            certificate_sha256: digest('a'),
            request: b"request".to_vec(),
            timeout: Duration::from_secs(7),
            maximum_response_bytes: 16_384,
            cancelled: false,
        }]
    );
}

// Redacts trust and cancellation failures while preserving exact bounded transport outcomes.
#[test]
fn paired_exchange_maps_closed_remote_failures_without_diagnostics() {
    for (remote, expected) in [
        (
            NodePrivateRemoteClientError::UntrustedPeer,
            NodePrivateDocumentExchangeError::Unavailable,
        ),
        (
            NodePrivateRemoteClientError::Cancelled,
            NodePrivateDocumentExchangeError::Unavailable,
        ),
        (
            NodePrivateRemoteClientError::TimedOut,
            NodePrivateDocumentExchangeError::TimedOut,
        ),
        (
            NodePrivateRemoteClientError::ResponseTooLarge,
            NodePrivateDocumentExchangeError::ResponseTooLarge,
        ),
    ] {
        let client = Arc::new(RemoteClientMock {
            result: Err(remote),
            calls: Mutex::new(Vec::new()),
        });
        let mut exchange = CorePairedNodeDocumentExchange::new(
            client,
            NodeAddress::parse("main.local").expect("address"),
            9_770,
            digest('a'),
            Arc::new(Cancellation(true)),
        );
        assert_eq!(
            exchange.exchange(b"secret-request", Duration::from_secs(1), 1_024),
            Err(expected)
        );
        assert!(!format!("{expected:?}").contains("secret-request"));
    }
}

// Returns one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}
