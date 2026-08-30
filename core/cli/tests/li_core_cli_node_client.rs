// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use li_core_cli::{
    NodePrivateClient, NodePrivateClientConfiguration, NodePrivateClientConfigurationError,
    NodePrivateClientError, NodePrivateDocumentExchangeError, NodePrivateDocumentExchangePort,
    NodeRequestIdentityError, NodeRequestIdentitySource, SystemNodeRequestIdentitySource,
};
use li_core_interface::{Sha256Digest, TechnicalName};
use li_node_manager::{
    NodePrivateRemoteError, NodePrivateRequest, NodePrivateResponse, NodePrivateTransport,
    NodePrivateTransportOutcome, NodePrivateTransportResponse,
};

const RESPONSE_LIMIT: usize = 4096;

// Holds one deterministic exchange observation without exposing request bytes in failures.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExchangeObservation {
    request: NodePrivateRequest,
    timeout: Duration,
    maximum_response_bytes: usize,
}

// Names one deterministic response behavior for the native exchange mock.
enum ExchangeStep {
    Success(NodePrivateResponse),
    Remote {
        code: &'static str,
        message: &'static str,
    },
    Mismatched(NodePrivateResponse),
    Bytes(Vec<u8>),
    Error(NodePrivateDocumentExchangeError),
}

// Executes scripted responses through the real Node request and response codecs.
struct ExchangeMock {
    steps: VecDeque<ExchangeStep>,
    observations: Rc<RefCell<Vec<ExchangeObservation>>>,
}

impl ExchangeMock {
    // Creates one exchange with exact ordered behavior and shared observations.
    fn new(
        steps: impl IntoIterator<Item = ExchangeStep>,
    ) -> (Self, Rc<RefCell<Vec<ExchangeObservation>>>) {
        let observations = Rc::new(RefCell::new(Vec::new()));
        (
            Self {
                steps: steps.into_iter().collect(),
                observations: Rc::clone(&observations),
            },
            observations,
        )
    }
}

impl NodePrivateDocumentExchangePort for ExchangeMock {
    // Decodes the actual request and returns the next response under observed transport limits.
    fn exchange(
        &mut self,
        request: &[u8],
        timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
        let request = NodePrivateTransport::decode_request(request).expect("typed request");
        self.observations.borrow_mut().push(ExchangeObservation {
            request: request.request().clone(),
            timeout,
            maximum_response_bytes,
        });
        match self.steps.pop_front().expect("scripted exchange step") {
            ExchangeStep::Success(response) => {
                NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
                    request.request_id().clone(),
                    NodePrivateTransportOutcome::Success(response),
                ))
                .map_err(|_| NodePrivateDocumentExchangeError::Unavailable)
            }
            ExchangeStep::Remote { code, message } => {
                NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
                    request.request_id().clone(),
                    NodePrivateTransportOutcome::Failure(
                        NodePrivateRemoteError::new(
                            TechnicalName::parse(code).expect("remote code"),
                            message,
                        )
                        .expect("remote error"),
                    ),
                ))
                .map_err(|_| NodePrivateDocumentExchangeError::Unavailable)
            }
            ExchangeStep::Mismatched(response) => {
                NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
                    digest('f'),
                    NodePrivateTransportOutcome::Success(response),
                ))
                .map_err(|_| NodePrivateDocumentExchangeError::Unavailable)
            }
            ExchangeStep::Bytes(bytes) => Ok(bytes),
            ExchangeStep::Error(error) => Err(error),
        }
    }
}

// Returns exact queued request identities or one deterministic entropy failure.
struct IdentityMock {
    values: VecDeque<Result<Sha256Digest, NodeRequestIdentityError>>,
}

impl IdentityMock {
    // Creates one identity source from exact ordered results.
    fn new(
        values: impl IntoIterator<Item = Result<Sha256Digest, NodeRequestIdentityError>>,
    ) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }
}

impl NodeRequestIdentitySource for IdentityMock {
    // Returns the next exact identity result without generating random test state.
    fn next_request_id(&mut self) -> Result<Sha256Digest, NodeRequestIdentityError> {
        self.values.pop_front().expect("scripted request identity")
    }
}

// Creates one canonical repeated-character digest.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Creates one client with the narrow response bound used by the transport tests.
fn client(
    step: ExchangeStep,
) -> (
    NodePrivateClient<ExchangeMock, IdentityMock>,
    Rc<RefCell<Vec<ExchangeObservation>>>,
) {
    let (exchange, observations) = ExchangeMock::new([step]);
    let configuration =
        NodePrivateClientConfiguration::new(Duration::from_millis(250), RESPONSE_LIMIT)
            .expect("configuration");
    (
        NodePrivateClient::new(
            exchange,
            IdentityMock::new([Ok(digest('a'))]),
            configuration,
        ),
        observations,
    )
}

// Routes a typed request through the real codec with the exact configured time and size limits.
#[test]
fn client_routes_typed_request_with_explicit_bounds() {
    let (mut client, observations) = client(ExchangeStep::Success(NodePrivateResponse::Nodes(
        Vec::new(),
    )));
    assert_eq!(
        client.execute(NodePrivateRequest::ReadNodes),
        Ok(NodePrivateResponse::Nodes(Vec::new()))
    );
    assert_eq!(
        observations.borrow().as_slice(),
        &[ExchangeObservation {
            request: NodePrivateRequest::ReadNodes,
            timeout: Duration::from_millis(250),
            maximum_response_bytes: RESPONSE_LIMIT,
        }]
    );
    assert_eq!(
        client.configuration().maximum_response_bytes(),
        RESPONSE_LIMIT
    );
}

// Fails closed for malformed, truncated, oversized, mismatched, timed-out, and entropy paths.
#[test]
fn client_failure_matrix_rejects_every_transport_boundary() {
    let valid = NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
        digest('a'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::Nodes(Vec::new())),
    ))
    .expect("valid response");
    let mut truncated = valid;
    truncated.pop();
    let cases = [
        (
            ExchangeStep::Bytes(b"not-json".to_vec()),
            NodePrivateClientError::MalformedResponse,
        ),
        (
            ExchangeStep::Bytes(truncated),
            NodePrivateClientError::MalformedResponse,
        ),
        (
            ExchangeStep::Bytes(vec![b'x'; RESPONSE_LIMIT + 1]),
            NodePrivateClientError::ResponseTooLarge,
        ),
        (
            ExchangeStep::Mismatched(NodePrivateResponse::Nodes(Vec::new())),
            NodePrivateClientError::MismatchedResponse,
        ),
        (
            ExchangeStep::Error(NodePrivateDocumentExchangeError::TimedOut),
            NodePrivateClientError::TimedOut,
        ),
        (
            ExchangeStep::Error(NodePrivateDocumentExchangeError::Unavailable),
            NodePrivateClientError::Unavailable,
        ),
        (
            ExchangeStep::Error(NodePrivateDocumentExchangeError::NotConfigured),
            NodePrivateClientError::NotConfigured,
        ),
        (
            ExchangeStep::Error(NodePrivateDocumentExchangeError::RequestTooLarge),
            NodePrivateClientError::RequestTooLarge,
        ),
        (
            ExchangeStep::Error(NodePrivateDocumentExchangeError::ResponseTooLarge),
            NodePrivateClientError::ResponseTooLarge,
        ),
        (
            ExchangeStep::Error(NodePrivateDocumentExchangeError::MalformedResponse),
            NodePrivateClientError::MalformedResponse,
        ),
    ];
    for (step, expected) in cases {
        let (mut client, _) = client(step);
        assert_eq!(client.execute(NodePrivateRequest::ReadNodes), Err(expected));
    }

    let (exchange, _) = ExchangeMock::new([ExchangeStep::Success(NodePrivateResponse::Nodes(
        Vec::new(),
    ))]);
    let mut client = NodePrivateClient::new(
        exchange,
        IdentityMock::new([Err(NodeRequestIdentityError::Unavailable)]),
        NodePrivateClientConfiguration::default(),
    );
    assert_eq!(
        client.execute(NodePrivateRequest::ReadNodes),
        Err(NodePrivateClientError::IdentityUnavailable)
    );
}

// Drops the remote message so a secret cannot survive Display or Debug formatting.
#[test]
fn remote_failure_redacts_secret_bearing_message() {
    let secret = "Bearer li_secret_material_that_must_not_escape";
    let (mut first_client, _) = client(ExchangeStep::Remote {
        code: "authorization_denied",
        message: secret,
    });
    let error = first_client
        .execute(NodePrivateRequest::ReadNodes)
        .expect_err("remote denial");
    assert_eq!(
        error,
        NodePrivateClientError::RemoteRejected {
            code: "authorization_denied".to_owned(),
        }
    );
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{error:?}").contains(secret));

    let secret_code = "bearer_private_secret";
    let (mut second_client, _) = client(ExchangeStep::Remote {
        code: secret_code,
        message: "rejected",
    });
    let error = second_client
        .execute(NodePrivateRequest::ReadNodes)
        .expect_err("unknown remote code");
    assert_eq!(
        error,
        NodePrivateClientError::RemoteRejected {
            code: "remote_error".to_owned(),
        }
    );
    assert!(!error.to_string().contains(secret_code));
    assert!(!format!("{error:?}").contains(secret_code));
}

// Rejects zero, unbounded, and excessive transport limits before any native I/O.
#[test]
fn client_configuration_closes_timeout_and_response_bounds() {
    assert_eq!(
        NodePrivateClientConfiguration::new(Duration::ZERO, 1),
        Err(NodePrivateClientConfigurationError::InvalidTimeout)
    );
    assert_eq!(
        NodePrivateClientConfiguration::new(Duration::from_secs(61), 1),
        Err(NodePrivateClientConfigurationError::InvalidTimeout)
    );
    assert_eq!(
        NodePrivateClientConfiguration::new(Duration::from_secs(1), 0),
        Err(NodePrivateClientConfigurationError::InvalidResponseBound)
    );
    assert_eq!(
        NodePrivateClientConfiguration::new(Duration::from_secs(1), 1024 * 1024 + 1),
        Err(NodePrivateClientConfigurationError::InvalidResponseBound)
    );
}

// Reads consecutive exact entropy blocks and rejects relative or exhausted sources.
#[test]
fn system_identity_source_uses_only_the_injected_absolute_entropy_path() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("entropy");
    std::fs::write(&path, [vec![0x12; 32], vec![0xab; 32]].concat()).expect("entropy fixture");
    let mut source = SystemNodeRequestIdentitySource::open(&path).expect("identity source");
    assert_eq!(
        source.next_request_id().expect("first").as_str(),
        "12".repeat(32)
    );
    assert_eq!(
        source.next_request_id().expect("second").as_str(),
        "ab".repeat(32)
    );
    assert_eq!(
        source.next_request_id(),
        Err(NodeRequestIdentityError::Unavailable)
    );
    assert!(SystemNodeRequestIdentitySource::open(Path::new("relative")).is_err());
}
