// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use li_node_manager::{
    NodePrivateRequest, NodePrivateResponse, NodePrivateTransport, NodePrivateTransportOutcome,
    NodePrivateTransportRequest, NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};

const MAX_TIMEOUT: Duration = Duration::from_secs(60);

// Describes the bounded exchange limits applied to every private Node request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodePrivateClientConfiguration {
    timeout: Duration,
    maximum_response_bytes: usize,
}

impl NodePrivateClientConfiguration {
    // Creates one client configuration only when both transport limits are useful and bounded.
    pub fn new(
        timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<Self, NodePrivateClientConfigurationError> {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(NodePrivateClientConfigurationError::InvalidTimeout);
        }
        if maximum_response_bytes == 0 || maximum_response_bytes > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
            return Err(NodePrivateClientConfigurationError::InvalidResponseBound);
        }
        Ok(Self {
            timeout,
            maximum_response_bytes,
        })
    }

    // Returns the complete-request timeout passed to the native exchange provider.
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    // Returns the largest response document accepted from the Node endpoint.
    pub const fn maximum_response_bytes(self) -> usize {
        self.maximum_response_bytes
    }
}

impl Default for NodePrivateClientConfiguration {
    // Supplies the ordinary five-second, one-megabyte private transport limits.
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            maximum_response_bytes: NODE_PRIVATE_MAX_DOCUMENT_BYTES,
        }
    }
}

// Describes an invalid private Node transport configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateClientConfigurationError {
    InvalidTimeout,
    InvalidResponseBound,
}

impl fmt::Display for NodePrivateClientConfigurationError {
    // Presents the failed configuration boundary without exposing platform details.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeout => formatter
                .write_str("private Node timeout must be between one nanosecond and 60 seconds"),
            Self::InvalidResponseBound => formatter
                .write_str("private Node response bound must be between one byte and one megabyte"),
        }
    }
}

impl Error for NodePrivateClientConfigurationError {}

// Names closed native I/O outcomes without retaining provider or secret-bearing text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateDocumentExchangeError {
    NotConfigured,
    TimedOut,
    Unavailable,
    RequestTooLarge,
    ResponseTooLarge,
    MalformedResponse,
}

// Exchanges one complete private Node document through the composition-owned native transport.
pub trait NodePrivateDocumentExchangePort {
    // Sends one request and returns one complete response under explicit time and size bounds.
    fn exchange(
        &mut self,
        request: &[u8],
        timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, NodePrivateDocumentExchangeError>;
}

// Describes failure to produce a fresh private request correlation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRequestIdentityError {
    Unavailable,
}

// Supplies fresh request identities without coupling the client to an entropy implementation.
pub trait NodeRequestIdentitySource {
    // Returns one fresh canonical SHA-256-shaped correlation identity.
    fn next_request_id(&mut self) -> Result<Sha256Digest, NodeRequestIdentityError>;
}

// Reads exact native entropy bytes from one composition-selected file descriptor.
pub struct SystemNodeRequestIdentitySource {
    entropy: File,
}

impl SystemNodeRequestIdentitySource {
    // Opens one explicit absolute entropy path without discovering or falling back to another source.
    pub fn open(path: &Path) -> Result<Self, NodeRequestIdentityError> {
        if !path.is_absolute() {
            return Err(NodeRequestIdentityError::Unavailable);
        }
        File::open(path)
            .map(|entropy| Self { entropy })
            .map_err(|_| NodeRequestIdentityError::Unavailable)
    }
}

impl NodeRequestIdentitySource for SystemNodeRequestIdentitySource {
    // Reads exactly 256 entropy bits and projects them into the wire correlation type.
    fn next_request_id(&mut self) -> Result<Sha256Digest, NodeRequestIdentityError> {
        let mut bytes = [0_u8; 32];
        self.entropy
            .read_exact(&mut bytes)
            .map_err(|_| NodeRequestIdentityError::Unavailable)?;
        Sha256Digest::parse(&lower_hex(&bytes)).map_err(|_| NodeRequestIdentityError::Unavailable)
    }
}

// Describes one fail-closed client result without preserving raw documents or provider messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePrivateClientError {
    NotConfigured,
    TimedOut,
    Unavailable,
    RequestTooLarge,
    ResponseTooLarge,
    IdentityUnavailable,
    MalformedResponse,
    MismatchedResponse,
    RemoteRejected { code: String },
}

impl fmt::Display for NodePrivateClientError {
    // Presents stable redacted language for each private client failure.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => formatter.write_str("this host has no configured Node endpoint"),
            Self::TimedOut => formatter.write_str("the private Node request timed out"),
            Self::Unavailable => formatter.write_str("the private Node endpoint is unavailable"),
            Self::RequestTooLarge => formatter.write_str("the private Node request is oversized"),
            Self::ResponseTooLarge => formatter.write_str("the private Node response is oversized"),
            Self::IdentityUnavailable => {
                formatter.write_str("a private Node request identity is unavailable")
            }
            Self::MalformedResponse => {
                formatter.write_str("the private Node response is malformed")
            }
            Self::MismatchedResponse => {
                formatter.write_str("the private Node response identity does not match its request")
            }
            Self::RemoteRejected { code } => {
                write!(formatter, "the private Node request was rejected ({code})")
            }
        }
    }
}

impl Error for NodePrivateClientError {}

// Owns request identity, codec, bounds, and response correlation for the existing Node wire contract.
pub struct NodePrivateClient<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    exchange: Exchange,
    identity: Identity,
    configuration: NodePrivateClientConfiguration,
}

impl<Exchange, Identity> NodePrivateClient<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    // Creates one concrete client from explicit native exchange and identity dependencies.
    pub const fn new(
        exchange: Exchange,
        identity: Identity,
        configuration: NodePrivateClientConfiguration,
    ) -> Self {
        Self {
            exchange,
            identity,
            configuration,
        }
    }

    // Executes one typed request through the existing closed Node codec and verifies correlation.
    pub fn execute(
        &mut self,
        request: NodePrivateRequest,
    ) -> Result<NodePrivateResponse, NodePrivateClientError> {
        self.execute_correlated(|_request_id| request)
    }

    // Executes one request constructed from the exact fresh transport identity it must bind.
    pub fn execute_correlated<Factory>(
        &mut self,
        factory: Factory,
    ) -> Result<NodePrivateResponse, NodePrivateClientError>
    where
        Factory: FnOnce(&Sha256Digest) -> NodePrivateRequest,
    {
        let request_id = self
            .identity
            .next_request_id()
            .map_err(|_| NodePrivateClientError::IdentityUnavailable)?;
        let request = factory(&request_id);
        let document = NodePrivateTransport::encode_request(&NodePrivateTransportRequest::new(
            request_id.clone(),
            request,
        ))
        .map_err(|_| NodePrivateClientError::RequestTooLarge)?;
        let response = self
            .exchange
            .exchange(
                &document,
                self.configuration.timeout(),
                self.configuration.maximum_response_bytes(),
            )
            .map_err(client_exchange_error)?;
        if response.len() > self.configuration.maximum_response_bytes() {
            return Err(NodePrivateClientError::ResponseTooLarge);
        }
        let response = NodePrivateTransport::decode_response(&response)
            .map_err(|_| NodePrivateClientError::MalformedResponse)?;
        if response.request_id() != &request_id {
            return Err(NodePrivateClientError::MismatchedResponse);
        }
        match response.into_outcome() {
            NodePrivateTransportOutcome::Success(response) => Ok(response),
            NodePrivateTransportOutcome::Failure(error) => {
                Err(NodePrivateClientError::RemoteRejected {
                    code: public_remote_error_code(error.code().as_str()).to_owned(),
                })
            }
        }
    }

    // Returns the immutable limits used for every request in this client lifecycle.
    pub const fn configuration(&self) -> NodePrivateClientConfiguration {
        self.configuration
    }

    // Returns the exchange provider for composition-level inspection after execution.
    pub const fn exchange(&self) -> &Exchange {
        &self.exchange
    }
}

// Preserves only response codes the existing Node endpoint can produce itself.
fn public_remote_error_code(code: &str) -> &'static str {
    match code {
        "authorization_denied" => "authorization_denied",
        "manager_error" => "manager_error",
        "gateway_authorization_denied" => "gateway_authorization_denied",
        "gateway_role_denied" => "gateway_role_denied",
        "gateway_contract_invalid" => "gateway_contract_invalid",
        "gateway_replay_conflict" => "gateway_replay_conflict",
        "gateway_state_corrupt" => "gateway_state_corrupt",
        "gateway_unavailable" => "gateway_unavailable",
        "uninstall_in_progress" => "uninstall_in_progress",
        "uninstall_busy" => "uninstall_busy",
        "uninstall_session_conflict" => "uninstall_session_conflict",
        "uninstall_barrier_unavailable" => "uninstall_barrier_unavailable",
        _ => "remote_error",
    }
}

// Maps one closed native I/O result without copying a provider error message.
fn client_exchange_error(error: NodePrivateDocumentExchangeError) -> NodePrivateClientError {
    match error {
        NodePrivateDocumentExchangeError::NotConfigured => NodePrivateClientError::NotConfigured,
        NodePrivateDocumentExchangeError::TimedOut => NodePrivateClientError::TimedOut,
        NodePrivateDocumentExchangeError::Unavailable => NodePrivateClientError::Unavailable,
        NodePrivateDocumentExchangeError::RequestTooLarge => {
            NodePrivateClientError::RequestTooLarge
        }
        NodePrivateDocumentExchangeError::ResponseTooLarge => {
            NodePrivateClientError::ResponseTooLarge
        }
        NodePrivateDocumentExchangeError::MalformedResponse => {
            NodePrivateClientError::MalformedResponse
        }
    }
}

// Encodes native entropy bytes into canonical lowercase hexadecimal text.
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
