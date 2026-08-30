// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use li_core_interface::{NodeId, NodeRole, NodeState, Sha256Digest};
use sha2::{Digest, Sha256};

use crate::{
    NodeConfiguration, NodePrivateRequest, NodePrivateResponse, NodePrivateTransport,
    NodePrivateTransportOutcome, NodePrivateTransportRequest, NodePrivateUnixPathGuard,
    NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};

// Names one stable process-owned Node health failure without exposing native paths or state bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeHealthError {
    InvalidContract,
    EndpointUnavailable,
    InvalidResponse,
    NotReady,
}

impl fmt::Display for NodeHealthError {
    // Presents fixed service-readiness language without identity or filesystem detail.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract => formatter.write_str("Node health contract is invalid"),
            Self::EndpointUnavailable => formatter.write_str("Node health endpoint is unavailable"),
            Self::InvalidResponse => formatter.write_str("Node health response is invalid"),
            Self::NotReady => formatter.write_str("Node is not ready"),
        }
    }
}

impl Error for NodeHealthError {}

// Exchanges one bounded health request through an explicit local process boundary.
pub trait NodeHealthExchange: Send + Sync {
    // Returns exactly one response document from the owner-authenticated Node listener.
    fn exchange(
        &self,
        socket_path: &Path,
        owner_uid: u32,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, NodeHealthError>;
}

// Supplies the production owner-checked Unix-domain health exchange.
#[derive(Default)]
pub struct SystemNodeHealthExchange;

impl NodeHealthExchange for SystemNodeHealthExchange {
    // Validates the socket identity and completes one length-framed request and response.
    fn exchange(
        &self,
        socket_path: &Path,
        owner_uid: u32,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, NodeHealthError> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(60)
            || request.is_empty()
            || request.len() > NODE_PRIVATE_MAX_DOCUMENT_BYTES
        {
            return Err(NodeHealthError::InvalidContract);
        }
        let _path_guard = NodePrivateUnixPathGuard::acquire(socket_path, owner_uid)
            .map_err(|_| NodeHealthError::EndpointUnavailable)?;
        let metadata = std::fs::symlink_metadata(socket_path)
            .map_err(|_| NodeHealthError::EndpointUnavailable)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(NodeHealthError::EndpointUnavailable);
        }
        let mut stream =
            UnixStream::connect(socket_path).map_err(|_| NodeHealthError::EndpointUnavailable)?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|_| NodeHealthError::EndpointUnavailable)?;
        write_document(&mut stream, request)?;
        read_document(&mut stream)
    }
}

// Owns the exact local API round trip used to prove Node process readiness.
pub struct NodeHealthProbe {
    exchange: Box<dyn NodeHealthExchange>,
}

impl NodeHealthProbe {
    // Creates one probe without discovering a socket, owner, identity, or timeout.
    pub fn new(exchange: Box<dyn NodeHealthExchange>) -> Self {
        Self { exchange }
    }

    // Proves the live listener can read the exact active durable local Node identity.
    pub fn observe(
        &self,
        configuration: &NodeConfiguration,
        expected_node_id: &NodeId,
        timeout: Duration,
    ) -> Result<(), NodeHealthError> {
        self.observe_identity(configuration, Some(expected_node_id), None, timeout)
    }

    // Proves the live listener returns the exact setup identity and role without opening SQLite.
    pub fn observe_expected(
        &self,
        configuration: &NodeConfiguration,
        expected_node_id: Option<&NodeId>,
        expected_role: NodeRole,
        timeout: Duration,
    ) -> Result<(), NodeHealthError> {
        self.observe_identity(
            configuration,
            expected_node_id,
            Some(expected_role),
            timeout,
        )
    }

    // Completes one role-aware private-API observation through a single closed decoder path.
    fn observe_identity(
        &self,
        configuration: &NodeConfiguration,
        expected_node_id: Option<&NodeId>,
        expected_role: Option<NodeRole>,
        timeout: Duration,
    ) -> Result<(), NodeHealthError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(NodeHealthError::InvalidContract);
        }
        let request_id = match expected_node_id {
            Some(node_id) => health_request_id(node_id)?,
            None => role_health_request_id(
                configuration,
                expected_role.ok_or(NodeHealthError::InvalidContract)?,
            )?,
        };
        let request = NodePrivateTransport::encode_request(&NodePrivateTransportRequest::new(
            request_id.clone(),
            NodePrivateRequest::ReadLocalNode,
        ))
        .map_err(|_| NodeHealthError::InvalidContract)?;
        let response = self.exchange.exchange(
            configuration.local_server().socket_path(),
            configuration.local_server().owner_uid(),
            &request,
            timeout,
        )?;
        let response = NodePrivateTransport::decode_response(&response)
            .map_err(|_| NodeHealthError::InvalidResponse)?;
        if response.request_id() != &request_id {
            return Err(NodeHealthError::InvalidResponse);
        }
        match response.outcome() {
            NodePrivateTransportOutcome::Success(NodePrivateResponse::LocalNode(node))
                if expected_node_id
                    .map(|node_id| node.identity().node_id() == node_id)
                    .unwrap_or(true)
                    && expected_role
                        .map(|role| node.role() == role)
                        .unwrap_or(true)
                    && node.state() == NodeState::Active =>
            {
                Ok(())
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::LocalNode(_)) => {
                Err(NodeHealthError::NotReady)
            }
            _ => Err(NodeHealthError::InvalidResponse),
        }
    }
}

// Derives one role-bound correlation identity for non-setup service activation health.
fn role_health_request_id(
    configuration: &NodeConfiguration,
    role: NodeRole,
) -> Result<Sha256Digest, NodeHealthError> {
    let mut digest = Sha256::new();
    digest.update(b"li_node_role_health_v1\0");
    digest.update(
        configuration
            .local_server()
            .socket_path()
            .as_os_str()
            .as_encoded_bytes(),
    );
    digest.update(configuration.local_server().owner_uid().to_be_bytes());
    digest.update(match role {
        NodeRole::Main => b"main".as_slice(),
        NodeRole::Child => b"child".as_slice(),
    });
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| NodeHealthError::InvalidContract)
}

// Derives one stable correlation identity without requiring mutable process entropy.
fn health_request_id(node_id: &NodeId) -> Result<Sha256Digest, NodeHealthError> {
    let mut digest = Sha256::new();
    digest.update(b"li_node_health_v1\0");
    digest.update(node_id.as_str().as_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| NodeHealthError::InvalidContract)
}

// Writes one complete bounded big-endian length frame.
fn write_document(stream: &mut UnixStream, document: &[u8]) -> Result<(), NodeHealthError> {
    let length = u32::try_from(document.len()).map_err(|_| NodeHealthError::InvalidContract)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(document))
        .map_err(|_| NodeHealthError::EndpointUnavailable)
}

// Reads one complete bounded big-endian length frame.
fn read_document(stream: &mut UnixStream) -> Result<Vec<u8>, NodeHealthError> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| NodeHealthError::EndpointUnavailable)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| NodeHealthError::InvalidResponse)?;
    if length == 0 || length > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodeHealthError::InvalidResponse);
    }
    let mut response = vec![0_u8; length];
    stream
        .read_exact(&mut response)
        .map_err(|_| NodeHealthError::EndpointUnavailable)?;
    Ok(response)
}
