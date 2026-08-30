// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{CredentialId, Sha256Digest};

use crate::{
    NodeProtectionApi, NodeProtectionApiError, NodeProtectionEndpoint, NodeProtectionRequest,
    NodeProtectionResponse, NodeProtectionTransport, NodeProtectionTransportError,
    NodeProtectionTransportOutcome,
};

// Names the one process role established before any connection request is decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeProtectionConnectionRole {
    Watchdog,
    Gateway,
}

// Owns role confinement and durable Watchdog retirement for one authenticated native connection.
pub struct NodeProtectionConnection {
    api: Arc<NodeProtectionApi>,
    principal_id: CredentialId,
    endpoint: NodeProtectionEndpoint,
    role: NodeProtectionConnectionRole,
    watchdog_authority: Option<li_gateway_manager::GatewayProtectionAuthority>,
}

impl NodeProtectionConnection {
    // Creates one role-confined state after the native listener authenticates its peer executable.
    pub fn new(
        api: Arc<NodeProtectionApi>,
        principal_id: CredentialId,
        connection_id: Sha256Digest,
        role: NodeProtectionConnectionRole,
    ) -> Self {
        Self {
            endpoint: NodeProtectionEndpoint::new(api.clone(), connection_id),
            api,
            principal_id,
            role,
            watchdog_authority: None,
        }
    }

    // Returns the immutable identity every request and response must retain on this connection.
    pub const fn connection_id(&self) -> &Sha256Digest {
        self.endpoint.connection_id()
    }

    // Dispatches one document only when it belongs to this connection's established role.
    pub fn handle(&mut self, document: &[u8]) -> Result<Vec<u8>, NodeProtectionTransportError> {
        let request = NodeProtectionTransport::decode_request(document)?;
        if request.connection_id() != self.connection_id() {
            return Err(NodeProtectionTransportError::InvalidDocument);
        }
        let request_role = request_role(request.request())?;
        if self.role != request_role {
            return Err(NodeProtectionTransportError::InvalidDocument);
        }
        if request_role == NodeProtectionConnectionRole::Watchdog
            && self.watchdog_authority.is_none()
            && !matches!(
                request.request(),
                NodeProtectionRequest::BeginWatchdogSession(_)
            )
        {
            return Err(NodeProtectionTransportError::InvalidDocument);
        }
        let response = self.endpoint.handle(&self.principal_id, document)?;
        let decoded = NodeProtectionTransport::decode_response(&response)?;
        match decoded.outcome() {
            NodeProtectionTransportOutcome::Success(
                NodeProtectionResponse::WatchdogSessionBegan(authority),
            ) => {
                self.watchdog_authority = Some(authority.clone());
            }
            NodeProtectionTransportOutcome::Success(
                NodeProtectionResponse::WatchdogSessionEnded,
            ) => {
                self.watchdog_authority = None;
            }
            NodeProtectionTransportOutcome::Success(
                NodeProtectionResponse::ControllerBinding(_)
                | NodeProtectionResponse::SiteStatus(_),
            ) => {}
            NodeProtectionTransportOutcome::Success(NodeProtectionResponse::GatewaySnapshot(_)) => {
            }
            _ => {}
        }
        Ok(response)
    }

    // Retires an exact active Watchdog session before the native stream is forgotten.
    pub fn disconnect(&mut self) -> Result<(), NodeProtectionApiError> {
        let Some(authority) = self.watchdog_authority.take() else {
            return Ok(());
        };
        let request = crate::NodeProtectionEndRequest::new(
            authority.node_id().clone(),
            authority.watchdog_session_id().clone(),
            authority.watchdog_session_generation(),
        );
        match self.api.dispatch(
            &self.principal_id,
            NodeProtectionRequest::EndWatchdogSession(request),
        )? {
            NodeProtectionResponse::WatchdogSessionEnded => Ok(()),
            _ => Err(NodeProtectionApiError::Corrupt),
        }
    }
}

// Confines one connection to Watchdog mutation or Gateway read, never both.
fn request_role(
    request: &NodeProtectionRequest,
) -> Result<NodeProtectionConnectionRole, NodeProtectionTransportError> {
    match request {
        NodeProtectionRequest::BeginWatchdogSession(_)
        | NodeProtectionRequest::CommitWatchdogCycle(_)
        | NodeProtectionRequest::EndWatchdogSession(_)
        | NodeProtectionRequest::ResolveControllerBinding(_)
        | NodeProtectionRequest::ReadSiteStatus(_) => Ok(NodeProtectionConnectionRole::Watchdog),
        NodeProtectionRequest::ReadGatewaySnapshot(_) => Ok(NodeProtectionConnectionRole::Gateway),
    }
}
