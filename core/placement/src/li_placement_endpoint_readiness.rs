// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use li_core_interface::PlacementEndpoint;

use crate::{LinuxEndpointReadinessProvider, MacosEndpointReadinessProvider, PlacementError};

// Checks that one exact placement endpoint accepts a bounded native connection.
pub struct SystemPlacementEndpointReadinessProvider {
    timeout: Duration,
}

impl SystemPlacementEndpointReadinessProvider {
    // Creates one positive bounded readiness deadline shared by both native platforms.
    pub fn new(timeout: Duration) -> Result<Self, PlacementError> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(PlacementError::InvalidRequest {
                reason: "placement endpoint readiness timeout is invalid",
            });
        }
        Ok(Self { timeout })
    }

    // Resolves the exact endpoint and accepts only one successful bounded connection.
    fn is_reachable(&self, endpoint: &PlacementEndpoint) -> Result<bool, PlacementError> {
        let authority = format!(
            "{}:{}",
            endpoint.address().host().as_str(),
            endpoint.address().port()
        );
        let addresses = authority
            .to_socket_addrs()
            .map_err(|_| PlacementError::EndpointUnavailable)?
            .collect::<Vec<SocketAddr>>();
        if addresses.is_empty() || addresses.len() > 16 {
            return Err(PlacementError::EndpointUnavailable);
        }
        Ok(addresses
            .iter()
            .any(|address| TcpStream::connect_timeout(address, self.timeout).is_ok()))
    }
}

impl LinuxEndpointReadinessProvider for SystemPlacementEndpointReadinessProvider {
    // Checks the exact sealed Linux endpoint without interpreting model output.
    fn is_ready(&self, endpoint: &PlacementEndpoint) -> Result<bool, PlacementError> {
        self.is_reachable(endpoint)
    }
}

impl MacosEndpointReadinessProvider for SystemPlacementEndpointReadinessProvider {
    // Checks the exact sealed macOS endpoint without interpreting model output.
    fn is_ready(&self, endpoint: &PlacementEndpoint) -> Result<bool, PlacementError> {
        self.is_reachable(endpoint)
    }
}
