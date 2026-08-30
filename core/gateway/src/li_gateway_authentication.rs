// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_authentication_manager::{AuthenticationError, AuthenticationManager};
use li_core_interface::LogicalModelName;

use crate::{GatewayAuthenticationProvider, GatewayError, GatewayPrincipal};

// Adapts AuthenticationManager's durable policy result to Gateway live enforcement.
pub struct AuthenticationManagerGatewayProvider {
    manager: Arc<AuthenticationManager>,
}

impl AuthenticationManagerGatewayProvider {
    // Creates one narrow authentication adapter without taking manager lifecycle ownership.
    pub const fn new(manager: Arc<AuthenticationManager>) -> Self {
        Self { manager }
    }
}

impl GatewayAuthenticationProvider for AuthenticationManagerGatewayProvider {
    // Verifies bearer identity and projects only key identity plus configured limits.
    fn authenticate(
        &self,
        bearer_token: &str,
        model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, GatewayError> {
        match self.manager.authenticate(bearer_token, model) {
            Ok(principal) => Ok(GatewayPrincipal::new(
                principal.key_id().clone(),
                principal.policy().limits(),
            )),
            Err(AuthenticationError::Unauthorized | AuthenticationError::NotFound) => {
                Err(GatewayError::AuthenticationDenied)
            }
            Err(_) => Err(GatewayError::provider(
                "authentication",
                "API-key authority is unavailable",
            )),
        }
    }
}
