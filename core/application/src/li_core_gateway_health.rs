// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use li_core_update_manager::{CoreUpdateNodeRole, CoreUpdateServiceContext};
use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayConfigurationMode, GatewayHealthError,
    GatewayHealthExchange, GatewayHealthObservation, GatewayHealthProbe,
    SystemGatewayHealthExchange, SystemGatewayNativeFileIo,
};

use crate::{
    CoreResidentProcess, CoreServiceSetupError, CoreServiceSetupObservation,
    CoreServiceSetupResidentHealth,
};

const GATEWAY_HEALTH_MAXIMUM_TIMEOUT: Duration = Duration::from_secs(10);

// Owns the exact configured Gateway identity and its local process health exchange.
pub struct CoreGatewayServiceHealth {
    configuration: GatewayConfiguration,
    probe: GatewayHealthProbe,
}

impl CoreGatewayServiceHealth {
    // Loads one owner-bound strict configuration before any service mutation begins.
    pub fn load(
        configuration_file: PathBuf,
        owner_user_id: u32,
    ) -> Result<Self, CoreServiceSetupError> {
        let reference =
            GatewayConfigurationFile::new(owner_user_id, configuration_file).map_err(|_| {
                gateway_health_provider_error("Gateway health configuration is invalid")
            })?;
        let configuration = GatewayConfiguration::load(&reference, &SystemGatewayNativeFileIo)
            .map_err(|_| {
                gateway_health_provider_error("Gateway health configuration is invalid")
            })?;
        Ok(Self::new(
            configuration,
            Arc::new(SystemGatewayHealthExchange),
        ))
    }

    // Creates one deterministic adapter from validated configuration and an injected exchange.
    pub const fn new(
        configuration: GatewayConfiguration,
        exchange: Arc<dyn GatewayHealthExchange>,
    ) -> Self {
        Self {
            configuration,
            probe: GatewayHealthProbe::new(exchange),
        }
    }
}

impl CoreServiceSetupResidentHealth for CoreGatewayServiceHealth {
    // Requires the exact Gateway role then verifies identity and live fresh telemetry locally.
    fn observe(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        if process != CoreResidentProcess::Gateway
            || gateway_mode(context.role()) != self.configuration.mode()
            || timeout.is_zero()
        {
            return Err(gateway_health_provider_error(
                "Gateway health request does not match its service role",
            ));
        }
        match self.probe.observe(
            &self.configuration,
            timeout.min(GATEWAY_HEALTH_MAXIMUM_TIMEOUT),
        ) {
            Ok(GatewayHealthObservation::Ready) => Ok(CoreServiceSetupObservation::Ready),
            Ok(GatewayHealthObservation::NotReady)
            | Err(
                GatewayHealthError::EndpointUnavailable
                | GatewayHealthError::DeadlineExceeded
                | GatewayHealthError::ResidentUnavailable,
            ) => Ok(CoreServiceSetupObservation::NotReady),
            Err(GatewayHealthError::AuthenticationUnavailable) => Err(
                gateway_health_provider_error("Gateway health authentication is unavailable"),
            ),
            Err(GatewayHealthError::InvalidContract | GatewayHealthError::InvalidResponse) => Err(
                gateway_health_provider_error("Gateway health response is invalid"),
            ),
        }
    }
}

// Converts the setup role vocabulary to the exact Gateway configuration mode.
const fn gateway_mode(role: CoreUpdateNodeRole) -> GatewayConfigurationMode {
    match role {
        CoreUpdateNodeRole::Main => GatewayConfigurationMode::Main,
        CoreUpdateNodeRole::Child => GatewayConfigurationMode::Child,
    }
}

// Creates one stable service-setup failure without provider or identity detail.
fn gateway_health_provider_error(reason: &'static str) -> CoreServiceSetupError {
    CoreServiceSetupError::provider("Gateway resident health", reason)
}
