// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayConfigurationMode, GatewayExposureError,
    GatewayExposureReadinessProvider, GatewayHealthError, GatewayHealthExchange,
    GatewayHealthObservation, GatewayHealthProbe, SystemGatewayHealthExchange,
    SystemGatewayNativeFileIo,
};

const EXPOSURE_GATEWAY_ADDRESS: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8000);
const EXPOSURE_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

// Proves the exact main public-listener identity and live resident health before exposure.
pub struct CoreGatewayExposureReadiness {
    configuration: GatewayConfiguration,
    probe: GatewayHealthProbe,
}

// Loads the current owner-bound Gateway contract lazily before every exposure enable request.
pub struct SystemCoreGatewayExposureReadiness {
    configuration_file: GatewayConfigurationFile,
}

impl SystemCoreGatewayExposureReadiness {
    // Creates one production readiness boundary from the exact installed Gateway document.
    pub fn new(
        configuration_file: std::path::PathBuf,
        owner_user_id: u32,
    ) -> Result<Self, GatewayExposureError> {
        Ok(Self {
            configuration_file: GatewayConfigurationFile::new(owner_user_id, configuration_file)
                .map_err(|_| GatewayExposureError::InvalidConfiguration)?,
        })
    }
}

impl GatewayExposureReadinessProvider for SystemCoreGatewayExposureReadiness {
    // Reloads strict configuration then proves exact resident identity and fresh health.
    fn require_ready(&self) -> Result<(), GatewayExposureError> {
        let configuration =
            GatewayConfiguration::load(&self.configuration_file, &SystemGatewayNativeFileIo)
                .map_err(|_| GatewayExposureError::GatewayUnavailable)?;
        CoreGatewayExposureReadiness::new(configuration, Arc::new(SystemGatewayHealthExchange))?
            .require_ready()
    }
}

impl CoreGatewayExposureReadiness {
    // Creates one readiness adapter only for the exact main public Gateway configuration.
    pub fn new(
        configuration: GatewayConfiguration,
        exchange: Arc<dyn GatewayHealthExchange>,
    ) -> Result<Self, GatewayExposureError> {
        validate_exposure_configuration(
            configuration.mode(),
            configuration.public_listener().map(|value| value.address()),
        )?;
        Ok(Self {
            configuration,
            probe: GatewayHealthProbe::new(exchange),
        })
    }
}

impl GatewayExposureReadinessProvider for CoreGatewayExposureReadiness {
    // Requires exact resident identity and fresh ready telemetry through owner-local health I/O.
    fn require_ready(&self) -> Result<(), GatewayExposureError> {
        exposure_health_result(
            self.probe
                .observe(&self.configuration, EXPOSURE_HEALTH_TIMEOUT),
        )
    }
}

// Validates that exposure can reach only the configured main public inference listener.
fn validate_exposure_configuration(
    mode: GatewayConfigurationMode,
    public_listener: Option<SocketAddr>,
) -> Result<(), GatewayExposureError> {
    if mode != GatewayConfigurationMode::Main || public_listener != Some(EXPOSURE_GATEWAY_ADDRESS) {
        return Err(GatewayExposureError::InvalidConfiguration);
    }
    Ok(())
}

// Maps every non-ready or unprovable health outcome to one redacted readiness denial.
fn exposure_health_result(
    observation: Result<GatewayHealthObservation, GatewayHealthError>,
) -> Result<(), GatewayExposureError> {
    match observation {
        Ok(GatewayHealthObservation::Ready) => Ok(()),
        Ok(GatewayHealthObservation::NotReady) | Err(_) => {
            Err(GatewayExposureError::GatewayUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Accepts only the exact main public address consumed by the exposure provider target.
    #[test]
    fn exposure_configuration_contract_is_closed() {
        assert_eq!(
            validate_exposure_configuration(
                GatewayConfigurationMode::Main,
                Some(EXPOSURE_GATEWAY_ADDRESS)
            ),
            Ok(())
        );
        for (mode, listener) in [
            (
                GatewayConfigurationMode::Child,
                Some(EXPOSURE_GATEWAY_ADDRESS),
            ),
            (GatewayConfigurationMode::Main, None),
            (
                GatewayConfigurationMode::Main,
                Some(SocketAddr::from(([127, 0, 0, 1], 8000))),
            ),
            (
                GatewayConfigurationMode::Main,
                Some(SocketAddr::from(([0, 0, 0, 0], 9000))),
            ),
        ] {
            assert_eq!(
                validate_exposure_configuration(mode, listener),
                Err(GatewayExposureError::InvalidConfiguration)
            );
        }
    }

    // Accepts only fresh ready health and redacts every native failure class identically.
    #[test]
    fn exposure_health_contract_fails_closed() {
        assert_eq!(
            exposure_health_result(Ok(GatewayHealthObservation::Ready)),
            Ok(())
        );
        assert_eq!(
            exposure_health_result(Ok(GatewayHealthObservation::NotReady)),
            Err(GatewayExposureError::GatewayUnavailable)
        );
        for error in [
            GatewayHealthError::InvalidContract,
            GatewayHealthError::EndpointUnavailable,
            GatewayHealthError::AuthenticationUnavailable,
            GatewayHealthError::InvalidResponse,
            GatewayHealthError::DeadlineExceeded,
            GatewayHealthError::ResidentUnavailable,
        ] {
            assert_eq!(
                exposure_health_result(Err(error)),
                Err(GatewayExposureError::GatewayUnavailable)
            );
        }
    }
}
