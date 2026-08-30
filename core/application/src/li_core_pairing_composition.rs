// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{NodeAddress, NodeIdentity};
use li_database::DatabaseManager;
use li_node_manager::{NodeConfiguration, NodeManager, NodePairingApiPort, NodePairingPlatform};
use li_pairing_manager::{
    HmacPairingSetupCodeProvider, LinuxPairingDirectLinkProvider, NativePairingDiscoveryProvider,
    OpenSslPairingTrustProvider, PairingContext, PairingDirectLinkProvider,
    PairingDiscoveryPlatform, PairingError, PairingManager, PairingSetupSecretFileReference,
    PairingTrustIdentityFiles, SystemPairingClock, SystemPairingDirectLinkIo,
    SystemPairingMaterialProvider, SystemPairingNativeCommandRunner,
    SystemPairingSetupSecretFileProvider, SystemPairingTrustWorkspaceIo,
};

use crate::{CoreNodePairingApi, CorePairingEnrollmentCoordinator, DatabasePairingStore};

// Rejects ConnectX authorization on platforms without an implemented direct-link proof.
struct UnsupportedPairingDirectLinkProvider;

impl PairingDirectLinkProvider for UnsupportedPairingDirectLinkProvider {
    // Fails closed without inspecting or logging the requested interface or peer address.
    fn verify(
        &self,
        _interface: &li_core_interface::NetworkInterfaceName,
        _peer_address: &NodeAddress,
    ) -> Result<(), PairingError> {
        Err(PairingError::DirectLinkUnavailable)
    }
}

// Composes the complete production pairing lifecycle from explicit Node configuration.
pub fn compose_core_node_pairing_api(
    configuration: &NodeConfiguration,
    owner_user_id: u32,
    database: Arc<DatabaseManager>,
    nodes: Arc<NodeManager>,
) -> Result<Arc<dyn NodePairingApiPort>, PairingError> {
    if !nodes.uses_database(&database) {
        return Err(PairingError::StateUnavailable);
    }
    let local = nodes
        .local_node()
        .map_err(|_| PairingError::StateUnavailable)?;
    let pairing = configuration.pairing();
    let runner = Arc::new(SystemPairingNativeCommandRunner);
    let discovery_platform = match pairing.platform() {
        NodePairingPlatform::Linux { .. } => PairingDiscoveryPlatform::LinuxAvahi,
        NodePairingPlatform::Macos => PairingDiscoveryPlatform::MacosBonjour,
    };
    let discovery = Arc::new(NativePairingDiscoveryProvider::new(
        discovery_platform,
        pairing.discovery_command().to_path_buf(),
        runner.clone(),
    )?);
    let direct_link: Arc<dyn PairingDirectLinkProvider> = match pairing.platform() {
        NodePairingPlatform::Linux {
            sys_class,
            ip_command,
        } => Arc::new(LinuxPairingDirectLinkProvider::new(
            sys_class.clone(),
            ip_command.clone(),
            Arc::new(SystemPairingDirectLinkIo),
            runner.clone(),
        )?),
        NodePairingPlatform::Macos => Arc::new(UnsupportedPairingDirectLinkProvider),
    };
    let material = Arc::new(SystemPairingMaterialProvider);
    let identity_files = PairingTrustIdentityFiles::new(
        pairing.site_private_key_file().to_path_buf(),
        pairing.site_public_key_file().to_path_buf(),
        pairing.site_ca_certificate_file().to_path_buf(),
        pairing.local_control_certificate_file().to_path_buf(),
    )?;
    let trust = Arc::new(OpenSslPairingTrustProvider::new(
        pairing.openssl_command().to_path_buf(),
        identity_files,
        pairing.trust_workspace().to_path_buf(),
        owner_user_id,
        runner,
        Arc::new(SystemPairingTrustWorkspaceIo),
        material.clone(),
    )?);
    let setup_reference = PairingSetupSecretFileReference::new(
        pairing.setup_secret_file().to_path_buf(),
        owner_user_id,
    )?;
    let setup_code = Arc::new(HmacPairingSetupCodeProvider::load(
        &setup_reference,
        &SystemPairingSetupSecretFileProvider,
    )?);
    let context = PairingContext::new(
        NodeIdentity::new(
            local.identity().node_id().clone(),
            local.identity().machine_id().clone(),
            local.identity().installation_id().clone(),
        ),
        local.role(),
        local.display_name().clone(),
        local.control_address().clone(),
        configuration.remote_server().bind_address().port(),
        pairing.public_key_sha256().clone(),
        pairing.certificate_sha256().clone(),
    );
    let clock = Arc::new(SystemPairingClock);
    let store = Arc::new(DatabasePairingStore::new(database.clone()));
    let manager = Arc::new(PairingManager::new(
        context,
        discovery,
        direct_link,
        trust,
        material,
        setup_code,
        clock.clone(),
        store.clone(),
    ));
    let enrollment = Arc::new(
        CorePairingEnrollmentCoordinator::new(database, nodes)
            .map_err(|_| PairingError::StateUnavailable)?,
    );
    Ok(Arc::new(CoreNodePairingApi::new(
        manager, enrollment, store, clock,
    )))
}
