// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{
    DisplayName, InstallationId, MachineId, NodeAddress, NodeId, NodeRole, Sha256Digest,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::CoreServiceCutoverRecovery;

pub const CORE_SETUP_RESULT_SCHEMA_NAME: &str = "li_core_setup_result";
pub const CORE_SETUP_RESULT_SCHEMA_VERSION: u32 = 1;
pub const MAXIMUM_CORE_SETUP_RESULT_BYTES: usize = 32 * 1024;
const MAXIMUM_CORE_SETUP_PATH_BYTES: usize = 4 * 1024;

// Identifies one exact setup phase in durable transaction order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreSetupPhase {
    Prepared,
    IdentityPrepared,
    MaterialPrepared,
    ConfigurationsInstalled,
    ServicesInstalled,
    Completed,
}

// Identifies whether this invocation installed state or replayed a committed result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreSetupDisposition {
    Installed,
    Replayed,
}

// Carries every explicit listener selected before setup performs native work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreSetupNetworkPlan {
    node_private_address: SocketAddr,
    gateway_private_address: SocketAddr,
    gateway_public_address: Option<SocketAddr>,
    watchdog_address: Option<SocketAddr>,
}

impl CoreSetupNetworkPlan {
    // Creates one complete listener plan without discovering or reserving a port.
    pub const fn new(
        node_private_address: SocketAddr,
        gateway_private_address: SocketAddr,
        gateway_public_address: Option<SocketAddr>,
        watchdog_address: Option<SocketAddr>,
    ) -> Self {
        Self {
            node_private_address,
            gateway_private_address,
            gateway_public_address,
            watchdog_address,
        }
    }

    // Returns the mutually authenticated Node control listener.
    pub const fn node_private_address(&self) -> SocketAddr {
        self.node_private_address
    }

    // Returns the Gateway listener used for authenticated node relays.
    pub const fn gateway_private_address(&self) -> SocketAddr {
        self.gateway_private_address
    }

    // Returns the main-only public inference listener.
    pub const fn gateway_public_address(&self) -> Option<SocketAddr> {
        self.gateway_public_address
    }

    // Returns the Linux-only Watchdog protocol listener.
    pub const fn watchdog_address(&self) -> Option<SocketAddr> {
        self.watchdog_address
    }
}

// Binds one idempotent setup request to immutable release, role, identity, and listener inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupRequest {
    request_id: Sha256Digest,
    context: CoreUpdateServiceContext,
    installation: CoreInstallation,
    display_name: DisplayName,
    control_address: NodeAddress,
    network: CoreSetupNetworkPlan,
}

impl CoreSetupRequest {
    // Creates one setup request without performing host discovery or assigning implicit ports.
    pub const fn new(
        request_id: Sha256Digest,
        context: CoreUpdateServiceContext,
        installation: CoreInstallation,
        display_name: DisplayName,
        control_address: NodeAddress,
        network: CoreSetupNetworkPlan,
    ) -> Self {
        Self {
            request_id,
            context,
            installation,
            display_name,
            control_address,
            network,
        }
    }

    // Returns the caller-owned idempotency identity.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }

    // Returns the exact platform and node role selected for setup.
    pub const fn context(&self) -> CoreUpdateServiceContext {
        self.context
    }

    // Returns the immutable verified Core installation being activated.
    pub const fn installation(&self) -> &CoreInstallation {
        &self.installation
    }

    // Returns the requested user-facing node name.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    // Returns the private control-plane address advertised by this node.
    pub const fn control_address(&self) -> &NodeAddress {
        &self.control_address
    }

    // Returns every listener address supplied by the composition root.
    pub const fn network(&self) -> CoreSetupNetworkPlan {
        self.network
    }
}

// Identifies one reversible provider mutation without exposing its native state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupReceipt {
    identity: Sha256Digest,
}

impl CoreSetupReceipt {
    // Creates one opaque content identity returned only after a provider reconciles mutation.
    pub const fn new(identity: Sha256Digest) -> Self {
        Self { identity }
    }

    // Returns the exact identity required for provider replay or rollback.
    pub const fn identity(&self) -> &Sha256Digest {
        &self.identity
    }
}

// Carries the durable public node identity prepared without private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupPreparedIdentity {
    receipt: CoreSetupReceipt,
    node_id: NodeId,
    machine_id: MachineId,
    installation_id: InstallationId,
    display_name: DisplayName,
    role: NodeRole,
    control_address: NodeAddress,
}

impl CoreSetupPreparedIdentity {
    // Creates one secret-free identity projection after native identity persistence succeeds.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        receipt: CoreSetupReceipt,
        node_id: NodeId,
        machine_id: MachineId,
        installation_id: InstallationId,
        display_name: DisplayName,
        role: NodeRole,
        control_address: NodeAddress,
    ) -> Self {
        Self {
            receipt,
            node_id,
            machine_id,
            installation_id,
            display_name,
            role,
            control_address,
        }
    }

    // Returns the provider receipt required for reverse-order rollback.
    pub const fn receipt(&self) -> &CoreSetupReceipt {
        &self.receipt
    }

    // Returns the stable logical node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the stable physical-machine identity.
    pub const fn machine_id(&self) -> &MachineId {
        &self.machine_id
    }

    // Returns the stable installed-Core identity.
    pub const fn installation_id(&self) -> &InstallationId {
        &self.installation_id
    }

    // Returns the user-facing name bound to this prepared identity.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    // Returns the main or child role bound to this prepared identity.
    pub const fn role(&self) -> NodeRole {
        self.role
    }

    // Returns the private control-plane address bound to this prepared identity.
    pub const fn control_address(&self) -> &NodeAddress {
        &self.control_address
    }
}

// Carries every secret-file reference produced by private material provisioning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupPairingTrustMaterial {
    site_private_key_file: PathBuf,
    site_public_key_file: PathBuf,
    site_ca_certificate_file: PathBuf,
    local_control_certificate_file: PathBuf,
    public_key_sha256: Sha256Digest,
    certificate_sha256: Sha256Digest,
}

// Carries the dedicated benchmark-signing references and verified public identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupBenchmarkSigningMaterial {
    private_key_file: PathBuf,
    public_key_file: PathBuf,
    public_key_sha256: Sha256Digest,
}

impl CoreSetupBenchmarkSigningMaterial {
    // Creates one secret-free projection of an issued Ed25519 signing identity.
    pub const fn new(
        private_key_file: PathBuf,
        public_key_file: PathBuf,
        public_key_sha256: Sha256Digest,
    ) -> Self {
        Self {
            private_key_file,
            public_key_file,
            public_key_sha256,
        }
    }

    // Returns the owner-private Ed25519 signing key path.
    pub fn private_key_file(&self) -> &Path {
        &self.private_key_file
    }

    // Returns the Ed25519 verification key path.
    pub fn public_key_file(&self) -> &Path {
        &self.public_key_file
    }

    // Returns the SHA-256 identity of the canonical public-key DER bytes.
    pub const fn public_key_sha256(&self) -> &Sha256Digest {
        &self.public_key_sha256
    }
}

// Carries the standalone main Node remote trust references and public leaf identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeTrustMaterial {
    authority_private_key_file: PathBuf,
    authority_certificate_file: PathBuf,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    client_certificate_file: PathBuf,
    client_private_key_file: PathBuf,
    server_certificate_sha256: Sha256Digest,
    client_certificate_sha256: Sha256Digest,
}

impl CoreSetupNodeTrustMaterial {
    // Creates one secret-free projection of the complete Node remote trust closure.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        authority_private_key_file: PathBuf,
        authority_certificate_file: PathBuf,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        client_certificate_file: PathBuf,
        client_private_key_file: PathBuf,
        server_certificate_sha256: Sha256Digest,
        client_certificate_sha256: Sha256Digest,
    ) -> Self {
        Self {
            authority_private_key_file,
            authority_certificate_file,
            server_certificate_file,
            server_private_key_file,
            client_certificate_file,
            client_private_key_file,
            server_certificate_sha256,
            client_certificate_sha256,
        }
    }

    // Returns the private Node certificate-authority key retained for later pairing transitions.
    pub fn authority_private_key_file(&self) -> &Path {
        &self.authority_private_key_file
    }

    // Returns the Node client-authority certificate consumed by the remote listener.
    pub fn authority_certificate_file(&self) -> &Path {
        &self.authority_certificate_file
    }

    // Returns the Node remote server certificate path.
    pub fn server_certificate_file(&self) -> &Path {
        &self.server_certificate_file
    }

    // Returns the Node remote server private-key path.
    pub fn server_private_key_file(&self) -> &Path {
        &self.server_private_key_file
    }

    // Returns the initially authorized local-main Node client certificate path.
    pub fn client_certificate_file(&self) -> &Path {
        &self.client_certificate_file
    }

    // Returns the initially authorized local-main Node client private-key path.
    pub fn client_private_key_file(&self) -> &Path {
        &self.client_private_key_file
    }

    // Returns the verified Node remote server leaf identity.
    pub const fn server_certificate_sha256(&self) -> &Sha256Digest {
        &self.server_certificate_sha256
    }

    // Returns the verified initially authorized Node client leaf identity.
    pub const fn client_certificate_sha256(&self) -> &Sha256Digest {
        &self.client_certificate_sha256
    }
}

// Carries the standalone main Gateway private-relay trust references and public leaf identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupGatewayTrustMaterial {
    authority_private_key_file: PathBuf,
    authority_certificate_file: PathBuf,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    relay_client_certificate_file: PathBuf,
    relay_client_private_key_file: PathBuf,
    server_certificate_sha256: Sha256Digest,
    relay_client_certificate_sha256: Sha256Digest,
}

impl CoreSetupGatewayTrustMaterial {
    // Creates one secret-free projection of the complete Gateway private-relay trust closure.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        authority_private_key_file: PathBuf,
        authority_certificate_file: PathBuf,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        relay_client_certificate_file: PathBuf,
        relay_client_private_key_file: PathBuf,
        server_certificate_sha256: Sha256Digest,
        relay_client_certificate_sha256: Sha256Digest,
    ) -> Self {
        Self {
            authority_private_key_file,
            authority_certificate_file,
            server_certificate_file,
            server_private_key_file,
            relay_client_certificate_file,
            relay_client_private_key_file,
            server_certificate_sha256,
            relay_client_certificate_sha256,
        }
    }

    // Returns the private Gateway certificate-authority key retained for later child enrollment.
    pub fn authority_private_key_file(&self) -> &Path {
        &self.authority_private_key_file
    }

    // Returns the Gateway private-relay certificate-authority path.
    pub fn authority_certificate_file(&self) -> &Path {
        &self.authority_certificate_file
    }

    // Returns the Gateway private-listener server certificate path.
    pub fn server_certificate_file(&self) -> &Path {
        &self.server_certificate_file
    }

    // Returns the Gateway private-listener server private-key path.
    pub fn server_private_key_file(&self) -> &Path {
        &self.server_private_key_file
    }

    // Returns the local main relay-client certificate path.
    pub fn relay_client_certificate_file(&self) -> &Path {
        &self.relay_client_certificate_file
    }

    // Returns the local main relay-client private-key path.
    pub fn relay_client_private_key_file(&self) -> &Path {
        &self.relay_client_private_key_file
    }

    // Returns the verified Gateway private-listener server leaf identity.
    pub const fn server_certificate_sha256(&self) -> &Sha256Digest {
        &self.server_certificate_sha256
    }

    // Returns the verified local main relay-client leaf identity.
    pub const fn relay_client_certificate_sha256(&self) -> &Sha256Digest {
        &self.relay_client_certificate_sha256
    }
}

// Carries the Linux Watchdog listener, controller, allowlist, and health-client trust closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupWatchdogTrustMaterial {
    authority_private_key_file: PathBuf,
    authority_certificate_file: PathBuf,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    controller_certificate_file: PathBuf,
    controller_private_key_file: PathBuf,
    controller_allowlist_file: PathBuf,
    server_certificate_sha256: Sha256Digest,
    controller_certificate_sha256: Sha256Digest,
}

impl CoreSetupWatchdogTrustMaterial {
    // Creates one secret-free projection of the complete Linux Watchdog trust closure.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        authority_private_key_file: PathBuf,
        authority_certificate_file: PathBuf,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        controller_certificate_file: PathBuf,
        controller_private_key_file: PathBuf,
        controller_allowlist_file: PathBuf,
        server_certificate_sha256: Sha256Digest,
        controller_certificate_sha256: Sha256Digest,
    ) -> Self {
        Self {
            authority_private_key_file,
            authority_certificate_file,
            server_certificate_file,
            server_private_key_file,
            controller_certificate_file,
            controller_private_key_file,
            controller_allowlist_file,
            server_certificate_sha256,
            controller_certificate_sha256,
        }
    }

    // Returns the private Watchdog certificate-authority key.
    pub fn authority_private_key_file(&self) -> &Path {
        &self.authority_private_key_file
    }

    // Returns the shared Watchdog server/controller trust anchor used by Core health.
    pub fn authority_certificate_file(&self) -> &Path {
        &self.authority_certificate_file
    }

    // Returns the Watchdog server certificate path.
    pub fn server_certificate_file(&self) -> &Path {
        &self.server_certificate_file
    }

    // Returns the Watchdog server private-key path.
    pub fn server_private_key_file(&self) -> &Path {
        &self.server_private_key_file
    }

    // Returns the Core-health controller certificate path.
    pub fn controller_certificate_file(&self) -> &Path {
        &self.controller_certificate_file
    }

    // Returns the Core-health controller private-key path.
    pub fn controller_private_key_file(&self) -> &Path {
        &self.controller_private_key_file
    }

    // Returns the canonical Watchdog controller allowlist path.
    pub fn controller_allowlist_file(&self) -> &Path {
        &self.controller_allowlist_file
    }

    // Returns the verified Watchdog server leaf identity used for health pinning.
    pub const fn server_certificate_sha256(&self) -> &Sha256Digest {
        &self.server_certificate_sha256
    }

    // Returns the verified Core-health controller leaf identity used by the allowlist.
    pub const fn controller_certificate_sha256(&self) -> &Sha256Digest {
        &self.controller_certificate_sha256
    }
}

impl CoreSetupPairingTrustMaterial {
    // Creates one secret-free projection of the exact provisioned pairing trust closure.
    pub const fn new(
        site_private_key_file: PathBuf,
        site_public_key_file: PathBuf,
        site_ca_certificate_file: PathBuf,
        local_control_certificate_file: PathBuf,
        public_key_sha256: Sha256Digest,
        certificate_sha256: Sha256Digest,
    ) -> Self {
        Self {
            site_private_key_file,
            site_public_key_file,
            site_ca_certificate_file,
            local_control_certificate_file,
            public_key_sha256,
            certificate_sha256,
        }
    }

    // Returns the exact owner-private site signing key path.
    pub fn site_private_key_file(&self) -> &Path {
        &self.site_private_key_file
    }

    // Returns the exact site public-key path.
    pub fn site_public_key_file(&self) -> &Path {
        &self.site_public_key_file
    }

    // Returns the exact site CA certificate path.
    pub fn site_ca_certificate_file(&self) -> &Path {
        &self.site_ca_certificate_file
    }

    // Returns the exact local control certificate path.
    pub fn local_control_certificate_file(&self) -> &Path {
        &self.local_control_certificate_file
    }

    // Returns the verified site public-key identity.
    pub const fn public_key_sha256(&self) -> &Sha256Digest {
        &self.public_key_sha256
    }

    // Returns the verified local control certificate identity.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }
}

// Carries every secret-file reference produced by private material provisioning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupPreparedMaterial {
    receipt: CoreSetupReceipt,
    database_file: PathBuf,
    pairing_setup_secret_file: PathBuf,
    api_key_file: Option<PathBuf>,
    benchmark_signing: Option<CoreSetupBenchmarkSigningMaterial>,
    pairing_trust: CoreSetupPairingTrustMaterial,
    node_trust: CoreSetupNodeTrustMaterial,
    gateway_trust: CoreSetupGatewayTrustMaterial,
    watchdog_trust: Option<CoreSetupWatchdogTrustMaterial>,
    material_identity: Sha256Digest,
}

impl CoreSetupPreparedMaterial {
    // Creates one complete secret-free projection including dedicated benchmark signing.
    #[allow(clippy::too_many_arguments)]
    pub const fn new_with_benchmark_signing(
        receipt: CoreSetupReceipt,
        database_file: PathBuf,
        pairing_setup_secret_file: PathBuf,
        api_key_file: Option<PathBuf>,
        benchmark_signing: CoreSetupBenchmarkSigningMaterial,
        pairing_trust: CoreSetupPairingTrustMaterial,
        node_trust: CoreSetupNodeTrustMaterial,
        gateway_trust: CoreSetupGatewayTrustMaterial,
        watchdog_trust: Option<CoreSetupWatchdogTrustMaterial>,
        material_identity: Sha256Digest,
    ) -> Self {
        Self {
            receipt,
            database_file,
            pairing_setup_secret_file,
            api_key_file,
            benchmark_signing: Some(benchmark_signing),
            pairing_trust,
            node_trust,
            gateway_trust,
            watchdog_trust,
            material_identity,
        }
    }

    // Returns the provider receipt required for reverse-order rollback.
    pub const fn receipt(&self) -> &CoreSetupReceipt {
        &self.receipt
    }

    // Returns the owner-private Node database path.
    pub fn database_file(&self) -> &Path {
        &self.database_file
    }

    // Returns the external PairingManager setup-secret reference.
    pub fn pairing_setup_secret_file(&self) -> &Path {
        &self.pairing_setup_secret_file
    }

    // Returns the main-only local inference credential path.
    pub fn api_key_file(&self) -> Option<&Path> {
        self.api_key_file.as_deref()
    }

    // Returns the dedicated benchmark-signing key references and public identity.
    pub const fn benchmark_signing(&self) -> Option<&CoreSetupBenchmarkSigningMaterial> {
        self.benchmark_signing.as_ref()
    }

    // Returns the exact provisioned pairing trust references and verified identities.
    pub const fn pairing_trust(&self) -> &CoreSetupPairingTrustMaterial {
        &self.pairing_trust
    }

    // Returns the complete standalone-main Node remote trust references and identities.
    pub const fn node_trust(&self) -> &CoreSetupNodeTrustMaterial {
        &self.node_trust
    }

    // Returns the complete standalone-main Gateway relay trust references and identities.
    pub const fn gateway_trust(&self) -> &CoreSetupGatewayTrustMaterial {
        &self.gateway_trust
    }

    // Returns the Linux-only Watchdog and Core-health trust closure.
    pub const fn watchdog_trust(&self) -> Option<&CoreSetupWatchdogTrustMaterial> {
        self.watchdog_trust.as_ref()
    }

    // Returns the digest of the complete private material closure.
    pub const fn material_identity(&self) -> &Sha256Digest {
        &self.material_identity
    }
}

// Carries one reversible complete configuration installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupInstalledConfigurations {
    receipt: CoreSetupReceipt,
}

impl CoreSetupInstalledConfigurations {
    // Creates one configuration receipt after every required document is durable.
    pub const fn new(receipt: CoreSetupReceipt) -> Self {
        Self { receipt }
    }

    // Returns the receipt required for exact configuration rollback.
    pub const fn receipt(&self) -> &CoreSetupReceipt {
        &self.receipt
    }
}

// Carries one committed independently supervised resident-service set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupInstalledServices {
    receipt: CoreSetupReceipt,
}

impl CoreSetupInstalledServices {
    // Creates one service receipt after native activation and semantic readiness succeed.
    pub const fn new(receipt: CoreSetupReceipt) -> Self {
        Self { receipt }
    }

    // Returns the exact service cutover identity.
    pub const fn receipt(&self) -> &CoreSetupReceipt {
        &self.receipt
    }
}

// Defines the stable successful JSON returned to the installer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoreSetupResult {
    schema: CoreSetupResultSchema,
    status: CoreSetupDisposition,
    node_id: String,
    machine_id: String,
    installation_id: String,
    display_name: String,
    role: String,
    control_address: String,
    api_key_file: Option<String>,
    inference_endpoint: Option<String>,
    services: Vec<String>,
}

impl CoreSetupResult {
    // Encodes the closed result as bounded canonical-key JSON for the installer boundary.
    pub fn encoded_json(&self) -> Result<Vec<u8>, CoreSetupError> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| CoreSetupError::InvalidContract {
            reason: "setup result could not be encoded",
        })?;
        bytes.push(b'\n');
        if bytes.len() > MAXIMUM_CORE_SETUP_RESULT_BYTES {
            return Err(CoreSetupError::InvalidContract {
                reason: "setup result exceeds its output boundary",
            });
        }
        Ok(bytes)
    }

    // Decodes one closed bounded result for durable-journal reconstruction.
    pub fn decoded_json(bytes: &[u8]) -> Result<Self, CoreSetupStoreError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_CORE_SETUP_RESULT_BYTES {
            return Err(CoreSetupStoreError::Corrupt);
        }
        serde_json::from_slice(bytes).map_err(|_| CoreSetupStoreError::Corrupt)
    }

    // Returns whether this invocation installed or replayed the setup transaction.
    pub const fn status(&self) -> CoreSetupDisposition {
        self.status
    }

    // Returns the user-facing node name consumed by installer completion UI.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    // Returns the canonical main or child role consumed by installer verification.
    pub fn role(&self) -> &str {
        &self.role
    }

    // Returns the main-only local API-key file reference.
    pub fn api_key_file(&self) -> Option<&str> {
        self.api_key_file.as_deref()
    }

    // Returns the main-only local inference endpoint.
    pub fn inference_endpoint(&self) -> Option<&str> {
        self.inference_endpoint.as_deref()
    }

    // Returns one replay result without changing any durable identity or endpoint.
    fn replayed(&self) -> Self {
        let mut result = self.clone();
        result.status = CoreSetupDisposition::Replayed;
        result
    }
}

// Projects the repository-wide nested setup-result schema identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CoreSetupResultSchema {
    name: String,
    version: u32,
}

// Carries one durable setup journal without any private material bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupJournal {
    request_id: Sha256Digest,
    request_identity: Sha256Digest,
    phase: CoreSetupPhase,
    identity: Option<CoreSetupPreparedIdentity>,
    material: Option<CoreSetupPreparedMaterial>,
    configurations: Option<CoreSetupInstalledConfigurations>,
    services: Option<CoreSetupInstalledServices>,
    result: Option<CoreSetupResult>,
}

impl CoreSetupJournal {
    // Creates one prepared transaction before the first provider mutation.
    pub const fn prepared(request_id: Sha256Digest, request_identity: Sha256Digest) -> Self {
        Self {
            request_id,
            request_identity,
            phase: CoreSetupPhase::Prepared,
            identity: None,
            material: None,
            configurations: None,
            services: None,
            result: None,
        }
    }

    // Reconstructs one typed durable journal while rejecting an incoherent closure shape.
    #[allow(clippy::too_many_arguments)]
    pub fn restored(
        request_id: Sha256Digest,
        request_identity: Sha256Digest,
        phase: CoreSetupPhase,
        identity: Option<CoreSetupPreparedIdentity>,
        material: Option<CoreSetupPreparedMaterial>,
        configurations: Option<CoreSetupInstalledConfigurations>,
        services: Option<CoreSetupInstalledServices>,
        result: Option<CoreSetupResult>,
    ) -> Result<Self, CoreSetupStoreError> {
        let journal = Self {
            request_id,
            request_identity,
            phase,
            identity,
            material,
            configurations,
            services,
            result,
        };
        if !journal.has_only_expected_closures()
            || (journal.phase == CoreSetupPhase::Completed) != journal.result.is_some()
        {
            return Err(CoreSetupStoreError::Corrupt);
        }
        Ok(journal)
    }

    // Returns the caller-owned setup idempotency identity.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }

    // Returns the complete secret-free request identity used for conflict detection.
    pub const fn request_identity(&self) -> &Sha256Digest {
        &self.request_identity
    }

    // Returns the last durably completed setup phase.
    pub const fn phase(&self) -> CoreSetupPhase {
        self.phase
    }

    // Returns the committed result only for a completed journal.
    pub const fn result(&self) -> Option<&CoreSetupResult> {
        self.result.as_ref()
    }

    // Returns the public identity closure durably bound to its completed phase.
    pub const fn identity(&self) -> Option<&CoreSetupPreparedIdentity> {
        self.identity.as_ref()
    }

    // Returns the secret-free material closure durably bound to its completed phase.
    pub const fn material(&self) -> Option<&CoreSetupPreparedMaterial> {
        self.material.as_ref()
    }

    // Returns the complete configuration receipt bound to its completed phase.
    pub const fn configurations(&self) -> Option<&CoreSetupInstalledConfigurations> {
        self.configurations.as_ref()
    }

    // Returns the resident-service receipt bound to its completed phase.
    pub const fn services(&self) -> Option<&CoreSetupInstalledServices> {
        self.services.as_ref()
    }

    // Advances from prepared state while binding the exact public identity closure.
    fn identity_prepared(
        &self,
        identity: CoreSetupPreparedIdentity,
    ) -> Result<Self, CoreSetupError> {
        if self.phase != CoreSetupPhase::Prepared || !self.has_only_expected_closures() {
            return Err(CoreSetupError::InvalidContract {
                reason: "setup journal phase transition is invalid",
            });
        }
        Ok(Self {
            request_id: self.request_id.clone(),
            request_identity: self.request_identity.clone(),
            phase: CoreSetupPhase::IdentityPrepared,
            identity: Some(identity),
            material: None,
            configurations: None,
            services: None,
            result: None,
        })
    }

    // Advances after private material while binding its paths, closure digest, and receipt.
    fn material_prepared(
        &self,
        material: CoreSetupPreparedMaterial,
    ) -> Result<Self, CoreSetupError> {
        if self.phase != CoreSetupPhase::IdentityPrepared || !self.has_only_expected_closures() {
            return Err(CoreSetupError::InvalidContract {
                reason: "setup journal phase transition is invalid",
            });
        }
        Ok(Self {
            request_id: self.request_id.clone(),
            request_identity: self.request_identity.clone(),
            phase: CoreSetupPhase::MaterialPrepared,
            identity: self.identity.clone(),
            material: Some(material),
            configurations: None,
            services: None,
            result: None,
        })
    }

    // Advances after configuration activation while binding its exact rollback receipt.
    fn configurations_installed(
        &self,
        configurations: CoreSetupInstalledConfigurations,
    ) -> Result<Self, CoreSetupError> {
        if self.phase != CoreSetupPhase::MaterialPrepared || !self.has_only_expected_closures() {
            return Err(CoreSetupError::InvalidContract {
                reason: "setup journal phase transition is invalid",
            });
        }
        Ok(Self {
            request_id: self.request_id.clone(),
            request_identity: self.request_identity.clone(),
            phase: CoreSetupPhase::ConfigurationsInstalled,
            identity: self.identity.clone(),
            material: self.material.clone(),
            configurations: Some(configurations),
            services: None,
            result: None,
        })
    }

    // Advances after service readiness while binding the committed cutover receipt.
    fn services_installed(
        &self,
        services: CoreSetupInstalledServices,
    ) -> Result<Self, CoreSetupError> {
        if self.phase != CoreSetupPhase::ConfigurationsInstalled
            || !self.has_only_expected_closures()
        {
            return Err(CoreSetupError::InvalidContract {
                reason: "setup journal phase transition is invalid",
            });
        }
        Ok(Self {
            request_id: self.request_id.clone(),
            request_identity: self.request_identity.clone(),
            phase: CoreSetupPhase::ServicesInstalled,
            identity: self.identity.clone(),
            material: self.material.clone(),
            configurations: self.configurations.clone(),
            services: Some(services),
            result: None,
        })
    }

    // Commits one exact result after the service phase has verified ready.
    fn completed(&self, result: CoreSetupResult) -> Result<Self, CoreSetupError> {
        if self.phase != CoreSetupPhase::ServicesInstalled
            || self.result.is_some()
            || !self.has_only_expected_closures()
        {
            return Err(CoreSetupError::InvalidContract {
                reason: "setup journal completion transition is invalid",
            });
        }
        Ok(Self {
            request_id: self.request_id.clone(),
            request_identity: self.request_identity.clone(),
            phase: CoreSetupPhase::Completed,
            identity: self.identity.clone(),
            material: self.material.clone(),
            configurations: self.configurations.clone(),
            services: self.services.clone(),
            result: Some(result),
        })
    }

    // Returns whether optional closures exactly match the journal's declared phase.
    fn has_only_expected_closures(&self) -> bool {
        let closure_count = [
            self.identity.is_some(),
            self.material.is_some(),
            self.configurations.is_some(),
            self.services.is_some(),
        ]
        .into_iter()
        .take_while(|present| *present)
        .count();
        let expected = match self.phase {
            CoreSetupPhase::Prepared => 0,
            CoreSetupPhase::IdentityPrepared => 1,
            CoreSetupPhase::MaterialPrepared => 2,
            CoreSetupPhase::ConfigurationsInstalled => 3,
            CoreSetupPhase::ServicesInstalled | CoreSetupPhase::Completed => 4,
        };
        closure_count == expected
            && [
                self.identity.is_some(),
                self.material.is_some(),
                self.configurations.is_some(),
                self.services.is_some(),
            ]
            .into_iter()
            .skip(expected)
            .all(|present| !present)
    }
}

// Carries one optimistic durable journal revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedCoreSetupJournal {
    journal: CoreSetupJournal,
    revision: u64,
}

impl VersionedCoreSetupJournal {
    // Creates one store result with a nonzero optimistic revision.
    pub fn new(journal: CoreSetupJournal, revision: u64) -> Result<Self, CoreSetupStoreError> {
        if revision == 0 {
            return Err(CoreSetupStoreError::Corrupt);
        }
        Ok(Self { journal, revision })
    }

    // Returns the durable setup journal.
    pub const fn journal(&self) -> &CoreSetupJournal {
        &self.journal
    }

    // Returns the optimistic revision required for replacement or removal.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Describes one stable setup-journal failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreSetupStoreError {
    Conflict,
    Unavailable,
    Corrupt,
}

impl fmt::Display for CoreSetupStoreError {
    // Presents stable journal language without paths or persisted document values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("Core setup journal revision conflicted"),
            Self::Unavailable => formatter.write_str("Core setup journal is unavailable"),
            Self::Corrupt => formatter.write_str("Core setup journal is corrupt"),
        }
    }
}

impl Error for CoreSetupStoreError {}

// Describes whether a provider left no mutation, rolled itself back, or requires recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreSetupProviderError {
    Unchanged {
        capability: &'static str,
        reason: &'static str,
    },
    RolledBack {
        capability: &'static str,
        reason: &'static str,
    },
    RecoveryRequired {
        capability: &'static str,
        reason: &'static str,
    },
}

impl CoreSetupProviderError {
    // Creates one stable failure that occurred before visible provider mutation.
    pub const fn unchanged(capability: &'static str, reason: &'static str) -> Self {
        Self::Unchanged { capability, reason }
    }

    // Creates one stable failure after the provider completed its own compensation.
    pub const fn rolled_back(capability: &'static str, reason: &'static str) -> Self {
        Self::RolledBack { capability, reason }
    }

    // Creates one stable failure whose native mutation state cannot be proven.
    pub const fn recovery_required(capability: &'static str, reason: &'static str) -> Self {
        Self::RecoveryRequired { capability, reason }
    }
}

// Describes one stable orchestration, provider, rollback, or recovery outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreSetupError {
    InvalidContract {
        reason: &'static str,
    },
    Busy,
    IdempotencyConflict,
    Store(CoreSetupStoreError),
    Provider {
        capability: &'static str,
        reason: &'static str,
    },
    RolledBack {
        capability: &'static str,
        reason: &'static str,
    },
    RecoveryRequired {
        capability: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for CoreSetupError {
    // Presents stable setup language without secrets, paths, or native diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { reason } => {
                write!(formatter, "Core setup contract is invalid: {reason}")
            }
            Self::Busy => formatter.write_str("another Core setup is active"),
            Self::IdempotencyConflict => {
                formatter.write_str("Core setup replay identity conflicts with its request")
            }
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Provider { capability, reason } => {
                write!(formatter, "Core setup {capability} failed: {reason}")
            }
            Self::RolledBack { capability, reason } => {
                write!(formatter, "Core setup {capability} rolled back: {reason}")
            }
            Self::RecoveryRequired { capability, reason } => {
                write!(
                    formatter,
                    "Core setup {capability} requires recovery: {reason}"
                )
            }
        }
    }
}

impl Error for CoreSetupError {}

impl From<CoreSetupStoreError> for CoreSetupError {
    // Preserves one stable journal failure at the orchestration boundary.
    fn from(error: CoreSetupStoreError) -> Self {
        Self::Store(error)
    }
}

// Holds one cross-process setup lock until the orchestration invocation ends.
pub trait CoreSetupExecutionLock: Send {}

// Supplies one nonblocking global setup lock before journal or provider access.
pub trait CoreSetupExecutionLockProvider: Send + Sync {
    // Acquires exclusive setup ownership or reports that another invocation is active.
    fn try_acquire(&self) -> Result<Box<dyn CoreSetupExecutionLock>, CoreSetupError>;
}

// Persists the secret-free transaction phase and final installer result.
pub trait CoreSetupJournalStore: Send + Sync {
    // Returns the only incomplete journal eligible for interrupted service compensation.
    fn recovery(&self) -> Result<Option<VersionedCoreSetupJournal>, CoreSetupStoreError>;

    // Reads one exact journal when the request has previously begun.
    fn read(
        &self,
        request_id: &Sha256Digest,
    ) -> Result<Option<VersionedCoreSetupJournal>, CoreSetupStoreError>;

    // Creates one journal or returns the concurrently authoritative existing record.
    fn create(
        &self,
        journal: CoreSetupJournal,
    ) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError>;

    // Replaces one exact optimistic revision after a phase becomes durable.
    fn replace(
        &self,
        journal: CoreSetupJournal,
        expected_revision: u64,
    ) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError>;

    // Removes one fully compensated incomplete transaction.
    fn remove(
        &self,
        request_id: &Sha256Digest,
        expected_revision: u64,
    ) -> Result<(), CoreSetupStoreError>;
}

// Provisions the durable Node identity and initial database record.
pub trait CoreSetupIdentityProvider: Send + Sync {
    // Creates or exactly replays the requested public identity without returning private keys.
    fn prepare(
        &self,
        request: &CoreSetupRequest,
    ) -> Result<CoreSetupPreparedIdentity, CoreSetupProviderError>;

    // Removes only state owned by one incomplete setup receipt.
    fn rollback(&self, receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError>;
}

// Provisions TLS, derivation secrets, and the main-only local API-key file.
pub trait CoreSetupMaterialProvider: Send + Sync {
    // Creates or exactly replays private material while returning references and identities only.
    fn prepare(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
    ) -> Result<CoreSetupPreparedMaterial, CoreSetupProviderError>;

    // Removes only private material owned by one incomplete setup receipt.
    fn rollback(&self, receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError>;
}

// Installs the complete Node, Gateway, and platform-specific Watchdog configuration set.
pub trait CoreSetupConfigurationProvider: Send + Sync {
    // Creates or exactly replays every closed configuration document as one reversible phase.
    fn install(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
        material: &CoreSetupPreparedMaterial,
    ) -> Result<CoreSetupInstalledConfigurations, CoreSetupProviderError>;

    // Removes only configuration state owned by one incomplete setup receipt.
    fn rollback(&self, receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError>;
}

// Activates and semantically verifies the complete independent resident service set.
pub trait CoreSetupServiceProvider: Send + Sync {
    // Observes one interrupted native restoration before source-bound journal validation.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreSetupProviderError>;

    // Completes native restoration while retaining the durable restored checkpoint.
    fn resume_recovery(&self) -> Result<(), CoreSetupProviderError>;

    // Clears the restored checkpoint only after reversible setup compensation is durable.
    fn complete_recovery(&self) -> Result<(), CoreSetupProviderError>;

    // Applies or health-verifies one exact native cutover after reversible phases are durable.
    fn apply(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
        material: &CoreSetupPreparedMaterial,
    ) -> Result<CoreSetupInstalledServices, CoreSetupProviderError>;
}

// Owns exact setup ordering, durable phase transitions, rollback, recovery, and replay.
pub struct CoreSetup {
    locks: Arc<dyn CoreSetupExecutionLockProvider>,
    store: Arc<dyn CoreSetupJournalStore>,
    identities: Arc<dyn CoreSetupIdentityProvider>,
    materials: Arc<dyn CoreSetupMaterialProvider>,
    configurations: Arc<dyn CoreSetupConfigurationProvider>,
    services: Arc<dyn CoreSetupServiceProvider>,
}

impl CoreSetup {
    // Creates one setup owner from every explicit persistence and native capability.
    pub fn new(
        locks: Arc<dyn CoreSetupExecutionLockProvider>,
        store: Arc<dyn CoreSetupJournalStore>,
        identities: Arc<dyn CoreSetupIdentityProvider>,
        materials: Arc<dyn CoreSetupMaterialProvider>,
        configurations: Arc<dyn CoreSetupConfigurationProvider>,
        services: Arc<dyn CoreSetupServiceProvider>,
    ) -> Self {
        Self {
            locks,
            store,
            identities,
            materials,
            configurations,
            services,
        }
    }

    // Runs or resumes one transaction and returns only after every resident verifies ready.
    pub fn setup(&self, request: &CoreSetupRequest) -> Result<CoreSetupResult, CoreSetupError> {
        validate_request(request)?;
        let _lock = self.locks.try_acquire()?;
        self.recover_interrupted_services()?;
        let request_identity = request_identity(request)?;
        let mut journal = self.load_or_create_journal(request, request_identity)?;
        if let Some(result) = completed_result(&journal, request)? {
            let expected = journal
                .journal()
                .services()
                .ok_or(CoreSetupError::Store(CoreSetupStoreError::Corrupt))?;
            let observed = self
                .services
                .apply(
                    request,
                    journal
                        .journal()
                        .identity()
                        .ok_or(CoreSetupError::Store(CoreSetupStoreError::Corrupt))?,
                    journal
                        .journal()
                        .material()
                        .ok_or(CoreSetupError::Store(CoreSetupStoreError::Corrupt))?,
                )
                .map_err(provider_error)?;
            if &observed != expected {
                return Err(replay_drift("resident services"));
            }
            return Ok(result.replayed());
        }

        let identity = match self.identities.prepare(request) {
            Ok(identity) => identity,
            Err(error) => {
                return self.rollback_reversible(request, &journal, None, None, None, error)
            }
        };
        if let Err(error) = validate_prepared_identity(request, &identity) {
            return self.rollback_reversible(
                request,
                &journal,
                Some(&identity),
                None,
                None,
                CoreSetupProviderError::rolled_back("node identity", error.reason()),
            );
        }
        if journal.journal().phase() < CoreSetupPhase::IdentityPrepared {
            journal = self.advance_after_reversible_mutation(
                request,
                &journal,
                journal.journal().identity_prepared(identity.clone())?,
                Some(&identity),
                None,
                None,
            )?;
        } else if journal.journal().identity() != Some(&identity) {
            return Err(replay_drift("node identity"));
        }

        let material = match self.materials.prepare(request, &identity) {
            Ok(material) => material,
            Err(error) => {
                return self.rollback_reversible(
                    request,
                    &journal,
                    Some(&identity),
                    None,
                    None,
                    error,
                )
            }
        };
        if let Err(error) = validate_prepared_material(request, &material) {
            return self.rollback_reversible(
                request,
                &journal,
                Some(&identity),
                Some(&material),
                None,
                CoreSetupProviderError::rolled_back("private material", error.reason()),
            );
        }
        if journal.journal().phase() < CoreSetupPhase::MaterialPrepared {
            journal = self.advance_after_reversible_mutation(
                request,
                &journal,
                journal.journal().material_prepared(material.clone())?,
                Some(&identity),
                Some(&material),
                None,
            )?;
        } else if journal.journal().material() != Some(&material) {
            return Err(replay_drift("private material"));
        }

        let configurations = match self.configurations.install(request, &identity, &material) {
            Ok(configurations) => configurations,
            Err(error) => {
                return self.rollback_reversible(
                    request,
                    &journal,
                    Some(&identity),
                    Some(&material),
                    None,
                    error,
                )
            }
        };
        if journal.journal().phase() < CoreSetupPhase::ConfigurationsInstalled {
            journal = self.advance_after_reversible_mutation(
                request,
                &journal,
                journal
                    .journal()
                    .configurations_installed(configurations.clone())?,
                Some(&identity),
                Some(&material),
                Some(&configurations),
            )?;
        } else if journal.journal().configurations() != Some(&configurations) {
            return Err(replay_drift("configurations"));
        }

        if journal.journal().phase() < CoreSetupPhase::ServicesInstalled {
            let services = match self.services.apply(request, &identity, &material) {
                Ok(services) => services,
                Err(CoreSetupProviderError::RecoveryRequired { capability, reason }) => {
                    return Err(CoreSetupError::RecoveryRequired { capability, reason })
                }
                Err(error) => {
                    return self.rollback_reversible(
                        request,
                        &journal,
                        Some(&identity),
                        Some(&material),
                        Some(&configurations),
                        error,
                    )
                }
            };
            journal = match self.advance(
                &journal,
                journal.journal().services_installed(services.clone())?,
            ) {
                Ok(journal) => journal,
                Err(_) => {
                    return Err(CoreSetupError::RecoveryRequired {
                        capability: "setup journal",
                        reason: "service activation committed before its phase could be recorded",
                    })
                }
            };
        } else {
            let services = self
                .services
                .apply(request, &identity, &material)
                .map_err(provider_error)?;
            if journal.journal().services() != Some(&services) {
                return Err(replay_drift("resident services"));
            }
        }
        let result = setup_result(request, &identity, &material)?;
        let completed = journal.journal().completed(result.clone())?;
        self.advance(&journal, completed)
            .map_err(|_| CoreSetupError::RecoveryRequired {
                capability: "setup journal",
                reason: "ready resident services could not be committed",
            })?;
        Ok(result)
    }

    // Restores native ownership before compensating the one exact incomplete setup journal.
    fn recover_interrupted_services(&self) -> Result<(), CoreSetupError> {
        let recovery = self.services.recovery().map_err(provider_error)?;
        if recovery == CoreServiceCutoverRecovery::None {
            return Ok(());
        }
        let journal = self.store.recovery()?;
        if recovery == CoreServiceCutoverRecovery::Restoring && journal.is_none() {
            return Err(CoreSetupError::RecoveryRequired {
                capability: "setup rollback",
                reason: "interrupted service restoration has no setup journal",
            });
        }
        if recovery == CoreServiceCutoverRecovery::Restoring {
            self.services.resume_recovery().map_err(provider_error)?;
        }
        if let Some(journal) = journal {
            let state = journal.journal();
            let (Some(identity), Some(material), Some(configurations)) =
                (state.identity(), state.material(), state.configurations())
            else {
                return Err(CoreSetupError::RecoveryRequired {
                    capability: "setup rollback",
                    reason: "interrupted service restoration journal is inconsistent",
                });
            };
            if state.phase() != CoreSetupPhase::ConfigurationsInstalled
                || state.services().is_some()
                || state.result().is_some()
            {
                return Err(CoreSetupError::RecoveryRequired {
                    capability: "setup rollback",
                    reason: "interrupted service restoration journal is inconsistent",
                });
            }
            let mut rollback_failed = false;
            rollback_failed |= self
                .configurations
                .rollback(configurations.receipt())
                .is_err();
            rollback_failed |= self.materials.rollback(material.receipt()).is_err();
            rollback_failed |= self.identities.rollback(identity.receipt()).is_err();
            if rollback_failed {
                return Err(CoreSetupError::RecoveryRequired {
                    capability: "setup rollback",
                    reason: "an interrupted setup phase could not be restored",
                });
            }
            self.store
                .remove(state.request_id(), journal.revision())
                .map_err(|_| CoreSetupError::RecoveryRequired {
                    capability: "setup journal",
                    reason: "compensated interrupted setup state could not be retired",
                })?;
        }
        self.services.complete_recovery().map_err(provider_error)?;
        Ok(())
    }

    // Loads one prior transaction or creates its prepared journal before native mutation.
    fn load_or_create_journal(
        &self,
        request: &CoreSetupRequest,
        request_identity: Sha256Digest,
    ) -> Result<VersionedCoreSetupJournal, CoreSetupError> {
        let journal = match self.store.read(request.request_id())? {
            Some(journal) => journal,
            None => self.store.create(CoreSetupJournal::prepared(
                request.request_id().clone(),
                request_identity.clone(),
            ))?,
        };
        validate_journal(&journal, request, &request_identity)?;
        Ok(journal)
    }

    // Advances one durable journal through optimistic replacement.
    fn advance(
        &self,
        current: &VersionedCoreSetupJournal,
        next: CoreSetupJournal,
    ) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError> {
        self.store.replace(next, current.revision())
    }

    // Records one reversible phase or compensates every prepared phase in reverse order.
    #[allow(clippy::too_many_arguments)]
    fn advance_after_reversible_mutation(
        &self,
        request: &CoreSetupRequest,
        journal: &VersionedCoreSetupJournal,
        next: CoreSetupJournal,
        identity: Option<&CoreSetupPreparedIdentity>,
        material: Option<&CoreSetupPreparedMaterial>,
        configurations: Option<&CoreSetupInstalledConfigurations>,
    ) -> Result<VersionedCoreSetupJournal, CoreSetupError> {
        match self.advance(journal, next) {
            Ok(journal) => Ok(journal),
            Err(CoreSetupStoreError::Conflict) => Err(CoreSetupError::RecoveryRequired {
                capability: "setup journal",
                reason: "a completed phase conflicted with durable setup state",
            }),
            Err(_) => self.rollback_reversible(
                request,
                journal,
                identity,
                material,
                configurations,
                CoreSetupProviderError::rolled_back(
                    "setup journal",
                    "a completed phase could not be recorded",
                ),
            ),
        }
    }

    // Compensates every reversible phase and removes its incomplete journal exactly once.
    #[allow(clippy::too_many_arguments)]
    fn rollback_reversible<Value>(
        &self,
        request: &CoreSetupRequest,
        journal: &VersionedCoreSetupJournal,
        identity: Option<&CoreSetupPreparedIdentity>,
        material: Option<&CoreSetupPreparedMaterial>,
        configurations: Option<&CoreSetupInstalledConfigurations>,
        failure: CoreSetupProviderError,
    ) -> Result<Value, CoreSetupError> {
        if let CoreSetupProviderError::RecoveryRequired { capability, reason } = failure {
            return Err(CoreSetupError::RecoveryRequired { capability, reason });
        }
        let mut rollback_failed = false;
        if let Some(configurations) = configurations {
            rollback_failed |= self
                .configurations
                .rollback(configurations.receipt())
                .is_err();
        }
        if let Some(material) = material {
            rollback_failed |= self.materials.rollback(material.receipt()).is_err();
        }
        if let Some(identity) = identity {
            rollback_failed |= self.identities.rollback(identity.receipt()).is_err();
        }
        if rollback_failed {
            return Err(CoreSetupError::RecoveryRequired {
                capability: "setup rollback",
                reason: "an incomplete setup phase could not be restored",
            });
        }
        if self
            .store
            .remove(request.request_id(), journal.revision())
            .is_err()
        {
            return Err(CoreSetupError::RecoveryRequired {
                capability: "setup journal",
                reason: "compensated setup state could not be retired",
            });
        }
        let (capability, reason) = provider_failure_parts(&failure);
        Err(CoreSetupError::RolledBack { capability, reason })
    }
}

// Validates role, platform, and explicitly injected listener invariants before mutation.
fn validate_request(request: &CoreSetupRequest) -> Result<(), CoreSetupError> {
    if !control_address_is_url_authority_safe(request.control_address().as_str()) {
        return Err(CoreSetupError::InvalidContract {
            reason: "setup control address must be a routable URL authority",
        });
    }
    let network = request.network();
    let mut ports = vec![
        network.node_private_address().port(),
        network.gateway_private_address().port(),
    ];
    if let Some(address) = network.gateway_public_address() {
        ports.push(address.port());
    }
    if let Some(address) = network.watchdog_address() {
        ports.push(address.port());
    }
    ports.sort_unstable();
    if ports.first() == Some(&0) || ports.windows(2).any(|values| values[0] == values[1]) {
        return Err(CoreSetupError::InvalidContract {
            reason: "setup listener ports must be nonzero and distinct",
        });
    }
    let role_valid = request.context().role() == CoreUpdateNodeRole::Main
        && network.gateway_public_address().is_some();
    let platform_valid = match request.context().platform() {
        CoreUpdateServicePlatform::Linux => network.watchdog_address().is_some(),
        CoreUpdateServicePlatform::Macos => network.watchdog_address().is_none(),
    };
    if !role_valid || !platform_valid {
        return Err(CoreSetupError::InvalidContract {
            reason: "initial setup must provision a standalone main listener plan",
        });
    }
    Ok(())
}

// Accepts only one routable IPv4 address or canonical lowercase DNS authority.
fn control_address_is_url_authority_safe(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.chars().any(char::is_whitespace) {
        return false;
    }
    if let Ok(address) = value.parse::<std::net::IpAddr>() {
        return matches!(
            address,
            std::net::IpAddr::V4(address)
                if !address.is_loopback()
                    && !address.is_unspecified()
                    && !address.is_multicast()
        );
    }
    if value != value.to_ascii_lowercase() || value == "localhost" {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

// Derives one stable request identity from every mutation-relevant secret-free input.
fn request_identity(request: &CoreSetupRequest) -> Result<Sha256Digest, CoreSetupError> {
    let mut digest = Sha256::new();
    for value in [
        "li_core_setup_request_v1".to_string(),
        platform_name(request.context().platform()).to_string(),
        role_name(request.context().role()).to_string(),
        request.installation().version().as_str().to_string(),
        request
            .installation()
            .source_identity()
            .as_str()
            .to_string(),
        request.display_name().as_str().to_string(),
        request.control_address().as_str().to_string(),
        request.network().node_private_address().to_string(),
        request.network().gateway_private_address().to_string(),
        request
            .network()
            .gateway_public_address()
            .map(|value| value.to_string())
            .unwrap_or_default(),
        request
            .network()
            .watchdog_address()
            .map(|value| value.to_string())
            .unwrap_or_default(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).map_err(|_| {
        CoreSetupError::InvalidContract {
            reason: "setup request identity could not be derived",
        }
    })
}

// Requires one journal to match its request and retain a coherent phase/result shape.
fn validate_journal(
    versioned: &VersionedCoreSetupJournal,
    request: &CoreSetupRequest,
    request_identity: &Sha256Digest,
) -> Result<(), CoreSetupError> {
    let journal = versioned.journal();
    if journal.request_id() != request.request_id() {
        return Err(CoreSetupError::Store(CoreSetupStoreError::Corrupt));
    }
    if journal.request_identity() != request_identity {
        return Err(CoreSetupError::IdempotencyConflict);
    }
    if (journal.phase() == CoreSetupPhase::Completed) != journal.result().is_some()
        || !journal.has_only_expected_closures()
    {
        return Err(CoreSetupError::Store(CoreSetupStoreError::Corrupt));
    }
    Ok(())
}

// Returns one committed replay only after revalidating its immutable request projection.
fn completed_result(
    journal: &VersionedCoreSetupJournal,
    request: &CoreSetupRequest,
) -> Result<Option<CoreSetupResult>, CoreSetupError> {
    let Some(result) = journal.journal().result() else {
        return Ok(None);
    };
    let Some(identity) = journal.journal().identity() else {
        return Err(CoreSetupError::Store(CoreSetupStoreError::Corrupt));
    };
    let Some(material) = journal.journal().material() else {
        return Err(CoreSetupError::Store(CoreSetupStoreError::Corrupt));
    };
    if result.schema.name != CORE_SETUP_RESULT_SCHEMA_NAME
        || result.schema.version != CORE_SETUP_RESULT_SCHEMA_VERSION
        || result.status != CoreSetupDisposition::Installed
        || result.display_name() != request.display_name().as_str()
        || result.role() != role_name(request.context().role())
        || result.node_id != identity.node_id().as_str()
        || result.machine_id != identity.machine_id().as_str()
        || result.installation_id != identity.installation_id().as_str()
        || result.control_address != identity.control_address.as_str()
        || result.api_key_file.as_deref()
            != material
                .api_key_file()
                .map(path_text)
                .transpose()?
                .as_deref()
        || result.inference_endpoint != expected_inference_endpoint(request)
        || result.services != expected_services(request.context().platform())
    {
        return Err(CoreSetupError::Store(CoreSetupStoreError::Corrupt));
    }
    Ok(Some(result.clone()))
}

// Requires prepared identity state to preserve every caller-owned public node value.
fn validate_prepared_identity(
    request: &CoreSetupRequest,
    identity: &CoreSetupPreparedIdentity,
) -> Result<(), CoreSetupError> {
    if identity.display_name != *request.display_name()
        || identity.control_address != *request.control_address()
        || identity.role != node_role(request.context().role())
    {
        return Err(CoreSetupError::RecoveryRequired {
            capability: "node identity",
            reason: "prepared identity does not match the setup request",
        });
    }
    Ok(())
}

// Requires the complete safe distinct standalone-main resident material closure.
fn validate_prepared_material(
    request: &CoreSetupRequest,
    material: &CoreSetupPreparedMaterial,
) -> Result<(), CoreSetupError> {
    let mut paths = vec![
        material.database_file(),
        material.pairing_setup_secret_file(),
        material.pairing_trust().site_private_key_file(),
        material.pairing_trust().site_public_key_file(),
        material.pairing_trust().site_ca_certificate_file(),
        material.pairing_trust().local_control_certificate_file(),
        material.node_trust().authority_private_key_file(),
        material.node_trust().authority_certificate_file(),
        material.node_trust().server_certificate_file(),
        material.node_trust().server_private_key_file(),
        material.node_trust().client_certificate_file(),
        material.node_trust().client_private_key_file(),
        material.gateway_trust().authority_private_key_file(),
        material.gateway_trust().authority_certificate_file(),
        material.gateway_trust().server_certificate_file(),
        material.gateway_trust().server_private_key_file(),
        material.gateway_trust().relay_client_certificate_file(),
        material.gateway_trust().relay_client_private_key_file(),
    ];
    if let Some(api_key_file) = material.api_key_file() {
        paths.push(api_key_file);
    }
    if let Some(signing) = material.benchmark_signing() {
        paths.extend([signing.private_key_file(), signing.public_key_file()]);
    }
    if let Some(watchdog) = material.watchdog_trust() {
        paths.extend([
            watchdog.authority_private_key_file(),
            watchdog.authority_certificate_file(),
            watchdog.server_certificate_file(),
            watchdog.server_private_key_file(),
            watchdog.controller_certificate_file(),
            watchdog.controller_private_key_file(),
            watchdog.controller_allowlist_file(),
        ]);
    }
    for path in &paths {
        if !is_normal_absolute_path(path)
            || *path == Path::new("/")
            || path.as_os_str().as_encoded_bytes().len() > MAXIMUM_CORE_SETUP_PATH_BYTES
        {
            return Err(CoreSetupError::InvalidContract {
                reason: "private material path is invalid",
            });
        }
    }
    if request.context().role() != CoreUpdateNodeRole::Main
        || material.api_key_file().is_none()
        || material.benchmark_signing().is_none()
    {
        return Err(CoreSetupError::InvalidContract {
            reason: "standalone-main private material is incomplete",
        });
    }
    let watchdog_valid = match request.context().platform() {
        CoreUpdateServicePlatform::Linux => material.watchdog_trust().is_some(),
        CoreUpdateServicePlatform::Macos => material.watchdog_trust().is_none(),
    };
    if !watchdog_valid {
        return Err(CoreSetupError::InvalidContract {
            reason: "resident trust material does not match the platform",
        });
    }
    if paths
        .iter()
        .enumerate()
        .any(|(index, path)| paths[..index].contains(path))
    {
        return Err(CoreSetupError::InvalidContract {
            reason: "private material paths must be distinct",
        });
    }
    Ok(())
}

// Builds the closed secret-free result consumed by the native installer.
fn setup_result(
    request: &CoreSetupRequest,
    identity: &CoreSetupPreparedIdentity,
    material: &CoreSetupPreparedMaterial,
) -> Result<CoreSetupResult, CoreSetupError> {
    let api_key_file = material.api_key_file().map(path_text).transpose()?;
    let inference_endpoint = expected_inference_endpoint(request);
    let services = expected_services(request.context().platform());
    Ok(CoreSetupResult {
        schema: CoreSetupResultSchema {
            name: CORE_SETUP_RESULT_SCHEMA_NAME.to_string(),
            version: CORE_SETUP_RESULT_SCHEMA_VERSION,
        },
        status: CoreSetupDisposition::Installed,
        node_id: identity.node_id().as_str().to_string(),
        machine_id: identity.machine_id().as_str().to_string(),
        installation_id: identity.installation_id().as_str().to_string(),
        display_name: identity.display_name.as_str().to_string(),
        role: role_name(request.context().role()).to_string(),
        control_address: identity.control_address.as_str().to_string(),
        api_key_file,
        inference_endpoint,
        services,
    })
}

// Returns the exact main-only inference endpoint projected into setup output.
fn expected_inference_endpoint(request: &CoreSetupRequest) -> Option<String> {
    request.network().gateway_public_address().map(|address| {
        format!(
            "http://{}:{}",
            request.control_address().as_str(),
            address.port()
        )
    })
}

// Returns the exact ordered resident identities for one platform.
fn expected_services(platform: CoreUpdateServicePlatform) -> Vec<String> {
    match platform {
        CoreUpdateServicePlatform::Linux => ["li_node", "li_watchdog", "li_gateway"],
        CoreUpdateServicePlatform::Macos => ["li_node", "li_gateway", ""],
    }
    .into_iter()
    .filter(|service| !service.is_empty())
    .map(str::to_string)
    .collect()
}

// Converts one provider-owned failure into the matching setup classification.
fn provider_error(error: CoreSetupProviderError) -> CoreSetupError {
    match error {
        CoreSetupProviderError::Unchanged { capability, reason } => {
            CoreSetupError::Provider { capability, reason }
        }
        CoreSetupProviderError::RolledBack { capability, reason } => {
            CoreSetupError::RolledBack { capability, reason }
        }
        CoreSetupProviderError::RecoveryRequired { capability, reason } => {
            CoreSetupError::RecoveryRequired { capability, reason }
        }
    }
}

// Classifies provider replay drift as recovery-owned instead of accepting a new closure.
const fn replay_drift(capability: &'static str) -> CoreSetupError {
    CoreSetupError::RecoveryRequired {
        capability,
        reason: "provider replay does not match its durable setup receipt",
    }
}

// Returns stable provider failure fields independently of its mutation classification.
const fn provider_failure_parts(error: &CoreSetupProviderError) -> (&'static str, &'static str) {
    match error {
        CoreSetupProviderError::Unchanged { capability, reason }
        | CoreSetupProviderError::RolledBack { capability, reason }
        | CoreSetupProviderError::RecoveryRequired { capability, reason } => (*capability, *reason),
    }
}

// Maps update context into the shared node entity role.
const fn node_role(role: CoreUpdateNodeRole) -> NodeRole {
    match role {
        CoreUpdateNodeRole::Main => NodeRole::Main,
        CoreUpdateNodeRole::Child => NodeRole::Child,
    }
}

// Returns the stable JSON spelling for one setup role.
const fn role_name(role: CoreUpdateNodeRole) -> &'static str {
    match role {
        CoreUpdateNodeRole::Main => "main",
        CoreUpdateNodeRole::Child => "child",
    }
}

// Returns the stable request-identity spelling for one native platform.
const fn platform_name(platform: CoreUpdateServicePlatform) -> &'static str {
    match platform {
        CoreUpdateServicePlatform::Linux => "linux",
        CoreUpdateServicePlatform::Macos => "macos",
    }
}

// Converts one Unicode path into stable output text without guessing an encoding.
fn path_text(path: &Path) -> Result<String, CoreSetupError> {
    path.to_str()
        .map(str::to_string)
        .ok_or(CoreSetupError::InvalidContract {
            reason: "setup result path text is invalid",
        })
}

// Returns whether one path is absolute and free of traversal or platform-prefix components.
fn is_normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Exposes the stable reason carried by contract and recovery validation failures.
trait CoreSetupErrorReason {
    // Returns one redacted reason suitable for provider compensation classification.
    fn reason(&self) -> &'static str;
}

impl CoreSetupErrorReason for CoreSetupError {
    // Returns one stable reason without formatting potentially sensitive context.
    fn reason(&self) -> &'static str {
        match self {
            Self::InvalidContract { reason }
            | Self::Provider { reason, .. }
            | Self::RolledBack { reason, .. }
            | Self::RecoveryRequired { reason, .. } => reason,
            Self::Busy => "another Core setup is active",
            Self::IdempotencyConflict => "setup replay identity conflicts",
            Self::Store(_) => "setup journal failed",
        }
    }
}
