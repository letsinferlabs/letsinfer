// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use li_core_interface::Sha256Digest;
use li_core_update_manager::CoreUpdateNodeRole;
use li_pairing_manager::{PairingNativeCommand, PairingNativeCommandRunner};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::li_core_setup::CoreSetupBenchmarkSigningMaterial;
use crate::{
    CoreSetupGatewayTrustMaterial, CoreSetupMaterialProvider, CoreSetupNodeTrustMaterial,
    CoreSetupPairingTrustMaterial, CoreSetupPreparedIdentity, CoreSetupPreparedMaterial,
    CoreSetupProviderError, CoreSetupReceipt, CoreSetupRequest, CoreSetupWatchdogTrustMaterial,
};

const SECRET_BYTES: usize = 32;
const MATERIAL_FILE_MODE: u32 = 0o600;
const MATERIAL_DIRECTORY_MODE: u32 = 0o700;
const MAXIMUM_MANIFEST_BYTES: usize = 64 * 1024;
const MAXIMUM_MATERIAL_FILE_BYTES: usize = 64 * 1024;
const MATERIAL_DIGEST_BUFFER_BYTES: usize = 8 * 1024;
const MATERIAL_LOCK_FILENAME: &str = ".li_core_setup_material.lock";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

// Owns one bounded material read buffer and clears it on every return path.
struct MaterialDigestBuffer([u8; MATERIAL_DIGEST_BUFFER_BYTES]);

impl Default for MaterialDigestBuffer {
    // Creates one completely initialized empty digest buffer.
    fn default() -> Self {
        Self([0; MATERIAL_DIGEST_BUFFER_BYTES])
    }
}

impl Drop for MaterialDigestBuffer {
    // Clears any private file fragment retained by a completed or failed digest read.
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

// Selects every exact material destination without allowing provider-local path discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupMaterialPaths {
    database_file: PathBuf,
    pairing_setup_secret_file: PathBuf,
    api_key_file: PathBuf,
    benchmark_signing: Option<CoreSetupBenchmarkSigningPaths>,
    pairing_trust: CoreSetupPairingTrustPaths,
    node_trust: CoreSetupNodeTrustPaths,
    gateway_trust: CoreSetupGatewayTrustPaths,
    watchdog_trust: Option<CoreSetupWatchdogTrustPaths>,
}

// Selects the dedicated Ed25519 benchmark-signing identity destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupBenchmarkSigningPaths {
    private_key_file: PathBuf,
    public_key_file: PathBuf,
}

impl CoreSetupBenchmarkSigningPaths {
    // Creates one explicit signing destination pair without native discovery.
    pub const fn new(private_key_file: PathBuf, public_key_file: PathBuf) -> Self {
        Self {
            private_key_file,
            public_key_file,
        }
    }

    // Returns the exact owner-private Ed25519 signing key destination.
    pub fn private_key_file(&self) -> &Path {
        &self.private_key_file
    }

    // Returns the exact Ed25519 verification key destination.
    pub fn public_key_file(&self) -> &Path {
        &self.public_key_file
    }
}

// Selects the four exact pairing trust destinations before identities are issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupPairingTrustPaths {
    site_private_key_file: PathBuf,
    site_public_key_file: PathBuf,
    site_ca_certificate_file: PathBuf,
    local_control_certificate_file: PathBuf,
}

// Selects the complete standalone-main Node remote trust destination closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeTrustPaths {
    authority_private_key_file: PathBuf,
    authority_certificate_file: PathBuf,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    client_certificate_file: PathBuf,
    client_private_key_file: PathBuf,
}

impl CoreSetupNodeTrustPaths {
    // Creates one explicit Node remote trust destination set without native discovery.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        authority_private_key_file: PathBuf,
        authority_certificate_file: PathBuf,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        client_certificate_file: PathBuf,
        client_private_key_file: PathBuf,
    ) -> Self {
        Self {
            authority_private_key_file,
            authority_certificate_file,
            server_certificate_file,
            server_private_key_file,
            client_certificate_file,
            client_private_key_file,
        }
    }
}

// Selects the complete standalone-main Gateway private-relay trust destination closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupGatewayTrustPaths {
    authority_private_key_file: PathBuf,
    authority_certificate_file: PathBuf,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    relay_client_certificate_file: PathBuf,
    relay_client_private_key_file: PathBuf,
}

impl CoreSetupGatewayTrustPaths {
    // Creates one explicit Gateway private-relay trust destination set without native discovery.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        authority_private_key_file: PathBuf,
        authority_certificate_file: PathBuf,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        relay_client_certificate_file: PathBuf,
        relay_client_private_key_file: PathBuf,
    ) -> Self {
        Self {
            authority_private_key_file,
            authority_certificate_file,
            server_certificate_file,
            server_private_key_file,
            relay_client_certificate_file,
            relay_client_private_key_file,
        }
    }
}

// Selects the Linux-only Watchdog listener, controller, allowlist, and health trust closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupWatchdogTrustPaths {
    authority_private_key_file: PathBuf,
    authority_certificate_file: PathBuf,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    controller_certificate_file: PathBuf,
    controller_private_key_file: PathBuf,
    controller_allowlist_file: PathBuf,
}

impl CoreSetupWatchdogTrustPaths {
    // Creates one explicit Watchdog trust destination set without native discovery.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        authority_private_key_file: PathBuf,
        authority_certificate_file: PathBuf,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        controller_certificate_file: PathBuf,
        controller_private_key_file: PathBuf,
        controller_allowlist_file: PathBuf,
    ) -> Self {
        Self {
            authority_private_key_file,
            authority_certificate_file,
            server_certificate_file,
            server_private_key_file,
            controller_certificate_file,
            controller_private_key_file,
            controller_allowlist_file,
        }
    }

    // Returns the Watchdog server-authority certificate used by Core health verification.
    pub fn authority_certificate_file(&self) -> &Path {
        &self.authority_certificate_file
    }

    // Returns the Core health controller certificate issued during standalone-main setup.
    pub fn controller_certificate_file(&self) -> &Path {
        &self.controller_certificate_file
    }

    // Returns the Core health controller private key issued during standalone-main setup.
    pub fn controller_private_key_file(&self) -> &Path {
        &self.controller_private_key_file
    }
}

impl CoreSetupPairingTrustPaths {
    // Creates one explicit trust destination set without generating identity material.
    pub const fn new(
        site_private_key_file: PathBuf,
        site_public_key_file: PathBuf,
        site_ca_certificate_file: PathBuf,
        local_control_certificate_file: PathBuf,
    ) -> Self {
        Self {
            site_private_key_file,
            site_public_key_file,
            site_ca_certificate_file,
            local_control_certificate_file,
        }
    }
}

impl CoreSetupMaterialPaths {
    // Creates one complete explicit destination set after rejecting aliases and relative paths.
    pub fn new(
        database_file: PathBuf,
        pairing_setup_secret_file: PathBuf,
        api_key_file: PathBuf,
        pairing_trust: CoreSetupPairingTrustPaths,
        node_trust: CoreSetupNodeTrustPaths,
        gateway_trust: CoreSetupGatewayTrustPaths,
        watchdog_trust: Option<CoreSetupWatchdogTrustPaths>,
    ) -> Result<Self, CoreSetupProviderError> {
        let mut paths = vec![
            database_file.as_path(),
            pairing_setup_secret_file.as_path(),
            api_key_file.as_path(),
            pairing_trust.site_private_key_file.as_path(),
            pairing_trust.site_public_key_file.as_path(),
            pairing_trust.site_ca_certificate_file.as_path(),
            pairing_trust.local_control_certificate_file.as_path(),
            node_trust.authority_private_key_file.as_path(),
            node_trust.authority_certificate_file.as_path(),
            node_trust.server_certificate_file.as_path(),
            node_trust.server_private_key_file.as_path(),
            node_trust.client_certificate_file.as_path(),
            node_trust.client_private_key_file.as_path(),
            gateway_trust.authority_private_key_file.as_path(),
            gateway_trust.authority_certificate_file.as_path(),
            gateway_trust.server_certificate_file.as_path(),
            gateway_trust.server_private_key_file.as_path(),
            gateway_trust.relay_client_certificate_file.as_path(),
            gateway_trust.relay_client_private_key_file.as_path(),
        ];
        if let Some(watchdog) = watchdog_trust.as_ref() {
            paths.extend([
                watchdog.authority_private_key_file.as_path(),
                watchdog.authority_certificate_file.as_path(),
                watchdog.server_certificate_file.as_path(),
                watchdog.server_private_key_file.as_path(),
                watchdog.controller_certificate_file.as_path(),
                watchdog.controller_private_key_file.as_path(),
                watchdog.controller_allowlist_file.as_path(),
            ]);
        }
        if paths
            .iter()
            .any(|path| !is_normal_absolute_path(path) || *path == Path::new("/"))
            || paths
                .iter()
                .enumerate()
                .any(|(index, path)| paths[..index].contains(path))
        {
            return Err(material_error(
                "private material paths are unsafe or ambiguous",
            ));
        }
        Ok(Self {
            database_file,
            pairing_setup_secret_file,
            api_key_file,
            benchmark_signing: None,
            pairing_trust,
            node_trust,
            gateway_trust,
            watchdog_trust,
        })
    }

    // Adds the explicit benchmark-signing destinations after rejecting aliases and unsafe paths.
    pub fn with_benchmark_signing(
        mut self,
        benchmark_signing: CoreSetupBenchmarkSigningPaths,
    ) -> Result<Self, CoreSetupProviderError> {
        let signing_paths = [
            benchmark_signing.private_key_file.as_path(),
            benchmark_signing.public_key_file.as_path(),
        ];
        let existing = self.all_paths();
        if signing_paths
            .iter()
            .any(|path| !is_normal_absolute_path(path) || *path == Path::new("/"))
            || signing_paths[0] == signing_paths[1]
            || signing_paths
                .iter()
                .any(|path| existing.iter().any(|existing| existing == path))
        {
            return Err(material_error(
                "private material paths are unsafe or ambiguous",
            ));
        }
        self.benchmark_signing = Some(benchmark_signing);
        Ok(self)
    }

    // Returns the shared database destination carried through the material closure.
    pub fn database_file(&self) -> &std::path::Path {
        &self.database_file
    }

    // Returns the exact pairing setup-secret destination.
    pub fn pairing_setup_secret_file(&self) -> &std::path::Path {
        &self.pairing_setup_secret_file
    }

    // Returns the main-only API-key destination.
    pub fn api_key_file(&self) -> &std::path::Path {
        &self.api_key_file
    }

    // Returns the dedicated benchmark-signing destination pair.
    pub const fn benchmark_signing(&self) -> Option<&CoreSetupBenchmarkSigningPaths> {
        self.benchmark_signing.as_ref()
    }

    // Returns the exact pairing trust destination and identity closure.
    pub const fn pairing_trust(&self) -> &CoreSetupPairingTrustPaths {
        &self.pairing_trust
    }

    // Returns the exact Node remote trust destination closure.
    pub const fn node_trust(&self) -> &CoreSetupNodeTrustPaths {
        &self.node_trust
    }

    // Returns the exact Gateway private-relay trust destination closure.
    pub const fn gateway_trust(&self) -> &CoreSetupGatewayTrustPaths {
        &self.gateway_trust
    }

    // Returns the Linux-only Watchdog trust destination closure.
    pub const fn watchdog_trust(&self) -> Option<&CoreSetupWatchdogTrustPaths> {
        self.watchdog_trust.as_ref()
    }

    // Returns every exact destination in the platform-closed private material set.
    pub fn all_paths(&self) -> Vec<&Path> {
        let mut paths = vec![
            self.database_file.as_path(),
            self.pairing_setup_secret_file.as_path(),
            self.api_key_file.as_path(),
            self.pairing_trust.site_private_key_file.as_path(),
            self.pairing_trust.site_public_key_file.as_path(),
            self.pairing_trust.site_ca_certificate_file.as_path(),
            self.pairing_trust.local_control_certificate_file.as_path(),
            self.node_trust.authority_private_key_file.as_path(),
            self.node_trust.authority_certificate_file.as_path(),
            self.node_trust.server_certificate_file.as_path(),
            self.node_trust.server_private_key_file.as_path(),
            self.node_trust.client_certificate_file.as_path(),
            self.node_trust.client_private_key_file.as_path(),
            self.gateway_trust.authority_private_key_file.as_path(),
            self.gateway_trust.authority_certificate_file.as_path(),
            self.gateway_trust.server_certificate_file.as_path(),
            self.gateway_trust.server_private_key_file.as_path(),
            self.gateway_trust.relay_client_certificate_file.as_path(),
            self.gateway_trust.relay_client_private_key_file.as_path(),
        ];
        if let Some(signing) = self.benchmark_signing.as_ref() {
            paths.extend([
                signing.private_key_file.as_path(),
                signing.public_key_file.as_path(),
            ]);
        }
        if let Some(watchdog) = self.watchdog_trust.as_ref() {
            paths.extend([
                watchdog.authority_private_key_file.as_path(),
                watchdog.authority_certificate_file.as_path(),
                watchdog.server_certificate_file.as_path(),
                watchdog.server_private_key_file.as_path(),
                watchdog.controller_certificate_file.as_path(),
                watchdog.controller_private_key_file.as_path(),
                watchdog.controller_allowlist_file.as_path(),
            ]);
        }
        paths
    }

    // Returns whether every destination is a strict descendant of one explicit material root.
    pub fn is_contained_by(&self, root: &Path) -> bool {
        self.all_paths()
            .into_iter()
            .all(|path| path != root && path.starts_with(root))
    }
}

// Carries generated trust bytes only across the injected atomic material boundary.
pub struct CoreSetupIssuedPairingTrust {
    site_private_key: Vec<u8>,
    site_public_key: Vec<u8>,
    site_ca_certificate: Vec<u8>,
    local_control_certificate: Vec<u8>,
    public_key_sha256: Sha256Digest,
    certificate_sha256: Sha256Digest,
}

impl CoreSetupIssuedPairingTrust {
    // Creates one complete bounded trust package and its independently verified identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        site_private_key: Vec<u8>,
        site_public_key: Vec<u8>,
        site_ca_certificate: Vec<u8>,
        local_control_certificate: Vec<u8>,
        public_key_sha256: Sha256Digest,
        certificate_sha256: Sha256Digest,
    ) -> Result<Self, CoreSetupProviderError> {
        if site_private_key.is_empty()
            || site_public_key.is_empty()
            || site_ca_certificate.is_empty()
            || local_control_certificate.is_empty()
            || site_private_key.len() > 16 * 1024
            || site_public_key.len() > 8 * 1024
            || site_ca_certificate.len() > 64 * 1024
            || local_control_certificate.len() > 64 * 1024
        {
            return Err(material_error(
                "pairing trust issuance returned invalid material",
            ));
        }
        Ok(Self {
            site_private_key,
            site_public_key,
            site_ca_certificate,
            local_control_certificate,
            public_key_sha256,
            certificate_sha256,
        })
    }

    // Projects the issued public identities onto the exact configured trust destinations.
    pub fn material(&self, paths: &CoreSetupPairingTrustPaths) -> CoreSetupPairingTrustMaterial {
        CoreSetupPairingTrustMaterial::new(
            paths.site_private_key_file.clone(),
            paths.site_public_key_file.clone(),
            paths.site_ca_certificate_file.clone(),
            paths.local_control_certificate_file.clone(),
            self.public_key_sha256.clone(),
            self.certificate_sha256.clone(),
        )
    }
}

impl Drop for CoreSetupIssuedPairingTrust {
    // Clears every retained private or public trust byte after persistence or failure.
    fn drop(&mut self) {
        self.site_private_key.fill(0);
        self.site_public_key.fill(0);
        self.site_ca_certificate.fill(0);
        self.local_control_certificate.fill(0);
    }
}

// Carries one dedicated Ed25519 benchmark-signing identity until atomic persistence.
pub struct CoreSetupIssuedBenchmarkSigning {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    public_key_sha256: Sha256Digest,
}

impl CoreSetupIssuedBenchmarkSigning {
    // Creates one bounded issued identity after its public/private key match was verified.
    pub fn new(
        mut private_key: Vec<u8>,
        mut public_key: Vec<u8>,
        public_key_sha256: Sha256Digest,
    ) -> Result<Self, CoreSetupProviderError> {
        if private_key.is_empty()
            || public_key.is_empty()
            || private_key.len() > 16 * 1024
            || public_key.len() > 8 * 1024
        {
            private_key.fill(0);
            public_key.fill(0);
            return Err(material_error(
                "benchmark signing issuance returned invalid material",
            ));
        }
        Ok(Self {
            private_key,
            public_key,
            public_key_sha256,
        })
    }

    // Projects only paths and the verified public identity onto prepared setup material.
    fn material(
        &self,
        paths: &CoreSetupBenchmarkSigningPaths,
    ) -> CoreSetupBenchmarkSigningMaterial {
        CoreSetupBenchmarkSigningMaterial::new(
            paths.private_key_file.clone(),
            paths.public_key_file.clone(),
            self.public_key_sha256.clone(),
        )
    }
}

impl Drop for CoreSetupIssuedBenchmarkSigning {
    // Clears both retained key encodings after persistence or any failed operation.
    fn drop(&mut self) {
        self.private_key.fill(0);
        self.public_key.fill(0);
    }
}

// Carries one private authority and distinct server/client leaf identities until persistence.
pub struct CoreSetupIssuedMutualTlsTrust {
    authority_private_key: Vec<u8>,
    authority_certificate: Vec<u8>,
    server_certificate: Vec<u8>,
    server_private_key: Vec<u8>,
    client_certificate: Vec<u8>,
    client_private_key: Vec<u8>,
    server_certificate_sha256: Sha256Digest,
    client_certificate_sha256: Sha256Digest,
}

impl CoreSetupIssuedMutualTlsTrust {
    // Creates one bounded mutual-TLS closure after the issuer verifies both leaf identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_private_key: Vec<u8>,
        authority_certificate: Vec<u8>,
        server_certificate: Vec<u8>,
        server_private_key: Vec<u8>,
        client_certificate: Vec<u8>,
        client_private_key: Vec<u8>,
        server_certificate_sha256: Sha256Digest,
        client_certificate_sha256: Sha256Digest,
    ) -> Result<Self, CoreSetupProviderError> {
        let values = [
            authority_private_key.as_slice(),
            authority_certificate.as_slice(),
            server_certificate.as_slice(),
            server_private_key.as_slice(),
            client_certificate.as_slice(),
            client_private_key.as_slice(),
        ];
        if values
            .iter()
            .any(|value| value.is_empty() || value.len() > 64 * 1024)
        {
            return Err(material_error(
                "resident trust issuance returned invalid material",
            ));
        }
        Ok(Self {
            authority_private_key,
            authority_certificate,
            server_certificate,
            server_private_key,
            client_certificate,
            client_private_key,
            server_certificate_sha256,
            client_certificate_sha256,
        })
    }
}

impl Drop for CoreSetupIssuedMutualTlsTrust {
    // Clears every retained authority, leaf, and private-key byte on every exit path.
    fn drop(&mut self) {
        self.authority_private_key.fill(0);
        self.authority_certificate.fill(0);
        self.server_certificate.fill(0);
        self.server_private_key.fill(0);
        self.client_certificate.fill(0);
        self.client_private_key.fill(0);
    }
}

// Carries the complete standalone-main resident trust closure across atomic persistence.
pub struct CoreSetupIssuedResidentTrust {
    benchmark_signing: CoreSetupIssuedBenchmarkSigning,
    pairing: CoreSetupIssuedPairingTrust,
    node: CoreSetupIssuedMutualTlsTrust,
    gateway: CoreSetupIssuedMutualTlsTrust,
    watchdog: Option<CoreSetupIssuedMutualTlsTrust>,
}

impl CoreSetupIssuedResidentTrust {
    // Creates one platform-closed package with a dedicated Ed25519 benchmark signer.
    pub const fn new_with_benchmark_signing(
        benchmark_signing: CoreSetupIssuedBenchmarkSigning,
        pairing: CoreSetupIssuedPairingTrust,
        node: CoreSetupIssuedMutualTlsTrust,
        gateway: CoreSetupIssuedMutualTlsTrust,
        watchdog: Option<CoreSetupIssuedMutualTlsTrust>,
    ) -> Self {
        Self {
            benchmark_signing,
            pairing,
            node,
            gateway,
            watchdog,
        }
    }

    // Projects one complete secret-free prepared material result for an atomic I/O owner.
    pub fn prepared_material(
        &self,
        receipt: CoreSetupReceipt,
        paths: &CoreSetupMaterialPaths,
        identity: &CoreSetupPreparedIdentity,
        include_api_key: bool,
        material_identity: Sha256Digest,
    ) -> Result<CoreSetupPreparedMaterial, CoreSetupProviderError> {
        let materials = self.materials(paths, identity)?;
        Ok(CoreSetupPreparedMaterial::new_with_benchmark_signing(
            receipt,
            paths.database_file.clone(),
            paths.pairing_setup_secret_file.clone(),
            include_api_key.then(|| paths.api_key_file.clone()),
            materials.benchmark_signing,
            materials.pairing,
            materials.node,
            materials.gateway,
            materials.watchdog,
            material_identity,
        ))
    }

    // Projects every secret-free trust reference and public identity onto configured paths.
    fn materials(
        &self,
        paths: &CoreSetupMaterialPaths,
        identity: &CoreSetupPreparedIdentity,
    ) -> Result<ResidentTrustMaterials, CoreSetupProviderError> {
        let benchmark_signing =
            self.benchmark_signing
                .material(paths.benchmark_signing.as_ref().ok_or_else(|| {
                    material_error("benchmark signing material closure is incomplete")
                })?);
        let node = CoreSetupNodeTrustMaterial::new(
            paths.node_trust.authority_private_key_file.clone(),
            paths.node_trust.authority_certificate_file.clone(),
            paths.node_trust.server_certificate_file.clone(),
            paths.node_trust.server_private_key_file.clone(),
            paths.node_trust.client_certificate_file.clone(),
            paths.node_trust.client_private_key_file.clone(),
            self.node.server_certificate_sha256.clone(),
            self.node.client_certificate_sha256.clone(),
        );
        let gateway = CoreSetupGatewayTrustMaterial::new(
            paths.gateway_trust.authority_private_key_file.clone(),
            paths.gateway_trust.authority_certificate_file.clone(),
            paths.gateway_trust.server_certificate_file.clone(),
            paths.gateway_trust.server_private_key_file.clone(),
            paths.gateway_trust.relay_client_certificate_file.clone(),
            paths.gateway_trust.relay_client_private_key_file.clone(),
            self.gateway.server_certificate_sha256.clone(),
            self.gateway.client_certificate_sha256.clone(),
        );
        let watchdog = match (&paths.watchdog_trust, &self.watchdog) {
            (Some(paths), Some(trust)) => Some(CoreSetupWatchdogTrustMaterial::new(
                paths.authority_private_key_file.clone(),
                paths.authority_certificate_file.clone(),
                paths.server_certificate_file.clone(),
                paths.server_private_key_file.clone(),
                paths.controller_certificate_file.clone(),
                paths.controller_private_key_file.clone(),
                paths.controller_allowlist_file.clone(),
                trust.server_certificate_sha256.clone(),
                trust.client_certificate_sha256.clone(),
            )),
            (None, None) => None,
            _ => {
                return Err(material_error(
                    "resident trust platform closure is incomplete",
                ))
            }
        };
        let watchdog_allowlist = self.watchdog.as_ref().map(|trust| {
            format!(
                "version=1\ninstallation_id={}\ncontroller={},{}\n",
                identity.installation_id().as_str(),
                identity.node_id().as_str(),
                trust.client_certificate_sha256.as_str()
            )
            .into_bytes()
        });
        Ok(ResidentTrustMaterials {
            benchmark_signing,
            pairing: self.pairing.material(&paths.pairing_trust),
            node,
            gateway,
            watchdog,
            watchdog_allowlist,
        })
    }
}

// Retains only secret-free projections plus the Linux allowlist bytes required for persistence.
struct ResidentTrustMaterials {
    benchmark_signing: CoreSetupBenchmarkSigningMaterial,
    pairing: CoreSetupPairingTrustMaterial,
    node: CoreSetupNodeTrustMaterial,
    gateway: CoreSetupGatewayTrustMaterial,
    watchdog: Option<CoreSetupWatchdogTrustMaterial>,
    watchdog_allowlist: Option<Vec<u8>>,
}

// Supplies bounded cryptographic entropy without coupling setup policy to one CSPRNG.
pub trait CoreSetupMaterialEntropy: Send + Sync {
    // Fills the entire destination or fails without partial success.
    fn fill(&self, destination: &mut [u8]) -> Result<(), CoreSetupProviderError>;
}

// Supplies production material entropy from the operating-system CSPRNG.
#[derive(Default)]
pub struct SystemCoreSetupMaterialEntropy;

impl CoreSetupMaterialEntropy for SystemCoreSetupMaterialEntropy {
    // Fills the complete destination or returns one stable redacted failure.
    fn fill(&self, destination: &mut [u8]) -> Result<(), CoreSetupProviderError> {
        getrandom::fill(destination)
            .map_err(|_| material_error("private material entropy is unavailable"))
    }
}

// Issues and verifies the complete standalone-main resident trust closure.
pub trait CoreSetupResidentTrustIssuer: Send + Sync {
    // Returns one platform-closed identity package bound to the exact setup request and Node.
    fn issue(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
    ) -> Result<CoreSetupIssuedResidentTrust, CoreSetupProviderError>;
}

// Defines bounded owner-only workspace operations for Core-setup resident trust issuance.
pub trait CoreSetupTrustWorkspaceIo: Send + Sync {
    // Creates or validates one owner-private staging root.
    fn ensure_private_root(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupProviderError>;

    // Creates one collision-rejecting owner-private operation workspace.
    fn create_private_workspace(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupProviderError>;

    // Writes one new bounded owner-private input file.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupProviderError>;

    // Creates one empty owner-private output file for an exact native command.
    fn create_private_output_file(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupProviderError>;

    // Reads one nonempty bounded owner-private output without following links.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Vec<u8>, CoreSetupProviderError>;

    // Removes exactly one closed Core-setup trust workspace and no foreign entry.
    fn remove_workspace(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<bool, CoreSetupProviderError>;
}

// Performs no-follow resident trust workspace operations on Unix hosts.
#[derive(Default)]
pub struct SystemCoreSetupTrustWorkspaceIo;

impl CoreSetupTrustWorkspaceIo for SystemCoreSetupTrustWorkspaceIo {
    // Creates or validates one owner-private staging root.
    fn ensure_private_root(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupProviderError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => validate_trust_directory_metadata(&metadata, owner_user_id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_trust_directory(path)?;
                validate_trust_directory_metadata(
                    &fs::symlink_metadata(path)
                        .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))?,
                    owner_user_id,
                )
            }
            Err(_) => Err(material_error("OpenSSL trust workspace is unavailable")),
        }
    }

    // Creates one collision-rejecting owner-private operation workspace.
    fn create_private_workspace(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupProviderError> {
        let parent = path
            .parent()
            .ok_or_else(|| material_error("OpenSSL trust workspace is unavailable"))?;
        validate_trust_directory_metadata(
            &fs::symlink_metadata(parent)
                .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))?,
            owner_user_id,
        )?;
        create_trust_directory(path)?;
        validate_trust_directory_metadata(
            &fs::symlink_metadata(path)
                .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))?,
            owner_user_id,
        )
    }

    // Writes one new bounded owner-private input file and synchronizes its parent.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupProviderError> {
        if payload.is_empty() || payload.len() > maximum_bytes {
            return Err(material_error("OpenSSL trust workspace payload is invalid"));
        }
        validate_trust_parent(path, owner_user_id)?;
        let mut file = create_trust_file(path)?;
        file.write_all(payload)
            .and_then(|_| file.sync_all())
            .map_err(|_| material_recovery_error("OpenSSL trust workspace write is ambiguous"))?;
        sync_trust_directory(
            path.parent()
                .ok_or_else(|| material_error("OpenSSL trust workspace is unavailable"))?,
        )
    }

    // Creates one empty owner-private output file and synchronizes its parent.
    fn create_private_output_file(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupProviderError> {
        validate_trust_parent(path, owner_user_id)?;
        create_trust_file(path)?
            .sync_all()
            .map_err(|_| material_recovery_error("OpenSSL trust workspace write is ambiguous"))?;
        sync_trust_directory(
            path.parent()
                .ok_or_else(|| material_error("OpenSSL trust workspace is unavailable"))?,
        )
    }

    // Reads one stable bounded owner-private output without following its leaf.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Vec<u8>, CoreSetupProviderError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| material_error("OpenSSL trust output is invalid"))?;
        let initial = file
            .metadata()
            .map_err(|_| material_error("OpenSSL trust output is invalid"))?;
        validate_trust_file_metadata(&initial, owner_user_id, maximum_bytes, true)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| material_error("OpenSSL trust output is invalid"))?;
        let final_metadata = file
            .metadata()
            .map_err(|_| material_error("OpenSSL trust output is invalid"))?;
        if bytes.is_empty()
            || bytes.len() > maximum_bytes
            || !same_trust_file_metadata(&initial, &final_metadata)
        {
            bytes.fill(0);
            return Err(material_error("OpenSSL trust output is invalid"));
        }
        Ok(bytes)
    }

    // Removes only exact known regular workspace files and then the empty workspace.
    fn remove_workspace(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<bool, CoreSetupProviderError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => {
                return Err(material_recovery_error(
                    "OpenSSL trust cleanup is ambiguous",
                ))
            }
        };
        validate_trust_directory_metadata(&metadata, owner_user_id)?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)
            .map_err(|_| material_recovery_error("OpenSSL trust cleanup is ambiguous"))?
        {
            let entry =
                entry.map_err(|_| material_recovery_error("OpenSSL trust cleanup is ambiguous"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| material_recovery_error("OpenSSL trust cleanup is ambiguous"))?;
            if !is_core_setup_trust_workspace_file(&name) {
                return Err(material_recovery_error(
                    "OpenSSL trust workspace contains an unknown entry",
                ));
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| material_recovery_error("OpenSSL trust cleanup is ambiguous"))?;
            validate_trust_file_metadata(&metadata, owner_user_id, 64 * 1024, false)?;
            entries.push(entry.path());
        }
        for entry in entries {
            fs::remove_file(entry)
                .map_err(|_| material_recovery_error("OpenSSL trust cleanup is ambiguous"))?;
        }
        fs::remove_dir(path)
            .map_err(|_| material_recovery_error("OpenSSL trust cleanup is ambiguous"))?;
        sync_trust_directory(
            path.parent()
                .ok_or_else(|| material_recovery_error("OpenSSL trust cleanup is ambiguous"))?,
        )?;
        Ok(true)
    }
}

// Issues all initial resident P-256 trust identities through bounded shell-free OpenSSL argv.
pub struct OpenSslCoreSetupResidentTrustIssuer {
    openssl: PathBuf,
    workspace_root: PathBuf,
    owner_user_id: u32,
    runner: Arc<dyn PairingNativeCommandRunner>,
    io: Arc<dyn CoreSetupTrustWorkspaceIo>,
}

impl OpenSslCoreSetupResidentTrustIssuer {
    // Creates one explicit shell-free issuer without discovering OpenSSL or trust paths.
    pub fn new(
        openssl: PathBuf,
        workspace_root: PathBuf,
        owner_user_id: u32,
        runner: Arc<dyn PairingNativeCommandRunner>,
        io: Arc<dyn CoreSetupTrustWorkspaceIo>,
    ) -> Result<Self, CoreSetupProviderError> {
        if !is_normal_absolute_path(&openssl)
            || openssl.file_name().and_then(OsStr::to_str) != Some("openssl")
            || !is_normal_absolute_path(&workspace_root)
            || workspace_root == Path::new("/")
        {
            return Err(material_error(
                "OpenSSL trust issuer configuration is invalid",
            ));
        }
        Ok(Self {
            openssl,
            workspace_root,
            owner_user_id,
            runner,
            io,
        })
    }

    // Executes one exact bounded OpenSSL command and redacts all native output.
    fn run(&self, arguments: Vec<String>) -> Result<(), CoreSetupProviderError> {
        let command = PairingNativeCommand::new(self.openssl.clone(), arguments)
            .map_err(|_| material_error("OpenSSL trust issuer command is invalid"))?;
        let output = self
            .runner
            .run(&command, Duration::from_secs(15), 8 * 1024)
            .map_err(|_| material_error("OpenSSL trust issuance failed"))?;
        if output.timed_out() || output.status() != 0 {
            return Err(material_error("OpenSSL trust issuance failed"));
        }
        Ok(())
    }

    // Returns one UTF-8 native path argument without leaking it into errors.
    fn argument(path: &Path) -> Result<String, CoreSetupProviderError> {
        path.to_str()
            .map(str::to_string)
            .ok_or_else(|| material_error("OpenSSL trust issuer path is invalid"))
    }

    // Creates one empty output file under the private workspace boundary.
    fn output(&self, path: &Path) -> Result<(), CoreSetupProviderError> {
        self.io
            .create_private_output_file(path, self.owner_user_id)
            .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))
    }

    // Reads one exact bounded private workspace file.
    fn read(&self, path: &Path, maximum: usize) -> Result<Vec<u8>, CoreSetupProviderError> {
        self.io
            .read_private_file(path, maximum, self.owner_user_id)
            .map_err(|_| material_error("OpenSSL trust output is invalid"))
    }

    // Generates one ring-compatible PKCS#8 P-256 private key for portable certificate issuance.
    fn generate_p256_private_key(&self, destination: &Path) -> Result<(), CoreSetupProviderError> {
        let private_document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| material_error("P-256 trust issuance failed"))?;
        let mut private_key = pem_document("PRIVATE KEY", private_document.as_ref());
        let result = self
            .io
            .write_private_file(destination, &private_key, 16 * 1024, self.owner_user_id)
            .map_err(|_| material_error("OpenSSL trust workspace is unavailable"));
        private_key.fill(0);
        result
    }
}

impl CoreSetupResidentTrustIssuer for OpenSslCoreSetupResidentTrustIssuer {
    // Generates, verifies, fingerprints, and always cleans one platform-closed workspace.
    fn issue(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
    ) -> Result<CoreSetupIssuedResidentTrust, CoreSetupProviderError> {
        self.io
            .ensure_private_root(&self.workspace_root, self.owner_user_id)
            .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))?;
        let workspace = self
            .workspace_root
            .join(format!("setup-{}", identity.installation_id().as_str()));
        self.io
            .remove_workspace(&workspace, self.owner_user_id)
            .map_err(|_| {
                material_recovery_error("OpenSSL trust workspace recovery is ambiguous")
            })?;
        self.io
            .create_private_workspace(&workspace, self.owner_user_id)
            .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))?;
        let result = self.issue_in_workspace(request, identity, &workspace);
        let cleanup = self
            .io
            .remove_workspace(&workspace, self.owner_user_id)
            .map_err(|_| material_recovery_error("OpenSSL trust workspace cleanup is ambiguous"));
        match (result, cleanup) {
            (Ok(value), Ok(_)) => Ok(value),
            (Err(error), Ok(_)) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }
}

impl OpenSslCoreSetupResidentTrustIssuer {
    // Performs the complete shell-free resident generation and verification sequence.
    fn issue_in_workspace(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
        workspace: &Path,
    ) -> Result<CoreSetupIssuedResidentTrust, CoreSetupProviderError> {
        let benchmark_signing = self.issue_benchmark_signing_in_workspace(workspace)?;
        let pairing = self.issue_pairing_in_workspace(identity, workspace)?;
        let node = self.issue_mutual_tls_in_workspace(
            workspace,
            "node",
            "Lets Infer Node Remote CA",
            "Lets Infer Node Remote Server",
            "Lets Infer Main Node Client",
            identity.control_address().as_str(),
            11,
        )?;
        let gateway = self.issue_mutual_tls_in_workspace(
            workspace,
            "gateway",
            "Lets Infer Gateway Private CA",
            "Lets Infer Gateway Private Server",
            "Lets Infer Main Relay Client",
            identity.control_address().as_str(),
            21,
        )?;
        let watchdog = match request.context().platform() {
            li_core_update_manager::CoreUpdateServicePlatform::Linux => {
                Some(self.issue_mutual_tls_in_workspace(
                    workspace,
                    "watchdog",
                    "Lets Infer Watchdog CA",
                    "Lets Infer Watchdog Server",
                    "Lets Infer Core Health Controller",
                    identity.control_address().as_str(),
                    31,
                )?)
            }
            li_core_update_manager::CoreUpdateServicePlatform::Macos => None,
        };
        Ok(CoreSetupIssuedResidentTrust::new_with_benchmark_signing(
            benchmark_signing,
            pairing,
            node,
            gateway,
            watchdog,
        ))
    }

    // Issues one Ed25519 benchmark signer without depending on platform OpenSSL algorithms.
    fn issue_benchmark_signing_in_workspace(
        &self,
        _workspace: &Path,
    ) -> Result<CoreSetupIssuedBenchmarkSigning, CoreSetupProviderError> {
        let private_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| material_error("benchmark signing issuance failed"))?;
        let key_pair = Ed25519KeyPair::from_pkcs8(private_document.as_ref())
            .map_err(|_| material_error("benchmark signing issuance failed"))?;
        let mut public_der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
        public_der.extend_from_slice(ED25519_SPKI_PREFIX);
        public_der.extend_from_slice(key_pair.public_key().as_ref());
        let public_key_sha256 = Sha256Digest::parse(&sha256_bytes(&public_der)?)
            .map_err(|_| material_error("benchmark signing public identity is invalid"))?;
        let private_key = pem_document("PRIVATE KEY", private_document.as_ref());
        let public_key = pem_document("PUBLIC KEY", &public_der);
        public_der.fill(0);
        CoreSetupIssuedBenchmarkSigning::new(private_key, public_key, public_key_sha256)
    }

    // Performs the existing PairingManager-owned site trust issuance without widening its files.
    fn issue_pairing_in_workspace(
        &self,
        identity: &CoreSetupPreparedIdentity,
        workspace: &Path,
    ) -> Result<CoreSetupIssuedPairingTrust, CoreSetupProviderError> {
        let private_key = workspace.join("li_site_private_key.pem");
        let public_key = workspace.join("li_site_public_key.pem");
        let ca_certificate = workspace.join("li_site_ca_certificate.pem");
        let request = workspace.join("li_candidate_public_key.pem");
        let extensions = workspace.join("li_member_extensions.cnf");
        let local_certificate = workspace.join("li_local_control_certificate.pem");
        let public_der = workspace.join("li_site_public_key.der");
        let private_public_der = workspace.join("li_site_private_public_key.der");
        let local_der = workspace.join("li_local_control_certificate.der");
        for output in [
            &public_key,
            &ca_certificate,
            &request,
            &local_certificate,
            &public_der,
            &private_public_der,
            &local_der,
        ] {
            self.output(output)?;
        }
        let extension_bytes = format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=URI:letsinfer://node/{}\n", identity.node_id().as_str());
        self.io
            .write_private_file(
                &extensions,
                extension_bytes.as_bytes(),
                4 * 1024,
                self.owner_user_id,
            )
            .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))?;
        let path = |value: &Path| Self::argument(value);
        self.generate_p256_private_key(&private_key)?;
        self.run(vec![
            "pkey".into(),
            "-in".into(),
            path(&private_key)?,
            "-pubout".into(),
            "-out".into(),
            path(&public_key)?,
        ])?;
        self.run(vec![
            "req".into(),
            "-new".into(),
            "-x509".into(),
            "-key".into(),
            path(&private_key)?,
            "-sha256".into(),
            "-days".into(),
            "3650".into(),
            "-subj".into(),
            "/CN=Lets Infer Site CA".into(),
            "-addext".into(),
            "basicConstraints=critical,CA:TRUE".into(),
            "-addext".into(),
            "keyUsage=critical,keyCertSign,digitalSignature".into(),
            "-out".into(),
            path(&ca_certificate)?,
        ])?;
        self.run(vec![
            "req".into(),
            "-new".into(),
            "-key".into(),
            path(&private_key)?,
            "-subj".into(),
            format!("/CN={}", identity.node_id().as_str()),
            "-out".into(),
            path(&request)?,
        ])?;
        self.run(vec![
            "x509".into(),
            "-req".into(),
            "-in".into(),
            path(&request)?,
            "-CA".into(),
            path(&ca_certificate)?,
            "-CAkey".into(),
            path(&private_key)?,
            "-set_serial".into(),
            "1".into(),
            "-days".into(),
            "3650".into(),
            "-sha256".into(),
            "-extfile".into(),
            path(&extensions)?,
            "-out".into(),
            path(&local_certificate)?,
        ])?;
        for purpose in ["sslserver", "sslclient"] {
            self.run(vec![
                "verify".into(),
                "-CAfile".into(),
                path(&ca_certificate)?,
                "-purpose".into(),
                purpose.into(),
                path(&local_certificate)?,
            ])?;
        }
        self.run(vec![
            "verify".into(),
            "-CAfile".into(),
            path(&ca_certificate)?,
            path(&ca_certificate)?,
        ])?;
        self.run(vec![
            "pkey".into(),
            "-pubin".into(),
            "-in".into(),
            path(&public_key)?,
            "-noout".into(),
        ])?;
        self.run(vec![
            "pkey".into(),
            "-pubin".into(),
            "-in".into(),
            path(&public_key)?,
            "-outform".into(),
            "DER".into(),
            "-out".into(),
            path(&public_der)?,
        ])?;
        self.run(vec![
            "pkey".into(),
            "-in".into(),
            path(&private_key)?,
            "-pubout".into(),
            "-outform".into(),
            "DER".into(),
            "-out".into(),
            path(&private_public_der)?,
        ])?;
        let public_der_bytes = self.read(&public_der, 64 * 1024)?;
        if self.read(&private_public_der, 64 * 1024)? != public_der_bytes {
            return Err(material_error("OpenSSL trust key identities differ"));
        }
        self.run(vec![
            "x509".into(),
            "-in".into(),
            path(&local_certificate)?,
            "-outform".into(),
            "DER".into(),
            "-out".into(),
            path(&local_der)?,
        ])?;
        let local_der_bytes = self.read(&local_der, 64 * 1024)?;
        CoreSetupIssuedPairingTrust::new(
            self.read(&private_key, 16 * 1024)?,
            self.read(&public_key, 8 * 1024)?,
            self.read(&ca_certificate, 64 * 1024)?,
            self.read(&local_certificate, 64 * 1024)?,
            Sha256Digest::parse(&sha256_bytes(&public_der_bytes)?)
                .map_err(|_| material_error("OpenSSL public identity is invalid"))?,
            Sha256Digest::parse(&sha256_bytes(&local_der_bytes)?)
                .map_err(|_| material_error("OpenSSL certificate identity is invalid"))?,
        )
    }

    // Issues one CA plus distinct server and client leaves under role-specific workspace names.
    #[allow(clippy::too_many_arguments)]
    fn issue_mutual_tls_in_workspace(
        &self,
        workspace: &Path,
        role: &str,
        authority_common_name: &str,
        server_common_name: &str,
        client_common_name: &str,
        server_name: &str,
        serial: u32,
    ) -> Result<CoreSetupIssuedMutualTlsTrust, CoreSetupProviderError> {
        let authority_private_key = workspace.join(format!("li_{role}_authority.key"));
        let authority_certificate = workspace.join(format!("li_{role}_authority.crt"));
        let server_private_key = workspace.join(format!("li_{role}_server.key"));
        let server_request = workspace.join(format!("li_{role}_server.csr"));
        let server_extensions = workspace.join(format!("li_{role}_server.cnf"));
        let server_certificate = workspace.join(format!("li_{role}_server.crt"));
        let server_der = workspace.join(format!("li_{role}_server.der"));
        let client_private_key = workspace.join(format!("li_{role}_client.key"));
        let client_request = workspace.join(format!("li_{role}_client.csr"));
        let client_extensions = workspace.join(format!("li_{role}_client.cnf"));
        let client_certificate = workspace.join(format!("li_{role}_client.crt"));
        let client_der = workspace.join(format!("li_{role}_client.der"));
        for output in [
            &authority_certificate,
            &server_request,
            &server_certificate,
            &server_der,
            &client_request,
            &client_certificate,
            &client_der,
        ] {
            self.output(output)?;
        }
        let subject_alt_name = certificate_subject_alt_name(server_name)?;
        let server_extension_bytes = format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName={subject_alt_name}\n"
        );
        let client_extension_bytes = b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n";
        self.io
            .write_private_file(
                &server_extensions,
                server_extension_bytes.as_bytes(),
                4 * 1024,
                self.owner_user_id,
            )
            .and_then(|_| {
                self.io.write_private_file(
                    &client_extensions,
                    client_extension_bytes,
                    4 * 1024,
                    self.owner_user_id,
                )
            })
            .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))?;
        let path = |value: &Path| Self::argument(value);
        self.generate_p256_private_key(&authority_private_key)?;
        self.run(vec![
            "req".into(),
            "-new".into(),
            "-x509".into(),
            "-key".into(),
            path(&authority_private_key)?,
            "-sha256".into(),
            "-days".into(),
            "3650".into(),
            "-subj".into(),
            format!("/CN={authority_common_name}"),
            "-addext".into(),
            "basicConstraints=critical,CA:TRUE".into(),
            "-addext".into(),
            "keyUsage=critical,keyCertSign,cRLSign,digitalSignature".into(),
            "-out".into(),
            path(&authority_certificate)?,
        ])?;
        self.issue_leaf(
            &authority_private_key,
            &authority_certificate,
            &server_private_key,
            &server_request,
            &server_extensions,
            &server_certificate,
            server_common_name,
            serial,
            "sslserver",
        )?;
        self.issue_leaf(
            &authority_private_key,
            &authority_certificate,
            &client_private_key,
            &client_request,
            &client_extensions,
            &client_certificate,
            client_common_name,
            serial
                .checked_add(1)
                .ok_or_else(|| material_error("OpenSSL trust serial is invalid"))?,
            "sslclient",
        )?;
        self.run(vec![
            "verify".into(),
            "-CAfile".into(),
            path(&authority_certificate)?,
            path(&authority_certificate)?,
        ])?;
        for (certificate, der) in [
            (&server_certificate, &server_der),
            (&client_certificate, &client_der),
        ] {
            self.run(vec![
                "x509".into(),
                "-in".into(),
                path(certificate)?,
                "-outform".into(),
                "DER".into(),
                "-out".into(),
                path(der)?,
            ])?;
        }
        let server_der = self.read(&server_der, 64 * 1024)?;
        let client_der = self.read(&client_der, 64 * 1024)?;
        CoreSetupIssuedMutualTlsTrust::new(
            self.read(&authority_private_key, 16 * 1024)?,
            self.read(&authority_certificate, 64 * 1024)?,
            self.read(&server_certificate, 64 * 1024)?,
            self.read(&server_private_key, 16 * 1024)?,
            self.read(&client_certificate, 64 * 1024)?,
            self.read(&client_private_key, 16 * 1024)?,
            Sha256Digest::parse(&sha256_bytes(&server_der)?)
                .map_err(|_| material_error("OpenSSL server identity is invalid"))?,
            Sha256Digest::parse(&sha256_bytes(&client_der)?)
                .map_err(|_| material_error("OpenSSL client identity is invalid"))?,
        )
    }

    // Issues and verifies one role-specific leaf under an already created authority.
    #[allow(clippy::too_many_arguments)]
    fn issue_leaf(
        &self,
        authority_private_key: &Path,
        authority_certificate: &Path,
        private_key: &Path,
        request: &Path,
        extensions: &Path,
        certificate: &Path,
        common_name: &str,
        serial: u32,
        purpose: &str,
    ) -> Result<(), CoreSetupProviderError> {
        let path = |value: &Path| Self::argument(value);
        self.generate_p256_private_key(private_key)?;
        self.run(vec![
            "req".into(),
            "-new".into(),
            "-key".into(),
            path(private_key)?,
            "-subj".into(),
            format!("/CN={common_name}"),
            "-out".into(),
            path(request)?,
        ])?;
        self.run(vec![
            "x509".into(),
            "-req".into(),
            "-in".into(),
            path(request)?,
            "-CA".into(),
            path(authority_certificate)?,
            "-CAkey".into(),
            path(authority_private_key)?,
            "-set_serial".into(),
            serial.to_string(),
            "-days".into(),
            "3650".into(),
            "-sha256".into(),
            "-extfile".into(),
            path(extensions)?,
            "-out".into(),
            path(certificate)?,
        ])?;
        self.run(vec![
            "verify".into(),
            "-CAfile".into(),
            path(authority_certificate)?,
            "-purpose".into(),
            purpose.to_string(),
            path(certificate)?,
        ])
    }
}

// Returns a safe OpenSSL subject-alternative-name value for one validated Node address.
fn certificate_subject_alt_name(value: &str) -> Result<String, CoreSetupProviderError> {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Ok(format!("IP:{value}"));
    }
    if value.is_empty()
        || value.len() > 253
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(material_error("resident trust server name is invalid"));
    }
    Ok(format!("DNS:{value}"))
}

// Creates one new mode-0700 trust directory without following or reusing a collision.
fn create_trust_directory(path: &Path) -> Result<(), CoreSetupProviderError> {
    let mut builder = DirBuilder::new();
    builder.mode(MATERIAL_DIRECTORY_MODE);
    builder
        .create(path)
        .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))
}

// Creates one new mode-0600 trust file without following or reusing its leaf.
fn create_trust_file(path: &Path) -> Result<File, CoreSetupProviderError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MATERIAL_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))
}

// Requires one workspace parent to remain an owner-private ordinary directory.
fn validate_trust_parent(path: &Path, owner_user_id: u32) -> Result<(), CoreSetupProviderError> {
    let parent = path
        .parent()
        .ok_or_else(|| material_error("OpenSSL trust workspace is unavailable"))?;
    validate_trust_directory_metadata(
        &fs::symlink_metadata(parent)
            .map_err(|_| material_error("OpenSSL trust workspace is unavailable"))?,
        owner_user_id,
    )
}

// Requires one directory observation to be owner-private and not a symbolic link.
fn validate_trust_directory_metadata(
    metadata: &fs::Metadata,
    owner_user_id: u32,
) -> Result<(), CoreSetupProviderError> {
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != MATERIAL_DIRECTORY_MODE
    {
        return Err(material_error("OpenSSL trust workspace is unsafe"));
    }
    Ok(())
}

// Requires one trust file observation to be a bounded owner-private single-link regular file.
fn validate_trust_file_metadata(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    maximum_bytes: usize,
    nonempty: bool,
) -> Result<(), CoreSetupProviderError> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != MATERIAL_FILE_MODE
        || metadata.nlink() != 1
        || metadata.len() > maximum_bytes as u64
        || (nonempty && metadata.len() == 0)
    {
        return Err(material_error("OpenSSL trust workspace file is unsafe"));
    }
    Ok(())
}

// Returns whether one open trust file retained its complete descriptor identity while read.
fn same_trust_file_metadata(initial: &fs::Metadata, final_metadata: &fs::Metadata) -> bool {
    initial.dev() == final_metadata.dev()
        && initial.ino() == final_metadata.ino()
        && initial.uid() == final_metadata.uid()
        && initial.mode() == final_metadata.mode()
        && initial.nlink() == final_metadata.nlink()
        && initial.len() == final_metadata.len()
        && initial.mtime() == final_metadata.mtime()
        && initial.mtime_nsec() == final_metadata.mtime_nsec()
        && initial.ctime() == final_metadata.ctime()
        && initial.ctime_nsec() == final_metadata.ctime_nsec()
}

// Synchronizes one exact trust directory after a file or directory mutation.
fn sync_trust_directory(path: &Path) -> Result<(), CoreSetupProviderError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| material_recovery_error("OpenSSL trust workspace sync is ambiguous"))
}

// Returns whether one workspace entry belongs to the exact Core-setup trust issuer vocabulary.
fn is_core_setup_trust_workspace_file(name: &str) -> bool {
    if matches!(
        name,
        "li_site_private_key.pem"
            | "li_benchmark_signing_private_key.pem"
            | "li_benchmark_signing_public_key.pem"
            | "li_benchmark_signing_public_key.der"
            | "li_benchmark_signing_private_public_key.der"
            | "li_site_public_key.pem"
            | "li_site_ca_certificate.pem"
            | "li_candidate_public_key.pem"
            | "li_member_extensions.cnf"
            | "li_local_control_certificate.pem"
            | "li_site_public_key.der"
            | "li_site_private_public_key.der"
            | "li_local_control_certificate.der"
    ) {
        return true;
    }
    ["node", "gateway", "watchdog"].iter().any(|role| {
        [
            "authority.key",
            "authority.crt",
            "server.key",
            "server.csr",
            "server.cnf",
            "server.crt",
            "server.der",
            "client.key",
            "client.csr",
            "client.cnf",
            "client.crt",
            "client.der",
        ]
        .iter()
        .any(|suffix| name == format!("li_{role}_{suffix}"))
    })
}

// Owns atomic no-follow persistence, crash reconciliation, and receipt-bound rollback.
pub trait CoreSetupMaterialIo: Send + Sync {
    // Returns an exact prior closure for quiet replay before generating new secrets.
    fn read(
        &self,
        receipt: &CoreSetupReceipt,
    ) -> Result<Option<CoreSetupPreparedMaterial>, CoreSetupProviderError>;

    // Atomically creates or reconciles one complete closure and returns the authoritative winner.
    fn create(
        &self,
        receipt: &CoreSetupReceipt,
        paths: &CoreSetupMaterialPaths,
        prepared_identity: &CoreSetupPreparedIdentity,
        pairing_secret: &[u8; SECRET_BYTES],
        api_key: Option<&[u8; SECRET_BYTES]>,
        trust: &CoreSetupIssuedResidentTrust,
        material_identity: &Sha256Digest,
    ) -> Result<CoreSetupPreparedMaterial, CoreSetupProviderError>;

    // Removes only exact files recorded as created by this receipt.
    fn rollback(&self, receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError>;
}

// Identifies one durable native publication boundary for crash-recovery evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreSetupMaterialPublication {
    StagingDirectory,
    StagedFile,
    PreparingIntent,
    TargetFile,
    CompleteIntent,
}

// Observes durable material publications without receiving any secret bytes or paths.
pub trait CoreSetupMaterialPublicationObserver: Send + Sync {
    // Returns after one durable publication or injects an ambiguous crash boundary.
    fn did_publish(
        &self,
        publication: CoreSetupMaterialPublication,
        publication_index: usize,
    ) -> Result<(), CoreSetupProviderError>;
}

// Accepts every production material publication without adding side effects.
struct NoopCoreSetupMaterialPublicationObserver;

impl CoreSetupMaterialPublicationObserver for NoopCoreSetupMaterialPublicationObserver {
    // Preserves the ordinary production path after every durable publication.
    fn did_publish(
        &self,
        _publication: CoreSetupMaterialPublication,
        _publication_index: usize,
    ) -> Result<(), CoreSetupProviderError> {
        Ok(())
    }
}

// Performs descriptor-relative durable material transactions beneath one owner-private root.
pub struct SystemCoreSetupMaterialIo {
    root: PathBuf,
    owner_user_id: u32,
    process_lock: Mutex<()>,
    publications: Arc<dyn CoreSetupMaterialPublicationObserver>,
}

impl SystemCoreSetupMaterialIo {
    // Creates one native owner rooted at an explicit normal absolute material directory.
    pub fn new(root: PathBuf, owner_user_id: u32) -> Result<Self, CoreSetupProviderError> {
        if !is_normal_absolute_path(&root) || root == Path::new("/") {
            return Err(material_error("private material root is invalid"));
        }
        Ok(Self {
            root,
            owner_user_id,
            process_lock: Mutex::new(()),
            publications: Arc::new(NoopCoreSetupMaterialPublicationObserver),
        })
    }

    // Creates one native owner with an injected secret-free publication observer for tests.
    pub fn new_with_publication_observer(
        root: PathBuf,
        owner_user_id: u32,
        publications: Arc<dyn CoreSetupMaterialPublicationObserver>,
    ) -> Result<Self, CoreSetupProviderError> {
        let mut value = Self::new(root, owner_user_id)?;
        value.publications = publications;
        Ok(value)
    }

    // Runs one operation under both process-local and cross-process exclusive ownership.
    fn with_lock<Value>(
        &self,
        body: impl FnOnce(&File) -> Result<Value, CoreSetupProviderError>,
    ) -> Result<Value, CoreSetupProviderError> {
        let _process = self.process_lock.lock().map_err(|_| {
            CoreSetupProviderError::recovery_required(
                "private material",
                "private material process lock is unavailable",
            )
        })?;
        let root = open_private_directory(&self.root, self.owner_user_id)?;
        let lock = open_private_lock(&root, self.owner_user_id)?;
        let status = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
        if status != 0 {
            return Err(material_recovery_error(
                "private material cross-process lock is unavailable",
            ));
        }
        let result = body(&root);
        let _ = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
        result
    }

    // Returns the receipt-specific manifest filename without accepting caller path bytes.
    fn manifest_name(receipt: &CoreSetupReceipt) -> String {
        format!(
            ".li_core_setup_material_{}.json",
            receipt.identity().as_str()
        )
    }

    // Returns the receipt-specific private staging directory name.
    fn staging_name(receipt: &CoreSetupReceipt) -> String {
        format!(
            ".li_core_setup_material_{}.pending",
            receipt.identity().as_str()
        )
    }

    // Advances one secret-free publication sequence after durable native state exists.
    fn observed(
        &self,
        publication: CoreSetupMaterialPublication,
        publication_index: &mut usize,
    ) -> Result<(), CoreSetupProviderError> {
        let current = *publication_index;
        *publication_index = current
            .checked_add(1)
            .ok_or_else(|| material_recovery_error("private material publication overflowed"))?;
        self.publications.did_publish(publication, current)
    }
}

impl CoreSetupMaterialIo for SystemCoreSetupMaterialIo {
    // Reconciles one durable intent and returns its exact secret-free closure.
    fn read(
        &self,
        receipt: &CoreSetupReceipt,
    ) -> Result<Option<CoreSetupPreparedMaterial>, CoreSetupProviderError> {
        self.with_lock(|root| {
            let mut publication_index = 0;
            let name = Self::manifest_name(receipt);
            let Some(mut manifest) = read_manifest(root, &name, self.owner_user_id, &self.root)?
            else {
                return Ok(None);
            };
            require_manifest_receipt(&manifest, receipt)?;
            reconcile_manifest(
                root,
                &mut manifest,
                self.owner_user_id,
                self,
                &mut publication_index,
            )?;
            if manifest.state != "complete" {
                manifest.state = "complete".to_string();
                write_manifest(root, &name, &manifest, self.owner_user_id)?;
                self.observed(
                    CoreSetupMaterialPublication::CompleteIntent,
                    &mut publication_index,
                )?;
            }
            material_from_manifest(&manifest).map(Some)
        })
    }

    // Stages every bounded payload, durably records intent, then publishes exact files.
    fn create(
        &self,
        receipt: &CoreSetupReceipt,
        paths: &CoreSetupMaterialPaths,
        prepared_identity: &CoreSetupPreparedIdentity,
        pairing_secret: &[u8; SECRET_BYTES],
        api_key: Option<&[u8; SECRET_BYTES]>,
        trust: &CoreSetupIssuedResidentTrust,
        material_identity: &Sha256Digest,
    ) -> Result<CoreSetupPreparedMaterial, CoreSetupProviderError> {
        self.with_lock(|root| {
            let mut publication_index = 0;
            let manifest_name = Self::manifest_name(receipt);
            if let Some(mut manifest) =
                read_manifest(root, &manifest_name, self.owner_user_id, &self.root)?
            {
                require_manifest_receipt(&manifest, receipt)?;
                reconcile_manifest(
                    root,
                    &mut manifest,
                    self.owner_user_id,
                    self,
                    &mut publication_index,
                )?;
                return material_from_manifest(&manifest);
            }
            let staging_name = Self::staging_name(receipt);
            remove_receipt_staging(root, &staging_name, self.owner_user_id)?;
            create_private_directory_at(root, &staging_name, self.owner_user_id)?;
            self.observed(
                CoreSetupMaterialPublication::StagingDirectory,
                &mut publication_index,
            )?;
            let staging = open_private_directory_at(root, &staging_name, self.owner_user_id)?;
            let materials = trust.materials(paths, prepared_identity)?;
            let benchmark_signing_paths = paths.benchmark_signing.as_ref().ok_or_else(|| {
                material_error("benchmark signing material closure is incomplete")
            })?;
            let mut files = vec![
                material_file(
                    "pairing_setup_secret",
                    &paths.pairing_setup_secret_file,
                    pairing_secret,
                    &self.root,
                )?,
                material_file(
                    "benchmark_signing_private_key",
                    &benchmark_signing_paths.private_key_file,
                    &trust.benchmark_signing.private_key,
                    &self.root,
                )?,
                material_file(
                    "benchmark_signing_public_key",
                    &benchmark_signing_paths.public_key_file,
                    &trust.benchmark_signing.public_key,
                    &self.root,
                )?,
                material_file(
                    "site_private_key",
                    &paths.pairing_trust.site_private_key_file,
                    &trust.pairing.site_private_key,
                    &self.root,
                )?,
                material_file(
                    "site_public_key",
                    &paths.pairing_trust.site_public_key_file,
                    &trust.pairing.site_public_key,
                    &self.root,
                )?,
                material_file(
                    "site_ca_certificate",
                    &paths.pairing_trust.site_ca_certificate_file,
                    &trust.pairing.site_ca_certificate,
                    &self.root,
                )?,
                material_file(
                    "local_control_certificate",
                    &paths.pairing_trust.local_control_certificate_file,
                    &trust.pairing.local_control_certificate,
                    &self.root,
                )?,
                material_file(
                    "node_authority_private_key",
                    &paths.node_trust.authority_private_key_file,
                    &trust.node.authority_private_key,
                    &self.root,
                )?,
                material_file(
                    "node_authority_certificate",
                    &paths.node_trust.authority_certificate_file,
                    &trust.node.authority_certificate,
                    &self.root,
                )?,
                material_file(
                    "node_server_certificate",
                    &paths.node_trust.server_certificate_file,
                    &trust.node.server_certificate,
                    &self.root,
                )?,
                material_file(
                    "node_server_private_key",
                    &paths.node_trust.server_private_key_file,
                    &trust.node.server_private_key,
                    &self.root,
                )?,
                material_file(
                    "node_client_certificate",
                    &paths.node_trust.client_certificate_file,
                    &trust.node.client_certificate,
                    &self.root,
                )?,
                material_file(
                    "node_client_private_key",
                    &paths.node_trust.client_private_key_file,
                    &trust.node.client_private_key,
                    &self.root,
                )?,
                material_file(
                    "gateway_authority_private_key",
                    &paths.gateway_trust.authority_private_key_file,
                    &trust.gateway.authority_private_key,
                    &self.root,
                )?,
                material_file(
                    "gateway_authority_certificate",
                    &paths.gateway_trust.authority_certificate_file,
                    &trust.gateway.authority_certificate,
                    &self.root,
                )?,
                material_file(
                    "gateway_server_certificate",
                    &paths.gateway_trust.server_certificate_file,
                    &trust.gateway.server_certificate,
                    &self.root,
                )?,
                material_file(
                    "gateway_server_private_key",
                    &paths.gateway_trust.server_private_key_file,
                    &trust.gateway.server_private_key,
                    &self.root,
                )?,
                material_file(
                    "gateway_relay_client_certificate",
                    &paths.gateway_trust.relay_client_certificate_file,
                    &trust.gateway.client_certificate,
                    &self.root,
                )?,
                material_file(
                    "gateway_relay_client_private_key",
                    &paths.gateway_trust.relay_client_private_key_file,
                    &trust.gateway.client_private_key,
                    &self.root,
                )?,
            ];
            if let (Some(paths), Some(trust), Some(allowlist)) = (
                paths.watchdog_trust.as_ref(),
                trust.watchdog.as_ref(),
                materials.watchdog_allowlist.as_ref(),
            ) {
                files.extend([
                    material_file(
                        "watchdog_authority_private_key",
                        &paths.authority_private_key_file,
                        &trust.authority_private_key,
                        &self.root,
                    )?,
                    material_file(
                        "watchdog_authority_certificate",
                        &paths.authority_certificate_file,
                        &trust.authority_certificate,
                        &self.root,
                    )?,
                    material_file(
                        "watchdog_server_certificate",
                        &paths.server_certificate_file,
                        &trust.server_certificate,
                        &self.root,
                    )?,
                    material_file(
                        "watchdog_server_private_key",
                        &paths.server_private_key_file,
                        &trust.server_private_key,
                        &self.root,
                    )?,
                    material_file(
                        "watchdog_controller_certificate",
                        &paths.controller_certificate_file,
                        &trust.client_certificate,
                        &self.root,
                    )?,
                    material_file(
                        "watchdog_controller_private_key",
                        &paths.controller_private_key_file,
                        &trust.client_private_key,
                        &self.root,
                    )?,
                    material_file(
                        "watchdog_controller_allowlist",
                        &paths.controller_allowlist_file,
                        allowlist,
                        &self.root,
                    )?,
                ]);
            }
            if let Some(api_key) = api_key {
                files.insert(
                    1,
                    material_file("api_key", &paths.api_key_file, api_key, &self.root)?,
                );
            }
            for file in &mut files {
                let payload = material_payload(
                    file.role.as_str(),
                    pairing_secret,
                    api_key,
                    trust,
                    materials.watchdog_allowlist.as_deref(),
                )?;
                write_private_file_at(&staging, &file.role, payload, self.owner_user_id)?;
                self.observed(
                    CoreSetupMaterialPublication::StagedFile,
                    &mut publication_index,
                )?;
                let _ =
                    open_relative_parent(root, Path::new(&file.target), self.owner_user_id, true)?;
                file.created =
                    !target_matches(root, &file.target, &file.sha256, self.owner_user_id)?;
                if !file.created {
                    unlink_file_at(&staging, &file.role)?;
                }
            }
            sync_file(&staging)?;
            let manifest = MaterialManifest {
                schema: MaterialManifestSchema {
                    name: "li_core_setup_material_intent".to_string(),
                    version: 1,
                },
                state: "preparing".to_string(),
                receipt_identity: receipt.identity().as_str().to_string(),
                database_file: path_text(paths.database_file())?,
                pairing_setup_secret_file: path_text(paths.pairing_setup_secret_file())?,
                api_key_file: api_key
                    .map(|_| path_text(paths.api_key_file()))
                    .transpose()?,
                benchmark_signing: MaterialBenchmarkSigningManifest::from_material(
                    &materials.benchmark_signing,
                )?,
                pairing_trust: MaterialPairingTrustManifest::from_material(&materials.pairing)?,
                node_trust: MaterialNodeTrustManifest::from_material(&materials.node)?,
                gateway_trust: MaterialGatewayTrustManifest::from_material(&materials.gateway)?,
                watchdog_trust: materials
                    .watchdog
                    .as_ref()
                    .map(MaterialWatchdogTrustManifest::from_material)
                    .transpose()?,
                material_identity: material_identity.as_str().to_string(),
                staging_directory: staging_name,
                files,
            };
            write_manifest(root, &manifest_name, &manifest, self.owner_user_id)?;
            self.observed(
                CoreSetupMaterialPublication::PreparingIntent,
                &mut publication_index,
            )?;
            let mut manifest = manifest;
            reconcile_manifest(
                root,
                &mut manifest,
                self.owner_user_id,
                self,
                &mut publication_index,
            )?;
            manifest.state = "complete".to_string();
            write_manifest(root, &manifest_name, &manifest, self.owner_user_id)?;
            self.observed(
                CoreSetupMaterialPublication::CompleteIntent,
                &mut publication_index,
            )?;
            material_from_manifest(&manifest)
        })
    }

    // Removes only receipt-created exact-hash files in reverse order and preserves prior files.
    fn rollback(&self, receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError> {
        self.with_lock(|root| {
            let manifest_name = Self::manifest_name(receipt);
            let Some(manifest) =
                read_manifest(root, &manifest_name, self.owner_user_id, &self.root)?
            else {
                return Ok(());
            };
            require_manifest_receipt(&manifest, receipt)?;
            for file in manifest.files.iter().rev().filter(|file| file.created) {
                remove_exact_target(root, &file.target, &file.sha256, self.owner_user_id)?;
            }
            remove_receipt_staging(root, &manifest.staging_directory, self.owner_user_id)?;
            unlink_file_at(root, &manifest_name)?;
            sync_file(root)
        })
    }
}

// Stores one strict secret-free material intent.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialManifest {
    schema: MaterialManifestSchema,
    state: String,
    receipt_identity: String,
    database_file: String,
    pairing_setup_secret_file: String,
    api_key_file: Option<String>,
    benchmark_signing: MaterialBenchmarkSigningManifest,
    pairing_trust: MaterialPairingTrustManifest,
    node_trust: MaterialNodeTrustManifest,
    gateway_trust: MaterialGatewayTrustManifest,
    watchdog_trust: Option<MaterialWatchdogTrustManifest>,
    material_identity: String,
    staging_directory: String,
    files: Vec<MaterialFileManifest>,
}

// Stores dedicated benchmark-signing references and the verified DER public identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialBenchmarkSigningManifest {
    private_key_file: String,
    public_key_file: String,
    public_key_sha256: String,
}

impl MaterialBenchmarkSigningManifest {
    // Converts one secret-free signer projection into durable path and identity fields.
    fn from_material(
        material: &CoreSetupBenchmarkSigningMaterial,
    ) -> Result<Self, CoreSetupProviderError> {
        Ok(Self {
            private_key_file: path_text(material.private_key_file())?,
            public_key_file: path_text(material.public_key_file())?,
            public_key_sha256: material.public_key_sha256().as_str().to_string(),
        })
    }
}

// Stores the nested material-intent schema identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialManifestSchema {
    name: String,
    version: u32,
}

// Stores exact trust references and public identities without private bytes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialPairingTrustManifest {
    site_private_key_file: String,
    site_public_key_file: String,
    site_ca_certificate_file: String,
    local_control_certificate_file: String,
    public_key_sha256: String,
    certificate_sha256: String,
}

impl MaterialPairingTrustManifest {
    // Converts one secret-free trust projection into durable path and identity fields.
    fn from_material(
        material: &CoreSetupPairingTrustMaterial,
    ) -> Result<Self, CoreSetupProviderError> {
        Ok(Self {
            site_private_key_file: path_text(material.site_private_key_file())?,
            site_public_key_file: path_text(material.site_public_key_file())?,
            site_ca_certificate_file: path_text(material.site_ca_certificate_file())?,
            local_control_certificate_file: path_text(material.local_control_certificate_file())?,
            public_key_sha256: material.public_key_sha256().as_str().to_string(),
            certificate_sha256: material.certificate_sha256().as_str().to_string(),
        })
    }
}

// Stores the complete secret-free Node remote trust closure.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialNodeTrustManifest {
    authority_private_key_file: String,
    authority_certificate_file: String,
    server_certificate_file: String,
    server_private_key_file: String,
    client_certificate_file: String,
    client_private_key_file: String,
    server_certificate_sha256: String,
    client_certificate_sha256: String,
}

impl MaterialNodeTrustManifest {
    // Converts one Node trust projection into durable secret-free path and identity fields.
    fn from_material(
        material: &CoreSetupNodeTrustMaterial,
    ) -> Result<Self, CoreSetupProviderError> {
        Ok(Self {
            authority_private_key_file: path_text(material.authority_private_key_file())?,
            authority_certificate_file: path_text(material.authority_certificate_file())?,
            server_certificate_file: path_text(material.server_certificate_file())?,
            server_private_key_file: path_text(material.server_private_key_file())?,
            client_certificate_file: path_text(material.client_certificate_file())?,
            client_private_key_file: path_text(material.client_private_key_file())?,
            server_certificate_sha256: material.server_certificate_sha256().as_str().to_string(),
            client_certificate_sha256: material.client_certificate_sha256().as_str().to_string(),
        })
    }
}

// Stores the complete secret-free Gateway private-relay trust closure.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialGatewayTrustManifest {
    authority_private_key_file: String,
    authority_certificate_file: String,
    server_certificate_file: String,
    server_private_key_file: String,
    relay_client_certificate_file: String,
    relay_client_private_key_file: String,
    server_certificate_sha256: String,
    relay_client_certificate_sha256: String,
}

impl MaterialGatewayTrustManifest {
    // Converts one Gateway trust projection into durable secret-free path and identity fields.
    fn from_material(
        material: &CoreSetupGatewayTrustMaterial,
    ) -> Result<Self, CoreSetupProviderError> {
        Ok(Self {
            authority_private_key_file: path_text(material.authority_private_key_file())?,
            authority_certificate_file: path_text(material.authority_certificate_file())?,
            server_certificate_file: path_text(material.server_certificate_file())?,
            server_private_key_file: path_text(material.server_private_key_file())?,
            relay_client_certificate_file: path_text(material.relay_client_certificate_file())?,
            relay_client_private_key_file: path_text(material.relay_client_private_key_file())?,
            server_certificate_sha256: material.server_certificate_sha256().as_str().to_string(),
            relay_client_certificate_sha256: material
                .relay_client_certificate_sha256()
                .as_str()
                .to_string(),
        })
    }
}

// Stores the Linux-only secret-free Watchdog listener, controller, and allowlist closure.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialWatchdogTrustManifest {
    authority_private_key_file: String,
    authority_certificate_file: String,
    server_certificate_file: String,
    server_private_key_file: String,
    controller_certificate_file: String,
    controller_private_key_file: String,
    controller_allowlist_file: String,
    server_certificate_sha256: String,
    controller_certificate_sha256: String,
}

impl MaterialWatchdogTrustManifest {
    // Converts one Watchdog trust projection into durable secret-free path and identity fields.
    fn from_material(
        material: &CoreSetupWatchdogTrustMaterial,
    ) -> Result<Self, CoreSetupProviderError> {
        Ok(Self {
            authority_private_key_file: path_text(material.authority_private_key_file())?,
            authority_certificate_file: path_text(material.authority_certificate_file())?,
            server_certificate_file: path_text(material.server_certificate_file())?,
            server_private_key_file: path_text(material.server_private_key_file())?,
            controller_certificate_file: path_text(material.controller_certificate_file())?,
            controller_private_key_file: path_text(material.controller_private_key_file())?,
            controller_allowlist_file: path_text(material.controller_allowlist_file())?,
            server_certificate_sha256: material.server_certificate_sha256().as_str().to_string(),
            controller_certificate_sha256: material
                .controller_certificate_sha256()
                .as_str()
                .to_string(),
        })
    }
}

// Stores one exact staged-to-final file transition and rollback ownership bit.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialFileManifest {
    role: String,
    target: String,
    sha256: String,
    created: bool,
}

// Implements role policy and exact replay over injected secure material capabilities.
pub struct ApplicationCoreSetupMaterialProvider {
    paths: CoreSetupMaterialPaths,
    entropy: Arc<dyn CoreSetupMaterialEntropy>,
    issuer: Arc<dyn CoreSetupResidentTrustIssuer>,
    io: Arc<dyn CoreSetupMaterialIo>,
}

impl ApplicationCoreSetupMaterialProvider {
    // Creates one provider without opening files, invoking native trust, or generating entropy.
    pub const fn new(
        paths: CoreSetupMaterialPaths,
        entropy: Arc<dyn CoreSetupMaterialEntropy>,
        issuer: Arc<dyn CoreSetupResidentTrustIssuer>,
        io: Arc<dyn CoreSetupMaterialIo>,
    ) -> Self {
        Self {
            paths,
            entropy,
            issuer,
            io,
        }
    }
}

impl CoreSetupMaterialProvider for ApplicationCoreSetupMaterialProvider {
    // Replays or atomically provisions the exact role-bound private material closure.
    fn prepare(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
    ) -> Result<CoreSetupPreparedMaterial, CoreSetupProviderError> {
        require_request_identity(request, identity)?;
        require_platform_paths(request, &self.paths)?;
        let receipt = material_receipt(request, identity)?;
        if let Some(material) = self.io.read(&receipt)? {
            require_material(request, &self.paths, &receipt, &material)?;
            return Ok(material);
        }
        let mut secrets =
            SetupSecretMaterial::new(request.context().role() == CoreUpdateNodeRole::Main);
        self.entropy.fill(&mut secrets.pairing_secret)?;
        if let Some(api_key) = secrets.api_key.as_mut() {
            self.entropy.fill(api_key)?;
        }
        let trust = self.issuer.issue(request, identity)?;
        let material_identity = material_identity(
            &receipt,
            &self.paths,
            identity,
            &secrets.pairing_secret,
            secrets.api_key.as_ref(),
            &trust,
        )?;
        let material = self.io.create(
            &receipt,
            &self.paths,
            identity,
            &secrets.pairing_secret,
            secrets.api_key.as_ref(),
            &trust,
            &material_identity,
        )?;
        require_material(request, &self.paths, &receipt, &material)?;
        Ok(material)
    }

    // Delegates exact reverse rollback to the atomic material owner.
    fn rollback(&self, receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError> {
        self.io.rollback(receipt)
    }
}

// Owns generated setup secrets and clears them on every success or error return path.
struct SetupSecretMaterial {
    pairing_secret: [u8; SECRET_BYTES],
    api_key: Option<[u8; SECRET_BYTES]>,
}

impl SetupSecretMaterial {
    // Creates the exact role-bound secret set before entropy fills it.
    fn new(include_api_key: bool) -> Self {
        Self {
            pairing_secret: [0_u8; SECRET_BYTES],
            api_key: include_api_key.then_some([0_u8; SECRET_BYTES]),
        }
    }
}

impl Drop for SetupSecretMaterial {
    // Clears every generated secret regardless of the operation exit path.
    fn drop(&mut self) {
        self.pairing_secret.fill(0);
        if let Some(api_key) = self.api_key.as_mut() {
            api_key.fill(0);
        }
    }
}

// Requires the prepared identity to preserve every request-owned public identity field.
fn require_request_identity(
    request: &CoreSetupRequest,
    identity: &CoreSetupPreparedIdentity,
) -> Result<(), CoreSetupProviderError> {
    if request.context().role() != CoreUpdateNodeRole::Main {
        return Err(material_error(
            "initial setup must provision a standalone main node",
        ));
    }
    let role = match request.context().role() {
        CoreUpdateNodeRole::Main => li_core_interface::NodeRole::Main,
        CoreUpdateNodeRole::Child => li_core_interface::NodeRole::Child,
    };
    if identity.role() != role
        || identity.display_name() != request.display_name()
        || identity.control_address() != request.control_address()
    {
        return Err(material_error(
            "prepared identity does not match the material request",
        ));
    }
    Ok(())
}

// Derives one stable receipt from the request and prepared identity without private bytes.
fn material_receipt(
    request: &CoreSetupRequest,
    identity: &CoreSetupPreparedIdentity,
) -> Result<CoreSetupReceipt, CoreSetupProviderError> {
    digest_fields(&[
        b"letsinfer-core-setup-material-receipt-v1\0",
        request.request_id().as_str().as_bytes(),
        identity.node_id().as_str().as_bytes(),
        identity.installation_id().as_str().as_bytes(),
    ])
    .map(CoreSetupReceipt::new)
}

// Binds one closure identity to every secret and issued trust byte without persisting them.
fn material_identity(
    receipt: &CoreSetupReceipt,
    paths: &CoreSetupMaterialPaths,
    identity: &CoreSetupPreparedIdentity,
    pairing_secret: &[u8; SECRET_BYTES],
    api_key: Option<&[u8; SECRET_BYTES]>,
    trust: &CoreSetupIssuedResidentTrust,
) -> Result<Sha256Digest, CoreSetupProviderError> {
    let materials = trust.materials(paths, identity)?;
    let mut digest = Sha256::new();
    digest_field(&mut digest, b"letsinfer-core-setup-material-closure-v1\0")?;
    digest_field(&mut digest, receipt.identity().as_str().as_bytes())?;
    digest_field(&mut digest, identity.node_id().as_str().as_bytes())?;
    digest_field(&mut digest, identity.installation_id().as_str().as_bytes())?;
    material_identity_entry(&mut digest, "database", paths.database_file(), &[])?;
    material_identity_entry(
        &mut digest,
        "pairing_setup_secret",
        paths.pairing_setup_secret_file(),
        pairing_secret,
    )?;
    if let Some(api_key) = api_key {
        material_identity_entry(&mut digest, "api_key", paths.api_key_file(), api_key)?;
    }
    let benchmark_signing_paths = paths
        .benchmark_signing
        .as_ref()
        .ok_or_else(|| material_error("benchmark signing material closure is incomplete"))?;
    material_identity_entry(
        &mut digest,
        "benchmark_signing_private_key",
        &benchmark_signing_paths.private_key_file,
        &trust.benchmark_signing.private_key,
    )?;
    material_identity_entry(
        &mut digest,
        "benchmark_signing_public_key",
        &benchmark_signing_paths.public_key_file,
        &trust.benchmark_signing.public_key,
    )?;
    material_identity_value(
        &mut digest,
        "benchmark_signing_public_key_sha256",
        trust
            .benchmark_signing
            .public_key_sha256
            .as_str()
            .as_bytes(),
    )?;
    material_identity_entry(
        &mut digest,
        "site_private_key",
        &paths.pairing_trust.site_private_key_file,
        &trust.pairing.site_private_key,
    )?;
    material_identity_entry(
        &mut digest,
        "site_public_key",
        &paths.pairing_trust.site_public_key_file,
        &trust.pairing.site_public_key,
    )?;
    material_identity_entry(
        &mut digest,
        "site_ca_certificate",
        &paths.pairing_trust.site_ca_certificate_file,
        &trust.pairing.site_ca_certificate,
    )?;
    material_identity_entry(
        &mut digest,
        "local_control_certificate",
        &paths.pairing_trust.local_control_certificate_file,
        &trust.pairing.local_control_certificate,
    )?;
    material_identity_value(
        &mut digest,
        "site_public_key_sha256",
        trust.pairing.public_key_sha256.as_str().as_bytes(),
    )?;
    material_identity_value(
        &mut digest,
        "local_control_certificate_sha256",
        trust.pairing.certificate_sha256.as_str().as_bytes(),
    )?;
    material_identity_mutual_tls(
        &mut digest,
        "node",
        &paths.node_trust.authority_private_key_file,
        &paths.node_trust.authority_certificate_file,
        &paths.node_trust.server_certificate_file,
        &paths.node_trust.server_private_key_file,
        &paths.node_trust.client_certificate_file,
        &paths.node_trust.client_private_key_file,
        "client",
        &trust.node,
    )?;
    material_identity_mutual_tls(
        &mut digest,
        "gateway",
        &paths.gateway_trust.authority_private_key_file,
        &paths.gateway_trust.authority_certificate_file,
        &paths.gateway_trust.server_certificate_file,
        &paths.gateway_trust.server_private_key_file,
        &paths.gateway_trust.relay_client_certificate_file,
        &paths.gateway_trust.relay_client_private_key_file,
        "relay_client",
        &trust.gateway,
    )?;
    match (&paths.watchdog_trust, &trust.watchdog) {
        (Some(paths), Some(trust)) => {
            material_identity_mutual_tls(
                &mut digest,
                "watchdog",
                &paths.authority_private_key_file,
                &paths.authority_certificate_file,
                &paths.server_certificate_file,
                &paths.server_private_key_file,
                &paths.controller_certificate_file,
                &paths.controller_private_key_file,
                "controller",
                trust,
            )?;
            material_identity_entry(
                &mut digest,
                "watchdog_controller_allowlist",
                &paths.controller_allowlist_file,
                materials.watchdog_allowlist.as_deref().ok_or_else(|| {
                    material_error("resident trust platform closure is incomplete")
                })?,
            )?;
        }
        (None, None) => material_identity_value(&mut digest, "watchdog", b"absent")?,
        _ => {
            return Err(material_error(
                "resident trust platform closure is incomplete",
            ))
        }
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| material_error("private material identity is invalid"))
}

// Adds one exact role, path, and payload triple to the material closure identity.
fn material_identity_entry(
    digest: &mut Sha256,
    role: &str,
    path: &Path,
    payload: &[u8],
) -> Result<(), CoreSetupProviderError> {
    digest_field(digest, role.as_bytes())?;
    digest_field(digest, path.as_os_str().as_bytes())?;
    digest_field(digest, payload)
}

// Adds one exact labeled public identity field to the material closure identity.
fn material_identity_value(
    digest: &mut Sha256,
    role: &str,
    value: &[u8],
) -> Result<(), CoreSetupProviderError> {
    digest_field(digest, role.as_bytes())?;
    digest_field(digest, value)
}

// Adds one complete role-specific mutual-TLS path, byte, and digest closure.
#[allow(clippy::too_many_arguments)]
fn material_identity_mutual_tls(
    digest: &mut Sha256,
    role: &str,
    authority_private_key_file: &Path,
    authority_certificate_file: &Path,
    server_certificate_file: &Path,
    server_private_key_file: &Path,
    client_certificate_file: &Path,
    client_private_key_file: &Path,
    client_role: &str,
    trust: &CoreSetupIssuedMutualTlsTrust,
) -> Result<(), CoreSetupProviderError> {
    let field = |suffix: &str| format!("{role}_{suffix}");
    material_identity_entry(
        digest,
        &field("authority_private_key"),
        authority_private_key_file,
        &trust.authority_private_key,
    )?;
    material_identity_entry(
        digest,
        &field("authority_certificate"),
        authority_certificate_file,
        &trust.authority_certificate,
    )?;
    material_identity_entry(
        digest,
        &field("server_certificate"),
        server_certificate_file,
        &trust.server_certificate,
    )?;
    material_identity_entry(
        digest,
        &field("server_private_key"),
        server_private_key_file,
        &trust.server_private_key,
    )?;
    material_identity_entry(
        digest,
        &field(&format!("{client_role}_certificate")),
        client_certificate_file,
        &trust.client_certificate,
    )?;
    material_identity_entry(
        digest,
        &field(&format!("{client_role}_private_key")),
        client_private_key_file,
        &trust.client_private_key,
    )?;
    material_identity_value(
        digest,
        &field("server_certificate_sha256"),
        trust.server_certificate_sha256.as_str().as_bytes(),
    )?;
    material_identity_value(
        digest,
        &field(&format!("{client_role}_certificate_sha256")),
        trust.client_certificate_sha256.as_str().as_bytes(),
    )
}

// Requires Linux Watchdog trust and forbids it on macOS before entropy or native issuance.
fn require_platform_paths(
    request: &CoreSetupRequest,
    paths: &CoreSetupMaterialPaths,
) -> Result<(), CoreSetupProviderError> {
    let expected_watchdog = match request.context().platform() {
        li_core_update_manager::CoreUpdateServicePlatform::Linux => true,
        li_core_update_manager::CoreUpdateServicePlatform::Macos => false,
    };
    if paths.benchmark_signing.is_none() || paths.watchdog_trust.is_some() != expected_watchdog {
        return Err(material_error(
            "private material platform closure is incomplete",
        ));
    }
    Ok(())
}

// Requires an authoritative I/O result to match every configured role-bound reference.
fn require_material(
    request: &CoreSetupRequest,
    paths: &CoreSetupMaterialPaths,
    receipt: &CoreSetupReceipt,
    material: &CoreSetupPreparedMaterial,
) -> Result<(), CoreSetupProviderError> {
    let expected_api = Some(paths.api_key_file.as_path());
    let benchmark_signing = material.benchmark_signing();
    let node = material.node_trust();
    let gateway = material.gateway_trust();
    if request.context().role() != CoreUpdateNodeRole::Main
        || material.receipt() != receipt
        || material.database_file() != paths.database_file
        || material.pairing_setup_secret_file() != paths.pairing_setup_secret_file
        || material.api_key_file() != expected_api
        || !benchmark_signing_material_matches(benchmark_signing, paths.benchmark_signing.as_ref())
        || material.pairing_trust().site_private_key_file()
            != paths.pairing_trust.site_private_key_file
        || material.pairing_trust().site_public_key_file()
            != paths.pairing_trust.site_public_key_file
        || material.pairing_trust().site_ca_certificate_file()
            != paths.pairing_trust.site_ca_certificate_file
        || material.pairing_trust().local_control_certificate_file()
            != paths.pairing_trust.local_control_certificate_file
        || node.authority_private_key_file() != paths.node_trust.authority_private_key_file
        || node.authority_certificate_file() != paths.node_trust.authority_certificate_file
        || node.server_certificate_file() != paths.node_trust.server_certificate_file
        || node.server_private_key_file() != paths.node_trust.server_private_key_file
        || node.client_certificate_file() != paths.node_trust.client_certificate_file
        || node.client_private_key_file() != paths.node_trust.client_private_key_file
        || gateway.authority_private_key_file() != paths.gateway_trust.authority_private_key_file
        || gateway.authority_certificate_file() != paths.gateway_trust.authority_certificate_file
        || gateway.server_certificate_file() != paths.gateway_trust.server_certificate_file
        || gateway.server_private_key_file() != paths.gateway_trust.server_private_key_file
        || gateway.relay_client_certificate_file()
            != paths.gateway_trust.relay_client_certificate_file
        || gateway.relay_client_private_key_file()
            != paths.gateway_trust.relay_client_private_key_file
        || !watchdog_material_matches(material.watchdog_trust(), paths.watchdog_trust.as_ref())
    {
        return Err(CoreSetupProviderError::recovery_required(
            "private material",
            "material persistence result does not match its requested closure",
        ));
    }
    Ok(())
}

// Requires the prepared benchmark signer to retain both configured key destinations.
fn benchmark_signing_material_matches(
    material: Option<&CoreSetupBenchmarkSigningMaterial>,
    paths: Option<&CoreSetupBenchmarkSigningPaths>,
) -> bool {
    match (material, paths) {
        (Some(material), Some(paths)) => {
            material.private_key_file() == paths.private_key_file
                && material.public_key_file() == paths.public_key_file
        }
        _ => false,
    }
}

// Requires the optional Watchdog projection to match every Linux-only configured role.
fn watchdog_material_matches(
    material: Option<&CoreSetupWatchdogTrustMaterial>,
    paths: Option<&CoreSetupWatchdogTrustPaths>,
) -> bool {
    match (material, paths) {
        (Some(material), Some(paths)) => {
            material.authority_private_key_file() == paths.authority_private_key_file
                && material.authority_certificate_file() == paths.authority_certificate_file
                && material.server_certificate_file() == paths.server_certificate_file
                && material.server_private_key_file() == paths.server_private_key_file
                && material.controller_certificate_file() == paths.controller_certificate_file
                && material.controller_private_key_file() == paths.controller_private_key_file
                && material.controller_allowlist_file() == paths.controller_allowlist_file
        }
        (None, None) => true,
        _ => false,
    }
}

// Computes one unambiguous length-delimited SHA-256 identity.
fn digest_fields(fields: &[&[u8]]) -> Result<Sha256Digest, CoreSetupProviderError> {
    let mut digest = Sha256::new();
    for field in fields {
        digest_field(&mut digest, field)?;
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| material_error("private material identity is invalid"))
}

// Adds one length-delimited field to an in-progress private material identity.
fn digest_field(digest: &mut Sha256, field: &[u8]) -> Result<(), CoreSetupProviderError> {
    digest.update(
        u64::try_from(field.len())
            .map_err(|_| material_error("private material identity is oversized"))?
            .to_be_bytes(),
    );
    digest.update(field);
    Ok(())
}

// Creates one stable redacted material failure.
fn material_error(reason: &'static str) -> CoreSetupProviderError {
    CoreSetupProviderError::rolled_back("private material", reason)
}

// Creates one stable ambiguous native-material failure.
fn material_recovery_error(reason: &'static str) -> CoreSetupProviderError {
    CoreSetupProviderError::recovery_required("private material", reason)
}

// Converts one normal absolute path without exposing it in diagnostics.
fn path_text(path: &Path) -> Result<String, CoreSetupProviderError> {
    path.to_str()
        .filter(|value| !value.chars().any(char::is_control))
        .map(str::to_string)
        .ok_or_else(|| material_error("private material path is invalid"))
}

// Returns whether a path is absolute, normalized, and free of control bytes.
fn is_normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().as_bytes().len() <= 4096
        && path.components().all(|component| {
            matches!(component, Component::RootDir | Component::Normal(_))
                && !component
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .any(u8::is_ascii_control)
        })
}

// Opens and validates the configured owner-private material root without following its leaf.
fn open_private_directory(path: &Path, owner_user_id: u32) -> Result<File, CoreSetupProviderError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| material_error("private material root is unavailable"))?;
    validate_private_directory(&file, owner_user_id)?;
    Ok(file)
}

// Validates one open directory descriptor against the owner-only material boundary.
fn validate_private_directory(
    file: &File,
    owner_user_id: u32,
) -> Result<(), CoreSetupProviderError> {
    let metadata = file
        .metadata()
        .map_err(|_| material_error("private material metadata is unavailable"))?;
    if !metadata.is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != MATERIAL_DIRECTORY_MODE
    {
        return Err(material_error(
            "private material directory metadata is unsafe",
        ));
    }
    Ok(())
}

// Opens or creates the fixed private lock file relative to the validated root descriptor.
fn open_private_lock(root: &File, owner_user_id: u32) -> Result<File, CoreSetupProviderError> {
    let name = CString::new(MATERIAL_LOCK_FILENAME).expect("fixed lock name");
    for _ in 0..4 {
        let descriptor = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor >= 0 {
            let file = unsafe { File::from_raw_fd(descriptor) };
            validate_private_file(&file, owner_user_id, false)?;
            return Ok(file);
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
            return Err(material_recovery_error(
                "private material lock is unavailable",
            ));
        }
        let descriptor = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                MATERIAL_FILE_MODE,
            )
        };
        if descriptor >= 0 {
            let file = unsafe { File::from_raw_fd(descriptor) };
            validate_private_file(&file, owner_user_id, false)?;
            sync_file(root)?;
            return Ok(file);
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
            return Err(material_recovery_error(
                "private material lock is unavailable",
            ));
        }
    }
    Err(material_recovery_error(
        "private material lock is unavailable",
    ))
}

// Validates one open owner-only regular file descriptor.
fn validate_private_file(
    file: &File,
    owner_user_id: u32,
    nonempty: bool,
) -> Result<(), CoreSetupProviderError> {
    let metadata = file
        .metadata()
        .map_err(|_| material_error("private material metadata is unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != MATERIAL_FILE_MODE
        || metadata.nlink() != 1
        || (nonempty && metadata.len() == 0)
    {
        return Err(material_error("private material file metadata is unsafe"));
    }
    Ok(())
}

// Creates one owner-only child directory relative to the trusted root descriptor.
fn create_private_directory_at(
    root: &File,
    name: &str,
    owner_user_id: u32,
) -> Result<(), CoreSetupProviderError> {
    let name = native_name(name)?;
    if unsafe {
        libc::mkdirat(
            root.as_raw_fd(),
            name.as_ptr(),
            MATERIAL_DIRECTORY_MODE as libc::mode_t,
        )
    } != 0
    {
        return Err(material_recovery_error(
            "private material staging could not be created",
        ));
    }
    let directory = open_private_directory_at(
        root,
        name.to_str()
            .map_err(|_| material_error("private material native name is invalid"))?,
        owner_user_id,
    )?;
    sync_file(&directory)
}

// Opens one owner-private direct child directory without following it.
fn open_private_directory_at(
    root: &File,
    name: &str,
    owner_user_id: u32,
) -> Result<File, CoreSetupProviderError> {
    let name = native_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(material_recovery_error(
            "private material staging is unavailable",
        ));
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_private_directory(&file, owner_user_id)?;
    Ok(file)
}

// Opens one optional private child directory while preserving unsafe native failures.
fn open_optional_private_directory_at(
    root: &File,
    name: &str,
    owner_user_id: u32,
) -> Result<Option<File>, CoreSetupProviderError> {
    let name = native_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(material_recovery_error(
                "private material staging is unavailable",
            ))
        };
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_private_directory(&file, owner_user_id)?;
    Ok(Some(file))
}

// Writes one new bounded owner-only file and synchronizes its descriptor.
fn write_private_file_at(
    root: &File,
    name: &str,
    payload: &[u8],
    owner_user_id: u32,
) -> Result<(), CoreSetupProviderError> {
    if payload.is_empty() || payload.len() > 64 * 1024 {
        return Err(material_error("private material payload is invalid"));
    }
    let name = native_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            MATERIAL_FILE_MODE,
        )
    };
    if descriptor < 0 {
        return Err(material_recovery_error(
            "private material staging write is ambiguous",
        ));
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    validate_private_file(&file, owner_user_id, false)?;
    file.write_all(payload)
        .and_then(|_| file.sync_all())
        .map_err(|_| material_recovery_error("private material staging write is ambiguous"))
}

// Synchronizes one file or directory descriptor.
fn sync_file(file: &File) -> Result<(), CoreSetupProviderError> {
    file.sync_all()
        .map_err(|_| material_recovery_error("private material persistence is ambiguous"))
}

// Converts one direct native child name without separators or control bytes.
fn native_name(name: &str) -> Result<CString, CoreSetupProviderError> {
    if name.is_empty()
        || name.len() > 255
        || name.contains('/')
        || name.bytes().any(|value| value.is_ascii_control())
    {
        return Err(material_error("private material native name is invalid"));
    }
    CString::new(name).map_err(|_| material_error("private material native name is invalid"))
}

// Opens an existing private file relative to one trusted descriptor.
fn open_existing_file_at(
    root: &File,
    name: &str,
    owner_user_id: u32,
) -> Result<Option<File>, CoreSetupProviderError> {
    let name = native_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(material_error("private material file is unavailable"))
        };
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_private_file(&file, owner_user_id, true)?;
    Ok(Some(file))
}

// Reads one bounded strict manifest relative to the material root.
fn read_manifest(
    root: &File,
    name: &str,
    owner_user_id: u32,
    material_root: &Path,
) -> Result<Option<MaterialManifest>, CoreSetupProviderError> {
    let Some(mut file) = open_existing_file_at(root, name, owner_user_id)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAXIMUM_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| material_error("private material intent is unavailable"))?;
    if bytes.len() > MAXIMUM_MANIFEST_BYTES {
        return Err(material_error("private material intent is oversized"));
    }
    let manifest: MaterialManifest = serde_json::from_slice(&bytes)
        .map_err(|_| material_error("private material intent is corrupt"))?;
    if manifest.schema.name != "li_core_setup_material_intent"
        || manifest.schema.version != 1
        || !matches!(manifest.state.as_str(), "preparing" | "complete")
    {
        return Err(material_error("private material intent is corrupt"));
    }
    validate_material_manifest(&manifest, material_root)?;
    Ok(Some(manifest))
}

// Requires one durable material intent to contain the exact closed role and path shape.
fn validate_material_manifest(
    manifest: &MaterialManifest,
    material_root: &Path,
) -> Result<(), CoreSetupProviderError> {
    let role_paths = material_manifest_role_paths(manifest);
    let roles = manifest
        .files
        .iter()
        .map(|file| file.role.as_str())
        .collect::<BTreeSet<_>>();
    let expected = role_paths
        .iter()
        .map(|(role, _)| *role)
        .collect::<BTreeSet<_>>();
    let targets = manifest
        .files
        .iter()
        .map(|file| file.target.as_str())
        .collect::<BTreeSet<_>>();
    let paths = material_manifest_paths(manifest);
    let unique_paths = paths.iter().copied().collect::<BTreeSet<_>>();
    if roles != expected
        || roles.len() != manifest.files.len()
        || targets.len() != manifest.files.len()
        || paths.len() != unique_paths.len()
        || paths.iter().any(|path| {
            !is_normal_absolute_path(Path::new(path)) || *path == "/" || path.len() > 4096
        })
        || manifest.files.iter().any(|file| {
            !is_normal_relative_path(Path::new(&file.target)) || !is_lower_sha256(&file.sha256)
        })
        || manifest.files.iter().any(|file| {
            role_paths
                .iter()
                .find(|(role, _)| *role == file.role)
                .is_none_or(|(_, path)| {
                    !target_matches_absolute_path(&file.target, path, material_root)
                })
        })
        || !is_lower_sha256(&manifest.receipt_identity)
        || !is_lower_sha256(&manifest.material_identity)
        || !is_lower_sha256(&manifest.benchmark_signing.public_key_sha256)
        || !is_lower_sha256(&manifest.pairing_trust.public_key_sha256)
        || !is_lower_sha256(&manifest.pairing_trust.certificate_sha256)
        || !is_lower_sha256(&manifest.node_trust.server_certificate_sha256)
        || !is_lower_sha256(&manifest.node_trust.client_certificate_sha256)
        || !is_lower_sha256(&manifest.gateway_trust.server_certificate_sha256)
        || !is_lower_sha256(&manifest.gateway_trust.relay_client_certificate_sha256)
        || manifest.watchdog_trust.as_ref().is_some_and(|trust| {
            !is_lower_sha256(&trust.server_certificate_sha256)
                || !is_lower_sha256(&trust.controller_certificate_sha256)
        })
    {
        return Err(material_error("private material intent is corrupt"));
    }
    Ok(())
}

// Returns every exact persisted role-to-absolute-path binding from one strict intent.
fn material_manifest_role_paths(manifest: &MaterialManifest) -> Vec<(&'static str, &str)> {
    let mut paths = vec![
        (
            "pairing_setup_secret",
            manifest.pairing_setup_secret_file.as_str(),
        ),
        (
            "benchmark_signing_private_key",
            manifest.benchmark_signing.private_key_file.as_str(),
        ),
        (
            "benchmark_signing_public_key",
            manifest.benchmark_signing.public_key_file.as_str(),
        ),
        (
            "site_private_key",
            manifest.pairing_trust.site_private_key_file.as_str(),
        ),
        (
            "site_public_key",
            manifest.pairing_trust.site_public_key_file.as_str(),
        ),
        (
            "site_ca_certificate",
            manifest.pairing_trust.site_ca_certificate_file.as_str(),
        ),
        (
            "local_control_certificate",
            manifest
                .pairing_trust
                .local_control_certificate_file
                .as_str(),
        ),
        (
            "node_authority_private_key",
            manifest.node_trust.authority_private_key_file.as_str(),
        ),
        (
            "node_authority_certificate",
            manifest.node_trust.authority_certificate_file.as_str(),
        ),
        (
            "node_server_certificate",
            manifest.node_trust.server_certificate_file.as_str(),
        ),
        (
            "node_server_private_key",
            manifest.node_trust.server_private_key_file.as_str(),
        ),
        (
            "node_client_certificate",
            manifest.node_trust.client_certificate_file.as_str(),
        ),
        (
            "node_client_private_key",
            manifest.node_trust.client_private_key_file.as_str(),
        ),
        (
            "gateway_authority_private_key",
            manifest.gateway_trust.authority_private_key_file.as_str(),
        ),
        (
            "gateway_authority_certificate",
            manifest.gateway_trust.authority_certificate_file.as_str(),
        ),
        (
            "gateway_server_certificate",
            manifest.gateway_trust.server_certificate_file.as_str(),
        ),
        (
            "gateway_server_private_key",
            manifest.gateway_trust.server_private_key_file.as_str(),
        ),
        (
            "gateway_relay_client_certificate",
            manifest
                .gateway_trust
                .relay_client_certificate_file
                .as_str(),
        ),
        (
            "gateway_relay_client_private_key",
            manifest
                .gateway_trust
                .relay_client_private_key_file
                .as_str(),
        ),
    ];
    if let Some(api_key) = manifest.api_key_file.as_deref() {
        paths.push(("api_key", api_key));
    }
    if let Some(watchdog) = manifest.watchdog_trust.as_ref() {
        paths.extend([
            (
                "watchdog_authority_private_key",
                watchdog.authority_private_key_file.as_str(),
            ),
            (
                "watchdog_authority_certificate",
                watchdog.authority_certificate_file.as_str(),
            ),
            (
                "watchdog_server_certificate",
                watchdog.server_certificate_file.as_str(),
            ),
            (
                "watchdog_server_private_key",
                watchdog.server_private_key_file.as_str(),
            ),
            (
                "watchdog_controller_certificate",
                watchdog.controller_certificate_file.as_str(),
            ),
            (
                "watchdog_controller_private_key",
                watchdog.controller_private_key_file.as_str(),
            ),
            (
                "watchdog_controller_allowlist",
                watchdog.controller_allowlist_file.as_str(),
            ),
        ]);
    }
    paths
}

// Requires one relative target to be the exact projection of its absolute role path.
fn target_matches_absolute_path(target: &str, absolute: &str, material_root: &Path) -> bool {
    Path::new(absolute)
        .strip_prefix(material_root)
        .ok()
        .filter(|relative| is_normal_relative_path(relative))
        .and_then(Path::to_str)
        == Some(target)
}

// Returns every absolute material path persisted by one strict intent.
fn material_manifest_paths(manifest: &MaterialManifest) -> Vec<&str> {
    let mut paths = vec![manifest.database_file.as_str()];
    paths.extend(
        material_manifest_role_paths(manifest)
            .into_iter()
            .map(|(_, path)| path),
    );
    paths
}

// Returns whether one staged target is a normalized nonempty descendant path.
fn is_normal_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path.components().all(|component| {
            matches!(component, Component::Normal(_))
                && !component
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .any(u8::is_ascii_control)
        })
}

// Returns whether one text value is an exact lowercase SHA-256 identity.
fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Atomically publishes one strict manifest relative to the material root.
fn write_manifest(
    root: &File,
    name: &str,
    manifest: &MaterialManifest,
    owner_user_id: u32,
) -> Result<(), CoreSetupProviderError> {
    let bytes = serde_json::to_vec(manifest)
        .map_err(|_| material_error("private material intent is invalid"))?;
    if bytes.len() > MAXIMUM_MANIFEST_BYTES {
        return Err(material_error("private material intent is oversized"));
    }
    let temporary = format!(".{name}.pending");
    let _ = unlink_file_at(root, &temporary);
    write_private_file_at(root, &temporary, &bytes, owner_user_id)?;
    rename_child(root, &temporary, root, name)?;
    sync_file(root)
}

// Requires the durable intent to belong to the exact replay receipt.
fn require_manifest_receipt(
    manifest: &MaterialManifest,
    receipt: &CoreSetupReceipt,
) -> Result<(), CoreSetupProviderError> {
    if manifest.receipt_identity != receipt.identity().as_str()
        || manifest.staging_directory != SystemCoreSetupMaterialIo::staging_name(receipt)
    {
        return Err(material_error(
            "private material intent identity is corrupt",
        ));
    }
    Ok(())
}

// Returns one secret-free material closure from a validated manifest.
fn material_from_manifest(
    manifest: &MaterialManifest,
) -> Result<CoreSetupPreparedMaterial, CoreSetupProviderError> {
    Ok(CoreSetupPreparedMaterial::new_with_benchmark_signing(
        CoreSetupReceipt::new(
            Sha256Digest::parse(&manifest.receipt_identity)
                .map_err(|_| material_error("private material intent identity is corrupt"))?,
        ),
        PathBuf::from(&manifest.database_file),
        PathBuf::from(&manifest.pairing_setup_secret_file),
        manifest.api_key_file.as_ref().map(PathBuf::from),
        CoreSetupBenchmarkSigningMaterial::new(
            PathBuf::from(&manifest.benchmark_signing.private_key_file),
            PathBuf::from(&manifest.benchmark_signing.public_key_file),
            Sha256Digest::parse(&manifest.benchmark_signing.public_key_sha256)
                .map_err(|_| material_error("private material trust identity is corrupt"))?,
        ),
        CoreSetupPairingTrustMaterial::new(
            PathBuf::from(&manifest.pairing_trust.site_private_key_file),
            PathBuf::from(&manifest.pairing_trust.site_public_key_file),
            PathBuf::from(&manifest.pairing_trust.site_ca_certificate_file),
            PathBuf::from(&manifest.pairing_trust.local_control_certificate_file),
            Sha256Digest::parse(&manifest.pairing_trust.public_key_sha256)
                .map_err(|_| material_error("private material trust identity is corrupt"))?,
            Sha256Digest::parse(&manifest.pairing_trust.certificate_sha256)
                .map_err(|_| material_error("private material trust identity is corrupt"))?,
        ),
        CoreSetupNodeTrustMaterial::new(
            PathBuf::from(&manifest.node_trust.authority_private_key_file),
            PathBuf::from(&manifest.node_trust.authority_certificate_file),
            PathBuf::from(&manifest.node_trust.server_certificate_file),
            PathBuf::from(&manifest.node_trust.server_private_key_file),
            PathBuf::from(&manifest.node_trust.client_certificate_file),
            PathBuf::from(&manifest.node_trust.client_private_key_file),
            Sha256Digest::parse(&manifest.node_trust.server_certificate_sha256)
                .map_err(|_| material_error("private material trust identity is corrupt"))?,
            Sha256Digest::parse(&manifest.node_trust.client_certificate_sha256)
                .map_err(|_| material_error("private material trust identity is corrupt"))?,
        ),
        CoreSetupGatewayTrustMaterial::new(
            PathBuf::from(&manifest.gateway_trust.authority_private_key_file),
            PathBuf::from(&manifest.gateway_trust.authority_certificate_file),
            PathBuf::from(&manifest.gateway_trust.server_certificate_file),
            PathBuf::from(&manifest.gateway_trust.server_private_key_file),
            PathBuf::from(&manifest.gateway_trust.relay_client_certificate_file),
            PathBuf::from(&manifest.gateway_trust.relay_client_private_key_file),
            Sha256Digest::parse(&manifest.gateway_trust.server_certificate_sha256)
                .map_err(|_| material_error("private material trust identity is corrupt"))?,
            Sha256Digest::parse(&manifest.gateway_trust.relay_client_certificate_sha256)
                .map_err(|_| material_error("private material trust identity is corrupt"))?,
        ),
        manifest
            .watchdog_trust
            .as_ref()
            .map(|trust| {
                Ok(CoreSetupWatchdogTrustMaterial::new(
                    PathBuf::from(&trust.authority_private_key_file),
                    PathBuf::from(&trust.authority_certificate_file),
                    PathBuf::from(&trust.server_certificate_file),
                    PathBuf::from(&trust.server_private_key_file),
                    PathBuf::from(&trust.controller_certificate_file),
                    PathBuf::from(&trust.controller_private_key_file),
                    PathBuf::from(&trust.controller_allowlist_file),
                    Sha256Digest::parse(&trust.server_certificate_sha256).map_err(|_| {
                        material_error("private material trust identity is corrupt")
                    })?,
                    Sha256Digest::parse(&trust.controller_certificate_sha256).map_err(|_| {
                        material_error("private material trust identity is corrupt")
                    })?,
                ))
            })
            .transpose()?,
        Sha256Digest::parse(&manifest.material_identity)
            .map_err(|_| material_error("private material closure identity is corrupt"))?,
    ))
}

// Creates one file intent from an exact target and payload digest.
fn material_file(
    role: &str,
    target: &Path,
    payload: &[u8],
    root: &Path,
) -> Result<MaterialFileManifest, CoreSetupProviderError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| material_error("private material target escapes its root"))?;
    if relative.components().count() == 0
        || !relative
            .components()
            .all(|value| matches!(value, Component::Normal(_)))
    {
        return Err(material_error("private material target is invalid"));
    }
    Ok(MaterialFileManifest {
        role: role.to_string(),
        target: path_text(relative)?,
        sha256: sha256_bytes(payload)?,
        created: false,
    })
}

// Returns the exact staged payload selected by a closed material role.
fn material_payload<'a>(
    role: &str,
    pairing_secret: &'a [u8; SECRET_BYTES],
    api_key: Option<&'a [u8; SECRET_BYTES]>,
    trust: &'a CoreSetupIssuedResidentTrust,
    watchdog_allowlist: Option<&'a [u8]>,
) -> Result<&'a [u8], CoreSetupProviderError> {
    match role {
        "pairing_setup_secret" => Ok(pairing_secret),
        "api_key" => api_key
            .map(|value| &value[..])
            .ok_or_else(|| material_error("private material role is invalid")),
        "benchmark_signing_private_key" => Ok(&trust.benchmark_signing.private_key),
        "benchmark_signing_public_key" => Ok(&trust.benchmark_signing.public_key),
        "site_private_key" => Ok(&trust.pairing.site_private_key),
        "site_public_key" => Ok(&trust.pairing.site_public_key),
        "site_ca_certificate" => Ok(&trust.pairing.site_ca_certificate),
        "local_control_certificate" => Ok(&trust.pairing.local_control_certificate),
        "node_authority_private_key" => Ok(&trust.node.authority_private_key),
        "node_authority_certificate" => Ok(&trust.node.authority_certificate),
        "node_server_certificate" => Ok(&trust.node.server_certificate),
        "node_server_private_key" => Ok(&trust.node.server_private_key),
        "node_client_certificate" => Ok(&trust.node.client_certificate),
        "node_client_private_key" => Ok(&trust.node.client_private_key),
        "gateway_authority_private_key" => Ok(&trust.gateway.authority_private_key),
        "gateway_authority_certificate" => Ok(&trust.gateway.authority_certificate),
        "gateway_server_certificate" => Ok(&trust.gateway.server_certificate),
        "gateway_server_private_key" => Ok(&trust.gateway.server_private_key),
        "gateway_relay_client_certificate" => Ok(&trust.gateway.client_certificate),
        "gateway_relay_client_private_key" => Ok(&trust.gateway.client_private_key),
        "watchdog_authority_private_key" => {
            watchdog_trust(trust).map(|value| value.authority_private_key.as_slice())
        }
        "watchdog_authority_certificate" => {
            watchdog_trust(trust).map(|value| value.authority_certificate.as_slice())
        }
        "watchdog_server_certificate" => {
            watchdog_trust(trust).map(|value| value.server_certificate.as_slice())
        }
        "watchdog_server_private_key" => {
            watchdog_trust(trust).map(|value| value.server_private_key.as_slice())
        }
        "watchdog_controller_certificate" => {
            watchdog_trust(trust).map(|value| value.client_certificate.as_slice())
        }
        "watchdog_controller_private_key" => {
            watchdog_trust(trust).map(|value| value.client_private_key.as_slice())
        }
        "watchdog_controller_allowlist" => {
            watchdog_allowlist.ok_or_else(|| material_error("private material role is invalid"))
        }
        _ => Err(material_error("private material role is invalid")),
    }
}

// Returns the required Linux Watchdog issued closure for a Watchdog file role.
fn watchdog_trust(
    trust: &CoreSetupIssuedResidentTrust,
) -> Result<&CoreSetupIssuedMutualTlsTrust, CoreSetupProviderError> {
    trust
        .watchdog
        .as_ref()
        .ok_or_else(|| material_error("private material role is invalid"))
}

// Returns a lowercase SHA-256 digest for one bounded material payload.
fn sha256_bytes(payload: &[u8]) -> Result<String, CoreSetupProviderError> {
    Ok(format!("{:x}", Sha256::digest(payload)))
}

// Encodes one DER document as a canonical newline-terminated PEM document.
fn pem_document(label: &str, der: &[u8]) -> Vec<u8> {
    let encoded = BASE64.encode(der);
    let mut document = format!("-----BEGIN {label}-----\n").into_bytes();
    for line in encoded.as_bytes().chunks(64) {
        document.extend_from_slice(line);
        document.push(b'\n');
    }
    document.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    document
}

// Tests whether one existing target matches an exact payload identity.
fn target_matches(
    root: &File,
    relative: &str,
    expected: &str,
    owner_user_id: u32,
) -> Result<bool, CoreSetupProviderError> {
    match open_relative_file(root, Path::new(relative), owner_user_id)? {
        Some(file) => {
            if file_sha256(&file)? != expected {
                return Err(material_error("pre-existing private material differs"));
            }
            Ok(true)
        }
        None => Ok(false),
    }
}

// Opens a normalized descendant using no-follow directory descriptors for every component.
fn open_relative_file(
    root: &File,
    relative: &Path,
    owner_user_id: u32,
) -> Result<Option<File>, CoreSetupProviderError> {
    let (parent, name) = open_relative_parent(root, relative, owner_user_id, false)?;
    open_existing_file_at(&parent, &name, owner_user_id)
}

// Opens or creates every descendant parent without following intermediate links.
fn open_relative_parent(
    root: &File,
    relative: &Path,
    owner_user_id: u32,
    create: bool,
) -> Result<(File, String), CoreSetupProviderError> {
    let components = relative
        .components()
        .map(|value| match value {
            Component::Normal(name) => name.to_owned(),
            _ => OsStr::new("").to_owned(),
        })
        .collect::<Vec<_>>();
    if components.is_empty() || components.iter().any(|value| value.is_empty()) {
        return Err(material_error("private material target is invalid"));
    }
    let mut directory = root
        .try_clone()
        .map_err(|_| material_error("private material root is unavailable"))?;
    for component in &components[..components.len() - 1] {
        let name = component
            .to_str()
            .ok_or_else(|| material_error("private material target is invalid"))?;
        match open_private_directory_at(&directory, name, owner_user_id) {
            Ok(next) => directory = next,
            Err(_) if create => {
                create_private_directory_at(&directory, name, owner_user_id)?;
                directory = open_private_directory_at(&directory, name, owner_user_id)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((
        directory,
        components
            .last()
            .and_then(|value| value.to_str())
            .ok_or_else(|| material_error("private material target is invalid"))?
            .to_string(),
    ))
}

// Reconciles every staged or already-published file in one durable intent.
fn reconcile_manifest(
    root: &File,
    manifest: &mut MaterialManifest,
    owner_user_id: u32,
    io: &SystemCoreSetupMaterialIo,
    publication_index: &mut usize,
) -> Result<(), CoreSetupProviderError> {
    let staging = open_private_directory_at(root, &manifest.staging_directory, owner_user_id).ok();
    for file in &manifest.files {
        if target_matches(root, &file.target, &file.sha256, owner_user_id)? {
            continue;
        }
        if !file.created {
            return Err(material_error("pre-existing private material disappeared"));
        }
        let staging = staging
            .as_ref()
            .ok_or_else(|| material_recovery_error("private material staging is incomplete"))?;
        let staged = open_existing_file_at(staging, &file.role, owner_user_id)?
            .ok_or_else(|| material_recovery_error("private material staging is incomplete"))?;
        if file_sha256(&staged)? != file.sha256 {
            return Err(material_error("private material staging is corrupt"));
        }
        let (parent, name) =
            open_relative_parent(root, Path::new(&file.target), owner_user_id, true)?;
        rename_child(staging, &file.role, &parent, &name)?;
        sync_file(&parent)?;
        io.observed(CoreSetupMaterialPublication::TargetFile, publication_index)?;
    }
    if let Some(staging) = staging {
        sync_file(&staging)?;
    }
    Ok(())
}

// Computes one bounded open-file digest without reopening its path.
fn file_sha256(file: &File) -> Result<String, CoreSetupProviderError> {
    let mut file = file
        .try_clone()
        .map_err(|_| material_error("private material file is unavailable"))?;
    let mut digest = Sha256::new();
    let mut buffer = MaterialDigestBuffer::default();
    let mut length = 0_usize;
    loop {
        let count = file
            .read(&mut buffer.0)
            .map_err(|_| material_error("private material file is unavailable"))?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count)
            .ok_or_else(|| material_error("private material file is oversized"))?;
        if length > MAXIMUM_MATERIAL_FILE_BYTES {
            return Err(material_error("private material file is oversized"));
        }
        digest.update(&buffer.0[..count]);
        buffer.0[..count].fill(0);
    }
    Ok(format!("{:x}", digest.finalize()))
}

// Renames one direct child between trusted directory descriptors without path traversal.
fn rename_child(
    source: &File,
    source_name: &str,
    destination: &File,
    destination_name: &str,
) -> Result<(), CoreSetupProviderError> {
    let source_name = native_name(source_name)?;
    let destination_name = native_name(destination_name)?;
    if unsafe {
        libc::renameat(
            source.as_raw_fd(),
            source_name.as_ptr(),
            destination.as_raw_fd(),
            destination_name.as_ptr(),
        )
    } != 0
    {
        return Err(material_recovery_error(
            "private material publication is ambiguous",
        ));
    }
    Ok(())
}

// Removes one direct child file and treats absence as idempotent success.
fn unlink_file_at(root: &File, name: &str) -> Result<(), CoreSetupProviderError> {
    let name = native_name(name)?;
    if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(material_recovery_error(
                "private material cleanup is ambiguous",
            ));
        }
    }
    Ok(())
}

// Removes one empty or file-only receipt staging directory without traversing foreign names.
fn remove_receipt_staging(
    root: &File,
    name: &str,
    owner_user_id: u32,
) -> Result<(), CoreSetupProviderError> {
    let Some(directory) = open_optional_private_directory_at(root, name, owner_user_id)? else {
        return Ok(());
    };
    for role in [
        "pairing_setup_secret",
        "api_key",
        "benchmark_signing_private_key",
        "benchmark_signing_public_key",
        "site_private_key",
        "site_public_key",
        "site_ca_certificate",
        "local_control_certificate",
        "node_authority_private_key",
        "node_authority_certificate",
        "node_server_certificate",
        "node_server_private_key",
        "node_client_certificate",
        "node_client_private_key",
        "gateway_authority_private_key",
        "gateway_authority_certificate",
        "gateway_server_certificate",
        "gateway_server_private_key",
        "gateway_relay_client_certificate",
        "gateway_relay_client_private_key",
        "watchdog_authority_private_key",
        "watchdog_authority_certificate",
        "watchdog_server_certificate",
        "watchdog_server_private_key",
        "watchdog_controller_certificate",
        "watchdog_controller_private_key",
        "watchdog_controller_allowlist",
    ] {
        unlink_file_at(&directory, role)?;
    }
    let name = native_name(name)?;
    if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(material_recovery_error(
            "private material staging cleanup is ambiguous",
        ));
    }
    sync_file(root)
}

// Removes one exact created target only while its descriptor-bound digest still matches.
fn remove_exact_target(
    root: &File,
    relative: &str,
    expected: &str,
    owner_user_id: u32,
) -> Result<(), CoreSetupProviderError> {
    let Some(file) = open_relative_file(root, Path::new(relative), owner_user_id)? else {
        return Ok(());
    };
    if file_sha256(&file)? != expected {
        return Err(material_recovery_error(
            "private material rollback target changed",
        ));
    }
    let (parent, name) = open_relative_parent(root, Path::new(relative), owner_user_id, false)?;
    unlink_file_at(&parent, &name)?;
    sync_file(&parent)
}
