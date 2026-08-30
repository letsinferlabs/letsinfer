// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use li_core_interface::{
    DisplayName, EntityTimestamps, HardwareObservationId, InstallationId, MachineId, Node,
    NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState, Sha256Digest, UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayNativeFile, GatewayNativeFileIo,
    GatewayNativeIoError,
};
use li_node_manager::{
    NodeConfiguration, NodeConfigurationError, NodeConfigurationFile,
    NodeConfigurationFileProvider, NodeConfigurationFileReference, NodePairingCredentials,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    CoreCliConfiguration, CoreCliConfigurationFile, CoreCliConfigurationFileProvider,
    CorePairingActivationConfigurationPort, CorePairingActivationError,
    CorePairingPreparedActivation, CoreServiceCutoverFile, CoreServiceCutoverFileIo,
    SystemCoreServiceCutoverFileIo, CORE_CLI_CONFIGURATION_FILENAME,
    CORE_CLI_CONFIGURATION_SCHEMA_NAME, CORE_CLI_CONFIGURATION_SCHEMA_VERSION,
    GATEWAY_CONFIGURATION_FILENAME, MAXIMUM_CORE_CLI_CONFIGURATION_BYTES,
    NODE_CONFIGURATION_FILENAME,
};

const PREPARED_CONFIGURATION_FILENAME: &str = ".li_pairing_activation_configuration.json";
const PREPARED_CONFIGURATION_SCHEMA_NAME: &str = "li_pairing_activation_configuration";
const PREPARED_CONFIGURATION_SCHEMA_VERSION: u32 = 1;
const CHILD_NODE_CERTIFICATE_FILENAME: &str = "li_child_node.crt";
const CHILD_GATEWAY_SERVER_CERTIFICATE_FILENAME: &str = "li_child_gateway_server.crt";
const CHILD_GATEWAY_CLIENT_CERTIFICATE_FILENAME: &str = "li_child_gateway_client.crt";
const MAIN_CA_CERTIFICATE_FILENAME: &str = "li_main_ca.crt";
const MAIN_PUBLIC_KEY_FILENAME: &str = "li_main_public_key.pem";

// Stores one closed schema identity for the prepared configuration owner.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSchema {
    name: String,
    version: u32,
}

// Stores one exact active main Node without importing a private persistence shape.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredMainNode {
    node_id: String,
    machine_id: String,
    installation_id: String,
    display_name: String,
    control_address: String,
    latest_hardware_observation_id: Option<String>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

// Stores one bounded public credential package in canonical base64 form.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCredentials {
    main_public_key_base64: String,
    main_ca_certificate_base64: String,
    child_certificate_base64: String,
    membership_signature_base64: String,
    child_leaf_sha256: String,
    valid_from_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
}

// Stores exact original and staged configuration bytes with independent identities.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredConfigurationDocument {
    bytes_base64: String,
    sha256: String,
}

// Persists one complete recovery owner before any child configuration becomes active.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredPreparedConfiguration {
    schema: StoredSchema,
    receipt: String,
    request_identity: String,
    main: StoredMainNode,
    main_private_port: u16,
    main_certificate_sha256: String,
    credentials: StoredCredentials,
    original_cli: StoredConfigurationDocument,
    original_node: StoredConfigurationDocument,
    original_gateway: StoredConfigurationDocument,
    child_node: StoredConfigurationDocument,
    child_gateway: StoredConfigurationDocument,
    child_cli: StoredConfigurationDocument,
}

// Owns one explicit private configuration root and its exact Unix owner.
pub struct SystemCorePairingActivationConfiguration {
    root: PathBuf,
    owner_user_id: u32,
    io: Arc<dyn CoreServiceCutoverFileIo>,
}

impl SystemCorePairingActivationConfiguration {
    // Creates one production adapter over the existing owner-bound atomic file capability.
    pub fn new(root: PathBuf, owner_user_id: u32) -> Result<Self, CorePairingActivationError> {
        Self::with_io(
            root,
            owner_user_id,
            Arc::new(SystemCoreServiceCutoverFileIo),
        )
    }

    // Creates one deterministic adapter with an explicit no-follow file boundary.
    pub fn with_io(
        root: PathBuf,
        owner_user_id: u32,
        io: Arc<dyn CoreServiceCutoverFileIo>,
    ) -> Result<Self, CorePairingActivationError> {
        if !safe_root(&root) {
            return Err(CorePairingActivationError::ConfigurationUnavailable);
        }
        io.validate_root(&root, owner_user_id)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        Ok(Self {
            root,
            owner_user_id,
            io,
        })
    }

    // Returns one exact fixed child credential path under the validated root.
    fn path(&self, filename: &str) -> PathBuf {
        self.root.join(filename)
    }

    // Reads one required exact-mode owner file.
    fn required(&self, path: &Path) -> Result<Vec<u8>, CorePairingActivationError> {
        let file = self
            .io
            .read(path, self.owner_user_id)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?
            .ok_or(CorePairingActivationError::ConfigurationUnavailable)?;
        if file.mode() != 0o600 {
            return Err(CorePairingActivationError::ConfigurationUnavailable);
        }
        Ok(file.bytes().to_vec())
    }

    // Atomically writes one exact owner-only file through the shared native capability.
    fn replace(&self, path: &Path, bytes: &[u8]) -> Result<(), CorePairingActivationError> {
        let file = CoreServiceCutoverFile::new(bytes.to_vec(), 0o600)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        self.io
            .replace(path, &file, self.owner_user_id)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)
    }

    // Reconciles absent or exact public material without overwriting divergent state.
    fn reconcile_material(
        &self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), CorePairingActivationError> {
        match self
            .io
            .read(path, self.owner_user_id)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?
        {
            Some(file) if file.mode() == 0o600 && file.bytes() == bytes => Ok(()),
            Some(_) => Err(CorePairingActivationError::ConfigurationUnavailable),
            None => self.replace(path, bytes),
        }
    }

    // Reconciles one configuration from its exact original or already-staged child bytes.
    fn reconcile_configuration(
        &self,
        path: &Path,
        original: &[u8],
        child: &[u8],
    ) -> Result<(), CorePairingActivationError> {
        let current = self.required(path)?;
        if current == child {
            return Ok(());
        }
        if current != original {
            return Err(CorePairingActivationError::ConfigurationUnavailable);
        }
        self.replace(path, child)
    }

    // Restores one exact original only from original or activation-owned child bytes.
    fn restore_configuration(
        &self,
        path: &Path,
        original: &[u8],
        child: &[u8],
    ) -> Result<(), CorePairingActivationError> {
        let current = self.required(path)?;
        if current == original {
            return Ok(());
        }
        if current != child {
            return Err(CorePairingActivationError::RecoveryRequired);
        }
        self.replace(path, original)
    }

    // Reads and recomputes one exact durable prepared configuration owner.
    fn stored(
        &self,
        receipt: Option<&Sha256Digest>,
    ) -> Result<StoredPreparedConfiguration, CorePairingActivationError> {
        let bytes = self.required(&self.path(PREPARED_CONFIGURATION_FILENAME))?;
        let stored: StoredPreparedConfiguration = serde_json::from_slice(&bytes)
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?;
        validate_stored(&stored)?;
        if receipt.is_some_and(|expected| expected.as_str() != stored.receipt) {
            return Err(CorePairingActivationError::RecoveryRequired);
        }
        Ok(stored)
    }

    // Reconciles every public credential file owned by one stored preparation.
    fn reconcile_stored_material(
        &self,
        stored: &StoredPreparedConfiguration,
    ) -> Result<(), CorePairingActivationError> {
        let credentials = credentials_from_stored(&stored.credentials)?;
        for (filename, bytes) in [
            (
                CHILD_NODE_CERTIFICATE_FILENAME,
                credentials.child_certificate(),
            ),
            (
                CHILD_GATEWAY_SERVER_CERTIFICATE_FILENAME,
                credentials.child_certificate(),
            ),
            (
                CHILD_GATEWAY_CLIENT_CERTIFICATE_FILENAME,
                credentials.child_certificate(),
            ),
            (
                MAIN_CA_CERTIFICATE_FILENAME,
                credentials.main_ca_certificate(),
            ),
            (MAIN_PUBLIC_KEY_FILENAME, credentials.main_public_key()),
        ] {
            self.reconcile_material(&self.path(filename), bytes)?;
        }
        Ok(())
    }

    // Verifies every exact public credential file without repairing observed state.
    fn verify_stored_material(
        &self,
        stored: &StoredPreparedConfiguration,
    ) -> Result<(), CorePairingActivationError> {
        let credentials = credentials_from_stored(&stored.credentials)?;
        for (filename, expected) in [
            (
                CHILD_NODE_CERTIFICATE_FILENAME,
                credentials.child_certificate(),
            ),
            (
                CHILD_GATEWAY_SERVER_CERTIFICATE_FILENAME,
                credentials.child_certificate(),
            ),
            (
                CHILD_GATEWAY_CLIENT_CERTIFICATE_FILENAME,
                credentials.child_certificate(),
            ),
            (
                MAIN_CA_CERTIFICATE_FILENAME,
                credentials.main_ca_certificate(),
            ),
            (MAIN_PUBLIC_KEY_FILENAME, credentials.main_public_key()),
        ] {
            if self.required(&self.path(filename))? != expected {
                return Err(CorePairingActivationError::ConfigurationUnavailable);
            }
        }
        Ok(())
    }
}

impl CorePairingActivationConfigurationPort for SystemCorePairingActivationConfiguration {
    // Durably owns exact snapshots and staged public trust before returning its receipt.
    fn prepare(
        &self,
        request_identity: &Sha256Digest,
        main: &Node,
        main_private_port: u16,
        main_certificate_sha256: &Sha256Digest,
        credentials: &NodePairingCredentials,
    ) -> Result<Sha256Digest, CorePairingActivationError> {
        if self
            .io
            .read(
                &self.path(PREPARED_CONFIGURATION_FILENAME),
                self.owner_user_id,
            )
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?
            .is_some()
        {
            let stored = self.stored(None)?;
            let prepared = prepared_from_stored(&stored)?;
            if stored.request_identity != request_identity.as_str()
                || prepared.main() != main
                || prepared.main_private_port() != main_private_port
                || prepared.main_certificate_sha256() != main_certificate_sha256
                || prepared.credentials() != credentials
            {
                return Err(CorePairingActivationError::StateConflict);
            }
            self.reconcile_stored_material(&stored)?;
            return Sha256Digest::parse(&stored.receipt)
                .map_err(|_| CorePairingActivationError::RecoveryRequired);
        }
        for filename in credential_filenames() {
            if self
                .io
                .read(&self.path(filename), self.owner_user_id)
                .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?
                .is_some()
            {
                return Err(CorePairingActivationError::ConfigurationUnavailable);
            }
        }
        let original_cli = self.required(&self.path(CORE_CLI_CONFIGURATION_FILENAME))?;
        let original_node = self.required(&self.path(NODE_CONFIGURATION_FILENAME))?;
        let original_gateway = self.required(&self.path(GATEWAY_CONFIGURATION_FILENAME))?;
        let child_node = child_node_document(
            &original_node,
            &self.path(CHILD_NODE_CERTIFICATE_FILENAME),
            &self.path(MAIN_CA_CERTIFICATE_FILENAME),
        )?;
        let child_gateway = child_gateway_document(
            &original_gateway,
            &self.path(CHILD_GATEWAY_SERVER_CERTIFICATE_FILENAME),
            &self.path(CHILD_GATEWAY_CLIENT_CERTIFICATE_FILENAME),
            &self.path(MAIN_CA_CERTIFICATE_FILENAME),
            &site_private_key(&original_node)?,
        )?;
        let child_cli = child_cli_document(
            &original_cli,
            main,
            main_private_port,
            main_certificate_sha256,
            &self.path(CHILD_NODE_CERTIFICATE_FILENAME),
            &site_private_key(&original_node)?,
        )?;
        validate_cli_document(
            &self.path(CORE_CLI_CONFIGURATION_FILENAME),
            self.owner_user_id,
            &child_cli,
        )?;
        validate_node_document(
            &self.path(NODE_CONFIGURATION_FILENAME),
            self.owner_user_id,
            &child_node,
        )?;
        validate_gateway_document(
            &self.path(GATEWAY_CONFIGURATION_FILENAME),
            self.owner_user_id,
            &child_gateway,
        )?;
        let mut stored = StoredPreparedConfiguration {
            schema: StoredSchema {
                name: PREPARED_CONFIGURATION_SCHEMA_NAME.to_string(),
                version: PREPARED_CONFIGURATION_SCHEMA_VERSION,
            },
            receipt: String::new(),
            request_identity: request_identity.as_str().to_string(),
            main: stored_main(main),
            main_private_port,
            main_certificate_sha256: main_certificate_sha256.as_str().to_string(),
            credentials: stored_credentials(credentials),
            original_cli: stored_document(&original_cli)?,
            original_node: stored_document(&original_node)?,
            original_gateway: stored_document(&original_gateway)?,
            child_node: stored_document(&child_node)?,
            child_gateway: stored_document(&child_gateway)?,
            child_cli: stored_document(&child_cli)?,
        };
        stored.receipt = stored_receipt(&stored)?;
        let mut bytes = serde_json::to_vec_pretty(&stored)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        bytes.push(b'\n');
        self.replace(&self.path(PREPARED_CONFIGURATION_FILENAME), &bytes)?;
        self.reconcile_stored_material(&stored)?;
        Sha256Digest::parse(&stored.receipt)
            .map_err(|_| CorePairingActivationError::RecoveryRequired)
    }

    // Recovers only recomputed public material from the durable preparation owner.
    fn prepared(
        &self,
        receipt: &Sha256Digest,
    ) -> Result<CorePairingPreparedActivation, CorePairingActivationError> {
        prepared_from_stored(&self.stored(Some(receipt))?)
    }

    // Reconciles Node and Gateway child documents independently under one durable owner.
    fn commit(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError> {
        let stored = self.stored(Some(receipt))?;
        self.reconcile_stored_material(&stored)?;
        let original_node = document_bytes(&stored.original_node)?;
        let child_node = document_bytes(&stored.child_node)?;
        self.reconcile_configuration(
            &self.path(NODE_CONFIGURATION_FILENAME),
            &original_node,
            &child_node,
        )?;
        let original_gateway = document_bytes(&stored.original_gateway)?;
        let child_gateway = document_bytes(&stored.child_gateway)?;
        self.reconcile_configuration(
            &self.path(GATEWAY_CONFIGURATION_FILENAME),
            &original_gateway,
            &child_gateway,
        )?;
        self.reconcile_configuration(
            &self.path(CORE_CLI_CONFIGURATION_FILENAME),
            &document_bytes(&stored.original_cli)?,
            &document_bytes(&stored.child_cli)?,
        )
    }

    // Requires both active child documents and every exact public trust file.
    fn verify(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError> {
        let stored = self.stored(Some(receipt))?;
        self.verify_stored_material(&stored)?;
        if self.required(&self.path(NODE_CONFIGURATION_FILENAME))?
            != document_bytes(&stored.child_node)?
            || self.required(&self.path(GATEWAY_CONFIGURATION_FILENAME))?
                != document_bytes(&stored.child_gateway)?
            || self.required(&self.path(CORE_CLI_CONFIGURATION_FILENAME))?
                != document_bytes(&stored.child_cli)?
        {
            return Err(CorePairingActivationError::ConfigurationUnavailable);
        }
        Ok(())
    }

    // Restores exact main documents and removes only activation-owned public trust files.
    fn restore(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError> {
        let stored = self.stored(Some(receipt))?;
        self.restore_configuration(
            &self.path(CORE_CLI_CONFIGURATION_FILENAME),
            &document_bytes(&stored.original_cli)?,
            &document_bytes(&stored.child_cli)?,
        )?;
        self.restore_configuration(
            &self.path(GATEWAY_CONFIGURATION_FILENAME),
            &document_bytes(&stored.original_gateway)?,
            &document_bytes(&stored.child_gateway)?,
        )?;
        self.restore_configuration(
            &self.path(NODE_CONFIGURATION_FILENAME),
            &document_bytes(&stored.original_node)?,
            &document_bytes(&stored.child_node)?,
        )?;
        let credentials = credentials_from_stored(&stored.credentials)?;
        for (filename, bytes) in [
            (
                CHILD_NODE_CERTIFICATE_FILENAME,
                credentials.child_certificate(),
            ),
            (
                CHILD_GATEWAY_SERVER_CERTIFICATE_FILENAME,
                credentials.child_certificate(),
            ),
            (
                CHILD_GATEWAY_CLIENT_CERTIFICATE_FILENAME,
                credentials.child_certificate(),
            ),
            (
                MAIN_CA_CERTIFICATE_FILENAME,
                credentials.main_ca_certificate(),
            ),
            (MAIN_PUBLIC_KEY_FILENAME, credentials.main_public_key()),
        ] {
            remove_exact(self, &self.path(filename), bytes)?;
        }
        Ok(())
    }

    // Removes the prepared rollback owner only after exact main state remains observable.
    fn finish_rollback(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError> {
        let stored = self.stored(Some(receipt))?;
        if self.required(&self.path(CORE_CLI_CONFIGURATION_FILENAME))?
            != document_bytes(&stored.original_cli)?
            || self.required(&self.path(GATEWAY_CONFIGURATION_FILENAME))?
                != document_bytes(&stored.original_gateway)?
            || self.required(&self.path(NODE_CONFIGURATION_FILENAME))?
                != document_bytes(&stored.original_node)?
        {
            return Err(CorePairingActivationError::RecoveryRequired);
        }
        for filename in credential_filenames() {
            if self
                .io
                .read(&self.path(filename), self.owner_user_id)
                .map_err(|_| CorePairingActivationError::RecoveryRequired)?
                .is_some()
            {
                return Err(CorePairingActivationError::RecoveryRequired);
            }
        }
        self.io
            .remove(
                &self.path(PREPARED_CONFIGURATION_FILENAME),
                self.owner_user_id,
            )
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?;
        Ok(())
    }
}

// Returns every fixed activation-owned public credential filename.
const fn credential_filenames() -> [&'static str; 5] {
    [
        CHILD_NODE_CERTIFICATE_FILENAME,
        CHILD_GATEWAY_SERVER_CERTIFICATE_FILENAME,
        CHILD_GATEWAY_CLIENT_CERTIFICATE_FILENAME,
        MAIN_CA_CERTIFICATE_FILENAME,
        MAIN_PUBLIC_KEY_FILENAME,
    ]
}

// Removes one file only when its exact activation-owned bytes remain present.
fn remove_exact(
    configuration: &SystemCorePairingActivationConfiguration,
    path: &Path,
    expected: &[u8],
) -> Result<(), CorePairingActivationError> {
    let Some(file) = configuration
        .io
        .read(path, configuration.owner_user_id)
        .map_err(|_| CorePairingActivationError::RecoveryRequired)?
    else {
        return Ok(());
    };
    if file.mode() != 0o600 || file.bytes() != expected {
        return Err(CorePairingActivationError::RecoveryRequired);
    }
    configuration
        .io
        .remove(path, configuration.owner_user_id)
        .map(|_| ())
        .map_err(|_| CorePairingActivationError::RecoveryRequired)
}

// Builds one child Node document while preserving all unrelated closed fields exactly.
fn child_node_document(
    original: &[u8],
    child_certificate: &Path,
    main_ca: &Path,
) -> Result<Vec<u8>, CorePairingActivationError> {
    let mut value: Value = serde_json::from_slice(original)
        .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
    let remote = value
        .pointer_mut("/private_api/remote")
        .and_then(Value::as_object_mut)
        .ok_or(CorePairingActivationError::ConfigurationUnavailable)?;
    set_path(remote, "server_certificate_file", child_certificate)?;
    set_path(remote, "client_ca_file", main_ca)?;
    encode_value(&value)
}

// Builds one private-only child Gateway document with exact directional TLS roles.
fn child_gateway_document(
    original: &[u8],
    server_certificate: &Path,
    client_certificate: &Path,
    main_ca: &Path,
    private_key: &Path,
) -> Result<Vec<u8>, CorePairingActivationError> {
    let mut value: Value = serde_json::from_slice(original)
        .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
    let root = value
        .as_object_mut()
        .ok_or(CorePairingActivationError::ConfigurationUnavailable)?;
    root.insert("mode".to_string(), Value::String("child".to_string()));
    root.remove("public_listener");
    let tls = root
        .get_mut("private_listener")
        .and_then(|value| value.get_mut("tls"))
        .and_then(Value::as_object_mut)
        .ok_or(CorePairingActivationError::ConfigurationUnavailable)?;
    set_path(tls, "server_certificate_file", server_certificate)?;
    set_path(tls, "server_private_key_file", private_key)?;
    set_path(tls, "client_ca_file", main_ca)?;
    set_path(tls, "client_certificate_file", client_certificate)?;
    encode_value(&value)
}

// Builds one child CLI document bound to the exact paired-main private endpoint.
fn child_cli_document(
    original: &[u8],
    main: &Node,
    main_private_port: u16,
    main_certificate_sha256: &Sha256Digest,
    child_certificate: &Path,
    private_key: &Path,
) -> Result<Vec<u8>, CorePairingActivationError> {
    if main_private_port == 0 || !safe_root(child_certificate) || !safe_root(private_key) {
        return Err(CorePairingActivationError::ConfigurationUnavailable);
    }
    let mut value: Value = serde_json::from_slice(original)
        .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
    if value.pointer("/schema/name").and_then(Value::as_str)
        != Some(CORE_CLI_CONFIGURATION_SCHEMA_NAME)
        || value.pointer("/schema/version").and_then(Value::as_u64)
            != Some(u64::from(CORE_CLI_CONFIGURATION_SCHEMA_VERSION))
        || !value.pointer("/remote_main").is_some_and(Value::is_null)
    {
        return Err(CorePairingActivationError::ConfigurationUnavailable);
    }
    let root = value
        .as_object_mut()
        .ok_or(CorePairingActivationError::ConfigurationUnavailable)?;
    root.insert(
        "remote_main".to_string(),
        json!({
            "address": main.control_address().as_str(),
            "port": main_private_port,
            "server_certificate_sha256": main_certificate_sha256.as_str(),
            "client_certificate_file": child_certificate.to_string_lossy(),
            "client_private_key_file": private_key.to_string_lossy()
        }),
    );
    encode_value(&value)
}

// Returns the existing candidate private key referenced by the validated Node document.
fn site_private_key(original: &[u8]) -> Result<PathBuf, CorePairingActivationError> {
    let value: Value = serde_json::from_slice(original)
        .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
    let path = value
        .pointer("/pairing/site_private_key_file")
        .and_then(Value::as_str)
        .ok_or(CorePairingActivationError::ConfigurationUnavailable)?;
    if !safe_root(Path::new(path)) {
        return Err(CorePairingActivationError::ConfigurationUnavailable);
    }
    Ok(PathBuf::from(path))
}

// Replaces one required JSON path field with one normal absolute path.
fn set_path(
    object: &mut serde_json::Map<String, Value>,
    name: &str,
    path: &Path,
) -> Result<(), CorePairingActivationError> {
    if !object.contains_key(name) || !safe_root(path) {
        return Err(CorePairingActivationError::ConfigurationUnavailable);
    }
    object.insert(
        name.to_string(),
        Value::String(path.to_string_lossy().into_owned()),
    );
    Ok(())
}

// Encodes one mutated document deterministically with a terminal newline.
fn encode_value(value: &Value) -> Result<Vec<u8>, CorePairingActivationError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// Validates one child Node document through the production closed decoder.
fn validate_node_document(
    path: &Path,
    owner_user_id: u32,
    bytes: &[u8],
) -> Result<(), CorePairingActivationError> {
    let reference = NodeConfigurationFileReference::new(path.to_path_buf(), owner_user_id)
        .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
    NodeConfiguration::load(
        &reference,
        &MemoryNodeConfigurationFileProvider(bytes.to_vec(), owner_user_id),
    )
    .map(|_| ())
    .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)
}

// Validates one child Gateway document through the production closed decoder.
fn validate_gateway_document(
    path: &Path,
    owner_user_id: u32,
    bytes: &[u8],
) -> Result<(), CorePairingActivationError> {
    let reference = GatewayConfigurationFile::new(owner_user_id, path.to_path_buf())
        .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
    GatewayConfiguration::load(
        &reference,
        &MemoryGatewayConfigurationFileIo(bytes.to_vec(), owner_user_id),
    )
    .map(|_| ())
    .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)
}

// Validates one child CLI document through the production closed decoder.
fn validate_cli_document(
    path: &Path,
    owner_user_id: u32,
    bytes: &[u8],
) -> Result<(), CorePairingActivationError> {
    CoreCliConfiguration::load(
        path,
        owner_user_id,
        &MemoryCliConfigurationFileProvider(bytes.to_vec(), owner_user_id),
    )
    .map(|_| ())
    .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)
}

// Supplies one already-bounded CLI document to the production decoder.
struct MemoryCliConfigurationFileProvider(Vec<u8>, u32);

impl CoreCliConfigurationFileProvider for MemoryCliConfigurationFileProvider {
    // Returns one exact owner-only regular-file observation.
    fn read_no_follow(
        &self,
        _path: &Path,
        maximum_bytes: usize,
    ) -> Result<CoreCliConfigurationFile, crate::CoreCliProcessError> {
        if maximum_bytes != MAXIMUM_CORE_CLI_CONFIGURATION_BYTES || self.0.len() > maximum_bytes {
            return Err(crate::CoreCliProcessError::ConfigurationUnavailable);
        }
        Ok(CoreCliConfigurationFile::new(
            self.1,
            0o600,
            1,
            true,
            self.0.clone(),
        ))
    }
}

// Supplies one already-bounded Node document to the production decoder.
struct MemoryNodeConfigurationFileProvider(Vec<u8>, u32);

impl NodeConfigurationFileProvider for MemoryNodeConfigurationFileProvider {
    // Returns one exact owner-only regular-file observation.
    fn read_no_follow(
        &self,
        _path: &Path,
        maximum_bytes: usize,
    ) -> Result<NodeConfigurationFile, NodeConfigurationError> {
        if self.0.len() > maximum_bytes {
            return Err(NodeConfigurationError::DocumentTooLarge);
        }
        Ok(NodeConfigurationFile::new(
            self.1,
            0o600,
            1,
            true,
            self.0.clone(),
        ))
    }
}

// Supplies one already-bounded Gateway document to the production decoder.
struct MemoryGatewayConfigurationFileIo(Vec<u8>, u32);

impl GatewayNativeFileIo for MemoryGatewayConfigurationFileIo {
    // Returns one exact owner-only regular-file observation.
    fn read_no_follow(
        &self,
        _path: &Path,
        maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        if self.0.len() > maximum_bytes {
            return GatewayNativeFile::new(self.1, 0o600, 1, vec![0; maximum_bytes + 1]);
        }
        GatewayNativeFile::new(self.1, 0o600, 1, self.0.clone())
    }
}

// Stores one exact Node projection for durable restart reconstruction.
fn stored_main(main: &Node) -> StoredMainNode {
    StoredMainNode {
        node_id: main.identity().node_id().as_str().to_string(),
        machine_id: main.identity().machine_id().as_str().to_string(),
        installation_id: main.identity().installation_id().as_str().to_string(),
        display_name: main.display_name().as_str().to_string(),
        control_address: main.control_address().as_str().to_string(),
        latest_hardware_observation_id: main
            .latest_hardware_observation_id()
            .map(|value| value.as_str().to_string()),
        created_at_unix_milliseconds: main.timestamps().created_at().value(),
        updated_at_unix_milliseconds: main.timestamps().updated_at().value(),
    }
}

// Reconstructs one exact active main Node from the closed prepared owner.
fn main_from_stored(stored: &StoredMainNode) -> Result<Node, CorePairingActivationError> {
    Ok(Node::new(
        NodeIdentity::new(
            NodeId::parse(&stored.node_id)
                .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
            MachineId::parse(&stored.machine_id)
                .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
            InstallationId::parse(&stored.installation_id)
                .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
        ),
        DisplayName::parse(&stored.display_name)
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse(&stored.control_address)
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
        stored
            .latest_hardware_observation_id
            .as_deref()
            .map(HardwareObservationId::parse)
            .transpose()
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
        EntityTimestamps::new(
            UnixMilliseconds::new(stored.created_at_unix_milliseconds),
            UnixMilliseconds::new(stored.updated_at_unix_milliseconds),
        )
        .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
    ))
}

// Stores one exact public credential package without writing raw PEM into diagnostics.
fn stored_credentials(credentials: &NodePairingCredentials) -> StoredCredentials {
    StoredCredentials {
        main_public_key_base64: BASE64.encode(credentials.main_public_key()),
        main_ca_certificate_base64: BASE64.encode(credentials.main_ca_certificate()),
        child_certificate_base64: BASE64.encode(credentials.child_certificate()),
        membership_signature_base64: BASE64.encode(credentials.membership_signature()),
        child_leaf_sha256: credentials.child_leaf_sha256().as_str().to_string(),
        valid_from_unix_milliseconds: credentials.valid_from().value(),
        expires_at_unix_milliseconds: credentials.expires_at().value(),
    }
}

// Reconstructs one bounded public credential package with canonical base64 checks.
fn credentials_from_stored(
    stored: &StoredCredentials,
) -> Result<NodePairingCredentials, CorePairingActivationError> {
    let decode = |value: &str| {
        let bytes = BASE64
            .decode(value.as_bytes())
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?;
        if BASE64.encode(&bytes) != value {
            return Err(CorePairingActivationError::RecoveryRequired);
        }
        Ok(bytes)
    };
    NodePairingCredentials::new(
        decode(&stored.main_public_key_base64)?,
        decode(&stored.main_ca_certificate_base64)?,
        decode(&stored.child_certificate_base64)?,
        decode(&stored.membership_signature_base64)?,
        Sha256Digest::parse(&stored.child_leaf_sha256)
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
        UnixMilliseconds::new(stored.valid_from_unix_milliseconds),
        UnixMilliseconds::new(stored.expires_at_unix_milliseconds),
    )
    .map_err(|_| CorePairingActivationError::RecoveryRequired)
}

// Reconstructs the coordinator-facing public preparation projection.
fn prepared_from_stored(
    stored: &StoredPreparedConfiguration,
) -> Result<CorePairingPreparedActivation, CorePairingActivationError> {
    CorePairingPreparedActivation::new(
        main_from_stored(&stored.main)?,
        stored.main_private_port,
        Sha256Digest::parse(&stored.main_certificate_sha256)
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
        credentials_from_stored(&stored.credentials)?,
    )
}

// Stores one bounded document with an independently recomputed SHA-256 identity.
fn stored_document(
    bytes: &[u8],
) -> Result<StoredConfigurationDocument, CorePairingActivationError> {
    Ok(StoredConfigurationDocument {
        bytes_base64: BASE64.encode(bytes),
        sha256: digest(bytes)?.as_str().to_string(),
    })
}

// Decodes one canonical document and verifies its exact persisted identity.
fn document_bytes(
    stored: &StoredConfigurationDocument,
) -> Result<Vec<u8>, CorePairingActivationError> {
    let bytes = BASE64
        .decode(stored.bytes_base64.as_bytes())
        .map_err(|_| CorePairingActivationError::RecoveryRequired)?;
    if BASE64.encode(&bytes) != stored.bytes_base64 || digest(&bytes)?.as_str() != stored.sha256 {
        return Err(CorePairingActivationError::RecoveryRequired);
    }
    Ok(bytes)
}

// Validates schema, every nested identity, and the receipt over the receipt-free record.
fn validate_stored(stored: &StoredPreparedConfiguration) -> Result<(), CorePairingActivationError> {
    if stored.schema.name != PREPARED_CONFIGURATION_SCHEMA_NAME
        || stored.schema.version != PREPARED_CONFIGURATION_SCHEMA_VERSION
        || Sha256Digest::parse(&stored.request_identity).is_err()
        || Sha256Digest::parse(&stored.main_certificate_sha256).is_err()
    {
        return Err(CorePairingActivationError::RecoveryRequired);
    }
    prepared_from_stored(stored)?;
    document_bytes(&stored.original_cli)?;
    document_bytes(&stored.original_node)?;
    document_bytes(&stored.original_gateway)?;
    document_bytes(&stored.child_node)?;
    document_bytes(&stored.child_gateway)?;
    document_bytes(&stored.child_cli)?;
    if stored_receipt(stored)? != stored.receipt {
        return Err(CorePairingActivationError::RecoveryRequired);
    }
    Ok(())
}

// Computes one canonical receipt after excluding the receipt field itself.
fn stored_receipt(
    stored: &StoredPreparedConfiguration,
) -> Result<String, CorePairingActivationError> {
    let mut value =
        serde_json::to_value(stored).map_err(|_| CorePairingActivationError::RecoveryRequired)?;
    value
        .as_object_mut()
        .ok_or(CorePairingActivationError::RecoveryRequired)?
        .insert("receipt".to_string(), Value::String(String::new()));
    let bytes =
        serde_json::to_vec(&value).map_err(|_| CorePairingActivationError::RecoveryRequired)?;
    Ok(digest(&bytes)?.as_str().to_string())
}

// Returns one canonical SHA-256 digest.
fn digest(bytes: &[u8]) -> Result<Sha256Digest, CorePairingActivationError> {
    let value = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::parse(&value).map_err(|_| CorePairingActivationError::RecoveryRequired)
}

// Rejects root, relative, parent-traversing, or control-bearing filesystem paths.
fn safe_root(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && !path.as_os_str().is_empty()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}
