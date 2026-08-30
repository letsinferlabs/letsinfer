// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_authentication_manager::ControllerError;
use li_core_interface::{ControllerId, InstallationId, Sha256Digest};
use li_node_manager::{NodeControllerAuthorization, NodeControllerAuthorizationProjectionPort};
use li_watchdog_manager::{watchdog_crc32, WatchdogControllerAllowlist};
use sha2::{Digest, Sha256};

use crate::{
    CoreNativeServiceCommandRunner, CoreNativeServiceIo, SystemCoreNativeServiceCommandRunner,
    SystemCoreNativeServiceIo,
};

const MAXIMUM_ALLOWLIST_BYTES: u64 = 12_288;
const MAXIMUM_CERTIFICATE_BYTES: u64 = 64 * 1024;
const MAXIMUM_CONTROLLERS: usize = 8;
const RELOAD_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_RELOAD_OUTPUT_BYTES: usize = 8 * 1024;
const MAXIMUM_RELOAD_RECEIPT_BYTES: u64 = 1_048_576;
const RELOAD_RECEIPT_ATTEMPTS: usize = 500;
const RELOAD_RECEIPT_INTERVAL: Duration = Duration::from_millis(10);

// Selects every immutable file and service identity required by controller projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreControllerAuthorizationProjectionConfiguration {
    installation_id: InstallationId,
    protected_controller_id: ControllerId,
    protected_controller_certificate_file: PathBuf,
    allowlist_file: PathBuf,
    reload_receipt_file: PathBuf,
    owner_user_id: u32,
    supervisor_command: PathBuf,
}

impl CoreControllerAuthorizationProjectionConfiguration {
    // Creates one exact Linux projection contract without opening files or invoking services.
    pub fn new(
        installation_id: InstallationId,
        protected_controller_id: ControllerId,
        protected_controller_certificate_file: PathBuf,
        allowlist_file: PathBuf,
        reload_receipt_file: PathBuf,
        owner_user_id: u32,
        supervisor_command: PathBuf,
    ) -> Result<Self, ControllerError> {
        let paths = [
            protected_controller_certificate_file.as_path(),
            allowlist_file.as_path(),
            reload_receipt_file.as_path(),
            supervisor_command.as_path(),
        ];
        if paths.iter().any(|path| !normal_absolute_path(path))
            || paths
                .iter()
                .enumerate()
                .any(|(index, path)| paths[..index].contains(path))
            || supervisor_command != Path::new("/usr/bin/systemctl")
        {
            return Err(ControllerError::ProviderUnavailable);
        }
        Ok(Self {
            installation_id,
            protected_controller_id,
            protected_controller_certificate_file,
            allowlist_file,
            reload_receipt_file,
            owner_user_id,
            supervisor_command,
        })
    }
}

// Isolates owner-only atomic allowlist I/O from projection and rollback policy.
pub trait CoreControllerAuthorizationProjectionIo: Send + Sync {
    // Reads one exact nonempty owner-only file through a bounded no-follow descriptor.
    fn read(
        &self,
        path: &Path,
        owner_user_id: u32,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, ControllerError>;

    // Atomically replaces one exact owner-only file and persists its parent directory.
    fn replace(&self, path: &Path, bytes: &[u8], owner_user_id: u32)
        -> Result<(), ControllerError>;
}

// Isolates the exact synchronous Watchdog HUP boundary for deterministic failure tests.
pub trait CoreControllerAuthorizationReloadPort: Send + Sync {
    // Reloads and acknowledges the exact expected allowlist identity before reporting success.
    fn reload(&self, expected_allowlist_sha256: &Sha256Digest) -> Result<(), ControllerError>;
}

// Reads the exact allowlist identity acknowledged by the live Watchdog registry.
pub trait CoreControllerAuthorizationReloadReceiptPort: Send + Sync {
    // Returns the checksum-verified current live-reload receipt identity.
    fn allowlist_sha256(&self) -> Result<Sha256Digest, ControllerError>;
}

// Isolates bounded reload receipt waits for deterministic tests.
pub trait CoreControllerAuthorizationReloadWaiter: Send + Sync {
    // Waits exactly one already-bounded observation interval.
    fn wait(&self, duration: Duration) -> Result<(), ControllerError>;
}

// Applies the ordinary bounded native sleep between receipt observations.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreControllerAuthorizationReloadWaiter;

impl CoreControllerAuthorizationReloadWaiter for SystemCoreControllerAuthorizationReloadWaiter {
    // Waits only the fixed short reload observation interval.
    fn wait(&self, duration: Duration) -> Result<(), ControllerError> {
        if duration != RELOAD_RECEIPT_INTERVAL {
            return Err(ControllerError::ProviderUnavailable);
        }
        std::thread::sleep(duration);
        Ok(())
    }
}

// Reconciles the complete durable controller set through atomic file and last-good reload steps.
pub struct CoreControllerAuthorizationProjection {
    configuration: CoreControllerAuthorizationProjectionConfiguration,
    protected_certificate_sha256: Sha256Digest,
    io: Arc<dyn CoreControllerAuthorizationProjectionIo>,
    reload: Arc<dyn CoreControllerAuthorizationReloadPort>,
    transaction: Mutex<()>,
}

impl CoreControllerAuthorizationProjection {
    // Loads the protected Core-health controller and validates the installed initial allowlist.
    pub fn load(
        configuration: CoreControllerAuthorizationProjectionConfiguration,
        io: Arc<dyn CoreControllerAuthorizationProjectionIo>,
        reload: Arc<dyn CoreControllerAuthorizationReloadPort>,
    ) -> Result<Self, ControllerError> {
        let certificate = io.read(
            &configuration.protected_controller_certificate_file,
            configuration.owner_user_id,
            MAXIMUM_CERTIFICATE_BYTES,
        )?;
        let protected_certificate_sha256 = certificate_fingerprint(&certificate)?;
        let allowlist_bytes = io.read(
            &configuration.allowlist_file,
            configuration.owner_user_id,
            MAXIMUM_ALLOWLIST_BYTES,
        )?;
        let allowlist = WatchdogControllerAllowlist::parse(&allowlist_bytes)
            .map_err(|_| ControllerError::ProviderUnavailable)?;
        if allowlist.installation_id() != configuration.installation_id.as_str()
            || !allowlist.authorizes(
                configuration.protected_controller_id.as_str(),
                protected_certificate_sha256.as_str(),
            )
        {
            return Err(ControllerError::ProviderUnavailable);
        }
        Ok(Self {
            configuration,
            protected_certificate_sha256,
            io,
            reload,
            transaction: Mutex::new(()),
        })
    }

    // Restores the exact prior bytes and live registry after an incomplete replacement.
    fn restore(&self, prior: &[u8]) -> Result<(), ControllerError> {
        let prior_allowlist = WatchdogControllerAllowlist::parse(prior)
            .map_err(|_| ControllerError::ProviderUnavailable)?;
        let prior_sha256 = Sha256Digest::parse(prior_allowlist.sha256())?;
        self.io.replace(
            &self.configuration.allowlist_file,
            prior,
            self.configuration.owner_user_id,
        )?;
        self.reload.reload(&prior_sha256)?;
        let observed = self.io.read(
            &self.configuration.allowlist_file,
            self.configuration.owner_user_id,
            MAXIMUM_ALLOWLIST_BYTES,
        )?;
        if observed != prior {
            return Err(ControllerError::ProviderUnavailable);
        }
        Ok(())
    }
}

impl NodeControllerAuthorizationProjectionPort for CoreControllerAuthorizationProjection {
    // Serializes one complete set, reloads atomically, and restores prior trust on every failure.
    fn reconcile(
        &self,
        controllers: &[NodeControllerAuthorization],
    ) -> Result<(), ControllerError> {
        let _transaction = self
            .transaction
            .lock()
            .map_err(|_| ControllerError::ProviderUnavailable)?;
        let desired = encode_allowlist(
            &self.configuration.installation_id,
            &self.configuration.protected_controller_id,
            &self.protected_certificate_sha256,
            controllers,
        )?;
        let desired_allowlist = WatchdogControllerAllowlist::parse(&desired)
            .map_err(|_| ControllerError::ProviderUnavailable)?;
        let desired_sha256 = Sha256Digest::parse(desired_allowlist.sha256())?;
        let prior = self.io.read(
            &self.configuration.allowlist_file,
            self.configuration.owner_user_id,
            MAXIMUM_ALLOWLIST_BYTES,
        )?;
        let current = WatchdogControllerAllowlist::parse(&prior)
            .map_err(|_| ControllerError::ProviderUnavailable)?;
        if current.installation_id() != self.configuration.installation_id.as_str()
            || !current.authorizes(
                self.configuration.protected_controller_id.as_str(),
                self.protected_certificate_sha256.as_str(),
            )
        {
            return Err(ControllerError::ProviderUnavailable);
        }
        let operation = (|| {
            if prior != desired {
                self.io.replace(
                    &self.configuration.allowlist_file,
                    &desired,
                    self.configuration.owner_user_id,
                )?;
            }
            self.reload.reload(&desired_sha256)?;
            let observed = self.io.read(
                &self.configuration.allowlist_file,
                self.configuration.owner_user_id,
                MAXIMUM_ALLOWLIST_BYTES,
            )?;
            if observed != desired {
                return Err(ControllerError::ProviderUnavailable);
            }
            Ok(())
        })();
        match operation {
            Ok(()) => Ok(()),
            Err(error) => match self.restore(&prior) {
                Ok(()) => Err(error),
                Err(_) => Err(ControllerError::ProviderUnavailable),
            },
        }
    }
}

// Adapts the existing secure native service file boundary to controller projection.
pub struct SystemCoreControllerAuthorizationProjectionIo {
    io: Arc<dyn CoreNativeServiceIo>,
}

impl SystemCoreControllerAuthorizationProjectionIo {
    // Creates one system adapter around the shared owner-only atomic file implementation.
    pub fn new() -> Self {
        Self {
            io: Arc::new(SystemCoreNativeServiceIo),
        }
    }
}

impl Default for SystemCoreControllerAuthorizationProjectionIo {
    // Creates the ordinary system I/O adapter without performing native work.
    fn default() -> Self {
        Self::new()
    }
}

impl CoreControllerAuthorizationProjectionIo for SystemCoreControllerAuthorizationProjectionIo {
    // Reads one exact existing projection input and rejects missing or unsafe files.
    fn read(
        &self,
        path: &Path,
        owner_user_id: u32,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, ControllerError> {
        self.io
            .read_private_file(path, owner_user_id, maximum_bytes)
            .map_err(|_| ControllerError::ProviderUnavailable)?
            .ok_or(ControllerError::ProviderUnavailable)
    }

    // Atomically replaces one owner-only allowlist through the shared durable file implementation.
    fn replace(
        &self,
        path: &Path,
        bytes: &[u8],
        owner_user_id: u32,
    ) -> Result<(), ControllerError> {
        self.io
            .replace_private_file(path, bytes, owner_user_id, 0o600)
            .map_err(|_| ControllerError::ProviderUnavailable)
    }
}

// Reads one checksum-bound Watchdog registry snapshot as the live reload acknowledgment.
pub struct SystemCoreControllerAuthorizationReloadReceipt {
    installation_id: InstallationId,
    snapshot_file: PathBuf,
    owner_user_id: u32,
    io: Arc<dyn CoreControllerAuthorizationProjectionIo>,
}

impl SystemCoreControllerAuthorizationReloadReceipt {
    // Creates one exact receipt reader without opening the Watchdog snapshot.
    pub fn new(
        installation_id: InstallationId,
        snapshot_file: PathBuf,
        owner_user_id: u32,
        io: Arc<dyn CoreControllerAuthorizationProjectionIo>,
    ) -> Result<Self, ControllerError> {
        if !normal_absolute_path(&snapshot_file) {
            return Err(ControllerError::ProviderUnavailable);
        }
        Ok(Self {
            installation_id,
            snapshot_file,
            owner_user_id,
            io,
        })
    }
}

impl CoreControllerAuthorizationReloadReceiptPort
    for SystemCoreControllerAuthorizationReloadReceipt
{
    // Verifies framing, checksum, installation identity, and allowlist identity together.
    fn allowlist_sha256(&self) -> Result<Sha256Digest, ControllerError> {
        let snapshot = self.io.read(
            &self.snapshot_file,
            self.owner_user_id,
            MAXIMUM_RELOAD_RECEIPT_BYTES,
        )?;
        reload_receipt_allowlist_sha256(&snapshot, &self.installation_id)
    }
}

// Requests the canonical user Watchdog service reload through one bounded shell-free command.
pub struct SystemCoreControllerAuthorizationReload {
    supervisor_command: PathBuf,
    runner: Arc<dyn CoreNativeServiceCommandRunner>,
    receipt: Arc<dyn CoreControllerAuthorizationReloadReceiptPort>,
    waiter: Arc<dyn CoreControllerAuthorizationReloadWaiter>,
}

impl SystemCoreControllerAuthorizationReload {
    // Creates one exact Linux supervisor adapter without invoking it.
    pub fn new(
        supervisor_command: PathBuf,
        receipt: Arc<dyn CoreControllerAuthorizationReloadReceiptPort>,
    ) -> Result<Self, ControllerError> {
        Self::new_with_runner(
            supervisor_command,
            Arc::new(SystemCoreNativeServiceCommandRunner),
            receipt,
            Arc::new(SystemCoreControllerAuthorizationReloadWaiter),
        )
    }

    // Creates one exact adapter with an injected shell-free runner for deterministic tests.
    pub fn new_with_runner(
        supervisor_command: PathBuf,
        runner: Arc<dyn CoreNativeServiceCommandRunner>,
        receipt: Arc<dyn CoreControllerAuthorizationReloadReceiptPort>,
        waiter: Arc<dyn CoreControllerAuthorizationReloadWaiter>,
    ) -> Result<Self, ControllerError> {
        if supervisor_command != Path::new("/usr/bin/systemctl") {
            return Err(ControllerError::ProviderUnavailable);
        }
        Ok(Self {
            supervisor_command,
            runner,
            receipt,
            waiter,
        })
    }
}

impl CoreControllerAuthorizationReloadPort for SystemCoreControllerAuthorizationReload {
    // Sends one exact HUP and waits for the checksum-bound expected registry acknowledgment.
    fn reload(&self, expected_allowlist_sha256: &Sha256Digest) -> Result<(), ControllerError> {
        let output = self
            .runner
            .run(
                &self.supervisor_command,
                &[
                    "--user".to_string(),
                    "kill".to_string(),
                    "--signal=HUP".to_string(),
                    "li_watchdog.service".to_string(),
                ],
                RELOAD_TIMEOUT,
                MAXIMUM_RELOAD_OUTPUT_BYTES,
            )
            .map_err(|_| ControllerError::ProviderUnavailable)?;
        if output.status() != 0 {
            return Err(ControllerError::ProviderUnavailable);
        }
        for _ in 0..RELOAD_RECEIPT_ATTEMPTS {
            if &self.receipt.allowlist_sha256()? == expected_allowlist_sha256 {
                return Ok(());
            }
            self.waiter.wait(RELOAD_RECEIPT_INTERVAL)?;
        }
        Err(ControllerError::ProviderUnavailable)
    }
}

// Builds one production projection from exact installed paths and resident identities.
pub fn compose_system_core_controller_authorization_projection(
    configuration: CoreControllerAuthorizationProjectionConfiguration,
) -> Result<Arc<dyn NodeControllerAuthorizationProjectionPort>, ControllerError> {
    let io = Arc::new(SystemCoreControllerAuthorizationProjectionIo::new());
    let receipt = Arc::new(SystemCoreControllerAuthorizationReloadReceipt::new(
        configuration.installation_id.clone(),
        configuration.reload_receipt_file.clone(),
        configuration.owner_user_id,
        io.clone(),
    )?);
    let reload = Arc::new(SystemCoreControllerAuthorizationReload::new(
        configuration.supervisor_command.clone(),
        receipt,
    )?);
    Ok(Arc::new(CoreControllerAuthorizationProjection::load(
        configuration,
        io,
        reload,
    )?))
}

// Encodes the protected local controller plus every active external controller canonically.
fn encode_allowlist(
    installation_id: &InstallationId,
    protected_controller_id: &ControllerId,
    protected_certificate_sha256: &Sha256Digest,
    controllers: &[NodeControllerAuthorization],
) -> Result<Vec<u8>, ControllerError> {
    let mut entries = BTreeMap::from([(
        protected_controller_id.as_str(),
        protected_certificate_sha256.as_str(),
    )]);
    let mut fingerprints = BTreeSet::from([protected_certificate_sha256.as_str()]);
    for controller in controllers {
        if entries.len() >= MAXIMUM_CONTROLLERS
            || entries
                .insert(
                    controller.controller_id().as_str(),
                    controller.certificate_sha256().as_str(),
                )
                .is_some()
            || !fingerprints.insert(controller.certificate_sha256().as_str())
        {
            return Err(ControllerError::ProviderUnavailable);
        }
    }
    let mut document = format!("version=1\ninstallation_id={}\n", installation_id.as_str());
    for (controller_id, fingerprint) in entries {
        document.push_str(&format!("controller={controller_id},{fingerprint}\n"));
    }
    if document.len() > MAXIMUM_ALLOWLIST_BYTES as usize
        || WatchdogControllerAllowlist::parse(document.as_bytes()).is_err()
    {
        return Err(ControllerError::ProviderUnavailable);
    }
    Ok(document.into_bytes())
}

// Computes the TLS peer fingerprint from exactly one canonical PEM certificate.
fn certificate_fingerprint(bytes: &[u8]) -> Result<Sha256Digest, ControllerError> {
    let certificates = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ControllerError::ProviderUnavailable)?;
    let [certificate] = certificates.as_slice() else {
        return Err(ControllerError::ProviderUnavailable);
    };
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(certificate.as_ref()))).map_err(Into::into)
}

// Verifies one complete Watchdog snapshot and returns its acknowledged allowlist identity.
fn reload_receipt_allowlist_sha256(
    snapshot: &[u8],
    installation_id: &InstallationId,
) -> Result<Sha256Digest, ControllerError> {
    if snapshot.is_empty()
        || snapshot.len() > MAXIMUM_RELOAD_RECEIPT_BYTES as usize
        || snapshot.last() != Some(&b'\n')
        || snapshot.contains(&0)
    {
        return Err(ControllerError::ProviderUnavailable);
    }
    let text = std::str::from_utf8(snapshot).map_err(|_| ControllerError::ProviderUnavailable)?;
    let checksum_start = text
        .rfind("checksum=")
        .filter(|index| *index > 0 && text.as_bytes()[index - 1] == b'\n')
        .ok_or(ControllerError::ProviderUnavailable)?;
    let body = &text[..checksum_start];
    let checksum = text[checksum_start..text.len() - 1]
        .strip_prefix("checksum=")
        .filter(|value| lower_hex(value, 8))
        .and_then(|value| u32::from_str_radix(value, 16).ok())
        .ok_or(ControllerError::ProviderUnavailable)?;
    if watchdog_crc32(body.as_bytes()) != checksum {
        return Err(ControllerError::ProviderUnavailable);
    }
    let mut lines = body.split_terminator('\n');
    if lines.next() != Some("schema=li_watchdog.controller-registry")
        || lines.next() != Some("version=1")
        || lines
            .next()
            .and_then(|line| line.strip_prefix("installation_id="))
            != Some(installation_id.as_str())
    {
        return Err(ControllerError::ProviderUnavailable);
    }
    let allowlist_sha256 = lines
        .next()
        .and_then(|line| line.strip_prefix("allowlist_sha256="))
        .filter(|value| lower_hex(value, 64))
        .ok_or(ControllerError::ProviderUnavailable)?;
    Sha256Digest::parse(allowlist_sha256).map_err(Into::into)
}

// Returns whether text is exact lowercase hexadecimal at one fixed length.
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Returns whether one explicit path is normal, absolute, and non-root without resolving it.
fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}
