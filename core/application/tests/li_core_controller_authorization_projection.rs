// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use li_authentication_manager::ControllerError;
use li_core_application::{
    CoreControllerAuthorizationProjection, CoreControllerAuthorizationProjectionConfiguration,
    CoreControllerAuthorizationProjectionIo, CoreControllerAuthorizationReloadPort,
    CoreControllerAuthorizationReloadReceiptPort, CoreControllerAuthorizationReloadWaiter,
    CoreNativeServiceCommandOutput, CoreNativeServiceCommandRunner,
    SystemCoreControllerAuthorizationReload, SystemCoreControllerAuthorizationReloadReceipt,
};
use li_core_interface::{ControllerId, InstallationId, Sha256Digest};
use li_core_update_manager::CoreUpdateError;
use li_node_manager::{NodeControllerAuthorization, NodeControllerAuthorizationProjectionPort};
use li_watchdog_manager::{watchdog_crc32, WatchdogControllerAllowlist};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};

// Stores exact test files and optional replacement failures behind the production I/O port.
#[derive(Default)]
struct ProjectionIo {
    files: Mutex<HashMap<PathBuf, Vec<u8>>>,
    replace_failures: Mutex<usize>,
}

impl ProjectionIo {
    // Inserts one immutable fixture file before projection construction.
    fn insert(&self, path: PathBuf, bytes: Vec<u8>) {
        self.files.lock().expect("files").insert(path, bytes);
    }

    // Returns one exact current file for postcondition assertions.
    fn file(&self, path: &Path) -> Vec<u8> {
        self.files.lock().expect("files")[path].clone()
    }

    // Arms exact future atomic replacement failures.
    fn fail_replacements(&self, count: usize) {
        *self.replace_failures.lock().expect("replace failures") = count;
    }
}

impl CoreControllerAuthorizationProjectionIo for ProjectionIo {
    // Returns one deterministic in-memory file without platform I/O.
    fn read(
        &self,
        path: &Path,
        _owner_user_id: u32,
        _maximum_bytes: u64,
    ) -> Result<Vec<u8>, ControllerError> {
        self.files
            .lock()
            .expect("files")
            .get(path)
            .cloned()
            .ok_or(ControllerError::ProviderUnavailable)
    }

    // Replaces one deterministic file or emits the armed exact failure.
    fn replace(
        &self,
        path: &Path,
        bytes: &[u8],
        _owner_user_id: u32,
    ) -> Result<(), ControllerError> {
        let mut failures = self.replace_failures.lock().expect("replace failures");
        if *failures > 0 {
            *failures -= 1;
            return Err(ControllerError::ProviderUnavailable);
        }
        drop(failures);
        self.files
            .lock()
            .expect("files")
            .insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }
}

// Returns queued deterministic reload outcomes and records every requested live transition.
#[derive(Default)]
struct Reload {
    calls: Mutex<usize>,
    outcomes: Mutex<VecDeque<Result<(), ControllerError>>>,
}

// Records the exact shell-free native reload command and returns one fixed status.
struct CommandRunner {
    calls: Mutex<Vec<(PathBuf, Vec<String>)>>,
    status: i32,
}

impl CoreNativeServiceCommandRunner for CommandRunner {
    // Captures executable and argv without invoking a shell or native service manager.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        _timeout: std::time::Duration,
        _maximum_stdout_bytes: usize,
    ) -> Result<CoreNativeServiceCommandOutput, CoreUpdateError> {
        self.calls
            .lock()
            .expect("command calls")
            .push((executable.to_path_buf(), arguments.to_vec()));
        Ok(CoreNativeServiceCommandOutput::new(self.status, Vec::new()))
    }
}

// Returns one exact live Watchdog allowlist identity without filesystem polling.
struct Receipt(Sha256Digest);

impl CoreControllerAuthorizationReloadReceiptPort for Receipt {
    // Returns the retained deterministic receipt identity.
    fn allowlist_sha256(&self) -> Result<Sha256Digest, ControllerError> {
        Ok(self.0.clone())
    }
}

// Accepts only the production reload receipt cadence without sleeping.
struct Waiter;

impl CoreControllerAuthorizationReloadWaiter for Waiter {
    // Completes one deterministic bounded poll interval.
    fn wait(&self, duration: std::time::Duration) -> Result<(), ControllerError> {
        assert_eq!(duration, std::time::Duration::from_millis(10));
        Ok(())
    }
}

impl Reload {
    // Creates one reload mock from exact invocation outcomes.
    fn with_outcomes(outcomes: impl IntoIterator<Item = Result<(), ControllerError>>) -> Self {
        Self {
            calls: Mutex::new(0),
            outcomes: Mutex::new(outcomes.into_iter().collect()),
        }
    }

    // Returns the exact number of live reload requests.
    fn calls(&self) -> usize {
        *self.calls.lock().expect("reload calls")
    }
}

impl CoreControllerAuthorizationReloadPort for Reload {
    // Returns the next exact result and defaults to success after its queue is exhausted.
    fn reload(&self, _expected_allowlist_sha256: &Sha256Digest) -> Result<(), ControllerError> {
        *self.calls.lock().expect("reload calls") += 1;
        self.outcomes
            .lock()
            .expect("reload outcomes")
            .pop_front()
            .unwrap_or(Ok(()))
    }
}

// Returns one self-signed public certificate and its exact DER fingerprint.
fn protected_certificate() -> (Vec<u8>, Sha256Digest) {
    let parameters =
        CertificateParams::new(vec!["watchdog.local".to_string()]).expect("certificate parameters");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("certificate key");
    let certificate = parameters.self_signed(&key).expect("certificate");
    let fingerprint = Sha256Digest::parse(&format!("{:x}", Sha256::digest(certificate.der())))
        .expect("fingerprint");
    (certificate.pem().into_bytes(), fingerprint)
}

// Returns one canonical initial allowlist containing only the protected Core controller.
fn initial_allowlist(
    installation_id: &InstallationId,
    protected_controller_id: &ControllerId,
    fingerprint: &Sha256Digest,
) -> Vec<u8> {
    format!(
        "version=1\ninstallation_id={}\ncontroller={},{}\n",
        installation_id.as_str(),
        protected_controller_id.as_str(),
        fingerprint.as_str()
    )
    .into_bytes()
}

// Composes one projection and returns every observable deterministic mock.
fn projection(
    outcomes: impl IntoIterator<Item = Result<(), ControllerError>>,
) -> (
    CoreControllerAuthorizationProjection,
    Arc<ProjectionIo>,
    Arc<Reload>,
    PathBuf,
    InstallationId,
    ControllerId,
) {
    let certificate_file = PathBuf::from("/var/lib/letsinfer/watchdog-controller.crt");
    let allowlist_file = PathBuf::from("/var/lib/letsinfer/watchdog-controllers.allow");
    let installation_id = InstallationId::parse(&"a".repeat(64)).expect("installation");
    let protected_controller_id = ControllerId::parse(&"b".repeat(32)).expect("controller");
    let (certificate, fingerprint) = protected_certificate();
    let io = Arc::new(ProjectionIo::default());
    io.insert(certificate_file.clone(), certificate);
    io.insert(
        allowlist_file.clone(),
        initial_allowlist(&installation_id, &protected_controller_id, &fingerprint),
    );
    let reload = Arc::new(Reload::with_outcomes(outcomes));
    let value = CoreControllerAuthorizationProjection::load(
        CoreControllerAuthorizationProjectionConfiguration::new(
            installation_id.clone(),
            protected_controller_id.clone(),
            certificate_file,
            allowlist_file.clone(),
            PathBuf::from("/var/lib/letsinfer/controller-snapshot.json"),
            501,
            PathBuf::from("/usr/bin/systemctl"),
        )
        .expect("configuration"),
        io.clone(),
        reload.clone(),
    )
    .expect("projection");
    (
        value,
        io,
        reload,
        allowlist_file,
        installation_id,
        protected_controller_id,
    )
}

// Atomically adds, replays, and removes external authorization without dropping the protected row.
#[test]
fn projection_reconciles_complete_sets_and_preserves_protected_authority() {
    let (projection, io, reload, path, installation_id, protected) =
        projection([Ok(()), Ok(()), Ok(())]);
    let external = NodeControllerAuthorization::new(
        ControllerId::parse(&"c".repeat(32)).expect("external controller"),
        Sha256Digest::parse(&"d".repeat(64)).expect("external certificate"),
    );
    projection
        .reconcile(std::slice::from_ref(&external))
        .expect("add projection");
    drop(projection);
    let restarted = CoreControllerAuthorizationProjection::load(
        CoreControllerAuthorizationProjectionConfiguration::new(
            installation_id.clone(),
            protected.clone(),
            PathBuf::from("/var/lib/letsinfer/watchdog-controller.crt"),
            path.clone(),
            PathBuf::from("/var/lib/letsinfer/controller-snapshot.json"),
            501,
            PathBuf::from("/usr/bin/systemctl"),
        )
        .expect("restart configuration"),
        io.clone(),
        reload.clone(),
    )
    .expect("restart projection");
    restarted
        .reconcile(std::slice::from_ref(&external))
        .expect("restart replay projection");
    let added = WatchdogControllerAllowlist::parse(&io.file(&path)).expect("added allowlist");
    assert_eq!(added.installation_id(), installation_id.as_str());
    assert!(added.authorizes(
        external.controller_id().as_str(),
        external.certificate_sha256().as_str()
    ));
    assert!(added
        .controller_id_for_fingerprint(&"d".repeat(64))
        .is_some());

    restarted.reconcile(&[]).expect("remove projection");
    let removed = WatchdogControllerAllowlist::parse(&io.file(&path)).expect("removed allowlist");
    assert_eq!(removed.controller_count(), 1);
    assert!(removed
        .controller_id_for_fingerprint(&"d".repeat(64))
        .is_none());
    assert_eq!(protected.as_str(), "b".repeat(32));
    assert_eq!(reload.calls(), 3);
}

// Restores and reloads the exact prior file when the live replacement cannot be accepted.
#[test]
fn projection_rolls_back_reload_failure_without_authorization_drift() {
    let (projection, io, reload, path, _, _) =
        projection([Err(ControllerError::ProviderUnavailable), Ok(())]);
    let prior = io.file(&path);
    let external = NodeControllerAuthorization::new(
        ControllerId::parse(&"c".repeat(32)).expect("external controller"),
        Sha256Digest::parse(&"d".repeat(64)).expect("external certificate"),
    );
    assert_eq!(
        projection.reconcile(&[external]),
        Err(ControllerError::ProviderUnavailable)
    );
    assert_eq!(io.file(&path), prior);
    assert_eq!(reload.calls(), 2);
}

// Rejects write and rollback ambiguity without claiming that a changed set became live.
#[test]
fn projection_fails_closed_on_atomic_write_or_recovery_failure() {
    let (projection, io, reload, path, _, _) = projection([]);
    let prior = io.file(&path);
    io.fail_replacements(2);
    let external = NodeControllerAuthorization::new(
        ControllerId::parse(&"c".repeat(32)).expect("external controller"),
        Sha256Digest::parse(&"d".repeat(64)).expect("external certificate"),
    );
    assert_eq!(
        projection.reconcile(&[external]),
        Err(ControllerError::ProviderUnavailable)
    );
    assert_eq!(io.file(&path), prior);
    assert_eq!(reload.calls(), 0);
}

// Uses one exact bounded systemctl argv and rejects a nonzero native reload result.
#[test]
fn system_reload_uses_only_the_canonical_watchdog_signal_command() {
    for (status, expected) in [(0, Ok(())), (1, Err(ControllerError::ProviderUnavailable))] {
        let allowlist = Sha256Digest::parse(&"e".repeat(64)).expect("allowlist");
        let runner = Arc::new(CommandRunner {
            calls: Mutex::new(Vec::new()),
            status,
        });
        let reload = SystemCoreControllerAuthorizationReload::new_with_runner(
            PathBuf::from("/usr/bin/systemctl"),
            runner.clone(),
            Arc::new(Receipt(allowlist.clone())),
            Arc::new(Waiter),
        )
        .expect("reload");
        assert_eq!(reload.reload(&allowlist), expected);
        assert_eq!(
            runner.calls.lock().expect("command calls").as_slice(),
            &[(
                PathBuf::from("/usr/bin/systemctl"),
                vec![
                    "--user".to_string(),
                    "kill".to_string(),
                    "--signal=HUP".to_string(),
                    "li_watchdog.service".to_string(),
                ],
            )]
        );
    }
}

// Accepts only a checksum-valid same-installation snapshot carrying the exact allowlist identity.
#[test]
fn system_reload_receipt_rejects_snapshot_identity_or_checksum_drift() {
    let installation = InstallationId::parse(&"a".repeat(64)).expect("installation");
    let allowlist = Sha256Digest::parse(&"e".repeat(64)).expect("allowlist");
    let snapshot_file = PathBuf::from("/var/lib/letsinfer/controller-snapshot.json");
    let body = format!(
        "schema=li_watchdog.controller-registry\nversion=1\ninstallation_id={}\nallowlist_sha256={}\nrevision=2\n",
        installation.as_str(),
        allowlist.as_str(),
    );
    let snapshot = format!("{body}checksum={:08x}\n", watchdog_crc32(body.as_bytes()));
    let io = Arc::new(ProjectionIo::default());
    io.insert(snapshot_file.clone(), snapshot.as_bytes().to_vec());
    let receipt = SystemCoreControllerAuthorizationReloadReceipt::new(
        installation,
        snapshot_file.clone(),
        501,
        io.clone(),
    )
    .expect("receipt");
    assert_eq!(receipt.allowlist_sha256(), Ok(allowlist));

    let mut corrupt = snapshot.into_bytes();
    corrupt[20] ^= 1;
    io.insert(snapshot_file, corrupt);
    assert_eq!(
        receipt.allowlist_sha256(),
        Err(ControllerError::ProviderUnavailable)
    );
}
