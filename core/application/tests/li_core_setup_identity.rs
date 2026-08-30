// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use li_core_application::{
    CoreSetupIdentityClock, CoreSetupIdentityProvider, CoreSetupIdentitySourceError,
    CoreSetupMachineIdentityProvider, CoreSetupNetworkPlan, CoreSetupProviderError,
    CoreSetupReceipt, CoreSetupRequest, DatabaseCoreSetupIdentityProvider,
};
use li_core_interface::{
    DisplayName, MachineId, NodeAddress, NodeRole, Sha256Digest, UnixMilliseconds,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
    CoreVersion,
};

// Supplies one exact machine identity or selected pre-mutation failure.
struct TestMachineIdentity {
    result: Result<MachineId, CoreSetupIdentitySourceError>,
    calls: AtomicUsize,
}

impl TestMachineIdentity {
    // Creates one successful deterministic native identity fixture.
    fn available() -> Self {
        Self::available_with('a')
    }

    // Creates one successful native identity fixture with an exact stable value.
    fn available_with(character: char) -> Self {
        Self {
            result: Ok(MachineId::parse(&character.to_string().repeat(32)).expect("machine")),
            calls: AtomicUsize::new(0),
        }
    }

    // Creates one selected native identity failure fixture.
    const fn failing(error: CoreSetupIdentitySourceError) -> Self {
        Self {
            result: Err(error),
            calls: AtomicUsize::new(0),
        }
    }
}

impl CoreSetupMachineIdentityProvider for TestMachineIdentity {
    // Returns the injected machine identity without touching the active host.
    fn machine_id(&self) -> Result<MachineId, CoreSetupIdentitySourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

// Supplies one exact setup timestamp or selected pre-mutation failure.
struct TestIdentityClock {
    result: Result<UnixMilliseconds, CoreSetupIdentitySourceError>,
    calls: AtomicUsize,
}

impl TestIdentityClock {
    // Creates one successful deterministic setup time.
    const fn available(value: u64) -> Self {
        Self {
            result: Ok(UnixMilliseconds::new(value)),
            calls: AtomicUsize::new(0),
        }
    }

    // Creates one selected clock failure fixture.
    const fn failing(error: CoreSetupIdentitySourceError) -> Self {
        Self {
            result: Err(error),
            calls: AtomicUsize::new(0),
        }
    }
}

impl CoreSetupIdentityClock for TestIdentityClock {
    // Returns the injected time without reading the wall clock.
    fn now(&self) -> Result<UnixMilliseconds, CoreSetupIdentitySourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result
    }
}

// Proves the production adapter persists every explicit standalone-main request input.
#[test]
fn database_identity_provider_preserves_every_public_request_input() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let database_file = temporary.path().join("core.sqlite3");
    let machine = Arc::new(TestMachineIdentity::available());
    let clock = Arc::new(TestIdentityClock::available(5_000));
    let provider =
        DatabaseCoreSetupIdentityProvider::new(database_file, machine.clone(), clock.clone());
    let request = request(1, CoreUpdateNodeRole::Main);
    let prepared = provider.prepare(&request).expect("prepare");
    assert_eq!(prepared.machine_id().as_str(), "a".repeat(32));
    assert_eq!(
        prepared.installation_id().as_str(),
        "b99e8d7ebba93caf346e9569c54af9ae390e3516e83b96afb5ea6dc7030fb2da"
    );
    assert_ne!(
        prepared.installation_id().as_str(),
        request.installation().source_identity().as_str()
    );
    assert_eq!(
        request.installation().source_identity().as_str(),
        "e".repeat(64)
    );
    assert_eq!(prepared.display_name(), request.display_name());
    assert_eq!(prepared.control_address(), request.control_address());
    assert_eq!(prepared.role(), NodeRole::Main);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(clock.calls.load(Ordering::SeqCst), 1);
}

// Proves one signed Core artifact receives independent installation identities on distinct hosts.
#[test]
fn database_identity_provider_separates_hosts_using_the_same_core_artifact() {
    let first_temporary = tempfile::tempdir().expect("first temporary directory");
    let second_temporary = tempfile::tempdir().expect("second temporary directory");
    let request = request(7, CoreUpdateNodeRole::Main);
    let first = DatabaseCoreSetupIdentityProvider::new(
        first_temporary.path().join("core.sqlite3"),
        Arc::new(TestMachineIdentity::available_with('a')),
        Arc::new(TestIdentityClock::available(5_000)),
    )
    .prepare(&request)
    .expect("first host");
    let second = DatabaseCoreSetupIdentityProvider::new(
        second_temporary.path().join("core.sqlite3"),
        Arc::new(TestMachineIdentity::available_with('b')),
        Arc::new(TestIdentityClock::available(5_000)),
    )
    .prepare(&request)
    .expect("second host");
    assert_ne!(first.machine_id(), second.machine_id());
    assert_ne!(first.installation_id(), second.installation_id());
    assert_eq!(
        request.installation().source_identity().as_str(),
        "e".repeat(64)
    );
}

// Proves separate installation requests on one host never reuse the installation identity.
#[test]
fn database_identity_provider_separates_installations_on_the_same_host() {
    let first_temporary = tempfile::tempdir().expect("first temporary directory");
    let second_temporary = tempfile::tempdir().expect("second temporary directory");
    let first_request = request(8, CoreUpdateNodeRole::Main);
    let second_request = request(9, CoreUpdateNodeRole::Main);
    let first = DatabaseCoreSetupIdentityProvider::new(
        first_temporary.path().join("core.sqlite3"),
        Arc::new(TestMachineIdentity::available()),
        Arc::new(TestIdentityClock::available(5_000)),
    )
    .prepare(&first_request)
    .expect("first installation");
    let second = DatabaseCoreSetupIdentityProvider::new(
        second_temporary.path().join("core.sqlite3"),
        Arc::new(TestMachineIdentity::available()),
        Arc::new(TestIdentityClock::available(5_000)),
    )
    .prepare(&second_request)
    .expect("second installation");
    assert_eq!(first.machine_id(), second.machine_id());
    assert_ne!(first.installation_id(), second.installation_id());
    assert_eq!(
        first_request.installation().source_identity(),
        second_request.installation().source_identity()
    );
}

// Proves child installation is a later pairing transition, never a setup-time DB mutation.
#[test]
fn database_identity_provider_rejects_child_before_native_reads_or_database_mutation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let database_file = temporary.path().join("core.sqlite3");
    let machine = Arc::new(TestMachineIdentity::available());
    let clock = Arc::new(TestIdentityClock::available(5_000));
    let provider = DatabaseCoreSetupIdentityProvider::new(
        database_file.clone(),
        machine.clone(),
        clock.clone(),
    );
    assert_eq!(
        provider.prepare(&request(2, CoreUpdateNodeRole::Child)),
        Err(CoreSetupProviderError::unchanged(
            "node identity",
            "standalone Core setup requires the main role"
        ))
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
    assert!(!database_file.exists());
}

// Proves adapter restart replays the durable receipt despite a later injected timestamp.
#[test]
fn database_identity_provider_restarts_with_the_exact_durable_closure() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let database_file = temporary.path().join("core.sqlite3");
    let request = request(3, CoreUpdateNodeRole::Main);
    let first = DatabaseCoreSetupIdentityProvider::new(
        database_file.clone(),
        Arc::new(TestMachineIdentity::available()),
        Arc::new(TestIdentityClock::available(5_000)),
    )
    .prepare(&request)
    .expect("first prepare");
    let replay = DatabaseCoreSetupIdentityProvider::new(
        database_file,
        Arc::new(TestMachineIdentity::available()),
        Arc::new(TestIdentityClock::available(9_000)),
    )
    .prepare(&request)
    .expect("replay");
    assert_eq!(replay, first);
}

// Proves native source failures are classified unchanged before any identity persistence call.
#[test]
fn database_identity_provider_classifies_injected_source_failures_before_mutation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let database_file = temporary.path().join("core.sqlite3");
    let clock = Arc::new(TestIdentityClock::available(5_000));
    let provider = DatabaseCoreSetupIdentityProvider::new(
        database_file.clone(),
        Arc::new(TestMachineIdentity::failing(
            CoreSetupIdentitySourceError::Unavailable,
        )),
        clock.clone(),
    );
    assert_eq!(
        provider.prepare(&request(4, CoreUpdateNodeRole::Main)),
        Err(CoreSetupProviderError::unchanged(
            "node identity",
            "native machine identity is unavailable"
        ))
    );
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);

    let provider = DatabaseCoreSetupIdentityProvider::new(
        database_file,
        Arc::new(TestMachineIdentity::available()),
        Arc::new(TestIdentityClock::failing(
            CoreSetupIdentitySourceError::Unavailable,
        )),
    );
    assert_eq!(
        provider.prepare(&request(5, CoreUpdateNodeRole::Main)),
        Err(CoreSetupProviderError::unchanged(
            "node identity",
            "setup clock is unavailable"
        ))
    );
}

// Proves exact receipt rollback is idempotent and a foreign receipt is never treated as owned.
#[test]
fn database_identity_provider_preserves_rollback_classification() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let provider = DatabaseCoreSetupIdentityProvider::new(
        temporary.path().join("core.sqlite3"),
        Arc::new(TestMachineIdentity::available()),
        Arc::new(TestIdentityClock::available(5_000)),
    );
    let prepared = provider
        .prepare(&request(6, CoreUpdateNodeRole::Main))
        .expect("prepare");
    assert_eq!(
        provider.rollback(&CoreSetupReceipt::new(digest('f'))),
        Err(CoreSetupProviderError::unchanged(
            "node identity",
            "rollback receipt does not own local identity"
        ))
    );
    provider.rollback(prepared.receipt()).expect("rollback");
    provider
        .rollback(prepared.receipt())
        .expect("rollback replay");
}

// Creates one exact setup request with every listener and installation identity explicit.
fn request(index: u8, role: CoreUpdateNodeRole) -> CoreSetupRequest {
    CoreSetupRequest::new(
        digest(char::from_digit(u32::from(index), 10).expect("request digit")),
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, role),
        CoreInstallation::new(
            CoreVersion::parse("0.12.0-rc.1").expect("version"),
            digest('e'),
        ),
        DisplayName::parse("Home AI").expect("display name"),
        NodeAddress::parse("homeai.local").expect("control address"),
        CoreSetupNetworkPlan::new(
            address(9443),
            address(9444),
            (role == CoreUpdateNodeRole::Main).then(|| address(11434)),
            Some(address(7443)),
        ),
    )
}

// Creates one explicit loopback socket address.
const fn address(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

// Creates one canonical SHA-256 identity fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}
