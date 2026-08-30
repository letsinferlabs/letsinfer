// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use li_core_interface::{CredentialId, Sha256Digest};
use li_node_manager::{
    ExpectedNodeProtectionExecutable, NodeProtectionConnectionRole, NodeProtectionPeerRoleError,
    NodeProtectionPeerRoleProvider, NodeProtectionProcessIdentity,
    NodeProtectionProcessIdentityProvider, SystemNodeProtectionPeerRoleProvider,
};

const OWNER_USER_ID: u32 = 501;
const PROCESS_ID: u32 = 42;

// Supplies exact process observations and native failures in deterministic order.
struct ProcessIdentityProviderMock(
    Mutex<VecDeque<Result<NodeProtectionProcessIdentity, NodeProtectionPeerRoleError>>>,
);

impl NodeProtectionProcessIdentityProvider for ProcessIdentityProviderMock {
    // Returns the next exact process observation without performing native I/O.
    fn identity(
        &self,
        _process_id: u32,
    ) -> Result<NodeProtectionProcessIdentity, NodeProtectionPeerRoleError> {
        self.0
            .lock()
            .expect("observations")
            .pop_front()
            .expect("expected observation")
    }
}

// Returns one repeated lowercase hexadecimal identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical digest.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns one canonical credential identity.
fn principal(character: char) -> CredentialId {
    CredentialId::parse(&identity(character, 32)).expect("principal")
}

// Returns one expected Gateway executable identity.
fn gateway_executable() -> ExpectedNodeProtectionExecutable {
    ExpectedNodeProtectionExecutable::new(
        PathBuf::from("/opt/letsinfer/bin/li_gateway"),
        digest('a'),
        principal('1'),
        NodeProtectionConnectionRole::Gateway,
    )
    .expect("Gateway executable")
}

// Returns one expected Watchdog executable identity.
fn watchdog_executable() -> ExpectedNodeProtectionExecutable {
    ExpectedNodeProtectionExecutable::new(
        PathBuf::from("/opt/letsinfer/bin/li_watchdog"),
        digest('b'),
        principal('2'),
        NodeProtectionConnectionRole::Watchdog,
    )
    .expect("Watchdog executable")
}

// Returns one process observation for an exact path, digest, PID, and start-tick pair.
fn observation(
    process_id: u32,
    start_ticks_before: u64,
    start_ticks_after: u64,
    path: &str,
    executable_sha256: Sha256Digest,
) -> NodeProtectionProcessIdentity {
    NodeProtectionProcessIdentity::new(
        process_id,
        start_ticks_before,
        start_ticks_after,
        PathBuf::from(path),
        executable_sha256,
    )
    .expect("observation")
}

// Creates the production role judgment over injected process-native observations.
fn provider(
    observations: Vec<Result<NodeProtectionProcessIdentity, NodeProtectionPeerRoleError>>,
) -> SystemNodeProtectionPeerRoleProvider {
    SystemNodeProtectionPeerRoleProvider::new(
        OWNER_USER_ID,
        gateway_executable(),
        watchdog_executable(),
        Arc::new(ProcessIdentityProviderMock(Mutex::new(observations.into()))),
    )
    .expect("provider")
}

// Proves exact executable observations select only their preconfigured immutable role.
#[test]
fn exact_gateway_and_watchdog_executables_receive_distinct_roles() {
    let provider = provider(vec![
        Ok(observation(
            PROCESS_ID,
            10,
            10,
            "/opt/letsinfer/bin/li_gateway",
            digest('a'),
        )),
        Ok(observation(
            PROCESS_ID,
            11,
            11,
            "/opt/letsinfer/bin/li_watchdog",
            digest('b'),
        )),
    ]);
    let gateway = provider
        .authorize(OWNER_USER_ID, PROCESS_ID)
        .expect("Gateway authorization");
    assert_eq!(gateway.role(), NodeProtectionConnectionRole::Gateway);
    assert_eq!(gateway.principal_id(), &principal('1'));
    let watchdog = provider
        .authorize(OWNER_USER_ID, PROCESS_ID)
        .expect("Watchdog authorization");
    assert_eq!(watchdog.role(), NodeProtectionConnectionRole::Watchdog);
    assert_eq!(watchdog.principal_id(), &principal('2'));
}

// Proves every stale, replaced, deleted, foreign, or unknown executable observation fails closed.
#[test]
fn process_identity_mutation_matrix_never_assigns_a_role() {
    let mutations = vec![
        (
            OWNER_USER_ID + 1,
            PROCESS_ID,
            Ok(observation(
                PROCESS_ID,
                10,
                10,
                "/opt/letsinfer/bin/li_gateway",
                digest('a'),
            )),
        ),
        (
            OWNER_USER_ID,
            PROCESS_ID,
            Ok(observation(
                PROCESS_ID + 1,
                10,
                10,
                "/opt/letsinfer/bin/li_gateway",
                digest('a'),
            )),
        ),
        (
            OWNER_USER_ID,
            PROCESS_ID,
            Ok(observation(
                PROCESS_ID,
                10,
                11,
                "/opt/letsinfer/bin/li_gateway",
                digest('a'),
            )),
        ),
        (
            OWNER_USER_ID,
            PROCESS_ID,
            Ok(observation(
                PROCESS_ID,
                10,
                10,
                "/opt/letsinfer/bin/li_gateway.replaced",
                digest('a'),
            )),
        ),
        (
            OWNER_USER_ID,
            PROCESS_ID,
            Ok(observation(
                PROCESS_ID,
                10,
                10,
                "/opt/letsinfer/bin/li_gateway",
                digest('c'),
            )),
        ),
        (
            OWNER_USER_ID,
            PROCESS_ID,
            Err(NodeProtectionPeerRoleError::AuthenticationFailed),
        ),
    ];
    for (user_id, process_id, process) in mutations {
        assert_eq!(
            provider(vec![process]).authorize(user_id, process_id),
            Err(NodeProtectionPeerRoleError::AuthenticationFailed)
        );
    }
}

// Proves a Gateway executable cannot claim Watchdog merely by sending a Watchdog request first.
#[test]
fn gateway_executable_is_never_promoted_to_watchdog() {
    let provider = provider(vec![Ok(observation(
        PROCESS_ID,
        10,
        10,
        "/opt/letsinfer/bin/li_gateway",
        digest('a'),
    ))]);
    let authorization = provider
        .authorize(OWNER_USER_ID, PROCESS_ID)
        .expect("Gateway authorization");
    assert_eq!(authorization.role(), NodeProtectionConnectionRole::Gateway);
    assert_ne!(authorization.role(), NodeProtectionConnectionRole::Watchdog);
}

// Proves overlapping paths, digests, principals, and swapped roles cannot form a role map.
#[test]
fn executable_role_configuration_is_closed_and_disjoint() {
    let processes = || {
        Arc::new(ProcessIdentityProviderMock(Mutex::new(VecDeque::new())))
            as Arc<dyn NodeProtectionProcessIdentityProvider>
    };
    let invalid_watchdogs = [
        ExpectedNodeProtectionExecutable::new(
            PathBuf::from("/opt/letsinfer/bin/li_gateway"),
            digest('b'),
            principal('2'),
            NodeProtectionConnectionRole::Watchdog,
        )
        .expect("same path"),
        ExpectedNodeProtectionExecutable::new(
            PathBuf::from("/opt/letsinfer/bin/li_watchdog"),
            digest('a'),
            principal('2'),
            NodeProtectionConnectionRole::Watchdog,
        )
        .expect("same digest"),
        ExpectedNodeProtectionExecutable::new(
            PathBuf::from("/opt/letsinfer/bin/li_watchdog"),
            digest('b'),
            principal('1'),
            NodeProtectionConnectionRole::Watchdog,
        )
        .expect("same principal"),
        ExpectedNodeProtectionExecutable::new(
            PathBuf::from("/opt/letsinfer/bin/li_watchdog"),
            digest('b'),
            principal('2'),
            NodeProtectionConnectionRole::Gateway,
        )
        .expect("wrong role"),
    ];
    for watchdog in invalid_watchdogs {
        assert!(SystemNodeProtectionPeerRoleProvider::new(
            OWNER_USER_ID,
            gateway_executable(),
            watchdog,
            processes(),
        )
        .is_err());
    }
}
