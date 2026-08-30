// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Take};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{CredentialId, Sha256Digest};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

use crate::NodeProtectionConnectionRole;

#[cfg(target_os = "linux")]
const MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

// Carries the principal and fixed request family assigned before wire decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionPeerAuthorization {
    principal_id: CredentialId,
    role: NodeProtectionConnectionRole,
}

impl NodeProtectionPeerAuthorization {
    // Creates one listener-owned authorization result.
    pub const fn new(principal_id: CredentialId, role: NodeProtectionConnectionRole) -> Self {
        Self { principal_id, role }
    }

    // Returns the exact Node protection API principal.
    pub const fn principal_id(&self) -> &CredentialId {
        &self.principal_id
    }

    // Returns the immutable request family assigned to the connection.
    pub const fn role(&self) -> NodeProtectionConnectionRole {
        self.role
    }
}

// Assigns a connection role from kernel peer facts rather than its first request.
pub trait NodeProtectionPeerRoleProvider: Send + Sync {
    // Authenticates one kernel user and process identity before API mutation.
    fn authorize(
        &self,
        user_id: u32,
        process_id: u32,
    ) -> Result<NodeProtectionPeerAuthorization, NodeProtectionPeerRoleError>;
}

// Carries one bounded executable observation with start ticks on both sides of native reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionProcessIdentity {
    process_id: u32,
    start_ticks_before: u64,
    start_ticks_after: u64,
    executable_path: PathBuf,
    executable_sha256: Sha256Digest,
}

impl NodeProtectionProcessIdentity {
    // Creates one complete observation without judging whether its start ticks remained stable.
    pub fn new(
        process_id: u32,
        start_ticks_before: u64,
        start_ticks_after: u64,
        executable_path: PathBuf,
        executable_sha256: Sha256Digest,
    ) -> Result<Self, NodeProtectionPeerRoleError> {
        if process_id <= 1
            || start_ticks_before == 0
            || start_ticks_after == 0
            || !is_normal_absolute_path(&executable_path)
        {
            return Err(NodeProtectionPeerRoleError::AuthenticationFailed);
        }
        Ok(Self {
            process_id,
            start_ticks_before,
            start_ticks_after,
            executable_path,
            executable_sha256,
        })
    }
}

// Observes only the kernel process facts required by executable-role judgment.
pub trait NodeProtectionProcessIdentityProvider: Send + Sync {
    // Reads one bounded process observation without assigning a product role.
    fn identity(
        &self,
        process_id: u32,
    ) -> Result<NodeProtectionProcessIdentity, NodeProtectionPeerRoleError>;
}

// Reads Linux procfs process identity through one narrow native boundary.
#[derive(Default)]
pub struct SystemNodeProtectionProcessIdentityProvider;

impl NodeProtectionProcessIdentityProvider for SystemNodeProtectionProcessIdentityProvider {
    // Reads a Linux PID start/path/digest/start observation and rejects unsupported platforms.
    fn identity(
        &self,
        process_id: u32,
    ) -> Result<NodeProtectionProcessIdentity, NodeProtectionPeerRoleError> {
        #[cfg(target_os = "linux")]
        {
            let start_ticks_before = linux_process_start_ticks(process_id)?;
            let executable_link = PathBuf::from(format!("/proc/{process_id}/exe"));
            let executable_path = std::fs::read_link(&executable_link)
                .map_err(|_| NodeProtectionPeerRoleError::AuthenticationFailed)?;
            let executable_sha256 = executable_identity(&executable_link)?;
            let start_ticks_after = linux_process_start_ticks(process_id)?;
            return NodeProtectionProcessIdentity::new(
                process_id,
                start_ticks_before,
                start_ticks_after,
                executable_path,
                executable_sha256,
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = process_id;
            Err(NodeProtectionPeerRoleError::PlatformUnavailable)
        }
    }
}

// Names one expected immutable installed service executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedNodeProtectionExecutable {
    canonical_path: PathBuf,
    executable_sha256: Sha256Digest,
    principal_id: CredentialId,
    role: NodeProtectionConnectionRole,
}

impl ExpectedNodeProtectionExecutable {
    // Creates one expected executable only from an absolute normalized installed path.
    pub fn new(
        canonical_path: PathBuf,
        executable_sha256: Sha256Digest,
        principal_id: CredentialId,
        role: NodeProtectionConnectionRole,
    ) -> Result<Self, NodeProtectionPeerRoleError> {
        if !is_normal_absolute_path(&canonical_path) {
            return Err(NodeProtectionPeerRoleError::InvalidConfiguration);
        }
        Ok(Self {
            canonical_path,
            executable_sha256,
            principal_id,
            role,
        })
    }

    // Returns the exact canonical installed executable path.
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    // Returns the immutable installed executable content identity.
    pub const fn executable_sha256(&self) -> &Sha256Digest {
        &self.executable_sha256
    }

    // Returns the API principal assigned to this executable.
    pub const fn principal_id(&self) -> &CredentialId {
        &self.principal_id
    }

    // Returns the request family assigned to this executable.
    pub const fn role(&self) -> NodeProtectionConnectionRole {
        self.role
    }
}

// Authenticates Linux Gateway and Watchdog peers by kernel PID, installed path, and exact bytes.
pub struct SystemNodeProtectionPeerRoleProvider {
    owner_user_id: u32,
    gateway: ExpectedNodeProtectionExecutable,
    watchdog: ExpectedNodeProtectionExecutable,
    processes: Arc<dyn NodeProtectionProcessIdentityProvider>,
}

impl SystemNodeProtectionPeerRoleProvider {
    // Creates one closed two-role map whose executable and principal identities cannot overlap.
    pub fn new(
        owner_user_id: u32,
        gateway: ExpectedNodeProtectionExecutable,
        watchdog: ExpectedNodeProtectionExecutable,
        processes: Arc<dyn NodeProtectionProcessIdentityProvider>,
    ) -> Result<Self, NodeProtectionPeerRoleError> {
        if gateway.role() != NodeProtectionConnectionRole::Gateway
            || watchdog.role() != NodeProtectionConnectionRole::Watchdog
            || gateway.canonical_path() == watchdog.canonical_path()
            || gateway.executable_sha256() == watchdog.executable_sha256()
            || gateway.principal_id() == watchdog.principal_id()
        {
            return Err(NodeProtectionPeerRoleError::InvalidConfiguration);
        }
        Ok(Self {
            owner_user_id,
            gateway,
            watchdog,
            processes,
        })
    }

    // Creates the ordinary Linux verifier over the bounded procfs identity provider.
    pub fn new_system(
        owner_user_id: u32,
        gateway: ExpectedNodeProtectionExecutable,
        watchdog: ExpectedNodeProtectionExecutable,
    ) -> Result<Self, NodeProtectionPeerRoleError> {
        Self::new(
            owner_user_id,
            gateway,
            watchdog,
            Arc::new(SystemNodeProtectionProcessIdentityProvider),
        )
    }
}

impl NodeProtectionPeerRoleProvider for SystemNodeProtectionPeerRoleProvider {
    // Rejects stale PIDs, replaced paths, changed bytes, and unknown same-user executables.
    fn authorize(
        &self,
        user_id: u32,
        process_id: u32,
    ) -> Result<NodeProtectionPeerAuthorization, NodeProtectionPeerRoleError> {
        if user_id != self.owner_user_id || process_id <= 1 {
            return Err(NodeProtectionPeerRoleError::AuthenticationFailed);
        }
        let observed = self.processes.identity(process_id)?;
        if observed.process_id != process_id
            || observed.start_ticks_before != observed.start_ticks_after
        {
            return Err(NodeProtectionPeerRoleError::AuthenticationFailed);
        }
        let expected = [&self.gateway, &self.watchdog]
            .into_iter()
            .find(|candidate| candidate.canonical_path() == observed.executable_path)
            .ok_or(NodeProtectionPeerRoleError::AuthenticationFailed)?;
        if &observed.executable_sha256 != expected.executable_sha256() {
            return Err(NodeProtectionPeerRoleError::AuthenticationFailed);
        }
        Ok(NodeProtectionPeerAuthorization::new(
            expected.principal_id().clone(),
            expected.role(),
        ))
    }
}

// Names fixed redacted peer-role verification failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeProtectionPeerRoleError {
    InvalidConfiguration,
    AuthenticationFailed,
    PlatformUnavailable,
}

// Hashes one bounded executable opened through the live procfs process reference.
#[cfg(target_os = "linux")]
fn executable_identity(path: &Path) -> Result<Sha256Digest, NodeProtectionPeerRoleError> {
    let file = File::open(path).map_err(|_| NodeProtectionPeerRoleError::AuthenticationFailed)?;
    let metadata = file
        .metadata()
        .map_err(|_| NodeProtectionPeerRoleError::AuthenticationFailed)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAXIMUM_EXECUTABLE_BYTES {
        return Err(NodeProtectionPeerRoleError::AuthenticationFailed);
    }
    let mut reader = file.take(MAXIMUM_EXECUTABLE_BYTES + 1);
    digest_reader(&mut reader)
}

// Hashes one bounded reader and rejects content beyond the executable limit.
#[cfg(target_os = "linux")]
fn digest_reader(reader: &mut Take<File>) -> Result<Sha256Digest, NodeProtectionPeerRoleError> {
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| NodeProtectionPeerRoleError::AuthenticationFailed)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| NodeProtectionPeerRoleError::AuthenticationFailed)?,
            )
            .ok_or(NodeProtectionPeerRoleError::AuthenticationFailed)?;
        if total > MAXIMUM_EXECUTABLE_BYTES {
            return Err(NodeProtectionPeerRoleError::AuthenticationFailed);
        }
        digest.update(&buffer[..count]);
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| NodeProtectionPeerRoleError::AuthenticationFailed)
}

// Reads one Linux process start tick so PID reuse cannot cross the executable observation.
#[cfg(target_os = "linux")]
fn linux_process_start_ticks(process_id: u32) -> Result<u64, NodeProtectionPeerRoleError> {
    let stat = std::fs::read_to_string(format!("/proc/{process_id}/stat"))
        .map_err(|_| NodeProtectionPeerRoleError::AuthenticationFailed)?;
    let closing = stat
        .rfind(')')
        .ok_or(NodeProtectionPeerRoleError::AuthenticationFailed)?;
    stat.get(closing + 1..)
        .ok_or(NodeProtectionPeerRoleError::AuthenticationFailed)?
        .split_whitespace()
        .nth(19)
        .ok_or(NodeProtectionPeerRoleError::AuthenticationFailed)?
        .parse::<u64>()
        .ok()
        .filter(|ticks| *ticks > 0)
        .ok_or(NodeProtectionPeerRoleError::AuthenticationFailed)
}

// Returns whether a path is absolute and already free of dot or empty components.
fn is_normal_absolute_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    if !path.is_absolute()
        || text.len() <= 1
        || text.ends_with('/')
        || text.contains("//")
        || text
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return false;
    }
    path.components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}
