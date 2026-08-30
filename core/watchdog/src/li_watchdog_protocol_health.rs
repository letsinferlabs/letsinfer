// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{InstallationId, NodeId, Sha256Digest};

use crate::WatchdogError;

const WATCHDOG_PROTOCOL_MAX_CORE_RELEASE_BYTES: usize = 127;

// Identifies the closed resident lifecycle exposed by Watchdog protocol version three.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogProtocolResidentLifecycle {
    Ready,
}

impl WatchdogProtocolResidentLifecycle {
    // Returns the exact protobuf enum value used by protocol version three.
    pub(crate) const fn wire_value(self) -> u64 {
        match self {
            Self::Ready => 1,
        }
    }

    // Parses one closed protobuf lifecycle value.
    pub(crate) fn from_wire(value: u64) -> Result<Self, WatchdogError> {
        match value {
            1 => Ok(Self::Ready),
            _ => Err(health_error("resident lifecycle is unsupported")),
        }
    }
}

// Proves one authenticated Watchdog resident is ready for an exact Core installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtocolResidentStatus {
    node_id: NodeId,
    core_release: String,
    core_source_identity: Sha256Digest,
    installation_id: InstallationId,
    lifecycle: WatchdogProtocolResidentLifecycle,
}

impl WatchdogProtocolResidentStatus {
    // Creates one ready resident identity after validating its bounded Core release.
    pub fn ready(
        node_id: NodeId,
        core_release: String,
        core_source_identity: Sha256Digest,
        installation_id: InstallationId,
    ) -> Result<Self, WatchdogError> {
        if core_release.is_empty()
            || core_release.len() > WATCHDOG_PROTOCOL_MAX_CORE_RELEASE_BYTES
            || core_release.chars().any(char::is_control)
            || core_release.chars().any(char::is_whitespace)
        {
            return Err(health_error("resident Core release is invalid"));
        }
        Ok(Self {
            node_id,
            core_release,
            core_source_identity,
            installation_id,
            lifecycle: WatchdogProtocolResidentLifecycle::Ready,
        })
    }

    // Returns the exact Node identity configured for this resident.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact Core release configured for this resident.
    pub fn core_release(&self) -> &str {
        &self.core_release
    }

    // Returns the immutable Core source manifest identity executed by this resident.
    pub const fn core_source_identity(&self) -> &Sha256Digest {
        &self.core_source_identity
    }

    // Returns the exact Core installation identity configured for this resident.
    pub const fn installation_id(&self) -> &InstallationId {
        &self.installation_id
    }

    // Returns the closed resident lifecycle.
    pub const fn lifecycle(&self) -> WatchdogProtocolResidentLifecycle {
        self.lifecycle
    }
}

// Creates one stable protocol contract failure without retaining untrusted bytes.
fn health_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("Watchdog protocol resident health", reason)
}
