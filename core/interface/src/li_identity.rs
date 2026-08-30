// SPDX-License-Identifier: AGPL-3.0-only

use crate::InterfaceError;

const IDENTITY_LENGTH: usize = 32;

// Stores one validated lowercase 128-bit hexadecimal identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct IdentityValue(String);

impl IdentityValue {
    // Validates one canonical Core identity without assigning its semantic type.
    fn parse(value: &str, subject: &'static str) -> Result<Self, InterfaceError> {
        if !is_lower_hex(value, IDENTITY_LENGTH) {
            return Err(InterfaceError::new(
                subject,
                "identity must be exactly 32 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the canonical identity bytes as text.
    fn as_str(&self) -> &str {
        &self.0
    }
}

// Identifies one enrolled Let's Infer node.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(IdentityValue);

impl NodeId {
    // Parses one canonical node identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "node identity").map(Self)
    }

    // Returns the canonical node identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one physical host independently of its node membership.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MachineId(IdentityValue);

impl MachineId {
    // Parses one canonical physical-machine identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "machine identity").map(Self)
    }

    // Returns the canonical physical-machine identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one installed Core instance on a physical host.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InstallationId(String);

impl InstallationId {
    // Parses one canonical Core installation identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        if !is_lower_hex(value, 64) {
            return Err(InterfaceError::new(
                "installation identity",
                "identity must be exactly 64 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the canonical Core installation identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Identifies one timestamped hardware observation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HardwareObservationId(IdentityValue);

impl HardwareObservationId {
    // Parses one canonical hardware-observation identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "hardware observation identity").map(Self)
    }

    // Returns the canonical hardware-observation identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one exact host-local model and runtime materialization.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeInstallationId(IdentityValue);

impl RuntimeInstallationId {
    // Parses one canonical runtime-installation identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "runtime installation identity").map(Self)
    }

    // Returns the canonical runtime-installation identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one logical model service owned by the main node.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelServiceId(IdentityValue);

impl ModelServiceId {
    // Parses one canonical model-service identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "model service identity").map(Self)
    }

    // Returns the canonical model-service identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one atomic runtime execution and endpoint.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlacementGroupId(IdentityValue);

impl PlacementGroupId {
    // Parses one canonical placement-group identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "placement group identity").map(Self)
    }

    // Returns the canonical placement-group identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one exact task and resource assignment on a node.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlacementId(IdentityValue);

impl PlacementId {
    // Parses one canonical placement identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "placement identity").map(Self)
    }

    // Returns the canonical placement identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one exclusive resource reservation owned by a placement.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceLeaseId(IdentityValue);

impl ResourceLeaseId {
    // Parses one canonical resource-lease identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "resource lease identity").map(Self)
    }

    // Returns the canonical resource-lease identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one long-running Core operation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId(IdentityValue);

impl OperationId {
    // Parses one canonical operation identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "operation identity").map(Self)
    }

    // Returns the canonical operation identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies secret material without exposing its path or contents.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialId(IdentityValue);

impl CredentialId {
    // Parses one canonical credential identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "credential identity").map(Self)
    }

    // Returns the canonical credential identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one paired controller independently of its replaceable certificate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ControllerId(IdentityValue);

impl ControllerId {
    // Parses one canonical controller identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "controller identity").map(Self)
    }

    // Returns the canonical controller identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one inference API key without exposing its secret.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApiKeyId(IdentityValue);

impl ApiKeyId {
    // Parses one canonical inference API-key identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "API key identity").map(Self)
    }

    // Returns the canonical inference API-key identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Identifies one bounded one-use node-pairing invitation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PairingInviteId(IdentityValue);

impl PairingInviteId {
    // Parses one canonical pairing-invitation identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        IdentityValue::parse(value, "pairing invitation identity").map(Self)
    }

    // Returns the canonical pairing-invitation identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Returns whether one identity is exact lowercase hexadecimal text.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
