// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{ControllerId, DisplayName, Sha256Digest, UnixMilliseconds};

use crate::{ControllerCertificate, ControllerError};

// Names the durable authorization level assigned to one controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerRole {
    Viewer,
    Operator,
    Administrator,
}

impl ControllerRole {
    // Returns whether this role satisfies one exact minimum authorization level.
    pub const fn permits(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }

    // Returns the closed persistence and wire spelling for this role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Administrator => "administrator",
        }
    }

    // Parses one closed role without accepting aliases or case folding.
    pub fn parse(value: &str) -> Result<Self, ControllerError> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "administrator" => Ok(Self::Administrator),
            _ => Err(ControllerError::InvalidRecord {
                reason: "controller role is invalid",
            }),
        }
    }

    // Returns the stable ordering used only for role policy.
    const fn rank(self) -> u8 {
        match self {
            Self::Viewer => 0,
            Self::Operator => 1,
            Self::Administrator => 2,
        }
    }
}

// Names whether one controller certificate awaits activation, authorizes, or is terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerState {
    Issued,
    Active,
    Revoked,
}

impl ControllerState {
    // Returns the closed persistence and wire spelling for this lifecycle state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    // Parses one closed state without inventing a compatibility mapping.
    pub fn parse(value: &str) -> Result<Self, ControllerError> {
        match value {
            "issued" => Ok(Self::Issued),
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            _ => Err(ControllerError::InvalidRecord {
                reason: "controller state is invalid",
            }),
        }
    }
}

// Stores one controller identity, public certificate, role, and durable lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Controller {
    controller_id: ControllerId,
    name: DisplayName,
    role: ControllerRole,
    certificate: ControllerCertificate,
    state: ControllerState,
    issued_at: UnixMilliseconds,
    activated_at: Option<UnixMilliseconds>,
    revoked_at: Option<UnixMilliseconds>,
}

impl Controller {
    // Creates one newly issued controller that cannot authorize before explicit activation.
    pub fn issued(
        controller_id: ControllerId,
        name: DisplayName,
        role: ControllerRole,
        certificate: ControllerCertificate,
        issued_at: UnixMilliseconds,
    ) -> Result<Self, ControllerError> {
        Self::restore(
            controller_id,
            name,
            role,
            certificate,
            ControllerState::Issued,
            issued_at,
            None,
            None,
        )
    }

    // Reconstructs one controller only when identity, certificate, state, and times agree.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        controller_id: ControllerId,
        name: DisplayName,
        role: ControllerRole,
        certificate: ControllerCertificate,
        state: ControllerState,
        issued_at: UnixMilliseconds,
        activated_at: Option<UnixMilliseconds>,
        revoked_at: Option<UnixMilliseconds>,
    ) -> Result<Self, ControllerError> {
        let lifecycle_valid = match state {
            ControllerState::Issued => activated_at.is_none() && revoked_at.is_none(),
            ControllerState::Active => activated_at.is_some() && revoked_at.is_none(),
            ControllerState::Revoked => revoked_at.is_some(),
        };
        if certificate.controller_id() != &controller_id
            || !certificate.is_valid_at(issued_at)
            || !lifecycle_valid
            || activated_at.is_some_and(|value| value < issued_at)
            || revoked_at.is_some_and(|value| {
                value < issued_at || activated_at.is_some_and(|activated| value < activated)
            })
        {
            return Err(ControllerError::InvalidRecord {
                reason: "controller lifecycle is inconsistent",
            });
        }
        Ok(Self {
            controller_id,
            name,
            role,
            certificate,
            state,
            issued_at,
            activated_at,
            revoked_at,
        })
    }

    // Returns the stable controller identity independently of certificate replacement.
    pub const fn controller_id(&self) -> &ControllerId {
        &self.controller_id
    }

    // Returns the user-facing controller name.
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    // Returns the durable controller authorization role.
    pub const fn role(&self) -> ControllerRole {
        self.role
    }

    // Returns the exact provider-validated public certificate.
    pub const fn certificate(&self) -> &ControllerCertificate {
        &self.certificate
    }

    // Returns the durable lifecycle state.
    pub const fn state(&self) -> ControllerState {
        self.state
    }

    // Returns when this exact certificate was accepted into the registry.
    pub const fn issued_at(&self) -> UnixMilliseconds {
        self.issued_at
    }

    // Returns when this exact certificate became authorized.
    pub const fn activated_at(&self) -> Option<UnixMilliseconds> {
        self.activated_at
    }

    // Returns when this exact controller authorization was revoked.
    pub const fn revoked_at(&self) -> Option<UnixMilliseconds> {
        self.revoked_at
    }

    // Returns an active copy after checking issuance and certificate lifetime.
    pub fn activated(&self, now: UnixMilliseconds) -> Result<Self, ControllerError> {
        if self.state == ControllerState::Revoked || !self.certificate.is_valid_at(now) {
            return Err(ControllerError::InvalidTransition);
        }
        if self.state == ControllerState::Active {
            return Ok(self.clone());
        }
        Self::restore(
            self.controller_id.clone(),
            self.name.clone(),
            self.role,
            self.certificate.clone(),
            ControllerState::Active,
            self.issued_at,
            Some(now),
            None,
        )
    }

    // Returns a terminally revoked copy without changing certificate or role identity.
    pub fn revoked(&self, now: UnixMilliseconds) -> Result<Self, ControllerError> {
        if self.state == ControllerState::Revoked {
            return Ok(self.clone());
        }
        Self::restore(
            self.controller_id.clone(),
            self.name.clone(),
            self.role,
            self.certificate.clone(),
            ControllerState::Revoked,
            self.issued_at,
            self.activated_at,
            Some(now),
        )
    }

    // Returns whether an issuance request exactly replays this durable registration.
    pub(crate) fn matches_registration(
        &self,
        name: &DisplayName,
        role: ControllerRole,
        certificate: &ControllerCertificate,
    ) -> bool {
        self.name == *name && self.role == role && self.certificate == *certificate
    }
}

// Carries one currently authorized controller identity and role to a policy consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerPrincipal {
    controller_id: ControllerId,
    role: ControllerRole,
    certificate_sha256: Sha256Digest,
}

impl ControllerPrincipal {
    // Creates one principal only after the manager revalidates durable active state.
    pub(crate) fn new(controller: &Controller) -> Self {
        Self {
            controller_id: controller.controller_id.clone(),
            role: controller.role,
            certificate_sha256: controller.certificate.certificate_sha256().clone(),
        }
    }

    // Returns the exact authorized controller identity.
    pub const fn controller_id(&self) -> &ControllerId {
        &self.controller_id
    }

    // Returns the durable role that satisfied policy.
    pub const fn role(&self) -> ControllerRole {
        self.role
    }

    // Returns the exact public certificate fingerprint used by this authorization.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }
}
