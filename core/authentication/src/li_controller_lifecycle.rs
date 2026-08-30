// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use li_core_interface::{ControllerId, DisplayName, Sha256Digest, UnixMilliseconds};

use crate::{
    AuthenticationChange, AuthenticationError, AuthenticationEvent, AuthenticationManager,
    AuthenticationStoreError, Controller, ControllerCertificate, ControllerCertificateMaterial,
    ControllerError, ControllerPrincipal, ControllerPublicKey, ControllerRole, ControllerState,
    VersionedController,
};

// Selects whether explicit replacement issues from a public key or imports a certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControllerCertificateSource {
    Issue(ControllerPublicKey),
    Import(ControllerCertificateMaterial),
}

// Names the committed event for one ordinary first registration.
#[derive(Clone, Copy)]
enum ControllerRegistrationKind {
    Issued,
    Imported,
}

impl AuthenticationManager {
    // Atomically registers one confirmed controller as active without persisting partial issuance.
    pub fn enroll_controller(
        &self,
        controller_id: ControllerId,
        name: DisplayName,
        role: ControllerRole,
        public_key: ControllerPublicKey,
    ) -> Result<AuthenticationChange<Controller>, ControllerError> {
        if let Some(current) = self.controller_store.read(&controller_id)? {
            require_controller_read(&current, &controller_id)?;
            return self.replace_controller(
                &controller_id,
                name,
                role,
                ControllerCertificateSource::Issue(public_key),
            );
        }
        let certificate = self
            .controller_certificates
            .issue(&controller_id, &public_key)?;
        if certificate.public_key_sha256() != public_key.sha256() {
            return Err(ControllerError::InvalidCertificate);
        }
        let now = self.controller_now()?;
        require_current_certificate(&certificate, &controller_id, now)?;
        require_unique_certificate(
            self.controller_store.all()?,
            &controller_id,
            certificate.certificate_sha256(),
        )?;
        let controller = Controller::issued(controller_id.clone(), name, role, certificate, now)?
            .activated(now)?;
        match self.controller_store.create(controller.clone()) {
            Ok(stored) => {
                require_controller_commit(&stored, &controller, 0)?;
                Ok(AuthenticationChange::new(
                    stored.controller().clone(),
                    Some(AuthenticationEvent::ControllerEnrolled { controller_id }),
                ))
            }
            Err(AuthenticationStoreError::Conflict) => {
                let observed = self
                    .controller_store
                    .read(&controller_id)?
                    .ok_or(AuthenticationStoreError::Conflict)?;
                require_controller_read(&observed, &controller_id)?;
                if observed.controller() == &controller {
                    Ok(AuthenticationChange::new(
                        observed.controller().clone(),
                        None,
                    ))
                } else {
                    Err(AuthenticationStoreError::Conflict.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    // Issues and stores one inactive certificate through the injected controller trust authority.
    pub fn issue_controller(
        &self,
        controller_id: ControllerId,
        name: DisplayName,
        role: ControllerRole,
        public_key: ControllerPublicKey,
    ) -> Result<AuthenticationChange<Controller>, ControllerError> {
        if let Some(replay) =
            self.replay_controller_registration(&controller_id, &name, role, |controller| {
                controller.certificate().public_key_sha256() == public_key.sha256()
            })?
        {
            return Ok(replay);
        }
        let certificate = self
            .controller_certificates
            .issue(&controller_id, &public_key)?;
        if certificate.public_key_sha256() != public_key.sha256() {
            return Err(ControllerError::InvalidCertificate);
        }
        self.register_controller(
            controller_id,
            name,
            role,
            certificate,
            ControllerRegistrationKind::Issued,
        )
    }

    // Validates and stores one inactive imported public certificate through the injected provider.
    pub fn import_controller(
        &self,
        controller_id: ControllerId,
        name: DisplayName,
        role: ControllerRole,
        material: ControllerCertificateMaterial,
    ) -> Result<AuthenticationChange<Controller>, ControllerError> {
        if let Some(replay) =
            self.replay_controller_registration(&controller_id, &name, role, |controller| {
                controller.certificate().public_material() == material.bytes()
            })?
        {
            return Ok(replay);
        }
        let certificate = self
            .controller_certificates
            .import(&controller_id, &material)?;
        self.register_controller(
            controller_id,
            name,
            role,
            certificate,
            ControllerRegistrationKind::Imported,
        )
    }

    // Explicitly replaces one controller certificate and atomically restores active authorization.
    pub fn replace_controller(
        &self,
        controller_id: &ControllerId,
        name: DisplayName,
        role: ControllerRole,
        source: ControllerCertificateSource,
    ) -> Result<AuthenticationChange<Controller>, ControllerError> {
        let current = self
            .controller_store
            .read(controller_id)?
            .ok_or(ControllerError::NotFound)?;
        require_controller_read(&current, controller_id)?;
        let exact_source = match &source {
            ControllerCertificateSource::Issue(public_key) => {
                current.controller().certificate().public_key_sha256() == public_key.sha256()
            }
            ControllerCertificateSource::Import(material) => {
                current.controller().certificate().public_material() == material.bytes()
            }
        };
        if current.controller().state() == ControllerState::Active
            && current.controller().name() == &name
            && current.controller().role() == role
            && exact_source
        {
            return Ok(AuthenticationChange::new(
                current.controller().clone(),
                None,
            ));
        }
        let certificate = self.resolve_certificate(controller_id, &source)?;
        let now = self.controller_now()?;
        require_current_certificate(&certificate, controller_id, now)?;
        if current
            .controller()
            .matches_registration(&name, role, &certificate)
            && current.controller().state() == ControllerState::Active
        {
            return Ok(AuthenticationChange::new(
                current.controller().clone(),
                None,
            ));
        }
        require_unique_certificate(
            self.controller_store.all()?,
            controller_id,
            certificate.certificate_sha256(),
        )?;
        let replacement = Controller::issued(controller_id.clone(), name, role, certificate, now)?
            .activated(now)?;
        match self
            .controller_store
            .replace(replacement.clone(), current.revision())
        {
            Ok(stored) => {
                require_controller_commit(&stored, &replacement, current.revision())?;
                Ok(AuthenticationChange::new(
                    stored.controller().clone(),
                    Some(AuthenticationEvent::ControllerReplaced {
                        controller_id: controller_id.clone(),
                    }),
                ))
            }
            Err(AuthenticationStoreError::Conflict) => {
                let observed = self
                    .controller_store
                    .read(controller_id)?
                    .ok_or(ControllerError::NotFound)?;
                require_controller_read(&observed, controller_id)?;
                if observed.controller() == &replacement {
                    Ok(AuthenticationChange::new(
                        observed.controller().clone(),
                        None,
                    ))
                } else {
                    Err(AuthenticationStoreError::Conflict.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    // Activates one exact issued controller after rechecking its certificate lifetime.
    pub fn activate_controller(
        &self,
        controller_id: &ControllerId,
    ) -> Result<AuthenticationChange<Controller>, ControllerError> {
        let current = self
            .controller_store
            .read(controller_id)?
            .ok_or(ControllerError::NotFound)?;
        require_controller_read(&current, controller_id)?;
        if current.controller().state() == ControllerState::Active {
            return Ok(AuthenticationChange::new(
                current.controller().clone(),
                None,
            ));
        }
        if current.controller().state() == ControllerState::Revoked {
            return Err(ControllerError::InvalidTransition);
        }
        let now = self.controller_now()?;
        require_certificate_lifetime(current.controller().certificate(), now)?;
        let active = current.controller().activated(now)?;
        self.replace_controller_state(
            current,
            active,
            AuthenticationEvent::ControllerActivated {
                controller_id: controller_id.clone(),
            },
        )
    }

    // Revokes one issued or active controller and suppresses duplicate terminal events.
    pub fn revoke_controller(
        &self,
        controller_id: &ControllerId,
    ) -> Result<AuthenticationChange<Controller>, ControllerError> {
        let current = self
            .controller_store
            .read(controller_id)?
            .ok_or(ControllerError::NotFound)?;
        require_controller_read(&current, controller_id)?;
        if current.controller().state() == ControllerState::Revoked {
            return Ok(AuthenticationChange::new(
                current.controller().clone(),
                None,
            ));
        }
        let revoked = current.controller().revoked(self.controller_now()?)?;
        self.replace_controller_state(
            current,
            revoked,
            AuthenticationEvent::ControllerRevoked {
                controller_id: controller_id.clone(),
            },
        )
    }

    // Returns one controller metadata snapshot without private material.
    pub fn controller(&self, controller_id: &ControllerId) -> Result<Controller, ControllerError> {
        let stored = self
            .controller_store
            .read(controller_id)?
            .ok_or(ControllerError::NotFound)?;
        require_controller_read(&stored, controller_id)?;
        Ok(stored.controller().clone())
    }

    // Returns every controller in stable identity order after complete uniqueness validation.
    pub fn controllers(&self) -> Result<Vec<Controller>, ControllerError> {
        let stored = self.controller_store.all()?;
        require_controller_records(&stored)?;
        let mut controllers = stored
            .into_iter()
            .map(|value| value.controller().clone())
            .collect::<Vec<_>>();
        controllers.sort_by(|left, right| {
            left.controller_id()
                .as_str()
                .cmp(right.controller_id().as_str())
        });
        Ok(controllers)
    }

    // Revalidates exact identity, certificate, state, lifetime, and minimum role per action.
    pub fn authorize_controller(
        &self,
        controller_id: &ControllerId,
        certificate_sha256: &Sha256Digest,
        minimum_role: ControllerRole,
    ) -> Result<ControllerPrincipal, ControllerError> {
        let stored = self
            .controller_store
            .read(controller_id)?
            .ok_or(ControllerError::Unauthorized)?;
        require_controller_read(&stored, controller_id)?;
        let controller = stored.controller();
        let now = self.controller_now()?;
        if controller.state() != ControllerState::Active
            || controller.certificate().certificate_sha256() != certificate_sha256
            || !controller.certificate().is_valid_at(now)
            || !controller.role().permits(minimum_role)
        {
            return Err(ControllerError::Unauthorized);
        }
        Ok(ControllerPrincipal::new(controller))
    }

    // Commits one first issuance or returns an exact nonterminal/active replay.
    fn register_controller(
        &self,
        controller_id: ControllerId,
        name: DisplayName,
        role: ControllerRole,
        certificate: ControllerCertificate,
        kind: ControllerRegistrationKind,
    ) -> Result<AuthenticationChange<Controller>, ControllerError> {
        let now = self.controller_now()?;
        require_current_certificate(&certificate, &controller_id, now)?;
        if let Some(existing) = self.controller_store.read(&controller_id)? {
            require_controller_read(&existing, &controller_id)?;
            if existing.controller().state() != ControllerState::Revoked
                && existing
                    .controller()
                    .matches_registration(&name, role, &certificate)
            {
                return Ok(AuthenticationChange::new(
                    existing.controller().clone(),
                    None,
                ));
            }
            return Err(AuthenticationStoreError::Conflict.into());
        }
        require_unique_certificate(
            self.controller_store.all()?,
            &controller_id,
            certificate.certificate_sha256(),
        )?;
        let controller = Controller::issued(controller_id.clone(), name, role, certificate, now)?;
        match self.controller_store.create(controller.clone()) {
            Ok(stored) => {
                require_controller_commit(&stored, &controller, 0)?;
                let event = match kind {
                    ControllerRegistrationKind::Issued => {
                        AuthenticationEvent::ControllerIssued { controller_id }
                    }
                    ControllerRegistrationKind::Imported => {
                        AuthenticationEvent::ControllerImported { controller_id }
                    }
                };
                Ok(AuthenticationChange::new(
                    stored.controller().clone(),
                    Some(event),
                ))
            }
            Err(AuthenticationStoreError::Conflict) => {
                let observed = self
                    .controller_store
                    .read(&controller_id)?
                    .ok_or(AuthenticationStoreError::Conflict)?;
                require_controller_read(&observed, &controller_id)?;
                if observed.controller() == &controller {
                    Ok(AuthenticationChange::new(
                        observed.controller().clone(),
                        None,
                    ))
                } else {
                    Err(AuthenticationStoreError::Conflict.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    // Returns an exact nonrevoked registration replay before invoking a mutable certificate provider.
    fn replay_controller_registration(
        &self,
        controller_id: &ControllerId,
        name: &DisplayName,
        role: ControllerRole,
        material_matches: impl FnOnce(&Controller) -> bool,
    ) -> Result<Option<AuthenticationChange<Controller>>, ControllerError> {
        let Some(existing) = self.controller_store.read(controller_id)? else {
            return Ok(None);
        };
        require_controller_read(&existing, controller_id)?;
        if existing.controller().state() != ControllerState::Revoked
            && existing.controller().name() == name
            && existing.controller().role() == role
            && material_matches(existing.controller())
        {
            Ok(Some(AuthenticationChange::new(
                existing.controller().clone(),
                None,
            )))
        } else {
            Err(AuthenticationStoreError::Conflict.into())
        }
    }

    // Resolves one explicit issue/import replacement source through the injected provider.
    fn resolve_certificate(
        &self,
        controller_id: &ControllerId,
        source: &ControllerCertificateSource,
    ) -> Result<ControllerCertificate, ControllerError> {
        match source {
            ControllerCertificateSource::Issue(public_key) => {
                let certificate = self
                    .controller_certificates
                    .issue(controller_id, public_key)?;
                if certificate.public_key_sha256() != public_key.sha256() {
                    return Err(ControllerError::InvalidCertificate);
                }
                Ok(certificate)
            }
            ControllerCertificateSource::Import(material) => Ok(self
                .controller_certificates
                .import(controller_id, material)?),
        }
    }

    // Replaces one lifecycle state with optimistic replay-safe conflict handling.
    fn replace_controller_state(
        &self,
        current: VersionedController,
        updated: Controller,
        event: AuthenticationEvent,
    ) -> Result<AuthenticationChange<Controller>, ControllerError> {
        match self
            .controller_store
            .replace(updated.clone(), current.revision())
        {
            Ok(stored) => {
                require_controller_commit(&stored, &updated, current.revision())?;
                Ok(AuthenticationChange::new(
                    stored.controller().clone(),
                    Some(event),
                ))
            }
            Err(AuthenticationStoreError::Conflict) => {
                let observed = self
                    .controller_store
                    .read(updated.controller_id())?
                    .ok_or(ControllerError::NotFound)?;
                require_controller_read(&observed, updated.controller_id())?;
                if observed.controller() == &updated
                    || (observed.controller().state() == updated.state()
                        && observed.controller().matches_registration(
                            updated.name(),
                            updated.role(),
                            updated.certificate(),
                        ))
                {
                    Ok(AuthenticationChange::new(
                        observed.controller().clone(),
                        None,
                    ))
                } else {
                    Err(AuthenticationStoreError::Conflict.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    // Reads controller time through the shared manager clock without API-key diagnostics.
    fn controller_now(&self) -> Result<UnixMilliseconds, ControllerError> {
        self.clock
            .now()
            .map_err(|_error: AuthenticationError| ControllerError::ClockUnavailable)
    }
}

// Requires one provider result to bind exact identity and current lifetime.
fn require_current_certificate(
    certificate: &ControllerCertificate,
    controller_id: &ControllerId,
    now: UnixMilliseconds,
) -> Result<(), ControllerError> {
    if certificate.controller_id() != controller_id {
        return Err(ControllerError::InvalidCertificate);
    }
    require_certificate_lifetime(certificate, now)
}

// Distinguishes malformed validity bounds from not-yet-valid and expired certificates.
fn require_certificate_lifetime(
    certificate: &ControllerCertificate,
    now: UnixMilliseconds,
) -> Result<(), ControllerError> {
    if now < certificate.valid_from() {
        Err(ControllerError::CertificateNotYetValid)
    } else if now >= certificate.expires_at() {
        Err(ControllerError::CertificateExpired)
    } else {
        Ok(())
    }
}

// Requires one store read to preserve its queried identity and a committed revision.
fn require_controller_read(
    stored: &VersionedController,
    expected_controller_id: &ControllerId,
) -> Result<(), ControllerError> {
    if stored.revision() == 0 || stored.controller().controller_id() != expected_controller_id {
        return Err(AuthenticationStoreError::Corrupt.into());
    }
    Ok(())
}

// Requires a mutation result to equal the proposed record at a newer revision.
fn require_controller_commit(
    stored: &VersionedController,
    expected: &Controller,
    prior_revision: u64,
) -> Result<(), ControllerError> {
    if stored.controller() != expected || stored.revision() <= prior_revision {
        return Err(AuthenticationStoreError::Corrupt.into());
    }
    Ok(())
}

// Rejects duplicate identities, fingerprints, and invalid revisions in one complete listing.
fn require_controller_records(records: &[VersionedController]) -> Result<(), ControllerError> {
    let controller_ids = records
        .iter()
        .map(|value| value.controller().controller_id())
        .collect::<HashSet<_>>();
    let certificate_sha256 = records
        .iter()
        .map(|value| value.controller().certificate().certificate_sha256())
        .collect::<HashSet<_>>();
    if controller_ids.len() != records.len()
        || certificate_sha256.len() != records.len()
        || records.iter().any(|value| value.revision() == 0)
    {
        return Err(AuthenticationStoreError::Corrupt.into());
    }
    Ok(())
}

// Requires a new or replacement certificate not to impersonate another controller identity.
fn require_unique_certificate(
    records: Vec<VersionedController>,
    controller_id: &ControllerId,
    certificate_sha256: &Sha256Digest,
) -> Result<(), ControllerError> {
    require_controller_records(&records)?;
    if records.iter().any(|record| {
        record.controller().controller_id() != controller_id
            && record.controller().certificate().certificate_sha256() == certificate_sha256
    }) {
        return Err(AuthenticationStoreError::Conflict.into());
    }
    Ok(())
}
