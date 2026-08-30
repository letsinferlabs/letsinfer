// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::{CoreInstallation, CoreUpdateError, CoreUpdateServiceProvider};

// Identifies the native supervisor family without exposing its command-line mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUpdateServicePlatform {
    Linux,
    Macos,
}

// Identifies the local node authority that determines the Gateway exposure mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUpdateNodeRole {
    Main,
    Child,
}

// Identifies one Core-owned resident service independently of its native label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoreUpdateResidentService {
    Node,
    Gateway,
    Watchdog,
}

// Describes the exact product mode that one resident service must implement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUpdateServiceMode {
    Node,
    PublicGateway,
    PrivateGateway,
    Watchdog,
}

// Binds one service handoff to its platform and local node authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreUpdateServiceContext {
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
}

impl CoreUpdateServiceContext {
    // Creates one explicit platform and node-role context.
    pub const fn new(platform: CoreUpdateServicePlatform, role: CoreUpdateNodeRole) -> Self {
        Self { platform, role }
    }

    // Returns the native supervisor family.
    pub const fn platform(&self) -> CoreUpdateServicePlatform {
        self.platform
    }

    // Returns the local node authority.
    pub const fn role(&self) -> CoreUpdateNodeRole {
        self.role
    }
}

// Captures exact loaded and active identities for one Core-owned service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdateServiceState {
    service: CoreUpdateResidentService,
    loaded_identity: Option<Sha256Digest>,
    active_identity: Option<Sha256Digest>,
}

impl CoreUpdateServiceState {
    // Creates one closed service state while rejecting an impossible active binding.
    pub fn new(
        service: CoreUpdateResidentService,
        loaded_identity: Option<Sha256Digest>,
        active_identity: Option<Sha256Digest>,
    ) -> Result<Self, CoreUpdateError> {
        if active_identity.is_some() && active_identity != loaded_identity {
            return Err(CoreUpdateError::InvalidContract {
                reason: "an active service identity must match its loaded identity",
            });
        }
        Ok(Self {
            service,
            loaded_identity,
            active_identity,
        })
    }

    // Returns the Core-owned service represented by this state.
    pub const fn service(&self) -> CoreUpdateResidentService {
        self.service
    }

    // Returns the exact loaded service-definition identity when present.
    pub const fn loaded_identity(&self) -> Option<&Sha256Digest> {
        self.loaded_identity.as_ref()
    }

    // Returns the exact active process identity when the service was running.
    pub const fn active_identity(&self) -> Option<&Sha256Digest> {
        self.active_identity.as_ref()
    }

    // Returns whether the service was loaded before the handoff.
    pub const fn was_loaded(&self) -> bool {
        self.loaded_identity.is_some()
    }

    // Returns whether the service was active before the handoff.
    pub const fn was_active(&self) -> bool {
        self.active_identity.is_some()
    }
}

// Stores the complete exact prior state behind one durable opaque manager receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdateServiceSnapshotRecord {
    update_id: Sha256Digest,
    receipt_id: Sha256Digest,
    current: CoreInstallation,
    context: CoreUpdateServiceContext,
    services: Vec<CoreUpdateServiceState>,
}

impl CoreUpdateServiceSnapshotRecord {
    // Creates one native service-fact receipt without applying product service policy.
    pub fn new(
        update_id: Sha256Digest,
        current: CoreInstallation,
        context: CoreUpdateServiceContext,
        services: Vec<CoreUpdateServiceState>,
    ) -> Result<Self, CoreUpdateError> {
        let receipt_id = snapshot_identity(&update_id, &current, context, &services)?;
        Ok(Self {
            update_id,
            receipt_id,
            current,
            context,
            services,
        })
    }

    // Returns the deterministic update identity that owns this snapshot.
    pub const fn update_id(&self) -> &Sha256Digest {
        &self.update_id
    }

    // Returns the content-bound opaque snapshot receipt.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }

    // Returns the exact Core installation active before service mutation.
    pub const fn current(&self) -> &CoreInstallation {
        &self.current
    }

    // Returns the platform and role captured before mutation.
    pub const fn context(&self) -> CoreUpdateServiceContext {
        self.context
    }

    // Returns the exact ordered resident-service states.
    pub fn services(&self) -> &[CoreUpdateServiceState] {
        &self.services
    }
}

// Defines durable exact-state storage independently of systemd or launchd.
pub trait CoreUpdateServiceSnapshotStore: Send + Sync {
    // Returns one prior snapshot for an idempotent update restart.
    fn read(
        &self,
        update_id: &Sha256Digest,
    ) -> Result<Option<CoreUpdateServiceSnapshotRecord>, CoreUpdateError>;

    // Stores one snapshot exactly once and returns the authoritative durable value.
    fn store(
        &self,
        snapshot: CoreUpdateServiceSnapshotRecord,
    ) -> Result<CoreUpdateServiceSnapshotRecord, CoreUpdateError>;
}

// Isolates fixed-argument systemd or launchd mechanics from update policy.
pub trait CoreUpdateServiceControl: Send + Sync {
    // Returns the immutable platform and local-role context.
    fn context(&self) -> Result<CoreUpdateServiceContext, CoreUpdateError>;

    // Observes one exact resident service without changing it.
    fn observe_service(
        &self,
        service: CoreUpdateResidentService,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError>;

    // Rebinds one loaded resident service to an exact Core and preserves activity.
    fn rebind_service(
        &self,
        service: CoreUpdateResidentService,
        mode: CoreUpdateServiceMode,
        installation: &CoreInstallation,
        active: bool,
    ) -> Result<(), CoreUpdateError>;

    // Tests one exact resident-service candidate binding without mutating it.
    fn service_is_ready(
        &self,
        service: CoreUpdateResidentService,
        mode: CoreUpdateServiceMode,
        installation: Option<&CoreInstallation>,
        active: bool,
    ) -> Result<bool, CoreUpdateError>;

    // Tests readiness within one caller-owned remaining global deadline.
    fn service_is_ready_with_timeout(
        &self,
        service: CoreUpdateResidentService,
        mode: CoreUpdateServiceMode,
        installation: Option<&CoreInstallation>,
        active: bool,
        timeout: Duration,
    ) -> Result<bool, CoreUpdateError> {
        if timeout.is_zero() {
            return Err(CoreUpdateError::provider(
                "service readiness",
                "resident service readiness deadline expired",
            ));
        }
        self.service_is_ready(service, mode, installation, active)
    }

    // Restores one exact prior resident-service definition, loaded state, and activity.
    fn restore_service(
        &self,
        state: &CoreUpdateServiceState,
        installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError>;
}

// Composes native service facts, mutations, and durable receipts without product judgment.
pub struct PlatformCoreUpdateServiceProvider {
    snapshots: Arc<dyn CoreUpdateServiceSnapshotStore>,
    control: Arc<dyn CoreUpdateServiceControl>,
}

impl PlatformCoreUpdateServiceProvider {
    // Creates one platform provider from explicit durable receipt and native control capabilities.
    pub fn new(
        snapshots: Arc<dyn CoreUpdateServiceSnapshotStore>,
        control: Arc<dyn CoreUpdateServiceControl>,
    ) -> Self {
        Self { snapshots, control }
    }
}

impl CoreUpdateServiceProvider for PlatformCoreUpdateServiceProvider {
    // Returns the immutable platform and node-role facts reported by native composition.
    fn context(&self) -> Result<CoreUpdateServiceContext, CoreUpdateError> {
        self.control.context()
    }

    // Returns one verified durable native-state receipt without interpreting its service set.
    fn snapshot_record(
        &self,
        update_id: &Sha256Digest,
    ) -> Result<Option<CoreUpdateServiceSnapshotRecord>, CoreUpdateError> {
        let record = self.snapshots.read(update_id)?;
        if let Some(record) = record.as_ref() {
            validate_snapshot_receipt(record)?;
        }
        Ok(record)
    }

    // Stores one verified native-state receipt without deciding whether its facts are admissible.
    fn store_snapshot_record(
        &self,
        snapshot: CoreUpdateServiceSnapshotRecord,
    ) -> Result<CoreUpdateServiceSnapshotRecord, CoreUpdateError> {
        validate_snapshot_receipt(&snapshot)?;
        let stored = self.snapshots.store(snapshot)?;
        validate_snapshot_receipt(&stored)?;
        Ok(stored)
    }

    // Delegates one caller-selected resident observation to native control.
    fn observe_service(
        &self,
        service: CoreUpdateResidentService,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        self.control.observe_service(service)
    }

    // Delegates one manager-selected native rebind without choosing its service or mode.
    fn rebind_service(
        &self,
        service: CoreUpdateResidentService,
        mode: CoreUpdateServiceMode,
        installation: &CoreInstallation,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        self.control
            .rebind_service(service, mode, installation, active)
    }

    // Delegates one bounded readiness observation without defining completion policy.
    fn service_is_ready_with_timeout(
        &self,
        service: CoreUpdateResidentService,
        mode: CoreUpdateServiceMode,
        installation: Option<&CoreInstallation>,
        active: bool,
        timeout: Duration,
    ) -> Result<bool, CoreUpdateError> {
        self.control
            .service_is_ready_with_timeout(service, mode, installation, active, timeout)
    }

    // Delegates one exact manager-selected restoration to native control.
    fn restore_service(
        &self,
        state: &CoreUpdateServiceState,
        installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        self.control.restore_service(state, installation)
    }
}

// Recomputes one content-bound durable receipt without applying product service policy.
fn validate_snapshot_receipt(
    record: &CoreUpdateServiceSnapshotRecord,
) -> Result<(), CoreUpdateError> {
    let expected = snapshot_identity(
        record.update_id(),
        record.current(),
        record.context(),
        record.services(),
    )?;
    if &expected != record.receipt_id() {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core service snapshot content does not match its receipt",
        });
    }
    Ok(())
}

// Derives one unambiguous receipt from every state required for exact restoration.
fn snapshot_identity(
    update_id: &Sha256Digest,
    current: &CoreInstallation,
    context: CoreUpdateServiceContext,
    services: &[CoreUpdateServiceState],
) -> Result<Sha256Digest, CoreUpdateError> {
    let mut digest = Sha256::new();
    append_identity_field(&mut digest, b"li_core_service_snapshot_v2");
    append_identity_field(&mut digest, update_id.as_str().as_bytes());
    append_identity_field(&mut digest, current.version().as_str().as_bytes());
    append_identity_field(&mut digest, current.source_identity().as_str().as_bytes());
    append_identity_field(&mut digest, platform_identity(context.platform()));
    append_identity_field(&mut digest, role_identity(context.role()));
    for state in services {
        append_identity_field(&mut digest, service_identity(state.service()));
        append_optional_digest(&mut digest, state.loaded_identity());
        append_optional_digest(&mut digest, state.active_identity());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).map_err(|_| {
        CoreUpdateError::InvalidContract {
            reason: "Core service snapshot identity could not be derived",
        }
    })
}

// Appends one length-delimited field to a deterministic receipt digest.
fn append_identity_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

// Appends one explicit optional digest without conflating absence and empty bytes.
fn append_optional_digest(digest: &mut Sha256, value: Option<&Sha256Digest>) {
    match value {
        Some(value) => {
            append_identity_field(digest, b"some");
            append_identity_field(digest, value.as_str().as_bytes());
        }
        None => append_identity_field(digest, b"none"),
    }
}

// Returns the stable receipt field for one native platform.
const fn platform_identity(platform: CoreUpdateServicePlatform) -> &'static [u8] {
    match platform {
        CoreUpdateServicePlatform::Linux => b"linux",
        CoreUpdateServicePlatform::Macos => b"macos",
    }
}

// Returns the stable receipt field for one node authority.
const fn role_identity(role: CoreUpdateNodeRole) -> &'static [u8] {
    match role {
        CoreUpdateNodeRole::Main => b"main",
        CoreUpdateNodeRole::Child => b"child",
    }
}

// Returns the stable receipt field for one resident service.
const fn service_identity(service: CoreUpdateResidentService) -> &'static [u8] {
    match service {
        CoreUpdateResidentService::Node => b"li_node",
        CoreUpdateResidentService::Gateway => b"li_gateway",
        CoreUpdateResidentService::Watchdog => b"li_watchdog",
    }
}
