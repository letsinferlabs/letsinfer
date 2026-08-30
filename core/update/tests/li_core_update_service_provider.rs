// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateError, CoreUpdateNodeRole, CoreUpdateResidentService,
    CoreUpdateServiceContext, CoreUpdateServiceControl, CoreUpdateServiceMode,
    CoreUpdateServicePlatform, CoreUpdateServiceProvider, CoreUpdateServiceSnapshotRecord,
    CoreUpdateServiceSnapshotStore, CoreUpdateServiceState, CoreVersion,
    PlatformCoreUpdateServiceProvider,
};

// Stores exact native-state receipts without applying product service policy.
#[derive(Default)]
struct MemorySnapshotStore {
    records: Mutex<BTreeMap<String, CoreUpdateServiceSnapshotRecord>>,
}

impl CoreUpdateServiceSnapshotStore for MemorySnapshotStore {
    // Returns one exact receipt by deterministic update identity.
    fn read(
        &self,
        update_id: &Sha256Digest,
    ) -> Result<Option<CoreUpdateServiceSnapshotRecord>, CoreUpdateError> {
        Ok(self
            .records
            .lock()
            .expect("snapshot records")
            .get(update_id.as_str())
            .cloned())
    }

    // Stores one exact receipt or returns the existing replay value.
    fn store(
        &self,
        snapshot: CoreUpdateServiceSnapshotRecord,
    ) -> Result<CoreUpdateServiceSnapshotRecord, CoreUpdateError> {
        let mut records = self.records.lock().expect("snapshot records");
        if let Some(existing) = records.get(snapshot.update_id().as_str()) {
            return Ok(existing.clone());
        }
        records.insert(snapshot.update_id().as_str().to_string(), snapshot.clone());
        Ok(snapshot)
    }
}

// Records only the native facts and mutations selected by its caller.
struct ServiceControlMock {
    context: CoreUpdateServiceContext,
    observation: CoreUpdateServiceState,
    events: Mutex<Vec<String>>,
    ready: bool,
}

impl CoreUpdateServiceControl for ServiceControlMock {
    // Returns the immutable platform and role facts supplied by composition.
    fn context(&self) -> Result<CoreUpdateServiceContext, CoreUpdateError> {
        Ok(self.context)
    }

    // Returns the configured native observation without service-set judgment.
    fn observe_service(
        &self,
        service: CoreUpdateResidentService,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        self.events
            .lock()
            .expect("service events")
            .push(format!("observe.{service:?}"));
        Ok(self.observation.clone())
    }

    // Records the exact caller-selected native binding and mode.
    fn rebind_service(
        &self,
        service: CoreUpdateResidentService,
        mode: CoreUpdateServiceMode,
        _installation: &CoreInstallation,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        self.events
            .lock()
            .expect("service events")
            .push(format!("rebind.{service:?}.{mode:?}.{active}"));
        Ok(())
    }

    // Returns the configured native readiness fact.
    fn service_is_ready(
        &self,
        service: CoreUpdateResidentService,
        mode: CoreUpdateServiceMode,
        _installation: Option<&CoreInstallation>,
        active: bool,
    ) -> Result<bool, CoreUpdateError> {
        self.events
            .lock()
            .expect("service events")
            .push(format!("ready.{service:?}.{mode:?}.{active}"));
        Ok(self.ready)
    }

    // Records one exact prior state selected by the caller.
    fn restore_service(
        &self,
        state: &CoreUpdateServiceState,
        _installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        self.events
            .lock()
            .expect("service events")
            .push(format!("restore.{:?}", state.service()));
        Ok(())
    }
}

// Returns one exact immutable Core installation fixture.
fn installation(version: &str, identity: char) -> CoreInstallation {
    CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        digest(identity),
    )
}

// Returns one canonical lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Proves the platform provider delegates facts, arbitrary manager modes, mutations, and receipts.
#[test]
fn platform_provider_contains_no_product_service_judgment() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Child);
    let current = installation("1.0.0", '1');
    let observation = CoreUpdateServiceState::new(
        CoreUpdateResidentService::Gateway,
        Some(current.source_identity().clone()),
        Some(current.source_identity().clone()),
    )
    .expect("observation");
    let control = Arc::new(ServiceControlMock {
        context,
        observation: observation.clone(),
        events: Mutex::new(Vec::new()),
        ready: true,
    });
    let provider = PlatformCoreUpdateServiceProvider::new(
        Arc::new(MemorySnapshotStore::default()),
        control.clone(),
    );
    assert_eq!(provider.context().expect("context"), context);
    assert_eq!(
        provider
            .observe_service(CoreUpdateResidentService::Node)
            .expect("observation"),
        observation
    );

    let update_id = digest('a');
    let extra_watchdog = CoreUpdateServiceState::new(
        CoreUpdateResidentService::Watchdog,
        Some(current.source_identity().clone()),
        Some(current.source_identity().clone()),
    )
    .expect("extra Watchdog fact");
    let receipt = CoreUpdateServiceSnapshotRecord::new(
        update_id.clone(),
        current.clone(),
        context,
        vec![extra_watchdog],
    )
    .expect("native receipt");
    assert_eq!(
        provider
            .store_snapshot_record(receipt.clone())
            .expect("stored receipt"),
        receipt
    );
    assert_eq!(
        provider.snapshot_record(&update_id).expect("read receipt"),
        Some(receipt)
    );

    let candidate = installation("1.1.0", '2');
    provider
        .rebind_service(
            CoreUpdateResidentService::Gateway,
            CoreUpdateServiceMode::PublicGateway,
            &candidate,
            true,
        )
        .expect("delegated rebind");
    assert!(provider
        .service_is_ready_with_timeout(
            CoreUpdateResidentService::Gateway,
            CoreUpdateServiceMode::PublicGateway,
            Some(&candidate),
            true,
            Duration::from_secs(1),
        )
        .expect("delegated readiness"));
    provider
        .restore_service(&observation, &current)
        .expect("delegated restoration");
    assert_eq!(
        *control.events.lock().expect("service events"),
        [
            "observe.Node",
            "rebind.Gateway.PublicGateway.true",
            "ready.Gateway.PublicGateway.true",
            "restore.Gateway",
        ]
    );
}

// Proves the mechanism preserves native not-ready facts and rejects a zero timeout.
#[test]
fn platform_provider_preserves_native_readiness_boundary() {
    let current = installation("1.0.0", '1');
    let control = Arc::new(ServiceControlMock {
        context: CoreUpdateServiceContext::new(
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        ),
        observation: CoreUpdateServiceState::new(CoreUpdateResidentService::Node, None, None)
            .expect("observation"),
        events: Mutex::new(Vec::new()),
        ready: false,
    });
    let provider =
        PlatformCoreUpdateServiceProvider::new(Arc::new(MemorySnapshotStore::default()), control);
    assert!(!provider
        .service_is_ready_with_timeout(
            CoreUpdateResidentService::Node,
            CoreUpdateServiceMode::Node,
            Some(&current),
            true,
            Duration::from_millis(1),
        )
        .expect("not ready"));
    assert!(provider
        .service_is_ready_with_timeout(
            CoreUpdateResidentService::Node,
            CoreUpdateServiceMode::Node,
            Some(&current),
            true,
            Duration::ZERO,
        )
        .is_err());
}
