// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, LogicalModelName, MachineId, ModelService,
    ModelServiceDesiredState, ModelServiceId, Node, NodeAddress, NodeId, NodeIdentity, NodeRole,
    NodeState, PlacementGroupId, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_gateway_manager::{
    GatewayHttpError, GatewayHttpModelAvailabilityProvider, GatewayHttpModelInventoryProvider,
    GatewayHttpModelProvider,
};
use li_node_manager::{
    NodeGatewayInventoryClock, NodeGatewayModelInventoryProvider, NodeGatewayModelProvider,
    NodeManager,
};
use rusqlite::{params, Connection};

// Supplies deterministic availability with explicit call and failure controls.
struct AvailabilityMock {
    available: Mutex<BTreeSet<LogicalModelName>>,
    calls: AtomicUsize,
    fail: AtomicBool,
}

impl GatewayHttpModelAvailabilityProvider for AvailabilityMock {
    // Returns configured availability without reserving test capacity.
    fn model_is_available(&self, model: &LogicalModelName) -> Result<bool, GatewayHttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(public_error());
        }
        Ok(self.available.lock().expect("available").contains(model))
    }
}

// Supplies mutable deterministic inventory time and one failure switch.
struct ClockMock {
    now: AtomicU64,
    fail: AtomicBool,
}

impl NodeGatewayInventoryClock for ClockMock {
    // Returns the configured test time or one generic provider failure.
    fn now(&self) -> Result<UnixMilliseconds, GatewayHttpError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(public_error());
        }
        Ok(UnixMilliseconds::new(self.now.load(Ordering::SeqCst)))
    }
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical logical model.
fn model(value: &str) -> LogicalModelName {
    LogicalModelName::parse(value).expect("model")
}

// Returns one coherent local node fixture.
fn node(role: NodeRole) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity('1', 32)).expect("node"),
            MachineId::parse(&identity('2', 32)).expect("machine"),
            InstallationId::parse(&identity('3', 64)).expect("installation"),
        ),
        DisplayName::parse("Home AI").expect("name"),
        role,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Opens one isolated NodeManager and returns its shared database path.
fn manager(directory: &tempfile::TempDir, role: NodeRole) -> Arc<NodeManager> {
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    Arc::new(
        NodeManager::open(database, node(role), "initialize-node")
            .expect("manager")
            .0,
    )
}

// Creates one model service and optionally advances it to running.
fn create_service(
    manager: &NodeManager,
    service_character: char,
    group_character: char,
    logical_model: &str,
    running: bool,
) {
    let service = ModelService::new(
        ModelServiceId::parse(&identity(service_character, 32)).expect("service"),
        model(logical_model),
        ModelServiceDesiredState::Stopped,
        Vec::new(),
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("service");
    manager
        .create_model_service(&format!("create-{service_character}"), service.clone())
        .expect("create service");
    if running {
        let attached = manager
            .attach_placement_group(
                &format!("attach-{service_character}"),
                service.service_id(),
                PlacementGroupId::parse(&identity(group_character, 32)).expect("group"),
                1,
                UnixMilliseconds::new(2_000),
            )
            .expect("attach");
        manager
            .transition_model_service(
                &format!("run-{service_character}"),
                service.service_id(),
                ModelServiceDesiredState::Running,
                attached.revision(),
                UnixMilliseconds::new(3_000),
            )
            .expect("run");
    }
}

// Returns one complete provider with injectable availability and time.
fn provider(
    manager: Arc<NodeManager>,
    available: &[&str],
) -> (
    NodeGatewayModelInventoryProvider,
    Arc<AvailabilityMock>,
    Arc<ClockMock>,
) {
    let availability = Arc::new(AvailabilityMock {
        available: Mutex::new(available.iter().map(|value| model(value)).collect()),
        calls: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
    });
    let clock = Arc::new(ClockMock {
        now: AtomicU64::new(123_999),
        fail: AtomicBool::new(false),
    });
    (
        NodeGatewayModelInventoryProvider::new(manager, availability.clone(), clock.clone()),
        availability,
        clock,
    )
}

// Projects only running services that retain immediate Gateway admission capacity.
#[test]
fn inventory_projects_running_available_models_in_stable_order() {
    let directory = tempfile::tempdir().expect("directory");
    let manager = manager(&directory, NodeRole::Main);
    create_service(&manager, '4', '6', "model-b", true);
    create_service(&manager, '5', '7', "model-a", false);
    let (provider, availability, _) = provider(manager, &["model-a", "model-b"]);
    let inventory = provider.inventory().expect("inventory");
    assert_eq!(inventory.observed_at_unix(), 123);
    assert_eq!(inventory.entries().len(), 1);
    assert_eq!(inventory.entries()[0].model().as_str(), "model-b");
    assert!(inventory.entries()[0].aliases().is_empty());
    assert_eq!(availability.calls.load(Ordering::SeqCst), 1);
}

// Resolves only one exact running canonical service and never invents alias behavior.
#[test]
fn model_resolver_uses_exact_node_owned_running_state() {
    let directory = tempfile::tempdir().expect("directory");
    let manager = manager(&directory, NodeRole::Main);
    create_service(&manager, '4', '6', "model-running", true);
    create_service(&manager, '5', '7', "model-stopped", false);
    let provider = NodeGatewayModelProvider::new(manager);
    assert_eq!(
        provider.resolve("model-running").unwrap().as_str(),
        "model-running"
    );
    for value in ["model-stopped", "missing-model", "INVALID MODEL"] {
        let error = provider.resolve(value).expect_err("unavailable model");
        assert_eq!(
            (error.status_code(), error.code()),
            (404, "model_not_found")
        );
    }
}

// Fails closed for child composition and every injected live-provider boundary.
#[test]
fn inventory_failure_matrix_is_redacted_and_deterministic() {
    let directory = tempfile::tempdir().expect("directory");
    let child = manager(&directory, NodeRole::Child);
    let (child_provider, child_availability, _) = provider(child, &["model-a"]);
    let error = child_provider.inventory().expect_err("child is private");
    assert_eq!(
        (error.status_code(), error.code()),
        (503, "gateway_unavailable")
    );
    assert_eq!(child_availability.calls.load(Ordering::SeqCst), 0);

    let directory = tempfile::tempdir().expect("directory");
    let main = manager(&directory, NodeRole::Main);
    create_service(&main, '4', '6', "model-a", true);
    let (provider, availability, clock) = provider(main, &["model-a"]);
    availability.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        provider.inventory().expect_err("availability").code(),
        "gateway_unavailable"
    );
    availability.fail.store(false, Ordering::SeqCst);
    clock.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        provider.inventory().expect_err("clock").code(),
        "gateway_unavailable"
    );
}

// Rejects duplicate live logical-model identities before querying Gateway state.
#[test]
fn inventory_rejects_ambiguous_persisted_models_before_availability() {
    let directory = tempfile::tempdir().expect("directory");
    let manager = manager(&directory, NodeRole::Main);
    create_service(&manager, '4', '6', "model-a", true);
    let payload = serde_json::to_vec(&serde_json::json!({
        "service_id": identity('5', 32),
        "logical_model": "model-a",
        "desired_state": "running",
        "placement_group_ids": [identity('7', 32)],
        "created_at_unix_milliseconds": 1_000,
        "updated_at_unix_milliseconds": 3_000
    }))
    .expect("payload");
    Connection::open(directory.path().join("core.sqlite3"))
        .expect("connection")
        .execute(
            "INSERT INTO li_database_records (
                collection, identifier, record_version, revision, payload,
                created_at_unix_ms, updated_at_unix_ms
             ) VALUES (?1, ?2, 1, 1, ?3, 1000, 3000)",
            params!["services", identity('5', 32), payload],
        )
        .expect("inject duplicate");
    let (provider, availability, _) = provider(manager, &["model-a"]);
    assert_eq!(
        provider.inventory().expect_err("ambiguous").code(),
        "gateway_unavailable"
    );
    assert_eq!(availability.calls.load(Ordering::SeqCst), 0);
}

// Returns one deliberately distinct provider error to prove composition redaction.
fn public_error() -> GatewayHttpError {
    GatewayHttpError::new(500, "provider_detail", "fixture provider detail")
}
