// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{InstallationId, MachineId, NodeRole, Sha256Digest, UnixMilliseconds};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{
    DatabaseNodeSetupIdentityStore, NodeSetupIdentity, NodeSetupIdentityError,
    NodeSetupIdentityInput,
};
use sha2::{Digest, Sha256};

use crate::{
    CoreSetupIdentityProvider, CoreSetupPreparedIdentity, CoreSetupProviderError, CoreSetupReceipt,
    CoreSetupRequest,
};

// Supplies the stable physical-machine identity through an explicit native adapter.
pub trait CoreSetupMachineIdentityProvider: Send + Sync {
    // Reads one canonical host identity without deriving it from mutable network state.
    fn machine_id(&self) -> Result<MachineId, CoreSetupIdentitySourceError>;
}

// Supplies setup time explicitly so persistence tests do not depend on the wall clock.
pub trait CoreSetupIdentityClock: Send + Sync {
    // Returns one non-negative setup observation time.
    fn now(&self) -> Result<UnixMilliseconds, CoreSetupIdentitySourceError>;
}

// Describes one stable injected machine-identity or clock failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreSetupIdentitySourceError {
    Invalid,
    Unavailable,
}

impl fmt::Display for CoreSetupIdentitySourceError {
    // Presents stable source language without native identifiers or diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => formatter.write_str("Core setup identity source is invalid"),
            Self::Unavailable => formatter.write_str("Core setup identity source is unavailable"),
        }
    }
}

impl Error for CoreSetupIdentitySourceError {}

// Reads setup time from the active host without owning any identity persistence.
#[derive(Default)]
pub struct SystemCoreSetupIdentityClock;

impl CoreSetupIdentityClock for SystemCoreSetupIdentityClock {
    // Returns the current Unix time through the same bounded domain value used by NodeManager.
    fn now(&self) -> Result<UnixMilliseconds, CoreSetupIdentitySourceError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CoreSetupIdentitySourceError::Unavailable)?;
        let milliseconds = u64::try_from(duration.as_millis())
            .map_err(|_| CoreSetupIdentitySourceError::Unavailable)?;
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Owns one explicitly closable bootstrap database operation and nothing beyond it.
pub trait CoreSetupIdentityDatabaseOperation: Send {
    // Creates or replays one exact setup-owned local identity closure.
    fn prepare(
        &self,
        input: NodeSetupIdentityInput,
    ) -> Result<NodeSetupIdentity, NodeSetupIdentityError>;

    // Removes one exact unchanged setup-owned identity closure.
    fn rollback(&self, receipt_identity: &Sha256Digest) -> Result<(), NodeSetupIdentityError>;

    // Closes the writable database owner before setup can enter its next phase.
    fn close(self: Box<Self>) -> Result<(), NodeSetupIdentityError>;
}

// Opens one operation-scoped bootstrap database owner without retaining it in Core setup.
pub trait CoreSetupIdentityDatabaseProvider: Send + Sync {
    // Opens one independent exact operation that its caller must close explicitly.
    fn open(&self) -> Result<Box<dyn CoreSetupIdentityDatabaseOperation>, NodeSetupIdentityError>;
}

// Opens production setup identity operations at one validated Node database path.
struct SystemCoreSetupIdentityDatabaseProvider {
    database_file: PathBuf,
}

impl CoreSetupIdentityDatabaseProvider for SystemCoreSetupIdentityDatabaseProvider {
    // Opens one writable owner only for the duration of one bootstrap operation.
    fn open(&self) -> Result<Box<dyn CoreSetupIdentityDatabaseOperation>, NodeSetupIdentityError> {
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(self.database_file.clone()))
                .map_err(|_| NodeSetupIdentityError::Unavailable)?,
        );
        Ok(Box::new(SystemCoreSetupIdentityDatabaseOperation {
            store: Some(DatabaseNodeSetupIdentityStore::new(database.clone())),
            database: Some(database),
        }))
    }
}

// Holds the production store and its sole writer until explicit operation completion.
struct SystemCoreSetupIdentityDatabaseOperation {
    store: Option<DatabaseNodeSetupIdentityStore>,
    database: Option<Arc<DatabaseManager>>,
}

impl CoreSetupIdentityDatabaseOperation for SystemCoreSetupIdentityDatabaseOperation {
    // Delegates one atomic preparation to the Node-owned bootstrap adapter.
    fn prepare(
        &self,
        input: NodeSetupIdentityInput,
    ) -> Result<NodeSetupIdentity, NodeSetupIdentityError> {
        self.store
            .as_ref()
            .ok_or(NodeSetupIdentityError::RecoveryRequired)?
            .prepare(input)
    }

    // Delegates one exact rollback to the Node-owned bootstrap adapter.
    fn rollback(&self, receipt_identity: &Sha256Digest) -> Result<(), NodeSetupIdentityError> {
        self.store
            .as_ref()
            .ok_or(NodeSetupIdentityError::RecoveryRequired)?
            .rollback(receipt_identity)
    }

    // Stops and joins the only writable database thread before returning to setup orchestration.
    fn close(mut self: Box<Self>) -> Result<(), NodeSetupIdentityError> {
        self.store.take();
        let database = self
            .database
            .take()
            .ok_or(NodeSetupIdentityError::RecoveryRequired)?;
        Arc::try_unwrap(database)
            .map_err(|_| NodeSetupIdentityError::RecoveryRequired)?
            .close()
            .map_err(|_| NodeSetupIdentityError::RecoveryRequired)
    }
}

// Adapts operation-scoped Node bootstrap persistence to Core setup's identity port.
pub struct DatabaseCoreSetupIdentityProvider {
    database: Arc<dyn CoreSetupIdentityDatabaseProvider>,
    machine_identity: Arc<dyn CoreSetupMachineIdentityProvider>,
    clock: Arc<dyn CoreSetupIdentityClock>,
}

impl DatabaseCoreSetupIdentityProvider {
    // Creates one production adapter without retaining a writable database owner.
    pub fn new(
        database_file: PathBuf,
        machine_identity: Arc<dyn CoreSetupMachineIdentityProvider>,
        clock: Arc<dyn CoreSetupIdentityClock>,
    ) -> Self {
        Self {
            database: Arc::new(SystemCoreSetupIdentityDatabaseProvider { database_file }),
            machine_identity,
            clock,
        }
    }

    // Creates one adapter with an explicit database-operation provider for lifecycle testing.
    pub fn with_database_provider(
        database: Arc<dyn CoreSetupIdentityDatabaseProvider>,
        machine_identity: Arc<dyn CoreSetupMachineIdentityProvider>,
        clock: Arc<dyn CoreSetupIdentityClock>,
    ) -> Self {
        Self {
            database,
            machine_identity,
            clock,
        }
    }

    // Opens, uses, and explicitly closes one bootstrap writer within a single setup operation.
    fn database_operation<Value>(
        &self,
        operation: impl FnOnce(
            &dyn CoreSetupIdentityDatabaseOperation,
        ) -> Result<Value, NodeSetupIdentityError>,
    ) -> Result<Value, NodeSetupIdentityError> {
        let database = self.database.open()?;
        let result = operation(database.as_ref());
        database.close()?;
        result
    }
}

impl CoreSetupIdentityProvider for DatabaseCoreSetupIdentityProvider {
    // Atomically creates or exactly replays the request's durable local Node identity.
    fn prepare(
        &self,
        request: &CoreSetupRequest,
    ) -> Result<CoreSetupPreparedIdentity, CoreSetupProviderError> {
        if request.context().role() != li_core_update_manager::CoreUpdateNodeRole::Main {
            return Err(CoreSetupProviderError::unchanged(
                "node identity",
                "standalone Core setup requires the main role",
            ));
        }
        let machine_id = self.machine_identity.machine_id().map_err(source_error)?;
        let installation_id = installation_id(request, &machine_id)?;
        let observed_at = self.clock.now().map_err(clock_error)?;
        let input = NodeSetupIdentityInput::new(
            request.request_id().clone(),
            machine_id,
            installation_id,
            request.display_name().clone(),
            node_role(request),
            request.control_address().clone(),
            observed_at,
        );
        let prepared = self
            .database_operation(|store| store.prepare(input))
            .map_err(prepare_error)?;
        let node = prepared.node();
        Ok(CoreSetupPreparedIdentity::new(
            CoreSetupReceipt::new(prepared.receipt_identity().clone()),
            node.identity().node_id().clone(),
            node.identity().machine_id().clone(),
            node.identity().installation_id().clone(),
            node.display_name().clone(),
            node.role(),
            node.control_address().clone(),
        ))
    }

    // Removes only exact unchanged setup-owned state bound to the supplied receipt.
    fn rollback(&self, receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError> {
        self.database_operation(|store| store.rollback(receipt.identity()))
            .map_err(rollback_error)
    }
}

// Derives one host-local installation identity without replacing signed Core provenance.
fn installation_id(
    request: &CoreSetupRequest,
    machine_id: &MachineId,
) -> Result<InstallationId, CoreSetupProviderError> {
    let mut digest = Sha256::new();
    for value in [
        "li_core_setup_installation_v1",
        machine_id.as_str(),
        request.request_id().as_str(),
        request.installation().source_identity().as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    InstallationId::parse(&format!("{:x}", digest.finalize())).map_err(|_| {
        CoreSetupProviderError::unchanged(
            "node identity",
            "host installation identity could not be derived",
        )
    })
}

// Returns the exact topology role already validated by the setup request contract.
fn node_role(request: &CoreSetupRequest) -> NodeRole {
    match request.context().role() {
        li_core_update_manager::CoreUpdateNodeRole::Main => NodeRole::Main,
        li_core_update_manager::CoreUpdateNodeRole::Child => NodeRole::Child,
    }
}

// Maps a pre-mutation native source failure without exposing host diagnostics.
fn source_error(error: CoreSetupIdentitySourceError) -> CoreSetupProviderError {
    match error {
        CoreSetupIdentitySourceError::Invalid => {
            CoreSetupProviderError::unchanged("node identity", "native machine identity is invalid")
        }
        CoreSetupIdentitySourceError::Unavailable => CoreSetupProviderError::unchanged(
            "node identity",
            "native machine identity is unavailable",
        ),
    }
}

// Maps a pre-mutation setup-clock failure without exposing native time diagnostics.
fn clock_error(error: CoreSetupIdentitySourceError) -> CoreSetupProviderError {
    match error {
        CoreSetupIdentitySourceError::Invalid => {
            CoreSetupProviderError::unchanged("node identity", "setup clock value is invalid")
        }
        CoreSetupIdentitySourceError::Unavailable => {
            CoreSetupProviderError::unchanged("node identity", "setup clock is unavailable")
        }
    }
}

// Maps durable preparation state to exact no-mutation or recovery classification.
fn prepare_error(error: NodeSetupIdentityError) -> CoreSetupProviderError {
    match error {
        NodeSetupIdentityError::Conflict | NodeSetupIdentityError::ReceiptMismatch => {
            CoreSetupProviderError::unchanged(
                "node identity",
                "committed local identity differs from the setup request",
            )
        }
        NodeSetupIdentityError::Corrupt
        | NodeSetupIdentityError::Unavailable
        | NodeSetupIdentityError::RecoveryRequired => CoreSetupProviderError::recovery_required(
            "node identity",
            "durable local identity could not be proven",
        ),
    }
}

// Maps rollback refusal without ever claiming compensation after revision drift.
fn rollback_error(error: NodeSetupIdentityError) -> CoreSetupProviderError {
    match error {
        NodeSetupIdentityError::ReceiptMismatch | NodeSetupIdentityError::Conflict => {
            CoreSetupProviderError::unchanged(
                "node identity",
                "rollback receipt does not own local identity",
            )
        }
        NodeSetupIdentityError::Corrupt
        | NodeSetupIdentityError::Unavailable
        | NodeSetupIdentityError::RecoveryRequired => CoreSetupProviderError::recovery_required(
            "node identity",
            "owned local identity could not be rolled back safely",
        ),
    }
}
