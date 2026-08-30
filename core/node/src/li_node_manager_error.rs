// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use li_core_interface::InterfaceError;
use li_database::DatabaseError;

// Describes one stable node orchestration failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeManagerError {
    Database(DatabaseError),
    Interface(InterfaceError),
    IdentityMismatch,
    DatabaseInUse,
    NotMain,
    InvalidNodeEnrollment {
        reason: &'static str,
    },
    NodeIdentityConflict {
        reason: &'static str,
    },
    InvalidNodeTransition {
        node_id: String,
        current: &'static str,
        action: &'static str,
    },
    InvalidLocalRoleTransition {
        reason: &'static str,
    },
    InvalidHardwareObservation {
        reason: &'static str,
    },
    InvalidModelService {
        reason: &'static str,
    },
    CorruptState {
        reason: &'static str,
    },
    InvalidOperationTransition {
        operation_id: String,
        current: &'static str,
        action: &'static str,
    },
}

impl fmt::Display for NodeManagerError {
    // Presents a stable failure without exposing persisted values or credentials.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "{error}"),
            Self::Interface(error) => write!(formatter, "{error}"),
            Self::IdentityMismatch => {
                formatter.write_str("node identity differs from committed local identity")
            }
            Self::DatabaseInUse => {
                formatter.write_str("node database is still owned by another manager")
            }
            Self::NotMain => formatter.write_str("node mutation requires the active main node"),
            Self::InvalidNodeEnrollment { reason } => {
                write!(formatter, "node enrollment is invalid: {reason}")
            }
            Self::NodeIdentityConflict { reason } => {
                write!(
                    formatter,
                    "node identity conflicts with committed state: {reason}"
                )
            }
            Self::InvalidNodeTransition {
                node_id,
                current,
                action,
            } => write!(
                formatter,
                "node transition is invalid for {node_id}: cannot {action} from {current}"
            ),
            Self::InvalidLocalRoleTransition { reason } => {
                write!(formatter, "local node role transition is invalid: {reason}")
            }
            Self::InvalidHardwareObservation { reason } => {
                write!(formatter, "hardware observation is invalid: {reason}")
            }
            Self::InvalidModelService { reason } => {
                write!(formatter, "model service is invalid: {reason}")
            }
            Self::CorruptState { reason } => write!(formatter, "node state is corrupt: {reason}"),
            Self::InvalidOperationTransition {
                operation_id,
                current,
                action,
            } => write!(
                formatter,
                "operation transition is invalid for {operation_id}: cannot {action} from {current}"
            ),
        }
    }
}

impl Error for NodeManagerError {}

impl From<DatabaseError> for NodeManagerError {
    // Preserves one stable database failure at the node boundary.
    fn from(error: DatabaseError) -> Self {
        Self::Database(error)
    }
}

impl From<InterfaceError> for NodeManagerError {
    // Preserves one stable interface failure at the node boundary.
    fn from(error: InterfaceError) -> Self {
        Self::Interface(error)
    }
}
