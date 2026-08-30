// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_audit_manager::{
    AuditAppendReceipt, AuditAppendRequest, AuditCheckpointCryptography, AuditCheckpointPolicy,
    AuditClock, AuditError, AuditIdentityProvider, AuditManager, AuditReplayId, SystemAuditClock,
    SystemAuditIdentityProvider,
};

use crate::{DatabaseAuditStore, NodeManager};

// States whether a domain mutation and its audit append share one durable commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeAuditCommitModel {
    IndependentDatabaseCommit,
}

// Composes already-committed domain mutations with an explicit non-atomic audit boundary.
pub struct NodeAuditComposition {
    manager: Arc<AuditManager>,
}

impl NodeAuditComposition {
    // Creates one composition boundary over a node-owned audit manager.
    pub const fn new(manager: Arc<AuditManager>) -> Self {
        Self { manager }
    }

    // Returns the honest durability model until managers accept shared transaction fragments.
    pub const fn commit_model(&self) -> NodeAuditCommitModel {
        NodeAuditCommitModel::IndependentDatabaseCommit
    }

    // Records a domain mutation only after its separate durable commit has succeeded.
    pub fn record_committed_domain_mutation(
        &self,
        request: AuditAppendRequest,
    ) -> Result<AuditAppendReceipt, NodeAuditCompositionError> {
        let replay_id = request.replay_id().clone();
        self.manager.append(request).map_err(|source| {
            NodeAuditCompositionError::DomainCommittedAuditFailed { replay_id, source }
        })
    }

    // Returns the underlying manager for read-only list, show, verify, and export operations.
    pub const fn manager(&self) -> &Arc<AuditManager> {
        &self.manager
    }
}

// Reports a durable audit gap without pretending the preceding domain mutation rolled back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeAuditCompositionError {
    DomainCommittedAuditFailed {
        replay_id: AuditReplayId,
        source: AuditError,
    },
}

impl fmt::Display for NodeAuditCompositionError {
    // Presents the required recovery boundary without domain data or credentials.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DomainCommittedAuditFailed { .. } => formatter.write_str(
                "domain mutation committed but its independent audit append requires recovery",
            ),
        }
    }
}

impl Error for NodeAuditCompositionError {}

impl NodeManager {
    // Composes the ordinary node-native audit manager from local identity and production providers.
    pub fn audit_manager(
        &self,
        cryptography: Arc<dyn AuditCheckpointCryptography>,
    ) -> AuditManager {
        self.audit_manager_with_dependencies(
            Arc::new(SystemAuditClock),
            Arc::new(SystemAuditIdentityProvider),
            cryptography,
            AuditCheckpointPolicy::production(),
        )
    }

    // Composes a deterministic node-native manager while retaining the database and local identity.
    pub fn audit_manager_with_dependencies(
        &self,
        clock: Arc<dyn AuditClock>,
        identities: Arc<dyn AuditIdentityProvider>,
        cryptography: Arc<dyn AuditCheckpointCryptography>,
        checkpoint_policy: AuditCheckpointPolicy,
    ) -> AuditManager {
        AuditManager::new(
            self.local_node_id.clone(),
            Arc::new(DatabaseAuditStore::new(Arc::clone(&self.database))),
            clock,
            identities,
            cryptography,
            checkpoint_policy,
        )
    }
}
