// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use li_core_interface::{
    EndpointOwnership, Placement, PlacementGroupId, PlacementId, Sha256Digest,
};

use crate::{PlacementError, PlacementStore};

pub(crate) const MAXIMUM_LOG_BYTES: usize = 1024 * 1024;
const MAXIMUM_LOG_LINES: u32 = 10_000;
const MAXIMUM_CURSOR_BYTES: usize = 512;
const MAXIMUM_WAIT: Duration = Duration::from_secs(1);

// Carries one provider-bound opaque cursor without exposing platform log internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementLogCursor {
    source_identity: Sha256Digest,
    position: String,
}

impl PlacementLogCursor {
    // Creates one bounded cursor returned by a trusted Placement log provider.
    pub fn new(source_identity: Sha256Digest, position: String) -> Result<Self, PlacementError> {
        if position.is_empty()
            || position.len() > MAXIMUM_CURSOR_BYTES
            || position.chars().any(char::is_control)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement log cursor is invalid or unbounded",
            });
        }
        Ok(Self {
            source_identity,
            position,
        })
    }

    // Returns the exact platform source identity that issued this cursor.
    pub const fn source_identity(&self) -> &Sha256Digest {
        &self.source_identity
    }

    // Returns the opaque bounded provider position.
    pub fn position(&self) -> &str {
        &self.position
    }
}

// Requests one bounded runtime-owned byte batch from an exact placement group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementLogReadRequest {
    placement_group_id: PlacementGroupId,
    cursor: Option<PlacementLogCursor>,
    maximum_lines: u32,
    maximum_bytes: usize,
    wait: Duration,
}

impl PlacementLogReadRequest {
    // Creates one bounded immediate read or long-poll request.
    pub fn new(
        placement_group_id: PlacementGroupId,
        cursor: Option<PlacementLogCursor>,
        maximum_lines: u32,
        maximum_bytes: usize,
        wait: Duration,
    ) -> Result<Self, PlacementError> {
        if maximum_lines == 0
            || maximum_lines > MAXIMUM_LOG_LINES
            || maximum_bytes == 0
            || maximum_bytes > MAXIMUM_LOG_BYTES
            || wait > MAXIMUM_WAIT
            || Duration::from_millis(wait.as_millis() as u64) != wait
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement log read bounds are invalid",
            });
        }
        Ok(Self {
            placement_group_id,
            cursor,
            maximum_lines,
            maximum_bytes,
            wait,
        })
    }

    // Returns the exact placement group selected by NodeManager.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the provider cursor from the prior batch when one exists.
    pub const fn cursor(&self) -> Option<&PlacementLogCursor> {
        self.cursor.as_ref()
    }

    // Returns the maximum logical line count accepted from the provider.
    pub const fn maximum_lines(&self) -> u32 {
        self.maximum_lines
    }

    // Returns the hard byte bound for one provider response.
    pub const fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }

    // Returns the bounded long-poll duration requested by a following client.
    pub const fn wait(&self) -> Duration {
        self.wait
    }
}

// Returns one bounded opaque runtime byte batch and its next exact cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementLogBatch {
    placement_group_id: PlacementGroupId,
    placement_id: PlacementId,
    cursor: PlacementLogCursor,
    payload: Vec<u8>,
    truncated: bool,
}

impl PlacementLogBatch {
    // Creates one provider result after enforcing the universal transport byte bound.
    pub fn new(
        placement_group_id: PlacementGroupId,
        placement_id: PlacementId,
        cursor: PlacementLogCursor,
        payload: Vec<u8>,
        truncated: bool,
    ) -> Result<Self, PlacementError> {
        if payload.len() > MAXIMUM_LOG_BYTES {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(Self {
            placement_group_id,
            placement_id,
            cursor,
            payload,
            truncated,
        })
    }

    // Returns the selected aggregate identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the exact endpoint-owner placement whose output was read.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the next exact provider cursor for replay-free continuation.
    pub const fn cursor(&self) -> &PlacementLogCursor {
        &self.cursor
    }

    // Returns runtime-owned bytes without interpreting Engine content.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    // Returns whether older bytes were omitted by bounded retention or response limits.
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

// Reads one platform-native runtime log source for an exact endpoint-owner placement.
pub trait PlacementRuntimeLogProvider: Send + Sync {
    // Returns one bounded batch or a redacted Placement error.
    fn read(
        &self,
        placement: &Placement,
        request: &PlacementLogReadRequest,
    ) -> Result<PlacementLogBatch, PlacementError>;
}

// Owns placement aggregate selection before delegating opaque bytes to one native provider.
pub(crate) fn read_placement_logs(
    store: &Arc<dyn PlacementStore>,
    provider: &Arc<dyn PlacementRuntimeLogProvider>,
    request: PlacementLogReadRequest,
) -> Result<PlacementLogBatch, PlacementError> {
    let record = store
        .read(request.placement_group_id())?
        .ok_or(PlacementError::GroupNotFound)?;
    let owners = record
        .record()
        .placements()
        .iter()
        .filter(|placement| placement.assignment().endpoint_ownership() == EndpointOwnership::Owner)
        .collect::<Vec<_>>();
    if owners.len() != 1 {
        return Err(PlacementError::ExecutionUnavailable);
    }
    let batch = provider.read(owners[0], &request)?;
    if batch.placement_group_id() != request.placement_group_id()
        || batch.placement_id() != owners[0].placement_id()
        || batch.payload().len() > request.maximum_bytes()
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(batch)
}
