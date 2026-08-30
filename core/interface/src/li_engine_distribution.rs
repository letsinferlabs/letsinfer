// SPDX-License-Identifier: AGPL-3.0-only

use crate::{ArtifactRevision, PlatformIdentity, RuntimeSource, Sha256Digest};

// Identifies one native Engine delivery mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEngineKind {
    NativeArchive,
    PythonStandalone,
    EmbeddedApplication,
}

// Binds a runtime to one immutable OCI or native Engine distribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineDistribution {
    Oci {
        reference: RuntimeSource,
        immutable_id: Sha256Digest,
        base: Option<RuntimeSource>,
        payload_id: Option<Sha256Digest>,
    },
    Native {
        kind: NativeEngineKind,
        platform: PlatformIdentity,
        payload_id: Sha256Digest,
        source_revision: ArtifactRevision,
    },
}

impl EngineDistribution {
    // Creates one digest-pinned OCI Engine identity.
    pub const fn oci(
        reference: RuntimeSource,
        immutable_id: Sha256Digest,
        base: Option<RuntimeSource>,
        payload_id: Option<Sha256Digest>,
    ) -> Self {
        Self::Oci {
            reference,
            immutable_id,
            base,
            payload_id,
        }
    }

    // Creates one immutable native Engine projection.
    pub const fn native(
        kind: NativeEngineKind,
        platform: PlatformIdentity,
        payload_id: Sha256Digest,
        source_revision: ArtifactRevision,
    ) -> Self {
        Self::Native {
            kind,
            platform,
            payload_id,
            source_revision,
        }
    }

    // Returns the exact execution payload digest when one is declared.
    pub const fn payload_id(&self) -> Option<&Sha256Digest> {
        match self {
            Self::Oci { payload_id, .. } => payload_id.as_ref(),
            Self::Native { payload_id, .. } => Some(payload_id),
        }
    }
}
