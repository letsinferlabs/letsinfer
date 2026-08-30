// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use li_core_interface::InterfaceError;

// Describes one stable pairing lifecycle failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairingError {
    Interface(InterfaceError),
    InvalidRequest { reason: &'static str },
    MainOnly,
    NotFound,
    Expired,
    Consumed,
    AttemptLimit,
    Unauthorized,
    EntropyUnavailable,
    DiscoveryUnavailable,
    DirectLinkUnavailable,
    TrustUnavailable,
    InvalidApproval,
    StoreConflict,
    StoreCorrupt,
    StoreUnavailable,
    StateUnavailable,
}

impl fmt::Display for PairingError {
    // Presents stable pairing language without exposing codes or proof material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interface(error) => write!(formatter, "{error}"),
            Self::InvalidRequest { reason } => {
                write!(formatter, "pairing request is invalid: {reason}")
            }
            Self::MainOnly => formatter.write_str("pairing invitations are main-node only"),
            Self::NotFound => formatter.write_str("pairing invitation was not found"),
            Self::Expired => formatter.write_str("pairing invitation expired"),
            Self::Consumed => formatter.write_str("pairing invitation was already consumed"),
            Self::AttemptLimit => formatter.write_str("pairing invitation attempt limit reached"),
            Self::Unauthorized => formatter.write_str("pairing request is unauthorized"),
            Self::EntropyUnavailable => {
                formatter.write_str("secure pairing material is unavailable")
            }
            Self::DiscoveryUnavailable => formatter.write_str("pairing discovery is unavailable"),
            Self::DirectLinkUnavailable => {
                formatter.write_str("pairing direct-link proof is unavailable")
            }
            Self::TrustUnavailable => formatter.write_str("pairing trust operation failed"),
            Self::InvalidApproval => formatter.write_str("pairing approval is invalid"),
            Self::StoreConflict => formatter.write_str("pairing state changed concurrently"),
            Self::StoreCorrupt => formatter.write_str("pairing state is corrupt"),
            Self::StoreUnavailable => formatter.write_str("pairing storage is unavailable"),
            Self::StateUnavailable => formatter.write_str("pairing state is unavailable"),
        }
    }
}

impl Error for PairingError {}

impl From<InterfaceError> for PairingError {
    // Preserves one shared interface failure at the pairing boundary.
    fn from(error: InterfaceError) -> Self {
        Self::Interface(error)
    }
}
