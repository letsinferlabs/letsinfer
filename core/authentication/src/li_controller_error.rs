// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use li_core_interface::InterfaceError;

use crate::{AuthenticationStoreError, ControllerCertificateError};

// Describes one closed controller-registry or authorization failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControllerError {
    Interface(InterfaceError),
    InvalidRecord { reason: &'static str },
    InvalidCertificate,
    CertificateNotYetValid,
    CertificateExpired,
    InvalidTransition,
    NotFound,
    Unauthorized,
    ClockUnavailable,
    ProviderUnavailable,
    Store(AuthenticationStoreError),
}

impl fmt::Display for ControllerError {
    // Presents stable language without controller material, identities, or provider diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interface(error) => write!(formatter, "{error}"),
            Self::InvalidRecord { reason } => write!(formatter, "controller is invalid: {reason}"),
            Self::InvalidCertificate => formatter.write_str("controller certificate is invalid"),
            Self::CertificateNotYetValid | Self::CertificateExpired | Self::Unauthorized => {
                formatter.write_str("controller is unauthorized")
            }
            Self::InvalidTransition => {
                formatter.write_str("controller lifecycle transition is invalid")
            }
            Self::NotFound => formatter.write_str("controller was not found"),
            Self::ClockUnavailable => formatter.write_str("controller time is unavailable"),
            Self::ProviderUnavailable => {
                formatter.write_str("controller certificate provider is unavailable")
            }
            Self::Store(AuthenticationStoreError::Conflict) => {
                formatter.write_str("controller state changed concurrently")
            }
            Self::Store(AuthenticationStoreError::Corrupt) => {
                formatter.write_str("controller state is corrupt")
            }
            Self::Store(AuthenticationStoreError::Unavailable) => {
                formatter.write_str("controller storage is unavailable")
            }
        }
    }
}

impl Error for ControllerError {}

impl From<InterfaceError> for ControllerError {
    // Preserves structural interface failure without rejected input.
    fn from(error: InterfaceError) -> Self {
        Self::Interface(error)
    }
}

impl From<AuthenticationStoreError> for ControllerError {
    // Preserves one stable store failure at the controller boundary.
    fn from(error: AuthenticationStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<ControllerCertificateError> for ControllerError {
    // Collapses certificate-provider diagnostics into one fixed public boundary.
    fn from(error: ControllerCertificateError) -> Self {
        match error {
            ControllerCertificateError::Invalid => Self::InvalidCertificate,
            ControllerCertificateError::Unavailable => Self::ProviderUnavailable,
        }
    }
}
