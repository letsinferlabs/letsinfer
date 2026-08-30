// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use li_core_interface::InterfaceError;

// Describes one stable authentication-store failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationStoreError {
    Conflict,
    Corrupt,
    Unavailable,
}

// Describes one stable API-key lifecycle or authentication failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationError {
    Interface(InterfaceError),
    InvalidPolicy { reason: &'static str },
    NotFound,
    Unauthorized,
    EntropyUnavailable,
    Store(AuthenticationStoreError),
}

impl fmt::Display for AuthenticationError {
    // Presents stable language without revealing whether a credential exists.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interface(error) => write!(formatter, "{error}"),
            Self::InvalidPolicy { reason } => {
                write!(formatter, "API-key policy is invalid: {reason}")
            }
            Self::NotFound => formatter.write_str("API key was not found"),
            Self::Unauthorized => formatter.write_str("API key is unauthorized"),
            Self::EntropyUnavailable => {
                formatter.write_str("secure API-key generation is unavailable")
            }
            Self::Store(AuthenticationStoreError::Conflict) => {
                formatter.write_str("API-key state changed concurrently")
            }
            Self::Store(AuthenticationStoreError::Corrupt) => {
                formatter.write_str("API-key state is corrupt")
            }
            Self::Store(AuthenticationStoreError::Unavailable) => {
                formatter.write_str("API-key storage is unavailable")
            }
        }
    }
}

impl Error for AuthenticationError {}

impl From<AuthenticationStoreError> for AuthenticationError {
    // Preserves one stable store failure at the manager boundary.
    fn from(error: AuthenticationStoreError) -> Self {
        Self::Store(error)
    }
}
