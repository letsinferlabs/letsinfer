// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

// Describes one stable interface construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceError {
    subject: &'static str,
    reason: &'static str,
}

impl InterfaceError {
    // Creates one failure at the exact interface boundary that rejected input.
    pub(crate) const fn new(subject: &'static str, reason: &'static str) -> Self {
        Self { subject, reason }
    }

    // Returns the stable interface subject that rejected input.
    pub const fn subject(&self) -> &'static str {
        self.subject
    }

    // Returns the stable reason without including rejected data.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for InterfaceError {
    // Presents a concise failure without leaking entity contents.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "core interface {} is invalid: {}",
            self.subject, self.reason
        )
    }
}

impl Error for InterfaceError {}
