// SPDX-License-Identifier: AGPL-3.0-only

// Labels the evidence attached to a runtime without deciding whether it may run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceLabel {
    Qualified,
    Unqualified,
    Unknown,
}
