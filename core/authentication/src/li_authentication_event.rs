// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{ApiKeyId, ControllerId};

// Describes one completed API-key lifecycle change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationEvent {
    ApiKeyCreated {
        key_id: ApiKeyId,
    },
    ApiKeyRevoked {
        key_id: ApiKeyId,
    },
    ApiKeyRotated {
        revoked_key_id: ApiKeyId,
        replacement_key_id: ApiKeyId,
    },
    ApiKeyPolicyUpdated {
        key_id: ApiKeyId,
    },
    ControllerIssued {
        controller_id: ControllerId,
    },
    ControllerImported {
        controller_id: ControllerId,
    },
    ControllerActivated {
        controller_id: ControllerId,
    },
    ControllerEnrolled {
        controller_id: ControllerId,
    },
    ControllerReplaced {
        controller_id: ControllerId,
    },
    ControllerRevoked {
        controller_id: ControllerId,
    },
}

// Returns one committed value and its optional non-replayed event.
#[derive(Debug)]
pub struct AuthenticationChange<Value> {
    value: Value,
    event: Option<AuthenticationEvent>,
}

impl<Value> AuthenticationChange<Value> {
    // Creates one manager result after a successful lifecycle action.
    pub(crate) const fn new(value: Value, event: Option<AuthenticationEvent>) -> Self {
        Self { value, event }
    }

    // Returns the committed authentication value.
    pub const fn value(&self) -> &Value {
        &self.value
    }

    // Returns mutable access for one-time secret presentation by the caller.
    pub fn value_mut(&mut self) -> &mut Value {
        &mut self.value
    }

    // Returns the domain event when this action changed durable state.
    pub const fn event(&self) -> Option<&AuthenticationEvent> {
        self.event.as_ref()
    }
}
