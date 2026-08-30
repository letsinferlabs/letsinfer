// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use crate::{
    action, ActionId, ActionMetadata, CommandInvocation, CommandParser, CommandParserError,
    CommandScope,
};

// Names the configured local node role used for command authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalRole {
    Main,
    Child,
}

impl LocalRole {
    // Returns the exact execution scope corresponding to this configured role.
    const fn scope(self) -> CommandScope {
        match self {
            Self::Main => CommandScope::Main,
            Self::Child => CommandScope::Child,
        }
    }
}

// Supplies only the configured-node fact required before typed dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandContext {
    local_role: Option<LocalRole>,
}

impl CommandContext {
    // Creates context for a host that has not configured a Let's Infer node.
    pub const fn unconfigured() -> Self {
        Self { local_role: None }
    }

    // Creates context for one configured main or child node.
    pub const fn configured(local_role: LocalRole) -> Self {
        Self {
            local_role: Some(local_role),
        }
    }

    // Returns the configured role without fabricating one for an unconfigured host.
    pub const fn local_role(self) -> Option<LocalRole> {
        self.local_role
    }
}

// Describes one stable pre-dispatch authorization failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandAuthorizationError {
    ConfiguredNodeRequired {
        action: ActionId,
    },
    ScopeDenied {
        action: ActionId,
        required: CommandScope,
        actual: LocalRole,
    },
}

impl fmt::Display for CommandAuthorizationError {
    // Presents exact role denials without exposing handler or state internals.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfiguredNodeRequired { action } => {
                write!(formatter, "{} requires a configured node", action.as_str())
            }
            Self::ScopeDenied {
                action,
                required,
                actual,
            } => write!(
                formatter,
                "{} requires {required:?} scope; local role is {actual:?}",
                action.as_str()
            ),
        }
    }
}

impl Error for CommandAuthorizationError {}

// Carries one authorized invocation and its exact audit contract to a handler boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCommand {
    invocation: CommandInvocation,
    metadata: &'static ActionMetadata,
}

impl AuthorizedCommand {
    // Returns the exact parsed invocation after role authorization.
    pub const fn invocation(&self) -> &CommandInvocation {
        &self.invocation
    }

    // Returns the authorization and audit metadata handlers must preserve.
    pub const fn metadata(&self) -> &'static ActionMetadata {
        self.metadata
    }
}

// Receives authorized typed leaves while manager handlers remain composition-root dependencies.
pub trait CommandDispatcher {
    type Output;
    type Error;

    // Dispatches one already-authorized typed leaf exactly once.
    fn dispatch(&mut self, command: AuthorizedCommand) -> Result<Self::Output, Self::Error>;
}

// Distinguishes parser, authorization, and injected handler failures.
#[derive(Debug, Eq, PartialEq)]
pub enum CommandExecutionError<DispatcherError> {
    Parser(CommandParserError),
    Authorization(CommandAuthorizationError),
    Dispatcher(DispatcherError),
}

// Authorizes one parsed command before any dispatcher can observe it.
pub fn authorize(
    invocation: CommandInvocation,
    context: CommandContext,
) -> Result<AuthorizedCommand, CommandAuthorizationError> {
    let metadata = action(invocation.action());
    if metadata.requires_configured_node() && context.local_role().is_none() {
        return Err(CommandAuthorizationError::ConfiguredNodeRequired {
            action: invocation.action(),
        });
    }
    if let Some(actual) = context.local_role() {
        let required = metadata.scope();
        if required != CommandScope::All && required != actual.scope() {
            return Err(CommandAuthorizationError::ScopeDenied {
                action: invocation.action(),
                required,
                actual,
            });
        }
    }
    Ok(AuthorizedCommand {
        invocation,
        metadata,
    })
}

// Parses, authorizes, and invokes one injected dispatcher in that fixed order.
pub fn authorize_and_dispatch<I, S, Dispatcher>(
    arguments: I,
    context: CommandContext,
    dispatcher: &mut Dispatcher,
) -> Result<Dispatcher::Output, CommandExecutionError<Dispatcher::Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
    Dispatcher: CommandDispatcher,
{
    let parser = CommandParser::new().map_err(CommandExecutionError::Parser)?;
    let invocation = parser
        .parse(arguments)
        .map_err(CommandExecutionError::Parser)?;
    let command = authorize(invocation, context).map_err(CommandExecutionError::Authorization)?;
    dispatcher
        .dispatch(command)
        .map_err(CommandExecutionError::Dispatcher)
}
