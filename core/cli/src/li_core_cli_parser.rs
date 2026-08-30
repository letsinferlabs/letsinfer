// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::li_core_cli_command::{OptionDefault, OptionSpec, OptionValueKind, PositionalSpec};
use crate::{
    actions, command_specs, ActionId, ArgumentId, ArgumentValue, AuditPolicy, CommandInvocation,
    CommandScope, CommandSpec, MutationClass,
};

// Describes one stable registry or argument parsing failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandParserError {
    InvalidContract { reason: &'static str },
    MissingCommand,
    UnknownCommand { command: String },
    UnknownOption { option: String },
    MissingOptionValue { option: String },
    MissingRequiredOption { option: &'static str },
    MissingPositional { argument: ArgumentId },
    UnexpectedPositional { value: String },
    InvalidInteger { option: &'static str, value: String },
    InvalidChoice { option: &'static str, value: String },
    UnexpectedOptionValue { option: String },
}

impl fmt::Display for CommandParserError {
    // Presents stable parser failures without inventing command fallbacks.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { reason } => {
                write!(formatter, "Core CLI registry is invalid: {reason}")
            }
            Self::MissingCommand => formatter.write_str("Core CLI command is required"),
            Self::UnknownCommand { command } => {
                write!(formatter, "unknown Core CLI command: {command}")
            }
            Self::UnknownOption { option } => write!(formatter, "unknown option: {option}"),
            Self::MissingOptionValue { option } => {
                write!(formatter, "option requires a value: {option}")
            }
            Self::MissingRequiredOption { option } => {
                write!(formatter, "required option is missing: {option}")
            }
            Self::MissingPositional { argument } => {
                write!(
                    formatter,
                    "required positional argument is missing: {argument:?}"
                )
            }
            Self::UnexpectedPositional { value } => {
                write!(formatter, "unexpected positional argument: {value}")
            }
            Self::InvalidInteger { option, value } => {
                write!(
                    formatter,
                    "option {option} requires an integer, received {value}"
                )
            }
            Self::InvalidChoice { option, value } => {
                write!(formatter, "option {option} does not accept {value}")
            }
            Self::UnexpectedOptionValue { option } => {
                write!(formatter, "flag does not accept a value: {option}")
            }
        }
    }
}

impl Error for CommandParserError {}

// Owns the validated declarative parser surface without binding manager handlers.
#[derive(Clone, Copy, Debug)]
pub struct CommandParser;

impl CommandParser {
    // Creates one parser only after proving registry and leaf equality.
    pub fn new() -> Result<Self, CommandParserError> {
        validate_contract()?;
        Ok(Self)
    }

    // Parses owned or borrowed argument words into one typed exact leaf invocation.
    pub fn parse<I, S>(&self, arguments: I) -> Result<CommandInvocation, CommandParserError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let arguments = arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_owned())
            .collect::<Vec<_>>();
        let specification = selected_specification(&arguments)?;
        parse_arguments(specification, &arguments[specification.path().len()..])
    }
}

// Proves the declarative action and parser registries are closed and identical.
fn validate_contract() -> Result<(), CommandParserError> {
    let action_ids = actions()
        .iter()
        .map(|metadata| metadata.id())
        .collect::<BTreeSet<_>>();
    let command_ids = command_specs()
        .iter()
        .map(|specification| specification.action())
        .collect::<BTreeSet<_>>();
    if action_ids.len() != actions().len() {
        return Err(CommandParserError::InvalidContract {
            reason: "action identifiers are duplicated",
        });
    }
    if command_ids.len() != command_specs().len() {
        return Err(CommandParserError::InvalidContract {
            reason: "parser action identifiers are duplicated",
        });
    }
    if action_ids != command_ids {
        return Err(CommandParserError::InvalidContract {
            reason: "action registry and parser leaves differ",
        });
    }

    let paths = command_specs()
        .iter()
        .map(|specification| specification.path())
        .collect::<BTreeSet<_>>();
    if paths.len() != command_specs().len() || paths.iter().any(|path| path.is_empty()) {
        return Err(CommandParserError::InvalidContract {
            reason: "parser paths are empty or duplicated",
        });
    }

    for metadata in actions() {
        // Uninstall is the sole node mutation that retires its own durable audit authority.
        if metadata.mutation() == MutationClass::Node
            && metadata.audit() != AuditPolicy::Always
            && metadata.id() != ActionId::Uninstall
        {
            return Err(CommandParserError::InvalidContract {
                reason: "node mutation lacks mandatory audit policy",
            });
        }
        if metadata.mutation() == MutationClass::Node
            && metadata.scope() != CommandScope::Main
            && !matches!(
                metadata.id(),
                ActionId::Uninstall
                    | ActionId::NodeAdd
                    | ActionId::NodePause
                    | ActionId::NodeResume
                    | ActionId::NodeRemove
            )
        {
            return Err(CommandParserError::InvalidContract {
                reason: "non-local node mutation is not main-scoped",
            });
        }
    }

    for specification in command_specs() {
        validate_leaf(*specification)?;
    }
    Ok(())
}

// Proves one leaf has unique options and typed destinations.
fn validate_leaf(specification: CommandSpec) -> Result<(), CommandParserError> {
    let options = specification
        .options()
        .iter()
        .map(|option| option.name)
        .collect::<BTreeSet<_>>();
    if options.len() != specification.options().len() {
        return Err(CommandParserError::InvalidContract {
            reason: "command leaf contains duplicate options",
        });
    }
    if specification
        .options()
        .iter()
        .any(|option| !option.name.starts_with("--"))
    {
        return Err(CommandParserError::InvalidContract {
            reason: "command leaf contains a noncanonical option",
        });
    }
    if specification
        .positionals()
        .windows(2)
        .any(|pair| !pair[0].required && pair[1].required)
    {
        return Err(CommandParserError::InvalidContract {
            reason: "required positional follows an optional positional",
        });
    }
    Ok(())
}

// Selects the longest exact registered command path from the argument prefix.
fn selected_specification(arguments: &[String]) -> Result<CommandSpec, CommandParserError> {
    if arguments.is_empty() {
        return Err(CommandParserError::MissingCommand);
    }
    command_specs()
        .iter()
        .filter(|specification| path_matches(**specification, arguments))
        .max_by_key(|specification| specification.path().len())
        .copied()
        .ok_or_else(|| CommandParserError::UnknownCommand {
            command: arguments
                .iter()
                .take_while(|argument| !argument.starts_with('-'))
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
        })
}

// Reports whether the argument prefix selects one exact command path.
fn path_matches(specification: CommandSpec, arguments: &[String]) -> bool {
    specification.path().len() <= arguments.len()
        && specification
            .path()
            .iter()
            .zip(arguments)
            .all(|(expected, actual)| *expected == actual)
}

// Parses one leaf's remaining arguments through its declared typed grammar.
fn parse_arguments(
    specification: CommandSpec,
    arguments: &[String],
) -> Result<CommandInvocation, CommandParserError> {
    let mut values = default_values(specification.options());
    let mut positionals = Vec::new();
    let mut index = 0;
    let mut options_enabled = true;
    while index < arguments.len() {
        let argument = &arguments[index];
        if options_enabled && argument == "--" {
            options_enabled = false;
            index += 1;
            continue;
        }
        if options_enabled && argument.starts_with('-') {
            let (name, attached_value) = option_parts(argument);
            let option = specification
                .options()
                .iter()
                .find(|option| option.name == name)
                .ok_or_else(|| CommandParserError::UnknownOption {
                    option: name.to_owned(),
                })?;
            index = parse_option(*option, attached_value, arguments, index, &mut values)?;
        } else {
            positionals.push(argument.clone());
        }
        index += 1;
    }
    parse_positionals(specification.positionals(), &positionals, &mut values)?;
    validate_required_options(specification.options(), &values)?;
    Ok(CommandInvocation::new(specification.action(), values))
}

// Produces argparse-compatible false and explicit value defaults.
fn default_values(options: &[OptionSpec]) -> BTreeMap<ArgumentId, ArgumentValue> {
    let mut values = BTreeMap::new();
    for option in options {
        let value = match (option.kind, option.default) {
            (OptionValueKind::Flag, _) => Some(ArgumentValue::Boolean(false)),
            (_, OptionDefault::Integer(value)) => Some(ArgumentValue::Integer(value)),
            (_, OptionDefault::Text(value)) => Some(ArgumentValue::Text(value.to_owned())),
            (_, OptionDefault::EmptyTextList) => Some(ArgumentValue::TextList(Vec::new())),
            (_, OptionDefault::None) => None,
        };
        if let Some(value) = value {
            values.insert(option.argument, value);
        }
    }
    values
}

// Separates a long option from argparse-compatible attached text.
fn option_parts(argument: &str) -> (&str, Option<&str>) {
    match argument.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (argument, None),
    }
}

// Parses one declared option and returns the last consumed argument index.
fn parse_option(
    option: OptionSpec,
    attached_value: Option<&str>,
    arguments: &[String],
    index: usize,
    values: &mut BTreeMap<ArgumentId, ArgumentValue>,
) -> Result<usize, CommandParserError> {
    if option.kind == OptionValueKind::Flag {
        if attached_value.is_some() {
            return Err(CommandParserError::UnexpectedOptionValue {
                option: option.name.to_owned(),
            });
        }
        values.insert(option.argument, ArgumentValue::Boolean(true));
        return Ok(index);
    }
    let (value, consumed_index) = match attached_value {
        Some(value) => (value, index),
        None => {
            let value =
                arguments
                    .get(index + 1)
                    .ok_or_else(|| CommandParserError::MissingOptionValue {
                        option: option.name.to_owned(),
                    })?;
            if value.starts_with("--") {
                return Err(CommandParserError::MissingOptionValue {
                    option: option.name.to_owned(),
                });
            }
            (value.as_str(), index + 1)
        }
    };
    validate_choice(option, value)?;
    let parsed = match option.kind {
        OptionValueKind::Integer => ArgumentValue::Integer(value.parse::<i64>().map_err(|_| {
            CommandParserError::InvalidInteger {
                option: option.name,
                value: value.to_owned(),
            }
        })?),
        OptionValueKind::Path => ArgumentValue::Path(value.into()),
        OptionValueKind::Text => ArgumentValue::Text(value.to_owned()),
        OptionValueKind::RepeatedText => {
            let mut entries = match values.remove(&option.argument) {
                Some(ArgumentValue::TextList(entries)) => entries,
                _ => Vec::new(),
            };
            entries.push(value.to_owned());
            ArgumentValue::TextList(entries)
        }
        OptionValueKind::Flag => unreachable!("flags return before value parsing"),
    };
    values.insert(option.argument, parsed);
    Ok(consumed_index)
}

// Enforces one option's closed value vocabulary when present.
fn validate_choice(option: OptionSpec, value: &str) -> Result<(), CommandParserError> {
    if !option.choices.is_empty() && !option.choices.contains(&value) {
        return Err(CommandParserError::InvalidChoice {
            option: option.name,
            value: value.to_owned(),
        });
    }
    Ok(())
}

// Binds ordered positional values and rejects missing or surplus input.
fn parse_positionals(
    specifications: &[PositionalSpec],
    positionals: &[String],
    values: &mut BTreeMap<ArgumentId, ArgumentValue>,
) -> Result<(), CommandParserError> {
    for (index, specification) in specifications.iter().enumerate() {
        match positionals.get(index) {
            Some(value) => {
                values.insert(
                    specification.argument,
                    ArgumentValue::Text(value.to_owned()),
                );
            }
            None if specification.required => {
                return Err(CommandParserError::MissingPositional {
                    argument: specification.argument,
                });
            }
            None => {}
        }
    }
    if let Some(value) = positionals.get(specifications.len()) {
        return Err(CommandParserError::UnexpectedPositional {
            value: value.to_owned(),
        });
    }
    Ok(())
}

// Enforces required options only after all last-value parsing completes.
fn validate_required_options(
    options: &[OptionSpec],
    values: &BTreeMap<ArgumentId, ArgumentValue>,
) -> Result<(), CommandParserError> {
    for option in options {
        if option.required && !values.contains_key(&option.argument) {
            return Err(CommandParserError::MissingRequiredOption {
                option: option.name,
            });
        }
    }
    Ok(())
}
