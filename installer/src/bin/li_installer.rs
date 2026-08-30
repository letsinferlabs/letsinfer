// SPDX-License-Identifier: AGPL-3.0-only

use std::env;

use li_installer::li_installer_arguments::InstallerArguments;
use li_installer::li_installer_display_manager::DisplayManager;

// Parses the shell handoff and converts the native lifecycle into one exit status.
fn main() {
    let raw_arguments = env::args().skip(1).collect::<Vec<_>>();
    let progress_enabled = argument_boolean(&raw_arguments, "progress-enabled").unwrap_or(true);
    let mut display = DisplayManager::new(progress_enabled);
    let result = InstallerArguments::parse(&raw_arguments)
        .and_then(|arguments| li_installer::run(&arguments, &mut display));
    if let Err(error) = result {
        display.failure(&error);
        std::process::exit(1);
    }
}

// Returns one early display boolean without weakening full argument validation.
fn argument_boolean(arguments: &[String], name: &str) -> Option<bool> {
    let wanted = format!("--{}", name);
    arguments
        .windows(2)
        .find(|values| values[0] == wanted)
        .and_then(|values| match values[1].as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}
