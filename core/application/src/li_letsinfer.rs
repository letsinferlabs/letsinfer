// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsStr;
use std::io::Write;
use std::process::ExitCode;

use li_core_application::{installed_core_cli_arguments, run_system_core_cli_process};
use li_core_cli::native_cli_root_help;

// Runs the public native CLI without a Python, shell, or direct-database fallback.
fn main() -> ExitCode {
    let mut process_arguments = std::env::args_os();
    let executable_name = process_arguments.next();
    let command_arguments = process_arguments.collect::<Vec<_>>();
    let public_launcher = executable_name
        .as_ref()
        .and_then(|value| std::path::Path::new(value).file_name())
        == Some(OsStr::new("letsinfer"));
    if public_launcher && root_help_requested(&command_arguments) {
        return present_root_help();
    }
    if public_launcher && root_version_requested(&command_arguments) {
        return present_root_version();
    }
    let arguments = if public_launcher {
        std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|_| ())
            .and_then(|executable| {
                installed_core_cli_arguments(&executable, command_arguments).map_err(|_| ())
            })
            .unwrap_or_default()
    } else {
        command_arguments
    };
    let owner_user_id = unsafe { libc::geteuid() };
    let mut standard_output = std::io::stdout().lock();
    let mut standard_error = std::io::stderr().lock();
    let status = run_system_core_cli_process(
        arguments,
        owner_user_id,
        &mut standard_output,
        &mut standard_error,
    );
    ExitCode::from(u8::try_from(status.as_i32()).unwrap_or(1))
}

// Returns whether the public launcher received the one configuration-free help invocation.
fn root_help_requested(arguments: &[std::ffi::OsString]) -> bool {
    arguments.len() == 1 && matches!(arguments[0].to_str(), Some("--help") | Some("-h"))
}

// Returns whether the public launcher received the one configuration-free version invocation.
fn root_version_requested(arguments: &[std::ffi::OsString]) -> bool {
    arguments.len() == 1 && arguments[0] == OsStr::new("--version")
}

// Presents root help without requiring an initialized Node or CLI configuration.
fn present_root_help() -> ExitCode {
    let mut standard_output = std::io::stdout().lock();
    if standard_output
        .write_all(native_cli_root_help().as_bytes())
        .is_ok()
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// Presents the shared Rust workspace version without requiring initialized Node state.
fn present_root_version() -> ExitCode {
    let mut standard_output = std::io::stdout().lock();
    if standard_output
        .write_all(concat!("letsinfer ", env!("CARGO_PKG_VERSION"), "\n").as_bytes())
        .is_ok()
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
