// SPDX-License-Identifier: AGPL-3.0-only

use std::process::ExitCode;

use li_core_application::{
    run_core_setup_process, SystemCoreSetupProcessApplicationRunner, SystemCoreSetupProcessIo,
};

// Runs the single-document native Core setup process and returns its stable status.
fn main() -> ExitCode {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let mut io = SystemCoreSetupProcessIo;
    let application = SystemCoreSetupProcessApplicationRunner;
    let status = run_core_setup_process(&arguments, &mut io, &application);
    ExitCode::from(u8::try_from(status).unwrap_or(1))
}
