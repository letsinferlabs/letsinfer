// SPDX-License-Identifier: AGPL-3.0-only

use li_core_application::run_core_watchdog_process;

// Runs the native Linux Watchdog with the exact CoreProcessLayout argument contract.
fn main() {
    if let Err(error) = run_core_watchdog_process(std::env::args_os().skip(1)) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
