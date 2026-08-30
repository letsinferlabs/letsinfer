// SPDX-License-Identifier: AGPL-3.0-only

use li_core_application::{run_core_node_process, CoreNodeProcessArguments};

// Runs the strict native Node resident without a Python compatibility path.
fn main() {
    let result = CoreNodeProcessArguments::parse(std::env::args_os().skip(1))
        .and_then(run_core_node_process);
    if let Err(error) = result {
        eprintln!("li_node: {error}");
        std::process::exit(1);
    }
}
