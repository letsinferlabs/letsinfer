// SPDX-License-Identifier: AGPL-3.0-only

use li_core_application::{run_core_gateway_process, CoreGatewayProcessArguments};

// Runs the strict native Gateway resident without a Python compatibility path.
fn main() {
    let result = CoreGatewayProcessArguments::parse(std::env::args_os().skip(1))
        .and_then(run_core_gateway_process);
    if let Err(error) = result {
        eprintln!("li_gateway: {error}");
        std::process::exit(1);
    }
}
