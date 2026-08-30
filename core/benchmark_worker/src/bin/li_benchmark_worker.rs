// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::process::ExitCode;

use li_benchmark_worker::run_native_benchmark_file;

// Starts the native worker only through its sealed input-file boundary.
fn main() -> ExitCode {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 3 || arguments[1] != "--input" {
        eprintln!("li_benchmark_worker: usage: li_benchmark_worker --input ABSOLUTE_PRIVATE_FILE");
        return ExitCode::FAILURE;
    }
    match run_native_benchmark_file(Path::new(&arguments[2])) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("li_benchmark_worker: {error}");
            ExitCode::FAILURE
        }
    }
}
