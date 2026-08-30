// SPDX-License-Identifier: AGPL-3.0-only

use li_installer_validator::validate_installation_probe;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

// Loads one JSON document with a concise path-specific error.
fn load_json(path: &Path) -> Result<Value, String> {
    let file = File::open(path)
        .map_err(|error| format!("cannot open JSON {}: {}", path.display(), error))?;
    serde_json::from_reader(BufReader::new(file))
        .map_err(|error| format!("cannot parse JSON {}: {}", path.display(), error))
}

// Validates one schema/document pair and returns its process result.
fn validate_probe_files(schema_path: &str, document_path: &str) -> Result<(), String> {
    let schema = load_json(Path::new(schema_path))?;
    let document = load_json(Path::new(document_path))?;
    let errors = validate_installation_probe(&schema, &document);
    if errors.is_empty() {
        return Ok(());
    }
    for error in &errors {
        eprintln!("{}", error);
    }
    Err(format!(
        "installation probe failed validation with {} error(s)",
        errors.len()
    ))
}

// Selects the exact installation-probe validation contract.
fn run(arguments: &[String]) -> Result<(), String> {
    match arguments {
        [schema, document] => validate_probe_files(schema, document),
        _ => Err("usage: li_installer_validate SCHEMA DOCUMENT".to_string()),
    }
}

// Converts the validator result into one stable process exit status.
fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if let Err(error) = run(&arguments) {
        eprintln!("{}", error);
        std::process::exit(1);
    }
}
