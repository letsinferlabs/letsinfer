// SPDX-License-Identifier: AGPL-3.0-only

use li_installer_validator::validate_installation_probe;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

// Loads the exact installation-probe schema under test.
fn schema() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../schemas/li_installer_installation_probe_v1.schema.json");
    serde_json::from_str(&fs::read_to_string(path).expect("schema should be readable"))
        .expect("schema should be JSON")
}

// Returns one dependency observation with its version, path, and install policy.
fn dependency(version: &str, path: &str, installable: bool) -> Value {
    json!({"version": version, "path": path, "installable": installable})
}

// Returns one complete valid Linux ARM64 installation-probe document.
fn valid_document() -> Value {
    json!({
        "schema": {"name": "letsinfer.installer.installation-probe", "version": 1},
        "status": "ready",
        "platform": {
            "os": "linux",
            "architecture": "arm64",
            "identifier": "linux-arm64"
        },
        "service_manager": {
            "provider": "systemd",
            "scope": "user",
            "user_domain_available": true,
            "persistence": {
                "mechanism": "systemd-linger",
                "available": true
            }
        },
        "dependencies": {
            "curl": dependency("curl fixture", "/mock/curl", false),
            "gh": dependency("gh version 2.97.0 (fixture)", "/mock/gh", true),
            "mktemp": dependency("", "/mock/mktemp", false),
            "openssl": dependency("OpenSSL fixture", "/mock/openssl", true),
            "ssh": dependency("OpenSSH fixture", "/mock/ssh", true),
            "ssh_keygen": dependency("OpenSSH fixture", "/mock/ssh-keygen", false),
            "sudo": dependency("sudo fixture", "/mock/sudo", false),
            "tar": dependency("tar fixture", "/mock/tar", false),
            "loginctl": dependency("systemd fixture", "/mock/loginctl", false),
            "systemctl": dependency("systemd fixture", "/mock/systemctl", false),
            "systemd_run": dependency("systemd fixture", "/mock/systemd-run", false)
        },
        "hardware": {
            "provider": {"id": "linux", "mode": "fixture"},
            "observation": {
                "observed_at_unix": 1_700_000_001_u64,
                "boot_id": "fixture-boot"
            },
            "operating_system": {
                "distribution": "ubuntu",
                "version": "24.04",
                "build": null,
                "kernel_version": "6.17.0-fixture"
            },
            "host": {
                "hardware_model": null,
                "cpu_model": "Cortex-X925 Fixture",
                "logical_cpu_count": 20,
                "memory_bytes": 128_000_000_000_u64,
                "memory_source": "proc-meminfo"
            },
            "accelerators": [{
                "index": 0,
                "vendor": "nvidia",
                "vendor_name": "NVIDIA",
                "name": "NVIDIA GB10 Fixture",
                "uuid": "GPU-FIXTURE",
                "pci_address": "0000000F:01:00.0",
                "driver": {"version": "580.159.03", "source": "nvidia-smi"},
                "compute": {
                    "api": "cuda",
                    "version": "13.0",
                    "capability": "12.1",
                    "architecture": "sm_121",
                    "family": null
                },
                "memory": {
                    "topology": "unified",
                    "framebuffer_bytes": null,
                    "addressing_mode": "ATS"
                },
                "partitioning": {"mig_mode": null},
                "gpu_core_count": null,
                "bus": null
            }],
            "software": {
                "docker_version": "29.2.1",
                "nvidia_container_toolkit_version": "1.20.0",
                "nvidia_cuda_max_version": "13.0"
            },
            "topology": {"mutable_links_observed": false}
        },
        "errors": []
    })
}

// Returns all structural and semantic errors for one document.
fn validation_errors(document: &Value) -> Vec<String> {
    validate_installation_probe(&schema(), document)
}

// Accepts one complete valid installation probe.
#[test]
fn accepts_valid_document() {
    assert!(validation_errors(&valid_document()).is_empty());
}

// Rejects an unknown field through the closed JSON Schema shape.
#[test]
fn rejects_unknown_field() {
    let mut document = valid_document();
    document["unexpected"] = Value::Bool(true);
    assert!(validation_errors(&document)
        .iter()
        .any(|error| error.contains("unknown property")));
}

// Rejects an NVIDIA SM architecture that differs from compute capability.
#[test]
fn rejects_incorrect_sm_architecture() {
    let mut document = valid_document();
    document["hardware"]["accelerators"][0]["compute"]["architecture"] =
        Value::String("sm_120".to_string());
    assert!(validation_errors(&document)
        .iter()
        .any(|error| error.contains("does not match")));
}

// Rejects unified NVIDIA memory without ATS addressing.
#[test]
fn rejects_unified_nvidia_memory_without_ats() {
    let mut document = valid_document();
    document["hardware"]["accelerators"][0]["memory"]["addressing_mode"] =
        Value::String("HMM".to_string());
    assert!(validation_errors(&document)
        .iter()
        .any(|error| error.contains("requires ATS")));
}

// Rejects readiness when the document carries dependency errors.
#[test]
fn rejects_ready_document_with_dependency_errors() {
    let mut document = valid_document();
    document["errors"] = json!(["missing dependency: curl"]);
    assert!(validation_errors(&document)
        .iter()
        .any(|error| error.contains("ready document has errors")));
}

// Rejects a dependency that omits its explicit install policy.
#[test]
fn rejects_dependency_without_install_policy() {
    let mut document = valid_document();
    document["dependencies"]["curl"]
        .as_object_mut()
        .expect("dependency should be an object")
        .remove("installable");
    assert!(validation_errors(&document)
        .iter()
        .any(|error| error.contains("missing required property installable")));
}

// Rejects a probe that omits the GitHub CLI observation emitted on every platform.
#[test]
fn rejects_missing_github_cli_observation() {
    let mut document = valid_document();
    document["dependencies"]
        .as_object_mut()
        .expect("dependencies should be an object")
        .remove("gh");
    assert!(validation_errors(&document)
        .iter()
        .any(|error| error.contains("missing required property gh")));
}

// Accepts a fail-closed Linux observation when systemd lingering is disabled.
#[test]
fn accepts_unavailable_systemd_linger() {
    let mut document = valid_document();
    document["status"] = Value::String("service_manager_unavailable".to_string());
    document["service_manager"]["persistence"]["available"] = Value::Bool(false);
    document["errors"] = json!(["service persistence is unavailable: systemd-linger"]);
    assert!(validation_errors(&document).is_empty());
}

// Rejects readiness when Linux systemd lingering is disabled.
#[test]
fn rejects_ready_document_without_systemd_linger() {
    let mut document = valid_document();
    document["service_manager"]["persistence"]["available"] = Value::Bool(false);
    assert!(validation_errors(&document)
        .iter()
        .any(|error| error.contains("unavailable state has no error")));
}
