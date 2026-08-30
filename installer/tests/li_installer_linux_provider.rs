// SPDX-License-Identifier: AGPL-3.0-only

use li_installer::li_installer_dependency_manager::{manage, DependencyManagerResult, ManagerMode};
use li_installer::li_installer_linux_provider;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const TEST_SCHEMA_ENVIRONMENT: &str = "LI_INSTALLER_TEST_SCHEMA";
const TEST_VALIDATOR_ENVIRONMENT: &str = "LI_INSTALLER_TEST_VALIDATOR";

// Returns the public repository root containing deterministic installer fixtures.
fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("installer should have a repository parent")
        .to_path_buf()
}

// Appends one exact native-provider argument pair.
fn push_argument(arguments: &mut Vec<String>, name: &str, value: impl AsRef<str>) {
    arguments.push(format!("--{}", name));
    arguments.push(value.as_ref().to_string());
}

// Returns one complete Linux provider composition for a deterministic fixture.
fn provider_arguments(fixture_name: &str, platform: &str) -> Vec<String> {
    let root = repository_root();
    let fixture = root.join("tests/li_installer/fixtures").join(fixture_name);
    let bin = fixture.join("bin");
    let mut arguments = Vec::new();
    for (name, value) in [
        ("platform", platform.to_string()),
        ("mode", "fixture".to_string()),
        (
            "schema-file",
            root.join("schemas/li_installer_installation_probe_v1.schema.json")
                .to_string_lossy()
                .into_owned(),
        ),
        ("status", "missing_dependencies".to_string()),
        (
            "missing-dependencies",
            "avahi_browse,avahi_publish_service".to_string(),
        ),
        ("service-manager-provider", "systemd".to_string()),
        ("service-manager-scope", "user".to_string()),
        ("service-manager-user-domain-available", "true".to_string()),
        (
            "service-persistence-mechanism",
            "systemd-linger".to_string(),
        ),
        ("service-persistence-available", "true".to_string()),
    ] {
        push_argument(&mut arguments, name, value);
    }
    let date = bin.join("date").to_string_lossy().into_owned();
    let dependencies = vec![
        ("curl", date.clone()),
        ("gh", date.clone()),
        ("mktemp", date.clone()),
        ("openssl", date.clone()),
        ("ssh", date.clone()),
        ("ssh_keygen", date.clone()),
        ("sudo", date.clone()),
        ("tar", date.clone()),
        (
            "apt_get",
            bin.join("apt-get").to_string_lossy().into_owned(),
        ),
        ("avahi_browse", String::new()),
        ("avahi_publish_service", String::new()),
        ("dnf", String::new()),
        ("docker", bin.join("docker").to_string_lossy().into_owned()),
        ("loginctl", date.clone()),
        (
            "nvidia_ctk",
            bin.join("nvidia-ctk").to_string_lossy().into_owned(),
        ),
        (
            "nvidia_smi",
            bin.join("nvidia-smi").to_string_lossy().into_owned(),
        ),
        ("pacman", String::new()),
        ("sg", String::new()),
        ("stat", String::new()),
        ("systemctl", date.clone()),
        ("systemd_run", date),
        ("zypper", String::new()),
    ];
    for (name, path) in dependencies {
        push_argument(&mut arguments, "dependency", format!("{}={}", name, path));
    }
    for name in [
        "avahi_browse",
        "avahi_publish_service",
        "docker",
        "nvidia_ctk",
        "openssl",
        "ssh",
    ] {
        push_argument(&mut arguments, "installable-dependency", name);
    }
    for (name, path) in [
        ("date-command", bin.join("date")),
        ("uname-command", bin.join("uname")),
        ("getconf-command", bin.join("getconf")),
        ("lscpu-command", bin.join("lscpu")),
        ("nvidia-smi-command", bin.join("nvidia-smi")),
        ("docker-command", bin.join("docker")),
        ("nvidia-ctk-command", bin.join("nvidia-ctk")),
        ("os-release-file", fixture.join("root/etc/os-release")),
        ("meminfo-file", fixture.join("root/proc/meminfo")),
        ("cpuinfo-file", fixture.join("root/proc/cpuinfo")),
        (
            "boot-id-file",
            fixture.join("root/proc/sys/kernel/random/boot_id"),
        ),
    ] {
        push_argument(&mut arguments, name, path.to_string_lossy());
    }
    arguments
}

// Validates one produced document through the canonical external Rust validator when bound.
fn validate_wire_document(platform: &str, document: &str) {
    let schema = env::var_os(TEST_SCHEMA_ENVIRONMENT);
    let validator = env::var_os(TEST_VALIDATOR_ENVIRONMENT);
    if schema.is_none() && validator.is_none() {
        return;
    }
    let schema = schema.expect("validator schema should accompany the validator command");
    let validator = validator.expect("validator command should accompany its schema");
    let temporary = env::temp_dir().join(format!(
        "li_installer_provider_validator_{}_{}.json",
        std::process::id(),
        platform.replace('-', "_")
    ));
    fs::write(&temporary, document).expect("provider document should be written");
    let output = Command::new(validator)
        .arg(schema)
        .arg(&temporary)
        .output()
        .expect("Rust validator should run");
    fs::remove_file(&temporary).expect("provider document should be removed");
    assert!(
        output.status.success(),
        "validator rejected {platform}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

// Runs both Linux architecture fixtures from the provider through the Rust validator wire.
#[test]
fn linux_platform_documents_cross_the_rust_validator_wire() {
    for (fixture, platform, architecture) in [
        ("li_installer_linux_arm64", "linux-arm64", "sm_121"),
        ("li_installer_linux_x86_64", "linux-x86_64", "sm_120"),
    ] {
        let document = li_installer_linux_provider::observe(&provider_arguments(fixture, platform))
            .expect("Linux fixture should produce a probe");
        let value: Value = serde_json::from_str(&document).expect("probe should be JSON");
        assert_eq!(
            value
                .pointer("/platform/identifier")
                .and_then(Value::as_str),
            Some(platform)
        );
        assert_eq!(
            value
                .pointer("/hardware/accelerators/0/compute/architecture")
                .and_then(Value::as_str),
            Some(architecture)
        );
        validate_wire_document(platform, &document);
    }
}

// Runs an injected package transaction through the internal dependency manager.
#[test]
fn applies_linux_dependency_fixture() {
    let root = repository_root();
    let fixture = root.join("tests/li_installer/fixtures/li_installer_linux_arm64");
    let document = li_installer_linux_provider::observe(&provider_arguments(
        "li_installer_linux_arm64",
        "linux-arm64",
    ))
    .expect("Linux fixture should produce a probe");
    let temporary = std::env::temp_dir().join(format!(
        "li_installer_dependency_fixture_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temporary);
    fs::create_dir(&temporary).expect("temporary fixture root should be created");
    let probe = temporary.join("probe.json");
    fs::write(&probe, document).expect("probe fixture should be written");
    let result = manage(ManagerMode::Apply, &probe, &fixture.join("bin/id"))
        .expect("dependency fixture should apply");
    assert_eq!(result, DependencyManagerResult::Installed);
    fs::remove_dir_all(&temporary).expect("temporary fixture root should be removed");
}
