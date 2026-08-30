// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use li_placement_manager::{
    PlacementError, ShellFreeCommand, ShellFreeCommandRunner, ShellFreeEnvironmentValue,
    SystemShellFreeCommandRunner,
};

// Returns one ordinary validated shell-free command fixture.
fn command(arguments: Vec<String>) -> ShellFreeCommand {
    ShellFreeCommand::new(
        PathBuf::from("/usr/bin/printf"),
        arguments,
        vec![ShellFreeEnvironmentValue::runtime("RUNTIME_MODE", "serve").expect("runtime")],
        vec![
            ShellFreeEnvironmentValue::core("PATH", "/usr/bin:/bin").expect("path"),
            ShellFreeEnvironmentValue::protected("LETSINFER_TASK_ID", "task-0").expect("protected"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("command")
}

// Rejects relative executables and every common shell trampoline.
#[test]
fn command_rejects_relative_and_shell_executables() {
    for executable in ["docker", "/bin/sh", "/bin/bash", "/usr/bin/env", "/bin/zsh"] {
        assert!(ShellFreeCommand::new(
            PathBuf::from(executable),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PathBuf::from("/tmp"),
        )
        .is_err());
    }
}

// Enforces runtime/Core environment ownership and protected namespace isolation.
#[test]
fn command_rejects_environment_override_and_owner_confusion() {
    assert!(ShellFreeEnvironmentValue::runtime("LETSINFER_SECRET", "value").is_err());
    assert!(ShellFreeEnvironmentValue::protected("HOME", "/tmp").is_err());
    let core = ShellFreeEnvironmentValue::core("HOME", "/tmp").expect("Core environment");
    assert!(ShellFreeCommand::new(
        PathBuf::from("/usr/bin/printf"),
        Vec::new(),
        vec![core],
        Vec::new(),
        PathBuf::from("/tmp"),
    )
    .is_err());
    let duplicate = ShellFreeEnvironmentValue::runtime("RUNTIME_MODE", "serve").expect("value");
    assert!(ShellFreeCommand::new(
        PathBuf::from("/usr/bin/printf"),
        Vec::new(),
        vec![duplicate.clone(), duplicate],
        Vec::new(),
        PathBuf::from("/tmp"),
    )
    .is_err());
}

// Rejects control characters, empty argv values, and relative working directories.
#[test]
fn command_rejects_ambiguous_arguments_and_working_directory() {
    assert!(ShellFreeCommand::new(
        PathBuf::from("/usr/bin/printf"),
        vec![String::new()],
        Vec::new(),
        Vec::new(),
        PathBuf::from("/tmp"),
    )
    .is_err());
    assert!(ShellFreeCommand::new(
        PathBuf::from("/usr/bin/printf"),
        vec!["unsafe\nargument".to_string()],
        Vec::new(),
        Vec::new(),
        PathBuf::from("relative"),
    )
    .is_err());
}

// Reuses only sealed executable, environment, and working-directory identity.
#[test]
fn derived_command_replaces_only_argv() {
    let original = command(vec!["%s".to_string(), "first".to_string()]);
    let derived = original
        .with_arguments(vec!["%s".to_string(), "second".to_string()])
        .expect("derived");
    assert_eq!(derived.executable(), original.executable());
    assert_eq!(derived.environment(), original.environment());
    assert_eq!(derived.working_directory(), original.working_directory());
    assert_eq!(derived.arguments(), ["%s", "second"]);
}

// Executes direct argv with a cleared explicit environment and bounded output.
#[test]
fn system_runner_executes_without_shell_or_unbounded_output() {
    let runner = SystemShellFreeCommandRunner;
    let command = command(vec!["%s".to_string(), "hello".to_string()]);
    let output = runner.run(&command, 32).expect("run");
    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"hello");
    assert_eq!(
        runner.run(&command, 3).expect_err("output bound"),
        PlacementError::ExecutionUnavailable
    );

    let directory = tempfile::tempdir().expect("temporary directory");
    let link = directory.path().join("printf-link");
    std::os::unix::fs::symlink("/usr/bin/printf", &link).expect("symlink");
    let linked = ShellFreeCommand::new(
        link,
        vec!["%s".to_string(), "unsafe".to_string()],
        Vec::new(),
        Vec::new(),
        PathBuf::from("/tmp"),
    )
    .expect("linked command");
    assert_eq!(
        runner.run(&linked, 32).expect_err("symlink executable"),
        PlacementError::ExecutionUnavailable
    );
}
