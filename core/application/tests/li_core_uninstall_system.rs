// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

use li_core_application::{CoreUninstallNativeRemovalPort, SystemCoreUninstallNativeRemoval};

// Proves owner cleanup and exact launcher retirement do not require a shell or privilege helper.
#[test]
fn native_removal_validates_then_retires_exact_owner_targets() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    let tree = root.join("managed");
    fs::create_dir(&tree).expect("managed root");
    fs::write(tree.join("state"), b"managed").expect("managed state");
    fs::set_permissions(&tree, fs::Permissions::from_mode(0o500)).expect("immutable root");
    let executable = root.join("li_letsinfer");
    fs::write(&executable, b"binary").expect("executable");
    let launcher = root.join("letsinfer");
    symlink(&executable, &launcher).expect("launcher");
    let owner = unsafe { libc::geteuid() };
    let removal = SystemCoreUninstallNativeRemoval;

    removal
        .validate_owner_tree(&tree, owner)
        .expect("validated owner tree");
    removal
        .validate_launcher(&launcher, &executable, None, owner)
        .expect("validated launcher");
    removal
        .remove_launcher(&launcher, None, owner)
        .expect("removed launcher");
    removal
        .remove_owner_tree(&tree, owner)
        .expect("removed owner tree");

    assert!(!launcher.exists());
    assert!(!tree.exists());
    assert!(executable.exists());
}

// Proves a linked tree or launcher target drift is rejected before any target is removed.
#[test]
fn native_removal_rejects_links_and_launcher_drift_without_mutation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    let outside = root.join("outside");
    fs::create_dir(&outside).expect("outside root");
    let linked_tree = root.join("managed");
    symlink(&outside, &linked_tree).expect("linked tree");
    let executable = root.join("li_letsinfer");
    let other = root.join("other");
    fs::write(&executable, b"binary").expect("executable");
    fs::write(&other, b"other").expect("other executable");
    let launcher = root.join("letsinfer");
    symlink(&other, &launcher).expect("launcher");
    let owner = unsafe { libc::geteuid() };
    let removal = SystemCoreUninstallNativeRemoval;

    assert!(removal.validate_owner_tree(&linked_tree, owner).is_err());
    assert!(removal
        .validate_launcher(&launcher, &executable, None, owner)
        .is_err());
    assert!(linked_tree.exists());
    assert!(launcher.exists());
    assert!(outside.exists());
}
