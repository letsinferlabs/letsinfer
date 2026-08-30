// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use li_core_interface::{InstallationId, PairingInviteId, Sha256Digest};
use li_pairing_manager::{
    HmacPairingSetupCodeProvider, PairingError, PairingSetupCodeProvider, PairingSetupSecretFile,
    PairingSetupSecretFileProvider, PairingSetupSecretFileReference,
    SystemPairingSetupSecretFileProvider,
};

// Supplies one exact descriptor observation or one injected native read failure.
struct TestSecretFileProvider {
    file: Option<(u32, u32, u64, bool, Vec<u8>)>,
}

impl PairingSetupSecretFileProvider for TestSecretFileProvider {
    // Returns one fresh secret observation so each load exercises ownership transfer and clearing.
    fn read_no_follow(&self, _path: &Path) -> Result<PairingSetupSecretFile, PairingError> {
        let (owner, mode, links, regular, bytes) =
            self.file.as_ref().ok_or(PairingError::StateUnavailable)?;
        Ok(PairingSetupSecretFile::new(
            *owner,
            *mode,
            *links,
            *regular,
            bytes.clone(),
        ))
    }
}

// Creates one exact owner-bound absolute test reference.
fn reference(owner_user_id: u32) -> PairingSetupSecretFileReference {
    PairingSetupSecretFileReference::new(
        PathBuf::from("/var/lib/letsinfer/secrets/pairing_setup.key"),
        owner_user_id,
    )
    .expect("secret reference")
}

// Loads one HMAC provider from the supplied descriptor-shaped observation.
fn load(
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    regular_file: bool,
    bytes: Vec<u8>,
) -> Result<HmacPairingSetupCodeProvider, PairingError> {
    HmacPairingSetupCodeProvider::load(
        &reference(owner_user_id),
        &TestSecretFileProvider {
            file: Some((owner_user_id, mode, link_count, regular_file, bytes)),
        },
    )
}

// Returns one canonical installation identity used by deterministic derivation tests.
fn installation(character: char) -> InstallationId {
    InstallationId::parse(&character.to_string().repeat(64)).expect("installation")
}

// Returns one canonical invitation identity used by deterministic derivation tests.
fn invitation(character: char) -> PairingInviteId {
    PairingInviteId::parse(&character.to_string().repeat(32)).expect("invitation")
}

// Returns one canonical nonce used by deterministic derivation tests.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Proves restart-stable decimal derivation and binding to every invitation identity input.
#[test]
fn hmac_derivation_is_restart_stable_and_bound_to_every_input() {
    let first = load(501, 0o600, 1, true, vec![0x31; 32]).expect("first provider");
    let restarted = load(501, 0o600, 1, true, vec![0x31; 32]).expect("restarted provider");
    let salt = [0x41; 16];
    let ordinary = first
        .derive(&installation('1'), &invitation('2'), &digest('3'), &salt)
        .expect("ordinary code");

    assert_eq!(
        restarted
            .derive(&installation('1'), &invitation('2'), &digest('3'), &salt)
            .expect("restart code"),
        ordinary
    );
    assert!(ordinary.iter().all(u8::is_ascii_digit));
    let mutations = [
        first.derive(&installation('4'), &invitation('2'), &digest('3'), &salt),
        first.derive(&installation('1'), &invitation('4'), &digest('3'), &salt),
        first.derive(&installation('1'), &invitation('2'), &digest('4'), &salt),
        first.derive(
            &installation('1'),
            &invitation('2'),
            &digest('3'),
            &[0x42; 16],
        ),
    ];
    assert!(mutations
        .into_iter()
        .all(|result| result.expect("mutated code") != ordinary));
}

// Rejects every unsafe metadata, size, path, and provider failure without exposing secret bytes.
#[test]
fn hmac_secret_loading_fails_closed_and_redacts_diagnostics() {
    let invalid = [
        load(501, 0o640, 1, true, vec![0x51; 32]),
        load(501, 0o600, 2, true, vec![0x51; 32]),
        load(501, 0o600, 1, false, vec![0x51; 32]),
        load(501, 0o600, 1, true, vec![0x51; 31]),
        load(501, 0o600, 1, true, vec![0x51; 33]),
    ];
    assert!(invalid
        .into_iter()
        .all(|result| matches!(result, Err(PairingError::StateUnavailable))));
    let wrong_owner = HmacPairingSetupCodeProvider::load(
        &reference(501),
        &TestSecretFileProvider {
            file: Some((502, 0o600, 1, true, vec![0x51; 32])),
        },
    );
    assert!(matches!(wrong_owner, Err(PairingError::StateUnavailable)));
    let provider_failure =
        HmacPairingSetupCodeProvider::load(&reference(501), &TestSecretFileProvider { file: None });
    assert!(matches!(
        provider_failure,
        Err(PairingError::StateUnavailable)
    ));
    assert!(matches!(
        PairingSetupSecretFileReference::new(PathBuf::from("relative.key"), 501),
        Err(PairingError::InvalidRequest { .. })
    ));

    let observed = PairingSetupSecretFile::new(501, 0o600, 1, true, b"private-secret".to_vec());
    let provider = load(501, 0o600, 1, true, vec![0x51; 32]).expect("provider");
    let diagnostics = format!("{observed:?} {provider:?}");
    assert!(diagnostics.contains("<redacted>"));
    assert!(!diagnostics.contains("private-secret"));
    assert!(!diagnostics.contains(&"51".repeat(32)));
}

// Exercises production no-follow I/O against an ordinary owner-only file, hard link, and symlink.
#[test]
fn system_secret_reader_requires_one_owner_only_regular_descriptor() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("pairing_setup.key");
    fs::write(&path, vec![0x61; 32]).expect("write secret");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secret permissions");
    let owner_user_id = fs::metadata(&path).expect("secret metadata").uid();
    let reference =
        PairingSetupSecretFileReference::new(path.clone(), owner_user_id).expect("reference");
    HmacPairingSetupCodeProvider::load(&reference, &SystemPairingSetupSecretFileProvider)
        .expect("system secret");

    let hard_link = directory.path().join("pairing_setup_hard_link.key");
    fs::hard_link(&path, hard_link).expect("hard link");
    assert!(matches!(
        HmacPairingSetupCodeProvider::load(&reference, &SystemPairingSetupSecretFileProvider),
        Err(PairingError::StateUnavailable)
    ));

    let symlink_path = directory.path().join("pairing_setup_symlink.key");
    symlink(&path, &symlink_path).expect("symlink");
    let symlink_reference = PairingSetupSecretFileReference::new(symlink_path, owner_user_id)
        .expect("symlink reference");
    assert!(matches!(
        HmacPairingSetupCodeProvider::load(
            &symlink_reference,
            &SystemPairingSetupSecretFileProvider,
        ),
        Err(PairingError::StateUnavailable)
    ));
}
