// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use li_authentication_manager::{
    ControllerCertificateError, ControllerCertificateMaterial, ControllerCertificateProvider,
    ControllerPublicKey,
};
use li_core_application::{
    CoreControllerCertificateAuthorityFiles, RcgenCoreControllerCertificateProvider,
    UnavailableCoreControllerCertificateProvider,
};
use li_core_interface::ControllerId;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SanType, PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};

// Returns one long-lived P-256 CA and its matching private key in setup-compatible PEM.
fn authority() -> (String, String) {
    let mut parameters = CertificateParams::new(Vec::<String>::new()).expect("parameters");
    parameters.not_before = rcgen::date_time_ymd(2020, 1, 1);
    parameters.not_after = rcgen::date_time_ymd(2120, 1, 1);
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("authority key");
    let certificate = parameters.self_signed(&key).expect("authority certificate");
    (certificate.pem(), key.serialize_pem())
}

// Returns one proof-compatible P-256 public key owned by the candidate fixture.
fn controller_public_key() -> ControllerPublicKey {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("controller key");
    ControllerPublicKey::new(key.public_key_der()).expect("controller public key")
}

// Issues one exact client profile and preserves canonical DER identities at the manager boundary.
#[test]
fn provider_issues_one_authority_bound_controller_certificate() {
    let (certificate, private_key) = authority();
    let provider = RcgenCoreControllerCertificateProvider::from_pem(
        certificate.as_bytes(),
        private_key.as_bytes(),
    )
    .expect("provider");
    let controller_id = ControllerId::parse(&"c".repeat(32)).expect("controller");
    let public_key = controller_public_key();
    let issued = provider
        .issue(&controller_id, &public_key)
        .expect("issued certificate");

    assert_eq!(issued.controller_id(), &controller_id);
    assert_eq!(issued.public_key_sha256(), public_key.sha256());
    assert_eq!(
        issued.certificate_sha256().as_str(),
        format!("{:x}", Sha256::digest(issued.public_material()))
    );
    assert!(issued.is_valid_at(issued.valid_from()));
    let parameters = CertificateParams::from_ca_cert_der(&issued.public_material().into())
        .expect("parse issued certificate");
    assert_eq!(parameters.is_ca, IsCa::NoCa);
    assert_eq!(
        parameters.key_usages,
        vec![KeyUsagePurpose::DigitalSignature]
    );
    assert_eq!(
        parameters.extended_key_usages,
        vec![ExtendedKeyUsagePurpose::ClientAuth]
    );
    assert!(matches!(
        parameters.subject_alt_names.as_slice(),
        [SanType::URI(value)] if value.as_str()
            == format!("urn:letsinfer:controller:{}", controller_id.as_str())
    ));
}

// Rejects mismatched authority material and malformed candidate keys without issuing a record.
#[test]
fn provider_rejects_every_untrusted_issuance_boundary() {
    let (certificate, _) = authority();
    let (_, unrelated_private_key) = authority();
    assert!(matches!(
        RcgenCoreControllerCertificateProvider::from_pem(
            certificate.as_bytes(),
            unrelated_private_key.as_bytes(),
        ),
        Err(ControllerCertificateError::Unavailable)
    ));

    let (certificate, private_key) = authority();
    let provider = RcgenCoreControllerCertificateProvider::from_pem(
        certificate.as_bytes(),
        private_key.as_bytes(),
    )
    .expect("provider");
    let controller_id = ControllerId::parse(&"c".repeat(32)).expect("controller");
    let malformed = ControllerPublicKey::new(vec![7; 96]).expect("bounded key");
    assert_eq!(
        provider.issue(&controller_id, &malformed),
        Err(ControllerCertificateError::Invalid)
    );
    assert_eq!(
        provider.import(
            &controller_id,
            &ControllerCertificateMaterial::new(vec![8; 256]).expect("material"),
        ),
        Err(ControllerCertificateError::Invalid)
    );
    let unavailable = UnavailableCoreControllerCertificateProvider;
    assert_eq!(
        unavailable.issue(&controller_id, &controller_public_key()),
        Err(ControllerCertificateError::Unavailable)
    );
}

// Loads only exact owner-only authority files and rejects relaxed private-key permissions.
#[test]
fn provider_loads_only_owner_private_authority_files() {
    let directory = tempfile::tempdir().expect("directory");
    let certificate_file = directory.path().join("controller-ca.crt");
    let private_key_file = directory.path().join("controller-ca.key");
    let (certificate, private_key) = authority();
    fs::write(&certificate_file, certificate).expect("certificate");
    fs::write(&private_key_file, private_key).expect("private key");
    fs::set_permissions(&certificate_file, fs::Permissions::from_mode(0o600))
        .expect("certificate mode");
    fs::set_permissions(&private_key_file, fs::Permissions::from_mode(0o600))
        .expect("private key mode");
    let files = CoreControllerCertificateAuthorityFiles::new(
        unsafe { libc::geteuid() },
        certificate_file,
        private_key_file.clone(),
    )
    .expect("files");
    let provider =
        Arc::new(RcgenCoreControllerCertificateProvider::load(&files).expect("loaded provider"));
    provider
        .issue(
            &ControllerId::parse(&"d".repeat(32)).expect("controller"),
            &controller_public_key(),
        )
        .expect("issued certificate");

    fs::set_permissions(&private_key_file, fs::Permissions::from_mode(0o644))
        .expect("relaxed mode");
    assert!(matches!(
        RcgenCoreControllerCertificateProvider::load(&files),
        Err(ControllerCertificateError::Unavailable)
    ));
}
