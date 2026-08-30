// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::OpenOptions;
use std::io::{Cursor, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use li_authentication_manager::{
    ControllerCertificate, ControllerCertificateError, ControllerCertificateMaterial,
    ControllerCertificateProvider, ControllerPublicKey,
};
use li_core_interface::{ControllerId, Sha256Digest, UnixMilliseconds};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType, SerialNumber, SubjectPublicKeyInfo,
};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const MAXIMUM_AUTHORITY_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAXIMUM_AUTHORITY_PRIVATE_KEY_BYTES: usize = 16 * 1024;
const CONTROLLER_CERTIFICATE_DAYS: i64 = 36_500;
const CONTROLLER_CERTIFICATE_CLOCK_SKEW_SECONDS: i64 = 300;
const CONTROLLER_CERTIFICATE_SERIAL_BYTES: usize = 20;
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

// Identifies the exact owner-only controller authority files selected by setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreControllerCertificateAuthorityFiles {
    owner_user_id: u32,
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}

impl CoreControllerCertificateAuthorityFiles {
    // Creates one unambiguous authority reference without opening either file.
    pub fn new(
        owner_user_id: u32,
        certificate_file: PathBuf,
        private_key_file: PathBuf,
    ) -> Result<Self, ControllerCertificateError> {
        if certificate_file == private_key_file
            || !normal_absolute_path(&certificate_file)
            || !normal_absolute_path(&private_key_file)
        {
            return Err(ControllerCertificateError::Unavailable);
        }
        Ok(Self {
            owner_user_id,
            certificate_file,
            private_key_file,
        })
    }
}

// Issues controller client certificates from setup's dedicated Watchdog controller authority.
pub struct RcgenCoreControllerCertificateProvider {
    authority: Certificate,
    authority_private_key: KeyPair,
    authority_certificate: CertificateDer<'static>,
}

impl RcgenCoreControllerCertificateProvider {
    // Loads, matches, and verifies the exact owner-only authority before accepting enrollment.
    pub fn load(
        files: &CoreControllerCertificateAuthorityFiles,
    ) -> Result<Self, ControllerCertificateError> {
        let certificate_bytes = read_private_file(
            &files.certificate_file,
            files.owner_user_id,
            MAXIMUM_AUTHORITY_CERTIFICATE_BYTES,
        )?;
        let private_key_bytes = read_private_file(
            &files.private_key_file,
            files.owner_user_id,
            MAXIMUM_AUTHORITY_PRIVATE_KEY_BYTES,
        )?;
        Self::from_pem(&certificate_bytes, &private_key_bytes)
    }

    // Constructs one provider from bounded PEM material for deterministic composition tests.
    pub fn from_pem(
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<Self, ControllerCertificateError> {
        let certificate_text = std::str::from_utf8(certificate_pem)
            .map_err(|_| ControllerCertificateError::Unavailable)?;
        let private_key_text = std::str::from_utf8(private_key_pem)
            .map_err(|_| ControllerCertificateError::Unavailable)?;
        let authority_certificate = one_certificate(certificate_pem)?;
        let authority_private_key = KeyPair::from_pem(private_key_text)
            .map_err(|_| ControllerCertificateError::Unavailable)?;
        let authority_parameters = CertificateParams::from_ca_cert_pem(certificate_text)
            .map_err(|_| ControllerCertificateError::Unavailable)?;
        if !matches!(authority_parameters.is_ca, IsCa::Ca(_)) {
            return Err(ControllerCertificateError::Unavailable);
        }
        let authority = authority_parameters
            .self_signed(&authority_private_key)
            .map_err(|_| ControllerCertificateError::Unavailable)?;
        let provider = Self {
            authority,
            authority_private_key,
            authority_certificate,
        };
        provider.verify_authority()?;
        Ok(provider)
    }

    // Proves that the retained authority key signs a currently valid client chain to the file CA.
    fn verify_authority(&self) -> Result<(), ControllerCertificateError> {
        let now = current_time()?;
        let not_before = maximum_time(
            now - time::Duration::seconds(CONTROLLER_CERTIFICATE_CLOCK_SKEW_SECONDS),
            self.authority.params().not_before,
        );
        let not_after = minimum_time(
            now + time::Duration::hours(1),
            self.authority.params().not_after,
        );
        if not_after <= now || not_after <= not_before {
            return Err(ControllerCertificateError::Unavailable);
        }
        let mut parameters = controller_parameters(
            "authority-check",
            not_before,
            not_after,
            &[1; CONTROLLER_CERTIFICATE_SERIAL_BYTES],
        )?;
        parameters.subject_alt_names.clear();
        let authority_public_key = self.authority_private_key.public_key_der();
        let public_key = SubjectPublicKeyInfo::from_der(&authority_public_key)
            .map_err(|_| ControllerCertificateError::Unavailable)?;
        let certificate = parameters
            .signed_by(&public_key, &self.authority, &self.authority_private_key)
            .map_err(|_| ControllerCertificateError::Unavailable)?;
        verify_client_certificate(
            &self.authority_certificate,
            certificate.der(),
            unix_time(now)?,
        )
    }

    // Issues one exact P-256 client certificate and preserves its DER fingerprint identity.
    fn issue_certificate(
        &self,
        controller_id: &ControllerId,
        public_key: &ControllerPublicKey,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        require_p256_spki(public_key.bytes())?;
        let subject_public_key = SubjectPublicKeyInfo::from_der(public_key.bytes())
            .map_err(|_| ControllerCertificateError::Invalid)?;
        let now = current_time()?;
        let not_before = maximum_time(
            now - time::Duration::seconds(CONTROLLER_CERTIFICATE_CLOCK_SKEW_SECONDS),
            self.authority.params().not_before,
        );
        let not_after = minimum_time(
            now + time::Duration::days(CONTROLLER_CERTIFICATE_DAYS),
            self.authority.params().not_after,
        );
        if not_after <= now || not_after <= not_before {
            return Err(ControllerCertificateError::Unavailable);
        }
        let mut serial = [0_u8; CONTROLLER_CERTIFICATE_SERIAL_BYTES];
        getrandom::fill(&mut serial).map_err(|_| ControllerCertificateError::Unavailable)?;
        if serial.iter().all(|byte| *byte == 0) {
            return Err(ControllerCertificateError::Unavailable);
        }
        let parameters =
            controller_parameters(controller_id.as_str(), not_before, not_after, &serial)?;
        let certificate = parameters
            .signed_by(
                &subject_public_key,
                &self.authority,
                &self.authority_private_key,
            )
            .map_err(|_| ControllerCertificateError::Unavailable)?;
        verify_client_certificate(
            &self.authority_certificate,
            certificate.der(),
            unix_time(now)?,
        )?;
        let material = certificate.der().as_ref().to_vec();
        ControllerCertificate::new(
            controller_id.clone(),
            digest(&material)?,
            public_key.sha256().clone(),
            material,
            unix_milliseconds(not_before)?,
            unix_milliseconds(not_after)?,
        )
    }
}

impl ControllerCertificateProvider for RcgenCoreControllerCertificateProvider {
    // Issues one authority-bound P-256 client certificate for a proven public key.
    fn issue(
        &self,
        controller_id: &ControllerId,
        public_key: &ControllerPublicKey,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        self.issue_certificate(controller_id, public_key)
    }

    // Rejects certificate import until the native cutover defines one complete import policy.
    fn import(
        &self,
        _controller_id: &ControllerId,
        _material: &ControllerCertificateMaterial,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        Err(ControllerCertificateError::Invalid)
    }
}

// Keeps controller enrollment unavailable on platforms without a controller authority closure.
#[derive(Default)]
pub struct UnavailableCoreControllerCertificateProvider;

impl ControllerCertificateProvider for UnavailableCoreControllerCertificateProvider {
    // Rejects issuance without the Linux controller authority generated by setup.
    fn issue(
        &self,
        _controller_id: &ControllerId,
        _public_key: &ControllerPublicKey,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        Err(ControllerCertificateError::Unavailable)
    }

    // Rejects import without a complete platform trust closure.
    fn import(
        &self,
        _controller_id: &ControllerId,
        _material: &ControllerCertificateMaterial,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        Err(ControllerCertificateError::Unavailable)
    }
}

// Creates the closed controller leaf profile shared by issuance and authority verification.
fn controller_parameters(
    controller_id: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    serial: &[u8],
) -> Result<CertificateParams, ControllerCertificateError> {
    let uri = format!("urn:letsinfer:controller:{controller_id}");
    let mut parameters = CertificateParams::new(Vec::<String>::new())
        .map_err(|_| ControllerCertificateError::Invalid)?;
    let mut name = DistinguishedName::new();
    name.push(
        DnType::CommonName,
        format!("Let's Infer controller {controller_id}"),
    );
    parameters.distinguished_name = name;
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    parameters.serial_number = Some(SerialNumber::from_slice(serial));
    parameters.subject_alt_names = vec![SanType::URI(
        uri.try_into()
            .map_err(|_| ControllerCertificateError::Invalid)?,
    )];
    parameters.is_ca = IsCa::NoCa;
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    parameters.use_authority_key_identifier_extension = true;
    Ok(parameters)
}

// Verifies one issued leaf against the exact authority certificate supplied to clients.
fn verify_client_certificate(
    authority: &CertificateDer<'static>,
    certificate: &CertificateDer<'static>,
    now: UnixTime,
) -> Result<(), ControllerCertificateError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(authority.clone())
        .map_err(|_| ControllerCertificateError::Unavailable)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| ControllerCertificateError::Unavailable)?;
    verifier
        .verify_client_cert(certificate, &[], now)
        .map(|_| ())
        .map_err(|_| ControllerCertificateError::Unavailable)
}

// Parses exactly one PEM certificate without accepting a hidden chain.
fn one_certificate(bytes: &[u8]) -> Result<CertificateDer<'static>, ControllerCertificateError> {
    let certificates = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ControllerCertificateError::Unavailable)?;
    match certificates.as_slice() {
        [certificate] => Ok(certificate.clone()),
        _ => Err(ControllerCertificateError::Unavailable),
    }
}

// Requires the exact uncompressed P-256 SubjectPublicKeyInfo accepted by enrollment proof.
fn require_p256_spki(bytes: &[u8]) -> Result<(), ControllerCertificateError> {
    if bytes.len() != 91 || !bytes.starts_with(P256_SPKI_PREFIX) {
        return Err(ControllerCertificateError::Invalid);
    }
    Ok(())
}

// Reads one retained owner-only regular file without following its final path component.
fn read_private_file(
    path: &Path,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ControllerCertificateError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ControllerCertificateError::Unavailable)?;
    let before = file
        .metadata()
        .map_err(|_| ControllerCertificateError::Unavailable)?;
    if !safe_private_file(&before, owner_user_id, maximum_bytes) {
        return Err(ControllerCertificateError::Unavailable);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ControllerCertificateError::Unavailable)?;
    let after = file
        .metadata()
        .map_err(|_| ControllerCertificateError::Unavailable)?;
    if bytes.is_empty()
        || bytes.len() > maximum_bytes
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || !safe_private_file(&after, owner_user_id, maximum_bytes)
    {
        return Err(ControllerCertificateError::Unavailable);
    }
    Ok(bytes)
}

// Requires one single-link owner-only nonempty regular material file.
fn safe_private_file(metadata: &std::fs::Metadata, owner: u32, maximum: usize) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == owner
        && metadata.mode() & 0o777 == 0o600
        && metadata.nlink() == 1
        && metadata.len() > 0
        && metadata.len() <= maximum as u64
}

// Returns current UTC only when the platform clock is inside the supported certificate range.
fn current_time() -> Result<OffsetDateTime, ControllerCertificateError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ControllerCertificateError::Unavailable)?
        .as_secs();
    let seconds = i64::try_from(seconds).map_err(|_| ControllerCertificateError::Unavailable)?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| ControllerCertificateError::Unavailable)
}

// Converts one nonnegative UTC time to the manager's exact millisecond boundary.
fn unix_milliseconds(
    value: OffsetDateTime,
) -> Result<UnixMilliseconds, ControllerCertificateError> {
    let milliseconds = value.unix_timestamp_nanos() / 1_000_000;
    let milliseconds =
        u64::try_from(milliseconds).map_err(|_| ControllerCertificateError::Unavailable)?;
    Ok(UnixMilliseconds::new(milliseconds))
}

// Converts one UTC time to rustls's second-resolution verification boundary.
fn unix_time(value: OffsetDateTime) -> Result<UnixTime, ControllerCertificateError> {
    let seconds = u64::try_from(value.unix_timestamp())
        .map_err(|_| ControllerCertificateError::Unavailable)?;
    Ok(UnixTime::since_unix_epoch(Duration::from_secs(seconds)))
}

// Computes the canonical lowercase SHA-256 identity of exact certificate DER.
fn digest(bytes: &[u8]) -> Result<Sha256Digest, ControllerCertificateError> {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| ControllerCertificateError::Unavailable)
}

// Selects the later of two trust boundaries.
fn maximum_time(left: OffsetDateTime, right: OffsetDateTime) -> OffsetDateTime {
    if left >= right {
        left
    } else {
        right
    }
}

// Selects the earlier of two trust boundaries.
fn minimum_time(left: OffsetDateTime, right: OffsetDateTime) -> OffsetDateTime {
    if left <= right {
        left
    } else {
        right
    }
}

// Returns whether a path is a normal non-root absolute path without resolving it.
fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}
