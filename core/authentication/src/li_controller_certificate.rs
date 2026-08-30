// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use li_core_interface::{ControllerId, Sha256Digest, UnixMilliseconds};
use sha2::{Digest, Sha256};

const MAXIMUM_CONTROLLER_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAXIMUM_CONTROLLER_PUBLIC_KEY_BYTES: usize = 256;
const MINIMUM_CONTROLLER_PUBLIC_KEY_BYTES: usize = 64;

// Owns bounded public-key bytes supplied by a controller without accepting private material.
#[derive(Clone, Eq, PartialEq)]
pub struct ControllerPublicKey {
    bytes: Vec<u8>,
    sha256: Sha256Digest,
}

impl ControllerPublicKey {
    // Validates one bounded public-key document and computes its immutable identity.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ControllerCertificateError> {
        if bytes.len() < MINIMUM_CONTROLLER_PUBLIC_KEY_BYTES
            || bytes.len() > MAXIMUM_CONTROLLER_PUBLIC_KEY_BYTES
        {
            return Err(ControllerCertificateError::Invalid);
        }
        let sha256 = digest(&bytes)?;
        Ok(Self { bytes, sha256 })
    }

    // Returns the public-key bytes only to the injected certificate provider.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    // Returns the canonical digest of the exact public-key bytes.
    pub const fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
}

impl fmt::Debug for ControllerPublicKey {
    // Presents only public-key size and identity without copying material into diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerPublicKey")
            .field(
                "bytes",
                &format_args!("<public material; {} bytes>", self.bytes.len()),
            )
            .field("sha256", &self.sha256)
            .finish()
    }
}

// Owns bounded certificate bytes supplied for validation and import.
#[derive(Clone, Eq, PartialEq)]
pub struct ControllerCertificateMaterial(Vec<u8>);

impl ControllerCertificateMaterial {
    // Accepts one nonempty bounded public certificate document.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ControllerCertificateError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_CONTROLLER_CERTIFICATE_BYTES {
            return Err(ControllerCertificateError::Invalid);
        }
        Ok(Self(bytes))
    }

    // Returns public certificate bytes only to the injected validation provider.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ControllerCertificateMaterial {
    // Presents only certificate size without embedding its material in diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_fmt(format_args!("<public certificate; {} bytes>", self.0.len()))
    }
}

// Stores one provider-validated controller certificate and its canonical DER identities.
#[derive(Clone, Eq, PartialEq)]
pub struct ControllerCertificate {
    controller_id: ControllerId,
    certificate_sha256: Sha256Digest,
    public_key_sha256: Sha256Digest,
    public_material: Vec<u8>,
    valid_from: UnixMilliseconds,
    expires_at: UnixMilliseconds,
}

impl ControllerCertificate {
    // Creates one certificate only when its DER, fingerprint, identity, and lifetime agree.
    pub fn new(
        controller_id: ControllerId,
        certificate_sha256: Sha256Digest,
        public_key_sha256: Sha256Digest,
        public_material: Vec<u8>,
        valid_from: UnixMilliseconds,
        expires_at: UnixMilliseconds,
    ) -> Result<Self, ControllerCertificateError> {
        if public_material.is_empty()
            || public_material.len() > MAXIMUM_CONTROLLER_CERTIFICATE_BYTES
            || digest(&public_material)? != certificate_sha256
            || expires_at <= valid_from
        {
            return Err(ControllerCertificateError::Invalid);
        }
        Ok(Self {
            controller_id,
            certificate_sha256,
            public_key_sha256,
            public_material,
            valid_from,
            expires_at,
        })
    }

    // Returns the controller identity asserted by the validated certificate.
    pub const fn controller_id(&self) -> &ControllerId {
        &self.controller_id
    }

    // Returns the canonical SHA-256 of the exact certificate bytes.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }

    // Returns the canonical SHA-256 of the certificate's exact public key.
    pub const fn public_key_sha256(&self) -> &Sha256Digest {
        &self.public_key_sha256
    }

    // Returns the validated canonical certificate DER for persistence or presentation.
    pub fn public_material(&self) -> &[u8] {
        &self.public_material
    }

    // Returns the inclusive certificate-validity boundary.
    pub const fn valid_from(&self) -> UnixMilliseconds {
        self.valid_from
    }

    // Returns the exclusive certificate-expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns whether this certificate is currently inside its provider-validated lifetime.
    pub const fn is_valid_at(&self, now: UnixMilliseconds) -> bool {
        now.value() >= self.valid_from.value() && now.value() < self.expires_at.value()
    }
}

impl fmt::Debug for ControllerCertificate {
    // Presents identities and bounds without embedding certificate bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerCertificate")
            .field("controller_id", &self.controller_id)
            .field("certificate_sha256", &self.certificate_sha256)
            .field("public_key_sha256", &self.public_key_sha256)
            .field(
                "public_material",
                &format_args!("<public certificate; {} bytes>", self.public_material.len()),
            )
            .field("valid_from", &self.valid_from)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

// Isolates certificate issuance and public-certificate validation from manager policy.
pub trait ControllerCertificateProvider: Send + Sync {
    // Issues one public controller certificate for an exact validated public key.
    fn issue(
        &self,
        controller_id: &ControllerId,
        public_key: &ControllerPublicKey,
    ) -> Result<ControllerCertificate, ControllerCertificateError>;

    // Validates one imported public certificate for an exact controller identity.
    fn import(
        &self,
        controller_id: &ControllerId,
        material: &ControllerCertificateMaterial,
    ) -> Result<ControllerCertificate, ControllerCertificateError>;
}

// Describes one fixed certificate-provider failure without material or native diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControllerCertificateError {
    Invalid,
    Unavailable,
}

impl fmt::Display for ControllerCertificateError {
    // Presents stable language without certificate, key, or provider details.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => formatter.write_str("controller certificate is invalid"),
            Self::Unavailable => {
                formatter.write_str("controller certificate provider is unavailable")
            }
        }
    }
}

impl Error for ControllerCertificateError {}

// Computes one canonical lowercase SHA-256 identity for public material.
fn digest(bytes: &[u8]) -> Result<Sha256Digest, ControllerCertificateError> {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| ControllerCertificateError::Invalid)
}
