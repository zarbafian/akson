//! Self-issued Ed25519 X.509 endpoint certificates (ADR-0011, design §8.3).
//!
//! Personal-profile endpoints present a self-signed certificate over their
//! `tls-endpoint` key; the peer pins its SHA-256/DER fingerprint at pairing
//! (design §8.1/§8.3). Generation is pure Rust (RustCrypto `x509-cert` +
//! `ed25519-dalek`) to match the rustls-rustcrypto provider (ADR-0011) — no C
//! on the crypto path.
//!
//! Signing the certificate is a use of the TLS key, so it goes through the
//! purpose gate: a key bound to any other purpose fails closed.
//!
//! What you write:
//! ```
//! use axon_crypto::cert::self_signed_endpoint;
//! use axon_crypto::keypair::PurposeKey;
//! use axon_crypto::purpose::KeyPurpose;
//! use std::time::Duration;
//! let key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[1u8; 32]);
//! let cert = self_signed_endpoint(&key, "axon-endpoint", Duration::from_secs(86_400)).unwrap();
//! assert!(cert.pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
//! ```
//! `cert.der` feeds rustls; `cert.fingerprint` is the value pinned at pairing.

use crate::identity::Fingerprint;
use crate::keypair::{KeyError, PurposeKey};
use crate::purpose::KeyPurpose;

use ed25519_dalek::ed25519::signature::{Error as SigError, Keypair, Signer};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::BitString;
use x509_cert::der::{Encode, EncodePem};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding,
    SubjectPublicKeyInfoOwned,
};
use x509_cert::time::Validity;

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error(transparent)]
    Purpose(#[from] KeyError),
    #[error("certificate construction failed: {0}")]
    Build(String),
}

/// A generated endpoint certificate.
#[derive(Debug, Clone)]
pub struct EndpointCert {
    /// DER bytes — what rustls consumes and what the fingerprint covers.
    pub der: Vec<u8>,
    /// PEM text — for on-disk storage.
    pub pem: Vec<u8>,
    /// SHA-256 over the complete DER (design §8.1) — pinned at pairing.
    pub fingerprint: Fingerprint,
}

/// Generates a self-signed certificate over `key` (which must be bound to
/// [`KeyPurpose::TlsEndpoint`]), valid from now for `valid_for`, with subject
/// and issuer `CN=<subject_cn>`.
pub fn self_signed_endpoint(
    key: &PurposeKey,
    subject_cn: &str,
    valid_for: Duration,
) -> Result<EndpointCert, CertError> {
    key.sign_with(KeyPurpose::TlsEndpoint, |sk| {
        build(sk, subject_cn, valid_for)
    })?
}

fn build(
    signing: &SigningKey,
    subject_cn: &str,
    valid_for: Duration,
) -> Result<EndpointCert, CertError> {
    let err = |e: &dyn std::fmt::Display| CertError::Build(e.to_string());

    let spki = SubjectPublicKeyInfoOwned::from_key(signing.verifying_key()).map_err(|e| err(&e))?;
    let subject = Name::from_str(&format!("CN={subject_cn}")).map_err(|e| err(&e))?;
    let serial = SerialNumber::from(1u32);
    let validity = Validity::from_now(valid_for).map_err(|e| err(&e))?;
    let signer = CertSigner(signing);

    let builder = CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, &signer)
        .map_err(|e| err(&e))?;
    let cert = builder.build::<CertSig>().map_err(|e| err(&e))?;

    let der = cert.to_der().map_err(|e| err(&e))?;
    let pem = cert
        .to_pem(x509_cert::der::pem::LineEnding::LF)
        .map_err(|e| err(&e))?
        .into_bytes();
    let fingerprint = Fingerprint::cert_sha256(&der);
    Ok(EndpointCert {
        der,
        pem,
        fingerprint,
    })
}

/// A signature that X.509 BitString-encodes itself. The orphan rule forbids
/// implementing this foreign trait on the foreign signature type, so we wrap.
struct CertSig(Signature);

impl SignatureBitStringEncoding for CertSig {
    fn to_bitstring(&self) -> x509_cert::der::Result<BitString> {
        BitString::from_bytes(&self.0.to_bytes())
    }
}

/// A signer producing [`CertSig`], delegating identity and algorithm to the
/// endpoint key (which already carries the pkcs8 impls).
struct CertSigner<'a>(&'a SigningKey);

impl Signer<CertSig> for CertSigner<'_> {
    fn try_sign(&self, msg: &[u8]) -> Result<CertSig, SigError> {
        Ok(CertSig(self.0.try_sign(msg)?))
    }
}

impl Keypair for CertSigner<'_> {
    type VerifyingKey = VerifyingKey;
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl DynSignatureAlgorithmIdentifier for CertSigner<'_> {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        self.0.signature_algorithm_identifier()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::FingerprintKind;
    use ed25519_dalek::Verifier;
    use x509_cert::certificate::Certificate;
    use x509_cert::der::Decode;

    fn tls_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[1u8; 32])
    }

    #[test]
    fn generates_self_consistent_cert() {
        let key = tls_key();
        let cert =
            self_signed_endpoint(&key, "axon-endpoint", Duration::from_secs(86_400)).unwrap();
        assert!(cert.pem.starts_with(b"-----BEGIN CERTIFICATE-----"));

        let parsed = Certificate::from_der(&cert.der).unwrap();
        // Self-signed: issuer equals subject.
        assert_eq!(
            parsed.tbs_certificate.issuer,
            parsed.tbs_certificate.subject
        );

        // The fingerprint is SHA-256 over exactly these DER bytes.
        assert_eq!(cert.fingerprint.kind, FingerprintKind::CertSha256);
        assert!(cert
            .fingerprint
            .matches(&Fingerprint::cert_sha256(&cert.der)));
    }

    #[test]
    fn self_signature_verifies_under_the_key() {
        let key = tls_key();
        let cert =
            self_signed_endpoint(&key, "axon-endpoint", Duration::from_secs(86_400)).unwrap();
        let parsed = Certificate::from_der(&cert.der).unwrap();

        // Re-encode the TBS and check the certificate's own signature under the
        // endpoint public key — proof it is a genuine self-signed cert.
        let tbs = parsed.tbs_certificate.to_der().unwrap();
        let sig_bytes = parsed.signature.as_bytes().unwrap();
        let signature = Signature::from_slice(sig_bytes).unwrap();
        let verifying = key.verifying();
        let vk = verifying.key_for(KeyPurpose::TlsEndpoint).unwrap();
        assert!(vk.verify(&tbs, &signature).is_ok());
    }

    #[test]
    fn wrong_purpose_fails_closed() {
        let card = PurposeKey::from_seed(KeyPurpose::AgentCard, &[1u8; 32]);
        assert!(matches!(
            self_signed_endpoint(&card, "axon-endpoint", Duration::from_secs(60)),
            Err(CertError::Purpose(_))
        ));
    }
}
