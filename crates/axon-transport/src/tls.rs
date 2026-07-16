//! TLS 1.3 mutual-auth configs with peer pinning (design §9.1, ADR-0011).
//!
//! The v1 profile is strict: TLS 1.3 only, mutual authentication, no
//! resumption/tickets, no 0-RTT, no fallback. Endpoint certificates are
//! self-signed (ADR-0011), so there is no CA chain to validate — instead each
//! side **pins** the peer's SHA-256/DER fingerprint (design §8.1/§8.3) via a
//! custom verifier. The crypto provider is the pure-Rust `rustls-rustcrypto`.
//!
//! What you write:
//! ```no_run
//! # use axon_transport::tls::{server_config, client_config};
//! # use axon_crypto::cert::self_signed_endpoint;
//! # use axon_crypto::keypair::PurposeKey;
//! # use axon_crypto::purpose::KeyPurpose;
//! # use std::time::Duration;
//! # let ours = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[1u8; 32]);
//! # let our_cert = self_signed_endpoint(&ours, "endpoint", Duration::from_secs(86_400)).unwrap();
//! # let peer_fingerprint = our_cert.fingerprint.clone();
//! let server = server_config(&ours, &our_cert, &peer_fingerprint).unwrap();
//! let client = client_config(&ours, &our_cert, &peer_fingerprint).unwrap();
//! ```

use std::sync::Arc;

use axon_crypto::cert::EndpointCert;
use axon_crypto::identity::Fingerprint;
use axon_crypto::keypair::{KeyError, PurposeKey};
use axon_crypto::purpose::KeyPurpose;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    ServerConfig, SignatureScheme,
};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Rustls(#[from] RustlsError),
}

/// The pure-Rust crypto provider (ADR-0011), fresh per config.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}

fn private_key(key: &PurposeKey) -> Result<PrivateKeyDer<'static>, TlsError> {
    let der = key.pkcs8_der(KeyPurpose::TlsEndpoint)?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
}

/// Shared pinning logic: accept exactly the peer whose leaf certificate has the
/// expected SHA-256/DER fingerprint, and verify handshake signatures with the
/// provider's algorithms.
#[derive(Debug)]
struct Pinned {
    expected: Fingerprint,
    provider: Arc<CryptoProvider>,
}

impl Pinned {
    fn check(&self, end_entity: &CertificateDer<'_>) -> Result<(), RustlsError> {
        if Fingerprint::cert_sha256(end_entity.as_ref()).matches(&self.expected) {
            Ok(())
        } else {
            // Not the pinned peer — fail closed (design §8.2 wrong-cert).
            Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn verify_tls13(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
}

/// TLS 1.2 is disabled (§9.1); this path is unreachable under a TLS-1.3-only
/// config, but the trait requires it.
fn tls12_disabled() -> Result<HandshakeSignatureValid, RustlsError> {
    Err(RustlsError::General("TLS 1.2 is disabled".into()))
}

#[derive(Debug)]
struct PinnedServerVerifier(Pinned);

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.0.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        tls12_disabled()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.0.verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.schemes()
    }
}

#[derive(Debug)]
struct PinnedClientVerifier(Pinned);

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        self.0.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        tls12_disabled()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.0.verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.schemes()
    }
}

/// A server config that presents `cert`, requires client auth, and accepts only
/// the client pinned to `peer` (design §9.1).
pub fn server_config(
    endpoint_key: &PurposeKey,
    cert: &EndpointCert,
    peer: &Fingerprint,
) -> Result<ServerConfig, TlsError> {
    let provider = provider();
    let verifier = Arc::new(PinnedClientVerifier(Pinned {
        expected: peer.clone(),
        provider: provider.clone(),
    }));
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(cert.der.clone())],
            private_key(endpoint_key)?,
        )?;
    // §9.1: no resumption/tickets, no 0-RTT.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.max_early_data_size = 0;
    Ok(config)
}

/// A client config that presents `cert` and accepts only the server pinned to
/// `peer` (design §9.1).
pub fn client_config(
    endpoint_key: &PurposeKey,
    cert: &EndpointCert,
    peer: &Fingerprint,
) -> Result<ClientConfig, TlsError> {
    let provider = provider();
    let verifier = Arc::new(PinnedServerVerifier(Pinned {
        expected: peer.clone(),
        provider: provider.clone(),
    }));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(cert.der.clone())],
            private_key(endpoint_key)?,
        )?;
    // §9.1: no resumption/tickets, no 0-RTT.
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}
