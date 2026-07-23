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
//! # use akson_transport::tls::{server_config, client_config};
//! # use akson_crypto::cert::self_signed_endpoint;
//! # use akson_crypto::keypair::PurposeKey;
//! # use akson_crypto::purpose::KeyPurpose;
//! # use std::time::Duration;
//! # let ours = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[1u8; 32]);
//! # let our_cert = self_signed_endpoint(&ours, "endpoint", Duration::from_secs(86_400)).unwrap();
//! # let peer_fingerprint = our_cert.fingerprint.clone();
//! let server = server_config(&ours, &our_cert, &peer_fingerprint).unwrap();
//! let client = client_config(&ours, &our_cert, &peer_fingerprint).unwrap();
//! ```

use std::sync::Arc;

use akson_crypto::cert::{check_cert_time_validity, CertTimeError, EndpointCert};
use akson_crypto::identity::Fingerprint;
use akson_crypto::keypair::{KeyError, PurposeKey};
use akson_crypto::purpose::KeyPurpose;

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

/// Refuses a presented certificate that is outside its `notBefore..=notAfter`
/// window at the handshake instant (design §9.1). Pinning a fingerprint proves
/// *which* key the peer holds, never that its certificate is still current — so
/// every verifier applies this in addition to its own identity check, mapping the
/// failure to the standard rustls certificate-expired alert.
fn check_cert_time(end_entity: &CertificateDer<'_>, now: UnixTime) -> Result<(), RustlsError> {
    let now_unix = now.as_secs() as i64;
    check_cert_time_validity(end_entity.as_ref(), now_unix).map_err(|e| match e {
        CertTimeError::Unparseable => {
            RustlsError::InvalidCertificate(CertificateError::BadEncoding)
        }
        CertTimeError::NotYetValid { .. } => {
            RustlsError::InvalidCertificate(CertificateError::NotValidYet)
        }
        CertTimeError::Expired { .. } => RustlsError::InvalidCertificate(CertificateError::Expired),
    })
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
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.0.check(end_entity)?;
        check_cert_time(end_entity, now)?;
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
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        self.0.check(end_entity)?;
        check_cert_time(end_entity, now)?;
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

/// Bootstrap-only client verifier: accepts *any* self-signed client
/// certificate but still verifies the handshake signature, so possession of the
/// presented key is proven and its fingerprint can be captured for the pairing
/// transcript (design §8.2). Pinning happens only after pairing.
#[derive(Debug)]
struct AcceptAnyClientVerifier {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AcceptAnyClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Anonymous connections are permitted at TLS: the receive server's
    /// application-layer gates refuse everything except the public
    /// `/.well-known/agent-card.json` for a client with no certificate
    /// (design §8.2 — the public card is served to anyone, and is the one
    /// thing that is).
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // Identity is not pinned yet; the fingerprint is captured post-handshake
        // and bound into the pairing transcript. Key possession is enforced by
        // verify_tls13_signature below. The certificate must still be within its
        // validity window, though — pairing must not pin an already-expired cert.
        check_cert_time(end_entity, now)?;
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
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Introduction-only server verifier's client-side mirror: accepts *any*
/// time-valid server certificate but still verifies the handshake signature,
/// so possession of the presented key is proven and its fingerprint can be
/// captured for the introduction transcript (ADR-0015). Identity is not
/// carried by TLS on first contact — it is proven against the imported root
/// commitment inside the handshake that follows. Never used for A2A traffic.
#[derive(Debug)]
struct AcceptAnyServerVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // No pin yet; the fingerprint is captured post-handshake and bound into
        // the signed transcript. The certificate must be within its validity
        // window — an introduction must not pin an already-expired cert.
        check_cert_time(end_entity, now)?;
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
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The introduction client config (design §8.2 step 4, ADR-0015): presents our
/// certificate, provisionally accepts the server's (see
/// [`AcceptAnyServerVerifier`]). The introduction protocol on top verifies the
/// server against the imported root and binds both certificates plus this
/// session's exporter into every proof; ordinary sends keep [`client_config`]'s
/// pinning untouched.
pub fn introduction_client_config(
    endpoint_key: &PurposeKey,
    cert: &EndpointCert,
) -> Result<ClientConfig, TlsError> {
    let provider = provider();
    let verifier = Arc::new(AcceptAnyServerVerifier {
        provider: provider.clone(),
    });
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

/// The RFC 9266 `tls-exporter` channel binding of a completed TLS 1.3
/// connection (ADR-0015): 32 bytes under the fixed label with an empty
/// context. Every introduction proof signs over it, so a proof can never be
/// replayed onto another connection.
pub fn channel_binding<Data>(conn: &rustls::ConnectionCommon<Data>) -> Option<[u8; 32]> {
    conn.export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", None)
        .ok()
}

/// A client config for fetching a stranger's PUBLIC discovery surface
/// (`/.well-known/agent-card.json`, design §8.2) before any import exists:
/// no client certificate, any time-valid server certificate accepted. The
/// fetched card is display-only until an introduction verifies it against an
/// imported root — never a trust input on its own.
pub fn discovery_client_config() -> Result<ClientConfig, TlsError> {
    let provider = provider();
    let verifier = Arc::new(AcceptAnyServerVerifier {
        provider: provider.clone(),
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

/// The bootstrap server config (design §8.2): presents the inviter's `cert`
/// (which the accepter pinned from the invitation) and requests a client
/// certificate it accepts unpinned, capturing the accepter's fingerprint for
/// the transcript. TLS 1.3 only; no resumption/tickets/0-RTT.
pub fn bootstrap_server_config(
    endpoint_key: &PurposeKey,
    cert: &EndpointCert,
) -> Result<ServerConfig, TlsError> {
    let provider = provider();
    let verifier = Arc::new(AcceptAnyClientVerifier {
        provider: provider.clone(),
    });
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(cert.der.clone())],
            private_key(endpoint_key)?,
        )?;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.max_early_data_size = 0;
    Ok(config)
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

/// A client config for a **public** processor endpoint (design §9.1): the server
/// cert is validated against the Mozilla CA root bundle (`webpki-roots`, compiled
/// in — no filesystem trust store, deterministic) using rustls' standard
/// WebPki verifier, and no client certificate is presented (public providers
/// authenticate the caller with a bearer credential, not mTLS). Use this only
/// when the processor has no pinned certificate; the pinned path
/// ([`client_config`]) is preferred and never falls back to CA trust silently —
/// the broker chooses per processor.
pub fn ca_client_config() -> Result<ClientConfig, TlsError> {
    let provider = provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // §9.1: no resumption/tickets, no 0-RTT — same as the pinned path.
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}
