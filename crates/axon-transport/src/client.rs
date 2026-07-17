//! The accepter-side pairing client (design §8.2 steps 3–7): the other half of
//! the exchange. It opens a server-authenticated TLS 1.3 connection pinned to
//! the invitation's certificate, presents its own material, receives the
//! inviter's equivalently-signed response, verifies it, and pins the inviter as
//! a peer. Both endpoints then hold each other's verified identity.

use std::sync::Arc;

use axon_crypto::cert::EndpointCert;
use axon_crypto::identity::{Fingerprint, FingerprintKind, PeerIdentity};
use axon_crypto::keypair::PurposeKey;
use axon_pairing::handler::BootstrapMaterial;
use axon_pairing::invitation::Invitation;
use axon_pairing::session::{build_material, to_peer_identity, verify_accepter, PairingContext};
use axon_pairing::state_machine::{verifier_of, PairingStore};
use axon_proto::v1::AgentCard;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::tls::{client_config, TlsError};

/// Cap on the inviter's response (design §9.1).
const MAX_RESPONSE_BODY: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error("invitation is malformed")]
    Malformed,
    #[error("invitation endpoint is not a usable URL")]
    BadEndpoint,
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("building accepter material: {0}")]
    Build(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("bootstrap rejected with status {0}")]
    Status(u16),
    #[error("the inviter's response failed verification: {0}")]
    Verify(String),
    #[error("persisting the inviter peer failed: {0}")]
    Store(String),
}

#[derive(Deserialize)]
struct Material {
    key_binding: serde_json::Value,
    extended_card: AgentCard,
    #[serde(default)]
    proofs: std::collections::BTreeMap<String, String>,
}

/// Accepts an invitation: connects to the inviter's bootstrap endpoint, presents
/// `accepter` material, verifies the inviter's response, and stores the inviter
/// as a peer via `store`. Returns the inviter's pinned identity.
///
/// `accepter.tls_sha256` must be `accepter_cert`'s fingerprint (the material is
/// bound to the certificate the accepter presents).
pub async fn accept_invitation<S: PairingStore>(
    invitation: &Invitation,
    accepter_tls_key: &PurposeKey,
    accepter_cert: &EndpointCert,
    accepter: &BootstrapMaterial,
    store: &mut S,
    now: OffsetDateTime,
) -> Result<PeerIdentity, AcceptError> {
    let verifier = verifier_of(&invitation.secret).ok_or(AcceptError::Malformed)?;

    // The pairing context both sides bind into the transcript.
    let ctx = PairingContext {
        invitation_verifier: verifier,
        inviter_tls_sha256: invitation.tls_certificate_sha256.clone(),
        accepter_tls_sha256: accepter_cert.fingerprint.value.clone(),
    };

    // The accepter's own material, signed over the transcript.
    let body = build_material(
        &ctx,
        &accepter.tls_sha256,
        &accepter.subject_issuer,
        &accepter.subject_agent,
        &accepter.signed_card,
        &accepter.keys,
        &accepter.not_before,
        &accepter.not_after,
        accepter.generation,
    )
    .map_err(|e| AcceptError::Build(e.to_string()))
    .and_then(|m| serde_json::to_vec(&m).map_err(|e| AcceptError::Build(e.to_string())))?;

    // Connect, pinning the inviter's server certificate from the invitation.
    let (host, port, path) =
        parse_endpoint(&invitation.endpoint).ok_or(AcceptError::BadEndpoint)?;
    let pinned = Fingerprint {
        kind: FingerprintKind::CertSha256,
        value: invitation.tls_certificate_sha256.clone(),
    };
    let config = client_config(accepter_tls_key, accepter_cert, &pinned)?;
    let connector = TlsConnector::from(Arc::new(config));

    let addr = tokio::net::lookup_host((host.as_str(), port))
        .await?
        .next()
        .ok_or(AcceptError::BadEndpoint)?;
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from(host).map_err(|_| AcceptError::BadEndpoint)?;
    let tls = connector.connect(server_name, tcp).await?;

    // Send the bootstrap POST and read the inviter's response.
    let response = post_bootstrap(tls, &path, &invitation.secret, body).await?;

    // Verify the inviter's material. The verified party is the inviter, so its
    // subject cert is the pinned server certificate.
    let material: Material =
        serde_json::from_slice(&response).map_err(|_| AcceptError::Verify("malformed".into()))?;
    let verified = verify_accepter(
        &verifier,
        &ctx.inviter_tls_sha256,
        &ctx.accepter_tls_sha256,
        &invitation.tls_certificate_sha256,
        &material.key_binding,
        &material.extended_card,
        &material.proofs,
        now,
    )
    .map_err(|e| AcceptError::Verify(e.to_string()))?;

    // Pin the inviter as a peer.
    let inviter_peer = to_peer_identity(&verified, &material.extended_card)
        .map_err(|e| AcceptError::Verify(e.to_string()))?;
    store
        .store_pending_peer(&inviter_peer)
        .map_err(|e| AcceptError::Store(e.to_string()))?;

    Ok(inviter_peer)
}

/// Sends the bootstrap POST over the TLS stream and returns the response body,
/// erroring on a non-200 status.
async fn post_bootstrap<T>(
    tls: T,
    path: &str,
    secret: &str,
    body: Vec<u8>,
) -> Result<Bytes, AcceptError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| AcceptError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(AUTHORIZATION, format!("Bearer {secret}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| AcceptError::Http(e.to_string()))?;

    let resp = sender
        .send_request(request)
        .await
        .map_err(|e| AcceptError::Http(e.to_string()))?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(AcceptError::Status(status));
    }
    let collected = Limited::new(resp.into_body(), MAX_RESPONSE_BODY)
        .collect()
        .await
        .map_err(|_| AcceptError::Http("response too large".into()))?;
    Ok(collected.to_bytes())
}

/// Extracts (host, port, path) from an `https://host[:port]/path` endpoint.
fn parse_endpoint(endpoint: &str) -> Option<(String, u16, String)> {
    let url = url::Url::parse(endpoint).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?.to_owned();
    let port = url.port_or_known_default()?;
    let path = if url.path().is_empty() {
        "/".to_owned()
    } else {
        url.path().to_owned()
    };
    Some((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::parse_endpoint;

    #[test]
    fn parses_endpoint_parts() {
        assert_eq!(
            parse_endpoint("https://host.example:8443/pair/bootstrap"),
            Some((
                "host.example".to_owned(),
                8443,
                "/pair/bootstrap".to_owned()
            ))
        );
        // Default https port.
        assert_eq!(
            parse_endpoint("https://host.example/bootstrap"),
            Some(("host.example".to_owned(), 443, "/bootstrap".to_owned()))
        );
        // Non-https is rejected.
        assert!(parse_endpoint("http://host/bootstrap").is_none());
    }
}
