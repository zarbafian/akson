//! End-to-end proof of the personal pairing bootstrap over HTTP-over-mTLS
//! (design §8.2) — the Layer-1 interop checkpoint. An inviter serves the
//! bootstrap endpoint; an accepter connects over TLS 1.3 (pinning the inviter's
//! cert from the invitation, presenting its own), POSTs a signed extended card
//! + key bindings + proof of possession, and receives the inviter's response.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axon_crypto::cert::{self_signed_endpoint, EndpointCert};
use axon_crypto::jwk::Ed25519PublicJwk;
use axon_crypto::keypair::PurposeKey;
use axon_crypto::purpose::KeyPurpose;
use axon_pairing::bootstrap::Transcript;
use axon_pairing::invitation::Invitation;
use axon_pairing::session::key_binding_digest_hex;
use axon_pairing::state_machine::MemoryLedger;
use axon_proto::card_sig;
use axon_proto::v1::AgentCard;
use axon_transport::bootstrap::{serve, BootstrapState};
use axon_transport::tls::{bootstrap_server_config, client_config};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

fn endpoint(seed: u8) -> (PurposeKey, EndpointCert) {
    let key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[seed; 32]);
    let cert = self_signed_endpoint(&key, "endpoint", Duration::from_secs(86_400)).unwrap();
    (key, cert)
}

/// Builds the accepter's bootstrap request body bound to `invitation_verifier`
/// and the two TLS fingerprints.
fn accepter_body(invitation_verifier: [u8; 32], inviter_tls: &str, accepter_tls: &str) -> Vec<u8> {
    let card_key = SigningKey::from_bytes(&[77u8; 32]);
    let card_jwk = Ed25519PublicJwk::from_key(&card_key.verifying_key());
    let key_binding = serde_json::json!({
        "schema_version": 1,
        "subject": { "issuer": "local", "agent": "accepter" },
        "tls_certificate_sha256": accepter_tls,
        "keys": {
            "agent-card": { "jwk": card_jwk, "thumbprint": card_jwk.thumbprint(),
                "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" }
        }
    });

    let mut card: AgentCard = serde_json::from_str(
        r#"{"name":"Accepter","description":"d","version":"1.0.0",
            "supportedInterfaces":[{"url":"https://a/x","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
            "capabilities":{"streaming":false,"pushNotifications":false}}"#,
    )
    .unwrap();
    let signing = PurposeKey::from_seed(KeyPurpose::AgentCard, &[77u8; 32]);
    card.signatures
        .push(card_sig::sign_card(&card, &signing).unwrap());

    let transcript = Transcript {
        invitation_verifier: URL_SAFE_NO_PAD.encode(invitation_verifier),
        inviter_tls_sha256: inviter_tls.to_owned(),
        accepter_tls_sha256: accepter_tls.to_owned(),
        key_binding_sha256: key_binding_digest_hex(&key_binding),
    };
    let mut proofs = BTreeMap::new();
    proofs.insert(
        "agent-card".to_owned(),
        URL_SAFE_NO_PAD.encode(card_key.sign(&transcript.to_bytes()).to_bytes()),
    );

    serde_json::to_vec(&serde_json::json!({
        "key_binding": key_binding,
        "extended_card": card,
        "proofs": proofs,
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_pairs_over_mtls() {
    let (inviter_key, inviter_cert) = endpoint(1);
    let (accepter_key, accepter_cert) = endpoint(2);
    let inviter_tls = inviter_cert.fingerprint.value.clone();
    let accepter_tls = accepter_cert.fingerprint.value.clone();

    // Inviter: create an invitation and seed the ledger. The server checks
    // expiry against real wall-clock time, so create it at "now".
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let (invitation, pending) = Invitation::create(
        "https://inviter/bootstrap".to_owned(),
        inviter_tls.clone(),
        "kid".to_owned(),
        now,
        900,
        5,
    );
    let verifier = pending.verifier();
    let mut ledger = MemoryLedger::new();
    ledger.add(pending);

    let state = Arc::new(BootstrapState {
        ledger: Mutex::new(ledger),
        inviter_tls_sha256: inviter_tls.clone(),
        inviter_response: b"INVITER-PENDING-PAIR".to_vec(),
    });

    // Inviter serves the bootstrap endpoint.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = bootstrap_server_config(&inviter_key, &inviter_cert).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    tokio::spawn(async move {
        let _ = serve(listener, acceptor, state).await;
    });

    // Accepter: connect, pinning the inviter's server cert; present own cert.
    let client_cfg =
        client_config(&accepter_key, &accepter_cert, &inviter_cert.fingerprint).unwrap();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(name, tcp)
        .await
        .expect("bootstrap handshake");

    // Send a raw HTTP/1.1 bootstrap POST.
    let body = accepter_body(verifier, &inviter_tls, &accepter_tls);
    let request = format!(
        "POST /bootstrap HTTP/1.1\r\nHost: inviter\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        invitation.secret,
        body.len()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.write_all(&body).await.unwrap();
    tls.flush().await.unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);

    assert!(
        text.starts_with("HTTP/1.1 200"),
        "expected 200, got response:\n{text}"
    );
    assert!(
        text.contains("INVITER-PENDING-PAIR"),
        "expected inviter response body, got:\n{text}"
    );
}
