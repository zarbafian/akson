//! The bootstrap endpoint's HTTP contract, as pure logic (design §8.2). This
//! maps an HTTP request's parts to a status and body without any socket or
//! server type, so it is fully testable; `axon-transport` serves it over
//! tokio-rustls + hyper and supplies the peer certificate fingerprint from the
//! mutual-TLS session.
//!
//! The request is `POST` with `Authorization: Bearer <secret>` and a JSON body
//! `{ "key_binding": {...}, "extended_card": {...}, "proofs": {...} }`. The peer
//! is identified by its mTLS certificate, never by a body claim.

use std::collections::BTreeMap;

use axon_proto::v1::AgentCard;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::handler::{handle_bootstrap, BootstrapStatus, InviterConfig};
use crate::state_machine::PairingStore;

/// An HTTP response from the bootstrap endpoint.
pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn status_only(status: u16) -> Self {
        Self {
            status,
            content_type: "application/octet-stream",
            body: Vec::new(),
        }
    }
}

#[derive(Deserialize)]
struct BootstrapBody {
    key_binding: Value,
    extended_card: AgentCard,
    #[serde(default)]
    proofs: BTreeMap<String, String>,
}

/// Handles a bootstrap HTTP request. `peer_tls_sha256` is the SHA-256/DER
/// fingerprint of the certificate the peer presented on this mutual-TLS
/// connection (the server extracts it from the TLS session).
#[allow(clippy::too_many_arguments)]
pub fn handle_http(
    ledger: &mut impl PairingStore,
    inviter: &InviterConfig,
    method: &str,
    authorization: Option<&str>,
    peer_tls_sha256: Option<&str>,
    body: &[u8],
    now_unix: i64,
    now: OffsetDateTime,
) -> HttpResponse {
    if method != "POST" {
        return HttpResponse::status_only(405);
    }
    // The mTLS layer already requires a client certificate; its absence here
    // means the connection is not mutually authenticated.
    let Some(peer) = peer_tls_sha256 else {
        return HttpResponse::status_only(401);
    };
    let Some(secret) = authorization.and_then(|a| a.strip_prefix("Bearer ")) else {
        return HttpResponse::status_only(401);
    };
    let Ok(parsed) = serde_json::from_slice::<BootstrapBody>(body) else {
        return HttpResponse::status_only(400);
    };

    let reply = handle_bootstrap(
        ledger,
        inviter,
        peer,
        secret,
        &parsed.key_binding,
        &parsed.extended_card,
        &parsed.proofs,
        now_unix,
        now,
    );

    let status = match reply.status {
        BootstrapStatus::Ok => 200,
        BootstrapStatus::Unauthorized => 401,
        BootstrapStatus::Conflict => 409,
        BootstrapStatus::Gone => 410,
        BootstrapStatus::BadRequest => 400,
        BootstrapStatus::Error => 500,
    };
    HttpResponse {
        status,
        content_type: "application/json",
        body: reply.body,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bootstrap::Transcript;
    use crate::invitation::Invitation;
    use crate::session::key_binding_digest_hex;
    use crate::state_machine::MemoryLedger;
    use axon_crypto::jwk::Ed25519PublicJwk;
    use axon_crypto::keypair::PurposeKey;
    use axon_crypto::purpose::KeyPurpose;
    use axon_proto::card_sig;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    const INVITER_TLS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ACCEPTER_TLS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn now_dt() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_748_736_000).unwrap()
    }

    fn config() -> InviterConfig<'static> {
        InviterConfig {
            tls_sha256: INVITER_TLS,
            response_body: b"INVITER-CARD",
        }
    }

    /// Seeds an invitation and returns (bearer header, JSON body bytes).
    fn seed(ledger: &mut MemoryLedger) -> (String, Vec<u8>) {
        let (artifact, pending) = Invitation::create(
            "https://inviter/bootstrap".to_owned(),
            INVITER_TLS.to_owned(),
            "kid".to_owned(),
            1_000,
            900,
            5,
        );
        let verifier = pending.verifier();
        ledger.add(pending);

        let card_key = SigningKey::from_bytes(&[10u8; 32]);
        let card_jwk = Ed25519PublicJwk::from_key(&card_key.verifying_key());
        let key_binding = serde_json::json!({
            "schema_version": 1,
            "subject": { "issuer": "local", "agent": "accepter" },
            "tls_certificate_sha256": ACCEPTER_TLS,
            "keys": {
                "agent-card": { "jwk": card_jwk, "thumbprint": card_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" }
            }
        });
        let mut card: AgentCard = serde_json::from_str(
            r#"{"name":"A","description":"d","version":"1.0.0",
                "supportedInterfaces":[{"url":"https://a/x","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
                "capabilities":{"streaming":false,"pushNotifications":false}}"#,
        )
        .unwrap();
        let signing = PurposeKey::from_seed(KeyPurpose::AgentCard, &[10u8; 32]);
        card.signatures
            .push(card_sig::sign_card(&card, &signing).unwrap());

        let transcript = Transcript {
            invitation_verifier: URL_SAFE_NO_PAD.encode(verifier),
            inviter_tls_sha256: INVITER_TLS.to_owned(),
            accepter_tls_sha256: ACCEPTER_TLS.to_owned(),
            key_binding_sha256: key_binding_digest_hex(&key_binding),
        };
        let mut proofs = BTreeMap::new();
        proofs.insert(
            "agent-card".to_owned(),
            URL_SAFE_NO_PAD.encode(card_key.sign(&transcript.to_bytes()).to_bytes()),
        );

        let body = serde_json::to_vec(&serde_json::json!({
            "key_binding": key_binding,
            "extended_card": card,
            "proofs": proofs,
        }))
        .unwrap();
        (format!("Bearer {}", artifact.secret), body)
    }

    fn post(
        ledger: &mut MemoryLedger,
        auth: Option<&str>,
        peer: Option<&str>,
        body: &[u8],
    ) -> HttpResponse {
        handle_http(ledger, &config(), "POST", auth, peer, body, 1_100, now_dt())
    }

    #[test]
    fn valid_bootstrap_is_200_with_inviter_response() {
        let mut ledger = MemoryLedger::new();
        let (auth, body) = seed(&mut ledger);
        let r = post(&mut ledger, Some(&auth), Some(ACCEPTER_TLS), &body);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"INVITER-CARD");
    }

    #[test]
    fn non_post_is_405() {
        let mut ledger = MemoryLedger::new();
        let r = handle_http(
            &mut ledger,
            &config(),
            "GET",
            Some("Bearer x"),
            Some(ACCEPTER_TLS),
            b"{}",
            1_100,
            now_dt(),
        );
        assert_eq!(r.status, 405);
    }

    #[test]
    fn missing_client_cert_is_401() {
        let mut ledger = MemoryLedger::new();
        let (auth, body) = seed(&mut ledger);
        assert_eq!(post(&mut ledger, Some(&auth), None, &body).status, 401);
    }

    #[test]
    fn missing_or_malformed_bearer_is_401() {
        let mut ledger = MemoryLedger::new();
        let (_auth, body) = seed(&mut ledger);
        assert_eq!(
            post(&mut ledger, None, Some(ACCEPTER_TLS), &body).status,
            401
        );
        assert_eq!(
            post(&mut ledger, Some("Basic zzz"), Some(ACCEPTER_TLS), &body).status,
            401
        );
    }

    #[test]
    fn unparseable_body_is_400() {
        let mut ledger = MemoryLedger::new();
        let (auth, _body) = seed(&mut ledger);
        assert_eq!(
            post(&mut ledger, Some(&auth), Some(ACCEPTER_TLS), b"not json").status,
            400
        );
    }

    #[test]
    fn unknown_secret_is_401() {
        let mut ledger = MemoryLedger::new();
        let (_auth, body) = seed(&mut ledger);
        let bogus = format!("Bearer {}", URL_SAFE_NO_PAD.encode([9u8; 32]));
        assert_eq!(
            post(&mut ledger, Some(&bogus), Some(ACCEPTER_TLS), &body).status,
            401
        );
    }
}
