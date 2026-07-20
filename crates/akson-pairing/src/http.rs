//! The bootstrap endpoint's HTTP contract, as pure logic (design §8.2). This
//! maps an HTTP request's parts to a status and body without any socket or
//! server type, so it is fully testable; `akson-transport` serves it over
//! tokio-rustls + hyper and supplies the peer certificate fingerprint from the
//! mutual-TLS session.
//!
//! The request is `POST` with `Authorization: Bearer <secret>` and a JSON body
//! `{ "key_binding": {...}, "extended_card": {...}, "proofs": {...} }`. The peer
//! is identified by its mTLS certificate, never by a body claim.

use std::collections::BTreeMap;

use akson_proto::v1::AgentCard;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::handler::{handle_bootstrap, BootstrapMaterial, BootstrapStatus};
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
    inviter: &BootstrapMaterial,
    method: &str,
    authorization: Option<&str>,
    peer_tls_sha256: Option<&str>,
    body: &[u8],
    now_unix: i64,
    now: OffsetDateTime,
) -> HttpResponse {
    // Enable-only-when-pairing (§8.2): with no live invitation and no retriable
    // consumed record, the bootstrap endpoint behaves as if unmounted (404). The
    // surface is inert whenever no pairing is in progress, rather than an
    // always-open port. This 404-vs-401 does reveal *that* a pairing is ongoing,
    // which is immaterial against a 256-bit, rate-limited, attempt-capped secret.
    match ledger.any_pairing_open(now_unix) {
        Ok(true) => {}
        Ok(false) => return HttpResponse::status_only(404),
        Err(_) => return HttpResponse::status_only(500),
    }
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
    use akson_crypto::jwk::Ed25519PublicJwk;
    use akson_crypto::keypair::PurposeKey;
    use akson_crypto::purpose::KeyPurpose;
    use akson_proto::card_sig;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    const INVITER_TLS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ACCEPTER_TLS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn now_dt() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_748_736_000).unwrap()
    }

    fn config() -> BootstrapMaterial {
        let card_key = PurposeKey::from_seed(KeyPurpose::AgentCard, &[20u8; 32]);
        let mut card: AgentCard = serde_json::from_str(
            r#"{"name":"Inviter","description":"d","version":"1.0.0",
                "supportedInterfaces":[{"url":"https://inviter/x","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
                "capabilities":{"streaming":false,"pushNotifications":false}}"#,
        )
        .unwrap();
        card.signatures
            .push(card_sig::sign_card(&card, &card_key).unwrap());
        let mut keys = BTreeMap::new();
        keys.insert(
            KeyPurpose::AgentCard,
            PurposeKey::from_seed(KeyPurpose::AgentCard, &[20u8; 32]),
        );
        BootstrapMaterial {
            tls_sha256: INVITER_TLS.to_owned(),
            subject_issuer: "local".to_owned(),
            subject_agent: "inviter".to_owned(),
            signed_card: card,
            keys,
            not_before: "2020-01-01T00:00:00Z".to_owned(),
            not_after: "2030-01-01T00:00:00Z".to_owned(),
            generation: 0,
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
    fn valid_bootstrap_is_200_with_inviter_material() {
        let mut ledger = MemoryLedger::new();
        let (auth, body) = seed(&mut ledger);
        let r = post(&mut ledger, Some(&auth), Some(ACCEPTER_TLS), &body);
        assert_eq!(r.status, 200);
        // The body is the inviter's built material, not a static blob.
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert!(v.get("key_binding").is_some());
        assert!(v.get("extended_card").is_some());
        assert!(v.get("proofs").is_some());
    }

    #[test]
    fn non_post_is_405() {
        // With a pairing enabled (invitation seeded), the method check applies:
        // a non-POST is 405 rather than the unmounted 404.
        let mut ledger = MemoryLedger::new();
        seed(&mut ledger);
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
    fn disabled_endpoint_is_404() {
        // No invitation seeded → no pairing in progress → the endpoint is inert
        // for every request, regardless of a valid-looking bearer or cert.
        let mut ledger = MemoryLedger::new();
        let bearer = format!("Bearer {}", URL_SAFE_NO_PAD.encode([1u8; 32]));
        assert_eq!(
            post(&mut ledger, Some(&bearer), Some(ACCEPTER_TLS), b"{}").status,
            404
        );
        // Even a non-POST is 404 (unmounted) rather than 405.
        let r = handle_http(
            &mut ledger,
            &config(),
            "GET",
            Some(&bearer),
            Some(ACCEPTER_TLS),
            b"{}",
            1_100,
            now_dt(),
        );
        assert_eq!(r.status, 404);
    }

    #[test]
    fn endpoint_reopens_for_a_retry_after_consume() {
        // After a successful pairing consumes the invitation, the endpoint stays
        // enabled within the retry window so an exact retry still replays.
        let mut ledger = MemoryLedger::new();
        let (auth, body) = seed(&mut ledger);
        assert_eq!(
            post(&mut ledger, Some(&auth), Some(ACCEPTER_TLS), &body).status,
            200
        );
        // The invitation is now consumed, but the retry window keeps it open.
        assert_eq!(
            post(&mut ledger, Some(&auth), Some(ACCEPTER_TLS), &body).status,
            200
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
