//! The bootstrap request handler (design §8.2): the whole inviter-side decision
//! as pure logic — pre-check, verify, consume-once, respond. The HTTP bootstrap
//! endpoint is a thin adapter that extracts the Bearer secret, the mTLS peer
//! certificate fingerprint, and the JSON body, then calls [`handle_bootstrap`]
//! and maps [`BootstrapStatus`] to an HTTP status.

use std::collections::BTreeMap;

use axon_proto::v1::AgentCard;
use serde_json::Value;
use time::OffsetDateTime;

use crate::session::verify_accepter;
use crate::state_machine::{accept, verifier_of, Accepted, PairingLedger};

/// Inviter-side configuration for a bootstrap.
pub struct InviterConfig<'a> {
    /// The inviter's own TLS certificate SHA-256 (hex), bound into the
    /// transcript both sides sign.
    pub tls_sha256: &'a str,
    /// The inviter's signed extended card and key bindings — the pending-pair
    /// response returned to the accepter (design §8.2 step 6). Opaque here.
    pub response_body: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapStatus {
    /// Paired or exact replay — the body carries the inviter's response.
    Ok,
    /// The secret maps to no live or consumed invitation.
    Unauthorized,
    /// Same secret, a changed transcript — an attack.
    Conflict,
    /// The invitation expired or ran out of attempts.
    Gone,
    /// The presented material failed verification.
    BadRequest,
}

pub struct BootstrapReply {
    pub status: BootstrapStatus,
    pub body: Vec<u8>,
}

/// Handles one bootstrap request. `accepter_tls_sha256` is the fingerprint of
/// the certificate presented on *this* mTLS connection (not a body claim).
#[allow(clippy::too_many_arguments)]
pub fn handle_bootstrap(
    ledger: &mut impl PairingLedger,
    inviter: &InviterConfig,
    accepter_tls_sha256: &str,
    bearer_secret: &str,
    key_binding_json: &Value,
    extended_card: &AgentCard,
    pop_proofs: &BTreeMap<String, String>,
    now_unix: i64,
    now: OffsetDateTime,
) -> BootstrapReply {
    let reply = |status, body| BootstrapReply { status, body };

    // Cheap pre-check: spend signature verification only on a secret that maps
    // to a known invitation (live or already consumed). An unknown secret is
    // rejected here, before any expensive work.
    let Some(verifier) = verifier_of(bearer_secret) else {
        return reply(BootstrapStatus::Unauthorized, vec![]);
    };
    if !ledger.active_exists(&verifier) && ledger.consumed(&verifier).is_none() {
        return reply(BootstrapStatus::Unauthorized, vec![]);
    }

    // Full verification of the accepter's presented material.
    let verified = match verify_accepter(
        &verifier,
        inviter.tls_sha256,
        accepter_tls_sha256,
        key_binding_json,
        extended_card,
        pop_proofs,
        now,
    ) {
        Ok(v) => v,
        Err(_) => return reply(BootstrapStatus::BadRequest, vec![]),
    };

    // Consume-once with idempotent retries.
    match accept(
        ledger,
        bearer_secret,
        verified.transcript.digest(),
        inviter.response_body.to_vec(),
        now_unix,
    ) {
        Ok(Accepted::Paired { response }) | Ok(Accepted::Replay { response }) => {
            reply(BootstrapStatus::Ok, response)
        }
        Ok(Accepted::TranscriptConflict) => reply(BootstrapStatus::Conflict, vec![]),
        Ok(Accepted::BadSecret) => reply(BootstrapStatus::Unauthorized, vec![]),
        Ok(Accepted::Expired | Accepted::AttemptsExhausted) => reply(BootstrapStatus::Gone, vec![]),
        Err(_) => reply(BootstrapStatus::BadRequest, vec![]),
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

    struct Request {
        secret: String,
        key_binding: Value,
        card: AgentCard,
        proofs: BTreeMap<String, String>,
    }

    /// Creates an invitation (seeded into `ledger`) and a matching valid
    /// accepter request bound to it.
    fn setup(ledger: &mut MemoryLedger) -> Request {
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

        Request {
            secret: artifact.secret,
            key_binding,
            card,
            proofs,
        }
    }

    fn config() -> InviterConfig<'static> {
        InviterConfig {
            tls_sha256: INVITER_TLS,
            response_body: b"INVITER-CARD",
        }
    }

    fn run(ledger: &mut MemoryLedger, req: &Request) -> BootstrapReply {
        handle_bootstrap(
            ledger,
            &config(),
            ACCEPTER_TLS,
            &req.secret,
            &req.key_binding,
            &req.card,
            &req.proofs,
            1_100,
            now_dt(),
        )
    }

    #[test]
    fn fresh_bootstrap_returns_the_inviter_response() {
        let mut ledger = MemoryLedger::new();
        let req = setup(&mut ledger);
        let reply = run(&mut ledger, &req);
        assert_eq!(reply.status, BootstrapStatus::Ok);
        assert_eq!(reply.body, b"INVITER-CARD");
    }

    #[test]
    fn retry_replays_the_same_response() {
        let mut ledger = MemoryLedger::new();
        let req = setup(&mut ledger);
        run(&mut ledger, &req);
        let reply = run(&mut ledger, &req);
        assert_eq!(reply.status, BootstrapStatus::Ok);
        assert_eq!(reply.body, b"INVITER-CARD");
    }

    #[test]
    fn unknown_secret_is_unauthorized_without_verification() {
        let mut ledger = MemoryLedger::new();
        let mut req = setup(&mut ledger);
        req.secret = URL_SAFE_NO_PAD.encode([9u8; 32]);
        assert_eq!(run(&mut ledger, &req).status, BootstrapStatus::Unauthorized);
    }

    #[test]
    fn tampered_card_is_bad_request() {
        let mut ledger = MemoryLedger::new();
        let mut req = setup(&mut ledger);
        req.card.name = "Evil".to_owned();
        assert_eq!(run(&mut ledger, &req).status, BootstrapStatus::BadRequest);
    }

    #[test]
    fn changed_transcript_retry_is_conflict() {
        let mut ledger = MemoryLedger::new();
        let req = setup(&mut ledger);
        run(&mut ledger, &req); // first pairs
                                // A second, differently-signed request under the same secret: re-sign the
                                // card binding a different accepter cert so the transcript digest differs.
        let mut conflicting = setup_conflicting(&req);
        // Point it at the same secret/invitation.
        conflicting.secret = req.secret.clone();
        // The pre-check passes (consumed exists); verification passes on its own
        // terms; the transcript digest differs → conflict.
        let reply = run(&mut ledger, &conflicting);
        assert_eq!(reply.status, BootstrapStatus::Conflict);
    }

    /// A second valid request for the same invitation but a different accepter
    /// identity (different keys/card), producing a different transcript.
    fn setup_conflicting(orig: &Request) -> Request {
        let secret = orig.secret.clone();
        let verifier = verifier_of(&secret).unwrap();
        let card_key = SigningKey::from_bytes(&[20u8; 32]);
        let card_jwk = Ed25519PublicJwk::from_key(&card_key.verifying_key());
        let key_binding = serde_json::json!({
            "schema_version": 1,
            "subject": { "issuer": "local", "agent": "accepter2" },
            "tls_certificate_sha256": ACCEPTER_TLS,
            "keys": {
                "agent-card": { "jwk": card_jwk, "thumbprint": card_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" }
            }
        });
        let mut card: AgentCard = serde_json::from_str(
            r#"{"name":"B","description":"d","version":"1.0.0",
                "supportedInterfaces":[{"url":"https://b/x","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
                "capabilities":{"streaming":false,"pushNotifications":false}}"#,
        )
        .unwrap();
        let signing = PurposeKey::from_seed(KeyPurpose::AgentCard, &[20u8; 32]);
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
        Request {
            secret,
            key_binding,
            card,
            proofs,
        }
    }
}
