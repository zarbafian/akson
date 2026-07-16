//! Inviter-side bootstrap verification (design §8.2 steps 4–5): everything the
//! inviter checks about an accepter's presented material before consuming the
//! invitation. The HTTP bootstrap endpoint is a thin adapter that extracts the
//! parts and calls [`verify_accepter`], then feeds the result to the
//! [state machine](crate::state_machine).
//!
//! The checks, in order and all fail-closed:
//! 1. the key-binding record passes its schema and every thumbprint equals its
//!    JWK ([`key_binding::verify`](crate::key_binding::verify));
//! 2. the record's claimed TLS certificate is exactly the one presented on this
//!    mutual-TLS connection — so a peer cannot present another identity's
//!    record over its own connection;
//! 3. the signed extended Agent Card verifies under the advertised
//!    `agent-card` key;
//! 4. every advertised key proves possession over the pairing transcript.
//!
//! The transcript binds the invitation and both certificates, so none of these
//! proofs can be replayed into another pairing.

use std::collections::BTreeMap;

use axon_crypto::keypair::PurposeVerifyingKey;
use axon_crypto::purpose::KeyPurpose;
use axon_proto::card_sig;
use axon_proto::v1::AgentCard;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::bootstrap::{verify_proof_of_possession, PopError, Transcript};
use crate::key_binding::{self, KeyBindingError, KeyBindingSet};

const AGENT_CARD_PURPOSE: &str = "agent-card";

#[derive(Debug, thiserror::Error)]
pub enum BootstrapVerifyError {
    #[error(transparent)]
    KeyBinding(#[from] KeyBindingError),
    #[error("the record's TLS certificate does not match the connection's")]
    TlsCertificateMismatch,
    #[error("the key binding advertises no agent-card key")]
    NoAgentCardKey,
    #[error("the extended Agent Card signature did not verify")]
    CardSignature,
    #[error(transparent)]
    ProofOfPossession(#[from] PopError),
}

/// The verified accepter: its key bindings and the transcript the inviter
/// reconstructed (whose digest keys the [state machine](crate::state_machine)).
#[derive(Debug)]
pub struct VerifiedAccepter {
    pub bindings: KeyBindingSet,
    pub transcript: Transcript,
}

/// Verifies all of the accepter's presented material. `accepter_tls_sha256` is
/// the SHA-256/DER fingerprint of the certificate presented on *this* mTLS
/// connection (not a claim in the body).
pub fn verify_accepter(
    invitation_verifier: &[u8; 32],
    inviter_tls_sha256: &str,
    accepter_tls_sha256: &str,
    key_binding_json: &Value,
    extended_card: &AgentCard,
    pop_proofs: &BTreeMap<String, String>,
    now: OffsetDateTime,
) -> Result<VerifiedAccepter, BootstrapVerifyError> {
    // 1. Schema + thumbprint==JWK + validity.
    let bindings = key_binding::verify(key_binding_json, now)?;

    // 2. The claimed TLS certificate must be the one on this connection.
    if !bindings
        .tls_certificate_sha256
        .eq_ignore_ascii_case(accepter_tls_sha256)
    {
        return Err(BootstrapVerifyError::TlsCertificateMismatch);
    }

    // 3. The extended card must be signed by the advertised agent-card key.
    let card_entry = bindings
        .keys
        .get(AGENT_CARD_PURPOSE)
        .ok_or(BootstrapVerifyError::NoAgentCardKey)?;
    let card_key = card_entry
        .jwk
        .to_key()
        .map_err(|_| BootstrapVerifyError::CardSignature)?;
    let card_vk = PurposeVerifyingKey::new(KeyPurpose::AgentCard, card_key);
    card_sig::verify_card(extended_card, &card_vk)
        .map_err(|_| BootstrapVerifyError::CardSignature)?;

    // 4. Proof of possession over the reconstructed transcript.
    let transcript = Transcript {
        invitation_verifier: URL_SAFE_NO_PAD.encode(invitation_verifier),
        inviter_tls_sha256: inviter_tls_sha256.to_owned(),
        accepter_tls_sha256: accepter_tls_sha256.to_owned(),
        key_binding_sha256: key_binding_digest_hex(key_binding_json),
    };
    verify_proof_of_possession(&bindings, &transcript, pop_proofs)?;

    Ok(VerifiedAccepter {
        bindings,
        transcript,
    })
}

/// SHA-256 (hex) over the RFC 8785 canonical key-binding record — the digest
/// both sides put in the transcript.
pub fn key_binding_digest_hex(key_binding_json: &Value) -> String {
    let canonical = json_canon::to_vec(key_binding_json).unwrap_or_default();
    hex::encode(Sha256::digest(canonical))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axon_crypto::jwk::Ed25519PublicJwk;
    use axon_crypto::keypair::PurposeKey;
    use ed25519_dalek::{Signer, SigningKey};

    // Valid 64-char hex SHA-256 fingerprints (the key-binding schema requires it).
    const INVITER_TLS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ACCEPTER_TLS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_748_736_000).unwrap()
    }

    fn card_json() -> &'static str {
        r#"{
            "name": "Accepter",
            "description": "d",
            "version": "1.0.0",
            "supportedInterfaces": [
                {"url": "https://accepter.example/a2a",
                 "protocolBinding": "HTTP+JSON",
                 "protocolVersion": "1.0"}
            ],
            "capabilities": {"streaming": false, "pushNotifications": false}
        }"#
    }

    /// Assembles a complete, valid accepter request: key bindings, a signed
    /// extended card, and PoP proofs over the correct transcript.
    fn valid_request() -> ([u8; 32], Value, AgentCard, BTreeMap<String, String>) {
        let verifier = [3u8; 32];
        let card_key = SigningKey::from_bytes(&[10u8; 32]);
        let task_key = SigningKey::from_bytes(&[11u8; 32]);
        let card_jwk = Ed25519PublicJwk::from_key(&card_key.verifying_key());
        let task_jwk = Ed25519PublicJwk::from_key(&task_key.verifying_key());

        let key_binding = serde_json::json!({
            "schema_version": 1,
            "subject": { "issuer": "local", "agent": "accepter" },
            "tls_certificate_sha256": ACCEPTER_TLS,
            "keys": {
                "agent-card": { "jwk": card_jwk, "thumbprint": card_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" },
                "task-result": { "jwk": task_jwk, "thumbprint": task_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" }
            }
        });

        // Sign the extended card with the advertised agent-card key.
        let mut card: AgentCard = serde_json::from_str(card_json()).unwrap();
        let signing = PurposeKey::from_seed(KeyPurpose::AgentCard, &[10u8; 32]);
        card.signatures
            .push(card_sig::sign_card(&card, &signing).unwrap());

        // Build the transcript the accepter signs and prove possession.
        let transcript = Transcript {
            invitation_verifier: URL_SAFE_NO_PAD.encode(verifier),
            inviter_tls_sha256: INVITER_TLS.to_owned(),
            accepter_tls_sha256: ACCEPTER_TLS.to_owned(),
            key_binding_sha256: key_binding_digest_hex(&key_binding),
        };
        let msg = transcript.to_bytes();
        let mut proofs = BTreeMap::new();
        proofs.insert(
            "agent-card".to_owned(),
            URL_SAFE_NO_PAD.encode(card_key.sign(&msg).to_bytes()),
        );
        proofs.insert(
            "task-result".to_owned(),
            URL_SAFE_NO_PAD.encode(task_key.sign(&msg).to_bytes()),
        );
        (verifier, key_binding, card, proofs)
    }

    fn run(
        verifier: &[u8; 32],
        accepter_tls: &str,
        kb: &Value,
        card: &AgentCard,
        proofs: &BTreeMap<String, String>,
    ) -> Result<VerifiedAccepter, BootstrapVerifyError> {
        verify_accepter(verifier, INVITER_TLS, accepter_tls, kb, card, proofs, now())
    }

    #[test]
    fn valid_request_verifies() {
        let (v, kb, card, proofs) = valid_request();
        assert!(run(&v, ACCEPTER_TLS, &kb, &card, &proofs).is_ok());
    }

    #[test]
    fn tls_certificate_must_match_the_connection() {
        let (v, kb, card, proofs) = valid_request();
        // The record claims ACCEPTER_TLS, but the connection presented another.
        assert!(matches!(
            run(&v, "cc", &kb, &card, &proofs),
            Err(BootstrapVerifyError::TlsCertificateMismatch)
        ));
    }

    #[test]
    fn tampered_card_fails() {
        let (v, kb, mut card, proofs) = valid_request();
        card.name = "Evil".to_owned();
        assert!(matches!(
            run(&v, ACCEPTER_TLS, &kb, &card, &proofs),
            Err(BootstrapVerifyError::CardSignature)
        ));
    }

    #[test]
    fn proof_over_a_different_invitation_fails() {
        let (_v, kb, card, proofs) = valid_request();
        // A different invitation verifier changes the transcript the proofs
        // must sign — captured proofs cannot be replayed here.
        assert!(matches!(
            run(&[9u8; 32], ACCEPTER_TLS, &kb, &card, &proofs),
            Err(BootstrapVerifyError::ProofOfPossession(_))
        ));
    }

    #[test]
    fn mismatched_thumbprint_fails_key_binding() {
        let (v, mut kb, card, proofs) = valid_request();
        kb["keys"]["task-result"]["thumbprint"] = Value::String(
            Ed25519PublicJwk::from_key(&SigningKey::from_bytes(&[99u8; 32]).verifying_key())
                .thumbprint(),
        );
        assert!(matches!(
            run(&v, ACCEPTER_TLS, &kb, &card, &proofs),
            Err(BootstrapVerifyError::KeyBinding(_))
        ));
    }
}
