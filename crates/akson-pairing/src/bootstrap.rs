//! The pairing transcript and proof of possession (design §8.2 step 5).
//!
//! Advertising a public key is not enough — a peer must prove it holds the
//! matching private key, or it could copy someone else's keys from a card and
//! pair as them. Each side signs a canonical [`Transcript`] with every
//! statement key it advertises; the other side verifies those signatures
//! against the advertised JWKs.
//!
//! The transcript binds the proof to *this* pairing: the invitation verifier
//! (this invitation), both endpoints' TLS certificate fingerprints (these two
//! machines), and the exact key-binding digest (these keys). A proof captured
//! from one pairing therefore cannot be replayed into another. Its SHA-256 is
//! also the retry-safety key: an exact retry carries the same transcript, a
//! changed transcript is an attack (design §8.2).
//!
//! What you write:
//! ```no_run
//! # use akson_pairing::bootstrap::{Transcript, verify_proof_of_possession};
//! # use akson_pairing::key_binding::KeyBindingSet;
//! # use std::collections::BTreeMap;
//! # fn go(bindings: &KeyBindingSet, transcript: &Transcript, proofs: &BTreeMap<String, String>) {
//! verify_proof_of_possession(bindings, transcript, proofs).unwrap();
//! # }
//! ```

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Signature;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::key_binding::KeyBindingSet;

#[derive(Debug, thiserror::Error)]
pub enum PopError {
    #[error("no proof of possession for advertised purpose {purpose}")]
    MissingProof { purpose: String },
    #[error("proof of possession for purpose {purpose} is malformed")]
    Malformed { purpose: String },
    #[error("proof of possession for purpose {purpose} does not verify")]
    BadProof { purpose: String },
    #[error("proof supplied for purpose {purpose} that was not advertised")]
    UnexpectedProof { purpose: String },
    #[error("advertised JWK for purpose {purpose} is invalid")]
    BadJwk { purpose: String },
}

/// The canonical bytes both sides bind their proofs to. Serialized with RFC
/// 8785 (JCS) so the two implementations agree byte-for-byte.
#[derive(Debug, Clone, Serialize)]
pub struct Transcript {
    /// base64url of the SHA-256 verifier of the invitation secret — ties the
    /// proof to this single invitation.
    pub invitation_verifier: String,
    /// SHA-256 (hex) of the inviter's DER endpoint certificate.
    pub inviter_tls_sha256: String,
    /// SHA-256 (hex) of the accepter's DER endpoint certificate.
    pub accepter_tls_sha256: String,
    /// SHA-256 (hex) over the canonical key-binding record being proven.
    pub key_binding_sha256: String,
}

impl Transcript {
    /// The exact bytes signed by each proof and digested for retry-safety.
    pub fn to_bytes(&self) -> Vec<u8> {
        // A fixed struct of strings cannot fail to canonicalize.
        json_canon::to_vec(self).unwrap_or_default()
    }

    /// SHA-256 over [`to_bytes`](Self::to_bytes) — the retry-safety key
    /// (design §8.2): an exact retry has the same digest; a changed transcript
    /// under the same secret is an attack.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }
}

/// Verifies that every advertised key signed the transcript, and that no proof
/// is supplied for a key that was not advertised. Fails closed on the first
/// missing, malformed, extra, or invalid proof.
pub fn verify_proof_of_possession(
    bindings: &KeyBindingSet,
    transcript: &Transcript,
    proofs: &BTreeMap<String, String>,
) -> Result<(), PopError> {
    verify_proofs_over(bindings, &transcript.to_bytes(), proofs)
}

/// The transcript-agnostic core of proof-of-possession: every advertised key
/// must have signed exactly `message`, and no unadvertised proof may appear.
/// The invitation flow signs a [`Transcript`]; the introduction (ADR-0015)
/// signs its own session-bound transcript — both land here.
pub fn verify_proofs_over(
    bindings: &KeyBindingSet,
    message: &[u8],
    proofs: &BTreeMap<String, String>,
) -> Result<(), PopError> {
    for (purpose, entry) in &bindings.keys {
        let proof = proofs.get(purpose).ok_or_else(|| PopError::MissingProof {
            purpose: purpose.clone(),
        })?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(proof)
            .map_err(|_| PopError::Malformed {
                purpose: purpose.clone(),
            })?;
        let signature = Signature::from_slice(&sig_bytes).map_err(|_| PopError::Malformed {
            purpose: purpose.clone(),
        })?;
        let key = entry.jwk.to_key().map_err(|_| PopError::BadJwk {
            purpose: purpose.clone(),
        })?;
        // verify_strict (not verify): the accepter's advertised key is
        // attacker-controlled at pairing, so reject small-order keys and
        // non-canonical R — the same discipline as DSSE/JWS. Otherwise a
        // small-order "key" could yield a passing proof without possession.
        key.verify_strict(message, &signature)
            .map_err(|_| PopError::BadProof {
                purpose: purpose.clone(),
            })?;
    }

    // No proof may reference a purpose that was not advertised.
    for purpose in proofs.keys() {
        if !bindings.keys.contains_key(purpose) {
            return Err(PopError::UnexpectedProof {
                purpose: purpose.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::key_binding::verify;
    use akson_crypto::jwk::Ed25519PublicJwk;
    use ed25519_dalek::{Signer, SigningKey};
    use time::OffsetDateTime;

    fn transcript() -> Transcript {
        Transcript {
            invitation_verifier: "dGVzdC12ZXJpZmllcg".to_owned(),
            inviter_tls_sha256: "aa".repeat(32),
            accepter_tls_sha256: "bb".repeat(32),
            key_binding_sha256: "cc".repeat(32),
        }
    }

    /// Build a key-binding record plus valid proofs for the two seeds' keys.
    fn bindings_and_proofs(
        card_seed: u8,
        task_seed: u8,
        sign_transcript: &Transcript,
    ) -> (KeyBindingSet, BTreeMap<String, String>) {
        let card = SigningKey::from_bytes(&[card_seed; 32]);
        let task = SigningKey::from_bytes(&[task_seed; 32]);
        let card_jwk = Ed25519PublicJwk::from_key(&card.verifying_key());
        let task_jwk = Ed25519PublicJwk::from_key(&task.verifying_key());
        let record = serde_json::json!({
            "schema_version": 1,
            "subject": { "issuer": "local", "agent": "agent-a" },
            "tls_certificate_sha256": "aa".repeat(32),
            "keys": {
                "agent-card": { "jwk": card_jwk, "thumbprint": card_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" },
                "task-result": { "jwk": task_jwk, "thumbprint": task_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" }
            }
        });
        let set = verify(&record, now()).unwrap();
        let msg = sign_transcript.to_bytes();
        let mut proofs = BTreeMap::new();
        proofs.insert(
            "agent-card".to_owned(),
            URL_SAFE_NO_PAD.encode(card.sign(&msg).to_bytes()),
        );
        proofs.insert(
            "task-result".to_owned(),
            URL_SAFE_NO_PAD.encode(task.sign(&msg).to_bytes()),
        );
        (set, proofs)
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_748_736_000).unwrap()
    }

    #[test]
    fn valid_proofs_verify() {
        let t = transcript();
        let (set, proofs) = bindings_and_proofs(1, 2, &t);
        assert!(verify_proof_of_possession(&set, &t, &proofs).is_ok());
    }

    #[test]
    fn proof_over_a_different_transcript_is_rejected() {
        let (set, proofs) = bindings_and_proofs(1, 2, &transcript());
        // Verify against a transcript the proofs did not sign (replay attempt).
        let mut other = transcript();
        other.accepter_tls_sha256 = "dd".repeat(32);
        assert!(matches!(
            verify_proof_of_possession(&set, &other, &proofs),
            Err(PopError::BadProof { .. })
        ));
    }

    #[test]
    fn missing_proof_is_rejected() {
        let t = transcript();
        let (set, mut proofs) = bindings_and_proofs(1, 2, &t);
        proofs.remove("task-result");
        assert!(matches!(
            verify_proof_of_possession(&set, &t, &proofs),
            Err(PopError::MissingProof { .. })
        ));
    }

    #[test]
    fn proof_by_the_wrong_key_is_rejected() {
        let t = transcript();
        let (set, _) = bindings_and_proofs(1, 2, &t);
        // Proofs signed by different keys (seeds 7,8) than advertised (1,2).
        let (_, wrong_proofs) = bindings_and_proofs(7, 8, &t);
        assert!(matches!(
            verify_proof_of_possession(&set, &t, &wrong_proofs),
            Err(PopError::BadProof { .. })
        ));
    }

    #[test]
    fn extra_proof_is_rejected() {
        let t = transcript();
        let (set, mut proofs) = bindings_and_proofs(1, 2, &t);
        proofs.insert("evidence".to_owned(), proofs["agent-card"].clone());
        assert!(matches!(
            verify_proof_of_possession(&set, &t, &proofs),
            Err(PopError::UnexpectedProof { .. })
        ));
    }

    #[test]
    fn transcript_digest_changes_with_content() {
        let mut a = transcript();
        let d1 = a.digest();
        a.accepter_tls_sha256 = "ee".repeat(32);
        assert_ne!(d1, a.digest());
    }
}
