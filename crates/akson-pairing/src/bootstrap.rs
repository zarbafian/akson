//! Proof of possession over advertised keys (design §8.2 step 4, ADR-0015).
//!
//! Advertising a public key is not enough — a peer must prove it holds the
//! matching private key, or it could copy someone else's keys from a card and
//! introduce as them. Each side signs the session-bound introduction
//! transcript (see [`introduction`](crate::introduction)) with every statement
//! key it advertises; the other side verifies those signatures against the
//! advertised JWKs with [`verify_proofs_over`].

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Signature;

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

/// Every advertised key must have signed exactly `message` (the introduction
/// transcript's signing bytes), and no unadvertised proof may appear. Fails
/// closed on the first missing, malformed, extra, or invalid proof.
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

    const MESSAGE: &[u8] = b"introduction-transcript-signing-bytes";

    /// Build a key-binding record plus valid proofs for the two seeds' keys.
    fn bindings_and_proofs(
        card_seed: u8,
        task_seed: u8,
        message: &[u8],
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
        let mut proofs = BTreeMap::new();
        proofs.insert(
            "agent-card".to_owned(),
            URL_SAFE_NO_PAD.encode(card.sign(message).to_bytes()),
        );
        proofs.insert(
            "task-result".to_owned(),
            URL_SAFE_NO_PAD.encode(task.sign(message).to_bytes()),
        );
        (set, proofs)
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_748_736_000).unwrap()
    }

    #[test]
    fn valid_proofs_verify() {
        let (set, proofs) = bindings_and_proofs(1, 2, MESSAGE);
        assert!(verify_proofs_over(&set, MESSAGE, &proofs).is_ok());
    }

    #[test]
    fn proof_over_a_different_message_is_rejected() {
        let (set, proofs) = bindings_and_proofs(1, 2, MESSAGE);
        assert!(matches!(
            verify_proofs_over(&set, b"another-session-entirely", &proofs),
            Err(PopError::BadProof { .. })
        ));
    }

    #[test]
    fn missing_proof_is_rejected() {
        let (set, mut proofs) = bindings_and_proofs(1, 2, MESSAGE);
        proofs.remove("task-result");
        assert!(matches!(
            verify_proofs_over(&set, MESSAGE, &proofs),
            Err(PopError::MissingProof { .. })
        ));
    }

    #[test]
    fn proof_by_the_wrong_key_is_rejected() {
        let (set, _) = bindings_and_proofs(1, 2, MESSAGE);
        let (_, wrong_proofs) = bindings_and_proofs(7, 8, MESSAGE);
        assert!(matches!(
            verify_proofs_over(&set, MESSAGE, &wrong_proofs),
            Err(PopError::BadProof { .. })
        ));
    }

    #[test]
    fn extra_proof_is_rejected() {
        let (set, mut proofs) = bindings_and_proofs(1, 2, MESSAGE);
        proofs.insert("evidence".to_owned(), proofs["agent-card"].clone());
        assert!(matches!(
            verify_proofs_over(&set, MESSAGE, &proofs),
            Err(PopError::UnexpectedProof { .. })
        ));
    }
}
