//! Agent Card JWS signing and verification (A2A §8.4, design §10.1).
//!
//! A2A signs the Agent Card with an RFC 7515 JWS carried in
//! [`AgentCardSignature`](crate::v1::AgentCardSignature). The signed payload is
//! fixed by A2A §8.4: take the card, drop default-valued properties and the
//! `signatures` field, canonicalize the rest with RFC 8785 (JCS), base64url.
//! Design §10.1 pins the algorithm to the EdDSA profile in
//! [`akson_crypto::jws`]; this module only supplies the card → payload mapping
//! and the [`AgentCardSignature`] glue, and lives beside the structural card
//! validator so a fetched card is both shape-checked and signature-checked
//! (closing review finding H6).
//!
//! What you write:
//! ```
//! # use akson_proto::card_sig::{sign_card, verify_card};
//! # use akson_crypto::keypair::PurposeKey;
//! # use akson_crypto::purpose::KeyPurpose;
//! # let card: akson_proto::v1::AgentCard = serde_json::from_str(
//! #   r#"{"name":"A","description":"d","version":"1.0.0",
//! #      "supportedInterfaces":[{"url":"https://a.example/a2a",
//! #        "protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
//! #      "capabilities":{"streaming":false,"pushNotifications":false}}"#).unwrap();
//! let key = PurposeKey::from_seed(KeyPurpose::AgentCard, &[1u8; 32]);
//! let mut card = card;
//! card.signatures.push(sign_card(&card, &key).unwrap());
//! verify_card(&card, &key.verifying()).unwrap();
//! ```
//! The default-value removal is exactly what the proto3 JSON mapping already
//! does (pbjson omits unset scalars), so serializing the card *is* the
//! canonicalization input; `signatures` is stripped explicitly.

use crate::v1::{AgentCard, AgentCardSignature};
use akson_crypto::jws::{self, Jws};
use akson_crypto::keypair::{PurposeKey, PurposeVerifyingKey};
use akson_crypto::purpose::KeyPurpose;

#[derive(Debug, thiserror::Error)]
pub enum CardSigError {
    #[error("card carries no signatures")]
    NoSignatures,
    #[error("no signature verified under the pinned Agent Card key")]
    NoValidSignature,
    #[error(transparent)]
    Purpose(#[from] akson_crypto::keypair::KeyError),
    #[error("card serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// The canonical JWS payload for `card`: the proto3 JSON mapping of the card
/// (defaults already omitted) with `signatures` removed, canonicalized with
/// RFC 8785. Deterministic across signer and verifier.
pub fn canonical_payload(card: &AgentCard) -> Result<Vec<u8>, CardSigError> {
    let mut value = serde_json::to_value(card)?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signatures");
    }
    Ok(json_canon::to_vec(&value)?)
}

/// Signs `card` with the Agent Card key, producing one `AgentCardSignature`.
/// The key must be bound to [`KeyPurpose::AgentCard`]; any other purpose fails
/// closed before signing. Existing `signatures` on the card are ignored — the
/// payload is always the signature-free canonical form — so multiple signers
/// sign identical bytes.
pub fn sign_card(card: &AgentCard, key: &PurposeKey) -> Result<AgentCardSignature, CardSigError> {
    let payload = canonical_payload(card)?;
    let jws = key.sign_with(KeyPurpose::AgentCard, |sk| jws::sign_detached(&payload, sk))?;
    Ok(AgentCardSignature {
        protected: jws.protected,
        signature: jws.signature,
        header: None,
    })
}

/// Verifies that `card` carries a valid Agent Card JWS under the pinned key.
/// The key must be bound to [`KeyPurpose::AgentCard`]. Fails closed unless the
/// card has at least one signature and one of them verifies under the pinned
/// key with the EdDSA profile (`alg: EdDSA`, `typ: JOSE`, `kid` = the key's RFC
/// 7638 thumbprint); an empty, tampered, wrong-key, or wrong-algorithm
/// signature does not pass.
pub fn verify_card(card: &AgentCard, key: &PurposeVerifyingKey) -> Result<(), CardSigError> {
    let verifying = key.key_for(KeyPurpose::AgentCard)?;
    if card.signatures.is_empty() {
        return Err(CardSigError::NoSignatures);
    }
    let payload = canonical_payload(card)?;
    for sig in &card.signatures {
        let jws = Jws {
            protected: sig.protected.clone(),
            signature: sig.signature.clone(),
        };
        if jws::verify_detached(&jws, &payload, verifying).is_ok() {
            return Ok(());
        }
    }
    Err(CardSigError::NoValidSignature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const CARD: &str = r#"{
        "name": "Recipe Agent",
        "description": "Agent that helps users with recipes.",
        "version": "1.0.0",
        "supportedInterfaces": [
            {"url": "https://agent.example/a2a",
             "protocolBinding": "HTTP+JSON",
             "protocolVersion": "1.0"}
        ],
        "capabilities": {"streaming": false, "pushNotifications": false}
    }"#;

    fn card() -> AgentCard {
        serde_json::from_str(CARD).unwrap()
    }

    fn card_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::AgentCard, &[1u8; 32])
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = card_key();
        let mut c = card();
        c.signatures.push(sign_card(&c, &key).unwrap());
        assert!(verify_card(&c, &key.verifying()).is_ok());
    }

    #[test]
    fn payload_ignores_existing_signatures() {
        // The payload the verifier reconstructs must not depend on whatever
        // signatures the card already carries.
        let key = card_key();
        let bare = card();
        let mut signed = card();
        signed.signatures.push(sign_card(&bare, &key).unwrap());
        assert_eq!(
            canonical_payload(&bare).unwrap(),
            canonical_payload(&signed).unwrap()
        );
    }

    #[test]
    fn rejects_unsigned_card() {
        let key = card_key();
        assert!(matches!(
            verify_card(&card(), &key.verifying()),
            Err(CardSigError::NoSignatures)
        ));
    }

    #[test]
    fn rejects_tampered_card() {
        let key = card_key();
        let mut c = card();
        c.signatures.push(sign_card(&c, &key).unwrap());
        c.name = "Evil Agent".to_owned();
        assert!(matches!(
            verify_card(&c, &key.verifying()),
            Err(CardSigError::NoValidSignature)
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let key = card_key();
        let other = PurposeKey::from_seed(KeyPurpose::AgentCard, &[9u8; 32]);
        let mut c = card();
        c.signatures.push(sign_card(&c, &key).unwrap());
        assert!(matches!(
            verify_card(&c, &other.verifying()),
            Err(CardSigError::NoValidSignature)
        ));
    }

    #[test]
    fn signing_requires_agent_card_purpose() {
        let wrong = PurposeKey::from_seed(KeyPurpose::TaskResult, &[1u8; 32]);
        assert!(matches!(
            sign_card(&card(), &wrong),
            Err(CardSigError::Purpose(_))
        ));
    }

    #[test]
    fn verifying_requires_agent_card_purpose() {
        let key = card_key();
        let mut c = card();
        c.signatures.push(sign_card(&c, &key).unwrap());
        let wrong = PurposeVerifyingKey::new(
            KeyPurpose::TaskResult,
            PurposeKey::from_seed(KeyPurpose::TaskResult, &[1u8; 32])
                .verifying()
                .to_jwk()
                .to_key()
                .unwrap(),
        );
        assert!(matches!(
            verify_card(&c, &wrong),
            Err(CardSigError::Purpose(_))
        ));
    }
}
