//! Minimal EdDSA JWS, detached flattened JSON serialization (ADR-0007).
//!
//! One profile only (design §10.1): `alg: EdDSA`, `typ: JOSE`, and a `kid`
//! that is the signer's RFC 7638 thumbprint. There is no algorithm agility to
//! confuse: `none`, symmetric, and `RS*`/`ES*`/`HS*` never parse, and a
//! protected header carrying any other member (`jku`, `x5u`, `crit`, …) is
//! rejected before signature math — no key URL is ever dereferenced.
//!
//! What you write:
//! ```
//! use axon_crypto::jws::{sign_detached, verify_detached};
//! use ed25519_dalek::SigningKey;
//! let key = SigningKey::from_bytes(&[7u8; 32]);
//! let payload = b"<already-canonical bytes>";
//! let jws = sign_detached(payload, &key);
//! verify_detached(&jws, payload, &key.verifying_key()).unwrap();
//! ```
//! The payload is opaque, canonical bytes the caller owns (for the Agent Card,
//! `axon_proto::card_sig` produces them by JCS over the card minus
//! `signatures`); this primitive never re-serializes it. The signing input is
//! the standard `BASE64URL(protected) "." BASE64URL(payload)`.
//!
//! Verification uses `verify_strict` (RFC 8032): it rejects small-order keys
//! and non-canonical `R`, and it recomputes `kid` from the pinned key so a
//! signature can never present key A under thumbprint B (the DSSE discipline,
//! ADR-0004).

use crate::jwk::thumbprint;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The only algorithm this profile signs or accepts.
pub const ALG: &str = "EdDSA";
/// The only `typ` this profile signs or accepts (design §10.1).
pub const TYP: &str = "JOSE";

#[derive(Debug, thiserror::Error)]
pub enum JwsError {
    #[error("unexpected alg: {found:?}, only {expected:?} is accepted")]
    Alg {
        expected: &'static str,
        found: String,
    },
    #[error("unexpected typ: {found:?}, only {expected:?} is accepted")]
    Typ {
        expected: &'static str,
        found: String,
    },
    #[error("key id mismatch: expected {expected:?}, found {found:?}")]
    KeyId { expected: String, found: String },
    #[error("invalid base64 in {field}")]
    Base64 { field: &'static str },
    #[error("malformed protected header")]
    Header,
    #[error("signature verification failed")]
    BadSignature,
}

/// The protected header. `deny_unknown_fields` is what turns "no `jku`, no
/// `crit`, no `x5u`" into a parse-time rejection rather than a check we might
/// forget: any member outside these three fails closed on the way in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

/// A detached JWS in flattened JSON serialization: only the two fields that
/// carry into an A2A `AgentCardSignature`. The payload is not stored here — it
/// is reconstructed from the signed object (the Agent Card) at verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jws {
    /// base64url (unpadded) of the canonical protected-header bytes.
    pub protected: String,
    /// base64url (unpadded) of the raw 64-byte Ed25519 signature.
    pub signature: String,
}

/// `BASE64URL(protected) "." BASE64URL(payload)` — the exact bytes signed.
/// The payload is signed via its base64url form (standard JWS, `b64: true`).
fn signing_input(protected_b64: &str, payload: &[u8]) -> Vec<u8> {
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let mut input = Vec::with_capacity(protected_b64.len() + 1 + payload_b64.len());
    input.extend_from_slice(protected_b64.as_bytes());
    input.push(b'.');
    input.extend_from_slice(payload_b64.as_bytes());
    input
}

/// Signs `payload` under the EdDSA profile. `kid` is derived from the key
/// (never taken on trust), and the protected header is serialized canonically
/// (JCS) so its bytes are reproducible in golden vectors.
pub fn sign_detached(payload: &[u8], key: &SigningKey) -> Jws {
    let header = ProtectedHeader {
        alg: ALG.to_owned(),
        typ: TYP.to_owned(),
        kid: thumbprint(&key.verifying_key()),
    };
    // json_canon over a fixed three-field struct cannot fail; fall back to an
    // empty header rather than panic, which verification would then reject.
    let header_bytes = json_canon::to_vec(&header).unwrap_or_default();
    let protected = URL_SAFE_NO_PAD.encode(&header_bytes);
    let sig = key.sign(&signing_input(&protected, payload));
    Jws {
        protected,
        signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    }
}

/// Verifies a detached JWS over `payload` under the EdDSA profile and the
/// pinned key. Fails closed unless the header parses to exactly
/// `{alg: EdDSA, typ: JOSE, kid}`, `kid` equals the RFC 7638 thumbprint
/// recomputed from `key`, and the strict Ed25519 signature checks out. The
/// received `protected` string is used verbatim in the signing input — the
/// header is never re-serialized — so a peer that encodes its header
/// differently still verifies.
pub fn verify_detached(jws: &Jws, payload: &[u8], key: &VerifyingKey) -> Result<(), JwsError> {
    let header_bytes = URL_SAFE_NO_PAD
        .decode(&jws.protected)
        .map_err(|_| JwsError::Base64 { field: "protected" })?;
    let header: ProtectedHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwsError::Header)?;
    if header.alg != ALG {
        return Err(JwsError::Alg {
            expected: ALG,
            found: header.alg,
        });
    }
    if header.typ != TYP {
        return Err(JwsError::Typ {
            expected: TYP,
            found: header.typ,
        });
    }
    let expected_kid = thumbprint(key);
    if header.kid != expected_kid {
        return Err(JwsError::KeyId {
            expected: expected_kid,
            found: header.kid,
        });
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&jws.signature)
        .map_err(|_| JwsError::Base64 { field: "signature" })?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| JwsError::Base64 { field: "signature" })?;
    key.verify_strict(&signing_input(&jws.protected, payload), &signature)
        .map_err(|_| JwsError::BadSignature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn sign_verify_round_trip() {
        let k = key();
        let payload = br#"{"a":1,"b":2}"#;
        let jws = sign_detached(payload, &k);
        assert!(verify_detached(&jws, payload, &k.verifying_key()).is_ok());
    }

    #[test]
    fn header_is_canonical_eddsa_jose() {
        let k = key();
        let jws = sign_detached(b"x", &k);
        let bytes = URL_SAFE_NO_PAD.decode(&jws.protected).unwrap();
        // JCS orders the members alg, kid, typ.
        let expected = format!(
            r#"{{"alg":"EdDSA","kid":"{}","typ":"JOSE"}}"#,
            thumbprint(&k.verifying_key())
        );
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn rejects_tampered_payload() {
        let k = key();
        let jws = sign_detached(b"payload", &k);
        assert!(matches!(
            verify_detached(&jws, b"payload!", &k.verifying_key()),
            Err(JwsError::BadSignature)
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let k = key();
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let jws = sign_detached(b"payload", &k);
        // kid is derived from the signer, so against `other` the kid check
        // fails first — still fails closed.
        assert!(matches!(
            verify_detached(&jws, b"payload", &other),
            Err(JwsError::KeyId { .. })
        ));
    }

    #[test]
    fn rejects_alg_none() {
        let k = key();
        let payload = b"payload";
        let jws = sign_detached(payload, &k);
        let forged = ProtectedHeader {
            alg: "none".to_owned(),
            typ: TYP.to_owned(),
            kid: thumbprint(&k.verifying_key()),
        };
        let tampered = Jws {
            protected: URL_SAFE_NO_PAD.encode(json_canon::to_vec(&forged).unwrap()),
            signature: jws.signature,
        };
        assert!(matches!(
            verify_detached(&tampered, payload, &k.verifying_key()),
            Err(JwsError::Alg { .. })
        ));
    }

    #[test]
    fn rejects_unknown_header_member() {
        // A protected header carrying `jku` (a key URL) must not even parse.
        let k = key();
        let kid = thumbprint(&k.verifying_key());
        let header = format!(
            r#"{{"alg":"EdDSA","typ":"JOSE","kid":"{kid}","jku":"https://evil.example/keys"}}"#
        );
        let jws = Jws {
            protected: URL_SAFE_NO_PAD.encode(header.as_bytes()),
            signature: sign_detached(b"x", &k).signature,
        };
        assert!(matches!(
            verify_detached(&jws, b"x", &k.verifying_key()),
            Err(JwsError::Header)
        ));
    }
}
