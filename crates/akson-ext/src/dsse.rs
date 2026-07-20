//! DSSE v1 envelopes (design §14.2).
//!
//! Akson profile on top of DSSE v1: exactly one signature per envelope, the
//! signature algorithm is Ed25519 (ADR-0004), and `keyid` is the signer's RFC
//! 7638 JWK thumbprint. The keyid is always *derived* from the verification
//! key, never taken on trust: [`sign`] computes it from the signing key and
//! [`verify`] recomputes it from the caller's key and requires the envelope to
//! match, so an envelope can never present key A under thumbprint B. The
//! expected `payloadType` is supplied by the verifier — an envelope can never
//! choose how it is interpreted. Purpose binding of keys is enforced one layer
//! up (`akson-crypto` key purposes).
//!
//! Verification uses `verify_strict` (RFC 8032 §5.1 / ed25519-dalek): it
//! rejects small-order public keys and non-canonical `R`, closing the
//! signature-malleability and low-order-point forgery classes.

use akson_crypto::jwk::thumbprint;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum DsseError {
    #[error("envelope must carry exactly one signature, found {0}")]
    SignatureCount(usize),
    #[error("payload type mismatch: expected {expected:?}, found {found:?}")]
    PayloadType { expected: String, found: String },
    #[error("key id mismatch: expected {expected:?}, found {found:?}")]
    KeyId { expected: String, found: String },
    #[error("invalid base64 in {field}")]
    Base64 { field: &'static str },
    #[error("signature verification failed")]
    BadSignature,
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// A DSSE v1 envelope. Field names follow the DSSE JSON representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Standard base64 of the payload bytes.
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    pub keyid: String,
    /// Standard base64 of the raw 64-byte Ed25519 signature.
    pub sig: String,
}

/// DSSE Pre-Authentication Encoding:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload`.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Signs `payload` as `payload_type`, producing a single-signature envelope
/// whose `keyid` is the signer's RFC 7638 thumbprint, derived here from the
/// key so it always matches.
pub fn sign(payload_type: &str, payload: &[u8], key: &SigningKey) -> Envelope {
    let signature = key.sign(&pae(payload_type, payload));
    Envelope {
        payload: STANDARD.encode(payload),
        payload_type: payload_type.to_owned(),
        signatures: vec![EnvelopeSignature {
            keyid: thumbprint(&key.verifying_key()),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    }
}

/// Verifies an envelope under the Akson profile and returns the payload bytes.
///
/// Fails closed unless: exactly one signature is present, `payload_type`
/// equals `expected_payload_type`, the signature's `keyid` equals the RFC 7638
/// thumbprint recomputed from `key` (so the envelope cannot claim a different
/// key's identity), and the Ed25519 signature strictly verifies under `key`
/// over the PAE of the decoded payload.
pub fn verify(
    envelope: &Envelope,
    expected_payload_type: &str,
    key: &VerifyingKey,
) -> Result<Vec<u8>, DsseError> {
    if envelope.signatures.len() != 1 {
        return Err(DsseError::SignatureCount(envelope.signatures.len()));
    }
    if envelope.payload_type != expected_payload_type {
        return Err(DsseError::PayloadType {
            expected: expected_payload_type.to_owned(),
            found: envelope.payload_type.clone(),
        });
    }
    let expected_keyid = thumbprint(key);
    let sig_entry = &envelope.signatures[0];
    if sig_entry.keyid != expected_keyid {
        return Err(DsseError::KeyId {
            expected: expected_keyid,
            found: sig_entry.keyid.clone(),
        });
    }
    let payload = decode_b64(&envelope.payload).ok_or(DsseError::Base64 { field: "payload" })?;
    let sig_bytes = decode_b64(&sig_entry.sig).ok_or(DsseError::Base64 { field: "sig" })?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| DsseError::Base64 { field: "sig" })?;
    // verify_strict rejects small-order keys and non-canonical R (RFC 8032).
    key.verify_strict(&pae(&envelope.payload_type, &payload), &signature)
        .map_err(|_| DsseError::BadSignature)?;
    Ok(payload)
}

/// DSSE accepts standard or URL-safe base64, padded or not, when parsing;
/// Akson always emits standard-with-padding.
fn decode_b64(s: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TYPE: &str = "application/vnd.akson.test+json";

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn pae_encoding_matches_spec_shape() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
        assert_eq!(pae("t", b""), b"DSSEv1 1 t 0 ".to_vec());
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = test_key();
        let env = sign(TYPE, br#"{"hello":"world"}"#, &key);
        assert_eq!(env.signatures[0].keyid, thumbprint(&key.verifying_key()));
        let payload = verify(&env, TYPE, &key.verifying_key()).unwrap();
        assert_eq!(payload, br#"{"hello":"world"}"#);
    }

    #[test]
    fn rejects_wrong_payload_type() {
        let key = test_key();
        let env = sign(TYPE, b"{}", &key);
        assert!(matches!(
            verify(&env, "application/other", &key.verifying_key()),
            Err(DsseError::PayloadType { .. })
        ));
    }

    #[test]
    fn rejects_keyid_not_matching_key() {
        // An envelope that presents key A's signature under a different
        // thumbprint must fail: verify recomputes the keyid from the key.
        let key = test_key();
        let mut env = sign(TYPE, b"{}", &key);
        env.signatures[0].keyid = "not-the-thumbprint".to_owned();
        assert!(matches!(
            verify(&env, TYPE, &key.verifying_key()),
            Err(DsseError::KeyId { .. })
        ));
    }

    #[test]
    fn rejects_tampered_payload() {
        let key = test_key();
        let mut env = sign(TYPE, b"{}", &key);
        env.payload = STANDARD.encode(b"{ }");
        assert!(matches!(
            verify(&env, TYPE, &key.verifying_key()),
            Err(DsseError::BadSignature)
        ));
    }

    #[test]
    fn rejects_multiple_signatures() {
        let key = test_key();
        let mut env = sign(TYPE, b"{}", &key);
        env.signatures.push(env.signatures[0].clone());
        assert!(matches!(
            verify(&env, TYPE, &key.verifying_key()),
            Err(DsseError::SignatureCount(2))
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let key = test_key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let env = sign(TYPE, b"{}", &key);
        // The envelope's keyid is key's thumbprint, so against `other` it is
        // the keyid check that fails first — still fails closed.
        assert!(matches!(
            verify(&env, TYPE, &other.verifying_key()),
            Err(DsseError::KeyId { .. })
        ));
    }
}
