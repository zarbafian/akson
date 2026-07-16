//! Identity/key-binding verification at pairing (design §8.1/§8.2 step 5).
//!
//! The peer's extended card carries a purpose-bound key-binding record: for
//! each statement purpose, a JWK, its RFC 7638 thumbprint, a generation, and a
//! validity interval. Untrusted JSON is first gated by the `key-binding.v1`
//! JSON Schema (closed purpose set, JWK shape, formats), then cryptographically
//! verified here: **every advertised thumbprint must equal the RFC 7638
//! thumbprint recomputed from its JWK** (closes review finding M6, the
//! "transported thumbprint not bound to its JWK" gap), and every interval must
//! be well-formed and cover the current time.
//!
//! What you write:
//! ```no_run
//! # use axon_pairing::key_binding::verify;
//! # use time::OffsetDateTime;
//! # let received_json = serde_json::json!({});
//! let result = verify(&received_json, OffsetDateTime::now_utc());
//! ```

use std::collections::BTreeMap;

use axon_crypto::jwk::Ed25519PublicJwk;
use axon_ext::schema::{self, SchemaId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, thiserror::Error)]
pub enum KeyBindingError {
    #[error("schema validation failed: {0}")]
    Schema(#[from] schema::SchemaError),
    #[error("could not parse key binding: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("invalid JWK for purpose {purpose}")]
    BadJwk { purpose: String },
    #[error("thumbprint does not match JWK for purpose {purpose}")]
    ThumbprintMismatch { purpose: String },
    #[error("the same key is advertised for more than one purpose (at {purpose})")]
    ReusedKey { purpose: String },
    #[error("invalid validity timestamp for purpose {purpose}")]
    BadTimestamp { purpose: String },
    #[error("validity interval is not well-formed for purpose {purpose}")]
    BadInterval { purpose: String },
    #[error("key for purpose {purpose} is not valid at the current time")]
    NotCurrentlyValid { purpose: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub issuer: String,
    pub agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub jwk: Ed25519PublicJwk,
    pub thumbprint: String,
    pub generation: u64,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBindingSet {
    pub schema_version: u8,
    pub subject: Identity,
    pub tls_certificate_sha256: String,
    /// Keyed by purpose; the schema restricts keys to the known statement
    /// purposes, so any key present here is a valid, known purpose.
    pub keys: BTreeMap<String, KeyEntry>,
}

/// Schema-gates, parses, and cryptographically verifies a received key-binding
/// record. Returns the parsed set on success.
pub fn verify(value: &Value, now: OffsetDateTime) -> Result<KeyBindingSet, KeyBindingError> {
    schema::validate(SchemaId::KeyBindingV1, value)?;
    let set: KeyBindingSet = serde_json::from_value(value.clone())?;

    let mut seen_thumbprints = std::collections::BTreeSet::new();
    for (purpose, entry) in &set.keys {
        // The JWK must be a valid Ed25519 point...
        entry.jwk.to_key().map_err(|_| KeyBindingError::BadJwk {
            purpose: purpose.clone(),
        })?;
        // ...and the advertised thumbprint must be *its* RFC 7638 thumbprint,
        // not an unrelated value (finding M6).
        let thumbprint = entry.jwk.thumbprint();
        if thumbprint != entry.thumbprint {
            return Err(KeyBindingError::ThumbprintMismatch {
                purpose: purpose.clone(),
            });
        }
        // Per-purpose key separation (design §8.1): the same key must not be
        // advertised for two purposes. Deduping on the *verified* thumbprint
        // means a forged thumbprint cannot hide reuse. Cross-purpose signature
        // replay is already blocked by domain separation (JWS typ/kid vs DSSE
        // payloadType), so this is defense-in-depth and design hygiene.
        if !seen_thumbprints.insert(thumbprint) {
            return Err(KeyBindingError::ReusedKey {
                purpose: purpose.clone(),
            });
        }

        let not_before = OffsetDateTime::parse(&entry.not_before, &Rfc3339).map_err(|_| {
            KeyBindingError::BadTimestamp {
                purpose: purpose.clone(),
            }
        })?;
        let not_after = OffsetDateTime::parse(&entry.not_after, &Rfc3339).map_err(|_| {
            KeyBindingError::BadTimestamp {
                purpose: purpose.clone(),
            }
        })?;
        if not_before >= not_after {
            return Err(KeyBindingError::BadInterval {
                purpose: purpose.clone(),
            });
        }
        if now < not_before || now >= not_after {
            return Err(KeyBindingError::NotCurrentlyValid {
                purpose: purpose.clone(),
            });
        }
    }
    Ok(set)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn jwk(seed: u8) -> Ed25519PublicJwk {
        Ed25519PublicJwk::from_key(&SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    /// A well-formed record whose thumbprints match their JWKs.
    fn record() -> Value {
        let card = jwk(1);
        let task = jwk(2);
        serde_json::json!({
            "schema_version": 1,
            "subject": { "issuer": "local", "agent": "agent-a" },
            "tls_certificate_sha256": "aa".repeat(32),
            "keys": {
                "agent-card": {
                    "jwk": card, "thumbprint": card.thumbprint(),
                    "generation": 0,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2030-01-01T00:00:00Z"
                },
                "task-result": {
                    "jwk": task, "thumbprint": task.thumbprint(),
                    "generation": 0,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2030-01-01T00:00:00Z"
                }
            }
        })
    }

    // 2025-06-01T00:00:00Z and 2031-01-01T00:00:00Z.
    fn now_2025() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_748_736_000).unwrap()
    }
    fn now_2031() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_924_992_000).unwrap()
    }

    #[test]
    fn valid_record_verifies() {
        let set = verify(&record(), now_2025()).unwrap();
        assert_eq!(set.subject.agent, "agent-a");
        assert_eq!(set.keys.len(), 2);
    }

    #[test]
    fn thumbprint_not_matching_jwk_is_rejected() {
        let mut r = record();
        // Swap in a different key's thumbprint under agent-card.
        r["keys"]["agent-card"]["thumbprint"] = Value::String(jwk(9).thumbprint());
        assert!(matches!(
            verify(&r, now_2025()),
            Err(KeyBindingError::ThumbprintMismatch { .. })
        ));
    }

    #[test]
    fn unknown_purpose_fails_schema() {
        let mut r = record();
        r["keys"]["root"] = r["keys"]["agent-card"].clone();
        assert!(matches!(
            verify(&r, now_2025()),
            Err(KeyBindingError::Schema(_))
        ));
    }

    #[test]
    fn same_key_for_two_purposes_is_rejected() {
        // Reuse the agent-card key (and its correct thumbprint) for task-result.
        let card = jwk(1);
        let r = serde_json::json!({
            "schema_version": 1,
            "subject": { "issuer": "local", "agent": "agent-a" },
            "tls_certificate_sha256": "aa".repeat(32),
            "keys": {
                "agent-card": { "jwk": card, "thumbprint": card.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" },
                "task-result": { "jwk": card, "thumbprint": card.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" }
            }
        });
        assert!(matches!(
            verify(&r, now_2025()),
            Err(KeyBindingError::ReusedKey { .. })
        ));
    }

    #[test]
    fn expired_key_is_rejected() {
        assert!(matches!(
            verify(&record(), now_2031()),
            Err(KeyBindingError::NotCurrentlyValid { .. })
        ));
    }

    #[test]
    fn inverted_interval_is_rejected() {
        let mut r = record();
        r["keys"]["agent-card"]["not_before"] = Value::String("2030-01-01T00:00:00Z".to_owned());
        r["keys"]["agent-card"]["not_after"] = Value::String("2020-01-01T00:00:00Z".to_owned());
        assert!(matches!(
            verify(&r, now_2025()),
            Err(KeyBindingError::BadInterval { .. })
        ));
    }
}
