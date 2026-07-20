//! Reliable-delivery primitives (design §9.2): RFC 9530 Content-Digest, the
//! covered-value idempotency tuple and its keyed commitment, and the tombstone
//! lifetime rule. The store methods that use these live in [`crate::Store`].
//!
//! Delivery is at least once with idempotent processing. Two requests are "the
//! same" iff every covered value matches: peer, Message id, exact body digest,
//! selected interface URL and tenant, A2A version, activated extension set,
//! content type, and HTTP method. The same peer + Message id with any covered
//! value changed is a conflict and a security event, never a second effect.
//!
//! The commitment is *keyed* (design §9.2/§15.3): it must not be an exportable
//! public content hash, so it is an HMAC under a per-database local key. The
//! Content-Digest, by contrast, is a public RFC 9530 field.
//!
//! What you write:
//! ```
//! use akson_store::delivery::{content_digest, CoveredValues};
//! assert_eq!(content_digest(b"hello"),
//!     "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:");
//! ```

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("Content-Digest is missing")]
    Missing,
    #[error("Content-Digest must carry exactly one value")]
    NotSingle,
    #[error("unsupported Content-Digest algorithm (only sha-256)")]
    Algorithm,
    #[error("malformed Content-Digest value")]
    Malformed,
    #[error("Content-Digest does not match the body")]
    Mismatch,
}

/// The base64 (standard) SHA-256 digest of `body` — the value carried in the
/// [`CoveredValues::body_digest`] field.
pub fn body_digest(body: &[u8]) -> String {
    STANDARD.encode(Sha256::digest(body))
}

/// The RFC 9530 `Content-Digest` field value for `body`: exactly one
/// `sha-256` entry as a Structured-Fields byte sequence (`:base64:`).
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", body_digest(body))
}

/// Parses and verifies a received `Content-Digest` header against `body`.
/// Fails closed unless it is exactly one `sha-256` value that matches
/// (design §9.2: a missing, duplicate, mismatched, or unsupported algorithm
/// rejects the request before Message parsing).
pub fn verify_content_digest(header: &str, body: &[u8]) -> Result<(), DeliveryError> {
    let header = header.trim();
    if header.is_empty() {
        return Err(DeliveryError::Missing);
    }
    // A duplicate (comma-separated list) is rejected: v1 accepts one value.
    if header.contains(',') {
        return Err(DeliveryError::NotSingle);
    }
    let (alg, value) = header.split_once('=').ok_or(DeliveryError::Malformed)?;
    if alg.trim() != "sha-256" {
        return Err(DeliveryError::Algorithm);
    }
    let inner = value
        .trim()
        .strip_prefix(':')
        .and_then(|v| v.strip_suffix(':'))
        .ok_or(DeliveryError::Malformed)?;
    let got = STANDARD
        .decode(inner)
        .map_err(|_| DeliveryError::Malformed)?;
    if got.as_slice() != Sha256::digest(body).as_slice() {
        return Err(DeliveryError::Mismatch);
    }
    Ok(())
}

/// The covered-value tuple that identifies a request for idempotency and
/// conflict detection (design §9.2). Serialized in a fixed field order; the
/// extension set is normalized (sorted, deduplicated) so ordering never
/// changes identity. `tenant` is omitted when absent, which is itself covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoveredValues {
    pub peer: String,
    pub message_id: String,
    /// base64 (standard) of the SHA-256 body digest — the exact body.
    pub body_digest: String,
    pub interface_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub a2a_version: String,
    pub extensions: Vec<String>,
    pub content_type: String,
    pub http_method: String,
}

impl CoveredValues {
    /// Normalizes the extension set (sorted, deduplicated) so two requests that
    /// list the same URIs in different orders are the same request.
    pub fn normalized(mut self) -> Self {
        self.extensions.sort();
        self.extensions.dedup();
        self
    }

    /// The RFC 8785 canonical bytes over which the commitment is computed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Serialization of a fixed struct with string fields cannot fail.
        json_canon_to_vec(self)
    }

    /// The keyed commitment: HMAC-SHA256 over the canonical covered values.
    /// Not a public content hash — the key is the database's local commitment
    /// key (design §9.2/§15.3).
    #[allow(clippy::expect_used)] // HMAC-SHA256 accepts any key length; a 32-byte key never errors.
    pub fn commitment(&self, key: &[u8; 32]) -> [u8; 32] {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&self.canonical_bytes());
        mac.finalize().into_bytes().into()
    }
}

/// The tombstone must outlive the sender's whole retry horizon (design §9.2):
/// it lasts through the task-retention window, and never less than the maximum
/// sender retry window plus contract expiry. All arguments are seconds.
pub fn tombstone_lifetime_secs(
    task_retention: u64,
    max_retry_window: u64,
    contract_expiry: u64,
) -> u64 {
    task_retention.max(max_retry_window + contract_expiry)
}

fn json_canon_to_vec<T: Serialize>(value: &T) -> Vec<u8> {
    json_canon::to_vec(value).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn covered() -> CoveredValues {
        CoveredValues {
            peer: "agent-b".to_owned(),
            message_id: "msg-1".to_owned(),
            body_digest: STANDARD.encode(Sha256::digest(b"body")),
            interface_url: "https://agent.example/a2a".to_owned(),
            tenant: None,
            a2a_version: "1.0".to_owned(),
            extensions: vec!["z".to_owned(), "a".to_owned()],
            content_type: "application/a2a+json".to_owned(),
            http_method: "POST".to_owned(),
        }
        .normalized()
    }

    #[test]
    fn content_digest_shape() {
        // RFC 9530 sha-256 of "hello".
        assert_eq!(
            content_digest(b"hello"),
            "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"
        );
    }

    #[test]
    fn verify_accepts_matching_digest() {
        assert!(verify_content_digest(&content_digest(b"hello"), b"hello").is_ok());
    }

    #[test]
    fn verify_rejects_mismatch_and_bad_alg() {
        assert!(matches!(
            verify_content_digest(&content_digest(b"hello"), b"world"),
            Err(DeliveryError::Mismatch)
        ));
        assert!(matches!(
            verify_content_digest("sha-512=:AAAA:", b"x"),
            Err(DeliveryError::Algorithm)
        ));
        assert!(matches!(
            verify_content_digest("sha-256=:a:, sha-256=:b:", b"x"),
            Err(DeliveryError::NotSingle)
        ));
        assert!(matches!(
            verify_content_digest("", b"x"),
            Err(DeliveryError::Missing)
        ));
    }

    #[test]
    fn extension_order_does_not_change_identity() {
        let a = covered();
        let mut b = a.clone();
        b.extensions = vec!["a".to_owned(), "z".to_owned()];
        assert_eq!(a.canonical_bytes(), b.normalized().canonical_bytes());
    }

    #[test]
    fn commitment_is_keyed_and_binds_every_field() {
        let key = [1u8; 32];
        let base = covered().commitment(&key);
        let mut changed = covered();
        changed.message_id = "msg-2".to_owned();
        assert_ne!(base, changed.commitment(&key));
        // Different key → different commitment (it is keyed, not a public hash).
        assert_ne!(base, covered().commitment(&[2u8; 32]));
    }

    #[test]
    fn tombstone_lifetime_is_the_larger_horizon() {
        // Retention dominates.
        assert_eq!(tombstone_lifetime_secs(1000, 100, 200), 1000);
        // Retry + contract expiry dominates.
        assert_eq!(tombstone_lifetime_secs(100, 300, 200), 500);
    }
}
