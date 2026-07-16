//! RFC 8785 JSON Canonicalization Scheme, via `json-canon`.
//!
//! Design §10.2/§14.1: Axon extension payloads are canonicalized with RFC
//! 8785 before digesting and DSSE signing. Inputs are expected to have passed
//! [`crate::ijson`] first, which guarantees canonicalization is lossless
//! (safe integer range, no duplicate keys).
//!
//! `serde_jcs` was evaluated first and rejected: it sorts object keys by
//! Unicode code point, not the UTF-16 code units RFC 8785 §3.2.3 requires
//! (caught by the frozen `jcs/utf16-key-sorting` golden vector).

use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum JcsError {
    #[error("canonicalization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Returns the RFC 8785 canonical UTF-8 bytes of `value`.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, JcsError> {
    Ok(json_canon::to_vec(value)?)
}

/// SHA-256 over the canonical bytes — the digest form used everywhere the
/// design says "canonical digest".
pub fn canonical_sha256(value: &Value) -> Result<[u8; 32], JcsError> {
    let bytes = canonical_bytes(value)?;
    Ok(Sha256::digest(&bytes).into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v = json!({"b": 2, "a": 1});
        assert_eq!(canonical_bytes(&v).unwrap(), br#"{"a":1,"b":2}"#);
    }

    #[test]
    fn digest_is_over_canonical_form() {
        let a = json!({"x": 1, "y": [1, 2]});
        let b = json!({"y": [1, 2], "x": 1});
        assert_eq!(canonical_sha256(&a).unwrap(), canonical_sha256(&b).unwrap());
    }
}
