//! Ed25519 public keys as JWKs (RFC 8037) with RFC 7638 thumbprints.
//!
//! Design §8.1/§14.2: public keys are represented as JWKs and identified by
//! RFC 7638 thumbprints; displays include the algorithm and full digest.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum JwkError {
    #[error("unsupported JWK: expected kty OKP, crv Ed25519")]
    Unsupported,
    #[error("invalid x coordinate")]
    InvalidX,
}

/// An Ed25519 public JWK. Only the three required members are modeled; any
/// other member is irrelevant to identity and excluded from the thumbprint
/// by RFC 7638 anyway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519PublicJwk {
    pub kty: String,
    pub crv: String,
    /// base64url (unpadded) raw 32-byte public key.
    pub x: String,
}

impl Ed25519PublicJwk {
    pub fn from_key(key: &VerifyingKey) -> Self {
        Self {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: URL_SAFE_NO_PAD.encode(key.as_bytes()),
        }
    }

    pub fn to_key(&self) -> Result<VerifyingKey, JwkError> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(JwkError::Unsupported);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|_| JwkError::InvalidX)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| JwkError::InvalidX)?;
        VerifyingKey::from_bytes(&arr).map_err(|_| JwkError::InvalidX)
    }

    /// RFC 7638 thumbprint: SHA-256 over the required members serialized in
    /// lexicographic order with no whitespace, base64url unpadded.
    ///
    /// The construction string is assembled directly (`crv`, `kty`, `x` are
    /// already lexicographically ordered) so the thumbprint cannot drift with
    /// a JSON library's escaping choices; the members are ASCII by
    /// construction.
    pub fn thumbprint(&self) -> String {
        let construction = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#,
            self.crv, self.kty, self.x
        );
        URL_SAFE_NO_PAD.encode(Sha256::digest(construction.as_bytes()))
    }
}

/// Convenience: the RFC 7638 thumbprint of a raw verifying key.
pub fn thumbprint(key: &VerifyingKey) -> String {
    Ed25519PublicJwk::from_key(key).thumbprint()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// RFC 8037 appendix A.3 published example.
    #[test]
    fn rfc8037_thumbprint_example() {
        let jwk = Ed25519PublicJwk {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned(),
        };
        assert_eq!(
            jwk.thumbprint(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn jwk_round_trip() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let jwk = Ed25519PublicJwk::from_key(&key);
        assert_eq!(jwk.to_key().unwrap(), key);
    }

    #[test]
    fn rejects_foreign_jwk() {
        let jwk = Ed25519PublicJwk {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: "AAAA".to_owned(),
        };
        assert!(matches!(jwk.to_key(), Err(JwkError::Unsupported)));
    }
}
