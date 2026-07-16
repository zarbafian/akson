//! The internal peer identity tuple (design §8.1).
//!
//! Policy pins a *typed, issuer-qualified* tuple, never a display name. Every
//! fingerprint records its algorithm and its full value; truncation is
//! presentation only and is never used for matching (design §8.1). Certificate
//! fingerprints are SHA-256 over the complete DER; public-key fingerprints are
//! RFC 7638 thumbprints; card/projection digests are SHA-256 over canonical
//! JSON.
//!
//! What you write:
//! ```
//! use axon_crypto::identity::{Fingerprint, FingerprintKind};
//! let fp = Fingerprint::cert_sha256(b"<der bytes>");
//! assert_eq!(fp.kind, FingerprintKind::CertSha256);
//! println!("{}", fp.display()); // "sha256:<full hex>"
//! ```

use crate::jwk::thumbprint;
use crate::purpose::KeyPurpose;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How a fingerprint was computed. Two fingerprints only match if their kind
/// matches too, so a certificate digest can never be confused with a card
/// digest even if the hex were to coincide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FingerprintKind {
    /// SHA-256 over the complete DER certificate.
    CertSha256,
    /// RFC 7638 JWK thumbprint of a public key.
    Jwk7638,
    /// SHA-256 over canonical (RFC 8785) JSON — card and projection digests.
    JsonSha256,
}

/// An algorithm-tagged, full-length fingerprint. The `value` is never
/// truncated; display code may shorten it, matching never does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub kind: FingerprintKind,
    /// Full digest: lowercase hex for the SHA-256 kinds, base64url (unpadded)
    /// for the RFC 7638 thumbprint.
    pub value: String,
}

impl Fingerprint {
    /// SHA-256 over the complete DER certificate.
    pub fn cert_sha256(der: &[u8]) -> Self {
        Self {
            kind: FingerprintKind::CertSha256,
            value: hex_lower(&Sha256::digest(der)),
        }
    }

    /// RFC 7638 thumbprint of an Ed25519 public key.
    pub fn jwk(key: &VerifyingKey) -> Self {
        Self {
            kind: FingerprintKind::Jwk7638,
            value: thumbprint(key),
        }
    }

    /// SHA-256 over already-canonical JSON bytes (a card or projection digest).
    pub fn json_sha256(canonical_bytes: &[u8]) -> Self {
        Self {
            kind: FingerprintKind::JsonSha256,
            value: hex_lower(&Sha256::digest(canonical_bytes)),
        }
    }

    /// Matches on kind and full value — never on a truncated prefix.
    pub fn matches(&self, other: &Fingerprint) -> bool {
        self.kind == other.kind && self.value == other.value
    }

    /// Display form: algorithm label and full digest (design §8.1).
    pub fn display(&self) -> String {
        let alg = match self.kind {
            FingerprintKind::CertSha256 | FingerprintKind::JsonSha256 => "sha256",
            FingerprintKind::Jwk7638 => "jwk-thumbprint",
        };
        format!("{alg}:{}", self.value)
    }
}

/// One current verification key and the role it is allowed to act in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBinding {
    pub purpose: KeyPurpose,
    /// RFC 7638 thumbprint of the verification key.
    pub thumbprint: Fingerprint,
}

impl KeyBinding {
    pub fn new(purpose: KeyPurpose, key: &VerifyingKey) -> Self {
        Self {
            purpose,
            thumbprint: Fingerprint::jwk(key),
        }
    }
}

/// The peer identity tuple pinned by policy (design §8.1). Issuer-qualified and
/// typed even where a profile has no federated issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentity {
    /// Identity issuer or trust domain; `None` where no federated issuer.
    pub issuer: Option<String>,
    /// Stable agent identity.
    pub agent_id: String,
    /// Workload or device identity, where one exists.
    pub workload_id: Option<String>,
    /// Endpoint instance identity.
    pub endpoint_id: String,
    /// Current TLS certificate thumbprint (SHA-256 over DER).
    pub tls_cert: Fingerprint,
    /// Current Agent Card JWS verification-key thumbprint (RFC 7638).
    pub agent_card_key: Fingerprint,
    /// Current task-statement, evidence, and outcome verification keys with
    /// their allowed purposes.
    pub key_bindings: Vec<KeyBinding>,
    /// Authenticated Agent Card security-projection digest.
    pub security_projection_digest: Fingerprint,
    /// Full Agent Card digest, kept for display and change history.
    pub full_card_digest: Fingerprint,
}

impl PeerIdentity {
    /// The current binding for `purpose`, if the peer pinned one.
    pub fn binding(&self, purpose: KeyPurpose) -> Option<&KeyBinding> {
        self.key_bindings.iter().find(|b| b.purpose == purpose)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // 0x0..=0xf map into the ASCII hex table; indexing is in range.
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cert_fingerprint_is_sha256_hex() {
        let fp = Fingerprint::cert_sha256(b"");
        // SHA-256 of the empty input.
        assert_eq!(
            fp.value,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(fp.display(), format!("sha256:{}", fp.value));
    }

    #[test]
    fn different_kinds_never_match() {
        let a = Fingerprint {
            kind: FingerprintKind::CertSha256,
            value: "abcd".to_owned(),
        };
        let b = Fingerprint {
            kind: FingerprintKind::JsonSha256,
            value: "abcd".to_owned(),
        };
        assert!(!a.matches(&b));
    }

    #[test]
    fn binding_lookup_by_purpose() {
        let card = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let ev = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        let id = PeerIdentity {
            issuer: None,
            agent_id: "agent-a".to_owned(),
            workload_id: None,
            endpoint_id: "ep-1".to_owned(),
            tls_cert: Fingerprint::cert_sha256(b"der"),
            agent_card_key: Fingerprint::jwk(&card),
            key_bindings: vec![
                KeyBinding::new(KeyPurpose::TaskResult, &card),
                KeyBinding::new(KeyPurpose::Evidence, &ev),
            ],
            security_projection_digest: Fingerprint::json_sha256(b"{}"),
            full_card_digest: Fingerprint::json_sha256(b"{}"),
        };
        let b = id.binding(KeyPurpose::Evidence).unwrap();
        assert!(b.thumbprint.matches(&Fingerprint::jwk(&ev)));
        assert!(id.binding(KeyPurpose::ContractProposal).is_none());
    }
}
