//! Purpose-bound Ed25519 keys (design §8.1, ADR-0004).
//!
//! A key is generated for exactly one [`KeyPurpose`] and carries it. Every
//! signing and verification call states the purpose it intends; a mismatch
//! fails closed before any signature math. This is the enforcement point for
//! "one key, one role" — the Agent Card JWS key can never sign a task result,
//! and a pinned task-result key can never be asked to verify an Agent Card.
//!
//! What you write:
//! ```
//! use axon_crypto::keypair::PurposeKey;
//! use axon_crypto::purpose::KeyPurpose;
//! use ed25519_dalek::Signer;
//! let card = PurposeKey::from_seed(KeyPurpose::AgentCard, &[1u8; 32]);
//! // Using it in its own role is fine:
//! card.sign_with(KeyPurpose::AgentCard, |sk| sk.sign(b"..")).unwrap();
//! // Using it in any other role fails closed:
//! assert!(card.sign_with(KeyPurpose::TaskResult, |sk| sk.sign(b"..")).is_err());
//! ```
//! The raw [`SigningKey`] is never handed out — it is only reachable inside the
//! `sign_with` closure, and only once the purpose has been checked.

use crate::jwk::{thumbprint, Ed25519PublicJwk};
use crate::purpose::KeyPurpose;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key purpose mismatch: key is bound to {actual:?}, used as {requested:?}")]
    Purpose {
        actual: KeyPurpose,
        requested: KeyPurpose,
    },
    #[error("public key bytes are not a valid Ed25519 point")]
    MalformedKey,
}

/// A secret Ed25519 key bound to one purpose.
pub struct PurposeKey {
    purpose: KeyPurpose,
    signing: SigningKey,
}

impl PurposeKey {
    /// Generates a fresh key from the OS CSPRNG for `purpose`.
    pub fn generate(purpose: KeyPurpose) -> Self {
        Self {
            purpose,
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Builds a key from a fixed 32-byte RFC 8032 seed. Deterministic — used
    /// by tests and golden vectors, never for production key material.
    pub fn from_seed(purpose: KeyPurpose, seed: &[u8; 32]) -> Self {
        Self {
            purpose,
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The public side, carrying the same purpose.
    pub fn verifying(&self) -> PurposeVerifyingKey {
        PurposeVerifyingKey {
            purpose: self.purpose,
            verifying: self.signing.verifying_key(),
        }
    }

    /// RFC 7638 thumbprint of the public key.
    pub fn thumbprint(&self) -> String {
        thumbprint(&self.signing.verifying_key())
    }

    /// Runs `f` with the raw signing key, but only if `intended` matches the
    /// key's bound purpose. This is the single door to the secret key, and it
    /// is gated: cross-purpose use returns [`KeyError::Purpose`] and `f` never
    /// runs. Returning the closure's value keeps callers (JWS, DSSE) able to
    /// reuse the underlying primitive without the key escaping.
    pub fn sign_with<T>(
        &self,
        intended: KeyPurpose,
        f: impl FnOnce(&SigningKey) -> T,
    ) -> Result<T, KeyError> {
        if intended != self.purpose {
            return Err(KeyError::Purpose {
                actual: self.purpose,
                requested: intended,
            });
        }
        Ok(f(&self.signing))
    }

    /// Exports the key as PKCS#8 DER, gated to `intended`. Unlike
    /// [`sign_with`](Self::sign_with) this hands the secret *out* — required
    /// because a TLS library (rustls, ADR-0011) must hold the key to sign
    /// handshakes. The purpose gate keeps it to the one role that legitimately
    /// needs it; use it nowhere else.
    pub fn pkcs8_der(&self, intended: KeyPurpose) -> Result<Vec<u8>, KeyError> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        self.sign_with(intended, |sk| {
            // PKCS#8 encoding of a valid Ed25519 key cannot fail; an empty
            // vector on the impossible error path is rejected downstream.
            sk.to_pkcs8_der()
                .map(|doc| doc.as_bytes().to_vec())
                .unwrap_or_default()
        })
    }
}

/// A public Ed25519 key bound to one purpose — what pairing pins and the
/// identity tuple stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurposeVerifyingKey {
    purpose: KeyPurpose,
    verifying: VerifyingKey,
}

impl PurposeVerifyingKey {
    pub fn new(purpose: KeyPurpose, verifying: VerifyingKey) -> Self {
        Self { purpose, verifying }
    }

    /// Builds a purpose-bound verifying key from a raw 32-byte Ed25519 public key —
    /// e.g. a peer's verification key rehydrated from the store. Fails closed if the
    /// bytes are not a valid point.
    pub fn from_public_bytes(purpose: KeyPurpose, bytes: &[u8; 32]) -> Result<Self, KeyError> {
        let verifying = VerifyingKey::from_bytes(bytes).map_err(|_| KeyError::MalformedKey)?;
        Ok(Self { purpose, verifying })
    }

    /// The raw 32-byte Ed25519 public key — for persistence.
    pub fn to_public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    pub fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    pub fn thumbprint(&self) -> String {
        thumbprint(&self.verifying)
    }

    pub fn to_jwk(&self) -> Ed25519PublicJwk {
        Ed25519PublicJwk::from_key(&self.verifying)
    }

    /// Yields the verifying key, but only for its bound purpose. Verification
    /// callers (e.g. `card_sig::verify_card`) go through this so a key pinned
    /// for one role can never be used to check another role's signature.
    pub fn key_for(&self, intended: KeyPurpose) -> Result<&VerifyingKey, KeyError> {
        if intended != self.purpose {
            return Err(KeyError::Purpose {
                actual: self.purpose,
                requested: intended,
            });
        }
        Ok(&self.verifying)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn same_purpose_signs() {
        let k = PurposeKey::from_seed(KeyPurpose::AgentCard, &[1u8; 32]);
        let sig = k
            .sign_with(KeyPurpose::AgentCard, |sk| sk.sign(b"msg"))
            .unwrap();
        assert!(k
            .verifying()
            .key_for(KeyPurpose::AgentCard)
            .unwrap()
            .verify_strict(b"msg", &sig)
            .is_ok());
    }

    #[test]
    fn cross_purpose_signing_fails_closed() {
        let k = PurposeKey::from_seed(KeyPurpose::AgentCard, &[1u8; 32]);
        let err = k
            .sign_with(KeyPurpose::TaskResult, |sk| sk.sign(b"msg"))
            .unwrap_err();
        assert!(matches!(
            err,
            KeyError::Purpose {
                actual: KeyPurpose::AgentCard,
                requested: KeyPurpose::TaskResult,
            }
        ));
    }

    #[test]
    fn cross_purpose_verification_fails_closed() {
        let k = PurposeKey::from_seed(KeyPurpose::TaskResult, &[2u8; 32]);
        assert!(matches!(
            k.verifying().key_for(KeyPurpose::AgentCard),
            Err(KeyError::Purpose { .. })
        ));
    }

    #[test]
    fn generate_is_random() {
        let a = PurposeKey::generate(KeyPurpose::Evidence);
        let b = PurposeKey::generate(KeyPurpose::Evidence);
        assert_ne!(a.thumbprint(), b.thumbprint());
    }

    #[test]
    fn seed_is_deterministic() {
        let a = PurposeKey::from_seed(KeyPurpose::Evidence, &[5u8; 32]);
        let b = PurposeKey::from_seed(KeyPurpose::Evidence, &[5u8; 32]);
        assert_eq!(a.thumbprint(), b.thumbprint());
    }
}
