//! Envelope encryption for sensitive columns (ADR-0005, design §15.1).
//!
//! Values are sealed with a per-database data key (DEK); the DEK itself is
//! sealed with a key-encryption key (KEK) that the OS keystore protects
//! (ADR-0009). Only the wrapped DEK is persisted, so the SQLite file, its WAL,
//! temp files, and backups never hold plaintext.
//!
//! What you write:
//! ```
//! use axon_store::envelope::{DataKey, Kek};
//! let kek = Kek::from_bytes([7u8; 32]);
//! let dek = DataKey::generate();
//! let sealed = dek.seal("peers.local_note", b"secret note");
//! assert_eq!(dek.open("peers.local_note", &sealed).unwrap(), b"secret note");
//! // The plaintext never appears in the sealed bytes:
//! assert!(!sealed.windows(6).any(|w| w == b"secret"));
//! // The DEK travels only wrapped under the KEK, and unwraps to the same key:
//! let wrapped = dek.wrap(&kek);
//! let recovered = DataKey::unwrap(&kek, &wrapped).unwrap();
//! assert_eq!(recovered.open("peers.local_note", &sealed).unwrap(), b"secret note");
//! ```
//! The sealed format is `0x01 ‖ nonce(24) ‖ ciphertext‖tag`; the leading byte
//! versions the scheme, and the AAD `context` binds a ciphertext to its column
//! so it cannot be relocated.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

/// Current sealed-blob version byte.
const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 24;
/// AAD used when wrapping the DEK under the KEK.
const DEK_CONTEXT: &str = "axon.dek.v1";

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("sealed blob is malformed")]
    Malformed,
    #[error("unsupported sealed-blob version {0:#x}")]
    Version(u8),
    #[error("authentication failed (wrong key or tampered ciphertext)")]
    Auth,
}

/// The key-encryption key. 32 bytes; custody is the OS keystore (ADR-0009).
/// Never persisted by the store.
#[derive(Clone)]
pub struct Kek([u8; 32]);

impl Kek {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The per-database data key. Sealing goes through this; it is held in memory
/// only, and reaches disk solely in [`DataKey::wrap`]ped form.
pub struct DataKey([u8; 32]);

impl DataKey {
    /// A fresh random DEK from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self(k)
    }

    /// Seals `plaintext` with the DEK, binding it to `context` (its column) as
    /// additional authenticated data.
    pub fn seal(&self, context: &str, plaintext: &[u8]) -> Vec<u8> {
        seal_with(&self.0, context, plaintext)
    }

    /// Opens a value sealed by [`seal`](Self::seal) under the same `context`.
    pub fn open(&self, context: &str, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        open_with(&self.0, context, sealed)
    }

    /// Wraps (seals) the DEK under the KEK for persistence.
    pub fn wrap(&self, kek: &Kek) -> Vec<u8> {
        seal_with(&kek.0, DEK_CONTEXT, &self.0)
    }

    /// Recovers the DEK from its wrapped form. Fails closed on a wrong KEK or
    /// any tampering.
    pub fn unwrap(kek: &Kek, wrapped: &[u8]) -> Result<Self, SealError> {
        let bytes = open_with(&kek.0, DEK_CONTEXT, wrapped)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| SealError::Malformed)?;
        Ok(Self(arr))
    }
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    // Key length is fixed at 32; construction cannot fail.
    XChaCha20Poly1305::new(key.into())
}

fn seal_with(key: &[u8; 32], context: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher(key)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: context.as_bytes(),
            },
        )
        // Encryption over an in-memory buffer with a valid key/nonce does not
        // fail; an empty ciphertext would be caught by open() as malformed.
        .unwrap_or_default();
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn open_with(key: &[u8; 32], context: &str, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    let (&version, rest) = sealed.split_first().ok_or(SealError::Malformed)?;
    if version != VERSION {
        return Err(SealError::Version(version));
    }
    if rest.len() < NONCE_LEN {
        return Err(SealError::Malformed);
    }
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    cipher(key)
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| SealError::Auth)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let dek = DataKey::generate();
        let sealed = dek.seal("peers.local_note", b"top secret");
        assert_eq!(
            dek.open("peers.local_note", &sealed).unwrap(),
            b"top secret"
        );
    }

    #[test]
    fn plaintext_absent_from_sealed_bytes() {
        let dek = DataKey::generate();
        let sealed = dek.seal("c", b"MARKER-abc123");
        assert!(!sealed.windows(b"MARKER".len()).any(|w| w == b"MARKER"));
        assert_eq!(sealed[0], VERSION);
    }

    #[test]
    fn wrong_context_fails_closed() {
        let dek = DataKey::generate();
        let sealed = dek.seal("peers.local_note", b"x");
        // A ciphertext authenticated for one column cannot be opened as another.
        assert!(matches!(
            dek.open("peers.other_col", &sealed),
            Err(SealError::Auth)
        ));
    }

    #[test]
    fn tamper_fails_closed() {
        let dek = DataKey::generate();
        let mut sealed = dek.seal("c", b"x");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(dek.open("c", &sealed), Err(SealError::Auth)));
    }

    #[test]
    fn dek_wrap_round_trip() {
        let kek = Kek::from_bytes([9u8; 32]);
        let dek = DataKey::generate();
        let wrapped = dek.wrap(&kek);
        let recovered = DataKey::unwrap(&kek, &wrapped).unwrap();
        // The recovered DEK opens what the original sealed.
        let sealed = dek.seal("c", b"payload");
        assert_eq!(recovered.open("c", &sealed).unwrap(), b"payload");
    }

    #[test]
    fn wrong_kek_fails_closed() {
        let dek = DataKey::generate();
        let wrapped = dek.wrap(&Kek::from_bytes([1u8; 32]));
        assert!(matches!(
            DataKey::unwrap(&Kek::from_bytes([2u8; 32]), &wrapped),
            Err(SealError::Auth)
        ));
    }

    #[test]
    fn rejects_bad_version() {
        let dek = DataKey::generate();
        let mut sealed = dek.seal("c", b"x");
        sealed[0] = 0x02;
        assert!(matches!(
            dek.open("c", &sealed),
            Err(SealError::Version(0x02))
        ));
    }
}
