//! Personal-pairing invitations (design §8.2): a single-use 256-bit bearer
//! secret carried out of band, of which the daemon keeps only a verifier.
//!
//! The secret is high-entropy, so the verifier is a plain SHA-256 (no
//! password-hashing needed) and the comparison is constant-time. The daemon
//! never stores the secret itself; an attacker who reads the database cannot
//! recover it, and a guess is checked against the verifier without leaking
//! timing. The invitation expires (default 15 min, §8.5) and caps attempts.
//!
//! What you write:
//! ```
//! use axon_pairing::invitation::Invitation;
//! let (artifact, mut pending) = Invitation::create(
//!     "https://inviter.example/bootstrap".into(),
//!     "aa..".into(),  // inviter TLS cert SHA-256 (hex)
//!     "kPrK..".into(), // inviter Agent Card key thumbprint
//!     1_000,           // now (unix secs)
//!     900,             // ttl secs
//!     5,               // max attempts
//! );
//! // The artifact travels out of band (file/QR); the daemon keeps `pending`.
//! assert!(pending.check_secret(&artifact.secret, 1_100).is_ok());
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// 256-bit bearer secret.
pub const SECRET_BYTES: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvitationError {
    #[error("invitation has expired")]
    Expired,
    #[error("no invitation attempts remain")]
    AttemptsExhausted,
    #[error("presented secret is malformed")]
    Malformed,
    #[error("presented secret does not match")]
    BadSecret,
}

/// The out-of-band artifact the accepting endpoint receives. It carries the
/// bearer secret and the inviter's pinning fingerprints; it is transferred over
/// an authenticated/confidential channel or in-person QR (design §8.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    /// The inviter's separate, rate-limited bootstrap endpoint.
    pub endpoint: String,
    /// SHA-256 (hex) over the inviter's complete DER endpoint certificate —
    /// the accepter pins the bootstrap TLS connection to this.
    pub tls_certificate_sha256: String,
    /// The inviter's Agent Card JWS key RFC 7638 thumbprint.
    pub agent_card_key_thumbprint: String,
    /// Expiry, unix seconds.
    pub not_after: i64,
    /// base64url (unpadded) of the 256-bit secret.
    pub secret: String,
}

/// What the daemon persists: the secret's verifier and its limits — never the
/// secret. Stored encrypted like any other sensitive record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvitation {
    /// SHA-256 of the secret.
    verifier: [u8; 32],
    pub not_after: i64,
    pub max_attempts: u32,
    pub attempts_used: u32,
}

impl Invitation {
    /// Creates an invitation: a random secret for the artifact, and the
    /// verifier-only record for the daemon.
    pub fn create(
        endpoint: String,
        tls_certificate_sha256: String,
        agent_card_key_thumbprint: String,
        now: i64,
        ttl_secs: i64,
        max_attempts: u32,
    ) -> (Invitation, PendingInvitation) {
        let mut secret = [0u8; SECRET_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let not_after = now.saturating_add(ttl_secs);
        let artifact = Invitation {
            endpoint,
            tls_certificate_sha256,
            agent_card_key_thumbprint,
            not_after,
            secret: URL_SAFE_NO_PAD.encode(secret),
        };
        let pending = PendingInvitation {
            verifier: Sha256::digest(secret).into(),
            not_after,
            max_attempts,
            attempts_used: 0,
        };
        (artifact, pending)
    }
}

impl PendingInvitation {
    /// Checks a presented secret against the verifier in constant time,
    /// counting the attempt. Fails closed on expiry, exhausted attempts, a
    /// malformed secret, or a mismatch. A genuine idempotent retry is
    /// short-circuited by the pairing state machine *before* this is called, so
    /// every call here is a fresh attempt against the brute-force cap.
    pub fn check_secret(&mut self, presented: &str, now: i64) -> Result<(), InvitationError> {
        if now >= self.not_after {
            return Err(InvitationError::Expired);
        }
        if self.attempts_used >= self.max_attempts {
            return Err(InvitationError::AttemptsExhausted);
        }
        self.attempts_used += 1;
        let bytes = URL_SAFE_NO_PAD
            .decode(presented)
            .map_err(|_| InvitationError::Malformed)?;
        if bytes.len() != SECRET_BYTES {
            return Err(InvitationError::Malformed);
        }
        let presented_verifier = Sha256::digest(&bytes);
        if self.verifier.ct_eq(presented_verifier.as_slice()).into() {
            Ok(())
        } else {
            Err(InvitationError::BadSecret)
        }
    }

    pub fn attempts_remaining(&self) -> u32 {
        self.max_attempts.saturating_sub(self.attempts_used)
    }

    /// The secret's verifier — the pairing ledger's lookup key. Not the secret,
    /// so exposing it is safe (it is the SHA-256 of a high-entropy value).
    pub fn verifier(&self) -> [u8; 32] {
        self.verifier
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn invitation() -> (Invitation, PendingInvitation) {
        Invitation::create(
            "https://inviter.example/bootstrap".to_owned(),
            "aa".repeat(32),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k".to_owned(),
            1_000,
            900,
            5,
        )
    }

    #[test]
    fn correct_secret_verifies() {
        let (artifact, mut pending) = invitation();
        assert!(pending.check_secret(&artifact.secret, 1_100).is_ok());
        // The secret is never stored on the record.
        assert!(serde_json::to_string(&pending)
            .unwrap()
            .find(&artifact.secret)
            .is_none());
    }

    #[test]
    fn wrong_secret_fails_and_counts_attempt() {
        let (_artifact, mut pending) = invitation();
        let other = URL_SAFE_NO_PAD.encode([9u8; SECRET_BYTES]);
        assert_eq!(
            pending.check_secret(&other, 1_100),
            Err(InvitationError::BadSecret)
        );
        assert_eq!(pending.attempts_remaining(), 4);
    }

    #[test]
    fn attempts_are_capped() {
        let (_artifact, mut pending) = invitation();
        let bad = URL_SAFE_NO_PAD.encode([9u8; SECRET_BYTES]);
        for _ in 0..5 {
            let _ = pending.check_secret(&bad, 1_100);
        }
        assert_eq!(
            pending.check_secret(&bad, 1_100),
            Err(InvitationError::AttemptsExhausted)
        );
    }

    #[test]
    fn expiry_fails_closed() {
        let (artifact, mut pending) = invitation();
        assert_eq!(
            pending.check_secret(&artifact.secret, 2_000),
            Err(InvitationError::Expired)
        );
    }

    #[test]
    fn malformed_secret_rejected() {
        let (_artifact, mut pending) = invitation();
        assert_eq!(
            pending.check_secret("not-base64!!", 1_100),
            Err(InvitationError::Malformed)
        );
        assert_eq!(
            pending.check_secret(&URL_SAFE_NO_PAD.encode([1u8; 8]), 1_100),
            Err(InvitationError::Malformed)
        );
    }
}
