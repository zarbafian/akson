//! The bootstrap state machine (design §8.2): consume an invitation exactly
//! once, and make retries idempotent.
//!
//! This is the pairing analogue of the reliable-delivery model. Keyed on the
//! secret's verifier and the presented transcript digest:
//! - a **fresh** valid bootstrap consumes the invitation and records the
//!   pending-pair response;
//! - an **exact retry** (same secret, same transcript) replays that response —
//!   no second peer is ever created;
//! - the **same secret with a changed transcript** is an attack;
//! - an expired or unknown secret fails closed.
//!
//! Persistence is a [`PairingLedger`]; [`MemoryLedger`] is the default. A
//! SQLite-backed ledger slots in behind the same trait without changing this
//! logic. Brute-force is bounded primarily by the 256-bit secret and the
//! (endpoint-level) bootstrap rate limit; the invitation's own attempt cap is a
//! secondary bound applied here when a secret reaches its invitation.
//!
//! What you write:
//! ```
//! use axon_pairing::invitation::Invitation;
//! use axon_pairing::state_machine::{accept, Accepted, MemoryLedger};
//! let (artifact, pending) = Invitation::create(
//!     "https://x/bootstrap".into(), "aa".into(), "kid".into(), 0, 900, 5);
//! let mut ledger = MemoryLedger::new();
//! ledger.add(pending);
//! let out = accept(&mut ledger, &artifact.secret, [7u8; 32], b"OK".to_vec(), 100).unwrap();
//! assert!(matches!(out, Accepted::Paired { .. }));
//! ```

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::invitation::{InvitationError, PendingInvitation};

/// The record kept for a consumed invitation until it expires: what a retry
/// must reproduce. The response and pending-pair details are stored encrypted
/// by the persistent ledger.
#[derive(Debug, Clone)]
pub struct Consumed {
    pub transcript_digest: [u8; 32],
    pub response: Vec<u8>,
}

/// The verdict of a bootstrap attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// First valid use: the invitation was consumed and the peer is pending.
    Paired { response: Vec<u8> },
    /// Exact retry of a consumed invitation with the same transcript.
    Replay { response: Vec<u8> },
    /// Same secret, a different transcript — an attack; nothing changes.
    TranscriptConflict,
    /// No live invitation matches the secret (unknown or already gone).
    BadSecret,
    /// The matching invitation has expired.
    Expired,
    /// The matching invitation ran out of attempts.
    AttemptsExhausted,
}

/// A pairing-ledger backend failure. Kept backend-agnostic (a `String`) so this
/// crate does not depend on any particular storage library; the SQLite-backed
/// ledger maps its database and sealing errors into it.
#[derive(Debug, thiserror::Error)]
#[error("pairing ledger backend error: {0}")]
pub struct LedgerError(pub String);

/// Persistence for the bootstrap: live invitations by verifier, and the
/// consumed records that make retries idempotent.
///
/// Every method is fallible: a persistent backend can fail, and — critically —
/// [`commit_consumed`](Self::commit_consumed) must not silently succeed, or a
/// consumed secret could be paired twice. Errors propagate to the caller, which
/// fails the request closed rather than proceeding.
pub trait PairingLedger {
    /// The consumed record for a verifier, if the invitation was already used.
    fn consumed(&self, verifier: &[u8; 32]) -> Result<Option<Consumed>, LedgerError>;
    /// Whether a live invitation exists for this verifier — a cheap pre-check
    /// so an unknown secret is rejected before any signature verification.
    fn active_exists(&self, verifier: &[u8; 32]) -> Result<bool, LedgerError>;
    /// Removes and returns the live invitation for a verifier, if present.
    fn take_active(
        &mut self,
        verifier: &[u8; 32],
    ) -> Result<Option<PendingInvitation>, LedgerError>;
    /// Re-inserts a live invitation (e.g. after a failed-but-not-final attempt).
    fn put_active(
        &mut self,
        verifier: [u8; 32],
        invitation: PendingInvitation,
    ) -> Result<(), LedgerError>;
    /// Atomically records a consumed invitation (the active one having been
    /// taken). On a real ledger this is one transaction — the secret is
    /// consumed in the same commit that creates the pending peer (§8.2).
    fn commit_consumed(
        &mut self,
        verifier: [u8; 32],
        consumed: Consumed,
    ) -> Result<(), LedgerError>;
}

/// The verifier (ledger key) for a presented base64url secret, or `None` if the
/// secret is malformed.
pub fn verifier_of(presented_secret: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(presented_secret).ok()?;
    Some(Sha256::digest(bytes).into())
}

/// Runs a bootstrap attempt against the ledger. Returns an error only if the
/// ledger backend fails (the request must then fail closed); every pairing
/// outcome — including bad/expired secrets — is an [`Accepted`] value.
pub fn accept(
    ledger: &mut impl PairingLedger,
    presented_secret: &str,
    transcript_digest: [u8; 32],
    response: Vec<u8>,
    now: i64,
) -> Result<Accepted, LedgerError> {
    let verifier = match verifier_of(presented_secret) {
        Some(v) => v,
        None => return Ok(Accepted::BadSecret),
    };

    // A consumed invitation is idempotent: same transcript replays, a changed
    // transcript under the same secret is an attack.
    if let Some(prior) = ledger.consumed(&verifier)? {
        return Ok(if prior.transcript_digest == transcript_digest {
            Accepted::Replay {
                response: prior.response,
            }
        } else {
            Accepted::TranscriptConflict
        });
    }

    let Some(mut invitation) = ledger.take_active(&verifier)? else {
        return Ok(Accepted::BadSecret);
    };

    match invitation.check_secret(presented_secret, now) {
        Ok(()) => {
            ledger.commit_consumed(
                verifier,
                Consumed {
                    transcript_digest,
                    response: response.clone(),
                },
            )?;
            Ok(Accepted::Paired { response })
        }
        // Expired or exhausted invitations are dead — not re-inserted.
        Err(InvitationError::Expired) => Ok(Accepted::Expired),
        Err(InvitationError::AttemptsExhausted) => Ok(Accepted::AttemptsExhausted),
        // A verifier match with a failing constant-time check is only reachable
        // via a hash collision; re-insert the (attempt-incremented) invitation.
        Err(InvitationError::BadSecret | InvitationError::Malformed) => {
            ledger.put_active(verifier, invitation)?;
            Ok(Accepted::BadSecret)
        }
    }
}

/// The default in-memory ledger (tests, ephemeral runs).
#[derive(Default)]
pub struct MemoryLedger {
    active: HashMap<[u8; 32], PendingInvitation>,
    consumed: HashMap<[u8; 32], Consumed>,
}

impl MemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a live invitation (from [`Invitation::create`]).
    pub fn add(&mut self, invitation: PendingInvitation) {
        self.active.insert(invitation.verifier(), invitation);
    }
}

impl PairingLedger for MemoryLedger {
    fn consumed(&self, verifier: &[u8; 32]) -> Result<Option<Consumed>, LedgerError> {
        Ok(self.consumed.get(verifier).cloned())
    }

    fn active_exists(&self, verifier: &[u8; 32]) -> Result<bool, LedgerError> {
        Ok(self.active.contains_key(verifier))
    }

    fn take_active(
        &mut self,
        verifier: &[u8; 32],
    ) -> Result<Option<PendingInvitation>, LedgerError> {
        Ok(self.active.remove(verifier))
    }

    fn put_active(
        &mut self,
        verifier: [u8; 32],
        invitation: PendingInvitation,
    ) -> Result<(), LedgerError> {
        self.active.insert(verifier, invitation);
        Ok(())
    }

    fn commit_consumed(
        &mut self,
        verifier: [u8; 32],
        consumed: Consumed,
    ) -> Result<(), LedgerError> {
        self.active.remove(&verifier);
        self.consumed.insert(verifier, consumed);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::invitation::Invitation;

    fn setup() -> (String, MemoryLedger) {
        let (artifact, pending) = Invitation::create(
            "https://inviter.example/bootstrap".to_owned(),
            "aa".repeat(32),
            "kid".to_owned(),
            1_000,
            900,
            5,
        );
        let mut ledger = MemoryLedger::new();
        ledger.add(pending);
        (artifact.secret, ledger)
    }

    const T1: [u8; 32] = [1u8; 32];
    const T2: [u8; 32] = [2u8; 32];

    #[test]
    fn fresh_bootstrap_pairs() {
        let (secret, mut ledger) = setup();
        let out = accept(&mut ledger, &secret, T1, b"RESPONSE".to_vec(), 1_100).unwrap();
        assert_eq!(
            out,
            Accepted::Paired {
                response: b"RESPONSE".to_vec()
            }
        );
    }

    #[test]
    fn exact_retry_replays_the_response() {
        let (secret, mut ledger) = setup();
        accept(&mut ledger, &secret, T1, b"RESPONSE".to_vec(), 1_100).unwrap();
        // A retry re-sends the same secret and transcript, and gets the saved
        // response back — no second peer.
        let out = accept(&mut ledger, &secret, T1, b"IGNORED".to_vec(), 1_200).unwrap();
        assert_eq!(
            out,
            Accepted::Replay {
                response: b"RESPONSE".to_vec()
            }
        );
    }

    #[test]
    fn same_secret_changed_transcript_is_conflict() {
        let (secret, mut ledger) = setup();
        accept(&mut ledger, &secret, T1, b"RESPONSE".to_vec(), 1_100).unwrap();
        let out = accept(&mut ledger, &secret, T2, b"x".to_vec(), 1_200).unwrap();
        assert_eq!(out, Accepted::TranscriptConflict);
    }

    #[test]
    fn unknown_secret_fails_closed() {
        let (_secret, mut ledger) = setup();
        let bogus = URL_SAFE_NO_PAD.encode([9u8; 32]);
        let out = accept(&mut ledger, &bogus, T1, b"x".to_vec(), 1_100).unwrap();
        assert_eq!(out, Accepted::BadSecret);
    }

    #[test]
    fn expired_invitation_fails_closed() {
        let (secret, mut ledger) = setup();
        let out = accept(&mut ledger, &secret, T1, b"x".to_vec(), 5_000).unwrap();
        assert_eq!(out, Accepted::Expired);
    }

    #[test]
    fn no_second_peer_from_a_conflicting_retry() {
        // After a conflict, the original consumed record is unchanged: a
        // correct retry still replays the original response.
        let (secret, mut ledger) = setup();
        accept(&mut ledger, &secret, T1, b"FIRST".to_vec(), 1_100).unwrap();
        accept(&mut ledger, &secret, T2, b"attack".to_vec(), 1_150).unwrap();
        let out = accept(&mut ledger, &secret, T1, b"x".to_vec(), 1_200).unwrap();
        assert_eq!(
            out,
            Accepted::Replay {
                response: b"FIRST".to_vec()
            }
        );
    }
}
