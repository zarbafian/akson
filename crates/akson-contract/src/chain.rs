//! The revision chain and compare-and-swap contract head (design §9.3, §10.2).
//!
//! Each Task has exactly one local head. A revision advances the head only when
//! it chains onto it — the successor's `predecessor_digest` equals the current
//! head digest and its revision is exactly one greater — and only while the head
//! is still open (awaiting input). A signed acceptance locks the head at one
//! exact digest; after that, later siblings or revisions are stale and cannot
//! retroactively cancel the authority issued for the locked head.
//!
//! This is the pure decision: given the current head and a parsed revision, say
//! whether to advance, and given an acceptance, lock the exact head. The durable
//! compare-and-swap (one head row per Task) is the store's job; it applies these
//! verdicts atomically.
//!
//! What you write:
//! ```
//! use akson_contract::{apply_revision, HeadState, RevisionVerdict};
//! # use akson_contract::parse_payload;
//! # use serde_json::{json, Value};
//! # fn contract(rev: u64, predecessor: Option<&str>) -> akson_contract::ParsedContract {
//! #   let mut v = json!({
//! #     "schema_version": 1, "contract_id": "00000000-0000-4000-8000-000000000000",
//! #     "revision": rev, "task_type": "https://akson.invalid/t", "message_id": "m1",
//! #     "requester": {"issuer": "a", "agent": "b", "root": "root-fixture"}, "performer": {"issuer": "c", "agent": "d", "root": "root-fixture"},
//! #     "objective": "o", "inputs": [], "deliverables": [{"role": "r", "media_type": "text/plain"}],
//! #     "evidence_slots": [], "requested_capabilities": [], "processor_constraints": {"disclosure": "none"},
//! #     "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
//! #     "result_recipient": "request-origin", "created_at": "2026-01-01T00:00:00Z",
//! #     "expires_at": "2030-01-01T00:00:00Z"
//! #   });
//! #   if let Some(p) = predecessor { v["predecessor_digest"] = Value::from(p); v["task_id"] = Value::from("t1"); }
//! #   parse_payload(&akson_ext::jcs::canonical_bytes(&v).unwrap()).unwrap()
//! # }
//! let rev0 = contract(0, None);
//! // Revision 0 opens a fresh head.
//! let head = match apply_revision(&HeadState::Empty, &rev0) {
//!     RevisionVerdict::Advance(h) => HeadState::Open(h),
//!     RevisionVerdict::Stale(_) => unreachable!(),
//! };
//! // A revision-1 that names rev0 as predecessor chains on.
//! let rev1 = contract(1, Some(&rev0.digest));
//! assert!(matches!(apply_revision(&head, &rev1), RevisionVerdict::Advance(_)));
//! ```

use crate::contract::ParsedContract;

/// The compare-and-swap head for one Task. Removal/absence of a head is
/// [`Empty`](HeadState::Empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadState {
    /// No contract yet for this Task.
    Empty,
    /// The current head, awaiting input — open to a chaining successor.
    Open(Head),
    /// The head was accepted and locked at this digest; no successor is allowed.
    Locked(Head),
}

/// A head position: which revision is current and its contract digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub revision: u64,
    pub digest: String,
}

/// The verdict of applying a revision to the head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionVerdict {
    /// Accept: the head advances to this position.
    Advance(Head),
    /// Reject as stale; the head does not change.
    Stale(StaleReason),
}

/// Why a revision was rejected as stale (design §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleReason {
    /// Revision 0 arrived but a head already exists (a sibling/duplicate).
    HeadAlreadyExists,
    /// A follow-up revision arrived with no head to chain from.
    NoHead,
    /// The revision number is not exactly one past the head.
    NonSequential,
    /// The predecessor digest does not equal the current head digest.
    PredecessorMismatch,
    /// The head is locked by a signed acceptance; no successor is allowed.
    HeadLocked,
}

/// Why an acceptance could not lock the head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LockError {
    #[error("no open head exists to accept")]
    NoOpenHead,
    /// The accepted digest is not the current open head (a stale acceptance).
    #[error("accepted digest is not the current head")]
    DigestMismatch,
    #[error("the head is already locked")]
    AlreadyLocked,
}

/// Decides whether a parsed revision advances the head (design §9.3). Pure: the
/// caller applies [`Advance`](RevisionVerdict::Advance) as an atomic
/// compare-and-swap against the stored head.
pub fn apply_revision(head: &HeadState, proposed: &ParsedContract) -> RevisionVerdict {
    let c = &proposed.contract;
    let advance = Head {
        revision: c.revision,
        digest: proposed.digest.clone(),
    };

    if c.revision == 0 {
        // A fresh head, or a stale sibling if one already exists.
        return match head {
            HeadState::Empty => RevisionVerdict::Advance(advance),
            _ => RevisionVerdict::Stale(StaleReason::HeadAlreadyExists),
        };
    }

    // A follow-up revision must chain onto an open head exactly.
    let current = match head {
        HeadState::Empty => return RevisionVerdict::Stale(StaleReason::NoHead),
        HeadState::Locked(_) => return RevisionVerdict::Stale(StaleReason::HeadLocked),
        HeadState::Open(h) => h,
    };
    if c.revision != current.revision + 1 {
        return RevisionVerdict::Stale(StaleReason::NonSequential);
    }
    // Schema guarantees a follow-up carries a predecessor_digest.
    if c.predecessor_digest.as_deref() != Some(current.digest.as_str()) {
        return RevisionVerdict::Stale(StaleReason::PredecessorMismatch);
    }
    RevisionVerdict::Advance(advance)
}

/// Locks the open head at `accepted_digest` — the atomic effect of a signed
/// acceptance (design §9.3). Fails closed unless the head is open at exactly
/// that digest, so a stale acceptance cannot lock a head that has since moved.
pub fn accept_head(head: &HeadState, accepted_digest: &str) -> Result<HeadState, LockError> {
    match head {
        HeadState::Empty => Err(LockError::NoOpenHead),
        HeadState::Locked(_) => Err(LockError::AlreadyLocked),
        HeadState::Open(h) if h.digest == accepted_digest => Ok(HeadState::Locked(h.clone())),
        HeadState::Open(_) => Err(LockError::DigestMismatch),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::parse_payload;
    use serde_json::{json, Value};

    fn contract(rev: u64, predecessor: Option<&str>) -> ParsedContract {
        let mut v = json!({
            "schema_version": 1,
            "contract_id": "00000000-0000-4000-8000-000000000000",
            "revision": rev,
            "task_type": "https://akson.invalid/t",
            "message_id": "m1",
            "requester": {"issuer": "a", "agent": "b", "root": "root-fixture"},
            "performer": {"issuer": "c", "agent": "d", "root": "root-fixture"},
            "objective": "o",
            "inputs": [],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [],
            "requested_capabilities": [],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z"
        });
        if let Some(p) = predecessor {
            v["predecessor_digest"] = Value::from(p);
            v["task_id"] = Value::from("t1");
        }
        parse_payload(&akson_ext::jcs::canonical_bytes(&v).unwrap()).unwrap()
    }

    fn advanced(head: &HeadState, c: &ParsedContract) -> HeadState {
        match apply_revision(head, c) {
            RevisionVerdict::Advance(h) => HeadState::Open(h),
            RevisionVerdict::Stale(r) => panic!("unexpected stale: {r:?}"),
        }
    }

    #[test]
    fn rev0_opens_a_fresh_head_and_chains() {
        let rev0 = contract(0, None);
        let head = advanced(&HeadState::Empty, &rev0);
        assert_eq!(
            head,
            HeadState::Open(Head {
                revision: 0,
                digest: rev0.digest.clone()
            })
        );

        let rev1 = contract(1, Some(&rev0.digest));
        let head = advanced(&head, &rev1);
        assert_eq!(
            head,
            HeadState::Open(Head {
                revision: 1,
                digest: rev1.digest.clone()
            })
        );
    }

    #[test]
    fn rev0_with_existing_head_is_stale() {
        let head = advanced(&HeadState::Empty, &contract(0, None));
        assert_eq!(
            apply_revision(&head, &contract(0, None)),
            RevisionVerdict::Stale(StaleReason::HeadAlreadyExists)
        );
    }

    #[test]
    fn follow_up_without_head_is_stale() {
        assert_eq!(
            apply_revision(&HeadState::Empty, &contract(1, Some(&"0".repeat(64)))),
            RevisionVerdict::Stale(StaleReason::NoHead)
        );
    }

    #[test]
    fn wrong_predecessor_is_stale() {
        let rev0 = contract(0, None);
        let head = advanced(&HeadState::Empty, &rev0);
        // rev1 names a predecessor that is not the head digest.
        let bad = contract(1, Some(&"f".repeat(64)));
        assert_eq!(
            apply_revision(&head, &bad),
            RevisionVerdict::Stale(StaleReason::PredecessorMismatch)
        );
    }

    #[test]
    fn non_sequential_revision_is_stale() {
        let rev0 = contract(0, None);
        let head = advanced(&HeadState::Empty, &rev0);
        // Jumps to revision 2 over an open revision-0 head.
        let skip = contract(2, Some(&rev0.digest));
        assert_eq!(
            apply_revision(&head, &skip),
            RevisionVerdict::Stale(StaleReason::NonSequential)
        );
    }

    #[test]
    fn acceptance_locks_the_exact_head_and_bars_successors() {
        let rev0 = contract(0, None);
        let head = advanced(&HeadState::Empty, &rev0);
        let locked = accept_head(&head, &rev0.digest).unwrap();
        assert_eq!(
            locked,
            HeadState::Locked(Head {
                revision: 0,
                digest: rev0.digest.clone()
            })
        );

        // A would-be successor onto a locked head is stale.
        let rev1 = contract(1, Some(&rev0.digest));
        assert_eq!(
            apply_revision(&locked, &rev1),
            RevisionVerdict::Stale(StaleReason::HeadLocked)
        );
    }

    #[test]
    fn stale_acceptance_cannot_lock() {
        let rev0 = contract(0, None);
        let head = advanced(&HeadState::Empty, &rev0);
        assert_eq!(
            accept_head(&head, &"a".repeat(64)),
            Err(LockError::DigestMismatch)
        );
        assert_eq!(
            accept_head(&HeadState::Empty, "x"),
            Err(LockError::NoOpenHead)
        );
        let locked = accept_head(&head, &rev0.digest).unwrap();
        assert_eq!(
            accept_head(&locked, &rev0.digest),
            Err(LockError::AlreadyLocked)
        );
    }
}
