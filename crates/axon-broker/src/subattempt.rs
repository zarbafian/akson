//! The processor sub-attempt state machine (design §13.1 "Processor calls are
//! effects").
//!
//! Sending plaintext to a processor discloses data and may incur cost, so every
//! call is a durable sub-attempt:
//! `prepared → dispatching → completed | failed | ambiguous | cancelled`.
//!
//! `dispatching` is the durable-before-effect point: the broker records
//! `dispatching` before the first byte leaves. A crash or lost response *after*
//! that resolves to `ambiguous` and is never auto-retried — a duplicate call could
//! double a disclosure or a cost, even for a local processor (crashes duplicate
//! work even without egress). A crash while still `prepared` sent nothing, so it
//! may be abandoned. Terminal states are final.
//!
//! This is the pure transition function; the durable record (provider, origin,
//! digests, idempotency key, cost bound) is stored by the broker/store, which
//! drives these transitions.
//!
//! What you write:
//! ```
//! use axon_broker::{SubAttemptState, SubAttemptEvent, next};
//! let s = SubAttemptState::Prepared;
//! let s = next(s, SubAttemptEvent::Dispatch).unwrap();
//! let s = next(s, SubAttemptEvent::Complete).unwrap();
//! assert_eq!(s, SubAttemptState::Completed);
//! assert!(s.is_terminal());
//! ```

use serde::{Deserialize, Serialize};

/// The state of one processor sub-attempt (design §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubAttemptState {
    /// The pre-dispatch record is durable; nothing has been sent — safe to abandon.
    Prepared,
    /// Recorded before the first byte leaves; a disclosure/cost may now occur.
    Dispatching,
    Completed,
    /// A clean failure with no possible transmission (e.g. a rejected address, a
    /// refused connection, or a pre-send validation error).
    Failed,
    /// The outcome is uncertain — a response may have been transmitted. Never
    /// auto-retried; the operator authorizes any new attempt after seeing the
    /// possible duplicate disclosure and cost.
    Ambiguous,
    Cancelled,
}

impl SubAttemptState {
    /// Whether this is a terminal state — no further transition is allowed.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            SubAttemptState::Completed
                | SubAttemptState::Failed
                | SubAttemptState::Ambiguous
                | SubAttemptState::Cancelled
        )
    }

    /// The persisted string form.
    pub fn as_str(self) -> &'static str {
        match self {
            SubAttemptState::Prepared => "prepared",
            SubAttemptState::Dispatching => "dispatching",
            SubAttemptState::Completed => "completed",
            SubAttemptState::Failed => "failed",
            SubAttemptState::Ambiguous => "ambiguous",
            SubAttemptState::Cancelled => "cancelled",
        }
    }

    /// Parses a persisted state string.
    #[allow(clippy::should_implement_trait)] // a fallible Option helper, not FromStr.
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "prepared" => SubAttemptState::Prepared,
            "dispatching" => SubAttemptState::Dispatching,
            "completed" => SubAttemptState::Completed,
            "failed" => SubAttemptState::Failed,
            "ambiguous" => SubAttemptState::Ambiguous,
            "cancelled" => SubAttemptState::Cancelled,
            _ => return None,
        })
    }
}

/// An event that drives a sub-attempt's state (design §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubAttemptEvent {
    /// Begin the dispatch (record `dispatching` before the first byte leaves).
    /// `prepared → dispatching`.
    Dispatch,
    /// The response was received in full. `dispatching → completed`.
    Complete,
    /// A clean failure with no possible transmission. `dispatching → failed`.
    Fail,
    /// The outcome is uncertain (a response may have been sent). `dispatching →
    /// ambiguous`.
    MarkAmbiguous,
    /// Cancel a non-terminal sub-attempt. `prepared → cancelled` (nothing sent),
    /// but `dispatching → ambiguous`: bytes may already have left, and cancellation
    /// cannot undo a disclosure (§13.1).
    Cancel,
    /// Recovery found a sub-attempt left `dispatching` by a crash: it resolves to
    /// `ambiguous` and is never re-run. `dispatching → ambiguous`.
    RecoverAfterCrash,
}

/// Why a transition was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("{state:?} is terminal; no further transition")]
    AlreadyTerminal { state: SubAttemptState },
    #[error("{event:?} is not valid from {state:?}")]
    Invalid {
        state: SubAttemptState,
        event: SubAttemptEvent,
    },
}

/// Applies an event to a sub-attempt state (design §13.1). Pure and total: a
/// terminal state or an out-of-order event fails closed, so the store can drive
/// transitions without re-deriving the rules.
pub fn next(
    state: SubAttemptState,
    event: SubAttemptEvent,
) -> Result<SubAttemptState, TransitionError> {
    use SubAttemptEvent as E;
    use SubAttemptState as S;

    if state.is_terminal() {
        return Err(TransitionError::AlreadyTerminal { state });
    }
    let invalid = || TransitionError::Invalid { state, event };
    Ok(match (state, event) {
        (S::Prepared, E::Dispatch) => S::Dispatching,
        (S::Dispatching, E::Complete) => S::Completed,
        (S::Dispatching, E::Fail) => S::Failed,
        (S::Dispatching, E::MarkAmbiguous) => S::Ambiguous,
        // Cancel is clean only before dispatch; once dispatching, a byte may have
        // left and cancellation cannot undo the disclosure — resolve ambiguous.
        (S::Prepared, E::Cancel) => S::Cancelled,
        (S::Dispatching, E::Cancel) => S::Ambiguous,
        // A crash after dispatch began is uncertain; before it, nothing was sent.
        (S::Dispatching, E::RecoverAfterCrash) => S::Ambiguous,
        _ => return Err(invalid()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use SubAttemptEvent as E;
    use SubAttemptState as S;

    #[test]
    fn happy_path_dispatches_and_completes() {
        let s = next(S::Prepared, E::Dispatch).unwrap();
        assert_eq!(s, S::Dispatching);
        let s = next(s, E::Complete).unwrap();
        assert_eq!(s, S::Completed);
        assert!(s.is_terminal());
    }

    #[test]
    fn crash_while_dispatching_is_ambiguous_never_retries() {
        let s = next(S::Dispatching, E::RecoverAfterCrash).unwrap();
        assert_eq!(s, S::Ambiguous);
        assert!(s.is_terminal());
        assert!(matches!(
            next(s, E::Dispatch),
            Err(TransitionError::AlreadyTerminal { .. })
        ));
    }

    #[test]
    fn prepared_crash_is_not_ambiguous() {
        // Nothing was sent before dispatch, so a prepared sub-attempt is not made
        // ambiguous by recovery — it can only be cancelled or dispatched.
        assert!(matches!(
            next(S::Prepared, E::RecoverAfterCrash),
            Err(TransitionError::Invalid { .. })
        ));
        assert_eq!(next(S::Prepared, E::Cancel).unwrap(), S::Cancelled);
    }

    #[test]
    fn cancel_is_clean_before_dispatch_but_ambiguous_while_dispatching() {
        assert_eq!(next(S::Prepared, E::Cancel).unwrap(), S::Cancelled);
        assert_eq!(next(S::Dispatching, E::Cancel).unwrap(), S::Ambiguous);
    }

    #[test]
    fn out_of_order_events_reject() {
        // Can't complete before dispatching.
        assert!(matches!(
            next(S::Prepared, E::Complete),
            Err(TransitionError::Invalid { .. })
        ));
        // Can't dispatch twice.
        assert!(matches!(
            next(S::Dispatching, E::Dispatch),
            Err(TransitionError::Invalid { .. })
        ));
    }

    #[test]
    fn terminal_states_are_final() {
        for s in [S::Completed, S::Failed, S::Ambiguous, S::Cancelled] {
            assert!(s.is_terminal());
            assert!(matches!(
                next(s, E::Cancel),
                Err(TransitionError::AlreadyTerminal { .. })
            ));
        }
    }

    #[test]
    fn state_string_round_trips() {
        for s in [
            S::Prepared,
            S::Dispatching,
            S::Completed,
            S::Failed,
            S::Ambiguous,
            S::Cancelled,
        ] {
            assert_eq!(SubAttemptState::from_str(s.as_str()), Some(s));
        }
        assert_eq!(SubAttemptState::from_str("bogus"), None);
    }
}
