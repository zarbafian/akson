//! The work-order attempt state machine (design §12.3).
//!
//! One authorized execution of a work order moves through
//! `pending → claimed → running → succeeded | failed | ambiguous | cancelled`.
//! The claim is the durable-before-effect point: an effectful work order is
//! durably claimed before its first effect, so a crash *after* the claim resolves
//! to `ambiguous` and is never auto-retried — re-running could double an effect.
//! A crash *before* the claim (`pending`) had no effect, so it may be abandoned.
//! Terminal states are final.
//!
//! This is the pure transition function; the atomic claim (nonce consumption and
//! budget reservation) is applied durably by the store, which drives these
//! transitions.
//!
//! What you write:
//! ```
//! use akson_authority::{AttemptState, AttemptEvent, next};
//! let s = AttemptState::Pending;
//! let s = next(s, AttemptEvent::Claim).unwrap();   // durable claim
//! let s = next(s, AttemptEvent::Start).unwrap();
//! let s = next(s, AttemptEvent::Succeed).unwrap();
//! assert_eq!(s, AttemptState::Succeeded);
//! assert!(s.is_terminal());
//! ```

use serde::{Deserialize, Serialize};

/// The state of one work-order attempt (design §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    /// Issued, no effect yet — safe to abandon.
    Pending,
    /// Durably claimed (nonce consumed, budget reserved); the point of no return.
    Claimed,
    /// Executing.
    Running,
    Succeeded,
    Failed,
    /// The outcome is uncertain (a crash after claim, or an unresolved effect).
    /// Never auto-retried.
    Ambiguous,
    Cancelled,
}

impl AttemptState {
    /// Whether this is a terminal state — no further transition is allowed.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            AttemptState::Succeeded
                | AttemptState::Failed
                | AttemptState::Ambiguous
                | AttemptState::Cancelled
        )
    }

    /// The persisted string form.
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptState::Pending => "pending",
            AttemptState::Claimed => "claimed",
            AttemptState::Running => "running",
            AttemptState::Succeeded => "succeeded",
            AttemptState::Failed => "failed",
            AttemptState::Ambiguous => "ambiguous",
            AttemptState::Cancelled => "cancelled",
        }
    }

    /// Parses a persisted state string.
    #[allow(clippy::should_implement_trait)] // a fallible Option helper, not the FromStr trait.
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => AttemptState::Pending,
            "claimed" => AttemptState::Claimed,
            "running" => AttemptState::Running,
            "succeeded" => AttemptState::Succeeded,
            "failed" => AttemptState::Failed,
            "ambiguous" => AttemptState::Ambiguous,
            "cancelled" => AttemptState::Cancelled,
            _ => return None,
        })
    }
}

/// An event that drives an attempt's state (design §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptEvent {
    /// Atomically claim the work order (nonce + budget). `pending → claimed`.
    Claim,
    /// Begin execution. `claimed → running`.
    Start,
    /// Execution completed successfully. `running → succeeded`.
    Succeed,
    /// Execution failed cleanly (no uncertain effect). `running → failed`.
    Fail,
    /// The outcome is uncertain. `claimed | running → ambiguous`.
    MarkAmbiguous,
    /// Cancel a non-terminal attempt. `pending | claimed → cancelled` (provably
    /// before the first effect), but `running → ambiguous`: a running attempt may
    /// already have committed an effect, and cancellation cannot undo a committed
    /// result (§13.1), so a clean `cancelled` would be dishonest.
    Cancel,
    /// Recovery found a claimed/running attempt after a crash: it resolves to
    /// `ambiguous` and is never re-run. `claimed | running → ambiguous`.
    RecoverAfterCrash,
}

/// Why a transition was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("{state:?} is terminal; no further transition")]
    AlreadyTerminal { state: AttemptState },
    #[error("{event:?} is not valid from {state:?}")]
    Invalid {
        state: AttemptState,
        event: AttemptEvent,
    },
}

/// Applies an event to an attempt state (design §12.3). Pure and total: a
/// terminal state or an out-of-order event fails closed, so the store can drive
/// transitions without re-deriving the rules.
pub fn next(state: AttemptState, event: AttemptEvent) -> Result<AttemptState, TransitionError> {
    use AttemptEvent as E;
    use AttemptState as S;

    if state.is_terminal() {
        return Err(TransitionError::AlreadyTerminal { state });
    }
    let invalid = || TransitionError::Invalid { state, event };
    Ok(match (state, event) {
        (S::Pending, E::Claim) => S::Claimed,
        (S::Claimed, E::Start) => S::Running,
        (S::Running, E::Succeed) => S::Succeeded,
        (S::Running, E::Fail) => S::Failed,
        (S::Claimed | S::Running, E::MarkAmbiguous) => S::Ambiguous,
        // A crash after the durable claim is uncertain, never auto-retried.
        (S::Claimed | S::Running, E::RecoverAfterCrash) => S::Ambiguous,
        // Cancel is clean only before the first effect (pending/claimed). A running
        // attempt may already have committed an effect that cancellation cannot undo
        // (§13.1), so — like a post-claim crash — it resolves to ambiguous.
        (S::Pending | S::Claimed, E::Cancel) => S::Cancelled,
        (S::Running, E::Cancel) => S::Ambiguous,
        _ => return Err(invalid()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use AttemptEvent as E;
    use AttemptState as S;

    #[test]
    fn happy_path_runs_to_succeeded() {
        let s = next(S::Pending, E::Claim).unwrap();
        assert_eq!(s, S::Claimed);
        let s = next(s, E::Start).unwrap();
        assert_eq!(s, S::Running);
        let s = next(s, E::Succeed).unwrap();
        assert_eq!(s, S::Succeeded);
        assert!(s.is_terminal());
    }

    #[test]
    fn crash_after_claim_resolves_ambiguous_never_retries() {
        // Claimed but crashed → ambiguous, terminal, no path back to running.
        let s = next(S::Claimed, E::RecoverAfterCrash).unwrap();
        assert_eq!(s, S::Ambiguous);
        assert!(s.is_terminal());
        assert!(matches!(
            next(s, E::Start),
            Err(TransitionError::AlreadyTerminal { .. })
        ));
        // Running but crashed → ambiguous too.
        assert_eq!(
            next(S::Running, E::RecoverAfterCrash).unwrap(),
            S::Ambiguous
        );
    }

    #[test]
    fn pending_crash_is_not_ambiguous() {
        // No effect happened before the claim, so a pending attempt is not made
        // ambiguous by recovery — it can only be cancelled or claimed.
        assert!(matches!(
            next(S::Pending, E::RecoverAfterCrash),
            Err(TransitionError::Invalid { .. })
        ));
        assert_eq!(next(S::Pending, E::Cancel).unwrap(), S::Cancelled);
    }

    #[test]
    fn cancel_is_clean_before_effect_but_ambiguous_while_running() {
        // Pending/claimed are provably before the first effect → clean cancel.
        for s in [S::Pending, S::Claimed] {
            assert_eq!(next(s, E::Cancel).unwrap(), S::Cancelled);
        }
        // Running may already have committed an effect cancellation can't undo, so
        // it resolves to ambiguous (never auto-retried), like a post-claim crash.
        assert_eq!(next(S::Running, E::Cancel).unwrap(), S::Ambiguous);
    }

    #[test]
    fn out_of_order_events_reject() {
        // Can't start before claiming, can't succeed before running.
        assert!(matches!(
            next(S::Pending, E::Start),
            Err(TransitionError::Invalid { .. })
        ));
        assert!(matches!(
            next(S::Claimed, E::Succeed),
            Err(TransitionError::Invalid { .. })
        ));
    }

    #[test]
    fn terminal_states_are_final() {
        for s in [S::Succeeded, S::Failed, S::Ambiguous, S::Cancelled] {
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
            S::Pending,
            S::Claimed,
            S::Running,
            S::Succeeded,
            S::Failed,
            S::Ambiguous,
            S::Cancelled,
        ] {
            assert_eq!(AttemptState::from_str(s.as_str()), Some(s));
        }
        assert_eq!(AttemptState::from_str("bogus"), None);
    }
}
