//! Model <-> code conformance: the TLA+ specs in `proof/specs` and the Rust
//! state machines in `crates/` must describe the same transition relations.
//!
//! Each test transcribes a TLA+ spec's transition relation and asserts the
//! implemented pure function agrees on EVERY (state, event) pair — so a
//! change to either side that forgets the other fails CI, and "the model
//! matches the code" is a checked fact rather than a review claim.
//!
//! That guarantee is why this crate is a workspace member: `cargo test
//! --workspace` runs it, so no Rust change can land while the model disagrees.
//! It was not true while the models lived in their own repository.
//!
//! What you write (the whole idea in one line):
//! ```
//! use akson_authority::{next, AttemptEvent, AttemptState};
//! assert_eq!(next(AttemptState::Pending, AttemptEvent::Claim),
//!            Ok(AttemptState::Claimed)); // TaskLifecycle.tla: Claim(m)
//! ```

#[cfg(test)]
mod attempt_conformance {
    //! specs/TaskLifecycle.tla <-> akson-authority/src/attempt.rs

    use akson_authority::{next, AttemptEvent, AttemptState, TransitionError};

    const STATES: [AttemptState; 7] = [
        AttemptState::Pending,
        AttemptState::Claimed,
        AttemptState::Running,
        AttemptState::Succeeded,
        AttemptState::Failed,
        AttemptState::Ambiguous,
        AttemptState::Cancelled,
    ];
    const EVENTS: [AttemptEvent; 7] = [
        AttemptEvent::Claim,
        AttemptEvent::Start,
        AttemptEvent::Succeed,
        AttemptEvent::Fail,
        AttemptEvent::MarkAmbiguous,
        AttemptEvent::Cancel,
        AttemptEvent::RecoverAfterCrash,
    ];

    /// The TaskLifecycle.tla transition relation, one arm per TLA action.
    /// `None` = the spec has no such transition (the pure fn must refuse).
    fn spec(s: AttemptState, e: AttemptEvent) -> Option<AttemptState> {
        use AttemptEvent as E;
        use AttemptState as S;
        match (s, e) {
            (S::Pending, E::Claim) => Some(S::Claimed), // Claim(m)
            (S::Claimed, E::Start) => Some(S::Running), // MarkRunning(m)
            (S::Running, E::Succeed) => Some(S::Succeeded), // WorkerSucceeds(m)
            (S::Running, E::Fail) => Some(S::Failed),   // WorkerFails(m)
            // MarkAmbiguous(m): claimed | running -> ambiguous
            (S::Claimed | S::Running, E::MarkAmbiguous) => Some(S::Ambiguous),
            // Recover: claimed | running -> ambiguous; pending is untouched
            // (TaskLifecycle.tla Recover's ELSE branch), so the pure fn must
            // refuse Pending+RecoverAfterCrash rather than transition it.
            (S::Claimed | S::Running, E::RecoverAfterCrash) => Some(S::Ambiguous),
            // CancelEarly(m): provably before any effect
            (S::Pending | S::Claimed, E::Cancel) => Some(S::Cancelled),
            // CancelRunning(m): an effect may already be out
            (S::Running, E::Cancel) => Some(S::Ambiguous),
            _ => None,
        }
    }

    fn is_terminal(s: AttemptState) -> bool {
        matches!(
            s,
            AttemptState::Succeeded
                | AttemptState::Failed
                | AttemptState::Ambiguous
                | AttemptState::Cancelled
        )
    }

    #[test]
    fn every_pair_agrees_with_the_model() {
        for s in STATES {
            for e in EVENTS {
                let got = next(s, e);
                match spec(s, e) {
                    Some(want) => assert_eq!(
                        got,
                        Ok(want),
                        "attempt.rs::next({s:?}, {e:?}) disagrees with TaskLifecycle.tla"
                    ),
                    None if is_terminal(s) => assert!(
                        matches!(got, Err(TransitionError::AlreadyTerminal { .. })),
                        "terminal {s:?} must refuse {e:?} as AlreadyTerminal, got {got:?}"
                    ),
                    None => assert!(
                        matches!(got, Err(TransitionError::Invalid { .. })),
                        "{s:?} must refuse {e:?} as Invalid, got {got:?}"
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod subattempt_conformance {
    //! specs/BrokerBudget.tla <-> akson-broker/src/subattempt.rs

    use akson_broker::{next, SubAttemptEvent, SubAttemptState, TransitionError};

    const STATES: [SubAttemptState; 6] = [
        SubAttemptState::Prepared,
        SubAttemptState::Dispatching,
        SubAttemptState::Completed,
        SubAttemptState::Failed,
        SubAttemptState::Ambiguous,
        SubAttemptState::Cancelled,
    ];
    const EVENTS: [SubAttemptEvent; 6] = [
        SubAttemptEvent::Dispatch,
        SubAttemptEvent::Complete,
        SubAttemptEvent::Fail,
        SubAttemptEvent::MarkAmbiguous,
        SubAttemptEvent::Cancel,
        SubAttemptEvent::RecoverAfterCrash,
    ];

    /// The BrokerBudget.tla transition relation, one arm per TLA action.
    fn spec(s: SubAttemptState, e: SubAttemptEvent) -> Option<SubAttemptState> {
        use SubAttemptEvent as E;
        use SubAttemptState as S;
        match (s, e) {
            (S::Prepared, E::Dispatch) => Some(S::Dispatching), // MarkDispatching(c)
            (S::Dispatching, E::Complete) => Some(S::Completed), // Complete(c)
            (S::Dispatching, E::Fail) => Some(S::Failed),       // Fail(c)
            (S::Dispatching, E::MarkAmbiguous) => Some(S::Ambiguous),
            (S::Prepared, E::Cancel) => Some(S::Cancelled), // CancelPrepared(c)
            (S::Dispatching, E::Cancel) => Some(S::Ambiguous), // CancelDispatching(c)
            // Recover: dispatching -> ambiguous; prepared survives a crash
            // (BrokerBudget.tla Recover's ELSE branch).
            (S::Dispatching, E::RecoverAfterCrash) => Some(S::Ambiguous),
            _ => None,
        }
    }

    fn is_terminal(s: SubAttemptState) -> bool {
        matches!(
            s,
            SubAttemptState::Completed
                | SubAttemptState::Failed
                | SubAttemptState::Ambiguous
                | SubAttemptState::Cancelled
        )
    }

    #[test]
    fn every_pair_agrees_with_the_model() {
        for s in STATES {
            for e in EVENTS {
                let got = next(s, e);
                match spec(s, e) {
                    Some(want) => assert_eq!(
                        got,
                        Ok(want),
                        "subattempt.rs::next({s:?}, {e:?}) disagrees with BrokerBudget.tla"
                    ),
                    None if is_terminal(s) => assert!(
                        matches!(got, Err(TransitionError::AlreadyTerminal { .. })),
                        "terminal {s:?} must refuse {e:?} as AlreadyTerminal, got {got:?}"
                    ),
                    None => assert!(
                        matches!(got, Err(TransitionError::Invalid { .. })),
                        "{s:?} must refuse {e:?} as Invalid, got {got:?}"
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod chain_conformance {
    //! specs/ContractChain.tla <-> akson-contract/src/chain.rs
    //!
    //! ContractChain.tla's CanAdvance/Accept guards, exercised against the
    //! real parsed-contract types.  Contracts are built the way chain.rs's
    //! own doctest builds them; a digest here is a function of the whole
    //! body, so changing `objective` yields a competing sibling.

    use akson_contract::{
        accept_head, apply_revision, HeadState, LockError, ParsedContract, RevisionVerdict,
        StaleReason,
    };
    use serde_json::{json, Value};

    fn contract(rev: u64, predecessor: Option<&str>, objective: &str) -> ParsedContract {
        let mut v = json!({
            "schema_version": 1, "contract_id": "00000000-0000-4000-8000-000000000000",
            "revision": rev, "task_type": "https://akson.invalid/t", "message_id": "m1",
            "requester": {"issuer": "a", "agent": "b", "root": "root-fixture"}, "performer": {"issuer": "c", "agent": "d", "root": "root-fixture"},
            "objective": objective, "inputs": [], "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [], "requested_capabilities": [], "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
            "result_recipient": "request-origin", "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z"
        });
        if let Some(p) = predecessor {
            v["predecessor_digest"] = Value::from(p);
            v["task_id"] = Value::from("t1");
        }
        akson_contract::parse_payload(&akson_ext::jcs::canonical_bytes(&v).unwrap()).unwrap()
    }

    fn advance(head: &HeadState, c: &ParsedContract) -> HeadState {
        match apply_revision(head, c) {
            RevisionVerdict::Advance(h) => HeadState::Open(h),
            RevisionVerdict::Stale(r) => panic!("expected Advance, got Stale({r:?})"),
        }
    }

    fn stale_reason(head: &HeadState, c: &ParsedContract) -> StaleReason {
        match apply_revision(head, c) {
            RevisionVerdict::Stale(r) => r,
            RevisionVerdict::Advance(_) => panic!("expected Stale, got Advance"),
        }
    }

    #[test]
    fn advance_guard_matches_can_advance() {
        let rev0 = contract(0, None, "o");

        // CanAdvance: empty /\ r = 0 /\ no predecessor  => Advance
        let open0 = advance(&HeadState::Empty, &rev0);

        // CanAdvance: open /\ r = head.rev + 1 /\ p = head.dig  => Advance
        let rev1 = contract(1, Some(&rev0.digest), "o");
        let open1 = advance(&open0, &rev1);

        // Everything else is Stale — ContractChain.tla has no such action:
        // a follow-up with no head to chain from,
        assert_eq!(stale_reason(&HeadState::Empty, &rev1), StaleReason::NoHead);
        // a second revision 0 (competing sibling) once a head exists,
        let sibling0 = contract(0, None, "o-sibling");
        assert_eq!(
            stale_reason(&open0, &sibling0),
            StaleReason::HeadAlreadyExists
        );
        // a skipped revision number,
        let rev2_skip = contract(2, Some(&rev0.digest), "o");
        assert_eq!(stale_reason(&open0, &rev2_skip), StaleReason::NonSequential);
        // a forged predecessor digest,
        let zeros = "0".repeat(64);
        let forged = contract(2, Some(&zeros), "o");
        assert_eq!(
            stale_reason(&open1, &forged),
            StaleReason::PredecessorMismatch
        );
        // and ANY revision against a locked head (LockIsFinal in the model).
        let locked = match &open1 {
            HeadState::Open(h) => HeadState::Locked(h.clone()),
            _ => unreachable!(),
        };
        let rev2 = contract(2, Some(&rev1.digest), "o");
        assert_eq!(stale_reason(&locked, &rev2), StaleReason::HeadLocked);
    }

    #[test]
    fn accept_guard_matches_accept() {
        let rev0 = contract(0, None, "o");
        let open0 = advance(&HeadState::Empty, &rev0);

        // Accept(d): open /\ head.dig = d  => lock
        assert!(accept_head(&open0, &rev0.digest).is_ok());

        // A stale acceptance (sibling digest) must not lock — the model's
        // LockedWasAdvanced / AtMostOneLock guards.
        let sibling = contract(0, None, "o-sibling");
        assert_eq!(
            accept_head(&open0, &sibling.digest).unwrap_err(),
            LockError::DigestMismatch
        );
        // No open head, nothing to accept.
        assert_eq!(
            accept_head(&HeadState::Empty, &rev0.digest).unwrap_err(),
            LockError::NoOpenHead
        );
        // Locked is final: a second acceptance is refused.
        let locked = match &open0 {
            HeadState::Open(h) => HeadState::Locked(h.clone()),
            _ => unreachable!(),
        };
        assert_eq!(
            accept_head(&locked, &rev0.digest).unwrap_err(),
            LockError::AlreadyLocked
        );
    }
}
