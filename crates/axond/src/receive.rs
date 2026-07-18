//! The A2A receive dispatcher (design §10.2, §9.2): the durable path a received
//! contract-proposal Message takes to become an inert, submitted Task.
//!
//! This composes the pieces built earlier into one no-surprise flow:
//! 1. **Idempotency** (§9.2) — a peek short-circuits an exact replay to its saved
//!    Task/response and refuses a changed-covered-value conflict, before any effect.
//! 2. **Validation** (§10.2) — [`receive_proposal`](axon_contract::receive_proposal)
//!    verifies the DSSE proposal, binds requester==origin / performer==local, binds
//!    every worker-input Part to its manifest entry, and checks the trusted-time
//!    window. A rejection never creates a Task.
//! 3. **Persistence** (§9.3) — the validated inert proposal is stored as the open
//!    head (revision zero, compare-and-swap) under a receiver-assigned Task id.
//! 4. **Commit** (§9.2) — the idempotency record is written durable-before-response,
//!    carrying the submitted Task id.
//!
//! It performs no model, tool, or network effect — the proposal arrives inert
//! (`TASK_STATE_SUBMITTED`) and waits for a local decision.

use axon_contract::{expires_at_unix, receive_proposal, Identity};
use axon_crypto::keypair::PurposeVerifyingKey;
use axon_proto::v1::Part;
use axon_store::delivery::CoveredValues;
use axon_store::{Receipt, Store, StoreError};

/// What a received proposal became (design §10.2). A rejection never creates a Task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// A durable, inert Task in `TASK_STATE_SUBMITTED`, awaiting a local decision.
    Submitted { task_id: String },
    /// An exact replay of an already-received Message — its saved Task id.
    Duplicate { task_id: Option<String> },
    /// The same (peer, Message id) with a changed covered value — refused (§9.2).
    Conflict,
    /// The proposal failed validation; no Task was created (§10.2).
    Rejected { reason: String },
}

/// Dispatches a received contract-proposal Message (design §10.2). `covered` is the
/// admitted request's covered-value tuple (from ingress); `parts` are the A2A
/// Message Parts; `body` is the exact request body (sealed for the idempotency
/// record). `trusted_now_unix` MUST be the §8.5 trusted time.
///
/// The only mutations are on a *fresh* valid proposal: the durable head write and
/// the idempotency commit. A duplicate, conflict, or rejection makes no head write.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_proposal(
    store: &Store,
    covered: &CoveredValues,
    parts: &[Part],
    proposal_key: &PurposeVerifyingKey,
    requester_origin: &Identity,
    local_performer: &Identity,
    body: &[u8],
    trusted_now_unix: i64,
) -> Result<DispatchOutcome, StoreError> {
    // 1. Idempotency: replay or refuse before any effect (§9.2).
    match store.peek(covered)? {
        Receipt::Duplicate { task_id, .. } => return Ok(DispatchOutcome::Duplicate { task_id }),
        Receipt::Conflict => return Ok(DispatchOutcome::Conflict),
        Receipt::Fresh => {}
    }

    // 2. Validate the proposal end to end — no I/O, no effect (§10.2).
    let received = match receive_proposal(
        &covered.message_id,
        parts,
        proposal_key,
        requester_origin,
        local_performer,
        trusted_now_unix,
    ) {
        Ok(r) => r,
        Err(e) => return reject(store, covered, body, trusted_now_unix, e.to_string()),
    };

    // 3. Assign the receiver's Task id and durably persist the inert proposal as the
    //    open head (revision zero, CAS).
    let task_id = format!("task-{}", &received.proposal.digest[..32]);
    let expires = match expires_at_unix(&received.proposal.contract) {
        Ok(t) => t,
        Err(e) => return reject(store, covered, body, trusted_now_unix, e.to_string()),
    };
    store.submit_revision(&task_id, &received.proposal, expires, trusted_now_unix)?;

    // 4. Commit the idempotency record with the submitted Task id (durable-before-
    //    response, §9.2).
    let response = submitted_json(&task_id);
    store.receive_request(
        covered,
        body,
        &response,
        Some(&task_id),
        "task",
        trusted_now_unix,
    )?;
    Ok(DispatchOutcome::Submitted { task_id })
}

/// Records a rejection for idempotency consistency (a replay of the same bad
/// proposal gets the same answer) and returns it. No Task is created (§10.2).
fn reject(
    store: &Store,
    covered: &CoveredValues,
    body: &[u8],
    now: i64,
    reason: String,
) -> Result<DispatchOutcome, StoreError> {
    let response = reject_json(&reason);
    store.receive_request(covered, body, &response, None, "rejected", now)?;
    Ok(DispatchOutcome::Rejected { reason })
}

fn submitted_json(task_id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"task_id": task_id, "state": "submitted"}))
        .unwrap_or_default()
}

fn reject_json(reason: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"state": "rejected", "reason": reason}))
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use axon_crypto::keypair::PurposeKey;
    use axon_crypto::purpose::KeyPurpose;
    use axon_ext::dsse::Envelope;
    use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use axon_proto::v1::part::Content;
    use axon_store::{ExternalCheckpoint, Store};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000; // within [2026, 2030)

    fn store() -> Store {
        let kek = axon_store::envelope::Kek::from_bytes([5u8; 32]);
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        Store::open_in_memory(&kek, cp).unwrap()
    }

    fn proposal_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    fn contract_payload() -> Vec<u8> {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
        let value = json!({
            "schema_version": 1,
            "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0,
            "task_type": "https://axon.invalid/t",
            "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"},
            "objective": "o",
            "inputs": [{
                "id": "src", "message_id": "msg-1", "part_index": 1,
                "kind": "text", "media_type": "text/plain", "charset": "utf-8",
                "canonical_rule": "utf8-exact", "byte_length": TEXT.len(),
                "sha256": sha, "worker_visible": true, "processor_visible": false
            }],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [],
            "requested_capabilities": [],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z"
        });
        axon_ext::jcs::canonical_bytes(&value).unwrap()
    }

    fn envelope_part(env: &Envelope) -> Part {
        Part {
            metadata: None,
            filename: String::new(),
            media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
            content: Some(Content::Data(
                serde_json::from_value(serde_json::to_value(env).unwrap()).unwrap(),
            )),
        }
    }

    fn message() -> Vec<Part> {
        let env = axon_contract::sign_proposal(&contract_payload(), &proposal_key()).unwrap();
        vec![
            envelope_part(&env),
            Part {
                metadata: None,
                filename: String::new(),
                media_type: "text/plain".to_owned(),
                content: Some(Content::Text(TEXT.to_owned())),
            },
        ]
    }

    fn covered(message_id: &str) -> CoveredValues {
        CoveredValues {
            peer: "requester".to_owned(),
            message_id: message_id.to_owned(),
            body_digest: "AA".repeat(32),
            interface_url: "https://local/a2a".to_owned(),
            tenant: None,
            a2a_version: "1.0".to_owned(),
            extensions: vec![],
            content_type: "application/a2a+json".to_owned(),
            http_method: "POST".to_owned(),
        }
    }

    fn dispatch(store: &Store, cov: &CoveredValues, parts: &[Part]) -> DispatchOutcome {
        dispatch_proposal(
            store,
            cov,
            parts,
            &proposal_key().verifying(),
            &ident("requester"),
            &ident("performer"),
            b"the-body",
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn a_valid_proposal_becomes_a_submitted_task_and_is_persisted() {
        let store = store();
        let outcome = dispatch(&store, &covered("msg-1"), &message());
        let task_id = match outcome {
            DispatchOutcome::Submitted { task_id } => task_id,
            other => panic!("expected Submitted, got {other:?}"),
        };
        // The inert proposal is durably the open head under that Task id.
        assert!(matches!(
            store.contract_head(&task_id).unwrap(),
            axon_contract::HeadState::Open(_)
        ));
    }

    #[test]
    fn an_exact_replay_is_a_duplicate_with_the_same_task_id() {
        let store = store();
        let first = dispatch(&store, &covered("msg-1"), &message());
        let task_id = match first {
            DispatchOutcome::Submitted { task_id } => task_id,
            other => panic!("expected Submitted, got {other:?}"),
        };
        // Re-dispatching the same Message id replays — no second head write.
        match dispatch(&store, &covered("msg-1"), &message()) {
            DispatchOutcome::Duplicate { task_id: Some(id) } => assert_eq!(id, task_id),
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    #[test]
    fn a_changed_covered_value_is_a_conflict() {
        let store = store();
        dispatch(&store, &covered("msg-1"), &message());
        // Same Message id, different body digest → conflict, nothing overwritten.
        let mut changed = covered("msg-1");
        changed.body_digest = "BB".repeat(32);
        assert_eq!(
            dispatch(&store, &changed, &message()),
            DispatchOutcome::Conflict
        );
    }

    #[test]
    fn an_invalid_proposal_is_rejected_with_no_task() {
        let store = store();
        // A proposal signed by the WRONG key fails verification → rejected.
        let wrong = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[9u8; 32]);
        let env = axon_contract::sign_proposal(&contract_payload(), &wrong).unwrap();
        let parts = vec![
            envelope_part(&env),
            Part {
                metadata: None,
                filename: String::new(),
                media_type: "text/plain".to_owned(),
                content: Some(Content::Text(TEXT.to_owned())),
            },
        ];
        match dispatch(&store, &covered("msg-1"), &parts) {
            DispatchOutcome::Rejected { .. } => {}
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
