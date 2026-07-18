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
//! 4. **Commit** (§9.2) — the A2A Task response is written durable-before-response,
//!    so an exact replay returns the identical bytes.
//!
//! It performs no model, tool, or network effect — the proposal arrives inert
//! (`TASK_STATE_SUBMITTED`) and waits for a local decision. The returned bytes are
//! the A2A response the peer receives.

use axon_contract::{expires_at_unix, receive_proposal, Identity, PartBody, ReceivedProposal};
use axon_crypto::keypair::PurposeVerifyingKey;
use axon_proto::v1::{Part, Task, TaskState, TaskStatus};
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

/// A dispatch result: the outcome and the exact A2A response bytes the peer
/// receives (identical on a fresh submit and its later replay).
#[derive(Debug, Clone)]
pub struct Dispatched {
    pub outcome: DispatchOutcome,
    pub response: Vec<u8>,
}

/// Dispatches a received contract-proposal Message (design §10.2). `covered` is the
/// admitted request's covered-value tuple (from ingress); `parts` are the A2A
/// Message Parts; `context_id` is the Message's A2A Context; `body` is the exact
/// request body (sealed for the idempotency record). `trusted_now_unix` MUST be the
/// §8.5 trusted time.
///
/// The only mutations are on a *fresh* valid proposal: the durable head write and
/// the idempotency commit. A duplicate, conflict, or rejection makes no head write.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_proposal(
    store: &Store,
    covered: &CoveredValues,
    parts: &[Part],
    context_id: &str,
    proposal_key: &PurposeVerifyingKey,
    requester_origin: &Identity,
    local_performer: &Identity,
    body: &[u8],
    trusted_now_unix: i64,
) -> Result<Dispatched, StoreError> {
    // 1. Idempotency: replay or refuse before any effect (§9.2).
    match store.peek(covered)? {
        Receipt::Duplicate { task_id, response } => {
            return Ok(Dispatched {
                outcome: DispatchOutcome::Duplicate { task_id },
                response,
            })
        }
        Receipt::Conflict => {
            return Ok(Dispatched {
                outcome: DispatchOutcome::Conflict,
                response: conflict_json(),
            })
        }
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
    // Record the A2A Context id on the head so the accepting decision can reference
    // it (it is Message-level, not a contract field).
    store.set_task_context(&task_id, context_id)?;
    // Persist the worker-visible input bytes (the contract holds only digests) so
    // the worker can be staged with them when the task later runs (§7.2). Done
    // before the idempotency commit, so a crash here re-runs on replay.
    persist_worker_inputs(store, &task_id, &received, trusted_now_unix)?;

    // 4. Commit the A2A Task response (durable-before-response, §9.2), so an exact
    //    replay returns these identical bytes.
    let response = submitted_task_json(&task_id, context_id);
    store.receive_request(
        covered,
        body,
        &response,
        Some(&task_id),
        "task",
        trusted_now_unix,
    )?;
    Ok(Dispatched {
        outcome: DispatchOutcome::Submitted { task_id },
        response,
    })
}

/// Persists the worker-visible input payloads of a fresh proposal (design §7.2):
/// the contract carries only each input's digest, so the actual bytes are kept
/// (sealed) to stage into the sandbox when the task runs. Each payload is exactly
/// what its manifest digest covers — already verified by `bind_inputs`, so the
/// stored bytes re-hash to `entry.sha256`.
fn persist_worker_inputs(
    store: &Store,
    task_id: &str,
    received: &ReceivedProposal,
    now: i64,
) -> Result<(), StoreError> {
    for (ordinal, entry) in received.proposal.contract.inputs.iter().enumerate() {
        if !entry.worker_visible {
            continue;
        }
        // bind_inputs guarantees exactly one Part per entry; skip defensively if
        // absent rather than panic.
        let Some(part) = received
            .inputs
            .iter()
            .find(|p| p.message_id == entry.message_id && p.part_index == entry.part_index)
        else {
            continue;
        };
        let bytes = match &part.body {
            PartBody::Text(s) => s.clone().into_bytes(),
            PartBody::Data(v) => match axon_ext::jcs::canonical_bytes(v) {
                Ok(b) => b,
                Err(_) => continue,
            },
        };
        store.put_task_input(
            task_id,
            &entry.id,
            ordinal as i64,
            &entry.media_type,
            entry.byte_length as i64,
            &entry.sha256,
            &bytes,
            now,
        )?;
    }
    Ok(())
}

/// Records a rejection for idempotency consistency (a replay of the same bad
/// proposal gets the same answer) and returns it. No Task is created (§10.2).
fn reject(
    store: &Store,
    covered: &CoveredValues,
    body: &[u8],
    now: i64,
    reason: String,
) -> Result<Dispatched, StoreError> {
    let response = reject_json(&reason);
    store.receive_request(covered, body, &response, None, "rejected", now)?;
    Ok(Dispatched {
        outcome: DispatchOutcome::Rejected { reason },
        response,
    })
}

/// The A2A Task the peer receives for a submitted proposal: inert, in
/// `TASK_STATE_SUBMITTED`, with no history or artifacts yet.
fn submitted_task_json(task_id: &str, context_id: &str) -> Vec<u8> {
    let task = Task {
        id: task_id.to_owned(),
        context_id: context_id.to_owned(),
        status: Some(TaskStatus {
            state: TaskState::Submitted as i32,
            message: None,
            timestamp: None,
        }),
        artifacts: Vec::new(),
        history: Vec::new(),
        metadata: None,
    };
    serde_json::to_vec(&task).unwrap_or_default()
}

fn reject_json(reason: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"state": "rejected", "reason": reason}))
        .unwrap_or_default()
}

fn conflict_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"state": "conflict"})).unwrap_or_default()
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

    fn text_part() -> Part {
        Part {
            metadata: None,
            filename: String::new(),
            media_type: "text/plain".to_owned(),
            content: Some(Content::Text(TEXT.to_owned())),
        }
    }

    fn message(key: &PurposeKey) -> Vec<Part> {
        let env = axon_contract::sign_proposal(&contract_payload(), key).unwrap();
        vec![envelope_part(&env), text_part()]
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

    fn dispatch(store: &Store, cov: &CoveredValues, parts: &[Part]) -> Dispatched {
        dispatch_proposal(
            store,
            cov,
            parts,
            "ctx-1",
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
        let result = dispatch(&store, &covered("msg-1"), &message(&proposal_key()));
        let task_id = match result.outcome {
            DispatchOutcome::Submitted { task_id } => task_id,
            other => panic!("expected Submitted, got {other:?}"),
        };
        // The inert proposal is durably the open head under that Task id.
        assert!(matches!(
            store.contract_head(&task_id).unwrap(),
            axon_contract::HeadState::Open(_)
        ));
        // The response is an A2A Task in TASK_STATE_SUBMITTED.
        let task: serde_json::Value = serde_json::from_slice(&result.response).unwrap();
        assert_eq!(task["id"], task_id);
        assert_eq!(task["status"]["state"], "TASK_STATE_SUBMITTED");
        // The worker-visible input bytes are persisted for later staging (§7.2):
        // the contract holds only the digest, but the actual Part bytes are kept.
        let inputs = store.list_task_inputs(&task_id).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].input_id, "src");
        assert_eq!(inputs[0].payload, TEXT.as_bytes());
        assert_eq!(inputs[0].sha256, hex::encode(Sha256::digest(TEXT.as_bytes())));
    }

    #[test]
    fn an_exact_replay_returns_the_identical_response() {
        let store = store();
        let first = dispatch(&store, &covered("msg-1"), &message(&proposal_key()));
        let task_id = match &first.outcome {
            DispatchOutcome::Submitted { task_id } => task_id.clone(),
            other => panic!("expected Submitted, got {other:?}"),
        };
        // Re-dispatching the same Message id replays — same task id, identical bytes.
        let replay = dispatch(&store, &covered("msg-1"), &message(&proposal_key()));
        match replay.outcome {
            DispatchOutcome::Duplicate { task_id: Some(id) } => assert_eq!(id, task_id),
            other => panic!("expected Duplicate, got {other:?}"),
        }
        assert_eq!(replay.response, first.response);
    }

    #[test]
    fn a_changed_covered_value_is_a_conflict() {
        let store = store();
        dispatch(&store, &covered("msg-1"), &message(&proposal_key()));
        let mut changed = covered("msg-1");
        changed.body_digest = "BB".repeat(32);
        assert_eq!(
            dispatch(&store, &changed, &message(&proposal_key())).outcome,
            DispatchOutcome::Conflict
        );
    }

    #[test]
    fn an_invalid_proposal_is_rejected_with_no_task() {
        let store = store();
        // Signed by the WRONG key → verification fails → rejected, no Task.
        let wrong = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[9u8; 32]);
        match dispatch(&store, &covered("msg-1"), &message(&wrong)).outcome {
            DispatchOutcome::Rejected { .. } => {}
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
