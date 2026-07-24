//! Recording the operator's decision on a submitted Task (design §10.2, §10.1).
//!
//! After reviewing the [risk card](crate::dispatch_control), the operator accepts,
//! rejects, or requests a revision. [`decide`] loads the task's stored proposal,
//! builds and signs the performer decision (bound to the exact revision digest),
//! and — on **accept** — locks the head (compare-and-swap), moving the Task from
//! "submitted" to "accepted, awaiting a work-order claim". No work runs yet; the
//! signed decision is the operator's authorization for the executor handoff.
//!
//! The performer decision key is passed in (the daemon resolves it from the local
//! keystore), so this composition is pure and testable.

use akson_contract::{parse_payload, sign_decision, Decision, DecisionKind, HeadState, Identity};
use akson_crypto::keypair::PurposeKey;
use akson_ext::dsse::Envelope;
use akson_store::Store;

use crate::control::Problem;

/// The outcome of a recorded decision.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    pub task_id: String,
    pub kind: DecisionKind,
    /// The signed performer decision, ready to deliver on the Task's status Message.
    pub decision: Envelope,
    /// Whether the head was locked (an accept).
    pub accepted: bool,
}

/// Records a decision on a submitted Task (design §10.2). `decided_at` is RFC 3339;
/// `now` is the trusted time for the durable lock. Fails closed: only an open head
/// can be decided, and an accept that loses the compare-and-swap is a conflict.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    store: &Store,
    task_id: &str,
    kind: DecisionKind,
    reason_code: Option<&str>,
    note: Option<&str>,
    decider: &Identity,
    decision_key: &PurposeKey,
    decided_at: &str,
    now: i64,
) -> Result<DecisionRecord, Problem> {
    let head = match store.contract_head(task_id).map_err(store_problem)? {
        HeadState::Open(head) => head,
        HeadState::Locked(_) => {
            return Err(problem(
                409,
                "already-decided",
                "this task is already accepted",
            ))
        }
        HeadState::Empty => return Err(problem(404, "no-such-task", "no such task")),
    };
    let payload = store
        .get_contract(&head.digest)
        .map_err(store_problem)?
        .ok_or_else(|| problem(404, "no-such-task", "no such task"))?;
    let parsed = parse_payload(&payload).map_err(|_| {
        problem(
            500,
            "corrupt-contract",
            "the stored contract could not be parsed",
        )
    })?;
    let context_id = store
        .task_context(task_id)
        .map_err(store_problem)?
        .unwrap_or_default();

    let decision = Decision {
        schema_version: 1,
        decision: kind,
        contract_id: parsed.contract.contract_id.clone(),
        contract_revision: head.revision,
        contract_digest: head.digest.clone(),
        task_id: task_id.to_owned(),
        context_id,
        decider: decider.clone(),
        reason_code: reason_code.map(str::to_owned),
        note: note.map(str::to_owned),
        decided_at: decided_at.to_owned(),
    };
    let signed = sign_decision(&decision, decision_key)
        .map_err(|_| problem(500, "sign-failed", "the decision could not be signed"))?;

    // An accept locks the exact head via compare-and-swap; a reject / revision
    // request signs the decision without moving the head.
    let accepted = if kind == DecisionKind::Accept {
        match store
            .accept_contract(task_id, &head.digest, now)
            .map_err(store_problem)?
        {
            Ok(()) => true,
            Err(_) => {
                return Err(problem(
                    409,
                    "accept-conflict",
                    "the task could not be accepted",
                ))
            }
        }
    } else {
        false
    };

    Ok(DecisionRecord {
        task_id: task_id.to_owned(),
        kind,
        decision: signed,
        accepted,
    })
}

fn store_problem(_e: akson_store::StoreError) -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:akson:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::receive::{dispatch_proposal, DispatchOutcome};
    use akson_contract::verify_decision;
    use akson_crypto::purpose::KeyPurpose;
    use akson_ext::dsse::Envelope;
    use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use akson_proto::v1::{part::Content, Part};
    use akson_store::delivery::CoveredValues;
    use akson_store::{ExternalCheckpoint, Store};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;

    fn store() -> Store {
        let kek = akson_store::envelope::Kek::from_bytes([11u8; 32]);
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

    fn decision_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractDecision, &[6u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
            root: "root-fixture".to_owned(),
        }
    }

    fn submit_one(store: &Store) -> String {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
        let value = json!({
            "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0, "task_type": "https://akson.invalid/t", "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester", "root": "root-fixture"},
            "performer": {"issuer": "iss", "agent": "performer", "root": "root-fixture"}, "objective": "o",
            "inputs": [{
                "id": "diff", "message_id": "msg-1", "part_index": 1, "kind": "text",
                "media_type": "text/x-diff", "charset": "utf-8", "canonical_rule": "utf8-exact",
                "byte_length": TEXT.len(), "sha256": sha,
                "worker_visible": true, "processor_visible": false
            }],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [], "requested_capabilities": ["respond"],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 8192},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"
        });
        let payload = akson_ext::jcs::canonical_bytes(&value).unwrap();
        let env: Envelope = akson_contract::sign_proposal(&payload, &proposal_key()).unwrap();
        let parts = vec![
            Part {
                metadata: None,
                filename: String::new(),
                media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
                content: Some(Content::Data(
                    serde_json::from_value(serde_json::to_value(&env).unwrap()).unwrap(),
                )),
            },
            Part {
                metadata: None,
                filename: String::new(),
                media_type: "text/x-diff".to_owned(),
                content: Some(Content::Text(TEXT.to_owned())),
            },
        ];
        let covered = CoveredValues {
            peer: "requester".to_owned(),
            message_id: "msg-1".to_owned(),
            body_digest: "AA".repeat(32),
            interface_url: "https://local/a2a".to_owned(),
            tenant: None,
            a2a_version: "1.0".to_owned(),
            extensions: vec![],
            content_type: "application/a2a+json".to_owned(),
            http_method: "POST".to_owned(),
        };
        match dispatch_proposal(
            store,
            &covered,
            &parts,
            "ctx-1",
            &proposal_key().verifying(),
            &ident("requester"),
            &ident("performer"),
            b"body",
            NOW,
        )
        .unwrap()
        .outcome
        {
            DispatchOutcome::Submitted { task_id } => task_id,
            other => panic!("expected Submitted, got {other:?}"),
        }
    }

    #[test]
    fn accept_locks_the_head_and_signs_a_verifiable_decision() {
        let store = store();
        let task_id = submit_one(&store);
        let record = decide(
            &store,
            &task_id,
            DecisionKind::Accept,
            None,
            None,
            &ident("performer"),
            &decision_key(),
            "2026-07-18T00:00:00Z",
            NOW,
        )
        .unwrap();
        assert!(record.accepted);
        // The head is now locked → it leaves the submitted inbox.
        assert!(matches!(
            store.contract_head(&task_id).unwrap(),
            HeadState::Locked(_)
        ));
        assert_eq!(store.list_submitted_tasks().unwrap().len(), 0);
        // The signed decision verifies under the decision purpose and binds the task.
        let verified = verify_decision(&record.decision, &decision_key().verifying()).unwrap();
        assert_eq!(verified.task_id, task_id);
        assert_eq!(verified.decision, DecisionKind::Accept);
    }

    #[test]
    fn a_second_accept_is_a_conflict() {
        let store = store();
        let task_id = submit_one(&store);
        decide(
            &store,
            &task_id,
            DecisionKind::Accept,
            None,
            None,
            &ident("performer"),
            &decision_key(),
            "2026-07-18T00:00:00Z",
            NOW,
        )
        .unwrap();
        let again = decide(
            &store,
            &task_id,
            DecisionKind::Accept,
            None,
            None,
            &ident("performer"),
            &decision_key(),
            "2026-07-18T00:00:00Z",
            NOW,
        )
        .unwrap_err();
        assert_eq!(again.status, 409);
    }

    #[test]
    fn reject_signs_without_locking_the_head() {
        let store = store();
        let task_id = submit_one(&store);
        let record = decide(
            &store,
            &task_id,
            DecisionKind::Reject,
            Some("insufficient-evidence"),
            None,
            &ident("performer"),
            &decision_key(),
            "2026-07-18T00:00:00Z",
            NOW,
        )
        .unwrap();
        assert!(!record.accepted);
        // The head stays open (reject-side head handling is a follow-up).
        assert!(matches!(
            store.contract_head(&task_id).unwrap(),
            HeadState::Open(_)
        ));
    }

    #[test]
    fn deciding_an_unknown_task_is_404() {
        let store = store();
        let err = decide(
            &store,
            "task-nope",
            DecisionKind::Accept,
            None,
            None,
            &ident("performer"),
            &decision_key(),
            "2026-07-18T00:00:00Z",
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 404);
    }
}
