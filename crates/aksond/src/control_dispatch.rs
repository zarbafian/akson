//! The store-backed control operations (design §16.4): the operator's task inbox
//! and the risk card of a submitted Task, served over the admin control socket.
//!
//! [`dispatch_control`] answers the read operations that need the store — `task
//! inbox` (the submitted proposals awaiting a decision) and `task show` (the §5.2
//! risk card the operator approves or denies). It returns a JSON result or an RFC
//! 9457 [`Problem`]; the daemon composes it with the health/worker operations
//! behind the surface-authorization gate.

use akson_contract::{parse_payload, project_risk_card, HeadState};
use akson_store::Store;

use crate::control::Problem;
use crate::socket::ControlRequest;

/// Handles a store-backed control request (design §16.4). `Diagnose` and the worker
/// operations are handled by the daemon; anything else here returns a `Problem`.
pub fn dispatch_control(
    store: &Store,
    request: &ControlRequest,
) -> Result<serde_json::Value, Problem> {
    match request {
        ControlRequest::TaskInbox => task_inbox(store),
        ControlRequest::TaskShow { task_id } => task_show(store, task_id),
        _ => Err(problem(
            400,
            "unsupported-operation",
            "this operation is not a store-backed control request",
        )),
    }
}

/// The submitted Tasks awaiting a decision (`akson task inbox`).
fn task_inbox(store: &Store) -> Result<serde_json::Value, Problem> {
    let tasks = store.list_submitted_tasks().map_err(store_problem)?;
    let items: Vec<_> = tasks
        .iter()
        .map(|t| {
            serde_json::json!({
                "task_id": t.task_id,
                "contract_id": t.contract_id,
                "revision": t.revision,
                "state": "submitted",
            })
        })
        .collect();
    Ok(serde_json::json!({ "tasks": items }))
}

/// The rendered §5.2 risk card of a submitted Task (`akson task show`).
fn task_show(store: &Store, task_id: &str) -> Result<serde_json::Value, Problem> {
    let head = match store.contract_head(task_id).map_err(store_problem)? {
        HeadState::Open(head) | HeadState::Locked(head) => head,
        HeadState::Empty => return Err(problem(404, "no-such-task", "no such task")),
    };
    let payload = store
        .get_contract(&head.digest)
        .map_err(store_problem)?
        .ok_or_else(|| problem(404, "no-such-task", "no such task"))?;
    // The stored payload was validated on submit; re-parse to project the card.
    let parsed = parse_payload(&payload).map_err(|_| {
        problem(
            500,
            "corrupt-contract",
            "the stored contract could not be parsed",
        )
    })?;
    let rendered = project_risk_card(&parsed).render();

    let sections: Vec<_> = rendered
        .sections
        .iter()
        .map(|s| serde_json::json!({ "heading": s.heading, "lines": s.lines }))
        .collect();
    Ok(serde_json::json!({
        "task_id": task_id,
        "revision": head.revision,
        "sentence": rendered.sentence,
        "sections": sections,
    }))
}

fn store_problem(_e: akson_store::StoreError) -> Problem {
    // A store error is generic to the caller — it names no internal detail.
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
    use crate::receive::dispatch_proposal;
    use akson_contract::Identity;
    use akson_crypto::keypair::PurposeKey;
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
        let kek = akson_store::envelope::Kek::from_bytes([9u8; 32]);
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
            root: "root-fixture".to_owned(),
        }
    }

    /// Submits one valid proposal into the store, returning its Task id.
    fn submit_one(store: &Store) -> String {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
        let value = json!({
            "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0, "task_type": "https://akson.invalid/task/code-review/v1",
            "message_id": "msg-1",
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
        let dispatched = dispatch_proposal(
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
        .unwrap();
        match dispatched.outcome {
            crate::receive::DispatchOutcome::Submitted { task_id } => task_id,
            other => panic!("expected Submitted, got {other:?}"),
        }
    }

    #[test]
    fn task_inbox_lists_a_submitted_task() {
        let store = store();
        // Empty inbox first.
        let empty = dispatch_control(&store, &ControlRequest::TaskInbox).unwrap();
        assert_eq!(empty["tasks"].as_array().unwrap().len(), 0);

        let task_id = submit_one(&store);
        let inbox = dispatch_control(&store, &ControlRequest::TaskInbox).unwrap();
        let tasks = inbox["tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["task_id"], task_id);
        assert_eq!(tasks[0]["state"], "submitted");
    }

    #[test]
    fn task_show_renders_the_risk_card() {
        let store = store();
        let task_id = submit_one(&store);
        let card = dispatch_control(
            &store,
            &ControlRequest::TaskShow {
                task_id: task_id.clone(),
            },
        )
        .unwrap();
        assert_eq!(card["task_id"], task_id);
        assert!(card["sentence"].as_str().unwrap().contains("code-review"));
        // Five §5.2 sections.
        assert_eq!(card["sections"].as_array().unwrap().len(), 5);
        assert_eq!(card["sections"][0]["heading"], "Who");
    }

    #[test]
    fn task_show_on_an_unknown_task_is_404() {
        let store = store();
        let problem = dispatch_control(
            &store,
            &ControlRequest::TaskShow {
                task_id: "task-nope".to_owned(),
            },
        )
        .unwrap_err();
        assert_eq!(problem.status, 404);
    }
}
