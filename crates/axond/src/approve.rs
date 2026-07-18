//! Approving or denying a submitted Task (design §10.2, §12.3): the operator's
//! decision, composed for the control socket.
//!
//! [`approve_and_issue`] is the operator's "yes" — it accepts the Task and hands
//! it to the worker in one action: sign the accept decision (locking the head),
//! then issue and durably claim the one-shot work order. [`deny`] is the "no" — it
//! signs a reject decision without locking the head.
//!
//! Every fail-closed check the operator would want *before* anything is committed
//! runs before the accept locks the head: the requester must be a paired peer (its
//! pinned TLS fingerprint binds the work order's request origin), and the accept
//! must grant at least one capability — a Task asking only for the outward-disclosing
//! capabilities is refused here, since those need a separate explicit confirmation.
//!
//! The signing keys and the local identity are passed in, so the composition is
//! pure and testable.

use axon_authority::{CapabilityComponent, WorkOrderKey};
use axon_contract::{parse_payload, Capability, DecisionKind, HeadState, Identity};
use axon_crypto::keypair::PurposeKey;
use axon_store::Store;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::control::Problem;
use crate::decision::decide;
use crate::issue::{issue_for_accepted, IssueConfig};

// Interim policy values — standing policy (§16.4) will supply these later.
/// The operator accepted at the local admin socket: a present human.
const ISSUER_ASSURANCE: &str = "local-human";
/// The local sandboxed worker that may claim the order.
const EXECUTOR: &str = "axon-worker";
/// The standing-policy version this decision was made under.
const POLICY_VERSION: u32 = 1;
/// The operation ceiling the worker's cgroup enforces (a resource limit, not a
/// contract field). A generous interim default.
const MAX_OPERATIONS: u32 = 1_000_000;

/// Approves a submitted Task: accept it and issue the one-shot work order (design
/// §10.2 then §12.3). `local` is this endpoint's identity — the decider and the
/// work-order issuer. Fails closed *before* the head is locked: the requester must
/// be paired, and the accept must grant at least one capability.
pub fn approve_and_issue(
    store: &Store,
    local: &Identity,
    decision_key: &PurposeKey,
    work_order_key: &WorkOrderKey,
    task_id: &str,
    now: i64,
) -> Result<serde_json::Value, Problem> {
    // Load the submitted contract to pre-check the requester and capabilities.
    let head = match store.contract_head(task_id).map_err(store_problem)? {
        HeadState::Open(head) => head,
        HeadState::Locked(_) => {
            return Err(problem(409, "already-decided", "this task is already accepted"))
        }
        HeadState::Empty => return Err(problem(404, "no-such-task", "no such task")),
    };
    let payload = store
        .get_contract(&head.digest)
        .map_err(store_problem)?
        .ok_or_else(|| problem(404, "no-such-task", "no such task"))?;
    let contract = parse_payload(&payload)
        .map_err(|_| problem(500, "corrupt-contract", "the stored contract could not be parsed"))?
        .contract;

    // The requester must be a paired peer — its pinned TLS fingerprint binds the
    // work order's request origin (design §8.1, §12.3). Refuse before locking.
    let requester_tls = store
        .peer_tls_fingerprint(&contract.requester.issuer, &contract.requester.agent)
        .map_err(store_problem)?
        .ok_or_else(|| {
            problem(
                409,
                "requester-not-paired",
                "the requester is not a paired peer; cannot bind the work order origin",
            )
        })?;

    // Accept grants only the non-disclosing capabilities (operator policy). If the
    // Task asks for none of those, the accept grants nothing — refuse here rather
    // than lock the head and then fail issuance.
    if !contract
        .requested_capabilities
        .iter()
        .any(|c| matches!(c, Capability::Respond | Capability::ReadSuppliedInputs))
    {
        return Err(problem(
            422,
            "no-grantable-capabilities",
            "accept grants no capability for this task; processor use and artifact export need a separate confirmation",
        ));
    }

    let decided_at = rfc3339(now)?;
    let record = decide(
        store,
        task_id,
        DecisionKind::Accept,
        None,
        None,
        local,
        decision_key,
        &decided_at,
        now,
    )?;
    let decision_id = decision_id(&record.decision);
    let nonce = fresh_nonce();

    let config = IssueConfig {
        issuer: local,
        issuer_assurance: ISSUER_ASSURANCE,
        daemon: &local.agent,
        executor: EXECUTOR,
        requester_tls_sha256: &requester_tls,
        work_order_key,
        nonce: &nonce,
        decision_id: &decision_id,
        policy_version: POLICY_VERSION,
        max_operations: MAX_OPERATIONS,
    };
    let issued = issue_for_accepted(store, task_id, &config, now)?;

    let granted: Vec<&str> = [
        (CapabilityComponent::Respond, "respond"),
        (CapabilityComponent::ReadSuppliedInputs, "read_supplied_inputs"),
        (CapabilityComponent::ProcessorUse, "processor_use"),
        (CapabilityComponent::ArtifactExport, "artifact_export"),
    ]
    .into_iter()
    .filter(|(component, _)| issued.order.capabilities.grants_component(*component))
    .map(|(_, name)| name)
    .collect();

    Ok(serde_json::json!({
        "approved": true,
        "task_id": task_id,
        "work_order_id": issued.order.work_order_id,
        "work_order_digest": issued.digest,
        "decision_id": decision_id,
        "granted_capabilities": granted,
    }))
}

/// Denies a submitted Task: signs a reject decision (design §10.2). The head is not
/// locked, so the reject is a signed record without an executor handoff.
pub fn deny(
    store: &Store,
    local: &Identity,
    decision_key: &PurposeKey,
    task_id: &str,
    reason: &str,
    now: i64,
) -> Result<serde_json::Value, Problem> {
    let decided_at = rfc3339(now)?;
    decide(
        store,
        task_id,
        DecisionKind::Reject,
        Some(reason),
        None,
        local,
        decision_key,
        &decided_at,
        now,
    )?;
    Ok(serde_json::json!({
        "denied": true,
        "task_id": task_id,
        "reason": reason,
    }))
}

/// A stable id for the signed decision — SHA-256 over its envelope bytes.
fn decision_id(decision: &axon_ext::dsse::Envelope) -> String {
    let bytes = serde_json::to_vec(decision).unwrap_or_default();
    format!("decision-{}", &hex_sha256(&bytes)[..32])
}

/// A fresh, unpredictable one-use work-order nonce (256 bits, hex).
fn fresh_nonce() -> String {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    hex_encode(&n)
}

fn rfc3339(now: i64) -> Result<String, Problem> {
    OffsetDateTime::from_unix_timestamp(now)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .ok_or_else(|| problem(500, "internal", "the request could not be processed"))
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn store_problem(_e: axon_store::StoreError) -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
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
    use axon_crypto::purpose::KeyPurpose;
    use axon_ext::dsse::Envelope;
    use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use axon_proto::v1::{part::Content, Part};
    use axon_store::delivery::CoveredValues;
    use axon_store::{ExternalCheckpoint, Store};
    use serde_json::json;
    use sha2::Digest;

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;
    const REQ_TLS: &str = "req-tls-fingerprint-abc123";

    fn store() -> Store {
        let kek = axon_store::envelope::Kek::from_bytes([21u8; 32]);
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

    fn work_order_key() -> WorkOrderKey {
        WorkOrderKey::from_bytes([7u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    /// Pins the requester's proposal key by their TLS fingerprint, so the approve
    /// reverse-lookup finds an origin to bind.
    fn pair_requester(store: &Store) {
        store
            .put_peer_key(
                REQ_TLS,
                "contract-proposal",
                "requester",
                "iss",
                &proposal_key().verifying().to_public_bytes(),
                NOW,
            )
            .unwrap();
    }

    /// Pairs the requester and submits a proposal requesting `caps`.
    fn pair_and_submit(store: &Store, caps: &[&str]) -> String {
        pair_requester(store);
        submit(store, caps)
    }

    /// Submits a proposal requesting `caps` (no pairing). Returns the Task id.
    fn submit(store: &Store, caps: &[&str]) -> String {
        let sha = hex::encode(sha2::Sha256::digest(TEXT.as_bytes()));
        let caps_json: Vec<serde_json::Value> = caps.iter().map(|c| json!(c)).collect();
        let value = json!({
            "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0, "task_type": "https://axon.invalid/t", "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"}, "objective": "o",
            "inputs": [{
                "id": "diff", "message_id": "msg-1", "part_index": 1, "kind": "text",
                "media_type": "text/x-diff", "charset": "utf-8", "canonical_rule": "utf8-exact",
                "byte_length": TEXT.len(), "sha256": sha,
                "worker_visible": true, "processor_visible": false
            }],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [], "requested_capabilities": caps_json,
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 8192, "max_cost_microusd": 500},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"
        });
        let payload = axon_ext::jcs::canonical_bytes(&value).unwrap();
        let env: Envelope = axon_contract::sign_proposal(&payload, &proposal_key()).unwrap();
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
    fn approve_accepts_and_issues_a_work_order() {
        let store = store();
        let task_id = pair_and_submit(&store, &["respond", "read_supplied_inputs"]);
        let out = approve_and_issue(
            &store,
            &ident("performer"),
            &decision_key(),
            &work_order_key(),
            &task_id,
            NOW,
        )
        .unwrap();

        assert_eq!(out["approved"], true);
        assert_eq!(out["task_id"], task_id);
        assert!(out["work_order_id"].as_str().unwrap().starts_with("wo-"));
        let granted: Vec<String> = out["granted_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert!(granted.contains(&"respond".to_owned()));
        assert!(granted.contains(&"read_supplied_inputs".to_owned()));
        assert!(!granted.contains(&"processor_use".to_owned()));

        // The head is locked (accepted) and the order was durably claimed.
        assert!(matches!(
            store.contract_head(&task_id).unwrap(),
            HeadState::Locked(_)
        ));
        assert!(store
            .attempt_state(out["work_order_id"].as_str().unwrap())
            .unwrap()
            .is_some());
    }

    #[test]
    fn approving_an_outward_only_task_is_422_and_does_not_lock_the_head() {
        let store = store();
        let task_id = pair_and_submit(&store, &["processor_use"]);
        let err = approve_and_issue(
            &store,
            &ident("performer"),
            &decision_key(),
            &work_order_key(),
            &task_id,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 422);
        // The pre-check ran before the accept, so the task is still submitted.
        assert!(matches!(
            store.contract_head(&task_id).unwrap(),
            HeadState::Open(_)
        ));
    }

    #[test]
    fn approving_an_unpaired_requester_is_409_and_does_not_lock_the_head() {
        let store = store();
        // Submit WITHOUT pairing the requester → reverse lookup finds no fingerprint.
        let task_id = submit(&store, &["respond"]);
        let err = approve_and_issue(
            &store,
            &ident("performer"),
            &decision_key(),
            &work_order_key(),
            &task_id,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 409);
        assert!(matches!(
            store.contract_head(&task_id).unwrap(),
            HeadState::Open(_)
        ));
    }

    #[test]
    fn deny_signs_a_reject_without_locking_the_head() {
        let store = store();
        let task_id = pair_and_submit(&store, &["respond"]);
        let out = deny(
            &store,
            &ident("performer"),
            &decision_key(),
            &task_id,
            "insufficient-evidence",
            NOW,
        )
        .unwrap();
        assert_eq!(out["denied"], true);
        assert_eq!(out["reason"], "insufficient-evidence");
        assert!(matches!(
            store.contract_head(&task_id).unwrap(),
            HeadState::Open(_)
        ));
    }
}
