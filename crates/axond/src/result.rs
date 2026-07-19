//! Completing an accepted Task with the worker's result (design §7.2, §14.1, §9.3).
//!
//! [`submit_result`] is the performer-side result path. The sandboxed worker,
//! having produced its outputs, submits them; this:
//!
//! 1. **gates** every output against the *exact* granted work order (§7.2 step 10)
//!    — an output outside its capability's scope is refused before anything is
//!    recorded;
//! 2. **assembles + signs** the result manifest under this endpoint's task-result
//!    key (§14.1), in the normative canonical order;
//! 3. **checks** the contract's required evidence slots (§14.3 — an omission cannot
//!    pass as success);
//! 4. **durably completes** the attempt: the signed manifest is staged in the same
//!    transaction that moves the attempt to `succeeded` (staged-then-atomic, §9.3).
//!
//! The task-result key is passed in, so the composition is pure and testable.

use axon_contract::{parse_payload, HeadState};
use axon_crypto::keypair::PurposeKey;
use axon_evidence::{
    check_slots, EvidenceEntry, ManifestHeader, Omission, OutputEntry, RequiredSlot,
    ResultManifest, SlotRecord, SlotResult,
};
use axon_store::{CompletionOutcome, Store};
use axon_worker::{gate_outputs, OutputChannel, ProposedOutput};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::control::Problem;

/// Which channel a worker output is emitted on (design §7.2) — selects the
/// capability that must authorize it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputKind {
    Response,
    Artifact,
}

impl OutputKind {
    fn channel(self) -> OutputChannel {
        match self {
            OutputKind::Response => OutputChannel::Response,
            OutputKind::Artifact => OutputChannel::Artifact,
        }
    }
}

/// One output a worker produced — everything the gate and the manifest need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultOutput {
    pub role: String,
    pub artifact_id: String,
    pub kind: OutputKind,
    pub recipient: String,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: String,
}

/// A worker's result submission over the narrow worker surface (design §16.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultSubmission {
    pub task_id: String,
    pub outputs: Vec<ResultOutput>,
    #[serde(default)]
    pub evidence: Vec<EvidenceEntry>,
    #[serde(default)]
    pub slots: Vec<SlotRecord>,
}

/// Completes an accepted Task with the worker's result (design §7.2 → §14.1). Fails
/// closed: the task must be accepted and have an issued work order; every output
/// must fall inside its granted scope; the required evidence slots must be
/// satisfied. Returns the signed result manifest (bundle digest) on success.
pub fn submit_result(
    store: &Store,
    task_result_key: &PurposeKey,
    submission: &ResultSubmission,
    now: i64,
) -> Result<serde_json::Value, Problem> {
    let task_id = &submission.task_id;

    // 1. Accepted task → contract + A2A context.
    let head = match store.contract_head(task_id).map_err(store_problem)? {
        HeadState::Locked(head) => head,
        HeadState::Open(_) => {
            return Err(problem(
                409,
                "not-accepted",
                "this task has not been accepted",
            ))
        }
        HeadState::Empty => return Err(problem(404, "no-such-task", "no such task")),
    };
    let payload = store
        .get_contract(&head.digest)
        .map_err(store_problem)?
        .ok_or_else(|| problem(404, "no-such-task", "no such task"))?;
    let contract = parse_payload(&payload)
        .map_err(|_| {
            problem(
                500,
                "corrupt-contract",
                "the stored contract could not be parsed",
            )
        })?
        .contract;
    let context_id = store
        .task_context(task_id)
        .map_err(store_problem)?
        .or_else(|| contract.context_id.clone())
        .unwrap_or_default();

    // 2. The claimed work order — its exact granted capabilities.
    let work_order_id = store
        .attempt_for_task(task_id)
        .map_err(store_problem)?
        .ok_or_else(|| problem(409, "no-work-order", "this task has no issued work order"))?;
    let issued = store
        .get_work_order(&work_order_id)
        .map_err(store_problem)?
        .ok_or_else(|| problem(500, "missing-work-order", "the work order is missing"))?;

    // 3. Output gate (§7.2 step 10): every output within its granted scope.
    let proposed: Vec<ProposedOutput> = submission
        .outputs
        .iter()
        .map(|o| ProposedOutput {
            channel: o.kind.channel(),
            recipient: o.recipient.clone(),
            media_type: o.media_type.clone(),
            bytes: o.byte_length,
        })
        .collect();
    gate_outputs(&issued.order.capabilities, &proposed).map_err(|e| Problem {
        type_: "urn:axon:error:output-refused".to_owned(),
        title: "a worker output exceeds its granted scope".to_owned(),
        status: 403,
        detail: Some(e.to_string()),
    })?;

    // 4. Required evidence slots (§14.3): an omission cannot pass as success.
    let required: Vec<RequiredSlot> = contract
        .evidence_slots
        .iter()
        .map(|s| RequiredSlot {
            slot_id: s.slot_id.clone(),
            required_result: SlotResult::Passed,
            require_full_disclosure: false,
        })
        .collect();
    check_slots(&required, &submission.slots).map_err(|e| Problem {
        type_: "urn:axon:error:evidence-incomplete".to_owned(),
        title: "the required evidence slots are not satisfied".to_owned(),
        status: 422,
        detail: Some(e.to_string()),
    })?;

    // 5. Assemble + sign the result manifest (§14.1).
    let header = ManifestHeader {
        task_id: task_id.clone(),
        context_id,
        contract_id: contract.contract_id.clone(),
        contract_revision: head.revision,
        contract_digest: head.digest.clone(),
        // v1 has no separate attempt receipt: the attempt is bound by its one-use
        // nonce, and the work order digest is the receipt the executor holds.
        attempt_digest: hex_sha256(issued.order.nonce.as_bytes()),
        work_order_receipt_digest: issued.digest.clone(),
    };
    let outputs: Vec<OutputEntry> = submission
        .outputs
        .iter()
        .enumerate()
        .map(|(i, o)| OutputEntry {
            role: o.role.clone(),
            artifact_id: o.artifact_id.clone(),
            part_index: i as u32,
            media_type: o.media_type.clone(),
            byte_length: o.byte_length,
            sha256: o.sha256.clone(),
        })
        .collect();
    let manifest = ResultManifest::assemble(
        header,
        outputs,
        submission.evidence.clone(),
        submission.slots.clone(),
        Vec::<Omission>::new(),
    );
    // bundle_digest validates the manifest (schema + canonical order); a manifest
    // the provided outputs cannot form is the worker's error, not ours.
    let bundle_digest = manifest.bundle_digest().map_err(|e| {
        problem_detail(422, "manifest-invalid", "the result manifest is invalid", e)
    })?;
    let envelope = manifest.sign(task_result_key).map_err(|_| {
        problem(
            500,
            "sign-failed",
            "the result manifest could not be signed",
        )
    })?;
    let envelope_bytes = serde_json::to_vec(&envelope)
        .map_err(|_| problem(500, "internal", "the request could not be processed"))?;

    // 6. Durably complete (staged-then-atomic).
    match store
        .complete_attempt_with_result(
            &work_order_id,
            task_id,
            &bundle_digest,
            &envelope_bytes,
            now,
        )
        .map_err(store_problem)?
    {
        CompletionOutcome::Completed | CompletionOutcome::AlreadyCompleted => {}
        CompletionOutcome::NotRunnable(_) => {
            return Err(problem(
                409,
                "not-runnable",
                "the attempt cannot complete from its current state",
            ))
        }
    }

    Ok(serde_json::json!({
        "completed": true,
        "task_id": task_id,
        "work_order_id": work_order_id,
        "bundle_digest": bundle_digest,
        "outputs": submission.outputs.len(),
    }))
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
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

fn problem_detail(status: u16, kind: &str, title: &str, e: impl std::fmt::Display) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: Some(e.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::approve::approve_and_issue;
    use crate::receive::{dispatch_proposal, DispatchOutcome};
    use axon_authority::WorkOrderKey;
    use axon_contract::Identity;
    use axon_crypto::keypair::PurposeKey;
    use axon_crypto::purpose::KeyPurpose;
    use axon_ext::dsse::Envelope;
    use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use axon_proto::v1::{part::Content, Part};
    use axon_store::delivery::CoveredValues;
    use axon_store::{ExternalCheckpoint, Store};
    use serde_json::json;

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;
    const REQ_TLS: &str = "req-tls-fingerprint-result";

    fn store() -> Store {
        let kek = axon_store::envelope::Kek::from_bytes([31u8; 32]);
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

    /// Pairs the requester, submits a proposal (max_response_bytes 8192), and
    /// approves it — leaving an accepted task with an issued work order.
    fn accepted_task(store: &Store) -> String {
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
        let sha = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(TEXT.as_bytes()))
        };
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
            "evidence_slots": [], "requested_capabilities": ["respond", "read_supplied_inputs"],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 8192},
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
        let task_id = match dispatch_proposal(
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
        };
        approve_and_issue(
            store,
            &ident("performer"),
            &PurposeKey::from_seed(KeyPurpose::ContractDecision, &[6u8; 32]),
            &WorkOrderKey::from_bytes([7u8; 32]),
            &task_id,
            None,
            false,
            NOW,
        )
        .unwrap();
        task_id
    }

    fn task_result_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::TaskResult, &[5u8; 32])
    }

    fn response(bytes: u64) -> ResultOutput {
        ResultOutput {
            role: "response".to_owned(),
            artifact_id: "a-1".to_owned(),
            kind: OutputKind::Response,
            recipient: "request-origin".to_owned(),
            media_type: "text/plain".to_owned(),
            byte_length: bytes,
            sha256: "c".repeat(64),
        }
    }

    #[test]
    fn a_gated_result_completes_and_verifies() {
        let store = store();
        let task_id = accepted_task(&store);
        let submission = ResultSubmission {
            task_id: task_id.clone(),
            outputs: vec![response(14)],
            evidence: vec![],
            slots: vec![],
        };
        let out = submit_result(&store, &task_result_key(), &submission, NOW).unwrap();
        assert_eq!(out["completed"], true);
        let digest = out["bundle_digest"].as_str().unwrap().to_owned();

        // The attempt is now succeeded, and the stored signed manifest verifies and
        // matches the reported bundle digest.
        let wo = store.attempt_for_task(&task_id).unwrap().unwrap();
        assert_eq!(
            store.attempt_state(&wo).unwrap(),
            Some(axon_authority::AttemptState::Succeeded)
        );
        let (stored_digest, manifest_bytes) = store.result_manifest(&wo).unwrap().unwrap();
        assert_eq!(stored_digest, digest);
        let envelope: Envelope = serde_json::from_slice(&manifest_bytes).unwrap();
        let (manifest, verified_digest) =
            ResultManifest::verify(&envelope, &task_result_key().verifying()).unwrap();
        assert_eq!(verified_digest, digest);
        assert_eq!(manifest.outputs.len(), 1);
    }

    #[test]
    fn an_over_budget_response_is_refused_by_the_gate() {
        let store = store();
        let task_id = accepted_task(&store);
        // The contract's max_response_bytes is 8192; 9000 exceeds the grant.
        let submission = ResultSubmission {
            task_id: task_id.clone(),
            outputs: vec![response(9000)],
            evidence: vec![],
            slots: vec![],
        };
        let err = submit_result(&store, &task_result_key(), &submission, NOW).unwrap_err();
        assert_eq!(err.status, 403);
        // Nothing was completed — the attempt is still claimed.
        let wo = store.attempt_for_task(&task_id).unwrap().unwrap();
        assert_eq!(
            store.attempt_state(&wo).unwrap(),
            Some(axon_authority::AttemptState::Claimed)
        );
        assert!(store.result_manifest(&wo).unwrap().is_none());
    }

    #[test]
    fn a_result_for_an_unaccepted_task_is_refused() {
        let store = store();
        let submission = ResultSubmission {
            task_id: "task-nope".to_owned(),
            outputs: vec![response(14)],
            evidence: vec![],
            slots: vec![],
        };
        let err = submit_result(&store, &task_result_key(), &submission, NOW).unwrap_err();
        assert_eq!(err.status, 404);
    }

    #[test]
    fn a_second_submit_is_idempotent() {
        let store = store();
        let task_id = accepted_task(&store);
        let submission = ResultSubmission {
            task_id: task_id.clone(),
            outputs: vec![response(14)],
            evidence: vec![],
            slots: vec![],
        };
        let first = submit_result(&store, &task_result_key(), &submission, NOW).unwrap();
        // A re-submit does not error and leaves the committed result in place.
        let again = submit_result(&store, &task_result_key(), &submission, NOW).unwrap();
        assert_eq!(again["completed"], true);
        assert_eq!(first["bundle_digest"], again["bundle_digest"]);
    }
}
