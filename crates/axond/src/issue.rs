//! Issuing the one-shot work order for an accepted Task (design §12.3, §12.1).
//!
//! Once the operator has accepted a Task (its head is locked), [`issue_for_accepted`]
//! turns the approved contract into a MAC'd, one-shot [`WorkOrder`] and durably
//! claims it (atomic nonce + budget), ready for the sandboxed worker.
//!
//! **Capability policy (operator choice: "the accept authorises the safe two"):**
//! the accept auto-grants only `respond` and `read_supplied_inputs` — the
//! capabilities that reply to the requester and read what they sent. `processor_use`
//! and `artifact_export` are the *outward-disclosing* capabilities; they are **not**
//! granted by the accept and require a separate, explicit confirmation before any
//! data leaves. Every grant's scope is derived from the contract (recipient, byte
//! budget, deadline, exact input ids), so the worker gets exactly what was approved.
//!
//! The local, non-contract inputs (issuer identity, executor audience, the requester
//! TLS fingerprint, the work-order key, the one-use nonce) come from [`IssueConfig`],
//! so the composition is pure and testable.

use axon_authority::{
    Audience, Budgets, CapabilityVector, Grant, IssuedWorkOrder, ProcessorUseScope, ReadInputsScope,
    RequestOrigin, RespondScope, WorkOrder, WorkOrderKey,
};
use axon_contract::{parse_payload, Capability, HeadState, Identity, ResultRecipient};
use axon_store::{ClaimOutcome, Store};

use crate::control::Problem;

/// The local, non-contract inputs needed to issue a work order (design §12.3).
pub struct IssueConfig<'a> {
    /// The local authority that issues the order.
    pub issuer: &'a Identity,
    /// The issuer's assurance level (e.g. `"local-human"` — the operator accepted).
    pub issuer_assurance: &'a str,
    pub daemon: &'a str,
    pub executor: &'a str,
    /// The requester peer's TLS leaf-cert fingerprint (binds the request origin).
    pub requester_tls_sha256: &'a str,
    pub work_order_key: &'a WorkOrderKey,
    /// The one-use nonce consumed at claim; MUST be fresh and unpredictable.
    pub nonce: &'a str,
    pub decision_id: &'a str,
    pub policy_version: u32,
    /// The operation ceiling the worker's cgroup enforces (not a contract field).
    pub max_operations: u32,
    /// The operator's explicit, per-approval decision to grant `processor_use`
    /// bound to this configured processor (design §12.1). `None` (the default) keeps
    /// the outward capability denied; `Some(id)` grants it only if the contract
    /// requested processor use and the processor is configured.
    pub processor_grant: Option<&'a str>,
}

/// Issues and durably claims the work order for an accepted Task (design §12.3).
/// Fails closed: the Task must be accepted (locked head); a task that requests no
/// accept-grantable capability is refused (the outward capabilities need a separate
/// confirmation); a reused nonce is a conflict.
pub fn issue_for_accepted(
    store: &Store,
    task_id: &str,
    config: &IssueConfig,
    now: i64,
) -> Result<IssuedWorkOrder, Problem> {
    // Only an accepted (locked) Task may be issued a work order.
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

    // Capability policy: accept auto-grants only the two non-disclosing capabilities.
    let recipient = recipient_str(contract.result_recipient);
    let input_ids: Vec<String> = contract.inputs.iter().map(|i| i.id.clone()).collect();
    let mut grants = Vec::new();
    for cap in &contract.requested_capabilities {
        match cap {
            Capability::Respond => grants.push(Grant::Respond(RespondScope {
                task_id: task_id.to_owned(),
                message_id: contract.message_id.clone(),
                recipient: recipient.to_owned(),
                max_responses: 1,
                max_bytes: contract.limits.max_response_bytes,
                deadline: contract.limits.deadline.clone(),
            })),
            Capability::ReadSuppliedInputs => {
                grants.push(Grant::ReadSuppliedInputs(ReadInputsScope {
                    input_ids: input_ids.clone(),
                    contract_digest: head.digest.clone(),
                }))
            }
            // Outward-disclosing — held for a separate explicit confirmation.
            Capability::ProcessorUse | Capability::ArtifactExport => {}
        }
    }

    // The operator may, at approval, additionally grant `processor_use` bound to a
    // specific configured processor — the explicit disclosure decision that lets the
    // peer task call a model. Fail closed: the contract must have requested it, and
    // the processor must be configured.
    if let Some(processor_id) = config.processor_grant {
        if !contract
            .requested_capabilities
            .iter()
            .any(|c| matches!(c, Capability::ProcessorUse))
        {
            return Err(problem(
                422,
                "processor-not-requested",
                "this task did not request processor use; it cannot be granted",
            ));
        }
        if store
            .get_processor(processor_id)
            .map_err(store_problem)?
            .is_none()
        {
            return Err(problem(
                404,
                "no-such-processor",
                "no processor is configured with that id (add it with `axon processor add`)",
            ));
        }
        grants.push(Grant::ProcessorUse(ProcessorUseScope {
            processor_id: processor_id.to_owned(),
            input_ids: input_ids.clone(),
            max_cost_microusd: contract.limits.max_cost_microusd.unwrap_or(0),
            max_bytes: contract.limits.max_response_bytes,
        }));
    }

    let capabilities = CapabilityVector::new(grants).map_err(|_| {
        problem(
            422,
            "no-grantable-capabilities",
            "accept grants no capability for this task; processor use and artifact export need a separate confirmation",
        )
    })?;

    let order = WorkOrder {
        version: 1,
        work_order_id: format!("wo-{}", &head.digest[..head.digest.len().min(32)]),
        issuer: config.issuer.clone(),
        issuer_assurance: config.issuer_assurance.to_owned(),
        audience: Audience {
            daemon: config.daemon.to_owned(),
            executor: config.executor.to_owned(),
        },
        request_origin: RequestOrigin {
            peer: contract.requester.clone(),
            tls_certificate_sha256: config.requester_tls_sha256.to_owned(),
        },
        task_id: task_id.to_owned(),
        context_id,
        message_id: contract.message_id.clone(),
        contract_revision: head.revision,
        contract_digest: head.digest.clone(),
        capabilities,
        input_manifest: input_ids,
        processor_digest: None,
        runner_digest: None,
        sandbox_digest: None,
        profile_digest: None,
        budgets: Budgets {
            max_cost_microusd: contract.limits.max_cost_microusd.unwrap_or(0),
            max_bytes: contract.limits.max_response_bytes,
            max_operations: config.max_operations,
        },
        evidence_slots: contract
            .evidence_slots
            .iter()
            .map(|s| s.slot_id.clone())
            .collect(),
        policy_version: config.policy_version,
        decision_id: config.decision_id.to_owned(),
        not_before: contract.created_at.clone(),
        deadline: contract.limits.deadline.clone(),
        nonce: config.nonce.to_owned(),
        remote_cancel: None,
    };

    let issued = order
        .issue(config.work_order_key)
        .map_err(|_| problem(500, "issue-failed", "the work order could not be issued"))?;

    // Durably claim: one insert consumes the one-use nonce + reserves the budget.
    match store.claim_attempt(&order, now).map_err(store_problem)? {
        ClaimOutcome::Claimed | ClaimOutcome::AlreadyClaimed(_) => {
            // Retain the issued order so the result gate later checks the worker's
            // outputs against these exact granted capabilities. Idempotent.
            store.put_work_order(&issued, now).map_err(store_problem)?;
            Ok(issued)
        }
        ClaimOutcome::NonceReused => Err(problem(
            409,
            "nonce-reused",
            "the work-order nonce was already used",
        )),
    }
}

fn recipient_str(r: ResultRecipient) -> &'static str {
    match r {
        ResultRecipient::RequestOrigin => "request-origin",
    }
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
    use crate::decision::decide;
    use crate::receive::{dispatch_proposal, DispatchOutcome};
    use axon_authority::CapabilityComponent;
    use axon_broker::{Disclosure, Origin, ProcessorConfig};
    use axon_contract::DecisionKind;
    use axon_crypto::keypair::PurposeKey;
    use axon_crypto::purpose::KeyPurpose;
    use axon_ext::dsse::Envelope;
    use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use axon_proto::v1::{part::Content, Part};
    use axon_store::delivery::CoveredValues;
    use axon_store::{ExternalCheckpoint, Store};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;
    const REQ_TLS: &str = "req-tls-fingerprint";

    fn store() -> Store {
        let kek = axon_store::envelope::Kek::from_bytes([12u8; 32]);
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

    fn config<'a>(key: &'a WorkOrderKey, issuer: &'a Identity, nonce: &'a str) -> IssueConfig<'a> {
        config_p(key, issuer, nonce, None)
    }

    fn config_p<'a>(
        key: &'a WorkOrderKey,
        issuer: &'a Identity,
        nonce: &'a str,
        processor: Option<&'a str>,
    ) -> IssueConfig<'a> {
        IssueConfig {
            processor_grant: processor,
            issuer,
            issuer_assurance: "local-human",
            daemon: "axond",
            executor: "worker-1",
            requester_tls_sha256: REQ_TLS,
            work_order_key: key,
            nonce,
            decision_id: "d-1",
            policy_version: 1,
            max_operations: 16,
        }
    }

    /// Submits a proposal requesting `caps`, then accepts it. Returns its task id.
    fn submit_and_accept(store: &Store, caps: &[&str]) -> String {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
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
        let decision_key = PurposeKey::from_seed(KeyPurpose::ContractDecision, &[6u8; 32]);
        decide(
            store,
            &task_id,
            DecisionKind::Accept,
            None,
            None,
            &ident("performer"),
            &decision_key,
            "2026-07-18T00:00:00Z",
            NOW,
        )
        .unwrap();
        task_id
    }

    #[test]
    fn issues_and_claims_a_work_order_granting_the_safe_capabilities() {
        let store = store();
        let task_id = submit_and_accept(&store, &["respond", "read_supplied_inputs"]);
        let key = WorkOrderKey::from_bytes([7u8; 32]);
        let issuer = ident("authority");
        let issued = issue_for_accepted(
            &store,
            &task_id,
            &config(&key, &issuer, &"n".repeat(43)),
            NOW,
        )
        .unwrap();

        // The order verifies under the work-order key and binds the task.
        issued.verify(&key).unwrap();
        assert_eq!(issued.order.task_id, task_id);
        // Both requested capabilities were granted; the outward two are absent.
        let caps = &issued.order.capabilities;
        assert!(caps.grants_component(CapabilityComponent::Respond));
        assert!(caps.grants_component(CapabilityComponent::ReadSuppliedInputs));
        assert!(!caps.grants_component(CapabilityComponent::ProcessorUse));
        assert!(!caps.grants_component(CapabilityComponent::ArtifactExport));
        // The attempt was durably claimed.
        assert!(store
            .attempt_state(&issued.order.work_order_id)
            .unwrap()
            .is_some());
    }

    #[test]
    fn processor_use_is_not_auto_granted() {
        let store = store();
        // A task requesting ONLY processor_use has nothing accept can grant.
        let task_id = submit_and_accept(&store, &["processor_use"]);
        let key = WorkOrderKey::from_bytes([7u8; 32]);
        let issuer = ident("authority");
        let err = issue_for_accepted(
            &store,
            &task_id,
            &config(&key, &issuer, &"n".repeat(43)),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 422);
    }

    fn add_processor(store: &Store, id: &str) {
        store
            .put_processor(
                &ProcessorConfig {
                    processor_id: id.to_owned(),
                    provider: "example-ai".to_owned(),
                    origin: Origin::https("api.example.com", 443),
                    disclosure: Disclosure::remote("Example AI", "us-east").retains("30d"),
                    path: "/".to_owned(),
                    auth: axon_broker::AuthScheme::Bearer,
                    config: serde_json::json!({"model": "review-1"}),
                    tls_certificate_sha256: None,
                },
                NOW,
            )
            .unwrap();
    }

    #[test]
    fn an_explicit_processor_grant_adds_processor_use_bound_to_that_processor() {
        let store = store();
        let task_id = submit_and_accept(&store, &["respond", "read_supplied_inputs", "processor_use"]);
        add_processor(&store, "reviewer");
        let key = WorkOrderKey::from_bytes([7u8; 32]);
        let issuer = ident("authority");
        let issued = issue_for_accepted(
            &store,
            &task_id,
            &config_p(&key, &issuer, &"n".repeat(43), Some("reviewer")),
            NOW,
        )
        .unwrap();
        let caps = &issued.order.capabilities;
        // The safe two plus the explicitly granted processor use.
        assert!(caps.grants_component(CapabilityComponent::Respond));
        assert!(caps.grants_component(CapabilityComponent::ProcessorUse));
        match caps.grant(CapabilityComponent::ProcessorUse) {
            Some(Grant::ProcessorUse(scope)) => assert_eq!(scope.processor_id, "reviewer"),
            other => panic!("expected a processor_use grant, got {other:?}"),
        }
    }

    #[test]
    fn a_processor_grant_the_contract_did_not_request_is_refused() {
        let store = store();
        // The contract asks only for the safe two — processor use was not requested.
        let task_id = submit_and_accept(&store, &["respond", "read_supplied_inputs"]);
        add_processor(&store, "reviewer");
        let key = WorkOrderKey::from_bytes([7u8; 32]);
        let issuer = ident("authority");
        let err = issue_for_accepted(
            &store,
            &task_id,
            &config_p(&key, &issuer, &"n".repeat(43), Some("reviewer")),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 422);
    }

    #[test]
    fn a_grant_naming_an_unconfigured_processor_is_refused() {
        let store = store();
        let task_id = submit_and_accept(&store, &["respond", "read_supplied_inputs", "processor_use"]);
        // No processor configured.
        let key = WorkOrderKey::from_bytes([7u8; 32]);
        let issuer = ident("authority");
        let err = issue_for_accepted(
            &store,
            &task_id,
            &config_p(&key, &issuer, &"n".repeat(43), Some("ghost")),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 404);
    }

    #[test]
    fn issuing_before_accept_is_refused() {
        let store = store();
        // Submit but do NOT accept (head stays open) — issuing must be refused.
        let task_id = {
            let value = json!({
                "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
                "revision": 0, "task_type": "https://axon.invalid/t", "message_id": "msg-1",
                "requester": {"issuer": "iss", "agent": "requester"},
                "performer": {"issuer": "iss", "agent": "performer"}, "objective": "o",
                "inputs": [], "deliverables": [{"role": "r", "media_type": "text/plain"}],
                "evidence_slots": [], "requested_capabilities": ["respond"],
                "processor_constraints": {"disclosure": "none"},
                "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 8192},
                "result_recipient": "request-origin",
                "created_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"
            });
            let payload = axon_ext::jcs::canonical_bytes(&value).unwrap();
            let env: Envelope = axon_contract::sign_proposal(&payload, &proposal_key()).unwrap();
            let parts = vec![Part {
                metadata: None,
                filename: String::new(),
                media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
                content: Some(Content::Data(
                    serde_json::from_value(serde_json::to_value(&env).unwrap()).unwrap(),
                )),
            }];
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
                &store,
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
        };
        let key = WorkOrderKey::from_bytes([7u8; 32]);
        let issuer = ident("authority");
        let err = issue_for_accepted(
            &store,
            &task_id,
            &config(&key, &issuer, &"n".repeat(43)),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 409);
    }
}
