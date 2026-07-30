//! Exporting a completed task's signed result as a portable bundle
//! (`akson task export`, design §14.1): the DSSE-signed result manifest plus the
//! exact output bytes it names, in the versioned `akson-result-bundle` format —
//! so anyone holding this endpoint's task-result public key can check the result
//! **offline** with `akson verify`, no daemon and no store.
//!
//! Only the side that *performed* the task can export: the signed manifest lives
//! in its `results` table, staged atomically with completion (§9.3). The
//! requester validates the manifest at delivery and durably keeps the verified
//! output bytes and its own signed outcome — but not the performer's envelope —
//! so a requester-side export is refused with exactly that explanation rather
//! than a bundle that could not carry the producer's signature.
//!
//! Fail-closed both ways: the assembled bundle is re-verified under this
//! endpoint's own task-result key before it is handed out — this daemon never
//! emits a bundle that `akson verify` would refuse.

use akson_contract::Identity;
use akson_crypto::keypair::PurposeVerifyingKey;
use akson_evidence::{BundleOutput, ResultBundle, SignerHint};
use akson_ext::dsse::Envelope;
use akson_store::Store;

use crate::control::Problem;

/// Assembles the result bundle of a task this endpoint performed. `exporter` is
/// this endpoint's identity, `root_thumbprint` its identity-root (agent-card)
/// thumbprint, and `task_result_key` its **own** task-result public key — the
/// key the stored manifest must verify under. Fails closed: no completed local
/// result, or a stored result this build cannot itself verify, is a refusal.
pub fn export_result_bundle(
    store: &Store,
    exporter: &Identity,
    root_thumbprint: &str,
    task_result_key: &PurposeVerifyingKey,
    task_id: &str,
) -> Result<serde_json::Value, Problem> {
    // The signed manifest exists only for a task performed here (its attempt).
    let manifest_row = match store.attempt_for_task(task_id).map_err(store_problem)? {
        Some(work_order_id) => store
            .result_manifest(&work_order_id)
            .map_err(store_problem)?,
        None => None,
    };
    let Some((stored_digest, manifest_bytes)) = manifest_row else {
        // Distinguish the requester side honestly: this endpoint may well hold
        // the task's verified outputs and its signed outcome — just not the
        // performer's manifest envelope, which is checked at delivery and not
        // retained (§14.5). Naming that here beats a bare "not found".
        let requester_side = store
            .list_outcomes()
            .map_err(store_problem)?
            .iter()
            .any(|o| o.task_id == task_id);
        if requester_side {
            return Err(problem(
                409,
                "not-the-performer",
                "this endpoint received this result; it validated the performer's signed manifest at delivery and keeps the verified outputs and its own outcome, but not the performer's envelope — export the bundle on the performer's endpoint",
            ));
        }
        return Err(problem(
            404,
            "no-result",
            "no completed result for this task on this endpoint",
        ));
    };
    let envelope: Envelope = serde_json::from_slice(&manifest_bytes).map_err(|_| {
        problem(
            500,
            "corrupt-result",
            "the stored result manifest could not be parsed",
        )
    })?;

    let outputs: Vec<BundleOutput> = store
        .list_task_outputs(task_id)
        .map_err(store_problem)?
        .iter()
        .map(|o| BundleOutput::from_bytes(&o.artifact_id, &o.role, &o.media_type, &o.payload))
        .collect();

    let signer = SignerHint {
        issuer: exporter.issuer.clone(),
        agent: exporter.agent.clone(),
        root_thumbprint: root_thumbprint.to_owned(),
        task_result_public_key_hex: hex::encode(task_result_key.to_public_bytes()),
        task_result_thumbprint: task_result_key.thumbprint(),
    };
    let bundle = ResultBundle::assemble(task_id, envelope, outputs, Some(signer));

    // Never emit a bundle this build cannot itself verify — the export is the
    // consumer's evidence, so it must pass the consumer's exact checks.
    let verified = bundle.verify(task_result_key).map_err(|e| Problem {
        type_: "urn:akson:error:export-invalid".to_owned(),
        title: "the assembled bundle does not verify; refusing to export it".to_owned(),
        status: 500,
        detail: Some(e.to_string()),
    })?;
    if verified.bundle_digest != stored_digest {
        return Err(problem(
            500,
            "export-invalid",
            "the assembled bundle's digest does not match the stored bundle digest",
        ));
    }

    let bundle_value = serde_json::to_value(&bundle)
        .map_err(|_| problem(500, "internal", "the request could not be processed"))?;
    Ok(serde_json::json!({
        "task_id": task_id,
        "bundle_digest": verified.bundle_digest,
        "outputs": verified.manifest.outputs.len(),
        "payload_bytes": verified.payload_bytes,
        "signer_task_result_public_key_hex": hex::encode(task_result_key.to_public_bytes()),
        "signer_task_result_thumbprint": task_result_key.thumbprint(),
        "bundle": bundle_value,
    }))
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
    use crate::approve::approve_and_issue;
    use crate::receive::{dispatch_proposal, DispatchOutcome};
    use crate::result::{submit_result, OutputKind, ResultOutput, ResultSubmission};
    use akson_authority::WorkOrderKey;
    use akson_crypto::keypair::PurposeKey;
    use akson_crypto::purpose::KeyPurpose;
    use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use akson_proto::v1::{part::Content, Part};
    use akson_store::delivery::CoveredValues;
    use akson_store::{ExternalCheckpoint, Store};
    use serde_json::json;

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;
    const REQ_TLS: &str = "req-tls-fingerprint-export";
    const ROOT: &str = "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn store() -> Store {
        let kek = akson_store::envelope::Kek::from_bytes([37u8; 32]);
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

    fn task_result_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::TaskResult, &[5u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
            root: ROOT.to_owned(),
        }
    }

    /// Pairs the requester, submits a proposal, and approves it — an accepted
    /// task with an issued work order (the `result.rs` fixture, verbatim shape).
    fn accepted_task(store: &Store) -> String {
        store
            .put_peer(&{
                use akson_crypto::identity::{Fingerprint, FingerprintKind, PeerIdentity};
                akson_store::StoredPeer {
                    identity: PeerIdentity {
                        issuer: Some("iss".to_owned()),
                        agent_id: "requester".to_owned(),
                        workload_id: None,
                        endpoint_id: "https://requester/a2a".to_owned(),
                        tls_cert: Fingerprint {
                            kind: FingerprintKind::CertSha256,
                            value: REQ_TLS.to_owned(),
                        },
                        agent_card_key: Fingerprint {
                            kind: FingerprintKind::Jwk7638,
                            value: ROOT.to_owned(),
                        },
                        key_bindings: vec![],
                        security_projection_digest: Fingerprint::json_sha256(b"{}"),
                        full_card_digest: Fingerprint::json_sha256(b"{}"),
                    },
                    local_note: String::new(),
                }
            })
            .unwrap();
        store
            .put_peer_key(
                REQ_TLS,
                "contract-proposal",
                "requester",
                "iss",
                &proposal_key().verifying().to_public_bytes(),
                ROOT,
                NOW,
            )
            .unwrap();
        let sha = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(TEXT.as_bytes()))
        };
        let value = json!({
            "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0, "task_type": "https://akson.invalid/t", "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester", "root": ROOT},
            "performer": {"issuer": "iss", "agent": "performer", "root": ROOT}, "objective": "o",
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
            peer: ROOT.to_owned(),
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

    /// Completes the accepted task with one `response` output.
    fn completed_task(store: &Store) -> String {
        let task_id = accepted_task(store);
        let submission = ResultSubmission {
            task_id: task_id.clone(),
            outputs: vec![ResultOutput {
                role: "response".to_owned(),
                artifact_id: "a-1".to_owned(),
                kind: OutputKind::Response,
                recipient: "request-origin".to_owned(),
                media_type: "text/plain".to_owned(),
                content: b"reviewed: LGTM".to_vec(),
            }],
            evidence: vec![],
            slots: vec![],
        };
        submit_result(store, &task_result_key(), &submission, NOW).unwrap();
        task_id
    }

    /// The end-to-end proof: a really-completed task exports a bundle that the
    /// offline verifier accepts under the performer's public key alone.
    #[test]
    fn a_completed_task_exports_a_bundle_that_verifies_offline() {
        let store = store();
        let task_id = completed_task(&store);
        let out = export_result_bundle(
            &store,
            &ident("performer"),
            ROOT,
            &task_result_key().verifying(),
            &task_id,
        )
        .unwrap();

        // Round-trip through bytes, exactly as `akson verify` reads the file.
        let bytes = serde_json::to_vec(&out["bundle"]).unwrap();
        let bundle = ResultBundle::from_slice(&bytes).unwrap();
        let verified = bundle.verify(&task_result_key().verifying()).unwrap();
        assert_eq!(
            verified.bundle_digest,
            out["bundle_digest"].as_str().unwrap()
        );
        assert_eq!(verified.manifest.header.task_id, task_id);
        assert_eq!(verified.manifest.outputs.len(), 1);
        // The signer hint carries the key the operator hands over out-of-band.
        assert_eq!(
            out["signer_task_result_public_key_hex"].as_str().unwrap(),
            hex::encode(task_result_key().verifying().to_public_bytes())
        );
    }

    #[test]
    fn an_unknown_task_is_refused() {
        let store = store();
        let err = export_result_bundle(
            &store,
            &ident("performer"),
            ROOT,
            &task_result_key().verifying(),
            "task-nope",
        )
        .unwrap_err();
        assert_eq!(err.status, 404);
    }

    #[test]
    fn an_accepted_but_uncompleted_task_is_refused() {
        let store = store();
        let task_id = accepted_task(&store);
        let err = export_result_bundle(
            &store,
            &ident("performer"),
            ROOT,
            &task_result_key().verifying(),
            &task_id,
        )
        .unwrap_err();
        assert_eq!(err.status, 404, "no completed result yet");
    }

    /// The requester holds verified outputs and its own outcome, never the
    /// performer's envelope — the refusal must say so, not claim "not found".
    #[test]
    fn a_requester_side_task_is_refused_with_the_honest_reason() {
        let store = store();
        store
            .record_outcome_with_outputs(
                &"d1".repeat(32),
                "task-recv",
                &"b2".repeat(32),
                &"c3".repeat(32),
                "accepted",
                b"{}",
                &[],
                "2026-07-18T00:00:00Z",
                NOW,
            )
            .unwrap();
        let err = export_result_bundle(
            &store,
            &ident("requester"),
            ROOT,
            &task_result_key().verifying(),
            "task-recv",
        )
        .unwrap_err();
        assert_eq!(err.status, 409);
        assert!(
            err.title.contains("performer"),
            "the refusal must point at the performer's endpoint: {}",
            err.title
        );
    }

    /// Export must fail closed on its own product: a stored manifest this
    /// endpoint's current key cannot verify is refused, never emitted.
    #[test]
    fn a_result_the_own_key_cannot_verify_is_not_exported() {
        let store = store();
        let task_id = completed_task(&store);
        let wrong = PurposeKey::from_seed(KeyPurpose::TaskResult, &[9u8; 32]);
        let err = export_result_bundle(
            &store,
            &ident("performer"),
            ROOT,
            &wrong.verifying(),
            &task_id,
        )
        .unwrap_err();
        assert_eq!(err.status, 500);
        assert!(err.title.contains("refusing to export"), "{}", err.title);
    }
}
