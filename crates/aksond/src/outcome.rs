//! Finalizing a delivered result: the requester's signed disposition (design §14.5).
//!
//! When a performer delivers a result, the requester [`finalize_result`]s it:
//!
//! 1. **verify** the result manifest under the performer's pinned task-result key
//!    (a manifest that does not verify is refused before anything is recorded);
//! 2. **match** it to an outstanding request this daemon actually sent — an
//!    unsolicited result (no matching `sent_request`) is refused;
//! 3. **check the delivered bytes** against the manifest — every output the
//!    manifest names must arrive, and each must re-hash to the digest the
//!    performer signed (§14.1);
//! 4. **sign** the [`Outcome`](akson_evidence::Outcome) that binds exactly this
//!    result (its bundle digest and the whole contract binding), under this
//!    endpoint's requester-outcome key, and record it durably alongside those
//!    bytes.
//!
//! The disposition here is `accepted` on a valid, bound, solicited result — the
//! cryptographic checks passed. Operator-driven `rejected`/`disputed` policy is a
//! later refinement.
//!
//! Because step 3 is fail-closed, an `accepted` outcome means the requester holds
//! exactly the bytes the performer signed for — which is what lets the requesting
//! agent read the result and act on it.
//!
//! The keys are passed in, so the composition is pure and testable.

use akson_contract::Identity;
use akson_crypto::keypair::{PurposeKey, PurposeVerifyingKey};
use akson_evidence::{Outcome, OutcomeState, ResultManifest};
use akson_ext::dsse::Envelope;
use akson_store::Store;

use crate::control::Problem;

/// One output payload that arrived with a delivered result: the bytes for the
/// manifest entry whose `artifact_id` this names (design §14.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredOutput {
    pub artifact_id: String,
    pub bytes: Vec<u8>,
}

/// Finalizes a delivered result into a signed requester outcome (design §14.5).
/// `performer_task_result_key` is the performer's pinned task-result verifying key;
/// `outcome_key` is this endpoint's requester-outcome signing key. `delivered` are
/// the output payloads that came with the manifest. `signed_at` is RFC 3339. Fails
/// closed: the manifest must verify, the result must answer a request this daemon
/// actually sent, and the delivered bytes must be exactly what the manifest names.
#[allow(clippy::too_many_arguments)]
pub fn finalize_result(
    store: &Store,
    requester: &Identity,
    sender: &Identity,
    sender_root: &str,
    outcome_key: &PurposeKey,
    performer_task_result_key: &PurposeVerifyingKey,
    manifest_envelope: &Envelope,
    delivered: &[DeliveredOutput],
    signed_at: &str,
    now: i64,
) -> Result<serde_json::Value, Problem> {
    // 1. Verify the manifest under the performer's task-result key.
    let (manifest, bundle_digest) =
        ResultManifest::verify(manifest_envelope, performer_task_result_key).map_err(|_| {
            problem(
                422,
                "manifest-invalid",
                "the result manifest did not verify",
            )
        })?;

    // 2. Match an outstanding request — refuse an unsolicited result.
    let sent = store
        .get_sent_request(&manifest.header.contract_digest)
        .map_err(store_problem)?
        .ok_or_else(|| {
            problem(
                409,
                "unsolicited-result",
                "no outstanding request matches this result",
            )
        })?;
    if sent.task_id != manifest.header.task_id {
        return Err(problem(
            409,
            "result-mismatch",
            "the result's task does not match the outstanding request",
        ));
    }
    // The authenticated sender MUST be the performer this task was assigned to.
    // Without this, any paired peer that learns a contract_digest + task_id could
    // deliver a result signed with its own task-result key and obtain a
    // requester-signed acceptance for another performer's task (codex review).
    if sent.performer_agent != sender.agent || sent.performer_issuer != sender.issuer {
        return Err(problem(
            403,
            "wrong-performer",
            "the result was not delivered by the assigned performer",
        ));
    }
    // The delivering ROOT must be the root this task was sent to: a
    // same-named peer that learns the digest/task id must not be able to
    // substitute its own signed result (PK-cutover review). Empty roots
    // (pre-V20 requests) refuse — fail closed.
    if sent.performer_root.is_empty() || sent.performer_root != sender_root {
        return Err(problem(
            403,
            "wrong-performer",
            "the result was not delivered by the assigned performer",
        ));
    }

    // 3. Check the delivered bytes against the manifest the performer signed.
    //
    // The manifest names each output by artifact_id and states its digest and
    // length. Every named output must arrive, and each must re-hash to that
    // digest — otherwise the requester would be storing (and its agent reading)
    // bytes the performer never signed for. Fail closed: one bad or missing
    // output refuses the whole delivery, so an accepted outcome always means the
    // complete, attested result is on hand.
    // Two manifest outputs sharing an artifact_id would let one delivered part
    // satisfy both entries, and only one row would survive storage — so an
    // accepted outcome could claim two artifacts the requester cannot both hold.
    // Refuse a manifest that names an artifact_id twice (codex review).
    let mut seen_ids = std::collections::BTreeSet::new();
    for entry in &manifest.outputs {
        if !seen_ids.insert(entry.artifact_id.as_str()) {
            return Err(problem(
                422,
                "output-duplicate",
                "the manifest names the same artifact more than once",
            ));
        }
    }
    let mut staged: Vec<(usize, &akson_evidence::OutputEntry, &[u8])> = Vec::new();
    for (ordinal, entry) in manifest.outputs.iter().enumerate() {
        let Some(part) = delivered
            .iter()
            .find(|d| d.artifact_id == entry.artifact_id)
        else {
            return Err(problem(
                422,
                "output-missing",
                "the result did not carry every output its manifest names",
            ));
        };
        if part.bytes.len() as u64 != entry.byte_length
            || crate::result::hex_sha256(&part.bytes) != entry.sha256
        {
            return Err(problem(
                422,
                "output-digest-mismatch",
                "a delivered output does not match the digest in the signed manifest",
            ));
        }
        staged.push((ordinal, entry, &part.bytes));
    }
    // An output the manifest does not name is not covered by the performer's
    // signature — refuse rather than silently drop it.
    if delivered.len() != manifest.outputs.len() {
        return Err(problem(
            422,
            "output-unbound",
            "the result carried an output its manifest does not name",
        ));
    }

    // 4. Sign the outcome that binds exactly this result, and record it.
    let outcome = Outcome::for_manifest(
        &manifest,
        OutcomeState::Accepted,
        requester.clone(),
        signed_at.to_owned(),
    )
    .map_err(|_| problem(500, "outcome", "the outcome could not be built"))?;
    outcome.check_binds_to(&manifest).map_err(|_| {
        problem(
            500,
            "outcome-binding",
            "the outcome does not bind the result",
        )
    })?;
    let envelope = outcome
        .sign(outcome_key)
        .map_err(|_| problem(500, "sign-failed", "the outcome could not be signed"))?;
    let outcome_digest = outcome
        .digest()
        .map_err(|_| problem(500, "outcome", "the outcome could not be digested"))?;
    let envelope_bytes = serde_json::to_vec(&envelope)
        .map_err(|_| problem(500, "internal", "the request could not be processed"))?;

    // Write the outputs and the outcome together (§14.1, requester mirror). One
    // transaction, so an outcome is never recorded for a result whose bytes this
    // endpoint did not durably keep, and a crash cannot leave committed bytes for
    // a later, differently-signed manifest to attach to. Idempotent on a
    // redelivery: the stored disposition wins and its digest is reported, so the
    // acknowledgement never claims a digest that is not on disk.
    let new_outputs: Vec<akson_store::NewTaskOutput<'_>> = staged
        .iter()
        .map(|(ordinal, entry, bytes)| akson_store::NewTaskOutput {
            artifact_id: &entry.artifact_id,
            ordinal: *ordinal as i64,
            role: &entry.role,
            media_type: &entry.media_type,
            byte_length: entry.byte_length as i64,
            sha256: &entry.sha256,
            payload: bytes,
        })
        .collect();
    let write = store
        .record_outcome_with_outputs(
            &manifest.header.contract_digest,
            &manifest.header.task_id,
            &bundle_digest,
            &outcome_digest,
            "accepted",
            &envelope_bytes,
            &new_outputs,
            signed_at,
            now,
        )
        .map_err(store_problem)?;
    let recorded_digest = match write {
        akson_store::OutcomeWrite::Recorded => outcome_digest,
        akson_store::OutcomeWrite::AlreadyRecorded { outcome_digest } => outcome_digest,
    };

    Ok(serde_json::json!({
        "finalized": true,
        "task_id": manifest.header.task_id,
        "state": "accepted",
        "bundle_digest": bundle_digest,
        "outcome_digest": recorded_digest,
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
    use akson_crypto::keypair::PurposeKey;
    use akson_crypto::purpose::KeyPurpose;
    use akson_evidence::{ManifestHeader, OutputEntry};
    use akson_store::{ExternalCheckpoint, SentRequest, Store};

    const NOW: i64 = 1_800_000_000;
    const CONTRACT_DIGEST: &str =
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const SIGNED_AT: &str = "2026-07-18T00:00:00Z";

    fn store() -> Store {
        let kek = akson_store::envelope::Kek::from_bytes([41u8; 32]);
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        Store::open_in_memory(&kek, cp).unwrap()
    }

    fn performer_task_result_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::TaskResult, &[5u8; 32])
    }

    fn outcome_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::RequesterOutcome, &[6u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    /// The one output every fixture manifest names.
    const RESPONSE: &[u8] = b"reviewed: LGTM";

    /// A signed result manifest for `task_id` bound to CONTRACT_DIGEST, naming one
    /// `response` output over [`RESPONSE`].
    fn signed_manifest(task_id: &str) -> Envelope {
        let manifest = ResultManifest::assemble(
            ManifestHeader {
                task_id: task_id.to_owned(),
                context_id: "ctx-1".to_owned(),
                contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
                contract_revision: 0,
                contract_digest: CONTRACT_DIGEST.to_owned(),
                attempt_digest: "b".repeat(64),
                work_order_receipt_digest: "c".repeat(64),
            },
            vec![OutputEntry {
                role: "response".to_owned(),
                artifact_id: "a-1".to_owned(),
                part_index: 0,
                media_type: "text/plain".to_owned(),
                byte_length: RESPONSE.len() as u64,
                sha256: crate::result::hex_sha256(RESPONSE),
            }],
            vec![],
            vec![],
            vec![],
        );
        manifest.sign(&performer_task_result_key()).unwrap()
    }

    /// The delivery that matches [`signed_manifest`].
    fn delivered() -> Vec<DeliveredOutput> {
        vec![DeliveredOutput {
            artifact_id: "a-1".to_owned(),
            bytes: RESPONSE.to_vec(),
        }]
    }

    fn record_sent(store: &Store, task_id: &str) {
        store
            .put_sent_request(
                &SentRequest {
                    contract_digest: CONTRACT_DIGEST.to_owned(),
                    task_id: task_id.to_owned(),
                    context_id: "ctx-1".to_owned(),
                    contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
                    performer_agent: "performer".to_owned(),
                    performer_issuer: "iss".to_owned(),
                    message_id: "msg-1".to_owned(),
                    performer_root: "root-fixture".to_owned(),
                },
                NOW,
            )
            .unwrap();
    }

    #[test]
    fn a_delivered_result_is_verified_and_the_outcome_is_signed_and_stored() {
        let store = store();
        record_sent(&store, "task-1");
        let envelope = signed_manifest("task-1");
        let out = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            &delivered(),
            SIGNED_AT,
            NOW,
        )
        .unwrap();
        assert_eq!(out["finalized"], true);
        assert_eq!(out["state"], "accepted");

        // The stored outcome verifies under the requester-outcome key and binds
        // the manifest.
        let (stored_digest, env_bytes) = store.get_outcome(CONTRACT_DIGEST).unwrap().unwrap();
        assert_eq!(stored_digest, out["outcome_digest"].as_str().unwrap());
        let stored_env: Envelope = serde_json::from_slice(&env_bytes).unwrap();
        let outcome = Outcome::verify(&stored_env, &outcome_key().verifying()).unwrap();
        assert_eq!(outcome.state, OutcomeState::Accepted);
        assert_eq!(outcome.task_id, "task-1");
        assert_eq!(
            outcome.result_manifest_digest,
            out["bundle_digest"].as_str().unwrap()
        );

        // And the requester now HOLDS the result, not just an attestation about
        // it — this is what lets its agent read the answer and act on it.
        let outputs = store.list_task_outputs("task-1").unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].role, "response");
        assert_eq!(outputs[0].payload, RESPONSE);
    }

    #[test]
    fn a_delivered_output_that_does_not_match_the_signed_digest_is_refused() {
        let store = store();
        record_sent(&store, "task-1");
        let envelope = signed_manifest("task-1");
        // The manifest is genuine and signed; the bytes are not the ones it covers.
        let tampered = vec![DeliveredOutput {
            artifact_id: "a-1".to_owned(),
            bytes: b"reviewed: SHIP IT".to_vec(),
        }];
        let err = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            &tampered,
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 422);
        // No-effect: neither the outcome nor the bytes are recorded (§19).
        assert!(store.list_outcomes().unwrap().is_empty());
        assert!(store.list_task_outputs("task-1").unwrap().is_empty());
    }

    #[test]
    fn a_result_delivered_without_its_output_bytes_is_refused() {
        let store = store();
        record_sent(&store, "task-1");
        let envelope = signed_manifest("task-1");
        // A manifest-only delivery: attested, but the requester would hold nothing.
        let err = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            &[],
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 422);
        assert!(store.list_outcomes().unwrap().is_empty());
    }

    #[test]
    fn an_output_the_manifest_does_not_name_is_refused() {
        let store = store();
        record_sent(&store, "task-1");
        let envelope = signed_manifest("task-1");
        // The named output is correct, but an extra part rides along uncovered by
        // the performer's signature.
        let mut smuggled = delivered();
        smuggled.push(DeliveredOutput {
            artifact_id: "a-2".to_owned(),
            bytes: b"unsigned extra".to_vec(),
        });
        let err = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            &smuggled,
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 422);
        assert!(store.list_outcomes().unwrap().is_empty());
        assert!(store.list_task_outputs("task-1").unwrap().is_empty());
    }

    #[test]
    fn an_unsolicited_result_is_refused() {
        let store = store();
        // No sent_request recorded.
        let envelope = signed_manifest("task-1");
        let err = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            &delivered(),
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 409);
        // No-effect: a refused result records no outcome (§19).
        assert!(store.list_outcomes().unwrap().is_empty());
    }

    #[test]
    fn a_manifest_signed_by_the_wrong_key_is_refused() {
        let store = store();
        record_sent(&store, "task-1");
        let envelope = signed_manifest("task-1");
        // Verify under a DIFFERENT task-result key → refused.
        let wrong = PurposeKey::from_seed(KeyPurpose::TaskResult, &[9u8; 32]);
        let err = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &wrong.verifying(),
            &envelope,
            &delivered(),
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 422);
        // No-effect: a manifest that fails to verify records no outcome (§19).
        assert!(store.list_outcomes().unwrap().is_empty());
    }

    /// A signed manifest whose two outputs share one artifact_id, delivered by two
    /// identical parts. Without the duplicate guard, one part satisfies both entries
    /// and one stored row backs an outcome that claims two artifacts (codex review).
    #[test]
    fn a_manifest_naming_the_same_artifact_twice_is_refused() {
        let store = store();
        record_sent(&store, "task-1");
        let manifest = ResultManifest::assemble(
            ManifestHeader {
                task_id: "task-1".to_owned(),
                context_id: "ctx-1".to_owned(),
                contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
                contract_revision: 0,
                contract_digest: CONTRACT_DIGEST.to_owned(),
                attempt_digest: "b".repeat(64),
                work_order_receipt_digest: "c".repeat(64),
            },
            vec![
                OutputEntry {
                    role: "a".to_owned(),
                    artifact_id: "dup".to_owned(),
                    part_index: 0,
                    media_type: "text/plain".to_owned(),
                    byte_length: RESPONSE.len() as u64,
                    sha256: crate::result::hex_sha256(RESPONSE),
                },
                OutputEntry {
                    role: "b".to_owned(),
                    artifact_id: "dup".to_owned(),
                    part_index: 1,
                    media_type: "text/plain".to_owned(),
                    byte_length: RESPONSE.len() as u64,
                    sha256: crate::result::hex_sha256(RESPONSE),
                },
            ],
            vec![],
            vec![],
            vec![],
        );
        let envelope = manifest.sign(&performer_task_result_key()).unwrap();
        let delivered = vec![
            DeliveredOutput {
                artifact_id: "dup".to_owned(),
                bytes: RESPONSE.to_vec(),
            },
            DeliveredOutput {
                artifact_id: "dup".to_owned(),
                bytes: RESPONSE.to_vec(),
            },
        ];
        let err = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            &delivered,
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 422);
        assert!(store.list_outcomes().unwrap().is_empty());
        assert!(store.list_task_outputs("task-1").unwrap().is_empty());
    }

    /// A redelivery for a settled task must not overwrite the stored bytes with a
    /// second, differently-signed manifest, and must report the digest that is on
    /// disk — not a freshly minted one (codex review A1/A6). Models the window a
    /// crash could open: the first delivery recorded, a second arrives with the
    /// same artifact_id but different content.
    #[test]
    fn a_redelivery_with_different_bytes_neither_overwrites_nor_reports_a_phantom_digest() {
        let store = store();
        record_sent(&store, "task-1");

        // First delivery: accepted, bytes stored.
        let first = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &signed_manifest("task-1"),
            &delivered(),
            SIGNED_AT,
            NOW,
        )
        .unwrap();
        let first_digest = first["outcome_digest"].as_str().unwrap().to_owned();

        // A second, genuinely-signed manifest for the SAME contract/task, but over
        // different bytes with the same artifact_id.
        const OTHER: &[u8] = b"reviewed: SHIP IT NOW";
        let manifest = ResultManifest::assemble(
            ManifestHeader {
                task_id: "task-1".to_owned(),
                context_id: "ctx-1".to_owned(),
                contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
                contract_revision: 0,
                contract_digest: CONTRACT_DIGEST.to_owned(),
                attempt_digest: "b".repeat(64),
                work_order_receipt_digest: "c".repeat(64),
            },
            vec![OutputEntry {
                role: "response".to_owned(),
                artifact_id: "a-1".to_owned(),
                part_index: 0,
                media_type: "text/plain".to_owned(),
                byte_length: OTHER.len() as u64,
                sha256: crate::result::hex_sha256(OTHER),
            }],
            vec![],
            vec![],
            vec![],
        );
        let envelope = manifest.sign(&performer_task_result_key()).unwrap();
        let second = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            &[DeliveredOutput {
                artifact_id: "a-1".to_owned(),
                bytes: OTHER.to_vec(),
            }],
            "2026-07-19T00:00:00Z",
            NOW + 1,
        )
        .unwrap();

        // The acknowledgement reports the FIRST (stored) digest, not the second.
        assert_eq!(second["outcome_digest"].as_str().unwrap(), first_digest);
        // The stored disposition and bytes are the first delivery's, untouched.
        let (stored_digest, _) = store.get_outcome(CONTRACT_DIGEST).unwrap().unwrap();
        assert_eq!(stored_digest, first_digest);
        let outputs = store.list_task_outputs("task-1").unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].payload, RESPONSE, "the first bytes still stand");
    }

    #[test]
    fn a_result_for_a_different_task_than_requested_is_refused() {
        let store = store();
        record_sent(&store, "task-1");
        // The manifest is for task-2, but the outstanding request is task-1.
        let envelope = signed_manifest("task-2");
        let err = finalize_result(
            &store,
            &ident("requester"),
            &ident("performer"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            &delivered(),
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 409);
    }

    #[test]
    fn a_result_delivered_by_the_wrong_peer_is_refused() {
        let store = store();
        record_sent(&store, "task-1"); // performer = performer/iss
        let envelope = signed_manifest("task-1"); // signed by the performer's key
                                                  // A DIFFERENT paired peer delivers the (validly-signed-by-performer) result.
        let err = finalize_result(
            &store,
            &ident("requester"),
            &ident("impostor"),
            "root-fixture",
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            &delivered(),
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 403, "a non-performer sender must be refused");
        assert!(store.list_outcomes().unwrap().is_empty());
    }
}
