//! Finalizing a delivered result: the requester's signed disposition (design §14.5).
//!
//! When a performer delivers a result, the requester [`finalize_result`]s it:
//!
//! 1. **verify** the result manifest under the performer's pinned task-result key
//!    (a manifest that does not verify is refused before anything is recorded);
//! 2. **match** it to an outstanding request this daemon actually sent — an
//!    unsolicited result (no matching `sent_request`) is refused;
//! 3. **sign** the [`Outcome`](axon_evidence::Outcome) that binds exactly this
//!    result (its bundle digest and the whole contract binding), under this
//!    endpoint's requester-outcome key, and record it durably.
//!
//! The disposition here is `accepted` on a valid, bound, solicited result — the
//! cryptographic checks passed. Operator-driven `rejected`/`disputed` policy is a
//! later refinement.
//!
//! The keys are passed in, so the composition is pure and testable.

use axon_contract::Identity;
use axon_crypto::keypair::{PurposeKey, PurposeVerifyingKey};
use axon_evidence::{Outcome, OutcomeState, ResultManifest};
use axon_ext::dsse::Envelope;
use axon_store::Store;

use crate::control::Problem;

/// Finalizes a delivered result into a signed requester outcome (design §14.5).
/// `performer_task_result_key` is the performer's pinned task-result verifying key;
/// `outcome_key` is this endpoint's requester-outcome signing key. `signed_at` is
/// RFC 3339. Fails closed: the manifest must verify, and the result must answer a
/// request this daemon actually sent.
pub fn finalize_result(
    store: &Store,
    requester: &Identity,
    outcome_key: &PurposeKey,
    performer_task_result_key: &PurposeVerifyingKey,
    manifest_envelope: &Envelope,
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

    // 3. Sign the outcome that binds exactly this result, and record it.
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

    store
        .put_outcome(
            &manifest.header.contract_digest,
            &manifest.header.task_id,
            &bundle_digest,
            &outcome_digest,
            "accepted",
            &envelope_bytes,
            signed_at,
            now,
        )
        .map_err(store_problem)?;

    Ok(serde_json::json!({
        "finalized": true,
        "task_id": manifest.header.task_id,
        "state": "accepted",
        "bundle_digest": bundle_digest,
        "outcome_digest": outcome_digest,
    }))
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
    use axon_crypto::keypair::PurposeKey;
    use axon_crypto::purpose::KeyPurpose;
    use axon_evidence::{ManifestHeader, OutputEntry};
    use axon_store::{ExternalCheckpoint, SentRequest, Store};

    const NOW: i64 = 1_800_000_000;
    const CONTRACT_DIGEST: &str =
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const SIGNED_AT: &str = "2026-07-18T00:00:00Z";

    fn store() -> Store {
        let kek = axon_store::envelope::Kek::from_bytes([41u8; 32]);
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

    /// A signed result manifest for `task_id` bound to CONTRACT_DIGEST.
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
                byte_length: 14,
                sha256: "d".repeat(64),
            }],
            vec![],
            vec![],
            vec![],
        );
        manifest.sign(&performer_task_result_key()).unwrap()
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
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
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
    }

    #[test]
    fn an_unsolicited_result_is_refused() {
        let store = store();
        // No sent_request recorded.
        let envelope = signed_manifest("task-1");
        let err = finalize_result(
            &store,
            &ident("requester"),
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 409);
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
            &outcome_key(),
            &wrong.verifying(),
            &envelope,
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 422);
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
            &outcome_key(),
            &performer_task_result_key().verifying(),
            &envelope,
            SIGNED_AT,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.status, 409);
    }
}
