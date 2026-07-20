//! The receive-path entry point (design §10.2, §7.2): validate a proposal
//! Message end to end, with no effect.
//!
//! `receive_proposal` composes the whole contract-engine pipeline over a received
//! A2A Message: extract the one contract-control Part, verify its DSSE envelope
//! under the `contract-proposal`-pinned key, enforce requester==mTLS-origin and
//! performer==local, bind every other Part to exactly one manifest entry, and
//! check the contract is within its trusted-time window. It performs no I/O and
//! invokes no model, tool, file, URL, or credential — the output is a validated,
//! inert proposal the caller then applies to the compare-and-swap head and
//! records as a `submitted` Task.
//!
//! What you write:
//! ```no_run
//! use akson_contract::{receive_proposal, apply_revision, HeadState};
//! # use akson_contract::Identity;
//! # use akson_crypto::keypair::PurposeVerifyingKey;
//! # let parts: Vec<akson_proto::v1::Part> = vec![];
//! # let key: PurposeVerifyingKey = unimplemented!();
//! # let requester: Identity = unimplemented!();
//! # let local: Identity = unimplemented!();
//! let received = receive_proposal("msg-1", &parts, &key, &requester, &local, 1_800_000_000)?;
//! // Then the store applies the revision to its head as an atomic CAS:
//! let verdict = apply_revision(&HeadState::Empty, &received.proposal);
//! # Ok::<(), akson_contract::ReceiveError>(())
//! ```

use akson_crypto::keypair::PurposeVerifyingKey;
use akson_proto::v1::Part;

use crate::contract::{Identity, ParsedContract};
use crate::expiry::{validity, Validity};
use crate::extraction::{extract_proposal, ExtractError};
use crate::manifest::{bind_inputs, BindError, InputPart};
use crate::proposal::{check_proposal_identities, verify_proposal, ProposalError};

/// A fully validated proposal: the parsed contract (with its digest) and the
/// worker-input Parts already bound to its manifest.
#[derive(Debug, Clone)]
pub struct ReceivedProposal {
    pub proposal: ParsedContract,
    pub inputs: Vec<InputPart>,
}

/// Why a received proposal was rejected. Every variant rejects before any Task
/// is created (design §10.2).
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    #[error("part extraction: {0}")]
    Extract(#[from] ExtractError),
    #[error("proposal verification: {0}")]
    Proposal(#[from] ProposalError),
    #[error("input-manifest binding: {0}")]
    Bind(#[from] BindError),
    #[error("contract has expired")]
    Expired,
    #[error("contract is not yet valid")]
    NotYetValid,
    #[error("contract timestamp is invalid: {0}")]
    Timestamp(#[from] crate::expiry::TimestampError),
}

/// Validates a received proposal Message end to end, returning the validated
/// (inert) proposal. Pure: no I/O, no effects. `trusted_now_unix` MUST be the
/// store's §8.5 trusted-time floor.
pub fn receive_proposal(
    message_id: &str,
    parts: &[Part],
    proposal_key: &PurposeVerifyingKey,
    requester_origin: &Identity,
    local_performer: &Identity,
    trusted_now_unix: i64,
) -> Result<ReceivedProposal, ReceiveError> {
    // 1. Separate the contract envelope from the worker-input Parts.
    let extracted = extract_proposal(message_id, parts)?;
    // 2. Verify the DSSE envelope and parse the contract.
    let proposal = verify_proposal(&extracted.envelope, proposal_key)?;
    // 3. Identity binding: requester == mTLS origin, performer == this endpoint.
    check_proposal_identities(&proposal.contract, requester_origin, local_performer)?;
    // 4. Every worker-input Part binds to exactly one manifest entry by digest.
    bind_inputs(&proposal.contract.inputs, &extracted.inputs)?;
    // 5. The contract must be within its trusted-time window.
    match validity(&proposal.contract, trusted_now_unix)? {
        Validity::Valid => {}
        Validity::Expired => return Err(ReceiveError::Expired),
        Validity::NotYetValid => return Err(ReceiveError::NotYetValid),
    }
    Ok(ReceivedProposal {
        proposal,
        inputs: extracted.inputs,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::proposal::sign_proposal;
    use akson_crypto::keypair::PurposeKey;
    use akson_crypto::purpose::KeyPurpose;
    use akson_ext::dsse::Envelope;
    use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use akson_proto::v1::part::Content;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TEXT: &str = "review this file";

    fn proposal_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    /// Builds a canonical contract payload that manifests one text input at the
    /// given Message part index.
    fn contract_payload(text_index: u32) -> Vec<u8> {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
        let value = json!({
            "schema_version": 1,
            "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0,
            "task_type": "https://akson.invalid/t",
            "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"},
            "objective": "o",
            "inputs": [{
                "id": "src", "message_id": "msg-1", "part_index": text_index,
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
        akson_ext::jcs::canonical_bytes(&value).unwrap()
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

    fn text_part(text: &str) -> Part {
        Part {
            metadata: None,
            filename: String::new(),
            media_type: "text/plain".to_owned(),
            content: Some(Content::Text(text.to_owned())),
        }
    }

    /// A well-formed proposal Message: contract Part at index 0, text at index 1.
    fn message() -> Vec<Part> {
        let env = sign_proposal(&contract_payload(1), &proposal_key()).unwrap();
        vec![envelope_part(&env), text_part(TEXT)]
    }

    const NOW: i64 = 1_800_000_000; // within [2026, 2030)

    #[test]
    fn valid_proposal_is_accepted_and_bound() {
        let received = receive_proposal(
            "msg-1",
            &message(),
            &proposal_key().verifying(),
            &ident("requester"),
            &ident("performer"),
            NOW,
        )
        .unwrap();
        assert_eq!(received.proposal.contract.revision, 0);
        assert_eq!(received.inputs.len(), 1);
        assert_eq!(received.inputs[0].part_index, 1);
    }

    #[test]
    fn tampered_input_part_fails_binding() {
        let env = sign_proposal(&contract_payload(1), &proposal_key()).unwrap();
        // Same length as TEXT ("review this file") but different bytes, so the
        // byte-length check passes and the digest check is what rejects it.
        assert_eq!("review this FILE".len(), TEXT.len());
        let parts = vec![envelope_part(&env), text_part("review this FILE")];
        let err = receive_proposal(
            "msg-1",
            &parts,
            &proposal_key().verifying(),
            &ident("requester"),
            &ident("performer"),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ReceiveError::Bind(BindError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn wrong_requester_origin_rejects() {
        let err = receive_proposal(
            "msg-1",
            &message(),
            &proposal_key().verifying(),
            &ident("impostor"),
            &ident("performer"),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ReceiveError::Proposal(ProposalError::RequesterMismatch)
        ));
    }

    #[test]
    fn expired_contract_rejects() {
        let year_2031 = 1_924_000_000;
        let err = receive_proposal(
            "msg-1",
            &message(),
            &proposal_key().verifying(),
            &ident("requester"),
            &ident("performer"),
            year_2031,
        )
        .unwrap_err();
        assert!(matches!(err, ReceiveError::Expired));
    }

    #[test]
    fn unmanifested_extra_part_rejects() {
        let env = sign_proposal(&contract_payload(1), &proposal_key()).unwrap();
        // A third Part with no manifest entry.
        let parts = vec![envelope_part(&env), text_part(TEXT), text_part("extra")];
        let err = receive_proposal(
            "msg-1",
            &parts,
            &proposal_key().verifying(),
            &ident("requester"),
            &ident("performer"),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ReceiveError::Bind(BindError::Unmanifested { .. })
        ));
    }
}
