//! Proposal signing, verification, and identity binding (design §10.2).
//!
//! A requester signs a contract revision under a key pinned for the
//! `contract-proposal` purpose. The performer verifies it and enforces the two
//! identity rules that stop a proposal from impersonating a peer: the signed
//! `requester` MUST equal the identity mapped from the authenticated mTLS origin,
//! and the signed `performer` MUST equal the local endpoint identity. A mismatch
//! is rejected before any Task is created.
//!
//! This is the DSSE + identity layer. Finding the one contract-control Part in an
//! A2A Message (and rejecting a missing or second one) is the receive-path
//! extraction step, layered on top of this.
//!
//! What you write:
//! ```
//! use akson_contract::{sign_proposal, verify_proposal, check_proposal_identities, Identity};
//! use akson_crypto::keypair::PurposeKey;
//! use akson_crypto::purpose::KeyPurpose;
//! # use serde_json::json;
//! # let value = json!({
//! #   "schema_version": 1, "contract_id": "00000000-0000-4000-8000-000000000000",
//! #   "revision": 0, "task_type": "https://akson.invalid/t", "message_id": "m1",
//! #   "requester": {"issuer": "iss", "agent": "requester"},
//! #   "performer": {"issuer": "iss", "agent": "performer"}, "objective": "o",
//! #   "inputs": [], "deliverables": [{"role": "r", "media_type": "text/plain"}],
//! #   "evidence_slots": [], "requested_capabilities": [], "processor_constraints": {"disclosure": "none"},
//! #   "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
//! #   "result_recipient": "request-origin", "created_at": "2026-01-01T00:00:00Z",
//! #   "expires_at": "2030-01-01T00:00:00Z"
//! # });
//! # let payload = akson_ext::jcs::canonical_bytes(&value).unwrap();
//! let key = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32]);
//! let envelope = sign_proposal(&payload, &key).unwrap();          // requester signs
//! let proposal = verify_proposal(&envelope, &key.verifying()).unwrap(); // performer verifies
//! check_proposal_identities(
//!     &proposal.contract,
//!     &Identity { issuer: "iss".into(), agent: "requester".into() }, // mapped from mTLS origin
//!     &Identity { issuer: "iss".into(), agent: "performer".into() }, // local endpoint identity
//! ).unwrap();
//! ```

use akson_crypto::keypair::{KeyError, PurposeKey, PurposeVerifyingKey};
use akson_crypto::purpose::KeyPurpose;
use akson_ext::dsse::{self, DsseError, Envelope};
use akson_ext::schema::SchemaId;

use crate::contract::{parse_payload, Contract, ContractError, Identity, ParsedContract};

/// Proposal signing/verification failures. Every variant fails closed.
#[derive(Debug, thiserror::Error)]
pub enum ProposalError {
    #[error("proposal key purpose: {0}")]
    Purpose(#[from] KeyError),
    #[error("dsse: {0}")]
    Dsse(#[from] DsseError),
    #[error("contract payload invalid: {0}")]
    Contract(#[from] ContractError),
    /// The signed requester is not the party authenticated by the mTLS origin.
    #[error("requester identity does not match the authenticated origin")]
    RequesterMismatch,
    /// The signed performer is not this endpoint.
    #[error("performer identity does not match the local endpoint")]
    PerformerMismatch,
}

/// The DSSE `payloadType` for a contract payload.
fn proposal_payload_type() -> String {
    SchemaId::ContractV1.payload_media_type()
}

/// Signs a canonical contract payload into a DSSE envelope under the
/// `contract-proposal` purpose. The payload is validated first, so a malformed
/// or non-canonical contract is never signed.
pub fn sign_proposal(payload: &[u8], key: &PurposeKey) -> Result<Envelope, ProposalError> {
    parse_payload(payload)?;
    let payload_type = proposal_payload_type();
    let envelope = key.sign_with(KeyPurpose::ContractProposal, |sk| {
        dsse::sign(&payload_type, payload, sk)
    })?;
    Ok(envelope)
}

/// Verifies a proposal envelope under the `contract-proposal` purpose and returns
/// the parsed contract with its digest.
///
/// Fails closed unless: the key is pinned for `contract-proposal`, the DSSE
/// envelope verifies (one signature, matching `payloadType`, thumbprint, strict
/// Ed25519), and the payload passes the full contract pipeline (I-JSON +
/// RFC 8785 canonical + schema).
pub fn verify_proposal(
    envelope: &Envelope,
    key: &PurposeVerifyingKey,
) -> Result<ParsedContract, ProposalError> {
    let vk = key.key_for(KeyPurpose::ContractProposal)?;
    let payload = dsse::verify(envelope, &proposal_payload_type(), vk)?;
    // parse_payload runs the full contract pipeline over exactly the signed
    // bytes: I-JSON, the RFC 8785-canonical assertion, schema, and the digest.
    Ok(parse_payload(&payload)?)
}

/// Enforces the two §10.2 identity rules: the signed `requester` MUST equal the
/// identity mapped from the authenticated mTLS origin, and the signed `performer`
/// MUST equal the local endpoint identity. Checked before Task creation.
pub fn check_proposal_identities(
    contract: &Contract,
    requester_origin: &Identity,
    local_performer: &Identity,
) -> Result<(), ProposalError> {
    if &contract.requester != requester_origin {
        return Err(ProposalError::RequesterMismatch);
    }
    if &contract.performer != local_performer {
        return Err(ProposalError::PerformerMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use akson_ext::jcs;
    use serde_json::json;

    fn payload() -> Vec<u8> {
        let value = json!({
            "schema_version": 1,
            "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0,
            "task_type": "https://akson.invalid/t",
            "message_id": "m1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"},
            "objective": "o",
            "inputs": [],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [],
            "requested_capabilities": [],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z"
        });
        jcs::canonical_bytes(&value).unwrap()
    }

    fn key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    #[test]
    fn sign_verify_round_trips_and_binds_identities() {
        let envelope = sign_proposal(&payload(), &key()).unwrap();
        let proposal = verify_proposal(&envelope, &key().verifying()).unwrap();
        assert_eq!(proposal.contract.revision, 0);
        check_proposal_identities(&proposal.contract, &ident("requester"), &ident("performer"))
            .unwrap();
    }

    #[test]
    fn wrong_purpose_key_cannot_sign_or_verify() {
        let wrong = PurposeKey::from_seed(KeyPurpose::ContractDecision, &[4u8; 32]);
        assert!(matches!(
            sign_proposal(&payload(), &wrong),
            Err(ProposalError::Purpose(_))
        ));
        let envelope = sign_proposal(&payload(), &key()).unwrap();
        assert!(matches!(
            verify_proposal(&envelope, &wrong.verifying()),
            Err(ProposalError::Purpose(_))
        ));
    }

    #[test]
    fn identity_mismatches_reject() {
        let proposal = verify_proposal(
            &sign_proposal(&payload(), &key()).unwrap(),
            &key().verifying(),
        )
        .unwrap();
        // Requester is not the authenticated origin.
        assert!(matches!(
            check_proposal_identities(
                &proposal.contract,
                &ident("someone-else"),
                &ident("performer")
            ),
            Err(ProposalError::RequesterMismatch)
        ));
        // Performer is not this endpoint.
        assert!(matches!(
            check_proposal_identities(&proposal.contract, &ident("requester"), &ident("not-me")),
            Err(ProposalError::PerformerMismatch)
        ));
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let mut envelope = sign_proposal(&payload(), &key()).unwrap();
        use base64::Engine;
        // Re-sign nothing; just corrupt the payload so the signature no longer covers it.
        let mut forged = payload();
        forged[0] ^= 0xff;
        envelope.payload = base64::engine::general_purpose::STANDARD.encode(forged);
        assert!(matches!(
            verify_proposal(&envelope, &key().verifying()),
            Err(ProposalError::Dsse(_))
        ));
    }
}
