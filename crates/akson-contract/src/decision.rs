//! Contract decisions (design §10.2): the performer's signed accept, reject, or
//! revision-request that binds a proposal to a Task.
//!
//! The requester signs a proposal; the performer signs a *separate* decision
//! referencing the exact proposal digest and the receiver-assigned Task and
//! Context identifiers. That decision — not the proposal — is the cryptographic
//! binding between the proposal and the Task, and it is signed under a key pinned
//! for the `contract-decision` purpose (distinct from the `contract-proposal`
//! key). A revision request is a decision too; it is not itself a new revision.
//!
//! What you write:
//! ```
//! use akson_contract::{sign_decision, verify_decision, Decision, DecisionKind, Identity};
//! use akson_crypto::keypair::PurposeKey;
//! use akson_crypto::purpose::KeyPurpose;
//! let key = PurposeKey::from_seed(KeyPurpose::ContractDecision, &[9u8; 32]);
//! let decision = Decision {
//!     schema_version: 1,
//!     decision: DecisionKind::Accept,
//!     contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".into(),
//!     contract_revision: 0,
//!     contract_digest: "a".repeat(64),
//!     task_id: "task-1".into(),
//!     context_id: "ctx-1".into(),
//!     decider: Identity { issuer: "iss".into(), agent: "performer".into() },
//!     reason_code: None,
//!     note: None,
//!     decided_at: "2026-01-01T00:00:00Z".into(),
//! };
//! let envelope = sign_decision(&decision, &key).unwrap();
//! let verified = verify_decision(&envelope, &key.verifying()).unwrap();
//! assert_eq!(verified.decision, DecisionKind::Accept);
//! ```

use akson_crypto::keypair::{KeyError, PurposeKey, PurposeVerifyingKey};
use akson_crypto::purpose::KeyPurpose;
use akson_ext::dsse::{self, DsseError, Envelope};
use akson_ext::schema::{self, SchemaId};
use akson_ext::{ijson, jcs};
use serde::{Deserialize, Serialize};

use crate::contract::{Identity, ParsedContract};

/// The three decisions a performer may sign (design §10.2). V1 has no
/// performer-authored counterproposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionKind {
    Accept,
    Reject,
    RevisionRequest,
}

/// A performer-signed decision (design §10.2). Field-for-field with
/// `spec/ext/decision.v1.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub schema_version: u32,
    pub decision: DecisionKind,
    pub contract_id: String,
    pub contract_revision: u64,
    /// Canonical digest of the exact proposal revision being decided.
    pub contract_digest: String,
    pub task_id: String,
    pub context_id: String,
    pub decider: Identity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub decided_at: String,
}

/// Decision build/verify failures. Every variant fails the decision closed.
#[derive(Debug, thiserror::Error)]
pub enum DecisionError {
    #[error("decision key purpose: {0}")]
    Purpose(#[from] KeyError),
    #[error("dsse: {0}")]
    Dsse(#[from] DsseError),
    #[error("decision payload is not valid I-JSON: {0}")]
    IJson(#[from] ijson::IJsonError),
    #[error("canonicalization failed: {0}")]
    Jcs(#[from] jcs::JcsError),
    #[error("decision payload is not RFC 8785 canonical")]
    NotCanonical,
    #[error("decision failed schema validation: {0}")]
    Schema(#[from] schema::SchemaError),
    #[error("decision shape invalid: {0}")]
    Shape(#[from] serde_json::Error),
    #[error("decision does not bind to the proposal: {0}")]
    Binding(&'static str),
}

/// The DSSE `payloadType` for a decision payload.
fn decision_payload_type() -> String {
    SchemaId::DecisionV1.payload_media_type()
}

/// Signs a decision into a DSSE envelope under the `contract-decision` purpose.
/// The payload is the RFC 8785-canonical decision JSON; signing is gated on the
/// key's purpose, so a wrong-purpose key never reaches the signer.
pub fn sign_decision(decision: &Decision, key: &PurposeKey) -> Result<Envelope, DecisionError> {
    let value = serde_json::to_value(decision)?;
    // Schema-validate before signing so we never emit a malformed decision.
    schema::validate(SchemaId::DecisionV1, &value)?;
    let payload = jcs::canonical_bytes(&value)?;
    let payload_type = decision_payload_type();
    let envelope = key.sign_with(KeyPurpose::ContractDecision, |sk| {
        dsse::sign(&payload_type, &payload, sk)
    })?;
    Ok(envelope)
}

/// Verifies a decision envelope under the `contract-decision` purpose and returns
/// the typed decision.
///
/// Fails closed unless: the key is pinned for `contract-decision`, the DSSE
/// envelope verifies (one signature, matching `payloadType`, thumbprint, strict
/// Ed25519), the payload is canonical I-JSON, and it validates against the
/// decision schema.
pub fn verify_decision(
    envelope: &Envelope,
    key: &PurposeVerifyingKey,
) -> Result<Decision, DecisionError> {
    // Purpose gate: the raw verifying key is released only for this purpose.
    let vk = key.key_for(KeyPurpose::ContractDecision)?;
    let payload = dsse::verify(envelope, &decision_payload_type(), vk)?;

    let value = ijson::parse(&payload)?;
    // The signed bytes must be canonical — one representation, digestible.
    if jcs::canonical_bytes(&value)? != payload {
        return Err(DecisionError::NotCanonical);
    }
    schema::validate(SchemaId::DecisionV1, &value)?;
    Ok(serde_json::from_value(value)?)
}

/// Checks that a verified decision binds to exactly this proposal (design §10.2):
/// the contract id, revision, and digest match, and the decider is the proposal's
/// performer (only the performer signs a decision). The caller separately checks
/// the Task and Context identifiers against the Task it holds.
pub fn check_binds_to(decision: &Decision, proposal: &ParsedContract) -> Result<(), DecisionError> {
    let c = &proposal.contract;
    if decision.contract_id != c.contract_id {
        return Err(DecisionError::Binding("contract id"));
    }
    if decision.contract_revision != c.revision {
        return Err(DecisionError::Binding("contract revision"));
    }
    if decision.contract_digest != proposal.digest {
        return Err(DecisionError::Binding("contract digest"));
    }
    if decision.decider != c.performer {
        return Err(DecisionError::Binding("decider is not the performer"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::parse_payload;
    use akson_crypto::purpose::KeyPurpose;
    use serde_json::json;

    fn decision_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractDecision, &[9u8; 32])
    }

    fn sample(kind: DecisionKind, digest: &str) -> Decision {
        Decision {
            schema_version: 1,
            decision: kind,
            contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
            contract_revision: 0,
            contract_digest: digest.to_owned(),
            task_id: "task-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            decider: Identity {
                issuer: "iss".to_owned(),
                agent: "performer".to_owned(),
            },
            reason_code: None,
            note: None,
            decided_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    fn proposal() -> ParsedContract {
        let v = json!({
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
        parse_payload(&jcs::canonical_bytes(&v).unwrap()).unwrap()
    }

    #[test]
    fn accept_round_trips_and_binds() {
        let p = proposal();
        let key = decision_key();
        let decision = sample(DecisionKind::Accept, &p.digest);
        let envelope = sign_decision(&decision, &key).unwrap();
        let verified = verify_decision(&envelope, &key.verifying()).unwrap();
        assert_eq!(verified, decision);
        check_binds_to(&verified, &p).unwrap();
    }

    #[test]
    fn reject_and_revision_request_round_trip() {
        let key = decision_key();
        for kind in [DecisionKind::Reject, DecisionKind::RevisionRequest] {
            let d = sample(kind, &"a".repeat(64));
            let e = sign_decision(&d, &key).unwrap();
            assert_eq!(
                verify_decision(&e, &key.verifying()).unwrap().decision,
                kind
            );
        }
    }

    #[test]
    fn wrong_purpose_key_cannot_sign_or_verify() {
        let wrong = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[9u8; 32]);
        let d = sample(DecisionKind::Accept, &"a".repeat(64));
        assert!(matches!(
            sign_decision(&d, &wrong),
            Err(DecisionError::Purpose(_))
        ));
        // A correctly-signed decision cannot be verified with a proposal-purpose key.
        let e = sign_decision(&d, &decision_key()).unwrap();
        assert!(matches!(
            verify_decision(&e, &wrong.verifying()),
            Err(DecisionError::Purpose(_))
        ));
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = decision_key();
        let mut envelope =
            sign_decision(&sample(DecisionKind::Accept, &"a".repeat(64)), &key).unwrap();
        // Flip the payload to a different (still schema-valid) decision.
        let forged = jcs::canonical_bytes(
            &serde_json::to_value(sample(DecisionKind::Reject, &"a".repeat(64))).unwrap(),
        )
        .unwrap();
        use base64::Engine;
        envelope.payload = base64::engine::general_purpose::STANDARD.encode(forged);
        assert!(matches!(
            verify_decision(&envelope, &key.verifying()),
            Err(DecisionError::Dsse(_))
        ));
    }

    #[test]
    fn decision_for_a_different_proposal_does_not_bind() {
        let p = proposal();
        // Right shape, wrong digest.
        let d = sample(DecisionKind::Accept, &"b".repeat(64));
        assert!(matches!(
            check_binds_to(&d, &p),
            Err(DecisionError::Binding("contract digest"))
        ));
        // Decider is not the performer.
        let mut d = sample(DecisionKind::Accept, &p.digest);
        d.decider.agent = "someone-else".to_owned();
        assert!(matches!(
            check_binds_to(&d, &p),
            Err(DecisionError::Binding("decider is not the performer"))
        ));
    }
}
