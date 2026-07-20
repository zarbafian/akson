//! The task-contract payload (design §10.2): the typed revision plus the
//! validate-and-digest pipeline that turns a DSSE-signed payload into a
//! `ParsedContract`.
//!
//! A contract payload is the exact bytes a DSSE envelope signs. Those bytes MUST
//! be RFC 8785-canonical (§10.2 "canonicalized with RFC 8785 before digesting
//! and DSSE signing"), so `parse_payload` re-canonicalizes and rejects any
//! payload that is not already canonical — there is one representation, and the
//! contract digest (what predecessors and decisions reference) is the SHA-256 of
//! exactly those signed bytes.
//!
//! What you write:
//! ```
//! # use serde_json::json;
//! # let value = json!({
//! #   "schema_version": 1,
//! #   "contract_id": "00000000-0000-4000-8000-000000000000",
//! #   "revision": 0,
//! #   "task_type": "https://akson.invalid/task/echo",
//! #   "message_id": "msg-1",
//! #   "requester": {"issuer": "a.example", "agent": "requester"},
//! #   "performer": {"issuer": "b.example", "agent": "performer"},
//! #   "objective": "demo",
//! #   "inputs": [],
//! #   "deliverables": [{"role": "report", "media_type": "text/plain"}],
//! #   "evidence_slots": [],
//! #   "requested_capabilities": [],
//! #   "processor_constraints": {"disclosure": "none"},
//! #   "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
//! #   "result_recipient": "request-origin",
//! #   "created_at": "2026-01-01T00:00:00Z",
//! #   "expires_at": "2030-01-01T00:00:00Z"
//! # });
//! # let payload = akson_ext::jcs::canonical_bytes(&value).unwrap();
//! use akson_contract::parse_payload;
//! let parsed = parse_payload(&payload).unwrap();
//! assert_eq!(parsed.contract.revision, 0);
//! assert!(parsed.contract.is_revision_zero());
//! assert_eq!(parsed.digest.len(), 64); // SHA-256 hex of the signed bytes
//! ```

use akson_ext::schema::{self, SchemaId};
use akson_ext::{ijson, jcs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// An issuer-qualified identity (design §8.1): the pair that names a party.
/// `Serialize` too, so a decision can embed the same identity shape it verifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub issuer: String,
    pub agent: String,
}

/// A Part's content kind. `text` digests exact UTF-8; `data` digests JCS JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PartKind {
    Text,
    Data,
}

/// The canonical-byte rule an input entry digests under (design §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum CanonicalRule {
    #[serde(rename = "utf8-exact")]
    Utf8Exact,
    #[serde(rename = "jcs")]
    Jcs,
}

/// A v1 capability component (informational request, never authority §10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Respond,
    ReadSuppliedInputs,
    ProcessorUse,
    ArtifactExport,
}

/// The bilateral ceiling on processor plaintext disclosure (design §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disclosure {
    None,
    LocalOnly,
    NamedRemote,
}

/// An acceptable trust class for an evidence slot (design §14.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustClass {
    SelfAttested,
    IndependentlyVerified,
    HardwareAttested,
}

/// Where the result is delivered. V1 fixes this to the request origin (§10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResultRecipient {
    RequestOrigin,
}

/// One ordered input-manifest entry binding an exact Message Part (design §10.2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InputEntry {
    pub id: String,
    pub message_id: String,
    pub part_index: u32,
    pub kind: PartKind,
    pub media_type: String,
    #[serde(default)]
    pub charset: Option<String>,
    pub canonical_rule: CanonicalRule,
    pub byte_length: u64,
    pub sha256: String,
    pub worker_visible: bool,
    pub processor_visible: bool,
}

/// A required deliverable and its media type.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Deliverable {
    pub role: String,
    pub media_type: String,
}

/// A required evidence slot with its acceptable trust classes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EvidenceSlot {
    pub slot_id: String,
    pub statement_type: String,
    pub trust_classes: Vec<TrustClass>,
}

/// Processor and data-handling constraints.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProcessorConstraints {
    pub disclosure: Disclosure,
}

/// Deadline, response, and cost limits.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Limits {
    pub deadline: String,
    pub max_response_bytes: u64,
    #[serde(default)]
    pub max_cost_microusd: Option<u64>,
}

/// A retention request in days.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RetentionRequest {
    pub days: u32,
}

/// One contract revision (design §10.2). Field-for-field with
/// `spec/ext/contract.v1.schema.json`; construct only via [`parse_payload`],
/// which validates against that schema before deserializing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Contract {
    pub schema_version: u32,
    pub contract_id: String,
    pub revision: u64,
    #[serde(default)]
    pub predecessor_digest: Option<String>,
    pub task_type: String,
    pub message_id: String,
    #[serde(default)]
    pub context_id: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    pub requester: Identity,
    pub performer: Identity,
    pub objective: String,
    pub inputs: Vec<InputEntry>,
    pub deliverables: Vec<Deliverable>,
    pub evidence_slots: Vec<EvidenceSlot>,
    pub requested_capabilities: Vec<Capability>,
    pub processor_constraints: ProcessorConstraints,
    pub limits: Limits,
    pub result_recipient: ResultRecipient,
    #[serde(default)]
    pub retention_request: Option<RetentionRequest>,
    pub created_at: String,
    pub expires_at: String,
}

impl Contract {
    /// Whether this is the initial revision — no predecessor, no existing Task.
    /// The schema already enforces the rev-0/later invariant; this is the typed
    /// read of it.
    pub fn is_revision_zero(&self) -> bool {
        self.revision == 0
    }
}

/// A validated contract plus the digest and canonical bytes it was signed over.
#[derive(Debug, Clone)]
pub struct ParsedContract {
    pub contract: Contract,
    /// SHA-256 (lowercase hex) of the canonical payload — the value a later
    /// revision's `predecessor_digest` and a decision's binding reference.
    pub digest: String,
    /// The exact canonical bytes (what DSSE signed and this digest covers).
    pub payload: Vec<u8>,
}

/// Contract validation failures. Every variant fails the proposal closed.
#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("contract payload is not valid I-JSON: {0}")]
    IJson(#[from] ijson::IJsonError),
    #[error("canonicalization failed: {0}")]
    Jcs(#[from] jcs::JcsError),
    /// The signed bytes are not RFC 8785-canonical — there must be exactly one
    /// representation of a contract (design §10.2).
    #[error("contract payload is not RFC 8785 canonical")]
    NotCanonical,
    #[error("contract failed schema validation: {0}")]
    Schema(#[from] schema::SchemaError),
    #[error("contract shape invalid: {0}")]
    Shape(#[from] serde_json::Error),
}

/// Validates a contract payload and returns the typed contract, its digest, and
/// the canonical bytes.
///
/// The pipeline fails closed at each step: I-JSON (rejects duplicate keys and
/// non-canonical numbers) → the bytes must equal their own RFC 8785
/// canonicalization → JSON Schema Draft 2020-12 (`contract.v1`) → typed
/// deserialization. The digest is the SHA-256 of the (canonical) input bytes.
pub fn parse_payload(payload: &[u8]) -> Result<ParsedContract, ContractError> {
    // I-JSON: duplicate keys and non-canonical numbers are rejected here.
    let value = ijson::parse(payload)?;
    // The signed payload must already be canonical, so the digest covers a
    // single, unambiguous representation.
    let canonical = jcs::canonical_bytes(&value)?;
    if canonical != payload {
        return Err(ContractError::NotCanonical);
    }
    // Schema is the authority on shape, ranges, and the rev-0/later invariant.
    schema::validate(SchemaId::ContractV1, &value)?;
    let contract: Contract = serde_json::from_value(value)?;
    let digest = hex::encode(Sha256::digest(payload));
    Ok(ParsedContract {
        contract,
        digest,
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Extracts the contract instance (`input.value`) from a schema vector and
    /// canonicalizes it the way a signer would before signing, so `parse_payload`
    /// sees the exact bytes a DSSE payload would carry.
    fn canonical(vector: &str) -> Vec<u8> {
        let envelope: Value = serde_json::from_str(vector).unwrap();
        let value = &envelope["input"]["value"];
        jcs::canonical_bytes(value).unwrap()
    }

    const VALID: &str = include_str!("../../../spec/vectors/schema/contract-v1-valid.json");
    const INVALID_REV0_TASKID: &str =
        include_str!("../../../spec/vectors/schema/contract-v1-invalid-rev0-taskid.json");
    const INVALID_UNKNOWN_CAP: &str =
        include_str!("../../../spec/vectors/schema/contract-v1-invalid-unknown-capability.json");

    #[test]
    fn valid_contract_parses_with_a_stable_digest() {
        let payload = canonical(VALID);
        let parsed = parse_payload(&payload).unwrap();
        assert_eq!(parsed.contract.schema_version, 1);
        assert_eq!(parsed.digest.len(), 64);
        assert!(parsed.digest.chars().all(|c| c.is_ascii_hexdigit()));
        // The digest is over exactly the canonical bytes.
        assert_eq!(parsed.payload, payload);
        // Re-parsing the same bytes yields the same digest (deterministic).
        assert_eq!(parse_payload(&payload).unwrap().digest, parsed.digest);
    }

    #[test]
    fn non_canonical_payload_is_rejected() {
        // The pretty-printed vector bytes are valid JSON but not RFC 8785
        // canonical (indentation, key order), so they cannot be a signed payload.
        let pretty = VALID.as_bytes();
        assert!(matches!(
            parse_payload(pretty),
            Err(ContractError::NotCanonical)
        ));
    }

    #[test]
    fn schema_invalid_contract_is_rejected() {
        // Revision 0 must not carry a task_id.
        let payload = canonical(INVALID_REV0_TASKID);
        assert!(matches!(
            parse_payload(&payload),
            Err(ContractError::Schema(_))
        ));
        // An unknown capability enum value is rejected (safety-critical §18).
        let payload = canonical(INVALID_UNKNOWN_CAP);
        assert!(matches!(
            parse_payload(&payload),
            Err(ContractError::Schema(_))
        ));
    }

    #[test]
    fn duplicate_keys_are_rejected_before_schema() {
        let dup = br#"{"schema_version":1,"schema_version":1}"#;
        assert!(matches!(parse_payload(dup), Err(ContractError::IJson(_))));
    }
}
