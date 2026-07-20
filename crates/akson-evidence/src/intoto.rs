//! In-toto Statement v1 attestations (design §14.2).
//!
//! Evidence uses a pinned version of the in-toto Attestation Framework in DSSE
//! envelopes. The v1 profile pins **in-toto Statement v1** with the in-toto
//! payload media type `application/vnd.in-toto+json`. A result bundle may carry
//! independently signed statements — authorization, execution, verification — whose
//! subjects reference the output artifacts and attempt (never the enclosing result
//! manifest, so there is no digest cycle).
//!
//! Akson defines only the minimal predicate *types*; the predicate body is the
//! caller's structured facts. This module builds, signs, and structurally validates
//! the Statement envelope — it does not interpret the predicate.
//!
//! What you write:
//! ```
//! use akson_evidence::{Statement, Subject, PREDICATE_EXECUTION_V1};
//! # use akson_crypto::keypair::PurposeKey;
//! # use akson_crypto::purpose::KeyPurpose;
//! use serde_json::json;
//! let stmt = Statement::new(
//!     vec![Subject::sha256("review.txt", &"d".repeat(64))],
//!     PREDICATE_EXECUTION_V1,
//!     json!({"terminal_state": "succeeded"}),
//! );
//! stmt.validate().unwrap();
//! let key = PurposeKey::from_seed(KeyPurpose::Evidence, &[3u8; 32]);
//! let env = stmt.sign(&key).unwrap();
//! assert_eq!(Statement::verify(&env, &key.verifying()).unwrap(), stmt);
//! ```

use std::collections::BTreeMap;

use akson_crypto::keypair::{PurposeKey, PurposeVerifyingKey};
use akson_crypto::purpose::KeyPurpose;
use akson_ext::dsse::{self, Envelope};
use akson_ext::jcs;
use serde::{Deserialize, Serialize};

use crate::result_manifest::OutputEntry;

/// The in-toto Statement v1 `_type` value.
pub const STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";
/// The DSSE `payloadType` for an in-toto statement (the in-toto envelope media
/// type). Distinct from Akson's own `vnd.akson-dev.*` types (§14.2).
pub const INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Akson's authorization predicate type (request digest, issuer, capability vector,
/// policy decision, executor audience — §14.2).
pub const PREDICATE_AUTHORIZATION_V1: &str = "https://akson.invalid/attestation/authorization/v1";
/// Akson's execution predicate type (materials, processor/runner/sandbox identity,
/// outputs, resource use, terminal state — §14.2).
pub const PREDICATE_EXECUTION_V1: &str = "https://akson.invalid/attestation/execution/v1";

/// One in-toto subject: a name and its digest set (SHA-256).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: DigestSet,
}

impl Subject {
    /// A subject named `name` with a SHA-256 (hex) digest.
    pub fn sha256(name: &str, hex: &str) -> Self {
        Self {
            name: name.to_owned(),
            digest: DigestSet {
                sha256: hex.to_owned(),
            },
        }
    }

    /// The subject for an output artifact Part — `role/artifact_id#part` named,
    /// digested by its SHA-256.
    pub fn from_output(out: &OutputEntry) -> Self {
        Self::sha256(
            &format!("{}/{}#{}", out.role, out.artifact_id, out.part_index),
            &out.sha256,
        )
    }
}

/// An in-toto digest set (design §14.2). SHA-256 only in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestSet {
    pub sha256: String,
}

/// An in-toto Statement v1 (design §14.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

/// Why an in-toto statement could not be built, validated, or verified.
#[derive(Debug, thiserror::Error)]
pub enum StatementError {
    #[error("canonicalization: {0}")]
    Jcs(#[from] akson_ext::jcs::JcsError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("dsse: {0}")]
    Dsse(#[from] dsse::DsseError),
    #[error("key: {0}")]
    Key(#[from] akson_crypto::keypair::KeyError),
    #[error("statement payloadType {got:?} is not the in-toto type")]
    WrongPayloadType { got: String },
    #[error("not a valid in-toto Statement v1: {0}")]
    Invalid(&'static str),
}

impl Statement {
    /// Builds a Statement v1 over `subjects` with `predicate_type` and `predicate`.
    pub fn new(subjects: Vec<Subject>, predicate_type: &str, predicate: serde_json::Value) -> Self {
        Self {
            type_: STATEMENT_TYPE_V1.to_owned(),
            subject: subjects,
            predicate_type: predicate_type.to_owned(),
            predicate,
        }
    }

    /// An execution statement whose subjects are exactly the manifest's outputs
    /// (design §14.2) — the producer/executor self-attestation covering the outputs.
    pub fn execution_over(outputs: &[OutputEntry], predicate: serde_json::Value) -> Self {
        Self::new(
            outputs.iter().map(Subject::from_output).collect(),
            PREDICATE_EXECUTION_V1,
            predicate,
        )
    }

    /// Structurally validates the statement (design §14.2): the pinned `_type`, at
    /// least one subject, each with a 64-hex SHA-256, and a non-empty predicate
    /// type. Does not interpret the predicate.
    pub fn validate(&self) -> Result<(), StatementError> {
        if self.type_ != STATEMENT_TYPE_V1 {
            return Err(StatementError::Invalid("_type is not Statement v1"));
        }
        if self.subject.is_empty() {
            return Err(StatementError::Invalid("no subjects"));
        }
        for s in &self.subject {
            if s.digest.sha256.len() != 64
                || !s.digest.sha256.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(StatementError::Invalid("subject digest is not sha256 hex"));
            }
        }
        if self.predicate_type.is_empty() {
            return Err(StatementError::Invalid("empty predicateType"));
        }
        Ok(())
    }

    /// The RFC 8785-canonical bytes of the statement (validated first).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StatementError> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        Ok(jcs::canonical_bytes(&value)?)
    }

    /// Signs the statement into a DSSE envelope under the evidence key with the
    /// in-toto payload type (design §14.2).
    pub fn sign(&self, key: &PurposeKey) -> Result<Envelope, StatementError> {
        let payload = self.canonical_bytes()?;
        Ok(key.sign_with(KeyPurpose::Evidence, |sk| {
            dsse::sign(INTOTO_PAYLOAD_TYPE, &payload, sk)
        })?)
    }

    /// Verifies an in-toto statement envelope under the `evidence` purpose. Fails
    /// closed unless the key is pinned for `evidence`, the DSSE envelope verifies
    /// (one signature, matching `payloadType`, thumbprint, strict Ed25519), the
    /// payload is canonical I-JSON, and the statement is structurally valid.
    pub fn verify(envelope: &Envelope, key: &PurposeVerifyingKey) -> Result<Self, StatementError> {
        if envelope.payload_type != INTOTO_PAYLOAD_TYPE {
            return Err(StatementError::WrongPayloadType {
                got: envelope.payload_type.clone(),
            });
        }
        let vk = key.key_for(KeyPurpose::Evidence)?;
        let payload = dsse::verify(envelope, INTOTO_PAYLOAD_TYPE, vk)?;
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        if jcs::canonical_bytes(&value)? != payload {
            return Err(StatementError::Invalid("payload is not canonical"));
        }
        let statement: Self = serde_json::from_value(value)?;
        statement.validate()?;
        Ok(statement)
    }

    /// The subject digest map, keyed by subject name — for cross-checking that a
    /// statement covers exactly the expected outputs.
    pub fn subject_digests(&self) -> BTreeMap<String, String> {
        self.subject
            .iter()
            .map(|s| (s.name.clone(), s.digest.sha256.clone()))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn output() -> OutputEntry {
        OutputEntry {
            role: "review".to_owned(),
            artifact_id: "art-1".to_owned(),
            part_index: 0,
            media_type: "text/plain".to_owned(),
            byte_length: 12,
            sha256: "d".repeat(64),
        }
    }

    fn key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::Evidence, &[3u8; 32])
    }

    #[test]
    fn execution_statement_covers_outputs_and_round_trips() {
        let stmt = Statement::execution_over(&[output()], json!({"terminal_state": "succeeded"}));
        stmt.validate().unwrap();
        assert_eq!(
            stmt.subject_digests()
                .get("review/art-1#0")
                .map(String::as_str),
            Some("d".repeat(64).as_str())
        );
        // The subject serializes as in-toto {name, digest:{sha256}}.
        let value = serde_json::to_value(&stmt).unwrap();
        assert_eq!(value["_type"], STATEMENT_TYPE_V1);
        assert_eq!(value["subject"][0]["digest"]["sha256"], "d".repeat(64));

        let env = stmt.sign(&key()).unwrap();
        assert_eq!(env.payload_type, INTOTO_PAYLOAD_TYPE);
        assert_eq!(Statement::verify(&env, &key().verifying()).unwrap(), stmt);
    }

    #[test]
    fn a_bad_subject_digest_is_rejected() {
        let stmt = Statement::new(
            vec![Subject::sha256("x", "not-a-digest")],
            PREDICATE_EXECUTION_V1,
            json!({}),
        );
        assert!(matches!(stmt.validate(), Err(StatementError::Invalid(_))));
    }

    #[test]
    fn no_subjects_is_rejected() {
        let stmt = Statement::new(vec![], PREDICATE_AUTHORIZATION_V1, json!({}));
        assert!(matches!(stmt.validate(), Err(StatementError::Invalid(_))));
    }

    #[test]
    fn a_wrong_purpose_key_fails_closed() {
        let stmt = Statement::execution_over(&[output()], json!({}));
        let env = stmt.sign(&key()).unwrap();
        // A task-result key (wrong purpose) cannot verify evidence.
        let tr = PurposeKey::from_seed(KeyPurpose::TaskResult, &[3u8; 32]);
        assert!(Statement::verify(&env, &tr.verifying()).is_err());
    }
}
