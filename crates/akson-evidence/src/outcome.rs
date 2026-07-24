//! The requester outcome (design §14.5) — the requester's signed
//! accept/reject/dispute of a completed task, and the producer's fixed receipt.
//!
//! Producer completion and requester acceptance are separate. After validating the
//! result manifest, the requester signs an [`Outcome`] that binds the exact
//! canonical result-manifest digest (the bundle digest) and the accepted contract
//! revision. An outcome cannot change what ran; a `disputed` outcome preserves all
//! prior evidence.
//!
//! A2A forbids attaching another Message to a terminal Task, so the outcome travels
//! as a *task-less* SendMessage (same Context, `referenceTaskIds` = the completed
//! task, no `taskId`). The producer records it and returns a
//! [`fixed receipt`](fixed_receipt) — a direct acknowledgment generated **without a
//! model or tool**.
//!
//! What you write:
//! ```
//! # use akson_evidence::{ManifestHeader, OutputEntry, ResultManifest, Outcome, OutcomeState};
//! # use akson_contract::Identity;
//! # use akson_crypto::keypair::PurposeKey;
//! # use akson_crypto::purpose::KeyPurpose;
//! # let header = ManifestHeader { task_id: "task-1".into(), context_id: "ctx-1".into(),
//! #   contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".into(), contract_revision: 0,
//! #   contract_digest: "a".repeat(64), attempt_digest: "b".repeat(64),
//! #   work_order_receipt_digest: "c".repeat(64) };
//! # let out = OutputEntry { role: "review".into(), artifact_id: "art-1".into(),
//! #   part_index: 0, media_type: "text/plain".into(), byte_length: 12, sha256: "d".repeat(64) };
//! let manifest = ResultManifest::assemble(header, vec![out], vec![], vec![], vec![]);
//! let requester = Identity { issuer: "iss".into(), agent: "requester".into(), root: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into() };
//! let outcome = Outcome::for_manifest(
//!     &manifest, OutcomeState::Accepted, requester, "2026-07-18T00:00:00Z".into()).unwrap();
//! // The outcome binds exactly this manifest.
//! outcome.check_binds_to(&manifest).unwrap();
//! let key = PurposeKey::from_seed(KeyPurpose::RequesterOutcome, &[9u8; 32]);
//! let env = outcome.sign(&key).unwrap();
//! assert_eq!(Outcome::verify(&env, &key.verifying()).unwrap(), outcome);
//! ```

use akson_contract::Identity;
use akson_crypto::keypair::{PurposeKey, PurposeVerifyingKey};
use akson_crypto::purpose::KeyPurpose;
use akson_ext::dsse::{self, Envelope};
use akson_ext::jcs;
use akson_ext::schema::{self, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::result_manifest::{ManifestError, ResultManifest};

/// The requester's disposition of a completed task (design §14.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeState {
    Accepted,
    Rejected,
    Disputed,
}

/// A signed requester outcome (design §14.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub schema_version: u32,
    pub task_id: String,
    pub context_id: String,
    pub contract_id: String,
    pub contract_revision: u64,
    pub contract_digest: String,
    /// The canonical result-manifest digest — the bundle digest (§14.1).
    pub result_manifest_digest: String,
    pub state: OutcomeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub requester: Identity,
    pub signed_at: String,
}

/// Why an outcome could not be built, validated, verified, or bound.
#[derive(Debug, thiserror::Error)]
pub enum OutcomeError {
    #[error("schema: {0}")]
    Schema(#[from] schema::SchemaError),
    #[error("canonicalization: {0}")]
    Jcs(#[from] akson_ext::jcs::JcsError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("dsse: {0}")]
    Dsse(#[from] dsse::DsseError),
    #[error("key: {0}")]
    Key(#[from] akson_crypto::keypair::KeyError),
    #[error("manifest: {0}")]
    Manifest(#[from] ManifestError),
    #[error("outcome payloadType {got:?} is not the outcome type")]
    WrongPayloadType { got: String },
    #[error("outcome does not bind to the manifest: {0}")]
    Binding(&'static str),
}

impl Outcome {
    /// Builds an outcome that binds `manifest` — copies its task/contract binding and
    /// its bundle digest (design §14.5). Add a reason/note with the builders.
    pub fn for_manifest(
        manifest: &ResultManifest,
        state: OutcomeState,
        requester: Identity,
        signed_at: String,
    ) -> Result<Self, OutcomeError> {
        Ok(Self {
            schema_version: 1,
            task_id: manifest.header.task_id.clone(),
            context_id: manifest.header.context_id.clone(),
            contract_id: manifest.header.contract_id.clone(),
            contract_revision: manifest.header.contract_revision,
            contract_digest: manifest.header.contract_digest.clone(),
            result_manifest_digest: manifest.bundle_digest()?,
            state,
            reason_code: None,
            note: None,
            requester,
            signed_at,
        })
    }

    /// Attaches a bounded reason code (builder).
    pub fn with_reason(mut self, reason_code: &str) -> Self {
        self.reason_code = Some(reason_code.to_owned());
        self
    }

    /// Attaches a human note (builder).
    pub fn with_note(mut self, note: &str) -> Self {
        self.note = Some(note.to_owned());
        self
    }

    /// Validates against `outcome.v1` (design §14.5).
    pub fn validate(&self) -> Result<(), OutcomeError> {
        let value = serde_json::to_value(self)?;
        schema::validate(SchemaId::OutcomeV1, &value)?;
        Ok(())
    }

    /// The RFC 8785-canonical bytes (validated first).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OutcomeError> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        Ok(jcs::canonical_bytes(&value)?)
    }

    /// A content-address of the outcome (its digest).
    pub fn digest(&self) -> Result<String, OutcomeError> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }

    /// Confirms the outcome binds `manifest` exactly (design §14.5): the bundle
    /// digest and the whole contract binding must match. A recipient checks this so
    /// an outcome cannot be replayed against a different result.
    pub fn check_binds_to(&self, manifest: &ResultManifest) -> Result<(), OutcomeError> {
        if self.result_manifest_digest != manifest.bundle_digest()? {
            return Err(OutcomeError::Binding("result-manifest digest"));
        }
        let h = &manifest.header;
        if self.task_id != h.task_id
            || self.context_id != h.context_id
            || self.contract_id != h.contract_id
            || self.contract_revision != h.contract_revision
            || self.contract_digest != h.contract_digest
        {
            return Err(OutcomeError::Binding("contract binding"));
        }
        Ok(())
    }

    /// Signs the outcome into a DSSE envelope under the requester-outcome key
    /// (design §14.5). Schema-validated before signing.
    pub fn sign(&self, key: &PurposeKey) -> Result<Envelope, OutcomeError> {
        let payload = self.canonical_bytes()?;
        let payload_type = SchemaId::OutcomeV1.payload_media_type();
        Ok(key.sign_with(KeyPurpose::RequesterOutcome, |sk| {
            dsse::sign(&payload_type, &payload, sk)
        })?)
    }

    /// Verifies an outcome envelope under the `requester-outcome` purpose. Fails
    /// closed unless the key is pinned for that purpose, the DSSE envelope verifies
    /// (one signature, matching `payloadType`, thumbprint, strict Ed25519), and the
    /// SECURITY NOTE (sec5 review, latent until an outcome-receive route
    /// exists): this verifies under the supplied key only — `requester.root`
    /// stays self-asserted. A future receiver must resolve the key from the
    /// requester's root-bound peer record before trusting the binding.
    /// canonical I-JSON payload validates against the schema.
    pub fn verify(envelope: &Envelope, key: &PurposeVerifyingKey) -> Result<Self, OutcomeError> {
        let payload_type = SchemaId::OutcomeV1.payload_media_type();
        if envelope.payload_type != payload_type {
            return Err(OutcomeError::WrongPayloadType {
                got: envelope.payload_type.clone(),
            });
        }
        let vk = key.key_for(KeyPurpose::RequesterOutcome)?;
        let payload = dsse::verify(envelope, &payload_type, vk)?;
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        schema::validate(SchemaId::OutcomeV1, &value)?;
        if jcs::canonical_bytes(&value)? != payload {
            return Err(OutcomeError::Binding("payload is not canonical"));
        }
        Ok(serde_json::from_value(value)?)
    }
}

/// The producer's fixed acknowledgment of a recorded outcome (design §14.5): a
/// direct Message receipt generated **without a model or tool**. It is a constant
/// shape binding the outcome digest and Context — never model output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Always `true` — a fixed acknowledgment, not a decision.
    pub received: bool,
    pub context_id: String,
    pub reference_task_id: String,
    /// The digest of the outcome being acknowledged.
    pub outcome_digest: String,
}

/// Builds the fixed receipt for a recorded outcome (design §14.5). Deterministic and
/// content-free: it binds the outcome's Context, task, and digest, and is generated
/// without any model or tool.
pub fn fixed_receipt(outcome: &Outcome) -> Result<Receipt, OutcomeError> {
    Ok(Receipt {
        received: true,
        context_id: outcome.context_id.clone(),
        reference_task_id: outcome.task_id.clone(),
        outcome_digest: outcome.digest()?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::result_manifest::{ManifestHeader, OutputEntry};

    fn manifest() -> ResultManifest {
        let header = ManifestHeader {
            task_id: "task-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
            contract_revision: 0,
            contract_digest: "a".repeat(64),
            attempt_digest: "b".repeat(64),
            work_order_receipt_digest: "c".repeat(64),
        };
        let out = OutputEntry {
            role: "review".to_owned(),
            artifact_id: "art-1".to_owned(),
            part_index: 0,
            media_type: "text/plain".to_owned(),
            byte_length: 12,
            sha256: "d".repeat(64),
        };
        ResultManifest::assemble(header, vec![out], vec![], vec![], vec![])
    }

    fn requester() -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: "requester".to_owned(),
            root: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        }
    }

    fn outcome() -> Outcome {
        Outcome::for_manifest(
            &manifest(),
            OutcomeState::Accepted,
            requester(),
            "2026-07-18T00:00:00Z".to_owned(),
        )
        .unwrap()
    }

    fn key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::RequesterOutcome, &[9u8; 32])
    }

    #[test]
    fn binds_the_manifest_and_round_trips() {
        let o = outcome();
        o.validate().unwrap();
        o.check_binds_to(&manifest()).unwrap();
        assert_eq!(
            o.result_manifest_digest,
            manifest().bundle_digest().unwrap()
        );

        let env = o.sign(&key()).unwrap();
        assert_eq!(Outcome::verify(&env, &key().verifying()).unwrap(), o);
    }

    #[test]
    fn does_not_bind_a_different_manifest() {
        let o = outcome();
        // A manifest with a different attempt digest → different bundle digest.
        let other = {
            let mut h = manifest().header.clone();
            h.attempt_digest = "e".repeat(64);
            let out = OutputEntry {
                role: "review".to_owned(),
                artifact_id: "art-1".to_owned(),
                part_index: 0,
                media_type: "text/plain".to_owned(),
                byte_length: 12,
                sha256: "d".repeat(64),
            };
            ResultManifest::assemble(h, vec![out], vec![], vec![], vec![])
        };
        assert!(matches!(
            o.check_binds_to(&other),
            Err(OutcomeError::Binding(_))
        ));
    }

    #[test]
    fn a_wrong_purpose_key_fails_closed() {
        let env = outcome().sign(&key()).unwrap();
        let result_key = PurposeKey::from_seed(KeyPurpose::TaskResult, &[9u8; 32]);
        assert!(Outcome::verify(&env, &result_key.verifying()).is_err());
    }

    #[test]
    fn fixed_receipt_binds_the_outcome() {
        let o = outcome();
        let receipt = fixed_receipt(&o).unwrap();
        assert!(receipt.received);
        assert_eq!(receipt.context_id, "ctx-1");
        assert_eq!(receipt.reference_task_id, "task-1");
        assert_eq!(receipt.outcome_digest, o.digest().unwrap());
    }

    #[test]
    fn reason_and_note_builders_validate() {
        let o = outcome()
            .with_reason("insufficient-evidence")
            .with_note("please add the license scan");
        o.validate().unwrap();
        assert_eq!(o.reason_code.as_deref(), Some("insufficient-evidence"));
    }
}
