//! The canonical result manifest (design §14.1) — the producer's signed statement
//! of exactly what a task produced.
//!
//! It names the task/contract/attempt it belongs to, and the sorted output
//! Artifacts, evidence statements, required-slot results, and declared omissions.
//! Array order is *normative* — bytewise by role, then object identifier, part
//! index, and digest — and enforced here by [`assemble`](ResultManifest::assemble),
//! not by the schema. The manifest is I-JSON, schema-valid, RFC 8785-canonical, and
//! DSSE-signed by the producer's task-result key. Its canonical digest is *the*
//! "bundle digest" the requester outcome binds (§14.1).
//!
//! Evidence statements reference the output subjects and attempt, never the
//! enclosing manifest — so there is no digest cycle.
//!
//! What you write:
//! ```
//! use akson_evidence::{ManifestHeader, OutputEntry, ResultManifest};
//! # use akson_crypto::keypair::PurposeKey;
//! # use akson_crypto::purpose::KeyPurpose;
//! let header = ManifestHeader {
//!     task_id: "task-1".into(), context_id: "ctx-1".into(),
//!     contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".into(),
//!     contract_revision: 0, contract_digest: "a".repeat(64),
//!     attempt_digest: "b".repeat(64), work_order_receipt_digest: "c".repeat(64),
//! };
//! let out = OutputEntry {
//!     role: "review".into(), artifact_id: "art-1".into(), part_index: 0,
//!     media_type: "text/plain".into(), byte_length: 12, sha256: "d".repeat(64),
//! };
//! let manifest = ResultManifest::assemble(header, vec![out], vec![], vec![], vec![]);
//! manifest.validate().unwrap();
//! let key = PurposeKey::from_seed(KeyPurpose::TaskResult, &[7u8; 32]);
//! let envelope = manifest.sign(&key).unwrap();
//! assert_eq!(ResultManifest::verify(&envelope, &key.verifying()).unwrap().0, manifest);
//! ```

use akson_crypto::keypair::{PurposeKey, PurposeVerifyingKey};
use akson_crypto::purpose::KeyPurpose;
use akson_ext::dsse::{self, Envelope};
use akson_ext::schema::{self, SchemaId};
use akson_ext::{jcs, namespace};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The manifest's task/contract/attempt binding (design §14.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestHeader {
    pub task_id: String,
    pub context_id: String,
    pub contract_id: String,
    pub contract_revision: u64,
    pub contract_digest: String,
    pub attempt_digest: String,
    pub work_order_receipt_digest: String,
}

/// One output Artifact Part (design §14.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputEntry {
    pub role: String,
    pub artifact_id: String,
    pub part_index: u32,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: String,
}

/// One evidence statement reference (design §14.1). Referenced by role from a slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub role: String,
    pub payload_type: String,
    pub byte_length: u64,
    pub sha256: String,
    pub signer_keyid: String,
}

/// The result of a required evidence slot and how much it discloses (design §14.3).
/// The two fields are orthogonal — a redacted view never turns a failure into a
/// pass. `result` in {passed, failed, error} requires an `evidence_role`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotRecord {
    pub slot_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_role: Option<String>,
    pub result: SlotResult,
    pub disclosure: Disclosure,
}

/// A slot's outcome (design §14.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotResult {
    Passed,
    Failed,
    Error,
    NotRun,
    Unavailable,
}

/// How much a slot's evidence is disclosed (design §14.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disclosure {
    Full,
    Summary,
    Redacted,
}

/// A declared omission or redaction (design §14.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Omission {
    pub subject: String,
    pub reason_code: String,
}

/// The canonical result manifest (design §14.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultManifest {
    pub schema_version: u32,
    #[serde(flatten)]
    pub header: ManifestHeader,
    pub outputs: Vec<OutputEntry>,
    pub evidence: Vec<EvidenceEntry>,
    pub slots: Vec<SlotRecord>,
    pub omissions: Vec<Omission>,
}

/// Why a result manifest could not be built, validated, or verified.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
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
    #[error("manifest payloadType {got:?} is not the result-manifest type")]
    WrongPayloadType { got: String },
    #[error("manifest arrays are not in the normative canonical order (§14.1)")]
    NotCanonicalOrder,
}

impl ResultManifest {
    /// Assembles a manifest and puts every array in the normative canonical order
    /// (design §14.1): outputs by (role, artifact_id, part_index, sha256), evidence
    /// by (role, payload_type, sha256), slots by slot_id, omissions by (subject,
    /// reason_code). Assembling is deterministic — the same inputs in any order
    /// yield the same manifest bytes.
    pub fn assemble(
        header: ManifestHeader,
        mut outputs: Vec<OutputEntry>,
        mut evidence: Vec<EvidenceEntry>,
        mut slots: Vec<SlotRecord>,
        mut omissions: Vec<Omission>,
    ) -> Self {
        outputs.sort_by(|a, b| {
            (&a.role, &a.artifact_id, a.part_index, &a.sha256).cmp(&(
                &b.role,
                &b.artifact_id,
                b.part_index,
                &b.sha256,
            ))
        });
        evidence.sort_by(|a, b| {
            (&a.role, &a.payload_type, &a.sha256).cmp(&(&b.role, &b.payload_type, &b.sha256))
        });
        slots.sort_by(|a, b| a.slot_id.cmp(&b.slot_id));
        omissions.sort_by(|a, b| (&a.subject, &a.reason_code).cmp(&(&b.subject, &b.reason_code)));
        Self {
            schema_version: 1,
            header,
            outputs,
            evidence,
            slots,
            omissions,
        }
    }

    /// Validates the manifest against `result-manifest.v1` (design §14.1) and
    /// confirms every array is in the normative canonical order. RFC 8785 sorts
    /// object *keys* but not array *elements*, so the ordering is not implied by
    /// canonicalization — a re-ordered manifest that still canonicalizes is rejected
    /// here rather than silently accepted.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let value = serde_json::to_value(self)?;
        schema::validate(SchemaId::ResultManifestV1, &value)?;
        if !self.is_canonically_ordered() {
            return Err(ManifestError::NotCanonicalOrder);
        }
        Ok(())
    }

    /// Whether every array is in the normative canonical order (design §14.1) — the
    /// order [`assemble`](Self::assemble) produces.
    fn is_canonically_ordered(&self) -> bool {
        self.outputs.is_sorted_by(|a, b| {
            (&a.role, &a.artifact_id, a.part_index, &a.sha256)
                <= (&b.role, &b.artifact_id, b.part_index, &b.sha256)
        }) && self.evidence.is_sorted_by(|a, b| {
            (&a.role, &a.payload_type, &a.sha256) <= (&b.role, &b.payload_type, &b.sha256)
        }) && self.slots.is_sorted_by(|a, b| a.slot_id <= b.slot_id)
            && self
                .omissions
                .is_sorted_by(|a, b| (&a.subject, &a.reason_code) <= (&b.subject, &b.reason_code))
    }

    /// The RFC 8785-canonical bytes of the manifest (validated first).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        Ok(jcs::canonical_bytes(&value)?)
    }

    /// *The* bundle digest (design §14.1): SHA-256 (hex) over the canonical bytes.
    /// The requester outcome binds exactly this value.
    pub fn bundle_digest(&self) -> Result<String, ManifestError> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }

    /// Signs the manifest into a DSSE envelope under the producer's task-result key
    /// (design §14.1). Schema-validated before signing, so a malformed manifest is
    /// never emitted.
    pub fn sign(&self, key: &PurposeKey) -> Result<Envelope, ManifestError> {
        let payload = self.canonical_bytes()?;
        let payload_type = SchemaId::ResultManifestV1.payload_media_type();
        Ok(key.sign_with(KeyPurpose::TaskResult, |sk| {
            dsse::sign(&payload_type, &payload, sk)
        })?)
    }

    /// Verifies a manifest envelope under the `task-result` purpose and returns the
    /// typed manifest and its bundle digest. Fails closed unless the key is pinned
    /// for `task-result`, the DSSE envelope verifies (one signature, matching
    /// `payloadType`, thumbprint, strict Ed25519), the payload is canonical I-JSON,
    /// and it validates against the schema.
    pub fn verify(
        envelope: &Envelope,
        key: &PurposeVerifyingKey,
    ) -> Result<(Self, String), ManifestError> {
        let payload_type = SchemaId::ResultManifestV1.payload_media_type();
        if envelope.payload_type != payload_type {
            return Err(ManifestError::WrongPayloadType {
                got: envelope.payload_type.clone(),
            });
        }
        let vk = key.key_for(KeyPurpose::TaskResult)?;
        let payload = dsse::verify(envelope, &payload_type, vk)?;
        // Re-assert the payload is canonical I-JSON and schema-valid.
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        schema::validate(SchemaId::ResultManifestV1, &value)?;
        if jcs::canonical_bytes(&value)? != payload {
            return Err(ManifestError::WrongPayloadType {
                got: namespace::DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
            });
        }
        let manifest: Self = serde_json::from_value(value)?;
        // Re-assert normative array ordering (codex review): JCS canonicalizes object
        // keys but not array order, so a signed manifest with non-canonically-ordered
        // outputs/evidence would otherwise verify and carry a divergent bundle digest.
        manifest.validate()?;
        let digest = hex::encode(Sha256::digest(&payload));
        Ok((manifest, digest))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn header() -> ManifestHeader {
        ManifestHeader {
            task_id: "task-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
            contract_revision: 0,
            contract_digest: "a".repeat(64),
            attempt_digest: "b".repeat(64),
            work_order_receipt_digest: "c".repeat(64),
        }
    }

    fn output(role: &str, artifact: &str, idx: u32) -> OutputEntry {
        OutputEntry {
            role: role.to_owned(),
            artifact_id: artifact.to_owned(),
            part_index: idx,
            media_type: "text/plain".to_owned(),
            byte_length: 12,
            sha256: "d".repeat(64),
        }
    }

    fn key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::TaskResult, &[7u8; 32])
    }

    #[test]
    fn assemble_sorts_outputs_canonically() {
        let manifest = ResultManifest::assemble(
            header(),
            vec![output("z-role", "art-2", 1), output("a-role", "art-1", 0)],
            vec![],
            vec![],
            vec![],
        );
        // Sorted by role first.
        assert_eq!(manifest.outputs[0].role, "a-role");
        assert_eq!(manifest.outputs[1].role, "z-role");
        // Re-assembling in the other order yields identical bytes.
        let other = ResultManifest::assemble(
            header(),
            vec![output("a-role", "art-1", 0), output("z-role", "art-2", 1)],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(
            manifest.canonical_bytes().unwrap(),
            other.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn validates_and_signs_round_trip() {
        let manifest = ResultManifest::assemble(
            header(),
            vec![output("review", "art-1", 0)],
            vec![],
            vec![],
            vec![],
        );
        manifest.validate().unwrap();
        let digest = manifest.bundle_digest().unwrap();
        assert_eq!(digest.len(), 64);

        let env = manifest.sign(&key()).unwrap();
        let (back, vdigest) = ResultManifest::verify(&env, &key().verifying()).unwrap();
        assert_eq!(back, manifest);
        assert_eq!(vdigest, digest);
    }

    #[test]
    fn a_wrong_purpose_key_fails_closed() {
        let manifest = ResultManifest::assemble(
            header(),
            vec![output("review", "art-1", 0)],
            vec![],
            vec![],
            vec![],
        );
        let env = manifest.sign(&key()).unwrap();
        // Verifying with an outcome key (wrong purpose) is refused.
        let outcome_key = PurposeKey::from_seed(KeyPurpose::RequesterOutcome, &[7u8; 32]);
        assert!(ResultManifest::verify(&env, &outcome_key.verifying()).is_err());
    }

    #[test]
    fn a_manifest_with_no_outputs_is_rejected() {
        // The schema requires at least one output.
        let manifest = ResultManifest::assemble(header(), vec![], vec![], vec![], vec![]);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn a_reordered_manifest_is_rejected() {
        // Hand-build a manifest whose outputs are NOT in canonical order (bypassing
        // assemble's sort). It is schema-valid and canonicalizes fine, but the
        // normative array order must be enforced by code.
        let manifest = ResultManifest {
            schema_version: 1,
            header: header(),
            outputs: vec![output("z-role", "art-2", 1), output("a-role", "art-1", 0)],
            evidence: vec![],
            slots: vec![],
            omissions: vec![],
        };
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::NotCanonicalOrder)
        ));
    }
}
