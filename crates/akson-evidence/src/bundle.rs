//! The exportable result bundle (`akson task export` → `akson verify`): one
//! versioned JSON file carrying the DSSE-signed result manifest (§14.1) and the
//! exact output bytes it names, so a result can be checked **offline** by anyone
//! holding the producer's task-result public key — no daemon, no store, no
//! network.
//!
//! What you write:
//! ```
//! use akson_evidence::{BundleOutput, ManifestHeader, OutputEntry, ResultBundle, ResultManifest};
//! # use akson_crypto::keypair::PurposeKey;
//! # use akson_crypto::purpose::KeyPurpose;
//! let output = BundleOutput::from_bytes("art-1", "response", "text/plain", b"reviewed: LGTM");
//! let header = ManifestHeader {
//!     task_id: "task-1".into(), context_id: "ctx-1".into(),
//!     contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".into(),
//!     contract_revision: 0, contract_digest: "a".repeat(64),
//!     attempt_digest: "b".repeat(64), work_order_receipt_digest: "c".repeat(64),
//! };
//! let entry = OutputEntry {
//!     role: output.role.clone(), artifact_id: output.artifact_id.clone(), part_index: 0,
//!     media_type: output.media_type.clone(), byte_length: output.byte_length,
//!     sha256: output.sha256.clone(),
//! };
//! let manifest = ResultManifest::assemble(header, vec![entry], vec![], vec![], vec![]);
//! let key = PurposeKey::from_seed(KeyPurpose::TaskResult, &[7u8; 32]);
//! let bundle = ResultBundle::assemble("task-1", manifest.sign(&key).unwrap(), vec![output], None);
//! let bytes = serde_json::to_vec(&bundle).unwrap();
//! let verified = ResultBundle::from_slice(&bytes).unwrap().verify(&key.verifying()).unwrap();
//! assert_eq!(verified.bundle_digest, manifest.bundle_digest().unwrap());
//! ```
//!
//! What a verified bundle establishes — and only this: the manifest was signed by
//! the holder of the supplied key, and the carried bytes are exactly the bytes
//! that signature covers. It does **not** establish who holds that key (that is
//! the caller's pinning decision), that the work ran in a sandbox, or that the
//! outputs are correct — the `akson verify` report says so line by line.
//!
//! Everything here fails closed and is pure: parsing is capped and typed, and a
//! bundle that cannot be fully verified yields an error naming the first check
//! that failed, never a partial success.

use std::collections::BTreeSet;

use akson_crypto::keypair::PurposeVerifyingKey;
use akson_ext::dsse::Envelope;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::result_manifest::{ManifestError, ResultManifest};
use crate::sarif::{parse_sarif, SarifLimits};

/// The `format` discriminator every result bundle carries.
pub const RESULT_BUNDLE_FORMAT: &str = "akson-result-bundle";

/// The bundle schema version this build emits and accepts.
pub const RESULT_BUNDLE_VERSION: u32 = 1;

/// The largest bundle file this build will parse. Fail-closed: a larger file is
/// refused before any of it is interpreted, so a hostile "bundle" cannot pin
/// unbounded memory behind a verification prompt.
pub const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

/// The media type a SARIF findings output declares (design §14.2).
pub const SARIF_MEDIA_TYPE: &str = "application/sarif+json";

/// One output's bytes and its convenience metadata. The metadata is *redundant
/// on purpose* — the signed manifest is the authority — and [`ResultBundle::verify`]
/// refuses a bundle whose copies contradict it, so a reader skimming the file
/// can never be told something the signature does not cover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleOutput {
    pub artifact_id: String,
    pub role: String,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: String,
    /// The exact output bytes, standard base64 with padding.
    pub content_base64: String,
}

impl BundleOutput {
    /// Builds an output entry from raw bytes, deriving the length, digest, and
    /// base64 — so an assembled bundle can never claim a digest for bytes it
    /// does not carry.
    pub fn from_bytes(artifact_id: &str, role: &str, media_type: &str, bytes: &[u8]) -> Self {
        Self {
            artifact_id: artifact_id.to_owned(),
            role: role.to_owned(),
            media_type: media_type.to_owned(),
            byte_length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
            content_base64: STANDARD.encode(bytes),
        }
    }
}

/// The exporting endpoint's claim about who signed — an **advisory hint**, not
/// proof. A bundle can carry any key here; `akson verify` says plainly that a
/// key taken from the bundle itself establishes internal consistency only.
/// Authorship needs the verifier to pin the key out-of-band (`--signer`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerHint {
    pub issuer: String,
    pub agent: String,
    /// RFC 7638 thumbprint of the exporter's identity root (agent-card) key —
    /// the value an identity token commits to.
    pub root_thumbprint: String,
    /// The exporter's task-result public key, 64 hex characters.
    pub task_result_public_key_hex: String,
    /// RFC 7638 thumbprint of that task-result key (the DSSE `keyid`).
    pub task_result_thumbprint: String,
}

/// A versioned, self-contained export of one task's signed result (§14.1): the
/// manifest envelope plus every output byte it names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultBundle {
    /// Always [`RESULT_BUNDLE_FORMAT`].
    pub format: String,
    /// Always [`RESULT_BUNDLE_VERSION`] for this build.
    pub schema_version: u32,
    /// The task this bundle claims to export — checked against the signed
    /// manifest's own `task_id` at verification.
    pub task_id: String,
    /// The DSSE envelope over the canonical result manifest (§14.1).
    pub manifest_envelope: Envelope,
    pub outputs: Vec<BundleOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerHint>,
}

/// Why a bundle could not be parsed or verified. Every variant names the check
/// that failed; none can be produced by a passing bundle.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("the file is {got} bytes, over the {max}-byte bundle cap")]
    TooLarge { got: usize, max: usize },
    #[error("not an akson result bundle: {0}")]
    NotABundle(String),
    #[error("bundle format {got:?} is not {RESULT_BUNDLE_FORMAT:?}")]
    WrongFormat { got: String },
    #[error("bundle schema_version {got} is not supported by this build (expected {RESULT_BUNDLE_VERSION})")]
    UnsupportedVersion { got: u32 },
    /// The signature or the signed manifest failed — the inner error says which
    /// (`dsse: signature verification failed`, `key id mismatch`, `schema: …`).
    #[error("result manifest: {0}")]
    Manifest(#[from] ManifestError),
    #[error("the bundle claims task {bundle:?} but the signed manifest is for task {manifest:?}")]
    TaskIdMismatch { bundle: String, manifest: String },
    #[error("the signed manifest names artifact {artifact_id:?} more than once")]
    DuplicateManifestArtifact { artifact_id: String },
    #[error("the bundle carries artifact {artifact_id:?} more than once")]
    DuplicateBundleArtifact { artifact_id: String },
    #[error("the bundle does not carry output {artifact_id:?}, which the signed manifest names")]
    OutputMissing { artifact_id: String },
    #[error("the bundle carries output {artifact_id:?}, which the signed manifest does not name")]
    OutputUnbound { artifact_id: String },
    #[error("output {artifact_id:?} is not valid base64")]
    OutputEncoding { artifact_id: String },
    #[error("output {artifact_id:?} does not re-hash to the digest in the signed manifest")]
    OutputDigestMismatch { artifact_id: String },
    #[error("output {artifact_id:?} declares metadata that contradicts the signed manifest")]
    OutputMetadataMismatch { artifact_id: String },
    #[error(
        "output {artifact_id:?} is declared SARIF but does not parse as SARIF 2.1.0: {detail}"
    )]
    Sarif { artifact_id: String, detail: String },
}

/// One SARIF output that parsed under the hostile-input profile (§14.2), for the
/// verification report. Structure only — nothing about the findings' truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SarifCheck {
    pub artifact_id: String,
    pub role: String,
    pub tool_name: String,
    pub findings: usize,
    /// Findings beyond the cap that were counted but not extracted.
    pub truncated_findings: usize,
}

/// What a fully verified bundle established. Holding this value means every
/// check passed; there is no partial form.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    /// The signed, schema-valid, canonically-ordered manifest.
    pub manifest: ResultManifest,
    /// *The* bundle digest (§14.1): SHA-256 over the canonical manifest bytes.
    pub bundle_digest: String,
    /// Total verified output bytes.
    pub payload_bytes: u64,
    /// Every SARIF-typed output, parsed under caps.
    pub sarif: Vec<SarifCheck>,
}

/// The minimal head parsed first, so a wrong format or a future version gets a
/// precise refusal rather than a generic parse error.
#[derive(Deserialize)]
struct BundleHead {
    format: Option<String>,
    schema_version: Option<u32>,
}

impl ResultBundle {
    /// Assembles a bundle. Dumb by design — [`verify`](Self::verify) is the
    /// authority; an exporter must verify its own product before emitting it.
    pub fn assemble(
        task_id: &str,
        manifest_envelope: Envelope,
        outputs: Vec<BundleOutput>,
        signer: Option<SignerHint>,
    ) -> Self {
        Self {
            format: RESULT_BUNDLE_FORMAT.to_owned(),
            schema_version: RESULT_BUNDLE_VERSION,
            task_id: task_id.to_owned(),
            manifest_envelope,
            outputs,
            signer,
        }
    }

    /// Parses a bundle file fail-closed: size cap first, then the format and
    /// version discriminators (so refusals are precise), then the full shape.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BundleError> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge {
                got: bytes.len(),
                max: MAX_BUNDLE_BYTES,
            });
        }
        let head: BundleHead =
            serde_json::from_slice(bytes).map_err(|e| BundleError::NotABundle(e.to_string()))?;
        match head.format.as_deref() {
            Some(RESULT_BUNDLE_FORMAT) => {}
            Some(other) => {
                return Err(BundleError::WrongFormat {
                    got: other.to_owned(),
                })
            }
            None => return Err(BundleError::NotABundle("no format field".to_owned())),
        }
        match head.schema_version {
            Some(RESULT_BUNDLE_VERSION) => {}
            Some(got) => return Err(BundleError::UnsupportedVersion { got }),
            None => {
                return Err(BundleError::NotABundle(
                    "no schema_version field".to_owned(),
                ))
            }
        }
        serde_json::from_slice(bytes).map_err(|e| BundleError::NotABundle(e.to_string()))
    }

    /// Verifies the whole bundle under `key` (a task-result purpose key) and
    /// returns what was established. Fails closed on the first check that does
    /// not hold:
    ///
    /// 1. the DSSE signature over the manifest verifies under `key`, and the
    ///    payload is a canonical, schema-valid, canonically-ordered manifest
    ///    ([`ResultManifest::verify`]);
    /// 2. the bundle's claimed `task_id` is the signed manifest's;
    /// 3. neither the manifest nor the bundle names an artifact twice (the
    ///    requester-side duplicate guard, mirrored);
    /// 4. every manifest-named output is carried, its convenience metadata
    ///    agrees with the signed entry, and its bytes re-hash to the signed
    ///    digest and length; nothing rides along that the manifest does not
    ///    name (mirror of `finalize_result`, §14.5 step 3);
    /// 5. every SARIF-typed output parses as SARIF 2.1.0 under the
    ///    hostile-input caps (§14.2).
    pub fn verify(&self, key: &PurposeVerifyingKey) -> Result<VerifiedBundle, BundleError> {
        // 1. Signature + manifest validity, in one fail-closed call.
        let (manifest, bundle_digest) = ResultManifest::verify(&self.manifest_envelope, key)?;

        // 2. The wrapper must not claim a different task than the signature covers.
        if self.task_id != manifest.header.task_id {
            return Err(BundleError::TaskIdMismatch {
                bundle: self.task_id.clone(),
                manifest: manifest.header.task_id.clone(),
            });
        }

        // 3. Duplicate artifact ids — one carried part must never satisfy two
        // signed entries (or two carried parts one entry).
        let mut seen = BTreeSet::new();
        for entry in &manifest.outputs {
            if !seen.insert(entry.artifact_id.as_str()) {
                return Err(BundleError::DuplicateManifestArtifact {
                    artifact_id: entry.artifact_id.clone(),
                });
            }
        }
        let mut seen = BTreeSet::new();
        for output in &self.outputs {
            if !seen.insert(output.artifact_id.as_str()) {
                return Err(BundleError::DuplicateBundleArtifact {
                    artifact_id: output.artifact_id.clone(),
                });
            }
        }

        // 4. Every named output present, consistent, and re-hashing to the
        // signed digest; 5. SARIF outputs parse under caps.
        let mut payload_bytes = 0u64;
        let mut sarif = Vec::new();
        for entry in &manifest.outputs {
            let Some(output) = self
                .outputs
                .iter()
                .find(|o| o.artifact_id == entry.artifact_id)
            else {
                return Err(BundleError::OutputMissing {
                    artifact_id: entry.artifact_id.clone(),
                });
            };
            if output.role != entry.role
                || output.media_type != entry.media_type
                || output.byte_length != entry.byte_length
                || output.sha256 != entry.sha256
            {
                return Err(BundleError::OutputMetadataMismatch {
                    artifact_id: entry.artifact_id.clone(),
                });
            }
            let bytes = STANDARD.decode(&output.content_base64).map_err(|_| {
                BundleError::OutputEncoding {
                    artifact_id: entry.artifact_id.clone(),
                }
            })?;
            if bytes.len() as u64 != entry.byte_length
                || hex::encode(Sha256::digest(&bytes)) != entry.sha256
            {
                return Err(BundleError::OutputDigestMismatch {
                    artifact_id: entry.artifact_id.clone(),
                });
            }
            payload_bytes = payload_bytes.saturating_add(entry.byte_length);
            if entry.media_type == SARIF_MEDIA_TYPE {
                let report = parse_sarif(&bytes, &SarifLimits::default()).map_err(|e| {
                    BundleError::Sarif {
                        artifact_id: entry.artifact_id.clone(),
                        detail: e.to_string(),
                    }
                })?;
                sarif.push(SarifCheck {
                    artifact_id: entry.artifact_id.clone(),
                    role: entry.role.clone(),
                    tool_name: report.tool_name,
                    findings: report.findings.len(),
                    truncated_findings: report.truncated_findings,
                });
            }
        }
        // An output the manifest does not name is not covered by the signature.
        if self.outputs.len() != manifest.outputs.len() {
            let unbound = self
                .outputs
                .iter()
                .find(|o| {
                    !manifest
                        .outputs
                        .iter()
                        .any(|e| e.artifact_id == o.artifact_id)
                })
                .map(|o| o.artifact_id.clone())
                .unwrap_or_default();
            return Err(BundleError::OutputUnbound {
                artifact_id: unbound,
            });
        }

        Ok(VerifiedBundle {
            manifest,
            bundle_digest,
            payload_bytes,
            sarif,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::result_manifest::{ManifestHeader, OutputEntry};
    use akson_crypto::keypair::PurposeKey;
    use akson_crypto::purpose::KeyPurpose;
    use akson_ext::dsse::DsseError;

    const RESPONSE: &[u8] = b"reviewed: LGTM";

    fn key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::TaskResult, &[7u8; 32])
    }

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

    fn entry_for(output: &BundleOutput, part_index: u32) -> OutputEntry {
        OutputEntry {
            role: output.role.clone(),
            artifact_id: output.artifact_id.clone(),
            part_index,
            media_type: output.media_type.clone(),
            byte_length: output.byte_length,
            sha256: output.sha256.clone(),
        }
    }

    /// A signed one-output bundle over [`RESPONSE`].
    fn bundle() -> ResultBundle {
        let output = BundleOutput::from_bytes("art-1", "response", "text/plain", RESPONSE);
        let manifest = ResultManifest::assemble(
            header(),
            vec![entry_for(&output, 0)],
            vec![],
            vec![],
            vec![],
        );
        ResultBundle::assemble("task-1", manifest.sign(&key()).unwrap(), vec![output], None)
    }

    fn roundtrip(bundle: &ResultBundle) -> ResultBundle {
        ResultBundle::from_slice(&serde_json::to_vec(bundle).unwrap()).unwrap()
    }

    #[test]
    fn a_valid_bundle_round_trips_and_verifies() {
        let verified = roundtrip(&bundle()).verify(&key().verifying()).unwrap();
        assert_eq!(verified.manifest.header.task_id, "task-1");
        assert_eq!(verified.payload_bytes, RESPONSE.len() as u64);
        assert_eq!(verified.bundle_digest.len(), 64);
        assert!(verified.sarif.is_empty());
    }

    #[test]
    fn a_flipped_manifest_byte_fails_naming_the_signature() {
        let mut b = bundle();
        // Flip one byte of the signed payload; the envelope stays well-formed.
        let mut payload = STANDARD.decode(&b.manifest_envelope.payload).unwrap();
        payload[0] ^= 0x01;
        b.manifest_envelope.payload = STANDARD.encode(payload);
        let err = b.verify(&key().verifying()).unwrap_err();
        assert!(
            matches!(
                err,
                BundleError::Manifest(ManifestError::Dsse(DsseError::BadSignature))
            ),
            "must fail on the signature, got: {err}"
        );
        assert!(err.to_string().contains("signature"), "{err}");
    }

    #[test]
    fn a_swapped_output_fails_naming_the_digest_mismatch() {
        let mut b = bundle();
        // The manifest and its signature are untouched; the carried bytes differ.
        b.outputs[0].content_base64 = STANDARD.encode(b"reviewed: SHIP IT");
        let err = b.verify(&key().verifying()).unwrap_err();
        assert!(
            matches!(&err, BundleError::OutputDigestMismatch { artifact_id } if artifact_id == "art-1"),
            "must name the mismatching artifact, got: {err}"
        );
    }

    #[test]
    fn the_wrong_key_is_refused() {
        let wrong = PurposeKey::from_seed(KeyPurpose::TaskResult, &[9u8; 32]);
        let err = bundle().verify(&wrong.verifying()).unwrap_err();
        // The envelope's keyid is the real signer's thumbprint, so the keyid
        // check refuses first — still the signature check, still fail-closed.
        assert!(
            matches!(
                err,
                BundleError::Manifest(ManifestError::Dsse(DsseError::KeyId { .. }))
            ),
            "got: {err}"
        );
    }

    #[test]
    fn a_wrong_purpose_key_is_refused() {
        let outcome_key = PurposeKey::from_seed(KeyPurpose::RequesterOutcome, &[7u8; 32]);
        assert!(bundle().verify(&outcome_key.verifying()).is_err());
    }

    #[test]
    fn a_truncated_bundle_is_a_typed_refusal_never_a_panic() {
        let bytes = serde_json::to_vec(&bundle()).unwrap();
        for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            let err = ResultBundle::from_slice(&bytes[..cut]).unwrap_err();
            assert!(
                matches!(err, BundleError::NotABundle(_)),
                "cut at {cut}: {err}"
            );
        }
    }

    #[test]
    fn a_wrong_format_and_a_future_version_are_refused_precisely() {
        let mut v: serde_json::Value = serde_json::to_value(bundle()).unwrap();
        v["format"] = "akson-other".into();
        let err = ResultBundle::from_slice(&serde_json::to_vec(&v).unwrap()).unwrap_err();
        assert!(matches!(err, BundleError::WrongFormat { got } if got == "akson-other"));

        let mut v: serde_json::Value = serde_json::to_value(bundle()).unwrap();
        v["schema_version"] = 2.into();
        let err = ResultBundle::from_slice(&serde_json::to_vec(&v).unwrap()).unwrap_err();
        assert!(matches!(err, BundleError::UnsupportedVersion { got: 2 }));
    }

    #[test]
    fn an_over_cap_file_is_refused_before_parsing() {
        let err = ResultBundle::from_slice(&vec![b'x'; MAX_BUNDLE_BYTES + 1]).unwrap_err();
        assert!(matches!(err, BundleError::TooLarge { .. }));
    }

    #[test]
    fn a_missing_output_is_refused() {
        let mut b = bundle();
        b.outputs.clear();
        let err = b.verify(&key().verifying()).unwrap_err();
        assert!(
            matches!(&err, BundleError::OutputMissing { artifact_id } if artifact_id == "art-1"),
            "got: {err}"
        );
    }

    #[test]
    fn an_unbound_extra_output_is_refused() {
        let mut b = bundle();
        b.outputs.push(BundleOutput::from_bytes(
            "art-2",
            "extra",
            "text/plain",
            b"unsigned extra",
        ));
        let err = b.verify(&key().verifying()).unwrap_err();
        assert!(
            matches!(&err, BundleError::OutputUnbound { artifact_id } if artifact_id == "art-2"),
            "got: {err}"
        );
    }

    #[test]
    fn a_duplicate_bundle_artifact_is_refused() {
        let mut b = bundle();
        let dup = b.outputs[0].clone();
        b.outputs.push(dup);
        let err = b.verify(&key().verifying()).unwrap_err();
        assert!(
            matches!(err, BundleError::DuplicateBundleArtifact { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn contradicting_convenience_metadata_is_refused() {
        let mut b = bundle();
        // The bytes still hash correctly; only the redundant copy lies.
        b.outputs[0].media_type = "application/zip".to_owned();
        let err = b.verify(&key().verifying()).unwrap_err();
        assert!(
            matches!(err, BundleError::OutputMetadataMismatch { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn a_task_id_contradicting_the_manifest_is_refused() {
        let mut b = bundle();
        b.task_id = "task-2".to_owned();
        let err = b.verify(&key().verifying()).unwrap_err();
        assert!(
            matches!(err, BundleError::TaskIdMismatch { .. }),
            "got: {err}"
        );
    }

    /// A SARIF-typed output must parse under the hostile-input profile; junk that
    /// merely claims the media type is refused, and a genuine log is summarized.
    #[test]
    fn sarif_outputs_are_parsed_under_caps() {
        let sarif = br#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clippy"}},
            "results":[{"ruleId":"unwrap","level":"warning","message":{"text":"avoid unwrap"}}]}]}"#;
        let findings = BundleOutput::from_bytes("art-s", "findings", SARIF_MEDIA_TYPE, sarif);
        let manifest = ResultManifest::assemble(
            header(),
            vec![entry_for(&findings, 0)],
            vec![],
            vec![],
            vec![],
        );
        let good = ResultBundle::assemble(
            "task-1",
            manifest.sign(&key()).unwrap(),
            vec![findings],
            None,
        );
        let verified = good.verify(&key().verifying()).unwrap();
        assert_eq!(verified.sarif.len(), 1);
        assert_eq!(verified.sarif[0].tool_name, "clippy");
        assert_eq!(verified.sarif[0].findings, 1);

        // Genuinely signed junk under the SARIF media type still refuses.
        let junk = BundleOutput::from_bytes("art-s", "findings", SARIF_MEDIA_TYPE, b"{}");
        let manifest =
            ResultManifest::assemble(header(), vec![entry_for(&junk, 0)], vec![], vec![], vec![]);
        let bad =
            ResultBundle::assemble("task-1", manifest.sign(&key()).unwrap(), vec![junk], None);
        let err = bad.verify(&key().verifying()).unwrap_err();
        assert!(matches!(err, BundleError::Sarif { .. }), "got: {err}");
    }
}
