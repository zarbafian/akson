//! Input-manifest binding (design §10.2): the check that ties every worker-input
//! Part to exactly one contract manifest entry, by digest.
//!
//! This is the safety heart of the contract. The worker only ever sees the Parts
//! the manifest names, digested under the exact rule the contract fixed, so a
//! proposal cannot smuggle an unmanifested Part past review, nor can a Part's
//! bytes differ from what was signed. Every Part must have exactly one entry and
//! every entry exactly one Part; an unmanifested, multiply-referenced,
//! kind-mismatched, or digest-mismatched Part rejects the proposal.
//!
//! What you write:
//! ```
//! use axon_contract::{bind_inputs, InputPart, PartBody};
//! # use axon_contract::parse_payload;
//! # use serde_json::json;
//! # use sha2::{Digest, Sha256};
//! # let text = "review this";
//! # let sha = hex::encode(Sha256::digest(text.as_bytes()));
//! # let value = json!({
//! #   "schema_version": 1, "contract_id": "00000000-0000-4000-8000-000000000000",
//! #   "revision": 0, "task_type": "https://axon.invalid/t", "message_id": "m1",
//! #   "requester": {"issuer": "a", "agent": "b"}, "performer": {"issuer": "c", "agent": "d"},
//! #   "objective": "o",
//! #   "inputs": [{"id": "src", "message_id": "m1", "part_index": 0, "kind": "text",
//! #     "media_type": "text/plain", "charset": "utf-8", "canonical_rule": "utf8-exact",
//! #     "byte_length": text.len(), "sha256": sha, "worker_visible": true, "processor_visible": false}],
//! #   "deliverables": [{"role": "r", "media_type": "text/plain"}], "evidence_slots": [],
//! #   "requested_capabilities": [], "processor_constraints": {"disclosure": "none"},
//! #   "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
//! #   "result_recipient": "request-origin", "created_at": "2026-01-01T00:00:00Z",
//! #   "expires_at": "2030-01-01T00:00:00Z"
//! # });
//! # let payload = axon_ext::jcs::canonical_bytes(&value).unwrap();
//! # let contract = parse_payload(&payload).unwrap().contract;
//! let parts = vec![InputPart {
//!     message_id: "m1".into(),
//!     part_index: 0,
//!     media_type: "text/plain".into(),
//!     body: PartBody::Text("review this".into()),
//! }];
//! bind_inputs(&contract.inputs, &parts).unwrap(); // every Part ↔ exactly one entry
//! ```

use std::collections::HashMap;

use axon_ext::jcs;
use sha2::{Digest, Sha256};

use crate::contract::{CanonicalRule, InputEntry, PartKind};

/// A worker-input Part, reduced to what the manifest binds: its coordinates,
/// media type, and content. The DSSE/Part-extraction layer builds these from a
/// real A2A Message; raw and URL Parts are unsupported in v1 (design §10.2), so
/// only text and data appear here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputPart {
    pub message_id: String,
    pub part_index: u32,
    pub media_type: String,
    pub body: PartBody,
}

/// A Part's content, carrying exactly what its canonical-byte rule digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartBody {
    /// A2A text Part: digested as the exact UTF-8 string bytes (`utf8-exact`).
    Text(String),
    /// A2A data Part: digested as RFC 8785 canonical JSON (`jcs`).
    Data(serde_json::Value),
}

/// Why an input Part failed to bind to the manifest. Each fails the proposal.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindError {
    #[error("Part ({message_id:?}, {part_index}) has no manifest entry")]
    Unmanifested { message_id: String, part_index: u32 },
    #[error("two Parts share coordinates ({message_id:?}, {part_index})")]
    DuplicatePart { message_id: String, part_index: u32 },
    #[error("manifest entries {a:?} and {b:?} reference the same Part")]
    MultiplyReferenced { a: String, b: String },
    #[error("manifest entry {id:?} references a Part that was not supplied")]
    DanglingEntry { id: String },
    #[error("manifest entry {id:?}: content kind does not match the Part")]
    KindMismatch { id: String },
    #[error("manifest entry {id:?}: media type does not match the Part")]
    MediaTypeMismatch { id: String },
    #[error("manifest entry {id:?}: byte length does not match the Part")]
    ByteLengthMismatch { id: String },
    #[error("manifest entry {id:?}: SHA-256 digest does not match the Part")]
    DigestMismatch { id: String },
    #[error("manifest entry {id:?}: data Part is not canonicalizable: {reason}")]
    Canonicalize { id: String, reason: String },
}

/// Binds every supplied worker-input Part to exactly one manifest entry, and
/// every manifest entry to exactly one Part (design §10.2). The contract-control
/// Part is not a worker input and must not appear in `parts`.
///
/// Fails closed on the first violation: an unmanifested Part, two Parts sharing
/// coordinates, two entries naming the same Part, an entry with no Part, or any
/// entry whose kind, media type, byte length, or digest disagrees with its Part.
pub fn bind_inputs(entries: &[InputEntry], parts: &[InputPart]) -> Result<(), BindError> {
    // Index entries by Part coordinates; two entries at the same coordinates
    // means one Part is multiply referenced.
    let mut by_coords: HashMap<(&str, u32), &InputEntry> = HashMap::new();
    for entry in entries {
        if let Some(prior) = by_coords.insert((&entry.message_id, entry.part_index), entry) {
            return Err(BindError::MultiplyReferenced {
                a: prior.id.clone(),
                b: entry.id.clone(),
            });
        }
    }

    // Each Part must resolve to its entry and match it; track which entries are
    // consumed so dangling (Part-less) entries are caught afterward.
    let mut seen_parts: HashMap<(&str, u32), ()> = HashMap::new();
    let mut matched: HashMap<&str, ()> = HashMap::new();
    for part in parts {
        let coords = (part.message_id.as_str(), part.part_index);
        if seen_parts.insert(coords, ()).is_some() {
            return Err(BindError::DuplicatePart {
                message_id: part.message_id.clone(),
                part_index: part.part_index,
            });
        }
        let entry = by_coords
            .get(&coords)
            .ok_or_else(|| BindError::Unmanifested {
                message_id: part.message_id.clone(),
                part_index: part.part_index,
            })?;
        check_part(entry, part)?;
        matched.insert(entry.id.as_str(), ());
    }

    // Every entry must have been matched by a supplied Part.
    for entry in entries {
        if !matched.contains_key(entry.id.as_str()) {
            return Err(BindError::DanglingEntry {
                id: entry.id.clone(),
            });
        }
    }
    Ok(())
}

/// Verifies one Part against its manifest entry: kind, media type, byte length,
/// and the digest under the entry's canonical-byte rule.
fn check_part(entry: &InputEntry, part: &InputPart) -> Result<(), BindError> {
    let id = || entry.id.clone();

    // Kind must agree, and it fixes the canonical rule (schema already couples
    // kind↔rule; this rejects a Part whose body is the wrong kind entirely).
    match (&part.body, entry.kind) {
        (PartBody::Text(_), PartKind::Text) => {}
        (PartBody::Data(_), PartKind::Data) => {}
        _ => return Err(BindError::KindMismatch { id: id() }),
    }
    if entry.media_type != part.media_type {
        return Err(BindError::MediaTypeMismatch { id: id() });
    }

    // Digest the content under the declared rule; text is exact UTF-8, data is
    // RFC 8785 canonical JSON.
    let bytes = match (&part.body, entry.canonical_rule) {
        (PartBody::Text(s), CanonicalRule::Utf8Exact) => s.clone().into_bytes(),
        (PartBody::Data(v), CanonicalRule::Jcs) => {
            jcs::canonical_bytes(v).map_err(|e| BindError::Canonicalize {
                id: id(),
                reason: e.to_string(),
            })?
        }
        // Kind and rule are coupled by the schema, so this pairing is unreachable
        // for a schema-valid contract; reject rather than guess.
        _ => return Err(BindError::KindMismatch { id: id() }),
    };

    if bytes.len() as u64 != entry.byte_length {
        return Err(BindError::ByteLengthMismatch { id: id() });
    }
    if hex::encode(Sha256::digest(&bytes)) != entry.sha256 {
        return Err(BindError::DigestMismatch { id: id() });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text_entry(id: &str, idx: u32, content: &str) -> InputEntry {
        InputEntry {
            id: id.to_owned(),
            message_id: "m1".to_owned(),
            part_index: idx,
            kind: PartKind::Text,
            media_type: "text/plain".to_owned(),
            charset: Some("utf-8".to_owned()),
            canonical_rule: CanonicalRule::Utf8Exact,
            byte_length: content.len() as u64,
            sha256: hex::encode(Sha256::digest(content.as_bytes())),
            worker_visible: true,
            processor_visible: false,
        }
    }

    fn data_entry(id: &str, idx: u32, value: &serde_json::Value) -> InputEntry {
        let bytes = jcs::canonical_bytes(value).unwrap();
        InputEntry {
            id: id.to_owned(),
            message_id: "m1".to_owned(),
            part_index: idx,
            kind: PartKind::Data,
            media_type: "application/json".to_owned(),
            charset: None,
            canonical_rule: CanonicalRule::Jcs,
            byte_length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
            worker_visible: true,
            processor_visible: false,
        }
    }

    fn text_part(idx: u32, content: &str) -> InputPart {
        InputPart {
            message_id: "m1".to_owned(),
            part_index: idx,
            media_type: "text/plain".to_owned(),
            body: PartBody::Text(content.to_owned()),
        }
    }

    #[test]
    fn exact_bijection_binds() {
        let value = json!({"b": 2, "a": 1});
        let entries = vec![text_entry("src", 0, "hello"), data_entry("cfg", 1, &value)];
        let parts = vec![
            text_part(0, "hello"),
            InputPart {
                message_id: "m1".to_owned(),
                part_index: 1,
                media_type: "application/json".to_owned(),
                // A different key order still canonicalizes to the same JCS bytes.
                body: PartBody::Data(json!({"a": 1, "b": 2})),
            },
        ];
        bind_inputs(&entries, &parts).unwrap();
    }

    #[test]
    fn unmanifested_part_rejects() {
        let entries = vec![text_entry("src", 0, "hello")];
        let parts = vec![text_part(0, "hello"), text_part(1, "extra")];
        assert_eq!(
            bind_inputs(&entries, &parts),
            Err(BindError::Unmanifested {
                message_id: "m1".to_owned(),
                part_index: 1,
            })
        );
    }

    #[test]
    fn dangling_entry_rejects() {
        let entries = vec![text_entry("src", 0, "hello"), text_entry("missing", 1, "x")];
        let parts = vec![text_part(0, "hello")];
        assert_eq!(
            bind_inputs(&entries, &parts),
            Err(BindError::DanglingEntry {
                id: "missing".to_owned()
            })
        );
    }

    #[test]
    fn multiply_referenced_part_rejects() {
        let entries = vec![text_entry("a", 0, "hello"), text_entry("b", 0, "hello")];
        let parts = vec![text_part(0, "hello")];
        assert!(matches!(
            bind_inputs(&entries, &parts),
            Err(BindError::MultiplyReferenced { .. })
        ));
    }

    #[test]
    fn digest_mismatch_rejects() {
        let entries = vec![text_entry("src", 0, "hello")];
        let parts = vec![text_part(0, "HELLO")]; // same length, different bytes
        assert_eq!(
            bind_inputs(&entries, &parts),
            Err(BindError::DigestMismatch {
                id: "src".to_owned()
            })
        );
    }

    #[test]
    fn kind_mismatch_rejects() {
        // Manifest says text; the Part is data.
        let entries = vec![text_entry("src", 0, "hello")];
        let parts = vec![InputPart {
            message_id: "m1".to_owned(),
            part_index: 0,
            media_type: "text/plain".to_owned(),
            body: PartBody::Data(json!("hello")),
        }];
        assert_eq!(
            bind_inputs(&entries, &parts),
            Err(BindError::KindMismatch {
                id: "src".to_owned()
            })
        );
    }

    #[test]
    fn media_type_mismatch_rejects() {
        let entries = vec![text_entry("src", 0, "hello")];
        let parts = vec![InputPart {
            message_id: "m1".to_owned(),
            part_index: 0,
            media_type: "text/markdown".to_owned(),
            body: PartBody::Text("hello".to_owned()),
        }];
        assert_eq!(
            bind_inputs(&entries, &parts),
            Err(BindError::MediaTypeMismatch {
                id: "src".to_owned()
            })
        );
    }

    #[test]
    fn empty_manifest_and_no_parts_binds() {
        assert!(bind_inputs(&[], &[]).is_ok());
    }
}
