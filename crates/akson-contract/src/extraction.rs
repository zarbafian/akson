//! A2A Message Part extraction (design §10.2): pulling the one contract-control
//! Part and the worker-input Parts out of a received A2A Message.
//!
//! The Message carries exactly one contract-control Part — the `data` Part whose
//! media type is the DSSE-envelope type (ADR-0012). Its `data` value is the DSSE
//! envelope. A missing or second contract Part rejects the request. Every *other*
//! Part is a worker input, reduced to an [`InputPart`] the manifest binds; raw
//! and URL Parts are unsupported in v1. Part indices are preserved from the
//! Message, because a manifest entry references a Part by its 0-based index.
//!
//! This is the shape adapter over the A2A proto; the DSSE verification, identity
//! binding, manifest binding, and expiry are applied on top (see `receive`).

use akson_ext::dsse::Envelope;
use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
use akson_proto::v1::{part::Content, Part};

use crate::manifest::{InputPart, PartBody};

/// The contract-control envelope plus the worker-input Parts, separated out of a
/// Message.
#[derive(Debug, Clone)]
pub struct Extracted {
    /// The DSSE envelope from the one contract-control Part (still unverified).
    pub envelope: Envelope,
    /// Every other Part, as manifest-bindable inputs, with Message indices kept.
    pub inputs: Vec<InputPart>,
}

/// Why a Message could not be separated into a proposal (design §10.2).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtractError {
    #[error("no contract-control Part (no Part carries the DSSE-envelope media type)")]
    MissingContractPart,
    #[error("more than one contract-control Part")]
    MultipleContractParts,
    #[error("the contract-control Part is not a data Part")]
    ContractPartNotData,
    #[error("the contract-control Part's data is not a DSSE envelope")]
    MalformedEnvelope,
    #[error("Part {index} is a raw or URL Part, unsupported in v1")]
    UnsupportedPartKind { index: u32 },
    #[error("Part {index} has no content")]
    EmptyPart { index: u32 },
    #[error("Part {index} data is not representable as JSON")]
    NonJsonData { index: u32 },
}

/// Separates a Message's Parts into the contract envelope and the worker inputs.
///
/// `message_id` is the enclosing Message's id, stamped onto every input so it
/// matches the manifest entries. Fails closed on a missing/second contract Part,
/// a contract Part that is not `data`, an unparseable envelope, or any raw/URL
/// worker Part.
pub fn extract_proposal(message_id: &str, parts: &[Part]) -> Result<Extracted, ExtractError> {
    let mut envelope: Option<Envelope> = None;
    let mut inputs = Vec::new();

    for (idx, part) in parts.iter().enumerate() {
        let index = idx as u32;
        let is_contract = part.media_type == DSSE_ENVELOPE_MEDIA_TYPE;

        match (&part.content, is_contract) {
            // The one contract-control Part: a data Part carrying the envelope.
            (Some(Content::Data(value)), true) => {
                if envelope.is_some() {
                    return Err(ExtractError::MultipleContractParts);
                }
                envelope = Some(parse_envelope(value)?);
            }
            // Envelope media type but not a data Part — malformed.
            (_, true) => return Err(ExtractError::ContractPartNotData),

            // Worker inputs: text digests exact UTF-8, data digests JCS.
            (Some(Content::Text(text)), false) => inputs.push(InputPart {
                message_id: message_id.to_owned(),
                part_index: index,
                media_type: part.media_type.clone(),
                body: PartBody::Text(text.clone()),
            }),
            (Some(Content::Data(value)), false) => {
                let json = to_json(value).ok_or(ExtractError::NonJsonData { index })?;
                inputs.push(InputPart {
                    message_id: message_id.to_owned(),
                    part_index: index,
                    media_type: part.media_type.clone(),
                    body: PartBody::Data(json),
                });
            }
            // Raw and URL Parts are unsupported in v1 (design §10.2).
            (Some(Content::Raw(_)) | Some(Content::Url(_)), false) => {
                return Err(ExtractError::UnsupportedPartKind { index })
            }
            (None, _) => return Err(ExtractError::EmptyPart { index }),
        }
    }

    let envelope = envelope.ok_or(ExtractError::MissingContractPart)?;
    Ok(Extracted { envelope, inputs })
}

/// Converts a protobuf `Value` (protobuf-JSON mapped) to a `serde_json::Value`.
fn to_json(value: &akson_proto::well_known::Value) -> Option<serde_json::Value> {
    serde_json::to_value(value).ok()
}

/// Parses the contract-control Part's data value as a DSSE envelope.
fn parse_envelope(value: &akson_proto::well_known::Value) -> Result<Envelope, ExtractError> {
    let json = to_json(value).ok_or(ExtractError::MalformedEnvelope)?;
    serde_json::from_value(json).map_err(|_| ExtractError::MalformedEnvelope)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use akson_proto::well_known::Value as PbValue;
    use serde_json::json;

    /// A protobuf Value carrying `v` under the protobuf-JSON mapping.
    fn pb(v: serde_json::Value) -> PbValue {
        serde_json::from_value(v).unwrap()
    }

    fn data_part(media_type: &str, v: serde_json::Value) -> Part {
        Part {
            metadata: None,
            filename: String::new(),
            media_type: media_type.to_owned(),
            content: Some(Content::Data(pb(v))),
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

    fn envelope_part(env: &Envelope) -> Part {
        data_part(DSSE_ENVELOPE_MEDIA_TYPE, serde_json::to_value(env).unwrap())
    }

    fn sample_envelope() -> Envelope {
        Envelope {
            payload: "eyJhIjoxfQ==".to_owned(),
            payload_type: "application/vnd.akson-dev.contract.v1+json".to_owned(),
            signatures: vec![akson_ext::dsse::EnvelopeSignature {
                keyid: "kid".to_owned(),
                sig: "AAAA".to_owned(),
            }],
        }
    }

    #[test]
    fn extracts_envelope_and_indexed_inputs() {
        let env = sample_envelope();
        // Contract Part at index 0; two worker inputs at indices 1 and 2.
        let parts = vec![
            envelope_part(&env),
            text_part("review this"),
            data_part("application/json", json!({"k": "v"})),
        ];
        let extracted = extract_proposal("m1", &parts).unwrap();
        assert_eq!(extracted.envelope.payload_type, env.payload_type);
        assert_eq!(extracted.inputs.len(), 2);
        // Indices are the Message positions, not 0..n of the inputs alone.
        assert_eq!(extracted.inputs[0].part_index, 1);
        assert_eq!(extracted.inputs[1].part_index, 2);
        assert_eq!(extracted.inputs[0].message_id, "m1");
        assert!(matches!(extracted.inputs[1].body, PartBody::Data(_)));
    }

    #[test]
    fn missing_contract_part_rejects() {
        let parts = vec![text_part("hi")];
        assert_eq!(
            extract_proposal("m1", &parts).unwrap_err(),
            ExtractError::MissingContractPart
        );
    }

    #[test]
    fn second_contract_part_rejects() {
        let env = sample_envelope();
        let parts = vec![envelope_part(&env), envelope_part(&env)];
        assert_eq!(
            extract_proposal("m1", &parts).unwrap_err(),
            ExtractError::MultipleContractParts
        );
    }

    #[test]
    fn raw_and_url_worker_parts_reject() {
        let env = sample_envelope();
        let raw = Part {
            metadata: None,
            filename: String::new(),
            media_type: "application/octet-stream".to_owned(),
            content: Some(Content::Raw(vec![1, 2, 3])),
        };
        let parts = vec![envelope_part(&env), raw];
        assert_eq!(
            extract_proposal("m1", &parts).unwrap_err(),
            ExtractError::UnsupportedPartKind { index: 1 }
        );
    }

    #[test]
    fn contract_media_type_on_non_data_part_rejects() {
        let bad = Part {
            metadata: None,
            filename: String::new(),
            media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
            content: Some(Content::Text("not an envelope".to_owned())),
        };
        assert_eq!(
            extract_proposal("m1", &[bad]).unwrap_err(),
            ExtractError::ContractPartNotData
        );
    }

    #[test]
    fn envelope_media_type_but_not_an_envelope_rejects() {
        // A data Part with the envelope media type but a non-envelope shape.
        let parts = vec![data_part(DSSE_ENVELOPE_MEDIA_TYPE, json!({"not": "dsse"}))];
        assert_eq!(
            extract_proposal("m1", &parts).unwrap_err(),
            ExtractError::MalformedEnvelope
        );
    }
}
