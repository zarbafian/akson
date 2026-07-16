//! The extension-schema registry: every Axon extension object validates
//! against its embedded, versioned JSON Schema (Draft 2020-12) from
//! `spec/ext/` before any field is trusted.
//!
//! Schemas are self-contained (internal `$defs` only, no remote `$ref`), so
//! compilation can never fetch anything. Instances must come out of
//! [`crate::ijson::parse`] first — schema validation assumes duplicate keys
//! and unsafe numbers were already rejected.

use std::sync::OnceLock;

use serde_json::Value;

use crate::namespace;

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("schema {0:?} failed to compile: {1}")]
    Compile(&'static str, String),
    #[error("instance does not conform to {schema:?}: {first_error}")]
    Invalid {
        schema: &'static str,
        first_error: String,
        error_count: usize,
    },
}

/// Every registered extension schema. Closed enum: an unknown object type is
/// not validatable and therefore not acceptable (design deny-by-default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaId {
    ContractV1,
    DecisionV1,
    KeyBindingV1,
    DeliveryV1,
    ResultManifestV1,
    EvidenceReferenceV1,
    VerifierSummaryV1,
    OutcomeV1,
}

impl SchemaId {
    pub const ALL: [SchemaId; 8] = [
        SchemaId::ContractV1,
        SchemaId::DecisionV1,
        SchemaId::KeyBindingV1,
        SchemaId::DeliveryV1,
        SchemaId::ResultManifestV1,
        SchemaId::EvidenceReferenceV1,
        SchemaId::VerifierSummaryV1,
        SchemaId::OutcomeV1,
    ];

    /// Registry name, matching the `spec/ext/<name>.v1.schema.json` file and
    /// the vector `input.schema` field.
    pub fn name(self) -> &'static str {
        match self {
            SchemaId::ContractV1 => "contract",
            SchemaId::DecisionV1 => "decision",
            SchemaId::KeyBindingV1 => "key-binding",
            SchemaId::DeliveryV1 => "delivery",
            SchemaId::ResultManifestV1 => "result-manifest",
            SchemaId::EvidenceReferenceV1 => "evidence-reference",
            SchemaId::VerifierSummaryV1 => "verifier-summary",
            SchemaId::OutcomeV1 => "outcome",
        }
    }

    pub fn version(self) -> u32 {
        1
    }

    pub fn by_name(name: &str, version: u32) -> Option<SchemaId> {
        SchemaId::ALL
            .into_iter()
            .find(|id| id.name() == name && id.version() == version)
    }

    /// The DSSE `payloadType` / Part media type for this object.
    pub fn payload_media_type(self) -> String {
        namespace::payload_media_type(self.name(), self.version())
    }

    fn source(self) -> &'static str {
        match self {
            SchemaId::ContractV1 => include_str!("../../../spec/ext/contract.v1.schema.json"),
            SchemaId::DecisionV1 => include_str!("../../../spec/ext/decision.v1.schema.json"),
            SchemaId::KeyBindingV1 => {
                include_str!("../../../spec/ext/key-binding.v1.schema.json")
            }
            SchemaId::DeliveryV1 => include_str!("../../../spec/ext/delivery.v1.schema.json"),
            SchemaId::ResultManifestV1 => {
                include_str!("../../../spec/ext/result-manifest.v1.schema.json")
            }
            SchemaId::EvidenceReferenceV1 => {
                include_str!("../../../spec/ext/evidence-reference.v1.schema.json")
            }
            SchemaId::VerifierSummaryV1 => {
                include_str!("../../../spec/ext/verifier-summary.v1.schema.json")
            }
            SchemaId::OutcomeV1 => include_str!("../../../spec/ext/outcome.v1.schema.json"),
        }
    }

    fn validator(self) -> Result<&'static jsonschema::Validator, SchemaError> {
        static VALIDATORS: [OnceLock<jsonschema::Validator>; SchemaId::ALL.len()] =
            [const { OnceLock::new() }; SchemaId::ALL.len()];
        let index = SchemaId::ALL
            .iter()
            .position(|id| *id == self)
            .unwrap_or_default();
        // OnceLock has no fallible init; compile eagerly and store, racing
        // initializations compute the same value.
        if VALIDATORS[index].get().is_none() {
            let schema: Value = serde_json::from_str(self.source())
                .map_err(|e| SchemaError::Compile(self.name(), e.to_string()))?;
            let validator = jsonschema::validator_for(&schema)
                .map_err(|e| SchemaError::Compile(self.name(), e.to_string()))?;
            let _ = VALIDATORS[index].set(validator);
        }
        VALIDATORS[index]
            .get()
            .ok_or_else(|| SchemaError::Compile(self.name(), "initialization raced".to_owned()))
    }
}

/// Cap on how many validation errors are counted, so a hostile instance
/// cannot make error enumeration itself expensive.
const MAX_COUNTED_ERRORS: usize = 64;

/// Validates `instance` against the schema. Fails closed reporting the first
/// error's location and failing keyword only — never the instance value — so
/// error text cannot leak task content, and bounded so it cannot be inflated.
pub fn validate(id: SchemaId, instance: &Value) -> Result<(), SchemaError> {
    let validator = id.validator()?;
    let mut errors = validator.iter_errors(instance);
    if let Some(first) = errors.next() {
        // `masked()` is the library's content-free Display: the failing
        // location and keyword without the instance value. schema_path names
        // which constraint failed. Neither leaks task content.
        let first_error = format!(
            "at {} ({})",
            truncate_on_char_boundary(&first.schema_path.to_string(), 256),
            truncate_on_char_boundary(&first.masked().to_string(), 256),
        );
        // Count remaining errors up to a bound (0 extra means "just this one").
        let error_count = 1 + errors.take(MAX_COUNTED_ERRORS).count();
        Err(SchemaError::Invalid {
            schema: id.name(),
            first_error,
            error_count,
        })
    } else {
        Ok(())
    }
}

/// Truncates to at most `max` bytes without splitting a UTF-8 character
/// (`String::truncate` panics on a non-boundary index).
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_schema_compiles() {
        for id in SchemaId::ALL {
            id.validator().unwrap();
        }
    }

    #[test]
    fn schema_ids_round_trip_by_name() {
        for id in SchemaId::ALL {
            assert_eq!(SchemaId::by_name(id.name(), id.version()), Some(id));
        }
        assert_eq!(SchemaId::by_name("contract", 2), None);
        assert_eq!(SchemaId::by_name("unknown", 1), None);
    }

    #[test]
    fn rejects_non_conforming_instance() {
        let err = validate(SchemaId::OutcomeV1, &serde_json::json!({"state": "done"}));
        assert!(matches!(err, Err(SchemaError::Invalid { .. })));
    }

    #[test]
    fn schema_ids_and_media_types_use_the_namespace() {
        for id in SchemaId::ALL {
            let schema: serde_json::Value = serde_json::from_str(id.source()).unwrap();
            let dollar_id = schema["$id"].as_str().unwrap();
            assert_eq!(
                dollar_id,
                format!(
                    "{}/schema.json",
                    namespace::ext_uri(id.name(), id.version())
                ),
                "schema {} drifted from the namespace module",
                id.name()
            );
            assert_eq!(
                id.payload_media_type(),
                format!("application/vnd.axon-dev.{}.v1+json", id.name())
            );
        }
    }
}
