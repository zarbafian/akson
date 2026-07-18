//! Evidence and requester outcome (design §14) — the producer's signed statement
//! of what a task produced, and the requester's signed acceptance of it.
//!
//! - [`ResultManifest`] — the canonical `result-manifest-v1` (§14.1): sorted
//!   outputs/evidence/slots, schema-valid, RFC 8785-canonical, DSSE-signed by the
//!   task-result key. Its canonical digest is *the* bundle digest.
//! - slot checking (§14.3) — required slots with orthogonal result × disclosure:
//!   redaction can never turn a failure into a pass.
//!
//! Everything here is pure/crypto logic; the durable staged-then-atomic completion
//! and the `axon evidence validate|export` CLI are wired at daemon assembly.

mod outcome;
mod result_manifest;
mod sarif;
mod slots;

pub use outcome::{fixed_receipt, Outcome, OutcomeError, OutcomeState, Receipt};
pub use result_manifest::{
    Disclosure, EvidenceEntry, ManifestError, ManifestHeader, Omission, OutputEntry,
    ResultManifest, SlotRecord, SlotResult,
};
pub use sarif::{parse_sarif, SarifError, SarifFinding, SarifLevel, SarifLimits, SarifReport};
pub use slots::{check_slots, RequiredSlot, SlotError};
