//! Contract validation, revision chain, decisions, risk-card projection
//! (design §10.2, §9.3, §5.2).
//!
//! M7 builds the decision core: extract the one contract-control Part, verify
//! its DSSE envelope under a `contract-proposal`-pinned key, validate the
//! payload (I-JSON + RFC 8785 canonical + JSON Schema), bind every other Part to
//! exactly one input-manifest entry, chain revisions under a compare-and-swap
//! head, and sign accept/reject/revision-request decisions.
//!
//! This module lands the first piece — the payload validate-and-digest spine
//! ([`parse_payload`]). Later pieces (Part extraction + identity binding, input
//! manifest binding, revision chain, decisions) build on the [`Contract`] and
//! the [`digest`](ParsedContract::digest) it produces.

mod contract;
mod manifest;

pub use contract::{
    parse_payload, CanonicalRule, Capability, Contract, ContractError, Deliverable, Disclosure,
    EvidenceSlot, Identity, InputEntry, Limits, ParsedContract, PartKind, ProcessorConstraints,
    ResultRecipient, RetentionRequest, TrustClass,
};
pub use manifest::{bind_inputs, BindError, InputPart, PartBody};
