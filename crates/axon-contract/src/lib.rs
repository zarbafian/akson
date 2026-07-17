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

mod chain;
mod contract;
mod decision;
mod manifest;
mod proposal;

pub use chain::{
    accept_head, apply_revision, Head, HeadState, LockError, RevisionVerdict, StaleReason,
};
pub use contract::{
    parse_payload, CanonicalRule, Capability, Contract, ContractError, Deliverable, Disclosure,
    EvidenceSlot, Identity, InputEntry, Limits, ParsedContract, PartKind, ProcessorConstraints,
    ResultRecipient, RetentionRequest, TrustClass,
};
pub use decision::{
    check_binds_to, sign_decision, verify_decision, Decision, DecisionError, DecisionKind,
};
pub use manifest::{bind_inputs, BindError, InputPart, PartBody};
pub use proposal::{check_proposal_identities, sign_proposal, verify_proposal, ProposalError};
