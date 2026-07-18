//! Contract validation, revision chain, decisions, risk-card projection
//! (design §10.2, §9.3, §5.2).
//!
//! M7 is the decision core. The receive path is one call — [`receive_proposal`]
//! — composing the pieces this crate provides, each usable on its own:
//!
//! - [`extract_proposal`] — pull the one contract-control Part and the
//!   worker-input Parts out of an A2A Message (ADR-0012 envelope media type);
//! - [`verify_proposal`] + [`check_proposal_identities`] — DSSE-verify under the
//!   `contract-proposal` key, requester==mTLS-origin, performer==local;
//! - [`parse_payload`] — I-JSON + RFC 8785-canonical + schema + typed
//!   [`Contract`] with its [`digest`](ParsedContract::digest);
//! - [`bind_inputs`] — every worker Part binds to exactly one manifest entry;
//! - [`validity`] — expiry against trusted time;
//! - [`apply_revision`] / [`accept_head`] — the compare-and-swap head;
//! - [`sign_decision`] / [`verify_decision`] — the performer's signed accept,
//!   reject, or revision request, bound to the exact proposal.
//!
//! `receive_proposal` performs no I/O and invokes no model, tool, file, URL, or
//! credential; it returns a validated, inert proposal the caller records as a
//! `submitted` Task and applies to its head.

mod chain;
mod contract;
mod decision;
mod expiry;
mod extraction;
mod manifest;
mod proposal;
mod receive;
mod risk_card;

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
pub use expiry::{expires_at_unix, validity, TimestampError, Validity};
pub use extraction::{extract_proposal, ExtractError, Extracted};
pub use manifest::{bind_inputs, BindError, InputPart, PartBody};
pub use proposal::{check_proposal_identities, sign_proposal, verify_proposal, ProposalError};
pub use receive::{receive_proposal, ReceiveError, ReceivedProposal};
pub use risk_card::{
    project_risk_card, EvidenceDestination, EvidenceSlotCard, ExposedInput, LimitsCard, RiskCard,
    WhatLeaves, WhatRuns, Who,
};
