//! Local authority: the orthogonal capability vector, one-shot work orders, the
//! claim/nonce/budget state machine, and deny/allow-once policy (design §12).
//!
//! Authority in Axon is never a bearer token a peer holds; it exists only in a
//! locally issued, one-shot work order addressed to a local executor (§12.2).
//! This crate builds those authorizations from local decisions.
//!
//! The first piece is the [`CapabilityVector`] (§12.1): independent, non-implying
//! components, of which only v1's four are grantable.

mod attempt;
mod capability;
mod work_order;

pub use attempt::{next, AttemptEvent, AttemptState, TransitionError};
pub use capability::{
    ArtifactExportScope, CapabilityComponent, CapabilityVector, Grant, ProcessorUseScope,
    ReadInputsScope, RespondScope, VectorError,
};
pub use work_order::{
    Audience, Budgets, IssuedWorkOrder, RemoteCancelCaveat, RequestOrigin, WorkOrder,
    WorkOrderError, WorkOrderKey,
};
