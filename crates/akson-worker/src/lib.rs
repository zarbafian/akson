//! Clean worker protocol and output gate (design §7.2 step 10, §13.1).
//!
//! The clean worker receives only the exact approved inputs — [staged](staging)
//! into a read-only directory the sandbox mounts — and typed capabilities, and
//! everything it emits passes back through the [output gate](gate), the last line
//! of defense that holds each result to exactly what the work order granted (size,
//! media type, recipient, count). The gate never trusts the worker.
//!
//! The worker's execution happens inside the OS isolation backend (`akson-sandbox`,
//! ADR-0006); this crate owns the protocol (input staging + the gate), both
//! independent of the isolation mechanism.

mod gate;
mod inert;
mod staging;

pub use gate::{gate_outputs, GateError, GateReject, OutputChannel, ProposedOutput};
pub use inert::{check_inert, NotInert};
pub use staging::{stage_inputs, StageError, StageItem, StagedInput, StagedInputs};
