//! Clean worker protocol and output gate (design §7.2 step 10, §13.1).
//!
//! The clean worker receives only the exact approved input manifest and typed
//! capabilities, and everything it emits passes back through the [output
//! gate](gate) — the last line of defense that holds each result to exactly what
//! the work order granted (size, media type, recipient, count). The gate never
//! trusts the worker.
//!
//! The worker's execution happens inside the OS isolation backend (`axon-sandbox`,
//! ADR-0006); this crate owns the protocol and the gate, both independent of the
//! isolation mechanism.

mod gate;

pub use gate::{gate_outputs, GateError, GateReject, OutputChannel, ProposedOutput};
