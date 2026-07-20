//! Processor broker (design §13.1, §15.2) — the only v1 component allowed to
//! disclose approved task plaintext to a processor, and the only egress path.
//!
//! Sending plaintext to a processor is an *effect*: it discloses data and may
//! incur cost. So every call is a durable [sub-attempt](subattempt) — `prepared →
//! dispatching → completed | failed | ambiguous | cancelled` — whose pre-dispatch
//! [record](ProcessorCall) (provider, exact origin + config digest, request
//! digest, work-order binding, idempotency key, cost bound, deadline, response
//! limit) is stored before a byte leaves. A crash after that resolves to
//! `ambiguous` and is never auto-retried.
//!
//! Two fail-closed [egress checks](address) stop a task — or a rebinding DNS
//! response — from steering the call elsewhere: the origin must be `https` and
//! allowlisted, and the address it *resolves to* must be globally routable
//! (no loopback/private/link-local/…). Redirects and ambient proxies are disabled
//! at the dispatch layer, and credentials never leave the broker.
//!
//! Each processor is a separate plaintext trust boundary; its
//! [configuration](ProcessorConfig) records the local/remote
//! [disclosure](Disclosure) the risk card shows before any data is sent (§15.2).
//!
//! This crate is the pure/durable core (state machine, bindings, egress checks,
//! disclosure); the live HTTPS dispatch (redirect-disabled client, connection-time
//! DNS validation, credential injection) is wired at daemon assembly (M12), and
//! the durable `processor_calls` records live in `akson-store`.

mod address;
mod call;
mod processor;
mod subattempt;

pub use address::{check_origin, check_resolved_address, EgressError, EgressPolicy, Origin};
pub use call::{CallBinding, CallBudget, CallError, ProcessorCall};
pub use processor::{AuthScheme, ConfigError, Disclosure, ProcessorConfig, ProcessorLocation};
pub use subattempt::{next, SubAttemptEvent, SubAttemptState, TransitionError};
