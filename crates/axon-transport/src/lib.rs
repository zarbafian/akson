//! A2A HTTP+JSON server/client on the pinned TLS 1.3 mTLS profile.
//!
//! M5 builds this in layers:
//! - [`tls`] — the TLS 1.3 mutual-auth transport with peer pinning (design
//!   §9.1, ADR-0011);
//! - [`ingress`] — the v1 profile gates and idempotency decision every
//!   authenticated request passes before an operation runs (§9.2, §10.1).
//!
//! The axum HTTP endpoint and client layer on top: they serve over the [`tls`]
//! configs and act on the [`ingress`] verdict.

pub mod bootstrap;
pub mod client;
pub mod ingress;
pub mod tls;
