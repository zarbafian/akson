//! Personal pairing (design §8.2): invitation, bootstrap, pending-to-active,
//! re-pair and removal.
//!
//! M6-core lands the two security-critical *verification primitives* first:
//! - [`invitation`] — the single-use 256-bit bearer secret, kept as a
//!   verifier only, checked in constant time with expiry and an attempt cap;
//! - [`key_binding`] — schema-gated verification that each advertised key
//!   thumbprint equals the RFC 7638 thumbprint of its JWK, with valid
//!   intervals (closes review finding M6).
//!
//! The bootstrap state machine (retry-safe transcript, atomic secret
//! consumption, pending→active) and the rate-limited HTTP bootstrap endpoint
//! layer on top of these and the TLS transport (M5).

pub mod bootstrap;
pub mod invitation;
pub mod key_binding;
