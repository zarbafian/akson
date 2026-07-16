//! A2A HTTP+JSON server/client on the pinned TLS 1.3 mTLS profile.
//!
//! M5 builds this in layers: [`tls`] is the TLS 1.3 mutual-auth transport with
//! peer pinning (design §9.1, ADR-0011). The A2A HTTP endpoint and client, and
//! the wiring of the reliable-delivery model (`axon_store::delivery`), layer on
//! top of these configs.

pub mod tls;
