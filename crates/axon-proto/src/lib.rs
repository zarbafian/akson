//! Standard A2A 1.0 types, generated from the vendored normative Protocol
//! Buffer definitions (spec/a2a/proto, pinned in spec/a2a/PIN — ADR-0002).
//!
//! This crate is the single place A2A types exist in the workspace. The
//! serde implementations are the standard proto3 JSON mapping, which is what
//! the A2A HTTP+JSON binding (`application/a2a+json`) carries. Axon's v1
//! profile restrictions (required extensions, nonblocking operations,
//! disabled streaming/push) are validation layered on top by the transport
//! and contract crates, never edits to the generated model.

/// Generated A2A types, package `lf.a2a.v1`.
#[allow(clippy::all, clippy::pedantic, rustdoc::all)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.serde.rs"));
}

/// Well-known-type structs (Struct, Value, Timestamp, …) used by the
/// generated model, re-exported so downstream crates need no direct pbjson
/// dependency.
pub use pbjson_types as well_known;

/// The pinned A2A protocol version, as carried in the `A2A-Version` header
/// (design §10.1).
pub const A2A_VERSION: &str = "1.0";

/// The A2A HTTP+JSON binding media type (design §3).
pub const A2A_MEDIA_TYPE: &str = "application/a2a+json";
