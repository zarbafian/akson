//! Axon extension formats: I-JSON validation, RFC 8785 canonicalization,
//! DSSE v1 envelopes, and the extension-URI namespace.
//!
//! Everything canonicalized, digested, or signed here is covered by golden
//! vectors under `spec/vectors/`, cross-checked in CI by the independent
//! Python implementation in `xcheck/`.
//!
//! Scope: design §3.2 (extension surface), §10.2 (contract payload rules),
//! §14.2 (evidence model). The JSON Schemas themselves land with milestone M1;
//! this module set is the byte-level foundation they validate against.

pub mod dsse;
pub mod ijson;
pub mod jcs;
pub mod namespace;
