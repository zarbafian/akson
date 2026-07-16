//! Key lifecycle, purpose binding, thumbprints, JWS, and keystore adapters —
//! thin wrappers over reviewed libraries only (design §3.3, ADR-0004).
//!
//! Milestone M3 fills in key generation, purpose enforcement, keystore
//! wrapping, and JWS. Present now: Ed25519 public JWKs and RFC 7638
//! thumbprints, which every signed Axon object uses as `keyid`.

pub mod jwk;
pub mod purpose;
