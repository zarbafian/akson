//! Key lifecycle, purpose binding, thumbprints, JWS, and keystore adapters —
//! thin wrappers over reviewed libraries only (design §3.3, ADR-0004).
//!
//! What lives here:
//! - [`jwk`] — Ed25519 public JWKs (RFC 8037) and RFC 7638 thumbprints, the
//!   `keyid` every signed Akson object uses.
//! - [`purpose`] — the closed set of key purposes.
//! - [`keypair`] — purpose-bound keys; cross-purpose use fails closed.
//! - [`keystore`] — key custody and the monotonic rollback counter (ADR-0009).
//! - [`jws`] — minimal EdDSA JWS for Agent Card signatures (ADR-0007). The
//!   Agent-Card-specific canonicalization lives in `akson_proto::card_sig`.
//! - [`identity`] — the internal peer identity tuple (design §8.1).
//! - [`cert`] — self-issued Ed25519 X.509 endpoint certificates (ADR-0011).

pub mod cert;
pub mod identity;
pub mod jwk;
pub mod jws;
pub mod keypair;
pub mod keystore;
pub mod purpose;
pub mod token;
