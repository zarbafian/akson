//! The daemon's own keys, derived from one persisted master seed (design §8.3,
//! §12.1; ADR-0009 interim custody).
//!
//! The endpoint needs several purpose-bound signing keys (the TLS endpoint key,
//! the contract-decision key, the evidence/outcome keys) plus one symmetric
//! work-order authority key. `PurposeKey` exposes no way to reload a saved secret,
//! so instead of persisting eight key files we persist **one** 32-byte master seed
//! and derive every key from it deterministically: distinct, stable across
//! restarts, and unpredictable to anyone without the master.
//!
//! Custody of the master is the same interim file the store's KEK uses; the
//! OS-keystore / TPM backend (ADR-0009) replaces where the master lives without
//! changing this derivation.
//!
//! What you write:
//! ```
//! use axond::IdentityKeys;
//! use axon_crypto::purpose::KeyPurpose;
//! let keys = IdentityKeys::from_master([7u8; 32]);
//! let decision = keys.purpose_key(KeyPurpose::ContractDecision);
//! assert_eq!(decision.purpose(), KeyPurpose::ContractDecision);
//! ```

use axon_authority::WorkOrderKey;
use axon_crypto::keypair::PurposeKey;
use axon_crypto::purpose::KeyPurpose;
use sha2::{Digest, Sha256};

/// The daemon's key material: one master seed, from which every purpose key and
/// the work-order MAC key are derived on demand.
#[derive(Clone)]
pub struct IdentityKeys {
    master: [u8; 32],
}

impl IdentityKeys {
    /// Wraps a 32-byte master seed. In production the seed comes from the OS
    /// CSPRNG and is held in interim file custody (see the daemon bootstrap).
    pub fn from_master(master: [u8; 32]) -> Self {
        Self { master }
    }

    /// The purpose-bound signing key for `purpose`. Deterministic in the master
    /// seed; two purposes never share key material (each derives from a distinct
    /// label), honouring one-key-one-role at the key material itself.
    pub fn purpose_key(&self, purpose: KeyPurpose) -> PurposeKey {
        PurposeKey::from_seed(purpose, &self.derive(purpose_label(purpose)))
    }

    /// The symmetric work-order authority key (design §12.1) — MACs the one-shot
    /// work orders this endpoint issues; never leaves the endpoint.
    pub fn work_order_key(&self) -> WorkOrderKey {
        WorkOrderKey::from_bytes(self.derive("work-order-mac"))
    }

    /// Derives a 32-byte sub-seed for `label`. Domain-separated and keyed by the
    /// secret master: `SHA-256("axon/identity-key/v1/" ‖ label ‖ 0x00 ‖ master)`.
    fn derive(&self, label: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"axon/identity-key/v1/");
        h.update(label.as_bytes());
        h.update([0u8]);
        h.update(self.master);
        h.finalize().into()
    }
}

/// The stable derivation label for each purpose — the kebab-case form that
/// `KeyPurpose` also serialises to, pinned here so a rename can never silently
/// re-derive (and so invalidate) an endpoint's keys.
fn purpose_label(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::TlsEndpoint => "tls-endpoint",
        KeyPurpose::AgentCard => "agent-card",
        KeyPurpose::ContractProposal => "contract-proposal",
        KeyPurpose::ContractDecision => "contract-decision",
        KeyPurpose::TaskResult => "task-result",
        KeyPurpose::Evidence => "evidence",
        KeyPurpose::RequesterOutcome => "requester-outcome",
        KeyPurpose::LocalAuthority => "local-authority",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axon_crypto::cert::self_signed_endpoint;
    use std::time::Duration;

    #[test]
    fn is_deterministic_in_the_master() {
        let a = IdentityKeys::from_master([3u8; 32]);
        let b = IdentityKeys::from_master([3u8; 32]);
        // Both the purpose keys and the (opaque) work-order key derive from the
        // same master, so the same purpose key is reproduced across restarts.
        assert_eq!(
            a.purpose_key(KeyPurpose::ContractDecision).thumbprint(),
            b.purpose_key(KeyPurpose::ContractDecision).thumbprint(),
        );
        let _ = a.work_order_key();
    }

    #[test]
    fn distinct_purposes_get_distinct_key_material() {
        let keys = IdentityKeys::from_master([9u8; 32]);
        let decision = keys.purpose_key(KeyPurpose::ContractDecision).thumbprint();
        let endpoint = keys.purpose_key(KeyPurpose::TlsEndpoint).thumbprint();
        let evidence = keys.purpose_key(KeyPurpose::Evidence).thumbprint();
        assert_ne!(decision, endpoint);
        assert_ne!(decision, evidence);
        assert_ne!(endpoint, evidence);
    }

    #[test]
    fn a_different_master_gives_different_keys() {
        let a = IdentityKeys::from_master([1u8; 32]);
        let b = IdentityKeys::from_master([2u8; 32]);
        assert_ne!(
            a.purpose_key(KeyPurpose::TlsEndpoint).thumbprint(),
            b.purpose_key(KeyPurpose::TlsEndpoint).thumbprint(),
        );
    }

    #[test]
    fn the_endpoint_key_produces_a_self_signed_cert() {
        let keys = IdentityKeys::from_master([4u8; 32]);
        let endpoint = keys.purpose_key(KeyPurpose::TlsEndpoint);
        let cert =
            self_signed_endpoint(&endpoint, "axon-endpoint", Duration::from_secs(3600)).unwrap();
        assert!(cert.pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
    }
}
