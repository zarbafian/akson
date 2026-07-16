//! Peer lifecycle after pairing (design §8.4): removal and change-driven
//! suspension.
//!
//! Personal v1 keeps it strict. Removing a peer immediately denies new sessions
//! and new work orders. An unexpected key, endpoint, issuer, or Agent Card
//! security-projection change suspends the connection for review — but a
//! cosmetic description/example change (only the full-card digest moves) does
//! not, so a peer refreshing its display text does not lock itself out.
//!
//! Rotating any pinned key in personal v1 requires explicit re-pairing (§8.4),
//! so a changed key is a suspension, never a silent accept.
//!
//! What you write:
//! ```no_run
//! use axon_pairing::lifecycle::{detect_change, PeerStatus};
//! # let pinned: axon_crypto::identity::PeerIdentity = unimplemented!();
//! # let presented = pinned.clone();
//! if let Some(reason) = detect_change(&pinned, &presented) {
//!     // suspend the connection, require operator review
//! }
//! assert!(PeerStatus::Active.may_start_session());
//! assert!(!PeerStatus::Removed.may_start_session());
//! ```

use axon_crypto::identity::PeerIdentity;

/// A pinned peer's status. Only `Active` may originate new work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStatus {
    Active,
    /// A safety-critical change was seen; new work is denied until reviewed.
    Suspended(SuspendReason),
    /// Explicitly removed; denies new sessions and new work orders (§8.4).
    Removed,
}

/// Why a connection was suspended (design §8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendReason {
    IssuerChanged,
    EndpointChanged,
    KeyChanged,
    ProjectionChanged,
}

impl PeerStatus {
    /// Whether the peer may originate a new session or work order. Only an
    /// active peer may; a suspended or removed one is denied (§8.4).
    pub fn may_start_session(&self) -> bool {
        matches!(self, PeerStatus::Active)
    }
}

/// Compares a freshly presented identity against the pinned one and reports the
/// first safety-critical change, or `None` if nothing policy-relevant changed.
/// A change of only the full-card digest (cosmetic display text) returns
/// `None` (design §8.4).
pub fn detect_change(pinned: &PeerIdentity, presented: &PeerIdentity) -> Option<SuspendReason> {
    if pinned.issuer != presented.issuer {
        return Some(SuspendReason::IssuerChanged);
    }
    if !pinned.tls_cert.matches(&presented.tls_cert) {
        return Some(SuspendReason::EndpointChanged);
    }
    if !pinned.agent_card_key.matches(&presented.agent_card_key)
        || pinned.key_bindings != presented.key_bindings
    {
        return Some(SuspendReason::KeyChanged);
    }
    if !pinned
        .security_projection_digest
        .matches(&presented.security_projection_digest)
    {
        return Some(SuspendReason::ProjectionChanged);
    }
    // A different full_card_digest alone is cosmetic and does not suspend.
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axon_crypto::identity::{Fingerprint, KeyBinding, PeerIdentity};
    use axon_crypto::purpose::KeyPurpose;
    use ed25519_dalek::SigningKey;

    fn vk(seed: u8) -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    fn peer() -> PeerIdentity {
        PeerIdentity {
            issuer: Some("trust.example".to_owned()),
            agent_id: "agent-a".to_owned(),
            workload_id: None,
            endpoint_id: "ep-1".to_owned(),
            tls_cert: Fingerprint::cert_sha256(b"der-1"),
            agent_card_key: Fingerprint::jwk(&vk(1)),
            key_bindings: vec![KeyBinding::new(KeyPurpose::TaskResult, &vk(2))],
            security_projection_digest: Fingerprint::json_sha256(b"proj-1"),
            full_card_digest: Fingerprint::json_sha256(b"card-1"),
        }
    }

    #[test]
    fn identical_identity_is_unchanged() {
        assert_eq!(detect_change(&peer(), &peer()), None);
    }

    #[test]
    fn cosmetic_card_change_does_not_suspend() {
        let mut presented = peer();
        presented.full_card_digest = Fingerprint::json_sha256(b"card-2-new-description");
        assert_eq!(detect_change(&peer(), &presented), None);
    }

    #[test]
    fn key_change_suspends() {
        let mut presented = peer();
        presented.agent_card_key = Fingerprint::jwk(&vk(9));
        assert_eq!(
            detect_change(&peer(), &presented),
            Some(SuspendReason::KeyChanged)
        );
    }

    #[test]
    fn key_binding_change_suspends() {
        let mut presented = peer();
        presented.key_bindings = vec![KeyBinding::new(KeyPurpose::TaskResult, &vk(9))];
        assert_eq!(
            detect_change(&peer(), &presented),
            Some(SuspendReason::KeyChanged)
        );
    }

    #[test]
    fn endpoint_and_issuer_and_projection_changes_suspend() {
        let mut ep = peer();
        ep.tls_cert = Fingerprint::cert_sha256(b"der-2");
        assert_eq!(
            detect_change(&peer(), &ep),
            Some(SuspendReason::EndpointChanged)
        );

        let mut iss = peer();
        iss.issuer = Some("other.example".to_owned());
        assert_eq!(
            detect_change(&peer(), &iss),
            Some(SuspendReason::IssuerChanged)
        );

        let mut proj = peer();
        proj.security_projection_digest = Fingerprint::json_sha256(b"proj-2");
        assert_eq!(
            detect_change(&peer(), &proj),
            Some(SuspendReason::ProjectionChanged)
        );
    }

    #[test]
    fn removed_and_suspended_deny_new_work() {
        assert!(PeerStatus::Active.may_start_session());
        assert!(!PeerStatus::Removed.may_start_session());
        assert!(!PeerStatus::Suspended(SuspendReason::KeyChanged).may_start_session());
    }
}
