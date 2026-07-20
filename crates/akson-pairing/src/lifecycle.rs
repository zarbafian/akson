//! A pinned peer's lifecycle: confirmation (§8.2 step 7), change-driven
//! suspension, and removal (§8.4).
//!
//! [`PeerStatus`] is the one status a *present* peer can hold — the single
//! machine `Pending → Active ⇄ Suspended`. A freshly paired peer is `Pending`
//! until the operator confirms it; only `Active` may originate work. Removal is
//! not a status but the peer's *absence*: `Store::remove_peer` deletes the
//! record, so a removed peer simply has no status (and the work path finds no
//! peer). The audit log records the removal.
//!
//! Personal v1 keeps suspension strict. An unexpected key, endpoint, issuer, or
//! Agent Card security-projection change suspends the connection for review —
//! but a cosmetic description/example change (only the full-card digest moves)
//! does not, so a peer refreshing its display text does not lock itself out.
//! Rotating any pinned key requires explicit re-pairing (§8.4), so a changed key
//! is a suspension, never a silent accept.
//!
//! What you write:
//! ```no_run
//! use akson_pairing::lifecycle::{detect_change, PeerStatus};
//! # let pinned: akson_crypto::identity::PeerIdentity = unimplemented!();
//! # let presented = pinned.clone();
//! if let Some(reason) = detect_change(&pinned, &presented) {
//!     // suspend the connection, require operator review
//! }
//! assert!(PeerStatus::Active.may_start_session());
//! assert!(!PeerStatus::Pending.may_start_session());
//! ```

use akson_crypto::identity::PeerIdentity;

/// The status a pinned peer holds while it exists (design §8.2 step 7, §8.4).
/// Removal is represented by the peer's absence, not a variant. This is the
/// single peer-status type; `akson-store` persists it in the `peers.status`
/// column via [`as_column`](PeerStatus::as_column) /
/// [`from_column`](PeerStatus::from_column).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStatus {
    /// Paired but not yet operator-confirmed (§8.2 step 7). No work until
    /// confirmed.
    Pending,
    /// Confirmed; the only status that may originate a session or work order.
    Active,
    /// A safety-critical change was seen (§8.4); new work is denied until an
    /// operator reviews it. Written by the receive/work-authorization path.
    Suspended(SuspendReason),
}

/// Why a connection was suspended (design §8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendReason {
    IssuerChanged,
    EndpointChanged,
    KeyChanged,
    ProjectionChanged,
}

impl SuspendReason {
    /// The stable token used in the persisted status string.
    pub fn as_str(self) -> &'static str {
        match self {
            SuspendReason::IssuerChanged => "issuer",
            SuspendReason::EndpointChanged => "endpoint",
            SuspendReason::KeyChanged => "key",
            SuspendReason::ProjectionChanged => "projection",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "issuer" => Some(SuspendReason::IssuerChanged),
            "endpoint" => Some(SuspendReason::EndpointChanged),
            "key" => Some(SuspendReason::KeyChanged),
            "projection" => Some(SuspendReason::ProjectionChanged),
            _ => None,
        }
    }
}

impl PeerStatus {
    /// Whether the peer may originate a new session or work order. Only an
    /// active peer may; a pending or suspended one is denied (§8.2, §8.4). A
    /// removed peer has no status, so callers treat its absence as denied.
    pub fn may_start_session(&self) -> bool {
        matches!(self, PeerStatus::Active)
    }

    /// Encodes the status for the `peers.status` column. `Suspended` carries its
    /// reason as `"suspended:<reason>"`.
    pub fn as_column(&self) -> String {
        match self {
            PeerStatus::Pending => "pending".to_owned(),
            PeerStatus::Active => "active".to_owned(),
            PeerStatus::Suspended(reason) => format!("suspended:{}", reason.as_str()),
        }
    }

    /// Parses a `peers.status` column value, or `None` if it is unrecognized
    /// (the store treats that as a corrupt record rather than guessing).
    pub fn from_column(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(PeerStatus::Pending),
            "active" => Some(PeerStatus::Active),
            other => other
                .strip_prefix("suspended:")
                .and_then(SuspendReason::from_str)
                .map(PeerStatus::Suspended),
        }
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
    use akson_crypto::identity::{Fingerprint, KeyBinding, PeerIdentity};
    use akson_crypto::purpose::KeyPurpose;
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
    fn only_active_may_start_work() {
        assert!(PeerStatus::Active.may_start_session());
        assert!(!PeerStatus::Pending.may_start_session());
        assert!(!PeerStatus::Suspended(SuspendReason::KeyChanged).may_start_session());
    }

    #[test]
    fn status_round_trips_through_the_column_form() {
        for s in [
            PeerStatus::Pending,
            PeerStatus::Active,
            PeerStatus::Suspended(SuspendReason::KeyChanged),
            PeerStatus::Suspended(SuspendReason::EndpointChanged),
        ] {
            assert_eq!(PeerStatus::from_column(&s.as_column()), Some(s.clone()));
        }
        assert_eq!(PeerStatus::from_column("bogus"), None);
        assert_eq!(PeerStatus::from_column("suspended:nonsense"), None);
    }
}
