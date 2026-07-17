//! The one-shot work order (design §12.3): a local, single-use authorization
//! addressed to a local executor.
//!
//! A work order is the only place authority exists (§12.2) — never a bearer token
//! a peer holds. It binds the exact request origin, contract revision and digest,
//! capability vector, input manifest, executor/sandbox/processor digests, budgets,
//! and a one-use nonce, then carries a local MAC so the executor can confirm it
//! came from the local authority. The MAC covers the RFC 8785-canonical bytes, so
//! the order's digest is stable and any field change invalidates it.
//!
//! What you write:
//! ```
//! use axon_authority::{WorkOrder, WorkOrderKey, CapabilityVector, Grant, RespondScope};
//! # use axon_authority::{Audience, RequestOrigin, Budgets};
//! # use axon_contract::Identity;
//! # let order = WorkOrder {
//! #   version: 1, work_order_id: "11111111-1111-4111-8111-111111111111".into(),
//! #   issuer: Identity { issuer: "local".into(), agent: "authority".into() },
//! #   issuer_assurance: "local-human".into(),
//! #   audience: Audience { daemon: "axond".into(), executor: "worker-1".into() },
//! #   request_origin: RequestOrigin { peer: Identity { issuer: "iss".into(), agent: "requester".into() }, tls_certificate_sha256: "ab".repeat(32) },
//! #   task_id: "task-1".into(), context_id: "ctx-1".into(), message_id: "msg-1".into(),
//! #   contract_revision: 0, contract_digest: "a".repeat(64),
//! #   capabilities: CapabilityVector::new(vec![Grant::Respond(RespondScope {
//! #     task_id: "task-1".into(), message_id: "msg-1".into(), recipient: "request-origin".into(),
//! #     max_responses: 1, max_bytes: 8192, deadline: "2030-01-01T00:00:00Z".into() })]).unwrap(),
//! #   input_manifest: vec!["src".into()],
//! #   processor_digest: None, runner_digest: None, sandbox_digest: None, profile_digest: None,
//! #   budgets: Budgets { max_cost_microusd: 500, max_bytes: 8192, max_operations: 4 },
//! #   evidence_slots: vec![], policy_version: 1, decision_id: "d-1".into(),
//! #   not_before: "2026-01-01T00:00:00Z".into(), deadline: "2030-01-01T00:00:00Z".into(),
//! #   nonce: "n".repeat(43), remote_cancel: None,
//! # };
//! let key = WorkOrderKey::from_bytes([7u8; 32]);
//! let issued = order.issue(&key).unwrap();       // local authority MACs it
//! issued.verify(&key).unwrap();                  // the executor confirms it
//! assert_eq!(issued.digest.len(), 64);
//! ```

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use axon_contract::Identity;

use crate::capability::CapabilityVector;

type HmacSha256 = Hmac<Sha256>;

/// The local audience: the exact daemon and executor a work order addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Audience {
    pub daemon: String,
    pub executor: String,
}

/// The authenticated request origin: the peer and the paired certificate it
/// presented (§12.3). The work order is bound to this exact origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestOrigin {
    pub peer: Identity,
    pub tls_certificate_sha256: String,
}

/// Aggregate budgets for the whole attempt (per-operation budgets live in the
/// capability scopes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budgets {
    pub max_cost_microusd: u64,
    pub max_bytes: u64,
    pub max_operations: u32,
}

/// Whether the authenticated origin may cancel this exact attempt (§12.1
/// `remote_cancel`). Absent means remote cancellation is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCancelCaveat {
    /// The origin identity permitted to cancel — the request origin, echoed so
    /// the caveat is self-contained.
    pub allowed_origin: Identity,
}

/// A one-shot work order (design §12.3), before it is MAC'd. Every field is bound
/// into the MAC via the canonical form, so the executor authorizes exactly this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkOrder {
    pub version: u32,
    pub work_order_id: String,
    /// The local authority that issued this order, and its assurance.
    pub issuer: Identity,
    pub issuer_assurance: String,
    pub audience: Audience,
    pub request_origin: RequestOrigin,
    pub task_id: String,
    pub context_id: String,
    pub message_id: String,
    pub contract_revision: u64,
    pub contract_digest: String,
    pub capabilities: CapabilityVector,
    /// The exact input/context manifest (logical input ids) the executor may use.
    pub input_manifest: Vec<String>,
    pub processor_digest: Option<String>,
    pub runner_digest: Option<String>,
    pub sandbox_digest: Option<String>,
    pub profile_digest: Option<String>,
    pub budgets: Budgets,
    pub evidence_slots: Vec<String>,
    pub policy_version: u32,
    pub decision_id: String,
    pub not_before: String,
    pub deadline: String,
    /// The one-use nonce; consumed atomically at claim (design §12.3).
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_cancel: Option<RemoteCancelCaveat>,
}

/// A local key that MACs work orders. Held by the local authority; the executor
/// verifies with the same key. A work order is local (§12.2), so a symmetric MAC
/// is sufficient and never leaves the host.
#[derive(Clone)]
pub struct WorkOrderKey([u8; 32]);

impl WorkOrderKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A MAC'd work order: the order, its canonical digest, and the local MAC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedWorkOrder {
    pub order: WorkOrder,
    /// SHA-256 (hex) of the canonical work-order bytes — the digest the executor
    /// descriptor is bound to.
    pub digest: String,
    /// HMAC-SHA256 (hex) over the canonical bytes under the local authority key.
    pub mac: String,
}

/// Work-order build/verify failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkOrderError {
    #[error("work order is not serializable to canonical JSON")]
    Canonicalize,
    #[error("work-order MAC does not verify")]
    BadMac,
    #[error("work-order digest does not match its contents")]
    DigestMismatch,
}

impl WorkOrder {
    /// The RFC 8785-canonical bytes of the order (the MAC and digest input).
    fn canonical_bytes(&self) -> Result<Vec<u8>, WorkOrderError> {
        json_canon::to_vec(self).map_err(|_| WorkOrderError::Canonicalize)
    }

    /// The SHA-256 (hex) digest of the canonical order.
    pub fn digest(&self) -> Result<String, WorkOrderError> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }

    /// MACs the order under `key`, producing an [`IssuedWorkOrder`].
    pub fn issue(&self, key: &WorkOrderKey) -> Result<IssuedWorkOrder, WorkOrderError> {
        let bytes = self.canonical_bytes()?;
        let digest = hex::encode(Sha256::digest(&bytes));
        #[allow(clippy::expect_used)] // HMAC accepts any key length; 32 bytes never errors.
        let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
        mac.update(&bytes);
        let tag = hex::encode(mac.finalize().into_bytes());
        Ok(IssuedWorkOrder {
            order: self.clone(),
            digest,
            mac: tag,
        })
    }
}

impl IssuedWorkOrder {
    /// Verifies the digest and the MAC under `key` (constant-time). Fails closed
    /// on any mismatch — a tampered field changes the canonical bytes and breaks
    /// both.
    pub fn verify(&self, key: &WorkOrderKey) -> Result<(), WorkOrderError> {
        let bytes = self.order.canonical_bytes()?;
        if hex::encode(Sha256::digest(&bytes)) != self.digest {
            return Err(WorkOrderError::DigestMismatch);
        }
        let tag = hex::decode(&self.mac).map_err(|_| WorkOrderError::BadMac)?;
        #[allow(clippy::expect_used)] // HMAC accepts any key length; 32 bytes never errors.
        let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
        mac.update(&bytes);
        mac.verify_slice(&tag).map_err(|_| WorkOrderError::BadMac)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::capability::{Grant, RespondScope};

    fn identity(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    fn order() -> WorkOrder {
        WorkOrder {
            version: 1,
            work_order_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            issuer: identity("authority"),
            issuer_assurance: "local-human".to_owned(),
            audience: Audience {
                daemon: "axond".to_owned(),
                executor: "worker-1".to_owned(),
            },
            request_origin: RequestOrigin {
                peer: identity("requester"),
                tls_certificate_sha256: "ab".repeat(32),
            },
            task_id: "task-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            message_id: "msg-1".to_owned(),
            contract_revision: 0,
            contract_digest: "a".repeat(64),
            capabilities: CapabilityVector::new(vec![Grant::Respond(RespondScope {
                task_id: "task-1".to_owned(),
                message_id: "msg-1".to_owned(),
                recipient: "request-origin".to_owned(),
                max_responses: 1,
                max_bytes: 8192,
                deadline: "2030-01-01T00:00:00Z".to_owned(),
            })])
            .unwrap(),
            input_manifest: vec!["src".to_owned()],
            processor_digest: None,
            runner_digest: None,
            sandbox_digest: None,
            profile_digest: None,
            budgets: Budgets {
                max_cost_microusd: 500,
                max_bytes: 8192,
                max_operations: 4,
            },
            evidence_slots: vec![],
            policy_version: 1,
            decision_id: "d-1".to_owned(),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            deadline: "2030-01-01T00:00:00Z".to_owned(),
            nonce: "n".repeat(43),
            remote_cancel: None,
        }
    }

    fn key() -> WorkOrderKey {
        WorkOrderKey::from_bytes([7u8; 32])
    }

    #[test]
    fn issue_then_verify_round_trips() {
        let issued = order().issue(&key()).unwrap();
        assert_eq!(issued.digest.len(), 64);
        issued.verify(&key()).unwrap();
        // The digest is deterministic (canonical bytes).
        assert_eq!(order().digest().unwrap(), issued.digest);
    }

    #[test]
    fn wrong_key_fails_the_mac() {
        let issued = order().issue(&key()).unwrap();
        let wrong = WorkOrderKey::from_bytes([9u8; 32]);
        assert_eq!(issued.verify(&wrong), Err(WorkOrderError::BadMac));
    }

    #[test]
    fn a_tampered_field_breaks_verification() {
        let mut issued = order().issue(&key()).unwrap();
        // Widen a budget after issuance — the canonical bytes no longer match the
        // digest the MAC was computed over.
        issued.order.budgets.max_bytes = 1_000_000;
        assert_eq!(issued.verify(&key()), Err(WorkOrderError::DigestMismatch));
    }

    #[test]
    fn a_forged_mac_over_a_changed_order_still_fails() {
        // Even if an attacker recomputes the digest for a changed order, they
        // cannot produce a valid MAC without the key.
        let mut issued = order().issue(&key()).unwrap();
        issued.order.budgets.max_bytes = 1_000_000;
        issued.digest = issued.order.digest().unwrap(); // fix the digest
        assert_eq!(issued.verify(&key()), Err(WorkOrderError::BadMac));
    }
}
