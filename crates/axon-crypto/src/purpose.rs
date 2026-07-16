//! Key purposes (ADR-0004, design §8.1).
//!
//! Every key is bound to exactly one purpose; signing and verification APIs
//! take the purpose and fail closed on any mismatch. This is a closed enum on
//! purpose — readers must reject unknown safety-critical values (design §18),
//! so there is no catch-all variant.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyPurpose {
    /// X.509 endpoint key for TLS (never used for statements).
    TlsEndpoint,
    /// Agent Card JWS signing (design §10.1).
    AgentCard,
    /// Requester-signed contract proposals (design §10.2).
    ContractProposal,
    /// Performer-signed accept/reject/revision-request decisions.
    ContractDecision,
    /// Producer-signed result manifests and task statements.
    TaskResult,
    /// Evidence statement signing (design §14.2).
    Evidence,
    /// Local work-order authority; never leaves the endpoint.
    LocalAuthority,
}

impl KeyPurpose {
    /// Purposes whose public keys are exchanged and pinned at pairing
    /// (design §8.2 step 5). `LocalAuthority` is deliberately absent.
    pub const PAIRED: [KeyPurpose; 6] = [
        KeyPurpose::TlsEndpoint,
        KeyPurpose::AgentCard,
        KeyPurpose::ContractProposal,
        KeyPurpose::ContractDecision,
        KeyPurpose::TaskResult,
        KeyPurpose::Evidence,
    ];
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_kebab_case() {
        assert_eq!(
            serde_json::to_string(&KeyPurpose::ContractProposal).unwrap(),
            "\"contract-proposal\""
        );
    }

    #[test]
    fn rejects_unknown_purpose() {
        assert!(serde_json::from_str::<KeyPurpose>("\"root\"").is_err());
    }

    #[test]
    fn local_authority_is_never_paired() {
        assert!(!KeyPurpose::PAIRED.contains(&KeyPurpose::LocalAuthority));
    }
}
