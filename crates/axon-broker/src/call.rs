//! The pre-dispatch processor-call record (design §13.1).
//!
//! Before a single byte leaves, the broker durably records everything that makes
//! the call reproducible and accountable: the provider, the exact origin and
//! configuration digest, the request-content digest, the work-order/task binding,
//! a generated idempotency key, the cost bound, the deadline, and the response
//! limit. That record is the sub-attempt's identity — a crash after it exists
//! resolves to `ambiguous`, and an exact retry reuses the same idempotency key.
//!
//! The idempotency key is *derived* from the work order, the config digest, and
//! the request digest, so re-preparing the identical call yields the identical key
//! (an exact retry), while any change to the destination, model, or request bytes
//! yields a new one.
//!
//! What you write:
//! ```
//! use axon_broker::{AuthScheme, CallBinding, CallBudget, ProcessorCall, ProcessorConfig, Disclosure, Origin};
//! use serde_json::json;
//! # let config = ProcessorConfig {
//! #   processor_id: "reviewer".into(), provider: "example-ai".into(),
//! #   origin: Origin::https("api.example.com", 443),
//! #   disclosure: Disclosure::remote("Example AI", "us-east"),
//! #   path: "/".into(), auth: AuthScheme::Bearer, headers: vec![], config: json!({"model": "m"}),
//! #   tls_certificate_sha256: None,
//! # };
//! let call = ProcessorCall::prepare(
//!     &config,
//!     b"review this diff",
//!     CallBinding { work_order_id: "wo-1".into(), work_order_digest: "aa".repeat(32), task_id: "task-1".into() },
//!     CallBudget { max_cost_microusd: 5000, deadline: "2030-01-01T00:00:00Z".into(), max_response_bytes: 65536, max_operations: 16 },
//! ).unwrap();
//! assert_eq!(call.request_digest.len(), 64);
//! // Re-preparing the identical call reuses the idempotency key.
//! let again = ProcessorCall::prepare(&config, b"review this diff",
//!     CallBinding { work_order_id: "wo-1".into(), work_order_digest: "aa".repeat(32), task_id: "task-1".into() },
//!     CallBudget { max_cost_microusd: 5000, deadline: "2030-01-01T00:00:00Z".into(), max_response_bytes: 65536, max_operations: 16 },
//! ).unwrap();
//! assert_eq!(call.idempotency_key, again.idempotency_key);
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::address::Origin;
use crate::processor::ProcessorConfig;

/// The task/work-order this call is bound to (design §13.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallBinding {
    pub work_order_id: String,
    pub work_order_digest: String,
    pub task_id: String,
}

/// The cost/latency/size ceilings for this call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallBudget {
    /// Estimated cost bound (a labeled estimate unless the provider enforces a hard
    /// reservation, §13.1).
    pub max_cost_microusd: u64,
    pub deadline: String,
    pub max_response_bytes: u64,
    /// The work order's aggregate operation cap: the total number of processor
    /// calls this attempt may make. Enforced durably by counting prepared calls,
    /// so per-call ceilings above cannot be multiplied by an unbounded call count
    /// (§12.1 aggregate budget).
    pub max_operations: u32,
}

/// Why a call could not be prepared or digested.
#[derive(Debug, thiserror::Error)]
#[error("processor call: {0}")]
pub struct CallError(String);

/// The durable pre-dispatch record for one processor call (design §13.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorCall {
    pub processor_id: String,
    pub provider: String,
    pub origin: Origin,
    /// Binds the exact approved processor configuration.
    pub config_digest: String,
    /// SHA-256 of the exact request plaintext being disclosed.
    pub request_digest: String,
    pub work_order_id: String,
    pub work_order_digest: String,
    pub task_id: String,
    /// Derived from `(work_order_id, config_digest, request_digest)` — an exact
    /// retry reuses it; any change yields a new key.
    pub idempotency_key: String,
    pub max_cost_microusd: u64,
    pub deadline: String,
    pub max_response_bytes: u64,
}

impl ProcessorCall {
    /// Builds the pre-dispatch record for disclosing `request_plaintext` to
    /// `config` under `binding`/`budget` (design §13.1). Computes the request and
    /// config digests and derives the idempotency key. Pure — no I/O; the caller
    /// persists this and only then dispatches.
    pub fn prepare(
        config: &ProcessorConfig,
        request_plaintext: &[u8],
        binding: CallBinding,
        budget: CallBudget,
    ) -> Result<Self, CallError> {
        let config_digest = config
            .config_digest()
            .map_err(|e| CallError(e.to_string()))?;
        let request_digest = hex::encode(Sha256::digest(request_plaintext));
        let idempotency_key =
            derive_idempotency_key(&binding.work_order_id, &config_digest, &request_digest)?;
        Ok(Self {
            processor_id: config.processor_id.clone(),
            provider: config.provider.clone(),
            origin: config.origin.clone(),
            config_digest,
            request_digest,
            work_order_id: binding.work_order_id,
            work_order_digest: binding.work_order_digest,
            task_id: binding.task_id,
            idempotency_key,
            max_cost_microusd: budget.max_cost_microusd,
            deadline: budget.deadline,
            max_response_bytes: budget.max_response_bytes,
        })
    }

    /// A content-address of the whole record — the sub-attempt's stored identity.
    pub fn digest(&self) -> Result<String, CallError> {
        let bytes = json_canon::to_vec(self).map_err(|e| CallError(e.to_string()))?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

/// Derives the idempotency key deterministically from the call's identity, so an
/// exact retry reuses it (design §13.1).
fn derive_idempotency_key(
    work_order_id: &str,
    config_digest: &str,
    request_digest: &str,
) -> Result<String, CallError> {
    let material = serde_json::json!({
        "work_order_id": work_order_id,
        "config_digest": config_digest,
        "request_digest": request_digest,
    });
    let bytes = json_canon::to_vec(&material).map_err(|e| CallError(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::processor::Disclosure;
    use serde_json::json;

    fn config() -> ProcessorConfig {
        ProcessorConfig {
            processor_id: "reviewer".to_owned(),
            provider: "example-ai".to_owned(),
            origin: Origin::https("api.example.com", 443),
            disclosure: Disclosure::remote("Example AI", "us-east"),
            path: "/".to_owned(),
            auth: crate::AuthScheme::Bearer,
            headers: Vec::new(),
            config: json!({"model": "review-1"}),
            tls_certificate_sha256: None,
        }
    }

    fn binding() -> CallBinding {
        CallBinding {
            work_order_id: "wo-1".to_owned(),
            work_order_digest: "aa".repeat(32),
            task_id: "task-1".to_owned(),
        }
    }

    fn budget() -> CallBudget {
        CallBudget {
            max_cost_microusd: 5000,
            deadline: "2030-01-01T00:00:00Z".to_owned(),
            max_response_bytes: 65536,
            max_operations: 16,
        }
    }

    #[test]
    fn prepare_binds_request_and_config() {
        let call =
            ProcessorCall::prepare(&config(), b"review this diff", binding(), budget()).unwrap();
        assert_eq!(
            call.request_digest,
            hex::encode(Sha256::digest(b"review this diff"))
        );
        assert_eq!(call.config_digest, config().config_digest().unwrap());
        assert_eq!(call.origin, Origin::https("api.example.com", 443));
        assert_eq!(call.max_response_bytes, 65536);
        assert_eq!(call.digest().unwrap().len(), 64);
    }

    #[test]
    fn identical_calls_share_an_idempotency_key() {
        let a = ProcessorCall::prepare(&config(), b"same request", binding(), budget()).unwrap();
        let b = ProcessorCall::prepare(&config(), b"same request", binding(), budget()).unwrap();
        assert_eq!(a.idempotency_key, b.idempotency_key);
    }

    #[test]
    fn a_different_request_gets_a_new_idempotency_key() {
        let a = ProcessorCall::prepare(&config(), b"request one", binding(), budget()).unwrap();
        let b = ProcessorCall::prepare(&config(), b"request two", binding(), budget()).unwrap();
        assert_ne!(a.idempotency_key, b.idempotency_key);
        assert_ne!(a.request_digest, b.request_digest);
    }

    #[test]
    fn a_different_config_gets_a_new_idempotency_key() {
        let a = ProcessorCall::prepare(&config(), b"same request", binding(), budget()).unwrap();
        let other = ProcessorConfig {
            config: json!({"model": "review-2"}),
            ..config()
        };
        let b = ProcessorCall::prepare(&other, b"same request", binding(), budget()).unwrap();
        assert_ne!(a.idempotency_key, b.idempotency_key);
    }
}
