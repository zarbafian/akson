//! Processor configuration and disclosure (design §15.2, §4.4).
//!
//! Each processor is a separate plaintext trust boundary. Its configuration
//! records whether it is local or remote and, when known, its operator, region,
//! retention, whether it trains on data, and its subprocessors — the facts the
//! risk card shows the operator *before* any disclosure. "End-to-end encrypted
//! transport" never implies an approved remote model cannot read its input.
//!
//! The [`config_digest`](ProcessorConfig::config_digest) binds the exact approved
//! configuration into every [call](crate::ProcessorCall) made against it, so a
//! silent config change breaks the binding.
//!
//! What you write:
//! ```
//! use axon_broker::{Disclosure, Origin, ProcessorConfig, ProcessorLocation};
//! use serde_json::json;
//! let cfg = ProcessorConfig {
//!     processor_id: "reviewer".into(),
//!     provider: "example-ai".into(),
//!     origin: Origin::https("api.example.com", 443),
//!     disclosure: Disclosure::remote("Example AI", "us-east").retains("30d"),
//!     config: json!({"model": "review-1", "temperature": 0}),
//! };
//! assert!(!cfg.is_local());
//! let _digest = cfg.config_digest().unwrap();
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::address::Origin;

/// Whether a processor's plaintext boundary is on this host or a remote service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessorLocation {
    Local,
    Remote,
}

/// What the operator is told about a processor before disclosing to it (§15.2).
/// Unknown facts are `None`/empty and are shown as "not disclosed", never assumed
/// benign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disclosure {
    pub location: ProcessorLocation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<String>,
    /// Whether the processor trains on submitted data, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trains_on_data: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subprocessors: Vec<String>,
}

impl Disclosure {
    /// A local processor — no remote operator, but still a plaintext boundary.
    pub fn local() -> Self {
        Self {
            location: ProcessorLocation::Local,
            operator: None,
            region: None,
            retention: None,
            trains_on_data: None,
            subprocessors: Vec::new(),
        }
    }

    /// A remote processor with a known operator and region.
    pub fn remote(operator: &str, region: &str) -> Self {
        Self {
            location: ProcessorLocation::Remote,
            operator: Some(operator.to_owned()),
            region: Some(region.to_owned()),
            retention: None,
            trains_on_data: None,
            subprocessors: Vec::new(),
        }
    }

    /// Records a data-retention disclosure (builder).
    pub fn retains(mut self, retention: &str) -> Self {
        self.retention = Some(retention.to_owned());
        self
    }
}

/// A configured processor (design §15.2). The `config` is opaque provider settings
/// (model, parameters); it and the origin/provider are bound by `config_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorConfig {
    /// The local handle the operator selects (`axon processor add <id>`).
    pub processor_id: String,
    /// The provider/family (e.g. `example-ai`, `local-llama`).
    pub provider: String,
    /// The exact HTTPS origin dialed. A task never supplies this.
    pub origin: Origin,
    pub disclosure: Disclosure,
    /// Opaque provider configuration (model name, parameters).
    pub config: serde_json::Value,
}

/// Why a processor configuration could not be digested.
#[derive(Debug, thiserror::Error)]
#[error("processor config is not canonicalizable: {0}")]
pub struct ConfigError(String);

impl ProcessorConfig {
    /// Whether this processor is local (design §15.2 — still a plaintext boundary).
    pub fn is_local(&self) -> bool {
        self.disclosure.location == ProcessorLocation::Local
    }

    /// The digest binding the exact approved configuration (design §13.1): SHA-256
    /// over the RFC 8785 canonical bytes of `{provider, origin, config}`. The local
    /// handle and disclosure metadata are excluded — the digest names *what is
    /// dispatched*, so a call stays bound across a cosmetic label edit but breaks on
    /// any change to the provider, destination, or model parameters.
    pub fn config_digest(&self) -> Result<String, ConfigError> {
        let bound = serde_json::json!({
            "provider": self.provider,
            "origin": self.origin,
            "config": self.config,
        });
        let bytes = json_canon::to_vec(&bound).map_err(|e| ConfigError(e.to_string()))?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> ProcessorConfig {
        ProcessorConfig {
            processor_id: "reviewer".to_owned(),
            provider: "example-ai".to_owned(),
            origin: Origin::https("api.example.com", 443),
            disclosure: Disclosure::remote("Example AI", "us-east").retains("30d"),
            config: json!({"model": "review-1", "temperature": 0}),
        }
    }

    #[test]
    fn local_and_remote_disclosure() {
        assert!(!cfg().is_local());
        let local = ProcessorConfig {
            disclosure: Disclosure::local(),
            ..cfg()
        };
        assert!(local.is_local());
    }

    #[test]
    fn config_digest_is_stable_and_ignores_the_local_handle() {
        let a = cfg().config_digest().unwrap();
        // A different local id / disclosure label does not move the digest.
        let relabelled = ProcessorConfig {
            processor_id: "reviewer-2".to_owned(),
            disclosure: Disclosure::remote("Example AI", "eu-west"),
            ..cfg()
        };
        assert_eq!(a, relabelled.config_digest().unwrap());
        // A different model does.
        let remodelled = ProcessorConfig {
            config: json!({"model": "review-2", "temperature": 0}),
            ..cfg()
        };
        assert_ne!(a, remodelled.config_digest().unwrap());
        // A different origin does.
        let moved = ProcessorConfig {
            origin: Origin::https("api.example.com", 8443),
            ..cfg()
        };
        assert_ne!(a, moved.config_digest().unwrap());
    }
}
