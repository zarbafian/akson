//! The orthogonal capability vector (design §12.1).
//!
//! Enforcement uses independent components, not cumulative NONE/READ/WRITE/EXEC
//! levels — components never imply one another. Running a verifier does not imply
//! host write, network, secret, or command authority. All twelve §12.1 components
//! are named by [`CapabilityComponent`]; only v1's four —
//! [`respond`](CapabilityComponent::Respond),
//! [`read_supplied_inputs`](CapabilityComponent::ReadSuppliedInputs),
//! [`processor_use`](CapabilityComponent::ProcessorUse), and
//! [`artifact_export`](CapabilityComponent::ArtifactExport) — are grantable, and
//! only those carry a scope in [`Grant`]. The rest are reserved for later phases;
//! the type system alone prevents granting them in v1.
//!
//! What you write:
//! ```
//! use akson_authority::{CapabilityVector, Grant, RespondScope};
//! let vector = CapabilityVector::new(vec![
//!     Grant::Respond(RespondScope {
//!         task_id: "task-1".into(),
//!         message_id: "msg-1".into(),
//!         recipient: "request-origin".into(),
//!         max_responses: 1,
//!         max_bytes: 8192,
//!         deadline: "2030-01-01T00:00:00Z".into(),
//!     }),
//! ]).unwrap();
//! assert_eq!(vector.grants().len(), 1);
//! ```

use serde::{Deserialize, Serialize};

/// Every §12.1 capability component. Only the v1-grantable four carry a [`Grant`];
/// the others are named so they can appear in risk cards and audit records and be
/// rejected explicitly, but cannot be granted in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityComponent {
    Respond,
    ReadSuppliedInputs,
    ReadSnapshot,
    ProcessorUse,
    StageWrite,
    RunProfile,
    Apply,
    Egress,
    SecretUse,
    ArtifactExport,
    Delegate,
    RemoteCancel,
}

impl CapabilityComponent {
    /// Whether this component may be granted in a v1 work order (§12.1). Only
    /// respond, read_supplied_inputs, processor_use, and artifact_export.
    pub fn grantable_in_v1(self) -> bool {
        matches!(
            self,
            CapabilityComponent::Respond
                | CapabilityComponent::ReadSuppliedInputs
                | CapabilityComponent::ProcessorUse
                | CapabilityComponent::ArtifactExport
        )
    }
}

/// `respond` scope: the exact task/message, recipient, and response bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RespondScope {
    pub task_id: String,
    pub message_id: String,
    pub recipient: String,
    pub max_responses: u32,
    pub max_bytes: u64,
    pub deadline: String,
}

/// `read_supplied_inputs` scope: the exact signed input-manifest entries the
/// worker may read, named by their logical ids and pinned by the manifest digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadInputsScope {
    pub input_ids: Vec<String>,
    /// Digest binding the exact contract that authorized these inputs.
    pub contract_digest: String,
}

/// `processor_use` scope: the exact configured processor, the approved input
/// manifest, and cost/byte budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorUseScope {
    pub processor_id: String,
    pub input_ids: Vec<String>,
    pub max_cost_microusd: u64,
    pub max_bytes: u64,
}

/// `artifact_export` scope: the exact recipient, task, and export bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactExportScope {
    pub recipient: String,
    pub task_id: String,
    pub media_types: Vec<String>,
    pub max_count: u32,
    pub max_bytes: u64,
}

/// One granted capability and its scope. The variants are exactly the v1-grantable
/// components — a non-v1 component has no `Grant`, so it cannot be authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "component", rename_all = "snake_case")]
pub enum Grant {
    Respond(RespondScope),
    ReadSuppliedInputs(ReadInputsScope),
    ProcessorUse(ProcessorUseScope),
    ArtifactExport(ArtifactExportScope),
}

impl Grant {
    /// The component this grant authorizes.
    pub fn component(&self) -> CapabilityComponent {
        match self {
            Grant::Respond(_) => CapabilityComponent::Respond,
            Grant::ReadSuppliedInputs(_) => CapabilityComponent::ReadSuppliedInputs,
            Grant::ProcessorUse(_) => CapabilityComponent::ProcessorUse,
            Grant::ArtifactExport(_) => CapabilityComponent::ArtifactExport,
        }
    }
}

/// Why a capability vector could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VectorError {
    #[error("capability vector grants {0:?} more than once")]
    DuplicateComponent(CapabilityComponent),
    #[error("capability vector is empty")]
    Empty,
}

/// The explicit capability vector a work order carries (§12.3): the exact set of
/// granted capabilities, at most one grant per component. Absence of a component
/// is a denial — there is no implicit authority.
///
/// `Deserialize` routes through [`CapabilityVector::new`], so a vector read from
/// JSON/IPC is held to the same invariants (non-empty, one grant per component) as
/// one built in-process — a duplicate or empty grant set cannot be synthesized past
/// the constructor. Serialization keeps the `{ "grants": [..] }` shape so the
/// work-order MAC bytes are unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityVector {
    grants: Vec<Grant>,
}

impl<'de> Deserialize<'de> for CapabilityVector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            grants: Vec<Grant>,
        }
        let raw = Raw::deserialize(deserializer)?;
        CapabilityVector::new(raw.grants).map_err(serde::de::Error::custom)
    }
}

impl CapabilityVector {
    /// Builds a vector, rejecting a duplicate component or an empty set. A grant
    /// per component is a full replacement, never additive — orthogonality means
    /// two `respond` grants would be ambiguous, so it is refused.
    pub fn new(grants: Vec<Grant>) -> Result<Self, VectorError> {
        if grants.is_empty() {
            return Err(VectorError::Empty);
        }
        for (i, g) in grants.iter().enumerate() {
            if grants[..i].iter().any(|h| h.component() == g.component()) {
                return Err(VectorError::DuplicateComponent(g.component()));
            }
        }
        Ok(Self { grants })
    }

    /// The granted capabilities.
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// The grant for a component, if present (the authority for that component).
    pub fn grant(&self, component: CapabilityComponent) -> Option<&Grant> {
        self.grants.iter().find(|g| g.component() == component)
    }

    /// Whether the vector grants a component. Absence is denial (§12.1).
    pub fn grants_component(&self, component: CapabilityComponent) -> bool {
        self.grant(component).is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn respond() -> Grant {
        Grant::Respond(RespondScope {
            task_id: "task-1".to_owned(),
            message_id: "msg-1".to_owned(),
            recipient: "request-origin".to_owned(),
            max_responses: 1,
            max_bytes: 8192,
            deadline: "2030-01-01T00:00:00Z".to_owned(),
        })
    }

    fn processor() -> Grant {
        Grant::ProcessorUse(ProcessorUseScope {
            processor_id: "local-x".to_owned(),
            input_ids: vec!["src".to_owned()],
            max_cost_microusd: 500,
            max_bytes: 4096,
        })
    }

    #[test]
    fn only_the_four_v1_components_are_grantable() {
        use CapabilityComponent::*;
        for c in [Respond, ReadSuppliedInputs, ProcessorUse, ArtifactExport] {
            assert!(c.grantable_in_v1(), "{c:?} should be grantable");
        }
        for c in [
            ReadSnapshot,
            StageWrite,
            RunProfile,
            Apply,
            Egress,
            SecretUse,
            Delegate,
            RemoteCancel,
        ] {
            assert!(!c.grantable_in_v1(), "{c:?} must not be grantable in v1");
        }
    }

    #[test]
    fn vector_indexes_by_component_and_denies_absent() {
        let v = CapabilityVector::new(vec![respond(), processor()]).unwrap();
        assert_eq!(v.grants().len(), 2);
        assert!(v.grants_component(CapabilityComponent::Respond));
        assert!(v.grants_component(CapabilityComponent::ProcessorUse));
        // Absence is denial — no implicit authority.
        assert!(!v.grants_component(CapabilityComponent::ArtifactExport));
        assert!(matches!(
            v.grant(CapabilityComponent::Respond),
            Some(Grant::Respond(_))
        ));
    }

    #[test]
    fn duplicate_component_and_empty_reject() {
        assert_eq!(
            CapabilityVector::new(vec![respond(), respond()]),
            Err(VectorError::DuplicateComponent(
                CapabilityComponent::Respond
            ))
        );
        assert_eq!(CapabilityVector::new(vec![]), Err(VectorError::Empty));
    }

    #[test]
    fn grant_carries_only_its_component() {
        assert_eq!(respond().component(), CapabilityComponent::Respond);
        assert_eq!(processor().component(), CapabilityComponent::ProcessorUse);
    }

    #[test]
    fn deserialize_enforces_the_constructor_invariants() {
        // A valid vector round-trips through the {"grants":[..]} shape.
        let v = CapabilityVector::new(vec![respond(), processor()]).unwrap();
        let json = serde_json::to_value(&v).unwrap();
        assert!(
            json.get("grants").is_some(),
            "shape must stay {{grants:[..]}}"
        );
        let back: CapabilityVector = serde_json::from_value(json).unwrap();
        assert_eq!(v, back);

        // A duplicate component in JSON is rejected at the deserialization boundary,
        // not silently accepted (which would let grant() shadow the second grant).
        let dup = serde_json::json!({"grants": [
            {"component": "respond", "task_id": "t", "message_id": "m",
             "recipient": "request-origin", "max_responses": 1, "max_bytes": 8192,
             "deadline": "2030-01-01T00:00:00Z"},
            {"component": "respond", "task_id": "t2", "message_id": "m2",
             "recipient": "request-origin", "max_responses": 1, "max_bytes": 8192,
             "deadline": "2030-01-01T00:00:00Z"}
        ]});
        assert!(serde_json::from_value::<CapabilityVector>(dup).is_err());

        // An empty grant set is rejected too (new() forbids it).
        let empty = serde_json::json!({"grants": []});
        assert!(serde_json::from_value::<CapabilityVector>(empty).is_err());
    }
}
