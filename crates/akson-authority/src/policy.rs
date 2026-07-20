//! Standing local policy (design §12.4): deny and allow-once.
//!
//! V1 keeps policy minimal. A standing rule is a local *deny* ceiling evaluated
//! by a reconciler outside the receive path — it never turns message parsing into
//! execution. Everything a deny rule does not cover falls to the operator, who
//! may deny or allow **once** (a per-proposal decision, not a persisted grant).
//! Standing *allow* rules ("always allow this exact bounded rule") are Phase 2.
//!
//! §12.4 also fixes the suspension rule: a changed peer key, Agent Card, contract
//! type, processor, sandbox, or extension version suspends an otherwise-matching
//! rule. [`binding_changed`] is that primitive — it reports the first such change,
//! which both a future standing-allow rule and the §5.2 risk card (which
//! highlights any key/card/endpoint/processor change) consume.
//!
//! What you write:
//! ```
//! use akson_authority::{evaluate, PolicyDecision, StandingRule};
//! use akson_contract::Identity;
//! let peer = Identity { issuer: "iss".into(), agent: "requester".into() };
//! let rules = vec![StandingRule::deny(peer.clone(), Some("https://akson.invalid/spam".into()))];
//! // A denied task type is refused without a prompt; anything else prompts.
//! assert_eq!(evaluate(&rules, &peer, "https://akson.invalid/spam"), PolicyDecision::Deny);
//! assert_eq!(evaluate(&rules, &peer, "https://akson.invalid/review"), PolicyDecision::Prompt);
//! ```

use serde::{Deserialize, Serialize};

use akson_contract::Identity;

/// The outcome of evaluating standing policy against a proposal (design §12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// A standing deny rule matched — refuse without prompting.
    Deny,
    /// No standing rule applies — prompt the operator, who may deny or allow
    /// once (§5.2). Allow-once then issues a one-shot work order.
    Prompt,
}

/// A standing local policy rule. V1 has only deny; allow is Phase 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StandingRule {
    /// Deny work from `subject`. `task_type` `None` denies every task type from
    /// that subject; `Some(t)` denies only that type.
    Deny {
        subject: Identity,
        task_type: Option<String>,
    },
}

impl StandingRule {
    /// A deny rule for a subject and optional task type.
    pub fn deny(subject: Identity, task_type: Option<String>) -> Self {
        StandingRule::Deny { subject, task_type }
    }

    /// Whether this rule matches a request from `subject` for `task_type`.
    fn matches(&self, subject: &Identity, task_type: &str) -> bool {
        match self {
            StandingRule::Deny {
                subject: s,
                task_type: t,
            } => s == subject && t.as_deref().is_none_or(|t| t == task_type),
        }
    }
}

/// Evaluates standing policy: [`Deny`](PolicyDecision::Deny) if any deny rule
/// matches, else [`Prompt`](PolicyDecision::Prompt). Pure; runs outside the
/// receive path (§12.4).
pub fn evaluate(rules: &[StandingRule], subject: &Identity, task_type: &str) -> PolicyDecision {
    if rules.iter().any(|r| r.matches(subject, task_type)) {
        PolicyDecision::Deny
    } else {
        PolicyDecision::Prompt
    }
}

/// The safety-critical attributes a standing rule binds to (design §12.4). A
/// change in any of these suspends an otherwise-matching rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleBinding {
    /// The peer's Agent Card key thumbprint.
    pub peer_agent_card_key: String,
    pub contract_task_type: String,
    pub processor_id: Option<String>,
    pub sandbox_digest: Option<String>,
    pub extension_version: u32,
}

/// The first safety-critical change that suspends a rule (design §12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyChange {
    KeyChanged,
    TaskTypeChanged,
    ProcessorChanged,
    SandboxChanged,
    ExtensionChanged,
}

/// Reports the first safety-critical change between the pinned binding and the
/// currently presented one, or `None` if nothing policy-relevant changed
/// (design §12.4). A changed binding suspends a standing allow rule and is what
/// the §5.2 risk card highlights.
pub fn binding_changed(pinned: &RuleBinding, current: &RuleBinding) -> Option<PolicyChange> {
    if pinned.peer_agent_card_key != current.peer_agent_card_key {
        return Some(PolicyChange::KeyChanged);
    }
    if pinned.contract_task_type != current.contract_task_type {
        return Some(PolicyChange::TaskTypeChanged);
    }
    if pinned.processor_id != current.processor_id {
        return Some(PolicyChange::ProcessorChanged);
    }
    if pinned.sandbox_digest != current.sandbox_digest {
        return Some(PolicyChange::SandboxChanged);
    }
    if pinned.extension_version != current.extension_version {
        return Some(PolicyChange::ExtensionChanged);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    fn binding() -> RuleBinding {
        RuleBinding {
            peer_agent_card_key: "thumb-1".to_owned(),
            contract_task_type: "https://akson.invalid/review".to_owned(),
            processor_id: Some("local-x".to_owned()),
            sandbox_digest: Some("sbx-1".to_owned()),
            extension_version: 1,
        }
    }

    #[test]
    fn deny_rule_matches_by_subject_and_task_type() {
        let rules = vec![StandingRule::deny(
            peer("spammer"),
            Some("https://akson.invalid/spam".to_owned()),
        )];
        assert_eq!(
            evaluate(&rules, &peer("spammer"), "https://akson.invalid/spam"),
            PolicyDecision::Deny
        );
        // Different task type from the same peer is not denied by this rule.
        assert_eq!(
            evaluate(&rules, &peer("spammer"), "https://akson.invalid/review"),
            PolicyDecision::Prompt
        );
        // Different peer is not denied.
        assert_eq!(
            evaluate(&rules, &peer("other"), "https://akson.invalid/spam"),
            PolicyDecision::Prompt
        );
    }

    #[test]
    fn deny_all_task_types_from_a_subject() {
        let rules = vec![StandingRule::deny(peer("blocked"), None)];
        assert_eq!(
            evaluate(&rules, &peer("blocked"), "https://akson.invalid/anything"),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn no_rule_prompts() {
        assert_eq!(
            evaluate(&[], &peer("anyone"), "https://akson.invalid/x"),
            PolicyDecision::Prompt
        );
    }

    #[test]
    fn unchanged_binding_is_not_suspended() {
        assert_eq!(binding_changed(&binding(), &binding()), None);
    }

    #[test]
    fn each_safety_critical_change_is_reported() {
        let mut key = binding();
        key.peer_agent_card_key = "thumb-2".to_owned();
        assert_eq!(
            binding_changed(&binding(), &key),
            Some(PolicyChange::KeyChanged)
        );

        let mut proc = binding();
        proc.processor_id = Some("local-y".to_owned());
        assert_eq!(
            binding_changed(&binding(), &proc),
            Some(PolicyChange::ProcessorChanged)
        );

        let mut ext = binding();
        ext.extension_version = 2;
        assert_eq!(
            binding_changed(&binding(), &ext),
            Some(PolicyChange::ExtensionChanged)
        );

        let mut sbx = binding();
        sbx.sandbox_digest = Some("sbx-2".to_owned());
        assert_eq!(
            binding_changed(&binding(), &sbx),
            Some(PolicyChange::SandboxChanged)
        );
    }
}
