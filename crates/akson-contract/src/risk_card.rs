//! Risk-card projection (design §5.2): the five approval questions as structured
//! data for the CLI.
//!
//! Before local work, Akson groups the decision into five questions — Who, What
//! leaves, What runs, Limits, Evidence and destination. This module projects the
//! part of each question the *signed contract* fixes, as plain structured data
//! the CLI renders. The remaining context — the peer's assurance and any key/
//! card/endpoint change (§8.4), the processor's operator/region/retention/
//! training policy, the actual selected processor and its explicit denials, and
//! whether an independent verifier is configured — is not in the contract; the
//! CLI/authority overlays it from peer state and local policy. Keeping the two
//! apart means the contract projection is pure and deterministic.
//!
//! What you write:
//! ```
//! use akson_contract::project_risk_card;
//! # use akson_contract::parse_payload;
//! # use serde_json::json;
//! # let value = json!({
//! #   "schema_version": 1, "contract_id": "00000000-0000-4000-8000-000000000000",
//! #   "revision": 0, "task_type": "https://akson.invalid/t", "message_id": "m1",
//! #   "requester": {"issuer": "iss", "agent": "requester"},
//! #   "performer": {"issuer": "iss", "agent": "performer"}, "objective": "o",
//! #   "inputs": [], "deliverables": [{"role": "r", "media_type": "text/plain"}],
//! #   "evidence_slots": [], "requested_capabilities": ["respond"],
//! #   "processor_constraints": {"disclosure": "none"},
//! #   "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
//! #   "result_recipient": "request-origin", "created_at": "2026-01-01T00:00:00Z",
//! #   "expires_at": "2030-01-01T00:00:00Z"
//! # });
//! # let proposal = parse_payload(&akson_ext::jcs::canonical_bytes(&value).unwrap()).unwrap();
//! let card = project_risk_card(&proposal);
//! assert_eq!(card.limits.revision_digest, proposal.digest);
//! assert_eq!(card.who.requester.agent, "requester");
//! ```

use serde::Serialize;

use crate::contract::{
    Capability, Disclosure, Identity, ParsedContract, ResultRecipient, TrustClass,
};

/// The five §5.2 questions the contract fixes, ready for the CLI to render and
/// overlay with peer/policy context.
#[derive(Debug, Clone, Serialize)]
pub struct RiskCard {
    pub who: Who,
    pub what_leaves: WhatLeaves,
    pub what_runs: WhatRuns,
    pub limits: LimitsCard,
    pub evidence_and_destination: EvidenceDestination,
}

/// Question 1 — Who. Assurance and change highlighting are overlaid by the CLI.
#[derive(Debug, Clone, Serialize)]
pub struct Who {
    pub requester: Identity,
    pub task_type: String,
}

/// One input the worker or processor may see. Operator/region/retention/training
/// of the processor are overlaid by the CLI.
#[derive(Debug, Clone, Serialize)]
pub struct ExposedInput {
    pub id: String,
    pub media_type: String,
    pub byte_length: u64,
    pub worker_visible: bool,
    pub processor_visible: bool,
}

/// Question 2 — What leaves.
#[derive(Debug, Clone, Serialize)]
pub struct WhatLeaves {
    pub inputs: Vec<ExposedInput>,
    pub processor_disclosure: Disclosure,
}

/// Question 3 — What runs. The selected processor and its explicit denials are
/// overlaid by the authority.
#[derive(Debug, Clone, Serialize)]
pub struct WhatRuns {
    pub task_type: String,
    pub requested_capabilities: Vec<Capability>,
    pub processor_disclosure: Disclosure,
}

/// Question 4 — Limits.
#[derive(Debug, Clone, Serialize)]
pub struct LimitsCard {
    pub revision: u64,
    pub revision_digest: String,
    pub deadline: String,
    pub max_response_bytes: u64,
    pub max_cost_microusd: Option<u64>,
}

/// A required evidence slot in the card.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceSlotCard {
    pub slot_id: String,
    pub statement_type: String,
    pub trust_classes: Vec<TrustClass>,
}

/// Question 5 — Evidence and destination. Whether an independent verifier is
/// configured ("Independent verifier: none" unless one is) is overlaid by the CLI.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceDestination {
    pub evidence_slots: Vec<EvidenceSlotCard>,
    pub result_recipient: ResultRecipient,
    pub retention_days: Option<u32>,
}

/// Projects the contract-fixed portion of the five §5.2 questions. Pure and
/// deterministic — no peer or policy context enters here.
pub fn project_risk_card(proposal: &ParsedContract) -> RiskCard {
    let c = &proposal.contract;
    RiskCard {
        who: Who {
            requester: c.requester.clone(),
            task_type: c.task_type.clone(),
        },
        what_leaves: WhatLeaves {
            inputs: c
                .inputs
                .iter()
                .map(|e| ExposedInput {
                    id: e.id.clone(),
                    media_type: e.media_type.clone(),
                    byte_length: e.byte_length,
                    worker_visible: e.worker_visible,
                    processor_visible: e.processor_visible,
                })
                .collect(),
            processor_disclosure: c.processor_constraints.disclosure,
        },
        what_runs: WhatRuns {
            task_type: c.task_type.clone(),
            requested_capabilities: c.requested_capabilities.clone(),
            processor_disclosure: c.processor_constraints.disclosure,
        },
        limits: LimitsCard {
            revision: c.revision,
            revision_digest: proposal.digest.clone(),
            deadline: c.limits.deadline.clone(),
            max_response_bytes: c.limits.max_response_bytes,
            max_cost_microusd: c.limits.max_cost_microusd,
        },
        evidence_and_destination: EvidenceDestination {
            evidence_slots: c
                .evidence_slots
                .iter()
                .map(|s| EvidenceSlotCard {
                    slot_id: s.slot_id.clone(),
                    statement_type: s.statement_type.clone(),
                    trust_classes: s.trust_classes.clone(),
                })
                .collect(),
            result_recipient: c.result_recipient,
            retention_days: c.retention_request.as_ref().map(|r| r.days),
        },
    }
}

/// A rendered risk card (design §5.2): a concrete one-line approval sentence the
/// operator acts on, plus expandable detail — one section per §5.2 question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedRiskCard {
    /// The single concrete sentence shown for the approve/deny decision.
    pub sentence: String,
    /// The expandable detail, one [`RiskSection`] per §5.2 question.
    pub sections: Vec<RiskSection>,
}

/// One expandable detail section of a rendered risk card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskSection {
    pub heading: String,
    pub lines: Vec<String>,
}

impl RiskCard {
    /// Renders the card into a concrete approval sentence and expandable detail
    /// (design §5.2). Pure text over the contract-fixed data; peer/policy/processor
    /// context (operator, region, and "Independent verifier: none" unless one is
    /// configured) is overlaid by the caller before display.
    pub fn render(&self) -> RenderedRiskCard {
        let inputs = &self.what_leaves.inputs;
        let n = inputs.len();
        let total_bytes: u64 = inputs.iter().map(|i| i.byte_length).sum();
        let to_processor = inputs.iter().filter(|i| i.processor_visible).count();
        let disclosure = disclosure_phrase(self.what_leaves.processor_disclosure);
        let recipient = recipient_phrase(self.evidence_and_destination.result_recipient);

        let processor_clause = if to_processor > 0 {
            format!(", {to_processor} of them to {disclosure}")
        } else {
            String::new()
        };
        let sentence = format!(
            "Approve {} to run \"{}\": {n} input(s) ({total_bytes} B) go to the worker{processor_clause}; up to {} B come back to {recipient} by {}.",
            self.who.requester.agent, self.who.task_type, self.limits.max_response_bytes, self.limits.deadline,
        );

        let mut what_leaves: Vec<String> = inputs
            .iter()
            .map(|i| {
                let dest = match (i.worker_visible, i.processor_visible) {
                    (true, true) => "worker + processor",
                    (true, false) => "worker only",
                    (false, true) => "processor only",
                    (false, false) => "neither",
                };
                format!("{} — {} ({} B) → {dest}", i.id, i.media_type, i.byte_length)
            })
            .collect();
        what_leaves.push(format!("processor disclosure: {disclosure}"));

        let caps: Vec<&str> = self
            .what_runs
            .requested_capabilities
            .iter()
            .map(|c| capability_phrase(*c))
            .collect();

        let mut limits = vec![
            format!(
                "revision {} ({}…)",
                self.limits.revision,
                &self.limits.revision_digest[..self.limits.revision_digest.len().min(12)]
            ),
            format!("deadline: {}", self.limits.deadline),
            format!("max response: {} B", self.limits.max_response_bytes),
        ];
        if let Some(cost) = self.limits.max_cost_microusd {
            limits.push(format!("max cost: {cost} µUSD (estimate)"));
        }

        let mut destination: Vec<String> = self
            .evidence_and_destination
            .evidence_slots
            .iter()
            .map(|s| {
                let classes: Vec<&str> = s
                    .trust_classes
                    .iter()
                    .map(|t| trust_class_phrase(*t))
                    .collect();
                format!(
                    "slot {} — {} [{}]",
                    s.slot_id,
                    s.statement_type,
                    classes.join(", ")
                )
            })
            .collect();
        destination.push(format!("results to: {recipient}"));
        if let Some(days) = self.evidence_and_destination.retention_days {
            destination.push(format!("retention: {days} day(s)"));
        }

        RenderedRiskCard {
            sentence,
            sections: vec![
                RiskSection {
                    heading: "Who".to_owned(),
                    lines: vec![
                        format!(
                            "requester: {} (issuer {})",
                            self.who.requester.agent, self.who.requester.issuer
                        ),
                        format!("task type: {}", self.who.task_type),
                    ],
                },
                RiskSection {
                    heading: "What leaves".to_owned(),
                    lines: what_leaves,
                },
                RiskSection {
                    heading: "What runs".to_owned(),
                    lines: vec![format!(
                        "capabilities: {}",
                        if caps.is_empty() {
                            "none".to_owned()
                        } else {
                            caps.join(", ")
                        }
                    )],
                },
                RiskSection {
                    heading: "Limits".to_owned(),
                    lines: limits,
                },
                RiskSection {
                    heading: "Evidence & destination".to_owned(),
                    lines: destination,
                },
            ],
        }
    }
}

fn disclosure_phrase(d: Disclosure) -> &'static str {
    match d {
        Disclosure::None => "no processor",
        Disclosure::LocalOnly => "a local processor",
        Disclosure::NamedRemote => "a named remote processor",
    }
}

fn capability_phrase(c: Capability) -> &'static str {
    match c {
        Capability::Respond => "respond to the requester",
        Capability::ReadSuppliedInputs => "read the supplied inputs",
        Capability::ProcessorUse => "use a processor",
        Capability::ArtifactExport => "export artifacts",
    }
}

fn recipient_phrase(r: ResultRecipient) -> &'static str {
    match r {
        ResultRecipient::RequestOrigin => "the request origin",
    }
}

fn trust_class_phrase(t: TrustClass) -> &'static str {
    match t {
        TrustClass::SelfAttested => "self-attested",
        TrustClass::IndependentlyVerified => "independently verified",
        TrustClass::HardwareAttested => "hardware-attested",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::parse_payload;
    use serde_json::json;

    fn proposal() -> ParsedContract {
        let value = json!({
            "schema_version": 1,
            "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0,
            "task_type": "https://akson.invalid/task/code-review/v1",
            "message_id": "m1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"},
            "objective": "review the diff",
            "inputs": [{
                "id": "diff", "message_id": "m1", "part_index": 1, "kind": "text",
                "media_type": "text/x-diff", "charset": "utf-8", "canonical_rule": "utf8-exact",
                "byte_length": 42, "sha256": "a".repeat(64), "worker_visible": true,
                "processor_visible": false
            }],
            "deliverables": [{"role": "review", "media_type": "application/json"}],
            "evidence_slots": [{
                "slot_id": "authz", "statement_type": "https://in-toto.io/attestation",
                "trust_classes": ["self-attested"]
            }],
            "requested_capabilities": ["respond", "read_supplied_inputs"],
            "processor_constraints": {"disclosure": "local-only"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 8192, "max_cost_microusd": 500},
            "result_recipient": "request-origin",
            "retention_request": {"days": 30},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z"
        });
        parse_payload(&akson_ext::jcs::canonical_bytes(&value).unwrap()).unwrap()
    }

    #[test]
    fn projects_all_five_questions_from_the_contract() {
        let p = proposal();
        let card = project_risk_card(&p);

        // Who
        assert_eq!(card.who.requester.agent, "requester");
        assert!(card.who.task_type.contains("code-review"));
        // What leaves
        assert_eq!(card.what_leaves.inputs.len(), 1);
        assert_eq!(card.what_leaves.inputs[0].id, "diff");
        assert!(card.what_leaves.inputs[0].worker_visible);
        assert!(!card.what_leaves.inputs[0].processor_visible);
        assert_eq!(card.what_leaves.processor_disclosure, Disclosure::LocalOnly);
        // What runs
        assert_eq!(card.what_runs.requested_capabilities.len(), 2);
        // Limits (the revision digest is the exact signed-contract digest)
        assert_eq!(card.limits.revision_digest, p.digest);
        assert_eq!(card.limits.max_response_bytes, 8192);
        assert_eq!(card.limits.max_cost_microusd, Some(500));
        // Evidence and destination
        assert_eq!(card.evidence_and_destination.evidence_slots.len(), 1);
        assert_eq!(card.evidence_and_destination.retention_days, Some(30));
        assert_eq!(
            card.evidence_and_destination.result_recipient,
            ResultRecipient::RequestOrigin
        );
    }

    #[test]
    fn serializes_to_json_for_the_cli() {
        let card = project_risk_card(&proposal());
        let v = serde_json::to_value(&card).unwrap();
        // Enum renderings follow the wire vocabulary.
        assert_eq!(v["what_leaves"]["processor_disclosure"], "local-only");
        assert_eq!(
            v["evidence_and_destination"]["result_recipient"],
            "request-origin"
        );
        assert_eq!(v["what_runs"]["requested_capabilities"][0], "respond");
    }

    #[test]
    fn renders_a_concrete_approval_sentence_and_five_sections() {
        let rendered = project_risk_card(&proposal()).render();
        // The one-line sentence names the requester, task, input bytes, recipient,
        // and deadline — enough to approve or deny without expanding.
        for needle in [
            "requester",
            "code-review",
            "42 B",
            "the request origin",
            "2030-01-01",
        ] {
            assert!(
                rendered.sentence.contains(needle),
                "sentence missing {needle:?}: {}",
                rendered.sentence
            );
        }
        // Exactly the five §5.2 questions, in order.
        let headings: Vec<&str> = rendered
            .sections
            .iter()
            .map(|s| s.heading.as_str())
            .collect();
        assert_eq!(
            headings,
            [
                "Who",
                "What leaves",
                "What runs",
                "Limits",
                "Evidence & destination"
            ]
        );
        // Capabilities render readably; the slot's trust class is spelled out.
        assert!(rendered.sections[2].lines[0].contains("respond to the requester"));
        assert!(rendered.sections[2].lines[0].contains("read the supplied inputs"));
        assert!(rendered.sections[4]
            .lines
            .iter()
            .any(|l| l.contains("self-attested")));
        assert!(rendered.sections[4]
            .lines
            .iter()
            .any(|l| l.contains("retention: 30 day(s)")));
    }
}
