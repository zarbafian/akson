//! Required evidence slots (design §14.3): checking a result manifest's slot
//! records against what the contract required.
//!
//! Every slot carries two *orthogonal* fields — a `result`
//! (passed/failed/error/not_run/unavailable) and a `disclosure`
//! (full/summary/redacted). The rule the check enforces is: **omission cannot look
//! like success.** A missing slot, a non-passing result, or — for a contract that
//! requires *visible* passing evidence — a redacted/summarized view does not
//! satisfy the requirement. Disclosure never rewrites the result: a redacted view
//! of a failure is still a failure.
//!
//! What you write:
//! ```
//! use axon_evidence::{check_slots, RequiredSlot, SlotRecord, SlotResult, Disclosure};
//! let required = vec![RequiredSlot {
//!     slot_id: "license-scan".into(),
//!     required_result: SlotResult::Passed,
//!     require_full_disclosure: true,
//! }];
//! let provided = vec![SlotRecord {
//!     slot_id: "license-scan".into(), evidence_role: Some("license".into()),
//!     result: SlotResult::Passed, disclosure: Disclosure::Full,
//! }];
//! check_slots(&required, &provided).unwrap();
//! ```

use crate::result_manifest::{Disclosure, SlotRecord, SlotResult};

/// A slot the contract requires, and how it must be satisfied (design §14.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredSlot {
    pub slot_id: String,
    /// The result that satisfies the requirement — typically [`SlotResult::Passed`].
    /// Any other result (including `not_run`/`unavailable`) fails the check, so an
    /// omission cannot pass as success.
    pub required_result: SlotResult,
    /// Whether the evidence must be fully visible. A contract requiring "visible
    /// passing evidence" is not satisfied by a `summary` or `redacted` disclosure.
    pub require_full_disclosure: bool,
}

/// Why the provided slots do not satisfy the contract's required slots.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SlotError {
    #[error("required slot {0:?} is missing from the result manifest")]
    Missing(String),
    #[error("required slot {slot_id:?}: result is {got:?}, contract requires {want:?}")]
    ResultMismatch {
        slot_id: String,
        want: SlotResult,
        got: SlotResult,
    },
    #[error("required slot {slot_id:?} needs visible evidence but disclosure is {got:?}")]
    Redacted { slot_id: String, got: Disclosure },
    #[error("slot {0:?} has a passed/failed/error result but no evidence_role")]
    MissingEvidenceRole(String),
}

/// Checks that `provided` slot records satisfy every `required` slot (design
/// §14.3). Fails closed on the first unmet requirement. A provided slot not named
/// by any requirement is allowed (extra evidence is fine); a required slot that is
/// missing, non-passing, or under-disclosed fails.
pub fn check_slots(required: &[RequiredSlot], provided: &[SlotRecord]) -> Result<(), SlotError> {
    // Any conclusive slot must actually reference its evidence (belt-and-suspenders
    // over the schema, so a bug can't present a passing slot with no evidence).
    for slot in provided {
        let conclusive = matches!(
            slot.result,
            SlotResult::Passed | SlotResult::Failed | SlotResult::Error
        );
        if conclusive && slot.evidence_role.is_none() {
            return Err(SlotError::MissingEvidenceRole(slot.slot_id.clone()));
        }
    }

    for req in required {
        let Some(got) = provided.iter().find(|s| s.slot_id == req.slot_id) else {
            return Err(SlotError::Missing(req.slot_id.clone()));
        };
        if got.result != req.required_result {
            return Err(SlotError::ResultMismatch {
                slot_id: req.slot_id.clone(),
                want: req.required_result,
                got: got.result,
            });
        }
        if req.require_full_disclosure && got.disclosure != Disclosure::Full {
            return Err(SlotError::Redacted {
                slot_id: req.slot_id.clone(),
                got: got.disclosure,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn required(full: bool) -> Vec<RequiredSlot> {
        vec![RequiredSlot {
            slot_id: "license-scan".to_owned(),
            required_result: SlotResult::Passed,
            require_full_disclosure: full,
        }]
    }

    fn slot(result: SlotResult, disclosure: Disclosure) -> SlotRecord {
        SlotRecord {
            slot_id: "license-scan".to_owned(),
            evidence_role: Some("license".to_owned()),
            result,
            disclosure,
        }
    }

    #[test]
    fn a_passing_visible_slot_satisfies() {
        check_slots(
            &required(true),
            &[slot(SlotResult::Passed, Disclosure::Full)],
        )
        .unwrap();
    }

    #[test]
    fn a_missing_required_slot_fails() {
        assert_eq!(
            check_slots(&required(false), &[]),
            Err(SlotError::Missing("license-scan".to_owned()))
        );
    }

    #[test]
    fn a_failure_cannot_pass_even_if_present() {
        // Omission cannot look like success: a failed/not_run slot never satisfies.
        assert!(matches!(
            check_slots(
                &required(false),
                &[slot(SlotResult::Failed, Disclosure::Full)]
            ),
            Err(SlotError::ResultMismatch { .. })
        ));
        assert!(matches!(
            check_slots(
                &required(false),
                &[slot(SlotResult::NotRun, Disclosure::Full)]
            ),
            Err(SlotError::ResultMismatch { .. })
        ));
    }

    #[test]
    fn a_redacted_view_does_not_satisfy_visible_evidence() {
        // The result is passed, but the contract wants it visible and it is redacted.
        assert_eq!(
            check_slots(
                &required(true),
                &[slot(SlotResult::Passed, Disclosure::Redacted)]
            ),
            Err(SlotError::Redacted {
                slot_id: "license-scan".to_owned(),
                got: Disclosure::Redacted,
            })
        );
        // A summary also does not count as visible.
        assert!(matches!(
            check_slots(
                &required(true),
                &[slot(SlotResult::Passed, Disclosure::Summary)]
            ),
            Err(SlotError::Redacted { .. })
        ));
        // But when full disclosure is not required, a summary passes.
        check_slots(
            &required(false),
            &[slot(SlotResult::Passed, Disclosure::Summary)],
        )
        .unwrap();
    }

    #[test]
    fn a_conclusive_slot_without_evidence_is_refused() {
        let bad = SlotRecord {
            slot_id: "license-scan".to_owned(),
            evidence_role: None,
            result: SlotResult::Passed,
            disclosure: Disclosure::Full,
        };
        assert_eq!(
            check_slots(&required(false), &[bad]),
            Err(SlotError::MissingEvidenceRole("license-scan".to_owned()))
        );
    }
}
