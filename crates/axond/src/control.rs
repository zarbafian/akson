//! The local control surfaces and their authority separation (design §16.2).
//!
//! The daemon exposes two local surfaces: an OS-protected **admin** socket
//! (pairing, policy, approval, recovery, audit) and a narrow **worker** socket
//! (task input, progress, result submission, evidence references). The worker
//! surface can never pair a peer, create standing policy, approve a contract, issue
//! a work order, sign a requester outcome, or export unrelated content — even if
//! the process on it is same-UID.
//!
//! [`authorize`] is the pure gate: every control operation declares the minimum
//! surface it needs, and a request arriving on a lower surface is refused with an
//! RFC 9457 [`Problem`] that reveals nothing about hidden paths, policy, or peers.
//!
//! What you write:
//! ```
//! use axond::{authorize, ControlOp, Surface};
//! // The worker surface may submit a result…
//! authorize(Surface::Worker, ControlOp::SubmitResult).unwrap();
//! // …but never issue a work order.
//! assert!(authorize(Surface::Worker, ControlOp::IssueWorkOrder).is_err());
//! ```

use serde::{Deserialize, Serialize};

/// Which local surface a connection arrived on (design §16.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// The OS-protected admin socket — authority-bearing operator operations.
    Admin,
    /// The narrow adapter/worker socket — task I/O only.
    Worker,
}

impl Surface {
    /// Whether this surface is at least as privileged as `required`.
    fn satisfies(self, required: Surface) -> bool {
        // Admin dominates Worker; Worker satisfies only Worker.
        matches!(
            (self, required),
            (Surface::Admin, _) | (Surface::Worker, Surface::Worker)
        )
    }
}

/// A control-plane operation, grouped by the authority it needs (design §16.2,
/// §16.4). The wire protocol carries richer arguments; this is the authorization
/// unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlOp {
    // --- Worker surface (narrow task I/O, design §16.2) ---
    /// Deliver an approved task-input manifest to the worker.
    SubmitTaskInput,
    /// Report bounded progress from the worker.
    ReportProgress,
    /// Submit a bounded result artifact from the worker.
    SubmitResult,
    /// Reference an evidence statement produced by the worker.
    ReferenceEvidence,

    // --- Admin surface (authority-bearing, design §16.2/§16.4) ---
    /// Pair, accept, list, or remove a peer.
    Pair,
    /// Create or change standing policy.
    Policy,
    /// Approve or deny a contract proposal.
    ApproveContract,
    /// Issue a one-shot work order.
    IssueWorkOrder,
    /// Sign a requester outcome.
    SignOutcome,
    /// Deliver a completed Task's signed result to the requester.
    DeliverResult,
    /// Export content (verification pack, evidence).
    Export,
    /// Recovery and audit operations.
    Recovery,
    /// Configure a processor.
    Processor,
    /// Inspect the task inbox / a task.
    TaskInspect,
    /// Cancel a task.
    TaskCancel,
    /// Show a peer or the policy.
    Inspect,
    /// Report daemon and sandbox health (`axon doctor`, `axon status`).
    Diagnose,
}

impl ControlOp {
    /// The minimum surface this operation requires (design §16.2). The four worker
    /// operations need only the worker surface; everything authority-bearing or
    /// operator-facing needs the admin surface.
    pub fn required_surface(self) -> Surface {
        match self {
            ControlOp::SubmitTaskInput
            | ControlOp::ReportProgress
            | ControlOp::SubmitResult
            | ControlOp::ReferenceEvidence => Surface::Worker,
            _ => Surface::Admin,
        }
    }
}

/// An RFC 9457 Problem Details object (design §16.2). Deliberately generic — it
/// never discloses whether a hidden path, secret, policy rule, or internal peer
/// exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// A stable problem-type URI (a `urn:axon:*` tag; not dereferenced).
    #[serde(rename = "type")]
    pub type_: String,
    pub title: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Problem {
    /// A `403 Forbidden` for an operation not permitted on the caller's surface.
    /// The detail names only the surface, never the operation's internals.
    pub fn forbidden_surface(surface: Surface) -> Self {
        Self {
            type_: "urn:axon:error:forbidden-surface".to_owned(),
            title: "operation not permitted on this local surface".to_owned(),
            status: 403,
            detail: Some(
                match surface {
                    Surface::Worker => "the worker surface cannot perform admin operations",
                    Surface::Admin => "operation not permitted",
                }
                .to_owned(),
            ),
        }
    }
}

/// Authorizes `op` on `surface` (design §16.2). Returns `Ok` when the surface is at
/// least the operation's required surface, else an RFC 9457 [`Problem`].
pub fn authorize(surface: Surface, op: ControlOp) -> Result<(), Problem> {
    if surface.satisfies(op.required_surface()) {
        Ok(())
    } else {
        Err(Problem::forbidden_surface(surface))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const WORKER_OPS: [ControlOp; 4] = [
        ControlOp::SubmitTaskInput,
        ControlOp::ReportProgress,
        ControlOp::SubmitResult,
        ControlOp::ReferenceEvidence,
    ];

    const ADMIN_ONLY_OPS: [ControlOp; 11] = [
        ControlOp::Pair,
        ControlOp::Policy,
        ControlOp::ApproveContract,
        ControlOp::IssueWorkOrder,
        ControlOp::SignOutcome,
        ControlOp::DeliverResult,
        ControlOp::Export,
        ControlOp::Recovery,
        ControlOp::Processor,
        ControlOp::TaskCancel,
        ControlOp::Diagnose,
    ];

    #[test]
    fn admin_may_do_everything() {
        for op in WORKER_OPS.into_iter().chain(ADMIN_ONLY_OPS) {
            authorize(Surface::Admin, op).unwrap_or_else(|_| panic!("admin should allow {op:?}"));
        }
    }

    #[test]
    fn worker_may_only_do_the_four_task_io_ops() {
        for op in WORKER_OPS {
            authorize(Surface::Worker, op).unwrap_or_else(|_| panic!("worker should allow {op:?}"));
        }
    }

    #[test]
    fn worker_cannot_bear_authority() {
        // The exact §16.2 prohibitions: pair, policy, approve, issue, sign, export.
        for op in [
            ControlOp::Pair,
            ControlOp::Policy,
            ControlOp::ApproveContract,
            ControlOp::IssueWorkOrder,
            ControlOp::SignOutcome,
            ControlOp::Export,
        ] {
            let problem = authorize(Surface::Worker, op).unwrap_err();
            assert_eq!(problem.status, 403);
            // The error does not name the operation — no structure leaks.
            assert!(!format!("{problem:?}").to_lowercase().contains("workorder"));
        }
    }

    #[test]
    fn the_problem_is_generic_and_serializes_as_rfc9457() {
        let problem = Problem::forbidden_surface(Surface::Worker);
        let json = serde_json::to_value(&problem).unwrap();
        assert_eq!(json["type"], "urn:axon:error:forbidden-surface");
        assert_eq!(json["status"], 403);
        assert!(json.get("title").is_some());
    }
}
