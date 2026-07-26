//! The local control surfaces and their authority separation (design §16.2).
//!
//! The daemon exposes three local surfaces: an OS-protected **admin** socket
//! (pairing, policy, approval, recovery, audit), a narrow **worker** socket (task
//! input, progress, result submission, evidence references), and — when a
//! coordination UID is configured — a **coord** socket for a *different* local
//! principal (ADR-0016: stage, read, dispatch). Neither narrow surface can pair a
//! peer, create standing policy, approve a contract, issue a work order, sign a
//! requester outcome, or export unrelated content — even if the process on it is
//! same-UID.
//!
//! [`authorize`] is the pure gate: every control operation declares the minimum
//! surface it needs, and a request arriving on a surface that does not dominate it
//! is refused with an RFC 9457 [`Problem`] that reveals nothing about hidden paths,
//! policy, or peers.
//!
//! What you write:
//! ```
//! use aksond::{authorize, ControlOp, Surface};
//! // The worker surface may submit a result…
//! authorize(Surface::Worker, ControlOp::SubmitResult).unwrap();
//! // …but never issue a work order.
//! assert!(authorize(Surface::Worker, ControlOp::IssueWorkOrder).is_err());
//! // And consent is admin's alone: the coordination surface cannot mint it.
//! assert!(authorize(Surface::Coord, ControlOp::StageConsent).is_err());
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
    /// The coordination socket (ADR-0016): a *different* local principal
    /// stages outbound contracts and reads coordination state. It reaches no
    /// admin operation, and admin's own consent minting is not on it.
    Coord,
}

impl Surface {
    /// Whether this surface is at least as privileged as `required`.
    ///
    /// The relation is stated case by case rather than inferred, because
    /// ADR-0016 makes it deliberately asymmetric: admin dominates both of the
    /// narrow surfaces (so an operator can diagnose them), while `Worker` and
    /// `Coord` dominate nothing at all — including each other. A coord
    /// connection reaching a worker op, or the reverse, is exactly the
    /// confusion the third socket exists to prevent.
    fn satisfies(self, required: Surface) -> bool {
        matches!(
            (self, required),
            (Surface::Admin, _)
                | (Surface::Worker, Surface::Worker)
                | (Surface::Coord, Surface::Coord)
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
    /// Request the daemon to make a processor call on the worker's behalf.
    RequestProcessorCall,

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
    /// Send a task to a performer (sign + POST a contract proposal).
    SendTask,
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
    /// Run an approved task's worker in the sandbox and submit its result.
    RunWorker,
    /// Fulfil an approved task with an operator-provided result (no sandbox).
    FulfillTask,
    /// Show a peer or the policy.
    Inspect,
    /// Report daemon and sandbox health (`akson doctor`, `akson status`).
    Diagnose,
    /// Mint the one-shot consent receipt for an exact staged digest, after the
    /// operator has seen its risk card. Admin-only, deliberately: the outward
    /// disclosure is never the coordination driver's to authorize (ADR-0016).
    StageConsent,

    // --- Coordination surface (ADR-0016, akson_byom_exchange_v1) ---
    /// Identity + protocol/feature versions, for the driver's own handshake.
    CoordWhoAmI,
    /// A verified peer's identity tuple and card claims.
    CoordPeerShow,
    /// Stage outbound bytes, inert and idempotent on their content digest.
    CoordStage,
    /// The status and digests of a staged contract.
    CoordStageShow,
    /// One-shot: consume a consent receipt and dispatch the staged bytes.
    CoordDispatch,
    /// The verification status of a dispatched task.
    CoordTaskStatus,
    /// Durable cursored coordination events.
    CoordEventsRead,
    /// `FederationCapabilityEvidence` for a peer.
    CoordCapabilityEvidence,
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
            | ControlOp::ReferenceEvidence
            | ControlOp::RequestProcessorCall => Surface::Worker,
            ControlOp::CoordWhoAmI
            | ControlOp::CoordPeerShow
            | ControlOp::CoordStage
            | ControlOp::CoordStageShow
            | ControlOp::CoordDispatch
            | ControlOp::CoordTaskStatus
            | ControlOp::CoordEventsRead
            | ControlOp::CoordCapabilityEvidence => Surface::Coord,
            _ => Surface::Admin,
        }
    }
}

/// An RFC 9457 Problem Details object (design §16.2). Deliberately generic — it
/// never discloses whether a hidden path, secret, policy rule, or internal peer
/// exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// A stable problem-type URI (a `urn:akson:*` tag; not dereferenced).
    #[serde(rename = "type")]
    pub type_: String,
    pub title: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Problem {
    /// A problem with a `urn:akson:error:*` tag and no detail.
    pub fn new(status: u16, kind: &str, title: &str) -> Self {
        Self {
            type_: format!("urn:akson:error:{kind}"),
            title: title.to_owned(),
            status,
            detail: None,
        }
    }

    /// A `403 Forbidden` for an operation not permitted on the caller's surface.
    /// The detail names only the surface, never the operation's internals.
    pub fn forbidden_surface(surface: Surface) -> Self {
        Self {
            type_: "urn:akson:error:forbidden-surface".to_owned(),
            title: "operation not permitted on this local surface".to_owned(),
            status: 403,
            detail: Some(
                match surface {
                    // Not "cannot perform admin operations": with a third surface
                    // in the picture, a refused op may be another *narrow*
                    // surface's, and the detail must not misdescribe it.
                    Surface::Worker => "the worker surface cannot perform this operation",
                    // Names the surface and nothing else: a refusal must not
                    // tell a coordination driver which ops exist elsewhere.
                    Surface::Coord => "the coordination surface cannot perform this operation",
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

    const WORKER_OPS: [ControlOp; 5] = [
        ControlOp::SubmitTaskInput,
        ControlOp::ReportProgress,
        ControlOp::SubmitResult,
        ControlOp::ReferenceEvidence,
        ControlOp::RequestProcessorCall,
    ];

    const ADMIN_ONLY_OPS: [ControlOp; 15] = [
        ControlOp::Pair,
        ControlOp::Policy,
        ControlOp::ApproveContract,
        ControlOp::IssueWorkOrder,
        ControlOp::SignOutcome,
        ControlOp::DeliverResult,
        ControlOp::SendTask,
        ControlOp::Export,
        ControlOp::Recovery,
        ControlOp::Processor,
        ControlOp::TaskCancel,
        ControlOp::RunWorker,
        ControlOp::FulfillTask,
        ControlOp::Diagnose,
        // Minting consent for a staged disclosure is admin's alone (ADR-0016 §3).
        ControlOp::StageConsent,
    ];

    /// The eight ops of ADR-0016's registry — the whole coordination surface.
    const COORD_OPS: [ControlOp; 8] = [
        ControlOp::CoordWhoAmI,
        ControlOp::CoordPeerShow,
        ControlOp::CoordStage,
        ControlOp::CoordStageShow,
        ControlOp::CoordDispatch,
        ControlOp::CoordTaskStatus,
        ControlOp::CoordEventsRead,
        ControlOp::CoordCapabilityEvidence,
    ];

    #[test]
    fn admin_may_do_everything() {
        for op in WORKER_OPS
            .into_iter()
            .chain(ADMIN_ONLY_OPS)
            .chain(COORD_OPS)
        {
            authorize(Surface::Admin, op).unwrap_or_else(|_| panic!("admin should allow {op:?}"));
        }
    }

    #[test]
    fn coord_may_do_exactly_the_eight_coordination_ops() {
        for op in COORD_OPS {
            authorize(Surface::Coord, op).unwrap_or_else(|_| panic!("coord should allow {op:?}"));
        }
        // Deny-by-absence: everything else on this surface is unaddressable,
        // including consent — the driver can burn receipts, never mint them.
        for op in ADMIN_ONLY_OPS {
            assert_eq!(
                authorize(Surface::Coord, op).unwrap_err().status,
                403,
                "coord must not reach {op:?}"
            );
        }
    }

    #[test]
    fn the_two_narrow_surfaces_dominate_nothing_including_each_other() {
        // The asymmetry ADR-0016 chose: coord ops are not worker ops, and the
        // reverse. Surface confusion is exactly what the third socket prevents.
        for op in COORD_OPS {
            assert!(authorize(Surface::Worker, op).is_err(), "worker ⊅ {op:?}");
        }
        for op in WORKER_OPS {
            assert!(authorize(Surface::Coord, op).is_err(), "coord ⊅ {op:?}");
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
        assert_eq!(json["type"], "urn:akson:error:forbidden-surface");
        assert_eq!(json["status"], 403);
        assert!(json.get("title").is_some());
    }
}
