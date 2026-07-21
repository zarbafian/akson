//! The daemon's reaction to a delegated task arriving (design §12).
//!
//! Receiving is deliberately inert: `dispatch_proposal` stores a submitted Task and
//! issues no authority (there is a no-effect test pinning that). So *reacting* to a
//! new task — poking a harness, or enacting a standing auto-approval — cannot live
//! on the network-facing receive path; it runs here, on a separate daemon thread
//! that holds the daemon's keys and polls the store for tasks it has not yet seen.
//!
//! Two reactions, in order, once per task (a `task_reactions` row makes it exactly
//! once, across restarts):
//!
//! 1. **Auto-approve** — only if the operator set a standing policy for this peer
//!    that the task fits (allowed task type, within the byte ceiling, and asking
//!    for *no* outward disclosure). Fail-closed: no policy, or any mismatch, leaves
//!    the task submitted for a human decision. This is §12 local authority — the
//!    human pre-authorises, the daemon enforces; it never widens a grant.
//! 2. **Arrival hook** — if `AKSON_ON_TASK` is set, run it detached so a harness is
//!    poked (with `AKSON_TASK` and `AKSON_TASK_AUTO` in its environment) rather than
//!    polling the inbox.

use std::sync::Arc;
use std::time::Duration;

use akson_contract::{parse_payload, Capability, HeadState};
use akson_crypto::purpose::KeyPurpose;
use time::OffsetDateTime;

use crate::approve::approve_and_issue;
use crate::bootstrap::DaemonState;

/// How often the reactor sweeps for newly-arrived tasks.
const POLL_INTERVAL: Duration = Duration::from_millis(750);

/// Polls forever, reacting to each newly-submitted task once. Runs on its own
/// daemon thread; a transient store error is logged and the sweep retried.
pub fn run_reactor(state: Arc<DaemonState>) {
    loop {
        if let Err(e) = react_once(&state) {
            eprintln!("aksond: reactor sweep error: {e}");
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// One sweep: handle every task awaiting reaction, then fire their hooks with the
/// store lock released. Public so an integration test can drive a single,
/// deterministic sweep rather than waiting on the polling loop.
pub fn react_once(state: &DaemonState) -> Result<(), String> {
    let wall = OffsetDateTime::now_utc().unix_timestamp();
    // Phase 1 (locked): auto-approve what policy allows (idempotent — an accepted
    // task's head is Locked, so re-running never double-issues).
    let pending: Vec<(String, bool)> = {
        let store = state.store();
        let store = store.lock().map_err(|_| "store lock poisoned".to_owned())?;
        // Authority decisions run on the monotonic trusted clock, never the raw
        // wall clock — a rolled-back host clock must not revive expired authority
        // (codex review). If time is uncertain, auto-approve nothing this sweep.
        let trusted = store.trusted_now(wall).ok();
        let tasks = store.tasks_awaiting_reaction().map_err(|e| e.to_string())?;
        tasks
            .into_iter()
            .map(|t| {
                let auto = trusted
                    .map(|now| auto_approve_if_allowed(&store, state, &t.task_id, now))
                    .unwrap_or(false);
                (t.task_id, auto)
            })
            .collect()
    };
    // Phase 2 (unlocked): poke the harness. Spawning a process must not hold the
    // store lock, and a slow hook must not stall the sweep.
    if let Some(cmd) = state.config().on_task.as_deref() {
        for (task_id, auto) in &pending {
            spawn_hook(cmd, task_id, *auto);
        }
    }
    // Phase 3 (locked): mark each task handled — *after* the hook, so a crash
    // between re-fires the hook (at-least-once) rather than losing it. An
    // auto-approved task is already excluded by its Locked head; the mark stops a
    // still-submitted task's hook from re-firing every sweep.
    {
        let store = state.store();
        let store = store.lock().map_err(|_| "store lock poisoned".to_owned())?;
        for (task_id, _) in &pending {
            store
                .mark_task_reacted(task_id, wall)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Auto-approves the task iff the operator's standing policy for its requester
/// covers it. Returns whether it was approved. Fail-closed at every step.
fn auto_approve_if_allowed(
    store: &akson_store::Store,
    state: &DaemonState,
    task_id: &str,
    now: i64,
) -> bool {
    // Load the submitted contract. Anything unexpected → do not auto-approve.
    let head = match store.contract_head(task_id) {
        Ok(HeadState::Open(head)) => head,
        _ => return false,
    };
    let Ok(Some(payload)) = store.get_contract(&head.digest) else {
        return false;
    };
    let Ok(parsed) = parse_payload(&payload) else {
        return false;
    };
    let contract = parsed.contract;

    // The requester must be a confirmed-ACTIVE peer. A pending (not-yet-confirmed)
    // or removed peer is never auto-approved, even if a stale policy row survives —
    // auto-approval is trust the operator granted a peer they confirmed (codex review).
    if store.peer_status(&contract.requester.agent).ok().flatten()
        != Some(akson_store::PeerStatus::Active)
    {
        return false;
    }
    let Ok(Some(policy)) = store.get_auto_approve(&contract.requester.agent) else {
        return false; // no standing policy → always ask
    };
    if !policy.task_types.iter().any(|t| t == &contract.task_type) {
        return false;
    }
    if contract.limits.max_response_bytes > policy.max_response_bytes {
        return false;
    }
    // Never auto-approve outward disclosure — processor use or artifact export
    // always ask, whatever the policy says.
    let discloses = contract
        .requested_capabilities
        .iter()
        .any(|c| matches!(c, Capability::ProcessorUse | Capability::ArtifactExport));
    if discloses {
        return false;
    }

    // Enact it: issue the one-shot work order with only the non-disclosing grants
    // (processor=None, artifacts=false), exactly as an operator `task approve` would.
    let issued = approve_and_issue(
        store,
        &state.config().local_performer,
        &state.identity().purpose_key(KeyPurpose::ContractDecision),
        &state.identity().work_order_key(),
        task_id,
        None,
        false,
        now,
    );
    match issued {
        Ok(_) => true,
        Err(p) => {
            eprintln!(
                "aksond: auto-approve of {task_id} refused: {} ({})",
                p.title, p.status
            );
            false
        }
    }
}

/// Runs the arrival hook detached: `/bin/sh -c <cmd>` with the task id in the
/// environment (never interpolated into the command string, so task data cannot
/// inject shell). Failure to spawn is logged, never fatal.
fn spawn_hook(cmd: &str, task_id: &str, auto: bool) {
    let spawned = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .env("AKSON_TASK", task_id)
        .env("AKSON_TASK_AUTO", if auto { "1" } else { "0" })
        .stdin(std::process::Stdio::null())
        .spawn();
    if let Err(e) = spawned {
        eprintln!("aksond: task hook failed to spawn: {e}");
    }
}
