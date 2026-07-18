//! Running an approved Task's worker in the sandbox (design §7.2, §13.1) — the
//! receive-side counterpart to the M8→M9 tracer bullet, wired into the daemon.
//!
//! `axon task run <task_id>` composes the spine end to end for a Task that has
//! been approved (its one-shot work order issued):
//!
//!   work order (loaded + its capability grant) → stage exactly the approved
//!   inputs → launch a fully-confined worker (namespaces + mount + seccomp +
//!   cgroup) that reads `/inputs` and writes `/output/response` → gate that
//!   response against the granted scope → submit it, producing the signed result
//!   manifest (the same object `axon task deliver` then sends to the requester).
//!
//! The worker is the operator's command (`AXON_WORKER_CMD`), run as
//! `/bin/sh -c <cmd>`. It is confined by the M9 clean-worker baseline, which
//! blocks the fork/exec an external program needs — so a v1 worker is a
//! pure-shell adapter (a real model-backed worker needs a broader seccomp
//! allowlist, a later addition). The daemon refuses to run un-confined: if no
//! delegated cgroup is available, the call fails closed rather than launch.

use std::path::Path;

use axon_crypto::purpose::KeyPurpose;
use axon_sandbox::{
    BubblewrapLauncher, CgroupLimits, CgroupScope, DenyAction, SandboxLauncher, SandboxSpec,
    SeccompPolicy,
};
use axon_store::StoreError;
use axon_worker::{gate_outputs, stage_inputs, OutputChannel, ProposedOutput, StageItem};

use crate::bootstrap::DaemonState;
use crate::control::Problem;
use crate::result::{hex_sha256, submit_result, OutputKind, ResultOutput, ResultSubmission};

/// The response the worker writes goes to the request origin — the v1 invariant
/// (`send` fixes the contract's `result_recipient`, and `issue` fixes the grant's
/// recipient, to this same value).
const REQUEST_ORIGIN: &str = "request-origin";

/// Runs the approved Task's worker in the sandbox and submits its gated result
/// (design §7.2). Manages its own store locking (the sandbox launch is slow and
/// must not hold the lock): gather under the lock → stage + launch + gate with no
/// lock → submit under the lock. Fails closed at every gate.
pub fn run_worker(state: &DaemonState, task_id: &str) -> Result<serde_json::Value, Problem> {
    // Phase 1 — gather everything the run needs, then release the lock.
    let (capabilities, inputs, worker_command) = {
        let store = state.store();
        let store = store.lock().map_err(|_| internal())?;
        let work_order_id = store
            .attempt_for_task(task_id)
            .map_err(store_problem)?
            .ok_or_else(|| problem(409, "no-work-order", "this task has no issued work order"))?;
        let issued = store
            .get_work_order(&work_order_id)
            .map_err(store_problem)?
            .ok_or_else(|| problem(404, "no-work-order", "the work order is missing"))?;
        let inputs = store.list_task_inputs(task_id).map_err(store_problem)?;
        let worker_command = state.config().worker_command.clone().ok_or_else(|| {
            problem(
                409,
                "no-worker",
                "no worker is configured (set AXON_WORKER_CMD)",
            )
        })?;
        (issued.order.capabilities, inputs, worker_command)
    };

    // Phase 2 — stage, launch fully confined, and gate. No store lock is held.
    let run_dir = state.config().data_dir.join("run").join(task_id);
    let staging = run_dir.join("inputs");
    let output = run_dir.join("output");
    // A pristine run directory: staging refuses to write through a pre-existing
    // file, so clear any residue from a prior run first.
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&output)
        .map_err(|e| problem_detail(500, "run-setup", "could not prepare the run directory", e))?;

    let items: Vec<StageItem> = inputs
        .iter()
        .map(|i| StageItem {
            id: i.input_id.clone(),
            media_type: i.media_type.clone(),
            content: i.payload.clone(),
        })
        .collect();
    stage_inputs(&items, &staging, "/inputs")
        .map_err(|e| problem_detail(500, "stage-failed", "could not stage the inputs", e))?;

    // The isolation policy: a read-only root filesystem, the approved inputs at
    // /inputs, and a single writable /output for the response.
    let mut spec = SandboxSpec::clean_worker("/");
    for dir in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/alternatives"] {
        if Path::new(dir).exists() {
            spec = spec.ro_bind(dir, dir);
        }
    }
    spec = spec
        .ro_bind(path_str(&staging)?, "/inputs")
        .rw_bind(path_str(&output)?, "/output");

    let seccomp = SeccompPolicy::clean_worker_baseline(DenyAction::KillProcess);
    let cgroup = CgroupScope::create(
        &format!("axon-worker-{task_id}"),
        &CgroupLimits {
            max_memory_bytes: Some(256 * 1024 * 1024),
            max_pids: Some(64),
            cpu_max: None,
        },
    )
    .map_err(|e| {
        problem_detail(
            503,
            "no-confinement",
            "cannot confine the worker (no delegated cgroup); refusing to run un-isolated",
            e,
        )
    })?;

    BubblewrapLauncher
        .launch(
            &spec,
            "/bin/sh",
            &["-c".to_owned(), worker_command],
            &seccomp,
            &cgroup,
        )
        .map_err(|e| {
            problem_detail(500, "worker-failed", "the worker did not run to completion", e)
        })?;

    let body = std::fs::read(output.join("response")).map_err(|_| {
        problem(
            422,
            "no-response",
            "the worker produced no /output/response",
        )
    })?;

    // The output must fall inside the granted scope (§7.2 step 10) before it is
    // recorded — a response, to the request origin, within the byte budget.
    let proposed = ProposedOutput {
        channel: OutputChannel::Response,
        recipient: REQUEST_ORIGIN.to_owned(),
        media_type: "text/plain".to_owned(),
        bytes: body.len() as u64,
    };
    gate_outputs(&capabilities, &[proposed]).map_err(|e| {
        problem_detail(
            403,
            "output-denied",
            "the worker output is outside the granted scope",
            format!("offending output index {}", e.index),
        )
    })?;

    // Phase 3 — record the result under the lock, producing the signed manifest.
    let submission = ResultSubmission {
        task_id: task_id.to_owned(),
        outputs: vec![ResultOutput {
            role: "response".to_owned(),
            artifact_id: format!("resp-{task_id}"),
            kind: OutputKind::Response,
            recipient: REQUEST_ORIGIN.to_owned(),
            media_type: "text/plain".to_owned(),
            byte_length: body.len() as u64,
            sha256: hex_sha256(&body),
        }],
        evidence: vec![],
        slots: vec![],
    };
    let manifest = {
        let store = state.store();
        let store = store.lock().map_err(|_| internal())?;
        submit_result(
            &store,
            &state.identity().purpose_key(KeyPurpose::TaskResult),
            &submission,
            now_unix(),
        )?
    };

    // The response bytes were recorded (digest + length) into the durable result;
    // the run directory is scratch, so clear it.
    let _ = std::fs::remove_dir_all(&run_dir);
    Ok(serde_json::json!({
        "ran": true,
        "task_id": task_id,
        "response_bytes": body.len(),
        "result": manifest,
    }))
}

fn path_str(p: &Path) -> Result<&str, Problem> {
    p.to_str()
        .ok_or_else(|| problem(500, "run-setup", "the run directory path is not valid UTF-8"))
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn store_problem(_e: StoreError) -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn internal() -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    }
}

fn problem_detail(status: u16, kind: &str, title: &str, e: impl std::fmt::Display) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: Some(e.to_string()),
    }
}
