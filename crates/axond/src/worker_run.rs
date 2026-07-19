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

use std::os::fd::AsRawFd;
use std::path::Path;

use axon_crypto::purpose::KeyPurpose;
use axon_sandbox::{
    broker_socketpair, BubblewrapLauncher, CgroupLimits, CgroupScope, DenyAction, SandboxLauncher,
    SeccompPolicy,
};
use axon_store::StoreError;
use axon_worker::{gate_outputs, stage_inputs, OutputChannel, ProposedOutput, StageItem};

use crate::bootstrap::DaemonState;
use crate::broker::run_processor_call;
use crate::broker_channel::serve_broker_channel;
use crate::confinement::Confinement;
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
    let (work_order_id, capabilities, inputs, worker_command) = {
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
        (work_order_id, issued.order.capabilities, inputs, worker_command)
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

    // The boundary is a function of the grants (§13.1): default-deny, each grant
    // adds exactly its access. Stage only the inputs the read grant names, and bind
    // /inputs and /output only when the corresponding grant is present.
    let confinement = Confinement::from_capabilities(&capabilities);
    let items: Vec<StageItem> = inputs
        .iter()
        .filter(|i| confinement.input_ids.contains(&i.input_id))
        .map(|i| StageItem {
            id: i.input_id.clone(),
            media_type: i.media_type.clone(),
            content: i.payload.clone(),
        })
        .collect();
    if confinement.reads_inputs {
        stage_inputs(&items, &staging, "/inputs")
            .map_err(|e| problem_detail(500, "stage-failed", "could not stage the inputs", e))?;
    }

    // The read-only OS runtime substrate (interpreter + shared libraries, no task
    // data) is always present; the grant-derived /inputs and /output binds are
    // added by the confinement.
    let mut bind_dirs: Vec<String> =
        ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/alternatives"]
            .into_iter()
            .filter(|d| Path::new(d).exists())
            .map(str::to_owned)
            .collect();
    // Make the worker binary's own directory available (read-only) when it lives
    // outside the system dirs — e.g. a locally-built adapter. The command's first
    // token is the program; a bare name resolves on PATH (already under /usr).
    if let Some(dir) = worker_command
        .split_whitespace()
        .next()
        .filter(|t| t.contains('/'))
        .and_then(|t| Path::new(t).parent())
        .and_then(|p| p.to_str())
        .filter(|p| Path::new(p).is_dir())
        .map(str::to_owned)
    {
        if !bind_dirs.contains(&dir) {
            bind_dirs.push(dir);
        }
    }
    let runtime: Vec<(&str, &str)> = bind_dirs.iter().map(|d| (d.as_str(), d.as_str())).collect();
    let mut spec = confinement.to_spec(path_str(&staging)?, path_str(&output)?, &runtime);

    // A `processor_use` grant opens the broker channel: the worker inherits one
    // already-connected AF_UNIX fd (no socket() syscall — the network seal holds),
    // and the daemon services the other end. Its number is handed to the worker as
    // AXON_BROKER_FD; the daemon makes the real, credential-injected, budgeted call.
    let broker = if confinement.processor.is_some() {
        let (worker_fd, daemon_stream) =
            broker_socketpair().map_err(|e| problem_detail(500, "run-setup", "broker channel", e))?;
        spec = spec.setenv("AXON_BROKER_FD", &worker_fd.as_raw_fd().to_string());
        Some((worker_fd, daemon_stream))
    } else {
        None
    };

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

    let args = ["-c".to_owned(), worker_command];
    let launch = |spec: &_| {
        BubblewrapLauncher
            .launch(spec, "/bin/sh", &args, &seccomp, &cgroup)
            .map_err(|e| {
                problem_detail(500, "worker-failed", "the worker did not run to completion", e)
            })
    };
    match broker {
        // Service the broker channel on a scoped thread for the worker's lifetime,
        // then close the daemon's copy of the worker end so the handler sees EOF.
        Some((worker_fd, daemon_stream)) => std::thread::scope(|scope| {
            scope.spawn(|| {
                serve_broker_channel(daemon_stream, |processor_id, request| {
                    match run_processor_call(state, processor_id, &work_order_id, request) {
                        Ok(value) => value,
                        Err(p) => serde_json::json!({
                            "error": { "status": p.status, "title": p.title }
                        }),
                    }
                });
            });
            let result = launch(&spec);
            drop(worker_fd);
            result
        })?,
        None => launch(&spec)?,
    }

    // Collect what the worker produced: an optional response (/output/response) and
    // any artifacts it declared (/output/artifacts.json + files). Every output is
    // gated against the granted scope (§7.2 step 10) before it is recorded — the
    // adapter cannot pick a recipient or exceed a budget here.
    let mut proposed = Vec::new();
    let mut outputs = Vec::new();
    let mut response_bytes = 0usize;

    if let Ok(body) = std::fs::read(output.join("response")) {
        response_bytes = body.len();
        proposed.push(ProposedOutput {
            channel: OutputChannel::Response,
            recipient: REQUEST_ORIGIN.to_owned(),
            media_type: "text/plain".to_owned(),
            bytes: body.len() as u64,
        });
        outputs.push(ResultOutput {
            role: "response".to_owned(),
            artifact_id: format!("resp-{task_id}"),
            kind: OutputKind::Response,
            recipient: REQUEST_ORIGIN.to_owned(),
            media_type: "text/plain".to_owned(),
            byte_length: body.len() as u64,
            sha256: hex_sha256(&body),
        });
    }

    let artifact_count = collect_artifacts(&output, task_id, &mut proposed, &mut outputs)?;

    if outputs.is_empty() {
        return Err(problem(
            422,
            "no-output",
            "the worker produced no /output/response or artifacts",
        ));
    }

    gate_outputs(&capabilities, &proposed).map_err(|e| {
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
        outputs,
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

    // The outputs were recorded (digest + length) into the durable result; the run
    // directory is scratch, so clear it.
    let _ = std::fs::remove_dir_all(&run_dir);
    Ok(serde_json::json!({
        "ran": true,
        "task_id": task_id,
        "response_bytes": response_bytes,
        "artifacts": artifact_count,
        "result": manifest,
    }))
}

/// One artifact the worker declared in `/output/artifacts.json` (mirrors the SDK's
/// `ArtifactEntry`).
#[derive(serde::Deserialize)]
struct ArtifactEntry {
    role: String,
    media_type: String,
}

/// Reads the worker's declared artifacts and appends a gated proposal + a result
/// output for each. Returns how many were collected.
fn collect_artifacts(
    output: &Path,
    task_id: &str,
    proposed: &mut Vec<ProposedOutput>,
    outputs: &mut Vec<ResultOutput>,
) -> Result<usize, Problem> {
    let raw = match std::fs::read(output.join("artifacts.json")) {
        Ok(raw) => raw,
        Err(_) => return Ok(0),
    };
    let entries: Vec<ArtifactEntry> = serde_json::from_slice(&raw)
        .map_err(|e| problem_detail(422, "bad-artifacts", "the artifact manifest is invalid", e))?;
    for entry in &entries {
        let bytes = std::fs::read(output.join("artifacts").join(&entry.role)).map_err(|e| {
            problem_detail(422, "missing-artifact", "a declared artifact was not written", e)
        })?;
        proposed.push(ProposedOutput {
            channel: OutputChannel::Artifact,
            recipient: REQUEST_ORIGIN.to_owned(),
            media_type: entry.media_type.clone(),
            bytes: bytes.len() as u64,
        });
        outputs.push(ResultOutput {
            role: entry.role.clone(),
            artifact_id: format!("art-{task_id}-{}", entry.role),
            kind: OutputKind::Artifact,
            recipient: REQUEST_ORIGIN.to_owned(),
            media_type: entry.media_type.clone(),
            byte_length: bytes.len() as u64,
            sha256: hex_sha256(&bytes),
        });
    }
    Ok(entries.len())
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
