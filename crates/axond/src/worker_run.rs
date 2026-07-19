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
//! `/bin/sh -c <cmd>` and confined by the M9 clean-worker baseline. The baseline
//! permits a shell to spawn external tools and a real adapter to do socket I/O on
//! the broker fd, so a full model-backed adapter runs — while `socket()`/`connect()`
//! stay denied, keeping the network sealed. A `processor_use` grant opens a brokered
//! model channel; an `artifact_export` grant lets the worker return bounded
//! artifacts alongside (or instead of) the text response. The daemon refuses to run
//! un-confined: with no delegated cgroup, the call fails closed rather than launch.

use std::os::fd::AsRawFd;
use std::path::Path;

use axon_authority::AttemptEvent;
use axon_crypto::purpose::KeyPurpose;
use axon_sandbox::{
    broker_socketpair, BubblewrapLauncher, CgroupLimits, CgroupScope, DenyAction, SandboxLauncher,
    SeccompPolicy,
};
use axon_store::StoreError;
use axon_worker::{check_inert, gate_outputs, stage_inputs, OutputChannel, ProposedOutput, StageItem};

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

/// How the approved worker is launched inside the sandbox.
///
/// - `Shell` — the operator's `AXON_WORKER_CMD`, run as `/bin/sh -c <cmd>` under the
///   process-spawning [`clean_worker_baseline`](SeccompPolicy::clean_worker_baseline);
///   this is the dev stand-in that may shell out to tools.
/// - `Adapter` — `AXON_WORKER_EXEC` as a direct `argv` (no shell) under the strict
///   [`adapter_worker_baseline`](SeccompPolicy::adapter_worker_baseline): a single
///   production-adapter process that cannot spawn a child or open a socket.
enum Invocation {
    Shell(String),
    Adapter(Vec<String>),
}

impl Invocation {
    /// The invocation from config: a direct adapter (`worker_exec`) wins over the
    /// shell command (`worker_command`); `None` if neither is set.
    fn from_config(config: &crate::bootstrap::DaemonConfig) -> Option<Self> {
        if let Some(argv) = config.worker_exec.as_ref().filter(|a| !a.is_empty()) {
            Some(Invocation::Adapter(argv.clone()))
        } else {
            config.worker_command.clone().map(Invocation::Shell)
        }
    }

    /// The program bubblewrap execs: `/bin/sh` for a shell command, or the adapter's
    /// `argv[0]` for a direct run.
    fn program(&self) -> &str {
        match self {
            Invocation::Shell(_) => "/bin/sh",
            Invocation::Adapter(argv) => &argv[0],
        }
    }

    /// The arguments after `program`.
    fn args(&self) -> Vec<String> {
        match self {
            Invocation::Shell(cmd) => vec!["-c".to_owned(), cmd.clone()],
            Invocation::Adapter(argv) => argv[1..].to_vec(),
        }
    }

    /// The user tool's path token for the read-only bind of its own directory: the
    /// shell command's first word, or the adapter's `argv[0]`.
    fn bind_token(&self) -> Option<&str> {
        match self {
            Invocation::Shell(cmd) => cmd.split_whitespace().next(),
            Invocation::Adapter(argv) => Some(&argv[0]),
        }
    }

    /// The seccomp profile for this invocation.
    fn seccomp(&self) -> SeccompPolicy {
        match self {
            Invocation::Shell(_) => SeccompPolicy::clean_worker_baseline(DenyAction::KillProcess),
            Invocation::Adapter(_) => {
                SeccompPolicy::adapter_worker_baseline(DenyAction::KillProcess)
            }
        }
    }
}

/// Runs the approved Task's worker in the sandbox and submits its gated result
/// (design §7.2). Manages its own store locking (the sandbox launch is slow and
/// must not hold the lock): gather under the lock → stage + launch + gate with no
/// lock → submit under the lock. Fails closed at every gate.
pub fn run_worker(state: &DaemonState, task_id: &str) -> Result<serde_json::Value, Problem> {
    // Phase 1 — gather everything the run needs, then release the lock.
    let (work_order_id, capabilities, inputs, invocation) = {
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
        let invocation = Invocation::from_config(state.config()).ok_or_else(|| {
            problem(
                409,
                "no-worker",
                "no worker is configured (set AXON_WORKER_CMD or AXON_WORKER_EXEC)",
            )
        })?;
        (work_order_id, issued.order.capabilities, inputs, invocation)
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
    // outside the system dirs — e.g. a locally-built adapter. The bind token (the
    // shell command's first word, or the adapter's argv[0]) names it; a bare name
    // resolves on PATH (already under /usr).
    if let Some(dir) = invocation
        .bind_token()
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
    let mut broker = if confinement.processor.is_some() {
        let (worker_fd, daemon_stream) =
            broker_socketpair().map_err(|e| problem_detail(500, "run-setup", "broker channel", e))?;
        spec = spec.setenv("AXON_BROKER_FD", &worker_fd.as_raw_fd().to_string());
        Some((worker_fd, daemon_stream))
    } else {
        None
    };

    // The shell stand-in gets the process-spawning baseline; a production adapter
    // runs directly under the strict profile that denies process creation entirely.
    let seccomp = invocation.seccomp();
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

    let program = invocation.program().to_owned();
    let args = invocation.args();
    let launch = |spec: &_| {
        BubblewrapLauncher
            .launch(spec, &program, &args, &seccomp, &cgroup)
            .map_err(|e| {
                problem_detail(500, "worker-failed", "the worker did not run to completion", e)
            })
    };
    // Durable-before-effect: mark the attempt Running *before* the sandbox launches.
    // The launch is the effect — it may reach a model and spend budget — so the mark
    // is committed first. `Start` only fires from Claimed, so a duplicate or
    // concurrent `task run` finds the attempt already Running (or finished) and is
    // refused here, before a second launch. If the daemon crashes between this mark
    // and completion, recovery sees Running and resolves the attempt to Ambiguous.
    {
        let store = state.store();
        let store = store.lock().map_err(|_| internal())?;
        if store
            .advance_attempt(&work_order_id, AttemptEvent::Start, now_unix())
            .map_err(store_problem)?
            .is_err()
        {
            return Err(problem(
                409,
                "already-running",
                "this task's worker is already running or has finished",
            ));
        }
    }

    // From here the worker may execute. Run it, collect and gate its outputs, and
    // record the signed result; on any failure the attempt is marked Failed below so
    // it becomes terminal rather than lingering as Running. Every output is gated
    // against the granted scope (§7.2 step 10) before it is recorded — the adapter
    // cannot pick a recipient or exceed a budget here.
    let mut record = || -> Result<serde_json::Value, Problem> {
        match broker.take() {
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

        // Collect what the worker produced: an optional response (/output/response)
        // and any artifacts it declared (/output/artifacts.json + files).
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

        // Record the result under the lock, producing the signed manifest — this also
        // advances the attempt Running → Succeeded.
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
        Ok(serde_json::json!({
            "ran": true,
            "task_id": task_id,
            "response_bytes": response_bytes,
            "artifacts": artifact_count,
            "result": manifest,
        }))
    };
    let outcome = record();
    drop(record);

    match outcome {
        Ok(value) => {
            // The outputs were recorded (digest + length) into the durable result;
            // the run directory is scratch, so clear it.
            let _ = std::fs::remove_dir_all(&run_dir);
            Ok(value)
        }
        Err(e) => {
            // The worker may have executed but produced no recorded result. Mark the
            // attempt Failed (terminal) so a retry is not blocked by a lingering
            // Running state, then surface the error. The scratch run dir is left for
            // inspection.
            if let Ok(store) = state.store().lock() {
                let _ = store.advance_attempt(&work_order_id, AttemptEvent::Fail, now_unix());
            }
            Err(e)
        }
    }
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
        // A renderable artifact must be inert — no scripts, event handlers, or
        // external fetches that would execute when the requester views it (§20.4).
        check_inert(&entry.media_type, &bytes).map_err(|e| {
            problem_detail(
                403,
                "artifact-not-inert",
                "an artifact carries active content and was refused",
                e,
            )
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn collect_artifacts_records_declared_artifacts_and_tolerates_none() {
        let dir = std::env::temp_dir().join(format!("axon-wr-a-{}", std::process::id()));
        let artifacts = dir.join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        std::fs::write(
            dir.join("artifacts.json"),
            br#"[{"role":"findings","media_type":"application/sarif+json"}]"#,
        )
        .unwrap();
        std::fs::write(artifacts.join("findings"), b"{\"runs\":[]}").unwrap();

        let mut proposed = Vec::new();
        let mut outputs = Vec::new();
        let n = collect_artifacts(&dir, "task-1", &mut proposed, &mut outputs).unwrap();
        assert_eq!(n, 1);
        assert_eq!(proposed.len(), 1);
        assert!(matches!(proposed[0].channel, OutputChannel::Artifact));
        assert_eq!(proposed[0].media_type, "application/sarif+json");
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].role, "findings");
        assert!(matches!(outputs[0].kind, OutputKind::Artifact));

        // No manifest → zero artifacts, no error.
        let empty = std::env::temp_dir().join(format!("axon-wr-e-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        let (mut p2, mut o2) = (Vec::new(), Vec::new());
        assert_eq!(collect_artifacts(&empty, "task-1", &mut p2, &mut o2).unwrap(), 0);
        assert!(o2.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn a_non_inert_artifact_is_refused() {
        let dir = std::env::temp_dir().join(format!("axon-wr-inert-{}", std::process::id()));
        let artifacts = dir.join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        std::fs::write(
            dir.join("artifacts.json"),
            br#"[{"role":"diagram","media_type":"image/svg+xml"}]"#,
        )
        .unwrap();
        // An SVG carrying a script must be refused before it is recorded.
        std::fs::write(
            artifacts.join("diagram"),
            b"<svg><script>alert(1)</script></svg>",
        )
        .unwrap();
        let (mut p, mut o) = (Vec::new(), Vec::new());
        let err = collect_artifacts(&dir, "task-1", &mut p, &mut o).unwrap_err();
        assert_eq!(err.status, 403);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_declared_but_unwritten_artifact_is_an_error() {
        let dir = std::env::temp_dir().join(format!("axon-wr-m-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Manifest references an artifact whose file was never written.
        std::fs::write(
            dir.join("artifacts.json"),
            br#"[{"role":"ghost","media_type":"text/plain"}]"#,
        )
        .unwrap();
        let (mut p, mut o) = (Vec::new(), Vec::new());
        assert!(collect_artifacts(&dir, "task-1", &mut p, &mut o).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
