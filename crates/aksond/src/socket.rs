//! The local control socket: framing, peer authentication, and surface
//! authorization (design §16.2).
//!
//! A control socket is bound with owner-only permissions, and every connection is
//! (1) authenticated by Unix peer credentials — the peer's UID must be one the
//! socket [`Admission`]s — and (2) authorized by *surface* — a request is refused
//! unless the socket it arrived on (admin, worker, or coord) is privileged enough
//! for it. Only then is the request dispatched. Requests and responses are
//! newline-delimited JSON; failures are RFC 9457 [`Problem`] objects.
//!
//! Admission is per socket: admin and worker admit only the daemon's own UID,
//! while the coordination socket (ADR-0016) also admits one configured UID — and
//! is not created at all when none is configured.
//!
//! The dispatch itself is injected, so this module owns only the security framing;
//! the daemon supplies what each operation does.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::control::{authorize, ControlOp, Problem, Surface};
use crate::peercred::{current_uid, peer_credentials};

/// The runtime directory holding the daemon's sockets. In priority:
/// `$AKSON_RUNTIME_DIR` (the *exact* directory — used by the `--system` service
/// unit, which points it at a `RuntimeDirectory=`-created `/run/akson`, so a
/// system daemon and the operator's CLI rendezvous on a stable path);
/// else `$XDG_RUNTIME_DIR/akson` (a private, `0700`, per-user tmpfs); else a
/// UID-scoped temp directory. Both the daemon and the CLI resolve the path
/// through this one function, so they always agree.
pub fn socket_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("AKSON_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(rt) if !rt.is_empty() => PathBuf::from(rt).join("akson"),
        _ => std::env::temp_dir().join(format!("akson-{}", current_uid())),
    }
}

/// The admin control socket path (design §16.2).
pub fn admin_socket_path() -> PathBuf {
    socket_dir().join("admin.sock")
}

/// The worker control socket path (design §16.2).
pub fn worker_socket_path() -> PathBuf {
    socket_dir().join("worker.sock")
}

/// The coordination control socket path (ADR-0016). The file exists only when a
/// coordination UID is configured — see [`bind_coord_socket`].
pub fn coord_socket_path() -> PathBuf {
    socket_dir().join("coord.sock")
}

/// The configured coordination peer UID (`AKSON_COORD_UID`, ADR-0016 §1).
///
/// `Ok(None)` — unset or empty — means the coordination socket is **not created
/// at all** ("absent rather than guarded"; an unmounted endpoint cannot be
/// probed). A value that is not a UID is an error rather than a silent absence:
/// a typo must not quietly remove the surface an operator asked for.
pub fn configured_coord_uid() -> Result<Option<u32>, String> {
    parse_coord_uid(std::env::var_os("AKSON_COORD_UID").as_deref())
}

fn parse_coord_uid(value: Option<&std::ffi::OsStr>) -> Result<Option<u32>, String> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let text = raw
        .to_str()
        .ok_or_else(|| "AKSON_COORD_UID is not valid UTF-8".to_owned())?
        .trim();
    if text.is_empty() {
        return Ok(None);
    }
    text.parse::<u32>()
        .map(Some)
        .map_err(|_| format!("AKSON_COORD_UID must be a numeric uid, not {text:?}"))
}

/// The UIDs one socket admits, checked by `SO_PEERCRED` **before** the request
/// line is read (design §16.2, ADR-0016 §1).
///
/// Admin and worker admit exactly the daemon's own UID, as they always have.
/// Coord admits the configured coordination UID *or* the daemon's own, so the
/// operator can diagnose the surface without a second account. Anything else is
/// refused, and the refusal is the same generic problem for every reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission(Vec<u32>);

impl Admission {
    /// Only the daemon's own UID — the admin and worker rule, unchanged.
    pub fn same_uid(daemon_uid: u32) -> Self {
        Self(vec![daemon_uid])
    }

    /// The coordination rule: the configured peer UID, plus the daemon's own for
    /// diagnostics. A `coord_uid` equal to the daemon's collapses to one entry.
    pub fn coord(daemon_uid: u32, coord_uid: u32) -> Self {
        if coord_uid == daemon_uid {
            Self(vec![daemon_uid])
        } else {
            Self(vec![coord_uid, daemon_uid])
        }
    }

    /// Whether `uid` is admitted here.
    pub fn admits(&self, uid: u32) -> bool {
        self.0.contains(&uid)
    }

    /// The admitted UIDs, for the startup log line.
    pub fn uids(&self) -> &[u32] {
        &self.0
    }
}

/// A control request over the local socket. Each variant maps to a [`ControlOp`]
/// for the surface-authorization gate; richer arguments ride inside the variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Report daemon + sandbox health (`akson doctor` / `akson status`).
    Diagnose,
    /// Report this daemon's own identity + endpoint fingerprint (`akson whoami`).
    WhoAmI,
    /// List the submitted Tasks awaiting a decision (`akson task inbox`).
    TaskInbox,
    /// Render a submitted Task's risk card (`akson task show`).
    TaskShow { task_id: String },
    /// List paired peers (`akson peer list`).
    PeerList,
    /// This endpoint's identity token (`akson token`).
    Token,
    /// Import a peer's identity token under a local label — the trust decision
    /// of identity-token pairing (`akson peer add`, admin; design §8.2 step 3).
    /// `token` may carry the `@host:port` presentation suffix; an explicit
    /// `endpoint` wins over it. `update` refreshes label/hint of a live import.
    PeerAdd {
        token: String,
        label: String,
        #[serde(default)]
        endpoint: Option<String>,
        #[serde(default)]
        update: bool,
    },
    /// Rename a peer's local label (`akson peer label`, admin). Purely local.
    PeerLabel { label: String, new_label: String },
    /// Remove an imported peer: tombstone the import, advance its epoch, and
    /// drop the pinned peer state (`akson peer remove`, admin; §8.2 step 7).
    PeerImportRemove { label: String },
    /// The knock log — refused introductions (`akson peer knocks`).
    PeerKnocks,
    /// Dial the introduction toward an imported peer now (`akson peer ping`,
    /// admin) — the same handshake the first `task send` would trigger.
    PeerPing { label: String },
    /// Set a peer's standing auto-approval policy (`akson peer auto-approve`, admin):
    /// tasks of these types from this peer, within the byte ceiling, that ask for no
    /// outward disclosure, run without a per-task prompt. Empty `task_types` clears it.
    PeerAutoApprove {
        agent_id: String,
        task_types: Vec<String>,
        max_response_bytes: u64,
    },
    /// List tasks this daemon sent as requester (`akson task sent`).
    TaskSent,
    /// List recorded requester outcomes (`akson task outcomes`).
    TaskOutcomes,
    /// Read a task's output payloads (`akson task output`). Serves whichever side
    /// this endpoint is: the performer's staged outputs, or the ones a delivered
    /// result carried. With `role` set, only that output.
    TaskOutput {
        task_id: String,
        #[serde(default)]
        role: Option<String>,
    },
    /// Approve a submitted Task: accept it and issue the one-shot work order
    /// (`akson task approve`, admin only). `processor`, when set, additionally grants
    /// `processor_use` bound to that configured processor — the explicit,
    /// per-approval disclosure decision to let the peer task call a model.
    TaskApprove {
        task_id: String,
        #[serde(default)]
        processor: Option<String>,
        /// Additionally grant `artifact_export` (bounded artifacts, e.g. SARIF).
        #[serde(default)]
        artifacts: bool,
    },
    /// Deny a submitted Task: sign a reject decision (`akson task deny`, admin only).
    TaskDeny { task_id: String, reason: String },
    /// Run an approved Task's worker in the sandbox and submit its result
    /// (`akson task run`, admin only).
    TaskRun { task_id: String },
    /// Fulfil an approved Task with a result the local operator (or its own
    /// trusted agent) produced — the cooperative counterpart to `TaskRun`
    /// (`akson task fulfill`, admin only). No sandbox: the daemon still gates the
    /// result against the granted scope and signs the manifest over these exact
    /// bytes, but the work was done by the operator's agent, not a confined
    /// worker. For trusted, same-operator delegation (e.g. one of your agents
    /// asking another), where the value is the peer's own context, not isolation.
    TaskFulfill {
        task_id: String,
        outputs: Vec<FulfillOutput>,
    },
    /// Deliver a completed Task's signed result to the requester (admin only).
    TaskDeliver { task_id: String },
    /// Send a task to a performer (sign + POST a proposal, admin only).
    TaskSend(crate::send::TaskSpec),
    /// Submit a worker result for completion (the narrow worker surface).
    SubmitResult(crate::result::ResultSubmission),
    /// Request a processor call on the worker's behalf (the narrow worker surface).
    RequestProcessorCall {
        processor_id: String,
        work_order_id: String,
        request: String,
    },
    /// Configure a processor (admin only).
    ProcessorAdd {
        processor_id: String,
        provider: String,
        origin_host: String,
        origin_port: u16,
        #[serde(default)]
        local: bool,
        #[serde(default)]
        tls_certificate_sha256: Option<String>,
        /// The request path POSTed to (default `/`; e.g. `/v1/chat/completions`).
        #[serde(default)]
        path: Option<String>,
        /// Auth scheme: `bearer` (default), `none`, or a header name (`x-api-key`).
        #[serde(default)]
        auth: Option<String>,
        /// Static request headers as `name:value` strings (e.g. `anthropic-version:2023-06-01`).
        #[serde(default)]
        headers: Vec<String>,
    },
    /// List configured processors (admin only).
    ProcessorList,
    /// Set a processor's sealed credential (admin only).
    ProcessorCredential {
        processor_id: String,
        credential: String,
    },
    /// Issue a one-shot work order (admin only) — used here to exercise the gate.
    IssueWorkOrder { task_id: String },

    // --- The admin side of the coordination surface (ADR-0016 §3) ---
    /// Mint the one-shot consent receipt for an exact staged digest, after
    /// showing the operator its risk card (`akson stage consent <ref>`, admin
    /// only). Deliberately **not** on the coordination surface: the outward
    /// disclosure is never the driver's to authorize.
    StageConsent { stage_ref: String },

    // --- The coordination surface (ADR-0016 §2, `akson_byom_exchange_v1`) ---
    /// This daemon's identity, endpoint fingerprint, and protocol/feature
    /// versions — the driver's own handshake.
    #[serde(rename = "coord_whoami")]
    CoordWhoAmI,
    /// One named verified peer's identity tuple and card claims. Answers about
    /// the peer asked for and nothing else — it never enumerates.
    PeerShow { label: String },
    /// Stage outbound bytes: inert, and idempotent on their content digest.
    Stage {
        task_type: String,
        /// The operator's local label for the intended recipient.
        #[serde(default)]
        performer: String,
        /// The outbound bytes, base64 (standard alphabet, as `task_fulfill`).
        payload_base64: String,
    },
    /// A staged contract's status and digests.
    StageShow { stage_ref: String },
    /// One-shot: consume a consent receipt and dispatch the staged bytes.
    Dispatch {
        stage_ref: String,
        consent_receipt: String,
        execution_key: String,
    },
    /// The verification status of a dispatched task.
    TaskStatus { task_id: String },
    /// Durable cursored coordination events. An absent `cursor` starts at the
    /// beginning of the feed; cursors are opaque and only ever come from a reply.
    EventsRead {
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default)]
        limit: Option<u32>,
    },
    /// `FederationCapabilityEvidence` for a peer.
    CapabilityEvidence { label: String },
}

/// One output an operator provides via `TaskFulfill`. `content` is base64 so
/// arbitrary bytes (a design doc, a diagram, a SARIF file) cross the control
/// socket as a string. `role` picks the channel — `response` goes to the request
/// origin as the reply; any other role is an artifact — and must fit a granted
/// deliverable, or the daemon's gate refuses it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FulfillOutput {
    pub role: String,
    pub media_type: String,
    pub content_base64: String,
}

impl ControlRequest {
    /// The authorization unit for this request (design §16.2).
    pub fn op(&self) -> ControlOp {
        match self {
            ControlRequest::Diagnose | ControlRequest::WhoAmI | ControlRequest::Token => {
                ControlOp::Diagnose
            }
            ControlRequest::TaskInbox
            | ControlRequest::TaskShow { .. }
            | ControlRequest::TaskSent
            | ControlRequest::TaskOutcomes
            | ControlRequest::TaskOutput { .. } => ControlOp::TaskInspect,
            ControlRequest::PeerList | ControlRequest::PeerKnocks => ControlOp::Inspect,
            ControlRequest::PeerAdd { .. }
            | ControlRequest::PeerLabel { .. }
            | ControlRequest::PeerImportRemove { .. }
            | ControlRequest::PeerPing { .. } => ControlOp::Pair,
            ControlRequest::PeerAutoApprove { .. } => ControlOp::Policy,
            ControlRequest::TaskApprove { .. } | ControlRequest::TaskDeny { .. } => {
                ControlOp::ApproveContract
            }
            ControlRequest::TaskRun { .. } => ControlOp::RunWorker,
            ControlRequest::TaskFulfill { .. } => ControlOp::FulfillTask,
            ControlRequest::TaskDeliver { .. } => ControlOp::DeliverResult,
            ControlRequest::TaskSend(_) => ControlOp::SendTask,
            ControlRequest::SubmitResult(_) => ControlOp::SubmitResult,
            ControlRequest::RequestProcessorCall { .. } => ControlOp::RequestProcessorCall,
            ControlRequest::ProcessorAdd { .. }
            | ControlRequest::ProcessorList
            | ControlRequest::ProcessorCredential { .. } => ControlOp::Processor,
            ControlRequest::IssueWorkOrder { .. } => ControlOp::IssueWorkOrder,
            ControlRequest::StageConsent { .. } => ControlOp::StageConsent,
            ControlRequest::CoordWhoAmI => ControlOp::CoordWhoAmI,
            ControlRequest::PeerShow { .. } => ControlOp::CoordPeerShow,
            ControlRequest::Stage { .. } => ControlOp::CoordStage,
            ControlRequest::StageShow { .. } => ControlOp::CoordStageShow,
            ControlRequest::Dispatch { .. } => ControlOp::CoordDispatch,
            ControlRequest::TaskStatus { .. } => ControlOp::CoordTaskStatus,
            ControlRequest::EventsRead { .. } => ControlOp::CoordEventsRead,
            ControlRequest::CapabilityEvidence { .. } => ControlOp::CoordCapabilityEvidence,
        }
    }
}

/// A control response: a result value, or an RFC 9457 problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ControlResponse {
    Ok { result: serde_json::Value },
    Problem { problem: Problem },
}

/// Why the control socket could not serve.
#[derive(Debug, thiserror::Error)]
pub enum SocketError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Binds a control socket at `path` with owner-only (`0600`) permissions (design
/// §16.2). Removes a stale socket file first, so a restart rebinds cleanly.
pub fn bind_socket(path: &Path) -> Result<UnixListener, SocketError> {
    bind_socket_mode(path, 0o600)
}

fn bind_socket_mode(path: &Path, mode: u32) -> Result<UnixListener, SocketError> {
    // A stale socket file from a previous run would block the bind.
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Binds the coordination socket **only** when a coordination UID is configured
/// (ADR-0016 §1). `coord_uid` of `None` returns `Ok(None)` and creates no file at
/// all: absent rather than guarded, the posture ADR-0015 took when it left the
/// bootstrap endpoint unmounted. There is then nothing to connect to and nothing
/// to probe.
///
/// The file is `0660`, not `0600`: the coordination identity is a *different*
/// Unix user, so reachability is one visible OS grant (a group or an ACL on the
/// socket, inside a runtime directory that user may traverse) — while admission
/// stays the named-UID `SO_PEERCRED` check in the returned [`Admission`]. The
/// mode is not the boundary; the peer credential is.
pub fn bind_coord_socket(
    path: &Path,
    coord_uid: Option<u32>,
    daemon_uid: u32,
) -> Result<Option<(UnixListener, Admission)>, SocketError> {
    let Some(coord_uid) = coord_uid else {
        return Ok(None);
    };
    let listener = bind_socket_mode(path, 0o660)?;
    Ok(Some((listener, Admission::coord(daemon_uid, coord_uid))))
}

/// The largest request line the coordination surface accepts (ADR-0016). Ample
/// for a staged payload at [`MAX_STAGED_PAYLOAD_BYTES`](crate::MAX_STAGED_PAYLOAD_BYTES)
/// once base64 has inflated it by 4/3, and small enough that a separate principal
/// cannot pin unbounded daemon memory with one connection.
pub const MAX_COORD_REQUEST_BYTES: u64 = 1 << 20;

/// The per-surface request ceiling, or `None` for the daemon's own UID.
fn request_ceiling(surface: Surface) -> Option<u64> {
    match surface {
        Surface::Coord => Some(MAX_COORD_REQUEST_BYTES),
        Surface::Admin | Surface::Worker => None,
    }
}

/// Serves one connection (design §16.2): authenticate the peer's UID, read one
/// request, authorize it against `surface`, dispatch, and write the response. A
/// peer whose UID `admission` does not admit is refused before any request is
/// read; an operation not permitted on `surface` is refused before dispatch.
pub fn handle_connection<F>(
    stream: UnixStream,
    surface: Surface,
    admission: &Admission,
    dispatch: &F,
) -> Result<(), SocketError>
where
    F: Fn(&ControlRequest) -> Result<serde_json::Value, Problem>,
{
    // (1) Peer-credential authentication — refuse a foreign UID before reading.
    if !peer_credentials(&stream).is_ok_and(|cred| admission.admits(cred.uid)) {
        let problem = Problem {
            type_: "urn:akson:error:unauthorized".to_owned(),
            title: "local peer is not authorized".to_owned(),
            status: 403,
            detail: None,
        };
        return write_response(&stream, &ControlResponse::Problem { problem });
    }

    // A bounded read on the coordination surface: that peer is a *different*
    // principal, so what it can make the daemon buffer must have a ceiling. Admin
    // and worker are the daemon's own UID and stay unbounded — a `task send` spec
    // or a `task fulfill` payload is legitimately large.
    let mut line = String::new();
    let read = match request_ceiling(surface) {
        Some(max) => {
            let mut reader = BufReader::new(stream.try_clone()?.take(max + 1));
            reader.read_line(&mut line)?
        }
        None => BufReader::new(stream.try_clone()?).read_line(&mut line)?,
    };
    if request_ceiling(surface).is_some_and(|max| read as u64 > max) {
        let problem = Problem::new(
            413,
            "request-too-large",
            "the control request exceeds this surface's ceiling",
        );
        return write_response(&stream, &ControlResponse::Problem { problem });
    }
    let request: ControlRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let problem = Problem {
                type_: "urn:akson:error:malformed-request".to_owned(),
                title: "request is not a valid control request".to_owned(),
                status: 400,
                detail: Some(e.to_string()),
            };
            return write_response(&stream, &ControlResponse::Problem { problem });
        }
    };

    // (2) Surface authorization — the worker surface cannot do admin operations.
    let response = match authorize(surface, request.op()) {
        Err(problem) => ControlResponse::Problem { problem },
        Ok(()) => match dispatch(&request) {
            Ok(result) => ControlResponse::Ok { result },
            Err(problem) => ControlResponse::Problem { problem },
        },
    };
    write_response(&stream, &response)
}

/// How many connections one surface serves at the same time.
///
/// Bounded rather than unlimited, because a thread per connection with no
/// ceiling is a different denial with the same shape. At the ceiling the next
/// connection is served on the accept thread — the old behaviour — so the socket
/// degrades to serialised rather than dropping anyone.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Runs the accept loop, serving each connection on `surface` (design §16.2). Blocks
/// until the listener is closed. Per-connection errors are logged and skipped so one
/// bad peer cannot take the socket down.
///
/// **Connections are served concurrently, up to [`MAX_CONCURRENT_CONNECTIONS`].**
/// That is not throughput: an operation on this socket can block on the network
/// — a coordination `dispatch` carries bytes to a pinned peer — and while the
/// loop served one connection at a time, a peer that stalled a carriage stalled
/// *every* operation on that surface with it. The carrier's own timeouts bound
/// how long one such attempt lasts; this bounds who else has to wait for it.
/// Nothing here relaxes admission or authorization: each connection still runs
/// the full [`handle_connection`] gate, and shared state stays behind the
/// dispatcher's own locks. A connection that panics now takes only itself with
/// it rather than the accept loop, which is the intent the per-connection error
/// handling already had.
pub fn serve<F>(
    listener: &UnixListener,
    surface: Surface,
    admission: &Admission,
    dispatch: F,
) -> Result<(), SocketError>
where
    F: Fn(&ControlRequest) -> Result<serde_json::Value, Problem> + Sync,
{
    let serve_one = |stream| {
        if let Err(e) = handle_connection(stream, surface, admission, &dispatch) {
            eprintln!("aksond: control connection error: {e}");
        }
    };
    let in_flight = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("aksond: accept error: {e}");
                    continue;
                }
            };
            let claimed = in_flight.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if claimed >= MAX_CONCURRENT_CONNECTIONS {
                in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                serve_one(stream);
                continue;
            }
            let serve_one = &serve_one;
            let in_flight = &in_flight;
            scope.spawn(move || {
                serve_one(stream);
                in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
    });
    Ok(())
}

fn write_response(mut stream: &UnixStream, response: &ControlResponse) -> Result<(), SocketError> {
    let mut bytes = serde_json::to_vec(response)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

/// Sends one request to a control socket and reads the response (the CLI client
/// side). Same-process helper used by `akson-cli` and tests.
pub fn send_request(path: &Path, request: &ControlRequest) -> Result<ControlResponse, SocketError> {
    let stream = UnixStream::connect(path)?;
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    (&stream).write_all(&bytes)?;
    (&stream).flush()?;
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim())?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::peercred::current_uid;
    use std::thread;

    fn dispatch(req: &ControlRequest) -> Result<serde_json::Value, Problem> {
        match req {
            ControlRequest::Diagnose => Ok(serde_json::json!({"ready": true})),
            _ => Ok(serde_json::json!({"accepted": true})),
        }
    }

    /// Binds a socket in a temp dir, serves one connection on `surface` in a thread,
    /// sends `request` from this process, and returns the response.
    fn round_trip(surface: Surface, request: ControlRequest) -> ControlResponse {
        let dir = std::env::temp_dir().join(format!("aksond-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("ctl-{surface:?}-{:?}.sock", request.op()));
        let listener = bind_socket(&path).unwrap();

        let server = {
            let path = path.clone();
            thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                handle_connection(
                    stream,
                    surface,
                    &Admission::same_uid(current_uid()),
                    &dispatch,
                )
                .unwrap();
                drop(listener);
                let _ = std::fs::remove_file(&path);
            })
        };
        let response = send_request(&path, &request).unwrap();
        server.join().unwrap();
        response
    }

    #[test]
    fn the_socket_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("aksond-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("perm.sock");
        let _listener = bind_socket(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "control socket must be 0600");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn admin_surface_dispatches_a_diagnose() {
        let response = round_trip(Surface::Admin, ControlRequest::Diagnose);
        match response {
            ControlResponse::Ok { result } => assert_eq!(result["ready"], true),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn worker_surface_may_submit_a_result() {
        let response = round_trip(
            Surface::Worker,
            ControlRequest::SubmitResult(crate::result::ResultSubmission {
                task_id: "task-1".to_owned(),
                outputs: vec![],
                evidence: vec![],
                slots: vec![],
            }),
        );
        assert!(matches!(response, ControlResponse::Ok { .. }));
    }

    #[test]
    fn worker_surface_is_refused_an_admin_operation() {
        let response = round_trip(
            Surface::Worker,
            ControlRequest::IssueWorkOrder {
                task_id: "task-1".to_owned(),
            },
        );
        match response {
            ControlResponse::Problem { problem } => assert_eq!(problem.status, 403),
            other => panic!("expected a 403 Problem, got {other:?}"),
        }
    }

    // --- The coordination socket (ADR-0016 §1) ---

    #[test]
    fn an_unset_coord_uid_creates_no_socket_at_all() {
        let dir = std::env::temp_dir().join(format!("aksond-coord-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("coord.sock");
        let bound = bind_coord_socket(&path, None, current_uid()).unwrap();
        assert!(bound.is_none(), "no UID configured ⇒ no listener");
        assert!(
            !path.exists(),
            "absent rather than guarded: the socket file must not exist"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_configured_coord_uid_binds_a_socket_admitting_it_and_the_daemon() {
        let dir = std::env::temp_dir().join(format!("aksond-coord-bound-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("coord.sock");
        let peer = current_uid().wrapping_add(4242);
        let (listener, admission) = bind_coord_socket(&path, Some(peer), current_uid())
            .unwrap()
            .expect("a configured UID binds");
        assert!(path.exists());
        // The mode is deliberately group-reachable; admission is the peer credential.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o660);
        assert!(admission.admits(peer), "the configured driver is admitted");
        assert!(
            admission.admits(current_uid()),
            "and the daemon itself, for diagnostics"
        );
        assert!(!admission.admits(peer.wrapping_add(1)), "nobody else");
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_foreign_uid_is_refused_before_the_request_line_is_read() {
        let dir = std::env::temp_dir().join(format!("aksond-coord-foreign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("foreign.sock");
        let listener = bind_socket(&path).unwrap();
        // An admission set that does NOT contain our UID stands in for a foreign
        // peer connecting — the check is the same comparison either way.
        let admission = Admission::same_uid(current_uid().wrapping_add(1));
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, Surface::Coord, &admission, &dispatch).unwrap();
        });

        // Connect and write NOTHING: no request line ever crosses the socket.
        let stream = UnixStream::connect(&path).unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        server.join().unwrap();

        let response: ControlResponse = serde_json::from_str(line.trim()).unwrap();
        match response {
            ControlResponse::Problem { problem } => {
                assert_eq!(problem.status, 403);
                assert_eq!(problem.type_, "urn:akson:error:unauthorized");
                // The refusal names no peer, no op, and no surface internals.
                assert!(problem.detail.is_none());
            }
            other => panic!("expected an unauthorized Problem, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **One slow operation must not take the surface with it.** A coordination
    /// `dispatch` blocks on the network — it carries bytes to a pinned peer —
    /// and this loop used to serve connections strictly one at a time. A peer
    /// that stalled one carriage therefore stalled `coord_whoami`, `stage_show`,
    /// `events_read` and every other operation on that socket for as long as it
    /// cared to, which is a remote party denying a local surface.
    ///
    /// The oracle is the second connection's answer *while the first is still
    /// blocked*. With a sequential accept loop it never arrives, and this fails
    /// on the receive timeout instead of hanging.
    #[test]
    fn a_blocked_operation_does_not_deny_the_surface_to_another_connection() {
        use std::sync::mpsc;
        use std::sync::{Arc, Condvar, Mutex};
        use std::time::Duration;

        let dir = std::env::temp_dir().join(format!("aksond-busy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("busy.sock");
        let listener = bind_socket(&path).unwrap();

        // The first request blocks inside dispatch until this is released — the
        // stand-in for a carriage to a peer that is not answering.
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let blocking = {
            let gate = gate.clone();
            move |req: &ControlRequest| -> Result<serde_json::Value, Problem> {
                if matches!(req, ControlRequest::TaskInbox) {
                    let _ = entered_tx.send(());
                    let (lock, cv) = &*gate;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = cv.wait(released).unwrap();
                    }
                }
                Ok(serde_json::json!({"ready": true}))
            }
        };

        let admission = Admission::same_uid(current_uid());
        thread::spawn(move || {
            let _ = serve(&listener, Surface::Admin, &admission, blocking);
        });

        // Connection 1: occupy the surface.
        let slow = {
            let path = path.clone();
            thread::spawn(move || send_request(&path, &ControlRequest::TaskInbox))
        };
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the first request never reached dispatch");

        // Connection 2, while connection 1 is provably still inside dispatch.
        let (fast_tx, fast_rx) = mpsc::channel();
        {
            let path = path.clone();
            thread::spawn(move || fast_tx.send(send_request(&path, &ControlRequest::Diagnose)));
        }
        let answered = fast_rx.recv_timeout(Duration::from_secs(5));
        // Release the blocked op before asserting, so a failure does not leave a
        // parked thread holding the gate.
        {
            let (lock, cv) = &*gate;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }
        match answered {
            Ok(Ok(ControlResponse::Ok { result })) => assert_eq!(result["ready"], true),
            other => {
                panic!("a stalled operation denied the surface to a second connection: {other:?}")
            }
        }
        assert!(matches!(
            slow.join().unwrap().unwrap(),
            ControlResponse::Ok { .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_coord_uid_is_parsed_strictly() {
        use std::ffi::OsStr;
        assert_eq!(parse_coord_uid(None), Ok(None));
        assert_eq!(parse_coord_uid(Some(OsStr::new(""))), Ok(None));
        assert_eq!(parse_coord_uid(Some(OsStr::new("  "))), Ok(None));
        assert_eq!(parse_coord_uid(Some(OsStr::new("1234"))), Ok(Some(1234)));
        // A typo is an error, never a silently absent surface.
        assert!(parse_coord_uid(Some(OsStr::new("akson-coord"))).is_err());
        assert!(parse_coord_uid(Some(OsStr::new("-1"))).is_err());
    }

    #[test]
    fn the_three_socket_paths_are_siblings_in_the_runtime_dir() {
        let dir = socket_dir();
        assert_eq!(admin_socket_path(), dir.join("admin.sock"));
        assert_eq!(worker_socket_path(), dir.join("worker.sock"));
        assert_eq!(coord_socket_path(), dir.join("coord.sock"));
    }
}
