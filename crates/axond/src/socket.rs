//! The local control socket: framing, peer authentication, and surface
//! authorization (design §16.2).
//!
//! A control socket is bound with owner-only permissions, and every connection is
//! (1) authenticated by Unix peer credentials — the peer's UID must be the
//! daemon's — and (2) authorized by *surface* — a request is refused unless the
//! socket it arrived on (admin or worker) is privileged enough for it. Only then is
//! the request dispatched. Requests and responses are newline-delimited JSON;
//! failures are RFC 9457 [`Problem`] objects.
//!
//! The dispatch itself is injected, so this module owns only the security framing;
//! the daemon supplies what each operation does.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::control::{authorize, ControlOp, Problem, Surface};
use crate::peercred::{authenticate_same_uid, current_uid};

/// The per-user runtime directory for the daemon's sockets. Prefers
/// `$XDG_RUNTIME_DIR/axon` (a private, `0700`, per-user tmpfs), else a UID-scoped
/// temp directory.
pub fn socket_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(rt) if !rt.is_empty() => PathBuf::from(rt).join("axon"),
        _ => std::env::temp_dir().join(format!("axon-{}", current_uid())),
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

/// A control request over the local socket. Each variant maps to a [`ControlOp`]
/// for the surface-authorization gate; richer arguments ride inside the variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Report daemon + sandbox health (`axon doctor` / `axon status`).
    Diagnose,
    /// List the submitted Tasks awaiting a decision (`axon task inbox`).
    TaskInbox,
    /// Render a submitted Task's risk card (`axon task show`).
    TaskShow { task_id: String },
    /// Submit a bounded worker result (the narrow worker surface).
    SubmitResult { task_id: String, byte_length: u64 },
    /// Issue a one-shot work order (admin only) — used here to exercise the gate.
    IssueWorkOrder { task_id: String },
}

impl ControlRequest {
    /// The authorization unit for this request (design §16.2).
    pub fn op(&self) -> ControlOp {
        match self {
            ControlRequest::Diagnose => ControlOp::Diagnose,
            ControlRequest::TaskInbox | ControlRequest::TaskShow { .. } => ControlOp::TaskInspect,
            ControlRequest::SubmitResult { .. } => ControlOp::SubmitResult,
            ControlRequest::IssueWorkOrder { .. } => ControlOp::IssueWorkOrder,
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
    // A stale socket file from a previous run would block the bind.
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves one connection (design §16.2): authenticate the peer's UID, read one
/// request, authorize it against `surface`, dispatch, and write the response. A
/// peer whose UID is not `daemon_uid` is refused before any request is read; an
/// operation not permitted on `surface` is refused before dispatch.
pub fn handle_connection<F>(
    stream: UnixStream,
    surface: Surface,
    daemon_uid: u32,
    dispatch: &F,
) -> Result<(), SocketError>
where
    F: Fn(&ControlRequest) -> Result<serde_json::Value, Problem>,
{
    // (1) Peer-credential authentication — refuse a foreign UID before reading.
    if authenticate_same_uid(&stream, daemon_uid).is_err() {
        let problem = Problem {
            type_: "urn:axon:error:unauthorized".to_owned(),
            title: "local peer is not authorized".to_owned(),
            status: 403,
            detail: None,
        };
        return write_response(&stream, &ControlResponse::Problem { problem });
    }

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let request: ControlRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let problem = Problem {
                type_: "urn:axon:error:malformed-request".to_owned(),
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

/// Runs the accept loop, serving each connection on `surface` (design §16.2). Blocks
/// until the listener is closed. Per-connection errors are logged and skipped so one
/// bad peer cannot take the socket down.
pub fn serve<F>(
    listener: &UnixListener,
    surface: Surface,
    daemon_uid: u32,
    dispatch: F,
) -> Result<(), SocketError>
where
    F: Fn(&ControlRequest) -> Result<serde_json::Value, Problem>,
{
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_connection(stream, surface, daemon_uid, &dispatch) {
                    eprintln!("axond: control connection error: {e}");
                }
            }
            Err(e) => eprintln!("axond: accept error: {e}"),
        }
    }
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
/// side). Same-process helper used by `axon-cli` and tests.
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
#[allow(clippy::unwrap_used, clippy::panic)]
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
        let dir = std::env::temp_dir().join(format!("axond-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("ctl-{surface:?}-{:?}.sock", request.op()));
        let listener = bind_socket(&path).unwrap();

        let server = {
            let path = path.clone();
            thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                handle_connection(stream, surface, current_uid(), &dispatch).unwrap();
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
        let dir = std::env::temp_dir().join(format!("axond-perm-{}", std::process::id()));
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
            ControlRequest::SubmitResult {
                task_id: "task-1".to_owned(),
                byte_length: 12,
            },
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
}
