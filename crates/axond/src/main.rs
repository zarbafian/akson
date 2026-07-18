//! The Axon daemon (`axond serve`): binds the two OS-protected local sockets and
//! serves control requests (design §16.2).
//!
//! The admin socket carries authority-bearing operator operations; the worker
//! socket is narrow. Both authenticate the peer's UID and authorize by surface
//! before dispatch. This first assembly wires health (`diagnose`); the full command
//! set and durable state layer in on the same gates.

use std::os::unix::fs::PermissionsExt;

use axond::{
    admin_socket_path, bind_socket, current_uid, serve, socket_dir, worker_socket_path,
    ControlRequest, Problem, Surface,
};

fn dispatch(req: &ControlRequest) -> Result<serde_json::Value, Problem> {
    match req {
        ControlRequest::Diagnose => {
            let report = axon_sandbox::diagnose();
            let ready = axon_sandbox::all_required_available(&report);
            let capabilities: Vec<_> = report
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "feature": d.feature,
                        "available": d.available,
                        "required": d.required,
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "daemon": "axond",
                "sandbox_ready": ready,
                "capabilities": capabilities,
            }))
        }
        // Worker operations are authorized here but not yet backed by durable state;
        // acknowledge so the surface separation can be exercised end to end.
        _ => Ok(serde_json::json!({ "accepted": true })),
    }
}

fn run() -> std::io::Result<()> {
    // Private per-user runtime directory for the sockets (0700).
    let dir = socket_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    let uid = current_uid();
    let admin_path = admin_socket_path();
    let worker_path = worker_socket_path();
    let admin = bind_socket(&admin_path).map_err(std::io::Error::other)?;
    let worker = bind_socket(&worker_path).map_err(std::io::Error::other)?;

    eprintln!(
        "axond: serving admin at {} and worker at {} (uid {uid})",
        admin_path.display(),
        worker_path.display()
    );

    // The worker surface serves on its own thread; the admin surface on this one.
    let worker_thread = std::thread::spawn(move || {
        if let Err(e) = serve(&worker, Surface::Worker, uid, dispatch) {
            eprintln!("axond: worker socket stopped: {e}");
        }
    });
    serve(&admin, Surface::Admin, uid, dispatch).map_err(std::io::Error::other)?;
    let _ = worker_thread.join();
    Ok(())
}

fn main() -> std::process::ExitCode {
    // Only `serve` (the default) is wired in this assembly step.
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        None | Some("serve") => match run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("axond: {e}");
                std::process::ExitCode::FAILURE
            }
        },
        Some(other) => {
            eprintln!("axond: unknown command {other:?}; only `serve` is implemented");
            std::process::ExitCode::from(2)
        }
    }
}
