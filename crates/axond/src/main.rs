//! The Axon daemon (`axond serve`): opens the durable store and binds the two
//! OS-protected local control sockets (design §16.2, §16.4).
//!
//! The admin socket carries authority-bearing operator operations; the worker
//! socket is narrow. Both authenticate the peer's UID and authorize by surface
//! before dispatch. This assembly serves health (`diagnose`) and the store-backed
//! operator views (`task inbox`, `task show`); the decision, work-order, and mTLS
//! receive paths layer on the same shared store.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use axond::{
    admin_socket_path, bind_socket, current_uid, run_pair_listener, run_receive_listener, serve,
    socket_dir, worker_socket_path, ControlRequest, DaemonConfig, DaemonState, Surface,
};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = DaemonConfig::from_env();
    let state = Arc::new(DaemonState::bootstrap(&config)?);

    // Private per-user runtime directory for the sockets (0700).
    let dir = socket_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    let uid = current_uid();
    let admin_path = admin_socket_path();
    let worker_path = worker_socket_path();
    let admin = bind_socket(&admin_path)?;
    let worker = bind_socket(&worker_path)?;

    eprintln!(
        "axond: {}/{} serving admin at {} and worker at {} (uid {uid}); data in {}",
        config.local_performer.issuer,
        config.local_performer.agent,
        admin_path.display(),
        worker_path.display(),
        config.data_dir.display(),
    );

    // The A2A receive listener (if configured) runs on its own thread with its own
    // tokio runtime, sharing the daemon's store — a received Task shows up in the
    // operator's inbox at once. A listener failure is logged, not fatal to control.
    if let Some(addr) = config.receive_addr.clone() {
        let state = state.clone();
        eprintln!("axond: serving A2A receive (mTLS) at {addr}");
        std::thread::spawn(move || {
            if let Err(e) = run_receive_listener(state, &addr) {
                eprintln!("axond: receive listener stopped: {e}");
            }
        });
    }

    // The pairing bootstrap endpoint (if configured): its own thread + runtime,
    // sharing the daemon's store. Inert until an invitation is minted.
    if let Some(addr) = config.pair_addr.clone() {
        let state = state.clone();
        eprintln!("axond: serving pairing (mTLS) at {addr}");
        std::thread::spawn(move || {
            if let Err(e) = run_pair_listener(state, &addr) {
                eprintln!("axond: pairing listener stopped: {e}");
            }
        });
    }

    // Both surfaces share the one daemon state; each dispatch closure holds its own
    // handle. The worker surface serves on its own thread, the admin on this one.
    let worker_thread = {
        let state = state.clone();
        std::thread::spawn(move || {
            let d = move |req: &ControlRequest| state.dispatch(req);
            if let Err(e) = serve(&worker, Surface::Worker, uid, d) {
                eprintln!("axond: worker socket stopped: {e}");
            }
        })
    };
    let admin_dispatch = {
        let state = state.clone();
        move |req: &ControlRequest| state.dispatch(req)
    };
    serve(&admin, Surface::Admin, uid, admin_dispatch)?;
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
