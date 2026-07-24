//! The Akson daemon (`aksond serve`): opens the durable store and binds the two
//! OS-protected local control sockets (design §16.2, §16.4).
//!
//! The admin socket carries authority-bearing operator operations; the worker
//! socket is narrow. Both authenticate the peer's UID and authorize by surface
//! before dispatch. This assembly serves health (`diagnose`) and the store-backed
//! operator views (`task inbox`, `task show`); the decision, work-order, and mTLS
//! receive paths layer on the same shared store.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use aksond::{
    admin_socket_path, bind_socket, current_uid, run_receive_listener, serve,
    socket_dir, worker_socket_path, ControlRequest, DaemonConfig, DaemonState, Surface,
};

/// `aksond init` (design §16.4): create the data directory and bootstrap this
/// endpoint's durable identity (master secret + keys, the stable endpoint cert),
/// then print who it is and the fingerprint a peer must trust — without serving.
/// Idempotent: re-running loads the existing identity rather than replacing it.
fn init() -> Result<(), Box<dyn std::error::Error>> {
    let config = DaemonConfig::from_env();
    std::fs::create_dir_all(&config.data_dir)?;
    std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700))?;
    let state = DaemonState::bootstrap(&config)?;

    println!("akson initialized");
    println!(
        "  agent:        {}/{}",
        config.local_performer.issuer, config.local_performer.agent
    );
    println!("  data dir:     {}", config.data_dir.display());
    println!("  interface:    {}", config.interface_url);
    println!(
        "  receive:      {}",
        config.receive_addr.as_deref().unwrap_or("(control-only)")
    );
    println!(
        "  endpoint fp:  sha256:{}",
        state.endpoint_cert().fingerprint.value
    );

    // The token IS the pairing story (design §8.2): init ends by printing the
    // line you hand a peer — nothing else to mint, move, or confirm.
    let root = state
        .identity()
        .purpose_key(akson_crypto::purpose::KeyPurpose::AgentCard)
        .verifying()
        .to_public_bytes();
    let token = akson_crypto::token::encode_token(&root);
    let hint = state
        .config()
        .interface_url
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .filter(|hp| hp.contains(':'))
        .map(str::to_owned);
    let line = match hint {
        Some(h) => format!("{token}@{h}"),
        None => token,
    };
    println!("\n  identity token (public — hand this to whoever you want to work with):");
    println!("\n  {line}\n");
    println!("Start it with `aksond serve`; they import your line with `akson peer add <line> <a-label-they-choose>`.");
    Ok(())
}

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
        "aksond: {}/{} serving admin at {} and worker at {} (uid {uid}); data in {}",
        config.local_performer.issuer,
        config.local_performer.agent,
        admin_path.display(),
        worker_path.display(),
        config.data_dir.display(),
    );

    // The A2A receive listener (if configured) runs on its own thread with its own
    // tokio runtime, sharing the daemon's store — a received Task shows up in the
    // operator's inbox at once. The port is bound HERE, synchronously: a squatted
    // or unavailable address is fatal at startup, never a silently dead listener
    // behind a healthy-looking control plane (sec6 review). Use
    // AKSON_RECEIVE_ADDR=off for a deliberately control-only daemon.
    if let Some(addr) = config.receive_addr.clone() {
        let listener = aksond::bind_receive_addr(&addr)
            .map_err(|e| format!("cannot bind the receive address {addr}: {e}"))?;
        let state = state.clone();
        eprintln!("aksond: serving A2A receive (mTLS) at {addr}");
        std::thread::spawn(move || {
            if let Err(e) = run_receive_listener(state, listener) {
                eprintln!("aksond: receive listener stopped: {e}");
            }
        });
    }

    // The reactor: reacts to arriving tasks (standing auto-approval + the arrival
    // hook) on its own thread, off the inert receive path. Cheap when idle.
    {
        let state = state.clone();
        std::thread::spawn(move || aksond::run_reactor(state));
    }

    // Both surfaces share the one daemon state; each dispatch closure holds its own
    // handle. The worker surface serves on its own thread, the admin on this one.
    let worker_thread = {
        let state = state.clone();
        std::thread::spawn(move || {
            let d = move |req: &ControlRequest| state.dispatch(req);
            if let Err(e) = serve(&worker, Surface::Worker, uid, d) {
                eprintln!("aksond: worker socket stopped: {e}");
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
    let arg = std::env::args().nth(1);
    let result = match arg.as_deref() {
        None | Some("serve") => run(),
        Some("init") => init(),
        Some(other) => {
            eprintln!("aksond: unknown command {other:?}; expected `serve` or `init`");
            return std::process::ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aksond: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
