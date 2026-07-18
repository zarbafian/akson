//! The Axon operator CLI.
//!
//! Full command assembly (clap, the OpenAPI control client, every §16.4 command)
//! is M12, layering in on the daemon's admin control socket. Today: `axon doctor`
//! (host capability check, no daemon needed — the M9 exit surface, §13.1/§17.3) and
//! `axon status` (queries the running daemon over the admin socket, §16.2), over a
//! hand-rolled argument match so no CLI-framework decision is pre-empted.

use std::process::ExitCode;

use axon_sandbox::{all_required_available, diagnose, Diagnostic};
use axond::{admin_socket_path, send_request, ControlRequest, ControlResponse};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("doctor") => doctor(),
        Some("status") => status(),
        _ => {
            eprintln!("axon: implemented so far: `axon doctor` (host check) and `axon status` (query the daemon)");
            ExitCode::from(2)
        }
    }
}

/// Queries the running daemon over the admin control socket (design §16.2) and
/// prints its health. Exits non-zero if the daemon is unreachable or not ready.
fn status() -> ExitCode {
    let path = admin_socket_path();
    match send_request(&path, &ControlRequest::Diagnose) {
        Ok(ControlResponse::Ok { result }) => {
            let ready = result.get("sandbox_ready").and_then(|v| v.as_bool()) == Some(true);
            println!("axon status — daemon at {}", path.display());
            println!("  daemon:        up");
            println!("  sandbox_ready: {}", if ready { "yes" } else { "no" });
            if ready {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Ok(ControlResponse::Problem { problem }) => {
            eprintln!(
                "axon status: daemon refused the request ({})",
                problem.title
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!(
                "axon status: could not reach the daemon at {} ({e}). Is `axond serve` running?",
                path.display()
            );
            ExitCode::from(1)
        }
    }
}

/// Renders the sandbox capability report and returns a fail-closed exit code:
/// `0` when every required capability is available, `1` when the clean worker
/// could not launch (design §13.1: refuse rather than run un-isolated).
fn doctor() -> ExitCode {
    let report = diagnose();
    let width = report.iter().map(|d| d.feature.len()).max().unwrap_or(0);

    println!("axon doctor — sandbox capabilities");
    for d in &report {
        println!("  {:>width$}  {}", d.feature, status_line(d), width = width);
    }

    if all_required_available(&report) {
        println!("\nready: every required capability is available.");
        ExitCode::SUCCESS
    } else {
        let missing: Vec<&str> = report
            .iter()
            .filter(|d| d.required && !d.available)
            .map(|d| d.feature)
            .collect();
        eprintln!(
            "\nNOT READY: the clean worker cannot launch — missing {}.",
            missing.join(", ")
        );
        ExitCode::from(1)
    }
}

/// One capability's status column: `ok` / `MISSING` / `n/a`, an `(optional)` tag
/// for non-required capabilities, and the human-readable detail.
fn status_line(d: &Diagnostic) -> String {
    let mark = match (d.available, d.required) {
        (true, _) => "ok",
        (false, true) => "MISSING",
        (false, false) => "n/a",
    };
    let optional = if d.required { "" } else { " (optional)" };
    format!("{mark:<8}{optional} — {}", d.detail)
}
