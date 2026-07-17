//! The Axon operator CLI.
//!
//! Full command assembly (clap, the OpenAPI control client, every §16.4 command)
//! is M12. This binary carries only `axon doctor` today — the M9 exit surface
//! ("doctor reports every capability", design §13.1, §17.3) — over a hand-rolled
//! argument match so no CLI-framework decision is pre-empted.

use std::process::ExitCode;

use axon_sandbox::{all_required_available, diagnose, Diagnostic};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("doctor") => doctor(),
        _ => {
            eprintln!("axon: only `axon doctor` is implemented so far (see design/2026-07-16-implementation-plan.md M12)");
            ExitCode::from(2)
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
