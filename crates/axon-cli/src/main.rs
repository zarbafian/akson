//! The Axon operator CLI.
//!
//! A hand-rolled argument match over the daemon's admin control socket (§16.2), so
//! no CLI-framework decision is pre-empted:
//!
//! - `axon doctor` — host capability check, no daemon needed (§13.1/§17.3).
//! - `axon status` — daemon health over the admin socket (§16.2).
//! - `axon task inbox` — the submitted Tasks awaiting a decision (§16.4).
//! - `axon task show <id>` — a Task's §5.2 risk card, the approval surface.
//! - `axon task approve <id>` — accept the Task and issue its work order (§10.2/§12.3).
//! - `axon task deny <id> <reason>` — sign a reject decision (§10.2).
//! - `axon task deliver <id>` — deliver a completed Task's result to the requester (§7.2).

use std::ffi::{OsStr, OsString};
use std::process::ExitCode;

use axon_sandbox::{all_required_available, diagnose, Diagnostic};
use axond::{admin_socket_path, send_request, ControlRequest, ControlResponse};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("doctor") => doctor(),
        Some("status") => status(),
        Some("task") => task(&mut args),
        _ => {
            eprintln!("axon: commands: doctor, status, task {{inbox|show <id>|approve <id>|deny <id> <reason>}}");
            ExitCode::from(2)
        }
    }
}

/// Routes the `axon task …` subcommands over the admin control socket (§16.4).
fn task(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("inbox") => task_inbox(),
        Some("show") => match next_arg(args) {
            Some(id) => task_show(&id),
            None => usage("axon task show <task-id>"),
        },
        Some("approve") => match next_arg(args) {
            Some(id) => task_approve(&id),
            None => usage("axon task approve <task-id>"),
        },
        Some("deny") => match (next_arg(args), next_arg(args)) {
            (Some(id), Some(reason)) => task_deny(&id, &reason),
            _ => usage("axon task deny <task-id> <reason>"),
        },
        Some("deliver") => match next_arg(args) {
            Some(id) => task_deliver(&id),
            None => usage("axon task deliver <task-id>"),
        },
        _ => usage("axon task {inbox|show <id>|approve <id>|deny <id> <reason>|deliver <id>}"),
    }
}

/// The submitted Tasks awaiting a decision (`axon task inbox`).
fn task_inbox() -> ExitCode {
    let result = match call(&ControlRequest::TaskInbox) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let tasks = result["tasks"].as_array().cloned().unwrap_or_default();
    if tasks.is_empty() {
        println!("no submitted tasks.");
        return ExitCode::SUCCESS;
    }
    println!("submitted tasks ({}):", tasks.len());
    for t in &tasks {
        println!(
            "  {}  contract {}  rev {}  [{}]",
            t["task_id"].as_str().unwrap_or("?"),
            t["contract_id"].as_str().unwrap_or("?"),
            t["revision"],
            t["state"].as_str().unwrap_or("?"),
        );
    }
    ExitCode::SUCCESS
}

/// A submitted Task's §5.2 risk card — the operator's approval surface.
fn task_show(task_id: &str) -> ExitCode {
    let result = match call(&ControlRequest::TaskShow {
        task_id: task_id.to_owned(),
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    if let Some(sentence) = result["sentence"].as_str() {
        println!("{sentence}\n");
    }
    let empty = Vec::new();
    for section in result["sections"].as_array().unwrap_or(&empty) {
        println!("{}", section["heading"].as_str().unwrap_or(""));
        for line in section["lines"].as_array().unwrap_or(&empty) {
            println!("  {}", line.as_str().unwrap_or(""));
        }
    }
    ExitCode::SUCCESS
}

/// Approve a Task: accept it and issue the one-shot work order (`axon task approve`).
fn task_approve(task_id: &str) -> ExitCode {
    let result = match call(&ControlRequest::TaskApprove {
        task_id: task_id.to_owned(),
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let caps: Vec<&str> = result["granted_capabilities"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    println!("approved {task_id}");
    println!(
        "  work order: {}",
        result["work_order_id"].as_str().unwrap_or("?")
    );
    println!(
        "  granted:    {}",
        if caps.is_empty() {
            "(none)".to_owned()
        } else {
            caps.join(", ")
        }
    );
    ExitCode::SUCCESS
}

/// Deny a Task: sign a reject decision (`axon task deny`).
fn task_deny(task_id: &str, reason: &str) -> ExitCode {
    match call(&ControlRequest::TaskDeny {
        task_id: task_id.to_owned(),
        reason: reason.to_owned(),
    }) {
        Ok(_) => {
            println!("denied {task_id}: {reason}");
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// Deliver a completed Task's result to the requester (`axon task deliver`).
fn task_deliver(task_id: &str) -> ExitCode {
    let result = match call(&ControlRequest::TaskDeliver {
        task_id: task_id.to_owned(),
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let delivered = result["delivered"].as_bool() == Some(true);
    println!(
        "{} {task_id} → {} (status {})",
        if delivered {
            "delivered"
        } else {
            "NOT delivered"
        },
        result["recipient"].as_str().unwrap_or("?"),
        result["status"],
    );
    if delivered {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Sends one admin control request, returning its result value or an exit code
/// after printing a uniform error (a daemon refusal, or an unreachable daemon).
fn call(req: &ControlRequest) -> Result<serde_json::Value, ExitCode> {
    let path = admin_socket_path();
    match send_request(&path, req) {
        Ok(ControlResponse::Ok { result }) => Ok(result),
        Ok(ControlResponse::Problem { problem }) => {
            eprintln!("axon: {} ({})", problem.title, problem.status);
            Err(ExitCode::from(1))
        }
        Err(e) => {
            eprintln!(
                "axon: could not reach the daemon at {} ({e}). Is `axond serve` running?",
                path.display()
            );
            Err(ExitCode::from(1))
        }
    }
}

fn next_arg(args: &mut impl Iterator<Item = OsString>) -> Option<String> {
    args.next().and_then(|s| s.into_string().ok())
}

fn usage(form: &str) -> ExitCode {
    eprintln!("usage: {form}");
    ExitCode::from(2)
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
