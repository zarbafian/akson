//! The Axon operator CLI.
//!
//! A hand-rolled argument match over the daemon's admin control socket (§16.2), so
//! no CLI-framework decision is pre-empted:
//!
//! - `axon doctor` — host capability check, no daemon needed (§13.1/§17.3).
//! - `axon status` — daemon health over the admin socket (§16.2).
//! - `axon whoami` — this daemon's identity + endpoint fingerprint (§8.1).
//! - `axon task inbox` — the submitted Tasks awaiting a decision (§16.4).
//! - `axon task show <id>` — a Task's §5.2 risk card, the approval surface.
//! - `axon task approve <id> [--processor <id>]` — accept the Task and issue its
//!   work order; `--processor` additionally grants processor_use for a model (§12.1).
//! - `axon task run <id>` — run the approved Task's worker in the sandbox (§7.2/§13.1).
//! - `axon task deny <id> <reason>` — sign a reject decision (§10.2).
//! - `axon task deliver <id>` — deliver a completed Task's result to the requester (§7.2).
//! - `axon task send <spec.json>` — send a task to a performer (§10.2).
//! - `axon processor {add|list|credential}` — configure processors + credentials (§13.1/§15.2).
//! - `axon peer list` — the paired peers (§16.4).
//! - `axon peer confirm <agent>` — promote a pending peer to active (§8.2).
//! - `axon pair invite <out-file>` — mint a pairing invitation (§8.2).
//! - `axon pair accept <invitation-file>` — accept a pairing invitation (§8.2).

use std::ffi::{OsStr, OsString};
use std::process::ExitCode;

use axon_sandbox::{all_required_available, diagnose, Diagnostic};
use axond::{admin_socket_path, send_request, ControlRequest, ControlResponse, TaskSpec};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("doctor") => doctor(),
        Some("status") => status(),
        Some("whoami") => whoami(),
        Some("task") => task(&mut args),
        Some("processor") => processor(&mut args),
        Some("peer") => peer(&mut args),
        Some("pair") => pair(&mut args),
        _ => {
            eprintln!("axon: commands: doctor, status, whoami, task {{…}}, processor {{…}}, peer {{list|confirm}}, pair {{invite|accept}}");
            ExitCode::from(2)
        }
    }
}

/// Routes the `axon pair …` subcommands over the admin control socket (§8.2).
fn pair(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("invite") => match next_arg(args) {
            Some(out) => pair_invite(&out),
            None => usage("axon pair invite <out-file>"),
        },
        Some("accept") => match next_arg(args) {
            Some(file) => pair_accept(&file),
            None => usage("axon pair accept <invitation-file>"),
        },
        _ => usage("axon pair {invite <out-file>|accept <invitation-file>}"),
    }
}

/// Mint a pairing invitation and write it to a file (`axon pair invite <out>`).
fn pair_invite(out_file: &str) -> ExitCode {
    let result = match call(&ControlRequest::PairInvite) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let invitation = match serde_json::to_string_pretty(&result["invitation"]) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("axon: the daemon returned a malformed invitation");
            return ExitCode::from(1);
        }
    };
    // The invitation carries a bearer secret — write it owner-only.
    if let Err(e) = write_owner_only(out_file, invitation.as_bytes()) {
        eprintln!("axon: cannot write {out_file}: {e}");
        return ExitCode::from(2);
    }
    println!("invitation written to {out_file}");
    ExitCode::SUCCESS
}

/// Writes `bytes` to `path` with `0600` permissions (an invitation is a secret).
fn write_owner_only(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

/// Accept a pairing invitation from a file (`axon pair accept <file>`).
fn pair_accept(invitation_file: &str) -> ExitCode {
    let invitation = match std::fs::read_to_string(invitation_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("axon: cannot read {invitation_file}: {e}");
            return ExitCode::from(2);
        }
    };
    let result = match call(&ControlRequest::PairAccept { invitation }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    println!(
        "paired with {} ({})",
        result["peer"].as_str().unwrap_or("?"),
        result["endpoint"].as_str().unwrap_or("?"),
    );
    ExitCode::SUCCESS
}

/// Routes the `axon peer …` subcommands over the admin control socket (§16.4).
fn peer(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("list") => peer_list(),
        Some("confirm") => match next_arg(args) {
            Some(agent) => peer_confirm(&agent),
            None => usage("axon peer confirm <agent-id>"),
        },
        _ => usage("axon peer {list|confirm <agent-id>}"),
    }
}

/// Confirm a pending peer (`axon peer confirm <agent>`).
fn peer_confirm(agent_id: &str) -> ExitCode {
    let result = match call(&ControlRequest::PeerConfirm {
        agent_id: agent_id.to_owned(),
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    if result["confirmed"].as_bool() == Some(true) {
        println!("confirmed peer {agent_id}");
    } else {
        println!("peer {agent_id} was not pending (nothing to confirm)");
    }
    ExitCode::SUCCESS
}

/// The paired peers (`axon peer list`).
fn peer_list() -> ExitCode {
    let result = match call(&ControlRequest::PeerList) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let peers = result["peers"].as_array().cloned().unwrap_or_default();
    if peers.is_empty() {
        println!("no paired peers.");
        return ExitCode::SUCCESS;
    }
    println!("paired peers ({}):", peers.len());
    for p in &peers {
        println!(
            "  {}  {}  [{}]",
            p["agent_id"].as_str().unwrap_or("?"),
            p["endpoint"].as_str().unwrap_or("?"),
            p["status"].as_str().unwrap_or("?"),
        );
    }
    ExitCode::SUCCESS
}

/// Routes the `axon processor …` subcommands over the admin control socket (§13.1).
fn processor(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("add") => processor_add(args),
        Some("list") => processor_list(),
        Some("credential") => match (next_arg(args), next_arg(args)) {
            (Some(id), Some(cred)) => processor_credential(&id, &cred),
            _ => usage("axon processor credential <id> <credential>"),
        },
        _ => usage("axon processor {add <id> <provider> <host> <port> <pin-sha256>|list|credential <id> <cred>}"),
    }
}

/// Add a pinned processor (`axon processor add <id> <provider> <host> <port> <pin>`).
fn processor_add(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    let (id, provider, host, port, pin) = match (
        next_arg(args),
        next_arg(args),
        next_arg(args),
        next_arg(args).and_then(|p| p.parse::<u16>().ok()),
        next_arg(args),
    ) {
        (Some(id), Some(provider), Some(host), Some(port), Some(pin)) => {
            (id, provider, host, port, pin)
        }
        _ => {
            return usage(
                "axon processor add <id> <provider> <host> <port> <ca|pin-sha256> [--path <path>] [--auth <bearer|none|header>] [--header <name:value>]",
            )
        }
    };
    // Optional trailing flags: request path, auth scheme, static headers.
    let (mut path, mut auth, mut headers) = (None, None, Vec::new());
    while let Some(flag) = next_arg(args) {
        match flag.as_str() {
            "--path" => path = next_arg(args),
            "--auth" => auth = next_arg(args),
            "--header" => {
                if let Some(h) = next_arg(args) {
                    headers.push(h);
                }
            }
            _ => {}
        }
    }
    // `ca` selects a public endpoint validated against the CA roots (no pin, global
    // egress); anything else is a pinned cert (typically a local/self-signed server).
    let (local, pin) = if pin.eq_ignore_ascii_case("ca") {
        (false, None)
    } else {
        (true, Some(pin))
    };
    let result = match call(&ControlRequest::ProcessorAdd {
        processor_id: id.clone(),
        provider,
        origin_host: host,
        origin_port: port,
        local,
        tls_certificate_sha256: pin,
        path,
        auth,
        headers,
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    println!(
        "added processor {}",
        result["processor_id"].as_str().unwrap_or(&id)
    );
    ExitCode::SUCCESS
}

/// List configured processors (`axon processor list`).
fn processor_list() -> ExitCode {
    let result = match call(&ControlRequest::ProcessorList) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let procs = result["processors"].as_array().cloned().unwrap_or_default();
    if procs.is_empty() {
        println!("no processors configured.");
        return ExitCode::SUCCESS;
    }
    println!("processors ({}):", procs.len());
    for p in &procs {
        println!(
            "  {}  {}  {}  [{}{}]",
            p["processor_id"].as_str().unwrap_or("?"),
            p["provider"].as_str().unwrap_or("?"),
            p["origin"].as_str().unwrap_or("?"),
            if p["local"].as_bool() == Some(true) {
                "local"
            } else {
                "remote"
            },
            if p["pinned"].as_bool() == Some(true) {
                ", pinned"
            } else {
                ""
            },
        );
    }
    ExitCode::SUCCESS
}

/// Set a processor's credential (`axon processor credential <id> <credential>`).
fn processor_credential(id: &str, credential: &str) -> ExitCode {
    match call(&ControlRequest::ProcessorCredential {
        processor_id: id.to_owned(),
        credential: credential.to_owned(),
    }) {
        Ok(_) => {
            println!("credential set for processor {id}");
            ExitCode::SUCCESS
        }
        Err(code) => code,
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
            Some(id) => {
                // Optional grants: `--processor <id>` (processor_use), `--artifacts`.
                let (mut processor, mut artifacts) = (None, false);
                while let Some(flag) = next_arg(args) {
                    match flag.as_str() {
                        "--processor" => processor = next_arg(args),
                        "--artifacts" => artifacts = true,
                        _ => {}
                    }
                }
                task_approve(&id, processor.as_deref(), artifacts)
            }
            None => usage("axon task approve <task-id> [--processor <processor-id>] [--artifacts]"),
        },
        Some("run") => match next_arg(args) {
            Some(id) => task_run(&id),
            None => usage("axon task run <task-id>"),
        },
        Some("deny") => match (next_arg(args), next_arg(args)) {
            (Some(id), Some(reason)) => task_deny(&id, &reason),
            _ => usage("axon task deny <task-id> <reason>"),
        },
        Some("deliver") => match next_arg(args) {
            Some(id) => task_deliver(&id),
            None => usage("axon task deliver <task-id>"),
        },
        Some("send") => match next_arg(args) {
            Some(path) => task_send(&path),
            None => usage("axon task send <spec.json>"),
        },
        Some("sent") => task_sent(),
        Some("outcomes") => task_outcomes(),
        _ => usage(
            "axon task {inbox|show <id>|approve <id>|deny <id> <reason>|run <id>|deliver <id>|send <spec>|sent|outcomes}",
        ),
    }
}

/// Tasks this daemon sent as requester (`axon task sent`).
fn task_sent() -> ExitCode {
    let result = match call(&ControlRequest::TaskSent) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let sent = result["sent"].as_array().cloned().unwrap_or_default();
    if sent.is_empty() {
        println!("no sent tasks.");
        return ExitCode::SUCCESS;
    }
    println!("sent tasks ({}):", sent.len());
    for s in &sent {
        println!(
            "  {}  → {}  contract {}",
            s["task_id"].as_str().unwrap_or("?"),
            s["performer"].as_str().unwrap_or("?"),
            s["contract_id"].as_str().unwrap_or("?"),
        );
    }
    ExitCode::SUCCESS
}

/// Recorded requester outcomes (`axon task outcomes`).
fn task_outcomes() -> ExitCode {
    let result = match call(&ControlRequest::TaskOutcomes) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let outcomes = result["outcomes"].as_array().cloned().unwrap_or_default();
    if outcomes.is_empty() {
        println!("no recorded outcomes.");
        return ExitCode::SUCCESS;
    }
    println!("outcomes ({}):", outcomes.len());
    for o in &outcomes {
        println!(
            "  {}  [{}]  bundle {}",
            o["task_id"].as_str().unwrap_or("?"),
            o["state"].as_str().unwrap_or("?"),
            o["bundle_digest"].as_str().unwrap_or("?"),
        );
    }
    ExitCode::SUCCESS
}

/// Send a task to a performer from a JSON spec file (`axon task send`).
fn task_send(spec_path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(spec_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("axon: cannot read {spec_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let spec: TaskSpec = match serde_json::from_str(&text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("axon: {spec_path} is not a valid task spec: {e}");
            return ExitCode::from(2);
        }
    };
    let result = match call(&ControlRequest::TaskSend(spec)) {
        Ok(r) => r,
        Err(code) => return code,
    };
    println!(
        "sent to {}: task {}",
        result["performer"].as_str().unwrap_or("?"),
        result["task_id"].as_str().unwrap_or("?"),
    );
    ExitCode::SUCCESS
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
fn task_approve(task_id: &str, processor: Option<&str>, artifacts: bool) -> ExitCode {
    let result = match call(&ControlRequest::TaskApprove {
        task_id: task_id.to_owned(),
        processor: processor.map(str::to_owned),
        artifacts,
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

/// Run an approved Task's worker in the sandbox and submit its result
/// (`axon task run`).
fn task_run(task_id: &str) -> ExitCode {
    let result = match call(&ControlRequest::TaskRun {
        task_id: task_id.to_owned(),
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    println!("ran {task_id}");
    println!(
        "  response:   {} B",
        result["response_bytes"].as_u64().unwrap_or(0)
    );
    println!(
        "  bundle:     {}",
        result["result"]["bundle_digest"].as_str().unwrap_or("?")
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

/// Prints this daemon's own identity and endpoint fingerprint (`axon whoami`) —
/// what an operator shares with a peer to establish trust, and checks their own
/// configuration against.
fn whoami() -> ExitCode {
    let result = match call(&ControlRequest::WhoAmI) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let s = |k: &str| result[k].as_str().unwrap_or("—").to_owned();
    println!("axon identity");
    println!("  agent:        {}/{}", s("issuer"), s("agent"));
    println!("  interface:    {}", s("interface_url"));
    println!("  receive:      {}", s("receive_addr"));
    println!("  pairing:      {}", s("pair_addr"));
    println!("  endpoint fp:  sha256:{}", s("endpoint_fingerprint"));
    println!("  data dir:     {}", s("data_dir"));
    ExitCode::SUCCESS
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
