//! The Akson operator CLI.
//!
//! A hand-rolled argument match over the daemon's admin control socket (§16.2), so
//! no CLI-framework decision is pre-empted:
//!
//! - `akson doctor` — host capability check, no daemon needed (§13.1/§17.3).
//! - `akson status` — daemon health over the admin socket (§16.2).
//! - `akson whoami` — this daemon's identity + endpoint fingerprint (§8.1).
//! - `akson task inbox` — the submitted Tasks awaiting a decision (§16.4).
//! - `akson task show <id>` — a Task's §5.2 risk card, the approval surface.
//! - `akson task approve <id> [--processor <id>]` — accept the Task and issue its
//!   work order; `--processor` additionally grants processor_use for a model (§12.1).
//! - `akson task run <id>` — run the approved Task's worker in the sandbox (§7.2/§13.1).
//! - `akson task deny <id> <reason>` — sign a reject decision (§10.2).
//! - `akson task deliver <id>` — deliver a completed Task's result to the requester (§7.2).
//! - `akson task send <spec.json>` — send a task to a performer (§10.2).
//! - `akson processor {add|list|credential}` — configure processors + credentials (§13.1/§15.2).
//! - `akson peer list` — the paired peers (§16.4).
//! - `akson peer confirm <agent>` — promote a pending peer to active (§8.2).
//! - `akson pair invite <out-file>` — mint a pairing invitation (§8.2).
//! - `akson pair accept <invitation-file>` — accept a pairing invitation (§8.2).

use std::ffi::{OsStr, OsString};
use std::process::ExitCode;

use akson_sandbox::{all_required_available, diagnose, Diagnostic};
use aksond::{
    admin_socket_path, send_request, ControlRequest, ControlResponse, FulfillOutput, TaskSpec,
};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("doctor") => doctor(),
        Some("status") => status(),
        Some("whoami") => whoami(),
        Some("token") => token(),
        Some("task") => task(&mut args),
        Some("processor") => processor(&mut args),
        Some("peer") => peer(&mut args),
        Some("pair") => pair(&mut args),
        _ => {
            eprintln!("akson: commands: doctor, status, whoami, token, task {{…}}, processor {{…}}, peer {{add|list|label|remove|knocks|ping|confirm|auto-approve}}, pair {{invite|accept}}");
            ExitCode::from(2)
        }
    }
}

/// This endpoint's identity token (`akson token`, design §8.2 step 1): the
/// public line to hand a peer over any channel whose integrity you trust.
fn token() -> ExitCode {
    let result = match call(&ControlRequest::Token) {
        Ok(r) => r,
        Err(code) => return code,
    };
    println!(
        "  identity token (public — hand this to whoever you want to work with):\n"
    );
    println!("  {}\n", result["presentation"].as_str().unwrap_or("?"));
    println!(
        "  root key  {}   (full thumbprint; compare over a second channel if unsure)",
        result["root_thumbprint"].as_str().unwrap_or("?"),
    );
    println!("  they import it with:  akson peer add <that-line> <a-label-they-choose>");
    ExitCode::SUCCESS
}

/// Routes the `akson pair …` subcommands over the admin control socket (§8.2).
fn pair(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("invite") => match next_arg(args) {
            Some(out) => pair_invite(&out),
            None => usage("akson pair invite <out-file>"),
        },
        Some("accept") => match next_arg(args) {
            Some(file) => pair_accept(&file),
            None => usage("akson pair accept <invitation-file>"),
        },
        _ => usage("akson pair {invite <out-file>|accept <invitation-file>}"),
    }
}

/// Mint a pairing invitation and write it to a file (`akson pair invite <out>`).
fn pair_invite(out_file: &str) -> ExitCode {
    let result = match call(&ControlRequest::PairInvite) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let invitation = match serde_json::to_string_pretty(&result["invitation"]) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("akson: the daemon returned a malformed invitation");
            return ExitCode::from(1);
        }
    };
    // The invitation carries a bearer secret — write it owner-only.
    if let Err(e) = write_owner_only(out_file, invitation.as_bytes()) {
        eprintln!("akson: cannot write {out_file}: {e}");
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

/// Accept a pairing invitation from a file (`akson pair accept <file>`).
fn pair_accept(invitation_file: &str) -> ExitCode {
    let invitation = match std::fs::read_to_string(invitation_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("akson: cannot read {invitation_file}: {e}");
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

/// Routes the `akson peer …` subcommands over the admin control socket (§16.4).
fn peer(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("list") => peer_list(),
        Some("add") => {
            // akson peer add <token[@host:port]> <label> [--endpoint host:port] [--update]
            let (Some(token), Some(label)) = (next_arg(args), next_arg(args)) else {
                return usage("akson peer add <token[@host:port]> <label> [--endpoint host:port] [--update]");
            };
            let mut endpoint = None;
            let mut update = false;
            while let Some(flag) = next_arg(args) {
                match flag.as_str() {
                    "--endpoint" => endpoint = next_arg(args),
                    "--update" => update = true,
                    _ => {}
                }
            }
            peer_add(&token, &label, endpoint, update)
        }
        Some("label") => match (next_arg(args), next_arg(args)) {
            (Some(old), Some(new)) => peer_label(&old, &new),
            _ => usage("akson peer label <old-label> <new-label>"),
        },
        Some("remove") => match next_arg(args) {
            Some(label) => peer_remove(&label),
            None => usage("akson peer remove <label>"),
        },
        Some("knocks") => peer_knocks(),
        Some("ping") => match next_arg(args) {
            Some(label) => peer_ping(&label),
            None => usage("akson peer ping <label>"),
        },
        Some("confirm") => match next_arg(args) {
            Some(agent) => peer_confirm(&agent),
            None => usage("akson peer confirm <agent-id>"),
        },
        Some("auto-approve") => {
            // akson peer auto-approve <agent> --task-type <t> [--task-type <t>]… [--max-bytes N]
            // akson peer auto-approve <agent> --off
            let Some(agent) = next_arg(args) else {
                return usage(
                    "akson peer auto-approve <agent> --task-type <t> [--max-bytes N] | --off",
                );
            };
            let mut task_types = Vec::new();
            let mut max_bytes: u64 = 8192;
            let mut off = false;
            while let Some(flag) = next_arg(args) {
                match flag.as_str() {
                    "--task-type" => {
                        if let Some(t) = next_arg(args) {
                            task_types.push(t);
                        }
                    }
                    "--max-bytes" => {
                        if let Some(n) = next_arg(args).and_then(|s| s.parse().ok()) {
                            max_bytes = n;
                        }
                    }
                    "--off" => off = true,
                    _ => {}
                }
            }
            if !off && task_types.is_empty() {
                return usage(
                    "akson peer auto-approve <agent> --task-type <t> [--max-bytes N] | --off",
                );
            }
            peer_auto_approve(&agent, if off { Vec::new() } else { task_types }, max_bytes)
        }
        _ => usage(
            "akson peer {add <token> <label>|list|label <old> <new>|remove <label>|knocks|ping <label>|confirm <agent-id>|auto-approve <agent> …}",
        ),
    }
}

/// Import a peer's identity token under a locally chosen label — the one
/// trust decision of pairing (`akson peer add`, design §8.2 step 3).
fn peer_add(token: &str, label: &str, endpoint: Option<String>, update: bool) -> ExitCode {
    let result = match call(&ControlRequest::PeerAdd {
        token: token.to_owned(),
        label: label.to_owned(),
        endpoint,
        update,
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    println!(
        "imported {label}  root {}",
        result["root_thumbprint"].as_str().unwrap_or("?"),
    );
    match result["endpoint_hint"].as_str() {
        Some(hint) if !hint.is_empty() => {
            println!("the channel opens on first contact (`akson peer ping {label}` or a task send to it)");
            let _ = hint;
        }
        _ => println!(
            "no endpoint hint — add one with `akson peer add <token> {label} --endpoint host:port --update`, or let them dial you"
        ),
    }
    ExitCode::SUCCESS
}

/// Rename a peer's local label (`akson peer label`). Purely local.
fn peer_label(old: &str, new: &str) -> ExitCode {
    match call(&ControlRequest::PeerLabel {
        label: old.to_owned(),
        new_label: new.to_owned(),
    }) {
        Ok(_) => {
            println!("relabeled {old} -> {new}");
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// Remove an imported peer (`akson peer remove`): tombstones the import,
/// advances its epoch, and drops the pinned peer state.
fn peer_remove(label: &str) -> ExitCode {
    match call(&ControlRequest::PeerImportRemove {
        label: label.to_owned(),
    }) {
        Ok(_) => {
            println!("removed {label}; re-adding it later starts a fresh relationship");
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// The knock log (`akson peer knocks`): refused introductions, claims only.
fn peer_knocks() -> ExitCode {
    let result = match call(&ControlRequest::PeerKnocks) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let knocks = result["knocks"].as_array().cloned().unwrap_or_default();
    if knocks.is_empty() {
        println!("no refused introductions recorded.");
        return ExitCode::SUCCESS;
    }
    println!("refused introductions (claims are unauthenticated):");
    for k in &knocks {
        println!(
            "  claimed {}  from {}  [{} x{}]",
            k["claimed_root"].as_str().unwrap_or("?"),
            k["source"].as_str().unwrap_or("?"),
            k["refusal"].as_str().unwrap_or("?"),
            k["count"].as_u64().unwrap_or(0),
        );
    }
    println!("if a peer you added appears here: they still need `akson peer add <your token>`.");
    ExitCode::SUCCESS
}

/// Dial the introduction now (`akson peer ping <label>`).
fn peer_ping(label: &str) -> ExitCode {
    let result = match call(&ControlRequest::PeerPing {
        label: label.to_owned(),
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    println!(
        "introduced {label}: {} ({}/{})",
        result["introduced"].as_str().unwrap_or("?"),
        result["peer"]["issuer"].as_str().unwrap_or("?"),
        result["peer"]["agent"].as_str().unwrap_or("?"),
    );
    ExitCode::SUCCESS
}

/// Set or clear a peer's standing auto-approval policy (`akson peer auto-approve`).
fn peer_auto_approve(agent_id: &str, task_types: Vec<String>, max_response_bytes: u64) -> ExitCode {
    let result = match call(&ControlRequest::PeerAutoApprove {
        agent_id: agent_id.to_owned(),
        task_types: task_types.clone(),
        max_response_bytes,
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    if result["auto_approve"] == "off" {
        println!("auto-approve off for {agent_id}");
    } else {
        println!(
            "auto-approve on for {agent_id}: task types [{}], up to {max_response_bytes} B, no processor/artifacts",
            task_types.join(", ")
        );
    }
    ExitCode::SUCCESS
}

/// Confirm a pending peer (`akson peer confirm <agent>`).
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

/// The paired peers (`akson peer list`).
fn peer_list() -> ExitCode {
    let result = match call(&ControlRequest::PeerList) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let imports = result["imports"].as_array().cloned().unwrap_or_default();
    let peers = result["peers"].as_array().cloned().unwrap_or_default();
    if imports.is_empty() && peers.is_empty() {
        println!("no peers. exchange identity tokens and `akson peer add <token> <label>`.");
        return ExitCode::SUCCESS;
    }
    if !imports.is_empty() {
        println!("peers ({}):", imports.len());
        for i in &imports {
            let claims = i["claims"]
                .as_str()
                .map(|c| format!("  claims {c}"))
                .unwrap_or_default();
            println!(
                "  {}  [{}]  {}{}",
                i["label"].as_str().unwrap_or("?"),
                i["status"].as_str().unwrap_or("?"),
                i["endpoint_hint"].as_str().unwrap_or(""),
                claims,
            );
        }
    }
    if !peers.is_empty() {
        println!("invitation-paired peers ({}):", peers.len());
        for p in &peers {
            println!(
                "  {}  {}  [{}]",
                p["agent_id"].as_str().unwrap_or("?"),
                p["endpoint"].as_str().unwrap_or("?"),
                p["status"].as_str().unwrap_or("?"),
            );
        }
    }
    ExitCode::SUCCESS
}

/// Routes the `akson processor …` subcommands over the admin control socket (§13.1).
fn processor(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("add") => processor_add(args),
        Some("list") => processor_list(),
        Some("credential") => match (next_arg(args), next_arg(args)) {
            (Some(id), Some(cred)) => processor_credential(&id, &cred),
            _ => usage("akson processor credential <id> <credential>"),
        },
        _ => usage("akson processor {add <id> <provider> <host> <port> <pin-sha256>|list|credential <id> <cred>}"),
    }
}

/// Add a pinned processor (`akson processor add <id> <provider> <host> <port> <pin>`).
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
                "akson processor add <id> <provider> <host> <port> <ca|pin-sha256> [--path <path>] [--auth <bearer|none|header>] [--header <name:value>]",
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

/// List configured processors (`akson processor list`).
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

/// Set a processor's credential (`akson processor credential <id> <credential>`).
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

/// Routes the `akson task …` subcommands over the admin control socket (§16.4).
fn task(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("inbox") => task_inbox(),
        Some("show") => match next_arg(args) {
            Some(id) => task_show(&id),
            None => usage("akson task show <task-id>"),
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
            None => usage("akson task approve <task-id> [--processor <processor-id>] [--artifacts]"),
        },
        Some("run") => match next_arg(args) {
            Some(id) => task_run(&id),
            None => usage("akson task run <task-id>"),
        },
        Some("fulfill") | Some("fulfil") => {
            // `akson task fulfill <id> --file <path> [--role response] [--media-type text/plain]`
            // Provide a result this side's own agent produced, instead of running a
            // confined worker. `-` reads the bytes from stdin.
            let Some(id) = next_arg(args) else {
                return usage("akson task fulfill <task-id> --file <path> [--role <role>] [--media-type <mt>]");
            };
            let mut file = None;
            let mut role = "response".to_owned();
            let mut media_type = "text/plain".to_owned();
            while let Some(flag) = next_arg(args) {
                match flag.as_str() {
                    "--file" => file = next_arg(args),
                    "--role" => role = next_arg(args).unwrap_or(role),
                    "--media-type" => media_type = next_arg(args).unwrap_or(media_type),
                    _ => {}
                }
            }
            let Some(file) = file else {
                return usage("akson task fulfill <task-id> --file <path> [--role <role>] [--media-type <mt>]");
            };
            task_fulfill(&id, &file, &role, &media_type)
        }
        Some("deny") => match (next_arg(args), next_arg(args)) {
            (Some(id), Some(reason)) => task_deny(&id, &reason),
            _ => usage("akson task deny <task-id> <reason>"),
        },
        Some("deliver") => match next_arg(args) {
            Some(id) => task_deliver(&id),
            None => usage("akson task deliver <task-id>"),
        },
        Some("send") => match next_arg(args) {
            Some(path) => task_send(&path),
            None => usage("akson task send <spec.json>"),
        },
        Some("sent") => task_sent(),
        Some("outcomes") => task_outcomes(),
        Some("output") => match next_arg(args) {
            Some(id) => {
                // `--role <role>` narrows to one output; with it, the bytes are
                // printed bare so the result can be piped straight into the next
                // step. Without it, every output is listed with its digest.
                let mut role = None;
                while let Some(flag) = next_arg(args) {
                    if flag == "--role" {
                        role = next_arg(args);
                    }
                }
                task_output(&id, role.as_deref())
            }
            None => usage("akson task output <task-id> [--role <role>]"),
        },
        _ => usage(
            "akson task {inbox|show <id>|approve <id>|deny <id> <reason>|run <id>|fulfill <id> --file <path>|deliver <id>|send <spec>|sent|outcomes|output <id>}",
        ),
    }
}

/// Tasks this daemon sent as requester (`akson task sent`).
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

/// Recorded requester outcomes (`akson task outcomes`).
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

/// A task's output payloads (`akson task output`). With `--role`, prints just that
/// output's bytes — the form an agent pipes into whatever it does next. Without,
/// lists every output with its manifest digest.
fn task_output(task_id: &str, role: Option<&str>) -> ExitCode {
    let result = match call(&ControlRequest::TaskOutput {
        task_id: task_id.to_owned(),
        role: role.map(str::to_owned),
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let outputs = result["outputs"].as_array().cloned().unwrap_or_default();
    if outputs.is_empty() {
        eprintln!("akson: no stored outputs for {task_id}");
        return ExitCode::from(1);
    }
    if role.is_some() {
        // Write the exact bytes the manifest digest covers — not a UTF-8 view of
        // them. This is what makes `akson task output ... > file` reproduce the
        // artifact, and what lets `sha256sum` on the result match the digest below.
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        for o in &outputs {
            let Some(bytes) = o["content"].as_str().and_then(decode_base64) else {
                eprintln!("akson: the daemon returned an undecodable output payload");
                return ExitCode::from(1);
            };
            if out.write_all(&bytes).is_err() {
                return ExitCode::from(1);
            }
        }
        return if out.flush().is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    println!("outputs of {task_id} ({}):", outputs.len());
    for o in &outputs {
        println!(
            "  {:<12} {:<24} {} bytes  sha256 {}",
            o["role"].as_str().unwrap_or("?"),
            o["media_type"].as_str().unwrap_or("?"),
            o["byte_length"].as_u64().unwrap_or(0),
            o["sha256"].as_str().unwrap_or("?"),
        );
    }
    ExitCode::SUCCESS
}

/// Send a task to a performer from a JSON spec file (`akson task send`).
fn task_send(spec_path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(spec_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("akson: cannot read {spec_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let spec: TaskSpec = match serde_json::from_str(&text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("akson: {spec_path} is not a valid task spec: {e}");
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

/// The submitted Tasks awaiting a decision (`akson task inbox`).
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

/// Approve a Task: accept it and issue the one-shot work order (`akson task approve`).
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
/// (`akson task run`).
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

/// Fulfil an approved Task with a result this side's own agent produced, instead
/// of running a confined worker (`akson task fulfill`). `file` is `-` for stdin.
fn task_fulfill(task_id: &str, file: &str, role: &str, media_type: &str) -> ExitCode {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use std::io::Read as _;

    let bytes = if file == "-" {
        let mut buf = Vec::new();
        if std::io::stdin().read_to_end(&mut buf).is_err() {
            eprintln!("akson: could not read the result from stdin");
            return ExitCode::from(1);
        }
        buf
    } else {
        match std::fs::read(file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("akson: cannot read {file}: {e}");
                return ExitCode::from(1);
            }
        }
    };
    let result = match call(&ControlRequest::TaskFulfill {
        task_id: task_id.to_owned(),
        outputs: vec![FulfillOutput {
            role: role.to_owned(),
            media_type: media_type.to_owned(),
            content_base64: STANDARD.encode(&bytes),
        }],
    }) {
        Ok(r) => r,
        Err(code) => return code,
    };
    println!("fulfilled {task_id}");
    println!("  output:     {role} ({media_type}), {} B", bytes.len());
    println!(
        "  bundle:     {}",
        result["result"]["bundle_digest"].as_str().unwrap_or("?")
    );
    ExitCode::SUCCESS
}

/// Deny a Task: sign a reject decision (`akson task deny`).
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

/// Deliver a completed Task's result to the requester (`akson task deliver`).
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
            eprintln!("akson: {} ({})", problem.title, problem.status);
            Err(ExitCode::from(1))
        }
        Err(e) => {
            eprintln!(
                "akson: could not reach the daemon at {} ({e}). Is `aksond serve` running?",
                path.display()
            );
            Err(ExitCode::from(1))
        }
    }
}

/// Decodes a base64 output payload from the daemon.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.decode(text).ok()
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
            println!("akson status — daemon at {}", path.display());
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
                "akson status: daemon refused the request ({})",
                problem.title
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!(
                "akson status: could not reach the daemon at {} ({e}). Is `aksond serve` running?",
                path.display()
            );
            ExitCode::from(1)
        }
    }
}

/// Prints this daemon's own identity and endpoint fingerprint (`akson whoami`) —
/// what an operator shares with a peer to establish trust, and checks their own
/// configuration against.
fn whoami() -> ExitCode {
    let result = match call(&ControlRequest::WhoAmI) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let s = |k: &str| result[k].as_str().unwrap_or("—").to_owned();
    println!("akson identity");
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

    println!("akson doctor — sandbox capabilities");
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
