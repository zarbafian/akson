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
//! - `akson token` — this endpoint's identity token (§8.2).
//! - `akson peer add <token> <label>` — import a peer's token, the trust act (§8.2).
//! - `akson peer list` — imported peers under their labels (§16.4).

use std::ffi::{OsStr, OsString};
use std::process::ExitCode;

use akson_sandbox::{all_required_available, diagnose};
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
        Some("mcp") => mcp(&mut args),
        Some("service") => service(&mut args),
        Some("demo") => demo(),
        _ => {
            eprintln!("akson: commands: doctor, status, whoami, token, task {{…}}, processor {{…}}, peer {{add|list|label|remove|knocks|ping|auto-approve}}, mcp install <claude|codex>, service install, demo");
            ExitCode::from(2)
        }
    }
}

/// The sibling binary `name` next to this executable — never a bare or
/// guessed path (issue #5: an empty variable once registered `/akson-mcp`
/// and broke two harnesses; a helper must be incapable of that).
///
/// The resolved path is persisted into harness config or executed directly,
/// so it must be trustworthy: the real containing directory has to be owned
/// by this user (or root) and writable by no one else — otherwise a trusted
/// `/tmp/akson` could point at an attacker-planted `/tmp/aksond` (sec6
/// review). Symlinks are resolved first, so the checked directory is the real
/// one.
fn sibling_binary(name: &str) -> Result<std::path::PathBuf, String> {
    let me = std::env::current_exe().map_err(|e| format!("cannot locate this binary: {e}"))?;
    let dir = me
        .parent()
        .ok_or_else(|| "this binary has no parent directory".to_owned())?;
    let candidate = dir.join(name);
    if !candidate.is_file() {
        return Err(format!(
            "{name} not found next to this binary ({}); build it first: cargo build --release -p {name}",
            dir.display()
        ));
    }
    // Resolve symlinks, then vet the real directory the target lives in.
    let real = candidate
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", candidate.display()))?;
    let real_dir = real
        .parent()
        .ok_or_else(|| "resolved binary has no parent directory".to_owned())?;
    ensure_trusted_dir(real_dir)?;
    Ok(real)
}

/// Refuses a directory that ANY other user can write to (the `/tmp` plant in
/// the finding), or that is not owned by this user or root — the "safe path"
/// check before trusting a binary found inside it (sec6 review). Group-write
/// is deliberately allowed: whether the group is a trust boundary is the
/// operator's own filesystem decision (a private per-user group makes 0775 as
/// safe as 0755), and refusing it would break ordinary group-writable
/// checkouts; world-write is never a defensible choice.
fn ensure_trusted_dir(dir: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(dir).map_err(|e| format!("cannot stat {}: {e}", dir.display()))?;
    let me = aksond::current_uid();
    if md.uid() != me && md.uid() != 0 {
        return Err(format!(
            "{} is owned by uid {}, not you ({me}) or root — refusing to trust a binary there",
            dir.display(),
            md.uid()
        ));
    }
    if md.mode() & 0o002 != 0 {
        return Err(format!(
            "{} is world-writable (mode {:o}) — any user could plant a binary there; \
             build or install into a directory only you can write to",
            dir.display(),
            md.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Escapes a value for a systemd `Environment="KEY=<value>"` line: within the
/// double quotes only `"` and `\` are special. A control character (newline
/// especially) cannot be represented on one line and would let a value inject
/// a fresh unit directive — so those are refused outright (sec6 review).
fn systemd_env_value(value: &str) -> Result<String, String> {
    if value.chars().any(|c| c.is_control()) {
        return Err("environment value contains a control character".to_owned());
    }
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Escapes a value for a systemd command-line token (quoted): reject controls,
/// escape backslash and quote. The whole token is wrapped in `"..."` so a path
/// with spaces stays one argument (sec6 review: an unquoted `/tmp/a b/aksond`
/// would run `/tmp/a`).
fn systemd_quote(value: &str) -> Result<String, String> {
    if value.chars().any(|c| c.is_control()) {
        return Err("command path contains a control character".to_owned());
    }
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// Escapes a value for a TOML basic string (`"..."`): reject controls (which
/// would need `\uXXXX` and are never valid here), escape backslash and quote,
/// so `XDG_RUNTIME_DIR` or a path cannot break out and add a table (sec6
/// review).
fn toml_basic_string(value: &str) -> Result<String, String> {
    if value.chars().any(|c| c.is_control()) {
        return Err("value contains a control character".to_owned());
    }
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// Writes `contents` to `path` with owner-only (`0600`) permissions, via a
/// temp file in the same directory renamed into place — atomic, never a
/// world-readable window, never a partial read by a concurrent reader (sec6
/// review).
fn write_private_atomic(path: &std::path::Path, contents: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = path
        .parent()
        .ok_or_else(|| "target has no parent directory".to_owned())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.tmp{}", file_name(path), std::process::id()));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        f.write_all(contents.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot install {}: {e}", path.display())
    })
}

/// Like [`write_private_atomic`] but keeps the caller's default mode — for a
/// harness config that is the user's own, not a secret store.
fn write_atomic(path: &std::path::Path, contents: &str) -> Result<(), String> {
    use std::io::Write as _;
    let dir = path
        .parent()
        .ok_or_else(|| "target has no parent directory".to_owned())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.tmp{}", file_name(path), std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        f.write_all(contents.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot install {}: {e}", path.display())
    })
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("akson")
        .to_owned()
}

/// `akson mcp install <claude|codex>` — register the MCP server with a
/// harness, with the two sharp edges (issue #5) made impossible: the binary
/// path is absolute and verified to exist, and the daemon-selecting
/// XDG_RUNTIME_DIR travels in the server's environment.
fn mcp(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("install") => match next_arg(args) {
            Some(h) => mcp_install(&h),
            None => usage("akson mcp install <claude|codex>"),
        },
        _ => usage("akson mcp install <claude|codex>"),
    }
}

fn mcp_install(harness: &str) -> ExitCode {
    let bin = match sibling_binary("akson-mcp") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("akson: {e}");
            return ExitCode::from(2);
        }
    };
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
    if runtime_dir.is_empty() {
        eprintln!(
            "akson: XDG_RUNTIME_DIR is not set — the MCP server would not know which daemon to talk to.\nSet it to the SAME value your `aksond serve` uses, then re-run."
        );
        return ExitCode::from(2);
    }
    match harness {
        "claude" => {
            // The documented registration, executed with verified values:
            //   claude mcp add --scope user akson --env XDG_RUNTIME_DIR=… -- <abs>/akson-mcp
            let status = std::process::Command::new("claude")
                .args([
                    "mcp",
                    "add",
                    "--scope",
                    "user",
                    "akson",
                    "--env",
                    &format!("XDG_RUNTIME_DIR={runtime_dir}"),
                    "--",
                ])
                .arg(&bin)
                .status();
            match status {
                Ok(st) if st.success() => {
                    println!("registered akson with Claude Code (user scope)");
                    println!("  server:  {}", bin.display());
                    println!("  runtime: {runtime_dir}");
                    println!("keep akson_approve/akson_fulfill/akson_deliver/akson_send OFF any auto-allow list — that prompt is the trust decision.");
                    ExitCode::SUCCESS
                }
                Ok(st) => {
                    eprintln!("akson: `claude mcp add` exited with {st}");
                    ExitCode::from(1)
                }
                Err(_) => {
                    eprintln!(
                        "akson: the `claude` CLI is not on PATH. Run this yourself:\n\n  claude mcp add --scope user akson --env XDG_RUNTIME_DIR={runtime_dir} -- {}\n",
                        bin.display()
                    );
                    ExitCode::from(1)
                }
            }
        }
        "codex" => {
            let home = match std::env::var("HOME") {
                Ok(h) if !h.is_empty() => h,
                _ => {
                    eprintln!("akson: HOME is not set");
                    return ExitCode::from(2);
                }
            };
            let config = std::path::Path::new(&home).join(".codex/config.toml");
            // A read failure must NOT silently become an empty file we then
            // overwrite (sec6 review): only a genuinely absent file is empty.
            let existing = match std::fs::read_to_string(&config) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => {
                    eprintln!("akson: cannot read {} ({e}); leaving it untouched", config.display());
                    return ExitCode::from(2);
                }
            };
            // Best-effort guard against an obvious double-install. Not a TOML
            // parser — if the table is written unusually we may miss it; the
            // user then edits by hand (the message says where).
            if existing.contains("[mcp_servers.akson]") {
                println!(
                    "akson already appears in {} — edit it there if the path or runtime dir changed.",
                    config.display()
                );
                return ExitCode::SUCCESS;
            }
            // Escape both interpolated values so neither the runtime dir nor
            // the binary path can break out of its TOML string and add a table
            // (sec6 review).
            let (cmd_toml, rt_toml) = match (
                toml_basic_string(&bin.display().to_string()),
                toml_basic_string(&runtime_dir),
            ) {
                (Ok(c), Ok(r)) => (c, r),
                _ => {
                    eprintln!("akson: the binary path or XDG_RUNTIME_DIR contains a control character");
                    return ExitCode::from(2);
                }
            };
            let block = format!(
                "\n[mcp_servers.akson]\ncommand = {cmd_toml}\nenv = {{ XDG_RUNTIME_DIR = {rt_toml} }}\n",
            );
            // Atomic replace (temp + rename): no partial read, no lost content
            // window. Config keeps the user's own mode via the normal umask.
            if let Err(e) = write_atomic(&config, &(existing + &block)) {
                eprintln!("akson: {e}");
                return ExitCode::from(2);
            }
            println!("registered akson in {}", config.display());
            println!("  server:  {}", bin.display());
            println!("  runtime: {runtime_dir}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("akson: unknown harness {other:?}; expected claude or codex");
            ExitCode::from(2)
        }
    }
}

/// `akson service install [--now]` — a supervised systemd *user* service for
/// `aksond serve`, with the delegated cgroup the sandbox needs (issue #5:
/// the daemon should not be babysat in a terminal).
fn service(args: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some("install") => {
            let rest: Vec<String> = args.filter_map(|a| a.into_string().ok()).collect();
            let mut now = false;
            let mut system = false;
            let mut user: Option<String> = None;
            let mut it = rest.into_iter();
            while let Some(flag) = it.next() {
                match flag.as_str() {
                    "--now" => now = true,
                    "--system" => system = true,
                    "--user" => user = it.next(),
                    other => {
                        eprintln!("akson: unknown flag {other}");
                        return usage("akson service install [--system [--user <name>]] [--now]");
                    }
                }
            }
            if system {
                service_install_system(user)
            } else {
                service_install_user(now)
            }
        }
        _ => usage("akson service install [--system [--user <name>]] [--now]"),
    }
}

/// `sudo akson service install --system [--user <name>]` — the one-command,
/// always-on path: a *system* unit for `aksond serve` that survives reboot with
/// no linger. Runs as the operator's user (so the CLI, same uid, reaches it) on
/// a stable `/run/akson` socket, with the delegated cgroup the sandbox needs.
fn service_install_system(user: Option<String>) -> ExitCode {
    if aksond::current_uid() != 0 {
        eprintln!("akson: --system needs root — run: sudo akson service install --system");
        return ExitCode::from(2);
    }
    // Who the daemon runs as: an explicit --user, else the sudo invoker. Never
    // root (the daemon must run under a normal uid the operator's CLI shares).
    let target = user
        .or_else(|| std::env::var("SUDO_USER").ok())
        .filter(|u| !u.is_empty() && u != "root");
    let target = match target {
        Some(u) => u,
        None => {
            eprintln!("akson: could not tell which user to run as — invoke via sudo, or pass --user <name>");
            return ExitCode::from(2);
        }
    };
    if target.len() > 32 || !target.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        eprintln!("akson: --user must be a plain system user name");
        return ExitCode::from(2);
    }
    // A system service must run a root-owned binary: the unit is root-managed,
    // so pointing ExecStart at a build tree the operator's (non-root) user can
    // overwrite would hand that user control of a root-installed service. So we
    // *install* aksond into /usr/local/bin (root-owned) and run it from there —
    // also the conventional home for a system daemon. The source is the aksond
    // beside this CLI; root already executed this CLI from that tree under sudo,
    // so trusting its sibling is the same trust the operator just exercised.
    let src = match std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("aksond"))) {
        Some(p) if p.is_file() => p,
        _ => {
            eprintln!("akson: could not find aksond next to this CLI — build it: cargo build --release -p aksond");
            return ExitCode::from(2);
        }
    };
    let dst = std::path::Path::new("/usr/local/bin/aksond");
    let staged = std::path::Path::new("/usr/local/bin/.aksond.new");
    let install_bin = || -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::copy(&src, staged)?;
        std::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(staged, dst)
    };
    if let Err(e) = install_bin() {
        let _ = std::fs::remove_file(staged);
        eprintln!("akson: could not install {} ({e})", dst.display());
        return ExitCode::from(2);
    }
    println!("installed {} -> {}", src.display(), dst.display());
    let exec = match systemd_quote(&dst.display().to_string()) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("akson: the daemon path is not usable in a unit file ({e})");
            return ExitCode::from(2);
        }
    };
    // Carry only AKSON_* explicitly present (e.g. under `sudo -E`); the system
    // service otherwise relies on zero-env defaults under the target user's home.
    let mut env_lines = String::new();
    for key in [
        "AKSON_DATA_DIR",
        "AKSON_ISSUER",
        "AKSON_AGENT",
        "AKSON_INTERFACE_URL",
        "AKSON_RECEIVE_ADDR",
        "AKSON_WORKER_CMD",
        "AKSON_WORKER_EXEC",
        "AKSON_ON_TASK",
    ] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                match systemd_env_value(&v) {
                    Ok(escaped) => {
                        env_lines.push_str(&format!("Environment=\"{key}={escaped}\"\n"))
                    }
                    Err(e) => {
                        eprintln!("akson: {key} cannot go in a unit file ({e})");
                        return ExitCode::from(2);
                    }
                }
            }
        }
    }
    // RuntimeDirectory=akson creates /run/akson (0700, owned by the service
    // user); AKSON_RUNTIME_DIR points the daemon at it so the operator's CLI
    // finds the socket there (resolve_admin_socket fallback). WantedBy
    // multi-user.target + no linger = comes back on boot on a headless box.
    let unit = format!(
        "[Unit]\nDescription=Akson daemon — signed task exchange between sovereign agents\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nUser={target}\nRuntimeDirectory=akson\nRuntimeDirectoryMode=0700\nEnvironment=AKSON_RUNTIME_DIR=/run/akson\n# The sandbox needs a delegated cgroup subtree (memory + pids controllers).\nDelegate=yes\n{env_lines}ExecStart={exec} serve\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n",
    );
    let unit_path = std::path::Path::new("/etc/systemd/system/akson.service");
    if let Err(e) = write_private_atomic(unit_path, &unit) {
        eprintln!("akson: {e}");
        return ExitCode::from(2);
    }
    println!("wrote {} (User={target})", unit_path.display());
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
    match std::process::Command::new("systemctl")
        .args(["enable", "--now", "akson.service"])
        .status()
    {
        Ok(st) if st.success() => println!("akson.service enabled and started — survives reboot"),
        _ => {
            eprintln!("akson: could not enable the service; run: sudo systemctl enable --now akson.service");
            return ExitCode::from(1);
        }
    }
    println!("watch it with:  sudo journalctl -u akson -f");
    ExitCode::SUCCESS
}

fn service_install_user(start_now: bool) -> ExitCode {
    let bin = match sibling_binary("aksond") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("akson: {e}");
            return ExitCode::from(2);
        }
    };
    let home = match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => h,
        _ => {
            eprintln!("akson: HOME is not set");
            return ExitCode::from(2);
        }
    };
    // Carry the caller's akson environment into the unit, so the service runs
    // the SAME daemon the operator configured in this shell. Each value is
    // escaped for `Environment="KEY=<v>"`, and a control character is refused
    // outright — an unescaped newline would inject a fresh unit directive
    // (e.g. an ExecStartPre= that runs UNSANDBOXED as this user; sec6 review).
    let mut env_lines = String::new();
    for key in [
        "AKSON_DATA_DIR",
        "AKSON_ISSUER",
        "AKSON_AGENT",
        "AKSON_INTERFACE_URL",
        "AKSON_RECEIVE_ADDR",
        "AKSON_WORKER_CMD",
        "AKSON_WORKER_EXEC",
        "AKSON_ON_TASK",
        "XDG_RUNTIME_DIR",
    ] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                match systemd_env_value(&v) {
                    Ok(escaped) => {
                        env_lines.push_str(&format!("Environment=\"{key}={escaped}\"\n"))
                    }
                    Err(e) => {
                        eprintln!("akson: {key} cannot go in a unit file ({e}); unset it or set it inside the unit by hand");
                        return ExitCode::from(2);
                    }
                }
            }
        }
    }
    // The ExecStart path is quoted so a directory with spaces stays one
    // argument (sec6 review: unquoted `/tmp/a b/aksond` runs `/tmp/a`).
    let exec = match systemd_quote(&bin.display().to_string()) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("akson: the daemon path is not usable in a unit file ({e})");
            return ExitCode::from(2);
        }
    };
    let unit = format!(
        "[Unit]\nDescription=Akson daemon — signed task exchange between sovereign agents\nAfter=network-online.target\n\n[Service]\n# The sandbox needs a delegated cgroup subtree (memory + pids controllers).\nDelegate=yes\n{env_lines}ExecStart={exec} serve\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
    );
    let unit_dir = std::path::Path::new(&home).join(".config/systemd/user");
    let unit_path = unit_dir.join("akson.service");
    // Owner-only: the unit can carry secrets (an API key inside
    // AKSON_WORKER_CMD, a webhook in AKSON_ON_TASK), so it must not be
    // world-readable on a traversable home (sec6 review).
    if let Err(e) = write_private_atomic(&unit_path, &unit) {
        eprintln!("akson: {e}");
        return ExitCode::from(2);
    }
    println!("wrote {} (mode 0600)", unit_path.display());
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    if start_now {
        match std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "akson.service"])
            .status()
        {
            Ok(st) if st.success() => println!("akson.service enabled and started"),
            _ => {
                eprintln!("akson: could not enable the service; run: systemctl --user enable --now akson.service");
                return ExitCode::from(1);
            }
        }
    } else {
        println!("enable it with:  systemctl --user enable --now akson.service");
    }
    println!("survive logout with:  sudo loginctl enable-linger $USER");
    println!("watch it with:        journalctl --user -u akson -f");
    ExitCode::SUCCESS
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
        Some("auto-approve") => {
            // akson peer auto-approve <label> --task-type <t> [--task-type <t>]… [--max-bytes N]
            // akson peer auto-approve <label> --off
            let Some(agent) = next_arg(args) else {
                return usage(
                    "akson peer auto-approve <label> --task-type <t> [--max-bytes N] | --off",
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
                    "akson peer auto-approve <label> --task-type <t> [--max-bytes N] | --off",
                );
            }
            peer_auto_approve(&agent, if off { Vec::new() } else { task_types }, max_bytes)
        }
        _ => usage(
            "akson peer {add <token> <label>|list|label <old> <new>|remove <label>|knocks|ping <label>|auto-approve <agent> …}",
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
        println!("established peers ({}):", peers.len());
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
        println!("{sentence}");
        if let Some(label) = result["requester_label"].as_str() {
            println!("Your label for this requester: {label}");
        }
        println!();
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

/// The stable rendezvous the `--system` service unit binds
/// (`AKSON_RUNTIME_DIR=/run/akson`, created by `RuntimeDirectory=`).
const SYSTEM_SOCKET_DIR: &str = "/run/akson";

/// The admin socket to connect to. Honors the operator's own runtime dir first
/// (`admin_socket_path()` already consults `$AKSON_RUNTIME_DIR`/`$XDG_RUNTIME_DIR`);
/// if nothing is *listening* there, falls back to the system-service path so
/// `akson …` reaches a `--system` daemon with no env var to set. Probes by
/// attempting a connection rather than testing file existence — a dead daemon
/// can leave a stale socket file behind, and that must not shadow a live one.
/// Returns the per-user path when neither answers, so the "is `aksond serve`
/// running?" error names it.
fn resolve_admin_socket() -> std::path::PathBuf {
    use std::os::unix::net::UnixStream;
    let primary = admin_socket_path();
    let system = std::path::Path::new(SYSTEM_SOCKET_DIR).join("admin.sock");
    for cand in [&primary, &system] {
        if UnixStream::connect(cand).is_ok() {
            return cand.clone();
        }
    }
    primary
}

/// Sends one admin control request, returning its result value or an exit code
/// after printing a uniform error (a daemon refusal, or an unreachable daemon).
fn call(req: &ControlRequest) -> Result<serde_json::Value, ExitCode> {
    let path = resolve_admin_socket();
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
    let path = resolve_admin_socket();
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
/// One capability line for `akson doctor`, from either source — the running
/// daemon's self-report or a local probe.
struct Cap {
    feature: String,
    available: bool,
    required: bool,
    detail: String,
}

fn doctor() -> ExitCode {
    // Prefer the running daemon's own probe: it sees its real cgroup context (a
    // system service has a delegated cgroup, a plain login shell does not), so
    // `cgroup_delegation` reflects what will actually confine a worker. Fall back
    // to a local probe only when no daemon answers (e.g. a pre-install host check).
    let (source, caps, ready) = match daemon_diagnose() {
        Some((caps, ready)) => ("the running daemon", caps, ready),
        None => {
            let report = diagnose();
            let ready = all_required_available(&report);
            let caps = report
                .iter()
                .map(|d| Cap {
                    feature: d.feature.to_owned(),
                    available: d.available,
                    required: d.required,
                    detail: d.detail.clone(),
                })
                .collect::<Vec<_>>();
            ("this shell (no daemon reachable)", caps, ready)
        }
    };

    let width = caps.iter().map(|c| c.feature.len()).max().unwrap_or(0);
    println!("akson doctor — sandbox capabilities, as seen by {source}");
    for c in &caps {
        println!("  {:>width$}  {}", c.feature, cap_line(c), width = width);
    }

    if ready {
        println!("\nready: every required capability is available.");
        ExitCode::SUCCESS
    } else {
        let missing: Vec<&str> = caps
            .iter()
            .filter(|c| c.required && !c.available)
            .map(|c| c.feature.as_str())
            .collect();
        eprintln!(
            "\nNOT READY: the clean worker cannot launch — missing {}.",
            missing.join(", ")
        );
        ExitCode::from(1)
    }
}

/// Ask the running daemon for its own sandbox capabilities — it probes the
/// cgroup context it actually runs in. `None` if unreachable or the reply has no
/// capability array (an older daemon), so the caller falls back to a local probe.
fn daemon_diagnose() -> Option<(Vec<Cap>, bool)> {
    let result = match send_request(&resolve_admin_socket(), &ControlRequest::Diagnose) {
        Ok(ControlResponse::Ok { result }) => result,
        _ => return None,
    };
    let caps = result
        .get("capabilities")?
        .as_array()?
        .iter()
        .map(|c| Cap {
            feature: c["feature"].as_str().unwrap_or("?").to_owned(),
            available: c["available"].as_bool().unwrap_or(false),
            required: c["required"].as_bool().unwrap_or(false),
            detail: c["detail"].as_str().unwrap_or("").to_owned(),
        })
        .collect();
    let ready = result
        .get("sandbox_ready")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some((caps, ready))
}

/// One capability's status column: `ok` / `MISSING` / `n/a`, an `(optional)` tag
/// for non-required capabilities, and the human-readable detail.
fn cap_line(c: &Cap) -> String {
    let mark = match (c.available, c.required) {
        (true, _) => "ok",
        (false, true) => "MISSING",
        (false, false) => "n/a",
    };
    let optional = if c.required { "" } else { " (optional)" };
    if c.detail.is_empty() {
        format!("{mark:<8}{optional}")
    } else {
        format!("{mark:<8}{optional} — {}", c.detail)
    }
}

// ---------------------------------------------------------------------------
// `akson demo` — the whole §5.1 loop on one machine, narrated (issue #5:
// "two daemons and several terminals reads as complicated"). Two throwaway
// daemons pair over identity tokens, exchange a signed task, and the verified
// bytes come back — then everything is cleaned up.

/// Removes the whole demo workspace when the run ends. Declared before the
/// daemons in `run_demo`, so it drops LAST — after each child is killed.
struct WorkspaceGuard(std::path::PathBuf);

impl Drop for WorkspaceGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A spawned daemon that is killed when the demo ends (its files live under
/// the run's [`WorkspaceGuard`], removed there).
struct DemoDaemon {
    child: std::process::Child,
    runtime_dir: std::path::PathBuf,
}

impl Drop for DemoDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DemoDaemon {
    fn socket(&self) -> std::path::PathBuf {
        self.runtime_dir.join("akson/admin.sock")
    }

    fn call(&self, req: &ControlRequest) -> Result<serde_json::Value, String> {
        match send_request(&self.socket(), req) {
            Ok(ControlResponse::Ok { result }) => Ok(result),
            Ok(ControlResponse::Problem { problem }) => {
                Err(format!("{} ({})", problem.title, problem.status))
            }
            Err(e) => Err(format!("daemon unreachable: {e}")),
        }
    }
}

/// A loopback port the OS just told us is free. There is a race between this
/// probe and the daemon binding it; the daemon's receive bind is fatal
/// (`aksond` exits if the port is taken), so a lost race surfaces as the
/// readiness check timing out, never a silent misconnect (sec6 review).
fn free_loopback_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("cannot find a free port: {e}"))?;
    l.local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("cannot read the bound port: {e}"))
}

fn spawn_demo_daemon(
    aksond: &std::path::Path,
    base: &std::path::Path,
    name: &str,
    port: u16,
    worker: Option<&str>,
) -> Result<DemoDaemon, String> {
    // Per-daemon subdir under the run's random base (created exclusively in
    // run_demo), so nothing an attacker could pre-create is trusted, and the
    // demo never adopts a planted admin.sock (sec6 review).
    let runtime_dir = base.join(format!("{name}/run"));
    let data_dir = base.join(format!("{name}/data"));
    std::fs::create_dir_all(&runtime_dir).map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new(aksond);
    cmd.arg("serve")
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env("AKSON_DATA_DIR", &data_dir)
        .env("AKSON_ISSUER", "demo")
        .env("AKSON_AGENT", name)
        .env("AKSON_RECEIVE_ADDR", format!("127.0.0.1:{port}"))
        .env_remove("AKSON_INTERFACE_URL")
        .env_remove("AKSON_WORKER_CMD")
        .env_remove("AKSON_WORKER_EXEC")
        .env_remove("AKSON_ON_TASK")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(w) = worker {
        cmd.env("AKSON_WORKER_CMD", w);
    }
    let child = cmd.spawn().map_err(|e| format!("cannot start aksond: {e}"))?;
    let mut daemon = DemoDaemon { child, runtime_dir };
    // Wait for the admin socket to answer — but stop early if the daemon
    // exited (e.g. its receive port was squatted; the bind is fatal, sec6
    // review), rather than waiting the full timeout on a dead process.
    for _ in 0..100 {
        if daemon.call(&ControlRequest::WhoAmI).is_ok() {
            return Ok(daemon);
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            return Err(format!(
                "the {name} daemon exited before it was ready ({status}) — is its port free?"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("the daemon did not come up within 10s".to_owned())
}

fn demo() -> ExitCode {
    match run_demo() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("akson demo: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_demo() -> Result<(), String> {
    let aksond = sibling_binary("aksond")?;
    println!("== akson demo: the whole loop, two throwaway daemons on loopback ==\n");

    // One random base per run, created exclusively: a pre-existing directory
    // (an attacker's plant, or a stale run) makes create_dir fail, so the demo
    // never adopts state it did not create (sec6 review). 128 bits of entropy
    // makes a pre-create attack infeasible even in shared /tmp.
    let mut seed = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let run_id: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let base = std::env::temp_dir().join(format!("akson-demo-{run_id}"));
    std::fs::create_dir(&base)
        .map_err(|e| format!("cannot create the demo workspace {}: {e}", base.display()))?;
    // The whole run cleans up when this guard drops.
    let _workspace = WorkspaceGuard(base.clone());

    println!("1. starting bob (the performer; its worker is a shell stand-in)…");
    let bob = spawn_demo_daemon(
        &aksond,
        &base,
        "bob",
        free_loopback_port()?,
        Some(r#"[ -r /inputs/diff ] || exit 40; printf "reviewed: LGTM" > /output/response"#),
    )?;
    println!("   starting alice (the requester)…");
    let alice = spawn_demo_daemon(&aksond, &base, "alice", free_loopback_port()?, None)?;

    println!("\n2. exchanging identity tokens (the out-of-band step, done for you):");
    let bob_token = bob.call(&ControlRequest::Token)?;
    let alice_token = alice.call(&ControlRequest::Token)?;
    let bob_line = bob_token["presentation"].as_str().unwrap_or_default().to_owned();
    let alice_line = alice_token["presentation"].as_str().unwrap_or_default().to_owned();
    println!("   bob's line:   {bob_line}");
    println!("   alice's line: {alice_line}");

    println!("\n3. each operator imports the other's line under a label THEY choose:");
    alice.call(&ControlRequest::PeerAdd {
        token: bob_line,
        label: "bob".to_owned(),
        endpoint: None,
        update: false,
    })?;
    bob.call(&ControlRequest::PeerAdd {
        token: alice_line,
        label: "alice".to_owned(),
        endpoint: None,
        update: false,
    })?;
    println!("   alice: peer add <bob's line> bob      # alice's yes");
    println!("   bob:   peer add <alice's line> alice  # bob's yes");

    println!("\n4. first contact (mutually verified against the imported identities):");
    let ping = alice.call(&ControlRequest::PeerPing {
        label: "bob".to_owned(),
    })?;
    println!("   introduced: {}", ping["introduced"].as_str().unwrap_or("?"));

    println!("\n5. alice sends a code-review task to \"bob\" (her label):");
    let spec = TaskSpec {
        performer: "bob".to_owned(),
        task_type: "https://akson.invalid/task/code-review/v1".to_owned(),
        objective: "Review the supplied diff.".to_owned(),
        inputs: vec![aksond::TaskInput {
            id: "diff".to_owned(),
            media_type: "text/x-diff".to_owned(),
            text: "--- a\n+++ b\n".to_owned(),
        }],
        deliverables: vec![aksond::Deliverable {
            role: "response".to_owned(),
            media_type: "text/plain".to_owned(),
        }],
        capabilities: vec!["respond".to_owned(), "read_supplied_inputs".to_owned()],
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        max_response_bytes: 8192,
    };
    let sent = alice.call(&ControlRequest::TaskSend(spec))?;
    let task_id = sent["task_id"].as_str().unwrap_or_default().to_owned();
    println!("   sent: {task_id}");

    println!("\n6. on bob's side the task sits INERT until a human decides:");
    let card = bob.call(&ControlRequest::TaskShow {
        task_id: task_id.clone(),
    })?;
    println!("   the risk card says:");
    println!("     {}", card["sentence"].as_str().unwrap_or("?").replace('\n', "\n     "));
    if let Some(label) = card["requester_label"].as_str() {
        println!("     (bob's label for this requester: {label})");
    }

    println!("\n7. bob approves (this issues a one-shot work order)…");
    bob.call(&ControlRequest::TaskApprove {
        task_id: task_id.clone(),
        processor: None,
        artifacts: false,
    })?;

    // The work order is ONE-SHOT (a failed attempt is burned, by design), so
    // choose the execution path up front: the sandbox when this host can run
    // it, `task fulfill` — same gates, same signature, no sandbox — when not.
    if all_required_available(&diagnose()) {
        println!("8. bob runs the worker in the sandbox…");
        bob.call(&ControlRequest::TaskRun {
            task_id: task_id.clone(),
        })?;
        println!("   sandboxed run completed (no network, no credentials, only the named input)");
    } else {
        println!("8. this host can't run the sandbox (see `akson doctor`), so bob");
        println!("   fulfils from its own agent instead — still gated and signed:");
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        bob.call(&ControlRequest::TaskFulfill {
            task_id: task_id.clone(),
            outputs: vec![FulfillOutput {
                role: "response".to_owned(),
                media_type: "text/plain".to_owned(),
                content_base64: STANDARD.encode("reviewed: LGTM"),
            }],
        })?;
    }

    println!("9. bob delivers the signed result…");
    bob.call(&ControlRequest::TaskDeliver {
        task_id: task_id.clone(),
    })?;

    println!("\n10. alice reads the verified bytes (they re-hashed to the signed digest):");
    let output = alice.call(&ControlRequest::TaskOutput {
        task_id: task_id.clone(),
        role: Some("response".to_owned()),
    })?;
    let bytes = output["outputs"][0]["content"]
        .as_str()
        .and_then(|b| {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine as _;
            STANDARD.decode(b).ok()
        })
        .unwrap_or_default();
    println!("    → {:?}", String::from_utf8_lossy(&bytes));

    println!("\n== demo complete; both daemons and their state are being cleaned up ==");
    println!("Next: `aksond init` for your real daemon, `akson token` for your real line.");
    Ok(())
}
