//! An MCP server that exposes a local Akson daemon to an agent harness (Claude
//! Code, Codex, …). Each Akson operation is a tool; the harness's own
//! tool-permission prompt is the human's trust decision — so a peer's delegated
//! task is approved, or fulfilled, only when the operator says yes *in the
//! harness*, with the risk card in front of them. Akson stays thin: it carries the
//! delegation and enforces the grant; the human decides, the agent does the work.
//!
//! It speaks the daemon's admin control protocol over the same Unix socket the
//! `akson` CLI uses (`$XDG_RUNTIME_DIR/akson/admin.sock`), so it needs a running
//! `aksond serve` and inherits its authority — run it only where the CLI would.
//!
//! Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout (MCP stdio). Every
//! log line goes to stderr; stdout carries only protocol messages.
//!
//! What you write (register it once with your harness), e.g. Claude Code:
//! ```text
//! claude mcp add akson -- akson-mcp
//! ```
//! Then, in a session: "check my akson inbox" → the agent lists tasks → shows you
//! the risk card → asks to approve → does the work → fulfils and delivers. The
//! read-only tools are safe to allow; keep `akson_approve`/`akson_fulfill`/
//! `akson_deny`/`akson_deliver`/`akson_send` gated so each is a deliberate yes.

use std::io::{BufReader, Read, Write};

use aksond::{admin_socket_path, send_request, ControlRequest, ControlResponse, FulfillOutput};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

/// The MCP protocol versions this server implements. `initialize` echoes the
/// client's version only when it is one of these; otherwise it offers the latest.
const SUPPORTED_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const PROTOCOL_VERSION: &str = SUPPORTED_VERSIONS[0];

/// The largest single JSON-RPC message the server will buffer — bounded so a
/// client cannot make it grow memory without limit on a newline-free stream.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

fn main() {
    let mut reader = BufReader::new(std::io::stdin());
    let mut out = std::io::stdout();
    loop {
        let line = match read_capped_line(&mut reader, MAX_MESSAGE_BYTES) {
            LineRead::Line(bytes) => bytes,
            LineRead::Eof => break,
            LineRead::TooLarge => {
                // Cannot know the id; answer with a JSON-RPC parse error (id null).
                let _ = writeln!(out, "{}", error(None, -32700, "message too large"));
                let _ = out.flush();
                break;
            }
            LineRead::Err => break,
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let msg: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(_) => {
                // Malformed frame → JSON-RPC parse error with a null id (the id is
                // unknowable), so a strict client is not left waiting.
                let _ = writeln!(out, "{}", error(None, -32700, "parse error"));
                let _ = out.flush();
                continue;
            }
        };
        // A message with no `id` is a notification — act on it, never reply.
        let id = msg.get("id").cloned();
        let is_notification = id.is_none();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);

        let response = match method {
            _ if is_notification => None, // notifications get no response
            "initialize" => Some(ok(id, initialize_result(&params))),
            "tools/list" => Some(ok(id, json!({ "tools": tool_specs() }))),
            "tools/call" => Some(ok(id, call_tool(&params))),
            "ping" => Some(ok(id, json!({}))),
            _ => Some(error(id, -32601, "method not found")),
        };
        if let Some(response) = response {
            let _ = writeln!(out, "{response}");
            let _ = out.flush();
        }
    }
}

/// The outcome of reading one newline-terminated message, size-capped.
enum LineRead {
    Line(Vec<u8>),
    Eof,
    TooLarge,
    Err,
}

/// Reads bytes up to the next `\n`, at most `cap` bytes, never growing past it.
fn read_capped_line(reader: &mut impl Read, cap: usize) -> LineRead {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return if buf.is_empty() {
                    LineRead::Eof
                } else {
                    LineRead::Line(buf)
                }
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    return LineRead::Line(buf);
                }
                if buf.len() >= cap {
                    return LineRead::TooLarge;
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return LineRead::Err,
        }
    }
}

fn ok(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn initialize_result(params: &Value) -> Value {
    // Echo the client's protocol version only when we actually implement it;
    // otherwise offer our latest, so the client never believes we agreed to a
    // version we do not support (codex review).
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|v| SUPPORTED_VERSIONS.contains(v))
        .unwrap_or(PROTOCOL_VERSION);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "akson-mcp", "version": env!("CARGO_PKG_VERSION") },
    })
}

/// Runs a `tools/call`, returning an MCP tool result (`content` + `isError`).
fn call_tool(params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    match build_request(name, &args) {
        Ok(req) => match send_request(&admin_socket_path(), &req) {
            Ok(ControlResponse::Ok { result }) => tool_text(&render(name, &result), false),
            Ok(ControlResponse::Problem { problem }) => {
                tool_text(&format!("{} ({})", problem.title, problem.status), true)
            }
            Err(e) => tool_text(
                &format!(
                    "could not reach the daemon at {} ({e}). Is `aksond serve` running?",
                    admin_socket_path().display()
                ),
                true,
            ),
        },
        Err(msg) => tool_text(&msg, true),
    }
}

fn tool_text(text: &str, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

/// A string arg, or `None` if absent/empty.
fn arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// Maps a tool name + arguments to the daemon control request it performs.
fn build_request(name: &str, args: &Value) -> Result<ControlRequest, String> {
    let task_id = || {
        arg(args, "task_id")
            .map(str::to_owned)
            .ok_or_else(|| "task_id is required".to_owned())
    };
    Ok(match name {
        "akson_whoami" => ControlRequest::WhoAmI,
        "akson_inbox" => ControlRequest::TaskInbox,
        "akson_peers" => ControlRequest::PeerList,
        "akson_outcomes" => ControlRequest::TaskOutcomes,
        "akson_task_show" => ControlRequest::TaskShow {
            task_id: task_id()?,
        },
        "akson_output" => ControlRequest::TaskOutput {
            task_id: task_id()?,
            role: arg(args, "role").map(str::to_owned),
        },
        "akson_approve" => ControlRequest::TaskApprove {
            task_id: task_id()?,
            processor: arg(args, "processor").map(str::to_owned),
            artifacts: args
                .get("artifacts")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        "akson_deny" => ControlRequest::TaskDeny {
            task_id: task_id()?,
            reason: arg(args, "reason").unwrap_or("declined").to_owned(),
        },
        "akson_fulfill" => {
            let content = arg(args, "content").ok_or_else(|| "content is required".to_owned())?;
            ControlRequest::TaskFulfill {
                task_id: task_id()?,
                outputs: vec![FulfillOutput {
                    role: arg(args, "role").unwrap_or("response").to_owned(),
                    media_type: arg(args, "media_type").unwrap_or("text/plain").to_owned(),
                    content_base64: STANDARD.encode(content),
                }],
            }
        }
        "akson_deliver" => ControlRequest::TaskDeliver {
            task_id: task_id()?,
        },
        "akson_send" => ControlRequest::TaskSend(build_task_spec(args)?),
        other => return Err(format!("unknown tool: {other}")),
    })
}

fn build_task_spec(args: &Value) -> Result<aksond::TaskSpec, String> {
    use aksond::{Deliverable, TaskInput, TaskSpec};
    let performer = arg(args, "performer").ok_or_else(|| "performer is required".to_owned())?;
    let objective = arg(args, "objective").ok_or_else(|| "objective is required".to_owned())?;
    let inputs = match arg(args, "input_text") {
        Some(text) => vec![TaskInput {
            id: arg(args, "input_id").unwrap_or("context").to_owned(),
            media_type: arg(args, "input_media_type")
                .unwrap_or("text/plain")
                .to_owned(),
            text: text.to_owned(),
        }],
        None => vec![],
    };
    let capabilities = args
        .get("capabilities")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_else(|| vec!["respond".to_owned()]);
    Ok(TaskSpec {
        performer: performer.to_owned(),
        task_type: arg(args, "task_type")
            .unwrap_or("https://akson.cc/task/generic/v1")
            .to_owned(),
        objective: objective.to_owned(),
        inputs,
        deliverables: vec![Deliverable {
            role: arg(args, "deliverable_role")
                .unwrap_or("response")
                .to_owned(),
            media_type: arg(args, "deliverable_media_type")
                .unwrap_or("text/plain")
                .to_owned(),
        }],
        capabilities,
        deadline: arg(args, "deadline")
            .unwrap_or("2030-01-01T00:00:00Z")
            .to_owned(),
        max_response_bytes: args
            .get("max_response_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(512 * 1024),
    })
}

/// Renders a daemon result as human-readable text for the tool response. For a
/// single-role `akson_output` read the payload is decoded so the agent sees the
/// bytes, not base64.
fn render(name: &str, result: &Value) -> String {
    if name == "akson_output" {
        if let Some(outputs) = result.get("outputs").and_then(Value::as_array) {
            if outputs.len() == 1 {
                if let Some(bytes) = outputs[0]
                    .get("content")
                    .and_then(Value::as_str)
                    .and_then(|s| STANDARD.decode(s).ok())
                {
                    if let Ok(text) = String::from_utf8(bytes) {
                        return text;
                    }
                }
            }
        }
    }
    serde_json::to_string_pretty(result).unwrap_or_else(|_| result.to_string())
}

/// The tool catalogue. Read-only tools are safe to allow; the mutating ones —
/// approve, deny, fulfill, deliver, send — are where the harness should ask the
/// operator, so their descriptions say plainly what authority they exercise.
fn tool_specs() -> Value {
    let s = |props: Value, required: Value| json!({ "type": "object", "properties": props, "required": required });
    let task =
        || json!({ "task_id": { "type": "string", "description": "the task id, e.g. task-…" } });
    json!([
        tool("akson_whoami", "This endpoint's identity and certificate fingerprint. Read-only.", s(json!({}), json!([]))),
        tool("akson_inbox", "List delegated tasks awaiting a decision (the performer inbox). Read-only.", s(json!({}), json!([]))),
        tool("akson_peers", "List paired peers and their status. Read-only.", s(json!({}), json!([]))),
        tool("akson_outcomes", "List recorded outcomes for tasks this endpoint sent. Read-only.", s(json!({}), json!([]))),
        tool("akson_task_show", "Show the RISK CARD for an inbox task — exactly what it asks for (who, what leaves, capabilities, limits). Read this to the operator before approving. Read-only.", s(task(), json!(["task_id"]))),
        tool("akson_output", "Read a delivered result's bytes (or list outputs with digests if no role). Read-only.", s(json!({ "task_id": { "type": "string" }, "role": { "type": "string", "description": "one output role, e.g. response; omit to list all" } }), json!(["task_id"]))),
        tool("akson_approve", "APPROVE an inbox task: accept its contract and issue the one-shot work order. This authorises the granted capabilities — confirm with the operator (risk card) first. Optionally grant a named processor and/or artifact export.", s(json!({ "task_id": { "type": "string" }, "processor": { "type": "string", "description": "grant use of this configured processor id" }, "artifacts": { "type": "boolean", "description": "grant artifact export" } }), json!(["task_id"]))),
        tool("akson_deny", "DENY an inbox task: sign a rejection. No work is done.", s(json!({ "task_id": { "type": "string" }, "reason": { "type": "string" } }), json!(["task_id"]))),
        tool("akson_fulfill", "FULFIL an approved task with a result THIS side's own agent produced (no sandbox). The daemon gates it against the grant and signs the manifest. `content` is the result text.", s(json!({ "task_id": { "type": "string" }, "content": { "type": "string", "description": "the result the agent produced" }, "role": { "type": "string", "description": "default response" }, "media_type": { "type": "string", "description": "default text/plain" } }), json!(["task_id", "content"]))),
        tool("akson_deliver", "DELIVER a completed task's signed result back to the requester.", s(task(), json!(["task_id"]))),
        tool("akson_send", "SEND a task to a paired peer (sign + post a contract proposal). Delegates work to that peer.", s(json!({ "performer": { "type": "string", "description": "the peer agent id" }, "objective": { "type": "string" }, "task_type": { "type": "string" }, "input_text": { "type": "string" }, "input_id": { "type": "string" }, "input_media_type": { "type": "string" }, "capabilities": { "type": "array", "items": { "type": "string" } }, "deliverable_role": { "type": "string" }, "deliverable_media_type": { "type": "string" }, "deadline": { "type": "string" }, "max_response_bytes": { "type": "integer" } }), json!(["performer", "objective"]))),
    ])
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": input_schema })
}
