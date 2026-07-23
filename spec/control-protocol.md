# Local control protocol

How the `akson` CLI (and any alternate client) drives a running `aksond`. This is the
local operator/worker surface — distinct from the peer-facing A2A wire in
[`a2a/profile.md`](a2a/profile.md). Design references: §16.2 (control socket) and
§16.4 (control operations).

## A request, and its reply

One newline-terminated JSON request in, one newline-terminated JSON reply out. Ask
the daemon who it is:

~~~text
$ printf '{"op":"who_am_i"}\n' | socat - UNIX-CONNECT:"$XDG_RUNTIME_DIR/akson/admin.sock"
{"outcome":"ok","result":{"issuer":"orgB","agent":"bob","interface_url":"https://127.0.0.1:18444/a2a","receive_addr":"127.0.0.1:18444","endpoint_fingerprint":"9f86d0…","data_dir":"/tmp/bob-data"}}
~~~

That is the whole shape of every exchange. `akson whoami` is exactly this request; the
CLI is a thin front end that builds the request object, writes one line, and prints
`result` (or the `problem`).

- **What you write** is the request object: an `op` tag plus that op's arguments.
- **The plumbing** — framing, which socket, who may connect, which ops each socket
  allows — is the rest of this document, and is identical for every op.

## Framing

- Transport: a `SOCK_STREAM` **Unix domain socket**. No TCP, no TLS — the socket file
  and the OS are the security boundary.
- One request per connection: write one line, read one line, the daemon closes. There
  is no multiplexing, no streaming, and no request id (the reply is the reply).
- Encoding: UTF-8 JSON, terminated by a single `\n`. The request object is
  `{"op": "<snake_case>", …args}` — the `op` tag is the enum discriminant; arguments
  ride as sibling fields.
- Reply: `{"outcome": "ok", "result": <value>}` on success, or
  `{"outcome": "problem", "problem": <problem>}` on failure (see below).

## Who may connect

Every connection is checked twice before the request runs:

1. **Peer credentials.** The connecting process's UID (from `SO_PEERCRED`) must equal
   the daemon's UID. A foreign UID is refused before the request is even read. The
   socket file itself is bound `0600` in a `0700` per-user directory
   (`$XDG_RUNTIME_DIR/akson`, else a UID-scoped temp dir).
2. **Surface.** The daemon exposes two sockets; a request is refused unless the socket
   it arrived on is privileged enough for that op.

## The two sockets

| Socket | Path | For |
|---|---|---|
| **admin** | `$XDG_RUNTIME_DIR/akson/admin.sock` | Authority-bearing operator ops (peer import, approve, run, deliver, send, configure). |
| **worker** | `$XDG_RUNTIME_DIR/akson/worker.sock` | The narrow surface the sandboxed worker/adapter uses: submit a result, request a brokered processor call. |

Admin dominates worker: an admin-socket connection may invoke any op; a worker-socket
connection may invoke **only** the worker ops. This is why a confined worker that is
compromised still cannot approve a contract or send a task — those ops are not on its
surface. An op used on the wrong socket returns `403` with a `forbidden-surface`
problem that names only the surface, never the op's internals.

## Operations

`Surface` is the *minimum* socket an op needs (`worker` ops also work from admin). The
`akson …` column is the CLI that issues the op.

| `op` | Args | Surface | `akson …` | Result (on `ok`) |
|---|---|---|---|---|
| `diagnose` | — | admin | `doctor` / `status` | `{daemon:"aksond", capabilities:[…]}` — sandbox/host health |
| `who_am_i` | — | admin | `whoami` | `{issuer, agent, interface_url, receive_addr, endpoint_fingerprint, data_dir}` |
| `peer_list` | — | admin | `peer list` | `{peers:[{agent_id, endpoint, status}]}` |
| `peer_confirm` | `agent_id` | admin | `peer confirm <agent>` | `{confirmed:bool, agent_id}` |
| `token` | — | admin | `token` | `{token, presentation, root_thumbprint, hint}` — this endpoint's identity token (ADR-0013) |
| `peer_add` | `token, label, endpoint?, update?` | admin | `peer add <token> <label>` | the recorded import — the trust act of pairing (§8.2 step 3) |
| `peer_label` | `label, new_label` | admin | `peer label <old> <new>` | the renamed label (purely local) |
| `peer_import_remove` | `label` | admin | `peer remove <label>` | tombstones the import, advances its epoch, drops pinned state |
| `peer_knocks` | — | admin | `peer knocks` | refused introductions (claims are unauthenticated) |
| `peer_ping` | `label` | admin | `peer ping <label>` | dials the introduction now (ADR-0015) |
| `task_inbox` | — | admin | `task inbox` | `{tasks:[{task_id, contract_id, revision, state:"submitted"}]}` |
| `task_show` | `task_id` | admin | `task show <id>` | `{task_id, revision, sentence, sections:[{heading, lines}]}` — the §5.2 risk card |
| `task_approve` | `task_id`, `processor?`, `artifacts?` | admin | `task approve <id> [--processor <id>] [--artifacts]` | `{approved:true, work_order_id, granted_capabilities:[…]}` |
| `task_deny` | `task_id`, `reason` | admin | `task deny <id> <reason>` | a signed reject decision |
| `task_run` | `task_id` | admin | `task run <id>` | `{ran:true, task_id, response_bytes, artifacts, result:{bundle_digest, …}}` |
| `task_deliver` | `task_id` | admin | `task deliver <id>` | `{delivered:true, …}` |
| `task_send` | a `TaskSpec` object | admin | `task send <spec.json>` | `{sent:true, task_id, contract_digest}` |
| `task_sent` | — | admin | `task sent` | the requests this daemon sent |
| `task_outcomes` | — | admin | `task outcomes` | the recorded requester outcomes |
| `processor_add` | `processor_id, provider, origin_host, origin_port, local?, tls_certificate_sha256?, path?, auth?, headers[]` | admin | `processor add …` | `{added:true, processor_id}` |
| `processor_list` | — | admin | `processor list` | `{processors:[{processor_id, provider, origin, local, pinned}]}` |
| `processor_credential` | `processor_id`, `credential` | admin | `processor credential <id> <cred>` | `{credential_set:true, processor_id}` |
| `issue_work_order` | `task_id` | admin | — | `{accepted:true}` |
| `submit_result` | a `ResultSubmission` object | **worker** | — (the worker SDK) | `{completed:true, bundle_digest}` |
| `request_processor_call` | `processor_id, work_order_id, request` | **worker** | — (the worker SDK) | the broker reply: `{state, status, response}` or `{error}` |

> The confined worker does **not** speak this protocol directly for a model call — a
> `processor_use` grant hands it one already-connected fd (`AKSON_BROKER_FD`) and the
> daemon services `request_processor_call` on the other end. See §13.1 and the
> `akson-adapter-*` crates.

## Problems

A failure is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem object:

~~~json
{"type":"urn:akson:error:forbidden-surface","title":"operation not permitted on this surface","status":403}
~~~

- `type` — a stable `urn:akson:error:<kind>` tag (not dereferenced).
- `title` — a short human summary.
- `status` — an HTTP-style code (`403` surface, `404` no such task, `409` already
  running, `422` unprocessable, `500` internal, `503` cannot confine, …).
- `detail` — optional; present only when it adds nothing sensitive. Problems never
  disclose whether a hidden path, secret, policy rule, or internal peer exists.

## Compatibility

Result objects are **additive**: a newer daemon may add fields to a `result`, so a
client must ignore unknown fields rather than fail (matching the unknown-field policy
in [ADR 0010](adr/0010-unknown-fields.md)). The `op` tags, argument names, and the
`{outcome, …}` envelope are the stable contract. This document tracks the
`ControlRequest` surface in `crates/aksond/src/socket.rs`; that enum is the source of
truth.
