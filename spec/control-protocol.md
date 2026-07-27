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
- Connections on one socket are served **concurrently**, up to 16 at a time (beyond
  that the next is served on the accept thread, so the socket serialises rather than
  refusing anyone). An op can block on the network — `dispatch` carries bytes to a
  pinned peer — and while connections were served one at a time, a peer that stalled
  a carriage stalled every other op on that surface with it. Ordering between
  concurrent requests is therefore not guaranteed; each still passes the same
  admission and surface gates, and durable state is serialised by the store.
- Encoding: UTF-8 JSON, terminated by a single `\n`. The request object is
  `{"op": "<snake_case>", …args}` — the `op` tag is the enum discriminant; arguments
  ride as sibling fields.
- Reply: `{"outcome": "ok", "result": <value>}` on success, or
  `{"outcome": "problem", "problem": <problem>}` on failure (see below).

## Who may connect

Every connection is checked twice before the request runs:

1. **Peer credentials.** The connecting process's UID (from `SO_PEERCRED`) must be one
   the socket admits — **per socket**, not one rule for all three (see the table
   below). A UID that is not admitted is refused before the request line is even
   read, with a generic `unauthorized` problem that carries no detail, so a UID
   mismatch and an unreadable credential are indistinguishable.
2. **Surface.** A request is refused unless the socket it arrived on is privileged
   enough for that op.

## The three sockets

| Socket | Path | Admits | Mode | For |
|---|---|---|---|---|
| **admin** | `$XDG_RUNTIME_DIR/akson/admin.sock` | the daemon's own UID | `0600` | Authority-bearing operator ops (peer import, approve, run, deliver, send, configure, **stage consent**). |
| **worker** | `$XDG_RUNTIME_DIR/akson/worker.sock` | the daemon's own UID | `0600` | The narrow surface the sandboxed worker/adapter uses: submit a result, request a brokered processor call. |
| **coord** | `$XDG_RUNTIME_DIR/akson/coord.sock` | the UID named by `AKSON_COORD_UID`, **or** the daemon's own (diagnostics) | `0660` | The coordination surface ([ADR 0016](adr/0016-coordination-surface.md), `akson_byom_exchange_v1`): a *different* local principal stages outbound contracts and reads coordination state. |

Both narrow sockets live in the same `0700` per-user runtime directory
(`$AKSON_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/akson`, else a UID-scoped temp dir).

**The coordination socket exists only when it is configured.** With `AKSON_COORD_UID`
unset, `coord.sock` is **not created at all** — absent rather than guarded, the same
posture ADR-0015 took when it left the pairing bootstrap endpoint unmounted: there is
nothing to connect to and nothing to probe. A value that is not a numeric UID is fatal
at startup, so a typo cannot silently remove the surface. Its `0660` mode is *not* the
boundary — `SO_PEERCRED` is; the mode plus the runtime directory are what decide
whether a separate identity can reach the socket at all, and that grant is one visible
OS act. The coordination surface also bounds its request line at 1 MiB (a different
principal must not be able to make the daemon buffer without limit); admin and worker
are the daemon's own UID and stay unbounded.

Dominance is deliberately asymmetric:

- **Admin dominates both narrow surfaces.** An admin-socket connection may invoke any
  op, including the coordination ops — so an operator can diagnose that surface
  without a second account.
- **Worker and coord dominate nothing, including each other.** A worker connection may
  invoke only the worker ops; a coordination connection only the coordination ops. A
  compromised confined worker cannot approve a contract or send a task, and a
  compromised coordination driver cannot mint consent, reach a credential, or touch
  inbound authority — those ops are not on its surface.

An op used on the wrong socket returns `403` with a `forbidden-surface` problem that
names only the surface, never the op's internals.

## Operations

`Surface` is the *minimum* socket an op needs — and, for the narrow surfaces, the only
one besides admin (`worker` and `coord` ops also work from admin; nothing else works
from them). The `akson …` column is the CLI that issues the op.

| `op` | Args | Surface | `akson …` | Result (on `ok`) |
|---|---|---|---|---|
| `diagnose` | — | admin | `doctor` / `status` | `{daemon:"aksond", capabilities:[…]}` — sandbox/host health |
| `who_am_i` | — | admin | `whoami` | `{issuer, agent, interface_url, receive_addr, endpoint_fingerprint, data_dir}` |
| `peer_list` | — | admin | `peer list` | `{imports:[{label, root_thumbprint, endpoint_hint, status, claims}]}` — labeled relationships with their introduction state |
| `token` | — | admin | `token` | `{token, presentation, root_thumbprint, hint}` — this endpoint's identity token (ADR-0013) |
| `peer_add` | `token, label, endpoint?, update?` | admin | `peer add <token> <label>` | the recorded import — the trust act of pairing (§8.2 step 3) |
| `peer_label` | `label, new_label` | admin | `peer label <old> <new>` | the renamed label (purely local) |
| `peer_import_remove` | `label` | admin | `peer remove <label>` | tombstones the import, advances its epoch, drops pinned state |
| `peer_knocks` | — | admin | `peer knocks` | refused introductions (claims are unauthenticated) |
| `peer_ping` | `label` | admin | `peer ping <label>` | dials the introduction now (ADR-0015) |
| `peer_auto_approve` | `agent_id` (the peer's local **label**), `task_types[]`, `max_response_bytes` | admin | `peer auto-approve <label> --task-type <t>… [--max-bytes N] \| --off` | standing auto-approval bound to the introduced root: these task types from this peer, within the byte ceiling, run without a per-task prompt (never grants processor/artifacts); empty `task_types` clears it — `{auto_approve:"on"\|"off", …}` |
| `task_inbox` | — | admin | `task inbox` | `{tasks:[{task_id, contract_id, revision, state:"submitted"}]}` |
| `task_show` | `task_id` | admin | `task show <id>` | `{task_id, revision, sentence, sections:[{heading, lines}]}` — the §5.2 risk card |
| `task_approve` | `task_id`, `processor?`, `artifacts?` | admin | `task approve <id> [--processor <id>] [--artifacts]` | `{approved:true, work_order_id, granted_capabilities:[…]}` |
| `task_deny` | `task_id`, `reason` | admin | `task deny <id> <reason>` | a signed reject decision |
| `task_run` | `task_id` | admin | `task run <id>` | `{ran:true, task_id, response_bytes, artifacts, result:{bundle_digest, …}}` |
| `task_fulfill` | `task_id`, `outputs[]` of `{role, media_type, content_base64}` | admin | `task fulfill <id> --file <path> [--role <role>] [--media-type <mt>]` | `{fulfilled:true, task_id, outputs, result:{bundle_digest, …}}` — an operator-produced result in place of a sandboxed run (no worker); still gated against the granted scope and signed over these exact bytes |
| `task_deliver` | `task_id` | admin | `task deliver <id>` | `{delivered:true, …}` |
| `task_send` | a `TaskSpec` object | admin | `task send <spec.json>` | `{sent:true, task_id, contract_digest}` |
| `task_sent` | — | admin | `task sent` | the requests this daemon sent |
| `task_outcomes` | — | admin | `task outcomes` | the recorded requester outcomes |
| `task_output` | `task_id`, `role?` | admin | `task output <id> [--role <role>]` | `{task_id, outputs:[{artifact_id, role, media_type, byte_length, sha256, content}]}` — `content` is base64 (byte-exact under the digest); serves whichever side this endpoint is: the performer's staged outputs, or the ones a delivered result carried |
| `processor_add` | `processor_id, provider, origin_host, origin_port, local?, tls_certificate_sha256?, path?, auth?, headers[]` | admin | `processor add …` | `{added:true, processor_id}` |
| `processor_list` | — | admin | `processor list` | `{processors:[{processor_id, provider, origin, local, pinned}]}` |
| `processor_credential` | `processor_id`, `credential` | admin | `processor credential <id> <cred>` | `{credential_set:true, processor_id}` |
| `issue_work_order` | `task_id` | admin | — | `{accepted:true}` |
| `stage_consent` | `stage_ref` | admin | `stage consent <ref>` | `{consented:true, consent_receipt, stage_ref, staged_digest, max_uses:1, uses:0, minted_at, sentence, sections}` — the risk card for that exact staged digest **and** the one-shot receipt, from one call over the row it is minted against. `409 already-consented` while an unconsumed receipt exists, and `409 already-dispatched` once the **dispatch ledger** holds a dispatch for this staging — a second consent could only authorize a second disclosure of the same digest, and the recovery for an unacknowledged carriage is the driver's retry under the same `execution_key`, which the refusal's `detail` names. The card's closing line is read off that same ledger rather than asserted, so it can never claim "nothing has left this machine yet" over bytes that have |
| `submit_result` | a `ResultSubmission` object | **worker** | — (the worker SDK) | `{completed:true, bundle_digest}` |
| `request_processor_call` | `processor_id, work_order_id, request` | **worker** | — (the worker SDK) | the broker reply: `{state, status, response}` or `{error}` |

### The coordination ops (`coord`)

The registry is **deny-by-absence**: these eight ops are the whole surface, and
everything else — approve/deny, pairing, peer import, processor and credential ops,
`task send`/`fulfill`/`deliver`, configuration — returns `forbidden-surface`. Consent
is not here; it is `stage_consent` on admin, above.

| `op` | Args | Surface | Result (on `ok`) |
|---|---|---|---|
| `coord_whoami` | — | **coord** | `{protocol:"akson_byom_exchange_v1", protocol_version, issuer, agent, root_thumbprint, interface_url, endpoint_fingerprint, features[], unimplemented[], partial[]}` — narrower than `who_am_i` on purpose: no `data_dir`, no `receive_addr`. `features` is all eight ops; `unimplemented` and `partial` are both **empty** since `dispatch` gained its outbound carrier. Both fields stay present — a driver parses them, and "the list is empty" is an answer while "the field is gone" is a parse change. `partial` carries `{op, missing, detail}` when a part of an op is not built |
| `peer_show` | `label` | **coord** | `{label, root_thumbprint, verified, status, identity{issuer, agent_id, endpoint_id, tls_certificate_sha256, agent_card_thumbprint}, card_claims{security_projection_digest, full_card_digest, key_purposes[]}, endpoint_hint}` — the one peer asked for; `{verified:false, status:"imported"}` before an introduction; never the operator's private note. Unknown or malformed label ⇒ the same `404 unknown-peer` |
| `stage` | `task_type`, `performer` (a local **label**, may be empty), `payload_base64` | **coord** | `{stage_ref, staged_digest, payload_sha256, byte_length, task_type, performer, status:"staged", staged_at, consent:null, already_staged}` — **inert and idempotent**: the bytes are persisted (sealed) with a reference derived from their content digest; nothing starts, no authority is minted, no socket opens. The same bytes return the same reference with `already_staged:true` and write no second record. `task_type` and `performer` are admitted by the **dispatch envelope's own schema** (`spec/ext/coord-dispatch.v1.schema.json`), not by a second rule here: what may be staged is exactly what may later be sent, so a value cannot be accepted and then discovered to be unsendable after a consent receipt has been burned on it. `400 bad-task-type` / `404 unknown-peer` |
| `stage_show` | `stage_ref` | **coord** | the same record plus `consent` — `null`, or `{consent_receipt, staged_digest, max_uses, uses, minted_at}` once the operator has consented |
| `events_read` | `cursor?`, `limit?` (default 64, max 256) | **coord** | `{events:[{cursor, kind, stage_ref, at, detail}], next_cursor, has_more}` — the durable feed. Outbound kinds: `staged`, `consent_recorded`, `dispatched`, `egress_recorded` (one per carriage *attempt*, which is not a dispatch). Inbound kinds, on the receiving endpoint: `dispatch_received` (a verified arrival — digests, sender root, byte length; never the payload) and `dispatch_refused` (with the reason that caught it). Cursors are **opaque**: each event carries the cursor that resumes after it, and a cursor that did not come from a reply is refused `400 bad-cursor` |
| `dispatch` | `stage_ref`, `consent_receipt`, `execution_key` | **coord** | `{dispatch_receipt, stage_ref, staged_digest, payload_sha256, byte_length, task_type, performer, consent_receipt, execution_key, consent_spent:true, status:"dispatched", dispatched_at, replayed, egress{state, at, detail, retryable}}` — **one-shot**: the receipt is spent and the dispatch committed in one transaction, and the staged bytes are then carried to the pinned recipient. See the two paragraphs below |
| `task_status` | `task_id` | **coord** | `{task_id, stage_ref, staged_digest, payload_sha256, byte_length, task_type, performer, status, dispatch_receipt, consent_receipt, execution_key, dispatched_at, egress{…}, verification{state, result_manifest_digest, outcome_state, detail}}` — `verification.state` is `acknowledged` exactly when the pinned recipient echoed this staged digest, `unacknowledged` otherwise; `result_manifest_digest` and `outcome_state` are **permanently** null, because a coordination dispatch is not a contract and no result manifest or requester outcome will ever exist for it. Scoped to dispatches **this surface** committed, addressed by the dispatch receipt or the staged reference. Anything else — including an inbound task in the operator's inbox — is the same `404 unknown-task` |
| `capability_evidence` | `label` | **coord** | `{label, root_thumbprint, predicate_type, statement_digest, signer{purpose, thumbprint}, statement, evidence}` — a **DSSE-signed in-toto Statement v1** under `…/attestation/federation-capability/v1`, signed with this endpoint's `evidence` key: the same carrier result evidence uses, so a consumer verifies it with the code it already has. Every predicate dimension declares itself `locally_observed` or `peer_asserted`; a dimension this endpoint cannot answer reports `not_retained` rather than a default. Unknown or malformed label ⇒ the same `404 unknown-peer`, and nothing is signed |

**`dispatch` is the one op with an effect, so read its three arguments as three jobs.**
`stage_ref` says which bytes; `consent_receipt` is the operator's authority for exactly
those bytes and is spendable once; `execution_key` names **one attempt**. Re-sending the
same key is a *retry* — the same `dispatch_receipt` comes back with `replayed:true` and
nothing is spent again. A *different* key against a spent receipt is a *replay*, refused
`409 consent-spent`. No live receipt for the stage is `409 consent-required`; a key
already committed to other arguments is `409 execution-key-conflict`. The spend and its
record commit in one store transaction, guarded by a `uses < max_uses` compare-and-set
and a `UNIQUE` constraint on the receipt in the dispatch ledger, so the refusal survives
a daemon restart.

**The carrier: a coordination dispatch is not a contract, and gets its own envelope.**
`stage` fixes what the operator's risk card and consent digest cover — a payload, a
recipient label, a `task_type` — and akson's closed contract schema cannot hold that
without contract terms (an objective, a deliverable, a deadline) the operator never saw;
synthesising them would make the receipt authorize more than was read. So the bytes ride
a dedicated object, `spec/ext/coord-dispatch.v1.schema.json`, carried as a Part of media
type `application/vnd.akson-dev.coord-dispatch.v1+json` beside the raw payload Part, over
the same pinned mutual-TLS A2A POST every other peer-to-peer byte uses. Its members are
`{schema_version, protocol, task_type, recipient_label, recipient_root, sender_root,
payload_sha256, staged_digest, consent_receipt}` and `additionalProperties` is **false**,
so a contract term cannot be smuggled in later. The envelope is *not signed*: its
authenticity is the channel's, and there is no key purpose for a coordination dispatch —
borrowing `contract-proposal` to sign a non-contract would break one-key-one-role. The
consequence is stated rather than hidden: a coordination dispatch is authenticated, not
non-repudiable.

The receiver checks four things and admits nothing on a `422 coordination-refused`
otherwise (one generic refusal; the reason is recorded locally, never returned):
`sender_root` equals the root the mTLS handshake authenticated; `recipient_root` equals
its own root; SHA-256 over the payload bytes it actually read equals `payload_sha256`;
and the ADR-0016 §4 derivation over `{payload_sha256, recipient_label, task_type}`
reproduces `staged_digest` — which is why `recipient_label` is on the wire at all.
**Arrival is still not execution:** an admitted disclosure creates no Task, no contract
head, no work order, and nothing to approve. It is acknowledged, one `dispatch_received`
event is recorded, and the payload is *not retained* — retaining it would need an inbound
coordination op that ADR-0016's registry deliberately does not have. A refusal is
recorded the same way an admission is: through the §9.2 idempotency record, so one
`dispatch_refused` event costs a peer one *distinct* request and re-sending a refused
dispatch replays the same `422` and writes nothing further.

**Where the bytes are is a durable column, not an inference.** `egress.state` is
`pending` (committed, no acknowledgement — the state a crash between the commit and the
send leaves, and the schema default so it is true by construction), `sent` (the pinned
recipient echoed this exact staged digest — **terminal**), or `failed` (attempted and
refused). A dispatch whose carriage did not complete is recoverable: retrying under the
**same** `execution_key` re-attempts it and spends nothing, because the execution key
already owns the one dispatch row; a *different* key on that receipt stays
`409 consent-spent` throughout. That is at-least-once carriage of exactly one consented
disclosure, deduplicated at the recipient by the dispatch receipt, which is the A2A
Message id. Routing is resolved **before** the spend: a staging whose recipient is
unnamed, un-introduced, suspended, or has no usable https endpoint is refused
`409 unroutable-recipient` with the consent receipt still live, because burning a
one-shot consent on a disclosure that provably cannot leave is the worst failure this
surface has available to it.

**Carriage is bounded at every stage.** Name resolution, the TCP connect, the TLS
handshake, and the request/response exchange each have their own ceiling (5s, 10s, 10s,
30s), so a recipient that accepts the connection and then says nothing ends the attempt
instead of holding the surface. A timed-out attempt is `failed` — never `sent`, because
nothing echoed the staged digest and this endpoint will not claim a delivery it cannot
evidence — and `retryable`, with `egress.detail` naming the stage
(`urn:akson:error:peer-timeout`). The recovery is the ordinary one: retry under the same
`execution_key`, which re-carries the byte-identical body and spends nothing.

Golden vectors for every coordination op — request wire, reply field set, the staged
digest derivation and its idempotency, the dispatch envelope's wire shape, the cursor
encoding, and every refusal body — live in `spec/vectors/coordination/`, re-derived
independently by `xcheck/`. The two-process interop scenario
`harness/interop/scenario-coord-dispatch.sh` runs the whole chain across real sockets:
each step is a request on the control socket that owns it, so the surface gate runs for
real — the scenario asks **coord** to mint the consent first and requires the `403`.

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
