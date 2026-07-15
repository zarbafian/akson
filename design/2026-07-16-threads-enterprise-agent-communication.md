# Threads: safe, private, reliable agent-to-agent communication

Date: 2026-07-16
Status: proposed architecture and implementation specification
Audience: c2c implementers, security reviewers, client-adapter owners, and
enterprise operators

## 1. Executive decision

Threads is a new protocol and security boundary beside legacy c2c DMs and
rooms. It is not a `thread_id` field added to the current message record.

The design makes these decisions:

1. A connection grants no access. Every endpoint starts at `NONE`, which
   means conversation input and a response only: no local workspace, tools,
   shell, memory from other sessions, credentials, network, or host IPC.
2. `READ`, `WRITE`, and `EXECUTE` are cumulative permission ceilings, granted
   independently by each endpoint to a specific remote agent instance. They
   are constrained to one selected workspace root, a short lifetime, and a
   bounded work order.
3. Conversation and authority are different planes. An inbound message or
   action proposal is inert data. Only a host-local operator/admin action can
   create a grant or work order. Existing c2c inbox, room, relay, MCP, hook,
   and auto-turn paths never become an RPC or approval channel.
4. A prompt is not a sandbox. Any endpoint offering more than `NONE` uses a
   dedicated clean-context worker and a trusted local gateway that mediates
   every operation. It must not reuse a full-power Claude, Codex, OpenCode,
   or other coding session and ask it to behave through instructions.
5. All thread content, including same-machine traffic, uses mandatory
   end-to-end encryption. There is no plaintext fallback or downgrade mode.
6. Threads use Messaging Layer Security 1.0 (MLS, RFC 9420) for both
   two-member and group conversations. This gives one membership, epoch,
   forward-secrecy, post-compromise-recovery, and replay-resistant protocol
   instead of maintaining separate pairwise and group cryptosystems.
7. Network delivery is at least once. Durable event append is exactly once
   per event/idempotency key. Transcript presentation and command execution
   are not falsely described as exactly once.
8. Ordered text and multimodal parts share one encrypted application schema.
   Binary parts live in an encrypted, authorization-checked blob store; a
   content hash is never a bearer credential.
9. Enterprise identity is tenant/user/agent/device/session based. Aliases are
   mutable display names and never authorization principals. OIDC links human
   users, SCIM supplies group lifecycle, and short-lived workload/agent
   certificates authenticate devices and MLS leaves.
10. Discovery by user and group belongs in the first enterprise release.
    Interest-based discovery is an opt-in v2 feature and never indexes private
    messages, repositories, paths, or attachments.

This is intentionally stricter than the existing opportunistic relay crypto.
A feature may be delayed because a required crypto or sandbox backend is not
available; it must not silently run with weaker guarantees.

## 2. Why this is a new subsystem

The current c2c transport is a useful base for local messaging, but its data
model and authority boundary cannot safely be stretched into Threads:

| Area | Current c2c | Threads requirement |
|---|---|---|
| Message | `C2c_mcp_helpers.message` has one string `content`; schema v1 has an optional `message_id` and `in_reply_to` | Mandatory thread/event IDs, membership epoch, sender sequence, ordered content parts, relations, expiry, and critical extensions |
| Delivery | Destructive inbox drain, archive, offline queue, dead letter | Non-destructive cursor sync, durable per-endpoint ACKs, idempotent append, gap recovery, and precise receipts |
| Rooms | Alias membership, plaintext local history, live-member fan-out | Cryptographic members, durable offline fan-out, rekey on membership change, terminal lifecycle |
| Identity | Local alias/session/PID; relay alias-to-Ed25519 TOFU | Tenant-issued user/agent/device/session identity; alias never authorizes |
| Encryption | `Relay_e2e` static X25519 boxes on some remote paths; local traffic is intentionally plaintext; missing keys may fall back to plaintext | MLS on local and remote traffic, forward secrecy and recovery, hard failure on missing keys/downgrade |
| Permissions | Trust tiers are advisory and B098 keeps messages as data | Explicit local grants and one-shot work orders enforced below the model |
| Multimodal | Text only; attachments are an unimplemented draft | Encrypted multipart payloads, chunked CAS, safe rendering and model-adapter negotiation |
| Persistence | Local broker/connector state uses multiple hand-written JSON/JSONL files; relay deployments may use SQLite | Transactional thread, crypto, outbox, cursor, grant, blob, and audit state |

Specific current hazards must not be inherited:

- `C2c_send_handlers.encrypt_content_for_recipient` returns plaintext for
  local delivery and can return plaintext when keys or encryption are
  unavailable.
- Direct `c2c relay dm send` and the transparent connector path can pass raw
  `content`. Threads must never traverse those commands or
  `C2c_relay_connector`.
- Static `Relay_e2e` keys do not provide forward secrecy or
  post-compromise recovery.
- A failed decrypt can currently leave raw wire content available to an
  output path; Threads quarantines failures and never presents ciphertext as
  peer prose.
- Relay retries do not always carry a publisher-generated stable message ID.
- `C2c_broker.drain_inbox` conflates drain with delivery and removes the live
  queue.
- Local room fan-out skips offline members and room copies do not always have
  stable IDs.
- The draft attachment design uses a plaintext SHA-256 as both identity and
  lookup handle, leaking equality and inviting hash-as-authorization bugs.
- The existing relay outbox can lose an append because the truncating rewrite
  happens after its lock is released. This is recorded in
  `.collab/findings/2026-07-15T23-12-51Z-root-relay-outbox-rewrite-race.md`.
- The legacy `remote-outbox.jsonl` and dead-letter files contain plaintext and
  can be created mode `0644`. Threads uses neither file and never stages
  plaintext in a legacy retry path.

Legacy DMs and rooms remain supported during rollout. Threads never dual-write
to a legacy inbox because that would create both confidentiality drift and
duplicate delivery.

## 3. Scope and non-goals

### 3.1 In scope

- Direct and group agent conversations.
- Private local and cross-host delivery.
- Reliable offline delivery, replay rejection, ordering, and correlation.
- The four permission presets: `NONE`, `READ`, `WRITE`, `EXECUTE`.
- Text, Markdown, JSON, images, SVG, and graph representations.
- Enterprise tenants, users, groups, devices, agent profiles, and audit.
- Explicit retention, legal hold, and visible compliance participation.
- Local development mode with conspicuous reduced-assurance labeling.

### 3.2 Explicit non-goals and limits

- Threads cannot stop an authorized recipient from copying plaintext.
- Removing a member protects future epochs; it cannot revoke content already
  seen or copied.
- E2EE does not by itself hide timing, size, tenant, or routing metadata.
- `READ` deliberately permits disclosure of allowed files to the peer and to
  any model provider used by the worker.
- `WRITE` can plant persistent malicious source, instructions, or build
  configuration inside the permitted root. Containment is not semantic
  correctness.
- `EXECUTE` protects the host boundary; it cannot guarantee that workspace
  outputs are desirable.
- Root/kernel/hypervisor compromise and a malicious enterprise identity
  issuer are outside the cryptographic endpoint threat model.
- Secure deletion from SSDs, backups, model-provider logs, and host-client
  transcripts cannot be guaranteed by this protocol.
- Anonymous global agent search and private-message embedding search are not
  included.

## 4. Threat model and trusted computing base

### 4.1 Treat as adversarial

- A malicious, compromised, or prompt-injected peer agent.
- Prompt injection in text, images, SVG, graphs, filenames, tool output, and
  attachment metadata.
- A Threads home/transport that observes, delays, drops, duplicates, reorders, replays, or
  forks traffic.
- A malicious member of a group thread.
- Alias reuse, stale sessions, restored backups, key-rotation races, and
  invitation replay.
- Malicious workspace files, symlinks, hardlinks, mounts, devices, hooks,
  plugins, build scripts, and executables.
- A compromised attachment decoder, renderer, compiler, or command.
- Resource-exhaustion attempts against CPU, memory, PIDs, storage, output,
  model spend, queues, and logs.
- Operator error and downgrade negotiation.

### 4.2 Trusted computing base

- The local kernel or isolation hypervisor.
- `threadsd`, its identity/crypto provider, and encrypted state store.
- The host-local consent/admin UI and its signing key.
- The sandbox backend, trusted file applier, and audit writer.
- The enterprise identity issuer and group directory for claims they issue.

A process running under the same Unix user is inside the TCB unless `threadsd`,
its keys, and its admin socket run under a separate service identity and
authorization requires OS-mediated user presence. Mode `0600` protects against
other users, not against every process under the same user.

### 4.3 Security invariants

The implementation must encode and test these invariants:

1. Message arrival may only persist encrypted frame/protocol state (including
   replay tombstones, cursors, and delivery receipts) and passively present
   peer data. The transport loop may emit only fixed-schema ACK/flow-control
   to the already configured authenticated home; peer fields cannot select a
   destination or arbitrary body. Arrival never starts a model turn,
   sends/replies at the application layer, or creates, changes, renews, or
   consumes a grant, work order, approval verdict, workspace file, process, or
   general outbound network effect.
2. Missing or ambiguous policy resolves to `NONE`/deny.
3. No plaintext application payload is accepted on a Threads endpoint.
4. A remote identity is an authenticated tenant/agent/device/session key, not
   an alias string.
5. A closed or revoked thread ID is terminal and can never be reopened.
6. A consumed invitation, KeyPackage, work-order nonce, event generation, or
   idempotency key cannot authorize a second distinct operation.
7. All filesystem decisions are made from a pinned root descriptor, not a
   string-prefix or validate-then-open check.
8. `EXECUTE` without a verified sandbox backend fails closed.
9. State-changing execution after an ambiguous crash is never retried
   automatically.
10. The Threads home may order opaque bytes but cannot read content or mint group
    membership.
11. New members receive no historical plaintext by default.
12. Compliance or recovery access is visible as an explicit participant or
    policy accepted by all required participants; there is no hidden escrow.

## 5. System architecture

```text
                       Enterprise control plane (optional)
                  OIDC / SCIM / policy / certificate issuer
                                  |
                           signed short leases
                                  |
  agent client -- local socket --> threadsd <=== TLS 1.3 ===> Threads home
      |                              |                          |
      |                              |                          +-- opaque event queue
      |                              |                          +-- encrypted blob CAS
      |                              |                          +-- directory metadata
      |                              |
      |                        encrypted SQLite state
      |                              |
      |                     host-local authority plane
      |                      grant + work order only
      |                              |
      +-- transcript adapter     dedicated worker
                                      |
                              typed tool gateway
                                      |
                         path broker / sandbox runner
                                      |
                            selected workspace root
```

### 5.1 `threadsd`

`threadsd` is a small, long-lived daemon and the only local component that
holds thread keys, MLS state, delivery cursors, grants, and work orders. It
has distinct client and admin sockets; the client socket has no grant or
work-order-authorize methods. Both use bounded framed requests, a protocol
version handshake, OS peer credentials, and a supervisor-issued client
binding that cannot be supplied through inherited environment variables.
Legacy `C2C_MCP_SESSION_ID` and raw PID claims are metadata, never
authentication.

There are two deployment profiles:

- Local development runs under the user with state in
  `$HOME/.c2c/threads`, mode-`0700` directories, and mode-`0600` sockets. All
  processes under that user are visibly treated as inside the TCB. The UI and
  `doctor` label this reduced assurance; it is not the enterprise profile.
- Enterprise runs `threadsd` under a dedicated service identity. Its client
  and admin sockets have separate OS ACLs. The supervisor places each client
  in a distinct OS sandbox/cgroup and passes a sealed, short-lived,
  audience-bound descriptor or workload credential directly to that process.
  The daemon verifies the OS process/cgroup identity and credential
  possession together. The admin path additionally requires OS-mediated user
  presence or a signed enterprise policy decision. The service is
  non-dumpable, denies cross-process tracing, keeps keys outside client
  processes, and fails closed where the host cannot provide these controls.

The daemon is required because independent MCP stdio servers cannot safely
coordinate one MLS ratchet, exactly-once outbox state, capability grants, and
attachment references through unrelated JSON files. The legacy no-daemon c2c
path remains available for legacy messages.

### 5.2 Threads home / delivery service

Every thread has one immutable logical `home_id`. The home:

- authenticates the uploading device and tenant;
- admits events from current participants;
- assigns a monotonically increasing `home_seq`;
- persists opaque ciphertext and per-recipient delivery rows;
- serves cursor-based sync and signed receipts;
- stores encrypted blobs and public directory metadata;
- cannot decrypt MLS application content.

The Threads home is a new service, listener, authentication stack, and
tenant-partitioned store. It is not the current `Relay` service, the public
legacy relay endpoint, or a route through `C2c_relay_connector`. Legacy relay
aliases, Ed25519 TOFU, connector outboxes, protocol-version constants, and
global storage are ineligible for Threads. Shared low-level HTTP/TLS code must
sit below separate `Threads_home_auth`, `Threads_home_routes`, and
`Threads_home_store` boundaries and pass cross-tenant isolation tests.

A local-only thread can use a home embedded in `threadsd`. Enterprise and
cross-host threads use the tenant delivery service. Hosted HA uses one
quorum-backed database leader/term; clients queue locally instead of electing
a second home. A home receipt includes its term and a hash-chain predecessor.
Conflicting signed histories suspend the thread and raise a fork alert.

### 5.3 Agent adapter

An adapter maps safe thread messages to Claude, Codex, OpenCode, Pi, Grok,
agy, or another host. It does not receive MLS private keys or local grant
records. It preserves thread/event/request IDs and labels content as
third-party data.

Adapter delivery is persist-first:

1. `threadsd` durably ingests and decrypts an event.
2. It records a presentation attempt keyed by event ID.
3. The adapter passively presents a notification, or injects data only at a
   safe boundary in an already-active, locally authorized client turn.
4. It records `client_consumed` only after the host acknowledges the
   presentation boundary available on that client.

Where a host lacks idempotent injection, the adapter documents an at-least-once
ambiguous crash window instead of claiming exactly once.

Remote arrival never calls a host API that creates, resumes, or submits a
model turn. Passive presentation may update an inbox/UI/file watched for
display, but wake and turn submission remain separately local. A restricted
worker is constructed only after that local trigger and receives an
event-bound reply capability, not the endpoint client's general tool registry.

### 5.4 Dedicated worker

An existing full-power coding session is never repurposed as a restricted
Threads worker. `threadsd` launches a clean-context worker with only:

- the selected proposal/task and thread context;
- the permitted multimodal message parts;
- tool descriptors permitted by the work order;
- a private tool socket or inherited one-use capability descriptor.

At `NONE`, there is no workspace mount and no tool socket. For other levels,
the model can request typed operations, but enforcement occurs in the trusted
gateway and sandbox beneath it.

## 6. Identity, tenancy, and key hierarchy

### 6.1 Identifiers

All security identifiers are CSPRNG-generated values with typed prefixes.
They are case-sensitive and never user-chosen. The grammar is exactly the
listed prefix followed by unpadded base64url: 16 random bytes encode as 22
characters and 32 random bytes as 43 characters.

| Prefix | Bytes | Uniqueness scope | Meaning |
|---|---:|---|---|
| `tn_` | 16 | identity service | tenant/security boundary |
| `pr_` | 16 | tenant | human or service principal |
| `ag_` | 16 | tenant | stable agent profile |
| `dv_` | 16 | tenant | enrolled device/workload |
| `si_` | 16 | tenant | ephemeral `agent_instance_id` |
| `mi_` | 16 | route | one device's membership incarnation |
| `th_` | 16 | tenant | `c2c_thread_id` (not a Codex app-server thread) |
| `rt_` | 16 | tenant/home | opaque home routing thread ID |
| `fr_` | 16 | route/uploader device | stable outer-frame retry ID |
| `ev_` | 16 | c2c thread | immutable encrypted event |
| `hc_` | 16 | route | home-visible governance control record |
| `rq_` | 16 | c2c thread | conversational request |
| `kp_` | 16 | tenant/home | one-use KeyPackage reference |
| `ap_` | 16 | c2c thread | inert action proposal |
| `iv_` | 32 | tenant/home | invitation record (bearer secret is separate) |
| `gr_` | 32 | host-local authority store | local grant |
| `wo_` | 32 | host-local authority store | local work order |
| `bl_` | 32 | tenant/home | random blob handle |
| `up_` | 32 | tenant/home | expiring upload handle |

`alias` and `display_name` remain useful UX fields. They never appear alone in
an authorization decision or unique constraint.

OCaml represents every row above with a private, non-interchangeable abstract
ID type; handlers cannot pass an alias, Codex thread ID, or c2c session ID
where an identity ID is required. Protocol fields and mixed adapter records
use the explicit names `c2c_thread_id`, `agent_instance_id`, and
`codex_thread_id`. The shorter terms “thread” and “session” in prose are not
wire-field names.

### 6.2 Enterprise chain

The enterprise chain is:

```text
tenant trust bundle
  -> human/service principal (OIDC issuer + subject)
  -> registered agent profile and owner
  -> enrolled device/workload certificate
  -> short-lived agent-instance / MLS leaf certificate
```

- OIDC authenticates the operator during enrollment. Long-lived OIDC bearer
  tokens are not put in messages.
- SCIM synchronizes users and groups into the directory. Group claims are
  versioned snapshots, not mutable strings copied into capability tokens.
- A SPIFFE-compatible X.509 SVID is the preferred workload certificate. The
  URI SAN identifies one tenant/device/agent instance.
- MLS uses an X.509 credential whose end-entity public key equals the MLS leaf
  signing key. The MLS Authentication Service validates the chain, tenant,
  expected principal/agent/device reference IDs, expiry, and revocation before
  accepting a KeyPackage, Add, Update, or Commit.
- Transport mTLS and MLS leaf signing use different keys and certificates.
- Capability/work-order signing uses a separate host-local admin key.

Certificates are short-lived. A certificate refresh updates the MLS leaf
before expiry. User/group disablement stops new sessions immediately and
triggers configured removals from active threads; removal commits rotate the
MLS epoch.

### 6.3 Local development profile

Local development creates a synthetic tenant and local CA under the global
Threads state root. Pairing requires explicit fingerprint confirmation. This
profile is shown as `local-dev`, is not called enterprise-verified, and cannot
federate unless an operator explicitly enrolls it into a tenant.

Existing c2c Ed25519 identities may help import a display alias or bootstrap a
local fingerprint exchange. They are not silently promoted into enterprise
principal credentials.

### 6.4 Key storage and recovery

- Hardware-backed keys or the OS key store are preferred for device/admin
  identity.
- MLS secret state and sensitive database columns are encrypted with a local
  state key obtained from the OS key store. A mode-`0600` file fallback is
  development-only and reported as degraded by `c2c doctor`.
- Plaintext message archives are off by default. Stored application events and
  blobs remain ciphertext; decrypted presentation caches are bounded and
  short-lived.
- Backups contain encrypted state plus a monotonic signed checkpoint. Restoring
  state behind the last witnessed epoch/counter requires a rejoin; it never
  silently resumes an old ratchet.
- Organization recovery, if required, is an explicit MLS recovery participant
  or a visibly negotiated export participant. The Threads home never holds a hidden
  decryption key.

## 7. Thread lifecycle and membership

### 7.1 State machine

```text
OFFERED --all required accepts--> ACTIVE
   |--reject---------------------> REJECTED
   `--TTL------------------------> EXPIRED

ACTIVE --membership/credential change--> SUSPENDED --valid commit--> ACTIVE
ACTIVE --close--------------------------> CLOSING --ack/deadline--> CLOSED
ACTIVE/SUSPENDED/CLOSING --security revoke-------------------------> REVOKED
```

`REJECTED`, `EXPIRED`, `CLOSED`, and `REVOKED` are terminal. Reopening creates
a new `c2c_thread_id`, MLS group ID, KeyPackages, and invitation. A minimal
terminal-ID tombstone is retained permanently so the identifier can never be
accepted again. Participant fingerprints and other retention-sensitive fields
may age out, but a keyed hash of the ID, terminal state, final epoch/home
sequence, and terminal timestamp remains.

### 7.2 Create and accept

1. The initiator resolves exact agent/device identities and fetches fresh,
   signed MLS KeyPackages.
2. It validates each credential and atomically consumes each KeyPackage
   reference at the home.
3. It creates a random MLS group, adds invitees, and produces a Welcome.
4. The home stores a principal-bound, expiring `thread.offer` and Welcome.
5. An invitee validates the enterprise identity chain, full offer transcript,
   group policy hash, and expected participants before exposing an accept UI.
6. `accept` or `reject` binds the exact offer ID and transcript hash.
7. Application traffic is refused until all participants required by policy
   have accepted and the thread becomes `ACTIVE`.

An invite link, where supported, contains a 256-bit random secret in addition
to an authenticated intended principal. The home stores only its keyed hash,
consumes it transactionally once, and requires proof of the intended instance
key. A short human code is only a comparison/PAKE input, never a low-entropy
bearer credential.

### 7.3 Membership changes

- Thread governance is fixed in the accepted policy: creator-admin, named
  admins, or a quorum. It is independent of local workspace grants.
- A member add/remove starts with governance approvals signed by the required
  admin device keys. Each approval binds the proposal hash, old and target
  roster hashes, current epoch, expected successor epoch, policy hash, commit
  hash, and one-use nonce. The home stages this record before the matching MLS
  Commit. Endpoints validate the threshold and every binding before advancing
  MLS state. An unauthorized, missing, stale, or conflicting Commit is
  quarantined without state advancement.
- Application sends pause in `SUSPENDED` until the staged roster control and
  matching Commit are accepted and applied in `home_seq` order.
- Device replacement is a new MLS leaf; session IDs and old keys are never
  reused.
- Removing a device revokes local grants bound to that device and rotates the
  MLS epoch before further application traffic.
- New members do not decrypt prior epochs. Optional history transfer is a
  visible, policy-authorized encrypted snapshot event produced by a current
  member, not a server backdoor.
- Credential expiry/revocation follows MLS Authentication Service rules; a
  valid successor credential must preserve the expected agent/device identity.

The home maintains a transport roster without decrypting MLS content. Roster
and close transitions use a separate authenticated `home_control` envelope:

```json
{
  "control_version": 1,
  "control_id": "hc_...",
  "kind": "roster_transition",
  "tenant_id": "tn_...",
  "routing_thread_id": "rt_...",
  "prior_roster_sha256": "sha256:...",
  "target_roster_sha256": "sha256:...",
  "prior_mls_epoch": 12,
  "successor_mls_epoch": 13,
  "mls_commit_sha256": "sha256:...",
  "governance_policy_sha256": "sha256:...",
  "nonce": "...",
  "approvals": [
    {"device_id": "dv_...", "key_id": "...", "signature": "..."}
  ]
}
```

Approvals sign the JCS object with `approvals` omitted. The Threads home
validates enrolled device keys and the already accepted governance threshold,
then atomically assigns adjacent `home_seq` values to the control and exact
MLS Commit. The old roster can fetch both; the target routing roster becomes
effective only after the Commit sequence. Endpoints independently compare the
control, Commit, MLS state, and encrypted roster proposal before applying.
`close` uses the same envelope and threshold with a terminal-state hash.
Conflicting transitions suspend the route and do not advance its roster.

### 7.4 Closure

Because the home cannot see encrypted relation kinds, `CLOSING` admits a
bounded number/byte budget of opaque MLS application frames until the accepted
close deadline. Endpoints accept only delivery receipts, closure control, and
final responses to already-open conversational requests; they quarantine new
requests or proposals. This avoids leaking semantic classes merely to enforce
closure.
Closing:

- admits opaque application frames only until the governance-signed
  count/byte/deadline bound is exhausted, then rejects them; `CLOSED` rejects
  all new frames;
- destroys retained current-epoch secrets after the configured offline grace;
- expires queued blobs/events according to retention policy;
- writes and witnesses the terminal tombstone.

Inbound close is messaging control, not local authority. It cannot revoke a
grant, cancel a work order, kill a process, or discard an overlay. It bounds
and then closes future transport admission as specified above and becomes an
inert local authority-plane notice.
Existing locally authorized work follows its work-order deadline unless a
local operator/admin decision separately revokes it. A `security revoke`
transition may kill local work only when its source is host-local policy or a
locally trusted identity-revocation service, never a peer event.

## 8. Message plane: events, requests, and responses

### 8.1 Outer delivery frame

The API uses strict JSON; MLS messages retain their RFC-defined binary wire
format inside base64url. The home-visible frame contains routing and bounded
integrity metadata, not plaintext sender names, MIME types, filenames, message
relations, or content hashes:

```json
{
  "protocol": "c2c.threads",
  "version": 1,
  "tenant_id": "tn_A4...",
  "routing_thread_id": "rt_7m...",
  "frame_id": "fr_J8...",
  "frame_class": "mls_application",
  "mls_epoch": 12,
  "created_at_ms": 1784172345000,
  "expires_at_ms": 1784258745000,
  "ciphertext_sha256": "sha256:...",
  "ciphertext_b64": "...",
  "blob_refs": [
    {"storage_digest": "sha256:...", "ciphertext_size": 48191}
  ],
  "blob_refs_sha256": "sha256:<JCS(blob_refs)>",
  "critical_extensions": []
}
```

`frame_id` is generated once by the uploader and is stable for the exact
ciphertext retry. The home deduplicates only metadata it can authenticate:
`(tenant_id, routing_thread_id, uploader_device_id, frame_id)`. The same key
and ciphertext hash returns the original `home_seq` and signed receipt; the
same key with a different hash is `frame_id_conflict`. The home never attempts
to deduplicate on encrypted `event_id`, `sender_seq`, request ID, or
idempotency key. Those constraints are enforced by endpoints after decrypt.

The MLS `authenticated_data` field is the RFC 8785 canonical encoding of:

```json
{
  "aad_version": 1,
  "protocol": "c2c.threads",
  "version": 1,
  "tenant_id": "tn_A4...",
  "routing_thread_id": "rt_7m...",
  "frame_id": "fr_J8...",
  "frame_class": "mls_application",
  "mls_epoch": 12,
  "created_at_ms": 1784172345000,
  "expires_at_ms": 1784258745000,
  "blob_refs_sha256": "sha256:<JCS(blob_refs)>",
  "critical_extensions": []
}
```

After MLS authentication, every endpoint byte-compares these values with the
received outer frame and recomputes the complete ordered blob-reference
digest. A mismatch is quarantined. `ciphertext_sha256` and `ciphertext_b64`
are necessarily outside this object; MLS authenticates the ciphertext and the
signed home receipt binds its exact hash.

The authenticated upload connection identifies the sender device to the home.
MLS authenticates the group sender to recipients. The outer frame does not add
a second long-term author signature that would expose the sender and duplicate
MLS. The home returns a signed commit receipt binding:

```text
tenant_id, routing_thread_id, frame_id, MLS epoch,
ciphertext hash, home term, home_seq, accepted_at_ms,
previous_commit_hash, commit_hash
```

Clients exchange the latest home receipt hash inside encrypted application
messages. Divergent receipts reveal a fork to participants; an enterprise
witness makes truncation/fork evidence durable outside the home.

Unknown major versions, duplicate JSON keys, malformed UTF-8, excessive
nesting, unknown critical extensions, and fields outside declared bounds are
rejected. Unknown non-critical extensions are preserved end to end.

### 8.2 Encrypted application payload

The MLS `PrivateMessage` plaintext is canonical JSON generated by the local
gateway, with integer timestamps and no duplicate keys:

```json
{
  "content_version": 1,
  "c2c_thread_id": "th_R2...",
  "event_id": "ev_V9...",
  "sender": {
    "principal_id": "pr_...",
    "agent_id": "ag_...",
    "device_id": "dv_...",
    "agent_instance_id": "si_..."
  },
  "sender_seq": 87,
  "created_at_ms": 1784172345000,
  "relation": {
    "kind": "message",
    "in_reply_to": null,
    "request_id": null,
    "response_index": null,
    "final": null
  },
  "parts": [
    {
      "part_id": "p1",
      "media_type": "text/plain; charset=utf-8",
      "disposition": "inline",
      "inline_text": "Please review the attached graph."
    }
  ],
  "extensions": {},
  "critical_extensions": []
}
```

The gateway verifies that the encrypted sender IDs match the authenticated MLS
leaf credential. It rejects a mismatch even when decryption succeeds.

Initial limits:

- 256 KiB maximum encrypted application frame;
- 64 KiB maximum inline text/JSON part;
- 32 parts per event;
- JSON nesting depth 16;
- all IDs at most 128 ASCII characters and validated by type;
- no floating-point security fields.

### 8.3 Relation kinds

Supported v1 relation kinds are:

- `message`: ordinary conversation.
- `reply`: conversational reply with `in_reply_to`.
- `request`: asks named responders for one or more responses.
- `response`: correlated response; still an ordinary message, not an RPC
  return value.
- `action_proposal`: inert peer proposal for a possible local work order.
- `action_result`: sanitized result emitted by a locally completed work order.
- `receipt`: encrypted endpoint receipt.
- `control`: thread-level application control coordinated with MLS changes.

No relation kind is authority to call a tool or resolve a host approval.

### 8.4 Request/response correlation

A request adds:

```json
{
  "request_id": "rq_...",
  "responders": ["ag_..."],
  "response_mode": "single",
  "deadline_ms": 1784175945000
}
```

A response binds the request and request event:

```json
{
  "request_id": "rq_...",
  "in_reply_to": "ev_request...",
  "response_index": 0,
  "final": true,
  "status": "ok"
}
```

Rules:

- A `request_id` is unique in one thread and bound to exactly one request
  event.
- Streams are ordered independently per `(request_id, responder_agent_id)`
  from index zero.
- There is at most one final response per responder. An identical event retry
  is deduplicated; a different second final is quarantined.
- Unknown requests, unauthorized responders, skipped indexes, and responses
  after terminal expiry are quarantined with bounded diagnostics.
- `cancel` is advisory and cannot interrupt a host turn or process.
- Deadline expiry is local state. The broker never fabricates a peer response.
- Receipt, response, and effect completion are distinct concepts.

### 8.5 Normative schema bundle

The JSON snippets in this document illustrate the contract; implementation
starts by checking in the normative JSON Schema 2020-12 bundle under
`data/threads/schema/v1/` and generated OCaml codecs/golden vectors. The bundle
contains at least:

| Schema ID | Contract |
|---|---|
| `outer-frame-v1` | Required routing fields, `frame_class` (`mls_application`, `mls_handshake`, `home_control`), exact ciphertext/blob hashes, limits, and MLS authenticated-data comparison |
| `application-event-v1` | Sender, event/order fields, relation tagged union, ordered content-part tagged union, and extensions |
| `thread-offer-v1` / `thread-decision-v1` | Principal-bound offer, policy/roster transcript, KeyPackage/Welcome references, expiry, and exact accept/reject binding |
| `home-control-v1` | Roster/close tagged union, governance threshold approvals, commit/roster/policy hashes, nonce, and transition bounds |
| `sync-request-v1` / `sync-response-v1` | Route, cursor, limit, ordered frame/tombstone/boundary union, next cursor, `has_more`, and signed chain head |
| `transport-ack-v1` | Device, persisted-through sequence, sorted non-overlapping missing ranges, and prior receipt hash; never an application event |
| `endpoint-receipt-v1` | Receipt enum, referenced event/frame, actor, timestamp, and optional bounded diagnostic |
| `blob-*-v1` | Prepare/chunk/commit/fetch request and response bodies, hashes, quotas, entitlement, expiry, and idempotency semantics |
| `directory-profile-v1` | Signed leased public fields, capability/media limits, sequence, and expiry |
| `problem-v1` | Stable code, correlation ID, `retryable`, optional `retry_after_ms`, and bounded non-sensitive message |

For all schemas:

- `required` and `additionalProperties: false` are explicit at every object.
  Extensibility exists only inside bounded `extensions` maps and declared
  critical-extension arrays. Optional fields are omitted; `null` is accepted
  only where the schema union says so.
- Security IDs use a schema-specific prefix and 128-bit-or-greater base64url
  payload. Event-local `part_id` uses `p[1-9][0-9]{0,2}`. Strings, arrays,
  maps, nesting, Unicode normalization policy, enums, and byte sizes have
  explicit minima/maxima.
- JSON integers, including timestamps, sequence numbers, epochs, chunk
  indexes, and budgets, are in `0..9007199254740991`. V1 rejects exhaustion;
  a future version uses canonical decimal strings rather than silently losing
  precision. Floating-point values are forbidden in signed/hashed objects.
- Every derived hash declares its exact input. Object hashes use
  `SHA-256("c2c.threads/<schema-id>\0" || JCS(object-with-derived-hash-and-
  signature-fields-omitted))`; raw ciphertext/container/chunk hashes use the
  exact bytes. Arrays retain order. Signatures use the same domain-separated
  JCS input with the signature collection omitted.
- Decoders reject duplicate keys before schema validation. Encode/decode and
  canonicalize/parse are differential-tested across OCaml, the MLS bridge,
  and one independent implementation.

Each schema ships golden valid/minimum/maximum vectors, canonical bytes,
hash/signature inputs, and invalid vectors for duplicate/unknown fields,
boundary overflow, wrong unions, reordered or overlapping ranges, and altered
critical extensions. No network handler is implemented before its schema and
vectors exist.

HTTP mapping is also normative: malformed/unsupported input is `400`, failed
authentication `401`, policy denial `403`, uniform absent-or-cross-tenant
lookup `404`, idempotency/state/epoch conflict `409`, terminal resource `410`,
size limit `413`, authenticated but quarantined semantic/crypto input `422`,
quota/rate limit `429`, and transient home failure `503`. Only `429`/`503` and
explicitly classified transport failures are automatically retryable; the
`problem-v1` body and `Retry-After` agree.

## 9. Cryptography and replay safety

### 9.1 MLS profile

All direct and group threads use MLS 1.0 `PrivateMessage` framing.

- Mandatory suite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
  (`0x0001`), the MLS 1.0 mandatory-to-implement suite.
- Enterprise FIPS profile may require
  `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` (`0x0002`) if the selected,
  validated provider supports it.
- The suite is fixed when the thread is created. An unsupported or
  policy-forbidden suite is a hard failure, never a downgrade.
- Use an audited MLS implementation behind `C2c_threads_crypto.S`; do not
  implement TreeKEM, HPKE, or the MLS key schedule in project OCaml.
- The initial provider target is a pinned OpenMLS build behind a narrow C ABI
  or isolated helper. It must pass RFC/library vectors and cross-implementation
  interop before release.
- KeyPackages are one-use and replenished before exhaustion.
- Use bounded skipped-generation caches and reject enormous generation gaps
  to prevent key-derivation DoS.
- Send an Update/Commit on membership change, credential rotation, suspected
  compromise, and at a tenant-configured time/message interval.

TLS 1.3 with server authentication and device mTLS is still required around
MLS transport to reduce metadata exposure, injection, and selective-delivery
attacks. TLS 0-RTT is disabled for all state-changing endpoints because of its
replay properties.

### 9.2 Associated context

The encrypted application payload and validated MLS credential together bind:

```text
protocol and content version
tenant and thread/group ID
MLS epoch and authenticated leaf
principal/agent/device/session IDs
event ID and sender sequence
relation kind and reply/request pointers
attachment ciphertext digest, size, part ID, and media type
critical extension set
```

The home receipt separately binds routing, exact MLS ciphertext, and
`home_seq`. Changing any bound field fails validation or AEAD authentication.

### 9.3 Replay and crash rules

- `threadsd` serializes MLS operations through one in-process actor per group.
- Outbound protection operates on a cloned MLS state. One SQLite transaction
  compare-and-swaps the old state version to the new encrypted state, reserves
  `sender_seq`, and persists the exact ciphertext/outbox row. Only after commit
  may transport begin.
- Retries resend the exact persisted ciphertext. They never call MLS protect a
  second time for the same event.
- Inbound ingestion atomically persists the advanced MLS state, used
  generation/replay tombstone, event row, and delivery state before presenting
  plaintext.
- Endpoint post-decrypt unique constraints cover
  `(c2c_thread_id, epoch, sender_leaf, generation)`, `event_id`, and
  `(c2c_thread_id, sender_device, idempotency_key)`. The opaque home uses only
  its outer-frame uniqueness key defined in Section 8.1.
- Same idempotency key and same canonical payload hash returns the prior
  result. Same key with a different hash returns `idempotency_conflict`.
- Frames from old epochs are rejected after the bounded offline/skipped-key
  window; removed members never regain a current key.
- A state rollback behind a witnessed checkpoint forces rejoin/recovery.
- Resume tickets are short-lived, rotating, device-bound, and single-use.

No timestamp alone is a replay defense. Epochs, generations, random IDs,
unique constraints, and consumed-state records are authoritative; time only
bounds retention and expiry.

### 9.4 Privacy at rest

- Relay/home stores only MLS ciphertext, encrypted blobs, routing handles,
  quotas, sequence metadata, and receipts.
- Local event rows remain ciphertext. Decrypted content is passed through a
  bounded locked-memory buffer. If an adapter requires spill, it uses an
  application-encrypted temporary row under the state key; mode bits alone do
  not make a plaintext cache acceptable. Decrypted content is never written
  to a plaintext archive.
- MLS state, blob keys, grant details, and sensitive audit fields are
  application-encrypted under an OS-keystore state key.
- Filenames, MIME types, alt text, plaintext hashes, reply relations, and
  request IDs stay inside MLS ciphertext.
- Optional padding buckets reduce size leakage but are a deployment policy;
  timing and routing metadata remain visible.

## 10. Reliable delivery and ordering

### 10.1 Guarantees

Threads promises:

- at-least-once network delivery;
- exactly-once durable home admission for one authenticated outer-frame key;
- exactly-once endpoint append for one decrypted event/idempotency key;
- per-routing-thread total home order through `home_seq`;
- per-sender authenticated order through MLS generation and `sender_seq`;
- eventual delivery while the home, recipient membership, retention window,
  and quota remain valid.

Threads does not promise:

- exactly-once model attention;
- exactly-once transcript injection on a host without an idempotent API;
- exactly-once arbitrary command execution across process or host crashes;
- availability against a malicious home that withholds traffic.

### 10.2 Sender flow

1. Validate thread state, membership, epoch, payload, blobs, and local quota.
2. Generate stable `event_id` and idempotency key once.
3. Canonicalize payload, advance cloned MLS state, and persist the new state,
   ciphertext, and outbox row in one transaction.
4. Send with bounded exponential backoff and jitter.
5. Home transaction authenticates the device, checks tenant/transport-roster
   membership/epoch, deduplicates the stable outer frame key and ciphertext
   hash, allocates `home_seq`, writes frame/delivery/blob references, advances
   its hash chain, and commits. It does not inspect encrypted event IDs or
   application idempotency keys.
6. Only after durable commit does the home return `accepted`.
7. Sender records the signed receipt and removes the retry claim.

### 10.3 Recipient flow

Sync is cursor based and non-destructive:

```text
home_sync(routing_thread_id, membership_incarnation_id,
          after_home_seq, limit) -> frames, next_cursor
home_ack(routing_thread_id, membership_incarnation_id,
         persisted_through, selective_missing_ranges)
```

The client maps the opaque `routing_thread_id` to `c2c_thread_id` only inside
encrypted local state. Home APIs, deliveries, cursors, and blob entitlements
never use encrypted `c2c_thread_id`, `event_id`, request ID, or `part_id`.

Recipients buffer only bounded gaps and apply events strictly in contiguous
`home_seq` order. A gap triggers fetch/NACK. An event may be skipped only after
a signed home tombstone proves it expired or was administratively removed.
Such a tombstone is valid only for an application frame and binds the omitted
`home_seq`, routing thread, exact ciphertext hash, expiry/removal reason, and
prior receipt-chain hash. A missing control or MLS Commit can never be skipped;
it suspends the thread and requires recovery/rejoin.

The home records `visible_from_seq` and `visible_through_seq` for every device
membership incarnation. Every transport frame in that interval is fetchable
by that device; the log never selectively hides a sequence inside an interval.
A signed membership-start boundary lets a new member initialize its cursor at
`visible_from_seq - 1`, and a removed member receives through the matching
removal Commit. This preserves a global sequence without granting history.
Per-recipient transport ACKs/delivery rows are outside the sequenced event
log. Only explicit group-visible receipt events consume `home_seq`.

### 10.4 Receipt meanings

Receipt names are precise:

- `accepted`: home durably committed and assigned `home_seq`.
- `endpoint_persisted`: recipient `threadsd` durably stored the frame.
- `client_consumed`: recipient adapter advanced its presentation ledger.
- `read`: optional explicit human/agent signal, disabled by default.
- `expired`: delivery TTL elapsed and a terminal delivery record/DLQ exists.
- `quarantined`: authentication, epoch, schema, media, or policy validation
  failed; content was not presented.

Cumulative ACKs plus selective missing ranges avoid receipt storms. Receipts
are encrypted application events where participant visibility is appropriate;
home-level `accepted` receipts are signed transport metadata.

### 10.5 Backpressure and limits

The home enforces tenant, sender, recipient, thread, event-byte, blob-byte,
outstanding-event, and request-rate quotas before expensive work. Clients
bound:

- gap buffer count and bytes;
- skipped MLS generations;
- retry age and attempt count;
- decompressed/decoded media size;
- local outbox and DLQ size;
- audit label cardinality.

Quota failure is explicit and durable where an already accepted event expires;
there is no silent truncation or deletion.

## 11. Multimodal content and encrypted blobs

### 11.1 Supported v1 media

At minimum:

- `text/plain; charset=utf-8`
- `text/markdown; charset=utf-8`
- `application/json`
- `image/png`
- `image/jpeg`
- `image/webp`
- `image/svg+xml`
- `application/vnd.c2c.graph+json;version=1`
- `text/vnd.mermaid`
- `text/vnd.graphviz`

Text/JSON up to the inline cap can be embedded directly. Binary parts are
never base64-expanded inside the application event.

### 11.2 Blob manifest

Blob metadata lives inside the encrypted application payload:

```json
{
  "part_id": "p2",
  "media_type": "image/png",
  "disposition": "inline",
  "name": "terminal.png",
  "alt_text": "terminal showing a failed test",
  "blob": {
    "blob_id": "bl_...",
    "storage_digest": "sha256:<ciphertext-container>",
    "content_digest": "sha256:<plaintext>",
    "plaintext_size": 48123,
    "ciphertext_size": 48191,
    "chunk_size": 1048576,
    "chunk_count": 1,
    "aead": "aes-256-gcm-chunks-v1",
    "nonce_prefix_b64": "<8 random bytes>",
    "blob_key_b64": "<32 random bytes>"
  }
}
```

The outer frame exposes only storage digest and ciphertext size needed for
delivery admission.

### 11.3 Encryption and chunking

- Generate a fresh random 256-bit data key for every blob, even for identical
  plaintext.
- Encrypt 1 MiB chunks with AES-256-GCM. The 96-bit nonce is an 8-byte random
  per-blob prefix plus a 32-bit big-endian chunk index. A key is never reused
  across blobs and a chunk index is never repeated.
- AEAD associated data binds version, tenant, thread, event, part, media type,
  declared sizes, chunk index, and chunk count.
- `content_digest` is verified after decrypt but remains encrypted in the MLS
  manifest. `storage_digest` covers the complete encrypted container.
- Equal plaintext therefore produces unrelated home-visible digests.
- Use a reviewed crypto provider and golden vectors for the container. If the
  provider cannot guarantee the construction, ship no blob support rather
  than replace it with unauthenticated streaming.

### 11.4 Upload/download protocol

```text
prepare -> idempotent chunk PUTs -> commit -> reference in event
```

- `prepare` authenticates the tenant/device, reserves quota, returns a random
  upload ID, and expires quickly.
- A chunk PUT is idempotent on `(upload_id, index, ciphertext digest)`; a
  different body for the same tuple is a conflict.
- `commit` validates all chunk hashes, total size, container digest, and quota
  in one transaction.
- The home rejects an event referencing an uncommitted or wrong-tenant blob.
- At frame admission the home atomically creates one entitlement per ordered
  outer `blob_refs[index]` and eligible recipient membership incarnation. The
  key is `(tenant_id, routing_thread_id, home_seq/frame_id, blob_ref_index,
  storage_digest, recipient_device_id, membership_incarnation_id)`. It uses no
  encrypted event or part identifier. Current or former membership by itself
  is never sufficient; knowing `storage_digest` or `blob_id` is not
  authorization.
- Download authorization is short-lived and bound to that exact entitlement.
  After decrypt, the endpoint verifies that the index/digest is bound by MLS
  authenticated data to the encrypted event/part manifest. Public object URLs
  are never generated.
- Transactional `blob_refs` drive retention, legal hold, and mark/sweep GC.

Initial defaults reuse the existing proposal's conservative caps: 4 MiB per
blob and 8 MiB total per event. Chunking permits a tenant to configure larger
limits without whole-object buffering.

### 11.5 Safe media handling

- MIME is allowlisted and independently sniffed. A mismatch is quarantined or
  presented as opaque bytes, never trusted by extension/name.
- Images enforce input bytes, decoded dimensions, pixel count, frame count,
  recursion, and decompression-ratio limits.
- SVG is active content. It is never injected as raw browser DOM and never
  resolves scripts, styles, fonts, URLs, `foreignObject`, entities, or file
  references. Render only through a no-network parser sandbox to a raster, or
  present inert source.
- Mermaid and Graphviz are inert text. Rendering happens in the same bounded
  no-network sandbox.
- The graph JSON schema contains bounded nodes and edges with scalar
  attributes only; it forbids HTML, scripts, executable URLs, and renderer
  directives. Suggested defaults are 10,000 nodes and 20,000 edges.
- Unsupported media remains an inert attachment descriptor. It is not
  silently converted, opened, or fed to a model.
- External URLs are never auto-fetched.
- Inbound blobs never materialize in the workspace automatically. Importing a
  blob is a separate `WRITE` operation and work order.
- Malware/DLP inspection occurs at authorized endpoints before encryption or
  after decryption. Server-side plaintext scanning is incompatible with E2EE
  unless a visible scanner participant is added.

### 11.6 Client negotiation

Directory and thread-accept profiles advertise supported media types and
adapter limits. A sender may still send an allowed type unsupported by one
adapter; that adapter preserves the event and presents a safe descriptor.

At `NONE`, communication attachments may be shown to the model because they
are peer-supplied message content, not local workspace access—but only inside
an independently local-authorized turn after media validation. Attachment
arrival itself never starts that turn. This never grants the peer a local file
read or imports the attachment into the root.

## 12. Authority plane and permission model

### 12.1 Why the planes must be separate

The existing B098 rule is load-bearing: c2c is a bus, not an RPC surface. A
peer message cannot approve, execute, write, or resolve a host dialog. A
conventional remote filesystem API inside the inbox would delete that
invariant.

Threads therefore uses:

1. A message plane carrying conversation, `action_proposal`, and
   `action_result` data.
2. A host-local authority plane carrying grants and work orders. It is exposed
   only through an operator/admin socket or UI requiring local authority and
   is never an MCP tool available to a peer-controlled model.

An action proposal does not open an approval prompt, start a worker, mint a
grant, or consume a prior approval. The operator explicitly selects a stored
proposal and creates a work order. Unattended message-triggered automation is a
different future product and requires an explicit revision of B098.

`NONE` is an access ceiling, not wake authority. Receipt of a local or remote
Threads event does not itself start a model turn. A response can be produced
only inside a turn that the receiving host has independently authorized (for
example, an already-active client or an operator-started clean worker). Under
the current B098 exception, only eligible local-broker mail may use the
existing gated Codex auto-turn path; a remote Threads event is queued and
presented without auto-turn. Push notifications, hooks, retries, attachment
completion, and presence changes cannot widen this rule.

### 12.2 Permission presets

The UX remains simple and cumulative:

| Level | Effective ceiling |
|---|---|
| `NONE` | Conversation input and recipient-fixed response only. No workspace, tools, local memory, arbitrary MCP, shell, or host send capability. |
| `READ` | `NONE` plus bounded list/stat/read of allowed regular files below one pinned root. |
| `WRITE` | `READ` plus transactional create/replace of allowed regular files. Delete, rename, chmod, links, and protected paths remain denied unless separately caveated. |
| `EXECUTE` | `WRITE` plus named command profiles in a verified sandbox. |

No level implies:

- network or DNS;
- host home, other repositories, or parent directories;
- credentials, environment secrets, SSH agents, cloud metadata, Docker,
  sockets, devices, keyrings, GUI, or TTY;
- package installation;
- arbitrary executable paths, shell strings, plugins, hooks, or MCP servers;
- destructive operations outside the exact work-order caveats.

Each endpoint grants independently to one authenticated remote device/session.
A peer's requested or advertised level is data only.

### 12.3 Effective-policy intersection

Effective rights are the intersection of:

```text
hard platform safety
AND tenant maximum
AND IdP group policy
AND endpoint-local grant
AND exact work-order scope
AND current peer device/session membership
AND current subject membership incarnation and credential
AND path/command allowlists
AND verified sandbox capabilities
AND remaining time/use/resource budgets
```

Denies win. Unknown level/version, invalid signature, identity/key change,
expired record, root replacement, stale epoch, exhausted budget, unsupported
sandbox, audit failure, or contradictory policy resolves to deny/`NONE`.
Trust tiers (`same_repo`, `same_host`, `relay`) may inform display risk; they
never grant rights.

### 12.4 Local grant

A grant is local-only, signed, proof-of-possession bound, and never sent to the
peer or model transcript:

```json
{
  "version": 1,
  "grant_id": "gr_<256-bit-random>",
  "c2c_thread_id": "th_...",
  "subject": {
    "tenant_id": "tn_...",
    "principal_id": "pr_...",
    "agent_id": "ag_...",
    "device_id": "dv_...",
    "agent_instance_id": "si_...",
    "mls_leaf_fingerprint": "sha256:...",
    "membership_incarnation_id": "mi_..."
  },
  "root": {
    "display_path": "/work/project",
    "device": 123,
    "inode": 456,
    "mount_id": 7
  },
  "ceiling": "READ",
  "path_policy_hash": "sha256:...",
  "command_policy_hash": "sha256:...",
  "sandbox_profile_hash": "sha256:...",
  "issued_epoch": 12,
  "not_before_ms": 1784172345000,
  "expires_at_ms": 1784175945000,
  "max_jobs": 1,
  "issuer_key_id": "admin-key-7",
  "signature": "..."
}
```

Defaults are one job and a short TTL. `EXECUTE`, long-lived, multi-job, delete,
or protected-path grants require an explicit tenant caveat and may require
fresh user presence or two-person approval.

The subject proves possession through the authenticated MLS leaf and work
session binding; there is no copyable bearer token. `issued_epoch` is audited
provenance, not an epoch lock. Ordinary Update/Commit epochs do not invalidate
a grant. Subject removal, device/leaf replacement, membership-incarnation
change, session replacement, or explicit host-local security revocation does.

### 12.5 Action proposal and work order

A peer may send:

```json
{
  "proposal_version": 1,
  "proposal_id": "ap_...",
  "summary": "Run the OCaml unit tests and return failures",
  "requested_ceiling": "EXECUTE",
  "operations": [
    {
      "op": "exec",
      "profile": "dune-test",
      "parameters": {"targets": ["@runtest"]}
    }
  ]
}
```

It remains inert. A local operator action creates a signed work order binding:

- exact proposal event ID and canonical content hash;
- grant, thread, remote device/session key, membership incarnation, and the
  proposal's MLS epoch as provenance;
- normalized operation types/parameters or bounded operation grammar;
- selected root identity and protected-path policy;
- base hashes for possible mutations;
- command and sandbox profile hashes;
- per-operation and aggregate byte/file/CPU/memory/PID/output/time budgets;
- one-use nonce, deadline, and issuer signature.

Work-order state is monotonic:

```text
pending -> claimed -> running -> succeeded | failed | ambiguous | cancelled
```

The executor durably moves to `claimed` and appends a pre-effect audit record
before any effect. A crash after a command starts but before its outcome is
durable becomes `ambiguous`; it never automatically starts again.

A host-local revocation prevents new operations, kills the work
cgroup/microVM, and drops an uncommitted overlay. It cannot undo a committed
write. Root identity change, expiry, grant exhaustion, locally verified
subject removal/key replacement, or an explicit operator/admin decision
revokes pending work. A peer close/remove proposal alone never does.

## 13. Filesystem confinement

### 13.1 Root pinning and path format

The operator selects one root. `threadsd` opens it once with
`O_PATH|O_DIRECTORY` and records `statx` device, inode, and mount identity.
Protocol paths are relative virtual POSIX paths.

Reject:

- absolute paths, NUL, `..`, empty components, excessive depth/length;
- alternate separators and platform-special forms;
- Windows drive/UNC/device/ADS or reparse forms on Windows;
- URL/percent/double encoding;
- paths targeting a changed root identity.

On Linux, resolve in one kernel operation from the root FD with `openat2` and:

```text
RESOLVE_BENEATH
| RESOLVE_NO_MAGICLINKS
| RESOLVE_NO_SYMLINKS
| RESOLVE_NO_XDEV
```

Use the returned FD for the operation. Never validate a path and reopen it by
string. Only regular files/directories are allowed. Reject symlinks,
hardlink-sensitive mutations, devices, FIFOs, sockets, mount crossings, and
magic links.

Creates use a verified parent dirfd, `O_CREAT|O_EXCL|O_NOFOLLOW`, fixed modes,
and `umask 077`. Rename/delete, when caveated, use `*at` calls against verified
dirfds.

### 13.2 Read rules

`READ` exposes only typed operations:

- `fs.list(relative_dir, cursor, limit)`;
- `fs.stat(relative_path)`;
- `fs.read(relative_path, offset, length, expected_hash?)`.

Default limits cover bytes per read/job, total disclosed bytes, directory
entries, file count, and file size. Sparse files, changing files, and special
files fail safely. Responses include content hash and observed metadata so the
worker can detect a concurrent change.

Protected read patterns should include credential/env files and framework
keys by default. Organizations can add repository-specific secret detection
and DLP, but must not imply that a generic filename list finds every secret.

### 13.3 Write rules and transactional apply

`WRITE` operates in a read-only snapshot/lower tree plus private writable
copy/overlay:

1. Worker changes only the private upper tree.
2. Trusted applier produces a manifest of relative paths, base hashes, result
   hashes, byte counts, and operations.
3. It re-resolves every path from the root FD.
4. Creates write and fsync a same-directory mode-`0600` temp, then install
   with `renameat2(RENAME_NOREPLACE)` or the platform equivalent and fsync the
   parent.
5. A replacement is automatic only under an enforceable exclusive workspace
   lease held across final identity/hash validation and commit, or through a
   filesystem/repository backend with a real versioned compare-and-swap.
   Hash-check followed by ordinary rename is not CAS. On generic POSIX with
   possible outside writers, replacement returns a patch/isolated-worktree
   merge proposal for a host-local applier instead of overwriting the target.
6. Conflict leaves the host file untouched and returns a structured conflict.

Copy-up/replacement prevents mutation through an existing outside hardlink.
Direct in-place writes are not part of the high-assurance profile.

Default protected mutation paths include:

```text
.git/**
.c2c/**
.claude/**
.codex/**
.opencode/**
.gemini/**
**/.env*
**/*credential*
**/*secret*
client/MCP configuration
hooks and signing configuration
CI/release workflows
agent instruction/policy files
```

These are conservative defaults, not a complete secret classifier. Delete,
rename, chmod, xattrs, symlink/hardlink creation, and protected paths require
separate signed work-order caveats.

## 14. Command execution sandbox

### 14.1 Args are not a security boundary

Checking that strings in `argv` look like local paths cannot contain an
arbitrary program. Programs synthesize paths, read configuration, interpret
response files, load plugins, execute hooks, spawn children, or access the
network without a path argument. OS containment is authoritative; argument
validation is defense in depth.

The peer/worker selects a named command profile and structured parameters,
never an executable path or shell command string.

### 14.2 Command profile

Each profile fixes:

- executable file descriptor, immutable package identity, and SHA-256 digest;
- direct `execveat`/equivalent, with no `PATH` search;
- typed parameter grammar and known flags;
- which parameters are workspace paths and their `/workspace/...` rewrite;
- fixed cwd;
- environment allowlist and private `HOME`/temporary directory;
- stdin type and byte cap;
- subprocess/workspace-executable policy;
- wall time, CPU, memory, PIDs, file descriptors, output, file-size, and I/O
  budgets;
- sandbox backend/profile hash.

Reject unknown flags, response-file syntax, shell `-c`, `eval`, command
substitution, alternate cwd/config/loader options, plugin/hook injection,
`LD_PRELOAD`/`DYLD_*`, proxy/credential variables, and inherited arbitrary
environment.

Workspace executables and scripts are off by default. If a profile permits
them, they execute only inside the sandbox and may not weaken the host boundary.

### 14.3 Linux high-assurance backend

At minimum:

- separate unprivileged UID/user namespace;
- private mount, PID, IPC, UTS, and network namespaces;
- pivot into a minimal immutable runtime;
- a per-work-order filtered snapshot visible as `/workspace`; it contains
  only read-allowed inputs and the private writable output overlay, with
  protected and ungranted paths absent rather than merely hidden by prompts;
- no host home, broker/thread state, keys, audit store, Docker socket, SSH
  agent, TTY, devices, or host `/proc`;
- empty network namespace by default;
- `PR_SET_NO_NEW_PRIVS` and all capabilities dropped;
- seccomp denial of mount, `setns`, namespace creation, `ptrace`, BPF, keyring,
  raw devices, and other escape surfaces;
- cgroup-v2 CPU, memory, PID, I/O, and wall-clock enforcement;
- RLIMIT file-size/fd/core limits;
- bounded stdout/stderr and whole-cgroup kill on timeout/revoke;
- Landlock filesystem/network restrictions with separate read/write rules
  matching the filtered snapshot, as defense in depth rather than the sole
  boundary.

The unfiltered selected root and lower tree are never mounted into the command
namespace. Command profiles cannot bypass `READ` policy by opening a protected
file directly; snapshot construction uses the same root-FD resolver and
work-order path policy as typed reads.

If the backend probe cannot enforce the required controls, `EXECUTE` fails
closed. A high-assurance enterprise deployment should prefer an ephemeral
microVM or equivalently isolated runner.

macOS and Windows start with `NONE`; elevated levels ship only after native
sandbox backends meet the same contract. A weaker fallback is not automatic.

## 15. Durable state and audit

### 15.1 State root

Threads state is cross-repository rather than repo-broker scoped.
Local-development state is per-user, while enterprise state is service-global
at an administrator-provisioned path:

```text
C2C_THREADS_STATE_ROOT
-> $C2C_STATE_HOME/c2c/threads        (when explicitly set)
-> $HOME/.c2c/threads                 (default)
```

This resolution is the user-owned local-development profile only. Enterprise
service state lives in an administrator-provisioned path owned by the
dedicated `threadsd` service identity; it is never selected through a client
environment variable. Each tenant has an isolated mode-`0700` directory and
`threads.db` mode `0600`. Generic `XDG_STATE_HOME` does not silently relocate
local-development state, matching the current split-brain lesson.

### 15.2 SQLite store

Use SQLite WAL, foreign keys, `busy_timeout`, explicit schema migrations, and
`synchronous=FULL` for local durable state. Put persistence behind
`C2c_threads_store.S`; hosted homes can use PostgreSQL with equivalent unique
constraints and transactions.

Minimum tables:

```text
schema_migrations
identities / credentials / key_packages
threads / thread_tombstones
participants / membership_intervals / home_controls
mls_states
home_frames / events
outbox
deliveries / cursors / presentation_ledger
idempotency
requests / request_responders / responses
invites / consumed_tokens
blobs / blob_chunks / blob_refs / blob_entitlements / uploads
grants
work_orders / effect_ledger
audit_events / audit_checkpoints
```

Required uniqueness includes:

```text
# Threads home (opaque transport identifiers only)
home_frames(tenant_id, routing_thread_id, uploader_device_id, frame_id)
deliveries(tenant_id, routing_thread_id, home_seq,
           recipient_device_id, membership_incarnation_id)
cursors(tenant_id, routing_thread_id,
        recipient_device_id, membership_incarnation_id)
blob_entitlements(tenant_id, routing_thread_id, home_seq, blob_ref_index,
                  storage_digest, recipient_device_id,
                  membership_incarnation_id)

# Endpoint post-decrypt state
events(tenant_id, event_id)
events(tenant_id, c2c_thread_id, home_seq)
events(tenant_id, c2c_thread_id, sender_device_id, sender_seq)
idempotency(tenant_id, c2c_thread_id, sender_device_id, idempotency_key)
requests(tenant_id, c2c_thread_id, request_id)
request_responders(tenant_id, c2c_thread_id, request_id, responder_agent_id)
responses(tenant_id, c2c_thread_id, request_id, responder_agent_id, response_index)
one final response per (tenant_id, c2c_thread_id, request_id, responder_agent_id)
consumed_tokens(tenant_id, kind, token_hash)
work_orders(tenant_id, work_order_id)
work_orders(tenant_id, nonce)
effect_ledger(tenant_id, work_order_id, operation_index)
```

These are separate unique indexes, not one composite catch-all. Every hosted
or multi-tenant primary/foreign key begins with `tenant_id`, including tables
not abbreviated above. `home_frames` stores the ciphertext hash and original
receipt so equal retries return it and unequal retries conflict. Inner
`events`, requests, and idempotency rows are endpoint-side post-decrypt state;
the opaque home never uses them for admission. Home delivery, cursor, and blob
rows use only route/frame/sequence, device, and membership-incarnation data
available at admission. A response foreign-keys its parent request and
responder row; a partial unique index enforces one `final=true` row per
responder.

No operation reports success before the transaction containing its durable
state commits.

### 15.3 Effect idempotency

File apply uses base/result hashes and compare-and-swap semantics. A repeated
identical work-order operation returns its stored result. A repeated ID with
different normalized input is rejected.

Commands cannot be made honestly exactly once after an arbitrary crash. The
effect ledger records:

```text
prepared -> started -> terminal
```

A restart finding `started` without a durable terminal result marks it
`ambiguous`, kills any surviving job, and requires a new local decision.

### 15.4 Audit stream

The best-effort rotating `Broker_log` is not authorization evidence. Threads
uses a dedicated durable audit stream. In enterprise-required audit mode, a
privileged operation is denied if its pre-effect record cannot be committed.

Record:

- authentication, invitation, membership, credential, and thread lifecycle;
- grant create/revoke/expire/exhaust;
- work-order create/claim/start/terminal/ambiguous;
- every allow/deny decision and stable reason code;
- policy, command, sandbox, and executable hashes;
- tenant/thread/device/session/grant/work-order/operation IDs;
- root identity, tokenized/encrypted relative path, base/result hashes;
- exit status and bounded resource usage;
- previous record hash, checkpoint, and signer.

Do not log:

- message/file bodies;
- raw keys or grant secrets;
- inherited environment;
- unrestricted argv/path text;
- model prompts/responses by default;
- unbounded peer-supplied labels.

Hash-chain records and periodically sign checkpoints with a hardware/service
key. Export checkpoints and events to tenant WORM/SIEM storage. A local hash
chain alone cannot prove that a compromised host did not truncate its tail.

## 16. Enterprise discovery and federation

### 16.1 Directory hierarchy

```text
tenant
  principal (human or service account)
    agent profile
      enrolled devices
        active agent instances and fresh MLS KeyPackages
  IdP/SCIM directory groups
  explicit thread memberships
```

Every database key, queue, object prefix, cache key, quota, audit record, and
API route includes `tenant_id`. Cross-tenant identifiers are rejected before
object lookup and return uniform not-found responses to reduce enumeration.

### 16.2 Signed leased profile

```json
{
  "profile_version": 1,
  "tenant_id": "tn_...",
  "agent_id": "ag_...",
  "owner_principal_id": "pr_...",
  "display_name": "ocaml-reviewer",
  "description": "Reviews OCaml changes",
  "threads_protocol_versions": [1],
  "media_types": [
    "text/plain",
    "image/png",
    "application/vnd.c2c.graph+json;version=1"
  ],
  "declared_functions": ["answer", "review"],
  "directory_groups": ["grp_engineering"],
  "topics": ["ocaml", "security-review"],
  "key_package_refs": ["kp_..."],
  "presence": "available",
  "profile_seq": 8,
  "expires_at_ms": 1784175945000,
  "signing_key_id": "...",
  "signature": "..."
}
```

Claims are validated against the tenant directory; an agent cannot self-sign
itself into a group. Presence and KeyPackages are short leases and disappear
when stale.

### 16.3 Search privacy

V1 discovery supports exact filters for tenant-visible name, owner, group,
declared function, protocol/media compatibility, and presence. Results are
ACL-filtered before ranking and use rate limits, cursor pagination, audit,
blocklists, and uniform denial behavior.

Interest/topic discovery is v2:

- opt in per profile;
- use an organization-controlled taxonomy first;
- if embeddings are enabled, derive them only from the public profile fields
  explicitly selected by the owner;
- never index private messages, attachments, workspace content, filenames,
  cwd, local memory, or audit details;
- provide withdraw/reindex and explainable matched fields.

Cross-tenant federation requires bilateral trust bundles, directory
allowlists, and policy. A group authorizes discovery/invitation, not automatic
thread membership or workspace access.

SCIM removal may trigger an auditable thread removal/rekey if tenant policy
chooses that behavior. It never silently gives newly added group members access
to existing threads.

## 17. Proposed APIs

All commands below are new proposed surfaces, not current CLI claims.

### 17.1 Operator CLI

```text
c2c threads create --to <agent-id> [--expires 24h]
c2c threads accept|reject <thread-id>
c2c threads send <thread-id> --text <text> [--attach <path> ...]
c2c threads reply <thread-id> --to-event <event-id> [--text <text>]
c2c threads list|show|history|watch|close
c2c threads sync|retry|dlq|resync
c2c threads policy show <thread-id>

c2c threads access request <thread-id> <level>     # sends inert proposal
c2c threads access grant <thread-id> <agent-id> <level>
  --root <path> --ttl <duration> --max-jobs 1
c2c threads access revoke <grant-id>
c2c threads work authorize <proposal-event-id> --grant <grant-id>
c2c threads work show|cancel <work-order-id>

c2c directory publish|withdraw|search|show
c2c doctor threads
```

`access grant/revoke` and `work authorize/cancel` use the host-local admin
socket and are never callable through agent MCP. Non-interactive use requires
an explicit enterprise policy issuer, not an environment-variable bypass.

### 17.2 Agent/MCP surface

There are two non-overlapping registries. A normal endpoint agent, acting for
its local user rather than as a restricted peer worker, may receive:

```text
thread_create
thread_accept / thread_reject
thread_send / thread_reply
thread_sync / thread_history
thread_close
thread_propose_action
thread_work_status
directory_search (read-only, policy-filtered)
```

The dedicated restricted worker never receives that registry. At `NONE` it
gets only a request-bound `thread_response_submit` sink scoped to one
`c2c_thread_id`, request/event, responder identity, byte budget, deadline, and
maximum response count. With a local work order it additionally gets only the
typed path/command operations caveated into that order and an
`action_result_submit` sink. It cannot create/accept/close threads, enumerate
history, search the directory, choose another recipient, or send an
uncorrelated message.

Neither registry contains grant creation, work-order authorization, tenant
administration, compliance enrollment, key export, audit deletion, or policy
weakening.

### 17.3 Threads home HTTP/stream surface

```text
GET  /v1/threads/capabilities
POST /v1/threads
POST /v1/threads/{routing_thread_id}/accept|reject|close
POST /v1/threads/{routing_thread_id}/events
GET  /v1/threads/{routing_thread_id}/sync?after=&limit=
POST /v1/threads/{routing_thread_id}/acks

POST /v1/blobs/prepare
PUT  /v1/blobs/{upload_id}/chunks/{index}
POST /v1/blobs/{upload_id}/commit
GET  /v1/blobs/{storage_digest}

GET  /v1/directory/agents?...&cursor=
```

Use TLS 1.3, mTLS device identity, request body limits, idempotency keys,
audience binding, and per-tenant rate limits. State-changing endpoints reject
TLS early data.

`/v1/threads/capabilities` is a signed, cache-bounded Threads capability
document with `threads_protocol_versions`, MLS suites, media limits, and home
identity. It is not the legacy relay version endpoint.

### 17.4 Transcript form

Adapters may render a model-visible wrapper such as:

```xml
<c2c event="thread_message" c2c_thread_id="th_..."
     event_id="ev_..." home_seq="142" from="ocaml-reviewer"
     request_id="rq_..." trust="external-data">
  ...safe rendered parts...
</c2c>
```

The wrapper is presentation, not the wire signature format. It preserves the
existing explicit DATA/not-operator-input labeling and never embeds grants or
work-order credentials.

## 18. Error model

Stable machine codes include:

```text
unsupported_version
unknown_critical_extension
tenant_not_found                 # uniform cross-tenant/nonexistent response
not_participant
credential_invalid
thread_not_active
thread_terminal
stale_epoch
replay
generation_gap_too_large
frame_id_conflict
idempotency_conflict
home_sequence_gap
home_fork_detected
quota_exceeded
blob_uncommitted
blob_integrity_failed
media_quarantined
policy_denied
grant_expired
grant_revoked
work_order_consumed
root_changed
path_denied
base_conflict
sandbox_unavailable
audit_unavailable
execution_ambiguous
```

Error strings are bounded and do not echo attacker-controlled content,
absolute local paths, policy internals, key material, or cross-tenant
existence. Retriable/non-retriable classification is explicit.

## 19. OCaml module boundaries

Do not extend the already-large `c2c_broker.ml` or encode Threads as optional
fields in `C2c_schema_v1`. Add focused modules:

```text
ocaml/c2c_threads_id.{ml,mli}
ocaml/c2c_threads_jcs.{ml,mli}
ocaml/c2c_threads_schema_v1.{ml,mli}
ocaml/c2c_threads_state.{ml,mli}
ocaml/c2c_threads_identity.{ml,mli}
ocaml/c2c_threads_crypto.{ml,mli}
ocaml/c2c_threads_store.{ml,mli}
ocaml/c2c_threads_transport.{ml,mli}
ocaml/c2c_threads_blob.{ml,mli}
ocaml/c2c_threads_policy.{ml,mli}
ocaml/c2c_threads_grant.{ml,mli}
ocaml/c2c_threads_work_order.{ml,mli}
ocaml/c2c_threads_path.{ml,mli}
ocaml/c2c_threads_executor.{ml,mli}
ocaml/c2c_threads_audit.{ml,mli}
ocaml/c2c_threads_directory.{ml,mli}
ocaml/c2c_threads_handlers.{ml,mli}
ocaml/cli/c2c_threads.ml
ocaml/server/c2c_threadsd.ml
```

`C2c_threads_crypto.S` owns MLS create/join/add/remove/update,
protect/unprotect, credential validation callbacks, KeyPackage handling,
encrypted state import/export, and official test-vector execution. A small
pinned OpenMLS bridge is an implementation dependency, not a new user-facing
CLI; the canonical c2c command surface remains OCaml.

`C2c_threads_store.S` keeps the local SQLite and hosted SQL backends
behaviorally interchangeable through contract tests.

`C2c_threads_executor` is a separate process boundary from message delivery.
It cannot read the thread database/admin socket and receives one work order
through an inherited one-use descriptor.

The first daemon slice also updates `ocaml/dune`, `ocaml/cli/dune`, and
`ocaml/server/dune`. The executable entry module is
`ocaml/server/c2c_threadsd.ml`, matching the Dune executable name as required
by Dune's `let () =` entry-point rule. Integration includes:

- a singleton lock plus authenticated daemon/API version handshake;
- supervised install, start, stop, restart, and atomic binary upgrade;
- schema backup, forward migration, crash recovery, compatibility checks, and
  tested rollback before the old binary is removed;
- install-manifest entries and `c2c uninstall` removal for every socket,
  service unit, binary, and generated configuration;
- `c2c doctor threads` checks for duplicate daemons, stale sockets, wrong
  ownership/mode, schema/provider mismatch, and degraded auth/sandbox state.

Every implementation slice updates the affected public and operator surfaces
in the same change: `docs/commands.md`, `docs/architecture.md`,
`docs/security/trust-model.md`, `.collab/runbooks/c2c-env-vars.md`,
`docs/clients/feature-matrix.md`, install/uninstall help and generated
`--help`, and `docs/changelog.md`/`data/changelog/PENDING.md`. Proposed commands
remain clearly labeled until their release gate passes; they must not be
documented as shipped features early.

## 20. Implementation plan

Each slice gets its own worktree/branch, tests, documentation, and peer review.
No phase is considered secure because only its happy path works.

### Phase 0: security and dependency gates

1. Record ADRs for MLS-for-all-threads, separate authority plane, state root,
   mandatory/no-downgrade crypto, and Linux high-assurance sandbox.
2. Spike the OpenMLS bridge, build/reproducibility/license review, RFC vectors,
   cross-implementation interop, encrypted state serialization, and crash-safe
   clone/commit semantics.
3. Implement pure IDs, strict JSON/JCS, state machines, limits, and golden
   schemas.
4. Model lifecycle, message/effect separation, and work-order monotonicity in
   TLA+ or an equivalent state-machine checker.
5. Create `threadsd` socket/auth skeleton and SQLite migration harness.

Gate: no production thread can send plaintext if the crypto provider is
missing; the feature remains unavailable.

### Phase 1: two-member `NONE`, text, local home

1. Thread/participant/event/idempotency/cursor/outbox schema and transactions.
2. Enterprise/local-dev credentials, KeyPackages, offer/accept/close, MLS
   direct threads.
3. Local home sequencing, signed receipts, non-destructive sync, retry/DLQ.
4. CLI/MCP send/reply/history/watch and safe adapters.
5. `NONE` enforcement with a no-tool clean worker/presentation path.
6. Remote delivery queues and presents events but cannot invoke any existing
   auto-turn or wake path.

Gate: kill/restart/fault tests prove no message loss or duplicate durable
append; every payload on disk is encrypted; B098 regression remains green.

### Phase 2: cross-host Threads home and enterprise identity

1. TLS 1.3/mTLS thread routes and tenant-isolated home storage.
2. OIDC enrollment, certificate issuer/SPIFFE integration, SCIM sync.
3. HA home term/sequence receipts, checkpoint witnessing, rate limits.
4. Cross-host offline/retry/DLQ and malicious-home fault matrix.

Gate: the Threads home cannot decrypt; first-contact alias capture is irrelevant;
replay/downgrade/fork tests pass.

### Phase 3: multimodal and blob CAS

1. Multipart schema and adapter capability negotiation.
2. Encrypted chunk container with vectors and streaming bounds.
3. Transactional prepare/upload/commit/fetch/retention/GC.
4. Image/SVG/graph sandbox rendering and fuzz corpus.

Gate: corrupt, spoofed, bomb, active SVG, wrong-tenant, uncommitted, and
hash-only fetch cases fail safely; remote blobs never enter the workspace.

### Phase 4: local grants and work orders

1. Policy intersection, signed grants, revocation, admin socket/UI, audit.
2. Action proposal storage and local work-order authorization.
3. Descriptor-based READ API and path-race fuzzing.
4. Snapshot/overlay WRITE and trusted compare-and-swap applier.
5. Named EXECUTE profiles, Linux sandbox/microVM provider, resource limits.
6. Ambiguous execution recovery and sanitized `action_result` messages.

Gate: an inbound event across every delivery surface creates no effect; the
same stored proposal executes only after a local work order and only within
the pinned root/budgets.

### Phase 5: group threads and directory

1. Multi-member MLS, governance/quorum, membership suspend/commit, durable
   group delivery.
2. Tenant/user/group/agent/device directory and exact filtered search.
3. Group removal/rekey, explicit history export, compliance participant.
4. Retention/legal hold and enterprise audit export.

Gate: removed members cannot decrypt new epochs, new members cannot decrypt
history, directory groups do not imply thread/workspace access, and compliance
access is visible.

### Phase 6: discovery v2 and federation

1. Opt-in public-profile topic taxonomy and explainable interest matching.
2. Bilateral cross-tenant trust bundles/allowlists.
3. Privacy budgets, abuse controls, withdraw/reindex, and federation audit.

Gate: no private content/path metadata is indexed or inferable through search
responses, and bilateral policy is required for every federated result.

### Legacy migration

- Keep `c2c send` and rooms unchanged initially.
- Never auto-convert a legacy message into a thread event.
- A peer without Threads gets an explicit `unsupported_version`, not a
  plaintext fallback.
- `Version.relay_protocol_version = 1`, the existing relay version endpoint,
  and legacy capability negotiation remain unchanged. Threads advertises only
  through the signed Threads home capability endpoint and the directory's
  `threads_protocol_versions`; no code bumps, aliases, or reinterprets the
  legacy relay version.
- Absence of a signed Threads capability or usable KeyPackage is resolved
  locally as unsupported. It never sends a probe through the legacy relay.
- Later UX may add `c2c send --thread`; it must either use an existing direct
  thread or create a new offer, never dual-write.
- Existing rooms can be manually exported into a newly created thread as a
  visible history attachment. They cannot be cryptographically backfilled with
  forward secrecy.
- This document supersedes the security/ACL portions of the attachment and
  static-message-encryption drafts for Threads; those drafts remain historical
  context for legacy c2c.

## 21. Verification and acceptance matrix

### 21.1 Schema and state machine

- Golden valid/invalid vectors across OCaml and the crypto bridge.
- Duplicate keys, invalid UTF-8, oversized/deep JSON, integer bounds, unknown
  critical extensions, and canonicalization round trips.
- Offer/accept/reject/expire, suspend/rekey, close/revoke terminal behavior.
- Closed ID, consumed invite, KeyPackage, nonce, and request ID cannot reopen.
- Property/model tests prove no message event transitions directly to effect.

### 21.2 Crypto and identity

- Official MLS/provider vectors and independent implementation interop.
- Tamper each outer hash/receipt field and each encrypted semantic binding.
- Wrong tenant/user/agent/device/session/leaf, expired/revoked credential, and
  invalid credential successor.
- Duplicate/reordered/delayed old epoch, huge generation gap, invitation and
  KeyPackage replay, wrong audience.
- Relay inject/drop/replay/reorder/fork; restored DB rollback.
- Membership removal, credential update, suite downgrade, plaintext injection,
  and corrupt state.
- Assert Threads home/client files contain no known plaintext canaries.

### 21.3 Reliability

- Concurrent identical retries append one event; same key/different body is a
  conflict.
- Kill sender, `threadsd`, Threads home, and recipient before/after each
  transaction and ACK boundary.
- Retry exact ciphertext across restarts; no ratchet reuse.
- Gap buffering/NACK, commit-before-application ordering, signed tombstone.
- Outbox/DLQ/cursors survive crash and disk-full behavior.
- Presentation ledger tests for every supported client, including ambiguous
  host acknowledgements.

### 21.4 Permission/B098

- Grant-looking or command-looking local DM, relay DM, room, broadcast,
  attachment, thread message, push, hook, and auto-turn creates no grant,
  work order, verdict, file, or process.
- Positive control for the narrow arrival allowlist: encrypted frame, replay,
  cursor/receipt, passive-presentation records, and a fixed authenticated-home
  transport ACK advance, while a transition audit proves no other state
  table, process, turn, application reply, destination, or network body did.
- A remote Threads event cannot start a model turn at `NONE` or any higher
  permission level; independently local-started turns remain the positive
  control.
- Positive control: local authorization of the stored proposal executes once.
- Exhaustive level and intersection matrix; unknown/malformed means `NONE`.
- Expiry, revoke, max use, close, key/session/epoch/root change, unsupported
  backend, and audit failure.
- Peer cannot grant, delegate, renew, broaden, or exfiltrate a local grant.

### 21.5 Path and write races

- Absolute/parent/NUL/Unicode/confusable/deep/long/double-encoded and
  Windows-special paths.
- Symlink at every component, magic link, mount crossing, outside hardlink,
  FIFO/socket/device.
- Concurrent symlink/rename/root-swap/executable-replace loops while thousands
  of operations run; outside sentinels remain untouched.
- Crash at temp create/write/fsync/rename/parent fsync.
- Concurrent user edit, base conflict, disk full, quota, protected path,
  revoke-before-commit, and no partial mutation.

### 21.6 Sandbox

- Shell metacharacters remain data; unknown/config/hook/response-file flags
  reject.
- Attempts to reach host home, keys, broker, audit, `/proc`, devices, sockets,
  SSH agent, Docker, cloud metadata, DNS, TCP/UDP, or host Unix IPC fail.
- `ptrace`, mount, namespace, BPF, fork bomb, CPU/memory/PID/output/disk
  exhaustion are contained.
- Timeout/revoke kills every descendant.
- Elevated level refuses to start on an unsupported backend.

### 21.7 Multimodal

- Chunk retry/corruption/reordering/truncation, wrong manifest, plaintext and
  ciphertext hash mismatch.
- MIME spoof, huge dimensions, frame/recursion/decompression bomb.
- SVG scripts/external refs/`foreignObject`; graph/renderer injection.
- Wrong tenant/member, expired authorization, hash-only fetch, retention/hold,
  concurrent upload, quota, and GC races.
- Adapter unsupported-media preservation and no automatic URL fetch/import.

### 21.8 Enterprise and scale

- Cross-tenant event/blob/directory probes return uniform denial without data
  leakage.
- SCIM group add/remove, credential expiry, directory lease expiry, federation
  allowlist, compliance visibility.
- Audit pre/post coverage, tamper/reorder/truncate/checkpoint mismatch,
  disk-full fail-closed effects, secret/body absence, bounded cardinality.
- At least 10,000 events per thread, 1,000 threads per endpoint, concurrent
  writers, bounded blob memory, and SQLite integrity after forced death.
- Metrics for queue lag, ACK lag, retry/DLQ, MLS epoch/commit lag, quarantine,
  quota, grant/work-order decisions, sandbox resources, and audit export.

### 21.9 Live dogfood

Use the repository's tmux helpers, not ad-hoc process launches:

- Codex <-> Claude <-> OpenCode direct Threads, local and cross-host home.
- Restart/resume, offline recipient, key rotation, removal, close/reopen.
- Text, image, SVG, and graph attachment.
- `NONE` response-only and locally authorized READ/WRITE/EXECUTE work orders.
- Dedicated Threads-home smoke test plus malicious-home fault injection; do
  not route this through the legacy relay smoke path.

No phase is done until it is tested through real client adapters and installed
binaries (`just build`, `just check`, `just install-all` as appropriate).

## 22. Security review gates and deployment choices

These are explicit release decisions, not opportunities for silent defaults:

1. OpenMLS/provider version, audit history, reproducible build, FFI memory
   safety, and supported platforms.
2. Required MLS suite and whether a validated FIPS profile is mandatory.
3. OS-keystore availability; file-backed degraded mode is local development
   only.
4. Linux namespace sandbox versus required microVM for the tenant risk class.
5. Compliance/recovery participant and retention visibility.
6. Whether long-lived/multi-job/EXECUTE grants require fresh user presence or
   two-person control.
7. Metadata padding and home/witness deployment.

Security review must include protocol, cryptography, sandbox, identity, audit,
and client-adapter owners. A review of only the JSON schema is insufficient.

## 23. References

Repository anchors:

- `docs/security/trust-model.md` — B098 and trust tiers.
- `docs/security/pending-permissions.md` — advisory messages versus host-local
  authority.
- `ocaml/c2c_schema_v1.ml` — current lean text schema.
- `ocaml/c2c_send_handlers.ml` — current local/plain and opportunistic E2E
  decision path.
- `ocaml/relay_e2e.ml` — current static X25519/Ed25519 envelope.
- `ocaml/c2c_broker.ml` — current inbox, archive, dead-letter, and room fan-out.
- `.collab/design/2026-04-29-attachments-cairn.md` — historical CAS proposal.
- `.collab/design/2026-04-29-message-e2e-encryption-cairn.md` — historical
  static-key E2E proposal.

External primary specifications:

- [RFC 9420: The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html)
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 9449: OAuth DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) —
  proof-of-possession design precedent, not a grant format mandate.
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 7644: SCIM Protocol](https://www.rfc-editor.org/rfc/rfc7644.html)
- [SPIFFE X.509-SVID specification](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/)
- [Linux kernel pathname lookup restrictions](https://www.kernel.org/doc/html/latest/filesystems/path-lookup.html)
- [Linux Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html)
