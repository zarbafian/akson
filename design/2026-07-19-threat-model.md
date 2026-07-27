# Akson threat model (v1)

Companion to `2026-07-16-threads-enterprise-agent-communication.md`. It names what
Akson protects, whom it defends against, and where each defense is realized in the
build. Section references (§) point at the design; the mitigations are the code
that implements them.

## What we protect (assets)

1. **The local machine** — its filesystem, running processes, and network access.
2. **The user's authority** — the ability to act as this agent/operator. A peer must
   never gain it.
3. **Credentials** — the model/processor API keys and the endpoint's private keys.
4. **Peer exchange integrity & confidentiality** — a task, its inputs, and its
   result are what the requester sent and the performer produced, seen only by the
   intended parties.
5. **Auditability** — an honest record of what happened, including *uncertain*
   outcomes.

## Actors and trust boundaries

- **The operator / same-UID processes** — trusted; in the personal profile's TCB
  (§16.2). Same-UID socket access is convenience authentication, not proof of intent.
- **A remote peer** — *untrusted*. It authenticates (pinned mTLS) but its content —
  proposals, inputs, delivered results — is adversarial.
- **A worker / adapter running peer work** — *untrusted for that work*. It may be
  prompt-injected by peer input or simply hostile; it must hold no authority the
  operator did not grant for the task.
- **A coordination driver** — a *separate local principal* under a different Unix
  UID, reaching the daemon only over `coord.sock` (ADR-0016). Trusted to stage
  bytes it wants disclosed and to spend consent an operator already granted;
  **untrusted for everything else**, and structurally unable to reach it. This is
  the one actor that is neither the operator nor a remote peer, and the surface
  exists so that it can be bounded by an OS access domain rather than by a token.
- **A model / processor** — semi-trusted plaintext boundary (§15.2). It sees only
  what the task discloses and never the raw credential.
- **The network** — *untrusted*. Assume an active MITM.

The core principle (the two permission domains): the agent's own user-granted
authority is never touched by Akson; a **separate, additive** layer governs only what
*peer-originated* commands may do, and that layer is *enforced*, not advisory.

## Threats → mitigations

| # | Threat (attacker → goal) | Mitigation (where) |
|---|---|---|
| T1 | Malicious peer task → run code / read files / exfiltrate with the agent's authority | Peer work runs in a **grant-derived sandbox** that starts from zero authority (fresh user/mount/pid/net namespaces, seccomp default-deny, Landlock, cgroup, dropped caps); only the named inputs and one output are constructed in. A prompt-injected task still has no socket and no host fs. (§13.1; `confinement.rs`, `akson-sandbox`) |
| T2 | Peer task → reach the network / a model directly | `socket()`/`connect()` stay off the seccomp allowlist. A model is reachable **only** via the broker: the worker inherits one already-connected fd; the daemon makes the real call, injecting the credential and enforcing the egress allowlist and budget. Granted only by explicit `--processor` approval, never by default. (§13.1; `broker_channel.rs`, `issue.rs`) |
| T3 | Compromised/hostile worker output → deliver something out of scope | Every output is **gated** against the work-order capability vector (channel, exact recipient, media type, byte/count budget) before it is recorded. (§7.2; `gate_outputs`) |
| T4 | Hostile artifact → execute in the requester's viewer (XSS, tracking, XXE) | Renderable artifacts (SVG/HTML/Markdown/Mermaid/Graphviz) are **inert-checked**: scripts, event handlers, script/HTML-data URIs, external fetches, and DOCTYPE/ENTITY are refused before delivery. (§20.4; `akson-worker/inert.rs`) |
| T5 | Network MITM → intercept/alter/impersonate | **mTLS 1.3 only**, pinned to the peer's cert digest (no CA chain for peers), no resumption/tickets/0-RTT; the request is bound by an idempotency covered-value tuple and a DSSE signature. (§9.1; `akson-transport`) |
| T6 | Hostile bytes → crash/exhaust the parser (stack overflow, node/byte bomb) | Strict I-JSON with hard byte/depth/node caps, duplicate-key and unsafe-integer rejection, digests over original bytes; fuzz targets + hostile-input suites prove no panic/overflow. (§11.1, §20.4; `ijson.rs`, `fuzz/`, `hostile_*` tests) |
| T7 | Crash mid-operation → double effect, or lost-but-claimed-done | **Durable-before-effect**: the record advances to `dispatching`/`running` before any byte leaves; recovery at startup marks anything mid-flight `ambiguous` (never retried, never reported done); idempotency records survive a crash so a replay is a `Duplicate`. (§13.1, §15.5; `crash_matrix` test) |
| T8 | Forged/unsolicited result → record a fake outcome | A delivered result must match an outstanding `sent_request` and verify under the performer's task-result key; a mismatch is refused **before anything is recorded**. (§14.5; `outcome.rs`, no-effect tests) |
| T9 | SSRF / DNS rebinding via a processor origin | Origin must be `https` + on the allowlist; the **resolved address is re-checked** before dialing (global-unicast only unless a local processor opts in), so a rebind after resolution is refused. (§13.1; `akson-broker/address.rs`) |
| T10 | Replay of a prior request → duplicate work | Idempotency keyed on a keyed HMAC over the covered-value tuple; an exact replay returns the original saved response, a changed covered value is a `Conflict`. (§9.2; `delivery.rs`) |
| T11 | Receiving a task → side effects before the operator decides | The receive path is handed only a `&Store` (no transport/processor/fs), so it *cannot* call a model, dial out, run a worker, or read a file. Receiving produces an **inert** task; execution needs a separate explicit decision. (§10.2; no-effect proofs) |
| T12 | Hijack a peer identity at pairing / silent key swap | Identity is committed **out of band before contact**: the imported token pins the root key (ADR-0013), and the introduction proves possession of every advertised key over a transcript bound to both roots, both TLS fps, the key-binding digest, and the live session's RFC 9266 exporter (ADR-0015). Commit is a CAS on (root, epoch); removal tombstones the epoch so a racing introduction cannot resurrect a peer; changed material for an active peer suspends for review (§8.4), never re-pins. (§8.1–8.4; ADR-0013/0015) |
| T13 | Rollback the encrypted state to replay consumed nonces | State-generation counter vs. an external checkpoint (§15.5). **Residual:** interim custody (ADR-0009) has no external counter, so rollback is *undetectable* and the daemon degrades to operate-but-flagged rather than block. |
| T14 | Steal the identity root key → impersonate the endpoint at first contact | The root (Agent Card JWS) key is the token's sole commitment, so its private half **alone** lets an attacker introduce as that identity to any token holder — minting fresh subkeys and a fresh TLS certificate. A deliberate concentration (ADR-0013), accepted for v1 under the same interim sealed custody as every other key (see residuals); recovery is a new root plus out-of-band token re-exchange (§8.4 re-pair). Post-activation, an unexpected root-signed change still suspends (§8.4, T12). |
| T15 | Compromised coordination driver → reach operator authority (approve an inbound task, pair, read a credential, send a task) | The coordination surface is **deny by absence**: eight ops exist on it, and every other control op returns `403 forbidden-surface` — unaddressable, not merely unauthorized. `Surface::Coord` dominates nothing, including `Worker`, so the dominance relation cannot be walked upward. Admission is `SO_PEERCRED` against a configured UID, checked **before the request line is read**; with `AKSON_COORD_UID` unset the socket is not created at all, so there is nothing to probe. The matrix is asserted over a real socket for every op, not just the ones under test. (ADR-0016 §1–2; `control.rs::authorize`, `socket.rs`, `coord_boundary.rs`) |
| T16 | Compromised coordination driver → disclose bytes no human approved, or disclose twice | `stage` is **inert** — bytes and a content-derived reference, no model, no authority, no socket — and minting the one-shot consent receipt is an **admin** op that shows the operator the risk card for that exact staged digest first. `dispatch` spends the receipt and commits its record in one store transaction, guarded by a `uses < max_uses` compare-and-set *and* a `UNIQUE` receipt id in the dispatch ledger; a different execution key against a spent receipt is `409 consent-spent`, and the refusal survives a restart because it is in the schema, not in memory. Routing and envelope construction run **before** the spend, so a disclosure that provably cannot leave never burns consent. (ADR-0016 §3–4, §6; `coord.rs`) |
| T17 | Tampered or misrouted coordination disclosure → admit bytes at the wrong peer, or bytes no one consented to | The receiver checks four things and admits nothing otherwise: `sender_root` equals the root the mutual-TLS handshake authenticated, `recipient_root` equals its own, SHA-256 over the payload bytes it actually read equals `payload_sha256`, and the §4 derivation reproduces `staged_digest`. One generic `422`; the reason is recorded locally and never returned. **Arrival is still not execution** — an admitted disclosure creates no Task, no contract head, no work order, and nothing to approve, and the payload is not retained. (ADR-0016 §5; `coord_egress.rs`, `receive_http.rs`) |
| T18 | Remote recipient stalls the carrier, or a peer re-sends a refused dispatch forever → deny the local coordination surface, or grow its store without bound | Every stage of the outbound POST is separately bounded (resolve 5s, connect 10s, handshake 10s, exchange 30s), so a recipient that accepts the connection and then says nothing ends the attempt; the control sockets serve connections concurrently (up to 16), so one slow carriage delays only itself. A timed-out attempt is `failed`, never `sent`, and is retryable. Inbound, a **refusal** is committed through the same §9.2 idempotency record as an admission under its own response class, so a re-sent refused dispatch replays the same `422` and appends no second event — a peer pays one durable row per *distinct* request, exactly as an accepted dispatch does. The coordination request line is capped at 1 MiB (a separate principal must not be able to make the daemon buffer without limit). (ADR-0016 §6; `a2a_client.rs`, `socket.rs`, `receive_http.rs`) |

## Assumptions and residual risks

- **Key custody is interim** (ADR-0009): the master secret and DEK live in a
  file-based KEK (`0600`), not an OS keystore/TPM. A local attacker with the user's
  uid can read them. Rollback detection is therefore unavailable (T13). The real
  keystore backend is the remaining custody work.
- **Same-UID processes are in the TCB** in the personal profile. Isolation from
  other same-UID software is out of scope there; the isolated profile (separate
  service identity) narrows this.
- **Local principals are authenticated by UID, not by an attested process
  identity.** `SO_PEERCRED` says which *user* connected, never which program. That
  is the whole admission rule for all three control sockets, so anything running
  as the coordination UID reaches the coordination surface, and anything running
  as the daemon's UID reaches admin. The default profile has no UID separation at
  all: `coord.sock` is simply absent until `AKSON_COORD_UID` is configured, and
  the one-identity-per-role arrangement is the opt-in fleet profile in `deploy/`.
  Read every claim in this document at that assurance level.
- **A coordination dispatch is authenticated, not non-repudiable.** The ADR-0016
  envelope is **unsigned**: its authenticity is the channel's (pinned mutual TLS
  on both sides) and its integrity is the digest chain over the payload and the
  staged digest. There is no key purpose for a coordination dispatch, and
  borrowing `contract-proposal` to sign a non-contract would break the
  one-key-one-role rule this codebase holds elsewhere. The consequence: a
  recipient can be certain *which pinned peer* sent a disclosure, but cannot prove
  it to a third party. A future ADR that needs that adds an eighth paired purpose;
  nothing here forecloses it.
- **The receiving side of a coordination dispatch retains nothing.** It verifies,
  acknowledges, and records one `dispatch_received` event with the digests, the
  sender's root, and the byte length — never the payload. This is deliberate
  (reading one back would need an inbound coordination op ADR-0016's registry does
  not have, and storage without a reader is an unbounded liability), but it means
  an operator on the receiving side cannot audit *what* was disclosed to them from
  akson's own records, only that something was, and under which consent receipt.
- **The deployment profile's hardening has no score.** `systemd-analyze security`
  needs the units installed as root, which has not happened on any host, so no
  numeric exposure level is claimed for `deploy/akson-daemon.service` or
  `deploy/akson-coord.service`. What *is* verified is narrower and stated as such
  in `design/a0-evidence.md` A0.5: both units parse under `systemd-analyze verify`,
  and no sandbox-hostile directive is active in the daemon unit.
- **The TLS stack is `rustls-rustcrypto`** (ADR-0011): pure-Rust but community-
  maintained and less audited than aws-lc-rs. The `CryptoProvider` is the swap seam
  if it proves insufficient.
- **A shell-orchestrated worker can spawn tools** (the shell baseline allows
  `vfork`/`clone`/`execve`); those children inherit the same sandbox, so they gain
  no authority, but a worker that *needs* a broader syscall set is the operator's
  responsibility to vet. A **production adapter** (`AKSON_WORKER_EXEC`) instead runs
  directly under the strict `adapter_worker_baseline`, which drops the
  process-creation family: it cannot `fork`/`clone`/`vfork` a helper or thread, so
  even a shell reached via `execve` is inert (it cannot fork to run a command).
  (`SeccompPolicy::adapter_worker_baseline`, validated live against a confined
  adapter.)
- **Denial of service by a peer** (flooding introduction/receive) is rate-limited
  and body-capped — the introduction's admission gate holds unknown callers to a
  table lookup before any signature work (ADR-0015) — but sustained resource
  pressure is not fully modeled here.
- **Extended-card disclosure is bounded by relationship-graph secrecy, not by
  proof.** In the introduction the responder discloses its card after the dialer
  merely *claims* an imported root — responder-proves-first is what protects the
  dialer from hijacked endpoints, and someone must go first (ADR-0015). So anyone
  who knows your address and the thumbprint of a root you imported (neither is
  secret) can retrieve your extended card. The exposure is metadata-class —
  identity and public keys you would show any peer — and every such attempt lands
  in the knock log.
- **The broker enforces a per-work-order *operation count*, an *egress allowlist*,
  the *exact* approved processor, a *response-size* cap, and a *wall-clock* limit —
  but not a monetary ceiling.** `max_cost_microusd` is recorded, not enforced:
  pricing is per-provider and depends on token usage the broker does not parse, so a
  prompt-injected adapter granted `processor_use` can still request an expensive
  model or a large completion within the operation count. The count and size caps
  bound the blast radius; a true cost ceiling needs per-provider usage accounting
  (follow-up). The credential itself never reaches the adapter.
- **Peer key-binding expiry (`not_after`) is not enforced.** A paired peer is
  gated by operator-confirmed `active` status and certificate pinning; the receive
  resolver does not additionally reject a contract-proposal or task-result key past
  its declared `not_after` (the `peer_keys` table does not retain it). Key rotation
  is by re-pairing, which now fully revokes the prior certificate's keys. Enforcing
  binding expiry is a follow-up (needs a schema column + a resolve-time clock check).
- **The audit log detects tampering *within* the chain but not truncation of its
  *tail*.** `verify_chain` follows the hash links, so any edit to a retained record
  is caught, but deleting the most recent records leaves a shorter valid chain. A
  durable high-water sequence/terminal-hash anchor (tied to the T13 external
  checkpoint) is the follow-up; until then tail-truncation resistance rests on the
  same at-rest custody as the rest of the store.
- **`processor_visible: false` on an input is advisory, not enforced.** A worker
  granted both input-read and `processor_use` reads the input and can place any of
  its bytes into the opaque request it hands the broker, which does not inspect the
  body (same root as the cost-ceiling item). Marking an input not-processor-visible
  does not prevent a prompt-injected adapter from disclosing it. Enforcing this
  needs either a non-opaque broker request contract or excluding such inputs from a
  processor-enabled worker's readable set (follow-up).
- **Result manifests are not cross-checked against the contract's requirements.**
  The performer signs, and the requester verifies, that the delivered bytes match
  the manifest — but neither checks the manifest against the contract's declared
  `deliverables` (required roles/media types) or substantiates a passing evidence
  slot with an actual in-toto envelope (evidence bytes are not delivered, stored, or
  verified in v1). A performer can therefore complete a task while omitting an agreed
  deliverable, or assert a passing verification slot without evidence. The requester
  sees exactly what arrived, so this is a completeness/authenticity-of-claim gap, not
  a silent substitution; deliverable-role enforcement and evidence substantiation are
  tracked follow-ups.
- **Output byte limits are per-output, not aggregate.** A grant's `max_bytes` bounds
  each output; the number of outputs is bounded by `max_responses`/`max_count`. The
  total returned to the requester can therefore reach count×`max_bytes`. The risk
  card should be read as a per-item ceiling with a count, not a single total.
- **The worker's `/output` is host-backed and not disk-quota'd.** A worker can write
  to `/output` until the host filesystem fills; this is bounded by the wall-clock
  ceiling and refused on *read* above a per-file cap, but a sub-ceiling burst can
  still pressure host disk. A sized overlay/tmpfs for `/output` is the follow-up.
- **Physical access, kernel/hypervisor compromise, and side channels** are out of
  scope for v1.
