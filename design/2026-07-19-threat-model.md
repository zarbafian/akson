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
| T12 | Hijack a peer identity at pairing / silent key swap | Pairing is a consume-once ledger with proof-of-possession (verify_strict) over a transcript binding both TLS fps + the key-binding digest; a re-pair that would overwrite an existing peer is refused unless the operator removes it first. (§8.1–8.4; `akson-pairing`) |
| T13 | Rollback the encrypted state to replay consumed nonces | State-generation counter vs. an external checkpoint (§15.5). **Residual:** interim custody (ADR-0009) has no external counter, so rollback is *undetectable* and the daemon degrades to operate-but-flagged rather than block. |

## Assumptions and residual risks

- **Key custody is interim** (ADR-0009): the master secret and DEK live in a
  file-based KEK (`0600`), not an OS keystore/TPM. A local attacker with the user's
  uid can read them. Rollback detection is therefore unavailable (T13). The real
  keystore backend is the remaining custody work.
- **Same-UID processes are in the TCB** in the personal profile. Isolation from
  other same-UID software is out of scope there; the isolated profile (separate
  service identity) narrows this.
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
- **Denial of service by a peer** (flooding pairing/receive) is rate-limited and
  body-capped, but sustained resource pressure is not fully modeled here.
- **Physical access, kernel/hypervisor compromise, and side channels** are out of
  scope for v1.
