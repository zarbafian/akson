# Axon implementation plan

Status: proposed plan

Date: 2026-07-16

Source design: `design/2026-07-16-threads-enterprise-agent-communication.md`
(referenced below as "design §N"). Stack decision: **Rust** (confirmed
2026-07-16).

## 0. What done looks like

The plan drives toward two concrete transcripts. Everything below exists to
make these work, honestly, on a fresh machine.

Local evaluation (under five minutes, design §5.1):

~~~text
$ axon demo review change.patch
demo: created endpoints "requester" and "reviewer" (same host, same UID — lower assurance, labeled)
demo: paired
demo: sent code_review.v1 proposal (84 KiB patch, 2 context parts)
reviewer inbox: 1 task — risk card:
  Who:        requester @ this host (demo pairing)
  What leaves: change.patch (84 KiB), 2 context files -> processor "local" (ollama, localhost, no vendor account)
  What runs:  code_review.v1; denied: host files, network, secrets, mutation
  Limits:     revision r0 digest sha256:…, 10 min, 8 MiB, est. $0
  Evidence:   execution attestation (self-attested); Independent verifier: none
Approve once? [y/N] y
demo: attempt running… completed
demo: evidence validated (5 signatures, 7 digests) — self-attested
demo: findings: 3 (1 warning, 2 note) — summary.txt, findings.sarif
Outcome? [accept/reject/dispute] accept
demo: outcome signed and delivered. Done in 3m41s.
~~~

Cross-host loop (under ten minutes, design §4.3): same flow via `axon init`,
`axon serve`, `axon pair create|accept`, `axon review reviewer change.patch
--wait`, with the reviewer in the isolated profile.

The six-state product spine (design §23) that every milestone serves:

~~~text
authenticated request -> inert durable task -> explicit local decision
-> bounded clean execution -> standard evidence -> independently checkable outcome
~~~

## 1. How this plan maps to the design's phases

Design §19 defines Phase 0 (standards/security feasibility) and Phase 1 (the
first public release). We fold Phase 0 prototyping directly into the real
codebase instead of throwaway prototypes — but each Phase 0 gate becomes a
named review checkpoint (G0.x below) that must pass before dependent
milestones are declared done. Phases 2–4 are out of scope for this plan
except where an interface must not preclude them (capability vector,
secure-session provider seam).

## 2. Decisions and open ADRs

Decisions made now (each gets a short ADR in `spec/adr/`):

| # | Decision | Choice |
|---|---|---|
| ADR-0001 | Implementation language | Rust (workspace of small crates; two binaries: `axond`, `axon`) |
| ADR-0002 | A2A source of truth | Vendor the pinned A2A 1.0 protobuf definitions into `spec/a2a/`; generate Rust types with `prost`; JSON mapping per the A2A standard mapping; never hand-maintain a competing schema (design §3) |
| ADR-0003 | Storage | SQLite via `rusqlite` (bundled), WAL mode; c2c-style `CREATE TABLE IF NOT EXISTS` + explicit column-add migrations; sensitive columns encrypted at the application layer before persistence (design §15.1) |
| ADR-0004 | Signing | Ed25519 via `ed25519-dalek` v2; JWK + RFC 7638 thumbprints; separate keys per purpose from day one (design §8.1 target, no temporary key reuse) |

ADRs to resolve during M0–M2 with a spike each (decision criteria in the ADR,
fail closed until resolved):

| # | Open ADR | Candidates | Notes |
|---|---|---|---|
| ADR-0005 | Envelope encryption library for local state | Google Tink ciphertext format via `tink-rust` (maturity concern); `age`/rage format; RustCrypto AEAD (`chacha20poly1305`, NCC-audited) with a minimal documented envelope | Design §15.1 requires adopting a reviewed ciphertext format, not inventing one. If no Rust library qualifies, adopt Tink's wire format and test against Tink reference vectors |
| ADR-0006 | Sandbox launcher (design §13.1) | (a) minimal purpose-built Rust launcher: `clone3` namespaces via `nix`, `seccompiler` (rust-vmm), `landlock` crate, cgroups v2 direct; (b) bubblewrap as reviewed launcher + our seccomp/cgroup layer; (c) minijail | Phase 0 gate: the concrete launcher and seccomp profile must be selected and published. Spike S2 decides |
| ADR-0007 | JWS library for Agent Card signatures | `josekit`, `jsonwebtoken` (EdDSA), or minimal JWS over `ed25519-dalek` | Only `alg: EdDSA`, `typ: JOSE`, RFC 7638 `kid` needed (design §10.1) |
| ADR-0008 | DSSE/in-toto implementation | `in-toto` crate (in-toto-rs) if it passes review; else implement DSSE v1 + in-toto Statement v1 per spec with golden vectors cross-checked against the Python reference implementations | Implementing a published spec is allowed; inventing a format is not |
| ADR-0009 | OS keystore + rollback checkpoint | `keyring` crate (Secret Service) for key wrapping; `tss-esapi` (TPM2) optional feature for the monotonic state-generation checkpoint (design §15.5) | Where no TPM: report rollback detection unavailable, per design §15.5 |

External action items (block release, not development):

- **Extension namespace domain** (design §3.1 Phase 0 release gate): the
  project needs a stable HTTPS namespace for extension URIs and media types.
  Owner: maintainer. Needed before any URI string is frozen; until then use a
  clearly-marked placeholder constant in one module.
- **License**: Apache-2.0 proposed (design §17.1); commit `LICENSE` in M0.

## 3. What we take from c2c — and what we deliberately don't

c2c (`~/agentic/c2c`) is a prior agent-communication system; its canonical
implementation is OCaml. We reuse patterns and lessons, not code.

Reuse (patterns):

- **Durability discipline**: atomic tmp-file + fsync + rename writes, fixed
  lock ordering, dead-letter + redelivery, TTL leases (`ocaml/c2c_broker.ml`,
  `ocaml/relay_registration_lease.ml`).
- **SQLite schema patterns**: dedup table keyed by message id, *separate*
  nonce tables per purpose so one verifier cannot consume another's nonce,
  IF-NOT-EXISTS plus column-add migrations (`ocaml/relay_sqlite_support.ml`).
- **Signed-request construction**: canonical blob = method, path, query,
  body-SHA256, timestamp, nonce with per-purpose signing context
  (`ocaml/relay_signed_ops.mli`) — precursor to Axon's purpose-bound keys.
- **Secure worker launch**: capability token never in argv/disk/logs,
  fail-closed resume after crash, injectable backend seam for hermetic tests
  (`ocaml/c2c_codex_app_server.mli`).
- **Test topology**: two isolated state volumes force traffic through the
  network path; sealed containers with memory/pids limits and
  `no-new-privileges` (`docker-compose.e2e-multi-agent.yml`,
  `docker-tests/`).
- **"Bus, never RPC" invariant** (c2c B098): inbound message content can never
  satisfy an approval or trigger a privileged action. Same invariant as design
  §6.3 "arrival is not execution"; c2c proved it survives dogfooding.
- **Adapter know-how**: `docs/MSG_IO_METHODS.md` and
  `docs/clients/feature-matrix.md` catalog what actually works per agent CLI.

Avoid (documented dead ends):

- PTY/bracketed-paste or history-file injection into running agent sessions
  (`findings-pty.md`, `findings-ipc.md`). Axon's clean-worker model avoids
  this by construction — adapters run agents non-interactively from launch.
- Mid-turn sideband injection without explicit queue semantics (c2c Codex
  bugs 19637/19638). Axon adapters invoke agents per-task, never inject.
- Unbounded relay/queue growth without backpressure (c2c B219: relay dies
  under load). Axon v1 has no relay, but the same lesson applies to the
  inbox/outbox: hard limits before allocation (design §9.1, §11.1).

## 4. Repository layout

~~~text
axon/
  Cargo.toml                 # workspace
  crates/
    axon-proto/              # vendored-A2A generated types, JSON mapping, profile validation (§10.1)
    axon-ext/                # Axon extension schemas, I-JSON checks, JCS, DSSE envelopes, golden vectors (§3.2, §10.2, §14)
    axon-crypto/             # key lifecycle, purposes, thumbprints, JWS, keystore adapters — thin wrappers only (§8.1)
    axon-store/              # encrypted SQLite state, outbox/inbox, tombstones, audit chain, generation checkpoint (§9.2, §15)
    axon-transport/          # HTTP+JSON A2A server/client, mTLS profile, Content-Digest, delivery extension (§9)
    axon-pairing/            # invitation, bootstrap endpoint, pending->active, re-pair/removal (§8.2, §8.4)
    axon-contract/           # contract validation, revision chain, decisions, risk-card projection (§10.2–10.4)
    axon-authority/          # policy (deny/allow-once), capability vector, one-shot work orders (§12)
    axon-sandbox/            # Linux launcher: namespaces, seccomp, cgroups v2, Landlock; capability probing (§13.1)
    axon-worker/             # clean worker protocol, output gate (§13.1, §7.2)
    axon-broker/             # processor broker, durable sub-attempts (§13.1)
    axon-evidence/           # result manifest, in-toto statements, SARIF profile, validation (§14)
    axond/                   # daemon binary: wiring, local sockets, OpenAPI control API (§16.2)
    axon-cli/                # `axon` binary: all §16.4 commands, risk card, doctor
    axon-adapter-sdk/        # adapter contract (§16.3), fixtures, conformance tests
  adapters/
    opencode/                # OpenCode + documented local-model path (§4.4)
    codex/                   # Codex via supported non-interactive interface (§4.4)
  spec/
    a2a/                     # pinned A2A version, vendored protos, mapping doc, conformance vectors
    ext/                     # Axon extension registry: JSON Schemas, media types, versions
    vectors/                 # golden vectors: JCS, DSSE, digests, dedup, manifests
    adr/                     # ADRs
    threat-model.md
  xcheck/                    # independent Python cross-checker for vectors (in-toto/securesystemslib/rfc8785)
  tests/e2e/                 # two-endpoint docker topology, crash matrix, benchmarks
  design/
~~~

Crate dependency rule: `axon-proto`, `axon-ext`, `axon-crypto` depend on
nothing internal; `axond` is the only crate that wires everything. Trusted
code (§7.1) — transport parse path, policy, authority, output gate, evidence
validation — stays in dedicated crates with no dependency on adapter or
worker-payload code.

## 5. Library selections (pinned in ADR-0001 appendix)

| Concern | Crate |
|---|---|
| async runtime / HTTP | `tokio`, `axum` (server), `reqwest` with rustls and redirects disabled (client) |
| TLS | `rustls` + `tokio-rustls`; TLS 1.3 only, session tickets and 0-RTT off, custom pinned-peer verifier; `rcgen` for self-issued endpoint certs; `x509-parser` |
| A2A types | `prost` from vendored protos |
| JSON | `serde_json`; I-JSON + duplicate-key rejection in `axon-ext` |
| JSON Schema 2020-12 | `jsonschema` |
| RFC 8785 JCS | `json-canon` (`serde_jcs` rejected: sorts keys by code point, not UTF-16 code units — caught by the `jcs/utf16-key-sorting` golden vector) |
| Signatures | `ed25519-dalek` v2; JWS per ADR-0007; DSSE/in-toto per ADR-0008 |
| SARIF | `serde-sarif` (parse behind strict limits, preserve original bytes) |
| Storage | `rusqlite` (bundled SQLite, WAL); envelope encryption per ADR-0005 |
| Keystore/TPM | `keyring`; optional `tss-esapi` |
| Sandbox | per ADR-0006 (`landlock`, `seccompiler`, `nix`, cgroups v2) |
| CLI | `clap`; risk card as plain terminal prompt in v1 (no TUI dependency) |
| Local control API | `utoipa` (OpenAPI 3.1), `http-api-problem` (RFC 9457) |
| Telemetry | `tracing`; `opentelemetry` behind an off-by-default feature |
| IDs / time | `uuid` (v4), RFC 3339 via `time` |

Rule from design §3.3: no cryptographic primitive implementations of our own;
every one of these is a configuration-and-tests consumer of a maintained
library.

## 6. Milestones

Sizes: S ≈ days, M ≈ 1–2 weeks, L ≈ 2–4 weeks, XL ≈ 4+ weeks (single
developer + agent assistance; parallel tracks noted). Each milestone lists
its exit criteria; design §20 test families are built *with* the milestone,
not after.

### Track 1 — foundations and formats

**M0. Project foundations (S)**
Workspace scaffold, CI (fmt, clippy, test, deny), `LICENSE`,
`SECURITY.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`, ADR process, `spec/`
skeleton, placeholder extension-namespace constant.
*Exit:* CI green on empty crates; ADR-0001..0004 merged.

**M1. Extension schemas and golden vectors (L)** — `axon-ext`, `xcheck/`
JSON Schemas (2020-12) for: contract, decision, ordered input manifest,
identity/key binding, passive delivery, result manifest, evidence reference,
verifier summary, outcome (design §3.2, §10.2, §14.1). I-JSON validation,
duplicate-key rejection, JCS canonicalization, DSSE envelope
sign/verify. Golden vectors for every schema; independent Python
cross-checker (`rfc8785`, `securesystemslib`, `in-toto`) run in CI.
*Exit:* G0 gate "contract signatures and digests match independent
implementations" (design §19 Phase 0) passes via xcheck.

**M2. A2A profile (M)** — `axon-proto`, `spec/a2a/`
Vendor pinned A2A 1.0 protos; prost codegen; standard JSON mapping;
profile validation: required-extension negotiation, `A2A-Version`,
`A2A-Extensions` echo, nonblocking profile (`returnImmediately`, streaming
and push off), task-state mapping table (design §10.1, §10.4). Mapping doc +
conformance vectors in `spec/a2a/`.
*Exit:* profile validator rejects every §20.1 negative vector (duplicate
keys, invalid UTF-8, non-I-JSON numbers, unknown critical fields, downgrade).

### Track 2 — identity, state, transport (starts after M0; parallel to M1/M2 tail)

**M3. Keys and identity (M)** — `axon-crypto` — **core done** (commit
`6d88b6f`)
Key generation per purpose (TLS, Agent Card JWS, task-statement,
local-authority, evidence), RFC 7638 thumbprints, purpose binding, keystore
wrapping (ADR-0009), identity tuple record (design §8.1), Agent Card JWS
sign/verify (ADR-0007) — all landed with vectors.
Self-issued X.509 endpoint certs **move to M5/M6**: they are the
`tls-endpoint` key's cert, generated once and consumed by the mTLS listener
and pairing bootstrap, and the cert-generation library choice is inseparable
from the TLS-stack ADR (rustls) made there. `identity::Fingerprint::cert_sha256`
already stands ready to fingerprint the DER.
*Exit (met):* cross-purpose key use fails closed in tests; thumbprint/JWS
vectors match xcheck.

**M4. State store (L)** — `axon-store` — **core done** (commit `35dccc4`)
Encrypted SQLite. **Landed (M4-core):** the cross-cutting machinery — envelope
sealing (ADR-0005, XChaCha20Poly1305, keystore-wrapped DEK), `user_version`
migrations + `meta`, state-generation recovery (§15.5), trusted-time floor
(§8.5), the hash-linked `audit` table (§15.3), and the representative encrypted
`peers` table (stores the M3 identity tuple). Both exit criteria met.
**Deferred to their engines:** the domain tables — `peer_key_history`,
`invitations` (M6); `outbox`, `inbox_objects`, `replay_tombstones` (M5);
`tasks`, `contracts`, `decisions`, `policy` (M7); `work_orders`, `attempts`,
`processor_calls` (M8); `artifacts`, `evidence`, `outcomes` (M11) — each added
as its own numbered migration when the engine that writes it lands.
*Exit (met):* §20.7 storage scan finds no plaintext; restore of an old
snapshot provably enters recovery and disables automatic authority.

**M5. Transport and reliable delivery (L)** — `axon-transport` — **core done**
(commits `f078551`, `8e5a3c0`; delivery model in M5-core `d4656cd`)
Landed: the pure-Rust TLS 1.3 mutual-auth layer with peer pinning (ADR-0011,
verified end to end over tokio-rustls), and `ingress::admit` — the fail-closed
profile + Content-Digest + required-extension gates and the idempotency
decision (Accept/Duplicate/Conflict/Rejected). **Deferred to the tracer bullet
(post-M7):** the axum HTTP server that *dispatches operations* and the reqwest
client — they need operations to serve (task proposal, decision), which are
M6/M7; building them now means a placeholder echo, which the tracer bullet
already owns. The M6 pairing bootstrap is the first real consumer of the TLS
layer.
Original scope for reference —
axum A2A endpoint + reqwest client on the pinned TLS profile (§9.1): TLS 1.3
only, mTLS after pairing, no resumption/0-RTT/redirect/compression, limits
before allocation. RFC 9530 `Content-Digest` (single sha-256, reject
otherwise). Durable-before-response receive path; outbox retry with
byte-identical bodies; dedup on the full covered tuple returning the saved
byte-equivalent response with the identical Task id; conflict on any
covered-value change; keyed replay tombstones outliving the retry horizon
(§9.2). Scoped GetTask/ListTasks/CancelTask with no cross-peer oracle
(§10.1).
*Exit:* G0 gate "same-request retry returns the identical Task id; any
covered change rejected"; crash tests at every transaction boundary lose no
acknowledged receipt and duplicate no task (§20.2).

**M6. Pairing (L)** — `axon-pairing` + `axon-transport` — **bootstrap live**
Landed (pure, tested): invitation create + verifier-only bearer secret
(constant-time, expiry, attempt cap); mode-0600 file / stdin transfer;
extended-card + key-binding verification (thumbprint==JWK, closes Codex M6;
plus per-purpose key-reuse rejection); transcript + proof of possession
(`verify_strict`); the consume-once **state machine** (retry-safe replay /
transcript-conflict, `PairingLedger` trait + in-memory impl); composed
inviter-side **verification** (`session::verify_accepter`, incl. TLS-cert
binding) and the **handler**; the sender-side **`build_material`** (symmetric
exchange). **Live:** the HTTP bootstrap endpoint over the M5 TLS layer
(`axon-transport::bootstrap::serve` on `tls::bootstrap_server_config`), proven
end-to-end over mTLS — the **Layer-1 interop checkpoint**. Server is generic
over the ledger. **Persistent ledger done:** `PairingLedger` is now fallible
(`Result`, so `commit_consumed` cannot silently fail), and `impl PairingLedger
for Store` (schema V3: `invitations`, `pending_pairs`, sealed) survives restart
with `purge_expired_pairing` GC — proven end-to-end over mTLS.
**Peer persistence done:** a successful bootstrap now stores the paired peer
(the §8.1 identity tuple, endpoint id from the card interface URL, projection vs
full-card digests) via the `PairingStore` trait — `Store` persists to the
encrypted `peers` table; proven end-to-end (pair over mTLS, then `get_peer`).
**Security-hardened** (self-review of the bootstrap/persistence flow): fixed
peer-identity overwrite (a pairing can no longer silently replace an existing
peer that shares an attacker-chosen agent id — refused via `detect_change`, §8.4)
and unbounded request body (64 KiB cap, 413); added token-bucket rate limiting on
`serve`. **Two-way pairing complete:** the inviter builds a real per-request
response (`build_material`); `verify_accepter` is symmetric (explicit subject
cert); the accepter-side client (`client::accept_invitation`) connects over the
pinned TLS, presents its material, verifies the inviter's response, and pins it —
proven by `two_way_pairing_both_sides_pin_each_other` (both stores hold the other
as a verified peer, the G0 shape). **Lifecycle/ops hardening done:**
enable-only-when-pairing gate (`PairingLedger::any_pairing_open` — no live
invitation and no retriable consumed record ⇒ the bootstrap endpoint answers 404,
as if unmounted); pending→active *confirmation* (schema V4 `status` column, a
freshly paired peer lands pending — `store_pending_peer` — until `confirm_peer`,
which audits `peer.confirmed`; `pending_peer_ids`/`peer_status` expose it);
peer removal + explicit re-pair (`remove_peer` audits `peer.removed` and deletes,
then a fresh pairing re-lands pending — the hijack guard is never bypassed).
**Remaining (deferred to daemon-assembly milestone, both binaries still stubs):**
QR invitation transfer; `axon pair confirm` / `axon endpoint check` /
`axon pair diagnose` CLI.
*Exit:* §20.2 pairing suite: exact-transcript retry idempotent,
changed-transcript rejected as attack, secret never logged, MITM/wrong-cert
matrix fails closed. Demonstrated on two real machines (G0 pairing gate).
Also the **Layer 1 interop checkpoint** (below): first live cross-
implementation handshake via the signed Agent Card fetch over mTLS.

### Track 3 — the decision and execution core

**M7. Contract engine (L)** — `axon-contract`
Contract Part extraction (exactly one control Part), DSSE + schema + JCS
digest validation, requester-identity == mTLS origin check, input-manifest
binding of every Part (unmanifested/duplicate/kind/digest mismatch rejects),
revision chain with compare-and-swap head, decision signing (accept /
reject / revision-request), expiry per trusted time (§10.2, §9.3). Risk-card
projection: the five questions as structured data consumed by the CLI (§5.2).
**DONE** (standards-first, all unit+doctested). Pure/crypto core:
`parse_payload` (I-JSON → RFC 8785-canonical assertion → schema → typed +
SHA-256 digest over the signed bytes); `bind_inputs` input-manifest binding
(every Part ↔ exactly one entry by digest; text=utf8-exact, data=jcs; fails
closed on unmanifested/duplicate/multiply-referenced/dangling/kind/media-type/
byte-length/digest); `apply_revision` + `accept_head` compare-and-swap head
(chain-on-exact, lock-on-accept, later siblings/revisions stale); `sign_decision`
/`verify_decision`/`check_binds_to` (contract-decision-pinned DSSE, bound to the
exact proposal); `sign_proposal`/`verify_proposal`/`check_proposal_identities`
(contract-proposal-pinned DSSE + requester==mTLS-origin, performer==local);
`validity` expiry over trusted time; `project_risk_card` (§5.2 five questions as
structured data). Integration: `extract_proposal` (the one contract-control Part
by the ADR-0012 DSSE-envelope media type; raw/URL rejected) → `receive_proposal`
composes the whole pipeline into one **no-effect** entry point (no I/O, no
model/tool/file/URL/credential). Persistence: schema V5 `contract_heads` +
`contracts`, with `submit_revision` (durable CAS), `accept_contract` (lock,
audited), `get_contract`, `purge_expired_contracts`.
**Remaining (deferred, not M7-contract-engine scope):** wiring `receive_proposal`
into a live HTTP receive dispatcher (the A2A server DISPATCH path is deferred to
the tracer bullet, post-M7); the formal no-effect harness (M15 hardening — the
property is structurally guaranteed by `receive_proposal` doing zero I/O).
*Exit:* §20.3 contract vectors; a valid proposal yields an inert
`submitted` Task and provably invokes no model, tool, file, URL, or
credential (no-effect harness, below).

**M8. Local authority (M)** — `axon-authority` — **DONE** (core library)
Capability vector (all components typed now; only v1's four are grantable:
respond, read_supplied_inputs, processor_use, artifact_export §12.1),
deny / allow-once policy, one-shot work order with every §12.3 binding,
atomic claim + budget + nonce consumption, `pending → claimed → running →
succeeded|failed|ambiguous|cancelled`, remote-cancel caveat handling
(TaskNotCancelableError otherwise).
**Done** (all unit-tested): `CapabilityVector` (§12.1 — twelve components named,
only the four v1-grantable carry a `Grant`; the type system prevents granting the
rest; absence is denial, components never imply one another); `WorkOrder`
binding every §12.3 field with a local HMAC (`issue`/`verify` over RFC 8785
bytes — any field change breaks the digest, a recomputed digest still needs the
key); `next` attempt state machine (crash-after-claim → ambiguous, never
auto-retried; terminal states final); durable **atomic claim** in the store
(schema V6 `attempts`: one insert consumes the one-use nonce + reserves budget;
idempotent re-claim, nonce-reuse refused; `advance_attempt` drives transitions;
`resolve_crashed_attempts` → ambiguous); `evaluate` deny/allow-once policy +
`binding_changed` suspension primitive (§12.4, also feeds the §5.2 risk card);
`WorkOrder::remote_cancel_allowed` (§12.1). **Remaining (deferred, not
authority-core scope):** the executor descriptor (CLOEXEC, cgroup-bound, one-use)
is the M9 sandbox/worker handoff; wiring policy→issue→claim into the daemon flow
is M12 assembly.
*Exit:* §20.3 authority suite: work order binds exact task/revision/inputs/
processor/nonce; crash-after-claim resolves ambiguous, never auto-retries.

**M9. Sandbox and clean worker (XL)** — `axon-sandbox`, `axon-worker` — **DONE (isolation)**; worker-run composition is M12
Spike S2 first (ADR-0006, ~1 week, timeboxed): build the candidate launcher,
run the §13.1 checklist as tests, publish profile. Then: namespaces (user,
mount, PID, net, IPC, UTS), `no_new_privs`, default-deny seccomp, cgroups v2
limits, digest-pinned read-only runtime + tmpfs scratch/output, fd allowlist,
private `/proc`, no network, Landlock where available; capability probing
fails closed; worker protocol (input manifest in, bounded progress/result
out) over the work-order descriptor (CLOEXEC, one-use); output gate: size,
media-type, recipient, schema checks (§7.2 step 10).
**Backend decided + backend-independent pieces done** (all unit-tested):
**ADR-0006 accepted — bubblewrap** for the namespace/mount/`pivot_root`/exec
boundary (the independently-reviewed sandbox §13.1/§13.4/§19 require), with
pure-Rust seccomp + Landlock kept (bwrap takes the seccomp BPF via `--seccomp`),
all behind a `SandboxLauncher` trait seam. *(Decision history: bwrap → native →
bwrap; the native reversal was reverted after an adversarial design review found
the reasons were ergonomic not security, and found CRITICAL native gaps — no
inherited-fd allowlist, heavy alloc between fork/exec.)* `BubblewrapLauncher`
(v1 default) `build_argv` authors the hardened policy (unit-tested); `launch()`
probes then execs bwrap. `NativeLauncher`/`build_plan` (`SandboxPlan` as data;
validated user+net entry + `pivot_root` filesystem isolation) is retained behind
the trait as **experimental**, promoted only after independent review + the
review's structural fixes. `axon-worker::gate_outputs`
(the output gate — every result held to the granted §12.1 scope: channel grant,
recipient, artifact media type, byte budget, response/artifact count; rejection
carries the offending index). `axon-sandbox`: fail-closed capability probe
(`detect` reads /proc+/sys honouring Ubuntu's AppArmor userns restriction,
`ensure` refuses a launch when any required feature is missing — validated live:
on this host userns is restricted so it correctly REFUSES); `SandboxSpec` +
`BubblewrapLauncher::build_argv` (the isolation policy as the bwrap argv —
--unshare-all/no-network, --die-with-parent, --cap-drop ALL, --clearenv, private
/proc+/dev, ro-bind digest-pinned runtime, tmpfs scratch/output, --seccomp fd,
--chdir — unit-tested; `launch()` probes first, fails closed).
**Four isolation pillars implemented and VALIDATED** (locally, with userns enabled
for the session, and by CI's `isolation` job on push):
- **seccomp** — `SeccompPolicy` default-deny allowlist compiled via `seccompiler`;
  `apply` sets `no_new_privs` + installs; a fork test proves a denied `socket()` is
  blocked (needs no userns).
- **Landlock** — `LandlockPolicy` read-only/read-write path confinement via
  `restrict_self`, best-effort per §13.1; a fork test proves a write outside the
  granted set is denied (needs no userns; CI-portable skip if unavailable).
- **Namespaces** — `enter_namespaces` unshares the set and maps uid/gid to root in
  the user namespace; a fork test proves mapped-root and no external network.
- **Mount/`pivot_root`** — `setup_root` builds a tmpfs root with read-only runtime
  binds (locked-flag-preserving remount) + tmpfs scratch, `pivot_root`s in, detaches
  the old root; a fork test proves ro-bind read-but-not-write, writable scratch, and
  the host filesystem gone. Plus the `NativeLauncher`/`SandboxPlan` policy and the
  fail-closed probe. `axon-sandbox` carries a documented crate-level
  `#![allow(unsafe_code)]` (it is the workspace OS-syscall boundary; every `unsafe`
  block has a `SAFETY:` note).
**Clean-worker launch FUNCTIONALLY COMPLETE via the reviewed backend, validated
end-to-end** (bwrap 0.11.1 + userns + delegated cgroup): `launch_confined` composes
probe → bubblewrap namespace/mount/`pivot_root`/exec isolation → the seccomp filter
(compiled to a memfd, handed via `--seccomp`; inherited-fd allowlist satisfied by
`std`'s CLOEXEC default) → cgroup v2 confinement (a leaf cgroup under the delegated
subtree with memory/pids/cpu limits; the worker moved in via a no-alloc `pre_exec`)
→ the output gate. Live tests confirm each layer from inside a real worker: host
`/etc` gone + env cleared + scratch writable; `Seccomp: 2`; a 64 MiB/16-pid cgroup
enforced. `diagnose()` backs `axon doctor` (every capability + fail-closed gate).
**Input staging + doctor + the full-stack seam are done.** `axon-worker::stage_inputs`
materialises exactly the approved inputs into a directory (with a `manifest.json`
of in-sandbox paths + SHA-256) the daemon read-only-binds — fails closed on unsafe
(slug-only, no traversal) / duplicate ids (§7.2 step 9, §13.1). `axon doctor` (the
M9 exit surface) renders `diagnose()` with a fail-closed exit code. An adversarial
review flagged that isolation lived in side-path helpers, so `SandboxLauncher::launch`
is now the *only* public launch entry and requires both a `SeccompPolicy` and a
`CgroupScope`: a partially-isolated launch is unrepresentable (no fail-open by
omission §13.1); the seccomp-only / pre-made-scope paths are `pub(crate)` building
blocks.
**Landlock at the worker entrypoint is done.** `SandboxSpec::landlock_profile`
derives the worker's Landlock policy straight from the spec's filesystem boundary
(read+execute the runtime binds and staged inputs, read-write the scratch/output
tmpfs, everything else denied); the worker applies it as its first in-sandbox
action — defense-in-depth inside the mount namespace. Validated live (read-not-write
a bind, write the tmpfs, no access outside) and by a pure-derivation unit test.
**§20.5 EXIT CRITERIA MET (validated live under bwrap + userns):** empty environment,
no host reach (`/etc` gone), **no generic network** (the worker's `/proc/net/dev`
lists only loopback — fresh net namespace), deadline/resource enforcement (64 MiB /
16-pid cgroup), probing fails closed, and `axon doctor` reports every capability.
**M9 clean-worker isolation is COMPLETE.**
**Deferred (properly M12 daemon assembly, not M9):** the worker protocol tail — the
runtime composition that stages the approved inputs, ro-binds them, launches via the
full-stack seam, and gates the bounded result — plus clone3 `CLONE_INTO_CGROUP` for
race-free cgroup placement (the current `pre_exec` placement is already correct;
clone3 would need hand-rolled fork/exec, the heavy-unsafe path the review cautioned
against, for a marginal gain). The experimental `NativeLauncher` (validated user+net
entry + `pivot_root` fs isolation) awaits independent review + the review's
structural fixes before it could ever be default.
*Exit:* §20.5 suite: empty environment, no host reach, no generic network,
deadline/resource enforcement, probing fails closed; `axon doctor` reports
every capability. **— all met.**

**M10. Processor broker (M)** — `axon-broker` — **CORE + DURABLE STATE DONE**
Only egress path for approved plaintext. Durable sub-attempt
(`prepared → dispatching → completed|failed|ambiguous|cancelled`), stored
provider/origin/config digest/request digest/idempotency key/cost bound
before dispatch, no redirects or ambient proxies, DNS/address-class checks,
credentials never leave the broker; ambiguous never auto-retries (§13.1).
`axon processor add|list|test` with local/remote disclosure recording
(§4.4, §15.2).
**Done** (standards-first, all unit+doctested): `axon-broker` pure core —
`subattempt.rs` (the state machine; `dispatching` is durable-before-effect, a crash
or cancel while dispatching → `ambiguous` never auto-retried, same crash/cancel
honesty as the attempt machine); `call.rs` `ProcessorCall::prepare` (the pre-dispatch
record with provider/origin/config-digest/request-digest/work-order-binding/cost/
deadline/limit + a deterministic idempotency key from `(work_order,config,request)`
so an exact retry reuses it); `address.rs` the two fail-closed egress gates —
`check_origin` (https + exact allowlist) and `check_resolved_address` (globally-
routable unicast only; loopback/private/link-local/unique-local/multicast/ipv4-mapped-
inward refused — anti-SSRF/rebinding; local processors opt in); `processor.rs`
`ProcessorConfig` + `Disclosure` (local/remote, operator/region/retention/training/
subprocessors §15.2) with `config_digest` binding the exact approved provider/origin/
model. Durable in `axon-store` schema V7: sealed `processors` (put/get/list) +
`processor_calls` (`prepare_call` idempotent-before-dispatch, `advance_call` self-CAS,
`resolve_crashed_calls` → ambiguous — the kill-during-dispatch exit criterion).
**Remaining (M12 assembly):** the live HTTPS dispatch (redirect-disabled reqwest/hyper
client, connection-time DNS validation calling `check_resolved_address`, credential
injection that never leaves the broker); credential storage (sealed, keyed by
processor); the duplicate-disclosure operator prompt on `ambiguous`; and the
`axon processor add|list|test` CLI verbs.
*Exit:* §20.5 broker suite; kill-during-dispatch yields ambiguous with the
duplicate-disclosure prompt path.

**M11. Evidence and outcome (L)** — `axon-evidence` — **STANDARDS CORE DONE**
`result-manifest-v1` build + JCS + DSSE; staged-then-atomic completion
(never partial completed §14.1); in-toto Statement v1 authorization and
execution attestations; SARIF 2.1.0 Errata 01 profile parser (hostile-input
limits, byte preservation, no URI fetch); required evidence slots with
orthogonal result × disclosure; `axon evidence validate|export` including
the portable personal verification pack; requester outcome as task-less
SendMessage with fixed receipt (§14.5); trust-class labeling from local
policy only.
**Done** (standards-first, all unit+doctested): `ResultManifest` (§14.1) —
`assemble` puts every array in the normative canonical order and `validate` enforces
that order *in code* (RFC 8785 sorts object keys, not array elements), schema-valid,
`bundle_digest` = *the* §14.1 bundle digest, `sign`/`verify` DSSE under the
task-result key. `check_slots` (§14.3) — "omission cannot look like success":
missing/non-passing/under-disclosed slots fail, result × disclosure stay orthogonal.
`Outcome` (§14.5) — binds the bundle digest + contract, DSSE under the
requester-outcome key, `check_binds_to` refuses replay; `fixed_receipt` is the
model-free acknowledgment. `parse_sarif` (§14.2) — hostile-input SARIF (I-JSON
limits, original-byte digest preserved, no URI fetch, bounded findings + truncation
count). `Statement` (§14.2) — in-toto Statement v1 (payloadType
`application/vnd.in-toto+json`), DSSE under the evidence key, `execution_over` covers
exactly the outputs; authorization/execution predicate types pinned. Each object
uses a *distinct* purpose key, so keys can't cross-sign.
**Remaining:** trust-class derivation (§14.4, from validated identities not
self-asserted fields); the composed `axon evidence validate` (the §14.2 V1 check
list); golden vectors + xcheck cross-check (the exit's "independent validator
validates a bundle"); durable staged-then-atomic completion in `axon-store`; and
`axon evidence export` + the portable verification pack + the CLI verbs (M12).
*Exit:* §20.6 suite; an independent validator (xcheck) validates a real
bundle without the producer's database (design §4.3).

### Track 4 — product surface

**M12. CLI and daemon assembly (L)** — `axond`, `axon-cli` — **CONTROL-PLANE SPINE DONE**
Local admin socket vs worker socket separation with peer-credential checks
(§16.2); OpenAPI 3.1 control API + RFC 9457; every §16.4 command; risk card
rendering (concrete approval sentence, expandable detail); quiet arrival
(no foregrounding, bounded inbox, local block/rate-limit §5.3); `axon
doctor` (§17.3); personal vs isolated profile wiring.
**Done** (the §16.2 security spine, all unit+integration-tested): `axond` is now a
lib+bin. `control.rs` — the two surfaces + `authorize`; every op declares its minimum
surface so the worker surface can never pair/policy/approve/issue/sign/export (the
exact §16.2 prohibitions); refusals are structure-free RFC 9457 `Problem`s.
`peercred.rs` — `SO_PEERCRED` auth, a peer is refused unless its UID is the daemon's
(scoped `unsafe`, socketpair-tested). `socket.rs` — `bind_socket` (0600),
`handle_connection` (authenticate → read → authorize-by-surface → dispatch →
respond), the `serve` loop, and the `send_request` client (newline-delimited JSON).
`axond serve` binds admin+worker sockets on a 0700 runtime dir; `axon status`
queries the daemon over the admin socket (`axon doctor` stays a daemon-free host
check). Validated LIVE: status → sandbox_ready/exit 0, fail-closed with no daemon,
sockets 0600, worker-surface admin op → 403.
The **A2A receive-dispatch logic is done**: `axond::dispatch_proposal` composes the
deferred M5/M7 receive path (idempotency peek → `receive_proposal` validation →
durable rev-0 open head → durable-before-response idempotency commit) into
`DispatchOutcome {Submitted|Duplicate|Conflict|Rejected}` — a rejection never creates
a Task. Tested in-memory (valid→Submitted+persisted, replay→Duplicate, changed-covered
→Conflict, wrong-key→Rejected). Added `axon_contract::expires_at_unix`.
**Remaining (the bulk of assembly, on these gates):** the OpenAPI 3.1 description +
generated clients; the HTTP/mTLS **receive server** that parses the A2A SendMessage +
runs `ingress::admit` + feeds `dispatch_proposal` + builds the A2A Task response
(follows the `axon-transport::bootstrap::serve` pattern); the broker live HTTPS
dispatch (M10); `axon processor`/`evidence`/`pair`/`task`/`outcome` verbs; durable
staged-then-atomic completion (M11); risk-card rendering (over M7 `project_risk_card`);
quiet arrival (bounded inbox, local block/rate-limit §5.3); personal vs isolated
profile wiring; and the full `axon demo review` receive half.
*Exit:* full loop driveable by CLI alone on one host; doctor output reviewed
against §17.3 list.

**M13. Adapters (L)** — `axon-adapter-sdk`, `adapters/*`
Adapter contract + conformance fixtures (§16.3): input manifest in, bounded
artifacts out, no recipient/network selection, passive-arrival and
duplicate-delivery tests. OpenCode adapter with a documented fully local
model path (no vendor account); Codex adapter via its supported
non-interactive task-bounded interface. If either cannot meet the contract,
the replacement ADR is written *here*, per §4.4.
*Exit:* G0 adapter gate: one Message/Task/status/Artifact round trip through
both adapters without semantic loss; both complete the code-review fixture
(§20.8).

**M14. Packaging and profiles (M)**
Signed .deb/.rpm, systemd user service (personal) and dedicated system
service (isolated), guided installer recommending isolated, `axon init`,
key/db bootstrap, migration + rollback-tested backups (§4.4, §17.3). SBOM +
dependency provenance in CI (§17.2).
*Exit:* fresh-VM install from package to working `axon init` with no manual
steps.

**M15. Hardening, gates, and release (XL)**
Fuzz targets (A2A parse, contract, manifest, SARIF, pairing bootstrap) with
`cargo-fuzz`; crash matrix runner (kill at every named commit point across
network/daemon/db/adapter/worker — §19 Phase 1 gate); no-effect proofs for
every inbound operation; two-machine benchmark of the ten-minute loop and
five-minute demo; SVG/Markdown/Mermaid/Graphviz inert-source checks (§20.4);
usability pass on risk card and state vocabulary (§20.8); threat model
published; maintainer sign-off on the extension surface (G0 final gate).
*Exit:* every §19 Phase 1 gate item checked; tag v0.1.0.

### Review-tracked follow-ups

The Codex review of M0–M2 (`spec/reviews/2026-07-16-codex-m2.md`) surfaced
genuine gaps whose implementation belongs to later milestones. They are
anchored here so they are not lost:

- **M3** — JWS Agent Card signature verification (ADR-0007): **done** —
  `axon_proto::card_sig::verify_card` over `axon_crypto::jws` (EdDSA/JOSE,
  RFC 7638 `kid`, header allowlist), golden vector `jws/agent-card-eddsa`
  cross-checked. Pinning the verification key at pairing remains M6.
- **M5** — outbound `validate_task`/`validate_artifact`/response-echo profile
  checks; couple Message validation to the negotiated extension set.
- **M5/M6** — self-issued X.509 endpoint certificate generation (moved from
  M3): **done** — `axon_crypto::cert::self_signed_endpoint` (pure-Rust
  `x509-cert` + `ed25519-dalek`, ADR-0011), purpose-gated to `tls-endpoint`,
  self-signature verified, fingerprint via `identity::Fingerprint::cert_sha256`.
  Remaining: wire it into the rustls mTLS listener (M5 transport).
- **M6** — at pairing, verify each transported key-binding thumbprint equals
  its JWK: **done** — `axon_pairing::key_binding::verify` (schema gate +
  thumbprint==RFC 7638(JWK) + validity).
- **M7** — input-manifest ↔ exact Message-Part binding and per-field
  uniqueness; contract timestamp ordering and TTL maxima (with M8 trusted
  time); full processor/resource ceilings; minimum-disclosure policy.
- **M11** — result-manifest semantic validation (evidence resolution,
  bytewise ordering, dup-role/slot rejection) and per-attempt/task evidence
  binding.
- **M15 (hostile-input)** — a hostile A2A **data Part** is decoded by prost and
  converted (`extraction.rs::to_json`) then JCS-canonicalised in `bind_inputs`
  without the I-JSON depth/node caps the contract payload gets, so a deeply
  nested/huge data Part is a CPU/stack DoS on the receive path (digest still
  fails closed — not a correctness/authorization defect). Fix belongs with the
  A2A-parse fuzz/recursion-bound work: bound prost decode depth and apply
  `ijson` depth/node limits to each data Part before canonicalisation. (From the
  M7–M9 adversarial review, 2026-07-18.)
- **ADR (before M5)** — **done** (ADR-0010): standard A2A objects preserve
  non-critical unknown fields via `pbjson ignore_unknown_fields()`, unknown
  safety-critical enum values still reject, extension objects stay
  reject-unknown. Remaining: verify/forward over *original bytes* (not the
  typed re-serialization) on the M5 receive path (card_sig refinement).
- **M6/M14 (endpoint certificate rotation)** — the daemon's endpoint
  certificate is minted once at bootstrap for `ENDPOINT_CERT_VALIDITY` (365
  days, `axond::bootstrap`) and persisted, because its SHA-256 is exactly what
  peers pin at pairing (§8.1) — regenerating it moves the fingerprint and
  breaks every pinned peer. There is **no rotation path**. Until 2026-07-20 the
  TLS verifiers ignored the certificate's validity window, so an expired
  certificate kept authenticating silently; now that
  `axon_crypto::cert::check_cert_time_validity` is enforced by all three
  verifiers, an endpoint simply **stops being reachable by every paired peer
  one year after first start**, with no in-band recovery. Needed: mint a
  successor before expiry, carry both (old + new fingerprint) through an
  overlap window, distribute the new fingerprint over the existing
  authenticated channel so peers re-pin without an out-of-band invitation, and
  surface remaining validity in `axon doctor` / `axon peer list`. This is a
  liveness cliff, not an authorization defect — it fails closed. (From the
  M13-era security review, 2026-07-20.)
- **M12 (operator-configurable operation ceiling)** — `approve.rs`
  `MAX_OPERATIONS` is a hardcoded `const` (now 64, was 1_000_000 — a ceiling
  that bounded nothing until the durable ledger landed). It is the aggregate
  number of processor calls one approval may make, so it directly bounds
  worst-case spend at `MAX_OPERATIONS × max_cost_microusd`; the right value is
  policy, not a constant. Needed: carry it on the approval (a
  `--max-operations` on `axon task approve`, defaulted by standing policy
  §12.4) so an operator can raise it for a genuinely long task without
  recompiling, and lower it for untrusted peers. (From the M13-era security
  review, 2026-07-20.)

### Tracer bullet checkpoint (after M7 + a minimal M8)

**Execution half DONE** (`harness/runner/tests/clean_worker_e2e.rs`, 2026-07-18):
the M8→M9 spine is proven end-to-end — a locally-issued, MAC-verified work order →
stage exactly the approved inputs → launch a fully-confined worker (namespaces +
mount + seccomp + cgroup, via the only public seam) that reads them and writes a
bounded result → gate that result against the work order's respond grant (and reject
an over-budget one). The worker is a dev-only pure-shell echo (non-shippable, §4.4).
Runs in CI's isolation job. **Remaining (receive half, M12):** the proposal →
contract → decision → work-order-issue path over the live HTTP dispatch, and exposing
it as the `axon demo review` CLI verb behind a `dev-insecure-worker` feature.

As soon as contract + authority exist, wire `axon demo review` end-to-end on
localhost using the real schemas, real signing, real store — with a dev-only
subprocess worker (clearly non-shippable, behind a `dev-insecure-worker`
feature that release builds cannot enable) and a dev-only echo processor.
This proves the six-state spine integrates before the sandbox lands, and
becomes the permanent integration test. The echo path never satisfies any
gate (§4.4) and is never packaged. This is also the **Layer 2 interop
checkpoint** (below): the first full task lifecycle across two independent
stacks.

### Cross-implementation interop checkpoints

Two independent implementations flush out spec-prose ambiguities that one
implementation cannot see. Stage the interop deliberately by layer — each
isolates a distinct failure class, so hit them in order rather than debugging
transport, canonicalization, and protocol semantics at once. "Independent
peer" means genuinely different code: the Python `xcheck`, a reference A2A SDK
(`a2a-python`/`a2a-js`) driven as a conformance peer, or a second daemon — not
a re-run of the same Rust.

- **Layer 0 — agree on bytes (continuous, from M1).** An independent
  implementation reproduces every frozen vector's canonical bytes/signatures;
  no wire involved. This is `xcheck/` today (it already caught the `serde_jcs`
  UTF-16 bug and validated the Agent Card JWS pipeline). *Best time:* per
  canonical format, the moment it is frozen. A second independent reproducer
  (e.g. Codex regenerating `spec/vectors/`) is additive insurance here.
- **Layer 1 — one request over real mTLS (at M6).** Catches framing,
  `application/a2a+json`, `A2A-Version`/`A2A-Extensions` headers, TLS 1.3 and
  cert pinning — the wire, not the semantics. *Best time:* M6, using the
  **signed Agent Card fetch** as the first cross-implementation handshake: the
  card is fully specified and vector-covered, so a mismatch is unambiguously a
  transport/framing bug. Needs M5 transport + M6 pairing.
- **Layer 2 — a full task lifecycle (at the tracer bullet).** Propose →
  accept → work-order → result → outcome across two independent stacks;
  exercises extension negotiation, the six-state matrix, and contract/decision
  signing. *Best time:* the tracer-bullet checkpoint above (contract +
  minimal authority). This is the first genuine *conversation*, and the
  compelling demo form — two different agent brains (e.g. Codex and Claude),
  each speaking through a conformant transport — is meaningful here.

The interop peer at Layers 1–2 should include a reference A2A SDK, because the
bug worth finding is "axon vs. the reference", not "axon vs. a second axon that
shares axon's assumptions".

### Dependency sketch

~~~text
M0 -> M1 -> M2 ------------------\
   \-> M3 -> M4 -> M5 -> M6 ------> M7 -> M8 -> [tracer bullet]
              S2 spike -> M9 ----/         \-> M10 -> M11 -> M12 -> M13 -> M14 -> M15
~~~

Parallelizable from the start: M1/M2 (formats) alongside M3/M4 (identity/
state); the S2 sandbox spike alongside M5–M7. Good agent-delegation units:
golden vectors + xcheck, negative-vector suites, fuzz targets, crash-matrix
runner, packaging.

## 7. Verification strategy (design §20 → concrete harnesses)

- **Golden vectors + independent cross-check** (`spec/vectors/`, `xcheck/`):
  every canonical byte, digest, DSSE signature, and dedup tuple verified by
  Python implementations we don't write the Rust code against. Runs in CI.
- **No-effect harness** (§20.3): all effect capabilities (model call, file
  open outside store, URL fetch, process spawn, credential read) live behind
  seams in trusted crates; the harness drives every inbound A2A operation
  against a spy implementation asserting zero calls, plus an strace-based
  integration variant for the assembled daemon.
- **Crash matrix**: named commit points (receive-store, tombstone write,
  decision sign, work-order claim, broker dispatch, result stage, completion
  commit, outcome record) each get a kill-and-restart test asserting the
  §6.3 invariants (no lost receipt, no duplicate attempt, ambiguous where
  required).
- **Two-endpoint e2e** (`tests/e2e/`): docker topology adapted from c2c —
  two containers, separate volumes, traffic forced over the network, sealed
  with resource limits. Containers are test infrastructure only, not release
  artifacts (§4.4).
- **Fuzzing**: `cargo-fuzz` targets for every parser that touches peer bytes;
  corpus seeded from vectors; limits-before-allocation asserted.
- **Parser-safety suite** (§20.4): byte/nesting/count boundaries, URL
  never-fetch, SVG/Markdown/Mermaid/Graphviz inert-source, SARIF strict
  profile.
- **Storage/privacy scans** (§20.7): grep-style scans of db, WAL, temp files,
  logs, and core dumps for planted plaintext markers after full-loop runs.
- **Benchmarks** (§4.3): scripted fresh-install timing for the demo and
  cross-host loops; separate setup benchmark for processor install so the
  headline metric can't hide it.

## 8. Risks

| Risk | Mitigation |
|---|---|
| A2A 1.0 pin drifts or protos change | Vendor protos + conformance vectors in-repo; profile doc records exact commit/version; §18 rules for updates |
| No qualifying Rust envelope-encryption library (ADR-0005) | Adopt Tink's ciphertext format with reference vectors; worst case is more test surface, not a new format |
| Sandbox launcher scope creep (M9 is the hardest milestone) | Timeboxed S2 spike with a published checklist; bubblewrap fallback keeps us on a reviewed launcher; fail-closed probing ships regardless |
| Codex non-interactive interface volatility (seen in c2c) | Adapter SDK isolates it; §4.4 replacement-ADR rule; OpenCode local path is the independent second adapter |
| Extension namespace domain not secured | Development proceeds on a placeholder constant; release gate blocks on it; single-module change to swap |
| Keystore/TPM absent on target machines | ADR-0009: report rollback detection unavailable and degrade per §15.5 rather than block install |
| Solo bandwidth vs. design breadth | Tracer bullet keeps an integrated loop green from mid-plan; deferred list (§4.2) is a hard no-new-scope boundary |

## 9. Immediate next steps

1. M0: scaffold the workspace, CI, `spec/` skeleton, ADR-0001..0004.
2. Start M1 (schemas + vectors + xcheck) and M3 (keys) in parallel.
3. Vendor A2A protos and open the M2 mapping doc.
4. Kick off the S2 sandbox spike (ADR-0006) — longest-lead risk.
5. Maintainer actions: secure the extension-namespace domain; confirm
   Apache-2.0.
