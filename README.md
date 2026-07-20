# Axon

![Status: pre-release](https://img.shields.io/badge/status-pre--release-orange)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-dea584?logo=rust&logoColor=white)
![License: Apache-2.0 (proposed)](https://img.shields.io/badge/license-Apache--2.0%20%28proposed%29-blue)

**Private, reliable connections between agents.**

> Connect an agent, approve exactly what it may do, and receive a result whose
> inputs, producer, limits, and verification can be checked independently.

Axon is an open-source, local-first gateway that lets independently operated
agents exchange tasks, messages, artifacts, and evidence — without sharing
credentials or giving a peer ambient access to the local machine. It speaks
standard [A2A 1.0](https://a2a-protocol.org/latest/specification/) over
mutually authenticated TLS 1.3 and adds a small, versioned extension surface
for signed task contracts, durable delivery, and portable evidence.

**Status: pre-release, under active development.** The end-to-end spine now runs
as a developer preview — two daemons pair, exchange a signed task, run it in a
real sandbox, and settle a verifiable outcome (see [Try it](#try-it)) — but key
custody is interim, the worker is a shell stand-in, and extension namespaces and
licensing are not finalized. Not yet fit for real use.

The first product slice is a two-party code review:

~~~text
authenticated request -> inert durable task -> explicit local decision
-> bounded clean execution -> standard evidence -> independently checkable outcome
~~~

1. Two endpoints pair without any hosted account.
2. A requester sends a signed `code_review.v1` proposal with an immutable
   change.
3. The reviewer sees one risk card and approves or denies the exact contract.
4. An approved clean, sandboxed worker receives only the supplied change.
5. It returns findings (SARIF) and signed evidence (DSSE/in-toto).
6. The requester validates the bundle independently and signs an outcome.

## 🔒 Security, privacy & safety

Axon carries one core principle:

> A peer's commands run in a **separate, enforced, reduced-authority domain**.
> The agent's own user-granted authority is never touched.

Everything below is how that line holds, stated as what axon does. Each property
is grounded in the [threat model](design/2026-07-19-threat-model.md) and the
[design](design/2026-07-16-threads-enterprise-agent-communication.md) (§ marks
the section).

| Guarantee | How axon holds it |
|---|---|
| **Direct and local-first** | Two endpoints pair with no hosted account and no relay, over mutually-authenticated TLS 1.3, pinning each other's certificate by fingerprint at pairing — not by CA or DNS. (§8.2, §9.1) |
| **Arrival is not execution** | Receiving any message, task, artifact, or control frame never starts a model, mints authority, touches a workspace, invokes a tool, or fetches a URL. Arrival is quiet and abuse-resistant. (§6.3) |
| **Grant-derived sandbox** | Peer work starts from zero ambient authority: fresh user/mount/pid/net namespaces, default-deny seccomp, Landlock, cgroup limits, dropped capabilities. Only the named inputs and one output are constructed in — a prompt-injected task has no socket and no host filesystem. (§13.1) |
| **Sealed model access** | `socket()` and `connect()` are denied. A model is reachable only through the broker: the worker inherits one already-connected fd, and the daemon makes the real call, injecting the credential and enforcing an egress allowlist and budget. The model credential never enters the worker. (§13.1) |
| **Strict adapter profile** | A production adapter runs as a single process that cannot create another — no `fork`, `clone`, or `vfork`. Even a shell reached via `execve` cannot spawn a command. |
| **Explicit human decision** | The operator sees one risk card and approves or denies the exact signed contract. The outward-disclosing grants — reaching a model, exporting an artifact — are never automatic. (§5.2) |
| **Verifiable outcomes** | Results are signed (DSSE/in-toto) and findings are standard (SARIF); the requester validates the bundle independently and signs an outcome. Effects are durable-before-effect, and honest crash recovery marks the uncertain `ambiguous` rather than done. (§7.2, §14.5) |
| **Inert evidence** | Rendered artifacts (SVG, HTML, Graphviz, Markdown, Mermaid) are scanned for active content — scripts, event handlers, external fetches — and refused before delivery. (§20.4) |
| **Hardened parsing & storage** | Bounded, canonical inputs (I-JSON caps, JCS) fail closed at every gate, backed by fuzz and hostile-input suites; the durable store is envelope-encrypted at rest under a trusted-time floor. (§11.1, §15.1) |

These are the properties axon is built to hold. Key custody is still interim and
a few residual risks remain open — the
[threat model](design/2026-07-19-threat-model.md) tracks each one, honestly.

## Try it

A full two-party round trip between two local daemons — `alice` (requester) and
`bob` (performer) — driven entirely by the `axon` CLI. Everything stays on the
loopback interface over mutually authenticated TLS; no hosted account is
involved.

Build the daemon and CLI:

~~~text
cargo build -p axond -p axon-cli   # produces target/debug/{axond,axon}
~~~

**Terminal A — start `bob`, the performer.** `AXON_WORKER_CMD` is the worker the
sandbox runs for an approved task; here it is a pure-shell stand-in that reads the
supplied input and writes a response.

~~~text
export XDG_RUNTIME_DIR=/tmp/bob AXON_DATA_DIR=/tmp/bob-data
export AXON_ISSUER=orgB AXON_AGENT=bob
export AXON_INTERFACE_URL=https://127.0.0.1:18444/a2a
export AXON_RECEIVE_ADDR=127.0.0.1:18444 AXON_PAIR_ADDR=127.0.0.1:19444
export AXON_WORKER_CMD='[ -r /inputs/diff ] || exit 40; printf "reviewed: LGTM" > /output/response'
mkdir -p "$XDG_RUNTIME_DIR"; target/debug/axond serve
~~~

**Terminal B — start `alice`, the requester.**

~~~text
export XDG_RUNTIME_DIR=/tmp/alice AXON_DATA_DIR=/tmp/alice-data
export AXON_ISSUER=orgA AXON_AGENT=alice
export AXON_INTERFACE_URL=https://127.0.0.1:18443/a2a
export AXON_RECEIVE_ADDR=127.0.0.1:18443 AXON_PAIR_ADDR=127.0.0.1:19443
mkdir -p "$XDG_RUNTIME_DIR"; target/debug/axond serve
~~~

**Terminal C — pair them, send a task, approve it, run it, deliver the result.**
Point the CLI at whichever daemon it should command with `XDG_RUNTIME_DIR`.

~~~text
alice() { XDG_RUNTIME_DIR=/tmp/alice target/debug/axon "$@"; }
bob()   { XDG_RUNTIME_DIR=/tmp/bob   target/debug/axon "$@"; }

# 1. Pair (alice invites, bob accepts), then each confirms the new peer.
alice pair invite /tmp/inv.json
bob   pair accept /tmp/inv.json
alice peer confirm bob
bob   peer confirm alice

# 2. alice sends a code-review task to bob.
cat > /tmp/task.json <<'JSON'
{ "performer": "bob",
  "task_type": "https://axon.invalid/task/code-review/v1",
  "objective": "Review the supplied diff.",
  "inputs": [{ "id": "diff", "media_type": "text/x-diff", "text": "--- a\n+++ b\n" }],
  "deliverables": [{ "role": "review", "media_type": "text/plain" }],
  "capabilities": ["respond", "read_supplied_inputs"],
  "deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 8192 }
JSON
alice task send /tmp/task.json          # -> task-<id>

# 3. bob reviews the risk card, approves (issuing a one-shot work order),
#    runs the worker in the sandbox, and delivers the signed result.
bob task inbox
bob task show    task-<id>              # the §5.2 risk card
bob task approve task-<id>
bob task run     task-<id>              # confined worker: reads /inputs, writes /output
bob task deliver task-<id>

# 4. alice records the verifiable outcome; the bundle digest matches bob's.
alice task outcomes

# 5. ...and reads what bob actually produced. The delivery carried the bytes
#    alongside the signed manifest, and alice accepted them only because each
#    re-hashed to the digest bob signed for.
alice task output task-<id>              # role, media type, size, digest
alice task output task-<id> --role response   # just the bytes, ready to pipe
~~~

`axon whoami` prints a daemon's own identity and endpoint fingerprint;
`axon doctor` reports whether the host can run the clean-worker sandbox. The
sandboxed `task run` needs Linux with unprivileged user namespaces and a
delegated cgroup v2 subtree; without them the daemon refuses to run the worker
rather than run it unconfined.

### Review with a real model

The stand-in worker above just echoes. A real reviewer runs one of the bundled
adapters, which reach a model **only through the broker** — the confined worker
has no network of its own, so the daemon makes the credential-injected, budgeted
call on its behalf. Build an adapter and make it `bob`'s worker command (needs a
reachable model endpoint and an API key, so this steps outside the loopback demo):

~~~text
cargo build -p axon-adapter-openai        # or -p axon-adapter-anthropic

# AXON_WORKER_EXEC runs the adapter DIRECTLY — no wrapping shell — under the strict
# adapter seccomp profile: a single confined process that cannot create another
# process (no fork/clone) and cannot open a socket. --sarif emits findings as a
# validated application/sarif+json artifact instead of a plain response. (Use an
# absolute path, or a name on PATH inside the sandbox.)
export AXON_WORKER_EXEC="$PWD/target/debug/axon-adapter-openai --processor gpt --model gpt-4o --sarif"
#   ...then start bob's `axond serve` so it picks up this worker.

# Register the model endpoint as a pinned processor and store its credential.
bob processor add gpt openai api.openai.com 443 ca --path /v1/chat/completions --auth bearer
bob processor credential gpt "$OPENAI_API_KEY"
~~~

Reaching a model and exporting an artifact are the two *outward-disclosing*
grants: the task must request them, and `bob` must grant each explicitly at
approval — neither is ever automatic.

~~~text
# In the proposal, alongside respond/read_supplied_inputs:
#   "capabilities": ["respond", "read_supplied_inputs", "processor_use", "artifact_export"]
bob task approve task-<id> --processor gpt --artifacts   # grants processor_use + artifact_export
bob task run     task-<id>                               # confined adapter -> broker -> model -> SARIF
~~~

The returned SARIF is validated before it is emitted, so a model that answers with
malformed or oversized findings fails closed. For Anthropic's Messages API, use the
Anthropic adapter and point the processor at it instead:
`... anthropic api.anthropic.com 443 ca --path /v1/messages --auth x-api-key --header anthropic-version:2023-06-01`.

### Two agents, cooperating

Because a delivered result carries its bytes, the requesting side can *read* what
its peer produced and send the next task built from it. That turns the one-shot
round trip into a working conversation between two agents that own different
components:

~~~text
alice owns the web UI                    bob owns the API server
  1. alice → bob   feature  "add GET /stats"
  2. bob   → alice feature  "it's live, here's the shape — render it"
  3. alice → bob   defect   "uptime arrives in ms, the shape says seconds"
  4. bob   → alice feature  "added error_rate, render that too"
  5. alice → bob   defect   "/stats 500s when users = 0"
  6. bob   → alice confirm  "fixed — re-check against the shape"
~~~

Neither side ever sees the other's source: the only thing that crosses is a signed
task and its signed result. Both endpoints send *and* perform, so each pins the
other's proposal and task-result keys at pairing.

- `crates/axond/tests/cooperation_e2e.rs` runs the whole scenario hermetically
  (`cargo test -p axond --test cooperation_e2e`). Its closing assertion is the
  point: every round's input digest equals the previous round's output digest, so
  the six exchanges form one unbroken chain.
- `bench/cooperate.sh` runs the same six rounds across two hosts with a real
  model behind each side's worker.

## Acknowledgments

Axon's founding idea comes from **c2c**, a prior agent-communication system:
inbound message content can never satisfy an approval or trigger a privileged
action — *arrival is not execution*. c2c showed that this invariant holds up
under real dogfooding, and it is the spine of axon's security model (§6.3). Axon
reuses c2c's hard-won patterns — durable-before-effect writes, per-purpose nonce
separation, capability tokens that never touch argv or logs — as patterns and
lessons, not code. Axon is an independent Rust implementation. With gratitude to
c2c for the groundwork.

## Documents

- **[Documentation site](docs/index.html)** — the friendly path in: install,
  quickstart, pointing it at a real model, and driving it from Claude Code or
  Codex on Linux. Open the file directly, or serve `docs/` over any static host.
- [Design](design/2026-07-16-threads-enterprise-agent-communication.md) — the
  normative product and security design.
- [Implementation plan](design/2026-07-16-implementation-plan.md) — milestones
  and decisions for the v1 build.
- [Threat model](design/2026-07-19-threat-model.md) — assets, actors, and how each
  defense is realized in the build.
- [Control protocol](spec/control-protocol.md) — the local socket the `axon` CLI
  speaks to a running `axond` (framing, surfaces, operations).
- [ADRs](spec/adr/) — recorded decisions.
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities.

## Development

~~~text
cargo build --workspace
cargo test --workspace
cargo fmt --all --check && cargo clippy --workspace --all-targets
~~~

Rust toolchain is pinned in `rust-toolchain.toml`. Golden vectors under
`spec/vectors/` are cross-checked by an independent Python implementation in
`xcheck/`.

## License

Apache-2.0 (proposed; final maintainer licensing decision is a Phase 1
release gate — see the implementation plan).
