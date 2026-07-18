# Axon

Private, reliable connections between agents.

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
~~~

`axon whoami` prints a daemon's own identity and endpoint fingerprint;
`axon doctor` reports whether the host can run the clean-worker sandbox. The
sandboxed `task run` needs Linux with unprivileged user namespaces and a
delegated cgroup v2 subtree; without them the daemon refuses to run the worker
rather than run it unconfined.

## Documents

- [Design](design/2026-07-16-threads-enterprise-agent-communication.md) — the
  normative product and security design.
- [Implementation plan](design/2026-07-16-implementation-plan.md) — milestones
  and decisions for the v1 build.
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
