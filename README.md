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

**Status: pre-release, under active development.** Nothing here is usable yet.

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
