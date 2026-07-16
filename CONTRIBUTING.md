# Contributing

Thanks for your interest. Axon is early — the fastest way to help is to read
the [design](design/2026-07-16-threads-enterprise-agent-communication.md) and
[implementation plan](design/2026-07-16-implementation-plan.md), then pick up
a milestone task or file a focused issue.

## Ground rules

- **Standards first.** Don't add an Axon-specific format when an established
  one fits (design §3). New wire fields need an ADR (design §3.1).
- **Fail closed.** Missing, malformed, or downgraded state resolves to no
  effect — never a warning-and-continue path.
- **No hand-rolled crypto.** Cryptographic primitives come from the reviewed
  libraries pinned in the workspace; we test configuration, not math.
- **Vectors with code.** Anything canonicalized, digested, or signed lands
  with golden vectors under `spec/vectors/` that the independent `xcheck/`
  implementation verifies in CI.

## Development

~~~text
cargo build --workspace
cargo test --workspace
cargo fmt --all && cargo clippy --workspace --all-targets
cargo deny check          # licenses, advisories, sources
python xcheck/run.py spec/vectors
~~~

The toolchain is pinned in `rust-toolchain.toml`. CI runs all of the above.

## Pull requests

- Keep PRs scoped to one milestone task where possible.
- Security-sensitive areas (crypto, identity, authorization, sandbox,
  evidence) additionally require updated threat cases and vectors — see
  GOVERNANCE.md.
- By contributing you agree your contribution is licensed under the
  repository license (Apache-2.0).

## Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
