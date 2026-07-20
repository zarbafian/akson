# ADR-0001: Rust implementation and workspace layout

Status: accepted
Date: 2026-07-16

## Context

The design (§3, §13, §15) mandates reuse of reviewed libraries for TLS 1.3
mutual authentication, X.509, Ed25519, DSSE v1, in-toto, JSON Schema 2020-12,
RFC 8785 JCS, SARIF, OS keystores, and Linux sandboxing
(namespaces/seccomp/cgroups v2/Landlock), and forbids implementing
cryptographic primitives or inventing formats. Candidates evaluated: Rust,
Go, OCaml (continuity with the prior c2c system).

## Decision

Akson is implemented in Rust as a Cargo workspace of small crates with two
binaries, `aksond` and `akson`. Rationale: rustls gives the exact TLS profile
control the design requires (1.3-only, resumption and 0-RTT off, custom
pinned-peer verification); maintained crates exist for every mandated
standard (`jsonschema`, `json-canon`, `ed25519-dalek`, `serde-sarif`,
`landlock`, `seccompiler`, `keyring`); and hostile-input parsing benefits
from memory safety. (`serde_jcs` was the initial JCS pick; the frozen
`jcs/utf16-key-sorting` golden vector rejected it for sorting object keys by
code point instead of RFC 8785's UTF-16 code units.) OCaml was rejected because it lacks maintained DSSE,
in-toto, JSON Schema 2020-12, JCS, SARIF, Landlock, and seccomp libraries —
exactly the things the design forbids hand-rolling. Go was a close second;
its Tink library remains the fallback ciphertext format for ADR-0005.

Trusted code (§7.1) — transport parse path, policy, authority, output gate,
evidence validation — lives in dedicated crates that never depend on adapter
or worker-payload code. `unsafe_code` is denied workspace-wide; the sandbox
crate may carve out an exception behind a reviewed module if launcher
syscalls require it (revisit in ADR-0006).

## Consequences

- Library selections are pinned in the workspace manifest; exact versions in
  the committed `Cargo.lock`; policy enforced by `cargo deny`.
- No code sharing with c2c's OCaml tree; c2c contributes patterns and test
  topology only.
- Independent verification of canonical bytes/signatures is done in Python
  (`xcheck/`), keeping the golden vectors implementation-independent.
