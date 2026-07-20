# Architecture decision records

An ADR records one decision with lasting consequences: standards disposition,
wire formats, library selection, security posture. Akson-specific wire formats
additionally must satisfy design §3.1 before shipping in a stable release.

Process:

1. Copy the template below into `NNNN-short-title.md` (next free number).
2. Open a PR. The ADR is `proposed` until merged with maintainer approval,
   then `accepted`. Superseding requires a new ADR that links both ways.
3. Security-relevant ADRs list the affected threat cases and test vectors.

Template:

~~~markdown
# ADR-NNNN: title

Status: proposed | accepted | superseded by ADR-MMMM
Date: YYYY-MM-DD

## Context
What requirement forces a decision, and what was evaluated.

## Decision
The choice, stated normatively.

## Consequences
What becomes easier, harder, or irreversible; affected tests/vectors.
~~~

Index:

| # | Title | Status |
|---|---|---|
| [0001](0001-rust-workspace.md) | Rust implementation and workspace layout | accepted |
| [0002](0002-a2a-source-of-truth.md) | Vendored A2A definitions as source of truth | accepted |
| [0003](0003-storage.md) | SQLite storage with application-layer encryption | accepted |
| [0004](0004-signing.md) | Ed25519 purpose-separated signing keys | accepted |
| [0005](0005-envelope-encryption.md) | Envelope encryption for sensitive columns | accepted |
| [0006](0006-sandbox-launcher.md) | Sandbox launcher — bubblewrap for namespaces/mount + pure-Rust seccomp/Landlock | accepted |
| [0007](0007-jws-agent-card.md) | Minimal EdDSA JWS for Agent Card signatures | accepted |
| 0008 | DSSE/in-toto implementation | open |
| [0009](0009-keystore-rollback.md) | Keystore abstraction and rollback checkpoint | accepted |
| [0010](0010-unknown-fields.md) | Unknown-field handling for standard A2A objects | accepted |
| [0011](0011-tls-stack.md) | TLS stack and self-issued endpoint certificates | accepted |
| [0012](0012-dsse-envelope-media-type.md) | One DSSE-envelope media type for all signed extension objects | accepted |
