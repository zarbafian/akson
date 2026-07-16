# Architecture decision records

An ADR records one decision with lasting consequences: standards disposition,
wire formats, library selection, security posture. Axon-specific wire formats
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
| 0005 | Envelope-encryption library | open |
| 0006 | Sandbox launcher | open |
| 0007 | JWS library for Agent Card signatures | open |
| 0008 | DSSE/in-toto implementation | open |
| 0009 | OS keystore and rollback checkpoint | open |
