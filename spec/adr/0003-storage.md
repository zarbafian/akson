# ADR-0003: SQLite storage with application-layer encryption

Status: accepted
Date: 2026-07-16

## Context

Design §15.1 requires durable local state whose sensitive columns and blobs
are encrypted before persistence with an audited envelope-encryption library
under an OS-keystore-protected key, with no plaintext in WAL files, temp
files, or backups. Design §9.2 requires durable-before-response receipt and
idempotent replay.

## Decision

State lives in one SQLite database per endpoint via `rusqlite` (bundled
SQLite, WAL mode, foreign keys on). Schema management follows the pattern
proven in c2c: `CREATE TABLE IF NOT EXISTS` for the base schema plus
explicit, tested column-add migrations with documented DEFAULT sentinels.
Sensitive values are encrypted at the application layer before they reach
SQLite (library and ciphertext format: ADR-0005), so SQLite, its WAL, and
file-level backups never see task plaintext. Full-database encryption
(SQLCipher) is not relied on as the protection boundary. Every
durability-relevant write (inbox receipt, tombstone, decision, work-order
claim, attempt state, completion) is a single transaction or a documented
recoverable commit protocol, and the crash matrix kills at each boundary.

## Consequences

- The plaintext-scan test (design §20.7) runs against the db file, WAL, and
  temp directory after full-loop runs and must find no planted markers.
- Backup/restore tooling operates on ciphertext and must preserve the
  external state-generation checkpoint semantics (ADR-0009).
- Blobs above a small threshold may move to an encrypted file store later;
  that change requires only a storage-crate migration, not a format change.
