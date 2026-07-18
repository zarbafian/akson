//! Schema DDL, `user_version` migrations, and the `meta` key/value helpers.
//!
//! Migrations follow the c2c pattern (ADR-0003): a base schema guarded by
//! SQLite's `user_version`, so opening an existing database is idempotent and
//! future column-adds are explicit, numbered steps.
//!
//! M4-core defines the cross-cutting tables — `meta` (wrapped DEK + the
//! state-generation and trusted-time checkpoints), `audit` (hash-linked), and
//! the representative encrypted `peers` table. The domain tables
//! (`tasks`, `contracts`, `work_orders`, …) are added by the milestones whose
//! engines populate them, each as its own numbered migration.

use rusqlite::Connection;

/// Version 1: the M4-core cross-cutting schema.
const V1: &str = r#"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE audit (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    event     TEXT NOT NULL,
    detail    TEXT NOT NULL,
    prev_hash BLOB NOT NULL,
    hash      BLOB NOT NULL
) STRICT;

CREATE TABLE peers (
    agent_id              TEXT PRIMARY KEY,
    issuer                TEXT,
    endpoint_id           TEXT NOT NULL,
    agent_card_thumbprint TEXT NOT NULL,
    record                BLOB NOT NULL,
    created_generation    INTEGER NOT NULL
) STRICT;
"#;

/// Version 2 (M5-core): the receiver-side reliable-delivery tables (design
/// §9.2). `inbox_objects` holds the idempotency record (sealed body and
/// response) while the payload is retained; `replay_tombstones` holds the
/// keyed commitment and sealed response after payload retention ends.
const V2: &str = r#"
CREATE TABLE inbox_objects (
    peer           TEXT NOT NULL,
    message_id     TEXT NOT NULL,
    commitment     BLOB NOT NULL,
    body_digest    TEXT NOT NULL,
    task_id        TEXT,
    response_class TEXT NOT NULL,
    body           BLOB NOT NULL,
    response       BLOB NOT NULL,
    received_at    INTEGER NOT NULL,
    PRIMARY KEY (peer, message_id)
) STRICT;

CREATE TABLE replay_tombstones (
    peer           TEXT NOT NULL,
    message_id     TEXT NOT NULL,
    commitment     BLOB NOT NULL,
    task_id        TEXT,
    response_class TEXT NOT NULL,
    response       BLOB NOT NULL,
    expires_at     INTEGER NOT NULL,
    PRIMARY KEY (peer, message_id)
) STRICT;
"#;

/// Version 3 (M6): the persistent pairing ledger (design §8.2). `invitations`
/// holds live bearer-secret verifiers with their sealed pending record;
/// `pending_pairs` holds the consumed-secret idempotency record (transcript
/// digest + sealed response) retained until the invitation's expiry.
const V3: &str = r#"
CREATE TABLE invitations (
    verifier   BLOB PRIMARY KEY,
    pending    BLOB NOT NULL,
    not_after  INTEGER NOT NULL
) STRICT;

CREATE TABLE pending_pairs (
    verifier           BLOB PRIMARY KEY,
    transcript_digest  BLOB NOT NULL,
    response           BLOB NOT NULL,
    expires_at         INTEGER NOT NULL
) STRICT;
"#;

/// Version 4 (M6): a freshly paired peer is *pending* until the operator
/// confirms it (design §8.2 step 7). `status` is `'pending'` or `'active'`; only
/// an active peer may exchange work. Existing peers predate the concept and are
/// treated as already-confirmed, so the added column defaults to `'active'`.
const V4: &str = r#"
ALTER TABLE peers ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
"#;

/// Version 5 (M7): the task-contract head and stored revisions (design §9.3,
/// §10.2). `contract_heads` is the one compare-and-swap head per Task (`open`
/// while awaiting input, `locked` once a decision accepts it). `contracts` holds
/// each validated revision by its canonical digest, payload sealed at rest;
/// retained until expiry.
const V5: &str = r#"
CREATE TABLE contract_heads (
    task_id     TEXT PRIMARY KEY,
    contract_id TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    digest      TEXT NOT NULL,
    status      TEXT NOT NULL
) STRICT;

CREATE TABLE contracts (
    digest      TEXT PRIMARY KEY,
    task_id     TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    payload     BLOB NOT NULL,
    expires_at  INTEGER NOT NULL
) STRICT;
"#;

/// Version 6 (M8): work-order attempts (design §12.3). One row per attempt is the
/// atomic claim — its insertion consumes the one-use `nonce` (UNIQUE) and records
/// the reserved budgets in the same statement. `state` tracks
/// pending→claimed→…→terminal; a claimed/running row found after a crash resolves
/// to `ambiguous` and is never re-run.
const V6: &str = r#"
CREATE TABLE attempts (
    work_order_id     TEXT PRIMARY KEY,
    nonce             TEXT NOT NULL UNIQUE,
    task_id           TEXT NOT NULL,
    work_order_digest TEXT NOT NULL,
    state             TEXT NOT NULL,
    max_cost_microusd INTEGER NOT NULL,
    max_bytes         INTEGER NOT NULL,
    max_operations    INTEGER NOT NULL,
    claimed_at        INTEGER NOT NULL,
    deadline          TEXT NOT NULL
) STRICT;
"#;

/// Version 7 (M10): the processor broker (design §13.1, §15.2). `processors` holds
/// each configured processor (sealed config + a plaintext `location` so a listing
/// needs no unseal). `processor_calls` is the durable sub-attempt: one row per
/// prepared call, keyed by its deterministic `idempotency_key`, recorded before a
/// byte leaves; a `dispatching` row found after a crash resolves to `ambiguous`.
const V7: &str = r#"
CREATE TABLE processors (
    processor_id  TEXT PRIMARY KEY,
    provider      TEXT NOT NULL,
    location      TEXT NOT NULL,
    config        BLOB NOT NULL,
    added_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE processor_calls (
    idempotency_key    TEXT PRIMARY KEY,
    work_order_id      TEXT NOT NULL,
    task_id            TEXT NOT NULL,
    processor_id       TEXT NOT NULL,
    provider           TEXT NOT NULL,
    config_digest      TEXT NOT NULL,
    request_digest     TEXT NOT NULL,
    origin             TEXT NOT NULL,
    state              TEXT NOT NULL,
    max_cost_microusd  INTEGER NOT NULL,
    max_response_bytes INTEGER NOT NULL,
    deadline           TEXT NOT NULL,
    prepared_at        INTEGER NOT NULL
) STRICT;
"#;

/// Version 8 (M12): a peer's verification keys, retained at pairing so a received
/// message can be verified (design §8.1, §10.2). Keyed by the peer's TLS
/// fingerprint and key purpose; the public key is not secret, so it is stored in
/// the clear. The receive server resolves a connecting peer's contract-proposal key
/// from here by the handshake's leaf-cert fingerprint.
const V8: &str = r#"
CREATE TABLE peer_keys (
    tls_fingerprint TEXT NOT NULL,
    purpose         TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    issuer          TEXT NOT NULL,
    public_key      BLOB NOT NULL,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (tls_fingerprint, purpose)
) STRICT;
"#;

/// Version 9 (M12): the A2A Context id of a submitted Task. It is Message-level,
/// not a contract property, so it is recorded on the head separately from the
/// contract revision (design §10.2) — the decision that accepts the Task needs it.
const V9: &str = r#"
ALTER TABLE contract_heads ADD COLUMN context_id TEXT NOT NULL DEFAULT '';
"#;

/// Each numbered migration and the `user_version` it establishes. Steps run in
/// order; opening an up-to-date database runs none. New milestones append here.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, V1),
    (2, V2),
    (3, V3),
    (4, V4),
    (5, V5),
    (6, V6),
    (7, V7),
    (8, V8),
    (9, V9),
];

/// Applies pragmas and runs outstanding migrations. Idempotent. Returns the
/// resulting `journal_mode` so the caller can assert WAL actually took effect
/// (the durable claim/CAS paths depend on WAL snapshot isolation).
pub fn open_and_migrate(conn: &Connection) -> rusqlite::Result<String> {
    // Setting journal_mode returns the resulting mode as a row (and yields
    // "memory" for an in-memory database, which is expected, not an error).
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "busy_timeout", 5000)?;

    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (target, ddl) in MIGRATIONS {
        if version < *target {
            conn.execute_batch(ddl)?;
            conn.pragma_update(None, "user_version", *target)?;
        }
    }
    Ok(mode)
}

/// Reads a raw `meta` value.
pub fn meta_get(conn: &Connection, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
}

/// Writes a raw `meta` value (insert or replace).
pub fn meta_set(conn: &Connection, key: &str, value: &[u8]) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )?;
    Ok(())
}

/// Reads a `u64` stored as 8 big-endian bytes.
pub fn meta_get_u64(conn: &Connection, key: &str) -> rusqlite::Result<Option<u64>> {
    Ok(meta_get(conn, key)?.and_then(|b| {
        let arr: [u8; 8] = b.try_into().ok()?;
        Some(u64::from_be_bytes(arr))
    }))
}

/// Writes a `u64` as 8 big-endian bytes.
pub fn meta_set_u64(conn: &Connection, key: &str, value: u64) -> rusqlite::Result<()> {
    meta_set(conn, key, &value.to_be_bytes())
}

/// Reads an `i64` stored as 8 big-endian bytes.
pub fn meta_get_i64(conn: &Connection, key: &str) -> rusqlite::Result<Option<i64>> {
    Ok(meta_get(conn, key)?.and_then(|b| {
        let arr: [u8; 8] = b.try_into().ok()?;
        Some(i64::from_be_bytes(arr))
    }))
}

/// Writes an `i64` as 8 big-endian bytes.
pub fn meta_set_i64(conn: &Connection, key: &str, value: i64) -> rusqlite::Result<()> {
    meta_set(conn, key, &value.to_be_bytes())
}
