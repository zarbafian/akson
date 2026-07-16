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

/// Applies pragmas and runs outstanding migrations. Idempotent.
pub fn open_and_migrate(conn: &Connection) -> rusqlite::Result<()> {
    // Setting journal_mode returns the resulting mode as a row (and yields
    // "memory" for an in-memory database, which is expected, not an error).
    let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "busy_timeout", 5000)?;

    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version < 1 {
        conn.execute_batch(V1)?;
        conn.pragma_update(None, "user_version", 1)?;
    }
    Ok(())
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
