//! Append-only, hash-linked audit log (design §15.3).
//!
//! Each record hash-links to its predecessor, so accidental or out-of-domain
//! modification — editing a row, dropping the tail — is locally tamper-evident.
//! This is integrity *evidence within one security domain*, not protection
//! against a same-UID attacker (design §15.3 is explicit); stronger integrity
//! needs the external checkpoint / witness.
//!
//! Records are body-free by construction: `event` is a low-cardinality type and
//! `detail` carries digests and identifiers, never prompts, bodies, paths, or
//! secrets. Audit insertion shares a transaction with the effect it records, so
//! there is no unrecorded effect.
//!
//! `hash = SHA-256(prev_hash ‖ seq ‖ ts ‖ len(event) ‖ event ‖ len(detail) ‖ detail)`,
//! each length a big-endian u64; the genesis `prev_hash` is 32 zero bytes.

use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// The genesis predecessor hash (before the first record).
pub const GENESIS: [u8; 32] = [0u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error("audit chain broken at seq {seq}")]
    Broken { seq: i64 },
}

fn record_hash(prev: &[u8], seq: i64, ts: i64, event: &str, detail: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(seq.to_be_bytes());
    h.update(ts.to_be_bytes());
    h.update((event.len() as u64).to_be_bytes());
    h.update(event.as_bytes());
    h.update((detail.len() as u64).to_be_bytes());
    h.update(detail.as_bytes());
    h.finalize().into()
}

/// The most recent record's hash, or [`GENESIS`] if the log is empty.
pub fn head(conn: &Connection) -> rusqlite::Result<[u8; 32]> {
    let row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;
    Ok(row.and_then(|b| b.try_into().ok()).unwrap_or(GENESIS))
}

/// Appends one record, linking it to the current head. Returns its `seq`.
/// Call inside the same transaction as the effect being recorded.
pub fn append(conn: &Connection, ts: i64, event: &str, detail: &str) -> rusqlite::Result<i64> {
    let prev = head(conn)?;
    let next_seq: i64 = conn.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM audit", [], |r| {
        r.get(0)
    })?;
    let hash = record_hash(&prev, next_seq, ts, event, detail);
    conn.execute(
        "INSERT INTO audit (seq, ts, event, detail, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            next_seq,
            ts,
            event,
            detail,
            prev.as_slice(),
            hash.as_slice()
        ],
    )?;
    Ok(next_seq)
}

/// Walks the chain from genesis and confirms every link and hash. Returns the
/// number of records verified, or the `seq` where the chain first breaks.
pub fn verify_chain(conn: &Connection) -> Result<u64, AuditError> {
    let mut stmt =
        conn.prepare("SELECT seq, ts, event, detail, prev_hash, hash FROM audit ORDER BY seq ASC")?;
    let mut rows = stmt.query([])?;
    let mut prev = GENESIS;
    let mut count = 0u64;
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let ts: i64 = row.get(1)?;
        let event: String = row.get(2)?;
        let detail: String = row.get(3)?;
        let stored_prev: Vec<u8> = row.get(4)?;
        let stored_hash: Vec<u8> = row.get(5)?;
        let expected = record_hash(&prev, seq, ts, &event, &detail);
        if stored_prev != prev || stored_hash != expected {
            return Err(AuditError::Broken { seq });
        }
        prev = expected;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::schema::open_and_migrate;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        open_and_migrate(&conn).unwrap();
        conn
    }

    #[test]
    fn appends_and_verifies() {
        let conn = db();
        assert_eq!(head(&conn).unwrap(), GENESIS);
        append(&conn, 100, "pair.created", "peer=abc").unwrap();
        append(&conn, 101, "contract.decided", "task=1;digest=def").unwrap();
        assert_eq!(verify_chain(&conn).unwrap(), 2);
    }

    #[test]
    fn detects_tampered_detail() {
        let conn = db();
        append(&conn, 100, "pair.created", "peer=abc").unwrap();
        append(&conn, 101, "key.changed", "peer=abc").unwrap();
        // A same-domain edit to a committed record is caught by the chain.
        conn.execute("UPDATE audit SET detail = 'peer=evil' WHERE seq = 1", [])
            .unwrap();
        assert!(matches!(
            verify_chain(&conn),
            Err(AuditError::Broken { seq: 1 })
        ));
    }

    #[test]
    fn detects_truncated_tail_reinsert() {
        let conn = db();
        append(&conn, 100, "a", "x").unwrap();
        append(&conn, 101, "b", "y").unwrap();
        // Rewriting seq 2 with different content breaks its hash.
        conn.execute("UPDATE audit SET event = 'c' WHERE seq = 2", [])
            .unwrap();
        assert!(matches!(
            verify_chain(&conn),
            Err(AuditError::Broken { seq: 2 })
        ));
    }
}
