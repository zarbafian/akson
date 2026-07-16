//! Encrypted SQLite state for one endpoint (ADR-0003, ADR-0005, design §15).
//!
//! M4-core builds the cross-cutting machinery every table relies on:
//! - [`envelope`] — column sealing under a keystore-protected key (ADR-0005);
//! - [`schema`] — `user_version` migrations and the `meta` key/value store;
//! - [`audit`] — the hash-linked, body-free audit log (design §15.3);
//! - state-generation recovery (design §15.5) and the trusted-time floor
//!   (design §8.5), both compared against an external checkpoint held outside
//!   backups;
//! - `peers`, the representative encrypted table, storing the M3 identity
//!   tuple with an operator-private note sealed.
//!
//! Domain tables (`tasks`, `contracts`, `work_orders`, `attempts`, `artifacts`,
//! `evidence`, `outcomes`, `outbox`, `inbox_objects`, …) are added by the
//! milestones whose engines populate them, each as its own numbered migration.
//!
//! What you write:
//! ```
//! use axon_store::{Store, ExternalCheckpoint};
//! use axon_store::envelope::Kek;
//! let kek = Kek::from_bytes([7u8; 32]);
//! let cp = ExternalCheckpoint { state_generation: 0, trusted_time: 0, rollback_detectable: true };
//! let store = Store::open_in_memory(&kek, cp).unwrap();
//! assert!(store.recovery().automatic_authority_enabled());
//! ```

pub mod audit;
pub mod envelope;
pub mod schema;

use std::path::Path;

use axon_crypto::identity::PeerIdentity;
use envelope::{DataKey, Kek, SealError};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

const WRAPPED_DEK: &str = "wrapped_dek";
const STATE_GENERATION: &str = "state_generation";
const TRUSTED_TIME: &str = "trusted_time";
const PEER_RECORD_CONTEXT: &str = "peers.record";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Seal(#[from] SealError),
    #[error(transparent)]
    Audit(#[from] audit::AuditError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// State held outside the database and its backups (the OS keystore/TPM, per
/// ADR-0009 and design §15.5/§8.5). Startup compares it with the database.
#[derive(Debug, Clone, Copy)]
pub struct ExternalCheckpoint {
    /// The monotonic state generation last reserved before an authority write.
    pub state_generation: u64,
    /// The last trusted wall-clock (unix seconds).
    pub trusted_time: i64,
    /// Whether the platform protects the checkpoint independently. When false,
    /// rollback cannot be detected and the store degrades rather than blocking.
    pub rollback_detectable: bool,
}

/// Whether the store opened in a state where automatic effects are safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// Checkpoint agrees with the database.
    Normal,
    /// No independent checkpoint exists (design §15.5): operate, but flagged.
    RollbackDetectionUnavailable,
    /// The database disagrees with the checkpoint — restored backup or a
    /// crash between reserve and commit. Automatic authority is disabled.
    Recovery(RecoveryReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryReason {
    StateGenerationMismatch { external: u64, database: u64 },
}

impl Recovery {
    /// The exit-criterion hook: a restored/rolled-back database must not resume
    /// automatic effects (design §15.5). Unavailable detection still operates
    /// (design §15.5 degrades rather than blocks).
    pub fn automatic_authority_enabled(&self) -> bool {
        !matches!(self, Recovery::Recovery(_))
    }

    pub fn is_recovery(&self) -> bool {
        matches!(self, Recovery::Recovery(_))
    }
}

/// Result of observing the wall clock against the trusted-time floor (§8.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeStatus {
    Ok {
        floor: i64,
    },
    /// Time moved backward past tolerance — enter time-uncertain recovery.
    Uncertain {
        floor: i64,
        observed: i64,
    },
}

/// A pinned peer: the design §8.1 identity tuple plus an operator-private note.
/// The whole record is sealed at rest; only public identifiers stay queryable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPeer {
    pub identity: PeerIdentity,
    /// Operator-private annotation; sensitive, sealed.
    pub local_note: String,
}

/// One endpoint's encrypted state database.
pub struct Store {
    conn: Connection,
    dek: DataKey,
    recovery: Recovery,
}

impl Store {
    /// Opens (creating if absent) the database at `path`.
    pub fn open(
        path: &Path,
        kek: &Kek,
        checkpoint: ExternalCheckpoint,
    ) -> Result<Self, StoreError> {
        Self::from_conn(Connection::open(path)?, kek, checkpoint)
    }

    /// Opens an in-memory database — tests and ephemeral runs.
    pub fn open_in_memory(kek: &Kek, checkpoint: ExternalCheckpoint) -> Result<Self, StoreError> {
        Self::from_conn(Connection::open_in_memory()?, kek, checkpoint)
    }

    fn from_conn(
        conn: Connection,
        kek: &Kek,
        checkpoint: ExternalCheckpoint,
    ) -> Result<Self, StoreError> {
        schema::open_and_migrate(&conn)?;

        // Load the wrapped DEK, or generate one on first init and adopt the
        // external checkpoint as the database's initial state.
        let dek = match schema::meta_get(&conn, WRAPPED_DEK)? {
            Some(wrapped) => DataKey::unwrap(kek, &wrapped)?,
            None => {
                let dek = DataKey::generate();
                schema::meta_set(&conn, WRAPPED_DEK, &dek.wrap(kek))?;
                schema::meta_set_u64(&conn, STATE_GENERATION, checkpoint.state_generation)?;
                schema::meta_set_i64(&conn, TRUSTED_TIME, checkpoint.trusted_time)?;
                dek
            }
        };

        let db_gen = schema::meta_get_u64(&conn, STATE_GENERATION)?.unwrap_or(0);
        let recovery = if !checkpoint.rollback_detectable {
            Recovery::RollbackDetectionUnavailable
        } else if db_gen != checkpoint.state_generation {
            Recovery::Recovery(RecoveryReason::StateGenerationMismatch {
                external: checkpoint.state_generation,
                database: db_gen,
            })
        } else {
            Recovery::Normal
        };

        Ok(Self {
            conn,
            dek,
            recovery,
        })
    }

    /// The recovery verdict determined at open.
    pub fn recovery(&self) -> &Recovery {
        &self.recovery
    }

    /// The state generation committed in the database.
    pub fn state_generation(&self) -> Result<u64, StoreError> {
        Ok(schema::meta_get_u64(&self.conn, STATE_GENERATION)?.unwrap_or(0))
    }

    /// Commits a new state generation in the database. Per design §15.5 the
    /// caller reserves the higher generation in the external checkpoint first,
    /// then calls this inside the same authority transaction.
    pub fn set_state_generation(&self, generation: u64) -> Result<(), StoreError> {
        schema::meta_set_u64(&self.conn, STATE_GENERATION, generation)?;
        Ok(())
    }

    /// The trusted wall-clock floor (§8.5).
    pub fn trusted_time_floor(&self) -> Result<i64, StoreError> {
        Ok(schema::meta_get_i64(&self.conn, TRUSTED_TIME)?.unwrap_or(0))
    }

    /// Observes wall clock `now`. If it moved backward past `tolerance_secs`,
    /// reports time-uncertain (design §8.5); otherwise advances the floor.
    pub fn observe_time(&self, now: i64, tolerance_secs: i64) -> Result<TimeStatus, StoreError> {
        let floor = schema::meta_get_i64(&self.conn, TRUSTED_TIME)?.unwrap_or(now);
        if now < floor - tolerance_secs {
            return Ok(TimeStatus::Uncertain {
                floor,
                observed: now,
            });
        }
        if now > floor {
            schema::meta_set_i64(&self.conn, TRUSTED_TIME, now)?;
        }
        Ok(TimeStatus::Ok {
            floor: now.max(floor),
        })
    }

    /// Appends a body-free audit record (design §15.3). Returns its `seq`.
    pub fn audit(&self, ts: i64, event: &str, detail: &str) -> Result<i64, StoreError> {
        Ok(audit::append(&self.conn, ts, event, detail)?)
    }

    /// Verifies the audit chain; returns the number of records.
    pub fn verify_audit(&self) -> Result<u64, StoreError> {
        Ok(audit::verify_chain(&self.conn)?)
    }

    /// Inserts or updates a pinned peer. The full record is sealed; the agent
    /// id, endpoint, issuer, and Agent Card thumbprint stay queryable.
    pub fn put_peer(&self, peer: &StoredPeer) -> Result<(), StoreError> {
        let sealed = self
            .dek
            .seal(PEER_RECORD_CONTEXT, &serde_json::to_vec(peer)?);
        let id = &peer.identity;
        self.conn.execute(
            "INSERT INTO peers (agent_id, issuer, endpoint_id, agent_card_thumbprint, record, created_generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(agent_id) DO UPDATE SET
                 issuer = excluded.issuer,
                 endpoint_id = excluded.endpoint_id,
                 agent_card_thumbprint = excluded.agent_card_thumbprint,
                 record = excluded.record",
            params![
                id.agent_id,
                id.issuer,
                id.endpoint_id,
                id.agent_card_key.value,
                sealed,
                self.state_generation()? as i64,
            ],
        )?;
        Ok(())
    }

    /// Reads a pinned peer by agent id, unsealing the record.
    pub fn get_peer(&self, agent_id: &str) -> Result<Option<StoredPeer>, StoreError> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT record FROM peers WHERE agent_id = ?1",
                [agent_id],
                |r| r.get(0),
            )
            .optional()?;
        match sealed {
            Some(bytes) => {
                let json = self.dek.open(PEER_RECORD_CONTEXT, &bytes)?;
                Ok(Some(serde_json::from_slice(&json)?))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axon_crypto::identity::{Fingerprint, PeerIdentity};

    fn kek() -> Kek {
        Kek::from_bytes([3u8; 32])
    }

    fn checkpoint(gen: u64) -> ExternalCheckpoint {
        ExternalCheckpoint {
            state_generation: gen,
            trusted_time: 1000,
            rollback_detectable: true,
        }
    }

    fn sample_peer(note: &str) -> StoredPeer {
        let vk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        StoredPeer {
            identity: PeerIdentity {
                issuer: None,
                agent_id: "agent-a".to_owned(),
                workload_id: None,
                endpoint_id: "ep-1".to_owned(),
                tls_cert: Fingerprint::cert_sha256(b"der"),
                agent_card_key: Fingerprint::jwk(&vk),
                key_bindings: vec![],
                security_projection_digest: Fingerprint::json_sha256(b"{}"),
                full_card_digest: Fingerprint::json_sha256(b"{}"),
            },
            local_note: note.to_owned(),
        }
    }

    #[test]
    fn peer_round_trip_seals_record() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        store.put_peer(&sample_peer("private annotation")).unwrap();
        let got = store.get_peer("agent-a").unwrap().unwrap();
        assert_eq!(got.local_note, "private annotation");
        assert!(store.get_peer("nobody").unwrap().is_none());
    }

    #[test]
    fn wrong_kek_fails_closed_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        Store::open(&path, &kek(), checkpoint(0)).unwrap();
        let wrong = Kek::from_bytes([9u8; 32]);
        assert!(matches!(
            Store::open(&path, &wrong, checkpoint(0)),
            Err(StoreError::Seal(_))
        ));
    }

    #[test]
    fn state_generation_mismatch_enters_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let store = Store::open(&path, &kek(), checkpoint(0)).unwrap();
            store.set_state_generation(3).unwrap(); // advanced to gen 3
        }
        // External checkpoint advanced to 4 while this db is an old snapshot at 3.
        let store = Store::open(&path, &kek(), checkpoint(4)).unwrap();
        assert!(store.recovery().is_recovery());
        assert!(!store.recovery().automatic_authority_enabled());
        // Reopening in lockstep is Normal.
        let store = Store::open(&path, &kek(), checkpoint(3)).unwrap();
        assert_eq!(*store.recovery(), Recovery::Normal);
        assert!(store.recovery().automatic_authority_enabled());
    }

    #[test]
    fn rollback_detection_unavailable_still_operates() {
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: false,
        };
        let store = Store::open_in_memory(&kek(), cp).unwrap();
        assert_eq!(*store.recovery(), Recovery::RollbackDetectionUnavailable);
        assert!(store.recovery().automatic_authority_enabled());
    }

    #[test]
    fn trusted_time_backward_is_uncertain() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        assert!(matches!(
            store.observe_time(1000, 300).unwrap(),
            TimeStatus::Ok { .. }
        ));
        // Within tolerance: still ok.
        assert!(matches!(
            store.observe_time(800, 300).unwrap(),
            TimeStatus::Ok { .. }
        ));
        // Past tolerance below the floor: uncertain.
        assert!(matches!(
            store.observe_time(600, 300).unwrap(),
            TimeStatus::Uncertain { .. }
        ));
    }
}
