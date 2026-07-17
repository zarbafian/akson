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
pub mod delivery;
pub mod envelope;
pub mod schema;

use std::path::Path;

use axon_crypto::identity::PeerIdentity;
use axon_pairing::invitation::PendingInvitation;
use axon_pairing::state_machine::{Consumed, LedgerError, PairingLedger, PairingStore};
use delivery::CoveredValues;
use envelope::{DataKey, Kek, SealError};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

const WRAPPED_DEK: &str = "wrapped_dek";
const COMMITMENT_KEY: &str = "commitment_key";
const STATE_GENERATION: &str = "state_generation";
const TRUSTED_TIME: &str = "trusted_time";
const PEER_RECORD_CONTEXT: &str = "peers.record";
const COMMITMENT_KEY_CONTEXT: &str = "meta.commitment_key";
const INBOX_BODY_CONTEXT: &str = "inbox.body";
const INBOX_RESPONSE_CONTEXT: &str = "inbox.response";
const INVITATION_CONTEXT: &str = "pairing.invitation";
const PAIR_RESPONSE_CONTEXT: &str = "pairing.response";

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

/// The verdict of an idempotent receive (design §9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receipt {
    /// First time this (peer, Message id) was seen; the record was stored.
    Fresh,
    /// An exact replay: every covered value matched. Return the saved response
    /// and the same server-assigned Task id — no second effect.
    Duplicate {
        task_id: Option<String>,
        response: Vec<u8>,
    },
    /// Same (peer, Message id) but a covered value changed — a conflict and a
    /// security event. Nothing is stored or overwritten.
    Conflict,
}

/// One endpoint's encrypted state database.
pub struct Store {
    conn: Connection,
    dek: DataKey,
    commitment_key: [u8; 32],
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

        // The local commitment key (design §9.2/§15.3) is sealed under the DEK.
        // Bootstrap it independently so a V1 database gains one on upgrade.
        let commitment_key = match schema::meta_get(&conn, COMMITMENT_KEY)? {
            Some(sealed) => dek
                .open(COMMITMENT_KEY_CONTEXT, &sealed)?
                .try_into()
                .map_err(|_| SealError::Malformed)?,
            None => {
                let mut key = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut key);
                schema::meta_set(
                    &conn,
                    COMMITMENT_KEY,
                    &dek.seal(COMMITMENT_KEY_CONTEXT, &key),
                )?;
                key
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
            commitment_key,
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

    /// Idempotent receive (design §9.2). Stores the request's covered-value
    /// commitment, sealed body, and sealed response on first sight; on a repeat
    /// of the same (peer, Message id) it returns the saved response and Task id
    /// if every covered value matches, or [`Receipt::Conflict`] if any differs.
    /// A duplicate never creates a second effect. The caller writes the record
    /// before returning its response to the peer (durable-before-response).
    pub fn receive_request(
        &self,
        covered: &CoveredValues,
        body: &[u8],
        response: &[u8],
        task_id: Option<&str>,
        response_class: &str,
        now: i64,
    ) -> Result<Receipt, StoreError> {
        let commitment = covered.commitment(&self.commitment_key);

        // A prior sighting may be a live inbox record or an aged-out tombstone.
        if let Some(prior) = self.prior_response(&covered.peer, &covered.message_id)? {
            return Ok(self.decide(&commitment, prior));
        }

        let sealed_body = self.dek.seal(INBOX_BODY_CONTEXT, body);
        let sealed_response = self.dek.seal(INBOX_RESPONSE_CONTEXT, response);
        self.conn.execute(
            "INSERT INTO inbox_objects
                 (peer, message_id, commitment, body_digest, task_id, response_class, body, response, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                covered.peer,
                covered.message_id,
                commitment.as_slice(),
                covered.body_digest,
                task_id,
                response_class,
                sealed_body,
                sealed_response,
                now,
            ],
        )?;
        Ok(Receipt::Fresh)
    }

    /// Checks whether this request was already seen, without storing anything
    /// (design §9.2). Used to decide idempotency *before* processing: a
    /// [`Receipt::Duplicate`] is replayed, a [`Receipt::Conflict`] is refused,
    /// and [`Receipt::Fresh`] means the caller should process and then commit
    /// with [`receive_request`](Self::receive_request).
    pub fn peek(&self, covered: &CoveredValues) -> Result<Receipt, StoreError> {
        let commitment = covered.commitment(&self.commitment_key);
        match self.prior_response(&covered.peer, &covered.message_id)? {
            Some(prior) => Ok(self.decide(&commitment, prior)),
            None => Ok(Receipt::Fresh),
        }
    }

    /// Moves a retained inbox record to a replay tombstone: the payload body is
    /// dropped, but the keyed commitment, Task id, and sealed response are kept
    /// for exact replay until `expires_at` (design §9.2). Returns whether a
    /// record was demoted.
    pub fn demote_to_tombstone(
        &self,
        peer: &str,
        message_id: &str,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let moved = tx.execute(
            "INSERT INTO replay_tombstones
                     (peer, message_id, commitment, task_id, response_class, response, expires_at)
                 SELECT peer, message_id, commitment, task_id, response_class, response, ?3
                 FROM inbox_objects WHERE peer = ?1 AND message_id = ?2",
            params![peer, message_id, expires_at],
        )?;
        tx.execute(
            "DELETE FROM inbox_objects WHERE peer = ?1 AND message_id = ?2",
            params![peer, message_id],
        )?;
        tx.commit()?;
        Ok(moved > 0)
    }

    /// A prior sighting of a (peer, Message id): its stored commitment, Task
    /// id, and sealed response, read from the inbox record or a tombstone.
    fn prior_response(
        &self,
        peer: &str,
        message_id: &str,
    ) -> Result<Option<PriorSighting>, StoreError> {
        let read = |r: &rusqlite::Row| {
            Ok(PriorSighting {
                commitment: r.get(0)?,
                task_id: r.get(1)?,
                response: r.get(2)?,
            })
        };
        let row = self
            .conn
            .query_row(
                "SELECT commitment, task_id, response FROM inbox_objects
                 WHERE peer = ?1 AND message_id = ?2",
                params![peer, message_id],
                read,
            )
            .optional()?;
        if row.is_some() {
            return Ok(row);
        }
        self.conn
            .query_row(
                "SELECT commitment, task_id, response FROM replay_tombstones
                 WHERE peer = ?1 AND message_id = ?2",
                params![peer, message_id],
                read,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Compares a fresh commitment against a stored sighting.
    fn decide(&self, commitment: &[u8; 32], prior: PriorSighting) -> Receipt {
        if prior.commitment != commitment {
            return Receipt::Conflict;
        }
        match self.dek.open(INBOX_RESPONSE_CONTEXT, &prior.response) {
            Ok(response) => Receipt::Duplicate {
                task_id: prior.task_id,
                response,
            },
            // A stored response that will not unseal is corruption, not a
            // match; fail closed to a conflict rather than replay garbage.
            Err(_) => Receipt::Conflict,
        }
    }
}

/// A prior sighting's stored commitment, Task id, and sealed response.
struct PriorSighting {
    commitment: Vec<u8>,
    task_id: Option<String>,
    response: Vec<u8>,
}

impl Store {
    /// Purges expired invitations and consumed pending-pair records — the
    /// pairing-ledger GC (design §8.2: retained only until invitation expiry).
    pub fn purge_expired_pairing(&self, now: i64) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM invitations WHERE not_after <= ?1", [now])?;
        self.conn
            .execute("DELETE FROM pending_pairs WHERE expires_at <= ?1", [now])?;
        Ok(())
    }
}

fn ledger_err<E: std::fmt::Display>(e: E) -> LedgerError {
    LedgerError(e.to_string())
}

/// The persistent, encrypted pairing ledger (design §8.2). Invitations and
/// consumed-secret records survive restart; sealed values are encrypted with
/// the database DEK.
impl PairingLedger for Store {
    fn consumed(&self, verifier: &[u8; 32]) -> Result<Option<Consumed>, LedgerError> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT transcript_digest, response, expires_at FROM pending_pairs WHERE verifier = ?1",
                [verifier.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(ledger_err)?;
        match row {
            Some((digest, sealed, expires_at)) => {
                let response = self
                    .dek
                    .open(PAIR_RESPONSE_CONTEXT, &sealed)
                    .map_err(ledger_err)?;
                let transcript_digest: [u8; 32] = digest.try_into().map_err(|_| {
                    LedgerError("stored transcript digest is not 32 bytes".to_owned())
                })?;
                Ok(Some(Consumed {
                    transcript_digest,
                    response,
                    expires_at,
                }))
            }
            None => Ok(None),
        }
    }

    fn active_exists(&self, verifier: &[u8; 32]) -> Result<bool, LedgerError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM invitations WHERE verifier = ?1",
                [verifier.as_slice()],
                |r| r.get(0),
            )
            .map_err(ledger_err)?;
        Ok(count > 0)
    }

    fn take_active(
        &mut self,
        verifier: &[u8; 32],
    ) -> Result<Option<PendingInvitation>, LedgerError> {
        let tx = self.conn.unchecked_transaction().map_err(ledger_err)?;
        let sealed: Option<Vec<u8>> = tx
            .query_row(
                "SELECT pending FROM invitations WHERE verifier = ?1",
                [verifier.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(ledger_err)?;
        let result = match sealed {
            Some(bytes) => {
                let json = self
                    .dek
                    .open(INVITATION_CONTEXT, &bytes)
                    .map_err(ledger_err)?;
                let pending: PendingInvitation =
                    serde_json::from_slice(&json).map_err(ledger_err)?;
                tx.execute(
                    "DELETE FROM invitations WHERE verifier = ?1",
                    [verifier.as_slice()],
                )
                .map_err(ledger_err)?;
                Some(pending)
            }
            None => None,
        };
        tx.commit().map_err(ledger_err)?;
        Ok(result)
    }

    fn put_active(
        &mut self,
        verifier: [u8; 32],
        invitation: PendingInvitation,
    ) -> Result<(), LedgerError> {
        let json = serde_json::to_vec(&invitation).map_err(ledger_err)?;
        let sealed = self.dek.seal(INVITATION_CONTEXT, &json);
        self.conn
            .execute(
                "INSERT INTO invitations (verifier, pending, not_after) VALUES (?1, ?2, ?3)
                 ON CONFLICT(verifier) DO UPDATE SET pending = excluded.pending, not_after = excluded.not_after",
                params![verifier.as_slice(), sealed, invitation.not_after],
            )
            .map_err(ledger_err)?;
        Ok(())
    }

    fn commit_consumed(
        &mut self,
        verifier: [u8; 32],
        consumed: Consumed,
    ) -> Result<(), LedgerError> {
        let tx = self.conn.unchecked_transaction().map_err(ledger_err)?;
        // The secret is consumed (invitation removed) in the same transaction
        // that records the pending-pair response (§8.2). DO NOTHING on conflict
        // preserves the first record, so a race cannot create a second peer.
        tx.execute(
            "DELETE FROM invitations WHERE verifier = ?1",
            [verifier.as_slice()],
        )
        .map_err(ledger_err)?;
        let sealed = self.dek.seal(PAIR_RESPONSE_CONTEXT, &consumed.response);
        tx.execute(
            "INSERT INTO pending_pairs (verifier, transcript_digest, response, expires_at)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT(verifier) DO NOTHING",
            params![
                verifier.as_slice(),
                consumed.transcript_digest.as_slice(),
                sealed,
                consumed.expires_at
            ],
        )
        .map_err(ledger_err)?;
        tx.commit().map_err(ledger_err)?;
        Ok(())
    }
}

impl PairingStore for Store {
    fn store_pending_peer(&mut self, peer: &PeerIdentity) -> Result<(), LedgerError> {
        // A pairing must never silently overwrite an existing peer that shares
        // this (attacker-chosen) agent id with *different* cryptographic
        // identity — that would let an invited party hijack another peer's
        // record. A safety-critical change is refused; re-pairing must be
        // explicit (design §8.4). An unchanged identity is idempotent.
        if let Some(existing) = self.get_peer(&peer.agent_id).map_err(ledger_err)? {
            if let Some(reason) = axon_pairing::lifecycle::detect_change(&existing.identity, peer) {
                return Err(LedgerError(format!(
                    "refusing to overwrite peer {:?}: {reason:?} (re-pair explicitly)",
                    peer.agent_id
                )));
            }
        }
        self.put_peer(&StoredPeer {
            identity: peer.clone(),
            local_note: String::new(),
        })
        .map_err(ledger_err)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
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

    fn covered(message_id: &str, body: &[u8]) -> CoveredValues {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        use sha2::{Digest, Sha256};
        CoveredValues {
            peer: "agent-b".to_owned(),
            message_id: message_id.to_owned(),
            body_digest: STANDARD.encode(Sha256::digest(body)),
            interface_url: "https://agent.example/a2a".to_owned(),
            tenant: None,
            a2a_version: "1.0".to_owned(),
            extensions: vec![],
            content_type: "application/a2a+json".to_owned(),
            http_method: "POST".to_owned(),
        }
        .normalized()
    }

    #[test]
    fn idempotent_replay_returns_saved_response() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let cv = covered("m1", b"body");
        assert_eq!(
            store
                .receive_request(&cv, b"body", b"RESP", Some("task-9"), "task", 100)
                .unwrap(),
            Receipt::Fresh
        );
        // A retry with the same covered values returns the *original* response
        // and Task id, ignoring whatever the retry re-proposed.
        match store
            .receive_request(&cv, b"body", b"RESP-2", Some("task-other"), "task", 101)
            .unwrap()
        {
            Receipt::Duplicate { task_id, response } => {
                assert_eq!(task_id.as_deref(), Some("task-9"));
                assert_eq!(response, b"RESP");
            }
            other => panic!("expected duplicate, got {other:?}"),
        }
    }

    #[test]
    fn changed_covered_value_is_conflict() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        store
            .receive_request(&covered("m1", b"body"), b"body", b"RESP", None, "task", 100)
            .unwrap();
        // Same peer + Message id, different body → different digest → conflict.
        let changed = covered("m1", b"different");
        assert_eq!(
            store
                .receive_request(&changed, b"different", b"RESP", None, "task", 101)
                .unwrap(),
            Receipt::Conflict
        );
    }

    #[test]
    fn tombstone_preserves_replay_after_payload_drop() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let cv = covered("m1", b"body");
        store
            .receive_request(&cv, b"body", b"RESP", Some("task-9"), "task", 100)
            .unwrap();
        assert!(store.demote_to_tombstone("agent-b", "m1", 9999).unwrap());

        // Replay after the payload is dropped still returns the saved response.
        match store
            .receive_request(&cv, b"body", b"RESP-2", Some("task-x"), "task", 200)
            .unwrap()
        {
            Receipt::Duplicate { task_id, response } => {
                assert_eq!(task_id.as_deref(), Some("task-9"));
                assert_eq!(response, b"RESP");
            }
            other => panic!("expected duplicate, got {other:?}"),
        }
        // A changed covered value against the tombstone is still a conflict.
        let changed = covered("m1", b"different");
        assert_eq!(
            store
                .receive_request(&changed, b"different", b"R", None, "task", 201)
                .unwrap(),
            Receipt::Conflict
        );
    }
}
