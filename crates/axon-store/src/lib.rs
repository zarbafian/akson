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

use axon_contract::{
    accept_head, apply_revision, Head, HeadState, LockError, ParsedContract, RevisionVerdict,
};
use axon_crypto::identity::PeerIdentity;
use axon_pairing::invitation::PendingInvitation;
use axon_pairing::state_machine::{Consumed, LedgerError, PairingLedger, PairingStore};

/// The single peer-status type (design §8.2 step 7, §8.4). Persisted in the
/// queryable `peers.status` column (not sealed), so an idle-time gate need not
/// unseal the record; re-exported from `axon-pairing` where the lifecycle lives.
pub use axon_pairing::lifecycle::PeerStatus;
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
const CONTRACT_PAYLOAD_CONTEXT: &str = "contract.payload";

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
    #[error("corrupt store state: {0}")]
    Corrupt(String),
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

    /// Inserts or updates an already-active pinned peer (direct operator action,
    /// not a fresh pairing). The full record is sealed; the agent id, endpoint,
    /// issuer, and Agent Card thumbprint stay queryable.
    pub fn put_peer(&self, peer: &StoredPeer) -> Result<(), StoreError> {
        self.put_peer_status(peer, PeerStatus::Active)
    }

    /// Inserts a peer with `status_on_insert`, or updates the identity of an
    /// existing row. A conflict never changes an existing row's status: an
    /// idempotent re-store must not silently downgrade an active peer to pending
    /// (or re-open a pending one). Status transitions go through
    /// [`confirm_peer`](Self::confirm_peer) alone.
    fn put_peer_status(
        &self,
        peer: &StoredPeer,
        status_on_insert: PeerStatus,
    ) -> Result<(), StoreError> {
        let sealed = self
            .dek
            .seal(PEER_RECORD_CONTEXT, &serde_json::to_vec(peer)?);
        let id = &peer.identity;
        self.conn.execute(
            "INSERT INTO peers (agent_id, issuer, endpoint_id, agent_card_thumbprint, record, created_generation, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
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
                status_on_insert.as_column(),
            ],
        )?;
        Ok(())
    }

    /// The lifecycle status of a peer by agent id, or `None` if unknown. A cheap
    /// column read (no unseal) — the gate a work path checks before delivering.
    pub fn peer_status(&self, agent_id: &str) -> Result<Option<PeerStatus>, StoreError> {
        let s: Option<String> = self
            .conn
            .query_row(
                "SELECT status FROM peers WHERE agent_id = ?1",
                [agent_id],
                |r| r.get(0),
            )
            .optional()?;
        match s {
            Some(text) => PeerStatus::from_column(&text)
                .map(Some)
                .ok_or_else(|| StoreError::Corrupt(format!("unknown peer status {text:?}"))),
            None => Ok(None),
        }
    }

    /// The agent ids of peers awaiting the operator's confirmation (design §8.2
    /// step 7) — what `axon pair confirm` lists.
    pub fn pending_peer_ids(&self) -> Result<Vec<String>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT agent_id FROM peers WHERE status = 'pending' ORDER BY agent_id")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }

    /// Confirms a pending peer, moving it to active so it may exchange work
    /// (design §8.2 step 7). Idempotent-safe: returns `true` only when a pending
    /// peer was actually promoted (a distinct, auditable operator act), `false`
    /// if the peer was already active or does not exist. The transition and the
    /// audit record commit together.
    pub fn confirm_peer(&self, agent_id: &str, now: i64) -> Result<bool, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE peers SET status = 'active' WHERE agent_id = ?1 AND status = 'pending'",
            [agent_id],
        )?;
        if changed == 1 {
            audit::append(&tx, now, "peer.confirmed", agent_id)?;
        }
        tx.commit()?;
        Ok(changed == 1)
    }

    /// Forgets a pinned peer (design §8.4 removal): deletes the record so it may
    /// no longer exchange work — `get_peer` returns `None` and the work path
    /// finds no peer. Returns whether a peer existed; the removal is audited.
    ///
    /// This is also the sanctioned first half of an **explicit re-pair** (§8.4):
    /// re-pairing a peer whose pinned key/endpoint legitimately rotated is
    /// `remove_peer` (the deliberate operator act that authorizes dropping the
    /// old identity), then a fresh pairing — which lands *pending* and must be
    /// confirmed again. The [`store_pending_peer`](PairingStore::store_pending_peer)
    /// hijack guard is never bypassed; the operator removes first, on purpose.
    pub fn remove_peer(&self, agent_id: &str, now: i64) -> Result<bool, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let removed = tx.execute("DELETE FROM peers WHERE agent_id = ?1", [agent_id])?;
        if removed == 1 {
            audit::append(&tx, now, "peer.removed", agent_id)?;
        }
        tx.commit()?;
        Ok(removed == 1)
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

    fn any_pairing_open(&self, now: i64) -> Result<bool, LedgerError> {
        // A live invitation (not yet expired) or a still-retriable consumed
        // record keeps the endpoint enabled; expired rows do not (they are GC'd
        // by `purge_expired_pairing`).
        let count: i64 = self
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM invitations   WHERE not_after  > ?1)
                      + (SELECT COUNT(*) FROM pending_pairs WHERE expires_at > ?1)",
                [now],
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
        // A freshly paired peer lands *pending*: it may not exchange work until
        // the operator confirms it (§8.2 step 7). On an idempotent re-store the
        // status is left untouched, never downgraded.
        self.put_peer_status(
            &StoredPeer {
                identity: peer.clone(),
                local_note: String::new(),
            },
            PeerStatus::Pending,
        )
        .map_err(ledger_err)
    }
}

/// The task-contract head and stored revisions (design §9.3, §10.2). The pure
/// compare-and-swap logic lives in `axon-contract`; the store persists the head
/// and applies each verdict inside one transaction, so a submission is a true CAS
/// and a locked head cannot race a successor.
impl Store {
    /// Loads a Task's compare-and-swap head, or [`HeadState::Empty`] if none.
    pub fn contract_head(&self, task_id: &str) -> Result<HeadState, StoreError> {
        let row: Option<(u64, String, String)> = self
            .conn
            .query_row(
                "SELECT revision, digest, status FROM contract_heads WHERE task_id = ?1",
                [task_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match row {
            None => Ok(HeadState::Empty),
            Some((revision, digest, status)) => {
                let head = Head { revision, digest };
                match status.as_str() {
                    "open" => Ok(HeadState::Open(head)),
                    "locked" => Ok(HeadState::Locked(head)),
                    other => Err(StoreError::Corrupt(format!(
                        "unknown head status {other:?}"
                    ))),
                }
            }
        }
    }

    /// Submits a validated revision as an atomic compare-and-swap on the Task's
    /// head (design §9.3). On [`RevisionVerdict::Advance`] the head moves to the
    /// new (open) revision and the contract is stored (sealed, retained until
    /// `expires_at_unix`); a [`RevisionVerdict::Stale`] changes nothing. The whole
    /// decision-and-write is one transaction, so it is a real CAS.
    ///
    /// `task_id` is the receiver-assigned Task id (assigned for revision zero,
    /// which the contract itself does not carry). `expires_at_unix` is the
    /// contract's expiry as unix seconds, computed by the caller.
    pub fn submit_revision(
        &self,
        task_id: &str,
        proposal: &ParsedContract,
        expires_at_unix: i64,
        now: i64,
    ) -> Result<RevisionVerdict, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let head = self.contract_head(task_id)?;
        let verdict = apply_revision(&head, proposal);
        if let RevisionVerdict::Advance(new_head) = &verdict {
            let c = &proposal.contract;
            tx.execute(
                "INSERT INTO contract_heads (task_id, contract_id, revision, digest, status)
                 VALUES (?1, ?2, ?3, ?4, 'open')
                 ON CONFLICT(task_id) DO UPDATE SET
                     contract_id = excluded.contract_id,
                     revision = excluded.revision,
                     digest = excluded.digest,
                     status = 'open'",
                params![
                    task_id,
                    c.contract_id,
                    new_head.revision as i64,
                    new_head.digest
                ],
            )?;
            let sealed = self.dek.seal(CONTRACT_PAYLOAD_CONTEXT, &proposal.payload);
            tx.execute(
                "INSERT INTO contracts (digest, task_id, contract_id, revision, payload, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(digest) DO NOTHING",
                params![
                    proposal.digest,
                    task_id,
                    c.contract_id,
                    new_head.revision as i64,
                    sealed,
                    expires_at_unix
                ],
            )?;
            audit::append(&tx, now, "contract.submitted", &proposal.digest)?;
        }
        tx.commit()?;
        Ok(verdict)
    }

    /// Locks a Task's head at `accepted_digest` — the atomic effect of a signed
    /// acceptance (design §9.3). The pure `accept_head` decides; on success the
    /// row moves to `locked` and the acceptance is audited. Returns the inner
    /// [`LockError`] (a stale/duplicate acceptance) without failing the call.
    pub fn accept_contract(
        &self,
        task_id: &str,
        accepted_digest: &str,
        now: i64,
    ) -> Result<Result<(), LockError>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let head = self.contract_head(task_id)?;
        match accept_head(&head, accepted_digest) {
            Ok(_) => {
                tx.execute(
                    "UPDATE contract_heads SET status = 'locked' WHERE task_id = ?1",
                    [task_id],
                )?;
                audit::append(&tx, now, "contract.accepted", accepted_digest)?;
                tx.commit()?;
                Ok(Ok(()))
            }
            Err(e) => {
                tx.commit()?;
                Ok(Err(e))
            }
        }
    }

    /// Retrieves a stored contract revision's canonical payload by digest.
    pub fn get_contract(&self, digest: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT payload FROM contracts WHERE digest = ?1",
                [digest],
                |r| r.get(0),
            )
            .optional()?;
        match sealed {
            Some(bytes) => Ok(Some(self.dek.open(CONTRACT_PAYLOAD_CONTEXT, &bytes)?)),
            None => Ok(None),
        }
    }

    /// Purges stored contract revisions past their expiry (design §10.2).
    pub fn purge_expired_contracts(&self, now: i64) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM contracts WHERE expires_at <= ?1", [now])?;
        Ok(())
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
    fn paired_peer_is_pending_until_confirmed() {
        use axon_pairing::state_machine::PairingStore;
        let mut store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        store.store_pending_peer(&sample_peer("").identity).unwrap();

        // Freshly paired → pending, and listed as awaiting confirmation.
        assert_eq!(
            store.peer_status("agent-a").unwrap(),
            Some(PeerStatus::Pending)
        );
        assert_eq!(
            store.pending_peer_ids().unwrap(),
            vec!["agent-a".to_owned()]
        );

        // The operator confirms once; the promotion is reported and audited.
        let before = store.verify_audit().unwrap();
        assert!(store.confirm_peer("agent-a", 1_000).unwrap());
        assert_eq!(store.verify_audit().unwrap(), before + 1);
        assert_eq!(
            store.peer_status("agent-a").unwrap(),
            Some(PeerStatus::Active)
        );
        assert!(store.pending_peer_ids().unwrap().is_empty());

        // Confirming again is a no-op: already active, nothing audited.
        let after = store.verify_audit().unwrap();
        assert!(!store.confirm_peer("agent-a", 1_001).unwrap());
        assert!(!store.confirm_peer("nobody", 1_002).unwrap());
        assert_eq!(store.verify_audit().unwrap(), after);
    }

    #[test]
    fn remove_enables_explicit_repair_of_a_rotated_peer() {
        use axon_pairing::state_machine::PairingStore;
        let mut store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        store.store_pending_peer(&sample_peer("").identity).unwrap();
        store.confirm_peer("agent-a", 1_000).unwrap();

        // A same-id peer presenting a rotated key is refused: the hijack guard
        // (§8.4) never silently overwrites a pinned identity.
        let mut rotated = sample_peer("").identity;
        rotated.agent_card_key =
            Fingerprint::jwk(&ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]).verifying_key());
        assert!(store.store_pending_peer(&rotated).is_err());

        // The operator removes the peer on purpose (audited); it can no longer
        // exchange work.
        let before = store.verify_audit().unwrap();
        assert!(store.remove_peer("agent-a", 1_001).unwrap());
        assert_eq!(store.verify_audit().unwrap(), before + 1);
        assert!(store.get_peer("agent-a").unwrap().is_none());
        assert!(store.peer_status("agent-a").unwrap().is_none());

        // Now the rotated identity re-pairs cleanly — landing pending, requiring
        // a fresh confirmation, never silently active.
        store.store_pending_peer(&rotated).unwrap();
        assert_eq!(
            store.peer_status("agent-a").unwrap(),
            Some(PeerStatus::Pending)
        );
        store.confirm_peer("agent-a", 1_002).unwrap();
        assert_eq!(
            store
                .get_peer("agent-a")
                .unwrap()
                .unwrap()
                .identity
                .agent_card_key,
            rotated.agent_card_key
        );

        // Removing an unknown peer is a no-op, unaudited.
        let after = store.verify_audit().unwrap();
        assert!(!store.remove_peer("nobody", 1_003).unwrap());
        assert_eq!(store.verify_audit().unwrap(), after);
    }

    #[test]
    fn direct_put_peer_is_active_and_restore_never_downgrades() {
        use axon_pairing::state_machine::PairingStore;
        let mut store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        // An operator-added peer is active immediately.
        store.put_peer(&sample_peer("note")).unwrap();
        assert_eq!(
            store.peer_status("agent-a").unwrap(),
            Some(PeerStatus::Active)
        );
        // An idempotent re-store of the same identity must not silently reopen
        // it as pending.
        store.store_pending_peer(&sample_peer("").identity).unwrap();
        assert_eq!(
            store.peer_status("agent-a").unwrap(),
            Some(PeerStatus::Active)
        );
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

    // --- contract head persistence (M7) ---

    /// Builds a validated contract revision. `predecessor` and `task_id` are set
    /// for follow-up revisions (the schema requires both for rev > 0).
    fn parsed(rev: u64, predecessor: Option<&str>, task_id: Option<&str>) -> ParsedContract {
        let mut v = serde_json::json!({
            "schema_version": 1,
            "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": rev,
            "task_type": "https://axon.invalid/t",
            "message_id": "m1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"},
            "objective": "o",
            "inputs": [],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [],
            "requested_capabilities": [],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z"
        });
        if let Some(p) = predecessor {
            v["predecessor_digest"] = serde_json::Value::from(p);
        }
        if let Some(t) = task_id {
            v["task_id"] = serde_json::Value::from(t);
        }
        let payload = json_canon::to_vec(&v).unwrap();
        axon_contract::parse_payload(&payload).unwrap()
    }

    /// A valid revision-zero contract with a custom objective (a distinct digest).
    fn parsed_with_objective(objective: &str) -> ParsedContract {
        let v = serde_json::json!({
            "schema_version": 1,
            "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0,
            "task_type": "https://axon.invalid/t",
            "message_id": "m1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"},
            "objective": objective,
            "inputs": [],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [],
            "requested_capabilities": [],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z"
        });
        axon_contract::parse_payload(&json_canon::to_vec(&v).unwrap()).unwrap()
    }

    const EXPIRES: i64 = 1_893_456_000; // 2030-01-01

    #[test]
    fn submit_advances_head_and_stores_contract() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let rev0 = parsed(0, None, None);
        let verdict = store
            .submit_revision("task-1", &rev0, EXPIRES, 100)
            .unwrap();
        assert!(matches!(verdict, RevisionVerdict::Advance(_)));

        assert_eq!(
            store.contract_head("task-1").unwrap(),
            HeadState::Open(Head {
                revision: 0,
                digest: rev0.digest.clone()
            })
        );
        // The sealed payload round-trips back to the exact signed bytes.
        assert_eq!(
            store.get_contract(&rev0.digest).unwrap().unwrap(),
            rev0.payload
        );
        assert!(store.get_contract(&"0".repeat(64)).unwrap().is_none());
    }

    #[test]
    fn stale_revision_leaves_head_untouched() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let rev0 = parsed(0, None, None);
        store
            .submit_revision("task-1", &rev0, EXPIRES, 100)
            .unwrap();
        // A second, distinct rev-0 (a sibling) is stale; the head must not move.
        // It is still a valid revision zero (no task_id), differing only in its
        // objective, so it has a different digest.
        let sibling = parsed_with_objective("a different objective");
        assert_ne!(sibling.digest, rev0.digest);
        let verdict = store
            .submit_revision("task-1", &sibling, EXPIRES, 101)
            .unwrap();
        assert_eq!(
            verdict,
            RevisionVerdict::Stale(axon_contract::StaleReason::HeadAlreadyExists)
        );
        assert_eq!(
            store.contract_head("task-1").unwrap(),
            HeadState::Open(Head {
                revision: 0,
                digest: rev0.digest
            })
        );
    }

    #[test]
    fn chain_then_lock_bars_successors() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let rev0 = parsed(0, None, None);
        store
            .submit_revision("task-1", &rev0, EXPIRES, 100)
            .unwrap();
        let rev1 = parsed(1, Some(&rev0.digest), Some("task-1"));
        assert!(matches!(
            store
                .submit_revision("task-1", &rev1, EXPIRES, 101)
                .unwrap(),
            RevisionVerdict::Advance(_)
        ));

        // Accept (lock) the head at rev1, audited.
        let before = store.verify_audit().unwrap();
        assert!(store
            .accept_contract("task-1", &rev1.digest, 102)
            .unwrap()
            .is_ok());
        assert_eq!(store.verify_audit().unwrap(), before + 1);
        assert!(matches!(
            store.contract_head("task-1").unwrap(),
            HeadState::Locked(_)
        ));

        // A would-be successor onto a locked head is stale.
        let rev2 = parsed(2, Some(&rev1.digest), Some("task-1"));
        assert_eq!(
            store
                .submit_revision("task-1", &rev2, EXPIRES, 103)
                .unwrap(),
            RevisionVerdict::Stale(axon_contract::StaleReason::HeadLocked)
        );
    }

    #[test]
    fn accept_stale_digest_returns_lock_error() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let rev0 = parsed(0, None, None);
        store
            .submit_revision("task-1", &rev0, EXPIRES, 100)
            .unwrap();
        let r = store
            .accept_contract("task-1", &"a".repeat(64), 101)
            .unwrap();
        assert_eq!(r, Err(LockError::DigestMismatch));
        // Nothing was locked.
        assert!(matches!(
            store.contract_head("task-1").unwrap(),
            HeadState::Open(_)
        ));
    }

    #[test]
    fn head_and_contracts_survive_reopen_and_purge() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let rev0 = parsed(0, None, None);
        {
            let store = Store::open(&path, &kek(), checkpoint(0)).unwrap();
            store
                .submit_revision("task-1", &rev0, EXPIRES, 100)
                .unwrap();
        }
        {
            let store = Store::open(&path, &kek(), checkpoint(0)).unwrap();
            assert!(matches!(
                store.contract_head("task-1").unwrap(),
                HeadState::Open(_)
            ));
            assert!(store.get_contract(&rev0.digest).unwrap().is_some());
            // GC after expiry drops the stored revision.
            store.purge_expired_contracts(EXPIRES + 1).unwrap();
            assert!(store.get_contract(&rev0.digest).unwrap().is_none());
        }
    }
}
