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
//! use akson_store::{Store, ExternalCheckpoint};
//! use akson_store::envelope::Kek;
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

use akson_authority::{
    next, AttemptEvent, AttemptState, IssuedWorkOrder, TransitionError, WorkOrder,
};
use akson_broker::{ProcessorCall, ProcessorConfig, SubAttemptEvent, SubAttemptState};
use akson_contract::{
    accept_head, apply_revision, Head, HeadState, LockError, ParsedContract, RevisionVerdict,
};
use akson_crypto::identity::PeerIdentity;

/// The single peer-status type (design §8.2 step 7, §8.4). Persisted in the
/// queryable `peers.status` column (not sealed), so an idle-time gate need not
/// unseal the record; re-exported from `akson-pairing` where the lifecycle lives.
pub use akson_pairing::lifecycle::PeerStatus;
use delivery::CoveredValues;
use envelope::{DataKey, Kek, SealError};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

const WRAPPED_DEK: &str = "wrapped_dek";
const COMMITMENT_KEY: &str = "commitment_key";
const STATE_GENERATION: &str = "state_generation";
const TRUSTED_TIME: &str = "trusted_time";
/// Backward wall-clock tolerance for [`Store::trusted_now`] (§8.5): a step back
/// within this is absorbed by the monotonic floor; beyond it, time is uncertain and
/// authority decisions refuse rather than risk reviving expired authority.
const CLOCK_TOLERANCE_SECS: i64 = 300;
const PEER_RECORD_CONTEXT: &str = "peers.record";

/// Knock-log row ceiling: bounds what a source-rotating scanner can grow
/// (`record_knock` drops new triples at the cap, still counting known ones).
const KNOCK_LOG_CAP: i64 = 1024;

/// Maps one live `peer_imports` row. Live rows always hold a label (removal
/// frees it to NULL in the same statement that tombstones).
fn import_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<PeerImport> {
    Ok(PeerImport {
        root_thumbprint: r.get(0)?,
        label: r.get(1)?,
        endpoint_hint: r.get(2)?,
        epoch: r.get::<_, i64>(3)?.max(0) as u64,
        added_at: r.get(4)?,
    })
}
const COMMITMENT_KEY_CONTEXT: &str = "meta.commitment_key";
const INBOX_BODY_CONTEXT: &str = "inbox.body";
const INBOX_RESPONSE_CONTEXT: &str = "inbox.response";
const CONTRACT_PAYLOAD_CONTEXT: &str = "contract.payload";
const PROCESSOR_CONFIG_CONTEXT: &str = "processor.config";
const WORK_ORDER_CONTEXT: &str = "work_order.issued";
const RESULT_MANIFEST_CONTEXT: &str = "result.manifest";
const OUTCOME_CONTEXT: &str = "outcome.signed";
const PROCESSOR_CREDENTIAL_CONTEXT: &str = "processor.credential";
const TASK_INPUT_CONTEXT: &str = "task.input";
const TASK_OUTPUT_CONTEXT: &str = "task.output";

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
    #[error("unknown work-order attempt {0:?}")]
    UnknownAttempt(String),
    #[error("unknown processor call {0:?}")]
    UnknownProcessorCall(String),
    #[error("trusted time is uncertain: the wall clock moved backward past tolerance")]
    TimeUncertain,
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

/// A peer's persisted verification key (design §8.1): its identity and the raw
/// 32-byte Ed25519 public key, resolved by TLS fingerprint for the receive path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKey {
    pub agent_id: String,
    pub issuer: String,
    pub public_key: [u8; 32],
    /// The relationship's root thumbprint; empty on legacy fixture rows.
    pub root_thumbprint: String,
}

/// A submitted Task's open head (design §10.1) — one row of the operator inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHead {
    pub task_id: String,
    pub contract_id: String,
    pub revision: u64,
    pub contract_digest: String,
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

/// The result of an atomic work-order claim (design §12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// A fresh claim: the nonce was consumed and the budget reserved.
    Claimed,
    /// The same work order was already claimed — its current attempt state is
    /// returned. A duplicate never creates a second attempt (§9.2, §12.3).
    AlreadyClaimed(AttemptState),
    /// The one-use nonce belongs to a *different* work order — a replayed or
    /// forged nonce. Refused; nothing is claimed.
    NonceReused,
}

/// A paired peer's listing summary (plaintext columns; no sealed record unseal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSummary {
    pub agent_id: String,
    pub endpoint_id: String,
    pub status: String,
}

/// A worker-visible input payload for a received task (design §7.2), unsealed —
/// the actual bytes to stage into the sandbox, with the digest/length to check
/// them against the contract manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInput {
    pub input_id: String,
    pub ordinal: i64,
    pub media_type: String,
    pub byte_length: i64,
    pub sha256: String,
    pub payload: Vec<u8>,
}

/// An output payload of a completed task (design §14.1), unsealed — the bytes the
/// worker produced, with the digest/length the signed result manifest states for
/// them. Held by the performer (staged before completion) and by the requester
/// (stored on delivery, after the digest was checked against that manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskOutput {
    pub artifact_id: String,
    pub ordinal: i64,
    pub role: String,
    pub media_type: String,
    pub byte_length: i64,
    pub sha256: String,
    pub payload: Vec<u8>,
}

/// One output to persist alongside an accepted outcome — the borrowing input to
/// [`Store::record_outcome_with_outputs`], already checked against the manifest.
pub struct NewTaskOutput<'a> {
    pub artifact_id: &'a str,
    pub ordinal: i64,
    pub role: &'a str,
    pub media_type: &'a str,
    pub byte_length: i64,
    pub sha256: &'a str,
    pub payload: &'a [u8],
}

/// Whether [`Store::record_outcome_with_outputs`] wrote a new disposition or
/// found the task already settled (a redelivery).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomeWrite {
    /// The outputs and outcome were committed together.
    Recorded,
    /// An outcome for this contract already existed; nothing was written. The
    /// stored digest is returned so the acknowledgement matches disk.
    AlreadyRecorded { outcome_digest: String },
}

/// A peer's standing auto-approval policy (design §12): the operator's
/// pre-authorisation to run certain task types from this peer without a per-task
/// prompt, up to a byte ceiling. An empty `task_types` matches nothing (so the
/// policy never fires); tasks requesting outward disclosure (processor use or
/// artifact export) are never auto-approved regardless — those always ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApprovePolicy {
    pub task_types: Vec<String>,
    pub max_response_bytes: u64,
}

/// One provisional import (design §8.2 step 3): a peer's identity root key,
/// pinned by the operator out of band under a locally chosen label, before any
/// network contact. Not yet a peer — the full §8.1 tuple arrives only at the
/// introduction, which must commit against this row's live `epoch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerImport {
    /// RFC 7638 thumbprint of the identity root key (ADR-0013).
    pub root_thumbprint: String,
    /// The operator-chosen local handle; never crosses the wire.
    pub label: String,
    /// Unauthenticated routing hint (`host:port`), possibly empty.
    pub endpoint_hint: String,
    /// Relationship epoch; advanced by removal, so pre-removal authorization
    /// can never commit or verify again.
    pub epoch: u64,
    pub added_at: i64,
}

/// One knock-log row (ADR-0015): refused introductions, deduped by
/// (claimed root, source, refusal class) with a counter instead of a row per
/// attempt. Observability for `peer knocks` — claims are unauthenticated and
/// the log carries no authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Knock {
    pub claimed_root: String,
    pub source: String,
    pub refusal_class: String,
    pub first_at: i64,
    pub last_at: i64,
    pub count: u64,
}

/// The verdict of [`Store::commit_introduced_peer`] (ADR-0015 step 5): the
/// compare-and-swap over `(root, epoch)` that turns a verified introduction
/// into a pinned, active peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntroCommitOutcome {
    /// The full tuple and keys were pinned; the peer is active.
    Committed,
    /// Identical material was already pinned — an idempotent re-introduction
    /// (simultaneous dials, or a crash between the two sides' commits).
    AlreadyActive,
    /// No live import for this root: the operator never said yes (or a
    /// removal landed first). Nothing written.
    NotImported,
    /// The import's epoch moved past the one this handshake started under —
    /// a removal raced it. Nothing written.
    EpochChanged,
    /// The peer is (or just became) suspended per §8.4: pinned material
    /// changed, or a prior suspension stands. Never silently re-pinned.
    Suspended(String),
}

/// The verdict of an import mutation. Domain refusals are values, not errors:
/// the CLI renders each as guidance, and nothing is ever overwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    /// The import was recorded (fresh, or a tombstoned root revived under a
    /// fresh label — its epoch already advanced at removal).
    Added,
    /// The requested update was applied.
    Updated,
    /// A live import for this root already exists; nothing changed.
    DuplicateRoot,
    /// The label names a different live import; nothing changed.
    LabelTaken,
    /// No live import for this root; nothing changed.
    UnknownRoot,
}

/// A recorded requester outcome's listing summary (design §14.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeSummary {
    pub task_id: String,
    pub contract_digest: String,
    pub bundle_digest: String,
    pub state: String,
    pub outcome_digest: String,
}

/// A task this daemon sent as *requester* and is awaiting a result for (design
/// §14.5). Retained so a delivered result can be matched to an outstanding request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentRequest {
    pub contract_digest: String,
    pub task_id: String,
    pub context_id: String,
    /// The ROOT this task was sent to (the resolved relationship key) — the
    /// value outcome matching binds the delivering identity against. Empty on
    /// pre-V20 rows, which therefore refuse (fail closed).
    pub performer_root: String,
    pub contract_id: String,
    pub performer_agent: String,
    pub performer_issuer: String,
    pub message_id: String,
}

/// The result of durably completing an attempt with its result (design §14.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// The attempt advanced to `succeeded` and the result was staged atomically.
    Completed,
    /// The attempt was already completed — the committed result stands unchanged.
    AlreadyCompleted,
    /// The attempt cannot complete from this state (pending, or already a terminal
    /// failure/ambiguous/cancelled). Nothing was written.
    NotRunnable(AttemptState),
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
        mut conn: Connection,
        kek: &Kek,
        checkpoint: ExternalCheckpoint,
    ) -> Result<Self, StoreError> {
        // Every claim/CAS method reads then writes in one transaction; DEFERRED
        // (the default) takes no write lock until the write, so under a second
        // connection the guard read and the write are not serialized and the loser
        // gets a raw SQLITE_BUSY_SNAPSHOT instead of the right verdict. IMMEDIATE
        // takes the write lock at BEGIN, so the check-and-act is a genuine CAS.
        conn.set_transaction_behavior(rusqlite::TransactionBehavior::Immediate);

        let journal_mode = schema::open_and_migrate(&conn)?;
        // WAL must be in effect on disk — the claim/CAS serialization above relies
        // on its snapshot isolation. An in-memory database reports "memory" (WAL is
        // not applicable); any rollback-journal mode means WAL silently failed
        // (e.g. a network filesystem), so fail closed rather than run unserialized.
        if journal_mode != "wal" && journal_mode != "memory" {
            return Err(StoreError::Corrupt(format!(
                "journal_mode is {journal_mode:?}, expected wal (durable claim/CAS need WAL)"
            )));
        }

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

        // Adopt the external checkpoint's trusted time as a floor on every open,
        // not just first init. The checkpoint is the anti-rollback anchor (§15.5);
        // if it is skipped on reopen, restoring an older snapshot silently lowers
        // the monotonic time floor and revives authority that expired after the
        // snapshot, even when the state-generation counter did not move. Raising
        // the floor to at least the anchor closes that (codex review). Only when
        // rollback detection is actually available — the interim custody profile
        // (ADR-0009) carries no trustworthy anchor and must not be trusted to
        // advance time.
        if checkpoint.rollback_detectable {
            let stored = schema::meta_get_i64(&conn, TRUSTED_TIME)?.unwrap_or(0);
            if checkpoint.trusted_time > stored {
                schema::meta_set_i64(&conn, TRUSTED_TIME, checkpoint.trusted_time)?;
            }
        }

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

    /// The trusted `now` for an authority decision (§8.5). Observes the wall clock
    /// against the monotonic floor and returns the floor — never a value below the
    /// last trusted time, so a small forward clock is fine but a backward step can
    /// never revive expired authority (an expired contract, a lapsed nonce window).
    /// Errs [`StoreError::TimeUncertain`] if the clock moved backward past tolerance,
    /// so the caller refuses the decision rather than acting on a rolled-back clock.
    pub fn trusted_now(&self, wall_clock: i64) -> Result<i64, StoreError> {
        match self.observe_time(wall_clock, CLOCK_TOLERANCE_SECS)? {
            TimeStatus::Ok { floor } => Ok(floor),
            TimeStatus::Uncertain { .. } => Err(StoreError::TimeUncertain),
        }
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
    /// existing row. Keyed by the identity ROOT (the agent-card key thumbprint,
    /// design §8.1) — same-named peers coexist under different roots. A
    /// conflict never changes an existing row's status: an idempotent re-store
    /// must not silently reopen or downgrade a relationship.
    fn put_peer_status(
        &self,
        peer: &StoredPeer,
        status_on_insert: PeerStatus,
    ) -> Result<(), StoreError> {
        let id = &peer.identity;
        let root = id.agent_card_key.value.clone();
        if root.is_empty() {
            return Err(StoreError::Corrupt(
                "a peer must carry an identity root thumbprint".to_owned(),
            ));
        }
        let sealed = self
            .dek
            .seal(PEER_RECORD_CONTEXT, &serde_json::to_vec(peer)?);
        self.conn.execute(
            "INSERT INTO peers
                 (root_thumbprint, agent_id, issuer, endpoint_id,
                  agent_card_thumbprint, record, created_generation, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(root_thumbprint) DO UPDATE SET
                 agent_id = excluded.agent_id,
                 issuer = excluded.issuer,
                 endpoint_id = excluded.endpoint_id,
                 agent_card_thumbprint = excluded.agent_card_thumbprint,
                 record = excluded.record",
            params![
                root,
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
                "SELECT status FROM peers WHERE agent_id = ?1
                 ORDER BY root_thumbprint LIMIT 1",
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

    /// A peer's lifecycle status by its root — the production gate.
    pub fn peer_status_by_root(
        &self,
        root_thumbprint: &str,
    ) -> Result<Option<PeerStatus>, StoreError> {
        let s: Option<String> = self
            .conn
            .query_row(
                "SELECT status FROM peers WHERE root_thumbprint = ?1",
                [root_thumbprint],
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
            // Delete the peer's verification keys too. peer_keys is keyed by TLS
            // fingerprint; if a removed peer's rows survive, then re-pairing the same
            // agent with a NEW certificate leaves the OLD fingerprint pointing at an
            // agent that is once again Active — and the receive resolver, which checks
            // the agent's status but not which fingerprint is current, would admit a
            // holder of the revoked certificate. Removing the rows closes that
            // re-pairing bypass (codex review).
            tx.execute("DELETE FROM peer_keys WHERE agent_id = ?1", [agent_id])?;
            // Drop any standing auto-approval too, so re-pairing a *different*
            // entity under the same agent id cannot inherit the removed peer's
            // pre-authorisation (codex review).
            tx.execute("DELETE FROM auto_approve WHERE agent_id = ?1", [agent_id])?;
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
                "SELECT record FROM peers WHERE agent_id = ?1
                 ORDER BY root_thumbprint LIMIT 1",
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

    /// The pinned peer behind a root — the production lookup (peers key by
    /// root since the cutover; names are display).
    pub fn get_peer_by_root(&self, root_thumbprint: &str) -> Result<Option<StoredPeer>, StoreError> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT record FROM peers WHERE root_thumbprint = ?1",
                [root_thumbprint],
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

    /// The ONE peer answering to `agent_id`, fail-closed on ambiguity: with
    /// same-named peers coexisting, a name-scoped authority decision (reactor
    /// policy, requester matching at delivery) must refuse rather than guess.
    /// `None` means zero OR several — indistinguishable on purpose. Retired
    /// once ADR-0014 puts the root inside the contract.
    pub fn sole_peer_named(&self, agent_id: &str) -> Result<Option<StoredPeer>, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM peers WHERE agent_id = ?1",
            [agent_id],
            |r| r.get(0),
        )?;
        if count != 1 {
            return Ok(None);
        }
        self.get_peer(agent_id)
    }

    /// Whether any pinned peer answers to `agent_id` under a DIFFERENT root —
    /// the label-shadowing guard's query.
    pub fn peer_named_with_other_root(
        &self,
        agent_id: &str,
        root_thumbprint: &str,
    ) -> Result<bool, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM peers WHERE agent_id = ?1 AND root_thumbprint != ?2",
            params![agent_id, root_thumbprint],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    /// Every paired peer's listing summary, ordered by agent id (`akson peer list`).
    /// Reads only plaintext columns — the sealed record is not unsealed.
    pub fn list_peers(&self) -> Result<Vec<PeerSummary>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT agent_id, endpoint_id, status FROM peers ORDER BY agent_id")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(PeerSummary {
                    agent_id: r.get(0)?,
                    endpoint_id: r.get(1)?,
                    status: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Persists a peer's verification key for a purpose, keyed by its TLS
    /// fingerprint (design §8.1) — retained at pairing so a received message can be
    /// verified. The public key is not secret; it is stored in the clear. A re-pair
    /// (same fingerprint, new key) replaces it.
    #[allow(clippy::too_many_arguments)]
    pub fn put_peer_key(
        &self,
        tls_fingerprint: &str,
        purpose: &str,
        agent_id: &str,
        issuer: &str,
        public_key: &[u8; 32],
        root_thumbprint: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO peer_keys
                 (tls_fingerprint, purpose, agent_id, issuer, public_key, root_thumbprint, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(tls_fingerprint, purpose) DO UPDATE SET
                 agent_id = excluded.agent_id,
                 issuer = excluded.issuer,
                 public_key = excluded.public_key,
                 root_thumbprint = excluded.root_thumbprint,
                 updated_at = excluded.updated_at",
            params![
                tls_fingerprint,
                purpose,
                agent_id,
                issuer,
                public_key.as_slice(),
                root_thumbprint,
                now
            ],
        )?;
        audit::append(
            &tx,
            now,
            "peer.key_persisted",
            &format!("{agent_id}:{purpose}"),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Resolves a peer's verification key for `purpose` from the TLS leaf-cert
    /// fingerprint the handshake presented (design §10.2) — the receive server's
    /// peer lookup.
    pub fn peer_key(
        &self,
        tls_fingerprint: &str,
        purpose: &str,
    ) -> Result<Option<PeerKey>, StoreError> {
        let row: Option<(String, String, Vec<u8>, String)> = self
            .conn
            .query_row(
                "SELECT agent_id, issuer, public_key, root_thumbprint FROM peer_keys
                 WHERE tls_fingerprint = ?1 AND purpose = ?2",
                params![tls_fingerprint, purpose],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        match row {
            Some((agent_id, issuer, key, root_thumbprint)) => {
                let public_key: [u8; 32] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("peer key is not 32 bytes".to_owned()))?;
                Ok(Some(PeerKey {
                    agent_id,
                    issuer,
                    public_key,
                    root_thumbprint,
                }))
            }
            None => Ok(None),
        }
    }

    /// The pinned TLS leaf-cert fingerprint of the peer `issuer/agent_id` (design
    /// §8.1) — the reverse of [`peer_key`](Self::peer_key), used when issuing a
    /// work order to bind its request origin. A peer presents one endpoint cert
    /// across all its purpose keys, so any row for the identity yields it. Returns
    /// `None` for an unpaired peer.
    pub fn peer_tls_fingerprint(
        &self,
        issuer: &str,
        agent_id: &str,
    ) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT tls_fingerprint FROM peer_keys
                 WHERE issuer = ?1 AND agent_id = ?2 LIMIT 1",
                params![issuer, agent_id],
                |r| r.get(0),
            )
            .optional()?)
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

/// The task-contract head and stored revisions (design §9.3, §10.2). The pure
/// compare-and-swap logic lives in `akson-contract`; the store persists the head
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

    /// Records the A2A Context id of a Task (design §10.2). Message-level, kept on
    /// the head so the accepting decision can reference it. Idempotent.
    pub fn set_task_context(&self, task_id: &str, context_id: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE contract_heads SET context_id = ?1 WHERE task_id = ?2",
            params![context_id, task_id],
        )?;
        Ok(())
    }

    /// The A2A Context id recorded for a Task, if any (empty is treated as absent).
    pub fn task_context(&self, task_id: &str) -> Result<Option<String>, StoreError> {
        let ctx: Option<String> = self
            .conn
            .query_row(
                "SELECT context_id FROM contract_heads WHERE task_id = ?1",
                [task_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(ctx.filter(|c| !c.is_empty()))
    }

    /// Lists the Tasks whose head is `open` — the submitted proposals awaiting a
    /// local decision (design §10.1, `TASK_STATE_SUBMITTED`). The operator's inbox.
    /// Ordered by task id for a stable listing.
    pub fn list_submitted_tasks(&self) -> Result<Vec<TaskHead>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT task_id, contract_id, revision, digest FROM contract_heads
             WHERE status = 'open' ORDER BY task_id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(TaskHead {
                    task_id: r.get(0)?,
                    contract_id: r.get(1)?,
                    revision: r.get(2)?,
                    contract_digest: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The submitted tasks the daemon's reactor has not yet handled — those with an
    /// open head and no `task_reactions` row. The reactor fires the arrival hook and
    /// considers auto-approval exactly once per task, surviving restarts.
    pub fn tasks_awaiting_reaction(&self) -> Result<Vec<TaskHead>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT h.task_id, h.contract_id, h.revision, h.digest
             FROM contract_heads h
             LEFT JOIN task_reactions r ON r.task_id = h.task_id
             WHERE h.status = 'open' AND r.task_id IS NULL
             ORDER BY h.task_id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(TaskHead {
                    task_id: r.get(0)?,
                    contract_id: r.get(1)?,
                    revision: r.get(2)?,
                    contract_digest: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Marks a task as handled by the reactor (idempotent).
    pub fn mark_task_reacted(&self, task_id: &str, now: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO task_reactions (task_id, reacted_at) VALUES (?1, ?2)
             ON CONFLICT(task_id) DO NOTHING",
            params![task_id, now],
        )?;
        Ok(())
    }

    /// Sets (or replaces) a peer's standing auto-approval policy — the human's
    /// pre-authorisation for that peer (§12 local authority).
    pub fn put_auto_approve(
        &self,
        agent_id: &str,
        root_thumbprint: &str,
        policy: &AutoApprovePolicy,
        now: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO auto_approve
                 (root_thumbprint, agent_id, task_types, max_response_bytes, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(root_thumbprint) DO UPDATE SET
                 agent_id = excluded.agent_id,
                 task_types = excluded.task_types,
                 max_response_bytes = excluded.max_response_bytes,
                 updated_at = excluded.updated_at",
            params![
                root_thumbprint,
                agent_id,
                policy.task_types.join("\n"),
                policy.max_response_bytes as i64,
                now
            ],
        )?;
        Ok(())
    }

    /// A root's standing policy, or `None` (the safe default: always ask).
    /// Standing authority keys by the introduced ROOT — a name is never an
    /// authority handle (slice-3 review; root-key cutover).
    pub fn auto_approve_for_root(
        &self,
        root_thumbprint: &str,
    ) -> Result<Option<AutoApprovePolicy>, StoreError> {
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT task_types, max_response_bytes FROM auto_approve
                 WHERE root_thumbprint = ?1",
                [root_thumbprint],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.map(|(types, max)| AutoApprovePolicy {
            task_types: types
                .lines()
                .map(str::to_owned)
                .filter(|s| !s.is_empty())
                .collect(),
            max_response_bytes: max.max(0) as u64,
        }))
    }

    /// Removes a root's auto-approval policy (reverts to always-ask).
    pub fn delete_auto_approve(&self, root_thumbprint: &str) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "DELETE FROM auto_approve WHERE root_thumbprint = ?1",
            [root_thumbprint],
        )?;
        Ok(n == 1)
    }

    /// Records the operator's import of an identity token (design §8.2 step 3):
    /// pins `root_thumbprint` under a locally chosen label. The one trust act of
    /// pairing. A tombstoned root is revived as a new relationship (its epoch
    /// already advanced at removal); a live duplicate is reported, never
    /// overwritten; a label held by a different live import is refused.
    pub fn add_peer_import(
        &self,
        root_thumbprint: &str,
        label: &str,
        endpoint_hint: &str,
        now: i64,
    ) -> Result<ImportOutcome, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let existing: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT tombstoned_at FROM peer_imports WHERE root_thumbprint = ?1",
                [root_thumbprint],
                |r| r.get(0),
            )
            .optional()?;
        if matches!(existing, Some(None)) {
            return Ok(ImportOutcome::DuplicateRoot);
        }
        // Only live rows hold labels (removal frees them to NULL).
        let label_holder: Option<String> = self
            .conn
            .query_row(
                "SELECT root_thumbprint FROM peer_imports WHERE label = ?1",
                [label],
                |r| r.get(0),
            )
            .optional()?;
        if label_holder.is_some_and(|holder| holder != root_thumbprint) {
            return Ok(ImportOutcome::LabelTaken);
        }
        if existing.is_some() {
            self.conn.execute(
                "UPDATE peer_imports
                 SET label = ?2, endpoint_hint = ?3, added_at = ?4, tombstoned_at = NULL
                 WHERE root_thumbprint = ?1",
                params![root_thumbprint, label, endpoint_hint, now],
            )?;
        } else {
            self.conn.execute(
                "INSERT INTO peer_imports
                     (root_thumbprint, label, endpoint_hint, epoch, added_at, tombstoned_at)
                 VALUES (?1, ?2, ?3, 1, ?4, NULL)",
                params![root_thumbprint, label, endpoint_hint, now],
            )?;
        }
        tx.commit()?;
        Ok(ImportOutcome::Added)
    }

    /// `peer add --update` / `peer label`: refreshes the label and/or routing
    /// hint of a live import. Never touches the epoch — hints and names carry
    /// no trust state.
    pub fn update_peer_import(
        &self,
        root_thumbprint: &str,
        new_label: Option<&str>,
        new_endpoint: Option<&str>,
    ) -> Result<ImportOutcome, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let live: Option<i64> = self
            .conn
            .query_row(
                "SELECT epoch FROM peer_imports
                 WHERE root_thumbprint = ?1 AND tombstoned_at IS NULL",
                [root_thumbprint],
                |r| r.get(0),
            )
            .optional()?;
        if live.is_none() {
            return Ok(ImportOutcome::UnknownRoot);
        }
        if let Some(label) = new_label {
            let holder: Option<String> = self
                .conn
                .query_row(
                    "SELECT root_thumbprint FROM peer_imports WHERE label = ?1",
                    [label],
                    |r| r.get(0),
                )
                .optional()?;
            if holder.is_some_and(|h| h != root_thumbprint) {
                return Ok(ImportOutcome::LabelTaken);
            }
            self.conn.execute(
                "UPDATE peer_imports SET label = ?2 WHERE root_thumbprint = ?1",
                params![root_thumbprint, label],
            )?;
        }
        if let Some(endpoint) = new_endpoint {
            self.conn.execute(
                "UPDATE peer_imports SET endpoint_hint = ?2 WHERE root_thumbprint = ?1",
                params![root_thumbprint, endpoint],
            )?;
        }
        tx.commit()?;
        Ok(ImportOutcome::Updated)
    }

    /// Tombstones a live import and advances its epoch in the same statement
    /// (design §8.2 step 7): an introduction that started under the old epoch
    /// can no longer commit, and the freed label may be reused without
    /// inheriting anything. Returns false if no live import held this root.
    pub fn remove_peer_import(
        &self,
        root_thumbprint: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "UPDATE peer_imports
             SET tombstoned_at = ?2, epoch = epoch + 1, label = NULL
             WHERE root_thumbprint = ?1 AND tombstoned_at IS NULL",
            params![root_thumbprint, now],
        )?;
        Ok(n == 1)
    }

    /// Removes a whole relationship in ONE transaction (slice-3 review): the
    /// import tombstones (epoch bump, label freed) AND the pinned peer, its
    /// verification keys, and any standing auto-approval behind the same root
    /// drop together — a crash leaves the relationship either fully removed or
    /// fully intact, never half-revoked. Returns false if no live import held
    /// this root (nothing is touched then).
    pub fn remove_relationship(
        &self,
        root_thumbprint: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let removed = self.conn.execute(
            "UPDATE peer_imports
             SET tombstoned_at = ?2, epoch = epoch + 1, label = NULL
             WHERE root_thumbprint = ?1 AND tombstoned_at IS NULL",
            params![root_thumbprint, now],
        )?;
        if removed == 1 {
            let agent: Option<String> = self
                .conn
                .query_row(
                    "SELECT agent_id FROM peers
                     WHERE root_thumbprint = ?1 AND root_thumbprint != ''",
                    [root_thumbprint],
                    |r| r.get(0),
                )
                .optional()?;
            self.conn.execute(
                "DELETE FROM peers WHERE root_thumbprint = ?1 AND root_thumbprint != ''",
                [root_thumbprint],
            )?;
            self.conn.execute(
                "DELETE FROM peer_keys WHERE root_thumbprint = ?1 AND root_thumbprint != ''",
                [root_thumbprint],
            )?;
            self.conn.execute(
                "DELETE FROM auto_approve WHERE root_thumbprint = ?1 AND root_thumbprint != ''",
                [root_thumbprint],
            )?;
            let _ = agent; // policy rows key by root; the by-root delete above covered it
            audit::append(&tx, now, "peer.removed", root_thumbprint)?;
        }
        tx.commit()?;
        Ok(removed == 1)
    }

    /// The live import for a root, if any.
    pub fn peer_import(&self, root_thumbprint: &str) -> Result<Option<PeerImport>, StoreError> {
        self.conn
            .query_row(
                "SELECT root_thumbprint, label, endpoint_hint, epoch, added_at
                 FROM peer_imports
                 WHERE root_thumbprint = ?1 AND tombstoned_at IS NULL",
                [root_thumbprint],
                import_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Resolves the operator's local label to its live import — the CLI's
    /// label → thumbprint step at task creation.
    pub fn peer_import_by_label(&self, label: &str) -> Result<Option<PeerImport>, StoreError> {
        self.conn
            .query_row(
                "SELECT root_thumbprint, label, endpoint_hint, epoch, added_at
                 FROM peer_imports
                 WHERE label = ?1 AND tombstoned_at IS NULL",
                [label],
                import_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Live imports, ordered by label.
    pub fn list_peer_imports(&self) -> Result<Vec<PeerImport>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT root_thumbprint, label, endpoint_hint, epoch, added_at
             FROM peer_imports
             WHERE tombstoned_at IS NULL
             ORDER BY label",
        )?;
        let rows = stmt
            .query_map([], import_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Records a refused introduction (ADR-0015), deduped by (claimed root,
    /// source, refusal class): a repeat bumps a counter instead of adding a
    /// row, and the table is capped so a source-rotating scanner cannot grow
    /// the store — at the cap, known triples still count up while new ones are
    /// dropped. Best-effort observability, not audit.
    pub fn record_knock(
        &self,
        claimed_root: &str,
        source: &str,
        refusal_class: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let updated = self.conn.execute(
            "UPDATE knock_log SET last_at = ?4, count = count + 1
             WHERE claimed_root = ?1 AND source = ?2 AND refusal_class = ?3",
            params![claimed_root, source, refusal_class, now],
        )?;
        if updated == 1 {
            return Ok(());
        }
        let rows: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM knock_log", [], |r| r.get(0))?;
        if rows >= KNOCK_LOG_CAP {
            return Ok(());
        }
        self.conn.execute(
            "INSERT INTO knock_log
                 (claimed_root, source, refusal_class, first_at, last_at, count)
             VALUES (?1, ?2, ?3, ?4, ?4, 1)",
            params![claimed_root, source, refusal_class, now],
        )?;
        Ok(())
    }

    /// Commits a verified introduction (design §8.2 step 4, ADR-0015): pins the
    /// full identity tuple and verification keys under `(root, epoch)` as one
    /// compare-and-swap. A removal that raced the handshake fails the CAS
    /// (`EpochChanged`); identical re-introduction is idempotent; changed
    /// material — including a renamed subject — suspends per §8.4, never
    /// re-pins and never forks. Same-named peers under different roots simply
    /// coexist (the #2 fix). `keys` are the counterparty's verification keys
    /// as (purpose, public).
    pub fn commit_introduced_peer(
        &self,
        root_thumbprint: &str,
        expected_epoch: u64,
        peer: &StoredPeer,
        keys: &[(String, [u8; 32])],
        now: i64,
    ) -> Result<IntroCommitOutcome, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let epoch: Option<i64> = self
            .conn
            .query_row(
                "SELECT epoch FROM peer_imports
                 WHERE root_thumbprint = ?1 AND tombstoned_at IS NULL",
                [root_thumbprint],
                |r| r.get(0),
            )
            .optional()?;
        let Some(epoch) = epoch else {
            return Ok(IntroCommitOutcome::NotImported);
        };
        if epoch.max(0) as u64 != expected_epoch {
            return Ok(IntroCommitOutcome::EpochChanged);
        }

        let agent_id = peer.identity.agent_id.clone();
        let was_pinned = if let Some(existing) = self.get_peer_by_root(root_thumbprint)? {
            // Any change to the pinned material — a rotated certificate, a
            // renamed subject, moved keys — suspends for review (§8.4).
            if let Some(reason) =
                akson_pairing::lifecycle::detect_change(&existing.identity, &peer.identity)
            {
                self.conn.execute(
                    "UPDATE peers SET status = ?2 WHERE root_thumbprint = ?1",
                    params![root_thumbprint, PeerStatus::Suspended(reason).as_column()],
                )?;
                audit::append(&tx, now, "peer.suspended", root_thumbprint)?;
                tx.commit()?;
                return Ok(IntroCommitOutcome::Suspended(format!("{reason:?}")));
            }
            if existing.identity.agent_id != agent_id {
                self.conn.execute(
                    "UPDATE peers SET status = ?2 WHERE root_thumbprint = ?1",
                    params![
                        root_thumbprint,
                        PeerStatus::Suspended(
                            akson_pairing::lifecycle::SuspendReason::SubjectChanged
                        )
                        .as_column()
                    ],
                )?;
                audit::append(&tx, now, "peer.suspended", root_thumbprint)?;
                tx.commit()?;
                return Ok(IntroCommitOutcome::Suspended("SubjectChanged".to_owned()));
            }
            // Identical material. A suspended peer stays suspended — review is
            // the operator's, not the wire's.
            if matches!(
                self.peer_status_by_root(root_thumbprint)?,
                Some(PeerStatus::Suspended(_))
            ) {
                return Ok(IntroCommitOutcome::Suspended("previously-suspended".to_owned()));
            }
            true
        } else {
            false
        };

        self.put_peer_status(peer, PeerStatus::Active)?;
        self.conn.execute(
            "UPDATE peers SET status = 'active' WHERE root_thumbprint = ?1",
            params![root_thumbprint],
        )?;
        let issuer = peer.identity.issuer.clone().unwrap_or_default();
        let tls_fp = &peer.identity.tls_cert.value;
        for (purpose, public_key) in keys {
            self.conn.execute(
                "INSERT INTO peer_keys
                     (tls_fingerprint, purpose, agent_id, issuer, public_key, updated_at, root_thumbprint)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(tls_fingerprint, purpose) DO UPDATE SET
                     agent_id = excluded.agent_id,
                     issuer = excluded.issuer,
                     public_key = excluded.public_key,
                     updated_at = excluded.updated_at,
                     root_thumbprint = excluded.root_thumbprint",
                params![
                    tls_fp,
                    purpose,
                    agent_id,
                    issuer,
                    public_key.as_slice(),
                    now,
                    root_thumbprint
                ],
            )?;
        }
        audit::append(&tx, now, "peer.introduced", root_thumbprint)?;
        tx.commit()?;
        Ok(if was_pinned {
            IntroCommitOutcome::AlreadyActive
        } else {
            IntroCommitOutcome::Committed
        })
    }

    /// The pinned peer behind a root thumbprint, if an introduction committed
    /// one: `(agent_id, status_column)`. The label → root → peer join the CLI
    /// renders and the send path resolves.
    pub fn peer_by_root(&self, root_thumbprint: &str) -> Result<Option<(String, String)>, StoreError> {
        self.conn
            .query_row(
                "SELECT agent_id, status FROM peers WHERE root_thumbprint = ?1",
                [root_thumbprint],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(Into::into)
    }

    /// The transport-authenticated root a task's proposal arrived from
    /// (PK-cutover review): what delivery, approval, and the reactor bind the
    /// requester to. Empty for pre-V20 heads — callers fail closed.
    pub fn origin_root(&self, task_id: &str) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row(
                "SELECT origin_root FROM contract_heads WHERE task_id = ?1",
                [task_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// The knock log, most recent first — what `akson peer knocks` renders.
    pub fn knocks(&self) -> Result<Vec<Knock>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT claimed_root, source, refusal_class, first_at, last_at, count
             FROM knock_log ORDER BY last_at DESC, claimed_root",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Knock {
                    claimed_root: r.get(0)?,
                    source: r.get(1)?,
                    refusal_class: r.get(2)?,
                    first_at: r.get(3)?,
                    last_at: r.get(4)?,
                    count: r.get::<_, i64>(5)?.max(0) as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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
        origin_root: &str,
        expires_at_unix: i64,
        now: i64,
    ) -> Result<RevisionVerdict, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let head = self.contract_head(task_id)?;
        let verdict = apply_revision(&head, proposal);
        if let RevisionVerdict::Advance(new_head) = &verdict {
            let c = &proposal.contract;
            tx.execute(
                "INSERT INTO contract_heads
                     (task_id, contract_id, revision, digest, status, origin_root)
                 VALUES (?1, ?2, ?3, ?4, 'open', ?5)
                 ON CONFLICT(task_id) DO UPDATE SET
                     contract_id = excluded.contract_id,
                     revision = excluded.revision,
                     digest = excluded.digest,
                     status = 'open'",
                params![
                    task_id,
                    c.contract_id,
                    new_head.revision as i64,
                    new_head.digest,
                    origin_root
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
                // Self-contained CAS: lock only the exact open head `accept_head`
                // validated (its digest, still open), not merely the task id, so the
                // pre-condition is in the SQL. A 0-row result means the head moved —
                // fail closed.
                let changed = tx.execute(
                    "UPDATE contract_heads SET status = 'locked'
                     WHERE task_id = ?1 AND digest = ?2 AND status = 'open'",
                    params![task_id, accepted_digest],
                )?;
                if changed != 1 {
                    return Err(StoreError::Corrupt(format!(
                        "contract head for {task_id:?} moved under accept (digest {accepted_digest:?})"
                    )));
                }
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

/// Work-order attempts and the atomic claim (design §12.3). The pure state
/// machine lives in `akson-authority`; the store makes the claim durable — one row
/// insert consumes the one-use nonce and reserves the budget together — and drives
/// the state transitions.
impl Store {
    /// Atomically claims a work order (design §12.3): consumes its one-use nonce
    /// and reserves its budget in a single row insert. Idempotent — re-claiming
    /// the same work order returns its existing state, never a second attempt.
    /// A nonce presented for a *different* work order is refused as reuse. The
    /// caller MUST have verified the work order's MAC first.
    pub fn claim_attempt(&self, order: &WorkOrder, now: i64) -> Result<ClaimOutcome, StoreError> {
        let tx = self.conn.unchecked_transaction()?;

        // A prior claim of this exact work order is idempotent.
        if let Some(state) = self.attempt_state(&order.work_order_id)? {
            tx.commit()?;
            return Ok(ClaimOutcome::AlreadyClaimed(state));
        }
        // The nonce is one-use: if it belongs to another work order, refuse.
        let nonce_owner: Option<String> = tx
            .query_row(
                "SELECT work_order_id FROM attempts WHERE nonce = ?1",
                [&order.nonce],
                |r| r.get(0),
            )
            .optional()?;
        if nonce_owner.is_some() {
            tx.commit()?;
            return Ok(ClaimOutcome::NonceReused);
        }

        tx.execute(
            "INSERT INTO attempts
                 (work_order_id, nonce, task_id, work_order_digest, state,
                  max_cost_microusd, max_bytes, max_operations, claimed_at, deadline)
             VALUES (?1, ?2, ?3, ?4, 'claimed', ?5, ?6, ?7, ?8, ?9)",
            params![
                order.work_order_id,
                order.nonce,
                order.task_id,
                order
                    .digest()
                    .map_err(|e| StoreError::Corrupt(format!("work order not canonical: {e}")))?,
                order.budgets.max_cost_microusd as i64,
                order.budgets.max_bytes as i64,
                order.budgets.max_operations as i64,
                now,
                order.deadline,
            ],
        )?;
        audit::append(&tx, now, "attempt.claimed", &order.work_order_id)?;
        tx.commit()?;
        Ok(ClaimOutcome::Claimed)
    }

    /// The current state of an attempt by work-order id, if it exists.
    pub fn attempt_state(&self, work_order_id: &str) -> Result<Option<AttemptState>, StoreError> {
        let s: Option<String> = self
            .conn
            .query_row(
                "SELECT state FROM attempts WHERE work_order_id = ?1",
                [work_order_id],
                |r| r.get(0),
            )
            .optional()?;
        match s {
            None => Ok(None),
            Some(text) => AttemptState::from_str(&text)
                .map(Some)
                .ok_or_else(|| StoreError::Corrupt(format!("unknown attempt state {text:?}"))),
        }
    }

    /// Drives an attempt through the state machine (design §12.3). The pure
    /// `next` decides; a valid transition is persisted and audited. Returns the
    /// inner [`TransitionError`] (out-of-order or terminal) without failing the
    /// call; an unknown attempt is a [`StoreError::UnknownAttempt`].
    pub fn advance_attempt(
        &self,
        work_order_id: &str,
        event: AttemptEvent,
        now: i64,
    ) -> Result<Result<AttemptState, TransitionError>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let state = self
            .attempt_state(work_order_id)?
            .ok_or_else(|| StoreError::UnknownAttempt(work_order_id.to_owned()))?;
        match next(state, event) {
            Ok(new_state) => {
                // Self-contained CAS: the UPDATE re-asserts the state `next` decided
                // from, so the pre-condition lives in the SQL, not just the earlier
                // read. Serialized by IMMEDIATE, so it always matches; a 0-row result
                // would mean the state moved under us — fail closed rather than lie.
                let changed = tx.execute(
                    "UPDATE attempts SET state = ?1 WHERE work_order_id = ?2 AND state = ?3",
                    params![new_state.as_str(), work_order_id, state.as_str()],
                )?;
                if changed != 1 {
                    return Err(StoreError::Corrupt(format!(
                        "attempt {work_order_id} changed state concurrently (expected {})",
                        state.as_str()
                    )));
                }
                audit::append(
                    &tx,
                    now,
                    "attempt.transition",
                    &format!("{work_order_id}:{}", new_state.as_str()),
                )?;
                tx.commit()?;
                Ok(Ok(new_state))
            }
            Err(e) => {
                tx.commit()?;
                Ok(Err(e))
            }
        }
    }

    /// Resolves every attempt left claimed or running by a crash to `ambiguous`
    /// (design §12.3) — an effect may have started, so it is never auto-retried.
    /// Called during recovery. Returns how many were resolved.
    pub fn resolve_crashed_attempts(&self, now: i64) -> Result<usize, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let ids: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT work_order_id FROM attempts WHERE state IN ('claimed', 'running')",
            )?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for id in &ids {
            tx.execute(
                "UPDATE attempts SET state = 'ambiguous' WHERE work_order_id = ?1",
                [id],
            )?;
            audit::append(&tx, now, "attempt.transition", &format!("{id}:ambiguous"))?;
        }
        tx.commit()?;
        Ok(ids.len())
    }

    /// Persists an issued work order (design §12.3), sealed at rest. Idempotent: a
    /// re-issue of the same work order leaves the stored one unchanged. Retained so
    /// the result gate can check outputs against the exact granted capabilities.
    pub fn put_work_order(&self, issued: &IssuedWorkOrder, now: i64) -> Result<(), StoreError> {
        let json = serde_json::to_vec(issued)?;
        let sealed = self.dek.seal(WORK_ORDER_CONTEXT, &json);
        let tx = self.conn.unchecked_transaction()?;
        let inserted = tx.execute(
            "INSERT INTO work_orders (work_order_id, task_id, digest, order_json, issued_at)
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(work_order_id) DO NOTHING",
            params![
                issued.order.work_order_id,
                issued.order.task_id,
                issued.digest,
                sealed,
                now
            ],
        )?;
        if inserted == 1 {
            audit::append(&tx, now, "work_order.issued", &issued.order.work_order_id)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Retrieves a stored issued work order by its id (design §12.3).
    pub fn get_work_order(
        &self,
        work_order_id: &str,
    ) -> Result<Option<IssuedWorkOrder>, StoreError> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT order_json FROM work_orders WHERE work_order_id = ?1",
                [work_order_id],
                |r| r.get(0),
            )
            .optional()?;
        match sealed {
            Some(bytes) => {
                let json = self.dek.open(WORK_ORDER_CONTEXT, &bytes)?;
                Ok(Some(serde_json::from_slice(&json)?))
            }
            None => Ok(None),
        }
    }

    /// The work-order id of a task's attempt (design §12.3). v1 issues one work
    /// order per accepted Task, so a task maps to at most one attempt.
    pub fn attempt_for_task(&self, task_id: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT work_order_id FROM attempts WHERE task_id = ?1 LIMIT 1",
                [task_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Durably completes an attempt with its signed result (design §14.1, §9.3):
    /// in ONE transaction, advance the attempt to `succeeded` and stage the sealed
    /// result manifest — staged-then-atomic, so a result is never visible without
    /// the attempt being succeeded, nor vice versa. Idempotent: a re-submit of an
    /// already-completed attempt is [`CompletionOutcome::AlreadyCompleted`] and
    /// changes nothing (the committed result stands). An attempt that never claimed
    /// or already failed/ambiguous/cancelled is [`CompletionOutcome::NotRunnable`].
    pub fn complete_attempt_with_result(
        &self,
        work_order_id: &str,
        task_id: &str,
        bundle_digest: &str,
        manifest_envelope: &[u8],
        now: i64,
    ) -> Result<CompletionOutcome, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let state = self
            .attempt_state(work_order_id)?
            .ok_or_else(|| StoreError::UnknownAttempt(work_order_id.to_owned()))?;
        match state {
            // Already done — the committed result stands; do not overwrite.
            AttemptState::Succeeded => {
                tx.commit()?;
                Ok(CompletionOutcome::AlreadyCompleted)
            }
            // The worker submits its result at completion time, so the attempt may
            // still be claimed (never separately started) or running.
            AttemptState::Claimed | AttemptState::Running => {
                // Self-contained CAS on the exact source state (serialized by
                // IMMEDIATE); a 0-row result would mean it moved under us.
                let changed = tx.execute(
                    "UPDATE attempts SET state = 'succeeded'
                     WHERE work_order_id = ?1 AND state = ?2",
                    params![work_order_id, state.as_str()],
                )?;
                if changed != 1 {
                    return Err(StoreError::Corrupt(format!(
                        "attempt {work_order_id} changed state under completion"
                    )));
                }
                let sealed = self.dek.seal(RESULT_MANIFEST_CONTEXT, manifest_envelope);
                tx.execute(
                    "INSERT INTO results (work_order_id, task_id, bundle_digest, manifest, completed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![work_order_id, task_id, bundle_digest, sealed, now],
                )?;
                audit::append(
                    &tx,
                    now,
                    "attempt.transition",
                    &format!("{work_order_id}:succeeded"),
                )?;
                audit::append(&tx, now, "result.completed", bundle_digest)?;
                tx.commit()?;
                Ok(CompletionOutcome::Completed)
            }
            other => {
                tx.commit()?;
                Ok(CompletionOutcome::NotRunnable(other))
            }
        }
    }

    /// The stored (bundle_digest, sealed-then-opened signed result manifest) of a
    /// completed attempt, if any (design §14.1).
    pub fn result_manifest(
        &self,
        work_order_id: &str,
    ) -> Result<Option<(String, Vec<u8>)>, StoreError> {
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT bundle_digest, manifest FROM results WHERE work_order_id = ?1",
                [work_order_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            Some((digest, sealed)) => {
                let manifest = self.dek.open(RESULT_MANIFEST_CONTEXT, &sealed)?;
                Ok(Some((digest, manifest)))
            }
            None => Ok(None),
        }
    }
}

/// The requester side of the exchange (design §14.5): tracking the tasks this
/// daemon sent and recording its signed dispositions of their results.
impl Store {
    /// Records a task this daemon sent as requester (design §14.5). Idempotent on
    /// the contract digest — a re-send of the same contract leaves the record.
    pub fn put_sent_request(&self, req: &SentRequest, now: i64) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let inserted = tx.execute(
            "INSERT INTO sent_requests
                 (contract_digest, task_id, context_id, contract_id,
                  performer_agent, performer_issuer, message_id, performer_root, requested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(contract_digest) DO NOTHING",
            params![
                req.contract_digest,
                req.task_id,
                req.context_id,
                req.contract_id,
                req.performer_agent,
                req.performer_issuer,
                req.message_id,
                req.performer_root,
                now
            ],
        )?;
        if inserted == 1 {
            audit::append(&tx, now, "request.sent", &req.contract_digest)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The outstanding request for `contract_digest`, if this daemon sent it.
    pub fn get_sent_request(
        &self,
        contract_digest: &str,
    ) -> Result<Option<SentRequest>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT contract_digest, task_id, context_id, contract_id,
                        performer_agent, performer_issuer, message_id, performer_root
                 FROM sent_requests WHERE contract_digest = ?1",
                [contract_digest],
                |r| {
                    Ok(SentRequest {
                        contract_digest: r.get(0)?,
                        task_id: r.get(1)?,
                        context_id: r.get(2)?,
                        contract_id: r.get(3)?,
                        performer_agent: r.get(4)?,
                        performer_issuer: r.get(5)?,
                        message_id: r.get(6)?,
                        performer_root: r.get(7)?,
                    })
                },
            )
            .optional()?)
    }

    /// Records the requester's signed outcome for a result (design §14.5), sealed
    /// at rest. Idempotent on the contract digest — the first disposition stands.
    #[allow(clippy::too_many_arguments)]
    pub fn put_outcome(
        &self,
        contract_digest: &str,
        task_id: &str,
        bundle_digest: &str,
        outcome_digest: &str,
        state: &str,
        outcome_envelope: &[u8],
        signed_at: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let sealed = self.dek.seal(OUTCOME_CONTEXT, outcome_envelope);
        let tx = self.conn.unchecked_transaction()?;
        let inserted = tx.execute(
            "INSERT INTO outcomes
                 (contract_digest, task_id, bundle_digest, outcome_digest, state,
                  outcome, signed_at, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(contract_digest) DO NOTHING",
            params![
                contract_digest,
                task_id,
                bundle_digest,
                outcome_digest,
                state,
                sealed,
                signed_at,
                now
            ],
        )?;
        if inserted == 1 {
            audit::append(&tx, now, "outcome.signed", outcome_digest)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The requester's stored (outcome_digest, sealed-then-opened signed outcome
    /// envelope) for `contract_digest`, if any (design §14.5).
    pub fn get_outcome(
        &self,
        contract_digest: &str,
    ) -> Result<Option<(String, Vec<u8>)>, StoreError> {
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT outcome_digest, outcome FROM outcomes WHERE contract_digest = ?1",
                [contract_digest],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            Some((digest, sealed)) => {
                let envelope = self.dek.open(OUTCOME_CONTEXT, &sealed)?;
                Ok(Some((digest, envelope)))
            }
            None => Ok(None),
        }
    }

    /// Every task this daemon sent as requester, ordered by send time (`akson task
    /// sent`).
    pub fn list_sent_requests(&self) -> Result<Vec<SentRequest>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT contract_digest, task_id, context_id, contract_id,
                    performer_agent, performer_issuer, message_id, performer_root
             FROM sent_requests ORDER BY requested_at",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SentRequest {
                    contract_digest: r.get(0)?,
                    task_id: r.get(1)?,
                    context_id: r.get(2)?,
                    contract_id: r.get(3)?,
                    performer_agent: r.get(4)?,
                    performer_issuer: r.get(5)?,
                    message_id: r.get(6)?,
                    performer_root: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every recorded requester outcome, ordered by record time (`akson task
    /// outcomes`). Reads only plaintext columns — the sealed envelope is not opened.
    pub fn list_outcomes(&self) -> Result<Vec<OutcomeSummary>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT task_id, contract_digest, bundle_digest, state, outcome_digest
             FROM outcomes ORDER BY recorded_at",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(OutcomeSummary {
                    task_id: r.get(0)?,
                    contract_digest: r.get(1)?,
                    bundle_digest: r.get(2)?,
                    state: r.get(3)?,
                    outcome_digest: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

/// The outcome of preparing a processor call (design §13.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareOutcome {
    /// A fresh pre-dispatch record was stored in `prepared`.
    Prepared,
    /// The identical call (same idempotency key) was already prepared — its current
    /// sub-attempt state is returned. Re-preparing never creates a second record.
    AlreadyPrepared(SubAttemptState),
    /// This would be a *new* call for the work order, but the work order's aggregate
    /// operation budget (`max_operations`) is already spent. No record is stored and
    /// nothing is dispatched. An exact retry of an already-prepared call is never
    /// refused this way (it takes the `AlreadyPrepared` path first).
    BudgetExhausted {
        /// The aggregate operation cap that was reached.
        max_operations: u32,
    },
}

/// The processor broker's durable state (design §13.1, §15.2): configured
/// processors and the sub-attempt of every call. The pure logic (state machine,
/// bindings, egress checks) lives in `akson-broker`; this makes it durable.
impl Store {
    /// Stores (or updates) a processor configuration (design §15.2). The config is
    /// sealed under the DEK; `location` is kept in the clear so a listing needs no
    /// unseal. Audited as a configuration change.
    pub fn put_processor(&self, config: &ProcessorConfig, now: i64) -> Result<(), StoreError> {
        let json = serde_json::to_vec(config)?;
        let sealed = self.dek.seal(PROCESSOR_CONFIG_CONTEXT, &json);
        let location = if config.is_local() { "local" } else { "remote" };
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO processors (processor_id, provider, location, config, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(processor_id) DO UPDATE SET
                 provider = excluded.provider,
                 location = excluded.location,
                 config = excluded.config",
            params![config.processor_id, config.provider, location, sealed, now],
        )?;
        audit::append(&tx, now, "processor.configured", &config.processor_id)?;
        tx.commit()?;
        Ok(())
    }

    /// A configured processor by id, if present.
    pub fn get_processor(&self, processor_id: &str) -> Result<Option<ProcessorConfig>, StoreError> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT config FROM processors WHERE processor_id = ?1",
                [processor_id],
                |r| r.get(0),
            )
            .optional()?;
        match sealed {
            Some(bytes) => {
                let json = self.dek.open(PROCESSOR_CONFIG_CONTEXT, &bytes)?;
                Ok(Some(serde_json::from_slice(&json)?))
            }
            None => Ok(None),
        }
    }

    /// Every configured processor, ordered by id (backs `akson processor list`).
    pub fn list_processors(&self) -> Result<Vec<ProcessorConfig>, StoreError> {
        let sealeds: Vec<Vec<u8>> = {
            let mut stmt = self
                .conn
                .prepare("SELECT config FROM processors ORDER BY processor_id")?;
            let rows = stmt
                .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let mut out = Vec::with_capacity(sealeds.len());
        for bytes in sealeds {
            let json = self.dek.open(PROCESSOR_CONFIG_CONTEXT, &bytes)?;
            out.push(serde_json::from_slice(&json)?);
        }
        Ok(out)
    }

    /// Stores (or replaces) a processor's credential, sealed at rest (design
    /// §15.2). Injected into the request at dispatch; never written to the call
    /// record and never disclosed to the worker.
    pub fn put_credential(
        &self,
        processor_id: &str,
        credential: &[u8],
        now: i64,
    ) -> Result<(), StoreError> {
        let sealed = self.dek.seal(PROCESSOR_CREDENTIAL_CONTEXT, credential);
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO processor_credentials (processor_id, credential, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(processor_id) DO UPDATE SET
                 credential = excluded.credential, updated_at = excluded.updated_at",
            params![processor_id, sealed, now],
        )?;
        audit::append(&tx, now, "processor.credential_set", processor_id)?;
        tx.commit()?;
        Ok(())
    }

    /// A processor's stored credential, unsealed, if one is configured.
    pub fn get_credential(&self, processor_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT credential FROM processor_credentials WHERE processor_id = ?1",
                [processor_id],
                |r| r.get(0),
            )
            .optional()?;
        match sealed {
            Some(bytes) => Ok(Some(self.dek.open(PROCESSOR_CREDENTIAL_CONTEXT, &bytes)?)),
            None => Ok(None),
        }
    }

    /// Persists one worker-visible input payload for a received task (design §7.2),
    /// sealed at rest. Idempotent on `(task_id, input_id)`: re-receiving the same
    /// task (which is itself idempotent) does not duplicate or overwrite.
    #[allow(clippy::too_many_arguments)]
    pub fn put_task_input(
        &self,
        task_id: &str,
        input_id: &str,
        ordinal: i64,
        media_type: &str,
        byte_length: i64,
        sha256: &str,
        payload: &[u8],
        now: i64,
    ) -> Result<(), StoreError> {
        let sealed = self.dek.seal(TASK_INPUT_CONTEXT, payload);
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO task_inputs
                 (task_id, input_id, ordinal, media_type, byte_length, sha256, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(task_id, input_id) DO NOTHING",
            params![
                task_id,
                input_id,
                ordinal,
                media_type,
                byte_length,
                sha256,
                sealed
            ],
        )?;
        audit::append(&tx, now, "task.input_stored", task_id)?;
        tx.commit()?;
        Ok(())
    }

    /// The worker-visible input payloads for a task, unsealed, in manifest order.
    pub fn list_task_inputs(&self, task_id: &str) -> Result<Vec<TaskInput>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT input_id, ordinal, media_type, byte_length, sha256, payload
             FROM task_inputs WHERE task_id = ?1 ORDER BY ordinal",
        )?;
        let rows = stmt.query_map([task_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut inputs = Vec::new();
        for row in rows {
            let (input_id, ordinal, media_type, byte_length, sha256, sealed) = row?;
            let payload = self.dek.open(TASK_INPUT_CONTEXT, &sealed)?;
            inputs.push(TaskInput {
                input_id,
                ordinal,
                media_type,
                byte_length,
                sha256,
                payload,
            });
        }
        Ok(inputs)
    }

    /// Persists one output payload of a task (design §14.1), sealed at rest.
    /// Idempotent on `(task_id, artifact_id)`: re-staging or a duplicate delivery
    /// does not duplicate or overwrite.
    #[allow(clippy::too_many_arguments)]
    pub fn put_task_output(
        &self,
        task_id: &str,
        artifact_id: &str,
        ordinal: i64,
        role: &str,
        media_type: &str,
        byte_length: i64,
        sha256: &str,
        payload: &[u8],
        now: i64,
    ) -> Result<(), StoreError> {
        let sealed = self.dek.seal(TASK_OUTPUT_CONTEXT, payload);
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO task_outputs
                 (task_id, artifact_id, ordinal, role, media_type, byte_length, sha256, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(task_id, artifact_id) DO NOTHING",
            params![
                task_id,
                artifact_id,
                ordinal,
                role,
                media_type,
                byte_length,
                sha256,
                sealed
            ],
        )?;
        audit::append(&tx, now, "task.output_stored", task_id)?;
        tx.commit()?;
        Ok(())
    }

    /// Records an accepted requester outcome together with every output it
    /// covers, in a **single transaction** (design §14.1, requester mirror).
    ///
    /// The outputs and the outcome commit together or not at all. That is what
    /// makes "accepted" mean "I hold exactly the bytes I signed for": a crash
    /// can never leave committed output bytes that a *later*, differently-signed
    /// manifest then attaches itself to (`put_task_output` alone commits each
    /// output in its own transaction, and `ON CONFLICT DO NOTHING` would keep the
    /// stale bytes — codex review).
    ///
    /// Idempotent on `contract_digest`: a redelivery for a task whose disposition
    /// is already final does not re-stage outputs or mint a fresh outcome; it
    /// returns the stored digest so the acknowledgement matches what is on disk.
    /// The outputs are plain inserts (not `DO NOTHING`): a duplicate artifact_id
    /// within one manifest raises a constraint error and rolls the whole thing
    /// back, rather than silently coalescing two signed entries into one row.
    #[allow(clippy::too_many_arguments)]
    pub fn record_outcome_with_outputs(
        &self,
        contract_digest: &str,
        task_id: &str,
        bundle_digest: &str,
        outcome_digest: &str,
        state: &str,
        outcome_envelope: &[u8],
        outputs: &[NewTaskOutput<'_>],
        signed_at: &str,
        now: i64,
    ) -> Result<OutcomeWrite, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT outcome_digest FROM outcomes WHERE contract_digest = ?1",
                [contract_digest],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(outcome_digest) = existing {
            return Ok(OutcomeWrite::AlreadyRecorded { outcome_digest });
        }
        for o in outputs {
            let sealed = self.dek.seal(TASK_OUTPUT_CONTEXT, o.payload);
            tx.execute(
                "INSERT INTO task_outputs
                     (task_id, artifact_id, ordinal, role, media_type, byte_length, sha256, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    task_id,
                    o.artifact_id,
                    o.ordinal,
                    o.role,
                    o.media_type,
                    o.byte_length,
                    o.sha256,
                    sealed
                ],
            )?;
        }
        let sealed_outcome = self.dek.seal(OUTCOME_CONTEXT, outcome_envelope);
        tx.execute(
            "INSERT INTO outcomes
                 (contract_digest, task_id, bundle_digest, outcome_digest, state,
                  outcome, signed_at, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                contract_digest,
                task_id,
                bundle_digest,
                outcome_digest,
                state,
                sealed_outcome,
                signed_at,
                now
            ],
        )?;
        if !outputs.is_empty() {
            audit::append(&tx, now, "task.output_stored", task_id)?;
        }
        audit::append(&tx, now, "outcome.signed", outcome_digest)?;
        tx.commit()?;
        Ok(OutcomeWrite::Recorded)
    }

    /// The output payloads of a task, unsealed, in manifest order.
    pub fn list_task_outputs(&self, task_id: &str) -> Result<Vec<TaskOutput>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT artifact_id, ordinal, role, media_type, byte_length, sha256, payload
             FROM task_outputs WHERE task_id = ?1 ORDER BY ordinal",
        )?;
        let rows = stmt.query_map([task_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Vec<u8>>(6)?,
            ))
        })?;
        let mut outputs = Vec::new();
        for row in rows {
            let (artifact_id, ordinal, role, media_type, byte_length, sha256, sealed) = row?;
            let payload = self.dek.open(TASK_OUTPUT_CONTEXT, &sealed)?;
            outputs.push(TaskOutput {
                artifact_id,
                ordinal,
                role,
                media_type,
                byte_length,
                sha256,
                payload,
            });
        }
        Ok(outputs)
    }

    /// Durably records a processor call in `prepared` *before* it is dispatched
    /// (design §13.1) — so a crash after any byte leaves is recoverable as
    /// `ambiguous`. Idempotent on the call's idempotency key: re-preparing the
    /// identical call returns its existing sub-attempt state, never a second record.
    ///
    /// Enforces the work order's aggregate operation budget: a *new* call is refused
    /// with [`PrepareOutcome::BudgetExhausted`] once `max_operations` distinct calls
    /// already exist for the work order. The count and the insert share one
    /// transaction, so the cap holds under concurrency and across crashes — per-call
    /// cost/byte ceilings can no longer be multiplied by an unbounded call count
    /// (§12.1). An exact retry reuses its idempotency key and is never refused here.
    pub fn prepare_call(
        &self,
        call: &ProcessorCall,
        max_operations: u32,
        now: i64,
    ) -> Result<PrepareOutcome, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        if let Some(state) = self.call_state(&call.idempotency_key)? {
            tx.commit()?;
            return Ok(PrepareOutcome::AlreadyPrepared(state));
        }
        // A new call: it must fit under the work order's aggregate operation cap.
        // Counting inside this transaction makes the check-then-insert atomic.
        let existing: i64 = tx.query_row(
            "SELECT COUNT(*) FROM processor_calls WHERE work_order_id = ?1",
            [&call.work_order_id],
            |r| r.get(0),
        )?;
        if existing >= i64::from(max_operations) {
            tx.commit()?;
            return Ok(PrepareOutcome::BudgetExhausted { max_operations });
        }
        let origin = serde_json::to_string(&call.origin)?;
        tx.execute(
            "INSERT INTO processor_calls
                 (idempotency_key, work_order_id, task_id, processor_id, provider,
                  config_digest, request_digest, origin, state,
                  max_cost_microusd, max_response_bytes, deadline, prepared_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'prepared', ?9, ?10, ?11, ?12)",
            params![
                call.idempotency_key,
                call.work_order_id,
                call.task_id,
                call.processor_id,
                call.provider,
                call.config_digest,
                call.request_digest,
                origin,
                call.max_cost_microusd as i64,
                call.max_response_bytes as i64,
                call.deadline,
                now,
            ],
        )?;
        audit::append(&tx, now, "processor.prepared", &call.idempotency_key)?;
        tx.commit()?;
        Ok(PrepareOutcome::Prepared)
    }

    /// The current sub-attempt state of a prepared call, if it exists.
    pub fn call_state(&self, idempotency_key: &str) -> Result<Option<SubAttemptState>, StoreError> {
        let s: Option<String> = self
            .conn
            .query_row(
                "SELECT state FROM processor_calls WHERE idempotency_key = ?1",
                [idempotency_key],
                |r| r.get(0),
            )
            .optional()?;
        match s {
            None => Ok(None),
            Some(text) => SubAttemptState::from_str(&text)
                .map(Some)
                .ok_or_else(|| StoreError::Corrupt(format!("unknown sub-attempt state {text:?}"))),
        }
    }

    /// Drives a call's sub-attempt through the state machine (design §13.1). The
    /// pure `next` decides; a valid transition is persisted with a self-contained
    /// CAS (the UPDATE re-asserts the prior state) and audited. Returns the inner
    /// [`akson_broker::TransitionError`] without failing the call; an unknown call is
    /// a [`StoreError::UnknownProcessorCall`].
    pub fn advance_call(
        &self,
        idempotency_key: &str,
        event: SubAttemptEvent,
        now: i64,
    ) -> Result<Result<SubAttemptState, akson_broker::TransitionError>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let state = self
            .call_state(idempotency_key)?
            .ok_or_else(|| StoreError::UnknownProcessorCall(idempotency_key.to_owned()))?;
        match akson_broker::next(state, event) {
            Ok(new_state) => {
                let changed = tx.execute(
                    "UPDATE processor_calls SET state = ?1
                     WHERE idempotency_key = ?2 AND state = ?3",
                    params![new_state.as_str(), idempotency_key, state.as_str()],
                )?;
                if changed != 1 {
                    return Err(StoreError::Corrupt(format!(
                        "processor call {idempotency_key} changed state concurrently"
                    )));
                }
                audit::append(
                    &tx,
                    now,
                    "processor.transition",
                    &format!("{idempotency_key}:{}", new_state.as_str()),
                )?;
                tx.commit()?;
                Ok(Ok(new_state))
            }
            Err(e) => {
                tx.commit()?;
                Ok(Err(e))
            }
        }
    }

    /// Resolves every call left `dispatching` by a crash to `ambiguous` (design
    /// §13.1) — a byte may have left, so it is never auto-retried; the operator
    /// authorizes any new attempt after seeing the possible duplicate disclosure and
    /// cost. Called during recovery. Returns how many were resolved.
    pub fn resolve_crashed_calls(&self, now: i64) -> Result<usize, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let keys: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT idempotency_key FROM processor_calls WHERE state = 'dispatching'",
            )?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for k in &keys {
            tx.execute(
                "UPDATE processor_calls SET state = 'ambiguous'
                 WHERE idempotency_key = ?1 AND state = 'dispatching'",
                [k],
            )?;
            audit::append(&tx, now, "processor.transition", &format!("{k}:ambiguous"))?;
        }
        tx.commit()?;
        Ok(keys.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use akson_crypto::identity::{Fingerprint, PeerIdentity};

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
    fn remove_enables_explicit_repair_of_a_rotated_peer() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        store.put_peer(&sample_peer("")).unwrap();

        // The operator removes the peer on purpose (audited); it can no longer
        // exchange work.
        let before = store.verify_audit().unwrap();
        assert!(store.remove_peer("agent-a", 1_001).unwrap());
        assert_eq!(store.verify_audit().unwrap(), before + 1);
        assert!(store.get_peer("agent-a").unwrap().is_none());
        assert!(store.peer_status("agent-a").unwrap().is_none());

        // The rotated identity re-pins cleanly after the deliberate removal
        // (the fresh-introduction path re-verifies before this ever runs).
        let mut rotated = sample_peer("");
        rotated.identity.agent_card_key =
            Fingerprint::jwk(&ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]).verifying_key());
        store.put_peer(&rotated).unwrap();
        assert_eq!(
            store
                .get_peer("agent-a")
                .unwrap()
                .unwrap()
                .identity
                .agent_card_key,
            rotated.identity.agent_card_key
        );

        // Removing an unknown peer is a no-op, unaudited.
        let after = store.verify_audit().unwrap();
        assert!(!store.remove_peer("nobody", 1_003).unwrap());
        assert_eq!(store.verify_audit().unwrap(), after);
    }

    #[test]
    fn direct_put_peer_is_active_and_restore_keeps_status() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        store.put_peer(&sample_peer("note")).unwrap();
        assert_eq!(
            store.peer_status("agent-a").unwrap(),
            Some(PeerStatus::Active)
        );
        // An idempotent re-store of the same identity keeps it active.
        store.put_peer(&sample_peer("note")).unwrap();
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
    fn reopening_adopts_the_external_checkpoints_trusted_time_as_a_floor() {
        // A restored older snapshot must not lower the monotonic time floor below
        // the external anchor, or authority that expired after the snapshot revives
        // (codex review). On reopen, the floor is raised to the checkpoint's time.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            // First open at generation 5, time 1000; advance the floor to 1500.
            let cp = ExternalCheckpoint {
                state_generation: 5,
                trusted_time: 1000,
                rollback_detectable: true,
            };
            let store = Store::open(&path, &kek(), cp).unwrap();
            assert_eq!(store.trusted_now(1500).unwrap(), 1500);
        }
        // Reopen (same generation — no mismatch) with the anchor advanced to 5000.
        let cp = ExternalCheckpoint {
            state_generation: 5,
            trusted_time: 5000,
            rollback_detectable: true,
        };
        let store = Store::open(&path, &kek(), cp).unwrap();
        assert_eq!(*store.recovery(), Recovery::Normal);
        // The floor is now the anchor: a wall clock of 3000 is below it and refused,
        // so authority that expired at 4000 cannot be revived.
        assert_eq!(store.trusted_time_floor().unwrap(), 5000);
        assert!(matches!(
            store.observe_time(3000, 5).unwrap(),
            TimeStatus::Uncertain { .. }
        ));
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

    #[test]
    fn trusted_now_is_monotonic_and_refuses_a_large_backward_step() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        // Forward moves advance the floor and are returned as-is.
        assert_eq!(store.trusted_now(1_000_000).unwrap(), 1_000_000);
        assert_eq!(store.trusted_now(1_000_050).unwrap(), 1_000_050);
        // A small backward step (within tolerance) never returns below the floor.
        assert_eq!(store.trusted_now(1_000_040).unwrap(), 1_000_050);
        // A large backward step (past tolerance) is refused, not silently accepted —
        // so a rolled-back clock cannot revive expired authority.
        assert!(matches!(
            store.trusted_now(1_000_050 - 10_000),
            Err(StoreError::TimeUncertain)
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
            "task_type": "https://akson.invalid/t",
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
        akson_contract::parse_payload(&payload).unwrap()
    }

    /// A valid revision-zero contract with a custom objective (a distinct digest).
    fn parsed_with_objective(objective: &str) -> ParsedContract {
        let v = serde_json::json!({
            "schema_version": 1,
            "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0,
            "task_type": "https://akson.invalid/t",
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
        akson_contract::parse_payload(&json_canon::to_vec(&v).unwrap()).unwrap()
    }

    const EXPIRES: i64 = 1_893_456_000; // 2030-01-01

    #[test]
    fn submit_advances_head_and_stores_contract() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let rev0 = parsed(0, None, None);
        let verdict = store
            .submit_revision("task-1", &rev0, "origin-root-fixture", EXPIRES, 100)
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
            .submit_revision("task-1", &rev0, "origin-root-fixture", EXPIRES, 100)
            .unwrap();
        // A second, distinct rev-0 (a sibling) is stale; the head must not move.
        // It is still a valid revision zero (no task_id), differing only in its
        // objective, so it has a different digest.
        let sibling = parsed_with_objective("a different objective");
        assert_ne!(sibling.digest, rev0.digest);
        let verdict = store
            .submit_revision("task-1", &sibling, "origin-root-fixture", EXPIRES, 101)
            .unwrap();
        assert_eq!(
            verdict,
            RevisionVerdict::Stale(akson_contract::StaleReason::HeadAlreadyExists)
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
            .submit_revision("task-1", &rev0, "origin-root-fixture", EXPIRES, 100)
            .unwrap();
        let rev1 = parsed(1, Some(&rev0.digest), Some("task-1"));
        assert!(matches!(
            store
                .submit_revision("task-1", &rev1, "origin-root-fixture", EXPIRES, 101)
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
                .submit_revision("task-1", &rev2, "origin-root-fixture", EXPIRES, 103)
                .unwrap(),
            RevisionVerdict::Stale(akson_contract::StaleReason::HeadLocked)
        );
    }

    #[test]
    fn accept_stale_digest_returns_lock_error() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let rev0 = parsed(0, None, None);
        store
            .submit_revision("task-1", &rev0, "origin-root-fixture", EXPIRES, 100)
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
                .submit_revision("task-1", &rev0, "origin-root-fixture", EXPIRES, 100)
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

    // --- work-order attempts / atomic claim (M8) ---

    fn work_order(id: &str, nonce: &str) -> akson_authority::WorkOrder {
        use akson_authority::{
            Audience, Budgets, CapabilityVector, Grant, RequestOrigin, RespondScope,
        };
        use akson_contract::Identity;
        akson_authority::WorkOrder {
            version: 1,
            work_order_id: id.to_owned(),
            issuer: Identity {
                issuer: "local".to_owned(),
                agent: "authority".to_owned(),
            },
            issuer_assurance: "local-human".to_owned(),
            audience: Audience {
                daemon: "aksond".to_owned(),
                executor: "worker-1".to_owned(),
            },
            request_origin: RequestOrigin {
                peer: Identity {
                    issuer: "iss".to_owned(),
                    agent: "requester".to_owned(),
                },
                tls_certificate_sha256: "ab".repeat(32),
            },
            task_id: "task-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            message_id: "msg-1".to_owned(),
            contract_revision: 0,
            contract_digest: "a".repeat(64),
            capabilities: CapabilityVector::new(vec![Grant::Respond(RespondScope {
                task_id: "task-1".to_owned(),
                message_id: "msg-1".to_owned(),
                recipient: "request-origin".to_owned(),
                max_responses: 1,
                max_bytes: 8192,
                deadline: "2030-01-01T00:00:00Z".to_owned(),
            })])
            .unwrap(),
            input_manifest: vec!["src".to_owned()],
            processor_digest: None,
            runner_digest: None,
            sandbox_digest: None,
            profile_digest: None,
            budgets: Budgets {
                max_cost_microusd: 500,
                max_bytes: 8192,
                max_operations: 4,
            },
            evidence_slots: vec![],
            policy_version: 1,
            decision_id: "d-1".to_owned(),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            deadline: "2030-01-01T00:00:00Z".to_owned(),
            nonce: nonce.to_owned(),
            remote_cancel: None,
        }
    }

    #[test]
    fn claim_consumes_the_nonce_and_is_idempotent() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let order = work_order("wo-1", &"n".repeat(43));
        assert_eq!(
            store.claim_attempt(&order, 100).unwrap(),
            ClaimOutcome::Claimed
        );
        assert_eq!(
            store.attempt_state("wo-1").unwrap(),
            Some(AttemptState::Claimed)
        );
        // Re-claiming the same work order returns the existing state — no second
        // attempt.
        assert_eq!(
            store.claim_attempt(&order, 101).unwrap(),
            ClaimOutcome::AlreadyClaimed(AttemptState::Claimed)
        );
    }

    #[test]
    fn a_reused_nonce_on_a_different_order_is_refused() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let nonce = "n".repeat(43);
        store
            .claim_attempt(&work_order("wo-1", &nonce), 100)
            .unwrap();
        // A different work order presenting the same one-use nonce is refused.
        assert_eq!(
            store
                .claim_attempt(&work_order("wo-2", &nonce), 101)
                .unwrap(),
            ClaimOutcome::NonceReused
        );
        assert!(store.attempt_state("wo-2").unwrap().is_none());
    }

    #[test]
    fn advance_drives_the_state_machine_and_rejects_out_of_order() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let order = work_order("wo-1", &"n".repeat(43));
        store.claim_attempt(&order, 100).unwrap();
        assert_eq!(
            store
                .advance_attempt("wo-1", AttemptEvent::Start, 101)
                .unwrap(),
            Ok(AttemptState::Running)
        );
        assert_eq!(
            store
                .advance_attempt("wo-1", AttemptEvent::Succeed, 102)
                .unwrap(),
            Ok(AttemptState::Succeeded)
        );
        // A terminal attempt rejects further transitions (nothing persisted).
        assert!(matches!(
            store
                .advance_attempt("wo-1", AttemptEvent::Start, 103)
                .unwrap(),
            Err(TransitionError::AlreadyTerminal { .. })
        ));
        assert_eq!(
            store.attempt_state("wo-1").unwrap(),
            Some(AttemptState::Succeeded)
        );
        // An unknown attempt is a store error, not a transition verdict.
        assert!(matches!(
            store.advance_attempt("nope", AttemptEvent::Start, 104),
            Err(StoreError::UnknownAttempt(_))
        ));
    }

    #[test]
    fn crash_recovery_marks_claimed_and_running_ambiguous() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        // One attempt left claimed, one left running.
        store
            .claim_attempt(&work_order("wo-1", &"n".repeat(43)), 100)
            .unwrap();
        store
            .claim_attempt(&work_order("wo-2", &"m".repeat(43)), 100)
            .unwrap();
        store
            .advance_attempt("wo-2", AttemptEvent::Start, 101)
            .unwrap()
            .unwrap();

        assert_eq!(store.resolve_crashed_attempts(200).unwrap(), 2);
        assert_eq!(
            store.attempt_state("wo-1").unwrap(),
            Some(AttemptState::Ambiguous)
        );
        assert_eq!(
            store.attempt_state("wo-2").unwrap(),
            Some(AttemptState::Ambiguous)
        );
        // A second recovery pass finds nothing to resolve (idempotent).
        assert_eq!(store.resolve_crashed_attempts(201).unwrap(), 0);
    }

    #[test]
    fn attempts_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let order = work_order("wo-1", &"n".repeat(43));
        {
            let store = Store::open(&path, &kek(), checkpoint(0)).unwrap();
            store.claim_attempt(&order, 100).unwrap();
        }
        {
            let store = Store::open(&path, &kek(), checkpoint(0)).unwrap();
            // The nonce is still consumed after reopen — re-claim is idempotent.
            assert_eq!(
                store.claim_attempt(&order, 101).unwrap(),
                ClaimOutcome::AlreadyClaimed(AttemptState::Claimed)
            );
        }
    }

    #[test]
    fn a_work_order_round_trips_and_is_found_by_task() {
        use akson_authority::WorkOrderKey;
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let order = work_order("wo-1", &"n".repeat(43));
        let issued = order.issue(&WorkOrderKey::from_bytes([3u8; 32])).unwrap();
        store.claim_attempt(&order, 100).unwrap();
        store.put_work_order(&issued, 100).unwrap();

        // The stored order rehydrates identically and still verifies under its key.
        let got = store.get_work_order("wo-1").unwrap().expect("stored order");
        assert_eq!(got, issued);
        got.verify(&WorkOrderKey::from_bytes([3u8; 32])).unwrap();
        // Its task points back to the attempt.
        assert_eq!(
            store.attempt_for_task("task-1").unwrap(),
            Some("wo-1".to_owned())
        );
        assert!(store.get_work_order("wo-nope").unwrap().is_none());
        assert!(store.attempt_for_task("task-nope").unwrap().is_none());
    }

    // --- processor broker (M10) ---

    fn processor_config(id: &str) -> ProcessorConfig {
        ProcessorConfig {
            processor_id: id.to_owned(),
            provider: "example-ai".to_owned(),
            origin: akson_broker::Origin::https("api.example.com", 443),
            disclosure: akson_broker::Disclosure::remote("Example AI", "us-east"),
            path: "/".to_owned(),
            auth: akson_broker::AuthScheme::Bearer,
            headers: Vec::new(),
            config: serde_json::json!({"model": "review-1"}),
            tls_certificate_sha256: None,
        }
    }

    fn processor_call(request: &[u8]) -> ProcessorCall {
        ProcessorCall::prepare(
            &processor_config("reviewer"),
            request,
            akson_broker::CallBinding {
                work_order_id: "wo-1".to_owned(),
                work_order_digest: "aa".repeat(32),
                task_id: "task-1".to_owned(),
            },
            akson_broker::CallBudget {
                max_cost_microusd: 5000,
                deadline: "2030-01-01T00:00:00Z".to_owned(),
                max_response_bytes: 65536,
                max_operations: 16,
            },
        )
        .unwrap()
    }

    /// Same as `processor_call` but bound to a named work order, so a test can pin
    /// several distinct calls under one work order and exercise the aggregate cap.
    fn processor_call_for(request: &[u8], work_order_id: &str) -> ProcessorCall {
        ProcessorCall::prepare(
            &processor_config("reviewer"),
            request,
            akson_broker::CallBinding {
                work_order_id: work_order_id.to_owned(),
                work_order_digest: "aa".repeat(32),
                task_id: "task-1".to_owned(),
            },
            akson_broker::CallBudget {
                max_cost_microusd: 5000,
                deadline: "2030-01-01T00:00:00Z".to_owned(),
                max_response_bytes: 65536,
                max_operations: 16,
            },
        )
        .unwrap()
    }

    #[test]
    fn processor_config_round_trips_sealed() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        store
            .put_processor(&processor_config("reviewer"), 100)
            .unwrap();
        assert_eq!(
            store.get_processor("reviewer").unwrap().unwrap().provider,
            "example-ai"
        );
        assert_eq!(store.list_processors().unwrap().len(), 1);
        assert!(store.get_processor("nope").unwrap().is_none());
        // An update replaces in place (no second row).
        let mut updated = processor_config("reviewer");
        updated.provider = "example-ai-v2".to_owned();
        store.put_processor(&updated, 101).unwrap();
        assert_eq!(store.list_processors().unwrap().len(), 1);
        assert_eq!(
            store.get_processor("reviewer").unwrap().unwrap().provider,
            "example-ai-v2"
        );
    }

    #[test]
    fn prepare_call_is_idempotent() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let call = processor_call(b"review this");
        assert_eq!(
            store.prepare_call(&call, 16, 100).unwrap(),
            PrepareOutcome::Prepared
        );
        assert_eq!(
            store.call_state(&call.idempotency_key).unwrap(),
            Some(SubAttemptState::Prepared)
        );
        // Re-preparing the identical call never creates a second record.
        assert_eq!(
            store.prepare_call(&call, 16, 101).unwrap(),
            PrepareOutcome::AlreadyPrepared(SubAttemptState::Prepared)
        );
    }

    #[test]
    fn prepare_call_enforces_the_aggregate_operation_budget() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        // Two operations authorized for this work order.
        assert_eq!(
            store
                .prepare_call(&processor_call_for(b"one", "wo-cap"), 2, 100)
                .unwrap(),
            PrepareOutcome::Prepared
        );
        assert_eq!(
            store
                .prepare_call(&processor_call_for(b"two", "wo-cap"), 2, 101)
                .unwrap(),
            PrepareOutcome::Prepared
        );
        // A third DISTINCT call is over budget — refused, no record stored.
        assert_eq!(
            store
                .prepare_call(&processor_call_for(b"three", "wo-cap"), 2, 102)
                .unwrap(),
            PrepareOutcome::BudgetExhausted { max_operations: 2 }
        );
        // An exact retry of an already-prepared call is still idempotent, never
        // refused as over budget.
        assert_eq!(
            store
                .prepare_call(&processor_call_for(b"one", "wo-cap"), 2, 103)
                .unwrap(),
            PrepareOutcome::AlreadyPrepared(SubAttemptState::Prepared)
        );
        // A different work order has its own independent budget.
        assert_eq!(
            store
                .prepare_call(&processor_call_for(b"one", "wo-other"), 2, 104)
                .unwrap(),
            PrepareOutcome::Prepared
        );
    }

    #[test]
    fn advance_call_drives_the_state_machine() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let call = processor_call(b"x");
        store.prepare_call(&call, 16, 100).unwrap();
        assert_eq!(
            store
                .advance_call(&call.idempotency_key, SubAttemptEvent::Dispatch, 101)
                .unwrap()
                .unwrap(),
            SubAttemptState::Dispatching
        );
        assert_eq!(
            store
                .advance_call(&call.idempotency_key, SubAttemptEvent::Complete, 102)
                .unwrap()
                .unwrap(),
            SubAttemptState::Completed
        );
        // A terminal call cannot be advanced, and an unknown call is refused.
        assert!(store
            .advance_call(&call.idempotency_key, SubAttemptEvent::Dispatch, 103)
            .unwrap()
            .is_err());
        assert!(matches!(
            store.advance_call("nope", SubAttemptEvent::Dispatch, 104),
            Err(StoreError::UnknownProcessorCall(_))
        ));
    }

    #[test]
    fn crash_while_dispatching_resolves_ambiguous() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        // One call is mid-dispatch (a byte may have left); another only prepared.
        let dispatching = processor_call(b"disclosed");
        store.prepare_call(&dispatching, 16, 100).unwrap();
        store
            .advance_call(&dispatching.idempotency_key, SubAttemptEvent::Dispatch, 101)
            .unwrap()
            .unwrap();
        let prepared = processor_call(b"not yet sent");
        store.prepare_call(&prepared, 16, 102).unwrap();

        // Recovery sweeps only the dispatching one to ambiguous (never auto-retried).
        assert_eq!(store.resolve_crashed_calls(200).unwrap(), 1);
        assert_eq!(
            store.call_state(&dispatching.idempotency_key).unwrap(),
            Some(SubAttemptState::Ambiguous)
        );
        assert_eq!(
            store.call_state(&prepared.idempotency_key).unwrap(),
            Some(SubAttemptState::Prepared)
        );
        // Idempotent: a second sweep finds nothing dispatching.
        assert_eq!(store.resolve_crashed_calls(201).unwrap(), 0);
    }

    // --- peer verification keys (M12) ---

    #[test]
    fn put_peer_key_retains_the_proposal_key_by_fingerprint() {
        use akson_crypto::keypair::PurposeKey;
        use akson_crypto::purpose::KeyPurpose;

        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let proposal = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[5u8; 32]);
        store
            .put_peer_key("fp-abc",
                "contract-proposal",
                "peer-1",
                "local", &proposal.verifying().to_public_bytes(), "root-fixture", 100)
            .unwrap();
        // The proposal key is resolvable by TLS fingerprint + purpose.
        let pk = store
            .peer_key("fp-abc", "contract-proposal")
            .unwrap()
            .expect("the proposal key should be persisted");
        assert_eq!(pk.agent_id, "peer-1");
        assert_eq!(pk.issuer, "local");
        assert_eq!(pk.public_key, proposal.verifying().to_public_bytes());
        // An unknown fingerprint resolves to nothing.
        assert!(store
            .peer_key("other", "contract-proposal")
            .unwrap()
            .is_none());
    }

    const ROOT_FOR_TEST: &str = "test-root-thumbprint-aaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn auto_approve_policy_round_trips_and_clears() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        assert!(store.auto_approve_for_root(ROOT_FOR_TEST).unwrap().is_none());
        let policy = AutoApprovePolicy {
            task_types: vec!["t/design/v1".to_owned(), "t/review/v1".to_owned()],
            max_response_bytes: 8192,
        };
        store.put_auto_approve("peer-1", ROOT_FOR_TEST, &policy, 100).unwrap();
        assert_eq!(store.auto_approve_for_root(ROOT_FOR_TEST).unwrap().unwrap(), policy);
        assert!(store.delete_auto_approve(ROOT_FOR_TEST).unwrap());
        assert!(store.auto_approve_for_root(ROOT_FOR_TEST).unwrap().is_none());
    }

    #[test]
    fn a_task_is_offered_for_reaction_once() {
        // A submitted task is pending until marked; then never again (once-only,
        // even across a reactor restart, because the marker is durable).
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        assert!(store.tasks_awaiting_reaction().unwrap().is_empty());
        // Insert an open head directly (the reactor reads by task id).
        store
            .conn
            .execute(
                "INSERT INTO contract_heads (task_id, contract_id, revision, digest, status)
                 VALUES ('task-x', 'c-1', 0, 'd1', 'open')",
                [],
            )
            .unwrap();
        assert_eq!(store.tasks_awaiting_reaction().unwrap().len(), 1);
        store.mark_task_reacted("task-x", 101).unwrap();
        assert!(store.tasks_awaiting_reaction().unwrap().is_empty());
        // Idempotent mark.
        store.mark_task_reacted("task-x", 102).unwrap();
    }

    #[test]
    fn removing_a_peer_also_drops_its_verification_keys() {
        // A revoked peer's key rows must not survive removal. If they did, then
        // re-pairing the same agent with a NEW certificate would leave the OLD
        // fingerprint pointing at an again-active agent, and a holder of the
        // revoked certificate could still be resolved (codex review).
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        // sample_peer's agent is "agent-a"; give it a proposal key under some fp.
        store.put_peer(&sample_peer("to be removed")).unwrap();
        let key = [7u8; 32];
        store
            .put_peer_key("old-fp", "contract-proposal", "agent-a", "iss", &key, "root-fixture", 100)
            .unwrap();
        assert!(store
            .peer_key("old-fp", "contract-proposal")
            .unwrap()
            .is_some());

        assert!(store.remove_peer("agent-a", 101).unwrap());

        // The old fingerprint no longer resolves to any key — the bypass is closed.
        assert!(store
            .peer_key("old-fp", "contract-proposal")
            .unwrap()
            .is_none());
    }

    #[test]
    fn list_sent_requests_peers_and_outcomes() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        assert!(store.list_peers().unwrap().is_empty());
        assert!(store.list_sent_requests().unwrap().is_empty());
        assert!(store.list_outcomes().unwrap().is_empty());

        store
            .put_sent_request(
                &SentRequest {
                    contract_digest: "a".repeat(64),
                    task_id: "t1".to_owned(),
                    context_id: "c".to_owned(),
                    contract_id: "cid".to_owned(),
                    performer_agent: "p".to_owned(),
                    performer_issuer: "iss".to_owned(),
                    message_id: "m".to_owned(),
                    performer_root: "root-fixture".to_owned(),
                },
                100,
            )
            .unwrap();
        assert_eq!(store.list_sent_requests().unwrap().len(), 1);

        store
            .put_outcome(
                &"a".repeat(64),
                "t1",
                &"b".repeat(64),
                "od",
                "accepted",
                b"env",
                "2026-07-18T00:00:00Z",
                100,
            )
            .unwrap();
        let outs = store.list_outcomes().unwrap();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].task_id, "t1");
        assert_eq!(outs[0].state, "accepted");
    }

    #[test]
    fn processor_credentials_round_trip_sealed() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        store.put_credential("proc-1", b"sk-secret", 100).unwrap();
        assert_eq!(
            store.get_credential("proc-1").unwrap(),
            Some(b"sk-secret".to_vec())
        );
        // Replaced in place.
        store.put_credential("proc-1", b"sk-rotated", 200).unwrap();
        assert_eq!(
            store.get_credential("proc-1").unwrap(),
            Some(b"sk-rotated".to_vec())
        );
        assert!(store.get_credential("proc-none").unwrap().is_none());
    }

    #[test]
    fn task_inputs_round_trip_sealed_and_ordered() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        // Insert out of order; list returns them by ordinal.
        store
            .put_task_input(
                "task-1",
                "b",
                1,
                "text/plain",
                3,
                &"b".repeat(64),
                b"two",
                100,
            )
            .unwrap();
        store
            .put_task_input(
                "task-1",
                "a",
                0,
                "text/x-diff",
                5,
                &"a".repeat(64),
                b"first",
                100,
            )
            .unwrap();
        let inputs = store.list_task_inputs("task-1").unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].input_id, "a");
        assert_eq!(inputs[0].payload, b"first");
        assert_eq!(inputs[0].media_type, "text/x-diff");
        assert_eq!(inputs[1].input_id, "b");
        assert_eq!(inputs[1].payload, b"two");
        // Idempotent: re-storing the same (task, input) does not overwrite or dup.
        store
            .put_task_input(
                "task-1",
                "a",
                0,
                "text/x-diff",
                5,
                &"a".repeat(64),
                b"CHANGED",
                200,
            )
            .unwrap();
        let again = store.list_task_inputs("task-1").unwrap();
        assert_eq!(again.len(), 2);
        assert_eq!(again[0].payload, b"first");
        // A different task is isolated.
        assert!(store.list_task_inputs("task-2").unwrap().is_empty());
    }

    #[test]
    fn task_inputs_are_sealed_at_rest() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        store
            .put_task_input(
                "task-1",
                "a",
                0,
                "text/plain",
                6,
                &"a".repeat(64),
                b"secret",
                100,
            )
            .unwrap();
        // The plaintext must not appear in the raw column.
        let raw: Vec<u8> = store
            .conn
            .query_row(
                "SELECT payload FROM task_inputs WHERE input_id = 'a'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!raw.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn sent_requests_and_outcomes_round_trip() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let req = SentRequest {
            contract_digest: "a".repeat(64),
            task_id: "task-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            contract_id: "cid".to_owned(),
            performer_agent: "performer".to_owned(),
            performer_issuer: "iss".to_owned(),
            message_id: "msg-1".to_owned(),
            performer_root: "root-fixture".to_owned(),
        };
        store.put_sent_request(&req, 100).unwrap();
        assert_eq!(store.get_sent_request(&"a".repeat(64)).unwrap(), Some(req));
        assert!(store.get_sent_request("nope").unwrap().is_none());

        store
            .put_outcome(
                &"a".repeat(64),
                "task-1",
                &"b".repeat(64),
                "outcome-digest",
                "accepted",
                b"sealed-envelope-bytes",
                "2026-07-18T00:00:00Z",
                100,
            )
            .unwrap();
        let (digest, envelope) = store.get_outcome(&"a".repeat(64)).unwrap().unwrap();
        assert_eq!(digest, "outcome-digest");
        assert_eq!(envelope, b"sealed-envelope-bytes");
        assert!(store.get_outcome("nope").unwrap().is_none());
    }

    #[test]
    fn peer_tls_fingerprint_reverse_looks_up_the_pinned_cert() {
        let store = Store::open_in_memory(&kek(), checkpoint(0)).unwrap();
        let key = [7u8; 32];
        store
            .put_peer_key("fp-xyz", "contract-proposal", "peer-1", "local", &key, "root-fixture", 100)
            .unwrap();
        // The same peer's endpoint cert is found from its identity...
        assert_eq!(
            store.peer_tls_fingerprint("local", "peer-1").unwrap(),
            Some("fp-xyz".to_owned())
        );
        // ...and an unpaired identity yields nothing.
        assert!(store
            .peer_tls_fingerprint("local", "stranger")
            .unwrap()
            .is_none());
    }
}
