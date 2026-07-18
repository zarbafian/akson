//! Bringing the daemon up: opening the durable store and composing the
//! store-backed control dispatch (design §16.2, §16.4).
//!
//! [`DaemonState::bootstrap`] opens (creating on first run) the endpoint's
//! encrypted state database under the data directory and holds it behind a
//! `Mutex`, so the control sockets — which run on their own OS threads — and the
//! async receive server can share one store. [`dispatch`] is the store-backed
//! control handler the sockets call: health, the task inbox, and a task's risk
//! card today; the decision and work-order operations layer on the same seam.
//!
//! **Key custody here is interim.** [`load_or_init_kek`] keeps the store's
//! key-encryption key in an owner-only file next to the data — the honest MVP the
//! codebase already anticipates ("`MemoryKeyStore` is the default; the OS-keystore
//! and TPM backends are additive adapters", ADR-0009). The real custody backend
//! swaps in behind this one function without touching the rest of the daemon.
//!
//! What you write:
//! ```no_run
//! use axond::{DaemonConfig, DaemonState};
//! let state = DaemonState::bootstrap(&DaemonConfig::from_env())?;
//! # Ok::<(), axond::BootstrapError>(())
//! ```

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axon_contract::Identity;
use axon_store::envelope::Kek;
use axon_store::{ExternalCheckpoint, Store};
use rand::rngs::OsRng;
use rand::RngCore;
use time::OffsetDateTime;

use crate::control::Problem;
use crate::control_dispatch::dispatch_control;
use crate::keys::IdentityKeys;
use crate::socket::ControlRequest;

/// Why the daemon could not come up.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] axon_store::StoreError),
    #[error("config: {0}")]
    Config(String),
}

/// The daemon's runtime configuration (design §16.2). Resolved from the
/// environment for now; a `~/.config/axon` file and an `axon init` command layer
/// on top later without changing this shape.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Where the durable store and interim key material live (owner-only, `0700`).
    pub data_dir: PathBuf,
    /// This endpoint's own identity — the contract `performer` for received work.
    pub local_performer: Identity,
    /// The A2A interface URL this endpoint advertises (an idempotency covered
    /// value; the receiver checks the contract targets it).
    pub interface_url: String,
}

impl DaemonConfig {
    /// Resolves the configuration from the environment, with local-first defaults:
    /// `AXON_DATA_DIR` (else `$XDG_DATA_HOME/axon`, else `~/.local/share/axon`),
    /// `AXON_ISSUER`/`AXON_AGENT` for the local identity, and
    /// `AXON_INTERFACE_URL`.
    pub fn from_env() -> Self {
        let data_dir = env_nonempty("AXON_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(default_data_dir);
        let issuer = env_nonempty("AXON_ISSUER").unwrap_or_else(|| "local".to_owned());
        let agent = env_nonempty("AXON_AGENT").unwrap_or_else(|| "axon-local".to_owned());
        let interface_url = env_nonempty("AXON_INTERFACE_URL")
            .unwrap_or_else(|| "https://localhost/a2a".to_owned());
        Self {
            data_dir,
            local_performer: Identity { issuer, agent },
            interface_url,
        }
    }
}

/// The running daemon's shared state: the durable store (behind a `Mutex` so the
/// blocking control sockets and the async receive server share one connection)
/// and this endpoint's own signing keys.
pub struct DaemonState {
    store: Arc<Mutex<Store>>,
    identity: IdentityKeys,
    config: DaemonConfig,
}

impl DaemonState {
    /// Opens (creating on first run) the durable store under `config.data_dir`,
    /// loads this endpoint's key material, and returns the shared daemon state.
    /// Fails closed on an unreadable data directory, a malformed secret file, or a
    /// store that cannot open.
    pub fn bootstrap(config: &DaemonConfig) -> Result<Self, BootstrapError> {
        std::fs::create_dir_all(&config.data_dir)?;
        std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700))?;

        let kek = Kek::from_bytes(load_or_init_secret(&config.data_dir.join("kek"))?);
        let identity = IdentityKeys::from_master(load_or_init_secret(
            &config.data_dir.join("identity.seed"),
        )?);
        // Interim custody reports no external rollback counter (ADR-0009 / §15.5):
        // degrade (open, flag detection unavailable) rather than block.
        let checkpoint = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: OffsetDateTime::now_utc().unix_timestamp(),
            rollback_detectable: false,
        };
        let store = Store::open(&config.data_dir.join("state.db"), &kek, checkpoint)?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            identity,
            config: config.clone(),
        })
    }

    /// Wraps an already-open store and key material (tests, and the future
    /// OS-keystore path).
    pub fn from_parts(store: Store, identity: IdentityKeys, config: DaemonConfig) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            identity,
            config,
        }
    }

    /// A shared handle to the store — cloned into each socket's dispatch closure
    /// and, later, the receive server.
    pub fn store(&self) -> Arc<Mutex<Store>> {
        self.store.clone()
    }

    /// This endpoint's own signing keys.
    pub fn identity(&self) -> &IdentityKeys {
        &self.identity
    }

    /// The daemon's configuration.
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }
}

/// Handles one control request behind the surface-authorization gate (design
/// §16.2, §16.4). The gate has already refused any operation not permitted on the
/// caller's surface, so this only routes the permitted ones:
///
/// - `Diagnose` — daemon + sandbox health (no store needed).
/// - `TaskInbox` / `TaskShow` — the store-backed operator views.
/// - `SubmitResult` / `IssueWorkOrder` — acknowledged; their durable backing lands
///   in the next assembly step, so the surface separation stays exercised.
pub fn dispatch(store: &Mutex<Store>, req: &ControlRequest) -> Result<serde_json::Value, Problem> {
    match req {
        ControlRequest::Diagnose => Ok(diagnose_report()),
        ControlRequest::TaskInbox | ControlRequest::TaskShow { .. } => {
            let store = store.lock().map_err(|_| internal())?;
            dispatch_control(&store, req)
        }
        ControlRequest::SubmitResult { .. } | ControlRequest::IssueWorkOrder { .. } => {
            Ok(serde_json::json!({ "accepted": true }))
        }
    }
}

/// The daemon + sandbox health report (`axon doctor` / `axon status`).
fn diagnose_report() -> serde_json::Value {
    let report = axon_sandbox::diagnose();
    let ready = axon_sandbox::all_required_available(&report);
    let capabilities: Vec<_> = report
        .iter()
        .map(|d| {
            serde_json::json!({
                "feature": d.feature,
                "available": d.available,
                "required": d.required,
            })
        })
        .collect();
    serde_json::json!({
        "daemon": "axond",
        "sandbox_ready": ready,
        "capabilities": capabilities,
    })
}

/// A 32-byte secret from an owner-only file at `path`, generating it on first run
/// (design §15.5 interim custody; ADR-0009 seam). Backs both the store's KEK and
/// the identity master seed.
///
/// The file is created with `0600` before any bytes are written, so the secret is
/// never briefly world-readable; an existing file is re-tightened to `0600` on
/// load. Custody stronger than the filesystem (OS keystore, TPM) replaces exactly
/// this function.
fn load_or_init_secret(path: &Path) -> Result<[u8; 32], BootstrapError> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            BootstrapError::Config(format!(
                "the secret file {} is not exactly 32 bytes",
                path.display()
            ))
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(arr)
    } else {
        let mut arr = [0u8; 32];
        OsRng.fill_bytes(&mut arr);
        // create_new + mode(0o600): fail rather than clobber, and never exist
        // world-readable even for an instant.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&arr)?;
        file.flush()?;
        Ok(arr)
    }
}

fn default_data_dir() -> PathBuf {
    if let Some(xdg) = env_nonempty("XDG_DATA_HOME") {
        PathBuf::from(xdg).join("axon")
    } else if let Some(home) = env_nonempty("HOME") {
        PathBuf::from(home).join(".local/share/axon")
    } else {
        std::env::temp_dir().join("axon-data")
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn internal() -> Problem {
    Problem {
        type_: "urn:axon:error:internal".to_owned(),
        title: "the request could not be processed".to_owned(),
        status: 500,
        detail: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::receive::{dispatch_proposal, DispatchOutcome};
    use axon_crypto::keypair::PurposeKey;
    use axon_crypto::purpose::KeyPurpose;
    use axon_ext::dsse::Envelope;
    use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use axon_proto::v1::{part::Content, Part};
    use axon_store::delivery::CoveredValues;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;

    fn temp_dir(label: &str) -> PathBuf {
        // Distinct per test — the tests run in parallel and must not share a dir.
        let dir =
            std::env::temp_dir().join(format!("axond-bootstrap-{}-{label}", std::process::id()));
        // A previous run's fixture would collide; start clean.
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn config(data_dir: PathBuf) -> DaemonConfig {
        DaemonConfig {
            data_dir,
            local_performer: Identity {
                issuer: "iss".to_owned(),
                agent: "performer".to_owned(),
            },
            interface_url: "https://local/a2a".to_owned(),
        }
    }

    fn proposal_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    fn submit_one(store: &Store) -> String {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
        let value = json!({
            "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0, "task_type": "https://axon.invalid/task/code-review/v1",
            "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"}, "objective": "o",
            "inputs": [{
                "id": "diff", "message_id": "msg-1", "part_index": 1, "kind": "text",
                "media_type": "text/x-diff", "charset": "utf-8", "canonical_rule": "utf8-exact",
                "byte_length": TEXT.len(), "sha256": sha,
                "worker_visible": true, "processor_visible": false
            }],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [], "requested_capabilities": ["respond"],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 8192},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"
        });
        let payload = axon_ext::jcs::canonical_bytes(&value).unwrap();
        let env: Envelope = axon_contract::sign_proposal(&payload, &proposal_key()).unwrap();
        let parts = vec![
            Part {
                metadata: None,
                filename: String::new(),
                media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
                content: Some(Content::Data(
                    serde_json::from_value(serde_json::to_value(&env).unwrap()).unwrap(),
                )),
            },
            Part {
                metadata: None,
                filename: String::new(),
                media_type: "text/x-diff".to_owned(),
                content: Some(Content::Text(TEXT.to_owned())),
            },
        ];
        let covered = CoveredValues {
            peer: "requester".to_owned(),
            message_id: "msg-1".to_owned(),
            body_digest: "AA".repeat(32),
            interface_url: "https://local/a2a".to_owned(),
            tenant: None,
            a2a_version: "1.0".to_owned(),
            extensions: vec![],
            content_type: "application/a2a+json".to_owned(),
            http_method: "POST".to_owned(),
        };
        match dispatch_proposal(
            store,
            &covered,
            &parts,
            "ctx-1",
            &proposal_key().verifying(),
            &ident("requester"),
            &ident("performer"),
            b"body",
            NOW,
        )
        .unwrap()
        .outcome
        {
            DispatchOutcome::Submitted { task_id } => task_id,
            other => panic!("expected Submitted, got {other:?}"),
        }
    }

    #[test]
    fn bootstrap_opens_a_durable_store_and_serves_the_inbox() {
        let dir = temp_dir("open");
        let state = DaemonState::bootstrap(&config(dir.clone())).unwrap();

        // The data dir is owner-only, and the KEK file exists at 0600.
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let kek_mode = std::fs::metadata(dir.join("kek")).unwrap().permissions().mode();
        assert_eq!(kek_mode & 0o777, 0o600);

        // A submitted proposal is visible through the live dispatch.
        let task_id = {
            let store = state.store();
            let store = store.lock().unwrap();
            submit_one(&store)
        };
        let store = state.store();
        let inbox = dispatch(&store, &ControlRequest::TaskInbox).unwrap();
        let tasks = inbox["tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["task_id"], task_id);

        // The risk card renders for that task.
        let card = dispatch(
            &store,
            &ControlRequest::TaskShow {
                task_id: task_id.clone(),
            },
        )
        .unwrap();
        assert_eq!(card["sections"].as_array().unwrap().len(), 5);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reopened_store_keeps_its_state() {
        let dir = temp_dir("reopen");
        let (task_id, decision_thumb) = {
            let state = DaemonState::bootstrap(&config(dir.clone())).unwrap();
            let thumb = state
                .identity()
                .purpose_key(KeyPurpose::ContractDecision)
                .thumbprint();
            let store = state.store();
            let store = store.lock().unwrap();
            (submit_one(&store), thumb)
        };
        // Reopen from the same data dir (same file KEK and identity seed) — the
        // Task survives and the endpoint's keys are the same ones.
        let state = DaemonState::bootstrap(&config(dir.clone())).unwrap();
        assert_eq!(
            state
                .identity()
                .purpose_key(KeyPurpose::ContractDecision)
                .thumbprint(),
            decision_thumb,
        );
        let store = state.store();
        let inbox = dispatch(&store, &ControlRequest::TaskInbox).unwrap();
        assert_eq!(inbox["tasks"][0]["task_id"], task_id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diagnose_reports_daemon_health() {
        let dir = temp_dir("diag");
        let state = DaemonState::bootstrap(&config(dir.clone())).unwrap();
        let store = state.store();
        let report = dispatch(&store, &ControlRequest::Diagnose).unwrap();
        assert_eq!(report["daemon"], "axond");
        assert!(report["capabilities"].is_array());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
