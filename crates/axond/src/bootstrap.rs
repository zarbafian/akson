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
use std::time::Duration;

use axon_broker::{AuthScheme, Disclosure, Origin, ProcessorConfig};
use axon_contract::Identity;
use axon_crypto::cert::{self_signed_endpoint, EndpointCert};
use axon_crypto::identity::Fingerprint;
use axon_crypto::purpose::KeyPurpose;
use axon_store::envelope::Kek;
use axon_store::{ExternalCheckpoint, Store};
use rand::rngs::OsRng;
use rand::RngCore;
use time::OffsetDateTime;

use crate::approve::{approve_and_issue, deny};
use crate::broker::run_processor_call;
use crate::control::Problem;
use crate::control_dispatch::dispatch_control;
use crate::delivery::run_delivery;
use crate::keys::IdentityKeys;
use crate::pair_serve::run_pair_invite;
use crate::pairing::run_pair_accept;
use crate::result::submit_result;
use crate::send::run_send;
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
    /// Where to serve the mTLS A2A receive listener (e.g. `127.0.0.1:8443`).
    /// `None` runs control-only, with no network listener.
    pub receive_addr: Option<String>,
    /// Where to serve the mTLS pairing bootstrap endpoint (e.g. `127.0.0.1:9443`).
    /// `None` disables pairing over the network; also the invitation's endpoint URL.
    pub pair_addr: Option<String>,
    /// The worker command to run inside the sandbox for an approved task
    /// (`AXON_WORKER_CMD`). Run as `/bin/sh -c <cmd>` with the approved inputs
    /// read-only at `/inputs` and a writable `/output`; the worker writes its
    /// response to `/output/response`. `None` disables `axon task run`.
    pub worker_command: Option<String>,
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
        let receive_addr = env_nonempty("AXON_RECEIVE_ADDR");
        let pair_addr = env_nonempty("AXON_PAIR_ADDR");
        let worker_command = env_nonempty("AXON_WORKER_CMD");
        Self {
            data_dir,
            local_performer: Identity { issuer, agent },
            interface_url,
            receive_addr,
            pair_addr,
            worker_command,
        }
    }
}

/// The running daemon's shared state: the durable store (behind a `Mutex` so the
/// blocking control sockets and the async receive server share one connection),
/// this endpoint's own signing keys, and its stable endpoint certificate.
pub struct DaemonState {
    store: Arc<Mutex<Store>>,
    identity: IdentityKeys,
    endpoint_cert: EndpointCert,
    config: DaemonConfig,
}

impl DaemonState {
    /// Opens (creating on first run) the durable store under `config.data_dir`,
    /// loads this endpoint's key material and its persisted endpoint certificate,
    /// and returns the shared daemon state. Fails closed on an unreadable data
    /// directory, a malformed secret file, or a store that cannot open.
    pub fn bootstrap(config: &DaemonConfig) -> Result<Self, BootstrapError> {
        std::fs::create_dir_all(&config.data_dir)?;
        std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700))?;

        let kek = Kek::from_bytes(load_or_init_secret(&config.data_dir.join("kek"))?);
        let identity =
            IdentityKeys::from_master(load_or_init_secret(&config.data_dir.join("identity.seed"))?);
        // The endpoint certificate is generated once and persisted: its fingerprint
        // is what peers pin at pairing, so it MUST be stable across restarts and
        // across every connection (self_signed_endpoint embeds timestamps, so
        // regenerating it would move the fingerprint and break pinning).
        let endpoint_cert = load_or_init_endpoint_cert(&config.data_dir, &identity)?;
        // Interim custody reports no external rollback counter (ADR-0009 / §15.5):
        // degrade (open, flag detection unavailable) rather than block.
        let checkpoint = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: OffsetDateTime::now_utc().unix_timestamp(),
            rollback_detectable: false,
        };
        let store = Store::open(&config.data_dir.join("state.db"), &kek, checkpoint)?;
        // Crash recovery (§13.1, §15.5): any attempt or processor call left mid-flight
        // by a crash is *uncertain* — a byte may have left. Mark it ambiguous once at
        // startup; it is never silently retried, and never reported as completed.
        let now = OffsetDateTime::now_utc().unix_timestamp();
        store.resolve_crashed_attempts(now)?;
        store.resolve_crashed_calls(now)?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            identity,
            endpoint_cert,
            config: config.clone(),
        })
    }

    /// Wraps an already-open store, key material, and endpoint certificate (tests,
    /// and the future OS-keystore path). The certificate MUST be over the identity's
    /// tls-endpoint key.
    pub fn from_parts(
        store: Store,
        identity: IdentityKeys,
        endpoint_cert: EndpointCert,
        config: DaemonConfig,
    ) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            identity,
            endpoint_cert,
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

    /// This endpoint's stable self-signed certificate (its fingerprint is what
    /// peers pin at pairing).
    pub fn endpoint_cert(&self) -> &EndpointCert {
        &self.endpoint_cert
    }

    /// The daemon's configuration.
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Handles one control request behind the surface-authorization gate (design
    /// §16.2, §16.4). The gate has already refused any operation not permitted on
    /// the caller's surface, so this only routes the permitted ones:
    ///
    /// - `Diagnose` — daemon + sandbox health.
    /// - `TaskInbox` / `TaskShow` — the store-backed operator views.
    /// - `TaskApprove` — accept the Task and issue its one-shot work order,
    ///   signing with this endpoint's decision and work-order keys.
    /// - `TaskDeny` — sign a reject decision.
    /// - `SubmitResult` / `IssueWorkOrder` — acknowledged; their durable backing
    ///   lands in a later assembly step.
    pub fn dispatch(&self, req: &ControlRequest) -> Result<serde_json::Value, Problem> {
        match req {
            ControlRequest::Diagnose => Ok(diagnose_report()),
            ControlRequest::WhoAmI => Ok(serde_json::json!({
                "issuer": self.config.local_performer.issuer,
                "agent": self.config.local_performer.agent,
                "interface_url": self.config.interface_url,
                "receive_addr": self.config.receive_addr,
                "pair_addr": self.config.pair_addr,
                "endpoint_fingerprint": self.endpoint_cert.fingerprint.value,
                "data_dir": self.config.data_dir.display().to_string(),
            })),
            ControlRequest::TaskInbox | ControlRequest::TaskShow { .. } => {
                let store = self.store.lock().map_err(|_| internal())?;
                dispatch_control(&store, req)
            }
            ControlRequest::PeerList => {
                let store = self.store.lock().map_err(|_| internal())?;
                let items: Vec<_> = store
                    .list_peers()
                    .map_err(|_| internal())?
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "agent_id": p.agent_id, "endpoint": p.endpoint_id, "status": p.status,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "peers": items }))
            }
            ControlRequest::PeerConfirm { agent_id } => {
                let store = self.store.lock().map_err(|_| internal())?;
                let confirmed = store
                    .confirm_peer(agent_id, now_unix())
                    .map_err(|_| internal())?;
                Ok(serde_json::json!({ "confirmed": confirmed, "agent_id": agent_id }))
            }
            ControlRequest::TaskSent => {
                let store = self.store.lock().map_err(|_| internal())?;
                let items: Vec<_> = store
                    .list_sent_requests()
                    .map_err(|_| internal())?
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "task_id": s.task_id, "contract_id": s.contract_id,
                            "performer": s.performer_agent, "contract_digest": s.contract_digest,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "sent": items }))
            }
            ControlRequest::TaskOutcomes => {
                let store = self.store.lock().map_err(|_| internal())?;
                let items: Vec<_> = store
                    .list_outcomes()
                    .map_err(|_| internal())?
                    .iter()
                    .map(|o| {
                        serde_json::json!({
                            "task_id": o.task_id, "state": o.state,
                            "bundle_digest": o.bundle_digest, "outcome_digest": o.outcome_digest,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "outcomes": items }))
            }
            ControlRequest::TaskApprove {
                task_id,
                processor,
                artifacts,
            } => {
                let store = self.store.lock().map_err(|_| internal())?;
                approve_and_issue(
                    &store,
                    &self.config.local_performer,
                    &self.identity.purpose_key(KeyPurpose::ContractDecision),
                    &self.identity.work_order_key(),
                    task_id,
                    processor.as_deref(),
                    *artifacts,
                    now_unix(),
                )
            }
            ControlRequest::TaskDeny { task_id, reason } => {
                let store = self.store.lock().map_err(|_| internal())?;
                deny(
                    &store,
                    &self.config.local_performer,
                    &self.identity.purpose_key(KeyPurpose::ContractDecision),
                    task_id,
                    reason,
                    now_unix(),
                )
            }
            ControlRequest::SubmitResult(submission) => {
                let store = self.store.lock().map_err(|_| internal())?;
                submit_result(
                    &store,
                    &self.identity.purpose_key(KeyPurpose::TaskResult),
                    submission,
                    now_unix(),
                )
            }
            // Delivery, send, and processor calls manage their own store locking
            // (they must not hold the lock across the network I/O), so they take the
            // daemon state.
            ControlRequest::TaskRun { task_id } => crate::run_worker(self, task_id),
            ControlRequest::TaskDeliver { task_id } => run_delivery(self, task_id),
            ControlRequest::TaskSend(spec) => run_send(self, spec),
            ControlRequest::PairAccept { invitation } => run_pair_accept(self, invitation),
            ControlRequest::PairInvite => run_pair_invite(self),
            ControlRequest::RequestProcessorCall {
                processor_id,
                work_order_id,
                request,
            } => run_processor_call(self, processor_id, work_order_id, request.as_bytes()),
            ControlRequest::ProcessorAdd {
                processor_id,
                provider,
                origin_host,
                origin_port,
                local,
                tls_certificate_sha256,
                path,
                auth,
                headers,
            } => {
                let store = self.store.lock().map_err(|_| internal())?;
                let auth = match auth.as_deref() {
                    None | Some("bearer") => AuthScheme::Bearer,
                    Some("none") => AuthScheme::None,
                    Some(header) => AuthScheme::Header {
                        header: header.to_owned(),
                    },
                };
                // Parse `name:value` header strings, splitting on the first colon.
                let headers: Vec<(String, String)> = headers
                    .iter()
                    .filter_map(|h| h.split_once(':'))
                    .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
                    .collect();
                let config = ProcessorConfig {
                    processor_id: processor_id.clone(),
                    provider: provider.clone(),
                    origin: Origin::https(origin_host, *origin_port),
                    disclosure: if *local {
                        Disclosure::local()
                    } else {
                        Disclosure::remote(provider, "configured")
                    },
                    path: path.clone().unwrap_or_else(|| "/".to_owned()),
                    auth,
                    headers,
                    config: serde_json::json!({}),
                    tls_certificate_sha256: tls_certificate_sha256.clone(),
                };
                store.put_processor(&config, now_unix()).map_err(|_| internal())?;
                Ok(serde_json::json!({ "added": true, "processor_id": processor_id }))
            }
            ControlRequest::ProcessorList => {
                let store = self.store.lock().map_err(|_| internal())?;
                let procs = store.list_processors().map_err(|_| internal())?;
                let items: Vec<_> = procs
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "processor_id": p.processor_id,
                            "provider": p.provider,
                            "origin": format!("https://{}:{}", p.origin.host, p.origin.port),
                            "local": p.is_local(),
                            "pinned": p.tls_certificate_sha256.is_some(),
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "processors": items }))
            }
            ControlRequest::ProcessorCredential {
                processor_id,
                credential,
            } => {
                let store = self.store.lock().map_err(|_| internal())?;
                store
                    .put_credential(processor_id, credential.as_bytes(), now_unix())
                    .map_err(|_| internal())?;
                Ok(serde_json::json!({ "credential_set": true, "processor_id": processor_id }))
            }
            ControlRequest::IssueWorkOrder { .. } => Ok(serde_json::json!({ "accepted": true })),
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

/// How long the self-issued endpoint certificate is valid.
const ENDPOINT_CERT_VALIDITY: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// This endpoint's stable certificate, from `data_dir/endpoint.der`, generating it
/// on first run over the identity's tls-endpoint key (design §8.3). Persisting the
/// DER keeps the fingerprint — what peers pin at pairing — stable across restarts;
/// regenerating would move it and break pinning. The key is re-derived from the
/// master, so the persisted cert and the live key always match.
fn load_or_init_endpoint_cert(
    data_dir: &Path,
    identity: &IdentityKeys,
) -> Result<EndpointCert, BootstrapError> {
    let path = data_dir.join("endpoint.der");
    if path.exists() {
        let der = std::fs::read(&path)?;
        let fingerprint = Fingerprint::cert_sha256(&der);
        Ok(EndpointCert {
            der,
            pem: Vec::new(),
            fingerprint,
        })
    } else {
        let cert = self_signed_endpoint(
            &identity.purpose_key(KeyPurpose::TlsEndpoint),
            "axon-endpoint",
            ENDPOINT_CERT_VALIDITY,
        )
        .map_err(|e| BootstrapError::Config(format!("endpoint certificate: {e}")))?;
        std::fs::write(&path, &cert.der)?;
        Ok(cert)
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

/// The current wall-clock time. The decision path takes an explicit `now` for
/// testability; the live daemon supplies the trusted clock here.
fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
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
            receive_addr: None,
            pair_addr: None,
            worker_command: None,
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
        let kek_mode = std::fs::metadata(dir.join("kek"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(kek_mode & 0o777, 0o600);

        // A submitted proposal is visible through the live dispatch.
        let task_id = {
            let store = state.store();
            let store = store.lock().unwrap();
            submit_one(&store)
        };
        let inbox = state.dispatch(&ControlRequest::TaskInbox).unwrap();
        let tasks = inbox["tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["task_id"], task_id);

        // The risk card renders for that task.
        let card = state
            .dispatch(&ControlRequest::TaskShow {
                task_id: task_id.clone(),
            })
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
        let inbox = state.dispatch(&ControlRequest::TaskInbox).unwrap();
        assert_eq!(inbox["tasks"][0]["task_id"], task_id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diagnose_reports_daemon_health() {
        let dir = temp_dir("diag");
        let state = DaemonState::bootstrap(&config(dir.clone())).unwrap();
        let report = state.dispatch(&ControlRequest::Diagnose).unwrap();
        assert_eq!(report["daemon"], "axond");
        assert!(report["capabilities"].is_array());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn approve_over_dispatch_issues_a_work_order_with_the_derived_keys() {
        let dir = temp_dir("approve");
        let state = DaemonState::bootstrap(&config(dir.clone())).unwrap();
        let task_id = {
            let store = state.store();
            let store = store.lock().unwrap();
            // Pair the requester so the work-order origin can be bound.
            store
                .put_peer_key(
                    "req-fp",
                    "contract-proposal",
                    "requester",
                    "iss",
                    &proposal_key().verifying().to_public_bytes(),
                    NOW,
                )
                .unwrap();
            submit_one(&store)
        };
        // Approve over the same dispatch the sockets use — the daemon supplies its
        // derived decision and work-order keys.
        let out = state
            .dispatch(&ControlRequest::TaskApprove {
                task_id: task_id.clone(),
                processor: None,
                artifacts: false,
            })
            .unwrap();
        assert_eq!(out["approved"], true);
        assert!(out["work_order_id"].as_str().unwrap().starts_with("wo-"));
        // The accepted Task has left the submitted inbox.
        let inbox = state.dispatch(&ControlRequest::TaskInbox).unwrap();
        assert_eq!(inbox["tasks"].as_array().unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn processor_add_list_and_credential_round_trip() {
        let dir = temp_dir("processor");
        let state = DaemonState::bootstrap(&config(dir.clone())).unwrap();
        // Empty first.
        assert_eq!(
            state.dispatch(&ControlRequest::ProcessorList).unwrap()["processors"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        // Add a pinned local processor.
        let added = state
            .dispatch(&ControlRequest::ProcessorAdd {
                processor_id: "local-llm".to_owned(),
                provider: "local".to_owned(),
                origin_host: "127.0.0.1".to_owned(),
                origin_port: 8443,
                local: true,
                tls_certificate_sha256: Some("ab".repeat(32)),
                path: None,
                auth: None,
                headers: vec![],
            })
            .unwrap();
        assert_eq!(added["added"], true);
        // It is listed, local + pinned.
        let list = state.dispatch(&ControlRequest::ProcessorList).unwrap();
        let procs = list["processors"].as_array().unwrap();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0]["processor_id"], "local-llm");
        assert_eq!(procs[0]["local"], true);
        assert_eq!(procs[0]["pinned"], true);
        // The credential is set and stored sealed.
        let cred = state
            .dispatch(&ControlRequest::ProcessorCredential {
                processor_id: "local-llm".to_owned(),
                credential: "sk-secret".to_owned(),
            })
            .unwrap();
        assert_eq!(cred["credential_set"], true);
        assert_eq!(
            state
                .store()
                .lock()
                .unwrap()
                .get_credential("local-llm")
                .unwrap(),
            Some(b"sk-secret".to_vec())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
