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
//! use aksond::{DaemonConfig, DaemonState};
//! let state = DaemonState::bootstrap(&DaemonConfig::from_env())?;
//! # Ok::<(), aksond::BootstrapError>(())
//! ```

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use akson_broker::{AuthScheme, Disclosure, Origin, ProcessorConfig};
use akson_contract::Identity;
use akson_crypto::cert::{self_signed_endpoint, EndpointCert};
use akson_crypto::identity::Fingerprint;
use akson_crypto::purpose::KeyPurpose;
use akson_store::envelope::Kek;
use akson_store::{ExternalCheckpoint, Store};
use rand::rngs::OsRng;
use rand::RngCore;
use time::OffsetDateTime;

use crate::approve::{approve_and_issue, deny};
use crate::broker::run_processor_call;
use crate::control::Problem;
use crate::control_dispatch::dispatch_control;
use crate::delivery::run_delivery;
use crate::keys::IdentityKeys;
use crate::result::submit_result;
use crate::send::run_send;
use crate::socket::ControlRequest;

/// Why the daemon could not come up.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] akson_store::StoreError),
    #[error("config: {0}")]
    Config(String),
}

/// The daemon's runtime configuration (design §16.2). Resolved from the
/// environment for now; a `~/.config/akson` file and an `akson init` command layer
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
    /// Defaults to `127.0.0.1:18443`; `None` (via `AKSON_RECEIVE_ADDR=off`)
    /// runs control-only, with no network listener.
    pub receive_addr: Option<String>,
    /// The worker command to run inside the sandbox for an approved task
    /// (`AKSON_WORKER_CMD`). Run as `/bin/sh -c <cmd>` with the approved inputs
    /// read-only at `/inputs` and a writable `/output`; the worker writes its
    /// response to `/output/response`. `None` disables `akson task run`.
    pub worker_command: Option<String>,
    /// A production adapter to run **directly** — no wrapping shell — under the
    /// strict [`adapter_worker_baseline`](akson_sandbox::SeccompPolicy::adapter_worker_baseline)
    /// seccomp profile (`AKSON_WORKER_EXEC`, whitespace-split into `argv`; the program
    /// must be an absolute path or resolvable on `PATH` inside the sandbox). When set,
    /// it takes precedence over `worker_command`. This is the confined-adapter path
    /// (§13.1/§16.3): a single process that cannot spawn a child or open a socket.
    pub worker_exec: Option<Vec<String>>,
    /// An optional command the daemon runs when a delegated task arrives
    /// (`AKSON_ON_TASK`), so a harness is *poked* rather than polling the inbox. Run
    /// as `/bin/sh -c <cmd>`, detached, with `AKSON_TASK` (the task id) and
    /// `AKSON_TASK_AUTO` (`1` if a standing policy auto-approved it) in its
    /// environment. `None` disables the hook.
    pub on_task: Option<String>,
}

impl DaemonConfig {
    /// Resolves the configuration from the environment, with local-first defaults:
    /// `AKSON_DATA_DIR` (else `$XDG_DATA_HOME/akson`, else `~/.local/share/akson`),
    /// `AKSON_ISSUER`/`AKSON_AGENT` for the local identity, and
    /// `AKSON_INTERFACE_URL`.
    pub fn from_env() -> Self {
        let data_dir = env_nonempty("AKSON_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(default_data_dir);
        let issuer = env_nonempty("AKSON_ISSUER").unwrap_or_else(|| "local".to_owned());
        let agent = env_nonempty("AKSON_AGENT").unwrap_or_else(|| "akson-local".to_owned());
        // Issue #5: the happy path needs no addressing env at all — the
        // receive listener defaults to loopback:18443. `AKSON_RECEIVE_ADDR=off`
        // (or `none`) explicitly opts out for a control-only daemon (sec6
        // review: the default must not silently take away that mode). The
        // advertised interface URL derives from the bind address when unset —
        // set AKSON_INTERFACE_URL explicitly to expose beyond this machine or
        // through NAT (a derived URL is only ever right on the local network).
        let receive_addr = match std::env::var("AKSON_RECEIVE_ADDR") {
            Ok(v) if v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none") => None,
            Ok(v) if !v.is_empty() => Some(v),
            _ => Some("127.0.0.1:18443".to_owned()),
        };
        let interface_url = env_nonempty("AKSON_INTERFACE_URL").unwrap_or_else(|| {
            let addr = receive_addr.as_deref().unwrap_or("127.0.0.1:18443");
            // A wildcard bind cannot be advertised; fall back to loopback.
            let advertised = addr.replace("0.0.0.0", "127.0.0.1").replace("[::]", "[::1]");
            format!("https://{advertised}/a2a")
        });
        let worker_command = env_nonempty("AKSON_WORKER_CMD");
        // A production adapter runs directly (no shell) under the strict profile;
        // split the command line on whitespace into argv. Empty → None.
        let worker_exec = env_nonempty("AKSON_WORKER_EXEC")
            .map(|s| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>());
        let on_task = env_nonempty("AKSON_ON_TASK");
        Self {
            data_dir,
            // The local root is populated at bootstrap, once the identity
            // keys exist (ADR-0014: the performer's signed root must be ours).
            local_performer: Identity {
                issuer,
                agent,
                root: String::new(),
            },
            interface_url,
            receive_addr,
            worker_command,
            worker_exec,
            on_task,
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
        let mut config = config.clone();
        config.local_performer.root = own_root(&identity);
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            identity,
            endpoint_cert,
            config,
        })
    }

    /// Wraps an already-open store, key material, and endpoint certificate (tests,
    /// and the future OS-keystore path). The certificate MUST be over the identity's
    /// tls-endpoint key.
    pub fn from_parts(
        store: Store,
        identity: IdentityKeys,
        endpoint_cert: EndpointCert,
        mut config: DaemonConfig,
    ) -> Self {
        config.local_performer.root = own_root(&identity);
        Self {
            store: Arc::new(Mutex::new(store)),
            identity,
            endpoint_cert,
            config,
        }
    }

    /// Resolves a task spec's `performer` for sending (design §8.2): a label
    /// naming a live import resolves to its pinned peer's `(root, agent)` —
    /// running the introduction first when this is the relationship's first
    /// contact — while anything else returns `None` and passes through as a
    /// bare agent name (honored downstream only while unambiguous).
    fn resolve_performer(&self, performer: &str) -> Result<Option<(String, String)>, Problem> {
        let import = {
            let store = self.store.lock().map_err(|_| internal())?;
            let Some(import) = store.peer_import_by_label(performer).map_err(|_| internal())?
            else {
                // Labels are the ONLY send addressing (sec5 review): a bare
                // agent name would resolve by an attacker-influenced string
                // and then carry a genuine root, laundering the misroute.
                return Err(unknown_label(performer));
            };
            // A label must not silently shadow a real agent id (slice-3
            // review): if a DIFFERENT pinned peer also answers to this exact
            // string as its agent id, refuse rather than guess.
            if store
                .peer_named_with_other_root(performer, &import.root_thumbprint)
                .map_err(|_| internal())?
            {
                return Err(Problem::new(
                    409,
                    "ambiguous-performer",
                    "this name is both a local label and another peer's agent id — rename the label",
                ));
            }
            if let Some((agent_id, status)) = store
                .peer_by_root(&import.root_thumbprint)
                .map_err(|_| internal())?
            {
                if status == "active" {
                    return Ok(Some((import.root_thumbprint, agent_id)));
                }
                // Suspended stays the operator's call — never auto-heal (§8.4).
                return Err(Problem::new(
                    409,
                    "peer-suspended",
                    "this peer is suspended pending review; re-add it to start a fresh relationship",
                ));
            }
            import
        };
        // First contact: introduce, then send (the store lock is NOT held —
        // the dial re-locks to commit).
        let me = crate::introduce::IntroIdentity::from_state(self)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| internal())?;
        let (peer, _) = runtime
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(20),
                    crate::introduce::dial_introduction(
                        &me,
                        self.store.clone(),
                        &import,
                        OffsetDateTime::now_utc(),
                    ),
                )
                .await
                .map_err(|_| {
                    crate::introduce::IntroduceError::Http("introduction timed out".into())
                })?
            })
            .map_err(|e| match e {
                crate::introduce::IntroduceError::Refused => {
                    Problem::new(403, "introduction-refused", &e.to_string())
                }
                crate::introduce::IntroduceError::NoEndpoint => {
                    Problem::new(400, "no-endpoint", &e.to_string())
                }
                other => Problem::new(502, "introduction-failed", &other.to_string()),
            })?;
        Ok(Some((peer.agent_card_key.value.clone(), peer.agent_id)))
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
                "endpoint_fingerprint": self.endpoint_cert.fingerprint.value,
                "data_dir": self.config.data_dir.display().to_string(),
            })),
            ControlRequest::TaskInbox | ControlRequest::TaskShow { .. } => {
                let store = self.store.lock().map_err(|_| internal())?;
                dispatch_control(&store, req)
            }
            ControlRequest::PeerList => {
                let store = self.store.lock().map_err(|_| internal())?;
                // Token-imported relationships, under the operator's labels
                // (design §8.2): status joins the pinned peer when the
                // introduction has committed one.
                let imports: Vec<_> = store
                    .list_peer_imports()
                    .map_err(|_| internal())?
                    .iter()
                    .map(|i| {
                        let (claims, status) = store
                            .peer_by_root(&i.root_thumbprint)
                            .ok()
                            .flatten()
                            .map(|(agent, status)| (Some(agent), status))
                            .unwrap_or((None, "imported".to_owned()));
                        serde_json::json!({
                            "label": i.label, "root_thumbprint": i.root_thumbprint,
                            "endpoint_hint": i.endpoint_hint, "status": status,
                            "claims": claims,
                        })
                    })
                    .collect();
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
                Ok(serde_json::json!({ "peers": items, "imports": imports }))
            }
            ControlRequest::Token => {
                let root = self
                    .identity
                    .purpose_key(akson_crypto::purpose::KeyPurpose::AgentCard)
                    .verifying()
                    .to_public_bytes();
                let token = akson_crypto::token::encode_token(&root);
                // The presentation hint is the advertised interface's host:port;
                // scheme and path are implied by the token format (ADR-0013).
                let hint = host_port_of(&self.config.interface_url);
                let presentation = match &hint {
                    Some(h) => format!("{token}@{h}"),
                    None => token.clone(),
                };
                let thumb = self
                    .identity
                    .purpose_key(akson_crypto::purpose::KeyPurpose::AgentCard)
                    .verifying()
                    .to_jwk()
                    .thumbprint();
                Ok(serde_json::json!({
                    "token": token,
                    "presentation": presentation,
                    "root_thumbprint": thumb,
                    "hint": hint,
                }))
            }
            ControlRequest::PeerAdd {
                token,
                label,
                endpoint,
                update,
            } => {
                let (tok, suffix) = akson_crypto::token::split_presentation(token);
                let decoded = akson_crypto::token::decode_token(tok)
                    .map_err(|e| Problem::new(400, "bad-token", &e.to_string()))?;
                let thumb = root_thumbprint(&decoded.root_key)?;
                let own = self
                    .identity
                    .purpose_key(akson_crypto::purpose::KeyPurpose::AgentCard)
                    .verifying()
                    .to_jwk()
                    .thumbprint();
                if thumb == own {
                    return Err(Problem::new(
                        400,
                        "own-token",
                        "this is your own identity token — hand it to a peer instead",
                    ));
                }
                if !valid_label(label) {
                    return Err(Problem::new(
                        400,
                        "bad-label",
                        "labels are 1-64 chars of [a-z0-9-], no edge or doubled hyphen",
                    ));
                }
                // An explicit --endpoint wins over the @suffix (both unauthenticated).
                let hint = endpoint.clone().or_else(|| suffix.map(str::to_owned));
                if let Some(h) = &hint {
                    if !valid_hint(h) {
                        return Err(Problem::new(
                            400,
                            "bad-endpoint",
                            "the endpoint hint must be host:port, dialable as written",
                        ));
                    }
                }
                let store = self.store.lock().map_err(|_| internal())?;
                let outcome = if *update {
                    store
                        .update_peer_import(&thumb, Some(label), hint.as_deref())
                        .map_err(|_| internal())?
                } else {
                    store
                        .add_peer_import(&thumb, label, hint.as_deref().unwrap_or(""), now_unix())
                        .map_err(|_| internal())?
                };
                use akson_store::ImportOutcome as IO;
                match outcome {
                    IO::Added | IO::Updated => Ok(serde_json::json!({
                        "imported": true, "label": label, "root_thumbprint": thumb,
                        "endpoint_hint": hint,
                    })),
                    IO::DuplicateRoot => Err(Problem::new(
                        409,
                        "already-imported",
                        "this identity is already imported — `peer add --update` refreshes its label or endpoint",
                    )),
                    IO::LabelTaken => Err(Problem::new(
                        409,
                        "label-taken",
                        "another peer already holds this label — pick a different one",
                    )),
                    IO::UnknownRoot => Err(Problem::new(
                        404,
                        "unknown-peer",
                        "no live import holds this identity — add it without --update first",
                    )),
                }
            }
            ControlRequest::PeerLabel { label, new_label } => {
                if !valid_label(new_label) {
                    return Err(Problem::new(
                        400,
                        "bad-label",
                        "labels are 1-64 chars of [a-z0-9-], no edge or doubled hyphen",
                    ));
                }
                let store = self.store.lock().map_err(|_| internal())?;
                let import = store
                    .peer_import_by_label(label)
                    .map_err(|_| internal())?
                    .ok_or_else(|| unknown_label(label))?;
                use akson_store::ImportOutcome as IO;
                match store
                    .update_peer_import(&import.root_thumbprint, Some(new_label), None)
                    .map_err(|_| internal())?
                {
                    IO::Updated => Ok(serde_json::json!({ "label": new_label })),
                    IO::LabelTaken => Err(Problem::new(
                        409,
                        "label-taken",
                        "another peer already holds this label",
                    )),
                    _ => Err(internal()),
                }
            }
            ControlRequest::PeerImportRemove { label } => {
                let store = self.store.lock().map_err(|_| internal())?;
                let import = store
                    .peer_import_by_label(label)
                    .map_err(|_| internal())?
                    .ok_or_else(|| unknown_label(label))?;
                // One transaction (slice-3 review): the import tombstone and
                // every piece of pinned state behind the root drop together —
                // a crash cannot leave a half-revoked relationship, and the
                // response reports only what actually committed.
                let removed = store
                    .remove_relationship(&import.root_thumbprint, now_unix())
                    .map_err(|_| internal())?;
                Ok(serde_json::json!({ "removed": removed, "label": label }))
            }
            ControlRequest::PeerKnocks => {
                let store = self.store.lock().map_err(|_| internal())?;
                let items: Vec<_> = store
                    .knocks()
                    .map_err(|_| internal())?
                    .iter()
                    .map(|k| {
                        serde_json::json!({
                            "claimed_root": k.claimed_root, "source": k.source,
                            "refusal": k.refusal_class, "count": k.count,
                            "first_at": k.first_at, "last_at": k.last_at,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "knocks": items }))
            }
            ControlRequest::PeerPing { label } => {
                let import = {
                    let store = self.store.lock().map_err(|_| internal())?;
                    store
                        .peer_import_by_label(label)
                        .map_err(|_| internal())?
                        .ok_or_else(|| unknown_label(label))?
                };
                let me = crate::introduce::IntroIdentity::from_state(self)?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| internal())?;
                let (peer, outcome) = runtime
                    .block_on(async {
                        tokio::time::timeout(
                            Duration::from_secs(20),
                            crate::introduce::dial_introduction(
                                &me,
                                self.store.clone(),
                                &import,
                                time::OffsetDateTime::now_utc(),
                            ),
                        )
                        .await
                        .map_err(|_| {
                            crate::introduce::IntroduceError::Http(
                                "introduction timed out".into(),
                            )
                        })?
                    })
                    .map_err(|e| match e {
                        crate::introduce::IntroduceError::Refused => {
                            Problem::new(403, "introduction-refused", &e.to_string())
                        }
                        crate::introduce::IntroduceError::NoEndpoint => {
                            Problem::new(400, "no-endpoint", &e.to_string())
                        }
                        other => Problem::new(502, "introduction-failed", &other.to_string()),
                    })?;
                Ok(serde_json::json!({
                    "introduced": format!("{outcome:?}"),
                    "peer": {
                        "issuer": peer.issuer, "agent": peer.agent_id,
                        "root_thumbprint": peer.agent_card_key.value,
                        "label": label,
                    }
                }))
            }
            ControlRequest::PeerAutoApprove {
                agent_id: identifier,
                task_types,
                max_response_bytes,
            } => {
                let store = self.store.lock().map_err(|_| internal())?;
                // The identifier is the operator's LABEL; standing authority
                // binds to the introduced root, never to a self-declared name
                // (slice-3 review). The peer must be introduced first.
                let import = store
                    .peer_import_by_label(identifier)
                    .map_err(|_| internal())?
                    .ok_or_else(|| unknown_label(identifier))?;
                let Some((agent_id, _status)) = store
                    .peer_by_root(&import.root_thumbprint)
                    .map_err(|_| internal())?
                else {
                    return Err(Problem::new(
                        409,
                        "not-introduced",
                        "no introduced peer behind this label yet — `peer ping` it first",
                    ));
                };
                // Empty task types clears the policy — reverts to always-ask.
                if task_types.is_empty() {
                    let _ = &agent_id;
                    let cleared = store
                        .delete_auto_approve(&import.root_thumbprint)
                        .map_err(|_| internal())?;
                    Ok(
                        serde_json::json!({ "auto_approve": "off", "cleared": cleared, "label": identifier }),
                    )
                } else {
                    store
                        .put_auto_approve(
                            &agent_id,
                            &import.root_thumbprint,
                            &akson_store::AutoApprovePolicy {
                                task_types: task_types.clone(),
                                max_response_bytes: *max_response_bytes,
                            },
                            now_unix(),
                        )
                        .map_err(|_| internal())?;
                    Ok(serde_json::json!({
                        "auto_approve": "on",
                        "label": identifier,
                        "root_thumbprint": import.root_thumbprint,
                        "task_types": task_types,
                        "max_response_bytes": max_response_bytes,
                    }))
                }
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
            ControlRequest::TaskOutput { task_id, role } => {
                let store = self.store.lock().map_err(|_| internal())?;
                let outputs = store.list_task_outputs(task_id).map_err(|_| internal())?;
                let items: Vec<_> = outputs
                    .iter()
                    .filter(|o| role.as_ref().is_none_or(|r| &o.role == r))
                    .map(|o| {
                        use base64::engine::general_purpose::STANDARD;
                        use base64::Engine as _;
                        serde_json::json!({
                            "artifact_id": o.artifact_id, "role": o.role,
                            "media_type": o.media_type, "byte_length": o.byte_length,
                            "sha256": o.sha256,
                            // Base64, so what comes back out is byte-for-byte what
                            // the digest above covers. A lossy UTF-8 view here would
                            // silently corrupt any non-text artifact, and the whole
                            // point of the digest check is that these bytes are
                            // exactly what the performer signed for.
                            "content": STANDARD.encode(&o.payload),
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "task_id": task_id, "outputs": items }))
            }
            ControlRequest::TaskApprove {
                task_id,
                processor,
                artifacts,
            } => {
                let store = self.store.lock().map_err(|_| internal())?;
                let now = trusted_now(&store)?;
                approve_and_issue(
                    &store,
                    &self.config.local_performer,
                    &self.identity.purpose_key(KeyPurpose::ContractDecision),
                    &self.identity.work_order_key(),
                    task_id,
                    processor.as_deref(),
                    *artifacts,
                    now,
                )
            }
            ControlRequest::TaskDeny { task_id, reason } => {
                let store = self.store.lock().map_err(|_| internal())?;
                let now = trusted_now(&store)?;
                deny(
                    &store,
                    &self.config.local_performer,
                    &self.identity.purpose_key(KeyPurpose::ContractDecision),
                    task_id,
                    reason,
                    now,
                )
            }
            ControlRequest::SubmitResult(submission) => {
                let store = self.store.lock().map_err(|_| internal())?;
                let now = trusted_now(&store)?;
                submit_result(
                    &store,
                    &self.identity.purpose_key(KeyPurpose::TaskResult),
                    submission,
                    now,
                )
            }
            // Delivery, send, and processor calls manage their own store locking
            // (they must not hold the lock across the network I/O), so they take the
            // daemon state.
            ControlRequest::TaskRun { task_id } => crate::run_worker(self, task_id),
            ControlRequest::TaskFulfill { task_id, outputs } => {
                crate::run_fulfill(self, task_id, outputs)
            }
            ControlRequest::TaskDeliver { task_id } => run_delivery(self, task_id),
            ControlRequest::TaskSend(spec) => {
                // The spec's performer is the operator's LABEL (design §8.2),
                // resolved to the pinned peer's ROOT — the relationship key —
                // introducing first on first contact, exactly like `peer ping`.
                // Bare agent names refuse (sec5 review).
                match self.resolve_performer(&spec.performer)? {
                    Some((root, agent)) => {
                        let mut spec = spec.clone();
                        spec.performer = agent;
                        run_send(self, &spec, Some(&root))
                    }
                    None => unreachable!("resolve_performer refuses non-labels"),
                }
            }
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
                store
                    .put_processor(&config, now_unix())
                    .map_err(|_| internal())?;
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

/// The daemon + sandbox health report (`akson doctor` / `akson status`).
fn diagnose_report() -> serde_json::Value {
    let report = akson_sandbox::diagnose();
    let ready = akson_sandbox::all_required_available(&report);
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
        "daemon": "aksond",
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
            "akson-endpoint",
            ENDPOINT_CERT_VALIDITY,
        )
        .map_err(|e| BootstrapError::Config(format!("endpoint certificate: {e}")))?;
        std::fs::write(&path, &cert.der)?;
        Ok(cert)
    }
}

fn default_data_dir() -> PathBuf {
    if let Some(xdg) = env_nonempty("XDG_DATA_HOME") {
        PathBuf::from(xdg).join("akson")
    } else if let Some(home) = env_nonempty("HOME") {
        PathBuf::from(home).join(".local/share/akson")
    } else {
        std::env::temp_dir().join("akson-data")
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

/// The §8.5 trusted `now` for an authority decision: the wall clock observed against
/// the store's monotonic floor. A large backward step is refused (503) so a
/// rolled-back clock cannot revive expired authority (an expired contract, a lapsed
/// nonce window). The caller must already hold the store lock.
fn trusted_now(store: &Store) -> Result<i64, Problem> {
    store.trusted_now(now_unix()).map_err(|_| Problem {
        type_: "urn:akson:error:time-uncertain".to_owned(),
        title: "the trusted clock moved backward; refusing until time is re-established".to_owned(),
        status: 503,
        detail: None,
    })
}

fn internal() -> Problem {
    Problem {
        type_: "urn:akson:error:internal".to_owned(),
        title: "the request could not be processed".to_owned(),
        status: 500,
        detail: None,
    }
}

/// The ADR-0013 label grammar: 1–64 chars of `[a-z0-9-]`, no leading,
/// trailing, or doubled hyphen. Labels are routing keys and terminal output;
/// anything else is refused at entry.
fn valid_label(label: &str) -> bool {
    let ok_chars = !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    ok_chars && !label.starts_with('-') && !label.ends_with('-') && !label.contains("--")
}

/// An endpoint hint must be dialable as written: `host:port` with a clean
/// hostname/address and a real port — no paths, whitespace, or controls
/// (slice-3 review: a bad hint must fail at `peer add`, not at first contact,
/// and must not carry terminal-escape bytes into `peer list`).
fn valid_hint(hint: &str) -> bool {
    let Some((host, port)) = hint.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
        && port.parse::<u16>().map(|p| p > 0).unwrap_or(false)
}

/// This endpoint's own identity root thumbprint (ADR-0014): what the
/// performer field of every inbound contract must carry.
fn own_root(identity: &IdentityKeys) -> String {
    identity
        .purpose_key(KeyPurpose::AgentCard)
        .verifying()
        .to_jwk()
        .thumbprint()
}

fn unknown_label(label: &str) -> Problem {
    Problem::new(
        404,
        "unknown-peer",
        &format!("no imported peer is labeled {label:?}"),
    )
}

/// `https://host:port/…` → `host:port` — the token's presentation hint
/// (scheme and path are implied by the token format, ADR-0013). A URL without
/// an explicit port yields no hint: the hint must be dialable as written.
fn host_port_of(interface_url: &str) -> Option<String> {
    let rest = interface_url.strip_prefix("https://")?;
    let end = rest.find('/').unwrap_or(rest.len());
    let hp = &rest[..end];
    (!hp.is_empty() && hp.contains(':')).then(|| hp.to_owned())
}

/// The RFC 7638 thumbprint of a token's root key — the store's peer handle.
fn root_thumbprint(root_key: &[u8; 32]) -> Result<String, Problem> {
    akson_crypto::keypair::PurposeVerifyingKey::from_public_bytes(
        akson_crypto::purpose::KeyPurpose::AgentCard,
        root_key,
    )
    .map(|vk| vk.to_jwk().thumbprint())
    .map_err(|_| {
        Problem::new(
            400,
            "bad-token",
            "the token does not carry a valid Ed25519 key",
        )
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::receive::{dispatch_proposal, DispatchOutcome};
    use akson_crypto::keypair::PurposeKey;
    use akson_crypto::purpose::KeyPurpose;
    use akson_ext::dsse::Envelope;
    use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use akson_proto::v1::{part::Content, Part};
    use akson_store::delivery::CoveredValues;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;

    fn temp_dir(label: &str) -> PathBuf {
        // Distinct per test — the tests run in parallel and must not share a dir.
        let dir =
            std::env::temp_dir().join(format!("aksond-bootstrap-{}-{label}", std::process::id()));
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
                root: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            },
            interface_url: "https://local/a2a".to_owned(),
            receive_addr: None,
            worker_command: None,
            worker_exec: None,
            on_task: None,
        }
    }

    fn proposal_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32])
    }

    /// The token verbs over dispatch (design §8.2 steps 1–3): mint, import
    /// under a label, list, relabel, remove — the whole local pairing surface
    /// short of the network introduction.
    #[test]
    fn token_import_label_remove_roundtrip() {
        let a = DaemonState::bootstrap(&config(temp_dir("tok-a"))).unwrap();
        let b = DaemonState::bootstrap(&config(temp_dir("tok-b"))).unwrap();

        let token_b = b.dispatch(&ControlRequest::Token).unwrap();
        let token_str = token_b["token"].as_str().unwrap();
        assert!(token_str.starts_with("akson1"));
        assert_eq!(token_str.len(), 65);
        assert!(
            akson_crypto::token::decode_token(token_str).is_ok(),
            "own token decodes"
        );

        // A imports B's token under a label A chose.
        let added = a
            .dispatch(&ControlRequest::PeerAdd {
                token: format!("{token_str}@127.0.0.1:18444"),
                label: "bob-codex".to_owned(),
                endpoint: None,
                update: false,
            })
            .unwrap();
        assert_eq!(added["endpoint_hint"].as_str(), Some("127.0.0.1:18444"));

        // Importing your OWN token is caught.
        let own = a.dispatch(&ControlRequest::Token).unwrap();
        let own_err = a
            .dispatch(&ControlRequest::PeerAdd {
                token: own["token"].as_str().unwrap().to_owned(),
                label: "me".to_owned(),
                endpoint: None,
                update: false,
            })
            .unwrap_err();
        assert_eq!(own_err.status, 400);

        // A duplicate import is guided to --update, not overwritten.
        let dup = a
            .dispatch(&ControlRequest::PeerAdd {
                token: token_str.to_owned(),
                label: "other".to_owned(),
                endpoint: None,
                update: false,
            })
            .unwrap_err();
        assert_eq!(dup.status, 409);

        // The list shows the import, status `imported`, no claims yet.
        let list = a.dispatch(&ControlRequest::PeerList).unwrap();
        let imports = list["imports"].as_array().unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0]["label"].as_str(), Some("bob-codex"));
        assert_eq!(imports[0]["status"].as_str(), Some("imported"));
        assert!(imports[0]["claims"].is_null());

        // Relabel is local and free; remove tombstones.
        a.dispatch(&ControlRequest::PeerLabel {
            label: "bob-codex".to_owned(),
            new_label: "dana".to_owned(),
        })
        .unwrap();
        a.dispatch(&ControlRequest::PeerImportRemove {
            label: "dana".to_owned(),
        })
        .unwrap();
        let list = a.dispatch(&ControlRequest::PeerList).unwrap();
        assert!(list["imports"].as_array().unwrap().is_empty());

        // Nothing knocked in any of this.
        let knocks = a.dispatch(&ControlRequest::PeerKnocks).unwrap();
        assert!(knocks["knocks"].as_array().unwrap().is_empty());
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
            root: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        }
    }

    fn submit_one(store: &Store) -> String {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
        let value = json!({
            "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0, "task_type": "https://akson.invalid/task/code-review/v1",
            "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester", "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "performer": {"issuer": "iss", "agent": "performer", "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "objective": "o",
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
        let payload = akson_ext::jcs::canonical_bytes(&value).unwrap();
        let env: Envelope = akson_contract::sign_proposal(&payload, &proposal_key()).unwrap();
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
            peer: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
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
        assert_eq!(report["daemon"], "aksond");
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
            // Pair the requester so the work-order origin can be bound: the
            // peers row under its root plus the proposal key.
            {
                use akson_crypto::identity::{Fingerprint, FingerprintKind, PeerIdentity};
                store
                    .put_peer(&akson_store::StoredPeer {
                        identity: PeerIdentity {
                            issuer: Some("iss".to_owned()),
                            agent_id: "requester".to_owned(),
                            workload_id: None,
                            endpoint_id: "https://requester/a2a".to_owned(),
                            tls_cert: Fingerprint {
                                kind: FingerprintKind::CertSha256,
                                value: "req-fp".to_owned(),
                            },
                            agent_card_key: Fingerprint {
                                kind: FingerprintKind::Jwk7638,
                                value: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                            },
                            key_bindings: vec![],
                            security_projection_digest: Fingerprint::json_sha256(b"{}"),
                            full_card_digest: Fingerprint::json_sha256(b"{}"),
                        },
                        local_note: String::new(),
                    })
                    .unwrap();
            }
            store
                .put_peer_key("req-fp",
                    "contract-proposal",
                    "requester",
                    "iss", &proposal_key().verifying().to_public_bytes(), "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NOW)
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
