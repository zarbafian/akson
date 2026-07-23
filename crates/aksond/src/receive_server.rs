//! The A2A receive server (design §9.1, §10.2): the async mTLS accept loop that
//! feeds [`handle_receive`](crate::handle_receive).
//!
//! Each connection completes a TLS 1.3 mutual handshake, its client leaf-cert
//! fingerprint is captured, and the [`PeerResolver`] maps that fingerprint to the
//! pinned peer's identity and contract-proposal key — an unknown fingerprint is
//! refused (403) before any body is read. Then the request headers and a
//! size-capped body are handed to the synchronous receive handler.
//!
//! The store is `!Sync` (one connection), so it lives behind a `Mutex`; the
//! handler is sync, holding the lock only across one request. The peer-key
//! persistence that backs a real resolver (retaining each peer's proposal key at
//! pairing) is the remaining piece; the resolver seam keeps this server testable
//! and correct regardless of where those keys are stored.

use std::collections::{BTreeSet, HashMap};
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use akson_contract::Identity;
use akson_crypto::identity::Fingerprint;
use akson_crypto::keypair::PurposeVerifyingKey;
use akson_crypto::purpose::KeyPurpose;
use akson_store::{PeerStatus, Store, StoreError};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::CONTENT_TYPE;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use akson_pairing::introduction::{COMPLETE_PATH, HELLO_PATH, MAX_INTRODUCTION_BODY};
use akson_transport::limits::{
    BODY_READ_TIMEOUT, HANDSHAKE_TIMEOUT, HEADER_READ_TIMEOUT, MAX_CONCURRENT_CONNECTIONS,
};

use crate::introduce::{respond_introduction, IntroIdentity, PendingIntro};
use crate::receive_http::{handle_receive, HttpRequest, ReceiveConfig};

/// The A2A request-body cap (design §9.1 — bounded before allocation).
const MAX_RECEIVE_BODY: usize = 1024 * 1024;

/// The pinned peer resolved from a TLS leaf-cert fingerprint.
pub struct PeerContext {
    /// The peer's identity — the contract's `requester` must equal it.
    pub requester_origin: Identity,
    /// The peer's contract-proposal verifying key.
    pub proposal_key: PurposeVerifyingKey,
    /// The stable peer id used as an idempotency covered value.
    pub peer_id: String,
}

/// Resolves a peer from its TLS leaf-cert fingerprint (the pinned peer record).
/// Returns `None` for an unknown fingerprint — the connection is refused. Given the
/// already-locked store so a store-backed resolver needs no second connection.
pub trait PeerResolver: Send + Sync + 'static {
    fn resolve(&self, store: &Store, tls_fingerprint: &str) -> Option<PeerContext>;
}

/// The store name for a peer's contract-proposal verification key (matches
/// `KeyPurpose::ContractProposal`'s kebab-case form).
const PROPOSAL_KEY_PURPOSE: &str = "contract-proposal";

/// The store name for a peer's task-result verification key (matches
/// `KeyPurpose::TaskResult`'s kebab-case form) — used to verify delivered results.
const TASK_RESULT_KEY_PURPOSE: &str = "task-result";

/// The production [`PeerResolver`]: looks up the connecting peer's contract-proposal
/// key from the store by the handshake's leaf-cert fingerprint (design §10.2). An
/// unknown fingerprint or a key that no longer parses resolves to `None`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StorePeerResolver;

impl PeerResolver for StorePeerResolver {
    fn resolve(&self, store: &Store, tls_fingerprint: &str) -> Option<PeerContext> {
        let pk = store
            .peer_key(tls_fingerprint, PROPOSAL_KEY_PURPOSE)
            .ok()
            .flatten()?;
        // The peer must be ACTIVE — a surviving key row for a suspended or
        // removed peer must not admit work (codex review). Status resolves by
        // the key row's ROOT (names are display since the cutover); a legacy
        // fixture row with no root falls back to the name-scoped lookup.
        let active = if pk.root_thumbprint.is_empty() {
            store.peer_status(&pk.agent_id).ok().flatten() == Some(PeerStatus::Active)
        } else {
            store.peer_status_by_root(&pk.root_thumbprint).ok().flatten()
                == Some(PeerStatus::Active)
        };
        if !active {
            return None;
        }
        let proposal_key =
            PurposeVerifyingKey::from_public_bytes(KeyPurpose::ContractProposal, &pk.public_key)
                .ok()?;
        Some(PeerContext {
            requester_origin: Identity {
                issuer: pk.issuer,
                agent: pk.agent_id.clone(),
            },
            proposal_key,
            peer_id: pk.agent_id,
        })
    }
}

/// The receive server's shared state. The store is the *same* `Arc<Mutex<Store>>`
/// the control sockets hold, so a received Task is immediately visible to the
/// operator's inbox.
pub struct ReceiveState<R: PeerResolver> {
    store: Arc<Mutex<Store>>,
    resolver: R,
    local_performer: Identity,
    required_extensions: BTreeSet<String>,
    interface_url: String,
    /// This endpoint's requester-outcome key. `Some` iff the endpoint accepts
    /// delivered results (acts as a requester); `None` accepts only proposals.
    outcome_key: Option<akson_crypto::keypair::PurposeKey>,
    /// Introduction service (design §8.2 step 4, ADR-0015), when this endpoint
    /// accepts first contact over identity tokens.
    intro: Option<Arc<IntroIdentity>>,
    /// Fixed-window per-source limiter for the introduction route — the
    /// listener-level ceiling in front of the store-level admission gate.
    intro_rate: Mutex<HashMap<IpAddr, (u32, i64)>>,
}

impl<R: PeerResolver> ReceiveState<R> {
    pub fn new(
        store: Arc<Mutex<Store>>,
        resolver: R,
        local_performer: Identity,
        required_extensions: BTreeSet<String>,
        interface_url: String,
    ) -> Self {
        Self {
            store,
            resolver,
            local_performer,
            required_extensions,
            interface_url,
            outcome_key: None,
            intro: None,
            intro_rate: Mutex::new(HashMap::new()),
        }
    }

    /// Also accept delivered results, signing this endpoint's requester outcome
    /// with `outcome_key` (design §14.5).
    pub fn accepting_results(mut self, outcome_key: akson_crypto::keypair::PurposeKey) -> Self {
        self.outcome_key = Some(outcome_key);
        self
    }

    /// Also serve first-contact introductions (design §8.2 step 4) as this
    /// identity.
    pub fn with_introduction(mut self, identity: Arc<IntroIdentity>) -> Self {
        self.intro = Some(identity);
        self
    }

    /// Introduction requests: hand to the responder, which scopes the store
    /// lock itself (never across signature work). The rate gate ran pre-body
    /// in [`handle`]. The bool says the connection must close.
    #[allow(clippy::too_many_arguments)]
    fn respond_intro(
        &self,
        source: IpAddr,
        peer_fp: Option<&str>,
        exporter: Option<&[u8; 32]>,
        pending: &PendingIntro,
        path: &str,
        method: &str,
        content_type: &str,
        body: &[u8],
        wall_now_unix: i64,
    ) -> (u16, String, Vec<u8>, bool) {
        let Some(intro) = &self.intro else {
            let (code, ct, body) = intro_refused();
            return (code, ct, body, true);
        };
        respond_introduction(
            intro,
            &self.store,
            pending,
            path,
            method,
            content_type,
            &source.to_string(),
            peer_fp,
            exporter,
            body,
            wall_now_unix,
        )
    }

    /// Whether a client certificate resolves to an admitted peer — the cheap
    /// pre-body gate: an unknown certificate cannot force the 1 MiB read
    /// (slice-2 security review).
    fn peer_known(&self, fp: &str) -> bool {
        self.store
            .lock()
            .map(|store| self.resolver.resolve(&store, fp).is_some())
            .unwrap_or(false)
    }

    /// Fixed-window limiter over source *buckets* (a v4 address, a v6 /64 —
    /// rotating inside a delegated v6 prefix must not mint fresh budgets).
    /// The map is pruned at the cap and fails closed for NEW buckets while
    /// full, so a source-rotating scanner can neither grow it nor starve
    /// established sources (slice-2 security review).
    fn intro_rate_admit(&self, source: IpAddr, now: i64) -> bool {
        const WINDOW_SECS: i64 = 60;
        const MAX_PER_WINDOW: u32 = 10;
        const MAX_TRACKED: usize = 1024;
        let bucket = rate_bucket(source);
        let Ok(mut map) = self.intro_rate.lock() else {
            return false;
        };
        if map.len() >= MAX_TRACKED {
            map.retain(|_, (_, start)| now - *start < WINDOW_SECS);
            if map.len() >= MAX_TRACKED && !map.contains_key(&bucket) {
                return false;
            }
        }
        let entry = map.entry(bucket).or_insert((0, now));
        if now - entry.1 >= WINDOW_SECS {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 <= MAX_PER_WINDOW
    }

    /// Resolves the peer, then runs the receive handler — the synchronous core the
    /// async connection handler calls. An unresolvable peer is `403`; a poisoned
    /// store lock or store error is `500`; a backward clock is `503`. `wall_now_unix`
    /// is the raw wall clock; the §8.5 trusted time is derived from it here against
    /// the store's monotonic floor, so authority decisions never run on a rolled-back
    /// clock.
    #[allow(clippy::too_many_arguments)]
    fn respond(
        &self,
        peer_fp: Option<&str>,
        method: &str,
        content_type: &str,
        a2a_version: Option<&str>,
        content_digest: Option<&str>,
        activated_extensions: &[String],
        body: &[u8],
        wall_now_unix: i64,
    ) -> (u16, String, Vec<u8>) {
        let store = match self.store.lock() {
            Ok(s) => s,
            Err(_) => return problem_500(),
        };
        let Some(fp) = peer_fp else {
            return problem_403();
        };
        let Some(peer) = self.resolver.resolve(&store, fp) else {
            // Unknown or absent client certificate — refuse, revealing nothing.
            return problem_403();
        };
        // Derive the trusted time from the wall clock against the monotonic floor. A
        // large backward step is refused (503) rather than allowed to revive expired
        // authority downstream (§8.5).
        let trusted_now_unix = match store.trusted_now(wall_now_unix) {
            Ok(t) => t,
            Err(_) => return problem_503_time(),
        };
        // If this endpoint accepts results, resolve the sending peer's task-result
        // key so a delivered result manifest can be verified.
        let task_result_key = self.outcome_key.as_ref().and_then(|_| {
            store
                .peer_key(fp, TASK_RESULT_KEY_PURPOSE)
                .ok()
                .flatten()
                .and_then(|pk| {
                    PurposeVerifyingKey::from_public_bytes(KeyPurpose::TaskResult, &pk.public_key)
                        .ok()
                })
        });
        let config = ReceiveConfig {
            local_performer: &self.local_performer,
            requester_origin: &peer.requester_origin,
            proposal_key: &peer.proposal_key,
            required_extensions: &self.required_extensions,
            interface_url: &self.interface_url,
            outcome_key: self.outcome_key.as_ref(),
            performer_task_result_key: task_result_key.as_ref(),
        };
        let req = HttpRequest {
            method,
            content_type,
            a2a_version,
            content_digest,
            activated_extensions,
            tenant: None,
            peer: &peer.peer_id,
            body,
        };
        match handle_receive(&store, &config, &req, trusted_now_unix) {
            Ok(r) => (r.status, r.content_type, r.body),
            Err(StoreError::Db(_)) | Err(_) => problem_500(),
        }
    }
}

/// Serves receive connections until `listener` errors (design §9.1). Each runs on
/// its own task; a per-connection handshake or protocol failure is dropped, never
/// fatal to the accept loop.
pub async fn serve<R: PeerResolver>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<ReceiveState<R>>,
) -> std::io::Result<()> {
    serve_with_limits(
        listener,
        acceptor,
        state,
        MAX_CONCURRENT_CONNECTIONS,
        HANDSHAKE_TIMEOUT,
        HEADER_READ_TIMEOUT,
        BODY_READ_TIMEOUT,
    )
    .await
}

/// The accept loop with explicit pre-auth ceilings (design §9.1) — [`serve`] calls
/// this with the shared [`akson_transport::limits`] constants; tests pass small
/// values to exercise the timeout/cap behaviour quickly. The deadlines are
/// per-request, so multiple exchanges over one keep-alive connection are unbounded
/// in count and total duration as long as each exchange is prompt.
#[allow(clippy::too_many_arguments)]
async fn serve_with_limits<R: PeerResolver>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<ReceiveState<R>>,
    max_concurrent: usize,
    handshake_timeout: Duration,
    header_read_timeout: Duration,
    body_read_timeout: Duration,
) -> std::io::Result<()> {
    // Bound concurrent pre-auth connections; a permit is held for the whole
    // connection so a flood cannot spawn unbounded tasks (§9.1).
    let limiter = Arc::new(Semaphore::new(max_concurrent));
    loop {
        let (tcp, peer_addr) = listener.accept().await?;
        // Wait for a concurrency slot; the semaphore is never closed, so this only
        // errors on a bug — drop the connection if so.
        let Ok(permit) = limiter.clone().acquire_owned().await else {
            drop(tcp);
            continue;
        };
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Time-bound the handshake so a stalled peer cannot hold the slot.
            let Ok(Ok(tls)) = timeout(handshake_timeout, acceptor.accept(tcp)).await else {
                return;
            };
            let peer_fp = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| Fingerprint::cert_sha256(cert.as_ref()).value);
            // The introduction's session facts (ADR-0015): this connection's
            // RFC 9266 exporter, and one pending-hello slot per connection —
            // one authentication instance, per RFC 9266 §4.1.
            let exporter = akson_transport::tls::channel_binding(tls.get_ref().1);
            let pending: Arc<PendingIntro> = Arc::new(Mutex::new(Default::default()));
            let svc = service_fn(move |req| {
                handle(
                    state.clone(),
                    peer_fp.clone(),
                    peer_addr.ip(),
                    exporter,
                    pending.clone(),
                    req,
                    body_read_timeout,
                )
            });
            // header_read_timeout bounds each request's head and re-arms while a
            // keep-alive connection waits for the next request, so a slow-header
            // sender or idle squatter is cut off without capping an active session.
            // It needs a timer set explicitly.
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout)
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

async fn handle<R: PeerResolver>(
    state: Arc<ReceiveState<R>>,
    peer_fp: Option<String>,
    source: IpAddr,
    exporter: Option<[u8; 32]>,
    pending: Arc<PendingIntro>,
    req: Request<Incoming>,
    body_read_timeout: Duration,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().as_str().to_owned();
    // The introduction routes are matched by path BEFORE the A2A peer
    // resolver, with their own (much smaller) body cap (ADR-0015).
    let path = req.uri().path().to_owned();
    let is_intro = path == HELLO_PATH || path == COMPLETE_PATH;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Pre-body gates (slice-2 security review): a refused caller must not be
    // able to force the body read/allocation first.
    if is_intro {
        if !state.intro_rate_admit(source, now) {
            let (code, ct, body) = intro_refused();
            return Ok(close_response(code, &ct, body));
        }
    } else {
        // The A2A path admits only resolvable peers; an unknown certificate
        // is refused before the 1 MiB budget, and its connection closes so it
        // cannot squat a receive slot with keep-alive.
        let known = peer_fp.as_deref().is_some_and(|fp| state.peer_known(fp));
        if !known {
            let (code, ct, body) = problem_403();
            return Ok(close_response(code, &ct, body));
        }
    }

    let body_cap = if is_intro {
        MAX_INTRODUCTION_BODY
    } else {
        MAX_RECEIVE_BODY
    };
    let content_type = header(req.headers(), CONTENT_TYPE).unwrap_or_default();
    let a2a_version = header_named(req.headers(), "a2a-version");
    let content_digest = header_named(req.headers(), "content-digest");
    // Bounded (and skipped entirely on the introduction routes): a header must
    // not expand into an unbounded Vec of owned strings pre-admission.
    const MAX_ACTIVATED_EXTENSIONS: usize = 32;
    let activated: Vec<String> = if is_intro {
        Vec::new()
    } else {
        header_named(req.headers(), "a2a-extensions")
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_owned())
                    .filter(|x| !x.is_empty())
                    .take(MAX_ACTIVATED_EXTENSIONS)
                    .collect()
            })
            .unwrap_or_default()
    };

    // Cap the body before reading it into memory (§9.1), and bound the time to read
    // it so a slow-body sender is cut off (408) rather than holding the connection.
    let body = match timeout(
        body_read_timeout,
        Limited::new(req.into_body(), body_cap).collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(_)) => return Ok(status(413)),
        Err(_) => return Ok(status(408)),
    };

    let (code, content_type_out, out_body, close) = if is_intro {
        state.respond_intro(
            source,
            peer_fp.as_deref(),
            exporter.as_ref(),
            &pending,
            &path,
            &method,
            &content_type,
            &body,
            now,
        )
    } else {
        let (code, ct, body) = state.respond(
            peer_fp.as_deref(),
            &method,
            &content_type,
            a2a_version.as_deref(),
            content_digest.as_deref(),
            &activated,
            &body,
            now,
        );
        // A refusal on the work path also closes: no keep-alive squatting.
        let close = code == 403;
        (code, ct, body, close)
    };

    let mut out = Response::new(Full::new(Bytes::from(out_body)));
    *out.status_mut() = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Ok(value) = content_type_out.parse() {
        out.headers_mut().insert(CONTENT_TYPE, value);
    }
    if close {
        out.headers_mut()
            .insert(hyper::header::CONNECTION, "close".parse().unwrap_or_else(|_| unreachable!()));
    }
    Ok(out)
}

/// The introduction's uniform generic refusal, shaped exactly like the
/// responder's (ADR-0015: rate-limit and service-off refusals must be
/// indistinguishable from every other pre-verification refusal).
fn intro_refused() -> (u16, String, Vec<u8>) {
    problem(
        403,
        "introduction-refused",
        "the introduction was refused",
    )
}

/// A response that also closes the connection.
fn close_response(code: u16, content_type: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut out = Response::new(Full::new(Bytes::from(body)));
    *out.status_mut() = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Ok(value) = content_type.parse() {
        out.headers_mut().insert(CONTENT_TYPE, value);
    }
    out.headers_mut()
        .insert(hyper::header::CONNECTION, "close".parse().unwrap_or_else(|_| unreachable!()));
    out
}

/// The limiter's bucket: a v4 address as-is, a v6 address truncated to its
/// /64 — one delegated prefix, one budget.
fn rate_bucket(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V4(_) => source,
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(
                seg[0], seg[1], seg[2], seg[3], 0, 0, 0, 0,
            ))
        }
    }
}

fn header(headers: &HeaderMap, name: hyper::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn header_named(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn status(code: u16) -> Response<Full<Bytes>> {
    let mut out = Response::new(Full::new(Bytes::new()));
    *out.status_mut() = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    out
}

fn problem_403() -> (u16, String, Vec<u8>) {
    problem(
        403,
        "unauthorized-peer",
        "the client certificate is not a paired peer",
    )
}

fn problem_500() -> (u16, String, Vec<u8>) {
    problem(500, "internal", "the request could not be processed")
}

fn problem_503_time() -> (u16, String, Vec<u8>) {
    problem(
        503,
        "time-uncertain",
        "the trusted clock moved backward; refusing until time is re-established",
    )
}

fn problem(status: u16, kind: &str, title: &str) -> (u16, String, Vec<u8>) {
    let problem = crate::control::Problem {
        type_: format!("urn:akson:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    };
    (
        status,
        "application/problem+json".to_owned(),
        serde_json::to_vec(&problem).unwrap_or_default(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use akson_crypto::keypair::PurposeKey;
    use akson_crypto::purpose::KeyPurpose;
    use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use akson_proto::v1::{part::Content, Message, Part, SendMessageRequest};
    use akson_store::delivery::content_digest;
    use akson_store::{ExternalCheckpoint, Store};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;

    fn proposal_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    /// Pins an ACTIVE peer (a peer row + its contract-proposal key) — what a
    /// confirmed peer looks like in the store, so the resolver admits it.
    fn pin_active_peer(store: &Store, fp: &str, agent: &str, key: &PurposeVerifyingKey) {
        use akson_crypto::identity::{Fingerprint, FingerprintKind, PeerIdentity};
        use akson_store::StoredPeer;
        let cert = Fingerprint {
            kind: FingerprintKind::CertSha256,
            value: fp.to_owned(),
        };
        store
            .put_peer(&StoredPeer {
                identity: PeerIdentity {
                    issuer: Some("iss".to_owned()),
                    agent_id: agent.to_owned(),
                    workload_id: None,
                    endpoint_id: "https://peer/a2a".to_owned(),
                    tls_cert: cert.clone(),
                    agent_card_key: cert.clone(),
                    key_bindings: vec![],
                    security_projection_digest: cert.clone(),
                    full_card_digest: cert.clone(),
                },
                local_note: String::new(),
            })
            .unwrap();
        store
            .put_peer_key(
                fp,
                "contract-proposal",
                agent,
                "iss",
                &key.to_public_bytes(),
                NOW,
            )
            .unwrap();
    }

    /// A resolver that maps exactly one fingerprint to the test peer.
    struct OnevPeer;
    impl PeerResolver for OnevPeer {
        fn resolve(&self, _store: &Store, fp: &str) -> Option<PeerContext> {
            (fp == "known-fp").then(|| PeerContext {
                requester_origin: ident("requester"),
                proposal_key: proposal_key().verifying(),
                peer_id: "requester".to_owned(),
            })
        }
    }

    fn state() -> ReceiveState<OnevPeer> {
        let kek = akson_store::envelope::Kek::from_bytes([7u8; 32]);
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        let store = Store::open_in_memory(&kek, cp).unwrap();
        ReceiveState::new(
            Arc::new(Mutex::new(store)),
            OnevPeer,
            ident("performer"),
            BTreeSet::new(),
            "https://local/a2a".to_owned(),
        )
    }

    fn send_message_body() -> Vec<u8> {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
        let value = json!({
            "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0, "task_type": "https://akson.invalid/t", "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"}, "objective": "o",
            "inputs": [{
                "id": "src", "message_id": "msg-1", "part_index": 1, "kind": "text",
                "media_type": "text/plain", "charset": "utf-8", "canonical_rule": "utf8-exact",
                "byte_length": TEXT.len(), "sha256": sha,
                "worker_visible": true, "processor_visible": false
            }],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [], "requested_capabilities": [],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"
        });
        let payload = akson_ext::jcs::canonical_bytes(&value).unwrap();
        let env = akson_contract::sign_proposal(&payload, &proposal_key()).unwrap();
        let envelope_part = Part {
            metadata: None,
            filename: String::new(),
            media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
            content: Some(Content::Data(
                serde_json::from_value(serde_json::to_value(&env).unwrap()).unwrap(),
            )),
        };
        let text_part = Part {
            metadata: None,
            filename: String::new(),
            media_type: "text/plain".to_owned(),
            content: Some(Content::Text(TEXT.to_owned())),
        };
        let message = Message {
            message_id: "msg-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            parts: vec![envelope_part, text_part],
            ..Default::default()
        };
        serde_json::to_vec(&SendMessageRequest {
            message: Some(message),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn a_known_peer_posting_a_valid_message_gets_a_submitted_task() {
        let state = state();
        let body = send_message_body();
        let digest = content_digest(&body);
        let (code, ct, out) = state.respond(
            Some("known-fp"),
            "POST",
            "application/a2a+json",
            Some("1.0"),
            Some(&digest),
            &[],
            &body,
            NOW,
        );
        assert_eq!(code, 200);
        assert_eq!(ct, "application/a2a+json");
        let task: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(task["status"]["state"], "TASK_STATE_SUBMITTED");
    }

    #[test]
    fn a_large_backward_wall_clock_is_refused_503() {
        let state = state();
        let body = send_message_body();
        let digest = content_digest(&body);
        let post = |wall: i64| {
            state.respond(
                Some("known-fp"),
                "POST",
                "application/a2a+json",
                Some("1.0"),
                Some(&digest),
                &[],
                &body,
                wall,
            )
        };
        // The first request advances the trusted-time floor to NOW.
        assert_eq!(post(NOW).0, 200);
        // A wall clock far below the floor is refused (503), not allowed through to
        // decide authority on a rolled-back clock.
        assert_eq!(post(NOW - 10_000).0, 503);
    }

    #[test]
    fn an_unknown_fingerprint_is_refused_403() {
        let state = state();
        let (code, _, _) = state.respond(
            Some("stranger-fp"),
            "POST",
            "application/a2a+json",
            Some("1.0"),
            Some("sha-256=:x:"),
            &[],
            b"{}",
            NOW,
        );
        assert_eq!(code, 403);
    }

    #[test]
    fn an_absent_client_certificate_is_refused_403() {
        let state = state();
        let (code, _, _) = state.respond(
            None,
            "POST",
            "application/a2a+json",
            None,
            None,
            &[],
            b"",
            NOW,
        );
        assert_eq!(code, 403);
    }

    #[test]
    fn store_resolver_finds_a_persisted_peer_key() {
        let kek = akson_store::envelope::Kek::from_bytes([8u8; 32]);
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        let store = Store::open_in_memory(&kek, cp).unwrap();
        let vk = proposal_key().verifying();
        pin_active_peer(&store, "fp-1", "requester", &vk);

        let resolver = StorePeerResolver;
        let ctx = resolver
            .resolve(&store, "fp-1")
            .expect("known fingerprint resolves");
        assert_eq!(ctx.peer_id, "requester");
        assert_eq!(ctx.requester_origin.agent, "requester");
        assert_eq!(ctx.requester_origin.issuer, "iss");
        // The rehydrated key equals the peer's original proposal key.
        assert_eq!(ctx.proposal_key.to_public_bytes(), vk.to_public_bytes());
        // An unknown fingerprint resolves to nothing.
        assert!(resolver.resolve(&store, "stranger").is_none());
    }

    #[test]
    fn a_persisted_key_without_an_active_peer_is_refused() {
        // A surviving proposal-key row is not enough: without an ACTIVE peer row
        // (pending, removed, or superseded), the resolver must refuse admission.
        let kek = akson_store::envelope::Kek::from_bytes([9u8; 32]);
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        let store = Store::open_in_memory(&kek, cp).unwrap();
        let vk = proposal_key().verifying();
        // Pin the key ONLY — no peer row, so peer_status is absent.
        store
            .put_peer_key(
                "fp-1",
                "contract-proposal",
                "requester",
                "iss",
                &vk.to_public_bytes(),
                100,
            )
            .unwrap();

        assert!(
            StorePeerResolver.resolve(&store, "fp-1").is_none(),
            "a key without an active peer must not admit work"
        );
    }

    #[tokio::test]
    async fn a_stalled_pre_auth_handshake_is_dropped_within_the_timeout() {
        use akson_crypto::cert::self_signed_endpoint;
        use akson_crypto::keypair::PurposeKey;
        use akson_transport::tls::bootstrap_server_config;
        use tokio::io::AsyncReadExt;

        // A real TLS server config, but the client below never speaks TLS.
        let tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[5u8; 32]);
        let cert = self_signed_endpoint(&tls_key, "akson-endpoint", Duration::from_secs(3600))
            .expect("cert");
        let acceptor = TlsAcceptor::from(Arc::new(
            bootstrap_server_config(&tls_key, &cert).expect("config"),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Serve with a short handshake timeout so the test is fast.
        tokio::spawn(serve_with_limits(
            listener,
            acceptor,
            Arc::new(state()),
            8,
            Duration::from_millis(200),
            Duration::from_secs(5),
            Duration::from_secs(5),
        ));

        // Open a raw TCP connection and send NOTHING — never start the handshake.
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Without the handshake timeout the server would block reading the
        // ClientHello forever; with it, the connection is closed and the read
        // observes EOF well within the outer bound.
        let mut buf = [0u8; 1];
        let n = timeout(Duration::from_secs(3), client.read(&mut buf))
            .await
            .expect("the server must close the stalled connection, not hang")
            .unwrap();
        assert_eq!(n, 0, "a stalled pre-auth connection is dropped (EOF)");
    }
}
