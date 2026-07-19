//! The live processor-call dispatch (design §13.1, §15.2): the broker's outbound
//! HTTPS call, composed from the durable sub-attempt, the egress gates, and the
//! anti-SSRF connection-time address check.
//!
//! The security-critical steps live here; the raw HTTPS transport is a seam
//! ([`CallTransport`]) so the composition is fully testable without a live server.
//!
//! Order (§13.1): prepare the durable pre-dispatch record → record `dispatching`
//! BEFORE any byte leaves → resolve the origin and RE-CHECK the resolved address
//! at connection time (anti-rebinding) → inject the sealed credential and send →
//! record the terminal state honestly. A clean pre-send failure is `failed`; an
//! uncertain outcome (bytes may have left) is `ambiguous` and is never
//! auto-retried.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use axon_authority::{AttemptState, CapabilityComponent};
use axon_broker::{
    check_origin, check_resolved_address, AuthScheme, CallBinding, CallBudget, EgressPolicy,
    ProcessorCall, SubAttemptEvent, SubAttemptState,
};
use axon_crypto::cert::EndpointCert;
use axon_crypto::identity::{Fingerprint, FingerprintKind};
use axon_crypto::keypair::PurposeKey;
use axon_crypto::purpose::KeyPurpose;
use axon_store::{PrepareOutcome, Store};
use axon_transport::tls::{ca_client_config, client_config};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::bootstrap::DaemonState;
use crate::control::Problem;

/// A processor's HTTPS response.
pub struct CallResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why the transport failed, and whether it is *clean* (no byte left the host —
/// safe to mark `failed`) or *uncertain* (bytes may have left — must be `ambiguous`).
pub enum TransportError {
    /// No request byte left the host (connect/handshake failed before sending).
    Clean(String),
    /// The request may have been transmitted; the outcome is uncertain.
    Uncertain(String),
}

/// The raw HTTPS transport: connect to the **already-checked** `addr` (with SNI
/// `host`), trusting the processor's pinned certificate, inject the credential,
/// POST the request, and read the size-capped response. A seam so the dispatch
/// composition is testable without a live server.
pub trait CallTransport {
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn send(
        &self,
        host: &str,
        port: u16,
        addr: IpAddr,
        path: &str,
        expected_cert_sha256: Option<&str>,
        auth: &AuthScheme,
        credential: Option<&[u8]>,
        headers: &[(String, String)],
        request: &[u8],
        max_response_bytes: u64,
    ) -> impl std::future::Future<Output = Result<CallResponse, TransportError>>;
}

/// Dispatches a processor call (design §13.1). Fails closed at every gate, records
/// the sub-attempt durable-before-effect, and never re-dispatches a call that
/// already reached a terminal state.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_processor_call(
    store: &Mutex<Store>,
    processor_id: &str,
    request: &[u8],
    binding: CallBinding,
    budget: CallBudget,
    policy: &EgressPolicy,
    transport: &impl CallTransport,
    now: i64,
) -> Result<serde_json::Value, Problem> {
    // Phase 1 (locked): the config, the durable pre-dispatch record, and the move
    // to `dispatching` — all before any byte leaves.
    let (call, credential, expected_cert, path, auth, headers) = {
        let store = store.lock().map_err(|_| internal())?;
        let config = store
            .get_processor(processor_id)
            .map_err(store_problem)?
            .ok_or_else(|| problem(404, "no-such-processor", "no such processor"))?;
        // The configured origin must be https + allowlisted (a task never supplies it).
        check_origin(&config.origin, policy).map_err(|e| {
            problem_detail(
                403,
                "egress-refused",
                "the processor origin is not permitted",
                e,
            )
        })?;
        let call =
            ProcessorCall::prepare(&config, request, binding, budget).map_err(|_| internal())?;
        match store.prepare_call(&call, now).map_err(store_problem)? {
            PrepareOutcome::Prepared => {}
            // Idempotent: a call that already reached a terminal state is never re-sent.
            PrepareOutcome::AlreadyPrepared(state) if is_terminal(state) => {
                return Ok(outcome_json(&call, state, None));
            }
            PrepareOutcome::AlreadyPrepared(_) => {}
        }
        // Record `dispatching` before the first byte leaves (§13.1).
        advance(
            &store,
            &call.idempotency_key,
            SubAttemptEvent::Dispatch,
            now,
        )?;
        let credential = store.get_credential(processor_id).map_err(store_problem)?;
        (
            call,
            credential,
            config.tls_certificate_sha256.clone(),
            config.path.clone(),
            config.auth.clone(),
            config.headers.clone(),
        )
    };

    // Phase 2 (unlocked): resolve, RE-CHECK the resolved address, then send.
    let addr = match resolve(&call.origin.host, call.origin.port).await {
        Some(addr) => addr,
        None => {
            mark(store, &call.idempotency_key, SubAttemptEvent::Fail, now)?;
            return Err(problem(
                502,
                "unresolved",
                "the processor origin did not resolve",
            ));
        }
    };
    // Anti-SSRF / anti-rebinding: the address actually dialed is checked, not the name.
    if let Err(e) = check_resolved_address(addr, policy) {
        mark(store, &call.idempotency_key, SubAttemptEvent::Fail, now)?;
        return Err(problem_detail(
            403,
            "egress-refused",
            "the resolved address is not permitted",
            e,
        ));
    }
    let result = transport
        .send(
            &call.origin.host,
            call.origin.port,
            addr,
            &path,
            expected_cert.as_deref(),
            &auth,
            credential.as_deref(),
            &headers,
            request,
            call.max_response_bytes,
        )
        .await;

    // Phase 3 (locked): the terminal state, honestly.
    let event = match &result {
        Ok(_) => SubAttemptEvent::Complete,
        Err(TransportError::Clean(_)) => SubAttemptEvent::Fail,
        Err(TransportError::Uncertain(_)) => SubAttemptEvent::MarkAmbiguous,
    };
    let state = mark(store, &call.idempotency_key, event, now)?;
    match result {
        Ok(resp) => Ok(outcome_json(&call, state, Some(&resp))),
        Err(TransportError::Clean(d)) => Err(problem_detail(
            502,
            "dispatch-failed",
            "the processor call failed",
            d,
        )),
        Err(TransportError::Uncertain(d)) => Err(problem_detail(
            502,
            "dispatch-ambiguous",
            "the processor call outcome is uncertain",
            d,
        )),
    }
}

/// The production HTTPS transport (design §9.1, §13.1): mutual TLS pinned to the
/// processor's endpoint certificate, presenting this endpoint's own cert. It dials
/// the **already-checked** address (SNI `host`), so the anti-rebinding gate is not
/// bypassed by a re-resolve. The credential rides an `Authorization: Bearer`
/// header; no redirects are followed (a single POST); the response is size-capped.
pub struct HttpsTransport<'a> {
    pub endpoint_key: &'a PurposeKey,
    pub endpoint_cert: &'a EndpointCert,
}

impl CallTransport for HttpsTransport<'_> {
    #[allow(clippy::too_many_arguments)]
    async fn send(
        &self,
        host: &str,
        port: u16,
        addr: IpAddr,
        path: &str,
        expected_cert_sha256: Option<&str>,
        auth: &AuthScheme,
        credential: Option<&[u8]>,
        headers: &[(String, String)],
        request: &[u8],
        max_response_bytes: u64,
    ) -> Result<CallResponse, TransportError> {
        // Pinned processors (typically local/self-signed) get mutual TLS pinned to
        // their exact cert; public providers (no pinned cert) get server-auth TLS
        // validated against the Mozilla CA roots, presenting no client cert (they
        // authenticate the caller by the bearer credential). The choice is per
        // processor and never a silent fallback.
        let config = match expected_cert_sha256 {
            Some(fp) => {
                let pinned = Fingerprint {
                    kind: FingerprintKind::CertSha256,
                    value: fp.to_owned(),
                };
                client_config(self.endpoint_key, self.endpoint_cert, &pinned)
                    .map_err(|e| TransportError::Clean(e.to_string()))?
            }
            None => ca_client_config().map_err(|e| TransportError::Clean(e.to_string()))?,
        };
        let connector = TlsConnector::from(Arc::new(config));

        // Everything up to and including the handshake is a *clean* failure — no
        // request byte has left the host.
        let tcp = TcpStream::connect(SocketAddr::new(addr, port))
            .await
            .map_err(|e| TransportError::Clean(e.to_string()))?;
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| TransportError::Clean("bad host".to_owned()))?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| TransportError::Clean(e.to_string()))?;

        // From the first write on, a failure is *uncertain* — the request may have
        // been transmitted and processed.
        let auth_line = match credential.and_then(|c| auth.header_line(c)) {
            Some(line) => format!("{line}\r\n"),
            None => String::new(),
        };
        // Static per-processor headers (e.g. anthropic-version). CR/LF is stripped so
        // a header value cannot inject additional headers or a body.
        let static_lines: String = headers
            .iter()
            .map(|(name, value)| {
                let clean = |s: &str| s.replace(['\r', '\n'], "");
                format!("{}: {}\r\n", clean(name), clean(value))
            })
            .collect();
        let target = if path.starts_with('/') { path } else { "/" };
        let head = format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             {auth_line}{static_lines}Content-Length: {}\r\nConnection: close\r\n\r\n",
            request.len()
        );
        let exchange = async {
            tls.write_all(head.as_bytes()).await?;
            tls.write_all(request).await?;
            tls.flush().await?;
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match tls.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        raw.extend_from_slice(&chunk[..n]);
                        // Header + capped body is enough; stop once the body cap is
                        // reached (a generous headroom over the headers).
                        if raw.len() as u64 >= max_response_bytes + 8192 {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
            }
            Ok::<_, std::io::Error>(raw)
        };
        let raw = exchange
            .await
            .map_err(|e| TransportError::Uncertain(e.to_string()))?;
        let (status, body) = split_response(&raw)
            .ok_or_else(|| TransportError::Uncertain("no HTTP response".to_owned()))?;
        Ok(CallResponse { status, body })
    }
}

/// Splits an HTTP/1.1 response into (status code, body bytes), decoding a
/// `Transfer-Encoding: chunked` body. Real model endpoints (OpenAI included) stream
/// their reply chunked rather than with a `Content-Length`, so the raw body carries
/// chunk-size framing that must be removed before it is valid JSON.
fn split_response(raw: &[u8]) -> Option<(u16, Vec<u8>)> {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..sep]).ok()?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let raw_body = &raw[sep + 4..];
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let body = if chunked {
        dechunk(raw_body)
    } else {
        raw_body.to_vec()
    };
    Some((status, body))
}

/// Decodes an HTTP/1.1 chunked-transfer body to its payload. Each chunk is
/// `<hex-size>[;ext]\r\n<size bytes>\r\n`, ending at a `0`-size chunk. Tolerant of a
/// body truncated by the response cap (returns what was decoded so far) and of
/// malformed framing (returns the bytes decoded up to that point).
fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = data.windows(2).position(|w| w == b"\r\n") {
        let Some(hex) = std::str::from_utf8(&data[..nl]).ok().and_then(|l| {
            let tok = l.split(';').next()?.trim();
            usize::from_str_radix(tok, 16).ok()
        }) else {
            break;
        };
        data = &data[nl + 2..];
        if hex == 0 {
            break; // last chunk; trailers (if any) are ignored
        }
        let take = hex.min(data.len()); // cap-truncated bodies take what is present
        out.extend_from_slice(&data[..take]);
        data = &data[take..];
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        } else {
            break; // truncated mid-chunk
        }
    }
    out
}

/// Serves a worker's request to make a processor call (design §13.1). The worker
/// runs with no network of its own; the daemon dispatches on its behalf, but only
/// if the work order authorised processor use (§12.1 — which Option-2 does not
/// auto-grant at accept). Extracts what it needs under the store lock, then runs
/// the dispatch (which does its own two-phase locking) on a dedicated runtime.
pub fn run_processor_call(
    state: &DaemonState,
    processor_id: &str,
    work_order_id: &str,
    request: &[u8],
) -> Result<serde_json::Value, Problem> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (binding, budget, policy) = {
        let store = state.store();
        let store = store.lock().map_err(|_| internal())?;
        let issued = store
            .get_work_order(work_order_id)
            .map_err(store_problem)?
            .ok_or_else(|| problem(404, "no-work-order", "no such work order"))?;
        // The work order must grant processor use (§12.1); Option-2 holds this
        // outward-disclosing capability for a separate confirmation.
        if !issued
            .order
            .capabilities
            .grants_component(CapabilityComponent::ProcessorUse)
        {
            return Err(problem(
                403,
                "processor-use-not-granted",
                "the work order does not authorise processor use",
            ));
        }
        // The attempt must be active — no calls before it claims or after it ends.
        match store.attempt_state(work_order_id).map_err(store_problem)? {
            Some(AttemptState::Claimed) | Some(AttemptState::Running) => {}
            _ => {
                return Err(problem(
                    409,
                    "attempt-not-active",
                    "the attempt is not active",
                ))
            }
        }
        let config = store
            .get_processor(processor_id)
            .map_err(store_problem)?
            .ok_or_else(|| problem(404, "no-such-processor", "no such processor"))?;
        let binding = CallBinding {
            work_order_id: work_order_id.to_owned(),
            work_order_digest: issued.digest.clone(),
            task_id: issued.order.task_id.clone(),
        };
        let budget = CallBudget {
            max_cost_microusd: issued.order.budgets.max_cost_microusd,
            deadline: issued.order.deadline.clone(),
            max_response_bytes: issued.order.budgets.max_bytes,
        };
        // Allow the processor's exact origin; permit its local address only for a
        // declared-local processor.
        let mut policy = EgressPolicy::allowing([config.origin.clone()]);
        if config.is_local() {
            policy = policy.allow_local();
        }
        (binding, budget, policy)
    };

    let endpoint_key = state.identity().purpose_key(KeyPurpose::TlsEndpoint);
    let transport = HttpsTransport {
        endpoint_key: &endpoint_key,
        endpoint_cert: state.endpoint_cert(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| internal())?;
    let store = state.store();
    runtime.block_on(dispatch_processor_call(
        &store,
        processor_id,
        request,
        binding,
        budget,
        &policy,
        &transport,
        now,
    ))
}

fn is_terminal(state: SubAttemptState) -> bool {
    matches!(
        state,
        SubAttemptState::Completed
            | SubAttemptState::Failed
            | SubAttemptState::Ambiguous
            | SubAttemptState::Cancelled
    )
}

/// Advances the sub-attempt under an already-held lock.
fn advance(
    store: &Store,
    key: &str,
    event: SubAttemptEvent,
    now: i64,
) -> Result<SubAttemptState, Problem> {
    store
        .advance_call(key, event, now)
        .map_err(store_problem)?
        .map_err(|_| internal())
}

/// Locks the store and advances the sub-attempt (the terminal transitions after
/// the network I/O).
fn mark(
    store: &Mutex<Store>,
    key: &str,
    event: SubAttemptEvent,
    now: i64,
) -> Result<SubAttemptState, Problem> {
    let store = store.lock().map_err(|_| internal())?;
    advance(&store, key, event, now)
}

/// Resolves `host:port` to the first address, or `None`.
async fn resolve(host: &str, port: u16) -> Option<IpAddr> {
    tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .next()
        .map(|sa| sa.ip())
}

fn outcome_json(
    call: &ProcessorCall,
    state: SubAttemptState,
    resp: Option<&CallResponse>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "idempotency_key": call.idempotency_key,
        "state": state.as_str(),
    });
    if let Some(r) = resp {
        v["status"] = serde_json::json!(r.status);
        v["response"] = serde_json::json!(String::from_utf8_lossy(&r.body));
    }
    v
}

fn store_problem(_e: axon_store::StoreError) -> Problem {
    internal()
}

fn internal() -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    }
}

fn problem_detail(status: u16, kind: &str, title: &str, e: impl std::fmt::Display) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: Some(e.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use axon_broker::{AuthScheme, Origin, ProcessorConfig};
    use axon_crypto::cert::self_signed_endpoint;
    use axon_crypto::purpose::KeyPurpose;
    use axon_store::{ExternalCheckpoint, Store};
    use axon_transport::tls::bootstrap_server_config;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    const NOW: i64 = 1_800_000_000;

    fn store() -> StdMutex<Store> {
        let kek = axon_store::envelope::Kek::from_bytes([51u8; 32]);
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        StdMutex::new(Store::open_in_memory(&kek, cp).unwrap())
    }

    /// A local processor on 127.0.0.1 (so the resolved-address check needs the
    /// allow-local policy).
    fn processor(store: &StdMutex<Store>) -> (ProcessorConfig, EgressPolicy) {
        let config = ProcessorConfig {
            processor_id: "local-llm".to_owned(),
            provider: "local".to_owned(),
            origin: Origin::https("127.0.0.1", 8443),
            disclosure: axon_broker::Disclosure::remote("Local", "here"),
            path: "/".to_owned(),
            auth: AuthScheme::Bearer,
            headers: Vec::new(),
            config: serde_json::json!({"model": "m"}),
            tls_certificate_sha256: None,
        };
        {
            let s = store.lock().unwrap();
            s.put_processor(&config, NOW).unwrap();
            s.put_credential("local-llm", b"secret-key", NOW).unwrap();
        }
        let policy = EgressPolicy::allowing([config.origin.clone()]).allow_local();
        (config, policy)
    }

    fn binding() -> CallBinding {
        CallBinding {
            work_order_id: "wo-1".to_owned(),
            work_order_digest: "aa".repeat(32),
            task_id: "task-1".to_owned(),
        }
    }

    fn budget() -> CallBudget {
        CallBudget {
            max_cost_microusd: 1000,
            deadline: "2030-01-01T00:00:00Z".to_owned(),
            max_response_bytes: 65536,
        }
    }

    /// What the transport was handed: (dialed address, credential, request).
    type SeenCall = Option<(IpAddr, Option<Vec<u8>>, Vec<u8>)>;

    /// A transport that records what it was handed and returns a canned response.
    struct MockTransport {
        response: Result<(u16, Vec<u8>), TransportError>,
        seen: StdMutex<SeenCall>,
    }
    impl MockTransport {
        fn ok(status: u16, body: &[u8]) -> Self {
            Self {
                response: Ok((status, body.to_vec())),
                seen: StdMutex::new(None),
            }
        }
    }
    impl CallTransport for MockTransport {
        #[allow(clippy::too_many_arguments)]
        async fn send(
            &self,
            _host: &str,
            _port: u16,
            addr: IpAddr,
            _path: &str,
            _expected_cert: Option<&str>,
            _auth: &AuthScheme,
            credential: Option<&[u8]>,
            _headers: &[(String, String)],
            request: &[u8],
            _max: u64,
        ) -> Result<CallResponse, TransportError> {
            *self.seen.lock().unwrap() =
                Some((addr, credential.map(<[u8]>::to_vec), request.to_vec()));
            match &self.response {
                Ok((status, body)) => Ok(CallResponse {
                    status: *status,
                    body: body.clone(),
                }),
                Err(TransportError::Clean(d)) => Err(TransportError::Clean(d.clone())),
                Err(TransportError::Uncertain(d)) => Err(TransportError::Uncertain(d.clone())),
            }
        }
    }

    #[tokio::test]
    async fn a_call_completes_and_injects_the_credential_at_a_checked_address() {
        let store = store();
        let (_config, policy) = processor(&store);
        let transport = MockTransport::ok(200, b"{\"answer\":42}");

        let out = dispatch_processor_call(
            &store,
            "local-llm",
            b"the prompt",
            binding(),
            budget(),
            &policy,
            &transport,
            NOW,
        )
        .await
        .unwrap();

        assert_eq!(out["state"], "completed");
        assert_eq!(out["status"], 200);
        assert_eq!(out["response"], "{\"answer\":42}");
        // The transport was handed the checked address, the sealed credential, and
        // the exact request.
        let (addr, credential, request) = transport.seen.lock().unwrap().clone().unwrap();
        assert_eq!(addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(credential.as_deref(), Some(&b"secret-key"[..]));
        assert_eq!(request, b"the prompt");
    }

    #[tokio::test]
    async fn a_non_allowlisted_origin_is_refused_before_any_record() {
        let store = store();
        let (_config, _policy) = processor(&store);
        // A policy that does NOT allow the processor's origin.
        let empty = EgressPolicy::default().allow_local();
        let transport = MockTransport::ok(200, b"x");
        let err = dispatch_processor_call(
            &store,
            "local-llm",
            b"p",
            binding(),
            budget(),
            &empty,
            &transport,
            NOW,
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, 403);
        assert!(transport.seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn a_resolved_inward_address_is_refused_without_the_local_opt_in() {
        let store = store();
        let (config, _policy) = processor(&store);
        // Allow the origin but NOT non-global addresses → 127.0.0.1 is refused at
        // the connection-time check, and nothing is sent.
        let policy = EgressPolicy::allowing([config.origin.clone()]);
        let transport = MockTransport::ok(200, b"x");
        let err = dispatch_processor_call(
            &store,
            "local-llm",
            b"p",
            binding(),
            budget(),
            &policy,
            &transport,
            NOW,
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, 403);
        assert!(transport.seen.lock().unwrap().is_none());
        // The sub-attempt failed cleanly (nothing was transmitted). Compute the key
        // BEFORE locking — std Mutex is not reentrant.
        let key = call_key(&store);
        assert_eq!(
            store.lock().unwrap().call_state(&key).unwrap().unwrap(),
            SubAttemptState::Failed
        );
    }

    #[tokio::test]
    async fn an_uncertain_transport_marks_the_call_ambiguous() {
        let store = store();
        let (_config, policy) = processor(&store);
        let transport = MockTransport {
            response: Err(TransportError::Uncertain("reset mid-response".to_owned())),
            seen: StdMutex::new(None),
        };
        let err = dispatch_processor_call(
            &store,
            "local-llm",
            b"p",
            binding(),
            budget(),
            &policy,
            &transport,
            NOW,
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, 502);
        let key = call_key(&store);
        assert_eq!(
            store.lock().unwrap().call_state(&key).unwrap().unwrap(),
            SubAttemptState::Ambiguous
        );
    }

    /// A processor server: accepts one mTLS connection, reads the POST (headers +
    /// Content-Length body), captures the raw request, and answers with a canned
    /// JSON body.
    async fn capture_processor(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        captured: Arc<StdMutex<Vec<u8>>>,
    ) {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let (header_end, content_length) = loop {
            let n = tls.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                let len = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                break (pos + 4, len);
            }
        };
        while buf.len() < header_end + content_length {
            let n = tls.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        *captured.lock().unwrap() = buf.clone();
        let body = b"{\"answer\":42}";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        tls.write_all(resp.as_bytes()).await.unwrap();
        tls.write_all(body).await.unwrap();
        tls.flush().await.unwrap();
    }

    #[tokio::test]
    async fn the_https_transport_pins_the_processor_and_injects_the_credential() {
        // The processor's server cert (the daemon pins it); the daemon's own cert.
        let proc_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[71u8; 32]);
        let proc_cert =
            self_signed_endpoint(&proc_key, "processor", Duration::from_secs(3600)).unwrap();
        let daemon_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[72u8; 32]);
        let daemon_cert =
            self_signed_endpoint(&daemon_key, "daemon", Duration::from_secs(3600)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(Arc::new(
            bootstrap_server_config(&proc_key, &proc_cert).unwrap(),
        ));
        let captured = Arc::new(StdMutex::new(Vec::new()));
        let server = tokio::spawn(capture_processor(listener, acceptor, captured.clone()));

        // The pinned processor + its sealed credential.
        let store = store();
        let config = ProcessorConfig {
            processor_id: "local-llm".to_owned(),
            provider: "local".to_owned(),
            origin: Origin::https("127.0.0.1", port),
            disclosure: axon_broker::Disclosure::remote("Local", "here"),
            path: "/v1/chat/completions".to_owned(),
            auth: AuthScheme::Bearer,
            headers: vec![("anthropic-version".to_owned(), "2023-06-01".to_owned())],
            config: serde_json::json!({"model": "m"}),
            tls_certificate_sha256: Some(proc_cert.fingerprint.value.clone()),
        };
        {
            let s = store.lock().unwrap();
            s.put_processor(&config, NOW).unwrap();
            s.put_credential("local-llm", b"secret-key", NOW).unwrap();
        }
        let policy = EgressPolicy::allowing([config.origin.clone()]).allow_local();

        let transport = HttpsTransport {
            endpoint_key: &daemon_key,
            endpoint_cert: &daemon_cert,
        };
        let out = dispatch_processor_call(
            &store,
            "local-llm",
            b"{\"prompt\":\"hi\"}",
            binding(),
            budget(),
            &policy,
            &transport,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(out["state"], "completed");
        assert_eq!(out["status"], 200);
        assert_eq!(out["response"], "{\"answer\":42}");
        server.await.unwrap();

        // The processor received the POST at the configured path, with the injected
        // credential + the request body.
        let raw = String::from_utf8_lossy(&captured.lock().unwrap()).to_string();
        assert!(raw.contains("POST /v1/chat/completions HTTP/1.1"));
        assert!(raw.contains("Authorization: Bearer secret-key"));
        assert!(raw.contains("anthropic-version: 2023-06-01"));
        assert!(raw.contains("{\"prompt\":\"hi\"}"));
    }

    /// The single prepared call's idempotency key (there is exactly one per test).
    fn call_key(store: &StdMutex<Store>) -> String {
        let config = store
            .lock()
            .unwrap()
            .get_processor("local-llm")
            .unwrap()
            .unwrap();
        ProcessorCall::prepare(&config, b"p", binding(), budget())
            .unwrap()
            .idempotency_key
    }

    // --- run_processor_call authorization gates (the worker-facing entry) ---

    use crate::DaemonConfig;
    use crate::IdentityKeys;
    use axon_authority::{
        Audience, Budgets, CapabilityVector, Grant, RequestOrigin, RespondScope, WorkOrder,
        WorkOrderKey,
    };

    fn ident(agent: &str) -> axon_contract::Identity {
        axon_contract::Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    fn daemon() -> DaemonState {
        let identity = IdentityKeys::from_master([80u8; 32]);
        let cert = self_signed_endpoint(
            &identity.purpose_key(KeyPurpose::TlsEndpoint),
            "daemon",
            Duration::from_secs(3600),
        )
        .unwrap();
        let kek = axon_store::envelope::Kek::from_bytes([52u8; 32]);
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        let store = Store::open_in_memory(&kek, cp).unwrap();
        let config = DaemonConfig {
            data_dir: std::env::temp_dir().join("axond-broker-unused"),
            local_performer: ident("performer"),
            interface_url: "https://local/a2a".to_owned(),
            receive_addr: None,
            pair_addr: None,
            worker_command: None,
            worker_exec: None,
        };
        DaemonState::from_parts(store, identity, cert, config)
    }

    fn work_order(id: &str, grants: Vec<Grant>) -> WorkOrder {
        WorkOrder {
            version: 1,
            work_order_id: id.to_owned(),
            issuer: ident("performer"),
            issuer_assurance: "local-human".to_owned(),
            audience: Audience {
                daemon: "axond".to_owned(),
                executor: "axon-worker".to_owned(),
            },
            request_origin: RequestOrigin {
                peer: ident("requester"),
                tls_certificate_sha256: "aa".repeat(32),
            },
            task_id: "task-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            message_id: "msg-1".to_owned(),
            contract_revision: 0,
            contract_digest: "a".repeat(64),
            capabilities: CapabilityVector::new(grants).unwrap(),
            input_manifest: vec!["diff".to_owned()],
            processor_digest: None,
            runner_digest: None,
            sandbox_digest: None,
            profile_digest: None,
            budgets: Budgets {
                max_cost_microusd: 5000,
                max_bytes: 65536,
                max_operations: 16,
            },
            evidence_slots: vec![],
            policy_version: 1,
            decision_id: "d-1".to_owned(),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            deadline: "2030-01-01T00:00:00Z".to_owned(),
            nonce: format!("{id}-{}", "n".repeat(40)),
            remote_cancel: None,
        }
    }

    fn store_work_order(daemon: &DaemonState, id: &str, grants: Vec<Grant>) {
        let order = work_order(id, grants);
        let issued = order.issue(&WorkOrderKey::from_bytes([7u8; 32])).unwrap();
        let store = daemon.store();
        let store = store.lock().unwrap();
        store.claim_attempt(&order, NOW).unwrap();
        store.put_work_order(&issued, NOW).unwrap();
    }

    fn respond_grant() -> Grant {
        Grant::Respond(RespondScope {
            task_id: "task-1".to_owned(),
            message_id: "msg-1".to_owned(),
            recipient: "request-origin".to_owned(),
            max_responses: 1,
            max_bytes: 8192,
            deadline: "2030-01-01T00:00:00Z".to_owned(),
        })
    }

    #[test]
    fn a_processor_call_without_a_work_order_is_404() {
        let daemon = daemon();
        let err = run_processor_call(&daemon, "proc", "wo-nope", b"x").unwrap_err();
        assert_eq!(err.status, 404);
    }

    #[test]
    fn a_processor_call_not_granted_processor_use_is_refused() {
        let daemon = daemon();
        // The work order grants only respond — not processor use (Option-2 holds it).
        store_work_order(&daemon, "wo-1", vec![respond_grant()]);
        let err = run_processor_call(&daemon, "proc", "wo-1", b"x").unwrap_err();
        assert_eq!(err.status, 403);
    }

    #[test]
    fn split_response_decodes_a_chunked_body() {
        // Real endpoints (OpenAI) stream the reply chunked, with no Content-Length.
        // The decoded body must be exactly the JSON payload — no chunk framing. Two
        // chunks + the terminating zero chunk, sizes computed so the framing is exact.
        let p1 = r#"{"choices":[{"index":0,"#;
        let p2 = r#""message":{"content":"hi"}}]}"#;
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Transfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            p1.len(),
            p1,
            p2.len(),
            p2
        );
        let (status, body) = super::split_response(raw.as_bytes()).unwrap();
        assert_eq!(status, 200);
        // Reassembled across chunks and valid JSON (the adapter's next step).
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["choices"][0]["message"]["content"], "hi");
    }

    #[test]
    fn split_response_passes_a_content_length_body_through() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        let (status, body) = super::split_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, br#"{"a":1}"#);
    }

    #[test]
    fn dechunk_tolerates_a_cap_truncated_final_chunk() {
        // The transport may stop reading mid-chunk at the response cap; decode what
        // is present rather than dropping it.
        let truncated = b"5\r\nhel"; // declares 5 bytes, only 3 arrive
        assert_eq!(super::dechunk(truncated), b"hel");
    }
}
