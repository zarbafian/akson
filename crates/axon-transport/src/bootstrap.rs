//! The HTTP bootstrap server (design §8.2) — the first live HTTP-over-mTLS
//! surface. It serves pairing bootstrap over TLS 1.3 (server-authenticated,
//! client cert captured unpinned via [`tls::bootstrap_server_config`]),
//! extracts the accepter's certificate fingerprint from the completed
//! handshake, and hands the request to `axon_pairing::http::handle_http`.
//!
//! The endpoint runs only while a pairing is in progress and behind an
//! aggressive rate limit (design §8.2). The enable-only-when-pairing gate lives
//! in `axon_pairing::http::handle_http` (a global ledger check: no live
//! invitation and no retriable consumed record ⇒ 404, as if unmounted), so it
//! holds for every caller of the pure logic. The rate limit is applied here
//! around [`serve`]; a daemon may further choose not to bind the port at all
//! when idle.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axon_crypto::identity::Fingerprint;
use axon_pairing::handler::BootstrapMaterial;
use axon_pairing::http::handle_http;
use axon_pairing::state_machine::PairingStore;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::limits::{
    BODY_READ_TIMEOUT, HANDSHAKE_TIMEOUT, HEADER_READ_TIMEOUT, MAX_CONCURRENT_CONNECTIONS,
};

/// Maximum bootstrap request body (design §9.1: limits before allocation). A
/// signed card + key bindings + proofs is a few KiB; this is a generous cap
/// that bounds memory against a hostile accepter.
const MAX_BOOTSTRAP_BODY: usize = 64 * 1024;

/// A token-bucket rate limiter — the bootstrap endpoint is aggressively rate
/// limited (design §8.2). One global bucket suffices: the endpoint is active
/// only briefly during a single pairing.
pub struct RateLimiter {
    inner: Mutex<Bucket>,
    capacity: f64,
    refill_per_sec: f64,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            inner: Mutex::new(Bucket {
                tokens: capacity as f64,
                last: Instant::now(),
            }),
            capacity: capacity as f64,
            refill_per_sec,
        }
    }

    /// Consumes a token if one is available. A poisoned lock is recovered rather
    /// than panicking.
    pub fn allow(&self) -> bool {
        let mut b = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared bootstrap server state: the invitation ledger, the inviter's own TLS
/// fingerprint and pending-pair response, and the rate limiter. Generic over the
/// ledger so the same server runs against the in-memory or persistent ledger.
pub struct BootstrapState<L: PairingStore> {
    pub ledger: Mutex<L>,
    /// The inviter's own material, used to build its per-request response.
    pub inviter: BootstrapMaterial,
    pub rate_limiter: RateLimiter,
}

impl<L: PairingStore> BootstrapState<L> {
    /// Builds server state with an aggressive default rate limit (30 requests
    /// burst, refilling 5/s) suitable for a single pairing.
    pub fn new(ledger: L, inviter: BootstrapMaterial) -> Self {
        Self {
            ledger: Mutex::new(ledger),
            inviter,
            rate_limiter: RateLimiter::new(30, 5.0),
        }
    }
}

/// Serves bootstrap connections until `listener` errors. Each connection runs
/// on its own task; a per-connection handshake or protocol failure is dropped,
/// never fatal to the accept loop.
pub async fn serve<L: PairingStore + Send + 'static>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<BootstrapState<L>>,
) -> std::io::Result<()> {
    // Bound concurrent pre-auth connections; a permit is held for the whole
    // connection so a flood cannot spawn unbounded tasks (§9.1).
    let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let (tcp, _) = listener.accept().await?;
        // Rate-limit before the TLS handshake so a flood is cheap to shed.
        if !state.rate_limiter.allow() {
            drop(tcp);
            continue;
        }
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
            let Ok(Ok(tls)) = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await else {
                return;
            };
            // Capture the accepter's leaf certificate fingerprint from the
            // completed handshake (the identity bound into the transcript).
            let peer_fp = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| Fingerprint::cert_sha256(cert.as_ref()).value);
            let svc = service_fn(move |req| {
                handle(state.clone(), peer_fp.clone(), req, BODY_READ_TIMEOUT)
            });
            // A per-connection protocol error is dropped, not fatal. header_read_timeout
            // bounds each request's head (and re-arms per keep-alive request, so it also
            // caps idle time between exchanges); the body read is bounded inside `handle`.
            // Structured error logging is deferred to telemetry (design §15.4).
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

async fn handle<L: PairingStore + Send>(
    state: Arc<BootstrapState<L>>,
    peer_fp: Option<String>,
    req: Request<Incoming>,
    body_read_timeout: Duration,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().as_str().to_owned();
    let authorization = header(req.headers(), AUTHORIZATION);
    // Cap the body before reading it into memory (413 if oversized), and bound the
    // time to read it so a slow-body sender is cut off (408) (design §9.1).
    let body = match timeout(
        body_read_timeout,
        Limited::new(req.into_body(), MAX_BOOTSTRAP_BODY).collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(_)) => return Ok(status(413)),
        Err(_) => return Ok(status(408)),
    };

    let now = OffsetDateTime::now_utc();
    let response = {
        let mut ledger = match state.ledger.lock() {
            Ok(g) => g,
            Err(_) => return Ok(status(500)),
        };
        handle_http(
            &mut *ledger,
            &state.inviter,
            &method,
            authorization.as_deref(),
            peer_fp.as_deref(),
            &body,
            now.unix_timestamp(),
            now,
        )
    };

    let mut out = Response::new(Full::new(Bytes::from(response.body)));
    *out.status_mut() =
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Ok(value) = response.content_type.parse() {
        out.headers_mut().insert(CONTENT_TYPE, value);
    }
    Ok(out)
}

fn header(headers: &HeaderMap, name: hyper::header::HeaderName) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    #[test]
    fn bucket_allows_up_to_capacity_then_denies() {
        // No refill: exactly `capacity` requests are allowed, then denied.
        let limiter = RateLimiter::new(3, 0.0);
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow(), "the fourth request must be rate-limited");
    }
}
