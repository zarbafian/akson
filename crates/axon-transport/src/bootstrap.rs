//! The HTTP bootstrap server (design §8.2) — the first live HTTP-over-mTLS
//! surface. It serves pairing bootstrap over TLS 1.3 (server-authenticated,
//! client cert captured unpinned via [`tls::bootstrap_server_config`]),
//! extracts the accepter's certificate fingerprint from the completed
//! handshake, and hands the request to `axon_pairing::http::handle_http`.
//!
//! The endpoint is meant to run only while an invitation is live and behind an
//! aggressive rate limit (design §8.2); that gating is the daemon's to apply
//! around [`serve`].

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axon_crypto::identity::Fingerprint;
use axon_pairing::handler::InviterConfig;
use axon_pairing::http::handle_http;
use axon_pairing::state_machine::MemoryLedger;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Shared bootstrap server state: the invitation ledger, and the inviter's own
/// TLS fingerprint and pending-pair response.
pub struct BootstrapState {
    pub ledger: Mutex<MemoryLedger>,
    pub inviter_tls_sha256: String,
    pub inviter_response: Vec<u8>,
}

/// Serves bootstrap connections until `listener` errors. Each connection runs
/// on its own task; a per-connection handshake or protocol failure is dropped,
/// never fatal to the accept loop.
pub async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<BootstrapState>,
) -> std::io::Result<()> {
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
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
            let svc = service_fn(move |req| handle(state.clone(), peer_fp.clone(), req));
            // A per-connection protocol error is dropped, not fatal. Structured
            // error logging is deferred to the telemetry work (design §15.4).
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

async fn handle(
    state: Arc<BootstrapState>,
    peer_fp: Option<String>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().as_str().to_owned();
    let authorization = header(req.headers(), AUTHORIZATION);
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();

    let now = OffsetDateTime::now_utc();
    let response = {
        let mut ledger = match state.ledger.lock() {
            Ok(g) => g,
            Err(_) => return Ok(status(500)),
        };
        let inviter = InviterConfig {
            tls_sha256: &state.inviter_tls_sha256,
            response_body: &state.inviter_response,
        };
        handle_http(
            &mut *ledger,
            &inviter,
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
