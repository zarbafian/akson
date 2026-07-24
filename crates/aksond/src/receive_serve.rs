//! Running the live A2A receive listener (design §9.1): the network face of the
//! daemon, wired to the same store the control sockets serve.
//!
//! [`run_receive_listener`] assembles the pieces the receive server needs — a
//! self-signed endpoint certificate over the daemon's `tls-endpoint` key, an mTLS
//! acceptor that completes a TLS 1.3 mutual handshake and captures each client's
//! leaf-cert fingerprint (pinned at the application layer by [`StorePeerResolver`],
//! not at TLS), and a [`ReceiveState`] sharing the daemon's `Arc<Mutex<Store>>` —
//! then serves the accept loop on its own tokio runtime. Because it owns its
//! runtime, it composes on a plain OS thread alongside the blocking control
//! sockets.
//!
//! A received, validated proposal lands as an inert `SUBMITTED` Task in the shared
//! store, so it appears in the operator's inbox the moment it is accepted.

use std::sync::Arc;

use akson_crypto::purpose::KeyPurpose;
use akson_transport::tls::bootstrap_server_config;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::bootstrap::DaemonState;
use crate::receive_server::{serve as serve_receive, ReceiveState, StorePeerResolver};

/// Why the receive listener could not run.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveServeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("endpoint certificate: {0}")]
    Cert(#[from] akson_crypto::cert::CertError),
    #[error("tls: {0}")]
    Tls(String),
    #[error("introduction identity: {0}")]
    Identity(String),
}

/// Binds the receive address, returning the listener — so a squatted port is a
/// LOUD failure at startup, not a silent listener death in a detached thread
/// (sec6 review). The caller makes the failure fatal; [`run_receive_listener`]
/// then serves on the returned listener.
pub fn bind_receive_addr(addr: &str) -> Result<std::net::TcpListener, ReceiveServeError> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Serves the mTLS A2A receive listener on a pre-bound `listener` until it
/// errors (design §9.1), running its own tokio runtime. Blocks; call it from a
/// dedicated thread.
pub fn run_receive_listener(
    state: Arc<DaemonState>,
    listener: std::net::TcpListener,
) -> Result<(), ReceiveServeError> {
    // The endpoint presents its stable self-signed cert over its tls-endpoint key;
    // the peer pinned this fingerprint at pairing (design §8.1/§8.3).
    let endpoint_key = state.identity().purpose_key(KeyPurpose::TlsEndpoint);
    // Accept any client cert at TLS and capture its fingerprint; the resolver pins
    // it against the store's peer records (an unknown fingerprint is a 403).
    let server_config = bootstrap_server_config(&endpoint_key, state.endpoint_cert())
        .map_err(|e| ReceiveServeError::Tls(e.to_string()))?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // First contact over identity tokens is served on this same listener
    // (design §8.2 step 4): route-matched before the A2A resolver, gated by
    // the operator's imports.
    let intro = crate::introduce::IntroIdentity::from_state(&state)
        .map_err(|p| ReceiveServeError::Identity(p.title))?;

    // The daemon acts as both performer (receives proposals) and requester
    // (accepts delivered results and signs its outcome), so it accepts results too.
    let receive_state = Arc::new(
        ReceiveState::new(
            state.store(),
            StorePeerResolver,
            state.config().local_performer.clone(),
            // The required Akson extension set the signed card advertises
            // (design §10.1): an inbound request that does not activate them
            // is refused — runtime now matches the card's contract.
            akson_ext::namespace::required_extension_uris()
                .into_iter()
                .collect(),
            state.config().interface_url.clone(),
        )
        .accepting_results(state.identity().purpose_key(KeyPurpose::RequesterOutcome))
        .with_introduction(Arc::new(intro)),
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = TcpListener::from_std(listener)?;
        serve_receive(listener, acceptor, receive_state).await
    })?;
    Ok(())
}
