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

use std::collections::BTreeSet;
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
}

/// Serves the mTLS A2A receive listener on `addr` until it errors (design §9.1),
/// running its own tokio runtime. Blocks; call it from a dedicated thread.
pub fn run_receive_listener(state: Arc<DaemonState>, addr: &str) -> Result<(), ReceiveServeError> {
    // The endpoint presents its stable self-signed cert over its tls-endpoint key;
    // the peer pinned this fingerprint at pairing (design §8.1/§8.3).
    let endpoint_key = state.identity().purpose_key(KeyPurpose::TlsEndpoint);
    // Accept any client cert at TLS and capture its fingerprint; the resolver pins
    // it against the store's peer records (an unknown fingerprint is a 403).
    let server_config = bootstrap_server_config(&endpoint_key, state.endpoint_cert())
        .map_err(|e| ReceiveServeError::Tls(e.to_string()))?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // The daemon acts as both performer (receives proposals) and requester
    // (accepts delivered results and signs its outcome), so it accepts results too.
    let receive_state = Arc::new(
        ReceiveState::new(
            state.store(),
            StorePeerResolver,
            state.config().local_performer.clone(),
            BTreeSet::new(),
            state.config().interface_url.clone(),
        )
        .accepting_results(state.identity().purpose_key(KeyPurpose::RequesterOutcome)),
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = TcpListener::bind(addr).await?;
        serve_receive(listener, acceptor, receive_state).await
    })?;
    Ok(())
}
