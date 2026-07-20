//! The pairing inviter side (design §8.2): the daemon serves the bootstrap
//! endpoint over the SAME store the rest of the daemon uses, and mints
//! invitations.
//!
//! The transport bootstrap server is generic over a [`PairingStore`]; the daemon's
//! store lives behind an `Arc<Mutex<Store>>` shared with the control sockets and
//! the receive server. [`SharedStore`] adapts that shared handle to the
//! `PairingStore` trait by locking per call, so a paired peer is durable in the one
//! store every surface reads. [`run_pair_listener`] serves the endpoint; a mint
//! ([`run_pair_invite`]) writes the live invitation into that same store, and the
//! endpoint is inert (404) until one is live (§8.2).

use std::sync::{Arc, Mutex};

use akson_crypto::identity::PeerIdentity;
use akson_crypto::purpose::KeyPurpose;
use akson_pairing::invitation::{Invitation, PendingInvitation};
use akson_pairing::key_binding::KeyBindingSet;
use akson_pairing::state_machine::{Consumed, LedgerError, PairingLedger, PairingStore};
use akson_store::Store;
use akson_transport::bootstrap::{serve, BootstrapState};
use akson_transport::tls::bootstrap_server_config;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::bootstrap::DaemonState;
use crate::control::Problem;
use crate::pairing::bootstrap_material;

/// Adapts the daemon's shared `Arc<Mutex<Store>>` to [`PairingStore`], locking the
/// one store per call so the bootstrap server pairs into the same durable state
/// the control and receive surfaces read.
pub struct SharedStore(pub Arc<Mutex<Store>>);

fn poisoned<E>(_e: E) -> LedgerError {
    LedgerError("the store is poisoned".to_owned())
}

impl PairingLedger for SharedStore {
    fn consumed(&self, verifier: &[u8; 32]) -> Result<Option<Consumed>, LedgerError> {
        self.0.lock().map_err(poisoned)?.consumed(verifier)
    }
    fn active_exists(&self, verifier: &[u8; 32]) -> Result<bool, LedgerError> {
        self.0.lock().map_err(poisoned)?.active_exists(verifier)
    }
    fn any_pairing_open(&self, now: i64) -> Result<bool, LedgerError> {
        self.0.lock().map_err(poisoned)?.any_pairing_open(now)
    }
    fn take_active(
        &mut self,
        verifier: &[u8; 32],
    ) -> Result<Option<PendingInvitation>, LedgerError> {
        self.0.lock().map_err(poisoned)?.take_active(verifier)
    }
    fn put_active(
        &mut self,
        verifier: [u8; 32],
        invitation: PendingInvitation,
    ) -> Result<(), LedgerError> {
        self.0
            .lock()
            .map_err(poisoned)?
            .put_active(verifier, invitation)
    }
    fn commit_consumed(
        &mut self,
        verifier: [u8; 32],
        consumed: Consumed,
    ) -> Result<(), LedgerError> {
        self.0
            .lock()
            .map_err(poisoned)?
            .commit_consumed(verifier, consumed)
    }
}

impl PairingStore for SharedStore {
    fn store_pending_peer(&mut self, peer: &PeerIdentity) -> Result<(), LedgerError> {
        self.0.lock().map_err(poisoned)?.store_pending_peer(peer)
    }
    fn persist_peer_keys(&mut self, keys: &KeyBindingSet, now: i64) -> Result<(), LedgerError> {
        self.0
            .lock()
            .map_err(poisoned)?
            .persist_peer_keys(keys, now)
    }
}

/// Why the pairing listener could not run.
#[derive(Debug, thiserror::Error)]
pub enum PairServeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("material: {0}")]
    Material(String),
    #[error("tls: {0}")]
    Tls(String),
}

/// Serves the pairing bootstrap endpoint on `addr` (design §8.2), sharing the
/// daemon's store. Runs its own tokio runtime; blocks — call from a dedicated
/// thread. Inert (404) until an invitation is minted with [`run_pair_invite`].
pub fn run_pair_listener(state: Arc<DaemonState>, addr: &str) -> Result<(), PairServeError> {
    let material = bootstrap_material(&state).map_err(|p| PairServeError::Material(p.title))?;
    let endpoint_key = state.identity().purpose_key(KeyPurpose::TlsEndpoint);
    let server_config = bootstrap_server_config(&endpoint_key, state.endpoint_cert())
        .map_err(|e| PairServeError::Tls(e.to_string()))?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let bstate = Arc::new(BootstrapState::new(SharedStore(state.store()), material));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = TcpListener::bind(addr).await?;
        serve(listener, acceptor, bstate).await
    })?;
    Ok(())
}

/// Mints a pairing invitation (design §8.2 step 1): records the live invitation in
/// the shared store and returns it. Requires the pairing listener to be configured
/// (`AKSON_PAIR_ADDR`), since the invitation must carry that reachable endpoint URL.
pub fn run_pair_invite(state: &DaemonState) -> Result<serde_json::Value, Problem> {
    let pair_addr = state.config().pair_addr.as_ref().ok_or_else(|| {
        problem(
            409,
            "pairing-not-enabled",
            "the pairing endpoint is not configured (set AKSON_PAIR_ADDR)",
        )
    })?;
    let url = format!("https://{pair_addr}/bootstrap");
    let cert_fp = state.endpoint_cert().fingerprint.value.clone();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (invitation, pending) = Invitation::create(url, cert_fp, "kid".to_owned(), now, 900, 5);
    let verifier = pending.verifier();
    {
        let store = state.store();
        let mut store = store.lock().map_err(|_| internal())?;
        store
            .put_active(verifier, pending)
            .map_err(|_| internal())?;
    }
    let invitation = serde_json::to_value(&invitation).map_err(|_| internal())?;
    Ok(serde_json::json!({ "invitation": invitation }))
}

fn internal() -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:akson:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    }
}
