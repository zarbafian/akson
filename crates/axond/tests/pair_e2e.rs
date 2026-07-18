//! End-to-end: a daemon accepts a pairing invitation from an inviter's bootstrap
//! server over mutual TLS, and pins the inviter — its peer record AND its
//! verification keys (design §8.2).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axon_contract::Identity;
use axon_crypto::cert::self_signed_endpoint;
use axon_crypto::purpose::KeyPurpose;
use axon_pairing::handler::BootstrapMaterial;
use axon_pairing::invitation::Invitation;
use axon_pairing::state_machine::PairingLedger;
use axon_proto::card_sig;
use axon_proto::v1::AgentCard;
use axon_store::envelope::Kek;
use axon_store::{ExternalCheckpoint, Store};
use axon_transport::bootstrap::{serve, BootstrapState};
use axon_transport::tls::bootstrap_server_config;
use axond::{run_pair_accept, ControlRequest, DaemonConfig, DaemonState, IdentityKeys};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn checkpoint() -> ExternalCheckpoint {
    ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    }
}

/// An endpoint's pairing material: a signed Agent Card + its paired-purpose keys.
fn material(identity: &IdentityKeys, tls_sha256: &str, agent: &str) -> BootstrapMaterial {
    let card_value = json!({
        "name": agent,
        "description": "axon endpoint",
        "version": "1.0.0",
        "supportedInterfaces": [{
            "url": format!("https://{agent}/a2a"),
            "protocolBinding": "HTTP+JSON",
            "protocolVersion": "1.0",
        }],
        "capabilities": { "streaming": false, "pushNotifications": false },
    });
    let mut card: AgentCard = serde_json::from_value(card_value).unwrap();
    card.signatures
        .push(card_sig::sign_card(&card, &identity.purpose_key(KeyPurpose::AgentCard)).unwrap());
    // Only statement keys — TLS identity is pinned by the certificate digest.
    let mut keys = BTreeMap::new();
    for purpose in KeyPurpose::PAIRED {
        if purpose == KeyPurpose::TlsEndpoint {
            continue;
        }
        keys.insert(purpose, identity.purpose_key(purpose));
    }
    BootstrapMaterial {
        tls_sha256: tls_sha256.to_owned(),
        subject_issuer: "iss".to_owned(),
        subject_agent: agent.to_owned(),
        signed_card: card,
        keys,
        not_before: "2020-01-01T00:00:00Z".to_owned(),
        not_after: "2035-01-01T00:00:00Z".to_owned(),
        generation: 0,
    }
}

#[tokio::test]
async fn a_daemon_accepts_an_invitation_and_pins_the_inviter_with_its_keys() {
    // The inviter: a standalone bootstrap server.
    let inviter_id = IdentityKeys::from_master([90u8; 32]);
    let inviter_tls = inviter_id.purpose_key(KeyPurpose::TlsEndpoint);
    let inviter_cert =
        self_signed_endpoint(&inviter_tls, "inviter", Duration::from_secs(3600)).unwrap();
    let inviter_fp = inviter_cert.fingerprint.value.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("https://127.0.0.1:{port}/bootstrap");
    // The invitation must be created at REAL now — the inviter server checks it
    // against its wall clock (a fixed test time in the future is rejected).
    let now_unix = time::OffsetDateTime::now_utc().unix_timestamp();
    let (invitation, pending) =
        Invitation::create(url, inviter_fp.clone(), "kid".to_owned(), now_unix, 900, 5);
    let verifier = pending.verifier();
    let mut inviter_store = Store::open_in_memory(&Kek::from_bytes([90u8; 32]), checkpoint()).unwrap();
    inviter_store.put_active(verifier, pending).unwrap();
    let state = Arc::new(BootstrapState::new(
        inviter_store,
        material(&inviter_id, &inviter_fp, "inviter"),
    ));
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&inviter_tls, &inviter_cert).unwrap(),
    ));
    tokio::spawn(serve(listener, acceptor, state));

    // The accepter: a daemon.
    let acc_id = IdentityKeys::from_master([91u8; 32]);
    let acc_cert = self_signed_endpoint(
        &acc_id.purpose_key(KeyPurpose::TlsEndpoint),
        "accepter",
        Duration::from_secs(3600),
    )
    .unwrap();
    let acc_store = Store::open_in_memory(&Kek::from_bytes([91u8; 32]), checkpoint()).unwrap();
    let config = DaemonConfig {
        data_dir: std::env::temp_dir().join("axond-pair-unused"),
        local_performer: Identity {
            issuer: "iss".to_owned(),
            agent: "accepter".to_owned(),
        },
        interface_url: "https://accepter/a2a".to_owned(),
        receive_addr: None,
        pair_addr: None,
    };
    let daemon = Arc::new(DaemonState::from_parts(acc_store, acc_id, acc_cert, config));
    let daemon_store = daemon.store();

    // Accept the invitation (run_pair_accept blocks on its own runtime).
    let invitation_json = serde_json::to_string(&invitation).unwrap();
    let d = daemon.clone();
    let out = tokio::task::spawn_blocking(move || run_pair_accept(&d, &invitation_json))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out["paired"], true);
    assert_eq!(out["peer"], "inviter");

    // The daemon pinned the inviter as a peer AND retained its contract-proposal
    // key — so it can later verify the inviter's proposals.
    let store = daemon_store.lock().unwrap();
    assert!(store.get_peer("inviter").unwrap().is_some());
    assert!(store
        .peer_key(&inviter_fp, "contract-proposal")
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn two_daemons_pair_via_the_daemon_bootstrap_endpoint() {
    use axon_transport::bootstrap::{serve as serve_bootstrap, BootstrapState};
    use axond::{run_pair_invite, SharedStore};

    // The inviter daemon A: its bootstrap endpoint serves over its own store.
    let a_id = IdentityKeys::from_master([92u8; 32]);
    let a_cert = self_signed_endpoint(
        &a_id.purpose_key(KeyPurpose::TlsEndpoint),
        "inviter",
        Duration::from_secs(3600),
    )
    .unwrap();
    let a_fp = a_cert.fingerprint.value.clone();

    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_port = a_listener.local_addr().unwrap().port();
    let a_store = Store::open_in_memory(&Kek::from_bytes([92u8; 32]), checkpoint()).unwrap();
    let a_config = DaemonConfig {
        data_dir: std::env::temp_dir().join("axond-pair-a-unused"),
        local_performer: Identity {
            issuer: "iss".to_owned(),
            agent: "inviter".to_owned(),
        },
        interface_url: "https://inviter/a2a".to_owned(),
        receive_addr: None,
        pair_addr: Some(format!("127.0.0.1:{a_port}")),
    };
    let a = Arc::new(DaemonState::from_parts(a_store, a_id, a_cert, a_config));

    // Serve A's bootstrap endpoint over A's shared store.
    let a_material = material(a.identity(), &a_fp, "inviter");
    let bstate = Arc::new(BootstrapState::new(SharedStore(a.store()), a_material));
    let a_acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&a.identity().purpose_key(KeyPurpose::TlsEndpoint), a.endpoint_cert())
            .unwrap(),
    ));
    tokio::spawn(serve_bootstrap(a_listener, a_acceptor, bstate));

    // A mints an invitation into its shared store (run_pair_invite blocks).
    let a_for_invite = a.clone();
    let minted = tokio::task::spawn_blocking(move || run_pair_invite(&a_for_invite))
        .await
        .unwrap()
        .unwrap();
    let invitation_json = serde_json::to_string(&minted["invitation"]).unwrap();

    // The accepter daemon B accepts it.
    let b_id = IdentityKeys::from_master([93u8; 32]);
    let b_cert = self_signed_endpoint(
        &b_id.purpose_key(KeyPurpose::TlsEndpoint),
        "accepter",
        Duration::from_secs(3600),
    )
    .unwrap();
    let b_store = Store::open_in_memory(&Kek::from_bytes([93u8; 32]), checkpoint()).unwrap();
    let b_config = DaemonConfig {
        data_dir: std::env::temp_dir().join("axond-pair-b-unused"),
        local_performer: Identity {
            issuer: "iss".to_owned(),
            agent: "accepter".to_owned(),
        },
        interface_url: "https://accepter/a2a".to_owned(),
        receive_addr: None,
        pair_addr: None,
    };
    let b = Arc::new(DaemonState::from_parts(b_store, b_id, b_cert, b_config));
    let b_store_handle = b.store();

    let b_for_accept = b.clone();
    let out = tokio::task::spawn_blocking(move || run_pair_accept(&b_for_accept, &invitation_json))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out["paired"], true);
    assert_eq!(out["peer"], "inviter");

    // Both endpoints now hold the other as a peer, in their own durable stores.
    assert!(b_store_handle.lock().unwrap().get_peer("inviter").unwrap().is_some());
    assert!(a.store().lock().unwrap().get_peer("accepter").unwrap().is_some());

    // The new peer is pending; the operator confirms it to activate it (§8.2 step 7).
    let confirmed = a
        .dispatch(&ControlRequest::PeerConfirm {
            agent_id: "accepter".to_owned(),
        })
        .unwrap();
    assert_eq!(confirmed["confirmed"], true);
    // A second confirm is a no-op (already active).
    let again = a
        .dispatch(&ControlRequest::PeerConfirm {
            agent_id: "accepter".to_owned(),
        })
        .unwrap();
    assert_eq!(again["confirmed"], false);

    // whoami reports this daemon's own identity + endpoint fingerprint (what an
    // operator shares with a peer).
    let who = a.dispatch(&ControlRequest::WhoAmI).unwrap();
    assert_eq!(who["agent"], "inviter");
    assert_eq!(who["endpoint_fingerprint"], a_fp);
}
