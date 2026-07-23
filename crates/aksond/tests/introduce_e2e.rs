//! First contact end-to-end (design §8.2 step 4, ADR-0015): a real TLS 1.3
//! session on loopback, the dialer holding only the responder's imported root
//! and endpoint hint — exactly what an identity token carries. Proves the
//! whole flow: hello → responder proof → dialer proof → ack → both stores
//! pin an ACTIVE peer with its verification keys; re-introduction is
//! idempotent; an unimported dialer gets the generic refusal and a knock.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use akson_contract::Identity;
use akson_crypto::cert::self_signed_endpoint;
use akson_crypto::keypair::PurposeKey;
use akson_crypto::purpose::KeyPurpose;
use akson_proto::card_sig;
use akson_proto::v1::AgentCard;
use akson_store::envelope::Kek;
use akson_store::{ExternalCheckpoint, IntroCommitOutcome, PeerStatus, Store};
use akson_transport::tls::bootstrap_server_config;
use aksond::{
    dial_introduction, intro_profile, serve_receive, IntroIdentity, IntroduceError,
    ReceiveState, StorePeerResolver,
};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn store() -> Arc<Mutex<Store>> {
    let cp = ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    };
    Arc::new(Mutex::new(
        Store::open_in_memory(&Kek::from_bytes([7u8; 32]), cp).unwrap(),
    ))
}

/// A profile-valid signed card for `agent` (the bar `validate_agent_card`
/// sets: v1 interface, streaming/push off, extended card, the full required
/// extension set, mandatory mTLS).
fn signed_card(agent: &str, card_key: &PurposeKey) -> AgentCard {
    let extensions: Vec<serde_json::Value> = akson_ext::namespace::required_extension_uris()
        .into_iter()
        .map(|uri| serde_json::json!({ "uri": uri, "required": true }))
        .collect();
    let mut card: AgentCard = serde_json::from_value(serde_json::json!({
        "name": agent, "description": "e2e endpoint", "version": "1.0.0",
        "supportedInterfaces": [{
            "url": "https://peer.example/a2a",
            "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0",
        }],
        "capabilities": {
            "streaming": false, "pushNotifications": false,
            "extendedAgentCard": true, "extensions": extensions,
        },
        "securitySchemes": { "mtls": { "mtlsSecurityScheme": { "description": "pinned" } } },
        "securityRequirements": [{ "schemes": { "mtls": { "list": [] } } }],
    }))
    .unwrap();
    card.signatures.push(card_sig::sign_card(&card, card_key).unwrap());
    card
}

/// One endpoint's introduction identity from a seed — what
/// `IntroIdentity::from_state` assembles in the live daemon.
fn identity(agent: &str, seed: u8) -> IntroIdentity {
    let mut keys = BTreeMap::new();
    for purpose in KeyPurpose::PAIRED {
        if purpose == KeyPurpose::TlsEndpoint {
            continue;
        }
        keys.insert(
            purpose,
            PurposeKey::from_seed(purpose, &[seed ^ (purpose as u8); 32]),
        );
    }
    let card_key = &keys[&KeyPurpose::AgentCard];
    let own_root = card_key.verifying().to_jwk().thumbprint();
    let signed_card = signed_card(agent, card_key);
    let tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[seed; 32]);
    let cert = self_signed_endpoint(&tls_key, "akson-endpoint", Duration::from_secs(3600)).unwrap();
    IntroIdentity {
        keys,
        signed_card,
        tls_key,
        cert,
        own_root,
        issuer: "local".to_owned(),
        agent: agent.to_owned(),
        profile: intro_profile(),
    }
}

fn ident(agent: &str) -> Identity {
    Identity {
        issuer: "local".to_owned(),
        agent: agent.to_owned(),
    }
}

/// Serves B's receive listener with introductions enabled; returns its port.
async fn serve_responder(responder: IntroIdentity, store_b: Arc<Mutex<Store>>) -> u16 {
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&responder.tls_key, &responder.cert).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = Arc::new(
        ReceiveState::new(
            store_b,
            StorePeerResolver,
            ident(&responder.agent.clone()),
            BTreeSet::new(),
            "https://127.0.0.1/a2a".to_owned(),
        )
        .with_introduction(Arc::new(responder)),
    );
    tokio::spawn(serve_receive(listener, acceptor, state));
    port
}

#[tokio::test]
async fn mutual_import_introduces_and_pins_both_sides() {
    let now = OffsetDateTime::now_utc();
    let now_unix = now.unix_timestamp();
    let alice = identity("alice", 3);
    let bob = identity("bob", 5);
    let (store_a, store_b) = (store(), store());

    // The out-of-band exchange: each operator imported the other's token.
    store_b
        .lock()
        .unwrap()
        .add_peer_import(&alice.own_root, "their-alice", "", now_unix)
        .unwrap();
    let port = serve_responder(identity("bob", 5), store_b.clone()).await;
    store_a
        .lock()
        .unwrap()
        .add_peer_import(&bob.own_root, "bob-codex", &format!("127.0.0.1:{port}"), now_unix)
        .unwrap();
    let import = store_a
        .lock()
        .unwrap()
        .peer_import_by_label("bob-codex")
        .unwrap()
        .unwrap();

    // First task send would trigger exactly this dial.
    let (peer, outcome) = dial_introduction(&alice, store_a.clone(), &import, now)
        .await
        .expect("introduction succeeds");
    assert_eq!(outcome, IntroCommitOutcome::Committed);
    assert_eq!(peer.agent_id, "bob");
    assert_eq!(peer.agent_card_key.value, bob.own_root);

    // Both sides hold an ACTIVE peer with its verification keys pinned.
    {
        let a = store_a.lock().unwrap();
        assert_eq!(a.peer_status("bob").unwrap(), Some(PeerStatus::Active));
        let pk = a
            .peer_key(&bob.cert.fingerprint.value, "contract-proposal")
            .unwrap()
            .expect("bob's proposal key pinned at A");
        assert_eq!(pk.agent_id, "bob");
    }
    {
        let b = store_b.lock().unwrap();
        assert_eq!(b.peer_status("alice").unwrap(), Some(PeerStatus::Active));
        let pk = b
            .peer_key(&alice.cert.fingerprint.value, "task-result")
            .unwrap()
            .expect("alice's task-result key pinned at B");
        assert_eq!(pk.agent_id, "alice");
    }

    // Running it again (simultaneous dials / crash between commits) is
    // idempotent, not an error and not a second peer.
    let (_, outcome) = dial_introduction(&alice, store_a.clone(), &import, now)
        .await
        .expect("re-introduction is idempotent");
    assert_eq!(outcome, IntroCommitOutcome::AlreadyActive);
}

#[tokio::test]
async fn an_unimported_dialer_is_refused_generically_and_knocks() {
    let now = OffsetDateTime::now_utc();
    let now_unix = now.unix_timestamp();
    let bob = identity("bob", 5);
    let store_b = store();
    // B imported nobody. Mallory still holds B's public token (anyone can).
    let mallory = identity("mallory", 9);
    let port = serve_responder(identity("bob", 5), store_b.clone()).await;

    let store_m = store();
    store_m
        .lock()
        .unwrap()
        .add_peer_import(&bob.own_root, "target", &format!("127.0.0.1:{port}"), now_unix)
        .unwrap();
    let import = store_m
        .lock()
        .unwrap()
        .peer_import_by_label("target")
        .unwrap()
        .unwrap();

    let err = dial_introduction(&mallory, store_m, &import, now)
        .await
        .expect_err("an unimported dialer must be refused");
    assert!(matches!(err, IntroduceError::Refused), "got: {err}");

    // The refusal left a knock, keyed by the unauthenticated claim.
    let knocks = store_b.lock().unwrap().knocks().unwrap();
    assert_eq!(knocks.len(), 1);
    assert_eq!(knocks[0].claimed_root, mallory.own_root);
    assert_eq!(knocks[0].refusal_class, "not-imported");
    // And nothing was pinned.
    assert!(store_b
        .lock()
        .unwrap()
        .peer_status("mallory")
        .unwrap()
        .is_none());
}
