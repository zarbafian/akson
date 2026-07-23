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

/// The slice-2 review's ABA case, at the responder: a handshake admitted
/// under epoch E must not commit after a removal — even when a re-add has
/// made the import live again under E+1. And the connection is terminal
/// after its one complete (RFC 9266 one-instance rule).
#[test]
fn removal_between_flights_refuses_the_stale_handshake() {
    use akson_pairing::introduction::{
        build_intro_material, Hello, IntroTranscript, Role, COMPLETE_PATH, HELLO_PATH,
        INTRODUCTION_MEDIA_TYPE, PROTOCOL_VERSION, TOKEN_VERSION,
    };
    use aksond::{respond_introduction, PendingIntro};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let now = 1_800_000_000i64;
    let alice = identity("alice", 3);
    let bob = identity("bob", 5);
    let store_b = store();
    store_b
        .lock()
        .unwrap()
        .add_peer_import(&alice.own_root, "alice", "", now)
        .unwrap();

    let pending = PendingIntro::default();
    let exporter = [9u8; 32];
    let alice_tls = alice.cert.fingerprint.value.clone();
    let nonce = URL_SAFE_NO_PAD.encode([7u8; 32]);

    // Flight 1: hello admits under epoch 1 and keeps the connection open.
    let hello = Hello {
        protocol_version: PROTOCOL_VERSION,
        token_version: TOKEN_VERSION,
        target_root: bob.own_root.clone(),
        claimed_root: alice.own_root.clone(),
        nonce: nonce.clone(),
    };
    let (code, _, _, close) = respond_introduction(
        &bob,
        &store_b,
        &pending,
        HELLO_PATH,
        "POST",
        INTRODUCTION_MEDIA_TYPE,
        "203.0.113.7",
        Some(&alice_tls),
        Some(&exporter),
        &serde_json::to_vec(&hello).unwrap(),
        now,
    );
    assert_eq!((code, close), (200, false), "hello admits, connection stays");

    // The operator removes AND re-adds between the flights: the import is
    // live again — under a new epoch.
    {
        let s = store_b.lock().unwrap();
        assert!(s.remove_peer_import(&alice.own_root, now + 1).unwrap());
        s.add_peer_import(&alice.own_root, "alice-again", "", now + 2)
            .unwrap();
    }

    // Flight 3: a perfectly valid complete for THIS session — refused, and
    // nothing pinned: the CAS ran against the admission-time epoch.
    let t = IntroTranscript {
        protocol_version: PROTOCOL_VERSION,
        token_version: TOKEN_VERSION,
        role: Role::Dialer,
        dialer_root: alice.own_root.clone(),
        responder_root: bob.own_root.clone(),
        dialer_tls_sha256: alice_tls.clone(),
        responder_tls_sha256: bob.cert.fingerprint.value.clone(),
        tls_exporter: URL_SAFE_NO_PAD.encode(exporter),
        nonce: nonce.clone(),
        key_binding_sha256: String::new(),
    };
    let material = build_intro_material(
        &t,
        "local",
        "alice",
        &alice.signed_card,
        &alice.keys,
        "2020-01-01T00:00:00Z",
        "2035-01-01T00:00:00Z",
        0,
    )
    .unwrap();
    let (code, _, _, close) = respond_introduction(
        &bob,
        &store_b,
        &pending,
        COMPLETE_PATH,
        "POST",
        INTRODUCTION_MEDIA_TYPE,
        "203.0.113.7",
        Some(&alice_tls),
        Some(&exporter),
        &serde_json::to_vec(&material).unwrap(),
        now + 3,
    );
    assert_eq!((code, close), (403, true), "stale handshake must not commit");
    assert!(store_b.lock().unwrap().peer_status("alice").unwrap().is_none());

    // The connection is terminal: another hello on it refuses too.
    let (code, _, _, close) = respond_introduction(
        &bob,
        &store_b,
        &pending,
        HELLO_PATH,
        "POST",
        INTRODUCTION_MEDIA_TYPE,
        "203.0.113.7",
        Some(&alice_tls),
        Some(&exporter),
        &serde_json::to_vec(&hello).unwrap(),
        now + 4,
    );
    assert_eq!((code, close), (403, true), "one instance per connection");
}

/// The public discovery surface (design §8.2): an ANONYMOUS client — no
/// certificate at all — can fetch `/.well-known/agent-card.json` and nothing
/// else; the served card is the signed, profile-valid one.
#[tokio::test]
async fn well_known_card_is_served_to_anonymous_clients_and_nothing_else_is() {
    use akson_transport::tls::discovery_client_config;
    use http_body_util::{BodyExt, Empty};
    use hyper_util::rt::TokioIo;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    let store_b = store();
    let port = serve_responder(identity("bob", 5), store_b.clone()).await;

    let connect = || async {
        let config = discovery_client_config().unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let tls = connector
            .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
            .await
            .unwrap();
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    };

    // The card is served, parses, and passes the same profile bar peers apply.
    let mut sender = connect().await;
    let req = hyper::Request::builder()
        .method("GET")
        .uri("/.well-known/agent-card.json")
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let card: akson_proto::v1::AgentCard = serde_json::from_slice(&body).unwrap();
    assert_eq!(card.name, "bob");
    akson_proto::profile::validate_agent_card(&card, &intro_profile()).unwrap();

    // The SAME anonymous client reaching for the work surface is refused.
    let mut sender = connect().await;
    let req = hyper::Request::builder()
        .method("POST")
        .uri("/a2a")
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 403, "anonymous A2A must refuse");
}
