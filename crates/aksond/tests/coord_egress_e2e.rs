//! The outbound coordination carrier, end to end and under attack (ADR-0016 §2).
//!
//! Every test here runs two independent endpoints over a **real TLS 1.3 mutual
//! handshake on a real socket**: A's `DaemonState` runs the real coordination
//! `dispatch`, and B's `ReceiveState`/`serve_receive` runs the real receive
//! server, with each side pinning the other's endpoint certificate exactly as
//! pairing left it. Nothing about the carriage is mocked, because a mock of a
//! transport proves nothing about a transport.
//!
//! The properties, and the way each is written to fail if its guard is removed
//! rather than to pass because the guard is spelled a certain way:
//!
//! 1. **Bytes that do not match the staged digest are refused.** The attacker is
//!    a *sender* that swaps the payload after building the envelope, and one
//!    that swaps the label the staged digest was taken over. B must refuse, and
//!    must record no arrival. The payload part is chosen by its media type and
//!    must be the only one of its kind, so neither its position nor its
//!    `filename` decides which bytes the envelope describes.
//! 2. **A dispatch whose send fails is recoverable and is not re-spendable.**
//!    The receipt is spent, the row is durable and not `sent`, a retry under the
//!    same execution key re-carries and succeeds, and a *different* key stays
//!    `409 consent-spent` throughout. Two ways for a send to fail are covered
//!    and they are not the same case: the recipient is *unreachable* (nothing
//!    ever arrives), and the recipient **admits the disclosure but the
//!    acknowledgement is lost** — the one that only works if the re-sent body is
//!    byte-identical and the recipient committed its §9.2 record before
//!    answering. A `200` that does not echo this staged digest is not an
//!    acknowledgement either.
//! 3. **A peer that is not the pinned recipient is refused.** Two directions: a
//!    sender whose pinned certificate does not match refuses to hand the bytes
//!    over at all, and a receiver that is not the addressee refuses an envelope
//!    that reached it over a perfectly good authenticated channel.
//! 4. **Carrying bytes did not make coord an admin.** Everything a driver could
//!    not reach before it could send is still unreachable.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use akson_contract::Identity;
use akson_crypto::cert::{self_signed_endpoint, EndpointCert};
use akson_crypto::identity::{Fingerprint, FingerprintKind, PeerIdentity};
use akson_crypto::purpose::KeyPurpose;
use akson_store::envelope::Kek;
use akson_store::{ExternalCheckpoint, Store, StoredPeer};
use akson_transport::tls::bootstrap_server_config;
use aksond::{
    serve_receive, ControlRequest, DaemonConfig, DaemonState, IdentityKeys, ReceiveState,
    StorePeerResolver,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const NOW: i64 = 1_800_000_000;
const TASK_TYPE: &str = "https://byom.example/task/exchange/v1";
const PAYLOAD: &[u8] = b"the coordination payload the operator consented to";

fn checkpoint() -> ExternalCheckpoint {
    ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    }
}

fn store(seed: u8) -> Store {
    Store::open_in_memory(&Kek::from_bytes([seed; 32]), checkpoint()).unwrap()
}

/// One endpoint: its master key material and the stable self-signed endpoint
/// certificate its peer pins.
struct Endpoint {
    keys: IdentityKeys,
    cert: EndpointCert,
    root: String,
    agent: String,
}

impl Endpoint {
    fn new(agent: &str, master: u8) -> Self {
        let keys = IdentityKeys::from_master([master; 32]);
        let cert = self_signed_endpoint(
            &keys.purpose_key(KeyPurpose::TlsEndpoint),
            agent,
            Duration::from_secs(3600),
        )
        .unwrap();
        let root = keys
            .purpose_key(KeyPurpose::AgentCard)
            .verifying()
            .to_jwk()
            .thumbprint();
        Self {
            keys,
            cert,
            root,
            agent: agent.to_owned(),
        }
    }

    fn identity(&self) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: self.agent.clone(),
            root: self.root.clone(),
        }
    }
}

/// Pins `peer` in `store` the way an introduction leaves it: the §8.1 tuple keyed
/// by the peer's root, its endpoint URL and certificate fingerprint, plus the
/// contract-proposal key row the receive resolver admits connections by.
fn pin_peer(store: &Store, label: &str, peer: &Endpoint, endpoint_url: &str) {
    store
        .add_peer_import(&peer.root, label, "127.0.0.1:0", NOW)
        .unwrap();
    store
        .put_peer(&StoredPeer {
            identity: PeerIdentity {
                issuer: Some("iss".to_owned()),
                agent_id: peer.agent.clone(),
                workload_id: None,
                endpoint_id: endpoint_url.to_owned(),
                tls_cert: peer.cert.fingerprint.clone(),
                agent_card_key: Fingerprint {
                    kind: FingerprintKind::Jwk7638,
                    value: peer.root.clone(),
                },
                key_bindings: vec![],
                security_projection_digest: Fingerprint::json_sha256(b"{\"p\":1}"),
                full_card_digest: Fingerprint::json_sha256(b"{\"c\":1}"),
            },
            local_note: String::new(),
        })
        .unwrap();
    store
        .put_peer_key(
            &peer.cert.fingerprint.value,
            "contract-proposal",
            &peer.agent,
            "iss",
            &peer
                .keys
                .purpose_key(KeyPurpose::ContractProposal)
                .verifying()
                .to_public_bytes(),
            &peer.root,
            NOW,
        )
        .unwrap();
}

/// Serves `endpoint`'s receive listener over `store` and returns its address.
async fn spawn_receive(endpoint: &Endpoint, store: Arc<Mutex<Store>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(ReceiveState::new(
        store,
        StorePeerResolver,
        endpoint.identity(),
        BTreeSet::new(),
        format!("https://127.0.0.1:{}/a2a", addr.port()),
    ));
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(
            &endpoint.keys.purpose_key(KeyPurpose::TlsEndpoint),
            &endpoint.cert,
        )
        .unwrap(),
    ));
    tokio::spawn(serve_receive(listener, acceptor, state));
    addr
}

/// A's daemon, over a store that already pins B at `b_url` under `label`.
fn sender_daemon(a: &Endpoint, b: &Endpoint, label: &str, b_url: &str) -> Arc<DaemonState> {
    let a_store = store(1);
    pin_peer(&a_store, label, b, b_url);
    let config = DaemonConfig {
        data_dir: std::env::temp_dir().join("aksond-coord-egress-unused"),
        local_performer: a.identity(),
        interface_url: "https://127.0.0.1:1/a2a".to_owned(),
        receive_addr: None,
        worker_command: None,
        worker_exec: None,
        on_task: None,
    };
    Arc::new(DaemonState::from_parts(
        a_store,
        a.keys.clone(),
        a.cert.clone(),
        config,
    ))
}

/// Stages `payload` for `label` on coord and mints its consent on admin.
fn staged_and_consented(state: &DaemonState, label: &str, payload: &[u8]) -> (String, String) {
    let staged = state
        .dispatch(&ControlRequest::Stage {
            task_type: TASK_TYPE.to_owned(),
            performer: label.to_owned(),
            payload_base64: STANDARD.encode(payload),
        })
        .unwrap();
    let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();
    let consent = state
        .dispatch(&ControlRequest::StageConsent {
            stage_ref: stage_ref.clone(),
        })
        .unwrap();
    (
        stage_ref,
        consent["consent_receipt"].as_str().unwrap().to_owned(),
    )
}

fn dispatch_req(stage_ref: &str, receipt: &str, key: &str) -> ControlRequest {
    ControlRequest::Dispatch {
        stage_ref: stage_ref.to_owned(),
        consent_receipt: receipt.to_owned(),
        execution_key: key.to_owned(),
    }
}

/// `DaemonState::dispatch` blocks on its own runtime; run it off the async worker
/// so B's receive server can serve the connection it opens.
async fn call(
    state: &Arc<DaemonState>,
    req: ControlRequest,
) -> Result<serde_json::Value, aksond::Problem> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || state.dispatch(&req))
        .await
        .unwrap()
}

fn coord_events(store: &Arc<Mutex<Store>>, kind: &str) -> Vec<serde_json::Value> {
    store
        .lock()
        .unwrap()
        .read_coord_events(0, 200)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.detail)
        .collect()
}

// ---------------------------------------------------------------------------
// The happy path first, so every refusal below is a refusal of something that
// would otherwise have worked.
// ---------------------------------------------------------------------------

/// One consented disclosure crosses a real mutual-TLS connection, is verified
/// digest-and-sender at the far end, and comes back `sent`.
#[tokio::test]
async fn a_consented_dispatch_reaches_the_pinned_recipient_and_is_recorded_sent() {
    let a = Endpoint::new("sender", 10);
    let b = Endpoint::new("recipient", 20);

    let b_store = Arc::new(Mutex::new(store(2)));
    pin_peer(
        &b_store.lock().unwrap(),
        "sender",
        &a,
        "https://127.0.0.1:1/a2a",
    );
    let b_addr = spawn_receive(&b, b_store.clone()).await;

    let a_state = sender_daemon(
        &a,
        &b,
        "partner",
        &format!("https://127.0.0.1:{}/a2a", b_addr.port()),
    );
    let (stage_ref, receipt) = staged_and_consented(&a_state, "partner", PAYLOAD);

    let sent = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-1"))
        .await
        .unwrap();
    assert_eq!(sent["egress"]["state"], "sent", "{sent}");
    assert_eq!(sent["egress"]["retryable"], false);
    assert_eq!(sent["consent_spent"], true);
    assert_eq!(sent["replayed"], false);

    // B recorded a verified arrival — the digests, the sender's root, and the
    // consent receipt that authorized it.
    let arrivals = coord_events(&b_store, "dispatch_received");
    assert_eq!(arrivals.len(), 1, "one arrival: {arrivals:?}");
    assert_eq!(arrivals[0]["staged_digest"], sent["staged_digest"]);
    assert_eq!(arrivals[0]["payload_sha256"], sent["payload_sha256"]);
    assert_eq!(arrivals[0]["sender_root"], a.root);
    assert_eq!(arrivals[0]["byte_length"], PAYLOAD.len());

    // ARRIVAL IS NOT EXECUTION: verified bytes created no task, no attempt, and
    // nothing for an operator to approve.
    {
        let b = b_store.lock().unwrap();
        assert!(b.list_submitted_tasks().unwrap().is_empty());
        assert!(b.list_outcomes().unwrap().is_empty());
    }

    // `task_status` now tells the truth in both halves: carriage acknowledged,
    // and the contract-shaped fields permanently null because this is not a
    // contract.
    let status = call(
        &a_state,
        ControlRequest::TaskStatus {
            task_id: stage_ref.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(status["egress"]["state"], "sent");
    assert_eq!(status["verification"]["state"], "acknowledged");
    assert_eq!(
        status["verification"]["result_manifest_digest"],
        serde_json::Value::Null
    );
    assert_eq!(
        status["verification"]["outcome_state"],
        serde_json::Value::Null
    );

    // And the handshake no longer claims a missing part.
    let who = call(&a_state, ControlRequest::CoordWhoAmI).await.unwrap();
    assert_eq!(who["partial"], serde_json::json!([]));
}

// ---------------------------------------------------------------------------
// 1. Bytes that do not match the staged digest must be refused.
// ---------------------------------------------------------------------------

/// The adversary is a **sender** that builds a well-formed envelope for a digest
/// the operator consented to and then puts different bytes beside it — the exact
/// substitution the whole consent-by-digest design exists to stop. It reaches B
/// over a genuinely authenticated, correctly pinned mTLS connection, so nothing
/// but the digest check can catch it.
///
/// Written against the defect: it asserts B *admits nothing*, so deleting the
/// digest comparison in `coord_egress::verify` turns it red.
#[tokio::test]
async fn bytes_that_do_not_match_the_staged_digest_are_refused() {
    let a = Endpoint::new("sender", 11);
    let b = Endpoint::new("recipient", 21);

    let b_store = Arc::new(Mutex::new(store(3)));
    pin_peer(
        &b_store.lock().unwrap(),
        "sender",
        &a,
        "https://127.0.0.1:1/a2a",
    );
    let b_addr = spawn_receive(&b, b_store.clone()).await;
    let b_url = format!("https://127.0.0.1:{}/a2a", b_addr.port());

    // The envelope A would legitimately have sent, for the bytes the operator saw.
    let envelope = serde_json::json!({
        "schema_version": 1,
        "protocol": "akson_byom_exchange_v1",
        "task_type": TASK_TYPE,
        "recipient_label": "partner",
        "recipient_root": b.root,
        "sender_root": a.root,
        "payload_sha256": hex_sha256(PAYLOAD),
        "staged_digest": staged_digest(PAYLOAD, "partner", TASK_TYPE),
        "consent_receipt": "consent-fixture",
    });

    // (a) The consented envelope, different bytes.
    let (status, _) = post_coord(
        &a,
        &b,
        &b_url,
        &envelope,
        b"BYTES THE OPERATOR NEVER SAW",
        "msg-swap",
    )
    .await;
    assert_eq!(status, 422, "substituted payload bytes must be refused");

    // (b) The right bytes, but the digest recomputation is fed a different
    //     recipient label than the one the staged digest was taken over. The
    //     payload hash still matches; only the ADR-0016 §4 derivation catches it.
    let mut relabelled = envelope.clone();
    relabelled["recipient_label"] = serde_json::json!("elsewhere");
    let (status, _) = post_coord(&a, &b, &b_url, &relabelled, PAYLOAD, "msg-relabel").await;
    assert_eq!(
        status, 422,
        "a staged digest that does not describe these bytes must be refused"
    );

    // (c) A contract term smuggled into the envelope. The operator's risk card
    //     named no objective, so an envelope carrying one is authorizing more
    //     than was consented to — and the receiver must refuse it rather than
    //     admit-and-ignore, because "ignored today" is a field someone reads
    //     tomorrow. `additionalProperties: false` is the guard; this is the test
    //     that it is actually enforced at the far end and not just published.
    let mut smuggled = envelope.clone();
    smuggled["objective"] = serde_json::json!("review this diff by Friday");
    let (status, _) = post_coord(&a, &b, &b_url, &smuggled, PAYLOAD, "msg-smuggle").await;
    assert_eq!(
        status, 422,
        "a contract term must not ride a coordination envelope"
    );

    // (d) And the control: untouched, the very same machinery admits it.
    let (status, body) = post_coord(&a, &b, &b_url, &envelope, PAYLOAD, "msg-clean").await;
    assert_eq!(
        status, 200,
        "the unmodified envelope must still be admitted"
    );
    let ack: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ack["staged_digest"], envelope["staged_digest"]);

    // Exactly one arrival — the clean one — and two refusals recorded with reasons.
    let arrivals = coord_events(&b_store, "dispatch_received");
    assert_eq!(arrivals.len(), 1, "only the untampered envelope arrived");
    let refusals = coord_events(&b_store, "dispatch_refused");
    let reasons: Vec<&str> = refusals
        .iter()
        .map(|r| r["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        vec!["payload-digest", "staged-digest", "malformed-envelope"]
    );
}

// ---------------------------------------------------------------------------
// 2. A failed send must be recoverable, and must never re-spend consent.
// ---------------------------------------------------------------------------

/// The recipient is unreachable when the dispatch commits, so the bytes cannot
/// leave. What must be true afterwards is everything at once:
///
/// - the receipt is spent and there IS a record of it (never spent-with-no-record);
/// - the record is durable and says `failed`, not `sent`;
/// - a **different** execution key is still `409 consent-spent`;
/// - the same execution key re-carries once the recipient is up, and still
///   spends nothing — one dispatch row, one `dispatched` event, from first
///   failure to eventual success.
#[tokio::test]
async fn a_dispatch_whose_send_fails_is_recoverable_and_never_respends_consent() {
    let a = Endpoint::new("sender", 12);
    let b = Endpoint::new("recipient", 22);

    // Reserve a port, then drop the listener: the address is well-formed and
    // pinned, and nothing is listening on it.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let b_url = format!("https://127.0.0.1:{dead_port}/a2a");

    let a_state = sender_daemon(&a, &b, "partner", &b_url);
    let (stage_ref, receipt) = staged_and_consented(&a_state, "partner", PAYLOAD);

    let failed = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-1"))
        .await
        .unwrap();
    // The disclosure decision committed even though the bytes did not move.
    assert_eq!(failed["consent_spent"], true);
    assert_eq!(failed["egress"]["state"], "failed");
    assert_eq!(failed["egress"]["retryable"], true);
    let dispatch_receipt = failed["dispatch_receipt"].as_str().unwrap().to_owned();

    // Spent WITH a record: both halves, read from the durable store.
    {
        let store = a_state.store();
        let store = store.lock().unwrap();
        assert!(
            store.unconsumed_consent(&stage_ref).unwrap().is_none(),
            "the receipt is spent"
        );
        let row = store.coord_dispatch(&dispatch_receipt).unwrap().unwrap();
        assert_eq!(row.receipt_id, receipt, "and the record names it");
        assert_ne!(row.egress_state, "sent");
        // The crash-recovery worklist can see it.
        let unsent = store.unsent_dispatches(10).unwrap();
        assert_eq!(unsent.len(), 1);
        assert_eq!(unsent[0].dispatch_receipt, dispatch_receipt);
    }

    // A DIFFERENT key on the spent receipt: still refused, failure or not.
    let replay = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-2"))
        .await
        .unwrap_err();
    assert_eq!(replay.status, 409);
    assert_eq!(replay.type_, "urn:akson:error:consent-spent");

    // Now the recipient comes up on the very port that was refused, and the
    // driver retries under the SAME key.
    let b_store = Arc::new(Mutex::new(store(4)));
    pin_peer(
        &b_store.lock().unwrap(),
        "sender",
        &a,
        "https://127.0.0.1:1/a2a",
    );
    let listener = TcpListener::bind(("127.0.0.1", dead_port)).await.unwrap();
    let state = Arc::new(ReceiveState::new(
        b_store.clone(),
        StorePeerResolver,
        b.identity(),
        BTreeSet::new(),
        b_url.clone(),
    ));
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&b.keys.purpose_key(KeyPurpose::TlsEndpoint), &b.cert).unwrap(),
    ));
    tokio::spawn(serve_receive(listener, acceptor, state));

    let recovered = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-1"))
        .await
        .unwrap();
    assert_eq!(recovered["egress"]["state"], "sent", "{recovered}");
    assert_eq!(recovered["replayed"], true, "a retry, not a new dispatch");
    assert_eq!(recovered["dispatch_receipt"], dispatch_receipt);
    assert_eq!(recovered["dispatched_at"], failed["dispatched_at"]);

    // Nothing was spent twice, and there is still exactly ONE dispatch.
    {
        let store = a_state.store();
        let store = store.lock().unwrap();
        assert!(store.unsent_dispatches(10).unwrap().is_empty());
        let dispatched = store
            .read_coord_events(0, 200)
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "dispatched")
            .count();
        assert_eq!(
            dispatched, 1,
            "one dispatch across a failure and a recovery"
        );
    }
    assert_eq!(coord_events(&b_store, "dispatch_received").len(), 1);

    // And a different key is STILL refused after the recovery succeeded.
    let replay = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-3"))
        .await
        .unwrap_err();
    assert_eq!(replay.type_, "urn:akson:error:consent-spent");
}

/// **The disclosure lands; the acknowledgement is lost.** This is the case V23,
/// `pending`, and the retry exist for, and the one a test that fails at TCP
/// connect never reaches: B genuinely receives the message, verifies it, records
/// the arrival and its §9.2 idempotency record, and *then* the connection dies
/// before A can read the 200.
///
/// Everything that must then be true:
///
/// - A records the attempt as not-acknowledged and keeps it retryable;
/// - B has admitted the disclosure exactly once;
/// - the retry under the same execution key is recognised as the **duplicate it
///   is** and replays B's stored acknowledgement — so A ends `sent` and
///   `task_status.verification` says `acknowledged`;
/// - and B still shows exactly one arrival, not two.
///
/// Two guards hold this up and neither had an oracle before: the body must be
/// byte-stable (a `HashMap`-backed `Part::Data` re-serialised differently every
/// time, so the retry arrived as a *different* body under the same Message id
/// and was refused `409 conflict` forever), and the recipient must commit that
/// idempotency record before answering.
#[tokio::test]
async fn a_dispatch_whose_acknowledgement_is_lost_is_replayed_not_conflicted() {
    let a = Endpoint::new("sender", 16);
    let b = Endpoint::new("recipient", 26);

    let b_store = Arc::new(Mutex::new(store(8)));
    pin_peer(
        &b_store.lock().unwrap(),
        "sender",
        &a,
        "https://127.0.0.1:1/a2a",
    );

    // One listener, one port, two servers over the same store: first the one
    // that swallows its own reply, then the real one.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let b_url = format!("https://127.0.0.1:{port}/a2a");
    let silent = tokio::spawn(silent_receive_once(
        b.keys.clone(),
        b.cert.clone(),
        b.identity(),
        a.identity(),
        a.keys.purpose_key(KeyPurpose::ContractProposal).verifying(),
        b_store.clone(),
        b_url.clone(),
        listener,
    ));

    let a_state = sender_daemon(&a, &b, "partner", &b_url);
    let (stage_ref, receipt) = staged_and_consented(&a_state, "partner", PAYLOAD);

    let lost = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-1"))
        .await
        .unwrap();
    silent.await.unwrap();

    // A has no acknowledgement, and says so rather than guessing.
    assert_ne!(lost["egress"]["state"], "sent", "{lost}");
    assert_eq!(lost["egress"]["retryable"], true);
    assert_eq!(lost["consent_spent"], true);

    // B, however, admitted it — once — and kept the idempotency record that
    // makes the retry safe.
    assert_eq!(
        coord_events(&b_store, "dispatch_received").len(),
        1,
        "the disclosure genuinely landed"
    );

    // The real receiver comes up on the same port; the driver retries the SAME
    // execution key, which spends nothing.
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let state = Arc::new(ReceiveState::new(
        b_store.clone(),
        StorePeerResolver,
        b.identity(),
        BTreeSet::new(),
        b_url.clone(),
    ));
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&b.keys.purpose_key(KeyPurpose::TlsEndpoint), &b.cert).unwrap(),
    ));
    tokio::spawn(serve_receive(listener, acceptor, state));

    let recovered = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-1"))
        .await
        .unwrap();
    assert_eq!(
        recovered["egress"]["state"], "sent",
        "a re-send of the same dispatch must replay the recipient's acknowledgement, not conflict: {recovered}"
    );
    assert_eq!(recovered["replayed"], true);
    assert_eq!(recovered["dispatch_receipt"], lost["dispatch_receipt"]);

    // Deduplicated at the recipient: still ONE arrival, and one dispatch here.
    assert_eq!(
        coord_events(&b_store, "dispatch_received").len(),
        1,
        "the retry must not be admitted a second time"
    );
    {
        let store = a_state.store();
        let store = store.lock().unwrap();
        assert!(store.unsent_dispatches(10).unwrap().is_empty());
        assert_eq!(
            store
                .read_coord_events(0, 200)
                .unwrap()
                .into_iter()
                .filter(|e| e.kind == "dispatched")
                .count(),
            1
        );
    }

    // And the driver's status read now tells the truth about a disclosure that
    // did arrive — the thing that used to stay `unacknowledged` permanently.
    let status = call(
        &a_state,
        ControlRequest::TaskStatus {
            task_id: stage_ref.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(status["verification"]["state"], "acknowledged");
}

/// **A 200 is not an acknowledgement.** The recipient answers, politely and
/// successfully, without echoing the staged digest it was sent. That is no
/// evidence that *this* disclosure landed, so carriage must record `failed` and
/// `task_status` must keep saying `unacknowledged` — a terminal `sent` here
/// would be the sender inventing a delivery from a peer's `200`.
#[tokio::test]
async fn a_recipient_that_does_not_echo_the_staged_digest_is_not_recorded_sent() {
    let a = Endpoint::new("sender", 17);
    let b = Endpoint::new("recipient", 27);

    // A server presenting B's real, pinned certificate — the channel is
    // perfect; only the answer is wrong.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let b_url = format!("https://127.0.0.1:{port}/a2a");
    tokio::spawn(always_200(
        b.keys.clone(),
        b.cert.clone(),
        serde_json::json!({
            "coordination": "acknowledged",
            "protocol": "akson_byom_exchange_v1",
            "staged_digest": staged_digest(b"some other disclosure", "partner", TASK_TYPE),
            "recipient_root": b.root,
        })
        .to_string(),
        listener,
    ));

    let a_state = sender_daemon(&a, &b, "partner", &b_url);
    let (stage_ref, receipt) = staged_and_consented(&a_state, "partner", PAYLOAD);
    let result = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-1"))
        .await
        .unwrap();
    assert_eq!(
        result["egress"]["state"], "failed",
        "a 200 that acknowledges another digest is not evidence this one landed: {result}"
    );
    assert_eq!(result["egress"]["retryable"], true);

    let status = call(
        &a_state,
        ControlRequest::TaskStatus {
            task_id: stage_ref.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(status["verification"]["state"], "unacknowledged");
}

/// A staging with nowhere to go must not burn the operator's consent. The
/// refusal has to come *before* the spend, so the receipt is still live
/// afterwards and the operator can fix the relationship instead of re-consenting.
#[tokio::test]
async fn a_dispatch_that_cannot_leave_does_not_spend_the_receipt() {
    let a = Endpoint::new("sender", 13);
    let b = Endpoint::new("recipient", 23);
    let a_state = sender_daemon(&a, &b, "partner", "https://127.0.0.1:1/a2a");

    // An unrouted staging: the operator's card said "no named recipient".
    let staged = a_state
        .dispatch(&ControlRequest::Stage {
            task_type: TASK_TYPE.to_owned(),
            performer: String::new(),
            payload_base64: STANDARD.encode(PAYLOAD),
        })
        .unwrap();
    let unrouted_ref = staged["stage_ref"].as_str().unwrap().to_owned();
    let consent = a_state
        .dispatch(&ControlRequest::StageConsent {
            stage_ref: unrouted_ref.clone(),
        })
        .unwrap();
    let unrouted_receipt = consent["consent_receipt"].as_str().unwrap().to_owned();

    let refused = call(
        &a_state,
        dispatch_req(&unrouted_ref, &unrouted_receipt, "exec-1"),
    )
    .await
    .unwrap_err();
    assert_eq!(refused.status, 409);
    assert_eq!(refused.type_, "urn:akson:error:unroutable-recipient");

    // The receipt survived, and no dispatch row exists to have spent it.
    {
        let store = a_state.store();
        let store = store.lock().unwrap();
        assert!(
            store.unconsumed_consent(&unrouted_ref).unwrap().is_some(),
            "an unroutable dispatch must not spend consent"
        );
        assert!(store.coord_dispatch(&unrouted_ref).unwrap().is_none());
        assert_eq!(
            store
                .staged_contract(&unrouted_ref)
                .unwrap()
                .unwrap()
                .status,
            "consented"
        );
    }

    // The same holds for a recipient that was imported but never introduced:
    // routable-looking, no pinned endpoint, no spend.
    {
        let store = a_state.store();
        let store = store.lock().unwrap();
        store
            .add_peer_import("root-never-introduced", "stranger", "127.0.0.1:1", NOW)
            .unwrap();
    }
    let (stranger_ref, stranger_receipt) = staged_and_consented(&a_state, "stranger", b"other");
    let refused = call(
        &a_state,
        dispatch_req(&stranger_ref, &stranger_receipt, "exec-2"),
    )
    .await
    .unwrap_err();
    assert_eq!(refused.type_, "urn:akson:error:unroutable-recipient");
    let store = a_state.store();
    let store = store.lock().unwrap();
    assert!(store.unconsumed_consent(&stranger_ref).unwrap().is_some());
}

// ---------------------------------------------------------------------------
// 3. A peer that is not the pinned recipient must be refused.
// ---------------------------------------------------------------------------

/// Two ways to reach the wrong peer, and both are closed.
///
/// (a) **The sender's pin does not match.** A's peer record for `partner` names
///     B's certificate; an impostor answers on that address instead. The TLS
///     handshake is pinned, so the bytes are never handed over — the dispatch
///     comes back `failed` with nothing sent.
///
/// (b) **The receiver is not the addressee.** A perfectly valid envelope for B
///     arrives at C over a channel C authenticated fine, because C also pins A.
///     `recipient_root` does not name C, so C refuses. This is the check the
///     transport cannot make for you, and removing it turns this red.
#[tokio::test]
async fn a_peer_that_is_not_the_pinned_recipient_is_refused() {
    let a = Endpoint::new("sender", 14);
    let b = Endpoint::new("recipient", 24);
    let impostor = Endpoint::new("impostor", 34);

    // (a) The impostor serves, presenting its OWN certificate.
    let imp_store = Arc::new(Mutex::new(store(5)));
    pin_peer(
        &imp_store.lock().unwrap(),
        "sender",
        &a,
        "https://127.0.0.1:1/a2a",
    );
    let imp_addr = spawn_receive(&impostor, imp_store.clone()).await;
    let imp_url = format!("https://127.0.0.1:{}/a2a", imp_addr.port());

    // A pins B's certificate but is pointed at the impostor's address.
    let a_state = sender_daemon(&a, &b, "partner", &imp_url);
    let (stage_ref, receipt) = staged_and_consented(&a_state, "partner", PAYLOAD);
    let result = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-1"))
        .await
        .unwrap();
    assert_eq!(
        result["egress"]["state"], "failed",
        "a certificate that is not the pinned one must not receive the disclosure"
    );
    assert!(coord_events(&imp_store, "dispatch_received").is_empty());
    assert!(
        coord_events(&imp_store, "dispatch_refused").is_empty(),
        "the impostor never saw a request at all — the handshake failed first"
    );

    // (b) A third endpoint that DOES pin A, receiving an envelope addressed to B.
    let c = Endpoint::new("elsewhere", 44);
    let c_store = Arc::new(Mutex::new(store(6)));
    pin_peer(
        &c_store.lock().unwrap(),
        "sender",
        &a,
        "https://127.0.0.1:1/a2a",
    );
    let c_addr = spawn_receive(&c, c_store.clone()).await;
    let c_url = format!("https://127.0.0.1:{}/a2a", c_addr.port());

    let for_b = serde_json::json!({
        "schema_version": 1,
        "protocol": "akson_byom_exchange_v1",
        "task_type": TASK_TYPE,
        "recipient_label": "partner",
        "recipient_root": b.root,
        "sender_root": a.root,
        "payload_sha256": hex_sha256(PAYLOAD),
        "staged_digest": staged_digest(PAYLOAD, "partner", TASK_TYPE),
        "consent_receipt": "consent-fixture",
    });
    let (status, _) = post_coord(&a, &c, &c_url, &for_b, PAYLOAD, "msg-misrouted").await;
    assert_eq!(
        status, 422,
        "an envelope addressed to another root must be refused"
    );

    // …and the same endpoint admits the same envelope once it IS the addressee,
    // so the refusal above is the recipient check and not something incidental.
    let mut for_c = for_b.clone();
    for_c["recipient_root"] = serde_json::json!(c.root);
    let (status, _) = post_coord(&a, &c, &c_url, &for_c, PAYLOAD, "msg-addressed").await;
    assert_eq!(status, 200);

    let reasons: Vec<String> = coord_events(&c_store, "dispatch_refused")
        .iter()
        .map(|r| r["reason"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(reasons, vec!["not-the-recipient"]);

    // A sender that lies about who it is fails the other half of the same check.
    let mut liar = for_c.clone();
    liar["sender_root"] = serde_json::json!(b.root);
    let (status, _) = post_coord(&a, &c, &c_url, &liar, PAYLOAD, "msg-liar").await;
    assert_eq!(
        status, 422,
        "a claimed sender that is not the pinned one must be refused"
    );
    let reasons: Vec<String> = coord_events(&c_store, "dispatch_refused")
        .iter()
        .map(|r| r["reason"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(reasons, vec!["not-the-recipient", "sender-mismatch"]);
}

/// **The payload part is named by its media type, and there must be exactly
/// one.** A raw part of some other type is not a coordination payload, and a
/// message carrying two candidates is ambiguous about which bytes its envelope
/// describes — so it is refused rather than resolved by taking whichever came
/// first. Neither position nor the part's `filename` decides anything.
#[tokio::test]
async fn a_payload_part_of_the_wrong_type_or_an_ambiguous_one_is_refused() {
    use akson_proto::v1::{part::Content, Part};

    let a = Endpoint::new("sender", 18);
    let b = Endpoint::new("recipient", 28);
    let b_store = Arc::new(Mutex::new(store(9)));
    pin_peer(
        &b_store.lock().unwrap(),
        "sender",
        &a,
        "https://127.0.0.1:1/a2a",
    );
    let b_addr = spawn_receive(&b, b_store.clone()).await;
    let b_url = format!("https://127.0.0.1:{}/a2a", b_addr.port());

    let envelope = serde_json::json!({
        "schema_version": 1,
        "protocol": "akson_byom_exchange_v1",
        "task_type": TASK_TYPE,
        "recipient_label": "partner",
        "recipient_root": b.root,
        "sender_root": a.root,
        "payload_sha256": hex_sha256(PAYLOAD),
        "staged_digest": staged_digest(PAYLOAD, "partner", TASK_TYPE),
        "consent_receipt": "consent-fixture",
    });
    let envelope_part = || Part {
        metadata: None,
        filename: String::new(),
        media_type: "application/vnd.akson-dev.coord-dispatch.v1+json".to_owned(),
        content: Some(Content::Data(
            serde_json::from_value(envelope.clone()).unwrap(),
        )),
    };
    let raw = |media_type: &str, filename: &str, bytes: &[u8]| Part {
        metadata: None,
        filename: filename.to_owned(),
        media_type: media_type.to_owned(),
        content: Some(Content::Raw(bytes.to_vec())),
    };

    // (a) The right bytes, under a media type that is not the payload's. The
    //     digest would match if the part were read at all; it must not be.
    let (status, _) = post_parts(
        &a,
        &b,
        &b_url,
        vec![envelope_part(), raw("text/plain", "", PAYLOAD)],
        "msg-mistyped",
    )
    .await;
    assert_eq!(status, 422, "a raw part of another type is not the payload");

    // (b) Two payload parts, the consented bytes first. Taking the first would
    //     admit this; ambiguity must be refused instead — and the part's
    //     `filename` naming the consented digest changes nothing, because
    //     nothing reads it.
    let (status, _) = post_parts(
        &a,
        &b,
        &b_url,
        vec![
            envelope_part(),
            raw("application/octet-stream", &hex_sha256(PAYLOAD), PAYLOAD),
            raw("application/octet-stream", "", b"a second candidate"),
        ],
        "msg-ambiguous",
    )
    .await;
    assert_eq!(
        status, 422,
        "two payload parts must not be resolved by order"
    );

    // (c) The control: one correctly typed part, and the same machinery admits it.
    let (status, _) = post_parts(
        &a,
        &b,
        &b_url,
        vec![
            envelope_part(),
            raw("application/octet-stream", "", PAYLOAD),
        ],
        "msg-well-formed",
    )
    .await;
    assert_eq!(status, 200);

    assert_eq!(coord_events(&b_store, "dispatch_received").len(), 1);
    let reasons: Vec<String> = coord_events(&b_store, "dispatch_refused")
        .iter()
        .map(|r| r["reason"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(reasons, vec!["payload-digest", "payload-digest"]);
}

// ---------------------------------------------------------------------------
// 4. Carrying bytes did not widen the surface.
// ---------------------------------------------------------------------------

/// Being able to put bytes on the wire is the largest capability this surface has
/// ever had, so this is where a boundary would quietly move. It has not: the
/// coordination identity still cannot mint the consent it spends, approve inbound
/// work, read a credential, send a task, or issue a work order — and the ops that
/// exist are still the eight of ADR-0016's registry.
#[tokio::test]
async fn a_carrying_coord_surface_still_cannot_reach_admin_authority() {
    use aksond::{authorize, ControlOp, Surface};

    let a = Endpoint::new("sender", 15);
    let b = Endpoint::new("recipient", 25);
    let b_store = Arc::new(Mutex::new(store(7)));
    pin_peer(
        &b_store.lock().unwrap(),
        "sender",
        &a,
        "https://127.0.0.1:1/a2a",
    );
    let b_addr = spawn_receive(&b, b_store.clone()).await;
    let a_state = sender_daemon(
        &a,
        &b,
        "partner",
        &format!("https://127.0.0.1:{}/a2a", b_addr.port()),
    );

    let (stage_ref, receipt) = staged_and_consented(&a_state, "partner", PAYLOAD);
    let sent = call(&a_state, dispatch_req(&stage_ref, &receipt, "exec-1"))
        .await
        .unwrap();
    assert_eq!(
        sent["egress"]["state"], "sent",
        "the carrier really works here"
    );

    // The gate, not the handler, is what keeps these off coord.
    for op in [
        ControlOp::StageConsent,
        ControlOp::ApproveContract,
        ControlOp::Processor,
        ControlOp::SendTask,
        ControlOp::IssueWorkOrder,
        ControlOp::TaskInspect,
        ControlOp::Pair,
        ControlOp::SignOutcome,
        ControlOp::Export,
    ] {
        assert!(
            authorize(Surface::Coord, op).is_err(),
            "{op:?} must not be reachable from coord"
        );
        authorize(Surface::Admin, op).unwrap();
    }

    // The recipient side gained nothing either: a verified disclosure created no
    // task to approve and no credential to read.
    let b = b_store.lock().unwrap();
    assert!(b.list_submitted_tasks().unwrap().is_empty());
    assert!(b.get_credential("p").unwrap().is_none());
}

// ---------------------------------------------------------------------------
// The attacker's tools: build and POST a coordination message by hand, so a test
// can send something the daemon would never build.
// ---------------------------------------------------------------------------

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// The ADR-0016 §4 staged digest, derived here independently of the daemon so a
/// test cannot agree with the implementation by sharing its bug.
fn staged_digest(payload: &[u8], performer: &str, task_type: &str) -> String {
    use sha2::{Digest, Sha256};
    let content = serde_json::json!({
        "payload_sha256": hex_sha256(payload),
        "performer": performer,
        "task_type": task_type,
    });
    hex::encode(Sha256::digest(
        akson_ext::jcs::canonical_bytes(&content).unwrap(),
    ))
}

/// POSTs a hand-built coordination message from `from` to `to` over real mutual
/// TLS, pinning `to`'s certificate. Returns (status, body).
async fn post_coord(
    from: &Endpoint,
    to: &Endpoint,
    url: &str,
    envelope: &serde_json::Value,
    payload: &[u8],
    message_id: &str,
) -> (u16, Vec<u8>) {
    use akson_proto::v1::{part::Content, Part};
    post_parts(
        from,
        to,
        url,
        vec![
            Part {
                metadata: None,
                filename: String::new(),
                media_type: "application/vnd.akson-dev.coord-dispatch.v1+json".to_owned(),
                content: Some(Content::Data(
                    serde_json::from_value(envelope.clone()).unwrap(),
                )),
            },
            Part {
                metadata: None,
                filename: String::new(),
                media_type: "application/octet-stream".to_owned(),
                content: Some(Content::Raw(payload.to_vec())),
            },
        ],
        message_id,
    )
    .await
}

/// The same, with the message's Parts chosen outright — so a test can send a
/// part list the daemon would never build.
async fn post_parts(
    from: &Endpoint,
    to: &Endpoint,
    url: &str,
    parts: Vec<akson_proto::v1::Part>,
    message_id: &str,
) -> (u16, Vec<u8>) {
    use akson_proto::v1::{Message, SendMessageRequest};
    let body = serde_json::to_vec(&SendMessageRequest {
        message: Some(Message {
            message_id: message_id.to_owned(),
            context_id: "ctx-coord".to_owned(),
            parts,
            ..Default::default()
        }),
        ..Default::default()
    })
    .unwrap();
    aksond::post_a2a(
        &from.keys.purpose_key(KeyPurpose::TlsEndpoint),
        &from.cert,
        url,
        &to.cert.fingerprint.value,
        &body,
    )
    .await
    .unwrap()
}

/// A recipient that does everything the real one does — real mutual TLS, the
/// real [`aksond::handle_receive`], the real durable commit — and then **drops
/// the connection instead of answering**. That is a lost acknowledgement: the
/// disclosure landed and is admitted; the sender simply never learns it.
///
/// It serves exactly one connection and returns, so the port is free for the
/// real receiver to take over.
#[allow(clippy::too_many_arguments)]
async fn silent_receive_once(
    keys: IdentityKeys,
    cert: EndpointCert,
    local: Identity,
    peer: Identity,
    peer_proposal_key: akson_crypto::keypair::PurposeVerifyingKey,
    store: Arc<Mutex<Store>>,
    interface_url: String,
    listener: TcpListener,
) {
    use tokio::io::AsyncReadExt;

    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&keys.purpose_key(KeyPurpose::TlsEndpoint), &cert).unwrap(),
    ));
    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();

    // Read the request head, then exactly Content-Length bytes of body.
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = tls.read(&mut chunk).await.unwrap();
        assert!(n > 0, "the sender closed before sending a request");
        raw.extend_from_slice(&chunk[..n]);
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8(raw[..head_end].to_vec()).unwrap();
    let header = |name: &str| -> Option<String> {
        head.lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_owned())
    };
    let length: usize = header("content-length").unwrap().parse().unwrap();
    while raw.len() < head_end + length {
        let n = tls.read(&mut chunk).await.unwrap();
        assert!(n > 0, "the sender closed mid-body");
        raw.extend_from_slice(&chunk[..n]);
    }
    let body = raw[head_end..head_end + length].to_vec();

    // Exactly what the real server extracts, so the §9.2 covered values match.
    let activated: Vec<String> = header("a2a-extensions")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_owned())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let content_type = header("content-type").unwrap_or_default();
    let a2a_version = header("a2a-version");
    let content_digest = header("content-digest");

    {
        let store = store.lock().unwrap();
        let config = aksond::ReceiveConfig {
            local_performer: &local,
            requester_origin: &peer,
            proposal_key: &peer_proposal_key,
            required_extensions: &BTreeSet::new(),
            interface_url: &interface_url,
            outcome_key: None,
            performer_task_result_key: None,
        };
        let req = aksond::HttpRequest {
            method: "POST",
            content_type: &content_type,
            a2a_version: a2a_version.as_deref(),
            content_digest: content_digest.as_deref(),
            activated_extensions: &activated,
            tenant: None,
            peer: &peer.root,
            body: &body,
        };
        let response = aksond::handle_receive(&store, &config, &req, NOW).unwrap();
        assert_eq!(
            response.status, 200,
            "the disclosure must genuinely be admitted before the reply is lost"
        );
    }
    // …and the reply never leaves. The connection closes here.
    drop(tls);
}

/// A server that presents `cert` and answers every request `200` with `body`,
/// whatever was asked. Used to prove the sender does not take a bare `200` for
/// an acknowledgement of its own disclosure.
async fn always_200(keys: IdentityKeys, cert: EndpointCert, body: String, listener: TcpListener) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&keys.purpose_key(KeyPurpose::TlsEndpoint), &cert).unwrap(),
    ));
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        let body = body.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            // Drain until the request head is complete; the body is irrelevant
            // to the point being made.
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let Ok(n) = tls.read(&mut chunk).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                raw.extend_from_slice(&chunk[..n]);
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/a2a+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = tls.write_all(response.as_bytes()).await;
            let _ = tls.flush().await;
        });
    }
}
