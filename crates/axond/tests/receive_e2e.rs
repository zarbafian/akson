//! End-to-end over real mutual TLS: the whole task exchange, up to the full
//! two-daemon round trip (design §9.1, §10.2, §12.3, §14.5).
//!
//! These drive the same receive server and the same [`DaemonState::dispatch`] the
//! live daemon runs — a TLS 1.3 mutual handshake, the client leaf-cert fingerprint
//! captured and resolved against the store's peer records via [`StorePeerResolver`],
//! over a real socket. The capstone (`two_daemons_run_the_whole_task_round_trip`)
//! wires two independent daemons together: A sends a task → B receives, approves,
//! completes, and delivers → A verifies the result and signs its outcome.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axon_contract::{sign_proposal, Identity};
use axon_crypto::cert::{self_signed_endpoint, EndpointCert};
use axon_crypto::keypair::PurposeKey;
use axon_crypto::purpose::KeyPurpose;
use axon_evidence::{ManifestHeader, Outcome, OutcomeState, OutputEntry, ResultManifest};
use axon_ext::dsse::Envelope;
use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
use axon_proto::v1::{part::Content, Message, Part, SendMessageRequest};
use axon_store::delivery::content_digest;
use axon_store::envelope::Kek;
use axon_store::SentRequest;
use axon_store::{ExternalCheckpoint, Store};
use axon_transport::tls::{bootstrap_server_config, client_config};
use axond::{
    serve_receive, ControlRequest, DaemonConfig, DaemonState, Deliverable, IdentityKeys,
    OutputKind, ReceiveState, ResultOutput, ResultSubmission, StorePeerResolver, TaskInput,
    TaskSpec,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const TEXT: &str = "review this file";
const NOW: i64 = 1_800_000_000; // within [2026, 2030)

fn ident(agent: &str) -> Identity {
    Identity {
        issuer: "iss".to_owned(),
        agent: agent.to_owned(),
    }
}

/// The peer's signed A2A `SendMessageRequest` bytes: a DSSE proposal Part plus the
/// referenced worker-input Part, signed by `proposal_key`.
fn send_message_body(proposal_key: &PurposeKey) -> Vec<u8> {
    let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
    let value = json!({
        "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
        "revision": 0, "task_type": "https://axon.invalid/task/code-review/v1",
        "message_id": "msg-1",
        "requester": {"issuer": "iss", "agent": "requester"},
        "performer": {"issuer": "iss", "agent": "performer"}, "objective": "o",
        "inputs": [{
            "id": "diff", "message_id": "msg-1", "part_index": 1, "kind": "text",
            "media_type": "text/plain", "charset": "utf-8", "canonical_rule": "utf8-exact",
            "byte_length": TEXT.len(), "sha256": sha,
            "worker_visible": true, "processor_visible": false
        }],
        "deliverables": [{"role": "r", "media_type": "text/plain"}],
        "evidence_slots": [], "requested_capabilities": ["respond", "read_supplied_inputs"],
        "processor_constraints": {"disclosure": "none"},
        "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
        "result_recipient": "request-origin",
        "created_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"
    });
    let payload = axon_ext::jcs::canonical_bytes(&value).unwrap();
    let env = sign_proposal(&payload, proposal_key).unwrap();
    let envelope_part = Part {
        metadata: None,
        filename: String::new(),
        media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
        content: Some(Content::Data(
            serde_json::from_value(serde_json::to_value(&env).unwrap()).unwrap(),
        )),
    };
    let text_part = Part {
        metadata: None,
        filename: String::new(),
        media_type: "text/plain".to_owned(),
        content: Some(Content::Text(TEXT.to_owned())),
    };
    let message = Message {
        message_id: "msg-1".to_owned(),
        context_id: "ctx-1".to_owned(),
        parts: vec![envelope_part, text_part],
        ..Default::default()
    };
    serde_json::to_vec(&SendMessageRequest {
        message: Some(message),
        ..Default::default()
    })
    .unwrap()
}

/// Binds an mTLS receive server over `store` on an ephemeral port and returns its
/// address. The acceptor accepts any client cert; the resolver pins it.
async fn spawn_receive(
    store: Arc<Mutex<Store>>,
    server_tls_key: &PurposeKey,
    server_cert: &EndpointCert,
) -> SocketAddr {
    let receive_state = Arc::new(ReceiveState::new(
        store,
        StorePeerResolver,
        ident("performer"),
        BTreeSet::new(),
        "https://local/a2a".to_owned(),
    ));
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(server_tls_key, server_cert).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_receive(listener, acceptor, receive_state));
    addr
}

/// Connects as the peer (presenting `peer_cert`, pinning `server_cert`), POSTs the
/// signed proposal, and returns (HTTP status, response body).
async fn post_proposal(
    addr: SocketAddr,
    peer_tls_key: &PurposeKey,
    peer_cert: &EndpointCert,
    server_cert: &EndpointCert,
    proposal_key: &PurposeKey,
) -> (u16, Vec<u8>) {
    post_body(
        addr,
        peer_tls_key,
        peer_cert,
        server_cert,
        send_message_body(proposal_key),
    )
    .await
}

/// POSTs an arbitrary A2A body over a fresh pinned mTLS connection.
async fn post_body(
    addr: SocketAddr,
    peer_tls_key: &PurposeKey,
    peer_cert: &EndpointCert,
    server_cert: &EndpointCert,
    body: Vec<u8>,
) -> (u16, Vec<u8>) {
    let client_cfg = client_config(peer_tls_key, peer_cert, &server_cert.fingerprint).unwrap();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    // The pinned verifier checks the fingerprint, not the name.
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();

    let digest = content_digest(&body);
    let request = format!(
        "POST /a2a HTTP/1.1\r\nHost: local\r\nContent-Type: application/a2a+json\r\n\
         a2a-version: 1.0\r\ncontent-digest: {digest}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.write_all(&body).await.unwrap();
    tls.flush().await.unwrap();

    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await.unwrap();
    split_response(&raw)
}

/// Reads an HTTP/1.1 response (the request set `Connection: close`, so read to EOF)
/// into (status code, body bytes).
fn split_response(raw: &[u8]) -> (u16, Vec<u8>) {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers/body separator");
    let head = String::from_utf8_lossy(&raw[..sep]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status code");
    (status, raw[sep + 4..].to_vec())
}

fn in_memory_store() -> Store {
    let cp = ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    };
    Store::open_in_memory(&Kek::from_bytes([9u8; 32]), cp).unwrap()
}

#[tokio::test]
async fn a_paired_peer_posts_a_proposal_over_mtls_and_it_becomes_a_submitted_task() {
    let peer_tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[1u8; 32]);
    let peer_cert = self_signed_endpoint(&peer_tls_key, "peer", Duration::from_secs(3600)).unwrap();
    let peer_proposal_key = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32]);
    let server_tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[2u8; 32]);
    let server_cert =
        self_signed_endpoint(&server_tls_key, "axon-endpoint", Duration::from_secs(3600)).unwrap();

    let store = in_memory_store();
    // Pair the peer: pin its proposal key by its endpoint-cert fingerprint.
    store
        .put_peer_key(
            &peer_cert.fingerprint.value,
            "contract-proposal",
            "requester",
            "iss",
            &peer_proposal_key.verifying().to_public_bytes(),
            NOW,
        )
        .unwrap();
    let store = Arc::new(Mutex::new(store));

    let addr = spawn_receive(store.clone(), &server_tls_key, &server_cert).await;
    let (status, body) = post_proposal(
        addr,
        &peer_tls_key,
        &peer_cert,
        &server_cert,
        &peer_proposal_key,
    )
    .await;

    assert_eq!(
        status, 200,
        "receive should accept the paired peer's proposal"
    );
    let task: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(task["status"]["state"], "TASK_STATE_SUBMITTED");
    let task_id = task["id"].as_str().unwrap().to_owned();

    // The very same store the operator reads now holds the submitted Task.
    let submitted = store.lock().unwrap().list_submitted_tasks().unwrap();
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0].task_id, task_id);
}

#[tokio::test]
async fn an_unpaired_peer_is_refused_403() {
    let stranger_tls = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[7u8; 32]);
    let stranger_cert =
        self_signed_endpoint(&stranger_tls, "stranger", Duration::from_secs(3600)).unwrap();
    let stranger_proposal = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[8u8; 32]);
    let server_tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[2u8; 32]);
    let server_cert =
        self_signed_endpoint(&server_tls_key, "axon-endpoint", Duration::from_secs(3600)).unwrap();

    // No peer keys pinned.
    let store = Arc::new(Mutex::new(in_memory_store()));
    let addr = spawn_receive(store.clone(), &server_tls_key, &server_cert).await;
    let (status, _) = post_proposal(
        addr,
        &stranger_tls,
        &stranger_cert,
        &server_cert,
        &stranger_proposal,
    )
    .await;

    assert_eq!(
        status, 403,
        "an unpinned peer must be refused before any effect"
    );
    assert_eq!(
        store.lock().unwrap().list_submitted_tasks().unwrap().len(),
        0
    );
}

#[tokio::test]
async fn the_whole_lifecycle_receive_inbox_show_approve_and_complete() {
    let peer_tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[1u8; 32]);
    let peer_cert = self_signed_endpoint(&peer_tls_key, "peer", Duration::from_secs(3600)).unwrap();
    let peer_proposal_key = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32]);
    let server_tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[2u8; 32]);
    let server_cert =
        self_signed_endpoint(&server_tls_key, "axon-endpoint", Duration::from_secs(3600)).unwrap();

    // A real daemon state — its derived keys sign the decision and work order.
    let config = DaemonConfig {
        data_dir: std::env::temp_dir().join("axond-lifecycle-unused"),
        local_performer: ident("performer"),
        interface_url: "https://local/a2a".to_owned(),
        receive_addr: None,
        pair_addr: None,
        worker_command: None,
    };
    let identity = IdentityKeys::from_master([33u8; 32]);
    let endpoint_cert = self_signed_endpoint(
        &identity.purpose_key(KeyPurpose::TlsEndpoint),
        "axon-endpoint",
        Duration::from_secs(3600),
    )
    .unwrap();
    let state = Arc::new(DaemonState::from_parts(
        in_memory_store(),
        identity,
        endpoint_cert,
        config,
    ));
    // Pair the peer in the daemon's own store, then serve receive over it.
    state
        .store()
        .lock()
        .unwrap()
        .put_peer_key(
            &peer_cert.fingerprint.value,
            "contract-proposal",
            "requester",
            "iss",
            &peer_proposal_key.verifying().to_public_bytes(),
            NOW,
        )
        .unwrap();
    let addr = spawn_receive(state.store(), &server_tls_key, &server_cert).await;

    // 1. The peer submits over mTLS.
    let (status, body) = post_proposal(
        addr,
        &peer_tls_key,
        &peer_cert,
        &server_cert,
        &peer_proposal_key,
    )
    .await;
    assert_eq!(status, 200);
    let task_id = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // 2. It appears in the operator's inbox (same store, admin dispatch).
    let inbox = state.dispatch(&ControlRequest::TaskInbox).unwrap();
    assert_eq!(inbox["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["tasks"][0]["task_id"], task_id);

    // 3. The risk card renders for review.
    let card = state
        .dispatch(&ControlRequest::TaskShow {
            task_id: task_id.clone(),
        })
        .unwrap();
    assert!(card["sentence"].as_str().unwrap().contains("code-review"));
    assert_eq!(card["sections"].as_array().unwrap().len(), 5);

    // 4. Approve: accept + issue the one-shot work order with the safe grants.
    let approved = state
        .dispatch(&ControlRequest::TaskApprove {
            task_id: task_id.clone(),
        })
        .unwrap();
    assert_eq!(approved["approved"], true);
    assert!(approved["work_order_id"]
        .as_str()
        .unwrap()
        .starts_with("wo-"));
    let granted: Vec<&str> = approved["granted_capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(granted.contains(&"respond"));
    assert!(granted.contains(&"read_supplied_inputs"));

    // 5. The accepted Task has left the submitted inbox.
    let inbox = state.dispatch(&ControlRequest::TaskInbox).unwrap();
    assert_eq!(inbox["tasks"].as_array().unwrap().len(), 0);

    // 6. The worker submits its result on the worker surface: it is gated against
    //    the granted scope, the manifest is signed, and the attempt is completed.
    let completed = state
        .dispatch(&ControlRequest::SubmitResult(ResultSubmission {
            task_id: task_id.clone(),
            outputs: vec![ResultOutput {
                role: "response".to_owned(),
                artifact_id: "a-1".to_owned(),
                kind: OutputKind::Response,
                recipient: "request-origin".to_owned(),
                media_type: "text/plain".to_owned(),
                byte_length: 14,
                sha256: "c".repeat(64),
            }],
            evidence: vec![],
            slots: vec![],
        }))
        .unwrap();
    assert_eq!(completed["completed"], true);
    let bundle = completed["bundle_digest"].as_str().unwrap().to_owned();

    // The signed result manifest is durably stored and verifies under the daemon's
    // task-result key, binding exactly the reported bundle digest.
    let wo = state
        .store()
        .lock()
        .unwrap()
        .attempt_for_task(&task_id)
        .unwrap()
        .unwrap();
    let (stored_digest, manifest_bytes) = state
        .store()
        .lock()
        .unwrap()
        .result_manifest(&wo)
        .unwrap()
        .unwrap();
    assert_eq!(stored_digest, bundle);
    let envelope: Envelope = serde_json::from_slice(&manifest_bytes).unwrap();
    let task_result_vk = state
        .identity()
        .purpose_key(KeyPurpose::TaskResult)
        .verifying();
    let (_manifest, verified_digest) = ResultManifest::verify(&envelope, &task_result_vk).unwrap();
    assert_eq!(verified_digest, bundle);
}

/// A performer's signed result manifest for `task_id`, bound to `contract_digest`.
fn performer_manifest(
    task_result_key: &PurposeKey,
    task_id: &str,
    contract_digest: &str,
) -> Envelope {
    let manifest = ResultManifest::assemble(
        ManifestHeader {
            task_id: task_id.to_owned(),
            context_id: "ctx-1".to_owned(),
            contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
            contract_revision: 0,
            contract_digest: contract_digest.to_owned(),
            attempt_digest: "b".repeat(64),
            work_order_receipt_digest: "c".repeat(64),
        },
        vec![OutputEntry {
            role: "response".to_owned(),
            artifact_id: "a-1".to_owned(),
            part_index: 0,
            media_type: "text/plain".to_owned(),
            byte_length: 14,
            sha256: "d".repeat(64),
        }],
        vec![],
        vec![],
        vec![],
    );
    manifest.sign(task_result_key).unwrap()
}

/// An A2A `SendMessageRequest` carrying a result manifest envelope as a Part.
fn result_message_body(manifest_envelope: &Envelope) -> Vec<u8> {
    let data = serde_json::from_value(serde_json::to_value(manifest_envelope).unwrap()).unwrap();
    let part = Part {
        metadata: None,
        filename: String::new(),
        media_type: axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
        content: Some(Content::Data(data)),
    };
    let message = Message {
        message_id: "result-1".to_owned(),
        context_id: "ctx-1".to_owned(),
        parts: vec![part],
        ..Default::default()
    };
    serde_json::to_vec(&SendMessageRequest {
        message: Some(message),
        ..Default::default()
    })
    .unwrap()
}

#[tokio::test]
async fn a_delivered_result_is_finalized_into_a_signed_outcome() {
    // The performer: its endpoint cert and its task-result signing key.
    let performer_tls = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[1u8; 32]);
    let performer_cert =
        self_signed_endpoint(&performer_tls, "performer", Duration::from_secs(3600)).unwrap();
    let performer_task_result = PurposeKey::from_seed(KeyPurpose::TaskResult, &[4u8; 32]);

    // The requester: its endpoint cert and its requester-outcome signing key.
    let requester_tls = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[2u8; 32]);
    let requester_cert =
        self_signed_endpoint(&requester_tls, "axon-endpoint", Duration::from_secs(3600)).unwrap();
    let requester_outcome_key = PurposeKey::from_seed(KeyPurpose::RequesterOutcome, &[7u8; 32]);

    let contract_digest = "a".repeat(64);
    let store = in_memory_store();
    // The requester recorded the request it sent, and pinned the performer's keys
    // at pairing (a contract-proposal key so the peer resolves, and the task-result
    // key so the delivered result verifies).
    store
        .put_sent_request(
            &SentRequest {
                contract_digest: contract_digest.clone(),
                task_id: "task-1".to_owned(),
                context_id: "ctx-1".to_owned(),
                contract_id: "cid".to_owned(),
                performer_agent: "performer".to_owned(),
                performer_issuer: "iss".to_owned(),
                message_id: "msg-1".to_owned(),
            },
            NOW,
        )
        .unwrap();
    store
        .put_peer_key(
            &performer_cert.fingerprint.value,
            "contract-proposal",
            "performer",
            "iss",
            &PurposeKey::from_seed(KeyPurpose::ContractProposal, &[3u8; 32])
                .verifying()
                .to_public_bytes(),
            NOW,
        )
        .unwrap();
    store
        .put_peer_key(
            &performer_cert.fingerprint.value,
            "task-result",
            "performer",
            "iss",
            &performer_task_result.verifying().to_public_bytes(),
            NOW,
        )
        .unwrap();
    let store = Arc::new(Mutex::new(store));

    // The requester's receive server accepts results and signs its outcome.
    let receive_state = Arc::new(
        ReceiveState::new(
            store.clone(),
            StorePeerResolver,
            ident("requester"),
            BTreeSet::new(),
            "https://local/a2a".to_owned(),
        )
        .accepting_results(PurposeKey::from_seed(
            KeyPurpose::RequesterOutcome,
            &[7u8; 32],
        )),
    );
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&requester_tls, &requester_cert).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_receive(listener, acceptor, receive_state));

    // The performer delivers its signed result to the requester's endpoint.
    let envelope = performer_manifest(&performer_task_result, "task-1", &contract_digest);
    let (status, body) = post_body(
        addr,
        &performer_tls,
        &performer_cert,
        &requester_cert,
        result_message_body(&envelope),
    )
    .await;
    assert_eq!(status, 200);
    let ack: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ack["finalized"], true);
    assert_eq!(ack["state"], "accepted");

    // The requester durably recorded its signed outcome; it verifies under the
    // requester-outcome key and accepts the task.
    let (_digest, env_bytes) = store
        .lock()
        .unwrap()
        .get_outcome(&contract_digest)
        .unwrap()
        .unwrap();
    let stored: Envelope = serde_json::from_slice(&env_bytes).unwrap();
    let outcome = Outcome::verify(&stored, &requester_outcome_key.verifying()).unwrap();
    assert_eq!(outcome.state, OutcomeState::Accepted);
    assert_eq!(outcome.task_id, "task-1");
}

/// A minimal pinned peer record: enough for outbound send/deliver (endpoint +
/// pinned cert); the card fingerprints are unused by those paths.
fn stored_peer(
    agent: &str,
    endpoint: &str,
    tls_cert: &axon_crypto::identity::Fingerprint,
) -> axon_store::StoredPeer {
    axon_store::StoredPeer {
        identity: axon_crypto::identity::PeerIdentity {
            issuer: Some("iss".to_owned()),
            agent_id: agent.to_owned(),
            workload_id: None,
            endpoint_id: endpoint.to_owned(),
            tls_cert: tls_cert.clone(),
            agent_card_key: tls_cert.clone(),
            key_bindings: vec![],
            security_projection_digest: tls_cert.clone(),
            full_card_digest: tls_cert.clone(),
        },
        local_note: String::new(),
    }
}

#[tokio::test]
async fn a_daemon_sends_a_proposal_that_reaches_the_performer_as_a_submitted_task() {
    // The requester A: its identity keys (endpoint + contract-proposal) all derive
    // from one master, exactly as the live daemon's do.
    let a_identity = IdentityKeys::from_master([10u8; 32]);
    let a_cert = self_signed_endpoint(
        &a_identity.purpose_key(KeyPurpose::TlsEndpoint),
        "requester",
        Duration::from_secs(3600),
    )
    .unwrap();

    // The performer B: endpoint cert + a receive server for proposals over B's store.
    let b_tls = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[2u8; 32]);
    let b_cert = self_signed_endpoint(&b_tls, "performer", Duration::from_secs(3600)).unwrap();
    let b_store = in_memory_store();
    // B pinned A's contract-proposal key at pairing (by A's endpoint-cert fingerprint).
    b_store
        .put_peer_key(
            &a_cert.fingerprint.value,
            "contract-proposal",
            "requester",
            "iss",
            &a_identity
                .purpose_key(KeyPurpose::ContractProposal)
                .verifying()
                .to_public_bytes(),
            NOW,
        )
        .unwrap();
    let b_store = Arc::new(Mutex::new(b_store));
    let b_addr = spawn_receive(b_store.clone(), &b_tls, &b_cert).await;

    // A's daemon, with a pinned peer record for B (its endpoint + cert).
    let a_store = in_memory_store();
    a_store
        .put_peer(&stored_peer(
            "performer",
            &format!("https://127.0.0.1:{}/a2a", b_addr.port()),
            &b_cert.fingerprint,
        ))
        .unwrap();
    let a_config = DaemonConfig {
        data_dir: std::env::temp_dir().join("axond-send-unused"),
        local_performer: ident("requester"),
        interface_url: "https://local/a2a".to_owned(),
        receive_addr: None,
        pair_addr: None,
        worker_command: None,
    };
    // A presents exactly the cert B pinned (its stable endpoint cert).
    let a_state = Arc::new(DaemonState::from_parts(
        a_store, a_identity, a_cert, a_config,
    ));
    let a_store = a_state.store();

    // A sends a task. `run_send` blocks on its own runtime, so run it off the async
    // worker; meanwhile B's receive server serves the incoming proposal.
    let spec = TaskSpec {
        performer: "performer".to_owned(),
        task_type: "https://axon.invalid/task/code-review/v1".to_owned(),
        objective: "review this file".to_owned(),
        inputs: vec![TaskInput {
            id: "diff".to_owned(),
            media_type: "text/x-diff".to_owned(),
            text: "--- a\n+++ b\n".to_owned(),
        }],
        deliverables: vec![Deliverable {
            role: "review".to_owned(),
            media_type: "text/plain".to_owned(),
        }],
        capabilities: vec!["respond".to_owned(), "read_supplied_inputs".to_owned()],
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        max_response_bytes: 8192,
    };
    let a_for_send = a_state.clone();
    let sent =
        tokio::task::spawn_blocking(move || a_for_send.dispatch(&ControlRequest::TaskSend(spec)))
            .await
            .unwrap()
            .unwrap();

    assert_eq!(sent["sent"], true);
    let contract_digest = sent["contract_digest"].as_str().unwrap();

    // The performer received it as a SUBMITTED Task…
    let submitted = b_store.lock().unwrap().list_submitted_tasks().unwrap();
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0].contract_digest, contract_digest);
    // …and the requester recorded the outstanding request, keyed by the same digest.
    assert!(a_store
        .lock()
        .unwrap()
        .get_sent_request(contract_digest)
        .unwrap()
        .is_some());
}

/// Pins a peer: its record (endpoint + cert) plus its contract-proposal key, and
/// optionally its task-result key (needed to verify that peer's results).
fn seed_peer(
    store: &Store,
    agent: &str,
    endpoint: &str,
    cert: &EndpointCert,
    proposal_pub: [u8; 32],
    task_result_pub: Option<[u8; 32]>,
) {
    store
        .put_peer(&stored_peer(agent, endpoint, &cert.fingerprint))
        .unwrap();
    store
        .put_peer_key(
            &cert.fingerprint.value,
            "contract-proposal",
            agent,
            "iss",
            &proposal_pub,
            NOW,
        )
        .unwrap();
    if let Some(tr) = task_result_pub {
        store
            .put_peer_key(
                &cert.fingerprint.value,
                "task-result",
                agent,
                "iss",
                &tr,
                NOW,
            )
            .unwrap();
    }
}

/// Builds a receive server over `state`'s store, presenting `state`'s cert; if
/// `results` it also accepts delivered results and signs its outcome.
fn receive_state_for(
    state: &DaemonState,
    agent: &str,
    results: bool,
) -> Arc<ReceiveState<StorePeerResolver>> {
    let base = ReceiveState::new(
        state.store(),
        StorePeerResolver,
        ident(agent),
        BTreeSet::new(),
        "https://local/a2a".to_owned(),
    );
    Arc::new(if results {
        base.accepting_results(state.identity().purpose_key(KeyPurpose::RequesterOutcome))
    } else {
        base
    })
}

fn acceptor_for(state: &DaemonState) -> TlsAcceptor {
    TlsAcceptor::from(Arc::new(
        bootstrap_server_config(
            &state.identity().purpose_key(KeyPurpose::TlsEndpoint),
            state.endpoint_cert(),
        )
        .unwrap(),
    ))
}

fn task_spec(max_response_bytes: u64) -> TaskSpec {
    TaskSpec {
        performer: "performer".to_owned(),
        task_type: "https://axon.invalid/task/code-review/v1".to_owned(),
        objective: "review this file".to_owned(),
        inputs: vec![TaskInput {
            id: "diff".to_owned(),
            media_type: "text/x-diff".to_owned(),
            text: "--- a\n+++ b\n".to_owned(),
        }],
        deliverables: vec![Deliverable {
            role: "review".to_owned(),
            media_type: "text/plain".to_owned(),
        }],
        capabilities: vec!["respond".to_owned(), "read_supplied_inputs".to_owned()],
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        max_response_bytes,
    }
}

#[tokio::test]
async fn two_daemons_run_the_whole_task_round_trip() {
    // Two daemons: A the requester, B the performer, each with its own keys + cert.
    let a_identity = IdentityKeys::from_master([10u8; 32]);
    let a_cert = self_signed_endpoint(
        &a_identity.purpose_key(KeyPurpose::TlsEndpoint),
        "requester",
        Duration::from_secs(3600),
    )
    .unwrap();
    let b_identity = IdentityKeys::from_master([20u8; 32]);
    let b_cert = self_signed_endpoint(
        &b_identity.purpose_key(KeyPurpose::TlsEndpoint),
        "performer",
        Duration::from_secs(3600),
    )
    .unwrap();

    // Public keys each side pinned of the other at pairing.
    let a_proposal_pub = a_identity
        .purpose_key(KeyPurpose::ContractProposal)
        .verifying()
        .to_public_bytes();
    let b_proposal_pub = b_identity
        .purpose_key(KeyPurpose::ContractProposal)
        .verifying()
        .to_public_bytes();
    let b_task_result_pub = b_identity
        .purpose_key(KeyPurpose::TaskResult)
        .verifying()
        .to_public_bytes();

    // Bind both receive ports first so the peer records can carry real URLs.
    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_listener.local_addr().unwrap();
    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();
    let a_url = format!("https://127.0.0.1:{}/a2a", a_addr.port());
    let b_url = format!("https://127.0.0.1:{}/a2a", b_addr.port());

    // Pair both directions.
    let a_store = in_memory_store();
    seed_peer(
        &a_store,
        "performer",
        &b_url,
        &b_cert,
        b_proposal_pub,
        Some(b_task_result_pub),
    );
    let b_store = in_memory_store();
    seed_peer(&b_store, "requester", &a_url, &a_cert, a_proposal_pub, None);

    let cfg = |dir: &str, agent: &str| DaemonConfig {
        data_dir: std::env::temp_dir().join(dir),
        local_performer: ident(agent),
        interface_url: "https://local/a2a".to_owned(),
        receive_addr: None,
        pair_addr: None,
        worker_command: None,
    };
    let a_state = Arc::new(DaemonState::from_parts(
        a_store,
        a_identity,
        a_cert,
        cfg("axond-rt-a", "requester"),
    ));
    let b_state = Arc::new(DaemonState::from_parts(
        b_store,
        b_identity,
        b_cert,
        cfg("axond-rt-b", "performer"),
    ));
    let a_store = a_state.store();

    // A serves results (finalizes B's delivery); B serves proposals (A's send).
    let a_outcome_vk = a_state
        .identity()
        .purpose_key(KeyPurpose::RequesterOutcome)
        .verifying();
    tokio::spawn(serve_receive(
        a_listener,
        acceptor_for(&a_state),
        receive_state_for(&a_state, "requester", true),
    ));
    tokio::spawn(serve_receive(
        b_listener,
        acceptor_for(&b_state),
        receive_state_for(&b_state, "performer", false),
    ));

    // 1. A sends a task → B receives it as SUBMITTED (run_send blocks on its own
    //    runtime, so run it off the async worker).
    let a_for_send = a_state.clone();
    let sent = tokio::task::spawn_blocking(move || {
        a_for_send.dispatch(&ControlRequest::TaskSend(task_spec(8192)))
    })
    .await
    .unwrap()
    .unwrap();
    let task_id = sent["task_id"].as_str().unwrap().to_owned();
    let contract_digest = sent["contract_digest"].as_str().unwrap().to_owned();

    // 2. B approves (accept + issue work order).
    let approved = b_state
        .dispatch(&ControlRequest::TaskApprove {
            task_id: task_id.clone(),
        })
        .unwrap();
    assert_eq!(approved["approved"], true);

    // 3. B completes with a gated result.
    let completed = b_state
        .dispatch(&ControlRequest::SubmitResult(ResultSubmission {
            task_id: task_id.clone(),
            outputs: vec![ResultOutput {
                role: "response".to_owned(),
                artifact_id: "a-1".to_owned(),
                kind: OutputKind::Response,
                recipient: "request-origin".to_owned(),
                media_type: "text/plain".to_owned(),
                byte_length: 14,
                sha256: "c".repeat(64),
            }],
            evidence: vec![],
            slots: vec![],
        }))
        .unwrap();
    assert_eq!(completed["completed"], true);

    // 4. B delivers the signed result → A finalizes it into a signed outcome.
    let b_for_deliver = b_state.clone();
    let tid = task_id.clone();
    let delivered = tokio::task::spawn_blocking(move || {
        b_for_deliver.dispatch(&ControlRequest::TaskDeliver { task_id: tid })
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(delivered["delivered"], true);

    // 5. The requester holds a signed, verifiable outcome that accepts the task.
    let (_digest, env_bytes) = a_store
        .lock()
        .unwrap()
        .get_outcome(&contract_digest)
        .unwrap()
        .unwrap();
    let outcome_env: Envelope = serde_json::from_slice(&env_bytes).unwrap();
    let outcome = Outcome::verify(&outcome_env, &a_outcome_vk).unwrap();
    assert_eq!(outcome.state, OutcomeState::Accepted);
    assert_eq!(outcome.task_id, task_id);
    assert_eq!(outcome.contract_digest, contract_digest);
}
