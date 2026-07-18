//! End-to-end over a real socket: a paired peer POSTs a signed contract proposal
//! over mutual TLS, and the daemon carries it through the whole pre-execution
//! lifecycle — inert `SUBMITTED` Task → operator inbox → risk card → accept +
//! work order (design §9.1, §10.2, §12.3).
//!
//! This drives the same receive server the daemon runs (a TLS 1.3 mutual
//! handshake, the client leaf-cert fingerprint captured and resolved against the
//! store's peer records via [`StorePeerResolver`]) and the same
//! [`DaemonState::dispatch`] the admin control socket serves — over a real socket,
//! with the store shared between them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axon_contract::{sign_proposal, Identity};
use axon_crypto::cert::{self_signed_endpoint, EndpointCert};
use axon_crypto::keypair::PurposeKey;
use axon_crypto::purpose::KeyPurpose;
use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
use axon_proto::v1::{part::Content, Message, Part, SendMessageRequest};
use axon_store::delivery::content_digest;
use axon_store::envelope::Kek;
use axon_store::{ExternalCheckpoint, Store};
use axon_evidence::ResultManifest;
use axon_ext::dsse::Envelope;
use axon_transport::tls::{bootstrap_server_config, client_config};
use axond::{
    serve_receive, ControlRequest, DaemonConfig, DaemonState, IdentityKeys, OutputKind,
    ReceiveState, ResultOutput, ResultSubmission, StorePeerResolver,
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
    let client_cfg = client_config(peer_tls_key, peer_cert, &server_cert.fingerprint).unwrap();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    // The pinned verifier checks the fingerprint, not the name.
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();

    let body = send_message_body(proposal_key);
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

    assert_eq!(status, 200, "receive should accept the paired peer's proposal");
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

    assert_eq!(status, 403, "an unpinned peer must be refused before any effect");
    assert_eq!(store.lock().unwrap().list_submitted_tasks().unwrap().len(), 0);
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
    };
    let state = Arc::new(DaemonState::from_parts(
        in_memory_store(),
        IdentityKeys::from_master([33u8; 32]),
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
    assert!(approved["work_order_id"].as_str().unwrap().starts_with("wo-"));
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
