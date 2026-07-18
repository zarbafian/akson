//! End-to-end: a paired peer POSTs a signed contract proposal over real mutual
//! TLS, and it becomes an inert `SUBMITTED` Task in the daemon's shared store
//! (design §9.1, §10.2).
//!
//! This drives the same receive server the daemon runs: a TLS 1.3 mutual
//! handshake, the client leaf-cert fingerprint captured and resolved against the
//! store's peer records ([`StorePeerResolver`]), then the synchronous receive
//! handler. It proves the network face over a real socket — not a mock resolver —
//! and that the store the receive server writes is the one the operator reads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axon_contract::{sign_proposal, Identity};
use axon_crypto::cert::self_signed_endpoint;
use axon_crypto::keypair::PurposeKey;
use axon_crypto::purpose::KeyPurpose;
use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
use axon_proto::v1::{part::Content, Message, Part, SendMessageRequest};
use axon_store::delivery::content_digest;
use axon_store::envelope::Kek;
use axon_store::{ExternalCheckpoint, Store};
use axon_transport::tls::{bootstrap_server_config, client_config};
use axond::{serve_receive, ReceiveState, StorePeerResolver};
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

/// The peer's signed A2A `SendMessageRequest` bytes (a DSSE proposal Part plus the
/// referenced worker-input Part), signed by `proposal_key`.
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
        "evidence_slots": [], "requested_capabilities": ["respond"],
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

/// Reads an HTTP/1.1 response to EOF (the request set `Connection: close`) and
/// returns (status code, body bytes).
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

#[tokio::test]
async fn a_paired_peer_posts_a_proposal_over_mtls_and_it_becomes_a_submitted_task() {
    // The peer's keys: an endpoint (TLS) key and a contract-proposal key.
    let peer_tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[1u8; 32]);
    let peer_cert = self_signed_endpoint(&peer_tls_key, "peer", Duration::from_secs(3600)).unwrap();
    let peer_proposal_key = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32]);

    // The daemon's endpoint key/cert and the shared store.
    let server_tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[2u8; 32]);
    let server_cert =
        self_signed_endpoint(&server_tls_key, "axon-endpoint", Duration::from_secs(3600)).unwrap();
    let cp = ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    };
    let store = Store::open_in_memory(&Kek::from_bytes([9u8; 32]), cp).unwrap();
    // Pair the peer: pin its proposal key by its endpoint-cert fingerprint, exactly
    // as pairing would. StorePeerResolver resolves the handshake fingerprint to it.
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

    let receive_state = Arc::new(ReceiveState::new(
        store.clone(),
        StorePeerResolver,
        ident("performer"),
        BTreeSet::new(),
        "https://local/a2a".to_owned(),
    ));

    // The server acceptor accepts any client cert (pinned at the app layer).
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&server_tls_key, &server_cert).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_receive(listener, acceptor, receive_state));

    // The client presents the peer cert and pins the server's cert fingerprint.
    let client_cfg = client_config(&peer_tls_key, &peer_cert, &server_cert.fingerprint).unwrap();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    // The pinned verifier checks the fingerprint, not the name.
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    let body = send_message_body(&peer_proposal_key);
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
    let (status, resp_body) = split_response(&raw);
    assert_eq!(status, 200, "receive should accept the paired peer's proposal");
    let task: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(task["status"]["state"], "TASK_STATE_SUBMITTED");
    let task_id = task["id"].as_str().unwrap().to_owned();

    // The very same store the operator reads now holds the submitted Task.
    let store = store.lock().unwrap();
    let submitted = store.list_submitted_tasks().unwrap();
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0].task_id, task_id);
}

#[tokio::test]
async fn an_unpaired_peer_is_refused_403() {
    // A stranger's endpoint cert that the store has never pinned.
    let stranger_tls = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[7u8; 32]);
    let stranger_cert =
        self_signed_endpoint(&stranger_tls, "stranger", Duration::from_secs(3600)).unwrap();
    let stranger_proposal = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[8u8; 32]);

    let server_tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[2u8; 32]);
    let server_cert =
        self_signed_endpoint(&server_tls_key, "axon-endpoint", Duration::from_secs(3600)).unwrap();
    let cp = ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    };
    let store = Store::open_in_memory(&Kek::from_bytes([9u8; 32]), cp).unwrap();
    let store = Arc::new(Mutex::new(store)); // no peer keys pinned

    let receive_state = Arc::new(ReceiveState::new(
        store.clone(),
        StorePeerResolver,
        ident("performer"),
        BTreeSet::new(),
        "https://local/a2a".to_owned(),
    ));
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(&server_tls_key, &server_cert).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_receive(listener, acceptor, receive_state));

    let client_cfg =
        client_config(&stranger_tls, &stranger_cert, &server_cert.fingerprint).unwrap();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();

    let body = send_message_body(&stranger_proposal);
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
    let (status, _) = split_response(&raw);
    assert_eq!(status, 403, "an unpinned peer must be refused before any effect");

    // No Task was created.
    assert_eq!(store.lock().unwrap().list_submitted_tasks().unwrap().len(), 0);
}
