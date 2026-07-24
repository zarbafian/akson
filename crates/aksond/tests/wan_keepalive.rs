//! Distributed keep-alive: several A2A exchanges over ONE mutual-TLS connection to
//! a **remote** peer (design §9.1, §10.2).
//!
//! The local `receive_e2e` keep-alive test proves the protocol reuses a connection
//! over loopback. This one proves it over a real network link, against a real
//! daemon, with the per-request read deadlines in force: each exchange is a
//! *distinct* signed contract (its own contract id, message id, and timestamps), so
//! every round trip does real work — signature verification, contract validity
//! against the performer's trusted clock, and a durable store write — and the
//! connection must survive all of them without being torn down or timing out.
//!
//! Ignored by default: it needs two live, already-paired endpoints. Run it **on the
//! requester host**, pointing at the performer:
//!
//! ```text
//! AKSON_WAN_DATA_DIR=$HOME/.akson-bench-requester \
//! AKSON_WAN_PEER_ADDR=10.0.0.2:18444 \
//! AKSON_WAN_PEER_CERT=<sha-256 hex of the performer's endpoint cert> \
//! AKSON_WAN_REQUESTER=orgA/alice \
//! AKSON_WAN_PERFORMER=orgB/bob \
//! AKSON_WAN_EXCHANGES=10 \
//!   cargo test -p aksond --test wan_keepalive -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use akson_crypto::cert::EndpointCert;
use akson_crypto::identity::{Fingerprint, FingerprintKind};
use akson_crypto::keypair::PurposeKey;
use akson_crypto::purpose::KeyPurpose;
use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
use akson_proto::v1::{part::Content, Message, Part, SendMessageRequest};
use akson_store::delivery::content_digest;
use aksond::IdentityKeys;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

const TEXT: &str = "review this diff for injection and authz mistakes";

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Splits `issuer/agent` into its two halves.
fn identity(spec: &str) -> (String, String) {
    let (issuer, agent) = spec
        .split_once('/')
        .unwrap_or_else(|| panic!("identity {spec:?} must be issuer/agent"));
    (issuer.to_owned(), agent.to_owned())
}

fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

/// One signed A2A `SendMessageRequest`, unique to `nth` so every exchange is a
/// distinct task rather than an idempotent replay.
fn exchange_body(
    proposal_key: &PurposeKey,
    requester: &(String, String),
    performer: &(String, String),
    now: i64,
    nth: usize,
) -> Vec<u8> {
    let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
    let message_id = format!("wan-msg-{nth}");
    // A distinct, well-formed UUID per exchange.
    let contract_id = format!("3f2a1b4c-9d8e-4f70-a1b2-{:012x}", nth + 1);
    let value = json!({
        "schema_version": 1, "contract_id": contract_id,
        "revision": 0, "task_type": "https://akson.invalid/task/code-review/v1",
        "message_id": message_id,
        "requester": {"issuer": requester.0, "agent": requester.1, "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "performer": {"issuer": performer.0, "agent": performer.1, "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "objective": "review the supplied diff",
        "inputs": [{
            "id": "diff", "message_id": message_id, "part_index": 1, "kind": "text",
            "media_type": "text/plain", "charset": "utf-8", "canonical_rule": "utf8-exact",
            "byte_length": TEXT.len(), "sha256": sha,
            "worker_visible": true, "processor_visible": false
        }],
        "deliverables": [{"role": "review", "media_type": "text/plain"}],
        "evidence_slots": [], "requested_capabilities": ["respond", "read_supplied_inputs"],
        "processor_constraints": {"disclosure": "none"},
        // Live timestamps: the performer revalidates these against its trusted clock.
        "limits": {"deadline": rfc3339(now + 3600), "max_response_bytes": 8192},
        "result_recipient": "request-origin",
        "created_at": rfc3339(now), "expires_at": rfc3339(now + 3600)
    });
    let payload = akson_ext::jcs::canonical_bytes(&value).unwrap();
    let env = akson_contract::sign_proposal(&payload, proposal_key).unwrap();
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
        message_id: message_id.clone(),
        context_id: format!("wan-ctx-{nth}"),
        parts: vec![envelope_part, text_part],
        ..Default::default()
    };
    serde_json::to_vec(&SendMessageRequest {
        message: Some(message),
        ..Default::default()
    })
    .unwrap()
}

/// Reads exactly ONE HTTP/1.1 response, leaving the connection open for the next.
async fn read_one_response<S>(tls: &mut S) -> (u16, Vec<u8>)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = tls.read(&mut tmp).await.unwrap();
        assert!(n > 0, "connection closed before the full response header");
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status code");
    let content_len = head
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_len {
        let n = tls.read(&mut tmp).await.unwrap();
        assert!(n > 0, "connection closed before the full response body");
        body.extend_from_slice(&tmp[..n]);
    }
    (status, body)
}

#[tokio::test]
#[ignore = "needs two live paired endpoints; runs on the distributed bench"]
async fn many_exchanges_share_one_connection_to_a_remote_peer() {
    let data_dir = env("AKSON_WAN_DATA_DIR").expect("set AKSON_WAN_DATA_DIR");
    let peer_addr = env("AKSON_WAN_PEER_ADDR").expect("set AKSON_WAN_PEER_ADDR (host:port)");
    let peer_cert = env("AKSON_WAN_PEER_CERT").expect("set AKSON_WAN_PEER_CERT (sha-256 hex)");
    let requester = identity(&env("AKSON_WAN_REQUESTER").unwrap_or_else(|| "orgA/alice".into()));
    let performer = identity(&env("AKSON_WAN_PERFORMER").unwrap_or_else(|| "orgB/bob".into()));
    let exchanges: usize = env("AKSON_WAN_EXCHANGES")
        .unwrap_or_else(|| "10".into())
        .parse()
        .expect("AKSON_WAN_EXCHANGES must be a number");

    // This endpoint's own identity, exactly as the running daemon derives it: the
    // keys come from the master seed, the certificate is the PERSISTED one (its
    // fingerprint is what the peer pinned, so it must not be regenerated).
    let seed: [u8; 32] = std::fs::read(format!("{data_dir}/identity.seed"))
        .expect("identity.seed")
        .as_slice()
        .try_into()
        .expect("identity.seed must be 32 bytes");
    let identity_keys = IdentityKeys::from_master(seed);
    let tls_key = identity_keys.purpose_key(KeyPurpose::TlsEndpoint);
    let proposal_key = identity_keys.purpose_key(KeyPurpose::ContractProposal);
    let der = std::fs::read(format!("{data_dir}/endpoint.der")).expect("endpoint.der");
    let fingerprint = Fingerprint::cert_sha256(&der);
    let our_cert = EndpointCert {
        der,
        pem: Vec::new(),
        fingerprint,
    };
    let peer_fingerprint = Fingerprint {
        kind: FingerprintKind::CertSha256,
        value: peer_cert,
    };

    // ONE pinned mutual-TLS connection for every exchange below.
    let client_cfg =
        akson_transport::tls::client_config(&tls_key, &our_cert, &peer_fingerprint).unwrap();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(&peer_addr)
        .await
        .unwrap_or_else(|e| panic!("connect {peer_addr}: {e}"));
    tcp.set_nodelay(true).unwrap();
    let handshake = Instant::now();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("mutual TLS handshake with the remote peer");
    let handshake_ms = handshake.elapsed().as_secs_f64() * 1000.0;
    println!("connected to {peer_addr}; handshake {handshake_ms:.1} ms");

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut latencies = Vec::with_capacity(exchanges);
    for i in 0..exchanges {
        let body = exchange_body(&proposal_key, &requester, &performer, now, i);
        let digest = content_digest(&body);
        let request = format!(
            "POST /a2a HTTP/1.1\r\nHost: akson\r\nContent-Type: application/a2a+json\r\n\
             a2a-version: 1.0\r\ncontent-digest: {digest}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );

        let started = Instant::now();
        tls.write_all(request.as_bytes()).await.unwrap();
        tls.write_all(&body).await.unwrap();
        tls.flush().await.unwrap();
        let (status, resp) = read_one_response(&mut tls).await;
        let elapsed = started.elapsed();
        latencies.push(elapsed);

        assert_eq!(
            status,
            200,
            "exchange {i} failed: {}",
            String::from_utf8_lossy(&resp)
        );
        let task: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(
            task["status"]["state"], "TASK_STATE_SUBMITTED",
            "exchange {i} did not submit a task"
        );
        println!(
            "  exchange {:>3}: {:>7.1} ms  task {}",
            i,
            elapsed.as_secs_f64() * 1000.0,
            task["id"].as_str().unwrap_or("?")
        );
    }

    // A deliberate idle gap, then one more exchange: the keep-alive connection must
    // still be usable, proving the per-request deadlines re-arm rather than capping
    // the session's total lifetime.
    let idle = Duration::from_secs(3);
    tokio::time::sleep(idle).await;
    let body = exchange_body(&proposal_key, &requester, &performer, now, exchanges);
    let digest = content_digest(&body);
    let request = format!(
        "POST /a2a HTTP/1.1\r\nHost: akson\r\nContent-Type: application/a2a+json\r\n\
         a2a-version: 1.0\r\ncontent-digest: {digest}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.write_all(&body).await.unwrap();
    tls.flush().await.unwrap();
    let (status, resp) = read_one_response(&mut tls).await;
    assert_eq!(
        status,
        200,
        "the connection did not survive a {}s idle gap: {}",
        idle.as_secs(),
        String::from_utf8_lossy(&resp)
    );

    let mut sorted = latencies.clone();
    sorted.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    println!(
        "\n{} exchanges over ONE connection (+1 after a {}s idle gap)\n  \
         p50 {:.1} ms   p95 {:.1} ms   max {:.1} ms   handshake {:.1} ms",
        exchanges,
        idle.as_secs(),
        ms(sorted[sorted.len() / 2]),
        ms(sorted[(sorted.len() * 95) / 100]),
        ms(*sorted.last().unwrap()),
        handshake_ms,
    );
}
