//! Delivering the signed result back to the requester (design §7.2, §14.5): the
//! outbound half of the round trip.
//!
//! Once a Task is completed, its signed result manifest is delivered to the
//! `result_recipient` — the request origin — over a fresh mutual-TLS connection
//! pinned to that peer's endpoint certificate (the mirror of the receive path).
//! The `respond` capability, granted at accept, is what authorises sending this
//! response to the requester.
//!
//! The store is `!Sync`, so everything the delivery needs is extracted **under the
//! lock** into a [`DeliveryJob`] first; the network I/O then runs lock-free.

use std::sync::Arc;
use std::time::Duration;

use axon_contract::{parse_payload, HeadState};
use axon_crypto::cert::self_signed_endpoint;
use axon_crypto::identity::{Fingerprint, FingerprintKind};
use axon_crypto::purpose::KeyPurpose;
use axon_ext::dsse::Envelope;
use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
use axon_proto::v1::{part::Content, Message, Part, SendMessageRequest};
use axon_store::delivery::content_digest;
use axon_store::Store;
use axon_transport::tls::client_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::bootstrap::DaemonState;
use crate::control::Problem;

/// Cap on the requester's acknowledgement (design §9.1).
const MAX_ACK_BODY: usize = 64 * 1024;
/// Endpoint-cert validity for the outbound connection (see [`crate::run_receive_listener`]).
const ENDPOINT_CERT_VALIDITY: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Everything a delivery needs, extracted from the store under the lock so the
/// network I/O can run without holding it.
pub struct DeliveryJob {
    task_id: String,
    context_id: String,
    message_id: String,
    manifest_envelope: Vec<u8>,
    recipient_endpoint: String,
    recipient_fingerprint: String,
}

/// Extracts the delivery for a completed Task (design §14.1). Fails closed: the
/// Task must be accepted, completed (a stored result), and its requester must be a
/// paired peer with a known endpoint.
pub fn prepare_delivery(store: &Store, task_id: &str) -> Result<DeliveryJob, Problem> {
    let head = match store.contract_head(task_id).map_err(store_problem)? {
        HeadState::Locked(head) => head,
        HeadState::Open(_) => {
            return Err(problem(
                409,
                "not-accepted",
                "this task has not been accepted",
            ))
        }
        HeadState::Empty => return Err(problem(404, "no-such-task", "no such task")),
    };
    let payload = store
        .get_contract(&head.digest)
        .map_err(store_problem)?
        .ok_or_else(|| problem(404, "no-such-task", "no such task"))?;
    let contract = parse_payload(&payload)
        .map_err(|_| {
            problem(
                500,
                "corrupt-contract",
                "the stored contract could not be parsed",
            )
        })?
        .contract;

    let work_order_id = store
        .attempt_for_task(task_id)
        .map_err(store_problem)?
        .ok_or_else(|| problem(409, "no-work-order", "this task has no issued work order"))?;
    let (bundle_digest, manifest_envelope) = store
        .result_manifest(&work_order_id)
        .map_err(store_problem)?
        .ok_or_else(|| problem(409, "not-completed", "this task has no completed result"))?;

    // The requester must be a paired peer with a known endpoint and pinned cert.
    let peer = store
        .get_peer(&contract.requester.agent)
        .map_err(store_problem)?
        .ok_or_else(|| {
            problem(
                409,
                "requester-unknown",
                "the requester is not a known peer",
            )
        })?;

    let context_id = store
        .task_context(task_id)
        .map_err(store_problem)?
        .or_else(|| contract.context_id.clone())
        .unwrap_or_default();

    Ok(DeliveryJob {
        task_id: task_id.to_owned(),
        context_id,
        message_id: format!("result-{}", &bundle_digest[..bundle_digest.len().min(16)]),
        manifest_envelope,
        recipient_endpoint: peer.identity.endpoint_id,
        recipient_fingerprint: peer.identity.tls_cert.value,
    })
}

/// Delivers the prepared result to the requester over mutual TLS, pinning the
/// requester's endpoint certificate (design §7.2, §9.1). `endpoint_key`/`cert` are
/// this endpoint's own — presented as the client certificate. Returns the outcome.
pub async fn deliver_job(
    job: DeliveryJob,
    endpoint_key: &axon_crypto::keypair::PurposeKey,
    endpoint_cert: &axon_crypto::cert::EndpointCert,
) -> Result<serde_json::Value, Problem> {
    let body = a2a_result_message(&job)?;
    let digest = content_digest(&body);

    let (host, port, path) = parse_endpoint(&job.recipient_endpoint).ok_or_else(|| {
        problem(
            500,
            "bad-endpoint",
            "the requester endpoint is not a usable URL",
        )
    })?;
    let pinned = Fingerprint {
        kind: FingerprintKind::CertSha256,
        value: job.recipient_fingerprint.clone(),
    };
    let config = client_config(endpoint_key, endpoint_cert, &pinned)
        .map_err(|_| problem(500, "tls", "the delivery TLS config could not be built"))?;
    let connector = TlsConnector::from(Arc::new(config));

    let addr = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| {
            problem(
                502,
                "unreachable",
                "the requester endpoint could not be resolved",
            )
        })?
        .next()
        .ok_or_else(|| problem(502, "unreachable", "the requester endpoint did not resolve"))?;
    let tcp = TcpStream::connect(addr).await.map_err(|_| {
        problem(
            502,
            "unreachable",
            "the requester endpoint refused the connection",
        )
    })?;
    let server_name =
        ServerName::try_from(host).map_err(|_| problem(500, "bad-endpoint", "bad host name"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|_| problem(502, "tls-handshake", "the requester TLS handshake failed"))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Type: application/a2a+json\r\n\
         a2a-version: 1.0\r\ncontent-digest: {digest}\r\nContent-Length: {len}\r\n\
         Connection: close\r\n\r\n",
        host_hdr = "axon",
        len = body.len(),
    );
    let write = async {
        tls.write_all(request.as_bytes()).await?;
        tls.write_all(&body).await?;
        tls.flush().await?;
        // Read only until the response headers complete — the status line is all we
        // need. Tolerate a peer that closes without a TLS close_notify.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.windows(4).any(|w| w == b"\r\n\r\n") || raw.len() >= MAX_ACK_BODY {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        Ok::<_, std::io::Error>(raw)
    };
    let raw = write
        .await
        .map_err(|e| problem_detail(502, "delivery-io", "delivering the result failed", e))?;
    let status = response_status(&raw)
        .ok_or_else(|| problem(502, "delivery-io", "the requester sent no HTTP status"))?;

    Ok(serde_json::json!({
        "delivered": status == 200,
        "status": status,
        "task_id": job.task_id,
        "recipient": job.recipient_endpoint,
    }))
}

/// Prepares and delivers a Task's result (design §7.2). Extracts the job under the
/// store lock, then runs the network I/O on a dedicated runtime — blocking, so it
/// composes with the synchronous control socket.
pub fn run_delivery(state: &DaemonState, task_id: &str) -> Result<serde_json::Value, Problem> {
    let job = {
        let store = state.store();
        let store = store
            .lock()
            .map_err(|_| problem(500, "internal", "the request could not be processed"))?;
        prepare_delivery(&store, task_id)?
    };
    let endpoint_key = state.identity().purpose_key(KeyPurpose::TlsEndpoint);
    let endpoint_cert =
        self_signed_endpoint(&endpoint_key, "axon-endpoint", ENDPOINT_CERT_VALIDITY)
            .map_err(|_| problem(500, "cert", "the endpoint certificate could not be built"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| problem(500, "internal", "the request could not be processed"))?;
    runtime.block_on(deliver_job(job, &endpoint_key, &endpoint_cert))
}

/// The A2A `SendMessageRequest` carrying the signed result manifest as a Part,
/// referencing the Task's context (design §14.1).
fn a2a_result_message(job: &DeliveryJob) -> Result<Vec<u8>, Problem> {
    let envelope: Envelope = serde_json::from_slice(&job.manifest_envelope).map_err(|_| {
        problem(
            500,
            "corrupt-result",
            "the stored result manifest is corrupt",
        )
    })?;
    let data = serde_json::to_value(&envelope)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| problem(500, "internal", "the request could not be processed"))?;
    let manifest_part = Part {
        metadata: None,
        filename: String::new(),
        media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
        content: Some(Content::Data(data)),
    };
    let message = Message {
        message_id: job.message_id.clone(),
        context_id: job.context_id.clone(),
        parts: vec![manifest_part],
        ..Default::default()
    };
    serde_json::to_vec(&SendMessageRequest {
        message: Some(message),
        ..Default::default()
    })
    .map_err(|_| problem(500, "internal", "the request could not be processed"))
}

/// Parses an endpoint URL into (host, port, path). Only `https` is usable.
fn parse_endpoint(endpoint: &str) -> Option<(String, u16, String)> {
    let url = Url::parse(endpoint).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?.to_owned();
    let port = url.port_or_known_default().unwrap_or(443);
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    Some((host, port, path.to_owned()))
}

/// The status code from an HTTP/1.1 response's start line.
fn response_status(raw: &[u8]) -> Option<u16> {
    let end = raw
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(raw.len());
    let line = std::str::from_utf8(&raw[..end]).ok()?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn store_problem(_e: axon_store::StoreError) -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    }
}

fn problem_detail(status: u16, kind: &str, title: &str, e: impl std::fmt::Display) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: Some(e.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axon_crypto::cert::{self_signed_endpoint, EndpointCert};
    use axon_crypto::keypair::PurposeKey;
    use axon_evidence::{ManifestHeader, OutputEntry, ResultManifest};
    use axon_proto::v1::part::Content as PartContent;
    use axon_transport::tls::bootstrap_server_config;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn tls_key(seed: u8) -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[seed; 32])
    }

    fn cert(key: &PurposeKey, cn: &str) -> EndpointCert {
        self_signed_endpoint(key, cn, Duration::from_secs(3600)).unwrap()
    }

    /// A signed result manifest and its DSSE-envelope bytes.
    fn signed_manifest(key: &PurposeKey) -> (Vec<u8>, String) {
        let manifest = ResultManifest::assemble(
            ManifestHeader {
                task_id: "task-1".to_owned(),
                context_id: "ctx-1".to_owned(),
                contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
                contract_revision: 0,
                contract_digest: "a".repeat(64),
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
        let envelope = manifest.sign(key).unwrap();
        let digest = manifest.bundle_digest().unwrap();
        (serde_json::to_vec(&envelope).unwrap(), digest)
    }

    /// A minimal requester server: accepts one mTLS connection, reads the POST
    /// body (by Content-Length), captures it, and answers 200.
    async fn capture_server(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        captured: Arc<StdMutex<Vec<u8>>>,
    ) {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        // Read headers, then exactly Content-Length body bytes.
        let (header_end, content_length) = loop {
            let n = tls.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                let len = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                break (pos + 4, len);
            }
        };
        while buf.len() < header_end + content_length {
            let n = tls.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        *captured.lock().unwrap() = buf[header_end..header_end + content_length].to_vec();
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
    }

    #[tokio::test]
    async fn delivers_the_signed_manifest_to_the_pinned_requester() {
        let task_result_key = PurposeKey::from_seed(KeyPurpose::TaskResult, &[5u8; 32]);
        let (envelope_bytes, bundle_digest) = signed_manifest(&task_result_key);

        // The requester's server cert (the performer's client pins its fingerprint).
        let server_key = tls_key(2);
        let server_cert = cert(&server_key, "requester");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(
            bootstrap_server_config(&server_key, &server_cert).unwrap(),
        ));
        let captured = Arc::new(StdMutex::new(Vec::new()));
        let server = tokio::spawn(capture_server(listener, acceptor, captured.clone()));

        // The performer's own endpoint cert (presented as the client certificate).
        let client_key = tls_key(1);
        let client_cert = cert(&client_key, "performer");
        let job = DeliveryJob {
            task_id: "task-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            message_id: "result-abc".to_owned(),
            manifest_envelope: envelope_bytes,
            recipient_endpoint: format!("https://127.0.0.1:{}/a2a", addr.port()),
            recipient_fingerprint: server_cert.fingerprint.value.clone(),
        };
        let out = deliver_job(job, &client_key, &client_cert).await.unwrap();
        assert_eq!(out["delivered"], true);
        assert_eq!(out["status"], 200);
        server.await.unwrap();

        // The requester received the exact signed manifest: parse the A2A message,
        // extract the DSSE envelope Part, and verify it under the task-result key.
        let body = captured.lock().unwrap().clone();
        let msg: SendMessageRequest = serde_json::from_slice(&body).unwrap();
        let part = &msg.message.unwrap().parts[0];
        assert_eq!(part.media_type, DSSE_ENVELOPE_MEDIA_TYPE);
        let data = match part.content.as_ref().unwrap() {
            PartContent::Data(d) => serde_json::to_value(d).unwrap(),
            _ => panic!("expected a data Part"),
        };
        let envelope: Envelope = serde_json::from_value(data).unwrap();
        let (_manifest, verified_digest) =
            ResultManifest::verify(&envelope, &task_result_key.verifying()).unwrap();
        assert_eq!(verified_digest, bundle_digest);
    }

    #[test]
    fn parse_endpoint_requires_https() {
        assert!(parse_endpoint("http://host/a2a").is_none());
        let (host, port, path) = parse_endpoint("https://host:9443/a2a").unwrap();
        assert_eq!((host.as_str(), port, path.as_str()), ("host", 9443, "/a2a"));
        // Default HTTPS port + empty path.
        let (_h, port, path) = parse_endpoint("https://host").unwrap();
        assert_eq!((port, path.as_str()), (443, "/"));
    }
}
