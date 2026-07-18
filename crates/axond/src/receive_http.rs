//! The A2A receive HTTP handler (design §10.2, §9.1/§9.2): turns a received
//! `SendMessage` request into an A2A response, on top of the ingress gates and the
//! [receive dispatcher](crate::dispatch_proposal).
//!
//! This is the synchronous request→response logic — parse the A2A `SendMessage`
//! body, run [`admit`](axon_transport::ingress::admit) (media type, `A2A-Version`,
//! Content-Digest, required extensions, idempotency), then dispatch the proposal
//! and map the outcome to an HTTP status. The async mTLS accept loop that feeds it
//! (peer-pinned, like the pairing bootstrap server) wraps this unchanged.
//!
//! The peer identity and its contract-proposal key are resolved from the pinned
//! peer (by TLS fingerprint) and passed in via [`ReceiveConfig`]; a task never
//! selects them.

use std::collections::BTreeSet;

use axon_contract::Identity;
use axon_crypto::keypair::PurposeVerifyingKey;
use axon_proto::v1::SendMessageRequest;
use axon_store::{Store, StoreError};
use axon_transport::ingress::{admit, Admit, Ingress, Reject};

use crate::control::Problem;
use crate::receive::{dispatch_proposal, DispatchOutcome};

const A2A_MEDIA_TYPE: &str = "application/a2a+json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";

/// The pinned-peer context a received Message is dispatched under (design §10.2).
/// Resolved from the peer's TLS fingerprint before the handler runs.
pub struct ReceiveConfig<'a> {
    /// This endpoint's identity — the contract's `performer` must equal it.
    pub local_performer: &'a Identity,
    /// The pinned peer's identity — the contract's `requester` must equal it.
    pub requester_origin: &'a Identity,
    /// The pinned peer's contract-proposal verifying key.
    pub proposal_key: &'a PurposeVerifyingKey,
    /// Extension URIs the request MUST activate (§10.1).
    pub required_extensions: &'a BTreeSet<String>,
    /// This endpoint's A2A interface URL (a covered value).
    pub interface_url: &'a str,
}

/// The received request's metadata (headers + the peer id the mTLS layer pinned)
/// and body.
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub content_type: &'a str,
    pub a2a_version: Option<&'a str>,
    pub content_digest: Option<&'a str>,
    pub activated_extensions: &'a [String],
    pub tenant: Option<&'a str>,
    /// The pinned peer id (from the TLS fingerprint → peer record).
    pub peer: &'a str,
    pub body: &'a [u8],
}

/// An HTTP response to write back to the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Handles a received A2A `SendMessage` (design §10.2). `trusted_now_unix` MUST be
/// the §8.5 trusted time. Returns the exact bytes to send the peer.
pub fn handle_receive(
    store: &Store,
    config: &ReceiveConfig,
    req: &HttpRequest,
    trusted_now_unix: i64,
) -> Result<HttpResponse, StoreError> {
    if !req.method.eq_ignore_ascii_case("POST") {
        return Ok(problem(405, "method-not-allowed", "only POST is supported"));
    }
    // Parse the A2A SendMessage body into its Message.
    let message = match serde_json::from_slice::<SendMessageRequest>(req.body)
        .ok()
        .and_then(|r| r.message)
    {
        Some(m) => m,
        None => {
            return Ok(problem(
                400,
                "malformed-request",
                "body is not a SendMessage with a message",
            ))
        }
    };

    // Ingress gates + idempotency peek (§9.2).
    let ingress = Ingress {
        peer: req.peer,
        method: req.method,
        content_type: req.content_type,
        a2a_version: req.a2a_version,
        content_digest: req.content_digest,
        activated_extensions: req.activated_extensions,
        interface_url: config.interface_url,
        tenant: req.tenant,
        message_id: &message.message_id,
        body: req.body,
    };
    match admit(store, config.required_extensions, &ingress)? {
        Admit::Rejected(reject) => Ok(reject_to_http(&reject)),
        Admit::Duplicate { response, .. } => Ok(a2a_ok(response)),
        Admit::Conflict => Ok(problem(
            409,
            "conflict",
            "a covered value changed for this Message id",
        )),
        Admit::Accept(covered) => {
            let dispatched = dispatch_proposal(
                store,
                &covered,
                &message.parts,
                &message.context_id,
                config.proposal_key,
                config.requester_origin,
                config.local_performer,
                req.body,
                trusted_now_unix,
            )?;
            let status = match dispatched.outcome {
                DispatchOutcome::Submitted { .. } | DispatchOutcome::Duplicate { .. } => 200,
                DispatchOutcome::Rejected { .. } => 422,
                DispatchOutcome::Conflict => 409,
            };
            Ok(HttpResponse {
                status,
                content_type: content_type_for(status),
                body: dispatched.response,
            })
        }
    }
}

fn content_type_for(status: u16) -> String {
    if status < 400 {
        A2A_MEDIA_TYPE.to_owned()
    } else {
        PROBLEM_MEDIA_TYPE.to_owned()
    }
}

fn a2a_ok(body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status: 200,
        content_type: A2A_MEDIA_TYPE.to_owned(),
        body,
    }
}

/// Maps an ingress rejection to its HTTP status (design §16.2). The Problem body is
/// generic and leaks no internal structure.
fn reject_to_http(reject: &Reject) -> HttpResponse {
    let (status, title) = match reject {
        Reject::UnsupportedMediaType => (415, "unsupported media type"),
        Reject::BadA2aVersion(_) => (400, "unsupported or missing A2A-Version"),
        Reject::ContentDigest(_) => (400, "content-digest missing or does not match the body"),
        Reject::MissingRequiredExtensions(_) => (400, "a required extension was not activated"),
    };
    problem(status, "ingress-rejected", title)
}

fn problem(status: u16, kind: &str, title: &str) -> HttpResponse {
    let problem = Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    };
    HttpResponse {
        status,
        content_type: PROBLEM_MEDIA_TYPE.to_owned(),
        body: serde_json::to_vec(&problem).unwrap_or_default(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use axon_crypto::keypair::PurposeKey;
    use axon_crypto::purpose::KeyPurpose;
    use axon_ext::dsse::Envelope;
    use axon_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use axon_proto::v1::{part::Content, Message, Part};
    use axon_store::delivery::content_digest;
    use axon_store::{ExternalCheckpoint, Store};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;

    fn store() -> Store {
        let kek = axon_store::envelope::Kek::from_bytes([6u8; 32]);
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        Store::open_in_memory(&kek, cp).unwrap()
    }

    fn proposal_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32])
    }

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
        }
    }

    fn contract_payload() -> Vec<u8> {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
        let value = json!({
            "schema_version": 1,
            "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0, "task_type": "https://axon.invalid/t", "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester"},
            "performer": {"issuer": "iss", "agent": "performer"},
            "objective": "o",
            "inputs": [{
                "id": "src", "message_id": "msg-1", "part_index": 1, "kind": "text",
                "media_type": "text/plain", "charset": "utf-8", "canonical_rule": "utf8-exact",
                "byte_length": TEXT.len(), "sha256": sha,
                "worker_visible": true, "processor_visible": false
            }],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [], "requested_capabilities": [],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"
        });
        axon_ext::jcs::canonical_bytes(&value).unwrap()
    }

    /// Serializes a full A2A SendMessage body carrying the signed proposal.
    fn send_message_body() -> Vec<u8> {
        let env: Envelope =
            axon_contract::sign_proposal(&contract_payload(), &proposal_key()).unwrap();
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
        let request = SendMessageRequest {
            message: Some(message),
            ..Default::default()
        };
        serde_json::to_vec(&request).unwrap()
    }

    fn config<'a>(
        performer: &'a Identity,
        requester: &'a Identity,
        key: &'a PurposeVerifyingKey,
        exts: &'a BTreeSet<String>,
    ) -> ReceiveConfig<'a> {
        ReceiveConfig {
            local_performer: performer,
            requester_origin: requester,
            proposal_key: key,
            required_extensions: exts,
            interface_url: "https://local/a2a",
        }
    }

    fn request<'a>(body: &'a [u8], digest: &'a str) -> HttpRequest<'a> {
        HttpRequest {
            method: "POST",
            content_type: "application/a2a+json",
            a2a_version: Some("1.0"),
            content_digest: Some(digest),
            activated_extensions: &[],
            tenant: None,
            peer: "requester",
            body,
        }
    }

    #[test]
    fn a_valid_send_message_yields_a_submitted_task() {
        let store = store();
        let perf = ident("performer");
        let req_id = ident("requester");
        let vk = proposal_key().verifying();
        let exts = BTreeSet::new();
        let cfg = config(&perf, &req_id, &vk, &exts);

        let body = send_message_body();
        let digest = content_digest(&body);
        let resp = handle_receive(&store, &cfg, &request(&body, &digest), NOW).unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/a2a+json");
        let task: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(task["id"].as_str().unwrap().starts_with("task-"));
        assert_eq!(task["status"]["state"], "TASK_STATE_SUBMITTED");

        // An exact replay returns the identical bytes.
        let replay = handle_receive(&store, &cfg, &request(&body, &digest), NOW).unwrap();
        assert_eq!(replay, resp);
    }

    #[test]
    fn a_wrong_content_type_is_415() {
        let store = store();
        let perf = ident("performer");
        let req_id = ident("requester");
        let vk = proposal_key().verifying();
        let exts = BTreeSet::new();
        let cfg = config(&perf, &req_id, &vk, &exts);

        let body = send_message_body();
        let digest = content_digest(&body);
        let mut req = request(&body, &digest);
        req.content_type = "application/json";
        let resp = handle_receive(&store, &cfg, &req, NOW).unwrap();
        assert_eq!(resp.status, 415);
        assert_eq!(resp.content_type, "application/problem+json");
    }

    #[test]
    fn a_get_is_405() {
        let store = store();
        let perf = ident("performer");
        let req_id = ident("requester");
        let vk = proposal_key().verifying();
        let exts = BTreeSet::new();
        let cfg = config(&perf, &req_id, &vk, &exts);
        let mut req = request(b"{}", "sha-256=:x:");
        req.method = "GET";
        assert_eq!(handle_receive(&store, &cfg, &req, NOW).unwrap().status, 405);
    }

    #[test]
    fn a_wrong_content_digest_is_400() {
        let store = store();
        let perf = ident("performer");
        let req_id = ident("requester");
        let vk = proposal_key().verifying();
        let exts = BTreeSet::new();
        let cfg = config(&perf, &req_id, &vk, &exts);

        let body = send_message_body();
        // A digest of the wrong bytes.
        let wrong = content_digest(b"not the body");
        let resp = handle_receive(&store, &cfg, &request(&body, &wrong), NOW).unwrap();
        assert_eq!(resp.status, 400);
    }
}
