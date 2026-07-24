//! The A2A receive HTTP handler (design §10.2, §9.1/§9.2): turns a received
//! `SendMessage` request into an A2A response, on top of the ingress gates and the
//! [receive dispatcher](crate::dispatch_proposal).
//!
//! This is the synchronous request→response logic — parse the A2A `SendMessage`
//! body, run [`admit`](akson_transport::ingress::admit) (media type, `A2A-Version`,
//! Content-Digest, required extensions, idempotency), then dispatch the proposal
//! and map the outcome to an HTTP status. The async mTLS accept loop that feeds it
//! (peer-pinned, like the pairing bootstrap server) wraps this unchanged.
//!
//! The peer identity and its contract-proposal key are resolved from the pinned
//! peer (by TLS fingerprint) and passed in via [`ReceiveConfig`]; a task never
//! selects them.

use std::collections::BTreeSet;

use akson_contract::Identity;
use akson_crypto::keypair::{PurposeKey, PurposeVerifyingKey};
use akson_ext::dsse::Envelope;
use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
use akson_ext::schema::SchemaId;
use akson_proto::v1::{part::Content, Part, SendMessageRequest};
use akson_store::{Store, StoreError};
use akson_transport::ingress::{admit, Admit, Ingress, Reject};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::control::Problem;
use crate::outcome::{finalize_result, DeliveredOutput};
use crate::receive::{dispatch_proposal, DispatchOutcome};

const A2A_MEDIA_TYPE: &str = "application/a2a+json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";

/// The pinned-peer context a received Message is dispatched under (design §10.2).
/// Resolved from the peer's TLS fingerprint before the handler runs.
pub struct ReceiveConfig<'a> {
    /// This endpoint's identity — the contract's `performer` (for a proposal) or
    /// the `requester` (for a delivered result) must equal it.
    pub local_performer: &'a Identity,
    /// The pinned peer's identity — the contract's `requester` must equal it.
    pub requester_origin: &'a Identity,
    /// The pinned peer's contract-proposal verifying key.
    pub proposal_key: &'a PurposeVerifyingKey,
    /// Extension URIs the request MUST activate (§10.1).
    pub required_extensions: &'a BTreeSet<String>,
    /// This endpoint's A2A interface URL (a covered value).
    pub interface_url: &'a str,
    /// This endpoint's requester-outcome signing key. `Some` iff the endpoint
    /// accepts delivered results (i.e. it is acting as a requester).
    pub outcome_key: Option<&'a PurposeKey>,
    /// The sending peer's task-result verifying key, resolved by TLS fingerprint —
    /// used to verify a delivered result manifest.
    pub performer_task_result_key: Option<&'a PurposeVerifyingKey>,
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

    // A delivered result carries a result-manifest envelope, not a proposal —
    // route it to the requester-outcome path (design §14.5).
    if let Some(envelope) = result_manifest_envelope(&message.parts) {
        let delivered = delivered_outputs(&message.parts);
        return Ok(handle_result(
            store,
            config,
            req.peer,
            &envelope,
            &delivered,
            trusted_now_unix,
        ));
    }

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

/// Handles a delivered result (design §14.5): verify it under the sender's
/// task-result key and sign this endpoint's requester outcome. Requires the
/// endpoint to be acting as a requester (an outcome key) and the sender to have a
/// pinned task-result key; otherwise the result is not accepted here.
fn handle_result(
    store: &Store,
    config: &ReceiveConfig,
    sender_root: &str,
    envelope: &Envelope,
    delivered: &[DeliveredOutput],
    trusted_now_unix: i64,
) -> HttpResponse {
    let (Some(outcome_key), Some(task_result_key)) =
        (config.outcome_key, config.performer_task_result_key)
    else {
        return problem(
            415,
            "results-not-accepted",
            "this endpoint does not accept delivered results",
        );
    };
    let signed_at = match OffsetDateTime::from_unix_timestamp(trusted_now_unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
    {
        Some(s) => s,
        None => return problem(500, "internal", "the request could not be processed"),
    };
    match finalize_result(
        store,
        config.local_performer,
        config.requester_origin, // the authenticated sender (must be the performer)
        sender_root,             // the authenticated sender's ROOT
        outcome_key,
        task_result_key,
        envelope,
        delivered,
        &signed_at,
        trusted_now_unix,
    ) {
        Ok(value) => a2a_ok(serde_json::to_vec(&value).unwrap_or_default()),
        Err(p) => HttpResponse {
            status: p.status,
            content_type: PROBLEM_MEDIA_TYPE.to_owned(),
            body: serde_json::to_vec(&p).unwrap_or_default(),
        },
    }
}

/// The result-manifest DSSE envelope in a message's parts, if the message is a
/// delivered result. Returns `None` for a proposal (a contract envelope) or a
/// message with no DSSE envelope part.
fn result_manifest_envelope(parts: &[Part]) -> Option<Envelope> {
    let result_type = SchemaId::ResultManifestV1.payload_media_type();
    parts
        .iter()
        .filter_map(part_envelope)
        .find(|env| env.payload_type == result_type)
}

/// The output payloads carried alongside a delivered result manifest: every raw
/// Part, keyed by the `filename` the performer set to the manifest's `artifact_id`.
/// Nothing is trusted here — `finalize_result` checks each against the signed
/// manifest before any of it is stored.
fn delivered_outputs(parts: &[Part]) -> Vec<DeliveredOutput> {
    parts
        .iter()
        .filter_map(|part| match part.content.as_ref()? {
            Content::Raw(bytes) => Some(DeliveredOutput {
                artifact_id: part.filename.clone(),
                bytes: bytes.to_vec(),
            }),
            _ => None,
        })
        .collect()
}

/// Parses a Part's DSSE envelope (its media type marks it), if present.
fn part_envelope(part: &Part) -> Option<Envelope> {
    if part.media_type != DSSE_ENVELOPE_MEDIA_TYPE {
        return None;
    }
    match part.content.as_ref()? {
        Content::Data(data) => {
            let value = serde_json::to_value(data).ok()?;
            serde_json::from_value(value).ok()
        }
        _ => None,
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
        type_: format!("urn:akson:error:{kind}"),
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
    use akson_crypto::keypair::PurposeKey;
    use akson_crypto::purpose::KeyPurpose;
    use akson_ext::dsse::Envelope;
    use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
    use akson_proto::v1::{part::Content, Message, Part};
    use akson_store::delivery::content_digest;
    use akson_store::{ExternalCheckpoint, Store};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TEXT: &str = "review this file";
    const NOW: i64 = 1_800_000_000;

    fn store() -> Store {
        let kek = akson_store::envelope::Kek::from_bytes([6u8; 32]);
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
            root: "root-fixture".to_owned(),
        }
    }

    fn contract_payload() -> Vec<u8> {
        let sha = hex::encode(Sha256::digest(TEXT.as_bytes()));
        let value = json!({
            "schema_version": 1,
            "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
            "revision": 0, "task_type": "https://akson.invalid/t", "message_id": "msg-1",
            "requester": {"issuer": "iss", "agent": "requester", "root": "root-fixture"},
            "performer": {"issuer": "iss", "agent": "performer", "root": "root-fixture"},
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
        akson_ext::jcs::canonical_bytes(&value).unwrap()
    }

    /// Serializes a full A2A SendMessage body carrying the signed proposal.
    fn send_message_body() -> Vec<u8> {
        let env: Envelope =
            akson_contract::sign_proposal(&contract_payload(), &proposal_key()).unwrap();
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
            outcome_key: None,
            performer_task_result_key: None,
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
