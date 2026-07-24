//! Sending a task as *requester* (design §10.2): the entry of the exchange.
//!
//! [`run_send`] turns an operator [`TaskSpec`] into a signed contract proposal and
//! delivers it to the performer over mutual TLS:
//!
//! 1. resolve the performer peer (its identity, endpoint, and pinned certificate);
//! 2. assemble the contract — this endpoint as `requester`, the peer as
//!    `performer`, a fresh contract id, and each input reduced to its digest — and
//!    sign it under this endpoint's contract-proposal key;
//! 3. POST it to the performer and read back the `SUBMITTED` Task;
//! 4. record the `sent_request` so the eventual result can be matched to it.
//!
//! The store is `!Sync`, so the proposal is assembled under the lock into a
//! [`SendPrepared`]; the network I/O then runs lock-free, and the `sent_request` is
//! recorded under the lock once the performer's Task id is known.

use akson_contract::{parse_payload, sign_proposal, Identity};
use akson_crypto::keypair::PurposeKey;
use akson_crypto::purpose::KeyPurpose;
use akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE;
use akson_proto::v1::{part::Content, Message, Part, SendMessageRequest};
use akson_store::{SentRequest, Store};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::a2a_client::post_a2a;
use crate::bootstrap::DaemonState;
use crate::control::Problem;

/// One input the requester supplies with the task (its content is worker-visible).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskInput {
    pub id: String,
    pub media_type: String,
    pub text: String,
}

/// A deliverable the requester asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deliverable {
    pub role: String,
    pub media_type: String,
}

/// The operator's task specification (`akson task send`). The daemon fills the
/// requester identity, ids, digests, and timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSpec {
    /// The performer peer's agent id (must be a paired peer).
    pub performer: String,
    pub task_type: String,
    pub objective: String,
    #[serde(default)]
    pub inputs: Vec<TaskInput>,
    pub deliverables: Vec<Deliverable>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// RFC 3339 deadline; also the contract's `expires_at`.
    pub deadline: String,
    pub max_response_bytes: u64,
}

/// A signed proposal ready to send, plus the metadata to record once sent.
pub struct SendPrepared {
    performer_endpoint: String,
    performer_fingerprint: String,
    performer_agent: String,
    performer_issuer: String,
    performer_root: String,
    message_body: Vec<u8>,
    contract_digest: String,
    contract_id: String,
    context_id: String,
    message_id: String,
}

/// Assembles and signs the proposal for `spec`, resolving the performer from the
/// store (design §10.2). `created_at` is RFC 3339. Fails closed: the performer must
/// be a paired peer, and the assembled contract must be valid.
pub fn prepare_send(
    store: &Store,
    local: &Identity,
    proposal_key: &PurposeKey,
    spec: &TaskSpec,
    performer_root: Option<&str>,
    created_at: &str,
) -> Result<SendPrepared, Problem> {
    // A label-resolved send carries the ROOT (the relationship key); a bare
    // agent name is honored only while it is unambiguous — with same-named
    // peers coexisting, guessing would sign confidential inputs over to the
    // wrong one (root-key cutover).
    let peer = match performer_root {
        Some(root) => store.get_peer_by_root(root).map_err(store_problem)?,
        None => store
            .sole_peer_named(&spec.performer)
            .map_err(store_problem)?,
    }
    .ok_or_else(|| {
        problem(
            409,
            "unknown-performer",
            "the performer is not a paired peer (or the name is ambiguous — use your label)",
        )
    })?;
    // Only an ACTIVE peer may be sent work, however it was addressed: a
    // suspended relationship stays the operator's call (§8.4; slice-3 review).
    let root = peer.identity.agent_card_key.value.clone();
    if store.peer_status_by_root(&root).map_err(store_problem)?
        != Some(akson_store::PeerStatus::Active)
    {
        return Err(problem(
            409,
            "peer-not-active",
            "the performer is not an active peer (suspended or removed)",
        ));
    }
    let performer_root_resolved = root.clone();
    let performer = Identity {
        issuer: peer.identity.issuer.clone().unwrap_or_default(),
        agent: peer.identity.agent_id.clone(),
        root: performer_root_resolved.clone(),
    };

    let contract_id = uuid_v4();
    let message_id = random_id("msg");
    let context_id = random_id("ctx");

    // Assemble the contract: each input reduced to its digest, referenced by the
    // Part index it will occupy (the proposal envelope is part 0).
    let inputs: Vec<serde_json::Value> = spec
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            json!({
                "id": input.id,
                "message_id": message_id,
                "part_index": (i as u32) + 1,
                "kind": "text",
                "media_type": input.media_type,
                "charset": "utf-8",
                "canonical_rule": "utf8-exact",
                "byte_length": input.text.len(),
                "sha256": hex_sha256(input.text.as_bytes()),
                "worker_visible": true,
                "processor_visible": false,
            })
        })
        .collect();
    let deliverables: Vec<serde_json::Value> = spec
        .deliverables
        .iter()
        .map(|d| json!({ "role": d.role, "media_type": d.media_type }))
        .collect();

    let contract = json!({
        "schema_version": 1,
        "contract_id": contract_id,
        "revision": 0,
        "task_type": spec.task_type,
        "message_id": message_id,
        "requester": { "issuer": local.issuer, "agent": local.agent, "root": local.root },
        "performer": { "issuer": performer.issuer, "agent": performer.agent, "root": performer.root },
        "objective": spec.objective,
        "inputs": inputs,
        "deliverables": deliverables,
        "evidence_slots": [],
        "requested_capabilities": spec.capabilities,
        "processor_constraints": { "disclosure": "none" },
        "limits": { "deadline": spec.deadline, "max_response_bytes": spec.max_response_bytes },
        "result_recipient": "request-origin",
        "created_at": created_at,
        "expires_at": spec.deadline,
    });

    let payload = akson_ext::jcs::canonical_bytes(&contract)
        .map_err(|_| problem(500, "internal", "the request could not be processed"))?;
    // Validate the assembled contract (and take its canonical digest) before signing.
    let parsed = parse_payload(&payload).map_err(|e| {
        problem_detail(
            400,
            "invalid-task",
            "the task spec is not a valid contract",
            e,
        )
    })?;
    let envelope = sign_proposal(&payload, proposal_key)
        .map_err(|_| problem(500, "sign-failed", "the proposal could not be signed"))?;

    // The message: the DSSE proposal envelope (part 0) then each input as a text Part.
    let mut parts = vec![Part {
        metadata: None,
        filename: String::new(),
        media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
        content: Some(Content::Data(
            serde_json::to_value(&envelope)
                .ok()
                .and_then(|v| serde_json::from_value(v).ok())
                .ok_or_else(|| problem(500, "internal", "the request could not be processed"))?,
        )),
    }];
    for input in &spec.inputs {
        parts.push(Part {
            metadata: None,
            filename: String::new(),
            media_type: input.media_type.clone(),
            content: Some(Content::Text(input.text.clone())),
        });
    }
    let message_body = serde_json::to_vec(&SendMessageRequest {
        message: Some(Message {
            message_id: message_id.clone(),
            context_id: context_id.clone(),
            parts,
            ..Default::default()
        }),
        ..Default::default()
    })
    .map_err(|_| problem(500, "internal", "the request could not be processed"))?;

    Ok(SendPrepared {
        performer_endpoint: peer.identity.endpoint_id,
        performer_fingerprint: peer.identity.tls_cert.value,
        performer_agent: performer.agent,
        performer_issuer: performer.issuer,
        performer_root: performer_root_resolved,
        message_body,
        contract_digest: parsed.digest,
        contract_id,
        context_id,
        message_id,
    })
}

/// Sends the prepared proposal to the performer over mutual TLS and returns the
/// `SUBMITTED` Task id (design §10.2, §9.1).
pub async fn send_prepared(
    prepared: &SendPrepared,
    endpoint_key: &PurposeKey,
    endpoint_cert: &akson_crypto::cert::EndpointCert,
) -> Result<String, Problem> {
    let (status, body) = post_a2a(
        endpoint_key,
        endpoint_cert,
        &prepared.performer_endpoint,
        &prepared.performer_fingerprint,
        &prepared.message_body,
    )
    .await?;
    if status != 200 {
        return Err(problem_detail(
            502,
            "send-rejected",
            "the performer did not accept the proposal",
            format!("status {status}: {}", String::from_utf8_lossy(&body)),
        ));
    }
    let task: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| problem(502, "send-io", "the performer sent no A2A Task"))?;
    task.get("id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| problem(502, "send-io", "the performer's Task had no id"))
}

/// Prepares, sends, and records a task (design §10.2). Assembles under the store
/// lock, runs the network I/O on a dedicated runtime, then records the sent request.
pub fn run_send(
    state: &DaemonState,
    spec: &TaskSpec,
    performer_root: Option<&str>,
) -> Result<serde_json::Value, Problem> {
    let now = OffsetDateTime::now_utc();
    let created_at = now
        .format(&Rfc3339)
        .map_err(|_| problem(500, "internal", "the request could not be processed"))?;
    let now_unix = now.unix_timestamp();

    let prepared = {
        let store = state.store();
        let store = store
            .lock()
            .map_err(|_| problem(500, "internal", "the request could not be processed"))?;
        prepare_send(
            &store,
            &state.config().local_performer,
            &state.identity().purpose_key(KeyPurpose::ContractProposal),
            spec,
            performer_root,
            &created_at,
        )?
    };

    let endpoint_key = state.identity().purpose_key(KeyPurpose::TlsEndpoint);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| problem(500, "internal", "the request could not be processed"))?;
    let task_id = runtime.block_on(send_prepared(
        &prepared,
        &endpoint_key,
        state.endpoint_cert(),
    ))?;

    // Record the outstanding request so the delivered result can be matched to it.
    {
        let store = state.store();
        let store = store
            .lock()
            .map_err(|_| problem(500, "internal", "the request could not be processed"))?;
        store
            .put_sent_request(
                &SentRequest {
                    contract_digest: prepared.contract_digest.clone(),
                    task_id: task_id.clone(),
                    context_id: prepared.context_id.clone(),
                    contract_id: prepared.contract_id.clone(),
                    performer_agent: prepared.performer_agent.clone(),
                    performer_issuer: prepared.performer_issuer.clone(),
                    message_id: prepared.message_id.clone(),
                    performer_root: prepared.performer_root.clone(),
                },
                now_unix,
            )
            .map_err(store_problem)?;
    }

    Ok(json!({
        "sent": true,
        "task_id": task_id,
        "contract_id": prepared.contract_id,
        "contract_digest": prepared.contract_digest,
        "performer": prepared.performer_agent,
    }))
}

/// A random UUID v4 (the contract-id format).
fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

/// A random opaque id with a readable prefix (message/context ids).
fn random_id(prefix: &str) -> String {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    format!("{prefix}-{}", hex(&b))
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn store_problem(_e: akson_store::StoreError) -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:akson:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    }
}

fn problem_detail(status: u16, kind: &str, title: &str, e: impl std::fmt::Display) -> Problem {
    Problem {
        type_: format!("urn:akson:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: Some(e.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use akson_contract::receive_proposal;
    use akson_crypto::purpose::KeyPurpose;
    use akson_proto::v1::SendMessageRequest;

    fn ident(agent: &str) -> Identity {
        Identity {
            issuer: "iss".to_owned(),
            agent: agent.to_owned(),
            root: "root-fixture".to_owned(),
        }
    }

    fn proposal_key() -> PurposeKey {
        PurposeKey::from_seed(KeyPurpose::ContractProposal, &[4u8; 32])
    }

    fn spec() -> TaskSpec {
        TaskSpec {
            performer: "performer".to_owned(),
            task_type: "https://akson.invalid/t".to_owned(),
            objective: "review this".to_owned(),
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
        }
    }

    /// Build a proposal (without a store) by resolving the performer inline, so the
    /// pure assembly can be checked: the built message must pass the performer's
    /// own §10.2 validation.
    fn build(local: &Identity, performer: &Identity, spec: &TaskSpec) -> Vec<u8> {
        // Mirror prepare_send's assembly with a fixed performer (no store lookup).
        let contract_id = uuid_v4();
        let message_id = random_id("msg");
        let inputs: Vec<serde_json::Value> = spec
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                json!({
                    "id": input.id, "message_id": message_id, "part_index": (i as u32) + 1,
                    "kind": "text", "media_type": input.media_type, "charset": "utf-8",
                    "canonical_rule": "utf8-exact", "byte_length": input.text.len(),
                    "sha256": hex_sha256(input.text.as_bytes()),
                    "worker_visible": true, "processor_visible": false,
                })
            })
            .collect();
        let contract = json!({
            "schema_version": 1, "contract_id": contract_id, "revision": 0,
            "task_type": spec.task_type, "message_id": message_id,
            "requester": { "issuer": local.issuer, "agent": local.agent, "root": local.root },
            "performer": { "issuer": performer.issuer, "agent": performer.agent, "root": performer.root },
            "objective": spec.objective,
            "inputs": inputs,
            "deliverables": spec.deliverables.iter().map(|d| json!({"role": d.role, "media_type": d.media_type})).collect::<Vec<_>>(),
            "evidence_slots": [], "requested_capabilities": spec.capabilities,
            "processor_constraints": { "disclosure": "none" },
            "limits": { "deadline": spec.deadline, "max_response_bytes": spec.max_response_bytes },
            "result_recipient": "request-origin",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": spec.deadline,
        });
        let payload = akson_ext::jcs::canonical_bytes(&contract).unwrap();
        let envelope = sign_proposal(&payload, &proposal_key()).unwrap();
        let mut parts = vec![Part {
            metadata: None,
            filename: String::new(),
            media_type: DSSE_ENVELOPE_MEDIA_TYPE.to_owned(),
            content: Some(Content::Data(
                serde_json::from_value(serde_json::to_value(&envelope).unwrap()).unwrap(),
            )),
        }];
        for input in &spec.inputs {
            parts.push(Part {
                metadata: None,
                filename: String::new(),
                media_type: input.media_type.clone(),
                content: Some(Content::Text(input.text.clone())),
            });
        }
        serde_json::to_vec(&SendMessageRequest {
            message: Some(Message {
                message_id,
                context_id: "ctx-1".to_owned(),
                parts,
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn a_built_proposal_passes_the_performers_validation() {
        let local = ident("requester");
        let performer = ident("performer");
        let body = build(&local, &performer, &spec());

        // The performer parses the message and validates the proposal exactly as its
        // receive path would (§10.2): DSSE verifies, identities bind, inputs bind.
        let msg = serde_json::from_slice::<SendMessageRequest>(&body)
            .unwrap()
            .message
            .unwrap();
        let received = receive_proposal(
            &msg.message_id,
            &msg.parts,
            &proposal_key().verifying(),
            &local,     // requester == the connecting origin
            &performer, // performer == the local endpoint
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(received.proposal.contract.objective, "review this");
        assert_eq!(received.proposal.contract.requester, local);
        assert_eq!(received.proposal.contract.performer, performer);
    }
}
