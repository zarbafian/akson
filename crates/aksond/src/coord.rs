//! The coordination surface (ADR-0016, `akson_byom_exchange_v1`): the bounded
//! local surface a *different* principal — kovee's byom dispatch driver — uses to
//! stage outbound contracts and read coordination state.
//!
//! What you write (over `coord.sock`):
//! ```text
//! {"op":"stage","task_type":"https://byom.example/task/exchange/v1","performer":"partner","payload_base64":"aGk="}
//! {"outcome":"ok","result":{"stage_ref":"stage-2ff0…","staged_digest":"2ff0…","status":"staged","already_staged":false,…}}
//! ```
//!
//! Two properties are the whole point of this module:
//!
//! - **Staging is inert** (ADR-0016 §4). [`stage`] writes bytes and returns a
//!   reference. It starts no model, mints no authority, touches no workspace,
//!   invokes no tool, and opens no socket — §6.3's "arrival is not execution",
//!   applied outbound. Structurally, every op here is handed the store and the
//!   daemon's own identity and nothing else: there is no transport, no broker, and
//!   no sandbox in scope to reach.
//! - **Consent is not on this surface** (ADR-0016 §3). [`stage_consent`] mints the
//!   one-shot receipt a future `dispatch` must consume, and it requires the
//!   **admin** surface: `ControlOp::StageConsent` needs [`Surface::Admin`], so a
//!   coordination connection gets `forbidden-surface` and never reaches the code
//!   below.
//!
//! `dispatch`, `task_status`, and `capability_evidence` are registered on the
//! surface and answer a typed `501` [`not_implemented`] problem — named plainly
//! rather than silently missing, so a driver's handshake can read exactly what
//! this build does.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use akson_store::{NewStagedContract, StagedContract, Store};

use crate::bootstrap::{valid_label, DaemonState};
use crate::control::Problem;
use crate::socket::ControlRequest;

/// The coordination protocol this surface speaks (ADR-0016).
pub const COORD_PROTOCOL: &str = "akson_byom_exchange_v1";
/// Its version. Bumped only by an ADR; the driver checks it at handshake.
pub const COORD_PROTOCOL_VERSION: u32 = 1;

/// The coordination ops this build answers.
const IMPLEMENTED: [&str; 5] = [
    "coord_whoami",
    "peer_show",
    "stage",
    "stage_show",
    "events_read",
];

/// The coordination ops that are registered but not implemented yet. Named here
/// (and in `coord_whoami`) so "not built" is never confused with "not allowed".
const UNIMPLEMENTED: [&str; 3] = ["dispatch", "task_status", "capability_evidence"];

/// Ceiling on the bytes one `stage` may persist. The coordination driver is a
/// separate principal: what it can write must be bounded, and a contract payload
/// that needs more than this is not a coordination message.
pub const MAX_STAGED_PAYLOAD_BYTES: usize = 512 * 1024;

/// Ceiling on a `task_type` URI — a bounded, printable identifier.
const MAX_TASK_TYPE_CHARS: usize = 512;

/// The default and maximum number of events one `events_read` returns.
const DEFAULT_EVENT_LIMIT: u32 = 64;
const MAX_EVENT_LIMIT: u32 = 256;

/// The opaque cursor's domain prefix. A cursor is base64url over this string plus
/// a sequence number: it can address a position in the event feed and nothing
/// else, and the encoding is not the driver's to construct.
const CURSOR_DOMAIN: &str = "akson-coord-events-v1:";

/// Handles one coordination-surface request (ADR-0016 §2), plus the admin-only
/// `stage_consent`. The surface gate has already run: reaching `StageConsent`
/// here means the caller held [`Surface::Admin`](crate::Surface::Admin).
pub fn dispatch_coord(
    state: &DaemonState,
    req: &ControlRequest,
) -> Result<serde_json::Value, Problem> {
    match req {
        ControlRequest::CoordWhoAmI => Ok(coord_whoami(state)),
        ControlRequest::PeerShow { label } => peer_show(state, label),
        ControlRequest::Stage {
            task_type,
            performer,
            payload_base64,
        } => stage(state, task_type, performer, payload_base64),
        ControlRequest::StageShow { stage_ref } => stage_show(state, stage_ref),
        ControlRequest::EventsRead { cursor, limit } => {
            events_read(state, cursor.as_deref(), *limit)
        }
        ControlRequest::StageConsent { stage_ref } => stage_consent(state, stage_ref),
        ControlRequest::Dispatch { .. } => Err(not_implemented("dispatch")),
        ControlRequest::TaskStatus { .. } => Err(not_implemented("task_status")),
        ControlRequest::CapabilityEvidence { .. } => Err(not_implemented("capability_evidence")),
        _ => Err(Problem::new(
            400,
            "unsupported-operation",
            "this operation is not a coordination request",
        )),
    }
}

/// A registered-but-unbuilt coordination op (ADR-0016 §2). `501`, and it names
/// the op: the driver must be able to tell "this build does not do it yet" from
/// "you may not do it" (`403 forbidden-surface`) and from "no such op"
/// (`400 malformed-request`).
pub fn not_implemented(op: &str) -> Problem {
    Problem {
        type_: "urn:akson:error:not-implemented".to_owned(),
        title: "this coordination operation is not implemented yet".to_owned(),
        status: 501,
        detail: Some(format!(
            "{op} is on the coordination surface but not implemented in this build"
        )),
    }
}

/// `coord_whoami` — the driver's handshake: who this daemon is, the endpoint
/// fingerprint a peer pins, and the protocol/feature versions.
///
/// Deliberately narrower than admin's `who_am_i`: no data directory, no receive
/// address. A different principal gets the identity it needs to address this
/// endpoint, not the daemon's local layout.
fn coord_whoami(state: &DaemonState) -> serde_json::Value {
    let config = state.config();
    serde_json::json!({
        "protocol": COORD_PROTOCOL,
        "protocol_version": COORD_PROTOCOL_VERSION,
        "issuer": config.local_performer.issuer,
        "agent": config.local_performer.agent,
        "root_thumbprint": config.local_performer.root,
        "interface_url": config.interface_url,
        "endpoint_fingerprint": format!("sha256:{}", state.endpoint_cert().fingerprint.value),
        "features": IMPLEMENTED,
        "unimplemented": UNIMPLEMENTED,
    })
}

/// `peer_show` — one named peer's identity tuple and card claims.
///
/// Answers about the label asked for and **nothing else**: there is no listing op
/// on this surface, and an unknown label gets the same generic `404` an
/// un-introduced one would, so probing learns only what the caller already named.
/// The operator's private note on a peer is never included.
fn peer_show(state: &DaemonState, label: &str) -> Result<serde_json::Value, Problem> {
    if !valid_label(label) {
        return Err(unknown_peer());
    }
    let store = state.store();
    let store = store.lock().map_err(|_| internal())?;
    let import = store
        .peer_import_by_label(label)
        .map_err(|_| internal())?
        .ok_or_else(unknown_peer)?;
    let root = import.root_thumbprint;
    let Some(peer) = store.get_peer_by_root(&root).map_err(|_| internal())? else {
        // Imported, but no introduction has committed the §8.1 tuple yet. Report
        // the relationship's state; invent no identity for it.
        return Ok(serde_json::json!({
            "label": label,
            "root_thumbprint": root,
            "verified": false,
            "status": "imported",
        }));
    };
    let status = store
        .peer_by_root(&root)
        .map_err(|_| internal())?
        .map(|(_, status)| status)
        .unwrap_or_else(|| "imported".to_owned());
    let id = &peer.identity;
    // The pinned purposes, as the wire spells them (kebab-case, ADR-0004).
    let purposes: Vec<_> = id
        .key_bindings
        .iter()
        .map(|b| serde_json::json!(b.purpose))
        .collect();
    Ok(serde_json::json!({
        "label": label,
        "root_thumbprint": root,
        "verified": true,
        "status": status,
        "identity": {
            "issuer": id.issuer,
            "agent_id": id.agent_id,
            "endpoint_id": id.endpoint_id,
            "tls_certificate_sha256": id.tls_cert.value,
            "agent_card_thumbprint": id.agent_card_key.value,
        },
        "card_claims": {
            "security_projection_digest": id.security_projection_digest.value,
            "full_card_digest": id.full_card_digest.value,
            "key_purposes": purposes,
        },
        "endpoint_hint": import.endpoint_hint,
    }))
}

/// The content a staged reference is derived from (ADR-0016 §4). The digest is
/// over the RFC 8785 canonical JSON of exactly these three fields — the payload
/// by its own digest, the recipient, and the task type — so "the same bytes" is a
/// precise claim: same payload, same recipient, same type ⇒ same reference.
fn staged_content(payload_sha256: &str, performer: &str, task_type: &str) -> serde_json::Value {
    serde_json::json!({
        "payload_sha256": payload_sha256,
        "performer": performer,
        "task_type": task_type,
    })
}

/// The staged digest and the reference derived from it (ADR-0016 §4). Pure, and
/// frozen by the `coordination/stage-*` golden vectors.
pub fn stage_reference(
    payload: &[u8],
    performer: &str,
    task_type: &str,
) -> Result<(String, String, String), Problem> {
    let payload_sha256 = hex(&Sha256::digest(payload));
    let content = staged_content(&payload_sha256, performer, task_type);
    let canonical = akson_ext::jcs::canonical_bytes(&content).map_err(|_| internal())?;
    let staged_digest = hex(&Sha256::digest(&canonical));
    // The reference IS a function of the content: a client cannot choose it, and
    // two stages of the same content cannot disagree about it. 32 hex characters
    // is a 128-bit prefix; the full digest is stored beside it under a UNIQUE
    // constraint, so even a contrived prefix collision is an insert error rather
    // than one staging silently answering for another.
    let stage_ref = format!("stage-{}", &staged_digest[..32]);
    Ok((stage_ref, staged_digest, payload_sha256))
}

/// `stage` — inert, idempotent staging of outbound bytes (ADR-0016 §4).
///
/// Writes the payload (sealed) plus a reference and one `staged` event, and
/// returns. Re-staging identical content returns the same reference with
/// `already_staged: true` and writes nothing.
fn stage(
    state: &DaemonState,
    task_type: &str,
    performer: &str,
    payload_base64: &str,
) -> Result<serde_json::Value, Problem> {
    if task_type.is_empty()
        || task_type.chars().count() > MAX_TASK_TYPE_CHARS
        || task_type
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(Problem::new(
            400,
            "bad-task-type",
            "task_type must be a non-empty printable URI with no whitespace",
        ));
    }
    if !performer.is_empty() && !valid_label(performer) {
        return Err(unknown_peer());
    }
    let payload = STANDARD.decode(payload_base64).map_err(|_| {
        Problem::new(
            400,
            "bad-payload",
            "payload_base64 is not valid base64 (standard alphabet)",
        )
    })?;
    if payload.is_empty() {
        return Err(Problem::new(
            400,
            "bad-payload",
            "there are no bytes to stage",
        ));
    }
    if payload.len() > MAX_STAGED_PAYLOAD_BYTES {
        return Err(Problem::new(
            413,
            "payload-too-large",
            "the staged payload exceeds the coordination ceiling",
        ));
    }
    let (stage_ref, staged_digest, payload_sha256) =
        stage_reference(&payload, performer, task_type)?;

    let store = state.store();
    let store = store.lock().map_err(|_| internal())?;
    // A recipient, when named, must be a relationship the *operator* imported.
    // Staging bytes for a label that names nothing is a driver bug, and it is
    // better learned here than at dispatch.
    if !performer.is_empty()
        && store
            .peer_import_by_label(performer)
            .map_err(|_| internal())?
            .is_none()
    {
        return Err(unknown_peer());
    }
    let now = trusted_now(&store)?;
    let event = serde_json::json!({
        "stage_ref": stage_ref,
        "staged_digest": staged_digest,
        "payload_sha256": payload_sha256,
        "task_type": task_type,
        "performer": performer,
        "byte_length": payload.len(),
    });
    let outcome = store
        .stage_contract(
            &NewStagedContract {
                stage_ref: &stage_ref,
                staged_digest: &staged_digest,
                task_type,
                performer,
                payload_sha256: &payload_sha256,
                payload: &payload,
                event,
            },
            now,
        )
        .map_err(|_| internal())?;
    let mut result = staged_json(outcome.record(), None);
    result["already_staged"] = serde_json::Value::Bool(outcome.already_staged());
    Ok(result)
}

/// `stage_show` — a staged contract's status and digests.
fn stage_show(state: &DaemonState, stage_ref: &str) -> Result<serde_json::Value, Problem> {
    let store = state.store();
    let store = store.lock().map_err(|_| internal())?;
    let staged = store
        .staged_contract(stage_ref)
        .map_err(|_| internal())?
        .ok_or_else(unknown_stage)?;
    let consent = store
        .unconsumed_consent(stage_ref)
        .map_err(|_| internal())?
        .map(|c| {
            serde_json::json!({
                "consent_receipt": c.receipt_id,
                "staged_digest": c.staged_digest,
                "max_uses": c.max_uses,
                "uses": c.uses,
                "minted_at": c.minted_at,
            })
        });
    Ok(staged_json(&staged, consent))
}

/// The one JSON shape a staged record has, in `stage` and `stage_show` alike.
fn staged_json(staged: &StagedContract, consent: Option<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "stage_ref": staged.stage_ref,
        "staged_digest": staged.staged_digest,
        "payload_sha256": staged.payload_sha256,
        "byte_length": staged.byte_length,
        "task_type": staged.task_type,
        "performer": staged.performer,
        "status": staged.status,
        "staged_at": staged.staged_at,
        "consent": consent,
    })
}

/// Encodes an event position as an opaque cursor (ADR-0016 §2).
pub fn encode_cursor(seq: i64) -> String {
    URL_SAFE_NO_PAD.encode(format!("{CURSOR_DOMAIN}{seq}"))
}

/// Decodes a cursor a reply produced. Anything else — a hand-built string, a
/// cursor from another feed, a negative position — is refused, never guessed at.
pub fn decode_cursor(cursor: &str) -> Result<i64, Problem> {
    let bad = || Problem::new(400, "bad-cursor", "that cursor did not come from this feed");
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| bad())?;
    let text = String::from_utf8(bytes).map_err(|_| bad())?;
    let seq = text.strip_prefix(CURSOR_DOMAIN).ok_or_else(bad)?;
    let seq: i64 = seq.parse().map_err(|_| bad())?;
    if seq < 0 {
        return Err(bad());
    }
    Ok(seq)
}

/// `events_read` — durable cursored coordination events. Each event carries the
/// cursor that resumes *after* it, so a driver can commit its position one event
/// at a time and never re-see what it acknowledged.
fn events_read(
    state: &DaemonState,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<serde_json::Value, Problem> {
    let after = match cursor {
        Some(c) => decode_cursor(c)?,
        None => 0,
    };
    let limit = limit
        .unwrap_or(DEFAULT_EVENT_LIMIT)
        .clamp(1, MAX_EVENT_LIMIT);
    let store = state.store();
    let store = store.lock().map_err(|_| internal())?;
    let events = store
        .read_coord_events(after, limit as usize)
        .map_err(|_| internal())?;
    let head = store.coord_events_head().map_err(|_| internal())?;
    let last = events.last().map(|e| e.seq).unwrap_or(after);
    let items: Vec<_> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "cursor": encode_cursor(e.seq),
                "kind": e.kind,
                "stage_ref": e.stage_ref,
                "at": e.at,
                "detail": e.detail,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "events": items,
        "next_cursor": encode_cursor(last),
        "has_more": last < head,
    }))
}

/// `stage_consent` — the operator's one-shot consent for exactly one staged
/// digest (ADR-0016 §3), **admin only**.
///
/// Returns the risk card *with* the receipt: the card is rendered from the very
/// row the receipt is minted against, in one call, so what the operator reads and
/// what the receipt authorizes cannot drift apart. A second consent while the
/// first is unconsumed is refused — one disclosure, one live authorization.
fn stage_consent(state: &DaemonState, stage_ref: &str) -> Result<serde_json::Value, Problem> {
    let store = state.store();
    let store = store.lock().map_err(|_| internal())?;
    let staged = store
        .staged_contract(stage_ref)
        .map_err(|_| internal())?
        .ok_or_else(unknown_stage)?;
    if store
        .unconsumed_consent(stage_ref)
        .map_err(|_| internal())?
        .is_some()
    {
        return Err(Problem::new(
            409,
            "already-consented",
            "an unconsumed consent receipt already exists for this staged digest",
        ));
    }
    let now = trusted_now(&store)?;
    let card = risk_card(&store, &staged)?;
    let receipt_id = format!("consent-{}", random_hex());
    let body = serde_json::json!({
        "receipt_id": receipt_id,
        "stage_ref": staged.stage_ref,
        "staged_digest": staged.staged_digest,
        "payload_sha256": staged.payload_sha256,
        "purpose": "coord.dispatch",
        "max_uses": 1,
        "minted_at": now,
    });
    let event = serde_json::json!({
        "stage_ref": staged.stage_ref,
        "staged_digest": staged.staged_digest,
        "consent_receipt": receipt_id,
        "max_uses": 1,
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|_| internal())?;
    let receipt = store
        .mint_consent_receipt(&staged.stage_ref, &receipt_id, &body_bytes, &event, now)
        .map_err(|_| internal())?
        .ok_or_else(|| {
            Problem::new(
                409,
                "already-consented",
                "an unconsumed consent receipt already exists for this staged digest",
            )
        })?;
    Ok(serde_json::json!({
        "consented": true,
        "consent_receipt": receipt.receipt_id,
        "stage_ref": receipt.stage_ref,
        "staged_digest": receipt.staged_digest,
        "max_uses": receipt.max_uses,
        "uses": receipt.uses,
        "minted_at": receipt.minted_at,
        "sentence": card.0,
        "sections": card.1,
    }))
}

/// The §5.2 risk card for a staged outbound disclosure: one sentence, then the
/// facts the decision rests on. The payload bytes are **not** rendered — the
/// operator consents to a digest and a recipient, and untrusted bytes never reach
/// the terminal.
fn risk_card(
    store: &Store,
    staged: &StagedContract,
) -> Result<(String, Vec<serde_json::Value>), Problem> {
    let recipient = if staged.performer.is_empty() {
        "no named recipient".to_owned()
    } else {
        format!("your peer {:?}", staged.performer)
    };
    let sentence = format!(
        "You are about to allow ONE outbound disclosure to {recipient}: {} bytes of {}.",
        staged.byte_length, staged.task_type
    );
    let mut who = vec![format!(
        "recipient label: {}",
        if staged.performer.is_empty() {
            "(none)"
        } else {
            &staged.performer
        }
    )];
    if !staged.performer.is_empty() {
        match store
            .peer_import_by_label(&staged.performer)
            .map_err(|_| internal())?
        {
            Some(import) => {
                who.push(format!("root thumbprint: {}", import.root_thumbprint));
                let status = store
                    .peer_by_root(&import.root_thumbprint)
                    .map_err(|_| internal())?
                    .map(|(agent, status)| format!("{status} (claims the name {agent:?})"))
                    .unwrap_or_else(|| "imported, not yet introduced".to_owned());
                who.push(format!("relationship: {status}"));
                if !import.endpoint_hint.is_empty() {
                    who.push(format!("endpoint hint: {}", import.endpoint_hint));
                }
            }
            None => who.push("this label no longer names an imported peer".to_owned()),
        }
    }
    let sections = vec![
        serde_json::json!({
            "heading": "What leaves this machine",
            "lines": [
                format!("task type:   {}", staged.task_type),
                format!("bytes:       {}", staged.byte_length),
                format!("payload:     sha256:{}", staged.payload_sha256),
                format!("staged as:   {}", staged.staged_digest),
            ],
        }),
        serde_json::json!({ "heading": "Who receives it", "lines": who }),
        serde_json::json!({
            "heading": "What this consent allows",
            "lines": [
                "exactly one dispatch of the staged digest above, once (max_uses 1)",
                "nothing else: it grants no model call, no credential, and no inbound authority",
                "akson does not interpret these bytes — it discloses them as staged",
            ],
        }),
        serde_json::json!({
            "heading": "Who staged it",
            "lines": [
                format!("the coordination surface ({COORD_PROTOCOL}), at unix time {}", staged.staged_at),
                "staging was inert: nothing has left this machine yet",
            ],
        }),
    ];
    Ok((sentence, sections))
}

fn unknown_peer() -> Problem {
    // The same problem for "no such label" and "malformed label": a coordination
    // driver learns nothing by probing shapes.
    Problem::new(
        404,
        "unknown-peer",
        "no imported peer answers to that label",
    )
}

fn unknown_stage() -> Problem {
    Problem::new(
        404,
        "unknown-stage",
        "no staged contract has that reference",
    )
}

fn internal() -> Problem {
    Problem::new(500, "internal", "the request could not be processed")
}

/// The §8.5 trusted `now`, as everywhere else authority is written: refuse rather
/// than record a coordination event under a rolled-back clock. The caller holds
/// the store lock.
fn trusted_now(store: &Store) -> Result<i64, Problem> {
    let wall = time::OffsetDateTime::now_utc().unix_timestamp();
    store.trusted_now(wall).map_err(|_| {
        Problem::new(
            503,
            "time-uncertain",
            "the trusted clock moved backward; refusing until time is re-established",
        )
    })
}

fn random_hex() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex(&b)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::control::{authorize, ControlOp, Surface};

    fn state(label: &str) -> (DaemonState, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "akson-coord-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = crate::bootstrap::DaemonConfig::from_env();
        config.data_dir = dir.clone();
        config.receive_addr = None;
        config.interface_url = "https://127.0.0.1:18443/a2a".to_owned();
        let state = DaemonState::bootstrap(&config).unwrap();
        (state, dir)
    }

    fn stage_req(payload: &str) -> ControlRequest {
        ControlRequest::Stage {
            task_type: "https://byom.example/task/exchange/v1".to_owned(),
            performer: String::new(),
            payload_base64: STANDARD.encode(payload),
        }
    }

    #[test]
    fn staging_the_same_bytes_twice_yields_one_record_and_the_same_reference() {
        let (state, dir) = state("idem");
        let first = dispatch_coord(&state, &stage_req("outbound bytes")).unwrap();
        let second = dispatch_coord(&state, &stage_req("outbound bytes")).unwrap();
        assert_eq!(first["stage_ref"], second["stage_ref"]);
        assert_eq!(first["staged_digest"], second["staged_digest"]);
        assert_eq!(first["already_staged"], false);
        assert_eq!(second["already_staged"], true);
        assert_eq!(first["staged_at"], second["staged_at"]);
        // Different bytes are a different disclosure, and get a different ref.
        let other = dispatch_coord(&state, &stage_req("other bytes")).unwrap();
        assert_ne!(other["stage_ref"], first["stage_ref"]);

        // One `staged` event per distinct content, never per call.
        let feed = dispatch_coord(
            &state,
            &ControlRequest::EventsRead {
                cursor: None,
                limit: None,
            },
        )
        .unwrap();
        let events = feed["events"].as_array().unwrap();
        assert_eq!(events.len(), 2, "two contents, two events, three calls");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_is_inert_no_task_no_attempt_no_authority_no_egress() {
        let (state, dir) = state("inert");
        let staged = dispatch_coord(&state, &stage_req("outbound bytes")).unwrap();
        let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();
        let store = state.store();
        let store = store.lock().unwrap();
        // No task: nothing entered the contract/inbox machinery.
        assert!(store.list_submitted_tasks().unwrap().is_empty());
        assert!(matches!(
            store.contract_head(&stage_ref).unwrap(),
            akson_contract::HeadState::Empty
        ));
        // No attempt: nothing could have run.
        assert!(store.attempt_for_task(&stage_ref).unwrap().is_none());
        // No authority: staging mints no consent receipt.
        assert!(store.unconsumed_consent(&stage_ref).unwrap().is_none());
        assert_eq!(
            store.staged_contract(&stage_ref).unwrap().unwrap().status,
            "staged"
        );
        // No egress: nothing was sent and no outcome recorded.
        assert!(store.list_sent_requests().unwrap().is_empty());
        assert!(store.list_outcomes().unwrap().is_empty());
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn consent_is_admin_only_and_binds_the_exact_staged_digest() {
        let (state, dir) = state("consent");
        let staged = dispatch_coord(&state, &stage_req("outbound bytes")).unwrap();
        let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();

        // The gate, not this module, is what keeps consent off the coord socket.
        assert!(authorize(Surface::Coord, ControlOp::StageConsent).is_err());
        authorize(Surface::Admin, ControlOp::StageConsent).unwrap();

        let consent = dispatch_coord(
            &state,
            &ControlRequest::StageConsent {
                stage_ref: stage_ref.clone(),
            },
        )
        .unwrap();
        assert_eq!(consent["staged_digest"], staged["staged_digest"]);
        assert_eq!(consent["max_uses"], 1);
        assert_eq!(consent["uses"], 0);
        assert!(consent["consent_receipt"]
            .as_str()
            .unwrap()
            .starts_with("consent-"));
        // The card the operator saw names the exact digest, and no payload bytes.
        let rendered = format!("{}", consent["sections"]);
        assert!(rendered.contains(staged["payload_sha256"].as_str().unwrap()));
        assert!(!rendered.contains("outbound bytes"));

        // The stage advances to `consented` and reports the live receipt.
        let shown = dispatch_coord(
            &state,
            &ControlRequest::StageShow {
                stage_ref: stage_ref.clone(),
            },
        )
        .unwrap();
        assert_eq!(shown["status"], "consented");
        assert_eq!(
            shown["consent"]["consent_receipt"],
            consent["consent_receipt"]
        );
        // A second consent while the first is unconsumed is refused.
        let again =
            dispatch_coord(&state, &ControlRequest::StageConsent { stage_ref }).unwrap_err();
        assert_eq!(again.status, 409);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_three_unbuilt_ops_answer_a_typed_problem_that_names_them() {
        let (state, dir) = state("unbuilt");
        for (req, op) in [
            (
                ControlRequest::Dispatch {
                    stage_ref: "stage-x".to_owned(),
                    consent_receipt: "consent-x".to_owned(),
                    execution_key: "k".to_owned(),
                },
                "dispatch",
            ),
            (
                ControlRequest::TaskStatus {
                    task_id: "task-1".to_owned(),
                },
                "task_status",
            ),
            (
                ControlRequest::CapabilityEvidence {
                    label: "partner".to_owned(),
                },
                "capability_evidence",
            ),
        ] {
            let problem = dispatch_coord(&state, &req).unwrap_err();
            assert_eq!(problem.status, 501);
            assert_eq!(problem.type_, "urn:akson:error:not-implemented");
            assert!(problem.detail.unwrap().contains(op), "must name {op}");
        }
        // And the handshake says the same thing, so a driver need not probe.
        let who = dispatch_coord(&state, &ControlRequest::CoordWhoAmI).unwrap();
        assert_eq!(who["protocol"], COORD_PROTOCOL);
        assert_eq!(who["protocol_version"], 1);
        assert_eq!(
            who["unimplemented"],
            serde_json::json!(["dispatch", "task_status", "capability_evidence"])
        );
        // Narrower than admin's who_am_i: no local layout crosses this surface.
        assert!(who.get("data_dir").is_none());
        assert!(who.get("receive_addr").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_show_answers_only_about_the_label_it_was_given() {
        let (state, dir) = state("peer");
        let problem = dispatch_coord(
            &state,
            &ControlRequest::PeerShow {
                label: "nobody".to_owned(),
            },
        )
        .unwrap_err();
        assert_eq!(problem.status, 404);
        // A malformed label is indistinguishable from an unknown one.
        let malformed = dispatch_coord(
            &state,
            &ControlRequest::PeerShow {
                label: "NOT a label".to_owned(),
            },
        )
        .unwrap_err();
        assert_eq!(malformed, problem);

        // An imported-but-not-introduced peer reports its state, no invented tuple.
        {
            let store = state.store();
            let store = store.lock().unwrap();
            store
                .add_peer_import("root-thumb-fixture", "partner", "127.0.0.1:18444", 1000)
                .unwrap();
        }
        let shown = dispatch_coord(
            &state,
            &ControlRequest::PeerShow {
                label: "partner".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(shown["verified"], false);
        assert_eq!(shown["status"], "imported");
        assert!(shown.get("identity").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_refuses_a_label_that_names_no_import_and_oversized_bytes() {
        let (state, dir) = state("refuse");
        let unknown = dispatch_coord(
            &state,
            &ControlRequest::Stage {
                task_type: "https://byom.example/task/exchange/v1".to_owned(),
                performer: "nobody".to_owned(),
                payload_base64: STANDARD.encode("bytes"),
            },
        )
        .unwrap_err();
        assert_eq!(unknown.status, 404);

        let big = dispatch_coord(
            &state,
            &ControlRequest::Stage {
                task_type: "https://byom.example/task/exchange/v1".to_owned(),
                performer: String::new(),
                payload_base64: STANDARD.encode(vec![b'x'; MAX_STAGED_PAYLOAD_BYTES + 1]),
            },
        )
        .unwrap_err();
        assert_eq!(big.status, 413);

        let bad_type = dispatch_coord(
            &state,
            &ControlRequest::Stage {
                task_type: "has a space".to_owned(),
                performer: String::new(),
                payload_base64: STANDARD.encode("bytes"),
            },
        )
        .unwrap_err();
        assert_eq!(bad_type.status, 400);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cursors_are_opaque_and_only_ever_come_from_a_reply() {
        assert_eq!(decode_cursor(&encode_cursor(0)).unwrap(), 0);
        assert_eq!(decode_cursor(&encode_cursor(4242)).unwrap(), 4242);
        for bogus in [
            "",
            "0",
            "4242",
            "!!!",
            &URL_SAFE_NO_PAD.encode("other-feed:1"),
        ] {
            assert!(decode_cursor(bogus).is_err(), "{bogus:?} must be refused");
        }
    }

    #[test]
    fn the_event_feed_resumes_from_a_cursor_without_re_delivering() {
        let (state, dir) = state("cursor");
        for i in 0..3 {
            dispatch_coord(&state, &stage_req(&format!("bytes {i}"))).unwrap();
        }
        let first = dispatch_coord(
            &state,
            &ControlRequest::EventsRead {
                cursor: None,
                limit: Some(2),
            },
        )
        .unwrap();
        assert_eq!(first["events"].as_array().unwrap().len(), 2);
        assert_eq!(first["has_more"], true);
        let cursor = first["next_cursor"].as_str().unwrap().to_owned();
        let rest = dispatch_coord(
            &state,
            &ControlRequest::EventsRead {
                cursor: Some(cursor),
                limit: None,
            },
        )
        .unwrap();
        assert_eq!(rest["events"].as_array().unwrap().len(), 1);
        assert_eq!(rest["has_more"], false);
        // A caller that polls again from the end sees nothing new.
        let tail = dispatch_coord(
            &state,
            &ControlRequest::EventsRead {
                cursor: Some(rest["next_cursor"].as_str().unwrap().to_owned()),
                limit: None,
            },
        )
        .unwrap();
        assert!(tail["events"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
