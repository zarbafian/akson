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
//!   one-shot receipt [`dispatch`] must consume, and it requires the **admin**
//!   surface: `ControlOp::StageConsent` needs [`Surface::Admin`], so a coordination
//!   connection gets `forbidden-surface` and never reaches the code below.
//!
//! And the third, which is what [`dispatch`] is for:
//!
//! - **One consent receipt dispatches once.** Staging is inert; dispatch is the
//!   act with an effect, so it spends the receipt. The spend and the record of it
//!   commit in one store transaction, and the *authority* it yields is an
//!   [`akson_store::ConsentBurn`] — no constructor, no `Clone`, no
//!   `Deserialize`, consumed by value at the point of effect. A borrowed permit is
//!   how one grant gets spent twice; this one cannot be borrowed.
//!
//! The bytes now actually leave: [`crate::coord_egress`] carries them to the
//! pinned recipient over the same mutual TLS every other peer-to-peer byte in
//! akson rides, in a coordination envelope that is deliberately **not** a
//! contract. Where they got to is a durable column, not an inference — see
//! [`egress_json`] and `akson_store::COORD_EGRESS_PENDING`.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use akson_crypto::purpose::KeyPurpose;
use akson_evidence::{Statement, Subject, PREDICATE_FEDERATION_CAPABILITY_V1};
use akson_store::{
    ConsentBurn, DispatchOutcome, DispatchRecord, NewStagedContract, Recovery, StagedContract,
    Store, COORD_EGRESS_FAILED, COORD_EGRESS_SENT, COORD_STATUS_DISPATCHED,
};

use crate::bootstrap::{valid_label, DaemonState};
use crate::control::Problem;
use crate::coord_egress::{self, resolve_route, Carriage, CoordRoute};
use crate::socket::ControlRequest;

/// The coordination protocol this surface speaks (ADR-0016).
pub const COORD_PROTOCOL: &str = "akson_byom_exchange_v1";
/// Its version. Bumped only by an ADR; the driver checks it at handshake.
pub const COORD_PROTOCOL_VERSION: u32 = 1;

/// The coordination ops this build answers — all eight of ADR-0016's registry.
const IMPLEMENTED: [&str; 8] = [
    "coord_whoami",
    "peer_show",
    "stage",
    "stage_show",
    "dispatch",
    "task_status",
    "events_read",
    "capability_evidence",
];

/// The coordination ops that are registered but answer nothing. Empty now; kept
/// (rather than removed) because a driver reads it at handshake, and "the list is
/// empty" is an answer while "the field is gone" is a parse change.
const UNIMPLEMENTED: [&str; 0] = [];

/// The coordination ops that answer but do not do the whole of their job. Empty
/// now that `dispatch` has a carrier — kept for the same reason as
/// [`UNIMPLEMENTED`], and the honest place for the next partial op.
const PARTIAL: [serde_json::Value; 0] = [];

/// What `egress.detail` says while a dispatch is committed but its carriage is
/// not known to have completed. This is a real state, not a placeholder: it is
/// what a crash between the commit and the send leaves behind, and it is the
/// default of the durable column rather than something code has to remember to
/// write.
pub const EGRESS_PENDING_DETAIL: &str = "the consent receipt is spent and the dispatch is committed, but this endpoint has no acknowledgement that the bytes left; retry under the same execution_key to resume carriage";

/// Ceiling on a caller-chosen opaque id (`stage_ref`, `consent_receipt`,
/// `execution_key`, `task_id`). These become durable primary keys, so their length
/// is not the driver's to choose freely.
const MAX_ID_CHARS: usize = 128;

/// Ceiling on the bytes one `stage` may persist. The coordination driver is a
/// separate principal: what it can write must be bounded, and a contract payload
/// that needs more than this is not a coordination message.
pub const MAX_STAGED_PAYLOAD_BYTES: usize = 512 * 1024;

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
        ControlRequest::Dispatch {
            stage_ref,
            consent_receipt,
            execution_key,
        } => dispatch(state, stage_ref, consent_receipt, execution_key),
        ControlRequest::TaskStatus { task_id } => task_status(state, task_id),
        ControlRequest::CapabilityEvidence { label } => capability_evidence(state, label),
        _ => Err(Problem::new(
            400,
            "unsupported-operation",
            "this operation is not a coordination request",
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
        // Empty since the carrier landed: `dispatch` now spends consent AND puts
        // the bytes on the wire, so there is no longer a part of it a driver
        // must know about before burning a receipt. The field stays (a driver
        // parses it; "the list is empty" is an answer, "the field is gone" is a
        // parse change), and it is the honest place for the next such gap.
        "partial": PARTIAL,
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
    // What may be staged is exactly what the dispatch envelope may carry, asked
    // of the envelope's own schema. Writing this rule out a second time here is
    // how a `task_type` used to stage, consent, and then fail at envelope-build
    // time with the one-shot receipt already burned — see
    // [`coord_egress::envelope_admits_task_type`].
    if !coord_egress::envelope_admits_task_type(task_type) {
        return Err(Problem::new(
            400,
            "bad-task-type",
            "task_type must be a bounded printable US-ASCII URI with no whitespace — exactly what the coordination envelope admits",
        ));
    }
    // A named recipient must be a valid local label AND one the envelope can
    // carry — the same one-definition rule, for the other member `stage` takes
    // from the driver.
    let label_ok =
        |label: &str| valid_label(label) && coord_egress::envelope_admits_recipient_label(label);
    if !performer.is_empty() && !label_ok(performer) {
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
///
/// **The dispatch ledger is consulted too, and it is the authority.** An
/// unconsumed receipt is not the only reason to refuse: a staging that has
/// already been dispatched has nothing left to authorize, and consenting again
/// would have handed the operator a card that read *"staging was inert: nothing
/// has left this machine yet"* over bytes that had already been carried to a
/// pinned peer and acknowledged by it. That is the §5.2 explicit-decision
/// invariant broken at the only point it exists to protect. So:
///
/// - **any** committed dispatch for this staging ⇒ `409 already-dispatched`,
///   naming the execution key and where its carriage got to;
/// - and the card's claim about what has already left is *derived* from that
///   same ledger read rather than asserted, so it cannot be true only by
///   coincidence.
///
/// Refused rather than permitted-with-an-honest-card, for two reasons. A second
/// consent could only authorize a second disclosure of the same digest, and
/// `coord_dispatches` resolves a `stage_ref` to a single row — a second one
/// would make `task_status` and `stage_show` ambiguous about which disclosure
/// they describe. And the recovery an operator actually wants when carriage has
/// not been acknowledged is the driver's retry under the same `execution_key`,
/// which spends nothing and re-carries the disclosure that already exists; the
/// refusal says so, so the honest card would only have been a slower route to
/// the wrong action.
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
    // The ledger, not the stage row's status projection: what did this staging
    // actually do?
    let dispatched = store.coord_dispatch(stage_ref).map_err(|_| internal())?;
    if let Some(record) = &dispatched {
        return Err(already_dispatched(record));
    }
    let now = trusted_now(&store)?;
    let card = risk_card(&store, &staged, dispatched.as_ref())?;
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
///
/// `dispatched` is this staging's row in the dispatch ledger, as read by the
/// caller. The card's closing claim about what has already left this machine is
/// rendered *from it*: a card that asserts inertness on its own has no way to
/// know, and the one that did was wrong for exactly the staging an operator is
/// most likely to be asked about twice.
fn risk_card(
    store: &Store,
    staged: &StagedContract,
    dispatched: Option<&DispatchRecord>,
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
                egress_line(dispatched),
            ],
        }),
    ];
    Ok((sentence, sections))
}

/// The card's one claim about what has already left this machine, read off the
/// dispatch ledger. Never asserted: an operator deciding whether to authorize a
/// disclosure must be told if this staging has already made one.
fn egress_line(dispatched: Option<&DispatchRecord>) -> String {
    let Some(record) = dispatched else {
        return "staging was inert: nothing has left this machine yet".to_owned();
    };
    match record.egress_state.as_str() {
        COORD_EGRESS_SENT => format!(
            "ALREADY DISCLOSED: dispatch {} was acknowledged by the recipient — these bytes have left this machine",
            record.dispatch_receipt
        ),
        COORD_EGRESS_FAILED => format!(
            "ALREADY DISPATCHED: consent was spent on dispatch {} and its carriage failed; the bytes may or may not have left",
            record.dispatch_receipt
        ),
        _ => format!(
            "ALREADY DISPATCHED: consent was spent on dispatch {} and no acknowledgement is recorded; the bytes may or may not have left",
            record.dispatch_receipt
        ),
    }
}

/// `stage_consent` against a staging the ledger says has already been
/// dispatched. It names the execution key on purpose: the recovery for a
/// carriage that was not acknowledged is a **retry under that key**, which
/// spends nothing, not a second consent — which would authorize a second
/// disclosure.
fn already_dispatched(record: &DispatchRecord) -> Problem {
    Problem {
        type_: "urn:akson:error:already-dispatched".to_owned(),
        title: "this staging has already been dispatched".to_owned(),
        status: 409,
        detail: Some(format!(
            "consent for this staged digest was already spent under execution_key {} (carriage {}); re-present that execution_key to resume carriage, which spends nothing",
            record.execution_key, record.egress_state
        )),
    }
}

/// `dispatch` — one-shot: spend the operator's consent receipt, commit the
/// dispatch of exactly the digest it binds, and carry those bytes to the pinned
/// recipient (ADR-0016 §2).
///
/// The three arguments are three different jobs:
///
/// - `stage_ref` says *which bytes*;
/// - `consent_receipt` is the operator's authority for those bytes, and it is
///   spendable once;
/// - `execution_key` is the driver's name for *one attempt*. Re-sending the same
///   key is a **retry**: it returns the same dispatch receipt, spends nothing,
///   and re-attempts carriage if the bytes are not known to have left. A
///   different key against a spent receipt is a **replay**: refused.
///
/// The order is the whole recovery story, so read it as four steps:
///
/// 1. **Route and build the envelope, under the lock, before anything is
///    spent.** A staging whose recipient is unnamed, un-introduced, suspended,
///    or unreachable-by-shape is refused with the receipt still live — and so is
///    one whose own members cannot form a conforming envelope. Burning an
///    operator's one-shot consent on a disclosure that provably cannot leave
///    would be the worst possible failure of this surface, and routing was only
///    half of "provably cannot leave": the envelope used to be built *after* the
///    spend, so an unsendable staging burned the receipt and then answered
///    `500` to every retry forever.
/// 2. **Spend and commit**, in the one [`Store::dispatch_staged`] transaction,
///    which yields a [`ConsentBurn`] only to the caller that won it. The row it
///    writes is `egress_state = 'pending'` by schema default, so a crash here
///    leaves the truth behind without anything having had to run.
/// 3. **Carry**, with the store lock released (the network must never be held
///    behind the database).
/// 4. **Record** what carriage did, monotonically — `sent` is terminal.
///
/// Crash between 2 and 4 ⇒ the row stays `pending`, the receipt stays spent, and
/// the driver's retry under the same `execution_key` resumes at step 3 without
/// spending anything. That is at-least-once *carriage* of exactly one consented
/// disclosure; the recipient deduplicates on the dispatch receipt, which is the
/// A2A Message id.
fn dispatch(
    state: &DaemonState,
    stage_ref: &str,
    consent_receipt: &str,
    execution_key: &str,
) -> Result<serde_json::Value, Problem> {
    if !valid_id(execution_key) {
        return Err(Problem::new(
            400,
            "bad-execution-key",
            "execution_key must be a non-empty bounded printable id",
        ));
    }
    if !valid_id(stage_ref) {
        return Err(unknown_stage());
    }
    if !valid_id(consent_receipt) {
        return Err(consent_required());
    }

    // --- 1 & 2: route and envelope, then spend. All under one lock; none of it
    // touches the network.
    let (staged, route, envelope, payload, outcome) = {
        let store = state.store();
        let store = store.lock().map_err(|_| internal())?;
        let staged = store
            .staged_contract(stage_ref)
            .map_err(|_| internal())?
            .ok_or_else(unknown_stage)?;
        // BEFORE the spend. Every refusal below leaves the receipt live.
        let route = resolve_route(&store, &staged)?;
        // Also before the spend: the bytes that would go on the wire must be
        // constructible at all. `dispatch_staged` resolves a retry only for the
        // execution key that owns the row and only when it names this same
        // receipt, so the receipt id used here is the one the record will hold
        // on both the first-carriage and the re-carriage path.
        let envelope = coord_egress::envelope(
            &staged,
            &route,
            &state.config().local_performer.root,
            consent_receipt,
        )?;
        let payload = store
            .staged_payload(stage_ref)
            .map_err(|_| internal())?
            .ok_or_else(internal)?;
        let now = trusted_now(&store)?;
        let dispatch_receipt = format!("dispatch-{}", random_hex());
        let event = serde_json::json!({
            "stage_ref": staged.stage_ref,
            "staged_digest": staged.staged_digest,
            "payload_sha256": staged.payload_sha256,
            "task_type": staged.task_type,
            "performer": staged.performer,
            "recipient_root": route.root,
            "byte_length": staged.byte_length,
            "consent_receipt": consent_receipt,
            "execution_key": execution_key,
            "dispatch_receipt": dispatch_receipt,
        });
        let outcome = store
            .dispatch_staged(
                stage_ref,
                consent_receipt,
                execution_key,
                &dispatch_receipt,
                &event,
                now,
            )
            .map_err(|_| internal())?;
        (staged, route, envelope, payload, outcome)
    };

    match outcome {
        // The one path that spent something. `disclose` consumes the burn by
        // value at the point of effect.
        DispatchOutcome::Dispatched(burn) => {
            disclose(state, &staged, &route, &envelope, &payload, burn)
                .map(|r| dispatched_json(&staged, &r, false))
        }
        // A retry. No burn exists here, so nothing can be spent again — but if
        // the bytes are not known to have left, this is exactly the call that
        // resumes their carriage.
        DispatchOutcome::AlreadyDispatched(record) => {
            let record = if record.egress_may_be_attempted() {
                re_disclose(state, &staged, &route, &envelope, &payload, record)?
            } else {
                record
            };
            Ok(dispatched_json(&staged, &record, true))
        }
        DispatchOutcome::ConsentSpent => Err(Problem::new(
            409,
            "consent-spent",
            "that consent receipt has already been dispatched; consent is one-shot",
        )),
        DispatchOutcome::ConsentUnknown => Err(consent_required()),
        DispatchOutcome::ExecutionKeyConflict(_) => Err(Problem::new(
            409,
            "execution-key-conflict",
            "that execution_key already names a different dispatch",
        )),
    }
}

/// Where the staged bytes leave this machine.
///
/// It takes the [`ConsentBurn`] **by value** because this is the point of effect:
/// the burn is the only proof that one receipt was spent, it cannot be cloned,
/// and after this call it does not exist. What the burn gates is precisely the
/// *first* carriage of a dispatch; re-carriage of an already-committed row goes
/// through [`re_disclose`], which spends nothing because reaching it at all means
/// the caller presented the execution key that already owns the row.
fn disclose(
    state: &DaemonState,
    staged: &StagedContract,
    route: &CoordRoute,
    envelope: &serde_json::Value,
    payload: &[u8],
    burn: ConsentBurn,
) -> Result<DispatchRecord, Problem> {
    let record = burn.into_record();
    carry_and_record(state, staged, route, envelope, payload, record)
}

/// Re-carries a dispatch that already committed but is not known to have landed
/// — the crash-recovery path, reached only by a retry under the same
/// `execution_key`. Spends nothing, mints nothing, and cannot create a second
/// dispatch row: the V22 primary key resolved this as a retry before any
/// compare-and-set ran.
fn re_disclose(
    state: &DaemonState,
    staged: &StagedContract,
    route: &CoordRoute,
    envelope: &serde_json::Value,
    payload: &[u8],
    record: DispatchRecord,
) -> Result<DispatchRecord, Problem> {
    carry_and_record(state, staged, route, envelope, payload, record)
}

/// Puts the (already built and validated) envelope on the wire and records where
/// it got to. The store lock is **not** held across the network I/O.
///
/// The body is byte-identical to the one an earlier attempt under this same
/// execution key produced, which is what makes the recipient's §9.2 idempotency
/// treat a re-carriage as the duplicate it is.
fn carry_and_record(
    state: &DaemonState,
    staged: &StagedContract,
    route: &CoordRoute,
    envelope: &serde_json::Value,
    payload: &[u8],
    record: DispatchRecord,
) -> Result<DispatchRecord, Problem> {
    let body = coord_egress::message_body(
        envelope,
        payload,
        &record.dispatch_receipt,
        &record.stage_ref,
    )?;

    let endpoint_key = state.identity().purpose_key(KeyPurpose::TlsEndpoint);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| internal())?;
    let carriage = runtime.block_on(coord_egress::carry(
        &endpoint_key,
        state.endpoint_cert(),
        route,
        &body,
        &staged.staged_digest,
    ));
    let (egress_state, detail) = match carriage {
        Carriage::Acknowledged { detail } => (COORD_EGRESS_SENT, detail),
        Carriage::Failed { detail } => (COORD_EGRESS_FAILED, detail),
    };

    let store = state.store();
    let store = store.lock().map_err(|_| internal())?;
    let now = trusted_now(&store)?;
    let event = serde_json::json!({
        "stage_ref": record.stage_ref,
        "staged_digest": record.staged_digest,
        "execution_key": record.execution_key,
        "dispatch_receipt": record.dispatch_receipt,
        "recipient_root": route.root,
        "egress_state": egress_state,
        "detail": detail,
    });
    store
        .record_egress(&record.execution_key, egress_state, &detail, &event, now)
        .map_err(|_| internal())?
        // The row was just read or written under this same execution key; its
        // disappearance is corruption, not a 404.
        .ok_or_else(internal)
}

/// The one JSON shape a dispatch has, whether it was just committed or replayed by
/// a retry. `replayed` is the only difference, and it is explicit rather than
/// inferable.
fn dispatched_json(
    staged: &StagedContract,
    record: &DispatchRecord,
    replayed: bool,
) -> serde_json::Value {
    serde_json::json!({
        "dispatch_receipt": record.dispatch_receipt,
        "stage_ref": record.stage_ref,
        "staged_digest": record.staged_digest,
        "payload_sha256": staged.payload_sha256,
        "byte_length": staged.byte_length,
        "task_type": staged.task_type,
        "performer": staged.performer,
        "consent_receipt": record.receipt_id,
        "execution_key": record.execution_key,
        "consent_spent": true,
        "status": COORD_STATUS_DISPATCHED,
        "dispatched_at": record.dispatched_at,
        "replayed": replayed,
        "egress": egress_json(record),
    })
}

/// Where a dispatch's bytes are, as the driver reads it. `state` is the durable
/// column, never an inference from anything this process remembers.
fn egress_json(record: &DispatchRecord) -> serde_json::Value {
    serde_json::json!({
        "state": record.egress_state,
        "at": record.egress_at,
        "detail": if record.egress_detail.is_empty() {
            EGRESS_PENDING_DETAIL.to_owned()
        } else {
            record.egress_detail.clone()
        },
        "retryable": record.egress_may_be_attempted(),
    })
}

/// `task_status` — the verification status of a task **this surface dispatched**
/// (ADR-0016 §2).
///
/// The scoping is the security content. This is not `task_show`: it reads the
/// dispatch ledger and nothing else, so an inbound proposal sitting in the
/// operator's inbox is not addressable here — it answers the same generic `404` a
/// made-up id gets. A compromised driver cannot turn a status read into a window
/// onto inbound work.
///
/// A dispatched task is addressed by its dispatch receipt or by the staged
/// reference it dispatched.
fn task_status(state: &DaemonState, task_id: &str) -> Result<serde_json::Value, Problem> {
    if !valid_id(task_id) {
        return Err(unknown_task());
    }
    let store = state.store();
    let store = store.lock().map_err(|_| internal())?;
    let record = store
        .coord_dispatch(task_id)
        .map_err(|_| internal())?
        .ok_or_else(unknown_task)?;
    // A dispatch row exists only because a stage row did; a missing one is
    // corruption, not a 404.
    let staged = store
        .staged_contract(&record.stage_ref)
        .map_err(|_| internal())?
        .ok_or_else(internal)?;
    Ok(serde_json::json!({
        "task_id": task_id,
        "stage_ref": record.stage_ref,
        "staged_digest": record.staged_digest,
        "payload_sha256": staged.payload_sha256,
        "byte_length": staged.byte_length,
        "task_type": staged.task_type,
        "performer": staged.performer,
        "status": staged.status,
        "dispatch_receipt": record.dispatch_receipt,
        "consent_receipt": record.receipt_id,
        "execution_key": record.execution_key,
        "dispatched_at": record.dispatched_at,
        "egress": egress_json(&record),
        "verification": verification_json(&record),
    }))
}

/// What can and cannot be verified about a dispatched coordination payload.
///
/// Two truths that must not be blurred into one optimistic answer:
///
/// - `state` is about **carriage**, and it is read off the durable egress
///   column: `acknowledged` means the pinned recipient echoed this exact staged
///   digest, `unacknowledged` means this endpoint has no such evidence — whether
///   because the send failed or because a crash left it unresolved.
/// - `result_manifest_digest` and `outcome_state` are **always null**, and that
///   is permanent rather than pending. They are contract-shaped fields, and a
///   coordination dispatch is not a contract: there is no deliverable to return,
///   so no result manifest and no requester outcome will ever exist for it.
///   Reporting them as "awaiting" would be a lie a fail-closed capability matrix
///   could not detect.
fn verification_json(record: &DispatchRecord) -> serde_json::Value {
    let acknowledged = record.egress_state == COORD_EGRESS_SENT;
    serde_json::json!({
        "state": if acknowledged { "acknowledged" } else { "unacknowledged" },
        "result_manifest_digest": serde_json::Value::Null,
        "outcome_state": serde_json::Value::Null,
        "detail": if acknowledged {
            "the pinned recipient acknowledged this staged digest; a coordination dispatch carries no contract, so no result manifest or outcome is verifiable against it".to_owned()
        } else if record.egress_state == COORD_EGRESS_FAILED {
            format!("carriage failed and no recipient acknowledged this staged digest: {}", record.egress_detail)
        } else {
            EGRESS_PENDING_DETAIL.to_owned()
        },
    })
}

/// `capability_evidence` — `FederationCapabilityEvidence` for one named peer
/// (ADR-0016 §2), as a **DSSE-signed in-toto Statement v1**.
///
/// Reuse, not a parallel format: the carrier is [`Statement`] under
/// [`PREDICATE_FEDERATION_CAPABILITY_V1`], signed with this endpoint's `evidence`
/// key — the same envelope, payload type, and verification path a result bundle's
/// evidence already uses, so a consumer's fail-closed capability matrix verifies it
/// with the code it has.
///
/// Every dimension is labelled `locally_observed` or `peer_asserted`, because the
/// two are worth different amounts and a matrix that conflates them is not
/// fail-closed. A dimension this endpoint genuinely cannot answer says so
/// (`state: "not_retained"`) rather than reporting a default.
///
/// Signing on a narrow surface is safe here because the driver contributes only a
/// label: every byte of the statement is assembled by the daemon from its own
/// state, and an unknown label is refused before anything is signed.
fn capability_evidence(state: &DaemonState, label: &str) -> Result<serde_json::Value, Problem> {
    if !valid_label(label) {
        return Err(unknown_peer());
    }
    let (root, predicate) = {
        let store = state.store();
        let store = store.lock().map_err(|_| internal())?;
        let import = store
            .peer_import_by_label(label)
            .map_err(|_| internal())?
            .ok_or_else(unknown_peer)?;
        let root = import.root_thumbprint.clone();
        let predicate = capability_predicate(&store, label, &import)?;
        (root, predicate)
    };

    // The subject is the relationship this evidence is about, digested by its
    // pinned root: the statement can be matched to a root without trusting the
    // label, which is local and renameable.
    let statement = Statement::new(
        vec![Subject::sha256(
            &format!("peer/{label}"),
            &hex(&Sha256::digest(root.as_bytes())),
        )],
        PREDICATE_FEDERATION_CAPABILITY_V1,
        predicate,
    );
    let canonical = statement.canonical_bytes().map_err(|_| internal())?;
    let key = state.identity().purpose_key(KeyPurpose::Evidence);
    let envelope = statement.sign(&key).map_err(|_| internal())?;
    Ok(serde_json::json!({
        "label": label,
        "root_thumbprint": root,
        "predicate_type": PREDICATE_FEDERATION_CAPABILITY_V1,
        "statement_digest": hex(&Sha256::digest(&canonical)),
        "signer": {
            "purpose": "evidence",
            "thumbprint": key.verifying().thumbprint(),
        },
        "statement": serde_json::to_value(&statement).map_err(|_| internal())?,
        "evidence": serde_json::to_value(&envelope).map_err(|_| internal())?,
    }))
}

/// One capability dimension: what it is, whether this endpoint saw it or the peer
/// claimed it, what state it is in, and the facts behind that state. Uniform, so a
/// consumer iterates rather than special-cases.
fn dimension(
    name: &str,
    source: &str,
    dim_state: &str,
    facts: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "dimension": name,
        "source": source,
        "state": dim_state,
        "facts": facts,
    })
}

const LOCAL: &str = "locally_observed";
const ASSERTED: &str = "peer_asserted";

/// The `FederationCapabilityEvidence` predicate body: the dimensions ADR-0016 §2
/// names, each from real daemon state. The caller holds the store lock.
fn capability_predicate(
    store: &Store,
    label: &str,
    import: &akson_store::PeerImport,
) -> Result<serde_json::Value, Problem> {
    let root = import.root_thumbprint.as_str();
    let peer = store.get_peer_by_root(root).map_err(|_| internal())?;
    let relationship = store
        .peer_by_root(root)
        .map_err(|_| internal())?
        .map(|(_, status)| status)
        .unwrap_or_else(|| "imported".to_owned());

    let identity = match &peer {
        Some(p) => dimension(
            "peer_identity",
            LOCAL,
            "verified",
            serde_json::json!({
                "root_thumbprint": root,
                "issuer": p.identity.issuer,
                "agent_id": p.identity.agent_id,
                "endpoint_id": p.identity.endpoint_id,
                "tls_certificate_sha256": p.identity.tls_cert.value,
                "agent_card_thumbprint": p.identity.agent_card_key.value,
                "relationship": relationship,
                "epoch": import.epoch,
            }),
        ),
        // Imported but not introduced: the §8.1 tuple does not exist yet, and no
        // identity is invented for it.
        None => dimension(
            "peer_identity",
            LOCAL,
            "unverified",
            serde_json::json!({
                "root_thumbprint": root,
                "relationship": relationship,
                "epoch": import.epoch,
                "reason": "no introduction has committed the §8.1 identity tuple",
            }),
        ),
    };

    let card = match &peer {
        Some(p) => dimension(
            "card_claims",
            ASSERTED,
            "pinned",
            serde_json::json!({
                "security_projection_digest": p.identity.security_projection_digest.value,
                "full_card_digest": p.identity.full_card_digest.value,
                "key_purposes": p.identity.key_bindings.iter()
                    .map(|b| serde_json::json!(b.purpose))
                    .collect::<Vec<_>>(),
            }),
        ),
        None => dimension(
            "card_claims",
            ASSERTED,
            "absent",
            serde_json::json!({
                "reason": "the peer has asserted no Agent Card to this endpoint yet",
            }),
        ),
    };

    // A real gap, reported as one. Introduction pins a key by thumbprint and does
    // not retain the card's validity window, so this endpoint cannot answer key
    // expiry — and a consumer must treat "not retained" as unknown, never as fine.
    let key_expiry = dimension(
        "key_expiry",
        ASSERTED,
        "not_retained",
        serde_json::json!({
            "reason": "akson pins key thumbprints at introduction and does not retain the card's not_before/not_after",
        }),
    );

    let rollback = {
        let (dim_state, detail) = match store.recovery() {
            Recovery::Normal => ("normal", "the checkpoint agrees with the database"),
            Recovery::RollbackDetectionUnavailable => (
                "detection_unavailable",
                "no independent rollback counter exists (interim custody, §15.5)",
            ),
            Recovery::Recovery(_) => (
                "recovery",
                "the database disagrees with the checkpoint; automatic authority is disabled",
            ),
        };
        dimension(
            "rollback_detection",
            LOCAL,
            dim_state,
            serde_json::json!({
                "detectable": matches!(store.recovery(), Recovery::Normal),
                "automatic_authority": store.recovery().automatic_authority_enabled(),
                "state_generation": store.state_generation().map_err(|_| internal())?,
                "trusted_time_floor": store.trusted_time_floor().map_err(|_| internal())?,
                "detail": detail,
            }),
        )
    };

    let confinement = {
        let report = akson_sandbox::diagnose();
        let missing: Vec<_> = report
            .iter()
            .filter(|d| d.required && !d.available)
            .map(|d| serde_json::json!(d.feature))
            .collect();
        dimension(
            "confinement",
            LOCAL,
            if missing.is_empty() {
                "ready"
            } else {
                "degraded"
            },
            serde_json::json!({
                "sandbox_ready": akson_sandbox::all_required_available(&report),
                "unavailable_required": missing,
            }),
        )
    };

    // Budget dimensions that actually exist: the operator's standing inbound
    // ceiling for this root, and this surface's own staging ceiling.
    let budget = {
        let policy = store.auto_approve_for_root(root).map_err(|_| internal())?;
        dimension(
            "budget",
            LOCAL,
            if policy.is_some() {
                "standing_policy"
            } else {
                "always_ask"
            },
            serde_json::json!({
                "auto_approve_task_types": policy.as_ref().map(|p| p.task_types.clone()),
                "auto_approve_max_response_bytes": policy.as_ref().map(|p| p.max_response_bytes),
                "max_staged_payload_bytes": MAX_STAGED_PAYLOAD_BYTES,
            }),
        )
    };

    let schemas = dimension(
        "evidence_schemas",
        LOCAL,
        if akson_ext::namespace::MEDIA_TYPES_ARE_PROVISIONAL {
            "provisional_media_types"
        } else {
            "registered"
        },
        serde_json::json!({
            "statement_type": akson_evidence::STATEMENT_TYPE_V1,
            "payload_type": akson_evidence::INTOTO_PAYLOAD_TYPE,
            "envelope_media_type": akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE,
            "schemas": akson_ext::schema::SchemaId::ALL
                .iter()
                .map(|s| serde_json::json!(format!("{}.v{}", s.name(), s.version())))
                .collect::<Vec<_>>(),
        }),
    );

    Ok(serde_json::json!({
        "schema_version": 1,
        "protocol": COORD_PROTOCOL,
        "label": label,
        "root_thumbprint": root,
        "dimensions": [identity, card, key_expiry, rollback, confinement, budget, schemas],
    }))
}

/// A caller-chosen opaque id: non-empty, bounded, printable, no whitespace. These
/// become durable keys, so they are validated before they can reach the store.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.chars().count() <= MAX_ID_CHARS
        && !id.chars().any(|c| c.is_control() || c.is_whitespace())
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

/// The same `404` for a task this surface never dispatched, a malformed id, and an
/// inbound task in the operator's inbox. `task_status` must not become a way to
/// discover that inbound work exists.
fn unknown_task() -> Problem {
    Problem::new(
        404,
        "unknown-task",
        "no task dispatched from this surface has that reference",
    )
}

/// `dispatch` without live consent. The same problem whether the receipt was never
/// minted, names another stage, or is malformed — the driver may hold a receipt, and
/// it learns nothing about ones it does not hold.
fn consent_required() -> Problem {
    Problem::new(
        409,
        "consent-required",
        "no live consent receipt binds that staged digest",
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

    /// The label every routable fixture below stages to.
    const RECIPIENT: &str = "partner";
    /// The recipient fixture's root. Pinned, introduced, and ACTIVE — but at an
    /// address nothing listens on, so carriage deterministically fails without
    /// any network. These unit tests are about the *decision*; the two-endpoint
    /// tests in `tests/coord_egress_e2e.rs` are about the wire.
    const RECIPIENT_ROOT: &str = "root-recipient-fixture";

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
        seed_recipient(&state);
        (state, dir)
    }

    /// One introduced, ACTIVE peer: an import under `label` plus the §8.1 tuple
    /// behind `root`, pinned at `endpoint_id`.
    fn peer_record(root: &str, endpoint_id: &str, cert_der: &[u8]) -> akson_store::StoredPeer {
        use akson_crypto::identity::{Fingerprint, FingerprintKind, PeerIdentity};
        akson_store::StoredPeer {
            identity: PeerIdentity {
                issuer: Some("orgA".to_owned()),
                agent_id: "alice".to_owned(),
                workload_id: None,
                endpoint_id: endpoint_id.to_owned(),
                tls_cert: Fingerprint::cert_sha256(cert_der),
                agent_card_key: Fingerprint {
                    kind: FingerprintKind::Jwk7638,
                    value: root.to_owned(),
                },
                key_bindings: vec![],
                security_projection_digest: Fingerprint::json_sha256(b"{\"p\":1}"),
                full_card_digest: Fingerprint::json_sha256(b"{\"c\":1}"),
            },
            local_note: String::new(),
        }
    }

    fn pin_peer(state: &DaemonState, root: &str, label: &str, endpoint_id: &str) {
        let store = state.store();
        let store = store.lock().unwrap();
        store
            .add_peer_import(root, label, "127.0.0.1:1", 1_753_574_000)
            .unwrap();
        store
            .put_peer(&peer_record(root, endpoint_id, b"der-fixture"))
            .unwrap();
    }

    /// Pins `partner` as an introduced, ACTIVE peer with a dialable-shaped
    /// endpoint. Port 1 is never listening, so `carry` fails on connect.
    fn seed_recipient(state: &DaemonState) {
        pin_peer(state, RECIPIENT_ROOT, RECIPIENT, "https://127.0.0.1:1/a2a");
    }

    fn stage_req(payload: &str) -> ControlRequest {
        ControlRequest::Stage {
            task_type: "https://byom.example/task/exchange/v1".to_owned(),
            performer: RECIPIENT.to_owned(),
            payload_base64: STANDARD.encode(payload),
        }
    }

    /// A staging with no named recipient — the shape that must never spend
    /// consent, because there is nowhere for its bytes to go.
    fn unrouted_stage_req(payload: &str) -> ControlRequest {
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
    fn the_handshake_names_all_eight_ops_and_claims_no_missing_part() {
        let (state, dir) = state("handshake");
        let who = dispatch_coord(&state, &ControlRequest::CoordWhoAmI).unwrap();
        assert_eq!(who["protocol"], COORD_PROTOCOL);
        assert_eq!(who["protocol_version"], 1);
        assert_eq!(
            who["features"],
            serde_json::json!([
                "coord_whoami",
                "peer_show",
                "stage",
                "stage_show",
                "dispatch",
                "task_status",
                "events_read",
                "capability_evidence"
            ])
        );
        assert_eq!(who["unimplemented"], serde_json::json!([]));
        // Both lists are present and empty: `dispatch` has a carrier, so nothing
        // is advertised as partial — and the field did not vanish, because a
        // driver parses it.
        assert_eq!(who["partial"], serde_json::json!([]));
        assert!(who.get("partial").is_some());
        // Narrower than admin's who_am_i: no local layout crosses this surface.
        assert!(who.get("data_dir").is_none());
        assert!(who.get("receive_addr").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Stages bytes and has ADMIN mint the consent receipt for them, returning
    /// `(stage_ref, consent_receipt)` — the state a driver's `dispatch` starts from.
    fn consented(state: &DaemonState, payload: &str) -> (String, String) {
        let staged = dispatch_coord(state, &stage_req(payload)).unwrap();
        let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();
        let consent = dispatch_coord(
            state,
            &ControlRequest::StageConsent {
                stage_ref: stage_ref.clone(),
            },
        )
        .unwrap();
        let receipt = consent["consent_receipt"].as_str().unwrap().to_owned();
        (stage_ref, receipt)
    }

    fn dispatch_req(stage_ref: &str, receipt: &str, key: &str) -> ControlRequest {
        ControlRequest::Dispatch {
            stage_ref: stage_ref.to_owned(),
            consent_receipt: receipt.to_owned(),
            execution_key: key.to_owned(),
        }
    }

    /// **The one-shot property, at the surface.** One receipt dispatches once: a
    /// second dispatch under a new execution key is refused, and the refusal comes
    /// from the durable `uses` column, not from anything this process remembers.
    #[test]
    fn one_receipt_dispatches_once_and_a_second_key_is_refused() {
        let (state, dir) = state("one-shot");
        let (stage_ref, receipt) = consented(&state, "outbound bytes");

        let first = dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap();
        assert_eq!(first["consent_receipt"], receipt);
        assert_eq!(first["status"], "dispatched");
        assert_eq!(first["consent_spent"], true);
        assert_eq!(first["replayed"], false);
        assert!(first["dispatch_receipt"]
            .as_str()
            .unwrap()
            .starts_with("dispatch-"));
        // Honest about the wire: nothing is listening at the pinned endpoint, so
        // carriage failed and the reply says so — the disclosure decision still
        // committed, and the receipt is still spent.
        assert_eq!(first["egress"]["state"], COORD_EGRESS_FAILED);
        assert_eq!(first["egress"]["retryable"], true);

        // A DIFFERENT execution key on the same receipt: refused, one-shot.
        let replay =
            dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-2")).unwrap_err();
        assert_eq!(replay.status, 409);
        assert_eq!(replay.type_, "urn:akson:error:consent-spent");

        // The durable state says so too: no live consent, exactly one dispatch.
        let store = state.store();
        let store = store.lock().unwrap();
        assert!(store.unconsumed_consent(&stage_ref).unwrap().is_none());
        assert_eq!(
            store.staged_contract(&stage_ref).unwrap().unwrap().status,
            "dispatched"
        );
        let dispatched = store
            .read_coord_events(0, 50)
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "dispatched")
            .count();
        assert_eq!(dispatched, 1, "one dispatch, one event");
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Retrying the same `execution_key` is safe: the same dispatch receipt comes
    /// back, marked `replayed`, and nothing is spent twice. This is the difference
    /// between a driver that lost its reply and a driver replaying an old one.
    #[test]
    fn the_same_execution_key_retries_to_the_same_receipt() {
        let (state, dir) = state("retry");
        let (stage_ref, receipt) = consented(&state, "outbound bytes");
        let first = dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap();
        let again = dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap();
        assert_eq!(again["dispatch_receipt"], first["dispatch_receipt"]);
        assert_eq!(again["dispatched_at"], first["dispatched_at"]);
        assert_eq!(again["replayed"], true);
        assert_eq!(first["replayed"], false);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dispatch cannot run without consent the driver did not mint — and consent is
    /// not on this surface, so it cannot mint one either.
    #[test]
    fn dispatch_without_a_live_consent_receipt_is_refused_and_stages_stay_inert() {
        let (state, dir) = state("no-consent");
        let staged = dispatch_coord(&state, &stage_req("outbound bytes")).unwrap();
        let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();

        // No receipt was ever minted for this stage.
        let refused = dispatch_coord(&state, &dispatch_req(&stage_ref, "consent-invented", "k1"))
            .unwrap_err();
        assert_eq!(refused.status, 409);
        assert_eq!(refused.type_, "urn:akson:error:consent-required");

        // Minting one is admin's, and the coord surface cannot reach it at all.
        assert!(authorize(Surface::Coord, ControlOp::StageConsent).is_err());

        // An unknown stage is a 404, and a malformed one is indistinguishable.
        for bad in ["stage-nope", "not a ref", ""] {
            let problem =
                dispatch_coord(&state, &dispatch_req(bad, "consent-x", "k2")).unwrap_err();
            assert_eq!(problem.status, 404, "{bad:?}");
        }
        // An unbounded execution key is refused before it can become a durable key.
        let long = "k".repeat(MAX_ID_CHARS + 1);
        let problem =
            dispatch_coord(&state, &dispatch_req(&stage_ref, "consent-x", &long)).unwrap_err();
        assert_eq!(problem.status, 400);

        // Nothing moved: the stage is still inert and nothing was dispatched.
        let store = state.store();
        let store = store.lock().unwrap();
        assert_eq!(
            store.staged_contract(&stage_ref).unwrap().unwrap().status,
            "staged"
        );
        assert!(store.coord_dispatch(&stage_ref).unwrap().is_none());
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A staging with no named recipient can be consented to — the operator's
    /// card says so in as many words — but it cannot be dispatched, and the
    /// refusal comes **before** the spend. Burning a one-shot consent on a
    /// disclosure that provably cannot leave would be this surface's worst
    /// possible failure.
    #[test]
    fn an_unroutable_stage_is_refused_before_the_receipt_is_spent() {
        let (state, dir) = state("unroutable");
        let staged = dispatch_coord(&state, &unrouted_stage_req("outbound bytes")).unwrap();
        let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();
        let consent = dispatch_coord(
            &state,
            &ControlRequest::StageConsent {
                stage_ref: stage_ref.clone(),
            },
        )
        .unwrap();
        let receipt = consent["consent_receipt"].as_str().unwrap().to_owned();

        let refused =
            dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap_err();
        assert_eq!(refused.status, 409);
        assert_eq!(refused.type_, "urn:akson:error:unroutable-recipient");

        let store = state.store();
        let store = store.lock().unwrap();
        assert!(
            store.unconsumed_consent(&stage_ref).unwrap().is_some(),
            "the receipt must still be live"
        );
        assert!(store.coord_dispatch(&stage_ref).unwrap().is_none());
        assert_eq!(
            store.staged_contract(&stage_ref).unwrap().unwrap().status,
            "consented"
        );
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A `task_type` the envelope cannot carry never reaches a consent
    /// receipt.** One non-ASCII character used to pass `stage`'s own check and
    /// fail the envelope schema's — after the burn — so the receipt was spent,
    /// the row sat `pending`, every retry answered `500`, and the bytes could
    /// never leave. `stage` now asks the envelope's schema, so the case is
    /// refused at the door with nothing durable written.
    #[test]
    fn a_task_type_the_envelope_cannot_carry_never_reaches_a_consent_receipt() {
        let (state, dir) = state("bad-type");
        for refused in [
            "https://byom.example/tâsk/v1",
            "https://byom.example/t\u{200b}ask/v1",
            "https://byom.example/tasк/v1",
        ] {
            let problem = dispatch_coord(
                &state,
                &ControlRequest::Stage {
                    task_type: refused.to_owned(),
                    performer: RECIPIENT.to_owned(),
                    payload_base64: STANDARD.encode("outbound bytes"),
                },
            )
            .unwrap_err();
            assert_eq!(problem.status, 400, "{refused:?}");
            assert_eq!(
                problem.type_, "urn:akson:error:bad-task-type",
                "{refused:?}"
            );
        }
        // Nothing durable: no stage row means no receipt can ever bind these.
        let store = state.store();
        let store = store.lock().unwrap();
        assert!(store.read_coord_events(0, 50).unwrap().is_empty());
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A dispatch whose envelope cannot be built refuses BEFORE the spend.**
    /// ADR-0016 §6 says a disclosure that provably cannot leave must not burn
    /// the receipt, and routing was only half of "cannot leave": the envelope
    /// used to be built after the spend. Here the pinned root is not a root
    /// shape, so no conforming envelope exists — and the receipt survives.
    #[test]
    fn a_dispatch_whose_envelope_cannot_be_built_does_not_spend_the_receipt() {
        let (state, dir) = state("bad-envelope");
        // A root the envelope schema's `root` pattern refuses. It reaches the
        // store the way any pinned identity does; nothing between `stage` and
        // the wire re-checks it, which is why the pre-spend build matters.
        pin_peer(&state, "not/a/root", "elsewhere", "https://127.0.0.1:1/a2a");
        let staged = dispatch_coord(
            &state,
            &ControlRequest::Stage {
                task_type: "https://byom.example/task/exchange/v1".to_owned(),
                performer: "elsewhere".to_owned(),
                payload_base64: STANDARD.encode("outbound bytes"),
            },
        )
        .unwrap();
        let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();
        let receipt = dispatch_coord(
            &state,
            &ControlRequest::StageConsent {
                stage_ref: stage_ref.clone(),
            },
        )
        .unwrap()["consent_receipt"]
            .as_str()
            .unwrap()
            .to_owned();

        let problem =
            dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap_err();
        assert_eq!(problem.type_, "urn:akson:error:bad-envelope");

        let store = state.store();
        let store = store.lock().unwrap();
        assert!(
            store.unconsumed_consent(&stage_ref).unwrap().is_some(),
            "an unsendable envelope must not burn the operator's receipt"
        );
        assert!(store.coord_dispatch(&stage_ref).unwrap().is_none());
        assert_eq!(
            store.staged_contract(&stage_ref).unwrap().unwrap().status,
            "consented"
        );
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A suspended relationship receives no outward disclosure**, and the
    /// refusal comes before the spend. §8.4 makes reinstatement the operator's
    /// call; a dispatch must never be the thing that heals it.
    #[test]
    fn a_suspended_recipient_is_unroutable_and_the_receipt_survives() {
        let (state, dir) = state("suspended");
        let (stage_ref, receipt) = consented(&state, "outbound bytes");
        {
            // The production path to suspension: a re-introduction presenting
            // rotated pinned material (§8.4).
            let store = state.store();
            let store = store.lock().unwrap();
            let epoch = store
                .peer_import_by_label(RECIPIENT)
                .unwrap()
                .unwrap()
                .epoch;
            let outcome = store
                .commit_introduced_peer(
                    RECIPIENT_ROOT,
                    epoch,
                    &peer_record(RECIPIENT_ROOT, "https://127.0.0.1:1/a2a", b"rotated-der"),
                    &[],
                    1_753_574_100,
                )
                .unwrap();
            assert!(
                matches!(outcome, akson_store::IntroCommitOutcome::Suspended(_)),
                "{outcome:?}"
            );
            assert_ne!(
                store.peer_status_by_root(RECIPIENT_ROOT).unwrap(),
                Some(akson_store::PeerStatus::Active)
            );
        }
        let refused =
            dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap_err();
        assert_eq!(refused.status, 409);
        assert_eq!(refused.type_, "urn:akson:error:unroutable-recipient");

        let store = state.store();
        let store = store.lock().unwrap();
        assert!(store.unconsumed_consent(&stage_ref).unwrap().is_some());
        assert!(store.coord_dispatch(&stage_ref).unwrap().is_none());
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A recipient pinned at something that is not a usable https URL cannot be
    /// dialled, so the disclosure provably cannot leave — refused before the
    /// spend, like every other unroutable shape.
    #[test]
    fn a_recipient_with_no_usable_https_endpoint_is_unroutable() {
        let (state, dir) = state("bad-endpoint");
        // Introduced and ACTIVE, but its pinned endpoint is not dialable.
        pin_peer(&state, "root-no-endpoint", "nowhere", "ep-alice-1");
        let staged = dispatch_coord(
            &state,
            &ControlRequest::Stage {
                task_type: "https://byom.example/task/exchange/v1".to_owned(),
                performer: "nowhere".to_owned(),
                payload_base64: STANDARD.encode("outbound bytes"),
            },
        )
        .unwrap();
        let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();
        let receipt = dispatch_coord(
            &state,
            &ControlRequest::StageConsent {
                stage_ref: stage_ref.clone(),
            },
        )
        .unwrap()["consent_receipt"]
            .as_str()
            .unwrap()
            .to_owned();

        let refused =
            dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap_err();
        assert_eq!(refused.status, 409);
        assert_eq!(refused.type_, "urn:akson:error:unroutable-recipient");
        let store = state.store();
        let store = store.lock().unwrap();
        assert!(store.unconsumed_consent(&stage_ref).unwrap().is_some());
        assert!(store.coord_dispatch(&stage_ref).unwrap().is_none());
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A staging that has already been dispatched cannot be consented again,
    /// and the card never claims otherwise.** `stage_consent` used to look only
    /// for an unconsumed receipt, so a dispatched staging minted a second one
    /// and handed the operator a card reading "staging was inert: nothing has
    /// left this machine yet" over bytes that had already been carried. The
    /// refusal names the recovery that actually exists: retry the execution key.
    #[test]
    fn a_dispatched_staging_cannot_be_consented_again() {
        let (state, dir) = state("re-consent");
        let (stage_ref, receipt) = consented(&state, "outbound bytes");
        let dispatched =
            dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap();

        let refused = dispatch_coord(
            &state,
            &ControlRequest::StageConsent {
                stage_ref: stage_ref.clone(),
            },
        )
        .unwrap_err();
        assert_eq!(refused.status, 409);
        assert_eq!(refused.type_, "urn:akson:error:already-dispatched");
        let detail = refused.detail.unwrap_or_default();
        assert!(detail.contains("exec-1"), "{detail}");
        assert!(detail.contains("carriage failed"), "{detail}");
        assert_eq!(dispatched["execution_key"], "exec-1");

        // And no second authorization exists: one staging, one disclosure.
        let store = state.store();
        let store = store.lock().unwrap();
        assert!(store.unconsumed_consent(&stage_ref).unwrap().is_none());
        let consents = store
            .read_coord_events(0, 200)
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "consent_recorded")
            .count();
        assert_eq!(consents, 1, "one staging, one consent");
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The card's claim about what has already left this machine is read off the
    /// dispatch ledger, not asserted. `stage_consent` refuses before it can
    /// render a card over a dispatched staging, so this exercises the renderer
    /// directly — the claim must be false-proof on its own terms, not merely
    /// unreachable.
    #[test]
    fn the_risk_card_reads_the_dispatch_ledger() {
        let (state, dir) = state("card");
        let (stage_ref, receipt) = consented(&state, "outbound bytes");
        let store = state.store();
        let store = store.lock().unwrap();
        let staged = store.staged_contract(&stage_ref).unwrap().unwrap();

        // Before any dispatch, the ledger is empty and the card says so.
        let (_, sections) = risk_card(&store, &staged, None).unwrap();
        let rendered = serde_json::Value::from(sections).to_string();
        assert!(rendered.contains("staging was inert"), "{rendered}");
        drop(store);

        dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap();
        let store = state.store();
        let store = store.lock().unwrap();
        let record = store.coord_dispatch(&stage_ref).unwrap().unwrap();
        let (_, sections) = risk_card(&store, &staged, Some(&record)).unwrap();
        let rendered = serde_json::Value::from(sections).to_string();
        assert!(
            !rendered.contains("staging was inert"),
            "the card must not claim inertness after a dispatch: {rendered}"
        );
        assert!(rendered.contains("ALREADY DISPATCHED"), "{rendered}");
        assert!(rendered.contains(&record.dispatch_receipt), "{rendered}");

        // And an acknowledged one says the bytes have left, in as many words.
        let sent = akson_store::DispatchRecord {
            egress_state: COORD_EGRESS_SENT.to_owned(),
            ..record
        };
        let (_, sections) = risk_card(&store, &staged, Some(&sent)).unwrap();
        let rendered = serde_json::Value::from(sections).to_string();
        assert!(rendered.contains("ALREADY DISCLOSED"), "{rendered}");
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A receipt minted for one stage cannot dispatch another one's bytes.
    #[test]
    fn a_receipt_does_not_travel_between_staged_digests() {
        let (state, dir) = state("cross");
        let (_, receipt) = consented(&state, "first bytes");
        let other = dispatch_coord(&state, &stage_req("second bytes")).unwrap();
        let other_ref = other["stage_ref"].as_str().unwrap().to_owned();

        let refused =
            dispatch_coord(&state, &dispatch_req(&other_ref, &receipt, "exec-1")).unwrap_err();
        assert_eq!(refused.status, 409);
        assert_eq!(refused.type_, "urn:akson:error:consent-required");
        // And the receipt it tried to borrow is still live for its own stage.
        let store = state.store();
        let store = store.lock().unwrap();
        assert_eq!(
            store.staged_contract(&other_ref).unwrap().unwrap().status,
            "staged"
        );
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `task_status` reports what this surface dispatched, addressed either way,
    /// and is honest about what a coordination dispatch can never have: no
    /// recipient acknowledged this one (nothing is listening), and no result
    /// manifest will ever exist for it, because it is not a contract.
    #[test]
    fn task_status_reports_a_dispatch_this_surface_committed() {
        let (state, dir) = state("status");
        let (stage_ref, receipt) = consented(&state, "outbound bytes");
        let dispatched =
            dispatch_coord(&state, &dispatch_req(&stage_ref, &receipt, "exec-1")).unwrap();
        let dispatch_receipt = dispatched["dispatch_receipt"].as_str().unwrap().to_owned();

        for id in [dispatch_receipt.as_str(), stage_ref.as_str()] {
            let status = dispatch_coord(
                &state,
                &ControlRequest::TaskStatus {
                    task_id: id.to_owned(),
                },
            )
            .unwrap();
            assert_eq!(status["task_id"], id);
            assert_eq!(status["stage_ref"], stage_ref);
            assert_eq!(status["staged_digest"], dispatched["staged_digest"]);
            assert_eq!(status["consent_receipt"], receipt);
            assert_eq!(status["execution_key"], "exec-1");
            assert_eq!(status["status"], "dispatched");
            assert_eq!(status["egress"]["state"], COORD_EGRESS_FAILED);
            assert_eq!(status["verification"]["state"], "unacknowledged");
            assert_eq!(
                status["verification"]["result_manifest_digest"],
                serde_json::Value::Null
            );
            assert_eq!(
                status["verification"]["outcome_state"],
                serde_json::Value::Null
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `capability_evidence` is a DSSE-signed in-toto Statement — akson's existing
    /// evidence carrier — and it verifies under this endpoint's `evidence` key.
    #[test]
    fn capability_evidence_is_a_verifiable_intoto_statement_with_labelled_sources() {
        let (state, dir) = state("capability");
        {
            let store = state.store();
            let store = store.lock().unwrap();
            store
                .add_peer_import("root-thumb-fixture", "other", "127.0.0.1:18444", 1000)
                .unwrap();
        }
        let evidence = dispatch_coord(
            &state,
            &ControlRequest::CapabilityEvidence {
                label: "other".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(evidence["label"], "other");
        assert_eq!(evidence["root_thumbprint"], "root-thumb-fixture");
        assert_eq!(
            evidence["predicate_type"],
            akson_evidence::PREDICATE_FEDERATION_CAPABILITY_V1
        );

        // The envelope is the same DSSE/in-toto carrier result evidence uses, and it
        // verifies under the endpoint's evidence key — not a parallel format.
        let envelope: akson_ext::dsse::Envelope =
            serde_json::from_value(evidence["evidence"].clone()).unwrap();
        assert_eq!(envelope.payload_type, akson_evidence::INTOTO_PAYLOAD_TYPE);
        let key = state
            .identity()
            .purpose_key(KeyPurpose::Evidence)
            .verifying();
        let verified = akson_evidence::Statement::verify(&envelope, &key).unwrap();
        assert_eq!(
            verified.predicate_type,
            akson_evidence::PREDICATE_FEDERATION_CAPABILITY_V1
        );
        // A wrong-purpose key cannot verify it (one key, one role).
        let wrong = state
            .identity()
            .purpose_key(KeyPurpose::TaskResult)
            .verifying();
        assert!(akson_evidence::Statement::verify(&envelope, &wrong).is_err());

        // Every dimension declares which of the two kinds of claim it is.
        let dims = verified.predicate["dimensions"].as_array().unwrap();
        let names: Vec<&str> = dims
            .iter()
            .map(|d| d["dimension"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "peer_identity",
                "card_claims",
                "key_expiry",
                "rollback_detection",
                "confinement",
                "budget",
                "evidence_schemas"
            ]
        );
        for d in dims {
            let source = d["source"].as_str().unwrap();
            assert!(
                source == "locally_observed" || source == "peer_asserted",
                "{source} is not one of the two"
            );
            assert!(d["state"].is_string());
            assert!(d["facts"].is_object());
        }
        // An un-introduced peer asserts no card, and none is invented for it.
        assert_eq!(dims[0]["state"], "unverified");
        assert_eq!(dims[1]["state"], "absent");
        // A gap this endpoint genuinely has is reported as a gap.
        assert_eq!(dims[2]["state"], "not_retained");

        // An unknown or malformed label yields the same 404 `peer_show` gives, and
        // signs nothing.
        for label in ["nobody", "NOT a label"] {
            let problem = dispatch_coord(
                &state,
                &ControlRequest::CapabilityEvidence {
                    label: label.to_owned(),
                },
            )
            .unwrap_err();
            assert_eq!(problem.status, 404, "{label:?}");
            assert_eq!(problem.type_, "urn:akson:error:unknown-peer");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The operator's private note on a peer never crosses this surface — not
    /// through `peer_show`, and not inside a signed capability statement either.
    #[test]
    fn capability_evidence_never_carries_the_operators_private_note() {
        use akson_crypto::identity::{Fingerprint, FingerprintKind, PeerIdentity};
        let (state, dir) = state("note");
        {
            let store = state.store();
            let store = store.lock().unwrap();
            store
                .add_peer_import("root-note-fixture", "other", "127.0.0.1:18444", 1000)
                .unwrap();
            store
                .put_peer(&akson_store::StoredPeer {
                    identity: PeerIdentity {
                        issuer: Some("orgA".to_owned()),
                        agent_id: "alice".to_owned(),
                        workload_id: None,
                        endpoint_id: "ep-alice-1".to_owned(),
                        tls_cert: Fingerprint::cert_sha256(b"der-fixture"),
                        agent_card_key: Fingerprint {
                            kind: FingerprintKind::Jwk7638,
                            value: "root-note-fixture".to_owned(),
                        },
                        key_bindings: vec![],
                        security_projection_digest: Fingerprint::json_sha256(b"{\"p\":1}"),
                        full_card_digest: Fingerprint::json_sha256(b"{\"c\":1}"),
                    },
                    local_note: "OPERATOR PRIVATE NOTE".to_owned(),
                })
                .unwrap();
        }
        let evidence = dispatch_coord(
            &state,
            &ControlRequest::CapabilityEvidence {
                label: "other".to_owned(),
            },
        )
        .unwrap();
        assert!(!evidence.to_string().contains("OPERATOR PRIVATE NOTE"));
        // The signed payload too, not just the wrapper.
        let envelope: akson_ext::dsse::Envelope =
            serde_json::from_value(evidence["evidence"].clone()).unwrap();
        let payload = STANDARD.decode(&envelope.payload).unwrap();
        assert!(!String::from_utf8_lossy(&payload).contains("OPERATOR PRIVATE NOTE"));
        // Now that the peer is introduced, the identity dimension is verified and
        // the card dimension carries what the peer asserted.
        let dims = serde_json::from_slice::<serde_json::Value>(&payload).unwrap()["predicate"]
            ["dimensions"]
            .clone();
        assert_eq!(dims[0]["state"], "verified");
        assert_eq!(dims[1]["state"], "pinned");
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
                .add_peer_import("root-thumb-fixture", "other", "127.0.0.1:18444", 1000)
                .unwrap();
        }
        let shown = dispatch_coord(
            &state,
            &ControlRequest::PeerShow {
                label: "other".to_owned(),
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
