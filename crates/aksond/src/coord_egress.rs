//! The outbound carrier for a consented coordination dispatch (ADR-0016 §2).
//!
//! What goes on the wire, and nothing else:
//!
//! ```text
//! POST https://<recipient>/a2a          (mutual TLS, pinned both ways)
//! SendMessage{ message_id = <dispatch receipt>, context_id = <stage ref>, parts = [
//!   application/vnd.akson-dev.coord-dispatch.v1+json   { staged_digest, payload_sha256,
//!                                                        task_type, recipient_label,
//!                                                        recipient_root, sender_root,
//!                                                        consent_receipt, … }
//!   application/octet-stream                           <the staged bytes, verbatim>
//! ]}
//! ```
//!
//! **A coordination dispatch is not a contract, and gets its own envelope.**
//! Akson's contract schema cannot hold an opaque byom payload without contract
//! terms — an objective, a deliverable, a deadline — that the risk card the
//! operator read never mentioned; synthesising them would make the consent
//! receipt authorize more than the operator actually agreed to. So the envelope
//! carries exactly what `stage` accepted and consent covered — the payload, its
//! recipient, its `task_type`, the staged digest — plus the identity of the
//! receipt that authorizes it, and the two roots the receiver needs to check it
//! is the addressee and the sender is who it claims. Every member is justified
//! in `spec/ext/coord-dispatch.v1.schema.json`; adding one means changing what
//! consent means.
//!
//! **How the receiver knows it is real.** Two independent checks, neither of
//! which trusts the envelope:
//!
//! 1. *Sender* — the connection is mutual TLS pinned to a peer record, so the
//!    root is the transport's, not a claim in the body. The envelope's
//!    `sender_root` must equal it, and its `recipient_root` must equal the
//!    receiver's own root, so a misrouted disclosure is refused even though the
//!    channel authenticated fine.
//! 2. *Digest* — SHA-256 over the received payload bytes must equal
//!    `payload_sha256`, and the ADR-0016 §4 derivation over
//!    `{payload_sha256, recipient_label, task_type}` must equal `staged_digest`.
//!    That second one is why `recipient_label` is on the wire: without it the
//!    receiver could check the bytes but not the digest the operator's consent
//!    actually binds.
//!
//! The envelope is **not signed**. Its authenticity is the channel's — the same
//! pinned mutual TLS every other peer-to-peer byte in akson rides — and its
//! integrity is the digest chain above. A signature would need a purpose key,
//! and there is no key purpose for "coordination dispatch": borrowing
//! `contract-proposal` to sign a non-contract is exactly the one-key-one-role
//! violation this codebase refuses elsewhere. The honest consequence is stated
//! rather than hidden: a coordination dispatch is authenticated, not
//! non-repudiable, and a recipient cannot prove to a third party who sent it.
//!
//! **One logical dispatch is one sequence of bytes.** [`message_body`] emits RFC
//! 8785 canonical JSON, so re-carrying a dispatch after a lost acknowledgement
//! produces *byte-identical* bytes. That is not tidiness: the recipient's §9.2
//! idempotency covers the body digest, so a body that re-serialised differently
//! would turn the retry ADR-0016 §6 promises into a `409 conflict` and leave a
//! delivered disclosure recorded as never delivered. `Part::Data` is a
//! `HashMap`-backed `Struct`, whose serde output has no fixed member order, so
//! serialising the request struct directly is exactly the trap this avoids.
//!
//! **What `stage` may accept is what the envelope may carry.** [`envelope_admits_task_type`]
//! and [`envelope_admits_recipient_label`] answer that question with the schema
//! itself, so `stage` cannot accept a value that only fails once a consent
//! receipt has been burned on it.

use akson_crypto::cert::EndpointCert;
use akson_crypto::keypair::PurposeKey;
use akson_ext::schema::{validate, SchemaId};
use akson_proto::v1::{part::Content, Message, Part, SendMessageRequest};
use akson_store::{StagedContract, Store};

use crate::a2a_client::post_a2a;
use crate::control::Problem;
use crate::coord::{stage_reference, COORD_PROTOCOL};

/// The Part media type carrying the coordination envelope. It is the payload
/// media type directly rather than the DSSE envelope type, because there is no
/// DSSE envelope here — see the module note on why this object is unsigned.
pub fn coord_dispatch_media_type() -> String {
    SchemaId::CoordDispatchV1.payload_media_type()
}

/// The Part media type carrying the staged bytes. Deliberately opaque: akson
/// does not interpret a coordination payload, and saying `application/json`
/// would invite something to try.
pub const COORD_PAYLOAD_MEDIA_TYPE: &str = "application/octet-stream";

// --- What may be staged is what may be enveloped ------------------------------

/// A candidate envelope: the two members a driver chooses, and a fixed,
/// schema-satisfying stand-in for every member the *daemon* chooses (the roots,
/// the digests, the receipt id). Validating it answers "could these two values
/// ever ride the envelope?" using the schema itself rather than a second,
/// hand-written rule that can drift from it.
fn candidate_envelope(task_type: &str, recipient_label: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "protocol": COORD_PROTOCOL,
        "task_type": task_type,
        "recipient_label": recipient_label,
        "recipient_root": "candidate-root",
        "sender_root": "candidate-root",
        "payload_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "staged_digest": "0000000000000000000000000000000000000000000000000000000000000000",
        "consent_receipt": "consent-candidate",
    })
}

/// A `task_type` known to satisfy the schema, used while testing a label.
const ADMISSIBLE_TASK_TYPE: &str = "https://example.invalid/task/v1";
/// A `recipient_label` known to satisfy the schema, used while testing a type.
const ADMISSIBLE_LABEL: &str = "peer";

/// Whether `task_type` can ride the coordination envelope (ADR-0016 §5).
///
/// **This is `stage`'s admissibility rule, and it is the envelope's own.** The
/// two used to be written separately — `stage` refused control and whitespace
/// characters, while the schema's `task_type` pattern admits only printable
/// US-ASCII — and one non-ASCII character fell into the gap: it staged, it
/// consented, and it failed only when the envelope was built, *after* the
/// one-shot receipt had been spent. There was then no way to make those bytes
/// leave and no way to get the receipt back. Asking the schema is what makes
/// "acceptable to stage" and "acceptable to send" one predicate with one
/// definition, so that gap cannot reopen by editing one of two places.
pub fn envelope_admits_task_type(task_type: &str) -> bool {
    validate(
        SchemaId::CoordDispatchV1,
        &candidate_envelope(task_type, ADMISSIBLE_LABEL),
    )
    .is_ok()
}

/// Whether `label` can ride the coordination envelope as `recipient_label`
/// (ADR-0016 §5) — the same one-definition rule as
/// [`envelope_admits_task_type`], for the other member `stage` accepts from the
/// driver.
pub fn envelope_admits_recipient_label(label: &str) -> bool {
    validate(
        SchemaId::CoordDispatchV1,
        &candidate_envelope(ADMISSIBLE_TASK_TYPE, label),
    )
    .is_ok()
}

/// A resolved recipient: everything needed to reach exactly one pinned peer, and
/// nothing the driver chose.
///
/// It is built from the *staged* recipient label under the store lock, before
/// any consent is spent. That order is the point: a dispatch that cannot
/// possibly leave must not burn the operator's one-shot receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordRoute {
    /// The label as staged — one of the three preimages of the staged digest.
    pub label: String,
    /// The relationship key. Labels are local and renameable; this is identity.
    pub root: String,
    /// The peer's A2A interface URL, as pinned at introduction.
    pub endpoint: String,
    /// The peer's endpoint-certificate fingerprint, as pinned at introduction.
    /// The TLS handshake is pinned to this, so an impostor at the same address
    /// fails the handshake rather than receiving the disclosure.
    pub tls_fingerprint: String,
}

/// Resolves the staged recipient to a live, pinned, ACTIVE peer, or refuses.
///
/// Called with the store lock held and **before** `dispatch_staged`, so every
/// refusal here leaves the consent receipt unspent. An unrouted stage (no
/// recipient label) is refused for the same reason: the operator's risk card
/// said "no named recipient", and there is nowhere for those bytes to go.
pub fn resolve_route(store: &Store, staged: &StagedContract) -> Result<CoordRoute, Problem> {
    if staged.performer.is_empty() {
        return Err(unroutable(
            "this staging named no recipient, so there is nowhere to disclose it",
        ));
    }
    let import = store
        .peer_import_by_label(&staged.performer)
        .map_err(|_| internal())?
        .ok_or_else(|| unroutable("that recipient label no longer names an imported peer"))?;
    let peer = store
        .get_peer_by_root(&import.root_thumbprint)
        .map_err(|_| internal())?
        .ok_or_else(|| {
            unroutable("that recipient has never been introduced, so no endpoint is pinned")
        })?;
    // Only an ACTIVE relationship receives an outward disclosure. A suspended
    // peer stays the operator's call (§8.4) — never auto-healed by a dispatch.
    if store
        .peer_status_by_root(&import.root_thumbprint)
        .map_err(|_| internal())?
        != Some(akson_store::PeerStatus::Active)
    {
        return Err(unroutable(
            "that recipient is not an active peer (suspended or removed)",
        ));
    }
    if crate::a2a_client::parse_endpoint(&peer.identity.endpoint_id).is_none() {
        return Err(unroutable(
            "that recipient's pinned endpoint is not a usable https URL",
        ));
    }
    Ok(CoordRoute {
        label: staged.performer.clone(),
        root: import.root_thumbprint,
        endpoint: peer.identity.endpoint_id,
        tls_fingerprint: peer.identity.tls_cert.value,
    })
}

/// The coordination dispatch envelope (ADR-0016 §2), schema-validated before it
/// can leave. Validating our own output is not ceremony: the schema is the
/// contract with the receiver, and a producer that only validates what it
/// receives discovers its own drift at the far end.
///
/// **It is built before the spend.** [`crate::coord::dispatch`] calls this under
/// the store lock, alongside [`resolve_route`] and ahead of
/// `Store::dispatch_staged`, so an envelope this endpoint cannot construct
/// refuses with the consent receipt still live. That is what ADR-0016 §6's
/// "closed structurally by ordering" has to mean: routing was only one of the
/// two ways a consented staging could turn out to be unsendable.
pub fn envelope(
    staged: &StagedContract,
    route: &CoordRoute,
    sender_root: &str,
    consent_receipt: &str,
) -> Result<serde_json::Value, Problem> {
    let value = serde_json::json!({
        "schema_version": 1,
        "protocol": COORD_PROTOCOL,
        "task_type": staged.task_type,
        "recipient_label": route.label,
        "recipient_root": route.root,
        "sender_root": sender_root,
        "payload_sha256": staged.payload_sha256,
        "staged_digest": staged.staged_digest,
        "consent_receipt": consent_receipt,
    });
    validate(SchemaId::CoordDispatchV1, &value).map_err(|_| {
        Problem::new(
            500,
            "bad-envelope",
            "the coordination envelope does not conform to its own schema",
        )
    })?;
    Ok(value)
}

/// The A2A `SendMessage` body carrying one coordination dispatch — **the same
/// bytes every time**, for a given dispatch.
///
/// `message_id` is the **dispatch receipt**: it is unique per committed
/// dispatch, so the recipient's §9.2 idempotency treats a re-attempt of the same
/// dispatch as the duplicate it is and replays its stored acknowledgement rather
/// than admitting the disclosure a second time.
///
/// That only works if the bytes are stable, which is why the body is emitted as
/// **RFC 8785 canonical JSON** rather than by serialising the request struct.
/// `Part::Data` is a `pbjson_types::Struct` over a `HashMap`, so serialising it
/// twice yields two different member orders and therefore two different body
/// digests. The recipient's §9.2 covered values include that digest: an
/// unstable body turns the retry ADR-0016 §6 promises — re-present the same
/// `execution_key` after a lost acknowledgement — into `409 conflict`, which
/// this endpoint records as `failed` for a disclosure that in fact arrived and
/// was admitted. Canonical output is the whole of the fix; nothing downstream
/// has to remember anything.
pub fn message_body(
    envelope: &serde_json::Value,
    payload: &[u8],
    dispatch_receipt: &str,
    stage_ref: &str,
) -> Result<Vec<u8>, Problem> {
    let envelope_part = Part {
        metadata: None,
        filename: String::new(),
        media_type: coord_dispatch_media_type(),
        content: Some(Content::Data(
            serde_json::from_value(envelope.clone()).map_err(|_| internal())?,
        )),
    };
    let payload_part = Part {
        metadata: None,
        // A human-readable label for a captured message, and nothing more: the
        // receiver never reads it. What binds these bytes to this envelope is
        // the digest check in `verify`, not this string and not the part's
        // position — see [`coord_payload`], which selects on media type and
        // refuses an ambiguous message outright.
        filename: envelope["payload_sha256"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        media_type: COORD_PAYLOAD_MEDIA_TYPE.to_owned(),
        content: Some(Content::Raw(payload.to_vec())),
    };
    let request = serde_json::to_value(SendMessageRequest {
        message: Some(Message {
            message_id: dispatch_receipt.to_owned(),
            context_id: stage_ref.to_owned(),
            parts: vec![envelope_part, payload_part],
            ..Default::default()
        }),
        ..Default::default()
    })
    .map_err(|_| internal())?;
    akson_ext::jcs::canonical_bytes(&request).map_err(|_| internal())
}

/// How one carriage attempt resolved. Deliberately two-valued: either the pinned
/// recipient acknowledged the exact staged digest, or it did not and we say why.
/// There is no "probably".
pub enum Carriage {
    /// The recipient returned 200 and echoed the staged digest we sent.
    Acknowledged { detail: String },
    /// The attempt failed. The consent stays spent; the dispatch row stays
    /// re-attemptable under the same execution key.
    Failed { detail: String },
}

/// POSTs one coordination dispatch to its pinned recipient over mutual TLS.
///
/// Never panics and never returns `Err`: a failed carriage is a *state* of the
/// dispatch, not an error of the dispatch operation, because the receipt is
/// already spent and the driver must be told what happened rather than handed a
/// refusal that implies nothing did.
pub async fn carry(
    endpoint_key: &PurposeKey,
    endpoint_cert: &EndpointCert,
    route: &CoordRoute,
    body: &[u8],
    staged_digest: &str,
) -> Carriage {
    let (status, response) = match post_a2a(
        endpoint_key,
        endpoint_cert,
        &route.endpoint,
        &route.tls_fingerprint,
        body,
    )
    .await
    {
        Ok(pair) => pair,
        Err(problem) => {
            return Carriage::Failed {
                detail: format!(
                    "{}: {}",
                    problem.type_,
                    problem.detail.as_deref().unwrap_or(&problem.title)
                ),
            }
        }
    };
    if status != 200 {
        return Carriage::Failed {
            detail: format!(
                "the recipient answered {status}: {}",
                summarize(&response, 200)
            ),
        };
    }
    // A 200 is not enough. The acknowledgement must name the digest we sent, or
    // we have no evidence that *this* disclosure is what landed.
    let acknowledged = serde_json::from_slice::<serde_json::Value>(&response)
        .ok()
        .and_then(|v| {
            v.get("staged_digest")
                .and_then(|d| d.as_str())
                .map(|d| d == staged_digest)
        })
        .unwrap_or(false);
    if acknowledged {
        Carriage::Acknowledged {
            detail: format!("acknowledged by {}", route.root),
        }
    } else {
        Carriage::Failed {
            detail: "the recipient answered 200 without acknowledging this staged digest"
                .to_owned(),
        }
    }
}

/// A bounded, printable one-line summary of a peer's response body — a peer must
/// not be able to write control characters into an operator's terminal or an
/// unbounded string into a durable column.
fn summarize(body: &[u8], max: usize) -> String {
    String::from_utf8_lossy(body)
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

// --- The receiving side ----------------------------------------------------

/// A verified inbound coordination dispatch: the facts, after every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedDispatch {
    pub staged_digest: String,
    pub payload_sha256: String,
    pub task_type: String,
    pub recipient_label: String,
    pub sender_root: String,
    pub consent_receipt: String,
    pub byte_length: usize,
}

/// Why an inbound coordination dispatch was refused. Each is a distinct defect,
/// but they map to one wire refusal — a sender learns that its envelope was not
/// admitted, not which check found it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordReject {
    /// The envelope does not conform to `coord-dispatch.v1`.
    Malformed,
    /// `sender_root` is not the root the mutual-TLS handshake authenticated.
    SenderMismatch,
    /// `recipient_root` is not this endpoint's own root.
    NotTheRecipient,
    /// No payload part, or its bytes do not hash to `payload_sha256`.
    PayloadDigest,
    /// The bytes hash correctly but the ADR-0016 §4 derivation does not
    /// reproduce `staged_digest` — the envelope does not describe its own
    /// payload, so it is not what any consent bound.
    StagedDigest,
}

impl CoordReject {
    pub fn reason(self) -> &'static str {
        match self {
            CoordReject::Malformed => "malformed-envelope",
            CoordReject::SenderMismatch => "sender-mismatch",
            CoordReject::NotTheRecipient => "not-the-recipient",
            CoordReject::PayloadDigest => "payload-digest",
            CoordReject::StagedDigest => "staged-digest",
        }
    }
}

/// The coordination envelope in a message's parts, if this message is one.
/// Returns the raw value; nothing about it is trusted until [`verify`] runs.
pub fn coord_dispatch_envelope(parts: &[Part]) -> Option<serde_json::Value> {
    let want = coord_dispatch_media_type();
    parts.iter().find_map(|part| {
        if part.media_type != want {
            return None;
        }
        match part.content.as_ref()? {
            Content::Data(data) => serde_json::to_value(data).ok(),
            _ => None,
        }
    })
}

/// The raw payload bytes carried alongside the envelope: the message's **one**
/// [`COORD_PAYLOAD_MEDIA_TYPE`] raw part.
///
/// Two rules, and neither trusts an ordering. The media type is required, so a
/// raw part of some other type is not a coordination payload and is never read
/// as one. And *exactly* one such part must exist: a message carrying two is
/// ambiguous about which bytes the envelope describes, so it is refused rather
/// than resolved by position. A sender that would like the digest check to run
/// over the first of several candidates therefore gets no such message admitted
/// at all.
fn coord_payload(parts: &[Part]) -> Option<&[u8]> {
    let mut candidates = parts
        .iter()
        .filter_map(|part| match part.content.as_ref()? {
            Content::Raw(bytes) if part.media_type == COORD_PAYLOAD_MEDIA_TYPE => Some(&bytes[..]),
            _ => None,
        });
    let only = candidates.next()?;
    candidates.next().is_none().then_some(only)
}

/// Verifies an inbound coordination dispatch against the transport-authenticated
/// sender and this endpoint's own identity (ADR-0016 §2).
///
/// `sender_root` is the root the mTLS layer resolved from the pinned peer
/// record — never a value out of the body. `local_root` is this endpoint's own.
/// The order is fail-closed and the cheap structural checks come first, so a
/// hostile sender cannot make the expensive ones run on garbage.
pub fn verify(
    envelope: &serde_json::Value,
    parts: &[Part],
    sender_root: &str,
    local_root: &str,
) -> Result<ReceivedDispatch, CoordReject> {
    validate(SchemaId::CoordDispatchV1, envelope).map_err(|_| CoordReject::Malformed)?;
    let field = |name: &str| -> Result<String, CoordReject> {
        envelope[name]
            .as_str()
            .map(str::to_owned)
            .ok_or(CoordReject::Malformed)
    };
    let claimed_sender = field("sender_root")?;
    if claimed_sender != sender_root {
        return Err(CoordReject::SenderMismatch);
    }
    if field("recipient_root")? != local_root {
        return Err(CoordReject::NotTheRecipient);
    }

    let payload = coord_payload(parts).ok_or(CoordReject::PayloadDigest)?;
    let payload_sha256 = field("payload_sha256")?;
    let recipient_label = field("recipient_label")?;
    let task_type = field("task_type")?;
    let staged_digest = field("staged_digest")?;

    // The SAME derivation the sender staged with (ADR-0016 §4), run over the
    // bytes that actually arrived. Two claims are checked, not one: that the
    // bytes are the bytes, and that the digest the operator consented to is the
    // digest those bytes produce.
    let (_, derived_staged, derived_payload) =
        stage_reference(payload, &recipient_label, &task_type)
            .map_err(|_| CoordReject::Malformed)?;
    if derived_payload != payload_sha256 {
        return Err(CoordReject::PayloadDigest);
    }
    if derived_staged != staged_digest {
        return Err(CoordReject::StagedDigest);
    }

    Ok(ReceivedDispatch {
        staged_digest,
        payload_sha256,
        task_type,
        recipient_label,
        sender_root: claimed_sender,
        consent_receipt: field("consent_receipt")?,
        byte_length: payload.len(),
    })
}

/// The acknowledgement a receiver returns for an admitted dispatch. It echoes
/// the staged digest, which is what lets the sender record `sent` for *this*
/// disclosure rather than for "something the peer said 200 to".
///
/// It acknowledges **arrival, verified** — nothing more. No work is started, no
/// task is created, and no authority is minted: §6.3's "arrival is not
/// execution", which is exactly why the reply promises no result.
pub fn acknowledgement(
    received: &ReceivedDispatch,
    local_root: &str,
    at: i64,
) -> serde_json::Value {
    serde_json::json!({
        "coordination": "acknowledged",
        "protocol": COORD_PROTOCOL,
        "staged_digest": received.staged_digest,
        "payload_sha256": received.payload_sha256,
        "recipient_root": local_root,
        "received_at": at,
    })
}

fn unroutable(detail: &str) -> Problem {
    // 409, not 404: the staging exists and the consent may exist; what does not
    // exist is a peer to disclose to. And it is raised BEFORE the spend, so the
    // operator's receipt is still live when the operator fixes the relationship.
    Problem {
        type_: "urn:akson:error:unroutable-recipient".to_owned(),
        title: "the staged recipient cannot receive a disclosure".to_owned(),
        status: 409,
        detail: Some(detail.to_owned()),
    }
}

fn internal() -> Problem {
    Problem::new(500, "internal", "the request could not be processed")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn staged() -> StagedContract {
        let payload = b"outbound bytes";
        let (stage_ref, staged_digest, payload_sha256) =
            stage_reference(payload, "partner", "https://byom.example/task/exchange/v1").unwrap();
        StagedContract {
            stage_ref,
            staged_digest,
            task_type: "https://byom.example/task/exchange/v1".to_owned(),
            performer: "partner".to_owned(),
            payload_sha256,
            byte_length: payload.len() as i64,
            status: "consented".to_owned(),
            staged_at: 1_800_000_000,
        }
    }

    fn route() -> CoordRoute {
        CoordRoute {
            label: "partner".to_owned(),
            root: "root-recipient-fixture".to_owned(),
            endpoint: "https://127.0.0.1:18444/a2a".to_owned(),
            tls_fingerprint: "fp-recipient".to_owned(),
        }
    }

    /// **One logical dispatch is one sequence of bytes.** Twelve builds of the
    /// same dispatch must produce one encoding, because the recipient's §9.2
    /// idempotency covers the body digest: an unstable body makes a re-carriage
    /// look like a *different* request under the same Message id, which is a
    /// `409 conflict` rather than the replayed acknowledgement ADR-0016 §6
    /// promises. `Part::Data` is a `HashMap`-backed Struct, so this went twelve
    /// ways before `message_body` canonicalized.
    #[test]
    fn the_body_of_one_dispatch_is_the_same_bytes_every_time() {
        let staged = staged();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..12 {
            let env = envelope(&staged, &route(), "root-sender-fixture", "consent-abc").unwrap();
            seen.insert(
                message_body(&env, b"outbound bytes", "dispatch-1", &staged.stage_ref).unwrap(),
            );
        }
        assert_eq!(
            seen.len(),
            1,
            "12 serialisations of one dispatch produced {} encodings",
            seen.len()
        );
        // And a *different* dispatch is different bytes — the stability above is
        // not the body having stopped depending on its content.
        let env = envelope(&staged, &route(), "root-sender-fixture", "consent-abc").unwrap();
        let other = message_body(&env, b"outbound bytes", "dispatch-2", &staged.stage_ref).unwrap();
        assert!(!seen.contains(&other));
    }

    /// **`stage`'s rule and the envelope's rule are one rule.** These predicates
    /// are the whole of `stage`'s task-type and label admissibility, and they
    /// answer with the schema, so the two cannot drift. The non-ASCII case is
    /// the one that used to stage, consent, and then destroy the receipt.
    #[test]
    fn what_may_be_staged_is_what_the_envelope_admits() {
        assert!(envelope_admits_task_type(
            "https://byom.example/task/exchange/v1"
        ));
        for refused in [
            "",                             // empty
            "https://byom.example/tâsk/v1", // one non-ASCII character
            "has a space",                  // whitespace
            "line\nbreak",                  // a control character
            &"x".repeat(513),               // over the schema's ceiling
        ] {
            assert!(
                !envelope_admits_task_type(refused),
                "{refused:?} must not be stageable"
            );
        }
        assert!(envelope_admits_recipient_label("partner"));
        for refused in ["", "NotALabel", "-leading", "a".repeat(65).as_str()] {
            assert!(
                !envelope_admits_recipient_label(refused),
                "{refused:?} must not be stageable"
            );
        }
        // The stand-ins are not what is being tested: a candidate built from two
        // admissible values must itself conform, or these predicates would
        // refuse everything for a reason of their own.
        validate(
            SchemaId::CoordDispatchV1,
            &candidate_envelope(ADMISSIBLE_TASK_TYPE, ADMISSIBLE_LABEL),
        )
        .expect("the candidate's own stand-in members must satisfy the schema");
    }

    /// `envelope` validates its own output against the registered schema, and
    /// refuses rather than emitting a member the receiver would reject. This is
    /// the guard `dispatch` now runs BEFORE the spend, so its failure leaves the
    /// operator's receipt live instead of destroying it.
    #[test]
    fn an_envelope_that_does_not_conform_is_refused_at_the_sender() {
        // A pinned root that is not a root shape: the schema's `root` pattern
        // admits no `/`, so this envelope can never be built.
        let mut bad_route = route();
        bad_route.root = "not/a/root".to_owned();
        let problem = envelope(&staged(), &bad_route, "root-sender-fixture", "consent-abc")
            .expect_err("a non-conforming envelope must not be produced");
        assert_eq!(problem.status, 500);
        assert_eq!(problem.type_, "urn:akson:error:bad-envelope");
        // The same for a receipt id the schema's opaque-id pattern refuses.
        assert!(envelope(&staged(), &route(), "root-sender-fixture", "consent abc").is_err());
        // And the control: unmodified, the very same call succeeds.
        assert!(envelope(&staged(), &route(), "root-sender-fixture", "consent-abc").is_ok());
    }

    /// The payload part is chosen by its media type and must be the only one of
    /// its kind. Neither its position nor its `filename` is trusted: a raw part
    /// of another type is not a coordination payload, and a message carrying two
    /// candidates is ambiguous about which bytes its envelope describes, so it
    /// is refused rather than resolved by ordering.
    #[test]
    fn the_payload_part_is_named_by_its_media_type_and_must_be_unique() {
        let raw = |media_type: &str, bytes: &[u8]| Part {
            metadata: None,
            filename: String::new(),
            media_type: media_type.to_owned(),
            content: Some(Content::Raw(bytes.to_vec())),
        };
        assert_eq!(
            coord_payload(&[raw(COORD_PAYLOAD_MEDIA_TYPE, b"bytes")]),
            Some(&b"bytes"[..])
        );
        // A raw part of some other media type is not a payload.
        assert_eq!(coord_payload(&[raw("text/plain", b"bytes")]), None);
        // Two candidates: ambiguous, so neither is picked.
        assert_eq!(
            coord_payload(&[
                raw(COORD_PAYLOAD_MEDIA_TYPE, b"bytes"),
                raw(COORD_PAYLOAD_MEDIA_TYPE, b"other bytes"),
            ]),
            None,
            "a message with two payload parts must not be resolved by ordering"
        );
        // A wrongly-typed part beside the real one changes nothing.
        assert_eq!(
            coord_payload(&[
                raw("text/plain", b"decoy"),
                raw(COORD_PAYLOAD_MEDIA_TYPE, b"bytes")
            ]),
            Some(&b"bytes"[..])
        );
    }

    /// The round trip, with nothing tampered: what the sender builds is exactly
    /// what the receiver admits.
    #[test]
    fn a_built_envelope_verifies_at_the_receiver() {
        let staged = staged();
        let route = route();
        let env = envelope(&staged, &route, "root-sender-fixture", "consent-abc").unwrap();
        let body = message_body(&env, b"outbound bytes", "dispatch-1", &staged.stage_ref).unwrap();
        let msg = serde_json::from_slice::<SendMessageRequest>(&body)
            .unwrap()
            .message
            .unwrap();
        let parsed = coord_dispatch_envelope(&msg.parts).unwrap();
        let received = verify(
            &parsed,
            &msg.parts,
            "root-sender-fixture",
            "root-recipient-fixture",
        )
        .unwrap();
        assert_eq!(received.staged_digest, staged.staged_digest);
        assert_eq!(received.payload_sha256, staged.payload_sha256);
        assert_eq!(received.consent_receipt, "consent-abc");
        assert_eq!(received.byte_length, "outbound bytes".len());
        // The dispatch receipt is the A2A message id — the recipient's
        // idempotency key for this exact disclosure.
        assert_eq!(msg.message_id, "dispatch-1");
    }

    /// The envelope carries what consent covered and **nothing that would make
    /// it a contract**. If someone ever adds a field here, this test is where
    /// they have to argue for it.
    #[test]
    fn the_envelope_has_no_contract_terms() {
        let env = envelope(&staged(), &route(), "root-sender-fixture", "consent-abc").unwrap();
        let mut members: Vec<&str> = env
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        members.sort_unstable();
        assert_eq!(
            members,
            vec![
                "consent_receipt",
                "payload_sha256",
                "protocol",
                "recipient_label",
                "recipient_root",
                "schema_version",
                "sender_root",
                "staged_digest",
                "task_type",
            ]
        );
        for invented in [
            "objective",
            "deliverables",
            "deadline",
            "limits",
            "requested_capabilities",
            "contract_id",
        ] {
            assert!(
                env.get(invented).is_none(),
                "{invented} is a contract term the operator never consented to"
            );
        }
    }
}
