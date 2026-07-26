//! Golden-vector tests for the coordination surface (family `coordination/`,
//! ADR-0016). `xcheck/run.py` re-derives the same values independently in Python;
//! this side rebuilds them from the implementation — the digests from
//! [`aksond::stage_reference`], the cursors from [`aksond::encode_cursor`], and
//! every reply and refusal from the **real dispatch** over a live daemon state.
//!
//! A vector is only worth something if both sides derive it without sharing code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use akson_crypto::identity::{Fingerprint, FingerprintKind, KeyBinding, PeerIdentity};
use akson_crypto::keypair::PurposeKey;
use akson_crypto::purpose::KeyPurpose;
use akson_store::StoredPeer;
use aksond::{
    encode_cursor, stage_reference, ControlRequest, DaemonConfig, DaemonState, Problem, Surface,
};
use serde_json::Value;

fn vectors() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/coordination");
    let mut cases = Vec::new();
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("missing {dir:?}: {e}")) {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap().to_owned();
        assert_eq!(
            name,
            format!(
                "coordination/{}",
                path.file_stem().unwrap().to_str().unwrap()
            ),
            "a vector's name must match its filename"
        );
        cases.push((name, case));
    }
    cases.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(cases.len() >= 24, "the coordination family is incomplete");
    cases
}

fn case<'a>(cases: &'a [(String, Value)], stem: &str) -> &'a Value {
    &cases
        .iter()
        .find(|(name, _)| name == &format!("coordination/{stem}"))
        .unwrap_or_else(|| panic!("no vector coordination/{stem}"))
        .1
}

fn keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn expected_keys(case: &Value, field: &str) -> Vec<String> {
    case["expected"][field]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

fn temp_state(label: &str) -> (DaemonState, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "akson-coord-vectors-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut config = DaemonConfig::from_env();
    config.data_dir = dir.join("data");
    config.receive_addr = None;
    config.interface_url = "https://127.0.0.1:18443/a2a".to_owned();
    (DaemonState::bootstrap(&config).unwrap(), dir)
}

/// One pinned verification key, as the introduction would have recorded it.
fn binding(purpose: KeyPurpose, key: &PurposeKey) -> KeyBinding {
    KeyBinding {
        purpose,
        thumbprint: Fingerprint {
            kind: FingerprintKind::Jwk7638,
            value: key.thumbprint(),
        },
    }
}

/// The peer fixture the `peer-show-*` vectors describe: an import under the label
/// `partner`, and (for the verified case) the pinned §8.1 tuple behind its root.
fn seed_peer(state: &DaemonState, root: &str, verified: bool) {
    let store = state.store();
    let store = store.lock().unwrap();
    store
        .add_peer_import(root, "partner", "127.0.0.1:18444", 1_753_574_000)
        .unwrap();
    if verified {
        let card = PurposeKey::from_seed(KeyPurpose::AgentCard, &[11u8; 32]);
        let proposal = PurposeKey::from_seed(KeyPurpose::ContractProposal, &[12u8; 32]);
        store
            .put_peer(&StoredPeer {
                identity: PeerIdentity {
                    issuer: Some("orgA".to_owned()),
                    agent_id: "alice".to_owned(),
                    workload_id: None,
                    endpoint_id: "ep-alice-1".to_owned(),
                    tls_cert: Fingerprint::cert_sha256(b"der-fixture"),
                    // `put_peer` keys the row by this thumbprint, so it IS the root.
                    agent_card_key: Fingerprint {
                        kind: FingerprintKind::Jwk7638,
                        value: root.to_owned(),
                    },
                    key_bindings: vec![
                        binding(KeyPurpose::AgentCard, &card),
                        binding(KeyPurpose::ContractProposal, &proposal),
                    ],
                    security_projection_digest: Fingerprint::json_sha256(b"{\"projection\":1}"),
                    full_card_digest: Fingerprint::json_sha256(b"{\"card\":1}"),
                },
                local_note: "OPERATOR PRIVATE NOTE".to_owned(),
            })
            .unwrap();
    }
}

/// The staged reference derivation and its idempotency — the byte facts.
#[test]
fn stage_reference_vectors() {
    let cases = vectors();
    for stem in ["stage-digest", "stage-digest-unrouted"] {
        let case = case(&cases, stem);
        let inp = &case["input"];
        let exp = &case["expected"];
        let payload = inp["payload_utf8"].as_str().unwrap().as_bytes();
        let (stage_ref, staged_digest, payload_sha256) = stage_reference(
            payload,
            inp["performer"].as_str().unwrap(),
            inp["task_type"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            payload_sha256,
            exp["payload_sha256"].as_str().unwrap(),
            "{stem}"
        );
        assert_eq!(
            staged_digest,
            exp["staged_digest"].as_str().unwrap(),
            "{stem}"
        );
        assert_eq!(stage_ref, exp["stage_ref"].as_str().unwrap(), "{stem}");
        // The canonical bytes the digest is taken over.
        let content = serde_json::json!({
            "payload_sha256": payload_sha256,
            "performer": inp["performer"],
            "task_type": inp["task_type"],
        });
        assert_eq!(
            String::from_utf8(akson_ext::jcs::canonical_bytes(&content).unwrap()).unwrap(),
            exp["canonical"].as_str().unwrap(),
            "{stem}: canonical"
        );
    }

    let idem = case(&cases, "stage-idempotent");
    let refs: Vec<String> = idem["input"]["stagings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            stage_reference(
                s["payload_utf8"].as_str().unwrap().as_bytes(),
                s["performer"].as_str().unwrap(),
                s["task_type"].as_str().unwrap(),
            )
            .unwrap()
            .0
        })
        .collect();
    assert_eq!(
        refs,
        expected_keys(idem, "stage_refs"),
        "identical content must derive one reference"
    );
}

/// The opaque cursor encoding.
#[test]
fn cursor_vectors() {
    let cases = vectors();
    let case = case(&cases, "events-cursor");
    let seqs: Vec<i64> = case["input"]["seqs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap())
        .collect();
    let cursors: Vec<String> = seqs.iter().map(|s| encode_cursor(*s)).collect();
    assert_eq!(cursors, expected_keys(case, "cursors"));
}

/// Every refusal shape, rebuilt from the real `Problem` constructors and compared
/// byte-for-byte with the frozen RFC 9457 body.
#[test]
fn refusal_vectors() {
    let cases = vectors();
    let body = |problem: &Problem| serde_json::to_string(problem).unwrap();

    let forbidden = case(&cases, "refusal-forbidden-surface");
    assert_eq!(
        body(&Problem::forbidden_surface(Surface::Coord)),
        forbidden["expected"]["body"].as_str().unwrap()
    );

    let unauthorized = case(&cases, "refusal-unauthorized");
    assert_eq!(
        body(&Problem {
            type_: "urn:akson:error:unauthorized".to_owned(),
            title: "local peer is not authorized".to_owned(),
            status: 403,
            detail: None,
        }),
        unauthorized["expected"]["body"].as_str().unwrap()
    );

    let too_large = case(&cases, "refusal-request-too-large");
    assert_eq!(
        body(&Problem::new(
            413,
            "request-too-large",
            "the control request exceeds this surface's ceiling"
        )),
        too_large["expected"]["body"].as_str().unwrap()
    );

    // The dispatch/status refusals, each produced by the REAL dispatch reaching the
    // real durable state — not by hand-building a `Problem` that happens to match.
    let (state, dir) = temp_state("refusals");
    let (first_ref, first_receipt) = consented(&state, "first bytes");
    let (second_ref, second_receipt) = consented(&state, "second bytes");

    // `consent-required`: a receipt that was never minted.
    let refusals = [
        (
            "refusal-consent-required",
            state
                .dispatch(&dispatch_req(&first_ref, "consent-invented", "exec-0001"))
                .unwrap_err(),
        ),
        (
            "refusal-unknown-task",
            state
                .dispatch(&ControlRequest::TaskStatus {
                    task_id: "task-7f3a".to_owned(),
                })
                .unwrap_err(),
        ),
    ];
    for (stem, problem) in refusals {
        let vector = case(&cases, stem);
        assert_eq!(
            body(&problem),
            vector["expected"]["body"].as_str().unwrap(),
            "{stem}"
        );
        assert_eq!(
            problem.status,
            vector["expected"]["status"].as_u64().unwrap() as u16,
            "{stem}"
        );
    }

    // `consent-spent`: dispatch once, then again under a different key.
    state
        .dispatch(&dispatch_req(&first_ref, &first_receipt, "exec-0001"))
        .unwrap();
    let spent = state
        .dispatch(&dispatch_req(&first_ref, &first_receipt, "exec-0002"))
        .unwrap_err();
    let vector = case(&cases, "refusal-consent-spent");
    assert_eq!(body(&spent), vector["expected"]["body"].as_str().unwrap());
    assert_eq!(spent.status, 409);

    // `execution-key-conflict`: a committed key reused for other arguments.
    let conflict = state
        .dispatch(&dispatch_req(&second_ref, &second_receipt, "exec-0001"))
        .unwrap_err();
    let vector = case(&cases, "refusal-execution-key-conflict");
    assert_eq!(
        body(&conflict),
        vector["expected"]["body"].as_str().unwrap()
    );
    assert_eq!(conflict.status, 409);
    let _ = fs::remove_dir_all(&dir);
}

/// Stages bytes over the coordination surface and has admin mint their consent —
/// the split ADR-0016 §3 requires — returning `(stage_ref, consent_receipt)`.
fn consented(state: &DaemonState, payload: &str) -> (String, String) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let staged = state
        .dispatch(&ControlRequest::Stage {
            task_type: "https://byom.example/task/exchange/v1".to_owned(),
            performer: String::new(),
            payload_base64: STANDARD.encode(payload),
        })
        .unwrap();
    let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();
    let consent = state
        .dispatch(&ControlRequest::StageConsent {
            stage_ref: stage_ref.clone(),
        })
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

/// Every op's frozen request wire — the `{"op": …}` tag plus that op's arguments.
#[test]
fn request_wire_vectors() {
    let cases = vectors();
    let staged_ref = case(&cases, "stage-digest")["expected"]["stage_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    let payload_b64 = case(&cases, "stage-reply")["input"]["request"]["payload_base64"]
        .as_str()
        .unwrap()
        .to_owned();
    let receipt = case(&cases, "stage-consent")["input"]["result"]["consent_receipt"]
        .as_str()
        .unwrap()
        .to_owned();

    let expected_wire = |stem: &str| {
        case(&cases, stem)["expected"]["request_wire"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    for (stem, request) in [
        ("coord-whoami", ControlRequest::CoordWhoAmI),
        (
            "peer-show-verified",
            ControlRequest::PeerShow {
                label: "partner".to_owned(),
            },
        ),
        (
            "stage-reply",
            ControlRequest::Stage {
                task_type: "https://byom.example/task/exchange/v1".to_owned(),
                performer: "partner".to_owned(),
                payload_base64: payload_b64,
            },
        ),
        (
            "stage-show-staged",
            ControlRequest::StageShow {
                stage_ref: staged_ref.clone(),
            },
        ),
        (
            "stage-consent",
            ControlRequest::StageConsent {
                stage_ref: staged_ref.clone(),
            },
        ),
        (
            "events-read",
            ControlRequest::EventsRead {
                cursor: None,
                limit: Some(2),
            },
        ),
        (
            "dispatch-reply",
            ControlRequest::Dispatch {
                stage_ref: staged_ref.clone(),
                consent_receipt: receipt,
                execution_key: "exec-0001".to_owned(),
            },
        ),
        (
            "task-status-reply",
            ControlRequest::TaskStatus {
                task_id: "dispatch-3a9e1f70c4b25d86e07f1a2b3c4d5e6f".to_owned(),
            },
        ),
        (
            "capability-evidence-reply",
            ControlRequest::CapabilityEvidence {
                label: "partner".to_owned(),
            },
        ),
    ] {
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            expected_wire(stem),
            "{stem}: request wire"
        );
        // And the wire parses back to the same request — no field renamed away.
        let parsed: ControlRequest = serde_json::from_str(&expected_wire(stem)).unwrap();
        assert_eq!(parsed, request, "{stem}: request round-trip");
    }
}

/// Every reply's field set and its deterministic content, from the real dispatch:
/// `coord_whoami`, `peer_show` (both states), `stage` (fresh and replayed),
/// `stage_show` (staged and consented), `stage_consent`, and `events_read`.
#[test]
fn reply_vectors() {
    let cases = vectors();
    let (state, dir) = temp_state("replies");
    let root = case(&cases, "peer-show-verified")["input"]["result"]["root_thumbprint"]
        .as_str()
        .unwrap()
        .to_owned();

    // --- coord_whoami ---
    let vector = case(&cases, "coord-whoami");
    let whoami = state.dispatch(&ControlRequest::CoordWhoAmI).unwrap();
    assert_eq!(keys(&whoami), expected_keys(vector, "result_keys"));
    for field in ["protocol", "protocol_version", "features", "unimplemented"] {
        assert_eq!(
            whoami[field], vector["input"]["result"][field],
            "coord_whoami: {field}"
        );
    }

    // --- peer_show: imported, then verified ---
    seed_peer(&state, &root, false);
    let vector = case(&cases, "peer-show-imported");
    let shown = state
        .dispatch(&ControlRequest::PeerShow {
            label: "partner".to_owned(),
        })
        .unwrap();
    assert_eq!(keys(&shown), expected_keys(vector, "result_keys"));
    assert_eq!(shown, vector["input"]["result"], "peer_show (imported)");

    seed_peer(&state, &root, true);
    let vector = case(&cases, "peer-show-verified");
    let shown = state
        .dispatch(&ControlRequest::PeerShow {
            label: "partner".to_owned(),
        })
        .unwrap();
    assert_eq!(keys(&shown), expected_keys(vector, "result_keys"));
    assert_eq!(
        keys(&shown["identity"]),
        keys(&vector["input"]["result"]["identity"])
    );
    assert_eq!(
        keys(&shown["card_claims"]),
        keys(&vector["input"]["result"]["card_claims"])
    );
    assert_eq!(shown["verified"], true);
    assert_eq!(shown["status"], "active");
    assert_eq!(
        shown["card_claims"]["key_purposes"],
        vector["input"]["result"]["card_claims"]["key_purposes"]
    );
    // The operator's private note on a peer never crosses this surface.
    assert!(!shown.to_string().contains("OPERATOR PRIVATE NOTE"));

    // --- stage, then the same bytes again ---
    let vector = case(&cases, "stage-reply");
    let request: ControlRequest =
        serde_json::from_str(vector["expected"]["request_wire"].as_str().unwrap()).unwrap();
    let staged = state.dispatch(&request).unwrap();
    assert_eq!(keys(&staged), expected_keys(vector, "result_keys"));
    for field in [
        "stage_ref",
        "staged_digest",
        "payload_sha256",
        "byte_length",
        "task_type",
        "performer",
        "status",
        "consent",
        "already_staged",
    ] {
        assert_eq!(
            staged[field], vector["input"]["result"][field],
            "stage: {field}"
        );
    }
    let replay_vector = case(&cases, "stage-reply-replay");
    let replayed = state.dispatch(&request).unwrap();
    assert_eq!(keys(&replayed), expected_keys(replay_vector, "result_keys"));
    assert_eq!(replayed["already_staged"], true);
    assert_eq!(replayed["stage_ref"], staged["stage_ref"]);
    assert_eq!(replayed["staged_at"], staged["staged_at"]);

    let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();

    // --- stage_show before consent ---
    let vector = case(&cases, "stage-show-staged");
    let shown = state
        .dispatch(&ControlRequest::StageShow {
            stage_ref: stage_ref.clone(),
        })
        .unwrap();
    assert_eq!(keys(&shown), expected_keys(vector, "result_keys"));
    assert_eq!(shown["status"], "staged");
    assert_eq!(shown["consent"], Value::Null);

    // --- stage_consent (admin) ---
    let vector = case(&cases, "stage-consent");
    let consent = state
        .dispatch(&ControlRequest::StageConsent {
            stage_ref: stage_ref.clone(),
        })
        .unwrap();
    assert_eq!(keys(&consent), expected_keys(vector, "result_keys"));
    assert_eq!(
        consent["sentence"], vector["expected"]["sentence"],
        "the risk-card sentence is frozen"
    );
    let headings: Vec<String> = consent["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["heading"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(headings, expected_keys(vector, "section_headings"));
    assert_eq!(consent["staged_digest"], staged["staged_digest"]);
    assert_eq!(consent["max_uses"], 1);
    assert_eq!(consent["uses"], 0);
    // The card renders the digest, never the staged bytes.
    let rendered = consent["sections"].to_string();
    assert!(rendered.contains(staged["staged_digest"].as_str().unwrap()));
    assert!(!rendered.contains("hello"));

    // --- stage_show after consent ---
    let vector = case(&cases, "stage-show-consented");
    let shown = state
        .dispatch(&ControlRequest::StageShow {
            stage_ref: stage_ref.clone(),
        })
        .unwrap();
    assert_eq!(keys(&shown), expected_keys(vector, "result_keys"));
    assert_eq!(shown["status"], "consented");
    assert_eq!(
        keys(&shown["consent"]),
        keys(&vector["input"]["result"]["consent"])
    );
    assert_eq!(
        shown["consent"]["consent_receipt"],
        consent["consent_receipt"]
    );

    // --- events_read: the two kinds this build emits, with their cursors ---
    let vector = case(&cases, "events-read");
    let feed = state
        .dispatch(&ControlRequest::EventsRead {
            cursor: None,
            limit: Some(2),
        })
        .unwrap();
    assert_eq!(keys(&feed), expected_keys(vector, "result_keys"));
    let events = feed["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    for event in events {
        assert_eq!(keys(event), expected_keys(vector, "event_keys"));
    }
    let kinds: Vec<String> = events
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(kinds, expected_keys(vector, "kinds"));
    assert_eq!(
        keys(&events[0]["detail"]),
        keys(&vector["input"]["result"]["events"][0]["detail"])
    );
    assert_eq!(
        keys(&events[1]["detail"]),
        keys(&vector["input"]["result"]["events"][1]["detail"])
    );
    // `next_cursor` is the last event's cursor: resume after what you have seen.
    assert_eq!(feed["next_cursor"], events[1]["cursor"]);
    assert_eq!(feed["has_more"], false);

    // --- dispatch: the receipt is spent, and the retry replays it ---
    let vector = case(&cases, "dispatch-reply");
    let receipt = consent["consent_receipt"].as_str().unwrap().to_owned();
    let dispatched = state
        .dispatch(&dispatch_req(&stage_ref, &receipt, "exec-0001"))
        .unwrap();
    assert_eq!(keys(&dispatched), expected_keys(vector, "result_keys"));
    for field in [
        "stage_ref",
        "staged_digest",
        "payload_sha256",
        "byte_length",
        "task_type",
        "performer",
        "consent_spent",
        "status",
        "replayed",
        "egress",
    ] {
        assert_eq!(
            dispatched[field], vector["input"]["result"][field],
            "dispatch: {field}"
        );
    }
    assert_eq!(dispatched["consent_receipt"], receipt);
    assert_eq!(dispatched["execution_key"], "exec-0001");

    let retry_vector = case(&cases, "dispatch-reply-retry");
    let retried = state
        .dispatch(&dispatch_req(&stage_ref, &receipt, "exec-0001"))
        .unwrap();
    assert_eq!(keys(&retried), expected_keys(retry_vector, "result_keys"));
    assert_eq!(retried["replayed"], true);
    // The frozen claim of the retry vector: same receipt, same timestamp.
    assert_eq!(
        retry_vector["expected"]["same_dispatch_receipt_as"],
        "coordination/dispatch-reply"
    );
    assert_eq!(retried["dispatch_receipt"], dispatched["dispatch_receipt"]);
    assert_eq!(retried["dispatched_at"], dispatched["dispatched_at"]);

    // --- task_status: addressable by the dispatch receipt or the staged ref ---
    let vector = case(&cases, "task-status-reply");
    let dispatch_receipt = dispatched["dispatch_receipt"].as_str().unwrap().to_owned();
    for id in [dispatch_receipt.as_str(), stage_ref.as_str()] {
        let status = state
            .dispatch(&ControlRequest::TaskStatus {
                task_id: id.to_owned(),
            })
            .unwrap();
        assert_eq!(keys(&status), expected_keys(vector, "result_keys"));
        assert_eq!(
            keys(&status["verification"]),
            expected_keys(vector, "verification_keys")
        );
        assert_eq!(status["task_id"], id);
        assert_eq!(status["status"], "dispatched");
        assert_eq!(
            status["verification"],
            vector["input"]["result"]["verification"]
        );
    }

    // --- capability_evidence: the field sets and every dimension's declared source ---
    let vector = case(&cases, "capability-evidence-reply");
    let evidence = state
        .dispatch(&ControlRequest::CapabilityEvidence {
            label: "partner".to_owned(),
        })
        .unwrap();
    assert_eq!(keys(&evidence), expected_keys(vector, "result_keys"));
    assert_eq!(
        keys(&evidence["statement"]),
        expected_keys(vector, "statement_keys")
    );
    assert_eq!(
        evidence["predicate_type"],
        vector["input"]["result"]["predicate_type"]
    );
    assert_eq!(evidence["signer"]["purpose"], "evidence");
    let dims = evidence["statement"]["predicate"]["dimensions"]
        .as_array()
        .unwrap();
    let names: Vec<String> = dims
        .iter()
        .map(|d| d["dimension"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, expected_keys(vector, "dimension_names"));
    let allowed = expected_keys(vector, "dimension_sources");
    for d in dims {
        assert_eq!(keys(d), expected_keys(vector, "dimension_keys"));
        assert!(
            allowed.contains(&d["source"].as_str().unwrap().to_owned()),
            "{} declares an unknown source",
            d["dimension"]
        );
    }
    // The envelope is the in-toto/DSSE carrier, verifiable under the evidence key.
    let envelope: akson_ext::dsse::Envelope =
        serde_json::from_value(evidence["evidence"].clone()).unwrap();
    assert_eq!(envelope.payload_type, akson_evidence::INTOTO_PAYLOAD_TYPE);
    let key = state
        .identity()
        .purpose_key(KeyPurpose::Evidence)
        .verifying();
    let statement = akson_evidence::Statement::verify(&envelope, &key).unwrap();
    assert_eq!(
        statement.predicate_type,
        akson_evidence::PREDICATE_FEDERATION_CAPABILITY_V1
    );

    let _ = fs::remove_dir_all(&dir);
}
