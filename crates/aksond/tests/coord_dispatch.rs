//! `dispatch`, `task_status`, and the boundary they must not widen (ADR-0016 §2).
//!
//! The coordination surface can now cause an effect, which makes this file the one
//! that matters. Everything here runs over **real Unix sockets** through the real
//! connection handler and a real daemon state, so the properties are the ones a
//! driver actually meets:
//!
//! 1. **One receipt, one dispatch.** Staging is inert; dispatch spends the
//!    operator's consent. A second dispatch under a new execution key is refused,
//!    and it is refused by a database column — reopening the store does not forgive
//!    it.
//! 2. **Retry is not replay.** The same `execution_key` returns the same dispatch
//!    receipt and spends nothing further.
//! 3. **Dispatching did not make coord an admin.** The driver still cannot mint the
//!    consent it burns, approve an inbound task, read a credential, or send a task —
//!    and the refusals change no durable state.
//! 4. **`task_status` sees only what this surface dispatched.** An inbound proposal
//!    in the operator's inbox is not addressable from coord, even though admin can
//!    render its risk card from the same store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use akson_contract::{parse_payload, RevisionVerdict};
use aksond::{
    bind_socket, handle_connection, send_request, Admission, ControlRequest, ControlResponse,
    DaemonConfig, DaemonState, Surface,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const NOW: i64 = 1_800_000_000;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "akson-coord-dispatch-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn daemon(dir: &Path) -> std::sync::Arc<DaemonState> {
    let mut config = DaemonConfig::from_env();
    config.data_dir = dir.join("data");
    config.receive_addr = None;
    let state = std::sync::Arc::new(DaemonState::bootstrap(&config).unwrap());
    seed_recipient(&state);
    state
}

/// The label every staging below discloses to, and its root.
const RECIPIENT: &str = "partner";
const RECIPIENT_ROOT: &str = "root-recipient-fixture";

/// Pins `partner` as an introduced, ACTIVE peer at an address nothing listens
/// on. Since slice 3, `dispatch` refuses BEFORE spending consent when the staged
/// recipient cannot receive a disclosure, so these tests need a real recipient —
/// but not a live one: they are about the one-shot property and the surface
/// boundary, and `tests/coord_egress_e2e.rs` is about the wire.
fn seed_recipient(state: &DaemonState) {
    use akson_crypto::identity::{Fingerprint, FingerprintKind, PeerIdentity};
    let store = state.store();
    let store = store.lock().unwrap();
    if store.peer_import_by_label(RECIPIENT).unwrap().is_some() {
        return; // a restarted daemon over the same data directory
    }
    store
        .add_peer_import(RECIPIENT_ROOT, RECIPIENT, "127.0.0.1:1", NOW)
        .unwrap();
    store
        .put_peer(&akson_store::StoredPeer {
            identity: PeerIdentity {
                issuer: Some("iss".to_owned()),
                agent_id: "alice".to_owned(),
                workload_id: None,
                endpoint_id: "https://127.0.0.1:1/a2a".to_owned(),
                tls_cert: Fingerprint::cert_sha256(b"der-fixture"),
                agent_card_key: Fingerprint {
                    kind: FingerprintKind::Jwk7638,
                    value: RECIPIENT_ROOT.to_owned(),
                },
                key_bindings: vec![],
                security_projection_digest: Fingerprint::json_sha256(b"{\"p\":1}"),
                full_card_digest: Fingerprint::json_sha256(b"{\"c\":1}"),
            },
            local_note: String::new(),
        })
        .unwrap();
}

/// Serves exactly one request on `surface` over a real socket, through the real
/// daemon dispatch — the same path `aksond serve` runs.
fn call(
    dir: &Path,
    tag: &str,
    state: &std::sync::Arc<DaemonState>,
    surface: Surface,
    req: &ControlRequest,
) -> ControlResponse {
    let path = dir.join(format!("{tag}.sock"));
    let listener = bind_socket(&path).unwrap();
    let admission = Admission::same_uid(aksond::current_uid());
    let served = state.clone();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle_connection(stream, surface, &admission, &move |req| {
            served.dispatch(req)
        })
        .unwrap();
    });
    let response = send_request(&path, req).unwrap();
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);
    response
}

fn ok(response: ControlResponse, what: &str) -> serde_json::Value {
    match response {
        ControlResponse::Ok { result } => result,
        ControlResponse::Problem { problem } => panic!("{what}: expected ok, got {problem:?}"),
    }
}

fn problem(response: ControlResponse, what: &str) -> aksond::Problem {
    match response {
        ControlResponse::Problem { problem } => problem,
        ControlResponse::Ok { result } => panic!("{what}: expected a problem, got {result}"),
    }
}

/// Stages bytes over **coord** and mints their consent over **admin** — the split
/// ADR-0016 §3 requires — returning `(stage_ref, consent_receipt)`.
fn staged_and_consented(
    dir: &Path,
    tag: &str,
    state: &std::sync::Arc<DaemonState>,
    payload_base64: &str,
) -> (String, String) {
    let staged = ok(
        call(
            dir,
            &format!("{tag}-stage"),
            state,
            Surface::Coord,
            &ControlRequest::Stage {
                task_type: "https://byom.example/task/exchange/v1".to_owned(),
                performer: RECIPIENT.to_owned(),
                payload_base64: payload_base64.to_owned(),
            },
        ),
        "stage on coord",
    );
    let stage_ref = staged["stage_ref"].as_str().unwrap().to_owned();
    let consent = ok(
        call(
            dir,
            &format!("{tag}-consent"),
            state,
            Surface::Admin,
            &ControlRequest::StageConsent {
                stage_ref: stage_ref.clone(),
            },
        ),
        "stage_consent on admin",
    );
    let receipt = consent["consent_receipt"].as_str().unwrap().to_owned();
    (stage_ref, receipt)
}

fn dispatch(stage_ref: &str, receipt: &str, key: &str) -> ControlRequest {
    ControlRequest::Dispatch {
        stage_ref: stage_ref.to_owned(),
        consent_receipt: receipt.to_owned(),
        execution_key: key.to_owned(),
    }
}

/// The whole chain, over sockets, on the surfaces that own each step — and then the
/// second dispatch that must not happen.
#[test]
fn one_consent_receipt_dispatches_once_over_the_real_coordination_socket() {
    let dir = temp_dir("one-shot");
    let state = daemon(&dir);
    let (stage_ref, receipt) = staged_and_consented(&dir, "a", &state, "b3V0Ym91bmQ=");

    let first = ok(
        call(
            &dir,
            "d1",
            &state,
            Surface::Coord,
            &dispatch(&stage_ref, &receipt, "exec-1"),
        ),
        "first dispatch",
    );
    assert_eq!(first["consent_spent"], true);
    assert_eq!(first["replayed"], false);
    assert_eq!(first["status"], "dispatched");
    let dispatch_receipt = first["dispatch_receipt"].as_str().unwrap().to_owned();

    // A new execution key on the spent receipt: one-shot means refused.
    let refused = problem(
        call(
            &dir,
            "d2",
            &state,
            Surface::Coord,
            &dispatch(&stage_ref, &receipt, "exec-2"),
        ),
        "second dispatch",
    );
    assert_eq!(refused.status, 409);
    assert_eq!(refused.type_, "urn:akson:error:consent-spent");

    // The same execution key: a retry, answering with the identical receipt.
    let retried = ok(
        call(
            &dir,
            "d3",
            &state,
            Surface::Coord,
            &dispatch(&stage_ref, &receipt, "exec-1"),
        ),
        "retry",
    );
    assert_eq!(retried["dispatch_receipt"], dispatch_receipt);
    assert_eq!(retried["dispatched_at"], first["dispatched_at"]);
    assert_eq!(retried["replayed"], true);

    // The feed shows exactly one dispatch across all three calls, and
    // `stage_show` reports the stage as dispatched with no live consent left.
    let feed = ok(
        call(
            &dir,
            "d4",
            &state,
            Surface::Coord,
            &ControlRequest::EventsRead {
                cursor: None,
                limit: None,
            },
        ),
        "events_read",
    );
    let kinds: Vec<&str> = feed["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    // Three calls, one dispatch. The two `egress_recorded` entries are the two
    // carriage ATTEMPTS (the first dispatch and the retry, both failing against
    // an address nothing listens on) — a carriage attempt is not a dispatch, and
    // the feed keeps them distinguishable.
    assert_eq!(
        kinds,
        vec![
            "staged",
            "consent_recorded",
            "dispatched",
            "egress_recorded",
            "egress_recorded"
        ]
    );
    assert_eq!(
        kinds.iter().filter(|k| **k == "dispatched").count(),
        1,
        "one consent, one dispatch, however many carriage attempts"
    );
    let shown = ok(
        call(
            &dir,
            "d5",
            &state,
            Surface::Coord,
            &ControlRequest::StageShow {
                stage_ref: stage_ref.clone(),
            },
        ),
        "stage_show",
    );
    assert_eq!(shown["status"], "dispatched");
    assert_eq!(shown["consent"], serde_json::Value::Null);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The receipt stays spent across a **daemon restart**: the state that refuses a
/// replay is on disk, not in the process. Without that, "one-shot" would only mean
/// "one-shot until aksond restarts".
#[test]
fn a_spent_receipt_is_still_refused_after_the_daemon_restarts() {
    let dir = temp_dir("restart");
    let (stage_ref, receipt) = {
        let state = daemon(&dir);
        let (stage_ref, receipt) = staged_and_consented(&dir, "r", &state, "b3V0Ym91bmQ=");
        ok(
            call(
                &dir,
                "r1",
                &state,
                Surface::Coord,
                &dispatch(&stage_ref, &receipt, "exec-1"),
            ),
            "dispatch before restart",
        );
        (stage_ref, receipt)
    };

    // A brand-new DaemonState over the same data directory: nothing in memory
    // survives, only the database.
    let restarted = daemon(&dir);
    let refused = problem(
        call(
            &dir,
            "r2",
            &restarted,
            Surface::Coord,
            &dispatch(&stage_ref, &receipt, "exec-after-restart"),
        ),
        "replay after restart",
    );
    assert_eq!(refused.status, 409);
    assert_eq!(refused.type_, "urn:akson:error:consent-spent");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Being able to dispatch did not promote the coordination identity. It still
/// cannot mint the very consent it spends, approve inbound work, read a credential,
/// or send a task — and each refusal leaves the store exactly as it was.
#[test]
fn a_dispatching_coord_surface_still_cannot_reach_admin_authority() {
    let dir = temp_dir("no-promotion");
    let state = daemon(&dir);
    let (stage_ref, receipt) = staged_and_consented(&dir, "p", &state, "b3V0Ym91bmQ=");
    ok(
        call(
            &dir,
            "p1",
            &state,
            Surface::Coord,
            &dispatch(&stage_ref, &receipt, "exec-1"),
        ),
        "dispatch",
    );

    // Stage a second contract, so there is something to try to self-consent for.
    let second = ok(
        call(
            &dir,
            "p2",
            &state,
            Surface::Coord,
            &ControlRequest::Stage {
                task_type: "https://byom.example/task/exchange/v1".to_owned(),
                performer: RECIPIENT.to_owned(),
                payload_base64: "c2Vjb25k".to_owned(),
            },
        ),
        "second stage",
    );
    let second_ref = second["stage_ref"].as_str().unwrap().to_owned();

    let admin_only = [
        (
            "self-consent",
            ControlRequest::StageConsent {
                stage_ref: second_ref.clone(),
            },
        ),
        (
            "approve",
            ControlRequest::TaskApprove {
                task_id: "task-1".to_owned(),
                processor: None,
                artifacts: false,
            },
        ),
        (
            "credential",
            ControlRequest::ProcessorCredential {
                processor_id: "p".to_owned(),
                credential: "secret".to_owned(),
            },
        ),
        (
            "send",
            ControlRequest::TaskSend(aksond::TaskSpec {
                performer: "partner".to_owned(),
                task_type: "https://example.test/t".to_owned(),
                objective: "do".to_owned(),
                inputs: vec![],
                deliverables: vec![],
                capabilities: vec![],
                deadline: "2030-01-01T00:00:00Z".to_owned(),
                max_response_bytes: 1024,
            }),
        ),
        (
            "issue",
            ControlRequest::IssueWorkOrder {
                task_id: "task-1".to_owned(),
            },
        ),
    ];
    for (i, (what, req)) in admin_only.iter().enumerate() {
        let refused = problem(
            call(&dir, &format!("p{}", 10 + i), &state, Surface::Coord, req),
            what,
        );
        assert_eq!(refused.status, 403, "{what}");
        assert_eq!(refused.type_, "urn:akson:error:forbidden-surface", "{what}");
    }

    // And nothing moved: the second stage has no consent, so it cannot be
    // dispatched either. A driver that cannot mint consent cannot dispatch.
    let store = state.store();
    let store = store.lock().unwrap();
    assert!(store.unconsumed_consent(&second_ref).unwrap().is_none());
    assert_eq!(
        store.staged_contract(&second_ref).unwrap().unwrap().status,
        "staged"
    );
    assert!(store.get_credential("p").unwrap().is_none());
    assert!(store.list_sent_requests().unwrap().is_empty());
    drop(store);

    let refused = problem(
        call(
            &dir,
            "p20",
            &state,
            Surface::Coord,
            &dispatch(&second_ref, "consent-invented", "exec-9"),
        ),
        "dispatch without consent",
    );
    assert_eq!(refused.status, 409);
    assert_eq!(refused.type_, "urn:akson:error:consent-required");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Puts one inbound proposal into the operator's inbox, as a peer's `task send`
/// would leave it, and returns its Task id.
fn submit_inbound_task(state: &DaemonState) -> String {
    let text = "review this file";
    let sha = hex::encode(Sha256::digest(text.as_bytes()));
    let value = json!({
        "schema_version": 1, "contract_id": "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718",
        "revision": 0, "task_type": "https://akson.invalid/task/code-review/v1",
        "message_id": "msg-1",
        "requester": {"issuer": "iss", "agent": "requester", "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "performer": {"issuer": "iss", "agent": "performer", "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "objective": "o",
        "inputs": [{
            "id": "diff", "message_id": "msg-1", "part_index": 1, "kind": "text",
            "media_type": "text/x-diff", "charset": "utf-8", "canonical_rule": "utf8-exact",
            "byte_length": text.len(), "sha256": sha,
            "worker_visible": true, "processor_visible": false
        }],
        "deliverables": [{"role": "r", "media_type": "text/plain"}],
        "evidence_slots": [], "requested_capabilities": ["respond"],
        "processor_constraints": {"disclosure": "none"},
        "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 8192},
        "result_recipient": "request-origin",
        "created_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"
    });
    let payload = akson_ext::jcs::canonical_bytes(&value).unwrap();
    let parsed = parse_payload(&payload).unwrap();
    let task_id = "task-inbound-1";
    let store = state.store();
    let store = store.lock().unwrap();
    let verdict = store
        .submit_revision(
            task_id,
            &parsed,
            "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1_893_456_000,
            NOW,
        )
        .unwrap();
    assert!(matches!(verdict, RevisionVerdict::Advance(_)));
    task_id.to_owned()
}

/// `task_status` is the coordination surface's only task read, and it reaches only
/// dispatches this surface itself wrote. The inbound task is right there in the same
/// database — admin renders its risk card — and coord still cannot see it.
#[test]
fn task_status_on_coord_cannot_see_an_inbound_task() {
    let dir = temp_dir("scope");
    let state = daemon(&dir);
    let inbound = submit_inbound_task(&state);

    // Admin can read it: the row exists, so a 404 below is scoping, not absence.
    let card = ok(
        call(
            &dir,
            "s1",
            &state,
            Surface::Admin,
            &ControlRequest::TaskShow {
                task_id: inbound.clone(),
            },
        ),
        "task_show on admin",
    );
    assert_eq!(card["task_id"], inbound);

    // `task_show` itself is unreachable from coord — it is not on the registry.
    let forbidden = problem(
        call(
            &dir,
            "s2",
            &state,
            Surface::Coord,
            &ControlRequest::TaskShow {
                task_id: inbound.clone(),
            },
        ),
        "task_show on coord",
    );
    assert_eq!(forbidden.status, 403);

    // And `task_status`, which *is* on the registry, does not answer for it.
    let refused = problem(
        call(
            &dir,
            "s3",
            &state,
            Surface::Coord,
            &ControlRequest::TaskStatus {
                task_id: inbound.clone(),
            },
        ),
        "task_status for an inbound task",
    );
    assert_eq!(refused.status, 404);
    assert_eq!(refused.type_, "urn:akson:error:unknown-task");

    // The same 404 a made-up id gets, so probing distinguishes nothing.
    let invented = problem(
        call(
            &dir,
            "s4",
            &state,
            Surface::Coord,
            &ControlRequest::TaskStatus {
                task_id: "task-does-not-exist".to_owned(),
            },
        ),
        "task_status for an invented id",
    );
    assert_eq!(invented, refused);

    // A task this surface DID dispatch answers, so the op is not simply broken.
    let (stage_ref, receipt) = staged_and_consented(&dir, "s", &state, "b3V0Ym91bmQ=");
    ok(
        call(
            &dir,
            "s5",
            &state,
            Surface::Coord,
            &dispatch(&stage_ref, &receipt, "exec-1"),
        ),
        "dispatch",
    );
    let status = ok(
        call(
            &dir,
            "s6",
            &state,
            Surface::Coord,
            &ControlRequest::TaskStatus {
                task_id: stage_ref.clone(),
            },
        ),
        "task_status for our own dispatch",
    );
    assert_eq!(status["stage_ref"], stage_ref);
    assert_eq!(status["consent_receipt"], receipt);
    assert_eq!(status["verification"]["state"], "unacknowledged");
    let _ = std::fs::remove_dir_all(&dir);
}
