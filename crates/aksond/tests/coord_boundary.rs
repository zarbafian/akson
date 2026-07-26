//! The boundary the coordination surface exists to be (ADR-0016).
//!
//! Slice 1a proved the pure gate; this drives the **real socket handler** for
//! every `ControlRequest` on every surface, so the property under test is the one
//! a driver actually meets: what a connection on `coord.sock` can and cannot
//! reach, and that the asymmetry is genuine in both directions.
//!
//! Four claims:
//!
//! 1. every admin op arriving on coord is refused with `forbidden-surface`;
//! 2. every coord op arriving on worker is refused, and every worker op arriving
//!    on coord is refused — `Worker` and `Coord` dominate nothing, including each
//!    other;
//! 3. admin dominates both, so an operator can diagnose the coordination surface
//!    without a second identity;
//! 4. `stage consent` is unreachable from coord — and the refusal mints nothing:
//!    the store holds no receipt afterwards.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use aksond::{
    bind_socket, handle_connection, send_request, Admission, ControlRequest, ControlResponse,
    DaemonConfig, DaemonState, FulfillOutput, Problem, ResultSubmission, Surface,
};

/// Every `ControlRequest` variant, with the surface it is meant to be reachable
/// from. The match has **no wildcard**: adding a variant to the control protocol
/// breaks this file until its surface is declared here, so the matrix below can
/// never silently miss an op.
fn intended_surface(req: &ControlRequest) -> Surface {
    match req {
        // --- admin: authority-bearing and operator-facing ---
        ControlRequest::Diagnose
        | ControlRequest::WhoAmI
        | ControlRequest::Token
        | ControlRequest::TaskInbox
        | ControlRequest::TaskShow { .. }
        | ControlRequest::TaskSent
        | ControlRequest::TaskOutcomes
        | ControlRequest::TaskOutput { .. }
        | ControlRequest::PeerList
        | ControlRequest::PeerKnocks
        | ControlRequest::PeerAdd { .. }
        | ControlRequest::PeerLabel { .. }
        | ControlRequest::PeerImportRemove { .. }
        | ControlRequest::PeerPing { .. }
        | ControlRequest::PeerAutoApprove { .. }
        | ControlRequest::TaskApprove { .. }
        | ControlRequest::TaskDeny { .. }
        | ControlRequest::TaskRun { .. }
        | ControlRequest::TaskFulfill { .. }
        | ControlRequest::TaskDeliver { .. }
        | ControlRequest::TaskSend(_)
        | ControlRequest::ProcessorAdd { .. }
        | ControlRequest::ProcessorList
        | ControlRequest::ProcessorCredential { .. }
        | ControlRequest::IssueWorkOrder { .. }
        // Consent stays here on purpose (ADR-0016 §3).
        | ControlRequest::StageConsent { .. } => Surface::Admin,

        // --- worker: narrow task I/O ---
        ControlRequest::SubmitResult(_) | ControlRequest::RequestProcessorCall { .. } => {
            Surface::Worker
        }

        // --- coord: the eight ops of `akson_byom_exchange_v1` ---
        ControlRequest::CoordWhoAmI
        | ControlRequest::PeerShow { .. }
        | ControlRequest::Stage { .. }
        | ControlRequest::StageShow { .. }
        | ControlRequest::Dispatch { .. }
        | ControlRequest::TaskStatus { .. }
        | ControlRequest::EventsRead { .. }
        | ControlRequest::CapabilityEvidence { .. } => Surface::Coord,
    }
}

fn all_requests() -> Vec<ControlRequest> {
    vec![
        ControlRequest::Diagnose,
        ControlRequest::WhoAmI,
        ControlRequest::Token,
        ControlRequest::TaskInbox,
        ControlRequest::TaskShow {
            task_id: "task-1".to_owned(),
        },
        ControlRequest::TaskSent,
        ControlRequest::TaskOutcomes,
        ControlRequest::TaskOutput {
            task_id: "task-1".to_owned(),
            role: None,
        },
        ControlRequest::PeerList,
        ControlRequest::PeerKnocks,
        ControlRequest::PeerAdd {
            token: "akson1".to_owned(),
            label: "partner".to_owned(),
            endpoint: None,
            update: false,
        },
        ControlRequest::PeerLabel {
            label: "a".to_owned(),
            new_label: "b".to_owned(),
        },
        ControlRequest::PeerImportRemove {
            label: "partner".to_owned(),
        },
        ControlRequest::PeerPing {
            label: "partner".to_owned(),
        },
        ControlRequest::PeerAutoApprove {
            agent_id: "partner".to_owned(),
            task_types: vec![],
            max_response_bytes: 0,
        },
        ControlRequest::TaskApprove {
            task_id: "task-1".to_owned(),
            processor: None,
            artifacts: false,
        },
        ControlRequest::TaskDeny {
            task_id: "task-1".to_owned(),
            reason: "no".to_owned(),
        },
        ControlRequest::TaskRun {
            task_id: "task-1".to_owned(),
        },
        ControlRequest::TaskFulfill {
            task_id: "task-1".to_owned(),
            outputs: vec![FulfillOutput {
                role: "response".to_owned(),
                media_type: "text/plain".to_owned(),
                content_base64: "aGk=".to_owned(),
            }],
        },
        ControlRequest::TaskDeliver {
            task_id: "task-1".to_owned(),
        },
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
        ControlRequest::ProcessorAdd {
            processor_id: "p".to_owned(),
            provider: "openai".to_owned(),
            origin_host: "api.example".to_owned(),
            origin_port: 443,
            local: false,
            tls_certificate_sha256: None,
            path: None,
            auth: None,
            headers: vec![],
        },
        ControlRequest::ProcessorList,
        ControlRequest::ProcessorCredential {
            processor_id: "p".to_owned(),
            credential: "secret".to_owned(),
        },
        ControlRequest::IssueWorkOrder {
            task_id: "task-1".to_owned(),
        },
        ControlRequest::StageConsent {
            stage_ref: "stage-0".to_owned(),
        },
        ControlRequest::SubmitResult(ResultSubmission {
            task_id: "task-1".to_owned(),
            outputs: vec![],
            evidence: vec![],
            slots: vec![],
        }),
        ControlRequest::RequestProcessorCall {
            processor_id: "p".to_owned(),
            work_order_id: "wo-1".to_owned(),
            request: "{}".to_owned(),
        },
        ControlRequest::CoordWhoAmI,
        ControlRequest::PeerShow {
            label: "partner".to_owned(),
        },
        ControlRequest::Stage {
            task_type: "https://byom.example/task/exchange/v1".to_owned(),
            performer: String::new(),
            payload_base64: "aGk=".to_owned(),
        },
        ControlRequest::StageShow {
            stage_ref: "stage-0".to_owned(),
        },
        ControlRequest::Dispatch {
            stage_ref: "stage-0".to_owned(),
            consent_receipt: "consent-0".to_owned(),
            execution_key: "k".to_owned(),
        },
        ControlRequest::TaskStatus {
            task_id: "task-1".to_owned(),
        },
        ControlRequest::EventsRead {
            cursor: None,
            limit: None,
        },
        ControlRequest::CapabilityEvidence {
            label: "partner".to_owned(),
        },
    ]
}

/// A stub dispatch: the gate is what is under test, so anything that reaches
/// dispatch answers `ok`. A `forbidden-surface` reply therefore proves the request
/// never reached the operation at all.
fn stub(_req: &ControlRequest) -> Result<serde_json::Value, Problem> {
    Ok(serde_json::json!({ "reached_dispatch": true }))
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "akson-coord-boundary-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Serves exactly one connection on `surface` over a real Unix socket and returns
/// the reply — the same code path `aksond serve` runs.
fn round_trip<F>(
    dir: &Path,
    tag: &str,
    surface: Surface,
    req: &ControlRequest,
    dispatch: F,
) -> ControlResponse
where
    F: Fn(&ControlRequest) -> Result<serde_json::Value, Problem> + Send + 'static,
{
    let path = dir.join(format!("{tag}.sock"));
    let listener = bind_socket(&path).unwrap();
    let admission = Admission::same_uid(aksond::current_uid());
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle_connection(stream, surface, &admission, &dispatch).unwrap();
    });
    let response = send_request(&path, req).unwrap();
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);
    response
}

fn forbidden(response: &ControlResponse, what: &str) {
    match response {
        ControlResponse::Problem { problem } => {
            assert_eq!(problem.status, 403, "{what}");
            assert_eq!(problem.type_, "urn:akson:error:forbidden-surface", "{what}");
            // The refusal names the surface and nothing else — a driver learns
            // nothing about the ops that exist elsewhere.
            let text = format!("{problem:?}").to_lowercase();
            for leak in ["work_order", "processor", "credential", "approve"] {
                assert!(!text.contains(leak), "{what}: refusal leaked {leak:?}");
            }
        }
        other => panic!("{what}: expected forbidden-surface, got {other:?}"),
    }
}

fn ok(response: &ControlResponse, what: &str) {
    match response {
        ControlResponse::Ok { result } => assert_eq!(result["reached_dispatch"], true, "{what}"),
        other => panic!("{what}: expected ok, got {other:?}"),
    }
}

#[test]
fn the_surface_matrix_holds_for_every_control_op_over_a_real_socket() {
    let dir = temp_dir("matrix");
    let requests = all_requests();
    // A sanity check on the enumeration itself: it must cover all three surfaces
    // and every op the coordination surface registers.
    assert_eq!(requests.len(), 36, "every ControlRequest variant is listed");
    assert_eq!(
        requests
            .iter()
            .filter(|r| intended_surface(r) == Surface::Coord)
            .count(),
        8,
        "ADR-0016's eight coordination ops"
    );

    for (i, req) in requests.iter().enumerate() {
        let intended = intended_surface(req);
        let what = format!("{:?} on ", req.op());

        // Admin dominates everything: even the coordination ops answer, so the
        // operator can diagnose the surface without a second identity.
        ok(
            &round_trip(&dir, &format!("a{i}"), Surface::Admin, req, stub),
            &format!("{what}admin"),
        );

        // Worker: only the two worker ops.
        let on_worker = round_trip(&dir, &format!("w{i}"), Surface::Worker, req, stub);
        if intended == Surface::Worker {
            ok(&on_worker, &format!("{what}worker"));
        } else {
            forbidden(&on_worker, &format!("{what}worker"));
        }

        // Coord: only the eight coordination ops. Every admin op — including
        // `stage_consent` — and every worker op is refused here.
        let on_coord = round_trip(&dir, &format!("c{i}"), Surface::Coord, req, stub);
        if intended == Surface::Coord {
            ok(&on_coord, &format!("{what}coord"));
        } else {
            forbidden(&on_coord, &format!("{what}coord"));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The refusal is not merely a status code: the operation does not run. A real
/// daemon state proves it — after `stage_consent` is refused on coord, no consent
/// receipt exists, and the staged contract is still merely `staged`.
#[test]
fn consent_refused_on_coord_mints_nothing() {
    let dir = temp_dir("consent");
    let mut config = DaemonConfig::from_env();
    config.data_dir = dir.join("data");
    config.receive_addr = None;
    let state = std::sync::Arc::new(DaemonState::bootstrap(&config).unwrap());

    // Stage over the coordination surface, as the driver would.
    let staged = {
        let state = state.clone();
        round_trip(
            &dir,
            "stage",
            Surface::Coord,
            &ControlRequest::Stage {
                task_type: "https://byom.example/task/exchange/v1".to_owned(),
                performer: String::new(),
                payload_base64: "b3V0Ym91bmQ=".to_owned(),
            },
            move |req| state.dispatch(req),
        )
    };
    let stage_ref = match staged {
        ControlResponse::Ok { result } => result["stage_ref"].as_str().unwrap().to_owned(),
        other => panic!("staging should succeed on coord, got {other:?}"),
    };

    // Now try to mint consent from the coordination surface.
    let refused = {
        let state = state.clone();
        round_trip(
            &dir,
            "consent",
            Surface::Coord,
            &ControlRequest::StageConsent {
                stage_ref: stage_ref.clone(),
            },
            move |req| state.dispatch(req),
        )
    };
    forbidden(&refused, "stage_consent on coord");

    // Nothing was minted, and the stage did not move.
    let store = state.store();
    let store = store.lock().unwrap();
    assert!(
        store.unconsumed_consent(&stage_ref).unwrap().is_none(),
        "a refused consent must mint nothing"
    );
    assert_eq!(
        store.staged_contract(&stage_ref).unwrap().unwrap().status,
        "staged"
    );
    // The same op over the admin socket does mint one — the boundary is the
    // surface, not the operation's existence.
    drop(store);
    let minted = {
        let state = state.clone();
        round_trip(
            &dir,
            "admin-consent",
            Surface::Admin,
            &ControlRequest::StageConsent {
                stage_ref: stage_ref.clone(),
            },
            move |req| state.dispatch(req),
        )
    };
    match minted {
        ControlResponse::Ok { result } => {
            assert!(result["consent_receipt"].as_str().is_some());
            assert_eq!(result["max_uses"], 1);
        }
        other => panic!("admin must be able to consent, got {other:?}"),
    }
    let store = state.store();
    let store = store.lock().unwrap();
    assert!(store.unconsumed_consent(&stage_ref).unwrap().is_some());
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A coordination request larger than the surface's ceiling is refused, and the
/// connection is not left holding unbounded daemon memory.
#[test]
fn an_oversized_coord_request_is_refused() {
    use std::io::{BufRead, BufReader, Write};
    let dir = temp_dir("oversize");
    let path = dir.join("coord.sock");
    let listener = bind_socket(&path).unwrap();
    let admission = Admission::same_uid(aksond::current_uid());
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle_connection(stream, Surface::Coord, &admission, &stub).unwrap();
    });

    let stream = UnixStream::connect(&path).unwrap();
    let filler = "x".repeat(2 * 1024 * 1024);
    let line = format!("{{\"op\":\"stage\",\"task_type\":\"{filler}\"}}\n");
    // The daemon may close after refusing, so a broken pipe here is fine.
    let _ = (&stream).write_all(line.as_bytes());
    let _ = (&stream).flush();
    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply).unwrap();
    server.join().unwrap();

    let response: ControlResponse = serde_json::from_str(reply.trim()).unwrap();
    match response {
        ControlResponse::Problem { problem } => {
            assert_eq!(problem.status, 413);
            assert_eq!(problem.type_, "urn:akson:error:request-too-large");
        }
        other => panic!("expected 413, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}
