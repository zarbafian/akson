//! Crash-injection matrix (design §13.1, §15.5, §19 Phase-1 gate): at each durable
//! commit point, a crash must leave a *recoverable* state — never a silently-retried
//! effect and never a lost-but-claimed-done one. Each case drives a real on-disk
//! store to a mid-flight state, drops it (the "crash"), and reopens it through
//! `DaemonState::bootstrap` (which runs recovery), then asserts the outcome.
//!
//! - a *running* worker attempt → recovered `ambiguous` (a byte may have left);
//! - a *dispatching* processor call → recovered `ambiguous`;
//! - a received request's idempotency record survives the crash, so a replay is a
//!   `Duplicate` (the exact same response), never a second effect.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use akson_authority::{
    AttemptEvent, AttemptState, Audience, Budgets, CapabilityVector, Grant, RequestOrigin,
    RespondScope, WorkOrder,
};
use akson_broker::{
    AuthScheme, CallBinding, CallBudget, Disclosure, Origin, ProcessorCall, ProcessorConfig,
    SubAttemptEvent, SubAttemptState,
};
use akson_contract::Identity;
use akson_store::delivery::CoveredValues;
use akson_store::Receipt;
use aksond::{DaemonConfig, DaemonState};

const NOW: i64 = 1_800_000_000;

fn unique_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("akson-crash-{tag}-{}-{n}", std::process::id()))
}

fn config(dir: &Path) -> DaemonConfig {
    DaemonConfig {
        data_dir: dir.to_path_buf(),
        local_performer: Identity {
            issuer: "iss".to_owned(),
            agent: "performer".to_owned(),
            root: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        },
        interface_url: "https://local/a2a".to_owned(),
        receive_addr: None,
        worker_command: None,
        worker_exec: None,
        on_task: None,
    }
}

fn work_order(id: &str, nonce: &str) -> WorkOrder {
    WorkOrder {
        version: 1,
        work_order_id: id.to_owned(),
        issuer: Identity {
            issuer: "local".to_owned(),
            agent: "authority".to_owned(),
            root: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        },
        issuer_assurance: "local-human".to_owned(),
        audience: Audience {
            daemon: "aksond".to_owned(),
            executor: "worker-1".to_owned(),
        },
        request_origin: RequestOrigin {
            peer: Identity {
                issuer: "iss".to_owned(),
                agent: "requester".to_owned(),
                root: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            },
            tls_certificate_sha256: "ab".repeat(32),
        },
        task_id: "task-1".to_owned(),
        context_id: "ctx-1".to_owned(),
        message_id: "msg-1".to_owned(),
        contract_revision: 0,
        contract_digest: "a".repeat(64),
        capabilities: CapabilityVector::new(vec![Grant::Respond(RespondScope {
            task_id: "task-1".to_owned(),
            message_id: "msg-1".to_owned(),
            recipient: "request-origin".to_owned(),
            max_responses: 1,
            max_bytes: 8192,
            deadline: "2030-01-01T00:00:00Z".to_owned(),
        })])
        .unwrap(),
        input_manifest: vec!["src".to_owned()],
        processor_digest: None,
        runner_digest: None,
        sandbox_digest: None,
        profile_digest: None,
        budgets: Budgets {
            max_cost_microusd: 500,
            max_bytes: 8192,
            max_operations: 4,
        },
        evidence_slots: vec![],
        policy_version: 1,
        decision_id: "d-1".to_owned(),
        not_before: "2026-01-01T00:00:00Z".to_owned(),
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        nonce: nonce.to_owned(),
        remote_cancel: None,
    }
}

fn processor_call(request: &[u8]) -> ProcessorCall {
    let config = ProcessorConfig {
        processor_id: "reviewer".to_owned(),
        provider: "local".to_owned(),
        origin: Origin::https("127.0.0.1", 8443),
        disclosure: Disclosure::local(),
        path: "/".to_owned(),
        auth: AuthScheme::Bearer,
        headers: Vec::new(),
        config: serde_json::json!({"model": "m"}),
        tls_certificate_sha256: None,
    };
    let binding = CallBinding {
        work_order_id: "wo-1".to_owned(),
        work_order_digest: "aa".repeat(32),
        task_id: "task-1".to_owned(),
    };
    let budget = CallBudget {
        max_cost_microusd: 5000,
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        max_response_bytes: 65536,
        max_operations: 16,
    };
    ProcessorCall::prepare(&config, request, binding, budget).unwrap()
}

#[test]
fn a_running_attempt_is_recovered_ambiguous_after_a_crash() {
    let dir = unique_dir("attempt");
    let cfg = config(&dir);
    let nonce = "n".repeat(43);

    // Session 1: claim the attempt and start it (running) — then "crash" (drop).
    {
        let state = DaemonState::bootstrap(&cfg).unwrap();
        let store = state.store();
        let store = store.lock().unwrap();
        store
            .claim_attempt(&work_order("wo-1", &nonce), NOW)
            .unwrap();
        store
            .advance_attempt("wo-1", AttemptEvent::Start, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(
            store.attempt_state("wo-1").unwrap(),
            Some(AttemptState::Running)
        );
    }

    // Session 2: reopening runs recovery — the running attempt is now ambiguous, and
    // stays ambiguous on a further restart (terminal, never re-run).
    let state = DaemonState::bootstrap(&cfg).unwrap();
    assert_eq!(
        state.store().lock().unwrap().attempt_state("wo-1").unwrap(),
        Some(AttemptState::Ambiguous)
    );
    drop(state);
    let state = DaemonState::bootstrap(&cfg).unwrap();
    assert_eq!(
        state.store().lock().unwrap().attempt_state("wo-1").unwrap(),
        Some(AttemptState::Ambiguous)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_dispatching_processor_call_is_recovered_ambiguous_after_a_crash() {
    let dir = unique_dir("call");
    let cfg = config(&dir);
    let call = processor_call(b"review this");

    // Session 1: prepare + dispatch (a byte may have left) — then crash.
    {
        let state = DaemonState::bootstrap(&cfg).unwrap();
        let store = state.store();
        let store = store.lock().unwrap();
        store.prepare_call(&call, 16, NOW).unwrap();
        store
            .advance_call(&call.idempotency_key, SubAttemptEvent::Dispatch, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(
            store.call_state(&call.idempotency_key).unwrap(),
            Some(SubAttemptState::Dispatching)
        );
    }

    // Session 2: reopening resolves the dispatching call to ambiguous.
    let state = DaemonState::bootstrap(&cfg).unwrap();
    assert_eq!(
        state
            .store()
            .lock()
            .unwrap()
            .call_state(&call.idempotency_key)
            .unwrap(),
        Some(SubAttemptState::Ambiguous)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_received_requests_idempotency_survives_a_crash_so_a_replay_is_a_duplicate() {
    let dir = unique_dir("idem");
    let cfg = config(&dir);
    let covered = CoveredValues {
        peer: "requester".to_owned(),
        message_id: "msg-1".to_owned(),
        body_digest: "AA".repeat(32),
        interface_url: "https://local/a2a".to_owned(),
        tenant: None,
        a2a_version: "1.0".to_owned(),
        extensions: vec![],
        content_type: "application/a2a+json".to_owned(),
        http_method: "POST".to_owned(),
    };

    // Session 1: commit the request's idempotency record, then crash.
    {
        let state = DaemonState::bootstrap(&cfg).unwrap();
        let store = state.store();
        let store = store.lock().unwrap();
        store
            .receive_request(
                &covered,
                b"the-body",
                b"THE-RESPONSE",
                Some("task-1"),
                "task",
                NOW,
            )
            .unwrap();
    }

    // Session 2: the durable record means a replay is a Duplicate with the identical
    // response and task id — the request is never processed a second time.
    let state = DaemonState::bootstrap(&cfg).unwrap();
    let store = state.store();
    let store = store.lock().unwrap();
    match store.peek(&covered).unwrap() {
        Receipt::Duplicate { task_id, response } => {
            assert_eq!(task_id.as_deref(), Some("task-1"));
            assert_eq!(response, b"THE-RESPONSE");
        }
        other => panic!("expected Duplicate after restart, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}
