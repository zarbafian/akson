//! Two agents, two components, many rounds: a cooperation scenario over Akson.
//!
//! Alice owns a **web UI**. Bob owns the **API server** it calls. Neither can see
//! the other's source — the only thing that crosses is a signed, delegated task and
//! its signed result. They converge on a working feature over six exchanges that
//! alternate direction and alternate *kind*:
//!
//! ```text
//!   1. alice → bob    feature   "add GET /stats {users, uptime_seconds}"
//!   2. bob   → alice  feature   "it's live, here's the shape — render it"
//!   3. alice → bob    defect    "you send uptime in ms; the shape says seconds"
//!   4. bob   → alice  feature   "added error_rate, render that too"
//!   5. alice → bob    defect    "/stats 500s when users = 0"
//!   6. bob   → alice  confirm   "fixed; re-check against the shape"
//! ```
//!
//! What this actually tests is the *medium*, not the agents: each round's task
//! inputs are built from the bytes the previous round delivered, so the chain only
//! runs to completion if a result's content really reaches the requesting side.
//! The final assertion pins that down — every round's input digest equals the
//! previous round's output digest, so the six exchanges form one unbroken chain
//! through six contracts, six work orders, and six signed outcomes.
//!
//! The two "agents" here are deliberately dumb pure functions ([`ApiAgent`] and
//! [`UiAgent`]): Akson carries the delegation and the evidence, the agent supplies
//! the smarts. Swapping in a model-backed worker changes nothing about the loop —
//! see `bench/cooperate.sh` for that same scenario against real models.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use akson_contract::Identity;
use akson_crypto::cert::{self_signed_endpoint, EndpointCert};
use akson_crypto::purpose::KeyPurpose;
use akson_store::envelope::Kek;
use akson_store::{ExternalCheckpoint, Store};
use akson_transport::tls::bootstrap_server_config;
use aksond::{
    serve_receive, ControlRequest, DaemonConfig, DaemonState, Deliverable, FulfillOutput,
    IdentityKeys, OutputKind, ReceiveState, ResultOutput, ResultSubmission, StorePeerResolver,
    TaskInput, TaskSpec,
};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const NOW: i64 = 1_800_000_000; // within [2026, 2030)

// ---------------------------------------------------------------------------
// The two agents. Each owns a component the other cannot see, and answers a task
// by mutating that component and reporting its public surface.
// ---------------------------------------------------------------------------

/// Bob's component: the API server. Holds the endpoints it serves and the unit it
/// actually sends uptime in — which starts out disagreeing with what it publishes.
#[derive(Default)]
struct ApiAgent {
    fields: Vec<String>,
    /// What `/stats` really returns for uptime. The published shape always says
    /// seconds; round 1 ships milliseconds, which is the defect alice catches.
    uptime_unit: &'static str,
    /// Whether the zero-user division bug is still present.
    divides_by_users: bool,
}

impl ApiAgent {
    /// Answers a delegated task. `objective` is what alice asked for; `inputs` is
    /// whatever she sent along (her last delivered result). Returns the response
    /// bytes bob signs and delivers back.
    fn serve(&mut self, objective: &str, _inputs: &[String]) -> String {
        if objective.contains("add GET /stats") {
            self.fields = vec!["users".to_owned(), "uptime_seconds".to_owned()];
            self.uptime_unit = "ms"; // the bug alice will report in round 3
            self.divides_by_users = true; // the bug alice will report in round 5
        }
        if objective.contains("uptime") && objective.contains("milliseconds") {
            self.uptime_unit = "s";
            // While fixing it bob also ships a field nobody asked for. He can only
            // tell alice about it by delegating a task to her — which is round 4.
            self.fields.push("error_rate".to_owned());
        }
        if objective.contains("500") && objective.contains("users") {
            self.divides_by_users = false;
        }
        self.publish()
    }

    /// The contract bob publishes for `/stats` — the only thing alice ever sees of
    /// his component.
    fn publish(&self) -> String {
        json!({
            "endpoint": "GET /stats",
            "fields": self.fields,
            "uptime_unit_actually_sent": self.uptime_unit,
            "safe_when_no_users": !self.divides_by_users,
        })
        .to_string()
    }
}

/// Alice's component: the web UI. Renders whatever fields the API publishes, and
/// reports back what it observed — including anything that contradicts the shape.
#[derive(Default)]
struct UiAgent {
    rendered: Vec<String>,
    observed_uptime_unit: String,
    observed_safe_when_no_users: bool,
}

impl UiAgent {
    /// Answers a delegated task from bob. `inputs` carries the API shape he
    /// delivered; alice wires her UI to it and reports what she now renders.
    fn serve(&mut self, _objective: &str, inputs: &[String]) -> String {
        for input in inputs {
            let Ok(shape) = serde_json::from_str::<serde_json::Value>(input) else {
                continue;
            };
            if let Some(fields) = shape["fields"].as_array() {
                self.rendered = fields
                    .iter()
                    .filter_map(|f| f.as_str().map(str::to_owned))
                    .collect();
            }
            self.observed_uptime_unit = shape["uptime_unit_actually_sent"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            self.observed_safe_when_no_users =
                shape["safe_when_no_users"].as_bool().unwrap_or(false);
        }
        json!({
            "renders": self.rendered,
            "uptime_unit_received": self.observed_uptime_unit,
            "blank_when_no_users": !self.observed_safe_when_no_users,
        })
        .to_string()
    }
}

// ---------------------------------------------------------------------------
// One endpoint, and the six-round drive.
// ---------------------------------------------------------------------------

/// A live daemon plus everything the other side must pin to talk to it.
struct Endpoint {
    state: Arc<DaemonState>,
    agent: String,
    url: String,
    cert: EndpointCert,
    proposal_pub: [u8; 32],
    task_result_pub: [u8; 32],
}

/// One completed exchange, kept so the chain can be checked at the end.
struct Round {
    label: &'static str,
    requester: String,
    performer: String,
    /// What the requester sent as the task's input, and what came back.
    input: String,
    output: String,
}

#[tokio::test]
async fn two_agents_build_interacting_components_over_six_delegated_rounds() {
    let (alice, bob) = paired_endpoints().await;
    let mut api = ApiAgent::default();
    let mut ui = UiAgent::default();
    let mut rounds: Vec<Round> = Vec::new();

    // Round 1 — alice asks for the endpoint. Nothing precedes it, so its input is
    // the one thing in the whole run that is not a previous result.
    let kickoff = json!({ "component": "web-ui", "needs": "a stats panel" }).to_string();
    let out = exchange(
        &alice,
        &bob,
        "add GET /stats returning users and uptime_seconds",
        &kickoff,
        |objective, inputs| api.serve(objective, inputs),
    )
    .await;
    rounds.push(Round {
        label: "feature: alice asks bob for GET /stats",
        requester: alice.agent.clone(),
        performer: bob.agent.clone(),
        input: kickoff,
        output: out,
    });

    // Round 2 — bob hands the shape back and asks alice to render it. The input is
    // verbatim what round 1 delivered.
    let input = rounds.last().unwrap().output.clone();
    let out = exchange(
        &bob,
        &alice,
        "/stats is live — render these fields in the UI",
        &input,
        |objective, inputs| ui.serve(objective, inputs),
    )
    .await;
    rounds.push(Round {
        label: "feature: bob asks alice to render it",
        requester: bob.agent.clone(),
        performer: alice.agent.clone(),
        input,
        output: out,
    });

    // Alice's UI is wired up, but it received milliseconds where the published
    // shape promised seconds. That contradiction is visible in her own output —
    // which is exactly what she reports as a defect.
    assert_eq!(
        ui.observed_uptime_unit, "ms",
        "round 2 should surface the unit mismatch alice reports next"
    );

    // Round 3 — a defect report, not a feature request.
    let input = rounds.last().unwrap().output.clone();
    let out = exchange(
        &alice,
        &bob,
        "defect: uptime arrives in milliseconds but the shape says uptime_seconds",
        &input,
        |objective, inputs| api.serve(objective, inputs),
    )
    .await;
    rounds.push(Round {
        label: "defect: alice reports the wrong uptime unit",
        requester: alice.agent.clone(),
        performer: bob.agent.clone(),
        input,
        output: out,
    });

    // Round 4 — bob adds a field of his own and asks for it to be shown.
    let input = rounds.last().unwrap().output.clone();
    let out = exchange(
        &bob,
        &alice,
        "feature: /stats now also returns error_rate — please render it",
        &input,
        |objective, inputs| ui.serve(objective, inputs),
    )
    .await;
    rounds.push(Round {
        label: "feature: bob adds error_rate, alice renders it",
        requester: bob.agent.clone(),
        performer: alice.agent.clone(),
        input,
        output: out,
    });

    // Round 5 — the second defect: something the UI can observe but not fix.
    let input = rounds.last().unwrap().output.clone();
    let out = exchange(
        &alice,
        &bob,
        "defect: /stats returns 500 when users is 0 and the panel goes blank",
        &input,
        |objective, inputs| api.serve(objective, inputs),
    )
    .await;
    rounds.push(Round {
        label: "defect: alice reports the zero-user 500",
        requester: alice.agent.clone(),
        performer: bob.agent.clone(),
        input,
        output: out,
    });

    // Round 6 — bob asks alice to re-check against the corrected shape.
    let input = rounds.last().unwrap().output.clone();
    let out = exchange(
        &bob,
        &alice,
        "fixed both — re-check the panel against the shape",
        &input,
        |objective, inputs| ui.serve(objective, inputs),
    )
    .await;
    rounds.push(Round {
        label: "confirm: alice re-checks and agrees",
        requester: bob.agent.clone(),
        performer: alice.agent.clone(),
        input,
        output: out,
    });

    // --- the components agree, and they only could have via what was delivered ---

    assert_eq!(rounds.len(), 6);

    // Both defects are gone, and each side learned it from the other's result.
    assert_eq!(ui.observed_uptime_unit, "s", "round 3's fix reached the UI");
    assert!(
        ui.observed_safe_when_no_users,
        "round 5's fix reached the UI"
    );
    // The UI renders exactly what the API publishes — convergence, not coincidence.
    assert_eq!(ui.rendered, api.fields);
    assert_eq!(
        ui.rendered,
        vec!["users", "uptime_seconds", "error_rate"],
        "the feature they built together"
    );

    // The chain: every round after the first was driven by the bytes the previous
    // round delivered. If a single result's content had failed to cross, this is
    // where it shows up.
    for pair in rounds.windows(2) {
        assert_eq!(
            pair[1].input, pair[0].output,
            "round '{}' must be driven by what round '{}' delivered",
            pair[1].label, pair[0].label
        );
    }

    // And the direction really did alternate — each side took a turn performing.
    for pair in rounds.windows(2) {
        assert_eq!(pair[1].requester, pair[0].performer);
        assert_eq!(pair[1].performer, pair[0].requester);
    }

    // Six exchanges, six signed outcomes, split across the two endpoints.
    let alice_outcomes = alice.state.store().lock().unwrap().list_outcomes().unwrap();
    let bob_outcomes = bob.state.store().lock().unwrap().list_outcomes().unwrap();
    assert_eq!(alice_outcomes.len(), 3, "alice requested rounds 1, 3, 5");
    assert_eq!(bob_outcomes.len(), 3, "bob requested rounds 2, 4, 6");
    for outcome in alice_outcomes.iter().chain(&bob_outcomes) {
        assert_eq!(outcome.state, "accepted");
    }
}

/// Drives one full exchange and returns the response bytes the requester ends up
/// holding: send → approve → the performer's agent answers → deliver → the
/// requester reads the delivered output back out of its own store.
///
/// This is the whole loop an operator would drive with
/// `akson task send` → `akson task approve` → `akson task run` → `akson task deliver`
/// → `akson task output`.
async fn exchange(
    requester: &Endpoint,
    performer: &Endpoint,
    objective: &str,
    input: &str,
    mut agent: impl FnMut(&str, &[String]) -> String,
) -> String {
    // 1. The requester signs and posts the proposal.
    let spec = TaskSpec {
        performer: performer.agent.clone(),
        task_type: "https://akson.invalid/task/component-change/v1".to_owned(),
        objective: objective.to_owned(),
        inputs: vec![TaskInput {
            id: "context".to_owned(),
            media_type: "application/json".to_owned(),
            text: input.to_owned(),
        }],
        deliverables: vec![Deliverable {
            role: "response".to_owned(),
            media_type: "application/json".to_owned(),
        }],
        capabilities: vec!["respond".to_owned(), "read_supplied_inputs".to_owned()],
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        max_response_bytes: 8192,
    };
    let sender = requester.state.clone();
    let sent =
        tokio::task::spawn_blocking(move || sender.dispatch(&ControlRequest::TaskSend(spec)))
            .await
            .unwrap()
            .unwrap();
    let task_id = sent["task_id"].as_str().unwrap().to_owned();

    // 2. The performer's operator approves it, which issues the one-shot work order.
    let approved = performer
        .state
        .dispatch(&ControlRequest::TaskApprove {
            task_id: task_id.clone(),
            processor: None,
            artifacts: false,
        })
        .unwrap();
    assert_eq!(approved["approved"], true, "approving {task_id}");

    // 3. The performer's agent does the work. It sees only what the contract
    //    delivered — the objective and the inputs staged for the worker — which is
    //    what a sandboxed worker reads from /inputs.
    let staged: Vec<String> = performer
        .state
        .store()
        .lock()
        .unwrap()
        .list_task_inputs(&task_id)
        .unwrap()
        .iter()
        .map(|i| String::from_utf8_lossy(&i.payload).into_owned())
        .collect();
    assert_eq!(staged, vec![input.to_owned()], "the input crossed intact");
    let response = agent(objective, &staged);

    let completed = performer
        .state
        .dispatch(&ControlRequest::SubmitResult(ResultSubmission {
            task_id: task_id.clone(),
            outputs: vec![ResultOutput {
                role: "response".to_owned(),
                artifact_id: format!("resp-{task_id}"),
                kind: OutputKind::Response,
                recipient: "request-origin".to_owned(),
                media_type: "application/json".to_owned(),
                content: response.clone().into_bytes(),
            }],
            evidence: vec![],
            slots: vec![],
        }))
        .unwrap();
    assert_eq!(completed["completed"], true);

    // 4. The performer delivers the signed result; the requester verifies it
    //    against the manifest and keeps the bytes.
    let deliverer = performer.state.clone();
    let tid = task_id.clone();
    let delivered = tokio::task::spawn_blocking(move || {
        deliverer.dispatch(&ControlRequest::TaskDeliver { task_id: tid })
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(delivered["delivered"], true, "delivering {task_id}");

    // 5. The requester reads the result back — `akson task output <id>`.
    let read = requester
        .state
        .dispatch(&ControlRequest::TaskOutput {
            task_id: task_id.clone(),
            role: Some("response".to_owned()),
        })
        .unwrap();
    // The payload comes back base64 so it is byte-exact, not a lossy UTF-8 view.
    let encoded = read["outputs"][0]["content"].as_str().unwrap();
    let bytes = STANDARD.decode(encoded).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(
        text, response,
        "the requester must hold exactly what the performer signed"
    );
    text
}

/// The cooperative path: the performer fulfils a task with a result its own agent
/// produced (`task fulfill`), not a sandboxed worker — the shape of "my Claude asks
/// my Codex, which answers from its own session." The daemon still gates and signs
/// it, so the requester's accepted result is exactly as verifiable as a sandboxed
/// run's, and it holds precisely the bytes the performer signed for.
#[tokio::test]
async fn a_performer_can_fulfil_a_task_from_its_own_agent_without_a_sandbox() {
    let (alice, bob) = paired_endpoints().await;

    // Alice delegates a design task. The brief carries none of the "session-only"
    // knowledge the answer will use — that is the whole point of asking the peer.
    let spec = TaskSpec {
        performer: bob.agent.clone(),
        task_type: "https://akson.cc/task/design/v1".to_owned(),
        objective: "Design a caching strategy for our checkout service.".to_owned(),
        inputs: vec![],
        deliverables: vec![Deliverable {
            role: "response".to_owned(),
            media_type: "text/plain".to_owned(),
        }],
        capabilities: vec!["respond".to_owned()],
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        max_response_bytes: 8192,
    };
    let sender = alice.state.clone();
    let sent =
        tokio::task::spawn_blocking(move || sender.dispatch(&ControlRequest::TaskSend(spec)))
            .await
            .unwrap()
            .unwrap();
    let task_id = sent["task_id"].as_str().unwrap().to_owned();

    // Bob approves, then fulfils with what his own agent produced (references facts
    // never present in the brief).
    bob.state
        .dispatch(&ControlRequest::TaskApprove {
            task_id: task_id.clone(),
            processor: None,
            artifacts: false,
        })
        .unwrap();
    let design = "Use an in-process LRU plus PostgreSQL materialized views; no Redis.";
    let fulfilled = bob
        .state
        .dispatch(&ControlRequest::TaskFulfill {
            task_id: task_id.clone(),
            outputs: vec![FulfillOutput {
                role: "response".to_owned(),
                media_type: "text/plain".to_owned(),
                content_base64: STANDARD.encode(design),
            }],
        })
        .unwrap();
    assert_eq!(
        fulfilled["fulfilled"], true,
        "fulfilment completes the task"
    );

    // Deliver, then alice reads the verified result — byte-exact.
    let deliverer = bob.state.clone();
    let tid = task_id.clone();
    let delivered = tokio::task::spawn_blocking(move || {
        deliverer.dispatch(&ControlRequest::TaskDeliver { task_id: tid })
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(delivered["delivered"], true);

    let read = alice
        .state
        .dispatch(&ControlRequest::TaskOutput {
            task_id: task_id.clone(),
            role: Some("response".to_owned()),
        })
        .unwrap();
    let got = STANDARD
        .decode(read["outputs"][0]["content"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        got,
        design.as_bytes(),
        "alice holds exactly what bob fulfilled"
    );
}

/// A task the operator DENIED must never be auto-approved by a later reactor sweep,
/// even under a matching standing policy — a rejection leaves the head open, so the
/// deny path marks it handled (codex review).
#[tokio::test]
async fn a_denied_task_is_not_later_auto_approved() {
    let (alice, bob) = paired_endpoints().await;
    bob.state
        .dispatch(&ControlRequest::PeerAutoApprove {
            agent_id: alice.agent.clone(),
            task_types: vec!["https://akson.cc/task/design/v1".to_owned()],
            max_response_bytes: 8192,
        })
        .unwrap();
    let spec = TaskSpec {
        performer: bob.agent.clone(),
        task_type: "https://akson.cc/task/design/v1".to_owned(),
        objective: "would fit the policy".to_owned(),
        inputs: vec![],
        deliverables: vec![Deliverable {
            role: "response".to_owned(),
            media_type: "text/plain".to_owned(),
        }],
        capabilities: vec!["respond".to_owned()],
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        max_response_bytes: 4096,
    };
    let sender = alice.state.clone();
    let task_id =
        tokio::task::spawn_blocking(move || sender.dispatch(&ControlRequest::TaskSend(spec)))
            .await
            .unwrap()
            .unwrap()["task_id"]
            .as_str()
            .unwrap()
            .to_owned();

    // The operator denies it before the reactor runs.
    let deny = bob
        .state
        .dispatch(&ControlRequest::TaskDeny {
            task_id: task_id.clone(),
            reason: "not this one".to_owned(),
        })
        .unwrap();
    assert_eq!(deny["denied"], true, "deny result: {deny}");
    let pending = bob
        .state
        .store()
        .lock()
        .unwrap()
        .tasks_awaiting_reaction()
        .unwrap();
    assert!(
        pending.iter().all(|t| t.task_id != task_id),
        "a denied task must be marked handled; still pending: {pending:?}"
    );

    // A sweep must NOT auto-approve the denied task.
    aksond::react_once(&bob.state).unwrap();
    assert!(
        bob.state
            .store()
            .lock()
            .unwrap()
            .attempt_for_task(&task_id)
            .unwrap()
            .is_none(),
        "a denied task must never be auto-approved"
    );
}

/// A standing per-peer policy auto-approves a fitting task (no human prompt), and
/// leaves a task outside the policy submitted for a decision. This is the opt-in
/// half of the trust model: the human pre-authorises a peer, the daemon enforces.
#[tokio::test]
async fn a_standing_policy_auto_approves_within_limits_and_asks_outside_them() {
    let (alice, bob) = paired_endpoints().await;
    // Bob's operator pre-authorises alice for this task type, up to 8 KiB.
    bob.state
        .dispatch(&ControlRequest::PeerAutoApprove {
            agent_id: alice.agent.clone(),
            task_types: vec!["https://akson.cc/task/design/v1".to_owned()],
            max_response_bytes: 8192,
        })
        .unwrap();

    let send = |objective: &str, max_bytes: u64| {
        let spec = TaskSpec {
            performer: bob.agent.clone(),
            task_type: "https://akson.cc/task/design/v1".to_owned(),
            objective: objective.to_owned(),
            inputs: vec![],
            deliverables: vec![Deliverable {
                role: "response".to_owned(),
                media_type: "text/plain".to_owned(),
            }],
            capabilities: vec!["respond".to_owned()],
            deadline: "2030-01-01T00:00:00Z".to_owned(),
            max_response_bytes: max_bytes,
        };
        let sender = alice.state.clone();
        async move {
            tokio::task::spawn_blocking(move || sender.dispatch(&ControlRequest::TaskSend(spec)))
                .await
                .unwrap()
                .unwrap()["task_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };

    // A fitting task and one over the byte ceiling.
    let fits = send("within policy", 4096).await;
    let over = send("over the byte ceiling", 100_000).await;

    // One reactor sweep on bob.
    aksond::react_once(&bob.state).unwrap();

    // The fitting task is auto-approved: it now has an issued work order.
    let has_work_order = |task_id: &str| {
        bob.state
            .store()
            .lock()
            .unwrap()
            .attempt_for_task(task_id)
            .unwrap()
            .is_some()
    };
    assert!(has_work_order(&fits), "the in-policy task is auto-approved");
    assert!(
        !has_work_order(&over),
        "the over-limit task waits for a human decision"
    );

    // A second sweep does nothing new (the task_reactions row makes it once-only).
    aksond::react_once(&bob.state).unwrap();
    assert!(has_work_order(&fits));
}

/// A fulfilment is gated exactly like a sandboxed run: a result outside the granted
/// scope (here, over the byte ceiling) is refused, and no outcome is delivered.
#[tokio::test]
async fn a_fulfilment_outside_the_granted_scope_is_refused() {
    let (alice, bob) = paired_endpoints().await;
    let spec = TaskSpec {
        performer: bob.agent.clone(),
        task_type: "https://akson.cc/task/design/v1".to_owned(),
        objective: "Small answer only.".to_owned(),
        inputs: vec![],
        deliverables: vec![Deliverable {
            role: "response".to_owned(),
            media_type: "text/plain".to_owned(),
        }],
        capabilities: vec!["respond".to_owned()],
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        max_response_bytes: 16, // a tight ceiling
    };
    let sender = alice.state.clone();
    let sent =
        tokio::task::spawn_blocking(move || sender.dispatch(&ControlRequest::TaskSend(spec)))
            .await
            .unwrap()
            .unwrap();
    let task_id = sent["task_id"].as_str().unwrap().to_owned();
    bob.state
        .dispatch(&ControlRequest::TaskApprove {
            task_id: task_id.clone(),
            processor: None,
            artifacts: false,
        })
        .unwrap();
    // 100 bytes against a 16-byte grant → the gate refuses it.
    let err = bob
        .state
        .dispatch(&ControlRequest::TaskFulfill {
            task_id: task_id.clone(),
            outputs: vec![FulfillOutput {
                role: "response".to_owned(),
                media_type: "text/plain".to_owned(),
                content_base64: STANDARD.encode("x".repeat(100)),
            }],
        })
        .unwrap_err();
    assert_eq!(err.status, 403, "an over-budget fulfilment is denied");
}

// ---------------------------------------------------------------------------
// Setup: two daemons that have paired with each other, both able to send AND
// perform (each pins the other's proposal *and* task-result key).
// ---------------------------------------------------------------------------

async fn paired_endpoints() -> (Endpoint, Endpoint) {
    let alice_identity = IdentityKeys::from_master([10u8; 32]);
    let bob_identity = IdentityKeys::from_master([20u8; 32]);
    let alice_cert = endpoint_cert(&alice_identity, "alice");
    let bob_cert = endpoint_cert(&bob_identity, "bob");

    // Bind both ports first so each peer record can carry the other's real URL.
    let alice_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let alice_url = format!(
        "https://127.0.0.1:{}/a2a",
        alice_listener.local_addr().unwrap().port()
    );
    let bob_url = format!(
        "https://127.0.0.1:{}/a2a",
        bob_listener.local_addr().unwrap().port()
    );

    let mut alice = Endpoint {
        state: Arc::new(DaemonState::from_parts(
            in_memory_store(),
            IdentityKeys::from_master([10u8; 32]),
            alice_cert.clone(),
            config("aksond-coop-alice", "alice"),
        )),
        agent: "alice".to_owned(),
        url: alice_url,
        cert: alice_cert,
        proposal_pub: public(&alice_identity, KeyPurpose::ContractProposal),
        task_result_pub: public(&alice_identity, KeyPurpose::TaskResult),
    };
    let mut bob = Endpoint {
        state: Arc::new(DaemonState::from_parts(
            in_memory_store(),
            IdentityKeys::from_master([20u8; 32]),
            bob_cert.clone(),
            config("aksond-coop-bob", "bob"),
        )),
        agent: "bob".to_owned(),
        url: bob_url,
        cert: bob_cert,
        proposal_pub: public(&bob_identity, KeyPurpose::ContractProposal),
        task_result_pub: public(&bob_identity, KeyPurpose::TaskResult),
    };

    // Pair in BOTH directions, pinning both key purposes each way — the difference
    // from a one-way requester/performer setup, and what lets either side delegate.
    pin_peer(&alice, &bob);
    pin_peer(&bob, &alice);

    // Both endpoints serve proposals *and* accept delivered results.
    serve(&mut alice, alice_listener);
    serve(&mut bob, bob_listener);
    (alice, bob)
}

/// Records `peer` in `local`'s store the way a real relationship lands
/// (design §8.2): an import under the peer's agent name as its label, then an
/// introduction commit that pins the identity and keys under the root — so
/// label resolution, root-bound standing policy, and the reactor's root gate
/// all see the shape the live daemon produces.
fn pin_peer(local: &Endpoint, peer: &Endpoint) {
    let store = local.state.store();
    let store = store.lock().unwrap();
    // The peer's REAL identity root (its agent-card thumbprint, populated at
    // bootstrap): the signed contract's requester.root carries this value, so
    // the pinned relationship must too (ADR-0014).
    let root = peer.state.config().local_performer.root.clone();
    store.add_peer_import(&root, &peer.agent, "", NOW).unwrap();
    let identity = akson_crypto::identity::PeerIdentity {
        issuer: Some("iss".to_owned()),
        agent_id: peer.agent.clone(),
        workload_id: None,
        endpoint_id: peer.url.clone(),
        tls_cert: peer.cert.fingerprint.clone(),
        agent_card_key: akson_crypto::identity::Fingerprint {
            kind: akson_crypto::identity::FingerprintKind::Jwk7638,
            value: root.clone(),
        },
        key_bindings: vec![],
        security_projection_digest: peer.cert.fingerprint.clone(),
        full_card_digest: peer.cert.fingerprint.clone(),
    };
    let keys = vec![
        ("contract-proposal".to_owned(), peer.proposal_pub),
        ("task-result".to_owned(), peer.task_result_pub),
    ];
    let outcome = store
        .commit_introduced_peer(
            &root,
            1,
            &akson_store::StoredPeer {
                identity,
                local_note: String::new(),
            },
            &keys,
            NOW,
        )
        .unwrap();
    assert!(matches!(
        outcome,
        akson_store::IntroCommitOutcome::Committed
    ));
}

fn serve(endpoint: &mut Endpoint, listener: TcpListener) {
    let receive = Arc::new(
        ReceiveState::new(
            endpoint.state.store(),
            StorePeerResolver,
            // The daemon's REAL local identity (root populated at bootstrap):
            // inbound performer.root must equal it (ADR-0014).
            endpoint.state.config().local_performer.clone(),
            BTreeSet::new(),
            endpoint.url.clone(),
        )
        // Both sides both send and perform, so both must finalize results.
        .accepting_results(
            endpoint
                .state
                .identity()
                .purpose_key(KeyPurpose::RequesterOutcome),
        ),
    );
    let acceptor = TlsAcceptor::from(Arc::new(
        bootstrap_server_config(
            &endpoint
                .state
                .identity()
                .purpose_key(KeyPurpose::TlsEndpoint),
            endpoint.state.endpoint_cert(),
        )
        .unwrap(),
    ));
    tokio::spawn(serve_receive(listener, acceptor, receive));
}

fn endpoint_cert(identity: &IdentityKeys, name: &str) -> EndpointCert {
    self_signed_endpoint(
        &identity.purpose_key(KeyPurpose::TlsEndpoint),
        name,
        Duration::from_secs(3600),
    )
    .unwrap()
}

fn public(identity: &IdentityKeys, purpose: KeyPurpose) -> [u8; 32] {
    identity.purpose_key(purpose).verifying().to_public_bytes()
}

fn config(dir: &str, agent: &str) -> DaemonConfig {
    DaemonConfig {
        data_dir: std::env::temp_dir().join(dir),
        local_performer: ident(agent),
        interface_url: "https://local/a2a".to_owned(),
        receive_addr: None,
        worker_command: None,
        worker_exec: None,
        on_task: None,
    }
}

fn ident(agent: &str) -> Identity {
    Identity {
        issuer: "iss".to_owned(),
        agent: agent.to_owned(),
        root: "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    }
}

fn in_memory_store() -> Store {
    Store::open_in_memory(
        &Kek::from_bytes([9u8; 32]),
        ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        },
    )
    .unwrap()
}
