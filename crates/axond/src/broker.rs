//! The live processor-call dispatch (design §13.1, §15.2): the broker's outbound
//! HTTPS call, composed from the durable sub-attempt, the egress gates, and the
//! anti-SSRF connection-time address check.
//!
//! The security-critical steps live here; the raw HTTPS transport is a seam
//! ([`CallTransport`]) so the composition is fully testable without a live server.
//!
//! Order (§13.1): prepare the durable pre-dispatch record → record `dispatching`
//! BEFORE any byte leaves → resolve the origin and RE-CHECK the resolved address
//! at connection time (anti-rebinding) → inject the sealed credential and send →
//! record the terminal state honestly. A clean pre-send failure is `failed`; an
//! uncertain outcome (bytes may have left) is `ambiguous` and is never
//! auto-retried.

use std::net::IpAddr;
use std::sync::Mutex;

use axon_broker::{
    check_origin, check_resolved_address, CallBinding, CallBudget, EgressPolicy, ProcessorCall,
    SubAttemptEvent, SubAttemptState,
};
use axon_store::{PrepareOutcome, Store};

use crate::control::Problem;

/// A processor's HTTPS response.
pub struct CallResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why the transport failed, and whether it is *clean* (no byte left the host —
/// safe to mark `failed`) or *uncertain* (bytes may have left — must be `ambiguous`).
pub enum TransportError {
    /// No request byte left the host (connect/handshake failed before sending).
    Clean(String),
    /// The request may have been transmitted; the outcome is uncertain.
    Uncertain(String),
}

/// The raw HTTPS transport: connect to the **already-checked** address, present no
/// client certificate (the credential authenticates), inject the credential, POST
/// the request, and read the size-capped response. A seam so the dispatch
/// composition is testable without a live server; the production impl uses rustls.
pub trait CallTransport {
    fn send(
        &self,
        host: &str,
        port: u16,
        addr: IpAddr,
        credential: Option<&[u8]>,
        request: &[u8],
        max_response_bytes: u64,
    ) -> impl std::future::Future<Output = Result<CallResponse, TransportError>>;
}

/// Dispatches a processor call (design §13.1). Fails closed at every gate, records
/// the sub-attempt durable-before-effect, and never re-dispatches a call that
/// already reached a terminal state.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_processor_call(
    store: &Mutex<Store>,
    processor_id: &str,
    request: &[u8],
    binding: CallBinding,
    budget: CallBudget,
    policy: &EgressPolicy,
    transport: &impl CallTransport,
    now: i64,
) -> Result<serde_json::Value, Problem> {
    // Phase 1 (locked): the config, the durable pre-dispatch record, and the move
    // to `dispatching` — all before any byte leaves.
    let (call, credential) = {
        let store = store.lock().map_err(|_| internal())?;
        let config = store
            .get_processor(processor_id)
            .map_err(store_problem)?
            .ok_or_else(|| problem(404, "no-such-processor", "no such processor"))?;
        // The configured origin must be https + allowlisted (a task never supplies it).
        check_origin(&config.origin, policy).map_err(|e| {
            problem_detail(403, "egress-refused", "the processor origin is not permitted", e)
        })?;
        let call =
            ProcessorCall::prepare(&config, request, binding, budget).map_err(|_| internal())?;
        match store.prepare_call(&call, now).map_err(store_problem)? {
            PrepareOutcome::Prepared => {}
            // Idempotent: a call that already reached a terminal state is never re-sent.
            PrepareOutcome::AlreadyPrepared(state) if is_terminal(state) => {
                return Ok(outcome_json(&call, state, None));
            }
            PrepareOutcome::AlreadyPrepared(_) => {}
        }
        // Record `dispatching` before the first byte leaves (§13.1).
        advance(&store, &call.idempotency_key, SubAttemptEvent::Dispatch, now)?;
        let credential = store.get_credential(processor_id).map_err(store_problem)?;
        (call, credential)
    };

    // Phase 2 (unlocked): resolve, RE-CHECK the resolved address, then send.
    let addr = match resolve(&call.origin.host, call.origin.port).await {
        Some(addr) => addr,
        None => {
            mark(store, &call.idempotency_key, SubAttemptEvent::Fail, now)?;
            return Err(problem(502, "unresolved", "the processor origin did not resolve"));
        }
    };
    // Anti-SSRF / anti-rebinding: the address actually dialed is checked, not the name.
    if let Err(e) = check_resolved_address(addr, policy) {
        mark(store, &call.idempotency_key, SubAttemptEvent::Fail, now)?;
        return Err(problem_detail(
            403,
            "egress-refused",
            "the resolved address is not permitted",
            e,
        ));
    }
    let result = transport
        .send(
            &call.origin.host,
            call.origin.port,
            addr,
            credential.as_deref(),
            request,
            call.max_response_bytes,
        )
        .await;

    // Phase 3 (locked): the terminal state, honestly.
    let event = match &result {
        Ok(_) => SubAttemptEvent::Complete,
        Err(TransportError::Clean(_)) => SubAttemptEvent::Fail,
        Err(TransportError::Uncertain(_)) => SubAttemptEvent::MarkAmbiguous,
    };
    let state = mark(store, &call.idempotency_key, event, now)?;
    match result {
        Ok(resp) => Ok(outcome_json(&call, state, Some(&resp))),
        Err(TransportError::Clean(d)) => {
            Err(problem_detail(502, "dispatch-failed", "the processor call failed", d))
        }
        Err(TransportError::Uncertain(d)) => Err(problem_detail(
            502,
            "dispatch-ambiguous",
            "the processor call outcome is uncertain",
            d,
        )),
    }
}

fn is_terminal(state: SubAttemptState) -> bool {
    matches!(
        state,
        SubAttemptState::Completed
            | SubAttemptState::Failed
            | SubAttemptState::Ambiguous
            | SubAttemptState::Cancelled
    )
}

/// Advances the sub-attempt under an already-held lock.
fn advance(
    store: &Store,
    key: &str,
    event: SubAttemptEvent,
    now: i64,
) -> Result<SubAttemptState, Problem> {
    store
        .advance_call(key, event, now)
        .map_err(store_problem)?
        .map_err(|_| internal())
}

/// Locks the store and advances the sub-attempt (the terminal transitions after
/// the network I/O).
fn mark(
    store: &Mutex<Store>,
    key: &str,
    event: SubAttemptEvent,
    now: i64,
) -> Result<SubAttemptState, Problem> {
    let store = store.lock().map_err(|_| internal())?;
    advance(&store, key, event, now)
}

/// Resolves `host:port` to the first address, or `None`.
async fn resolve(host: &str, port: u16) -> Option<IpAddr> {
    tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .next()
        .map(|sa| sa.ip())
}

fn outcome_json(
    call: &ProcessorCall,
    state: SubAttemptState,
    resp: Option<&CallResponse>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "idempotency_key": call.idempotency_key,
        "state": state.as_str(),
    });
    if let Some(r) = resp {
        v["status"] = serde_json::json!(r.status);
        v["response"] = serde_json::json!(String::from_utf8_lossy(&r.body));
    }
    v
}

fn store_problem(_e: axon_store::StoreError) -> Problem {
    internal()
}

fn internal() -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    }
}

fn problem_detail(status: u16, kind: &str, title: &str, e: impl std::fmt::Display) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: Some(e.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use axon_broker::{Origin, ProcessorConfig};
    use axon_store::{ExternalCheckpoint, Store};
    use std::sync::Mutex as StdMutex;

    const NOW: i64 = 1_800_000_000;

    fn store() -> StdMutex<Store> {
        let kek = axon_store::envelope::Kek::from_bytes([51u8; 32]);
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        StdMutex::new(Store::open_in_memory(&kek, cp).unwrap())
    }

    /// A local processor on 127.0.0.1 (so the resolved-address check needs the
    /// allow-local policy).
    fn processor(store: &StdMutex<Store>) -> (ProcessorConfig, EgressPolicy) {
        let config = ProcessorConfig {
            processor_id: "local-llm".to_owned(),
            provider: "local".to_owned(),
            origin: Origin::https("127.0.0.1", 8443),
            disclosure: axon_broker::Disclosure::remote("Local", "here"),
            config: serde_json::json!({"model": "m"}),
        };
        {
            let s = store.lock().unwrap();
            s.put_processor(&config, NOW).unwrap();
            s.put_credential("local-llm", b"secret-key", NOW).unwrap();
        }
        let policy = EgressPolicy::allowing([config.origin.clone()]).allow_local();
        (config, policy)
    }

    fn binding() -> CallBinding {
        CallBinding {
            work_order_id: "wo-1".to_owned(),
            work_order_digest: "aa".repeat(32),
            task_id: "task-1".to_owned(),
        }
    }

    fn budget() -> CallBudget {
        CallBudget {
            max_cost_microusd: 1000,
            deadline: "2030-01-01T00:00:00Z".to_owned(),
            max_response_bytes: 65536,
        }
    }

    /// What the transport was handed: (dialed address, credential, request).
    type SeenCall = Option<(IpAddr, Option<Vec<u8>>, Vec<u8>)>;

    /// A transport that records what it was handed and returns a canned response.
    struct MockTransport {
        response: Result<(u16, Vec<u8>), TransportError>,
        seen: StdMutex<SeenCall>,
    }
    impl MockTransport {
        fn ok(status: u16, body: &[u8]) -> Self {
            Self {
                response: Ok((status, body.to_vec())),
                seen: StdMutex::new(None),
            }
        }
    }
    impl CallTransport for MockTransport {
        async fn send(
            &self,
            _host: &str,
            _port: u16,
            addr: IpAddr,
            credential: Option<&[u8]>,
            request: &[u8],
            _max: u64,
        ) -> Result<CallResponse, TransportError> {
            *self.seen.lock().unwrap() =
                Some((addr, credential.map(<[u8]>::to_vec), request.to_vec()));
            match &self.response {
                Ok((status, body)) => Ok(CallResponse {
                    status: *status,
                    body: body.clone(),
                }),
                Err(TransportError::Clean(d)) => Err(TransportError::Clean(d.clone())),
                Err(TransportError::Uncertain(d)) => Err(TransportError::Uncertain(d.clone())),
            }
        }
    }

    #[tokio::test]
    async fn a_call_completes_and_injects_the_credential_at_a_checked_address() {
        let store = store();
        let (_config, policy) = processor(&store);
        let transport = MockTransport::ok(200, b"{\"answer\":42}");

        let out = dispatch_processor_call(
            &store,
            "local-llm",
            b"the prompt",
            binding(),
            budget(),
            &policy,
            &transport,
            NOW,
        )
        .await
        .unwrap();

        assert_eq!(out["state"], "completed");
        assert_eq!(out["status"], 200);
        assert_eq!(out["response"], "{\"answer\":42}");
        // The transport was handed the checked address, the sealed credential, and
        // the exact request.
        let (addr, credential, request) = transport.seen.lock().unwrap().clone().unwrap();
        assert_eq!(addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(credential.as_deref(), Some(&b"secret-key"[..]));
        assert_eq!(request, b"the prompt");
    }

    #[tokio::test]
    async fn a_non_allowlisted_origin_is_refused_before_any_record() {
        let store = store();
        let (_config, _policy) = processor(&store);
        // A policy that does NOT allow the processor's origin.
        let empty = EgressPolicy::default().allow_local();
        let transport = MockTransport::ok(200, b"x");
        let err = dispatch_processor_call(
            &store,
            "local-llm",
            b"p",
            binding(),
            budget(),
            &empty,
            &transport,
            NOW,
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, 403);
        assert!(transport.seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn a_resolved_inward_address_is_refused_without_the_local_opt_in() {
        let store = store();
        let (config, _policy) = processor(&store);
        // Allow the origin but NOT non-global addresses → 127.0.0.1 is refused at
        // the connection-time check, and nothing is sent.
        let policy = EgressPolicy::allowing([config.origin.clone()]);
        let transport = MockTransport::ok(200, b"x");
        let err = dispatch_processor_call(
            &store,
            "local-llm",
            b"p",
            binding(),
            budget(),
            &policy,
            &transport,
            NOW,
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, 403);
        assert!(transport.seen.lock().unwrap().is_none());
        // The sub-attempt failed cleanly (nothing was transmitted). Compute the key
        // BEFORE locking — std Mutex is not reentrant.
        let key = call_key(&store);
        assert_eq!(
            store.lock().unwrap().call_state(&key).unwrap().unwrap(),
            SubAttemptState::Failed
        );
    }

    #[tokio::test]
    async fn an_uncertain_transport_marks_the_call_ambiguous() {
        let store = store();
        let (_config, policy) = processor(&store);
        let transport = MockTransport {
            response: Err(TransportError::Uncertain("reset mid-response".to_owned())),
            seen: StdMutex::new(None),
        };
        let err = dispatch_processor_call(
            &store,
            "local-llm",
            b"p",
            binding(),
            budget(),
            &policy,
            &transport,
            NOW,
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, 502);
        let key = call_key(&store);
        assert_eq!(
            store.lock().unwrap().call_state(&key).unwrap().unwrap(),
            SubAttemptState::Ambiguous
        );
    }

    /// The single prepared call's idempotency key (there is exactly one per test).
    fn call_key(store: &StdMutex<Store>) -> String {
        let config = store.lock().unwrap().get_processor("local-llm").unwrap().unwrap();
        ProcessorCall::prepare(&config, b"p", binding(), budget())
            .unwrap()
            .idempotency_key
    }
}
