//! Servicing a confined worker's broker channel (design §13.1). The worker holds
//! one inherited `AF_UNIX` fd (see `akson_sandbox::broker_socketpair`); the daemon
//! holds the other end and answers processor-call requests on it while the worker
//! runs. The worker never reaches the network — the daemon makes the real call,
//! injecting the credential and enforcing the egress allowlist and the budget.
//!
//! Wire protocol: newline-delimited JSON, one request per line —
//! `{"processor_id":"<id>","request":"<prompt>"}` — answered by one JSON line, the
//! brokered result (or `{"error":{...}}`). The loop ends when the worker closes
//! its end.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use serde::Deserialize;

/// One processor-call request a confined worker writes on its broker fd.
#[derive(Debug, Deserialize)]
struct BrokerRequest {
    processor_id: String,
    /// The request body (a model prompt); carried as text.
    request: String,
}

/// Services the daemon end of a worker's broker channel until the worker closes
/// it. `dispatch(processor_id, request_bytes)` performs the actual gated,
/// credential-injected, budgeted call and returns the JSON result to relay back —
/// in the daemon it wraps `run_processor_call`; tests pass a stub. Malformed or
/// oversized lines are answered with an error object, never by acting.
pub(crate) fn serve_broker_channel<F>(stream: UnixStream, mut dispatch: F)
where
    F: FnMut(&str, &[u8]) -> serde_json::Value,
{
    // An independent handle for writing, so the read side can own the BufReader.
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    // Bound each request line so a stuck or hostile worker cannot make the daemon
    // buffer without limit.
    let reader = BufReader::new(stream);
    for line in reader.split(b'\n').take(1024) {
        let Ok(raw) = line else { break };
        if raw.is_empty() {
            continue;
        }
        if raw.len() > 1024 * 1024 {
            let _ = write_line(
                &mut writer,
                &serde_json::json!({"error": "request too large"}),
            );
            break;
        }
        let response = match serde_json::from_slice::<BrokerRequest>(&raw) {
            Ok(req) => dispatch(&req.processor_id, req.request.as_bytes()),
            Err(_) => serde_json::json!({"error": "malformed broker request"}),
        };
        if write_line(&mut writer, &response).is_err() {
            break;
        }
    }
}

fn write_line(writer: &mut UnixStream, value: &serde_json::Value) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes.push(b'\n');
    writer.write_all(&bytes)?;
    writer.flush()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use akson_sandbox::broker_socketpair;
    use std::io::Read;

    #[test]
    fn it_relays_a_request_to_the_dispatcher_and_answers() {
        let (worker, daemon) = broker_socketpair().unwrap();

        // The daemon services its end with a stub broker (no real model needed).
        let handle = std::thread::spawn(move || {
            serve_broker_channel(daemon, |processor_id, request| {
                serde_json::json!({
                    "status": 200,
                    "echo_processor": processor_id,
                    "echo_request": String::from_utf8_lossy(request),
                })
            });
        });

        // The worker writes a request line and reads the answer.
        let mut worker = UnixStream::from(worker);
        worker
            .write_all(b"{\"processor_id\":\"model-x\",\"request\":\"hello\"}\n")
            .unwrap();
        let mut buf = Vec::new();
        // Read one line back.
        let mut byte = [0u8; 1];
        loop {
            worker.read_exact(&mut byte).unwrap();
            if byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        let answer: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(answer["status"], 200);
        assert_eq!(answer["echo_processor"], "model-x");
        assert_eq!(answer["echo_request"], "hello");

        // Closing the worker end ends the loop.
        drop(worker);
        handle.join().unwrap();
    }

    #[test]
    fn a_malformed_line_is_answered_with_an_error_not_an_action() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let (worker, daemon) = broker_socketpair().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let called_in = Arc::clone(&called);

        let handle = std::thread::spawn(move || {
            serve_broker_channel(daemon, move |_, _| {
                called_in.store(true, Ordering::SeqCst);
                serde_json::json!({"status": 200})
            });
        });

        let mut worker = UnixStream::from(worker);
        worker.write_all(b"not json\n").unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            worker.read_exact(&mut byte).unwrap();
            if byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        let answer: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert!(answer.get("error").is_some(), "malformed → error object");

        drop(worker);
        handle.join().unwrap();
        assert!(
            !called.load(Ordering::SeqCst),
            "the dispatcher must not run for a malformed request"
        );
    }
}
