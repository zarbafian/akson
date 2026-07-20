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

use std::io::{BufReader, Read, Write};
use std::os::unix::net::UnixStream;

use serde::Deserialize;

/// The largest single broker request the daemon will buffer. A request is a
/// short JSON line (a processor id + a prompt); a megabyte is generous headroom.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// The most requests one worker may make over its channel before the daemon
/// stops reading (matches the previous `.take(1024)`).
const MAX_REQUESTS: usize = 1024;

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
    // Bound each request line *as it is read*, not after. `BufRead::split` would
    // buffer an entire newline-free line first, so a worker writing 200 MiB with
    // no `\n` could grow the daemon's memory without limit before any size check
    // fired (codex review). `read_capped_line` stops at the cap instead.
    let mut reader = BufReader::new(stream);
    for _ in 0..MAX_REQUESTS {
        let raw = match read_capped_line(&mut reader, MAX_REQUEST_BYTES) {
            LineRead::Line(bytes) => bytes,
            LineRead::Eof => break,
            LineRead::TooLarge => {
                let _ = write_line(
                    &mut writer,
                    &serde_json::json!({"error": "request too large"}),
                );
                break;
            }
            LineRead::Err => break,
        };
        if raw.is_empty() {
            continue;
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

/// The outcome of reading one `\n`-terminated request, size-capped.
enum LineRead {
    /// A complete line (without the trailing `\n`), at most `cap` bytes.
    Line(Vec<u8>),
    /// The stream ended cleanly at a request boundary.
    Eof,
    /// The line exceeded the cap before a `\n` arrived — refuse without buffering
    /// the rest.
    TooLarge,
    /// A read error.
    Err,
}

/// Reads bytes up to the next `\n`, accumulating at most `cap` bytes. Unlike
/// `BufRead::read_until` / `split`, it never grows its buffer past `cap`: once
/// `cap` bytes have arrived with no newline, it reports `TooLarge` immediately.
fn read_capped_line(reader: &mut impl Read, cap: usize) -> LineRead {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return LineRead::Eof,
            Ok(_) => {
                if byte[0] == b'\n' {
                    return LineRead::Line(buf);
                }
                if buf.len() >= cap {
                    return LineRead::TooLarge;
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return LineRead::Err,
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

    #[test]
    fn read_capped_line_stops_at_the_cap_without_a_newline() {
        // A newline-free stream longer than the cap must not be buffered whole —
        // it reports TooLarge as soon as the cap is reached (codex review: the old
        // BufRead::split buffered the entire line before any size check).
        let big = vec![b'x'; 100_000];
        let mut cursor = std::io::Cursor::new(big);
        match read_capped_line(&mut cursor, 1024) {
            LineRead::TooLarge => {}
            other => panic!(
                "expected TooLarge, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn read_capped_line_returns_a_short_line_and_then_eof() {
        let mut cursor = std::io::Cursor::new(b"hello\n".to_vec());
        match read_capped_line(&mut cursor, 1024) {
            LineRead::Line(b) => assert_eq!(b, b"hello"),
            _ => panic!("expected a line"),
        }
        assert!(matches!(read_capped_line(&mut cursor, 1024), LineRead::Eof));
    }

    #[test]
    fn an_oversized_request_is_refused_and_the_dispatcher_never_runs() {
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

        // Two megabytes with no newline — over the 1 MiB cap.
        let mut worker = UnixStream::from(worker);
        let _ = worker.write_all(&vec![b'x'; 2 * 1024 * 1024]);
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while worker.read_exact(&mut byte).is_ok() {
            if byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        let answer: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert!(
            answer.get("error").is_some(),
            "oversized → error, not action"
        );
        drop(worker);
        handle.join().unwrap();
        assert!(
            !called.load(Ordering::SeqCst),
            "the dispatcher must never run for an oversized request"
        );
    }
}
