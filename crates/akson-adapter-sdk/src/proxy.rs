//! A loopback OpenAI-compatible proxy for agent-tool workers (design
//! 2026-07-19-agent-harness).
//!
//! A confined *agent CLI* (Codex, herdr, …) cannot speak the broker-fd protocol the
//! other adapters use — it opens its own HTTP connection to a model. This proxy *is*
//! that model, from the agent's view: it listens on `127.0.0.1`, and forwards every
//! request over the inherited broker fd to the daemon, which makes the real,
//! credential-injected, budgeted, egress-checked call. Point the agent at
//! `http://127.0.0.1:<port>/v1` with any dummy key — the real credential is injected
//! daemon-side and never enters the sandbox.
//!
//! The network seal is preserved at the namespace layer: the worker runs in a net
//! namespace with loopback only and no external route, so the sole thing it can reach
//! is this proxy. The proxy forwards to exactly one processor; it selects no
//! recipient and reaches no other host.
//!
//! What you write (in an agent adapter's `main`):
//! ```no_run
//! # use std::sync::Arc;
//! # use akson_adapter_sdk::proxy::LoopbackProxy;
//! # fn go(broker: std::os::unix::net::UnixStream) -> std::io::Result<()> {
//! let proxy = Arc::new(LoopbackProxy::bind(broker, "reviewer")?);
//! let port = proxy.local_addr()?.port();
//! let serving = proxy.clone();
//! std::thread::spawn(move || serving.serve());     // serve for the agent's lifetime
//! // …spawn the agent CLI pointed at http://127.0.0.1:{port}/v1 …
//! # Ok(()) }
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

/// A loopback HTTP proxy that bridges an agent CLI to the broker fd.
pub struct LoopbackProxy {
    listener: TcpListener,
    processor: String,
    broker: Mutex<BrokerConn>,
}

/// The single serialized broker connection (one request/reply at a time).
struct BrokerConn {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl LoopbackProxy {
    /// Binds the proxy on `127.0.0.1:0`, forwarding every model call to `processor`
    /// over `broker` (the inherited broker fd, an already-connected AF_UNIX stream).
    pub fn bind(broker: UnixStream, processor: &str) -> std::io::Result<Self> {
        let reader = BufReader::new(broker.try_clone()?);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        Ok(Self {
            listener,
            processor: processor.to_owned(),
            broker: Mutex::new(BrokerConn {
                writer: broker,
                reader,
            }),
        })
    }

    /// The bound loopback address; point the agent at `http://127.0.0.1:<port>/v1`.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serves connections until the listener closes. One thread per connection (agent
    /// runtimes keep a connection pool); the broker call itself is serialized by the
    /// mutex, matching the single broker fd.
    pub fn serve(self: Arc<Self>) {
        for conn in self.listener.incoming() {
            let Ok(stream) = conn else { break };
            let me = Arc::clone(&self);
            std::thread::spawn(move || {
                let _ = me.handle(stream);
            });
        }
    }

    fn handle(&self, mut stream: TcpStream) -> std::io::Result<()> {
        let (path, body) = read_http_request(&mut stream)?;
        let response = if path.contains("/chat/completions") {
            match self.forward(&body) {
                Ok((status, body)) => http_response(status, &body),
                Err(msg) => http_response(502, error_json(&msg).as_bytes()),
            }
        } else if path.ends_with("/models") {
            // Agent runtimes may probe the model list on startup; answer emptily.
            http_response(200, br#"{"object":"list","data":[]}"#)
        } else {
            http_response(404, error_json("no such endpoint").as_bytes())
        };
        stream.write_all(&response)?;
        stream.flush()
    }

    /// Forwards one OpenAI request body over the broker and returns (status, body).
    fn forward(&self, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        let request = String::from_utf8_lossy(body).into_owned();
        let line = serde_json::to_string(&serde_json::json!({
            "processor_id": self.processor,
            "request": request,
        }))
        .map_err(|e| e.to_string())?;

        let mut b = self
            .broker
            .lock()
            .map_err(|_| "proxy broker poisoned".to_owned())?;
        b.writer
            .write_all(line.as_bytes())
            .map_err(|e| e.to_string())?;
        b.writer.write_all(b"\n").map_err(|e| e.to_string())?;
        b.writer.flush().map_err(|e| e.to_string())?;

        let mut reply = String::new();
        if b.reader.read_line(&mut reply).map_err(|e| e.to_string())? == 0 {
            return Err("the broker channel closed".to_owned());
        }
        let v: serde_json::Value = serde_json::from_str(reply.trim()).map_err(|e| e.to_string())?;
        if let Some(err) = v.get("error") {
            return Err(format!("the broker refused the call: {err}"));
        }
        let status = v
            .get("status")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(200) as u16;
        let response = v
            .get("response")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .as_bytes()
            .to_vec();
        Ok((status, response))
    }
}

/// Caps so a malformed request can't exhaust the confined worker's memory: the
/// request line + headers, and the declared body (a chat-completions request is
/// small — well under a few MiB).
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Reads an HTTP/1.1 request from `stream`, returning (path, body). The body length
/// is taken from `Content-Length` (agent clients always send it for a POST). Bounded:
/// oversized headers or a `Content-Length` beyond [`MAX_BODY_BYTES`] are refused
/// BEFORE any allocation, so one crafted request cannot OOM the proxy.
fn read_http_request(stream: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let too_large = |what| std::io::Error::new(std::io::ErrorKind::InvalidData, what);
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();

    let mut content_length = 0usize;
    let mut header_bytes = request_line.len();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        header_bytes += n;
        if header_bytes > MAX_HEADER_BYTES {
            return Err(too_large("request headers too large"));
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err(too_large("request body too large"));
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    Ok((path, body))
}

/// Builds an HTTP/1.1 `application/json` response with `Connection: close`.
fn http_response(status: u16, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn error_json(message: &str) -> String {
    serde_json::json!({ "error": { "message": message } }).to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A stand-in daemon end: reads one broker request, answers with a canned
    /// OpenAI chat-completion whose content is `content`, returns the request seen.
    fn mock_daemon(stream: UnixStream, content: &str) -> serde_json::Value {
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let completion =
            serde_json::json!({ "choices": [{ "message": { "role": "assistant", "content": content } }] })
                .to_string();
        let reply =
            serde_json::json!({ "state": "completed", "status": 200, "response": completion });
        writer.write_all(format!("{reply}\n").as_bytes()).unwrap();
        writer.flush().unwrap();
        request
    }

    #[test]
    fn forwards_a_chat_completion_over_the_broker() {
        let (worker_end, daemon_end) = UnixStream::pair().unwrap();
        let mock = std::thread::spawn(move || mock_daemon(daemon_end, "CONFINED: LGTM"));

        let proxy = Arc::new(LoopbackProxy::bind(worker_end, "reviewer").unwrap());
        let addr = proxy.local_addr().unwrap();
        let serving = Arc::clone(&proxy);
        std::thread::spawn(move || serving.serve());

        // An agent's OpenAI request to the loopback proxy.
        let body = br#"{"model":"m","messages":[{"role":"user","content":"review"}]}"#;
        let mut c = TcpStream::connect(addr).unwrap();
        let req = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        c.write_all(req.as_bytes()).unwrap();
        c.write_all(body).unwrap();
        c.flush().unwrap();
        let mut raw = Vec::new();
        c.read_to_end(&mut raw).unwrap();

        // The daemon saw our request body, addressed to the granted processor.
        let seen = mock.join().unwrap();
        assert_eq!(seen["processor_id"], "reviewer");
        let fwd: serde_json::Value =
            serde_json::from_str(seen["request"].as_str().unwrap()).unwrap();
        assert_eq!(fwd["messages"][0]["content"], "review");

        // The proxy returned the model's completion verbatim as the HTTP body.
        let text = String::from_utf8_lossy(&raw);
        let (_head, body) = text.split_once("\r\n\r\n").unwrap();
        let completion: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(
            completion["choices"][0]["message"]["content"],
            "CONFINED: LGTM"
        );
        assert!(text.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn an_oversized_content_length_is_refused_without_allocating() {
        let (worker_end, _daemon_end) = UnixStream::pair().unwrap();
        let proxy = Arc::new(LoopbackProxy::bind(worker_end, "reviewer").unwrap());
        let addr = proxy.local_addr().unwrap();
        let serving = Arc::clone(&proxy);
        std::thread::spawn(move || serving.serve());

        // A crafted 100 GB Content-Length with no body: must be refused before the
        // proxy tries to `vec![0u8; 100GB]` (which would OOM the confined worker).
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 100000000000\r\n\r\n",
        )
        .unwrap();
        c.flush().unwrap();
        let mut raw = String::new();
        c.read_to_string(&mut raw).unwrap();
        // The connection is closed without a 200 (no gigabyte allocation happened).
        assert!(
            !raw.starts_with("HTTP/1.1 200"),
            "oversized body must be refused"
        );
    }

    #[test]
    fn a_models_probe_gets_an_empty_list() {
        let (worker_end, _daemon_end) = UnixStream::pair().unwrap();
        let proxy = Arc::new(LoopbackProxy::bind(worker_end, "reviewer").unwrap());
        let addr = proxy.local_addr().unwrap();
        let serving = Arc::clone(&proxy);
        std::thread::spawn(move || serving.serve());

        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"GET /v1/models HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        c.flush().unwrap();
        let mut raw = String::new();
        c.read_to_string(&mut raw).unwrap();
        assert!(raw.starts_with("HTTP/1.1 200"));
        assert!(raw.contains(r#""data":[]"#));
    }
}
