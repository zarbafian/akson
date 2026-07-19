//! End-to-end for the Gemini adapter (design §16.3): run the real adapter binary
//! against a staged input, with an inherited broker fd wired to a mock model, and
//! assert the whole path — read input → build a generateContent request → call the
//! model through the broker → extract the reply → write the response. No sandbox or
//! live model needed; runs in the normal suite.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::Command;

use axon_sandbox::broker_socketpair;
use sha2::{Digest, Sha256};

fn stage_input(dir: &std::path::Path, id: &str, bytes: &[u8]) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(id), bytes).unwrap();
    let manifest = serde_json::json!({
        "inputs": [{
            "id": id, "path": format!("/inputs/{id}"), "media_type": "text/x-diff",
            "byte_length": bytes.len(), "sha256": hex::encode(Sha256::digest(bytes)),
        }]
    });
    std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
}

#[test]
fn the_adapter_reviews_an_input_via_a_brokered_generate_call() {
    let tmp = std::env::temp_dir().join(format!("axon-gemini-it-{}", std::process::id()));
    let input_root = tmp.join("inputs");
    let output_root = tmp.join("output");
    std::fs::create_dir_all(&output_root).unwrap();
    stage_input(&input_root, "diff", b"--- a\n+++ b\n@@\n-x\n+y\n");

    let (worker_end, daemon_end) = broker_socketpair().unwrap();
    let mock = std::thread::spawn(move || mock_daemon(daemon_end));

    let status = Command::new(env!("CARGO_BIN_EXE_axon-adapter-gemini"))
        .args(["--processor", "gemini", "--max-tokens", "256"])
        .env("AXON_INPUT_ROOT", &input_root)
        .env("AXON_OUTPUT_ROOT", &output_root)
        .env("AXON_BROKER_FD", worker_end.as_raw_fd().to_string())
        .status()
        .expect("spawn adapter");
    drop(worker_end);
    let seen_request = mock.join().unwrap();

    assert!(status.success(), "adapter exited non-zero");

    // The request is a generateContent body: a user content part + a token cap, and
    // NO model (the model is bound by the processor path).
    assert_eq!(seen_request["processor_id"], "gemini");
    let body: serde_json::Value =
        serde_json::from_str(seen_request["request"].as_str().unwrap()).unwrap();
    assert_eq!(body["generationConfig"]["maxOutputTokens"], 256);
    assert!(body.get("model").is_none());
    assert!(body["contents"][0]["parts"][0]["text"]
        .as_str()
        .unwrap()
        .contains("+y"));

    // The response is exactly the model's text the mock returned.
    let response = std::fs::read(output_root.join("response")).unwrap();
    assert_eq!(response, b"Reviewed: one nit on line 1.");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn the_adapter_emits_validated_sarif_as_an_artifact() {
    let tmp = std::env::temp_dir().join(format!("axon-gemini-sarif-{}", std::process::id()));
    let input_root = tmp.join("inputs");
    let output_root = tmp.join("output");
    std::fs::create_dir_all(&output_root).unwrap();
    stage_input(&input_root, "diff", b"--- a\n+++ b\n@@\n-x\n+y\n");

    let sarif = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"reviewer"}},"results":[{"message":{"text":"nit on line 1"}}]}]}"#;
    let (worker_end, daemon_end) = broker_socketpair().unwrap();
    let sarif_owned = sarif.to_owned();
    let mock = std::thread::spawn(move || mock_daemon_returning(daemon_end, &sarif_owned));

    let status = Command::new(env!("CARGO_BIN_EXE_axon-adapter-gemini"))
        .args(["--processor", "gemini", "--sarif"])
        .env("AXON_INPUT_ROOT", &input_root)
        .env("AXON_OUTPUT_ROOT", &output_root)
        .env("AXON_BROKER_FD", worker_end.as_raw_fd().to_string())
        .status()
        .expect("spawn adapter");
    drop(worker_end);
    mock.join().unwrap();
    assert!(status.success());

    let artifact = std::fs::read(output_root.join("artifacts").join("findings")).unwrap();
    assert_eq!(artifact, sarif.as_bytes());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output_root.join("artifacts.json")).unwrap())
            .unwrap();
    assert_eq!(manifest[0]["role"], "findings");
    assert_eq!(manifest[0]["media_type"], "application/sarif+json");
    let response = std::fs::read_to_string(output_root.join("response")).unwrap();
    assert!(response.contains("1 finding"), "response: {response}");

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Reads one broker request and answers with a canned Gemini generateContent reply
/// whose candidate text is "Reviewed: one nit on line 1.", returning the request.
fn mock_daemon(stream: UnixStream) -> serde_json::Value {
    mock_daemon_returning(stream, "Reviewed: one nit on line 1.")
}

/// As `mock_daemon`, but the candidate's text is `text`.
fn mock_daemon_returning(stream: UnixStream, text: &str) -> serde_json::Value {
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

    let message = serde_json::json!({
        "candidates": [{ "content": { "parts": [{ "text": text }], "role": "model" } }]
    })
    .to_string();
    let reply = serde_json::json!({ "state": "completed", "status": 200, "response": message });
    writer.write_all(format!("{reply}\n").as_bytes()).unwrap();
    writer.flush().unwrap();
    request
}
