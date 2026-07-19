//! End-to-end for the OpenAI adapter (design §16.3): run the real adapter binary
//! against a staged input, with an inherited broker fd wired to a mock model, and
//! assert the whole path — read input → build a chat-completions request → call the
//! model through the broker → extract the reply → write the response.
//!
//! This exercises the adapter's real fd broker protocol without a sandbox or a live
//! model (the confinement itself is covered by the sandbox's own §13.1 checklist and
//! the daemon worker-run e2e). It runs in the normal suite.

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
            "id": id,
            "path": format!("/inputs/{id}"),
            "media_type": "text/x-diff",
            "byte_length": bytes.len(),
            "sha256": hex::encode(Sha256::digest(bytes)),
        }]
    });
    std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
}

#[test]
fn the_adapter_reviews_an_input_via_a_brokered_model_call() {
    let tmp = std::env::temp_dir().join(format!("axon-openai-it-{}", std::process::id()));
    let input_root = tmp.join("inputs");
    let output_root = tmp.join("output");
    std::fs::create_dir_all(&output_root).unwrap();
    stage_input(&input_root, "diff", b"--- a\n+++ b\n@@\n-x\n+y\n");

    // The broker fd: the adapter inherits the worker end; the mock daemon services
    // the other end, standing in for the gateway + a model.
    let (worker_end, daemon_end) = broker_socketpair().unwrap();
    let mock = std::thread::spawn(move || mock_daemon(daemon_end));

    let status = Command::new(env!("CARGO_BIN_EXE_axon-adapter-openai"))
        .args(["--processor", "reviewer", "--model", "test-model"])
        .env("AXON_INPUT_ROOT", &input_root)
        .env("AXON_OUTPUT_ROOT", &output_root)
        .env("AXON_BROKER_FD", worker_end.as_raw_fd().to_string())
        .status()
        .expect("spawn adapter");
    // The daemon end still open in this process would keep the mock from seeing EOF;
    // the adapter made exactly one call and exited, so close our copy now.
    drop(worker_end);
    let seen_request = mock.join().unwrap();

    assert!(status.success(), "adapter exited non-zero");

    // The adapter asked the granted processor, with an OpenAI chat-completions body
    // carrying the model and the review prompt (which includes the diff).
    assert_eq!(seen_request["processor_id"], "reviewer");
    let body: serde_json::Value =
        serde_json::from_str(seen_request["request"].as_str().unwrap()).unwrap();
    assert_eq!(body["model"], "test-model");
    let prompt = body["messages"][0]["content"].as_str().unwrap();
    assert!(prompt.contains("+y"), "the prompt should include the diff");

    // The response is exactly the assistant's text the mock returned.
    let response = std::fs::read(output_root.join("response")).unwrap();
    assert_eq!(response, b"Looks good; one nit on line 1.");

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Reads one broker request and answers with a canned OpenAI chat-completion,
/// returning the request it saw.
fn mock_daemon(stream: UnixStream) -> serde_json::Value {
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

    let completion = serde_json::json!({
        "choices": [{ "message": { "role": "assistant", "content": "Looks good; one nit on line 1." } }]
    })
    .to_string();
    let reply = serde_json::json!({
        "state": "completed",
        "status": 200,
        "response": completion,
    });
    writer
        .write_all(format!("{reply}\n").as_bytes())
        .unwrap();
    writer.flush().unwrap();
    request
}
