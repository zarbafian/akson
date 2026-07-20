//! Drives the A2A v1 profile conformance vectors under `spec/a2a/vectors/`.
//! Each vector carries a standard A2A JSON object and the expected verdict;
//! invalid cases also pin a substring of the violation message so the right
//! rule fired.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use akson_proto::profile::{self, ProfileConfig, ProfileError};
use serde_json::Value;

fn check(name: &str, result: Result<(), ProfileError>, expected: &Value) {
    let valid = expected["valid"].as_bool().unwrap();
    match result {
        Ok(()) => assert!(valid, "{name}: expected violations, got none"),
        Err(err) => {
            assert!(!valid, "{name}: expected valid, got {err}");
            if let Some(substr) = expected["violation"].as_str() {
                assert!(
                    err.to_string().contains(substr),
                    "{name}: violation {err:?} does not mention {substr:?}"
                );
            }
        }
    }
}

fn to_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn profile_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/a2a/vectors");
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("missing {dir:?}: {e}")) {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        count += 1;
        let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap().to_owned();
        let input = &case["input"];
        let expected = &case["expected"];

        match case["kind"].as_str().unwrap() {
            "message" => {
                let message: akson_proto::v1::Message =
                    serde_json::from_value(input["message"].clone()).unwrap();
                check(&name, profile::validate_message(&message), expected);
            }
            "send-request" => {
                let request: akson_proto::v1::SendMessageRequest =
                    serde_json::from_value(input["request"].clone()).unwrap();
                check(
                    &name,
                    profile::validate_send_message_request(&request),
                    expected,
                );
            }
            "agent-card" => {
                let card: akson_proto::v1::AgentCard =
                    serde_json::from_value(input["card"].clone()).unwrap();
                let config = ProfileConfig::new(to_set(&input["required_extensions"])).unwrap();
                check(
                    &name,
                    profile::validate_agent_card(&card, &config),
                    expected,
                );
            }
            "task" => {
                let task: akson_proto::v1::Task =
                    serde_json::from_value(input["task"].clone()).unwrap();
                let state = task.status.as_ref().unwrap().state;
                check(&name, profile::validate_task_state(state), expected);
            }
            "negotiation" => {
                let result = profile::negotiate_extensions(
                    &to_set(&input["supported"]),
                    &to_set(&input["required"]),
                    &to_set(&input["activated"]),
                );
                if expected["valid"].as_bool().unwrap() {
                    let echo = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                    assert_eq!(echo, to_set(&input["activated"]), "{name}: echo differs");
                } else {
                    check(&name, result.map(|_| ()), expected);
                }
            }
            other => panic!("{name}: unknown vector kind {other:?}"),
        }
    }
    assert!(count >= 25, "expected the full vector set, found {count}");
}
