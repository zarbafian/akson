//! The A2A HTTP+JSON binding is the standard proto3 JSON mapping of the
//! vendored definitions. These tests pin the mapping behavior Axon relies
//! on: camelCase field names, enum name strings, flattened Part oneof,
//! unknown-field rejection, and lossless round trips.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axon_proto::v1::{Message, Part, Role, Task, TaskState};

#[test]
fn message_parses_from_a2a_json() {
    let json = r#"{
        "messageId": "msg-0001",
        "contextId": "ctx-0001",
        "role": "ROLE_USER",
        "parts": [
            {"text": "review this patch", "mediaType": "text/plain"},
            {"data": {"max_findings": 10}, "mediaType": "application/json"}
        ],
        "extensions": ["https://axon.invalid/ext/contract/v1"],
        "referenceTaskIds": ["task-0000"]
    }"#;
    let message: Message = serde_json::from_str(json).unwrap();
    assert_eq!(message.message_id, "msg-0001");
    assert_eq!(message.role, Role::User as i32);
    assert_eq!(message.parts.len(), 2);
    assert_eq!(message.extensions, ["https://axon.invalid/ext/contract/v1"]);
    assert_eq!(message.reference_task_ids, ["task-0000"]);

    let Some(axon_proto::v1::part::Content::Text(text)) = &message.parts[0].content else {
        panic!("first part must be text");
    };
    assert_eq!(text, "review this patch");
    assert_eq!(message.parts[0].media_type, "text/plain");
    assert!(matches!(
        message.parts[1].content,
        Some(axon_proto::v1::part::Content::Data(_))
    ));
}

#[test]
fn message_round_trips_losslessly() {
    let json = r#"{
        "messageId": "msg-0002",
        "role": "ROLE_AGENT",
        "parts": [{"text": "done", "mediaType": "text/plain"}]
    }"#;
    let message: Message = serde_json::from_str(json).unwrap();
    let reserialized = serde_json::to_string(&message).unwrap();
    let reparsed: Message = serde_json::from_str(&reserialized).unwrap();
    assert_eq!(message, reparsed);
}

#[test]
fn task_states_map_to_standard_names() {
    let cases = [
        (TaskState::Submitted, "TASK_STATE_SUBMITTED"),
        (TaskState::Working, "TASK_STATE_WORKING"),
        (TaskState::Completed, "TASK_STATE_COMPLETED"),
        (TaskState::Failed, "TASK_STATE_FAILED"),
        (TaskState::Canceled, "TASK_STATE_CANCELED"),
        (TaskState::InputRequired, "TASK_STATE_INPUT_REQUIRED"),
        (TaskState::Rejected, "TASK_STATE_REJECTED"),
        (TaskState::AuthRequired, "TASK_STATE_AUTH_REQUIRED"),
    ];
    for (state, name) in cases {
        let json = format!(
            r#"{{"id": "task-1", "status": {{"state": "{name}", "timestamp": "2026-07-16T12:00:00Z"}}}}"#
        );
        let task: Task = serde_json::from_str(&json).unwrap();
        assert_eq!(task.status.as_ref().unwrap().state, state as i32, "{name}");
        let out = serde_json::to_string(&task).unwrap();
        assert!(out.contains(name), "{name} not preserved in {out}");
    }
}

#[test]
fn unknown_standard_fields_are_ignored() {
    // Design §18 / ADR-0010: a non-critical unknown field on a *standard* A2A
    // object is preserved (ignored by the typed view), not rejected — so a
    // benign field from a newer A2A minor does not hard-fail. Axon extension
    // objects, by contrast, keep reject-unknown via their JSON Schemas.
    let json = r#"{"messageId": "msg-1", "role": "ROLE_USER", "parts": [], "bogus": true}"#;
    let msg: Message = serde_json::from_str(json).unwrap();
    assert_eq!(msg.message_id, "msg-1");
}

#[test]
fn unknown_enum_values_are_rejected() {
    let json = r#"{"id": "task-1", "status": {"state": "TASK_STATE_DONE"}}"#;
    assert!(serde_json::from_str::<Task>(json).is_err());
}

#[test]
fn part_oneof_is_flattened_in_json() {
    let part = Part {
        content: Some(axon_proto::v1::part::Content::Text("hi".to_owned())),
        media_type: "text/plain".to_owned(),
        ..Default::default()
    };
    let json: serde_json::Value = serde_json::to_value(&part).unwrap();
    assert_eq!(json["text"], "hi");
    assert_eq!(json["mediaType"], "text/plain");
    assert!(json.get("content").is_none(), "oneof must flatten: {json}");
}

#[test]
fn agent_card_parses_with_v1_profile_shape() {
    // The v1 profile advertises HTTP+JSON at protocol 1.0 on an
    // AgentInterface, disabled streaming/push, and extended-card support
    // (design §10.1, §8.2).
    let json = r#"{
        "name": "reviewer",
        "description": "Axon endpoint",
        "version": "0.0.1",
        "supportedInterfaces": [
            {"url": "https://reviewer.example:7300/a2a", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}
        ],
        "capabilities": {"streaming": false, "pushNotifications": false, "extensions": [], "extendedAgentCard": true},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": []
    }"#;
    let card: axon_proto::v1::AgentCard = serde_json::from_str(json).unwrap();
    assert_eq!(
        card.supported_interfaces[0].protocol_version,
        axon_proto::A2A_VERSION
    );
    assert_eq!(card.supported_interfaces[0].protocol_binding, "HTTP+JSON");
    let caps = card.capabilities.unwrap();
    assert_eq!(caps.streaming, Some(false));
    assert_eq!(caps.push_notifications, Some(false));
    assert_eq!(caps.extended_agent_card, Some(true));
}
