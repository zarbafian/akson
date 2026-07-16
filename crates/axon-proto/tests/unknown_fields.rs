//! ADR-0010 / design §18: standard A2A objects preserve non-critical unknown
//! fields (the typed view ignores them), while unknown values of a
//! safety-critical enum still fail closed.

#![allow(clippy::unwrap_used, clippy::panic)]

use axon_proto::v1::{AgentCard, Role, TaskState};

#[test]
fn unknown_standard_field_is_ignored_not_rejected() {
    // A card from a hypothetical newer A2A minor carries a field we do not
    // know. It must still parse (the unknown field is ignored), not hard-fail.
    let json = r#"{
        "name": "Recipe Agent",
        "description": "d",
        "version": "1.0.0",
        "supportedInterfaces": [
            {"url": "https://a.example/a2a",
             "protocolBinding": "HTTP+JSON",
             "protocolVersion": "1.0"}
        ],
        "capabilities": {"streaming": false, "pushNotifications": false},
        "futureFieldFromANewerMinor": {"anything": true}
    }"#;
    let card: AgentCard = serde_json::from_str(json).unwrap();
    assert_eq!(card.name, "Recipe Agent");
}

#[test]
fn unknown_enum_value_still_fails_closed() {
    // Known variants parse.
    assert!(serde_json::from_str::<Role>("\"ROLE_USER\"").is_ok());
    assert!(serde_json::from_str::<TaskState>("\"TASK_STATE_SUBMITTED\"").is_ok());
    // An unknown safety-critical enum value is rejected (we deliberately do
    // NOT enable ignore_unknown_enum_variants).
    assert!(serde_json::from_str::<Role>("\"ROLE_SUPERUSER\"").is_err());
    assert!(serde_json::from_str::<TaskState>("\"TASK_STATE_GODMODE\"").is_err());
}
