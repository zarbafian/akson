//! Peer-identity assembly from verified introduction material (design §8.1,
//! ADR-0015): [`peer_identity_from`] turns a verified key-binding set plus the
//! signed extended Agent Card into the durable §8.1 identity tuple — endpoint
//! URL, pinned TLS certificate, purpose-bound key thumbprints, and the
//! security-projection / full-card digests the §8.4 change detector watches.

use akson_crypto::identity::{Fingerprint, FingerprintKind, KeyBinding, PeerIdentity};
use akson_crypto::purpose::KeyPurpose;
use akson_proto::v1::AgentCard;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::key_binding::KeyBindingSet;

/// SHA-256 (hex) over the RFC 8785 canonical key-binding record — the digest
/// both sides put in the transcript.
pub fn key_binding_digest_hex(key_binding_json: &Value) -> String {
    let canonical = json_canon::to_vec(key_binding_json).unwrap_or_default();
    hex::encode(Sha256::digest(canonical))
}

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("serialization: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("key binding advertises an unknown purpose: {0}")]
    UnknownPurpose(String),
}

/// The §8.1 identity tuple from verified bindings + the signed card
/// (ADR-0015 step 5 — what the introduction pins).
pub fn peer_identity_from(
    bindings: &KeyBindingSet,
    extended_card: &AgentCard,
) -> Result<PeerIdentity, PeerError> {
    let card_value = serde_json::to_value(extended_card)?;
    let key_binding_value = serde_json::to_value(bindings)?;

    let endpoint_id = card_value
        .get("supportedInterfaces")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|i| i.get("url"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let jwk_fp = |thumbprint: &str| Fingerprint {
        kind: FingerprintKind::Jwk7638,
        value: thumbprint.to_owned(),
    };

    let mut key_bindings = Vec::with_capacity(bindings.keys.len());
    for (purpose_str, entry) in &bindings.keys {
        let purpose: KeyPurpose = serde_json::from_value(Value::String(purpose_str.clone()))
            .map_err(|_| PeerError::UnknownPurpose(purpose_str.clone()))?;
        key_bindings.push(KeyBinding {
            purpose,
            thumbprint: jwk_fp(&entry.thumbprint),
        });
    }

    let agent_card_key = bindings
        .keys
        .get("agent-card")
        .map(|e| jwk_fp(&e.thumbprint))
        .unwrap_or_else(|| jwk_fp(""));

    let projection = security_projection(&card_value, &key_binding_value);
    let security_projection_digest =
        Fingerprint::json_sha256(&json_canon::to_vec(&projection).unwrap_or_default());

    let mut full_card = card_value;
    if let Some(obj) = full_card.as_object_mut() {
        obj.remove("signatures");
    }
    let full_card_digest =
        Fingerprint::json_sha256(&json_canon::to_vec(&full_card).unwrap_or_default());

    Ok(PeerIdentity {
        issuer: Some(bindings.subject.issuer.clone()),
        agent_id: bindings.subject.agent.clone(),
        workload_id: None,
        endpoint_id,
        tls_cert: Fingerprint {
            kind: FingerprintKind::CertSha256,
            value: bindings.tls_certificate_sha256.clone(),
        },
        agent_card_key,
        key_bindings,
        security_projection_digest,
        full_card_digest,
    })
}

/// The security projection (design §8.1/§8.4): the stable fields policy pins,
/// excluding cosmetic ones. `required_extensions` lists only the required
/// extension URIs, sorted.
fn security_projection(card_value: &Value, key_binding: &Value) -> Value {
    let required_extensions: Vec<Value> = card_value
        .get("capabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(Value::as_array)
        .map(|arr| {
            let mut uris: Vec<String> = arr
                .iter()
                .filter(|e| e.get("required").and_then(Value::as_bool).unwrap_or(false))
                .filter_map(|e| e.get("uri").and_then(Value::as_str).map(str::to_owned))
                .collect();
            uris.sort();
            uris.into_iter().map(Value::String).collect()
        })
        .unwrap_or_default();

    let field = |name: &str| card_value.get(name).cloned().unwrap_or(Value::Null);
    json!({
        "supportedInterfaces": field("supportedInterfaces"),
        "securityRequirements": field("securityRequirements"),
        "securitySchemes": field("securitySchemes"),
        "requiredExtensions": Value::Array(required_extensions),
        "keyBinding": key_binding,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use akson_crypto::jwk::Ed25519PublicJwk;
    use ed25519_dalek::SigningKey;
    use time::OffsetDateTime;
    
    const TLS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_748_736_000).unwrap()
    }

    fn card() -> AgentCard {
        serde_json::from_str(
            r#"{
            "name": "Peer",
            "description": "d",
            "version": "1.0.0",
            "supportedInterfaces": [
                {"url": "https://peer.example/a2a",
                 "protocolBinding": "HTTP+JSON",
                 "protocolVersion": "1.0"}
            ],
            "capabilities": {"streaming": false, "pushNotifications": false}
        }"#,
        )
        .unwrap()
    }

    fn bindings() -> KeyBindingSet {
        let card_key = SigningKey::from_bytes(&[10u8; 32]);
        let task_key = SigningKey::from_bytes(&[11u8; 32]);
        let card_jwk = Ed25519PublicJwk::from_key(&card_key.verifying_key());
        let task_jwk = Ed25519PublicJwk::from_key(&task_key.verifying_key());
        let record = serde_json::json!({
            "schema_version": 1,
            "subject": { "issuer": "local", "agent": "peer" },
            "tls_certificate_sha256": TLS,
            "keys": {
                "agent-card": { "jwk": card_jwk, "thumbprint": card_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" },
                "task-result": { "jwk": task_jwk, "thumbprint": task_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" }
            }
        });
        crate::key_binding::verify(&record, now()).unwrap()
    }

    #[test]
    fn peer_identity_captures_endpoint_and_keys() {
        let peer = peer_identity_from(&bindings(), &card()).unwrap();
        assert_eq!(peer.agent_id, "peer");
        assert_eq!(peer.issuer.as_deref(), Some("local"));
        assert_eq!(peer.endpoint_id, "https://peer.example/a2a");
        assert_eq!(peer.tls_cert.value, TLS);
        assert!(peer.binding(KeyPurpose::AgentCard).is_some());
        assert!(peer.binding(KeyPurpose::TaskResult).is_some());
    }

    #[test]
    fn cosmetic_card_change_does_not_move_the_projection() {
        let set = bindings();
        let card1 = card();
        let peer1 = peer_identity_from(&set, &card1).unwrap();

        // Only the description changes (cosmetic) — projection stable, full
        // digest moves (design §8.4).
        let mut card2 = card1.clone();
        card2.description = "an entirely rewritten description".to_owned();
        let peer2 = peer_identity_from(&set, &card2).unwrap();

        assert!(
            peer1
                .security_projection_digest
                .matches(&peer2.security_projection_digest),
            "a cosmetic change must not move the security projection (§8.4)"
        );
        assert!(
            !peer1.full_card_digest.matches(&peer2.full_card_digest),
            "the full-card digest tracks every change"
        );
    }

    #[test]
    fn key_binding_digest_is_canonical_and_content_sensitive() {
        let a = serde_json::json!({"b": 1, "a": 2});
        let b = serde_json::json!({"a": 2, "b": 1});
        // Key order does not matter (RFC 8785)...
        assert_eq!(key_binding_digest_hex(&a), key_binding_digest_hex(&b));
        // ...content does.
        let c = serde_json::json!({"a": 2, "b": 3});
        assert_ne!(key_binding_digest_hex(&a), key_binding_digest_hex(&c));
    }
}
