//! Inviter-side bootstrap verification (design §8.2 steps 4–5): everything the
//! inviter checks about an accepter's presented material before consuming the
//! invitation. The HTTP bootstrap endpoint is a thin adapter that extracts the
//! parts and calls [`verify_accepter`], then feeds the result to the
//! [state machine](crate::state_machine).
//!
//! The checks, in order and all fail-closed:
//! 1. the key-binding record passes its schema and every thumbprint equals its
//!    JWK ([`key_binding::verify`](crate::key_binding::verify));
//! 2. the record's claimed TLS certificate is exactly the one presented on this
//!    mutual-TLS connection — so a peer cannot present another identity's
//!    record over its own connection;
//! 3. the signed extended Agent Card verifies under the advertised
//!    `agent-card` key;
//! 4. every advertised key proves possession over the pairing transcript.
//!
//! The transcript binds the invitation and both certificates, so none of these
//! proofs can be replayed into another pairing.

use std::collections::BTreeMap;

use axon_crypto::identity::{Fingerprint, FingerprintKind, KeyBinding, PeerIdentity};
use axon_crypto::keypair::{KeyError, PurposeKey, PurposeVerifyingKey};
use axon_crypto::purpose::KeyPurpose;
use axon_proto::card_sig;
use axon_proto::v1::AgentCard;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::bootstrap::{verify_proof_of_possession, PopError, Transcript};
use crate::key_binding::{self, KeyBindingError, KeyBindingSet};

const AGENT_CARD_PURPOSE: &str = "agent-card";

#[derive(Debug, thiserror::Error)]
pub enum BootstrapVerifyError {
    #[error(transparent)]
    KeyBinding(#[from] KeyBindingError),
    #[error("the record's TLS certificate does not match the connection's")]
    TlsCertificateMismatch,
    #[error("the key binding advertises no agent-card key")]
    NoAgentCardKey,
    #[error("the extended Agent Card signature did not verify")]
    CardSignature,
    #[error(transparent)]
    ProofOfPossession(#[from] PopError),
}

/// The verified accepter: its key bindings and the transcript the inviter
/// reconstructed (whose digest keys the [state machine](crate::state_machine)).
#[derive(Debug)]
pub struct VerifiedAccepter {
    pub bindings: KeyBindingSet,
    pub transcript: Transcript,
}

/// Verifies a party's presented bootstrap material. Symmetric: the inviter uses
/// it to verify the accepter, and the accepter uses it to verify the inviter's
/// response. `inviter_tls_sha256`/`accepter_tls_sha256` are the shared transcript
/// fingerprints; `subject_tls_sha256` is the certificate the *verified* party
/// presented on this connection (the accepter's mTLS cert when the inviter
/// verifies it; the inviter's pinned server cert when the accepter verifies it),
/// which the record's claimed TLS cert must match.
#[allow(clippy::too_many_arguments)]
pub fn verify_accepter(
    invitation_verifier: &[u8; 32],
    inviter_tls_sha256: &str,
    accepter_tls_sha256: &str,
    subject_tls_sha256: &str,
    key_binding_json: &Value,
    extended_card: &AgentCard,
    pop_proofs: &BTreeMap<String, String>,
    now: OffsetDateTime,
) -> Result<VerifiedAccepter, BootstrapVerifyError> {
    // 1. Schema + thumbprint==JWK + validity.
    let bindings = key_binding::verify(key_binding_json, now)?;

    // 2. The claimed TLS certificate must be the one the verified party
    //    presented on this connection.
    if !bindings
        .tls_certificate_sha256
        .eq_ignore_ascii_case(subject_tls_sha256)
    {
        return Err(BootstrapVerifyError::TlsCertificateMismatch);
    }

    // 3. The extended card must be signed by the advertised agent-card key.
    let card_entry = bindings
        .keys
        .get(AGENT_CARD_PURPOSE)
        .ok_or(BootstrapVerifyError::NoAgentCardKey)?;
    let card_key = card_entry
        .jwk
        .to_key()
        .map_err(|_| BootstrapVerifyError::CardSignature)?;
    let card_vk = PurposeVerifyingKey::new(KeyPurpose::AgentCard, card_key);
    card_sig::verify_card(extended_card, &card_vk)
        .map_err(|_| BootstrapVerifyError::CardSignature)?;

    // 4. Proof of possession over the reconstructed transcript.
    let transcript = Transcript {
        invitation_verifier: URL_SAFE_NO_PAD.encode(invitation_verifier),
        inviter_tls_sha256: inviter_tls_sha256.to_owned(),
        accepter_tls_sha256: accepter_tls_sha256.to_owned(),
        key_binding_sha256: key_binding_digest_hex(key_binding_json),
    };
    verify_proof_of_possession(&bindings, &transcript, pop_proofs)?;

    Ok(VerifiedAccepter {
        bindings,
        transcript,
    })
}

/// SHA-256 (hex) over the RFC 8785 canonical key-binding record — the digest
/// both sides put in the transcript.
pub fn key_binding_digest_hex(key_binding_json: &Value) -> String {
    let canonical = json_canon::to_vec(key_binding_json).unwrap_or_default();
    hex::encode(Sha256::digest(canonical))
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// The shared pairing context both sides bind into their transcript.
pub struct PairingContext {
    pub invitation_verifier: [u8; 32],
    pub inviter_tls_sha256: String,
    pub accepter_tls_sha256: String,
}

/// Builds one endpoint's bootstrap material — the `{ key_binding,
/// extended_card, proofs }` it sends (design §8.2). The sender-side counterpart
/// to [`verify_accepter`]: it assembles the key-binding record for `keys`,
/// signs the pairing transcript with every key (proof of possession), and
/// bundles the already-signed extended card. `my_tls_sha256` is the sender's
/// own certificate fingerprint (which the receiver checks against the
/// connection). `signed_card` must already carry its Agent Card JWS.
#[allow(clippy::too_many_arguments)]
pub fn build_material(
    ctx: &PairingContext,
    my_tls_sha256: &str,
    subject_issuer: &str,
    subject_agent: &str,
    signed_card: &AgentCard,
    keys: &BTreeMap<KeyPurpose, PurposeKey>,
    not_before: &str,
    not_after: &str,
    generation: u64,
) -> Result<Value, BuildError> {
    let mut key_entries = serde_json::Map::new();
    for (purpose, key) in keys {
        let jwk = key.verifying().to_jwk();
        key_entries.insert(
            purpose_key(*purpose),
            json!({
                "jwk": jwk,
                "thumbprint": jwk.thumbprint(),
                "generation": generation,
                "not_before": not_before,
                "not_after": not_after,
            }),
        );
    }
    let key_binding = json!({
        "schema_version": 1,
        "subject": { "issuer": subject_issuer, "agent": subject_agent },
        "tls_certificate_sha256": my_tls_sha256,
        "keys": Value::Object(key_entries),
    });

    let transcript = Transcript {
        invitation_verifier: URL_SAFE_NO_PAD.encode(ctx.invitation_verifier),
        inviter_tls_sha256: ctx.inviter_tls_sha256.clone(),
        accepter_tls_sha256: ctx.accepter_tls_sha256.clone(),
        key_binding_sha256: key_binding_digest_hex(&key_binding),
    };
    let message = transcript.to_bytes();

    let mut proofs = serde_json::Map::new();
    for (purpose, key) in keys {
        let signature = key.sign_with(*purpose, |sk| sk.sign(&message))?;
        proofs.insert(
            purpose_key(*purpose),
            Value::String(URL_SAFE_NO_PAD.encode(signature.to_bytes())),
        );
    }

    Ok(json!({
        "key_binding": key_binding,
        "extended_card": signed_card,
        "proofs": Value::Object(proofs),
    }))
}

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("serialization: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("key binding advertises an unknown purpose: {0}")]
    UnknownPurpose(String),
}

/// Assembles the durable peer identity tuple (design §8.1) from a verified
/// bootstrap. The endpoint id defaults to the peer's preferred Agent Card
/// interface URL. The security-projection digest covers only stable
/// identity/interface/security/extension fields plus the key binding, so a
/// cosmetic card change (description, skills) does not move it (§8.4); the
/// full-card digest covers the whole card for change history.
pub fn to_peer_identity(
    verified: &VerifiedAccepter,
    extended_card: &AgentCard,
) -> Result<PeerIdentity, PeerError> {
    let bindings = &verified.bindings;
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

/// The kebab-case schema key for a purpose (e.g. `agent-card`).
fn purpose_key(purpose: KeyPurpose) -> String {
    // KeyPurpose serializes to the kebab-case string the schema uses; a fixed
    // enum cannot fail to serialize.
    serde_json::to_value(purpose)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axon_crypto::jwk::Ed25519PublicJwk;
    use axon_crypto::keypair::PurposeKey;
    use ed25519_dalek::{Signer, SigningKey};

    // Valid 64-char hex SHA-256 fingerprints (the key-binding schema requires it).
    const INVITER_TLS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ACCEPTER_TLS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_748_736_000).unwrap()
    }

    fn card_json() -> &'static str {
        r#"{
            "name": "Accepter",
            "description": "d",
            "version": "1.0.0",
            "supportedInterfaces": [
                {"url": "https://accepter.example/a2a",
                 "protocolBinding": "HTTP+JSON",
                 "protocolVersion": "1.0"}
            ],
            "capabilities": {"streaming": false, "pushNotifications": false}
        }"#
    }

    /// Assembles a complete, valid accepter request: key bindings, a signed
    /// extended card, and PoP proofs over the correct transcript.
    fn valid_request() -> ([u8; 32], Value, AgentCard, BTreeMap<String, String>) {
        let verifier = [3u8; 32];
        let card_key = SigningKey::from_bytes(&[10u8; 32]);
        let task_key = SigningKey::from_bytes(&[11u8; 32]);
        let card_jwk = Ed25519PublicJwk::from_key(&card_key.verifying_key());
        let task_jwk = Ed25519PublicJwk::from_key(&task_key.verifying_key());

        let key_binding = serde_json::json!({
            "schema_version": 1,
            "subject": { "issuer": "local", "agent": "accepter" },
            "tls_certificate_sha256": ACCEPTER_TLS,
            "keys": {
                "agent-card": { "jwk": card_jwk, "thumbprint": card_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" },
                "task-result": { "jwk": task_jwk, "thumbprint": task_jwk.thumbprint(),
                    "generation": 0, "not_before": "2020-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" }
            }
        });

        // Sign the extended card with the advertised agent-card key.
        let mut card: AgentCard = serde_json::from_str(card_json()).unwrap();
        let signing = PurposeKey::from_seed(KeyPurpose::AgentCard, &[10u8; 32]);
        card.signatures
            .push(card_sig::sign_card(&card, &signing).unwrap());

        // Build the transcript the accepter signs and prove possession.
        let transcript = Transcript {
            invitation_verifier: URL_SAFE_NO_PAD.encode(verifier),
            inviter_tls_sha256: INVITER_TLS.to_owned(),
            accepter_tls_sha256: ACCEPTER_TLS.to_owned(),
            key_binding_sha256: key_binding_digest_hex(&key_binding),
        };
        let msg = transcript.to_bytes();
        let mut proofs = BTreeMap::new();
        proofs.insert(
            "agent-card".to_owned(),
            URL_SAFE_NO_PAD.encode(card_key.sign(&msg).to_bytes()),
        );
        proofs.insert(
            "task-result".to_owned(),
            URL_SAFE_NO_PAD.encode(task_key.sign(&msg).to_bytes()),
        );
        (verifier, key_binding, card, proofs)
    }

    fn run(
        verifier: &[u8; 32],
        accepter_tls: &str,
        kb: &Value,
        card: &AgentCard,
        proofs: &BTreeMap<String, String>,
    ) -> Result<VerifiedAccepter, BootstrapVerifyError> {
        // The verified party is the accepter, so its subject cert is accepter_tls.
        verify_accepter(
            verifier,
            INVITER_TLS,
            accepter_tls,
            accepter_tls,
            kb,
            card,
            proofs,
            now(),
        )
    }

    #[test]
    fn valid_request_verifies() {
        let (v, kb, card, proofs) = valid_request();
        assert!(run(&v, ACCEPTER_TLS, &kb, &card, &proofs).is_ok());
    }

    #[test]
    fn peer_identity_captures_endpoint_and_keys() {
        let (v, kb, card, proofs) = valid_request();
        let verified = run(&v, ACCEPTER_TLS, &kb, &card, &proofs).unwrap();
        let peer = to_peer_identity(&verified, &card).unwrap();
        assert_eq!(peer.agent_id, "accepter");
        assert_eq!(peer.issuer.as_deref(), Some("local"));
        assert_eq!(peer.endpoint_id, "https://accepter.example/a2a");
        assert_eq!(peer.tls_cert.value, ACCEPTER_TLS);
        assert!(peer.binding(KeyPurpose::AgentCard).is_some());
        assert!(peer.binding(KeyPurpose::TaskResult).is_some());
    }

    #[test]
    fn cosmetic_card_change_does_not_move_the_projection() {
        let (v, kb, card, proofs) = valid_request();
        let verified = run(&v, ACCEPTER_TLS, &kb, &card, &proofs).unwrap();
        let peer1 = to_peer_identity(&verified, &card).unwrap();

        // Only the description changes (cosmetic) — projection stable, full digest moves.
        let mut card2 = card.clone();
        card2.description = "an entirely rewritten description".to_owned();
        let peer2 = to_peer_identity(&verified, &card2).unwrap();

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
    fn built_material_round_trips_through_verify() {
        // The sender-side builder produces material the receiver-side verifier
        // accepts — the two halves of the exchange agree.
        let card_key = PurposeKey::from_seed(KeyPurpose::AgentCard, &[10u8; 32]);
        let mut card: AgentCard = serde_json::from_str(card_json()).unwrap();
        card.signatures
            .push(card_sig::sign_card(&card, &card_key).unwrap());

        let ctx = PairingContext {
            invitation_verifier: [3u8; 32],
            inviter_tls_sha256: INVITER_TLS.to_owned(),
            accepter_tls_sha256: ACCEPTER_TLS.to_owned(),
        };
        let mut keys = BTreeMap::new();
        keys.insert(
            KeyPurpose::AgentCard,
            PurposeKey::from_seed(KeyPurpose::AgentCard, &[10u8; 32]),
        );
        keys.insert(
            KeyPurpose::TaskResult,
            PurposeKey::from_seed(KeyPurpose::TaskResult, &[11u8; 32]),
        );

        let material = build_material(
            &ctx,
            ACCEPTER_TLS,
            "local",
            "accepter",
            &card,
            &keys,
            "2020-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            0,
        )
        .unwrap();

        let key_binding = material["key_binding"].clone();
        let extended_card: AgentCard =
            serde_json::from_value(material["extended_card"].clone()).unwrap();
        let proofs: BTreeMap<String, String> =
            serde_json::from_value(material["proofs"].clone()).unwrap();

        let result = verify_accepter(
            &ctx.invitation_verifier,
            INVITER_TLS,
            ACCEPTER_TLS,
            ACCEPTER_TLS,
            &key_binding,
            &extended_card,
            &proofs,
            now(),
        );
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn accepter_verifies_the_inviter_material() {
        // The other direction of the symmetric exchange: the inviter builds its
        // response material with its *own* TLS cert, and the accepter verifies
        // it — the verified party is the inviter, so the subject cert is the
        // inviter's (its pinned server cert), not the accepter's.
        let card_key = PurposeKey::from_seed(KeyPurpose::AgentCard, &[30u8; 32]);
        let mut card: AgentCard = serde_json::from_str(card_json()).unwrap();
        card.signatures
            .push(card_sig::sign_card(&card, &card_key).unwrap());

        let ctx = PairingContext {
            invitation_verifier: [4u8; 32],
            inviter_tls_sha256: INVITER_TLS.to_owned(),
            accepter_tls_sha256: ACCEPTER_TLS.to_owned(),
        };
        let mut keys = BTreeMap::new();
        keys.insert(
            KeyPurpose::AgentCard,
            PurposeKey::from_seed(KeyPurpose::AgentCard, &[30u8; 32]),
        );
        // Built by the inviter with its own cert as the subject.
        let material = build_material(
            &ctx,
            INVITER_TLS,
            "local",
            "inviter",
            &card,
            &keys,
            "2020-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            0,
        )
        .unwrap();

        let key_binding = material["key_binding"].clone();
        let extended_card: AgentCard =
            serde_json::from_value(material["extended_card"].clone()).unwrap();
        let proofs: BTreeMap<String, String> =
            serde_json::from_value(material["proofs"].clone()).unwrap();

        let result = verify_accepter(
            &ctx.invitation_verifier,
            INVITER_TLS,
            ACCEPTER_TLS,
            INVITER_TLS, // subject = the inviter's cert
            &key_binding,
            &extended_card,
            &proofs,
            now(),
        );
        assert!(
            result.is_ok(),
            "the accepter must verify the inviter's material: {:?}",
            result.err()
        );
    }

    #[test]
    fn tls_certificate_must_match_the_connection() {
        let (v, kb, card, proofs) = valid_request();
        // The record claims ACCEPTER_TLS, but the connection presented another.
        assert!(matches!(
            run(&v, "cc", &kb, &card, &proofs),
            Err(BootstrapVerifyError::TlsCertificateMismatch)
        ));
    }

    #[test]
    fn tampered_card_fails() {
        let (v, kb, mut card, proofs) = valid_request();
        card.name = "Evil".to_owned();
        assert!(matches!(
            run(&v, ACCEPTER_TLS, &kb, &card, &proofs),
            Err(BootstrapVerifyError::CardSignature)
        ));
    }

    #[test]
    fn proof_over_a_different_invitation_fails() {
        let (_v, kb, card, proofs) = valid_request();
        // A different invitation verifier changes the transcript the proofs
        // must sign — captured proofs cannot be replayed here.
        assert!(matches!(
            run(&[9u8; 32], ACCEPTER_TLS, &kb, &card, &proofs),
            Err(BootstrapVerifyError::ProofOfPossession(_))
        ));
    }

    #[test]
    fn mismatched_thumbprint_fails_key_binding() {
        let (v, mut kb, card, proofs) = valid_request();
        kb["keys"]["task-result"]["thumbprint"] = Value::String(
            Ed25519PublicJwk::from_key(&SigningKey::from_bytes(&[99u8; 32]).verifying_key())
                .thumbprint(),
        );
        assert!(matches!(
            run(&v, ACCEPTER_TLS, &kb, &card, &proofs),
            Err(BootstrapVerifyError::KeyBinding(_))
        ));
    }
}
