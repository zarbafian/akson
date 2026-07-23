//! The first-contact introduction (design §8.2 step 4, ADR-0015): mutual
//! verification against out-of-band root commitments, replacing the invitation
//! bootstrap. Both operators imported each other's identity token before any
//! bytes flow, so there is no secret and no negotiation — each side proves it
//! is the committed root, over a transcript bound to this TLS session.
//!
//! What a side writes (the responder, on a valid hello):
//! ```no_run
//! # use akson_pairing::introduction::*;
//! # use std::collections::BTreeMap;
//! # fn go(t: &IntroTranscript, keys: &BTreeMap<akson_crypto::purpose::KeyPurpose, akson_crypto::keypair::PurposeKey>, card: &akson_proto::v1::AgentCard) {
//! let material = build_intro_material(t, "local", "bob", card, keys,
//!     "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z", 0).unwrap();
//! # }
//! ```
//! and what it checks about the other side, all fail-closed and in order:
//! schema-valid key bindings; the record's TLS certificate byte-equal to this
//! connection's; **the agent-card key equal to the imported root** (this
//! replaces the bearer secret as the authorization to become a peer); the card
//! signed by that root and A2A-profile valid; proof of possession for every
//! advertised key over the session-bound transcript.

use std::collections::BTreeMap;

use akson_crypto::identity::Fingerprint;
use akson_crypto::keypair::{PurposeKey, PurposeVerifyingKey};
use akson_crypto::purpose::KeyPurpose;
use akson_proto::card_sig;
use akson_proto::profile::{self, ProfileConfig};
use akson_proto::v1::AgentCard;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bootstrap::{verify_proofs_over, PopError};
use crate::key_binding::{self, KeyBindingError, KeyBindingSet};
use crate::session::key_binding_digest_hex;

/// The introduction wire media type (ADR-0015).
pub const INTRODUCTION_MEDIA_TYPE: &str = "application/vnd.akson-dev.introduction.v1+json";
/// Flight 1/2 route on the receive listener.
pub const HELLO_PATH: &str = "/akson/introduce/v1/hello";
/// Flight 3/4 route on the receive listener.
pub const COMPLETE_PATH: &str = "/akson/introduce/v1/complete";
/// The introduction request-body cap (ADR-0015; far below the A2A cap).
pub const MAX_INTRODUCTION_BODY: usize = 64 * 1024;
/// Protocol and token versions this implementation speaks. Both are bound
/// into the transcript, so a rewritten version cannot survive verification.
pub const PROTOCOL_VERSION: u32 = 1;
pub const TOKEN_VERSION: u32 = 1;

/// The transcript's domain-separation string.
const DOMAIN: &[u8] = b"akson-introduction-v1";

/// Flight 1: the dialer names both roots and is refused generically before any
/// signature work unless `claimed_root` is imported on the responder. Carries
/// no keys and no card — the cheap admission gate (ADR-0015).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u32,
    pub token_version: u32,
    /// The responder's root thumbprint, from the token the dialer imported.
    pub target_root: String,
    /// The dialer's own root thumbprint — verified against its proof in
    /// flight 3, and against the responder's import set now.
    pub claimed_root: String,
    /// base64url, 32 random bytes; bound into the transcript.
    pub nonce: String,
}

/// Flights 2 and 3: one side's identity material and its proofs over the
/// session transcript. The same shape both directions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroMaterial {
    pub key_binding: Value,
    pub extended_card: AgentCard,
    #[serde(default)]
    pub proofs: BTreeMap<String, String>,
}

/// Flight 4: the responder committed; the dialer commits on receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroAck {
    pub ok: bool,
}

/// Which party a transcript instance is signed by. The role is inside the
/// signed bytes, so a responder proof can never be replayed as a dialer proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Dialer,
    Responder,
}

/// The bytes every introduction proof signs (ADR-0015): both roots, both
/// certificates, the live TLS session (RFC 9266 exporter), the versions, the
/// hello nonce, and the signer's exact key-binding record. Serialized with RFC
/// 8785 (JCS) under a length-prefixed domain string, so two implementations
/// agree byte-for-byte and no other Akson signature shares the input shape.
#[derive(Debug, Clone, Serialize)]
pub struct IntroTranscript {
    pub protocol_version: u32,
    pub token_version: u32,
    /// The role of the party whose keys sign this instance.
    pub role: Role,
    pub dialer_root: String,
    pub responder_root: String,
    /// SHA-256 (hex) of each side's DER endpoint certificate on *this*
    /// connection.
    pub dialer_tls_sha256: String,
    pub responder_tls_sha256: String,
    /// base64url of the 32-byte RFC 9266 `tls-exporter` value of this session.
    pub tls_exporter: String,
    /// The hello nonce, base64url.
    pub nonce: String,
    /// SHA-256 (hex) over the signer's canonical key-binding record.
    pub key_binding_sha256: String,
}

impl IntroTranscript {
    /// The exact signed bytes: `len(domain) ‖ domain ‖ len(jcs) ‖ jcs`, both
    /// lengths u64 little-endian — a PAE, so the domain can never collide with
    /// content.
    pub fn signing_bytes(&self) -> Vec<u8> {
        // A fixed struct of strings and integers cannot fail to canonicalize.
        let body = json_canon::to_vec(self).unwrap_or_default();
        let mut out = Vec::with_capacity(16 + DOMAIN.len() + body.len());
        out.extend_from_slice(&(DOMAIN.len() as u64).to_le_bytes());
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IntroError {
    #[error(transparent)]
    KeyBinding(#[from] KeyBindingError),
    #[error("the record's TLS certificate does not match the connection's")]
    TlsCertificateMismatch,
    #[error("the key binding advertises no agent-card key")]
    NoAgentCardKey,
    #[error("the agent-card key is not the imported root")]
    RootMismatch,
    #[error("the extended Agent Card signature did not verify")]
    CardSignature,
    #[error("the extended Agent Card fails profile validation: {0}")]
    CardProfile(String),
    #[error(transparent)]
    ProofOfPossession(#[from] PopError),
    #[error("building material: {0}")]
    Build(String),
}

/// The verified counterparty: its bindings (feed
/// [`peer_identity_from`](crate::session::peer_identity_from)) and root.
#[derive(Debug)]
pub struct VerifiedIntroduction {
    pub bindings: KeyBindingSet,
    /// The verified root as a display fingerprint (RFC 7638).
    pub root: Fingerprint,
}

/// Verifies one side's introduction material, all fail-closed (module doc has
/// the order). `expected_root_thumbprint` is the RFC 7638 thumbprint from the
/// verifier's *own import* of the counterparty's token — never from the wire.
/// `transcript` is reconstructed locally for the counterparty's role, except
/// its `key_binding_sha256`, which is computed here from the presented record.
#[allow(clippy::result_large_err)]
pub fn verify_introduction(
    expected_root_thumbprint: &str,
    transcript: &IntroTranscript,
    subject_tls_sha256: &str,
    material: &IntroMaterial,
    profile_config: &ProfileConfig,
    now: time::OffsetDateTime,
) -> Result<VerifiedIntroduction, IntroError> {
    // 1. Schema + thumbprint==JWK + validity.
    let bindings = key_binding::verify(&material.key_binding, now)?;

    // 2. The record's claimed TLS certificate must be the one presented on
    //    this connection.
    if !bindings
        .tls_certificate_sha256
        .eq_ignore_ascii_case(subject_tls_sha256)
    {
        return Err(IntroError::TlsCertificateMismatch);
    }

    // 3. The advertised agent-card key must BE the imported root — the
    //    commitment that authorizes this party to become a peer (ADR-0015).
    let card_entry = bindings
        .keys
        .get("agent-card")
        .ok_or(IntroError::NoAgentCardKey)?;
    if card_entry.thumbprint != expected_root_thumbprint {
        return Err(IntroError::RootMismatch);
    }

    // 4. The card must verify under that root...
    let card_key = card_entry
        .jwk
        .to_key()
        .map_err(|_| IntroError::CardSignature)?;
    let card_vk = PurposeVerifyingKey::new(KeyPurpose::AgentCard, card_key);
    card_sig::verify_card(&material.extended_card, &card_vk)
        .map_err(|_| IntroError::CardSignature)?;

    // 5. ...and pass the A2A profile (mTLS mandatory, streaming/push off,
    //    extended card, required extensions) — a root-signed card advertising
    //    a weaker interface is refused, not pinned.
    profile::validate_agent_card(&material.extended_card, profile_config)
        .map_err(|e| IntroError::CardProfile(e.to_string()))?;

    // 6. Proof of possession for every advertised key, over this session's
    //    transcript with the presented record's digest bound in.
    let mut bound = transcript.clone();
    bound.key_binding_sha256 = key_binding_digest_hex(&material.key_binding);
    verify_proofs_over(&bindings, &bound.signing_bytes(), &material.proofs)?;

    let root = Fingerprint {
        kind: akson_crypto::identity::FingerprintKind::Jwk7638,
        value: card_entry.thumbprint.clone(),
    };
    Ok(VerifiedIntroduction { bindings, root })
}

/// Builds one side's [`IntroMaterial`]: the key-binding record over `keys`,
/// the already-signed card, and proofs by every key over `transcript` with
/// this record's digest bound in. Mirror of the verify path above.
#[allow(clippy::too_many_arguments)]
pub fn build_intro_material(
    transcript: &IntroTranscript,
    subject_issuer: &str,
    subject_agent: &str,
    signed_card: &AgentCard,
    keys: &BTreeMap<KeyPurpose, PurposeKey>,
    not_before: &str,
    not_after: &str,
    generation: u64,
) -> Result<IntroMaterial, IntroError> {
    let mut key_entries = serde_json::Map::new();
    for (purpose, key) in keys {
        let jwk = key.verifying().to_jwk();
        key_entries.insert(
            purpose_name(*purpose),
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
        "tls_certificate_sha256": transcript_tls_of_signer(transcript),
        "keys": Value::Object(key_entries),
    });

    let mut bound = transcript.clone();
    bound.key_binding_sha256 = key_binding_digest_hex(&key_binding);
    let message = bound.signing_bytes();

    let mut proofs = BTreeMap::new();
    for (purpose, key) in keys {
        use ed25519_dalek::Signer;
        let signature = key
            .sign_with(*purpose, |sk| sk.sign(&message))
            .map_err(|e| IntroError::Build(e.to_string()))?;
        proofs.insert(
            purpose_name(*purpose),
            base64_url(&signature.to_bytes()),
        );
    }

    Ok(IntroMaterial {
        key_binding,
        extended_card: signed_card.clone(),
        proofs,
    })
}

/// The signer's own TLS fingerprint by role — the record must claim the
/// certificate its side presents on this connection.
fn transcript_tls_of_signer(t: &IntroTranscript) -> String {
    match t.role {
        Role::Dialer => t.dialer_tls_sha256.clone(),
        Role::Responder => t.responder_tls_sha256.clone(),
    }
}

fn purpose_name(purpose: KeyPurpose) -> String {
    serde_json::to_value(purpose)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const DIALER_TLS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RESPONDER_TLS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_748_736_000).unwrap()
    }

    const EXT_CONTRACT: &str = "https://akson.cc/ext/contract/v1";
    const EXT_KEY_BINDING: &str = "https://akson.cc/ext/key-binding/v1";

    fn profile() -> ProfileConfig {
        ProfileConfig::new(BTreeSet::from([
            EXT_CONTRACT.to_owned(),
            EXT_KEY_BINDING.to_owned(),
        ]))
        .unwrap()
    }

    /// A card that passes `validate_agent_card` (mirrors the valid conformance
    /// vector), unsigned — tests sign it with their chosen root.
    fn card() -> AgentCard {
        serde_json::from_value(json!({
            "name": "peer", "description": "d", "version": "0.0.1",
            "supportedInterfaces": [{
                "url": "https://peer.example:7300/a2a",
                "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"
            }],
            "capabilities": {
                "streaming": false, "pushNotifications": false,
                "extendedAgentCard": true,
                "extensions": [
                    { "uri": EXT_CONTRACT, "required": true },
                    { "uri": EXT_KEY_BINDING, "required": true }
                ]
            },
            "securitySchemes": {
                "mtls": { "mtlsSecurityScheme": { "description": "pinned" } }
            },
            "securityRequirements": [{ "schemes": { "mtls": { "list": [] } } }]
        }))
        .unwrap()
    }

    /// One party: its purpose keys, signed card, and root thumbprint.
    struct Party {
        keys: BTreeMap<KeyPurpose, PurposeKey>,
        card: AgentCard,
        root: String,
    }

    fn party(seed: u8) -> Party {
        let mut keys = BTreeMap::new();
        for purpose in [
            KeyPurpose::AgentCard,
            KeyPurpose::ContractProposal,
            KeyPurpose::TaskResult,
        ] {
            keys.insert(
                purpose,
                PurposeKey::from_seed(purpose, &[seed ^ (purpose as u8); 32]),
            );
        }
        let card_key = &keys[&KeyPurpose::AgentCard];
        let root = card_key.verifying().to_jwk().thumbprint();
        let mut card = card();
        card.signatures
            .push(card_sig::sign_card(&card, card_key).unwrap());
        Party { keys, card, root }
    }

    /// The transcript for `role`'s proofs on one shared session.
    fn transcript(role: Role, dialer: &Party, responder: &Party) -> IntroTranscript {
        IntroTranscript {
            protocol_version: PROTOCOL_VERSION,
            token_version: TOKEN_VERSION,
            role,
            dialer_root: dialer.root.clone(),
            responder_root: responder.root.clone(),
            dialer_tls_sha256: DIALER_TLS.to_owned(),
            responder_tls_sha256: RESPONDER_TLS.to_owned(),
            tls_exporter: "ZXhwb3J0ZXItdmFsdWUtZXhwb3J0ZXItdmFsdWUhIQ".to_owned(),
            nonce: "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uY2UhIQ".to_owned(),
            // Filled from the presented record on both build and verify.
            key_binding_sha256: String::new(),
        }
    }

    fn material(role: Role, dialer: &Party, responder: &Party) -> IntroMaterial {
        let signer = match role {
            Role::Dialer => dialer,
            Role::Responder => responder,
        };
        build_intro_material(
            &transcript(role, dialer, responder),
            "local",
            "peer",
            &signer.card,
            &signer.keys,
            "2020-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            0,
        )
        .unwrap()
    }

    #[test]
    fn both_roles_round_trip() {
        let (dialer, responder) = (party(1), party(2));
        // The dialer verifies the responder's proof (flight 2)...
        let v = verify_introduction(
            &responder.root,
            &transcript(Role::Responder, &dialer, &responder),
            RESPONDER_TLS,
            &material(Role::Responder, &dialer, &responder),
            &profile(),
            now(),
        )
        .unwrap();
        assert_eq!(v.root.value, responder.root);
        // ...and the responder verifies the dialer's (flight 3).
        let v = verify_introduction(
            &dialer.root,
            &transcript(Role::Dialer, &dialer, &responder),
            DIALER_TLS,
            &material(Role::Dialer, &dialer, &responder),
            &profile(),
            now(),
        )
        .unwrap();
        assert_eq!(v.root.value, dialer.root);
    }

    #[test]
    fn verified_bindings_feed_the_peer_identity() {
        let (dialer, responder) = (party(1), party(2));
        let v = verify_introduction(
            &responder.root,
            &transcript(Role::Responder, &dialer, &responder),
            RESPONDER_TLS,
            &material(Role::Responder, &dialer, &responder),
            &profile(),
            now(),
        )
        .unwrap();
        let peer = crate::session::peer_identity_from(&v.bindings, &responder.card).unwrap();
        assert_eq!(peer.endpoint_id, "https://peer.example:7300/a2a");
        assert_eq!(peer.agent_card_key.value, responder.root);
        assert_eq!(peer.tls_cert.value, RESPONDER_TLS);
    }

    #[test]
    fn a_different_root_than_imported_is_refused() {
        let (dialer, responder) = (party(1), party(2));
        let imposter = party(9); // valid material, wrong identity
        let err = verify_introduction(
            &responder.root, // what the dialer imported
            &transcript(Role::Responder, &dialer, &imposter),
            RESPONDER_TLS,
            &material(Role::Responder, &dialer, &imposter),
            &profile(),
            now(),
        )
        .unwrap_err();
        assert!(matches!(err, IntroError::RootMismatch));
    }

    #[test]
    fn a_proof_from_another_session_is_refused() {
        let (dialer, responder) = (party(1), party(2));
        let material = material(Role::Responder, &dialer, &responder);
        // Same parties, different TLS exporter — a replayed introduction.
        let mut other_session = transcript(Role::Responder, &dialer, &responder);
        other_session.tls_exporter = "b3RoZXItc2Vzc2lvbi1leHBvcnRlci12YWx1ZSEhIQ".to_owned();
        let err = verify_introduction(
            &responder.root,
            &other_session,
            RESPONDER_TLS,
            &material,
            &profile(),
            now(),
        )
        .unwrap_err();
        assert!(matches!(err, IntroError::ProofOfPossession(_)));
    }

    #[test]
    fn a_role_swapped_proof_is_refused() {
        let (dialer, responder) = (party(1), party(2));
        // The responder's material presented as if it were the dialer's proof:
        // the role is inside the signed bytes, so this cannot verify.
        let err = verify_introduction(
            &responder.root,
            &transcript(Role::Dialer, &dialer, &responder),
            RESPONDER_TLS,
            &material(Role::Responder, &dialer, &responder),
            &profile(),
            now(),
        )
        .unwrap_err();
        assert!(matches!(err, IntroError::ProofOfPossession(_)));
    }

    #[test]
    fn a_certificate_not_on_this_connection_is_refused() {
        let (dialer, responder) = (party(1), party(2));
        let err = verify_introduction(
            &responder.root,
            &transcript(Role::Responder, &dialer, &responder),
            // The connection shows a different certificate than the record claims.
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            &material(Role::Responder, &dialer, &responder),
            &profile(),
            now(),
        )
        .unwrap_err();
        assert!(matches!(err, IntroError::TlsCertificateMismatch));
    }

    #[test]
    fn a_profile_violating_card_is_refused_even_root_signed() {
        let (dialer, mut responder) = (party(1), party(2));
        // A correctly root-signed card that advertises streaming: the profile
        // validator must still refuse it (v2 review finding).
        let mut card = card();
        if let Some(caps) = card.capabilities.as_mut() {
            caps.streaming = Some(true);
        }
        card.signatures.clear();
        card.signatures.push(
            card_sig::sign_card(&card, &responder.keys[&KeyPurpose::AgentCard]).unwrap(),
        );
        responder.card = card;
        let err = verify_introduction(
            &responder.root,
            &transcript(Role::Responder, &dialer, &responder),
            RESPONDER_TLS,
            &material(Role::Responder, &dialer, &responder),
            &profile(),
            now(),
        )
        .unwrap_err();
        assert!(matches!(err, IntroError::CardProfile(_)));
    }

    #[test]
    fn transcript_bytes_are_domain_separated_and_content_sensitive() {
        let (dialer, responder) = (party(1), party(2));
        let a = transcript(Role::Dialer, &dialer, &responder);
        let mut b = a.clone();
        b.nonce = "ZGlmZmVyZW50LW5vbmNlLWRpZmZlcmVudC1ub25jZQ".to_owned();
        assert_ne!(a.signing_bytes(), b.signing_bytes());
        assert!(a.signing_bytes().windows(DOMAIN.len()).any(|w| w == DOMAIN));
    }
}
