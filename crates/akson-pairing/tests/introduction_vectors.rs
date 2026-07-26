//! Golden-vector tests for the introduction protocol (family `introduction/`,
//! ADR-0015). Four vector kinds live in the directory, told apart by their
//! input shape:
//!
//! - transcript cases (`input.transcript` + a single key): the signing bytes
//!   are exactly the RFC 8785 canonical JSON with the domain field inside;
//!   digest + Ed25519 PoP — one case per role, since the role member is
//!   inside the signed bytes.
//! - the hello case (`input.hello`): flight 1's exact wire bytes.
//! - proof cases (`input.keys`): the full `IntroMaterial` body for one role,
//!   rebuilt from seeds with `build_intro_material` and then pushed through
//!   `verify_introduction` — the frozen body must both reproduce and verify.
//! - refusal cases (`input.problem`): aksond wire shapes, exercised by
//!   `aksond/tests/introduce_e2e.rs` against the real handler; skipped here.
//!
//! `xcheck/` reproduces every expected value independently in Python.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use akson_crypto::keypair::PurposeKey;
use akson_crypto::purpose::KeyPurpose;
use akson_pairing::introduction::{
    build_intro_material, verify_introduction, Hello, IntroTranscript, Role,
};
use akson_pairing::session::key_binding_digest_hex;
use akson_proto::card_sig;
use akson_proto::profile::ProfileConfig;
use akson_proto::v1::AgentCard;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `key_binding_sha256` defaults to empty — proof-case transcripts omit it
/// (build/verify bind the presented record's digest themselves).
fn transcript_from(v: &Value) -> IntroTranscript {
    IntroTranscript {
        protocol_version: v["protocol_version"].as_u64().unwrap() as u32,
        token_version: v["token_version"].as_u64().unwrap() as u32,
        role: match v["role"].as_str().unwrap() {
            "dialer" => Role::Dialer,
            _ => Role::Responder,
        },
        dialer_root: v["dialer_root"].as_str().unwrap().to_owned(),
        responder_root: v["responder_root"].as_str().unwrap().to_owned(),
        dialer_tls_sha256: v["dialer_tls_sha256"].as_str().unwrap().to_owned(),
        responder_tls_sha256: v["responder_tls_sha256"].as_str().unwrap().to_owned(),
        tls_exporter: v["tls_exporter"].as_str().unwrap().to_owned(),
        nonce: v["nonce"].as_str().unwrap().to_owned(),
        key_binding_sha256: v["key_binding_sha256"].as_str().unwrap_or("").to_owned(),
    }
}

/// Transcript canonical bytes + digest + a single-key Ed25519 PoP.
fn check_transcript(name: &str, input: &Value, expected: &Value) {
    let t = transcript_from(&input["transcript"]);
    let bytes = t.signing_bytes();
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        expected["canonical"].as_str().unwrap(),
        "{name}: canonical"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        expected["digest_hex"].as_str().unwrap(),
        "{name}: digest"
    );
    let seed: [u8; 32] = hex::decode(input["private_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sk = SigningKey::from_bytes(&seed);
    assert_eq!(
        hex::encode(sk.verifying_key().to_bytes()),
        input["public_key_hex"].as_str().unwrap(),
        "{name}: public key"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(sk.sign(&bytes).to_bytes()),
        expected["signature_b64url"].as_str().unwrap(),
        "{name}: pop signature"
    );
}

/// Flight 1's exact wire bytes: field set and order are the frozen fact.
fn check_hello(name: &str, input: &Value, expected: &Value) {
    let h = &input["hello"];
    let hello = Hello {
        protocol_version: h["protocol_version"].as_u64().unwrap() as u32,
        token_version: h["token_version"].as_u64().unwrap() as u32,
        target_root: h["target_root"].as_str().unwrap().to_owned(),
        claimed_root: h["claimed_root"].as_str().unwrap().to_owned(),
        nonce: h["nonce"].as_str().unwrap().to_owned(),
    };
    let wire = expected["wire"].as_str().unwrap();
    assert_eq!(
        String::from_utf8(serde_json::to_vec(&hello).unwrap()).unwrap(),
        wire,
        "{name}: hello wire bytes"
    );
    // And the frozen wire parses back to the same hello.
    let parsed: Hello = serde_json::from_str(wire).unwrap();
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        serde_json::to_value(&hello).unwrap(),
        "{name}: hello round-trip"
    );
}

/// One role's full proof body: rebuild the `IntroMaterial` from the seeds,
/// compare it to the frozen body, and require the frozen body to pass the
/// real verifier against the signer's root.
fn check_proof(name: &str, input: &Value, expected: &Value) {
    let mut keys: BTreeMap<KeyPurpose, PurposeKey> = BTreeMap::new();
    for (purpose_name, seed_hex) in input["keys"].as_object().unwrap() {
        let purpose: KeyPurpose =
            serde_json::from_value(Value::String(purpose_name.clone())).unwrap();
        let seed: [u8; 32] = hex::decode(seed_hex.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        keys.insert(purpose, PurposeKey::from_seed(purpose, &seed));
    }

    // The signed card: input card + one signature by the agent-card key.
    let mut card: AgentCard = serde_json::from_value(input["card"].clone()).unwrap();
    card.signatures
        .push(card_sig::sign_card(&card, &keys[&KeyPurpose::AgentCard]).unwrap());

    let t = transcript_from(&input["transcript"]);
    let material = build_intro_material(
        &t,
        input["subject"]["issuer"].as_str().unwrap(),
        input["subject"]["agent"].as_str().unwrap(),
        &card,
        &keys,
        input["validity"]["not_before"].as_str().unwrap(),
        input["validity"]["not_after"].as_str().unwrap(),
        input["validity"]["generation"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&material).unwrap(),
        expected["material"],
        "{name}: material body"
    );

    // Intermediates a second implementation derives on the way.
    let kb_digest = key_binding_digest_hex(&material.key_binding);
    assert_eq!(
        kb_digest,
        expected["key_binding_sha256"].as_str().unwrap(),
        "{name}: key binding digest"
    );
    let mut bound = t.clone();
    bound.key_binding_sha256 = kb_digest;
    let canonical = bound.signing_bytes();
    assert_eq!(
        String::from_utf8(canonical.clone()).unwrap(),
        expected["transcript_canonical"].as_str().unwrap(),
        "{name}: transcript canonical"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&canonical)),
        expected["transcript_digest_hex"].as_str().unwrap(),
        "{name}: transcript digest"
    );

    // The frozen body must pass the real verifier: expected root and subject
    // TLS are the signer's side of the transcript.
    let frozen: akson_pairing::introduction::IntroMaterial =
        serde_json::from_value(expected["material"].clone()).unwrap();
    let (signer_root, signer_tls) = match t.role {
        Role::Dialer => (&t.dialer_root, &t.dialer_tls_sha256),
        Role::Responder => (&t.responder_root, &t.responder_tls_sha256),
    };
    let profile_uris: BTreeSet<String> = input["card"]["capabilities"]["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["uri"].as_str().unwrap().to_owned())
        .collect();
    let now =
        time::OffsetDateTime::from_unix_timestamp(input["now_unix"].as_i64().unwrap()).unwrap();
    let verified = verify_introduction(
        signer_root,
        &t,
        signer_tls,
        &frozen,
        &ProfileConfig::new(profile_uris).unwrap(),
        now,
    )
    .unwrap_or_else(|e| panic!("{name}: frozen material must verify: {e}"));
    assert_eq!(verified.root.value, *signer_root, "{name}: verified root");
}

#[test]
fn introduction_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/introduction");
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("missing {dir:?}: {e}")) {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap().to_owned();
        let input = &case["input"];
        let expected = &case["expected"];

        if input.get("problem").is_some() {
            // Refusal wire shapes are aksond's; its e2e test drives the real
            // handler against these vectors.
            continue;
        }
        count += 1;
        if input.get("hello").is_some() {
            check_hello(&name, input, expected);
        } else if input.get("keys").is_some() {
            check_proof(&name, input, expected);
        } else {
            check_transcript(&name, input, expected);
        }
    }
    assert!(
        count >= 5,
        "expected the full introduction vector set, ran {count}"
    );
}
