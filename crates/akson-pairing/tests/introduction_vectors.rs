//! Golden-vector tests for the introduction transcript (family
//! `introduction/`, ADR-0015): the signing bytes are exactly the RFC 8785
//! canonical JSON with the domain field inside. `xcheck/` reproduces the same
//! bytes independently.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use akson_pairing::introduction::{IntroTranscript, Role};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

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
        key_binding_sha256: v["key_binding_sha256"].as_str().unwrap().to_owned(),
    }
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
        count += 1;
        let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap().to_owned();
        let input = &case["input"];
        let expected = &case["expected"];

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
    assert!(count >= 1, "no introduction vectors ran");
}
