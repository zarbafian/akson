//! Golden-vector tests for pairing byte formats (family `pairing/`): the
//! invitation verifier, the canonical transcript + digest, and the Ed25519
//! proof of possession. `xcheck/` reproduces the same bytes independently.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use axon_pairing::bootstrap::Transcript;
use axon_pairing::state_machine::verifier_of;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

fn transcript_from(v: &Value) -> Transcript {
    Transcript {
        invitation_verifier: v["invitation_verifier"].as_str().unwrap().to_owned(),
        inviter_tls_sha256: v["inviter_tls_sha256"].as_str().unwrap().to_owned(),
        accepter_tls_sha256: v["accepter_tls_sha256"].as_str().unwrap().to_owned(),
        key_binding_sha256: v["key_binding_sha256"].as_str().unwrap().to_owned(),
    }
}

#[test]
fn pairing_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/pairing");
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("missing {dir:?}: {e}")) {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        count += 1;
        let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        let expected = &case["expected"];

        match name {
            "pairing/invitation-verifier" => {
                let v = verifier_of(input["secret_b64url"].as_str().unwrap()).unwrap();
                assert_eq!(hex::encode(v), expected["verifier_hex"].as_str().unwrap());
            }
            "pairing/transcript" => {
                let t = transcript_from(&input["transcript"]);
                assert_eq!(
                    String::from_utf8(t.to_bytes()).unwrap(),
                    expected["canonical"].as_str().unwrap(),
                    "canonical"
                );
                assert_eq!(hex::encode(t.digest()), expected["digest_hex"].as_str().unwrap());
            }
            "pairing/proof-of-possession" => {
                let t = transcript_from(&input["transcript"]);
                let seed: [u8; 32] = hex::decode(input["private_key_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let sig = SigningKey::from_bytes(&seed).sign(&t.to_bytes());
                assert_eq!(
                    URL_SAFE_NO_PAD.encode(sig.to_bytes()),
                    expected["signature_b64url"].as_str().unwrap()
                );
            }
            other => panic!("unknown pairing vector {other}"),
        }
    }
    assert!(count >= 3, "expected at least three pairing vectors");
}
