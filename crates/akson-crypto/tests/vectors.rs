//! Golden-vector tests for JWK thumbprints (family `thumbprint/`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use akson_crypto::jwk::Ed25519PublicJwk;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;

#[test]
fn thumbprint_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/thumbprint");
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("missing {dir:?}: {e}")) {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        count += 1;
        let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap();
        let expected = case["expected"]["thumbprint"].as_str().unwrap();

        let jwk = if let Some(j) = case["input"].get("jwk") {
            serde_json::from_value::<Ed25519PublicJwk>(j.clone()).unwrap()
        } else {
            let pk: [u8; 32] = hex::decode(case["input"]["public_key_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let jwk = Ed25519PublicJwk::from_key(&VerifyingKey::from_bytes(&pk).unwrap());
            assert_eq!(
                jwk.x,
                case["expected"]["jwk_x"].as_str().unwrap(),
                "{name}: JWK x differs"
            );
            jwk
        };
        assert_eq!(jwk.thumbprint(), expected, "{name}: thumbprint differs");
    }
    assert!(count >= 2, "expected at least two thumbprint vectors");
}
