//! Golden-vector tests for Agent Card JWS signing (family `jws/`).
//!
//! Reproduces the frozen `AgentCardSignature` from the card and the seed key,
//! and confirms the signed card verifies. `xcheck/` reproduces the same bytes
//! independently with `rfc8785` + `cryptography`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use axon_crypto::keypair::PurposeKey;
use axon_crypto::purpose::KeyPurpose;
use axon_proto::card_sig::{canonical_payload, sign_card, verify_card};
use axon_proto::v1::AgentCard;
use serde_json::Value;

#[test]
fn jws_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/jws");
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("missing {dir:?}: {e}")) {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        count += 1;
        let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let name = case["name"].as_str().unwrap();
        let expected = &case["expected"];

        let seed: [u8; 32] = hex::decode(case["input"]["private_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let key = PurposeKey::from_seed(KeyPurpose::AgentCard, &seed);
        let card: AgentCard = serde_json::from_value(case["input"]["card"].clone()).unwrap();

        // Canonical payload matches the frozen bytes.
        let payload = canonical_payload(&card).unwrap();
        assert_eq!(
            String::from_utf8(payload).unwrap(),
            expected["payload_jcs"].as_str().unwrap(),
            "{name}: canonical payload differs"
        );

        // Signature reproduces bit-for-bit (Ed25519 is deterministic).
        assert_eq!(
            key.thumbprint(),
            expected["kid"].as_str().unwrap(),
            "{name}: kid differs"
        );
        let sig = sign_card(&card, &key).unwrap();
        assert_eq!(
            sig.protected,
            expected["protected"].as_str().unwrap(),
            "{name}: protected header differs"
        );
        assert_eq!(
            sig.signature,
            expected["signature"].as_str().unwrap(),
            "{name}: signature differs"
        );

        // The frozen signature verifies on the reconstructed card.
        let mut signed = card;
        signed.signatures.push(sig);
        verify_card(&signed, &key.verifying())
            .unwrap_or_else(|e| panic!("{name}: signed card failed to verify: {e}"));
    }
    assert!(count >= 1, "expected at least one jws vector");
}
