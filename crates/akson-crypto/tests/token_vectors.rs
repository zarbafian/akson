//! Drives the ADR-0013 identity-token golden vectors under
//! `spec/vectors/token/` — the bytes a second implementation must match.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use akson_crypto::token::{decode_token, split_presentation, TokenError};
use serde_json::Value;

fn error_name(e: &TokenError) -> &'static str {
    match e {
        TokenError::TooLong => "too-long",
        TokenError::MixedCase => "mixed-case",
        TokenError::BadHrp => "bad-hrp",
        TokenError::BadChar(_) => "bad-char",
        TokenError::BadChecksum => "bad-checksum",
        TokenError::UnknownVersion(_) => "unknown-version",
        TokenError::BadLength => "bad-length",
    }
}

#[test]
fn token_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/token");
    let mut cases_run = 0;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("missing {dir:?}: {e}")) {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let file: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        for case in file["cases"].as_array().unwrap() {
            cases_run += 1;
            let name = case["name"].as_str().unwrap();
            let input = case["input"].as_str().unwrap();
            match case["expect"].as_str().unwrap() {
                "valid" => {
                    let t = decode_token(input).unwrap_or_else(|e| panic!("{name}: {e}"));
                    assert_eq!(u32::from(t.version), case["version"].as_u64().unwrap() as u32);
                    assert_eq!(hex::encode(t.root_key), case["root_key_hex"].as_str().unwrap());
                }
                "error" => {
                    let err = decode_token(input).expect_err(name);
                    assert_eq!(error_name(&err), case["error"].as_str().unwrap(), "{name}");
                }
                "presentation" => {
                    let (token, hint) = split_presentation(input);
                    assert_eq!(hint, case["hint"].as_str(), "{name}");
                    if case["token_expect"] == "valid" {
                        decode_token(token).unwrap_or_else(|e| panic!("{name}: {e}"));
                    }
                }
                other => panic!("{name}: unknown expectation {other}"),
            }
        }
    }
    assert!(cases_run >= 9, "vectors missing: only {cases_run} cases ran");
}
