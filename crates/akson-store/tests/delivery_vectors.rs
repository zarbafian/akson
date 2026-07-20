//! Golden-vector tests for reliable-delivery primitives (family `delivery/`):
//! the RFC 9530 Content-Digest and the keyed covered-value commitment.
//! `xcheck/` reproduces the same bytes independently.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use akson_store::delivery::{content_digest, verify_content_digest, CoveredValues};
use serde_json::Value;

#[test]
fn delivery_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/delivery");
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
            "delivery/content-digest" => {
                let body = input["body_utf8"].as_str().unwrap().as_bytes();
                let digest = content_digest(body);
                assert_eq!(
                    digest,
                    expected["content_digest"].as_str().unwrap(),
                    "{name}"
                );
                // The frozen digest must verify against the body.
                assert!(verify_content_digest(&digest, body).is_ok(), "{name}");
            }
            "delivery/covered-values-commitment" => {
                let c = &input["covered"];
                let covered = CoveredValues {
                    peer: c["peer"].as_str().unwrap().to_owned(),
                    message_id: c["message_id"].as_str().unwrap().to_owned(),
                    body_digest: c["body_digest"].as_str().unwrap().to_owned(),
                    interface_url: c["interface_url"].as_str().unwrap().to_owned(),
                    tenant: c.get("tenant").and_then(|t| t.as_str()).map(str::to_owned),
                    a2a_version: c["a2a_version"].as_str().unwrap().to_owned(),
                    extensions: c["extensions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect(),
                    content_type: c["content_type"].as_str().unwrap().to_owned(),
                    http_method: c["http_method"].as_str().unwrap().to_owned(),
                }
                .normalized();
                assert_eq!(
                    String::from_utf8(covered.canonical_bytes()).unwrap(),
                    expected["canonical"].as_str().unwrap(),
                    "{name}: canonical"
                );
                let key: [u8; 32] = hex::decode(input["commitment_key_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert_eq!(
                    hex::encode(covered.commitment(&key)),
                    expected["commitment_hex"].as_str().unwrap(),
                    "{name}: commitment"
                );
            }
            other => panic!("unknown delivery vector {other}"),
        }
    }
    assert!(count >= 2, "expected at least two delivery vectors");
}
