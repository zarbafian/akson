//! Enforces `spec/a2a/PIN`: every `sha256 <path> = <hex>` line must match the
//! actual bytes of the vendored file. An accidental edit to a vendored proto
//! would silently change the generated protocol types while leaving the
//! recorded upstream pin untouched (ADR-0002); this test catches that in CI.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

#[test]
fn vendored_protos_match_pin() {
    let a2a_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/a2a");
    let pin = fs::read_to_string(a2a_dir.join("PIN")).expect("PIN file");

    let mut checked = 0;
    for line in pin.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("sha256 ") else {
            continue;
        };
        let (rel_path, expected) = rest
            .split_once(" = ")
            .unwrap_or_else(|| panic!("malformed PIN line: {line:?}"));
        let bytes = fs::read(a2a_dir.join(rel_path.trim()))
            .unwrap_or_else(|e| panic!("reading {rel_path:?}: {e}"));
        let actual = hex::encode(Sha256::digest(&bytes));
        assert_eq!(
            actual,
            expected.trim(),
            "{rel_path}: vendored bytes do not match PIN"
        );
        checked += 1;
    }
    assert!(
        checked >= 6,
        "expected at least 6 pinned files, saw {checked}"
    );
}
