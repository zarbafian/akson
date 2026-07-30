//! `akson verify` end-to-end, against the real binary: a signed bundle on disk,
//! checked offline with a pinned key — and every break-first case the AKB
//! program rule demands: a flipped manifest byte fails naming the signature, a
//! swapped output fails naming the digest, the wrong key refuses, a truncated
//! file refuses without a panic.
//!
//! No daemon is started anywhere here: `akson verify` must be a pure function
//! of the file and the key.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use akson_crypto::keypair::PurposeKey;
use akson_crypto::purpose::KeyPurpose;
use akson_evidence::{
    BundleOutput, ManifestHeader, OutputEntry, ResultBundle, ResultManifest, SignerHint,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

const RESPONSE: &[u8] = b"reviewed: LGTM";

fn key() -> PurposeKey {
    PurposeKey::from_seed(KeyPurpose::TaskResult, &[7u8; 32])
}

fn key_hex() -> String {
    hex::encode(key().verifying().to_public_bytes())
}

/// A signed one-output bundle, with the signer hint an exporting daemon writes.
fn bundle() -> ResultBundle {
    let output = BundleOutput::from_bytes("art-1", "response", "text/plain", RESPONSE);
    let manifest = ResultManifest::assemble(
        ManifestHeader {
            task_id: "task-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            contract_id: "3f2a1b4c-9d8e-4f70-a1b2-c3d4e5f60718".to_owned(),
            contract_revision: 0,
            contract_digest: "a".repeat(64),
            attempt_digest: "b".repeat(64),
            work_order_receipt_digest: "c".repeat(64),
        },
        vec![OutputEntry {
            role: output.role.clone(),
            artifact_id: output.artifact_id.clone(),
            part_index: 0,
            media_type: output.media_type.clone(),
            byte_length: output.byte_length,
            sha256: output.sha256.clone(),
        }],
        vec![],
        vec![],
        vec![],
    );
    let envelope = manifest.sign(&key()).unwrap();
    let signer = SignerHint {
        issuer: "iss".to_owned(),
        agent: "performer".to_owned(),
        root_thumbprint: "root-thumb".to_owned(),
        task_result_public_key_hex: key_hex(),
        task_result_thumbprint: key().verifying().thumbprint(),
    };
    ResultBundle::assemble("task-1", envelope, vec![output], Some(signer))
}

/// Writes `contents` under a unique name in a per-test temp dir and returns the path.
fn write_file(name: &str, contents: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("akson-verify-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn write_bundle(name: &str, bundle: &ResultBundle) -> PathBuf {
    write_file(name, &serde_json::to_vec_pretty(bundle).unwrap())
}

/// Runs `akson verify` with a scrubbed environment (no daemon rendezvous).
fn run_verify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_akson"))
        .arg("verify")
        .args(args)
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("AKSON_RUNTIME_DIR")
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_valid_bundle_verifies_under_a_pinned_key() {
    let path = write_bundle("valid.json", &bundle());
    let out = run_verify(&[path.to_str().unwrap(), "--signer", &key_hex()]);
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "expected success: {text}\n{}",
        stderr(&out)
    );
    assert!(text.contains("verified: task task-1"), "{text}");
    assert!(text.contains("pinned via --signer"), "{text}");
    // The honest report: every check states both sides.
    assert!(text.contains("establishes"), "{text}");
    assert!(text.contains("does not"), "{text}");
    assert!(!text.contains("UNPINNED"), "{text}");
}

#[test]
fn without_a_pinned_key_the_report_says_unpinned() {
    let path = write_bundle("unpinned.json", &bundle());
    let out = run_verify(&[path.to_str().unwrap()]);
    let text = stdout(&out);
    assert!(out.status.success(), "{text}\n{}", stderr(&out));
    assert!(text.contains("UNPINNED"), "{text}");
    assert!(text.contains("not authorship"), "{text}");
}

#[test]
fn a_flipped_manifest_byte_fails_naming_the_signature() {
    let mut b = bundle();
    let mut payload = STANDARD.decode(&b.manifest_envelope.payload).unwrap();
    payload[0] ^= 0x01;
    b.manifest_envelope.payload = STANDARD.encode(payload);
    let path = write_bundle("flipped.json", &b);
    let out = run_verify(&[path.to_str().unwrap(), "--signer", &key_hex()]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("FAIL signature"), "{text}");
    assert!(text.contains("signature verification failed"), "{text}");
    assert!(!text.contains("verified: task"), "{text}");
}

#[test]
fn a_swapped_output_fails_naming_the_digest_mismatch() {
    let mut b = bundle();
    b.outputs[0].content_base64 = STANDARD.encode(b"reviewed: SHIP IT");
    let path = write_bundle("swapped.json", &b);
    let out = run_verify(&[path.to_str().unwrap(), "--signer", &key_hex()]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("FAIL outputs"), "{text}");
    assert!(text.contains("does not re-hash"), "{text}");
    assert!(
        text.contains("art-1"),
        "the failing artifact must be named: {text}"
    );
}

#[test]
fn the_wrong_peer_key_is_refused() {
    let path = write_bundle("wrongkey.json", &bundle());
    let wrong = PurposeKey::from_seed(KeyPurpose::TaskResult, &[9u8; 32]);
    let wrong_hex = hex::encode(wrong.verifying().to_public_bytes());
    let out = run_verify(&[path.to_str().unwrap(), "--signer", &wrong_hex]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("FAIL signature"), "{text}");
    assert!(!text.contains("verified: task"), "{text}");
}

#[test]
fn a_truncated_bundle_is_refused_never_a_panic() {
    let bytes = serde_json::to_vec_pretty(&bundle()).unwrap();
    let path = write_file("truncated.json", &bytes[..bytes.len() / 2]);
    let out = run_verify(&[path.to_str().unwrap(), "--signer", &key_hex()]);
    let text = stdout(&out);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{text}\n{err}");
    assert!(text.contains("FAIL bundle"), "{text}");
    assert!(!err.contains("panicked"), "must refuse, not panic: {err}");
}

#[test]
fn an_identity_token_as_signer_is_explained_not_accepted() {
    let path = write_bundle("token-signer.json", &bundle());
    let out = run_verify(&[
        path.to_str().unwrap(),
        "--signer",
        "akson1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7lykl4d",
    ]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("ROOT key"), "{err}");
    assert!(err.contains("task-result key"), "{err}");
}

#[test]
fn a_missing_signer_key_everywhere_is_a_refusal() {
    let mut b = bundle();
    b.signer = None;
    let path = write_bundle("no-signer.json", &b);
    let out = run_verify(&[path.to_str().unwrap()]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("FAIL signature"), "{text}");
    assert!(text.contains("--signer"), "{text}");
}
