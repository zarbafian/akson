//! Worker input staging (design §7.2 step 9, §13.1): materialising exactly the
//! approved inputs into a directory the sandbox mounts read-only.
//!
//! The worker "receives only the exact approved A2A Parts" (§13.1). The daemon
//! resolves each worker-visible input to its canonical bytes (text → exact UTF-8,
//! data → RFC 8785 JSON — the same rule the contract manifest digested), then
//! [`stage_inputs`] writes each to `staging_dir/<id>` and a `manifest.json` the
//! worker reads. The daemon read-only-binds `staging_dir` at `sandbox_input_root`,
//! so the worker sees those inputs and nothing else. Each staged entry carries its
//! SHA-256 so the worker can re-verify what it reads.
//!
//! What you write:
//! ```no_run
//! use axon_worker::{stage_inputs, StageItem};
//! # let dir = std::path::Path::new("/run/axon/task-1/inputs");
//! let items = vec![StageItem {
//!     id: "diff".into(),
//!     media_type: "text/x-diff".into(),
//!     content: b"--- a\n+++ b\n".to_vec(),
//! }];
//! let staged = stage_inputs(&items, dir, "/inputs").unwrap();
//! assert_eq!(staged.manifest[0].path, "/inputs/diff");
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// One resolved input to stage: its logical id, media type, and canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageItem {
    pub id: String,
    pub media_type: String,
    pub content: Vec<u8>,
}

/// A staged input as the worker sees it (path is inside the sandbox).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StagedInput {
    pub id: String,
    /// The path inside the sandbox (under `sandbox_input_root`).
    pub path: String,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: String,
}

/// The result of staging: the host directory to read-only-bind and the manifest
/// (also written as `manifest.json` in the directory).
#[derive(Debug, Clone)]
pub struct StagedInputs {
    pub dir: PathBuf,
    pub manifest: Vec<StagedInput>,
}

#[derive(Debug, Serialize)]
struct Manifest<'a> {
    inputs: &'a [StagedInput],
}

/// Why staging failed.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    #[error("input id {0:?} is not a safe filename (slug required, no path separators)")]
    UnsafeId(String),
    #[error("duplicate input id {0:?}")]
    DuplicateId(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serializing the input manifest: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Whether `id` is a safe input filename: a slug (`[a-z0-9][a-z0-9-]*`), so it can
/// never traverse out of the staging directory.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Writes each approved input to `staging_dir/<id>` and a `manifest.json`,
/// returning the manifest with in-sandbox paths under `sandbox_input_root`.
///
/// Fails closed on an unsafe id (path traversal) or a duplicate id — the worker
/// must receive exactly the approved set, unambiguously. Every file is created
/// with `O_CREAT|O_EXCL`, so staging never follows a symlink at the target and
/// never overwrites a pre-existing file: a non-pristine staging directory is
/// refused rather than written through.
pub fn stage_inputs(
    items: &[StageItem],
    staging_dir: &Path,
    sandbox_input_root: &str,
) -> Result<StagedInputs, StageError> {
    std::fs::create_dir_all(staging_dir)?;
    let root = sandbox_input_root.trim_end_matches('/');

    let mut manifest = Vec::with_capacity(items.len());
    for item in items {
        if !is_safe_id(&item.id) {
            return Err(StageError::UnsafeId(item.id.clone()));
        }
        if manifest.iter().any(|s: &StagedInput| s.id == item.id) {
            return Err(StageError::DuplicateId(item.id.clone()));
        }
        write_new(&staging_dir.join(&item.id), &item.content)?;
        manifest.push(StagedInput {
            id: item.id.clone(),
            path: format!("{root}/{}", item.id),
            media_type: item.media_type.clone(),
            byte_length: item.content.len() as u64,
            sha256: hex::encode(Sha256::digest(&item.content)),
        });
    }

    let json = serde_json::to_vec_pretty(&Manifest { inputs: &manifest })?;
    write_new(&staging_dir.join("manifest.json"), &json)?;
    Ok(StagedInputs {
        dir: staging_dir.to_path_buf(),
        manifest,
    })
}

/// Creates `path` with `O_CREAT|O_EXCL` and writes `content`. `create_new` refuses
/// a pre-existing file and refuses to follow a symlink at the final component (the
/// `O_EXCL` guarantee), so a poisoned staging directory fails closed.
fn write_new(path: &Path, content: &[u8]) -> Result<(), std::io::Error> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(content)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn items() -> Vec<StageItem> {
        vec![
            StageItem {
                id: "diff".to_owned(),
                media_type: "text/x-diff".to_owned(),
                content: b"--- a\n+++ b\n".to_vec(),
            },
            StageItem {
                id: "config".to_owned(),
                media_type: "application/json".to_owned(),
                content: br#"{"a":1}"#.to_vec(),
            },
        ]
    }

    #[test]
    fn stages_files_manifest_and_digests() {
        let dir = std::env::temp_dir().join(format!("axon-stage-{}", std::process::id()));
        let staged = stage_inputs(&items(), &dir, "/inputs").unwrap();

        // Files written with exact bytes.
        assert_eq!(std::fs::read(dir.join("diff")).unwrap(), b"--- a\n+++ b\n");
        // Manifest: in-sandbox paths + correct digests + byte lengths.
        assert_eq!(staged.manifest[0].path, "/inputs/diff");
        assert_eq!(
            staged.manifest[0].sha256,
            hex::encode(Sha256::digest(b"--- a\n+++ b\n"))
        );
        assert_eq!(staged.manifest[1].byte_length, 7);
        // manifest.json is present and parses back to the same entries.
        let json = std::fs::read(dir.join("manifest.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed["inputs"][1]["id"], "config");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_unsafe_ids_and_duplicates() {
        let dir = std::env::temp_dir().join(format!("axon-stage-bad-{}", std::process::id()));
        for bad in ["../escape", "a/b", ".hidden", "Upper", ""] {
            let it = vec![StageItem {
                id: bad.to_owned(),
                media_type: "text/plain".to_owned(),
                content: b"x".to_vec(),
            }];
            assert!(
                matches!(
                    stage_inputs(&it, &dir, "/inputs"),
                    Err(StageError::UnsafeId(_))
                ),
                "id {bad:?} should be rejected"
            );
        }
        let dup = vec![
            StageItem {
                id: "x".into(),
                media_type: "t".into(),
                content: vec![1],
            },
            StageItem {
                id: "x".into(),
                media_type: "t".into(),
                content: vec![2],
            },
        ];
        assert!(matches!(
            stage_inputs(&dup, &dir, "/inputs"),
            Err(StageError::DuplicateId(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_to_overwrite_a_preexisting_target() {
        let dir = std::env::temp_dir().join(format!("axon-stage-poison-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Poison the staging dir with a file at the id path (stands in for a symlink
        // an attacker might plant): staging must refuse rather than write through.
        std::fs::write(dir.join("diff"), b"pre-existing").unwrap();
        let item = vec![StageItem {
            id: "diff".to_owned(),
            media_type: "text/plain".to_owned(),
            content: b"new".to_vec(),
        }];
        assert!(matches!(
            stage_inputs(&item, &dir, "/inputs"),
            Err(StageError::Io(_))
        ));
        // The pre-existing content is untouched (not written through).
        assert_eq!(std::fs::read(dir.join("diff")).unwrap(), b"pre-existing");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
