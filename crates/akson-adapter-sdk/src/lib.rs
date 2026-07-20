//! The library an akson worker/adapter links to (design §16.3). An adapter runs
//! *inside* the sandbox as the performer's worker: it reads exactly the task-bound
//! inputs the operator approved, may call a model **only** through the broker (never
//! the network directly), and writes a bounded response — nothing else is reachable,
//! because the sandbox does not construct it.
//!
//! What you write:
//!
//! ```no_run
//! # fn prompt(_: &[u8]) -> String { String::new() }
//! use akson_adapter_sdk::Task;
//! let mut task = Task::load()?;                         // /inputs + AKSON_BROKER_FD
//! let diff = task.read("diff")?;                        // the approved input's bytes
//! let reply = task.call_model("reviewer", &prompt(&diff))?; // broker → daemon → model
//! task.respond(reply["body"].as_str().unwrap_or("").as_bytes())?; // /output/response
//! # Ok::<(), akson_adapter_sdk::Error>(())
//! ```
//!
//! The plumbing — reading the input manifest, the broker wire protocol, and the
//! output paths — is the SDK's job; the adapter only expresses intent.

#![allow(unsafe_code)] // one spot: adopting the inherited broker fd (documented below).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub mod conformance;
pub mod proxy;

/// The in-sandbox root the approved inputs are bound at (design §13.1).
const INPUT_ROOT: &str = "/inputs";
/// The in-sandbox root the worker's outputs are collected from.
const OUTPUT_ROOT: &str = "/output";
/// The environment variable naming the inherited broker fd (set only when the work
/// order granted `processor_use`).
const BROKER_FD_ENV: &str = "AKSON_BROKER_FD";

/// One approved input, as named in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Input {
    pub id: String,
    /// The in-sandbox path the input is staged at (informational; use [`Task::read`]).
    pub path: String,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    inputs: Vec<Input>,
}

/// Why an adapter operation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("the input manifest could not be parsed: {0}")]
    Manifest(serde_json::Error),
    #[error("no input named {0:?} was approved for this task")]
    UnknownInput(String),
    #[error("artifact role {0:?} is not a safe slug ([a-z0-9][a-z0-9-]*)")]
    UnsafeArtifactRole(String),
    #[error("input {id:?} does not match its manifest digest (expected {expected}, got {got})")]
    InputDigestMismatch {
        id: String,
        expected: String,
        got: String,
    },
    #[error("this task was not granted processor use; no model is reachable")]
    NoModelGrant,
    #[error("the {0} environment value is not a valid file descriptor")]
    BadBrokerFd(String),
    #[error("the broker channel closed before a reply arrived")]
    BrokerClosed,
    #[error("the broker reply was not valid JSON: {0}")]
    BrokerReply(serde_json::Error),
}

/// The task an adapter is running: its approved inputs, its writable output, and —
/// when granted — a brokered model channel.
pub struct Task {
    inputs: Vec<Input>,
    input_root: PathBuf,
    output_root: PathBuf,
    broker: Option<Broker>,
}

impl Task {
    /// Loads the task from the sandbox conventions: the manifest at
    /// `/inputs/manifest.json`, `/output` for results, and the broker fd from
    /// `AKSON_BROKER_FD` if `processor_use` was granted.
    ///
    /// The input/output roots default to `/inputs` and `/output` but honor
    /// `AKSON_INPUT_ROOT` / `AKSON_OUTPUT_ROOT`, which the conformance harness sets to
    /// run an adapter against a fixture outside the sandbox. In production the daemon
    /// leaves them unset, so the roots are the fixed in-sandbox mounts.
    pub fn load() -> Result<Self, Error> {
        let broker = match std::env::var(BROKER_FD_ENV) {
            Ok(v) => {
                let fd: i32 = v.parse().map_err(|_| Error::BadBrokerFd(v.clone()))?;
                Some(Broker::adopt(fd)?)
            }
            Err(_) => None,
        };
        let input_root =
            std::env::var("AKSON_INPUT_ROOT").unwrap_or_else(|_| INPUT_ROOT.to_owned());
        let output_root =
            std::env::var("AKSON_OUTPUT_ROOT").unwrap_or_else(|_| OUTPUT_ROOT.to_owned());
        Self::from_parts(Path::new(&input_root), Path::new(&output_root), broker)
    }

    /// Loads from explicit directories (for tests / non-standard layouts). `broker`
    /// is an already-connected stream to the daemon, or `None`.
    pub fn from_dirs(
        input_root: &Path,
        output_root: &Path,
        broker: Option<UnixStream>,
    ) -> Result<Self, Error> {
        let broker = match broker {
            Some(s) => Some(Broker::new(s)?),
            None => None,
        };
        Self::from_parts(input_root, output_root, broker)
    }

    fn from_parts(
        input_root: &Path,
        output_root: &Path,
        broker: Option<Broker>,
    ) -> Result<Self, Error> {
        let raw = std::fs::read(input_root.join("manifest.json"))?;
        let manifest: Manifest = serde_json::from_slice(&raw).map_err(Error::Manifest)?;
        Ok(Task {
            inputs: manifest.inputs,
            input_root: input_root.to_path_buf(),
            output_root: output_root.to_path_buf(),
            broker,
        })
    }

    /// The approved inputs, in manifest order.
    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    /// Whether this task may call a model (i.e. `processor_use` was granted).
    pub fn can_call_model(&self) -> bool {
        self.broker.is_some()
    }

    /// Reads an approved input by id and verifies it against its manifest digest.
    /// Fails if the id was not approved — an adapter can only read the exact set the
    /// operator allowed.
    pub fn read(&self, id: &str) -> Result<Vec<u8>, Error> {
        let entry = self
            .inputs
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| Error::UnknownInput(id.to_owned()))?;
        let bytes = std::fs::read(self.input_root.join(id))?;
        let got = hex::encode(Sha256::digest(&bytes));
        if got != entry.sha256 {
            return Err(Error::InputDigestMismatch {
                id: id.to_owned(),
                expected: entry.sha256.clone(),
                got,
            });
        }
        Ok(bytes)
    }

    /// Calls a model through the broker (design §13.1): the request crosses the one
    /// inherited fd to the daemon, which makes the real, credential-injected,
    /// budgeted call and returns its result. Fails closed if `processor_use` was not
    /// granted — there is no model to reach.
    pub fn call_model(
        &mut self,
        processor_id: &str,
        request: &str,
    ) -> Result<serde_json::Value, Error> {
        let broker = self.broker.as_mut().ok_or(Error::NoModelGrant)?;
        broker.call(processor_id, request)
    }

    /// Writes the worker's response to `/output/response`. The gateway gates it
    /// against the granted scope (recipient, byte budget) before delivering it — the
    /// adapter cannot choose a recipient or exceed the budget here.
    pub fn respond(&self, body: &[u8]) -> Result<(), Error> {
        std::fs::write(self.output_root.join("response"), body)?;
        Ok(())
    }

    /// Emits a bounded artifact (e.g. SARIF findings) under `role`, recording its
    /// media type in `/output/artifacts.json`. The gateway gates every artifact
    /// against the `artifact_export` grant (media type in the allowed set, count,
    /// byte budget, recipient) before it is delivered — this only proposes one.
    /// `role` must be a slug (`[a-z0-9][a-z0-9-]*`), so it cannot escape `/output`.
    pub fn write_artifact(&self, role: &str, media_type: &str, bytes: &[u8]) -> Result<(), Error> {
        if !is_slug(role) {
            return Err(Error::UnsafeArtifactRole(role.to_owned()));
        }
        let dir = self.output_root.join("artifacts");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(role), bytes)?;

        // Append to the manifest the gateway reads to learn each artifact's media
        // type (read-modify-write; one adapter, single-threaded).
        let manifest = self.output_root.join("artifacts.json");
        let mut entries: Vec<ArtifactEntry> = match std::fs::read(&manifest) {
            Ok(raw) => serde_json::from_slice(&raw).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        entries.retain(|e| e.role != role);
        entries.push(ArtifactEntry {
            role: role.to_owned(),
            media_type: media_type.to_owned(),
        });
        std::fs::write(
            &manifest,
            serde_json::to_vec(&entries).map_err(Error::Manifest)?,
        )?;
        Ok(())
    }
}

/// One artifact the worker produced, as listed in `/output/artifacts.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtifactEntry {
    pub role: String,
    pub media_type: String,
}

/// Whether `s` is a slug (`[a-z0-9][a-z0-9-]*`) — a safe single path component.
fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The adapter's side of the broker channel.
struct Broker {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Broker {
    /// Adopts the inherited broker fd.
    fn adopt(fd: i32) -> Result<Self, Error> {
        use std::os::fd::FromRawFd;
        // SAFETY: `fd` is the broker end the gateway created and passed to this
        // worker via `AKSON_BROKER_FD` (an already-connected AF_UNIX socket); the
        // worker is its sole owner inside the sandbox. Adopted exactly once.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        Self::new(stream)
    }

    fn new(stream: UnixStream) -> Result<Self, Error> {
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Broker {
            writer: stream,
            reader,
        })
    }

    fn call(&mut self, processor_id: &str, request: &str) -> Result<serde_json::Value, Error> {
        let line = serde_json::to_vec(&serde_json::json!({
            "processor_id": processor_id,
            "request": request,
        }))
        .map_err(Error::BrokerReply)?;
        self.writer.write_all(&line)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;

        let mut reply = String::new();
        if self.reader.read_line(&mut reply)? == 0 {
            return Err(Error::BrokerClosed);
        }
        serde_json::from_str(reply.trim()).map_err(Error::BrokerReply)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn stage(dir: &Path, id: &str, bytes: &[u8]) {
        std::fs::write(dir.join(id), bytes).unwrap();
        let manifest = serde_json::json!({
            "inputs": [{
                "id": id,
                "path": format!("/inputs/{id}"),
                "media_type": "text/plain",
                "byte_length": bytes.len(),
                "sha256": hex::encode(Sha256::digest(bytes)),
            }]
        });
        std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
    }

    #[test]
    fn reads_an_approved_input_and_writes_a_response() {
        let input = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        stage(input.path(), "diff", b"the diff");

        let task = Task::from_dirs(input.path(), output.path(), None).unwrap();
        assert_eq!(task.inputs().len(), 1);
        assert_eq!(task.read("diff").unwrap(), b"the diff");
        task.respond(b"reviewed").unwrap();
        assert_eq!(
            std::fs::read(output.path().join("response")).unwrap(),
            b"reviewed"
        );
    }

    #[test]
    fn writes_an_artifact_and_records_its_media_type() {
        let input = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        stage(input.path(), "diff", b"x");
        let task = Task::from_dirs(input.path(), output.path(), None).unwrap();

        task.write_artifact("findings", "application/sarif+json", b"{\"runs\":[]}")
            .unwrap();
        assert_eq!(
            std::fs::read(output.path().join("artifacts").join("findings")).unwrap(),
            b"{\"runs\":[]}"
        );
        let manifest: Vec<ArtifactEntry> =
            serde_json::from_slice(&std::fs::read(output.path().join("artifacts.json")).unwrap())
                .unwrap();
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].role, "findings");
        assert_eq!(manifest[0].media_type, "application/sarif+json");

        // A traversing role is refused.
        assert!(matches!(
            task.write_artifact("../escape", "text/plain", b"x"),
            Err(Error::UnsafeArtifactRole(_))
        ));
    }

    #[test]
    fn an_unapproved_input_cannot_be_read() {
        let input = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        stage(input.path(), "diff", b"x");
        let task = Task::from_dirs(input.path(), output.path(), None).unwrap();
        assert!(matches!(
            task.read("secrets"),
            Err(Error::UnknownInput(id)) if id == "secrets"
        ));
    }

    #[test]
    fn a_tampered_input_fails_the_digest_check() {
        let input = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        stage(input.path(), "diff", b"original");
        // Overwrite the staged file after the manifest was written.
        std::fs::write(input.path().join("diff"), b"tampered").unwrap();
        let task = Task::from_dirs(input.path(), output.path(), None).unwrap();
        assert!(matches!(
            task.read("diff"),
            Err(Error::InputDigestMismatch { .. })
        ));
    }

    #[test]
    fn calling_a_model_without_the_grant_fails_closed() {
        let input = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        stage(input.path(), "diff", b"x");
        let mut task = Task::from_dirs(input.path(), output.path(), None).unwrap();
        assert!(!task.can_call_model());
        assert!(matches!(
            task.call_model("reviewer", "hi"),
            Err(Error::NoModelGrant)
        ));
    }

    #[test]
    fn a_brokered_model_call_round_trips_over_the_channel() {
        let input = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        stage(input.path(), "diff", b"x");

        // A stand-in daemon end: read one request, answer with a canned reply.
        let (worker_end, daemon_end) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut daemon = daemon_end;
            let mut reader = BufReader::new(daemon.try_clone().unwrap());
            let mut req = String::new();
            reader.read_line(&mut req).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(req.trim()).unwrap();
            assert_eq!(parsed["processor_id"], "reviewer");
            daemon
                .write_all(b"{\"status\":200,\"body\":\"looks good\"}\n")
                .unwrap();
            req
        });

        let mut task = Task::from_dirs(input.path(), output.path(), Some(worker_end)).unwrap();
        assert!(task.can_call_model());
        let reply = task.call_model("reviewer", "review this").unwrap();
        assert_eq!(reply["status"], 200);
        assert_eq!(reply["body"], "looks good");
        let sent = handle.join().unwrap();
        assert!(sent.contains("review this"));
    }
}
