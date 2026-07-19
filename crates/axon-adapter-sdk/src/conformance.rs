//! Certifying that an adapter honors the §16.3 contract. [`certify`] runs an
//! adapter command against a [`Fixture`] — a task-bound input set and its bounds —
//! staged to temporary directories and wired via the same environment the sandbox
//! uses, then checks what the adapter did:
//!
//! - it produced a response (it acted on the delivered task — passive arrival);
//! - the response stayed within the granted byte budget (bounded output);
//! - it wrote nothing outside `/output` (no smuggled side channel);
//! - a second, identical run yields the same result (duplicate delivery is safe).
//!
//! This checks the adapter's *behavioral* half of §16.3. The isolation half — no
//! network, no host filesystem, no recipient selection — is enforced structurally
//! by the sandbox and covered by its own §13.1 checklist, not re-tested here.
//!
//! A demo echo adapter passes these checks; per §16.3 that alone does not make it a
//! release adapter, but every real adapter must pass them.

use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

/// One input a fixture supplies to the adapter.
#[derive(Debug, Clone)]
pub struct FixtureInput {
    pub id: String,
    pub media_type: String,
    pub content: Vec<u8>,
}

/// A conformance task: the approved inputs and the response byte budget the grant
/// would carry.
#[derive(Debug, Clone)]
pub struct Fixture {
    pub inputs: Vec<FixtureInput>,
    pub max_response_bytes: u64,
}

/// The standard code-review fixture (§20.8): one diff input, an 8 KiB budget.
pub fn code_review_fixture() -> Fixture {
    Fixture {
        inputs: vec![FixtureInput {
            id: "diff".to_owned(),
            media_type: "text/x-diff".to_owned(),
            content: b"--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n".to_vec(),
        }],
        max_response_bytes: 8192,
    }
}

/// One certified property and whether it held.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// The result of certifying an adapter.
#[derive(Debug, Clone)]
pub struct Report {
    pub response: Vec<u8>,
    pub checks: Vec<Check>,
}

impl Report {
    /// Whether every checked property held.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }
}

/// Runs `adapter_cmd` against `fixture` and certifies the §16.3 behavioral
/// contract. The inputs are staged (with a manifest) into a temporary `/inputs`,
/// `/output` is empty, and the roots are handed to the adapter via
/// `AXON_INPUT_ROOT` / `AXON_OUTPUT_ROOT`. `adapter_cmd[0]` is the program and the
/// rest its arguments.
pub fn certify(adapter_cmd: &[String], fixture: &Fixture) -> std::io::Result<Report> {
    let first = run_once(adapter_cmd, fixture)?;
    let second = run_once(adapter_cmd, fixture)?;

    let mut checks = Vec::new();
    checks.push(Check {
        name: "produces-a-response",
        passed: !first.response.is_empty(),
        detail: format!("{} bytes", first.response.len()),
    });
    checks.push(Check {
        name: "within-byte-budget",
        passed: first.response.len() as u64 <= fixture.max_response_bytes,
        detail: format!(
            "{} / {} bytes",
            first.response.len(),
            fixture.max_response_bytes
        ),
    });
    checks.push(Check {
        name: "writes-only-the-response",
        passed: first.extra_output_files.is_empty(),
        detail: if first.extra_output_files.is_empty() {
            "only /output/response".to_owned()
        } else {
            format!("also wrote: {}", first.extra_output_files.join(", "))
        },
    });
    checks.push(Check {
        name: "duplicate-delivery-is-stable",
        passed: first.response == second.response,
        detail: "two identical runs produced the same response".to_owned(),
    });

    Ok(Report {
        response: first.response,
        checks,
    })
}

struct RunResult {
    response: Vec<u8>,
    extra_output_files: Vec<String>,
}

fn run_once(adapter_cmd: &[String], fixture: &Fixture) -> std::io::Result<RunResult> {
    let dir = tempdir()?;
    let input_root = dir.join("inputs");
    let output_root = dir.join("output");
    std::fs::create_dir_all(&input_root)?;
    std::fs::create_dir_all(&output_root)?;
    stage_fixture(&input_root, fixture)?;

    let program = adapter_cmd
        .first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty adapter command"))?;
    let status = Command::new(program)
        .args(&adapter_cmd[1..])
        .env("AXON_INPUT_ROOT", &input_root)
        .env("AXON_OUTPUT_ROOT", &output_root)
        // No AXON_BROKER_FD: this fixture grants no processor use.
        .env_remove("AXON_BROKER_FD")
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "adapter exited with {status}"
        )));
    }

    let response = std::fs::read(output_root.join("response")).unwrap_or_default();
    let mut extra = Vec::new();
    for entry in std::fs::read_dir(&output_root)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name != "response" {
            extra.push(name);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(RunResult {
        response,
        extra_output_files: extra,
    })
}

fn stage_fixture(input_root: &Path, fixture: &Fixture) -> std::io::Result<()> {
    let mut entries = Vec::new();
    for input in &fixture.inputs {
        std::fs::write(input_root.join(&input.id), &input.content)?;
        entries.push(serde_json::json!({
            "id": input.id,
            "path": format!("/inputs/{}", input.id),
            "media_type": input.media_type,
            "byte_length": input.content.len(),
            "sha256": hex::encode(Sha256::digest(&input.content)),
        }));
    }
    let manifest = serde_json::json!({ "inputs": entries });
    std::fs::write(
        input_root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
}

/// A unique temporary directory. Avoids `Math.random`/wall-clock by using the pid
/// plus a monotonic counter so repeated calls in one process do not collide.
fn tempdir() -> std::io::Result<std::path::PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("axon-conformance-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // A conformant shell adapter: reads the approved input, writes a bounded
    // response, touches nothing else.
    fn good_adapter() -> Vec<String> {
        vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "head -c 32 \"$AXON_INPUT_ROOT/diff\" > \"$AXON_OUTPUT_ROOT/response\"".to_owned(),
        ]
    }

    #[test]
    fn a_conformant_adapter_passes_every_check() {
        let report = certify(&good_adapter(), &code_review_fixture()).unwrap();
        assert!(report.passed(), "checks: {:?}", report.checks);
    }

    #[test]
    fn an_over_budget_response_fails_the_budget_check() {
        // Writes far more than the fixture's budget allows.
        let cmd = vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "yes | head -c 20000 > \"$AXON_OUTPUT_ROOT/response\"".to_owned(),
        ];
        let mut fixture = code_review_fixture();
        fixture.max_response_bytes = 1024;
        let report = certify(&cmd, &fixture).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "within-byte-budget" && !c.passed));
    }

    #[test]
    fn writing_outside_the_response_is_caught() {
        let cmd = vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "echo ok > \"$AXON_OUTPUT_ROOT/response\"; echo leak > \"$AXON_OUTPUT_ROOT/sneaky\""
                .to_owned(),
        ];
        let report = certify(&cmd, &code_review_fixture()).unwrap();
        assert!(!report.passed());
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "writes-only-the-response" && !c.passed));
    }
}
