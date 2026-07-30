//! `akson verify <bundle>` — the offline consumer check of an exported result
//! bundle. No daemon, no store, no network: everything is established from the
//! file and the key the caller pins, and every check line prints what it
//! establishes **and what it does not** (the `docs/verifying-a-release.md`
//! discipline, applied to a task result).
//!
//! What you run:
//! ```text
//! akson verify akson-bundle-task-1.json --signer <64-hex task-result public key>
//! ```
//!
//! The checks, in order, each fail-closed (the first failure ends the run):
//!
//! 1. **bundle** — the file parses as one versioned `akson-result-bundle` within
//!    this build's caps.
//! 2. **signature** — the DSSE envelope over the result manifest verifies under
//!    the task-result key: `--signer` pins it (authorship relative to that key);
//!    without `--signer` the key the bundle itself carries is used, and the
//!    report says plainly that this proves consistency, not authorship.
//! 3. **manifest** — the signed payload is exactly one canonical, schema-valid,
//!    canonically-ordered `result-manifest-v1`; its digest is *the* bundle digest.
//! 4. **outputs** — every output the manifest names is carried exactly once and
//!    re-hashes to the signed digest and length; nothing rides along unsigned.
//! 5. **findings** — every SARIF-typed output parses as SARIF 2.1.0 under the
//!    hostile-input caps.
//!
//! The heavy lifting is `akson_evidence::ResultBundle::verify`; this module owns
//! only the argument handling and the honest report.

use std::process::ExitCode;

use akson_crypto::keypair::PurposeVerifyingKey;
use akson_crypto::purpose::KeyPurpose;
use akson_evidence::{BundleError, ManifestError, ResultBundle, VerifiedBundle, MAX_BUNDLE_BYTES};

/// Runs the offline verification and prints the report. Exit codes: `0` fully
/// verified, `1` any check failed or the file was refused, `2` unusable
/// arguments.
pub fn run(path: &str, signer: Option<&str>) -> ExitCode {
    // The pinned key is parsed before the file is touched: an unusable --signer
    // is an argument error, not a verification verdict.
    let pinned = match signer.map(parse_signer).transpose() {
        Ok(k) => k,
        Err(msg) => {
            eprintln!("akson verify: {msg}");
            return ExitCode::from(2);
        }
    };

    // Cap before read: a huge file is refused without buffering it.
    match std::fs::metadata(path) {
        Ok(md) if md.len() > MAX_BUNDLE_BYTES as u64 => {
            eprintln!(
                "akson verify: refusing {path}: the file is {} bytes, over the {MAX_BUNDLE_BYTES}-byte bundle cap",
                md.len()
            );
            return ExitCode::from(1);
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("akson verify: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("akson verify: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };

    println!("akson verify — result bundle {path}");
    println!();

    let bundle = match ResultBundle::from_slice(&bytes) {
        Ok(b) => b,
        Err(e) => {
            fail("bundle", &e.to_string());
            return ExitCode::from(1);
        }
    };
    check(
        "bundle",
        &format!(
            "well-formed akson-result-bundle v{}: task {}, {} output{}",
            bundle.schema_version,
            bundle.task_id,
            bundle.outputs.len(),
            plural(bundle.outputs.len()),
        ),
    );
    establishes("the file is one self-consistent, versioned bundle within this build's caps");
    does_not("who produced it, or that anything in it is attested — the checks below do that");

    // The verification key: pinned by the caller, or the bundle's own hint.
    let (key, key_is_pinned) = match &pinned {
        Some(k) => (k.clone(), true),
        None => match embedded_key(&bundle) {
            Ok(k) => (k, false),
            Err(msg) => {
                fail("signature", &msg);
                return ExitCode::from(1);
            }
        },
    };

    let verified = match bundle.verify(&key) {
        Ok(v) => v,
        Err(e) => {
            fail(failed_check(&e), &e.to_string());
            return ExitCode::from(1);
        }
    };

    report(&bundle, &verified, &key, key_is_pinned);
    ExitCode::SUCCESS
}

/// Prints the full per-check report of a bundle every check accepted.
fn report(
    bundle: &ResultBundle,
    verified: &VerifiedBundle,
    key: &PurposeVerifyingKey,
    key_is_pinned: bool,
) {
    let manifest = &verified.manifest;

    if key_is_pinned {
        check(
            "signature",
            &format!(
                "result manifest signed by task-result key {} (pinned via --signer)",
                key.thumbprint()
            ),
        );
        establishes("the holder of the key YOU pinned signed exactly this manifest — nobody else could have");
        does_not(
            "that the work ran in a sandbox, that the outputs are correct, or when it was signed",
        );
    } else {
        check(
            "signature",
            &format!(
                "result manifest verifies under the key the bundle itself carries ({}) — UNPINNED",
                key.thumbprint()
            ),
        );
        establishes("internal consistency only — a bundle can carry any key it likes");
        does_not("authorship; pin the peer's task-result key with --signer to establish that");
    }

    check(
        "manifest",
        &format!(
            "canonical result-manifest-v1; bundle digest sha256:{}",
            verified.bundle_digest
        ),
    );
    establishes("the signed statement is exactly one schema-valid, canonically ordered manifest; a requester outcome for this task binds exactly this digest");
    does_not("the truth of its header bindings — the contract, attempt, and work-order fields are digests of records this bundle does not carry");

    check(
        "outputs",
        &format!(
            "{n}/{n} named output{p} present; {b} B re-hash to the signed digests",
            n = manifest.outputs.len(),
            p = plural(manifest.outputs.len()),
            b = verified.payload_bytes,
        ),
    );
    establishes("the payload is byte-for-byte what the signer attested — nothing added, altered, or missing");
    does_not("that the bytes are useful, safe, or produced by any particular process");

    if verified.sarif.is_empty() {
        info("findings", "no SARIF outputs — nothing to check");
    } else {
        for s in &verified.sarif {
            let truncated = if s.truncated_findings > 0 {
                format!(
                    " (+{} beyond the cap, counted not shown)",
                    s.truncated_findings
                )
            } else {
                String::new()
            };
            check(
                "findings",
                &format!(
                    "{} parses as SARIF 2.1.0 within caps: tool {:?}, {} finding{}{}",
                    s.role,
                    s.tool_name,
                    s.findings,
                    plural(s.findings),
                    truncated,
                ),
            );
        }
        establishes("the findings artifacts are structurally SARIF, bounded by this build's caps");
        does_not("that the findings are true, complete, or actually produced by the named tool");
    }

    if !manifest.slots.is_empty() {
        for slot in &manifest.slots {
            info(
                "slots",
                &format!(
                    "slot {}: {:?} ({:?} disclosure)",
                    slot.slot_id, slot.result, slot.disclosure
                ),
            );
        }
        establishes("what the signer CLAIMS each required evidence slot produced (a redacted view can never turn a failure into a pass — result and disclosure are orthogonal)");
        does_not("the slot results themselves — the evidence behind them is referenced by digest and not carried in this bundle");
    }
    if !manifest.evidence.is_empty() {
        info(
            "evidence",
            &format!(
                "{} evidence statement{} referenced by digest — not carried in this bundle; nothing about them is established here",
                manifest.evidence.len(),
                plural(manifest.evidence.len()),
            ),
        );
    }
    if !manifest.omissions.is_empty() {
        for o in &manifest.omissions {
            info(
                "omissions",
                &format!(
                    "the signer declared {} omitted ({})",
                    o.subject, o.reason_code
                ),
            );
        }
    }

    println!();
    println!(
        "verified: task {}  bundle digest sha256:{}",
        manifest.header.task_id, verified.bundle_digest
    );
    if let Some(signer) = &bundle.signer {
        println!(
            "  the bundle claims (unverified hint): signed by {}/{}  root {}",
            signer.issuer, signer.agent, signer.root_thumbprint
        );
    }
    if !key_is_pinned {
        println!("  NOTE: the key was UNPINNED — this run proves consistency, not authorship.");
    }
}

/// Parses `--signer`: the peer's 64-hex-character Ed25519 task-result public
/// key. An identity token is refused with the reason — it names the wrong key.
fn parse_signer(arg: &str) -> Result<PurposeVerifyingKey, String> {
    if arg.starts_with("akson1") {
        return Err(
            "--signer got an identity token, which names the peer's ROOT key; result manifests \
             are signed by the peer's task-result key. Use the 64-hex key that `akson task export` \
             prints on the exporting endpoint, and compare its thumbprint over a channel you trust."
                .to_owned(),
        );
    }
    let bytes = hex::decode(arg)
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or_else(|| {
            "--signer must be the peer's task-result public key: 64 hex characters".to_owned()
        })?;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    PurposeVerifyingKey::from_public_bytes(KeyPurpose::TaskResult, &raw)
        .map_err(|_| "--signer is not a valid Ed25519 public key".to_owned())
}

/// The bundle's own signer hint, when no key was pinned.
fn embedded_key(bundle: &ResultBundle) -> Result<PurposeVerifyingKey, String> {
    let Some(signer) = &bundle.signer else {
        return Err(
            "the bundle carries no signer key and none was pinned — pass --signer <64-hex \
             task-result public key>"
                .to_owned(),
        );
    };
    parse_signer(&signer.task_result_public_key_hex).map_err(|_| {
        "the bundle's embedded signer key is not a valid Ed25519 public key".to_owned()
    })
}

/// Which report line a verification error belongs to, so a failure always names
/// its check.
fn failed_check(e: &BundleError) -> &'static str {
    match e {
        BundleError::Manifest(m) => match m {
            ManifestError::Dsse(_)
            | ManifestError::Key(_)
            | ManifestError::WrongPayloadType { .. } => "signature",
            _ => "manifest",
        },
        BundleError::Sarif { .. } => "findings",
        BundleError::TooLarge { .. }
        | BundleError::NotABundle(_)
        | BundleError::WrongFormat { .. }
        | BundleError::UnsupportedVersion { .. } => "bundle",
        _ => "outputs",
    }
}

fn check(name: &str, headline: &str) {
    println!("  ok  {name:<10} {headline}");
}

fn info(name: &str, headline: &str) {
    println!("  --  {name:<10} {headline}");
}

fn establishes(text: &str) {
    println!("      establishes    {text}");
}

fn does_not(text: &str) {
    println!("      does not       {text}");
}

fn fail(name: &str, detail: &str) {
    println!("  FAIL {name:<9} {detail}");
    println!("      nothing past this check can be established; the bundle is refused");
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}
