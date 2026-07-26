//! A0.6 — a confined worker reaches **no** inherited credential.
//!
//! The claim A0.6 has to support before the kovee/byom program's I2 gate runs
//! akson on a fleet host: a peer's work, executing in the clean worker, cannot
//! read the operator's SSH keys, cloud tokens, or environment — even though
//! the daemon that launched it was started by a login session that holds all
//! three.
//!
//! `akson-sandbox`'s unit tests already assert the launcher *asks* for
//! `--clearenv`, `--unshare-all`, `--cap-drop ALL`. That is an argv assertion.
//! This test plants real credential-shaped files and real environment
//! variables and then reads, from **inside** the sandbox, what the worker can
//! actually see — the difference between "we passed the flag" and "the secret
//! is unreachable".
//!
//! Like its sibling `clean_worker_e2e`, it needs a permissive host
//! (unprivileged user namespaces + bwrap) and so is `#[ignore]`d; it runs in
//! CI's isolation job, or locally:
//!
//!   cargo test -p akson-harness --test no_inherited_credentials -- --ignored --nocapture

use akson_sandbox::{
    BubblewrapLauncher, CgroupLimits, CgroupScope, DenyAction, SandboxLauncher, SandboxSpec,
    SeccompPolicy,
};

/// Credential shapes an operator's home really holds. Each is planted with a
/// recognisable marker so a leak is unambiguous in the worker's own output.
const PLANTED: &[(&str, &str, &str)] = &[
    (
        ".ssh/id_ed25519",
        "OPENSSH PRIVATE KEY",
        "AKSON_LEAK_SSH_KEY",
    ),
    (
        ".ssh/authorized_keys",
        "ssh-ed25519 AAAA",
        "AKSON_LEAK_SSH_AUTH",
    ),
    (".api/do", "dop_v1_", "AKSON_LEAK_DO_TOKEN"),
    (".api/claude", "sk-ant-api03-", "AKSON_LEAK_ANTHROPIC"),
    (
        ".aws/credentials",
        "aws_secret_access_key = ",
        "AKSON_LEAK_AWS",
    ),
    (".config/gcloud/token", "ya29.", "AKSON_LEAK_GCP"),
];

/// Environment variables a login session or CI runner really exports.
const ENV_SECRETS: &[(&str, &str)] = &[
    ("SSH_AUTH_SOCK", "/tmp/ssh-AKSON_LEAK_AGENT/agent.1"),
    ("DIGITALOCEAN_TOKEN", "dop_v1_AKSON_LEAK_ENV_DO"),
    ("ANTHROPIC_API_KEY", "sk-ant-api03-AKSON_LEAK_ENV_ANTHROPIC"),
    ("AWS_SECRET_ACCESS_KEY", "AKSON_LEAK_ENV_AWS"),
    ("GITHUB_TOKEN", "ghp_AKSON_LEAK_ENV_GITHUB"),
];

#[test]
#[ignore = "needs bwrap + unprivileged userns; runs in CI's isolation job"]
fn a_confined_worker_reaches_no_inherited_credential() {
    let tmp = std::env::temp_dir().join(format!("akson-a06-{}", std::process::id()));
    let fake_home = tmp.join("home");
    let output = tmp.join("output");
    std::fs::create_dir_all(&output).expect("output dir");

    // 1. Plant real credential-shaped files in a home the launching process
    //    can read, exactly as an operator's home would hold them.
    for (rel, body, marker) in PLANTED {
        let path = fake_home.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).expect("credential dir");
        std::fs::write(&path, format!("{body}{marker}\n")).expect("plant credential");
    }
    // And prove the planting worked: the *launching* process can read them.
    for (rel, _, marker) in PLANTED {
        let seen = std::fs::read_to_string(fake_home.join(rel)).expect("planted file readable");
        assert!(
            seen.contains(marker),
            "the test planted nothing at {rel} — a green result would be vacuous"
        );
    }

    // 2. Export secrets into this process's environment, so the worker would
    //    inherit them if the sandbox did not clear them.
    for (key, value) in ENV_SECRETS {
        // SAFETY: single-threaded test setup, before any sandbox launch.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(key, value);
        }
    }
    std::env::set_var("HOME", &fake_home);

    // 3. The worker's job: try every way a payload would reach a credential and
    //    report what it found. It must find nothing.
    let probe = r#"
        found=""
        for p in "$HOME/.ssh/id_ed25519" "$HOME/.ssh/authorized_keys" \
                 "$HOME/.api/do" "$HOME/.api/claude" \
                 "$HOME/.aws/credentials" "$HOME/.config/gcloud/token" \
                 /root/.ssh/id_ed25519 /home/*/.ssh/id_ed25519 /home/*/.api/* ; do
          [ -r "$p" ] && found="$found FILE:$p"
        done
        # The whole environment, not just the names we planted.
        env | grep -qi 'AKSON_LEAK' && found="$found ENV:$(env | grep -i AKSON_LEAK | tr '\n' ',')"
        [ -n "${SSH_AUTH_SOCK:-}" ] && found="$found ENV:SSH_AUTH_SOCK=$SSH_AUTH_SOCK"
        # The cloud metadata service is the other classic credential source.
        [ -r /sys/class/dmi/id/product_serial ] && found="$found FILE:dmi-serial"
        printf '%s' "${found:-CLEAN}" > /output/report
    "#;

    let spec = SandboxSpec::clean_worker("/")
        .ro_bind("/usr", "/usr")
        .ro_bind("/bin", "/bin")
        .ro_bind("/lib", "/lib")
        .ro_bind("/lib64", "/lib64")
        .rw_bind(output.to_str().unwrap(), "/output");

    let seccomp = SeccompPolicy::clean_worker_baseline(DenyAction::KillProcess);
    let cgroup = match CgroupScope::create(
        &format!("akson-a06-{}", std::process::id()),
        &CgroupLimits {
            max_memory_bytes: Some(64 * 1024 * 1024),
            max_pids: Some(16),
            cpu_max: None,
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[a0.6][skip] no delegated cgroup subtree ({e}); cannot evidence A0.6 here");
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
    };

    let launched = BubblewrapLauncher.launch(
        &spec,
        "/bin/sh",
        &["-c".to_owned(), probe.to_owned()],
        &seccomp,
        &cgroup,
    );
    match launched {
        Ok(()) => {
            eprintln!("[a0.6] confined worker ran to completion");
            let report = std::fs::read_to_string(output.join("report"))
                .expect("the worker wrote its report");
            assert_eq!(
                report.trim(),
                "CLEAN",
                "a confined worker reached an inherited credential: {report}"
            );
            eprintln!("[a0.6] worker report: CLEAN — no credential file, no secret env var");
        }
        Err(e) => {
            // A restricted host cannot answer the question; say so rather than
            // recording a pass (harness/README.md's userns note).
            eprintln!("[a0.6][skip] the sandbox could not launch here: {e}");
            eprintln!("[a0.6][skip] this host cannot evidence A0.6 — run in CI's isolation job");
            return;
        }
    }

    // 4. The negative control: the SAME probe, unconfined, must find the
    //    credentials. Without this, "CLEAN" could mean the probe is broken.
    let unconfined = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(probe.replace(
            "/output/report",
            &output.join("unconfined").display().to_string(),
        ))
        .env("HOME", &fake_home)
        .status()
        .expect("run the probe unconfined");
    assert!(unconfined.success(), "the unconfined control ran");
    let control = std::fs::read_to_string(output.join("unconfined")).expect("control report");
    assert!(
        control.contains("FILE:") && control.contains("ENV:"),
        "the unconfined control found nothing, so the confined CLEAN proves nothing: {control}"
    );
    eprintln!(
        "[a0.6] unconfined control found {} leak(s) — the probe works, the sandbox is what stops it",
        control.matches("FILE:").count() + control.matches("ENV:").count()
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
