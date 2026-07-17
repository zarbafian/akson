//! The sandbox launcher (design §13.1, ADR-0006): the isolation policy and the
//! bubblewrap backend that enforces it.
//!
//! Axon *authors* the isolation policy as a [`SandboxSpec`]; a [`SandboxLauncher`]
//! backend enforces it. The v1 backend is [`BubblewrapLauncher`], which turns the
//! spec into a `bwrap` command line — the security policy *is* that argv, so it is
//! unit-tested even though executing it needs a permissive Linux environment. The
//! trait is the swap seam for a future pure-Rust launcher.
//!
//! Every launch is gated by the [capability probe](crate::ensure): if a required
//! feature is unavailable the launcher refuses rather than run un-isolated.
//!
//! What you write:
//! ```
//! use axon_sandbox::{SandboxSpec, BubblewrapLauncher};
//! let spec = SandboxSpec::clean_worker("/run/axon/task-1")
//!     .ro_bind("/opt/axon/runtime", "/runtime")   // digest-pinned, read-only
//!     .tmpfs("/scratch")
//!     .setenv("AXON_TASK", "task-1");
//! let argv = BubblewrapLauncher::build_argv(&spec, "worker", &["--run".into()]);
//! assert_eq!(argv[0], "bwrap");
//! assert!(argv.iter().any(|a| a == "--unshare-all")); // no network, all namespaces
//! assert!(argv.iter().any(|a| a == "--clearenv"));    // empty environment
//! assert!(!argv.iter().any(|a| a == "--share-net"));  // never shares the network
//! ```

use crate::probe::{detect, ensure, required, MissingFeatures};

/// The isolation policy for one worker (design §13.1). Axon builds this; a
/// [`SandboxLauncher`] enforces it. Defaults are the strict clean-worker profile:
/// all namespaces unshared (so no network), an empty environment, a private
/// `/proc` and `/dev`, and every capability dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// Read-only binds `(host_path, sandbox_path)` — the digest-pinned runtime.
    pub ro_binds: Vec<(String, String)>,
    /// tmpfs mounts inside the sandbox (scratch and output).
    pub tmpfs: Vec<String>,
    /// The working directory inside the sandbox.
    pub chdir: String,
    /// Environment variables to set after clearing the environment. Nothing else
    /// is inherited.
    pub env: Vec<(String, String)>,
    /// Whether to give the worker a network namespace with connectivity. The v1
    /// clean worker never does (§13.1) — the broker is the only egress.
    pub allow_network: bool,
    /// An fd carrying the compiled seccomp BPF program, if one is installed.
    pub seccomp_fd: Option<i32>,
}

impl SandboxSpec {
    /// The strict clean-worker profile (design §13.1): no network, empty
    /// environment, working in `workdir`, no binds or tmpfs yet.
    pub fn clean_worker(workdir: &str) -> Self {
        Self {
            ro_binds: Vec::new(),
            tmpfs: Vec::new(),
            chdir: workdir.to_owned(),
            env: Vec::new(),
            allow_network: false,
            seccomp_fd: None,
        }
    }

    /// Adds a read-only bind of a host path to a sandbox path (builder).
    pub fn ro_bind(mut self, host: &str, sandbox: &str) -> Self {
        self.ro_binds.push((host.to_owned(), sandbox.to_owned()));
        self
    }

    /// Adds a tmpfs mount inside the sandbox (builder).
    pub fn tmpfs(mut self, path: &str) -> Self {
        self.tmpfs.push(path.to_owned());
        self
    }

    /// Sets an environment variable (the environment is otherwise empty).
    pub fn setenv(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_owned(), value.to_owned()));
        self
    }
}

/// Why a launch could not proceed.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// Required isolation features are unavailable; the launch is refused (§13.1).
    #[error(transparent)]
    IsolationUnavailable(#[from] MissingFeatures),
    #[error("failed to spawn the sandbox: {0}")]
    Spawn(#[from] std::io::Error),
}

/// A backend that enforces a [`SandboxSpec`] (ADR-0006). The trait is the swap
/// seam between the v1 bubblewrap backend and a future pure-Rust launcher.
pub trait SandboxLauncher {
    /// Launches `program` with `args` under `spec`, returning the child process.
    /// Implementations MUST run the capability probe first and fail closed.
    fn launch(
        &self,
        spec: &SandboxSpec,
        program: &str,
        args: &[String],
    ) -> Result<std::process::Child, SandboxError>;
}

/// The v1 launcher: constructs a `bwrap` command line from the spec and execs it
/// (ADR-0006).
#[derive(Debug, Clone, Default)]
pub struct BubblewrapLauncher;

impl BubblewrapLauncher {
    /// Builds the `bwrap` argv that enforces `spec` for `program`/`args`. Pure —
    /// this is the security policy in explicit flags, so it is fully testable
    /// without executing anything. The order is: isolation flags, mounts, then
    /// `--` and the program.
    pub fn build_argv(spec: &SandboxSpec, program: &str, args: &[String]) -> Vec<String> {
        let mut argv = vec!["bwrap".to_owned()];

        // Namespaces: unshare everything. --unshare-all includes the network, so
        // the worker has no network unless we explicitly share it (v1 never does).
        argv.push("--unshare-all".to_owned());
        if spec.allow_network {
            argv.push("--share-net".to_owned());
        }
        // Lifecycle and session hardening.
        argv.push("--die-with-parent".to_owned());
        argv.push("--new-session".to_owned());
        // Drop every capability; a userns already confines them, this is explicit.
        argv.push("--cap-drop".to_owned());
        argv.push("ALL".to_owned());
        // Empty environment, then only the declared variables.
        argv.push("--clearenv".to_owned());
        for (k, v) in &spec.env {
            argv.push("--setenv".to_owned());
            argv.push(k.clone());
            argv.push(v.clone());
        }
        // A private /proc and a minimal /dev.
        argv.push("--proc".to_owned());
        argv.push("/proc".to_owned());
        argv.push("--dev".to_owned());
        argv.push("/dev".to_owned());
        // Read-only, digest-pinned runtime binds.
        for (host, sandbox) in &spec.ro_binds {
            argv.push("--ro-bind".to_owned());
            argv.push(host.clone());
            argv.push(sandbox.clone());
        }
        // Writable scratch/output as tmpfs.
        for path in &spec.tmpfs {
            argv.push("--tmpfs".to_owned());
            argv.push(path.clone());
        }
        // The default-deny seccomp filter, if compiled.
        if let Some(fd) = spec.seccomp_fd {
            argv.push("--seccomp".to_owned());
            argv.push(fd.to_string());
        }
        argv.push("--chdir".to_owned());
        argv.push(spec.chdir.clone());

        argv.push("--".to_owned());
        argv.push(program.to_owned());
        argv.extend(args.iter().cloned());
        argv
    }
}

impl SandboxLauncher for BubblewrapLauncher {
    fn launch(
        &self,
        spec: &SandboxSpec,
        program: &str,
        args: &[String],
    ) -> Result<std::process::Child, SandboxError> {
        // Fail closed: refuse to run without the required isolation (§13.1).
        ensure(&detect(), required())?;
        let argv = Self::build_argv(spec, program, args);
        let child = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .spawn()?;
        Ok(child)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn spec() -> SandboxSpec {
        SandboxSpec::clean_worker("/run/axon/task-1")
            .ro_bind("/opt/axon/runtime", "/runtime")
            .tmpfs("/scratch")
            .tmpfs("/output")
            .setenv("AXON_TASK", "task-1")
    }

    fn argv() -> Vec<String> {
        BubblewrapLauncher::build_argv(&spec(), "worker", &["--run".to_owned()])
    }

    fn has_flag(argv: &[String], flag: &str) -> bool {
        argv.iter().any(|a| a == flag)
    }

    /// Finds the value that follows a flag in the argv.
    fn value_after<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
        argv.iter()
            .position(|a| a == flag)
            .and_then(|i| argv.get(i + 1))
            .map(String::as_str)
    }

    #[test]
    fn the_policy_hardens_by_default() {
        let argv = argv();
        assert_eq!(argv[0], "bwrap");
        // Namespaces, no network, lifecycle, empty env, caps dropped.
        assert!(has_flag(&argv, "--unshare-all"));
        assert!(!has_flag(&argv, "--share-net")); // clean worker has no network
        assert!(has_flag(&argv, "--die-with-parent"));
        assert!(has_flag(&argv, "--new-session"));
        assert!(has_flag(&argv, "--clearenv"));
        assert_eq!(value_after(&argv, "--cap-drop"), Some("ALL"));
        // Private /proc and /dev.
        assert_eq!(value_after(&argv, "--proc"), Some("/proc"));
        assert_eq!(value_after(&argv, "--dev"), Some("/dev"));
    }

    #[test]
    fn mounts_and_env_and_program_are_placed() {
        let argv = argv();
        // The read-only runtime bind and both tmpfs mounts.
        let ro = argv
            .windows(3)
            .any(|w| w == ["--ro-bind", "/opt/axon/runtime", "/runtime"].map(String::from));
        assert!(ro, "digest-pinned runtime must be a read-only bind");
        assert_eq!(argv.iter().filter(|a| *a == "--tmpfs").count(), 2);
        // The declared env var is set after clearenv.
        let clear = argv.iter().position(|a| a == "--clearenv").unwrap();
        let setenv = argv.iter().position(|a| a == "--setenv").unwrap();
        assert!(setenv > clear, "env is set only after clearing");
        // The program and its args come after the `--` separator, last.
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep + 1], "worker");
        assert_eq!(argv[sep + 2], "--run");
    }

    #[test]
    fn network_is_shared_only_when_explicitly_allowed() {
        let mut s = spec();
        s.allow_network = true;
        let argv = BubblewrapLauncher::build_argv(&s, "worker", &[]);
        assert!(has_flag(&argv, "--share-net"));
    }

    #[test]
    fn seccomp_fd_is_wired_when_present() {
        let mut s = spec();
        s.seccomp_fd = Some(7);
        let argv = BubblewrapLauncher::build_argv(&s, "worker", &[]);
        assert_eq!(value_after(&argv, "--seccomp"), Some("7"));
    }
}
