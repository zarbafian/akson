//! The sandbox launcher (design §13.1, ADR-0006): the isolation policy and the
//! backends that enforce it.
//!
//! Axon *authors* the isolation policy as a [`SandboxSpec`]; a [`SandboxLauncher`]
//! backend enforces it. Per ADR-0006 (revised after adversarial review), the **v1
//! default is [`BubblewrapLauncher`]** — bubblewrap, an independently-reviewed
//! sandbox (§13.1/§13.4/§19), enforces the namespace/mount/`pivot_root`/exec
//! boundary Axon authors, and the pure-Rust seccomp filter is handed to it via
//! `--seccomp`; Landlock is applied by the worker entrypoint. [`NativeLauncher`]
//! (the pure-Rust namespace/mount code) is retained **behind the same trait as an
//! experimental backend**, promoted to default only after independent review +
//! differential testing and the structural fixes the review named (inherited-fd
//! allowlist, a fork→exec-init process model, an unpredictable root). The trait is
//! the swap seam.
//!
//! Every launch is gated by the [capability probe](crate::ensure): if a required
//! feature is unavailable the launcher refuses rather than run un-isolated.
//!
//! What you write:
//! ```
//! use axon_sandbox::{SandboxSpec, NativeLauncher, Namespace};
//! let spec = SandboxSpec::clean_worker("/run/axon/task-1")
//!     .ro_bind("/opt/axon/runtime", "/runtime")   // digest-pinned, read-only
//!     .tmpfs("/scratch")
//!     .setenv("AXON_TASK", "task-1");
//! let plan = NativeLauncher::build_plan(&spec);
//! assert!(plan.unshares(Namespace::Net));   // no network
//! assert!(plan.unshares(Namespace::User));  // unprivileged isolation
//! assert!(plan.no_new_privs && plan.drop_all_caps && plan.clear_env);
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

/// A Linux namespace the worker is isolated into (design §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    User,
    Mount,
    Pid,
    Net,
    Ipc,
    Uts,
    Cgroup,
}

/// A filesystem mount the plan performs inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountOp {
    /// A private `/proc`.
    Proc,
    /// A minimal `/dev`.
    Dev,
    /// A read-only bind of a host path to a sandbox path.
    RoBind { host: String, sandbox: String },
    /// A writable tmpfs at a sandbox path.
    Tmpfs { path: String },
}

/// The resolved isolation steps for a worker — the policy as data (ADR-0006). A
/// [`NativeLauncher`] applies these; tests assert them directly, so the policy is
/// verified without executing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    /// Namespaces to unshare, in a stable order.
    pub unshare: Vec<Namespace>,
    /// Mounts to perform, in order (`/proc`, `/dev`, binds, tmpfs).
    pub mounts: Vec<MountOp>,
    /// The working directory inside the sandbox.
    pub chdir: String,
    /// The environment is always cleared first; these are the only variables set.
    pub clear_env: bool,
    pub env: Vec<(String, String)>,
    /// Drop every capability (§13.1).
    pub drop_all_caps: bool,
    /// Set `no_new_privs` before exec (§13.1) — also required to install seccomp.
    pub no_new_privs: bool,
}

impl SandboxPlan {
    /// Whether the plan unshares a given namespace.
    pub fn unshares(&self, ns: Namespace) -> bool {
        self.unshare.contains(&ns)
    }
}

/// Why a launch could not proceed.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// Required isolation features are unavailable; the launch is refused (§13.1).
    #[error(transparent)]
    IsolationUnavailable(#[from] MissingFeatures),
    #[error("failed to apply the sandbox: {0}")]
    Apply(String),
}

/// A backend that enforces a [`SandboxSpec`] (ADR-0006). The trait is the swap
/// seam between the v1 native launcher and any alternative (e.g. a bubblewrap
/// backend used as a test oracle).
pub trait SandboxLauncher {
    /// Launches `program` with `args` under `spec`. Implementations MUST run the
    /// capability probe first and fail closed.
    fn launch(
        &self,
        spec: &SandboxSpec,
        program: &str,
        args: &[String],
    ) -> Result<(), SandboxError>;
}

/// **Experimental** pure-Rust launcher (ADR-0006): resolves a spec into a
/// [`SandboxPlan`] and applies it with in-process syscalls — no external binary.
///
/// NOT the v1 default. Retained behind the trait and promoted only after
/// independent review + differential testing against bubblewrap and the structural
/// fixes the review named (inherited-fd allowlist + `close_range` sweep; a
/// fork→exec-init process model rather than heavy allocation between fork and
/// exec; an unpredictable `O_NOFOLLOW` root; unconditional `nosuid`/`nodev`; real
/// cgroup enforcement; best-effort Landlock ABI). Until then, use
/// [`BubblewrapLauncher`].
#[derive(Debug, Clone, Default)]
pub struct NativeLauncher;

impl NativeLauncher {
    /// Resolves `spec` into the ordered isolation steps. Pure — this is the
    /// security policy as data, so it is fully testable without applying anything.
    pub fn build_plan(spec: &SandboxSpec) -> SandboxPlan {
        // Always unshare user, mount, pid, ipc, uts, and cgroup. The network
        // namespace is unshared too (giving no connectivity) unless the spec
        // explicitly allows network — which the clean worker never does.
        let mut unshare = vec![
            Namespace::User,
            Namespace::Mount,
            Namespace::Pid,
            Namespace::Ipc,
            Namespace::Uts,
            Namespace::Cgroup,
        ];
        if !spec.allow_network {
            unshare.push(Namespace::Net);
        }

        // Mounts, in order: a private /proc and /dev, then the read-only
        // digest-pinned runtime binds, then writable tmpfs scratch/output.
        let mut mounts = vec![MountOp::Proc, MountOp::Dev];
        for (host, sandbox) in &spec.ro_binds {
            mounts.push(MountOp::RoBind {
                host: host.clone(),
                sandbox: sandbox.clone(),
            });
        }
        for path in &spec.tmpfs {
            mounts.push(MountOp::Tmpfs { path: path.clone() });
        }

        SandboxPlan {
            unshare,
            mounts,
            chdir: spec.chdir.clone(),
            clear_env: true,
            env: spec.env.clone(),
            drop_all_caps: true,
            no_new_privs: true,
        }
    }
}

impl SandboxLauncher for NativeLauncher {
    fn launch(
        &self,
        spec: &SandboxSpec,
        _program: &str,
        _args: &[String],
    ) -> Result<(), SandboxError> {
        // Fail closed: refuse to run without the required isolation (§13.1).
        ensure(&detect(), required())?;
        let _plan = Self::build_plan(spec);
        // Applying the namespace/mount/exec sequence (via nix/rustix) plus seccomp
        // and Landlock lands next; it requires a permissive Linux environment to
        // validate and is gated by the probe above. Refuse until then rather than
        // run a partially-isolated worker.
        Err(SandboxError::Apply(
            "native namespace/mount application not yet wired; validated in a permissive env"
                .into(),
        ))
    }
}

/// The **v1 default** launcher (ADR-0006): bubblewrap enforces the namespace/mount
/// policy Axon authors; the pure-Rust seccomp filter is handed to it via
/// `--seccomp <fd>`, and Landlock is applied by the worker entrypoint.
///
/// Bubblewrap is an independently-reviewed, widely-deployed sandbox, which is what
/// §13.1/§13.4/§19 call for at the escape boundary — and it handles the exact
/// classes of bug (inherited-fd leaks, the fork/exec model) that a hand-rolled
/// launcher is prone to.
#[derive(Debug, Clone, Default)]
pub struct BubblewrapLauncher;

impl BubblewrapLauncher {
    /// Builds the `bwrap` argv enforcing `spec`. Pure — the security policy in
    /// explicit flags, fully testable without executing. `seccomp_fd`, when set, is
    /// the fd of a compiled default-deny BPF program passed to `--seccomp`.
    ///
    /// The §13.1 inherited-fd allowlist is a *launch-time* duty of the caller: set
    /// `CLOEXEC` on every fd except stdio and `seccomp_fd` before spawning, so
    /// bubblewrap's child inherits only the allowlisted descriptors.
    pub fn build_argv(
        spec: &SandboxSpec,
        program: &str,
        args: &[String],
        seccomp_fd: Option<i32>,
    ) -> Vec<String> {
        let mut argv = vec!["bwrap".to_owned()];
        // All namespaces; --unshare-all includes the network, so no connectivity
        // unless network is explicitly allowed (the clean worker never does).
        argv.push("--unshare-all".to_owned());
        if spec.allow_network {
            argv.push("--share-net".to_owned());
        }
        argv.push("--die-with-parent".to_owned());
        argv.push("--new-session".to_owned());
        argv.push("--cap-drop".to_owned());
        argv.push("ALL".to_owned());
        argv.push("--clearenv".to_owned());
        for (k, v) in &spec.env {
            argv.push("--setenv".to_owned());
            argv.push(k.clone());
            argv.push(v.clone());
        }
        argv.push("--proc".to_owned());
        argv.push("/proc".to_owned());
        argv.push("--dev".to_owned());
        argv.push("/dev".to_owned());
        for (host, sandbox) in &spec.ro_binds {
            argv.push("--ro-bind".to_owned());
            argv.push(host.clone());
            argv.push(sandbox.clone());
        }
        for path in &spec.tmpfs {
            argv.push("--tmpfs".to_owned());
            argv.push(path.clone());
        }
        if let Some(fd) = seccomp_fd {
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
    ) -> Result<(), SandboxError> {
        // Fail closed: refuse to run without the required isolation (§13.1).
        ensure(&detect(), required())?;
        // (Seccomp-fd + the CLOEXEC fd-allowlist sweep are wired at daemon
        // integration; passing None here runs bubblewrap's own default profile.)
        let argv = Self::build_argv(spec, program, args, None);
        let status = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .status()
            .map_err(|e| SandboxError::Apply(format!("spawning bwrap: {e}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(SandboxError::Apply(format!("worker exited: {status}")))
        }
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

    #[test]
    fn the_plan_hardens_by_default() {
        let plan = NativeLauncher::build_plan(&spec());
        // Every namespace, including net (no connectivity) since network is off.
        for ns in [
            Namespace::User,
            Namespace::Mount,
            Namespace::Pid,
            Namespace::Net,
            Namespace::Ipc,
            Namespace::Uts,
            Namespace::Cgroup,
        ] {
            assert!(plan.unshares(ns), "{ns:?} must be unshared");
        }
        assert!(plan.clear_env);
        assert!(plan.drop_all_caps);
        assert!(plan.no_new_privs);
        assert_eq!(plan.chdir, "/run/axon/task-1");
    }

    #[test]
    fn mounts_are_ordered_proc_dev_binds_tmpfs() {
        let plan = NativeLauncher::build_plan(&spec());
        assert_eq!(plan.mounts[0], MountOp::Proc);
        assert_eq!(plan.mounts[1], MountOp::Dev);
        assert_eq!(
            plan.mounts[2],
            MountOp::RoBind {
                host: "/opt/axon/runtime".to_owned(),
                sandbox: "/runtime".to_owned()
            }
        );
        assert_eq!(
            plan.mounts
                .iter()
                .filter(|m| matches!(m, MountOp::Tmpfs { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn network_namespace_is_kept_only_when_network_is_allowed() {
        let mut s = spec();
        s.allow_network = true;
        let plan = NativeLauncher::build_plan(&s);
        // Allowing network means NOT unsharing the net namespace (keeps host net).
        assert!(!plan.unshares(Namespace::Net));
        // Everything else is still isolated.
        assert!(plan.unshares(Namespace::User));
    }

    #[test]
    fn only_declared_env_is_present_after_clearing() {
        let plan = NativeLauncher::build_plan(&spec());
        assert!(plan.clear_env);
        assert_eq!(
            plan.env,
            vec![("AXON_TASK".to_owned(), "task-1".to_owned())]
        );
    }

    #[test]
    fn native_launch_never_succeeds_yet() {
        // The experimental native launcher never returns Ok: without userns the
        // probe refuses; with userns the namespace/mount application is not wired.
        assert!(NativeLauncher.launch(&spec(), "worker", &[]).is_err());
    }

    // --- BubblewrapLauncher (v1 default, ADR-0006) ---

    fn bwrap_argv() -> Vec<String> {
        BubblewrapLauncher::build_argv(&spec(), "worker", &["--run".to_owned()], None)
    }

    fn has(argv: &[String], flag: &str) -> bool {
        argv.iter().any(|a| a == flag)
    }

    fn value_after<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
        argv.iter()
            .position(|a| a == flag)
            .and_then(|i| argv.get(i + 1))
            .map(String::as_str)
    }

    #[test]
    fn bwrap_policy_hardens_by_default() {
        let argv = bwrap_argv();
        assert_eq!(argv[0], "bwrap");
        assert!(has(&argv, "--unshare-all"));
        assert!(!has(&argv, "--share-net")); // clean worker has no network
        assert!(has(&argv, "--die-with-parent"));
        assert!(has(&argv, "--new-session"));
        assert!(has(&argv, "--clearenv"));
        assert_eq!(value_after(&argv, "--cap-drop"), Some("ALL"));
        assert_eq!(value_after(&argv, "--proc"), Some("/proc"));
        assert_eq!(value_after(&argv, "--dev"), Some("/dev"));
        // Program and args after the `--` separator, last.
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep + 1], "worker");
        assert_eq!(argv[sep + 2], "--run");
    }

    /// Live: run a real worker under bubblewrap and confirm the clean-worker
    /// properties from *inside* — host `/etc` gone, the environment cleared (only
    /// our `--setenv` survives), and the scratch tmpfs writable. Needs bwrap +
    /// unprivileged userns, so it is `#[ignore]`d and runs in CI's isolation job or
    /// locally once userns is enabled.
    #[test]
    #[ignore = "needs bwrap + unprivileged userns; runs in CI's isolation job"]
    fn live_bwrap_isolates_the_worker() {
        // A host env var that --clearenv must strip from the worker.
        std::env::set_var("AXON_HOST_SECRET", "leak");
        // A minimal read-only runtime so /bin/sh runs; no /etc (must be absent).
        let spec = SandboxSpec::clean_worker("/")
            .ro_bind("/usr", "/usr")
            .ro_bind("/bin", "/bin")
            .ro_bind("/lib", "/lib")
            .ro_bind("/lib64", "/lib64")
            .tmpfs("/scratch")
            .setenv("AXON_TASK", "task-1");
        let script = concat!(
            "[ ! -e /etc ] || exit 20\n",                // host filesystem gone
            "[ -z \"$AXON_HOST_SECRET\" ] || exit 21\n", // host env cleared
            "[ \"$AXON_TASK\" = task-1 ] || exit 22\n",  // our setenv present
            ": > /scratch/ok || exit 23\n",              // scratch writable
        );
        let result =
            BubblewrapLauncher.launch(&spec, "/bin/sh", &["-c".to_owned(), script.to_owned()]);
        std::env::remove_var("AXON_HOST_SECRET");
        // Exit 20 = /etc reachable, 21 = env leaked, 22 = setenv missing, 23 = scratch RO.
        assert!(
            result.is_ok(),
            "bwrap clean-worker isolation checks failed: {result:?}"
        );
    }

    #[test]
    fn bwrap_wires_binds_env_seccomp_and_network() {
        let argv = bwrap_argv();
        let ro = argv
            .windows(3)
            .any(|w| w == ["--ro-bind", "/opt/axon/runtime", "/runtime"].map(String::from));
        assert!(ro, "digest-pinned runtime must be a read-only bind");
        assert_eq!(argv.iter().filter(|a| *a == "--tmpfs").count(), 2);
        // env set only after clearenv.
        let clear = argv.iter().position(|a| a == "--clearenv").unwrap();
        let setenv = argv.iter().position(|a| a == "--setenv").unwrap();
        assert!(setenv > clear);
        // seccomp fd wired when provided.
        let with_fd = BubblewrapLauncher::build_argv(&spec(), "worker", &[], Some(7));
        assert_eq!(value_after(&with_fd, "--seccomp"), Some("7"));
        // network shared only when explicitly allowed.
        let mut netspec = spec();
        netspec.allow_network = true;
        assert!(has(
            &BubblewrapLauncher::build_argv(&netspec, "worker", &[], None),
            "--share-net"
        ));
    }
}
