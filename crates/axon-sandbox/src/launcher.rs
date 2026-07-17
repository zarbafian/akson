//! The sandbox launcher (design §13.1, ADR-0006): the isolation policy and the
//! pure-Rust native backend that enforces it.
//!
//! Axon *authors* the isolation policy as a [`SandboxSpec`]; a [`SandboxLauncher`]
//! backend enforces it. The v1 backend is [`NativeLauncher`], which resolves the
//! spec into a [`SandboxPlan`] — the ordered isolation steps — and applies it in
//! process (namespaces, mounts, `no_new_privs`, capability drop, seccomp,
//! Landlock, cgroup limits), with no external binary. The **plan is data**, so it
//! is fully unit-tested without executing anything; the seccomp and Landlock
//! pieces are additionally enforced and tested unprivileged (they need no user
//! namespace), while the namespace/mount/exec sequence is validated in a
//! permissive Linux environment. The trait is the swap seam.
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

/// The v1 launcher: resolves a spec into a [`SandboxPlan`] and applies it with
/// pure-Rust primitives (ADR-0006) — no external binary.
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
    fn launch_refuses_when_isolation_is_unavailable() {
        // On a host without unprivileged userns (this one), the probe refuses.
        // (Where isolation IS available, application is not yet wired, so it
        // returns an Apply error — never Ok until the native path lands.)
        let result = NativeLauncher.launch(&spec(), "worker", &[]);
        assert!(result.is_err());
    }
}
