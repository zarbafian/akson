//! The default-deny seccomp filter (design §13.1).
//!
//! A [`SeccompPolicy`] is an allowlist: the named syscalls are permitted and
//! every other syscall is denied. It compiles (via `seccompiler`, pure Rust) to a
//! BPF program that [`apply`](SeccompPolicy::apply) installs on the current
//! process after setting `no_new_privs`. Unlike the namespace/mount pieces,
//! seccomp needs no user namespace, so it is enforced — and *tested* — even on a
//! host that restricts unprivileged user namespaces.
//!
//! What you write:
//! ```
//! use axon_sandbox::{SeccompPolicy, DenyAction};
//! // Allow only what a trivial program needs; deny everything else.
//! let policy = SeccompPolicy::deny_all_except(
//!     vec![libc::SYS_exit_group, libc::SYS_write],
//!     DenyAction::KillProcess,
//! );
//! let program = policy.compile().unwrap(); // a BPF program, ready to install
//! assert!(!program.is_empty());
//! ```

use std::collections::BTreeMap;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

/// What happens to a syscall that is not on the allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyAction {
    /// Kill the whole process (the strict default for a clean worker).
    KillProcess,
    /// Fail the syscall with `errno` — useful for graceful degradation and for
    /// deterministic testing.
    Errno(u32),
}

impl DenyAction {
    fn action(self) -> SeccompAction {
        match self {
            DenyAction::KillProcess => SeccompAction::KillProcess,
            DenyAction::Errno(e) => SeccompAction::Errno(e),
        }
    }
}

/// A default-deny seccomp allowlist (design §13.1).
#[derive(Debug, Clone)]
pub struct SeccompPolicy {
    allow: Vec<i64>,
    deny: DenyAction,
}

/// Why a seccomp policy could not be compiled or applied.
#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("unsupported target architecture for seccomp")]
    UnsupportedArch,
    #[error("seccomp filter build/compile failed: {0}")]
    Compile(String),
    #[error("setting no_new_privs failed (errno {0})")]
    NoNewPrivs(i32),
    #[error("installing the seccomp filter failed: {0}")]
    Apply(String),
}

impl SeccompPolicy {
    /// A policy that allows exactly `allow` (syscall numbers) and applies `deny`
    /// to everything else.
    pub fn deny_all_except(allow: Vec<i64>, deny: DenyAction) -> Self {
        Self { allow, deny }
    }

    /// Compiles the policy to a BPF program (does not install it). Pure.
    pub fn compile(&self) -> Result<BpfProgram, SeccompError> {
        let arch = host_target_arch().ok_or(SeccompError::UnsupportedArch)?;
        // Each allowed syscall maps to an empty rule set (allow unconditionally).
        let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
            self.allow.iter().map(|&n| (n, Vec::new())).collect();
        let filter = SeccompFilter::new(
            rules,
            self.deny.action(),   // mismatch: denied syscalls
            SeccompAction::Allow, // match: allowed syscalls
            arch,
        )
        .map_err(|e| SeccompError::Compile(e.to_string()))?;
        BpfProgram::try_from(filter).map_err(|e| SeccompError::Compile(e.to_string()))
    }

    /// Installs the filter on the current process (design §13.1). Sets
    /// `no_new_privs` first — required to install seccomp unprivileged — then
    /// applies the program. The worker calls this after fork, before exec.
    ///
    /// A seccomp filter cannot be removed once installed; this is one-way.
    pub fn apply(&self) -> Result<(), SeccompError> {
        let program = self.compile()?;
        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is always safe to call.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(SeccompError::NoNewPrivs(errno()));
        }
        seccompiler::apply_filter(&program).map_err(|e| SeccompError::Apply(e.to_string()))
    }
}

/// The seccomp target architecture for this build, if supported.
fn host_target_arch() -> Option<TargetArch> {
    #[cfg(target_arch = "x86_64")]
    {
        Some(TargetArch::x86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Some(TargetArch::aarch64)
    }
    #[cfg(target_arch = "riscv64")]
    {
        Some(TargetArch::riscv64)
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        None
    }
}

fn errno() -> i32 {
    // SAFETY: __errno_location always returns a valid pointer.
    unsafe { *libc::__errno_location() }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_compiles_to_a_nonempty_program() {
        let policy = SeccompPolicy::deny_all_except(
            vec![libc::SYS_read, libc::SYS_write, libc::SYS_exit_group],
            DenyAction::KillProcess,
        );
        let program = policy.compile().unwrap();
        assert!(!program.is_empty());
    }

    /// Enforcement, validated unprivileged: a child installs a filter that denies
    /// `socket`, then calls it and reports whether it was blocked. This runs even
    /// on a userns-restricted host — seccomp needs no user namespace.
    #[test]
    fn a_denied_syscall_is_blocked_in_a_child() {
        // Allow just enough for the child to run and exit; deny everything else
        // (notably socket). Errno makes the outcome deterministic to check.
        let policy = SeccompPolicy::deny_all_except(
            vec![
                libc::SYS_exit_group,
                libc::SYS_exit,
                libc::SYS_write,
                libc::SYS_rt_sigreturn,
            ],
            DenyAction::Errno(libc::EPERM as u32),
        );
        // Compile in the parent so the child only does async-signal-safe work.
        let program = policy.compile().unwrap();

        // SAFETY: after fork the child performs only syscalls (no allocation,
        // no locks) before _exit — the async-signal-safe discipline.
        match unsafe { libc::fork() } {
            -1 => panic!("fork failed"),
            0 => {
                unsafe {
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                        libc::_exit(97);
                    }
                }
                if seccompiler::apply_filter(&program).is_err() {
                    unsafe { libc::_exit(98) };
                }
                // socket is not allowlisted → EPERM under the Errno deny action.
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                let code = if fd < 0 { 0 } else { 1 };
                unsafe { libc::_exit(code) };
            }
            pid => {
                let mut status = 0;
                // SAFETY: valid pid and status pointer.
                unsafe { libc::waitpid(pid, &mut status, 0) };
                assert!(libc::WIFEXITED(status), "child should exit normally");
                let code = libc::WEXITSTATUS(status);
                assert_ne!(code, 97, "PR_SET_NO_NEW_PRIVS failed in child");
                assert_ne!(code, 98, "apply_filter failed in child");
                assert_eq!(code, 0, "socket() must be denied by the seccomp filter");
            }
        }
    }
}
