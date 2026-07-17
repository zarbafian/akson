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

    /// A starting default-deny allowlist for the clean worker (design §13.1): the
    /// common syscalls a sandboxed program needs to start and do bounded work, with
    /// everything else denied. Deliberately conservative; task profiles refine it.
    /// Uses `Errno` so a missing syscall degrades rather than killing outright —
    /// the strict worker profile uses [`DenyAction::KillProcess`].
    pub fn clean_worker_baseline(deny: DenyAction) -> Self {
        Self::deny_all_except(
            vec![
                libc::SYS_read,
                libc::SYS_write,
                libc::SYS_readv,
                libc::SYS_writev,
                libc::SYS_pread64,
                libc::SYS_pwrite64,
                libc::SYS_lseek,
                libc::SYS_close,
                libc::SYS_openat,
                libc::SYS_open,
                libc::SYS_fstat,
                libc::SYS_newfstatat,
                libc::SYS_statx,
                libc::SYS_lstat,
                libc::SYS_stat,
                libc::SYS_access,
                libc::SYS_faccessat,
                libc::SYS_faccessat2,
                libc::SYS_readlink,
                libc::SYS_readlinkat,
                libc::SYS_getdents64,
                libc::SYS_getcwd,
                libc::SYS_mmap,
                libc::SYS_munmap,
                libc::SYS_mprotect,
                libc::SYS_mremap,
                libc::SYS_madvise,
                libc::SYS_brk,
                libc::SYS_rt_sigaction,
                libc::SYS_rt_sigprocmask,
                libc::SYS_rt_sigreturn,
                libc::SYS_sigaltstack,
                libc::SYS_ioctl,
                libc::SYS_fcntl,
                libc::SYS_dup,
                libc::SYS_dup2,
                libc::SYS_dup3,
                libc::SYS_pipe2,
                libc::SYS_poll,
                libc::SYS_ppoll,
                libc::SYS_execve,
                libc::SYS_exit,
                libc::SYS_exit_group,
                libc::SYS_wait4,
                libc::SYS_clone,
                libc::SYS_clone3,
                libc::SYS_futex,
                libc::SYS_getpid,
                libc::SYS_getppid,
                libc::SYS_gettid,
                libc::SYS_getuid,
                libc::SYS_getgid,
                libc::SYS_geteuid,
                libc::SYS_getegid,
                libc::SYS_arch_prctl,
                libc::SYS_set_tid_address,
                libc::SYS_set_robust_list,
                libc::SYS_rseq,
                libc::SYS_prlimit64,
                libc::SYS_getrandom,
                libc::SYS_clock_gettime,
                libc::SYS_clock_nanosleep,
                libc::SYS_nanosleep,
                libc::SYS_sched_getaffinity,
                libc::SYS_sched_yield,
                libc::SYS_uname,
                libc::SYS_sysinfo,
                libc::SYS_tgkill,
                libc::SYS_epoll_create1,
                libc::SYS_epoll_ctl,
                libc::SYS_epoll_pwait,
            ],
            deny,
        )
    }

    /// Compiles the policy and writes the BPF program to an anonymous `memfd`,
    /// returning the (non-`CLOEXEC`, so inheritable) fd to hand to `bwrap
    /// --seccomp` (design §13.1, ADR-0006). Because everything the daemon opens via
    /// `std` is `CLOEXEC`, only stdio and this fd cross into bubblewrap — the
    /// inherited-fd allowlist is satisfied structurally.
    pub fn to_memfd(&self) -> Result<std::os::fd::OwnedFd, SeccompError> {
        use std::os::fd::{FromRawFd, OwnedFd};
        let program = self.compile()?;
        // SAFETY: a valid C name; flag 0 keeps the fd inheritable for the child.
        let raw = unsafe { libc::memfd_create(c"axon-seccomp".as_ptr(), 0) };
        if raw < 0 {
            return Err(SeccompError::Apply(format!(
                "memfd_create (errno {})",
                errno()
            )));
        }
        // SAFETY: memfd_create returned a fresh owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // The BPF program is a packed array of sock_filter; write its raw bytes.
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                program.as_ptr().cast::<u8>(),
                std::mem::size_of_val(program.as_slice()),
            )
        };
        let mut done = 0;
        while done < bytes.len() {
            // SAFETY: writing our own buffer to our own memfd.
            let n = unsafe { libc::write(raw, bytes[done..].as_ptr().cast(), bytes.len() - done) };
            if n <= 0 {
                return Err(SeccompError::Apply(format!(
                    "write seccomp memfd (errno {})",
                    errno()
                )));
            }
            done += n as usize;
        }
        // SAFETY: rewind our own fd so bubblewrap reads from the start.
        if unsafe { libc::lseek(raw, 0, libc::SEEK_SET) } < 0 {
            return Err(SeccompError::Apply("lseek seccomp memfd".into()));
        }
        Ok(fd)
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
