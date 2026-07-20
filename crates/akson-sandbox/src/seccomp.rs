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
//! use akson_sandbox::{SeccompPolicy, DenyAction};
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
    /// common syscalls a sandboxed program needs to start and do bounded work, plus
    /// the process-spawning family, with everything else denied. This is the profile
    /// for the shell stand-in worker (`/bin/sh -c <cmd>`), which may `fork`/`exec`
    /// external tools. A production adapter runs directly and uses the tighter
    /// [`adapter_worker_baseline`]. The strict worker profile uses
    /// [`DenyAction::KillProcess`].
    pub fn clean_worker_baseline(deny: DenyAction) -> Self {
        let mut allow = common_worker_syscalls();
        // The process-CREATION family: a shell (dash) `fork`/`vfork`/`clone`s a child
        // before `execve`ing an external tool. A single-process adapter never creates
        // a process, so [`adapter_worker_baseline`] omits exactly this set. (Reaping —
        // `wait4` — and `pipe`/`splice` are *not* here: bubblewrap's own pid-1 monitor
        // needs them under this filter to reap the sandboxed child, so they live in
        // the common set.)
        allow.extend_from_slice(&[libc::SYS_vfork, libc::SYS_clone, libc::SYS_clone3]);
        Self::deny_all_except(allow, deny)
    }

    /// A default-deny allowlist for a **production adapter** (design §13.1): a single
    /// process that reads task inputs, does I/O on the inherited broker fd, and writes
    /// outputs — run directly, with **no wrapping shell and no process creation**.
    ///
    /// It is [`clean_worker_baseline`] minus the process-creation family
    /// (`clone`/`clone3`/`vfork`): a compromised adapter cannot spawn a helper or a
    /// thread, and — as in every profile — cannot `socket()`/`connect()` to reach the
    /// network. `execve` remains (bubblewrap performs the adapter's own launch under
    /// this filter), but without process creation the adapter can only replace its own
    /// image — and even a shell it `execve`s is inert, unable to `fork` to run a single
    /// external command. Validated live: the real `akson-adapter-openai` runs to
    /// completion confined over a brokered model call under this profile (bubblewrap's
    /// pid-1 monitor `fork`s the sandboxed child *before* the filter is installed, so
    /// omitting `clone`/`vfork` does not disturb the launch).
    pub fn adapter_worker_baseline(deny: DenyAction) -> Self {
        Self::deny_all_except(common_worker_syscalls(), deny)
    }

    /// A default-deny allowlist for an **agent-tool worker** (design
    /// 2026-07-19-agent-harness): a full agent CLI (Codex, herdr, OpenCode — Node
    /// runtimes) run confined, reaching its model through a loopback proxy.
    ///
    /// Unlike the adapter profiles this one permits the **socket family** and process
    /// creation, because the agent runtime forks/threads and must open a TCP socket to
    /// the in-sandbox proxy. Allowing `socket`/`connect` does NOT open the network: the
    /// worker runs in a net namespace with **loopback only and no route out**, so the
    /// only address it can reach is `127.0.0.1` (the proxy). seccomp cannot restrict
    /// `connect` to loopback — its argument is a pointer — so that seal is the
    /// namespace's job; this filter only enables the syscalls the runtime needs.
    ///
    /// This set is a *principled starting point* — a Node runtime touches many
    /// syscalls, so the exact list is tuned by live syscall discovery when a real
    /// agent runs under it (as the other profiles were).
    pub fn agent_worker_baseline(deny: DenyAction) -> Self {
        let mut allow = common_worker_syscalls();
        allow.extend_from_slice(&[
            // Process creation (a runtime forks/threads/execs, like the shell profile).
            libc::SYS_vfork,
            libc::SYS_clone,
            libc::SYS_clone3,
            // The socket family — only loopback is reachable (net namespace has no route).
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,
            libc::SYS_shutdown,
            libc::SYS_socketpair,
            // Async runtime primitives (libuv/V8 event loop).
            libc::SYS_epoll_wait,
            libc::SYS_eventfd2,
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            libc::SYS_timerfd_gettime,
            libc::SYS_signalfd4,
        ]);
        Self::deny_all_except(allow, deny)
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
        let raw = unsafe { libc::memfd_create(c"akson-seccomp".as_ptr(), 0) };
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

/// The syscalls common to every worker profile: enough for a single process to
/// start, read inputs, do I/O on already-open fds (including the inherited broker
/// fd), and write outputs — but *not* the process-CREATION family (that is added
/// only by [`SeccompPolicy::clean_worker_baseline`] for the shell stand-in).
///
/// Two subtleties, both validated live against a real confined adapter under
/// bubblewrap:
/// - `execve` is here, not shell-only: bubblewrap `execve`s the target program under
///   the filter, so every profile must permit it. What keeps a direct adapter from
///   spawning is the absence of `fork`/`vfork`/`clone` — without those it can only
///   replace its own image, never run a helper alongside its work.
/// - `wait4`, `pipe`/`pipe2`, and `splice` are here too: bubblewrap's own pid-1
///   monitor runs under this same filter and needs them to reap the sandboxed child.
///   They confer no spawning ability on their own (no `clone`/`fork` to create the
///   process being waited on).
fn common_worker_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        // Reaping + plumbing bubblewrap's pid-1 monitor performs under this filter
        // (it forked the sandboxed child *before* installing the filter).
        libc::SYS_wait4,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        // Zero-copy move between two already-open fds — no new authority (the process
        // can already read/write those fds); real tools use it to copy input→output.
        libc::SYS_splice,
        // Send/receive on an ALREADY-connected fd — how Rust's std does I/O on a
        // socket (the inherited broker fd). No new reach: socket(), connect(),
        // bind(), listen() stay off the list, so the worker can neither open a
        // socket nor connect anywhere.
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        // Vectored positional I/O — the same read/write authority as the scalar
        // variants above; the Rust std I/O layer uses them.
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_lseek,
        libc::SYS_close,
        // Close a range of file descriptors — how modern glibc/Rust closes inherited
        // fds at startup; only closes, never opens.
        libc::SYS_close_range,
        libc::SYS_openat,
        libc::SYS_open,
        // Create a directory. The worker can already create files in /output via
        // openat(O_CREAT); a directory is no more reach. Without it the adapter SDK's
        // write_artifact → create_dir_all("/output/artifacts") is killed, so a real
        // SARIF-producing adapter granted artifact_export cannot deliver (codex review).
        libc::SYS_mkdir,
        libc::SYS_mkdirat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        // Read-only filesystem statistics (block size, free space) on a path/fd the
        // worker can already reach — no isolation impact; real tools call it to size
        // their I/O buffers.
        libc::SYS_statfs,
        libc::SYS_fstatfs,
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
        libc::SYS_poll,
        libc::SYS_ppoll,
        // Present so bubblewrap can `execve` the target program under this filter;
        // process *creation* (fork/vfork/clone) is deliberately absent here.
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_futex,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_arch_prctl,
        // Process-control operations a runtime uses (e.g. PR_SET_NAME); the
        // security-relevant ones (PR_SET_SECCOMP, PR_SET_NO_NEW_PRIVS) are gated by
        // the already-applied no_new_privs + filter, so they cannot widen authority.
        libc::SYS_prctl,
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
    ]
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

    #[test]
    fn baseline_allows_a_shell_worker_to_run_external_tools_but_not_the_network() {
        let policy = SeccompPolicy::clean_worker_baseline(DenyAction::KillProcess);
        // The syscalls a shell needs to spawn an external tool that copies a file
        // (validated live against uutils `cat`), and the send/recv family a Rust
        // adapter uses to talk on the inherited broker fd (validated live against
        // the OpenAI adapter): without these the worker is SIGSYS-killed.
        for needed in [
            libc::SYS_vfork,
            libc::SYS_statfs,
            libc::SYS_prctl,
            libc::SYS_splice,
            libc::SYS_pipe,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
        ] {
            assert!(
                policy.allow.contains(&needed),
                "baseline must allow {needed}"
            );
        }
        // But the network stays sealed: the worker can neither OPEN a socket nor
        // connect anywhere — only I/O on fds it already holds is permitted.
        for denied in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_ptrace,
        ] {
            assert!(
                !policy.allow.contains(&denied),
                "baseline must NOT allow {denied}"
            );
        }
    }

    #[test]
    fn adapter_profile_denies_process_creation_but_keeps_io() {
        let adapter = SeccompPolicy::adapter_worker_baseline(DenyAction::KillProcess);
        // A single-process adapter can still start, read inputs, talk on the broker
        // fd, and write outputs — and bubblewrap can execve it under this filter.
        for needed in [
            libc::SYS_openat,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_mmap,
            libc::SYS_futex,
            libc::SYS_execve,
        ] {
            assert!(
                adapter.allow.contains(&needed),
                "adapter must allow {needed}"
            );
        }
        // But it cannot CREATE a process (no fork/vfork/clone — so it can neither
        // spawn a helper nor start a thread, and even a shell it execs cannot fork to
        // run a command), and — as in every profile — cannot open the network.
        for denied in [
            libc::SYS_vfork,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
        ] {
            assert!(
                !adapter.allow.contains(&denied),
                "adapter must NOT allow {denied}"
            );
        }
        // The shell baseline is a strict superset: everything the adapter allows,
        // plus the process-spawning family.
        let shell = SeccompPolicy::clean_worker_baseline(DenyAction::KillProcess);
        for &s in &adapter.allow {
            assert!(
                shell.allow.contains(&s),
                "shell baseline must be a superset ({s})"
            );
        }
        assert!(shell.allow.len() > adapter.allow.len());
    }

    #[test]
    fn agent_profile_adds_the_socket_family_and_process_creation() {
        let agent = SeccompPolicy::agent_worker_baseline(DenyAction::KillProcess);
        // An agent runtime opens a socket to the loopback proxy and forks/threads.
        for needed in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_clone,
            libc::SYS_epoll_wait,
            libc::SYS_eventfd2,
        ] {
            assert!(agent.allow.contains(&needed), "agent must allow {needed}");
        }
        // It is a strict superset of the adapter profile (adds sockets + spawning).
        let adapter = SeccompPolicy::adapter_worker_baseline(DenyAction::KillProcess);
        for &s in &adapter.allow {
            assert!(agent.allow.contains(&s), "agent must be a superset ({s})");
        }
        assert!(agent.allow.len() > adapter.allow.len());
        // The network reachability is bounded by the net namespace, not this filter —
        // socket() is allowed here; the fresh loopback-only ns is what seals egress.
        assert!(agent.compile().is_ok());
    }

    /// Enforcement, validated unprivileged: under the adapter profile a process
    /// cannot create another process — `fork()` (which glibc issues as `clone`) is
    /// denied. This is what makes even an `execve`'d shell inert: it cannot fork to
    /// run a command. Runs anywhere (seccomp needs no user namespace).
    #[test]
    fn adapter_profile_blocks_forking_a_child() {
        // Errno (not kill) so the forking child observes the denial and exits cleanly.
        let policy = SeccompPolicy::adapter_worker_baseline(DenyAction::Errno(libc::EPERM as u32));
        let program = policy.compile().unwrap();

        // SAFETY: the child performs only syscalls (no allocation/locks) before _exit.
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
                // clone/clone3/vfork are not allowlisted → fork() gets EPERM.
                let pid = unsafe { libc::fork() };
                let code = if pid < 0 { 0 } else { 1 };
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
                assert_eq!(code, 0, "fork() must be denied by the adapter profile");
            }
        }
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
