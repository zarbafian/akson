//! Linux namespace entry for the clean worker (design §13.1).
//!
//! [`enter_namespaces`] unshares the requested namespaces and, when a user
//! namespace is included, maps the current uid/gid to root *inside* it — so an
//! unprivileged daemon gains isolated root within the sandbox without any host
//! privilege. This is the unprivileged-isolation foundation the rest of the
//! clean-worker setup (mounts, `pivot_root`, seccomp, Landlock, exec) builds on.
//!
//! It must be called in a freshly forked child, before it creates threads or
//! execs, and before writing any file the mapping depends on. Unlike seccomp and
//! Landlock, this needs unprivileged user namespaces, which some hosts restrict —
//! so the live test is `#[ignore]`d and runs in CI's permissive `isolation` job.
//!
//! Note on PID: unsharing [`Pid`](crate::Namespace::Pid) affects the caller's
//! *future children*, not the caller — to make the worker PID 1 the daemon forks
//! once more after entering, which the launcher does when it wires up exec.

use std::fs;

use crate::launcher::Namespace;

/// Why entering namespaces failed.
#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error("unshare failed (errno {0})")]
    Unshare(i32),
    #[error("writing {0} failed")]
    Map(&'static str),
}

/// Unshares `namespaces` for the current process and, if `User` is among them,
/// maps the current uid/gid to root inside the new user namespace (design §13.1).
///
/// Combining `User` with the others in a single `unshare` is what makes the
/// unprivileged case work: the new user namespace grants the capabilities needed
/// to create the mount/net/etc. namespaces. `setgroups` is denied before the gid
/// map is written, as the kernel requires.
pub fn enter_namespaces(namespaces: &[Namespace]) -> Result<(), NamespaceError> {
    // SAFETY: getuid/getgid are always safe and never fail.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let flags = clone_flags(namespaces);
    // SAFETY: `flags` is a valid combination of CLONE_NEW* constants.
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(NamespaceError::Unshare(errno()));
    }

    if namespaces.contains(&Namespace::User) {
        // Denying setgroups is required before writing gid_map (Linux ≥ 3.19);
        // a kernel without the knob simply lacks the file, which is fine.
        let _ = fs::write("/proc/self/setgroups", b"deny");
        fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))
            .map_err(|_| NamespaceError::Map("uid_map"))?;
        fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))
            .map_err(|_| NamespaceError::Map("gid_map"))?;
    }
    Ok(())
}

/// Maps the plan's [`Namespace`]s to a `CLONE_NEW*` flag mask.
fn clone_flags(namespaces: &[Namespace]) -> libc::c_int {
    let mut flags = 0;
    for ns in namespaces {
        flags |= match ns {
            Namespace::User => libc::CLONE_NEWUSER,
            Namespace::Mount => libc::CLONE_NEWNS,
            Namespace::Pid => libc::CLONE_NEWPID,
            Namespace::Net => libc::CLONE_NEWNET,
            Namespace::Ipc => libc::CLONE_NEWIPC,
            Namespace::Uts => libc::CLONE_NEWUTS,
            Namespace::Cgroup => libc::CLONE_NEWCGROUP,
        };
    }
    flags
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
    fn clone_flags_covers_every_namespace() {
        // Pure: the flag mask includes each requested namespace's bit.
        let all = [
            Namespace::User,
            Namespace::Mount,
            Namespace::Pid,
            Namespace::Net,
            Namespace::Ipc,
            Namespace::Uts,
            Namespace::Cgroup,
        ];
        let f = clone_flags(&all);
        for bit in [
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWNS,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWCGROUP,
        ] {
            assert_ne!(f & bit, 0, "flag mask missing a namespace bit");
        }
    }

    /// Live isolation: entering a user + network namespace must give mapped-root
    /// and no external connectivity. Needs unprivileged user namespaces, so it is
    /// ignored by default and run by CI's permissive `isolation` job (or locally
    /// after enabling userns).
    #[test]
    #[ignore = "needs unprivileged user namespaces; runs in CI's isolation job"]
    fn user_and_network_namespace_isolate() {
        // SAFETY: the child performs namespace setup and syscalls, then _exit;
        // enter_namespaces' small allocations are fork-safe under glibc.
        match unsafe { libc::fork() } {
            -1 => panic!("fork failed"),
            0 => {
                let ns = [
                    Namespace::User,
                    Namespace::Net,
                    Namespace::Uts,
                    Namespace::Ipc,
                ];
                if enter_namespaces(&ns).is_err() {
                    unsafe { libc::_exit(90) };
                }
                // The daemon's uid is mapped to root inside the user namespace.
                if unsafe { libc::getuid() } != 0 {
                    unsafe { libc::_exit(91) };
                }
                // A fresh network namespace has no route to the outside; a TCP
                // connect to a public address must fail.
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                if fd < 0 {
                    unsafe { libc::_exit(92) };
                }
                let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                addr.sin_family = libc::AF_INET as libc::sa_family_t;
                addr.sin_port = 53u16.to_be();
                addr.sin_addr.s_addr = u32::from_ne_bytes([8, 8, 8, 8]); // 8.8.8.8
                let rc = unsafe {
                    libc::connect(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };
                // rc == 0 would mean the network was reachable — isolation failed.
                unsafe { libc::_exit(if rc == 0 { 93 } else { 0 }) };
            }
            pid => {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                assert!(libc::WIFEXITED(status), "child should exit normally");
                match libc::WEXITSTATUS(status) {
                    0 => {}
                    90 => panic!("entering user+net namespaces failed"),
                    91 => panic!("uid was not mapped to root inside the user namespace"),
                    92 => panic!("socket() failed in the child"),
                    93 => panic!("external network was reachable — net namespace not isolated"),
                    other => panic!("unexpected child exit code {other}"),
                }
            }
        }
    }
}
