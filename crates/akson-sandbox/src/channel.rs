//! The broker channel for a confined worker's model calls (design §13.1).
//!
//! A `processor_use` grant does not open the network for the worker — the seccomp
//! filter still denies `socket()`. Instead the gateway hands the worker one
//! **already-connected** `AF_UNIX` fd, inherited across `exec` into the sandbox,
//! and services the other end itself. The worker writes a request on that fd and
//! reads the completion; the daemon — outside the box, holding the credential, the
//! egress allowlist, and the budget — makes the real call. The only way "out" of
//! the sandbox is this one mediated pipe.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Creates a connected `AF_UNIX` stream pair for the broker channel. Returns the
/// **worker end** (a raw owned fd, left inheritable / non-`CLOEXEC` so it survives
/// `exec` into the sandbox — its number is handed to the worker via an environment
/// variable) and the **daemon end** as a [`UnixStream`] the gateway reads and
/// writes. The daemon end is marked `CLOEXEC` so it never leaks into the sandbox.
///
/// Because the worker inherits an already-open socket, it needs no `socket()` or
/// `connect()` syscall — the network seal (`socket` stays off the seccomp
/// allowlist) is untouched.
pub fn broker_socketpair() -> std::io::Result<(OwnedFd, UnixStream)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` is a valid two-element buffer; socketpair fills both entries on
    // success (return 0) and touches nothing on failure.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both are fresh, owned fds returned by socketpair; each is wrapped once.
    let worker = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let daemon = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    // The daemon end must not cross into the sandbox — mark it CLOEXEC. The worker
    // end is deliberately left inheritable (socketpair does not set CLOEXEC).
    set_cloexec(daemon.as_raw_fd())?;
    Ok((worker, UnixStream::from(daemon)))
}

use std::os::fd::AsRawFd;

fn set_cloexec(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: F_GETFD/F_SETFD on a valid fd; no memory is involved.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn the_pair_is_connected_and_the_daemon_end_is_cloexec() {
        let (worker, mut daemon) = broker_socketpair().unwrap();

        // The worker end is inheritable (non-CLOEXEC) so it can cross exec.
        // SAFETY: F_GETFD on a live fd.
        let wflags = unsafe { libc::fcntl(worker.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(
            wflags & libc::FD_CLOEXEC,
            0,
            "worker end must be inheritable"
        );

        // The daemon end is CLOEXEC so it never leaks into the sandbox.
        // SAFETY: F_GETFD on a live fd.
        let dflags = unsafe { libc::fcntl(daemon.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(dflags & libc::FD_CLOEXEC, 0, "daemon end must be CLOEXEC");

        // The two ends are connected: bytes written on one arrive on the other.
        let mut worker_stream = UnixStream::from(worker);
        worker_stream.write_all(b"ping\n").unwrap();
        let mut buf = [0u8; 5];
        daemon.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping\n");
        daemon.write_all(b"pong\n").unwrap();
        let mut back = [0u8; 5];
        worker_stream.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"pong\n");
    }
}
