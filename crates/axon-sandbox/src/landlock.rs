//! Landlock filesystem restriction (design §13.1, "Landlock where available").
//!
//! A [`LandlockPolicy`] confines the process to a set of paths: read-only paths
//! (the digest-pinned runtime and supplied inputs) and read-write paths (scratch
//! and output). Everything else on the filesystem becomes inaccessible. Like
//! seccomp, Landlock needs no user namespace and restricts *the calling process*
//! (via `restrict_self`), so it is enforced — and *tested* — unprivileged, even
//! on a userns-restricted host. Landlock is best-effort (§13.1): where the kernel
//! lacks it, [`apply`](LandlockPolicy::apply) reports [`NotEnforced`] rather than
//! failing, and the caller relies on the other layers.
//!
//! [`NotEnforced`]: LandlockOutcome::NotEnforced
//!
//! What you write:
//! ```no_run
//! use axon_sandbox::LandlockPolicy;
//! let policy = LandlockPolicy {
//!     read_only: vec!["/runtime".into()],
//!     read_write: vec!["/scratch".into(), "/output".into()],
//! };
//! let outcome = policy.apply().unwrap(); // restricts this process to those paths
//! println!("landlock: {outcome:?}");
//! ```

use std::path::PathBuf;

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};

/// The filesystem confinement for a worker (design §13.1).
#[derive(Debug, Clone, Default)]
pub struct LandlockPolicy {
    /// Paths the worker may read (and traverse) but not modify.
    pub read_only: Vec<PathBuf>,
    /// Paths the worker may read and write (scratch, output).
    pub read_write: Vec<PathBuf>,
}

/// How completely Landlock took effect (design §13.1 — best-effort).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockOutcome {
    /// The kernel enforced the full ruleset.
    FullyEnforced,
    /// The kernel enforced a subset (an older Landlock ABI).
    PartiallyEnforced,
    /// The kernel does not support Landlock; nothing was enforced.
    NotEnforced,
}

/// Why a Landlock policy could not be built or applied.
#[derive(Debug, thiserror::Error)]
#[error("landlock restriction failed: {0}")]
pub struct LandlockError(String);

impl LandlockPolicy {
    /// Restricts the current process to the policy's paths (design §13.1). Handles
    /// all filesystem access, then re-grants read to `read_only` paths and full
    /// access to `read_write` paths — everything else becomes inaccessible.
    /// Returns how completely the kernel enforced it. Idempotent-safe but one-way:
    /// a restriction cannot be loosened once applied.
    pub fn apply(&self) -> Result<LandlockOutcome, LandlockError> {
        let abi = ABI::V1;
        let err = |e: &dyn std::fmt::Display| LandlockError(e.to_string());

        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| err(&e))?
            .create()
            .map_err(|e| err(&e))?;
        for path in &self.read_only {
            let rule = PathBeneath::new(
                PathFd::new(path).map_err(|e| err(&e))?,
                AccessFs::from_read(abi),
            );
            ruleset = ruleset.add_rule(rule).map_err(|e| err(&e))?;
        }
        for path in &self.read_write {
            let rule = PathBeneath::new(
                PathFd::new(path).map_err(|e| err(&e))?,
                AccessFs::from_all(abi),
            );
            ruleset = ruleset.add_rule(rule).map_err(|e| err(&e))?;
        }
        let status = ruleset.restrict_self().map_err(|e| err(&e))?;
        Ok(match status.ruleset {
            RulesetStatus::FullyEnforced => LandlockOutcome::FullyEnforced,
            RulesetStatus::PartiallyEnforced => LandlockOutcome::PartiallyEnforced,
            RulesetStatus::NotEnforced => LandlockOutcome::NotEnforced,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;

    #[test]
    fn read_only_confinement_is_enforced_in_a_child() {
        // Layout: <tmp>/ro (allowed read-only, contains a file) and <tmp>/out
        // (not granted). Under the policy a read of ro/file must succeed and a
        // write into out/ must be denied.
        let tmp = std::env::temp_dir().join(format!("axon-ll-{}", std::process::id()));
        let ro = tmp.join("ro");
        let out = tmp.join("out");
        fs::create_dir_all(&ro).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(ro.join("input"), b"supplied").unwrap();

        let ro_file = CString::new(ro.join("input").to_str().unwrap()).unwrap();
        let out_file = CString::new(out.join("forbidden").to_str().unwrap()).unwrap();
        let policy = LandlockPolicy {
            read_only: vec![ro.clone()],
            read_write: vec![],
        };

        // SAFETY: the child performs only path opens and _exit; Landlock's ruleset
        // build allocates via glibc malloc, which is fork-safe (atfork handlers).
        let code = match unsafe { libc::fork() } {
            -1 => panic!("fork failed"),
            0 => {
                let outcome = match policy.apply() {
                    Ok(o) => o,
                    Err(_) => unsafe { libc::_exit(98) },
                };
                if outcome == LandlockOutcome::NotEnforced {
                    // Kernel without Landlock — skip the enforcement assertions.
                    unsafe { libc::_exit(96) };
                }
                // A read of the allowed file must succeed.
                let rfd = unsafe { libc::open(ro_file.as_ptr(), libc::O_RDONLY) };
                let read_ok = rfd >= 0;
                // A write outside the granted set must be denied.
                let wfd =
                    unsafe { libc::open(out_file.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644) };
                let write_denied = wfd < 0;
                let ok = read_ok && write_denied;
                unsafe { libc::_exit(if ok { 0 } else { 1 }) };
            }
            pid => {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                assert!(libc::WIFEXITED(status), "child should exit normally");
                libc::WEXITSTATUS(status)
            }
        };

        let _ = fs::remove_dir_all(&tmp);
        match code {
            96 => eprintln!("landlock not enforced on this kernel; enforcement assertions skipped"),
            98 => panic!("landlock apply() failed in the child"),
            0 => {}
            other => panic!("landlock confinement not enforced (child code {other})"),
        }
    }
}
