//! Sandbox capability diagnostics — the data behind `axon doctor` (design §17.3,
//! §13.1 exit: "doctor reports every capability").
//!
//! [`diagnose`] reports each isolation capability the clean worker depends on —
//! whether it is available, whether it is *required*, and a human-readable detail
//! (e.g. why user namespaces are blocked). [`all_required_available`] is the
//! fail-closed gate: if any required capability is missing, the worker must not
//! run. This surfaces the same facts the [probe](crate::probe) enforces, for a
//! human.
//!
//! What you write:
//! ```
//! use axon_sandbox::{diagnose, all_required_available};
//! let report = diagnose();
//! for d in &report {
//!     println!("{:>18}: {}{}", d.feature, if d.available { "ok" } else { "MISSING" },
//!              if d.required { "" } else { " (optional)" });
//! }
//! let _ready = all_required_available(&report);
//! ```

use std::path::Path;

use crate::cgroup::find_delegated_parent;
use crate::probe::detect;

/// One capability's status in the sandbox diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub feature: &'static str,
    pub available: bool,
    /// Whether a clean-worker launch requires this capability (Landlock and the
    /// experimental native launcher's extras are optional; the rest are required).
    pub required: bool,
    pub detail: String,
}

/// Produces the full sandbox capability report (design §17.3). Reads `/proc`,
/// `/sys`, and `PATH`; every check is best-effort and treats an unreadable signal
/// as unavailable.
pub fn diagnose() -> Vec<Diagnostic> {
    let f = detect();
    let req = |feature, available, detail: &str| Diagnostic {
        feature,
        available,
        required: true,
        detail: detail.to_owned(),
    };

    vec![
        req(
            "user_namespaces",
            f.user_namespaces,
            if f.user_namespaces {
                "available"
            } else {
                "blocked — check kernel.apparmor_restrict_unprivileged_userns / max_user_namespaces"
            },
        ),
        req("cgroup2", f.cgroup2, "unified cgroup v2 hierarchy"),
        req(
            "memory_controller",
            f.memory_controller,
            "cgroup memory.max",
        ),
        req("pids_controller", f.pids_controller, "cgroup pids.max"),
        req(
            "cgroup_delegation",
            find_delegated_parent().is_some(),
            "a writable delegated subtree with memory+pids controllers",
        ),
        req("seccomp", f.seccomp, "default-deny syscall filter"),
        req("no_new_privs", f.no_new_privs, "prctl(PR_SET_NO_NEW_PRIVS)"),
        req(
            "bubblewrap",
            which("bwrap").is_some(),
            "the v1 launcher backend (ADR-0006)",
        ),
        Diagnostic {
            feature: "landlock",
            available: f.landlock,
            required: false,
            detail: "best-effort filesystem confinement (§13.1)".to_owned(),
        },
    ]
}

/// Whether every *required* capability is available — the fail-closed gate a
/// launch checks (design §13.1: refuse rather than run un-isolated).
pub fn all_required_available(report: &[Diagnostic]) -> bool {
    report.iter().all(|d| !d.required || d.available)
}

/// Locates an executable on `PATH` (a small `which`).
fn which(program: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|p| is_executable(p))
}

fn is_executable(path: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: c is a valid C string; access() only reads it.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn report_covers_every_capability_and_marks_landlock_optional() {
        let report = diagnose();
        for expected in [
            "user_namespaces",
            "cgroup2",
            "memory_controller",
            "pids_controller",
            "cgroup_delegation",
            "seccomp",
            "no_new_privs",
            "bubblewrap",
            "landlock",
        ] {
            assert!(
                report.iter().any(|d| d.feature == expected),
                "diagnostic report missing {expected}"
            );
        }
        // Landlock is the only optional capability.
        let landlock = report.iter().find(|d| d.feature == "landlock").unwrap();
        assert!(!landlock.required);
        assert!(report.iter().filter(|d| !d.required).count() == 1);
    }

    #[test]
    fn required_gate_fails_when_any_required_is_missing() {
        // A synthetic report: one required feature missing → gate is closed.
        let ok = Diagnostic {
            feature: "x",
            available: true,
            required: true,
            detail: String::new(),
        };
        let missing = Diagnostic {
            feature: "y",
            available: false,
            required: true,
            detail: String::new(),
        };
        let optional_missing = Diagnostic {
            feature: "z",
            available: false,
            required: false,
            detail: String::new(),
        };
        assert!(all_required_available(&[
            ok.clone(),
            optional_missing.clone()
        ]));
        assert!(!all_required_available(&[ok, missing, optional_missing]));
    }
}
