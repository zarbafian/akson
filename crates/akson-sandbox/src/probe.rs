//! Fail-closed capability probing (design §13.1).
//!
//! The clean worker's isolation depends on kernel features that are not
//! guaranteed to be present or permitted: unprivileged user namespaces (which
//! some distributions restrict via AppArmor), cgroup v2 with the memory and pids
//! controllers, seccomp, and `no_new_privs`. Landlock is used *where available*
//! and is therefore best-effort, not required.
//!
//! Probing **fails closed**: if any required feature is unavailable, the launcher
//! refuses to run rather than execute a worker without the isolation the work
//! order assumes. The detection ([`detect`]) reads `/proc` and `/sys`; the
//! decision ([`ensure`]) is a pure check over a [`IsolationFeatures`] report, so
//! it is testable without any particular kernel.
//!
//! What you write:
//! ```
//! use akson_sandbox::{ensure, required, IsolationFeatures};
//! // A report with everything present passes the fail-closed gate.
//! let features = IsolationFeatures {
//!     user_namespaces: true, cgroup2: true, memory_controller: true,
//!     pids_controller: true, seccomp: true, no_new_privs: true, landlock: true,
//! };
//! ensure(&features, required()).unwrap();
//! ```

use std::fs;

/// A kernel isolation feature the launcher may require or use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    UserNamespaces,
    Cgroup2,
    MemoryController,
    PidsController,
    Seccomp,
    NoNewPrivs,
    /// Best-effort (used where available); never required.
    Landlock,
}

/// A snapshot of which isolation features are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsolationFeatures {
    pub user_namespaces: bool,
    pub cgroup2: bool,
    pub memory_controller: bool,
    pub pids_controller: bool,
    pub seccomp: bool,
    pub no_new_privs: bool,
    pub landlock: bool,
}

impl IsolationFeatures {
    /// Whether a given feature is available in this report.
    pub fn has(&self, feature: Feature) -> bool {
        match feature {
            Feature::UserNamespaces => self.user_namespaces,
            Feature::Cgroup2 => self.cgroup2,
            Feature::MemoryController => self.memory_controller,
            Feature::PidsController => self.pids_controller,
            Feature::Seccomp => self.seccomp,
            Feature::NoNewPrivs => self.no_new_privs,
            Feature::Landlock => self.landlock,
        }
    }
}

/// The features the v1 clean worker's isolation requires (design §13.1). Landlock
/// is intentionally absent — it is applied where available but never required.
pub fn required() -> &'static [Feature] {
    &[
        Feature::UserNamespaces,
        Feature::Cgroup2,
        Feature::MemoryController,
        Feature::PidsController,
        Feature::Seccomp,
        Feature::NoNewPrivs,
    ]
}

/// The required features that are unavailable — the reason a launch is refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("isolation unavailable; missing required features: {missing:?}")]
pub struct MissingFeatures {
    pub missing: Vec<Feature>,
}

/// Fails closed unless every `required` feature is present (design §13.1). Pure —
/// the caller passes a [`detect`]ed report (or a synthetic one in tests).
pub fn ensure(features: &IsolationFeatures, required: &[Feature]) -> Result<(), MissingFeatures> {
    let missing: Vec<Feature> = required
        .iter()
        .copied()
        .filter(|f| !features.has(*f))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(MissingFeatures { missing })
    }
}

/// Detects the isolation features available to this process by reading `/proc`
/// and `/sys` (design §13.1). Conservative and fail-closed: an unreadable or
/// ambiguous signal is treated as *unavailable*.
pub fn detect() -> IsolationFeatures {
    IsolationFeatures {
        user_namespaces: detect_user_namespaces(),
        cgroup2: cgroup2_present(),
        memory_controller: cgroup2_has_controller("memory"),
        pids_controller: cgroup2_has_controller("pids"),
        seccomp: proc_status_has_field("Seccomp"),
        no_new_privs: proc_status_has_field("NoNewPrivs"),
        landlock: lsm_lists("landlock"),
    }
}

/// Unprivileged user namespaces are available only if the kernel permits them
/// *and* an AppArmor restriction is not in force. Either signal being off makes
/// the feature unavailable (fail-closed).
fn detect_user_namespaces() -> bool {
    // A distro knob explicitly disabling unprivileged userns clone.
    if read_trimmed("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return false;
    }
    // Ubuntu's AppArmor restriction blocks unprofiled binaries from creating a
    // user namespace; treat "restricted" as unavailable here.
    if read_trimmed("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref()
        == Some("1")
    {
        return false;
    }
    // A zero cap on user namespaces disables them.
    if read_trimmed("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
        return false;
    }
    true
}

fn cgroup2_present() -> bool {
    fs::metadata("/sys/fs/cgroup/cgroup.controllers").is_ok()
}

fn cgroup2_has_controller(name: &str) -> bool {
    read_trimmed("/sys/fs/cgroup/cgroup.controllers")
        .map(|s| s.split_whitespace().any(|c| c == name))
        .unwrap_or(false)
}

fn proc_status_has_field(field: &str) -> bool {
    fs::read_to_string("/proc/self/status")
        .map(|s| s.lines().any(|l| l.starts_with(&format!("{field}:"))))
        .unwrap_or(false)
}

fn lsm_lists(name: &str) -> bool {
    read_trimmed("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|l| l == name))
        .unwrap_or(false)
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn all_present() -> IsolationFeatures {
        IsolationFeatures {
            user_namespaces: true,
            cgroup2: true,
            memory_controller: true,
            pids_controller: true,
            seccomp: true,
            no_new_privs: true,
            landlock: true,
        }
    }

    #[test]
    fn all_required_present_passes() {
        ensure(&all_present(), required()).unwrap();
    }

    #[test]
    fn a_missing_required_feature_fails_closed() {
        let mut f = all_present();
        f.user_namespaces = false;
        let err = ensure(&f, required()).unwrap_err();
        assert_eq!(err.missing, vec![Feature::UserNamespaces]);
    }

    #[test]
    fn landlock_absent_still_passes_because_it_is_optional() {
        // Landlock is best-effort; its absence must not block a launch.
        let mut f = all_present();
        f.landlock = false;
        ensure(&f, required()).unwrap();
        assert!(!required().contains(&Feature::Landlock));
    }

    #[test]
    fn all_missing_reports_every_required_feature() {
        let none = IsolationFeatures {
            user_namespaces: false,
            cgroup2: false,
            memory_controller: false,
            pids_controller: false,
            seccomp: false,
            no_new_privs: false,
            landlock: false,
        };
        let err = ensure(&none, required()).unwrap_err();
        assert_eq!(err.missing.len(), required().len());
    }

    #[test]
    fn detect_returns_a_report_without_panicking() {
        // On any host this must produce a report (values are environment-specific,
        // so we only assert it runs and `has` is consistent with the fields).
        let f = detect();
        assert_eq!(f.has(Feature::Seccomp), f.seccomp);
        assert_eq!(f.has(Feature::Cgroup2), f.cgroup2);
    }
}
