//! cgroup v2 resource limits for the clean worker (design §13.1).
//!
//! A [`CgroupScope`] is a leaf cgroup created under the daemon's delegated
//! subtree, with memory / pids / cpu limits applied before the worker is placed
//! in it. The scope removes the cgroup when dropped. cgroups need no user
//! namespace, so this is enforced — and tested — directly.
//!
//! Placing the worker: the launcher writes bubblewrap's pid to the scope's
//! `cgroup.procs` before bwrap forks the worker, so the whole sandbox tree is
//! bounded. (`clone3(CLONE_INTO_CGROUP)` is the race-free alternative once daemon
//! integration lands.)
//!
//! What you write:
//! ```no_run
//! use akson_sandbox::{CgroupScope, CgroupLimits};
//! let scope = CgroupScope::create("akson-worker-1", &CgroupLimits {
//!     max_memory_bytes: Some(256 * 1024 * 1024),
//!     max_pids: Some(64),
//!     cpu_max: None,
//! }).unwrap();
//! scope.add_process(std::process::id() as i32).unwrap();
//! // dropping `scope` removes the (now-empty) cgroup
//! ```

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The resource ceilings a worker cgroup enforces (design §13.1). `None` leaves a
/// dimension at the cgroup default (`max`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupLimits {
    pub max_memory_bytes: Option<u64>,
    pub max_pids: Option<u64>,
    /// `cpu.max` as `(quota_us, period_us)` — e.g. `(50_000, 100_000)` is 50% of
    /// one CPU. `None` is unlimited.
    pub cpu_max: Option<(u64, u64)>,
}

/// Why a cgroup could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    #[error("no writable delegated cgroup v2 subtree with the required controllers")]
    NoDelegatedSubtree,
    #[error("cgroup {op}: {source}")]
    Io {
        op: &'static str,
        source: std::io::Error,
    },
}

fn io(op: &'static str) -> impl FnOnce(std::io::Error) -> CgroupError {
    move |source| CgroupError::Io { op, source }
}

/// A worker's leaf cgroup. Removed on drop (which succeeds once it holds no
/// processes).
#[derive(Debug)]
pub struct CgroupScope {
    path: PathBuf,
}

impl CgroupScope {
    /// Creates a leaf cgroup `name` under the delegated subtree and applies
    /// `limits`. Fails closed if no writable delegated subtree with the memory and
    /// pids controllers exists (§13.1 requires cgroup enforcement).
    pub fn create(name: &str, limits: &CgroupLimits) -> Result<Self, CgroupError> {
        let parent = find_delegated_parent().ok_or(CgroupError::NoDelegatedSubtree)?;
        let path = parent.join(name);
        fs::create_dir(&path).map_err(io("create_dir"))?;
        let scope = Self { path };
        if let Some(m) = limits.max_memory_bytes {
            scope.write("memory.max", &m.to_string())?;
        }
        if let Some(p) = limits.max_pids {
            scope.write("pids.max", &p.to_string())?;
        }
        if let Some((quota, period)) = limits.cpu_max {
            scope.write("cpu.max", &format!("{quota} {period}"))?;
        }
        Ok(scope)
    }

    /// Moves a process into this cgroup, subjecting it (and its children) to the
    /// limits.
    pub fn add_process(&self, pid: i32) -> Result<(), CgroupError> {
        self.write("cgroup.procs", &pid.to_string())
    }

    /// The cgroup's path under `/sys/fs/cgroup`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A scope naming `path` without creating or owning any real cgroup — only for
    /// unit tests of launch paths that fail (probe/not-wired) before the cgroup is
    /// ever used. Drop's `remove_dir` is best-effort and harmless on such a path.
    #[cfg(test)]
    pub(crate) fn detached(path: PathBuf) -> Self {
        Self { path }
    }

    fn write(&self, file: &str, value: &str) -> Result<(), CgroupError> {
        fs::write(self.path.join(file), value).map_err(io(leaked(file)))
    }
}

impl Drop for CgroupScope {
    fn drop(&mut self) {
        // Removes only once the cgroup holds no processes; best-effort.
        let _ = fs::remove_dir(&self.path);
    }
}

/// A `&'static str` for the file being written, for the error `op`.
fn leaked(file: &str) -> &'static str {
    match file {
        "memory.max" => "write memory.max",
        "pids.max" => "write pids.max",
        "cpu.max" => "write cpu.max",
        "cgroup.procs" => "write cgroup.procs",
        _ => "write",
    }
}

/// Finds a writable cgroup v2 directory that has the memory and pids controllers
/// enabled for its children — the daemon's delegated subtree — by walking up from
/// the current process's cgroup.
pub(crate) fn find_delegated_parent() -> Option<PathBuf> {
    let cgroup = fs::read_to_string("/proc/self/cgroup").ok()?;
    // The unified (v2) entry is the `0::<path>` line.
    let rel = cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim()
        .trim_start_matches('/');
    let mut dir = Path::new("/sys/fs/cgroup").join(rel);
    loop {
        if has_controllers(&dir) && writable(&dir) {
            return Some(dir);
        }
        let parent = dir.parent()?.to_path_buf();
        if parent == Path::new("/sys/fs/cgroup") || parent == dir {
            return None;
        }
        dir = parent;
    }
}

fn has_controllers(dir: &Path) -> bool {
    fs::read_to_string(dir.join("cgroup.subtree_control"))
        .map(|s| {
            let set: Vec<&str> = s.split_whitespace().collect();
            set.contains(&"memory") && set.contains(&"pids")
        })
        .unwrap_or(false)
}

fn writable(dir: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: c is a valid C string; access() only reads it.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_expressed_by_dimension() {
        let l = CgroupLimits {
            max_memory_bytes: Some(1024),
            max_pids: None,
            cpu_max: Some((50_000, 100_000)),
        };
        assert_eq!(l.max_memory_bytes, Some(1024));
        assert!(l.max_pids.is_none());
        assert_eq!(l.cpu_max, Some((50_000, 100_000)));
    }

    /// Live: create a real cgroup, apply memory + pids limits, confine a child
    /// process, and confirm the limits and membership. Needs a writable delegated
    /// cgroup v2 subtree (a systemd user session provides one).
    #[test]
    #[ignore = "needs a writable delegated cgroup v2 subtree; runs in CI's isolation job"]
    fn cgroup_scope_applies_limits_and_confines_a_process() {
        let limits = CgroupLimits {
            max_memory_bytes: Some(64 * 1024 * 1024),
            max_pids: Some(16),
            cpu_max: None,
        };
        let name = format!("akson-test-{}", std::process::id());
        let scope = CgroupScope::create(&name, &limits).expect("create cgroup");

        assert_eq!(
            fs::read_to_string(scope.path().join("memory.max"))
                .unwrap()
                .trim(),
            "67108864"
        );
        assert_eq!(
            fs::read_to_string(scope.path().join("pids.max"))
                .unwrap()
                .trim(),
            "16"
        );

        // Confine a child and confirm it is a member.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        scope.add_process(child.id() as i32).expect("add process");
        let procs = fs::read_to_string(scope.path().join("cgroup.procs")).unwrap();
        assert!(
            procs
                .split_whitespace()
                .any(|p| p == child.id().to_string()),
            "worker pid must appear in cgroup.procs"
        );

        child.kill().unwrap();
        child.wait().unwrap();
        // Dropping `scope` removes the cgroup once the child has exited.
    }
}
