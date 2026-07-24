//! The Linux isolation launcher: namespaces, seccomp, cgroups v2, Landlock, and
//! fail-closed capability probing (design §13.1).
//!
//! This crate is the workspace's OS-syscall boundary: applying namespaces,
//! seccomp, Landlock, and cgroup limits requires direct `libc`/`prctl`/`seccomp`
//! calls, so `unsafe` (denied workspace-wide) is allowed here alone. Every
//! `unsafe` block carries a `SAFETY:` justification and is confined to raw
//! syscalls that do not allocate or lock.
#![allow(unsafe_code)]
//!
//! The isolation *mechanism* (the launcher backend) is decided by ADR-0006 and
//! requires a permissive Linux environment to validate. This module lands the
//! backend-independent, always-testable piece first: [`detect`]ing which kernel
//! isolation features are available and [`ensure`]-ing the required ones are
//! present before any worker runs — a launch is refused, never downgraded, when
//! isolation cannot be established.

mod cgroup;
mod channel;
mod diagnostics;
mod landlock;
mod launcher;
mod mount;
mod namespace;
mod probe;
mod seccomp;

pub use cgroup::{prepare_delegated_subtree, CgroupError, CgroupLimits, CgroupScope};
pub use channel::broker_socketpair;
pub use diagnostics::{all_required_available, diagnose, Diagnostic};
pub use landlock::{LandlockError, LandlockOutcome, LandlockPolicy};
pub use launcher::{
    BubblewrapLauncher, MountOp, Namespace, NativeLauncher, SandboxError, SandboxLauncher,
    SandboxPlan, SandboxSpec,
};
pub use mount::{setup_root, MountError};
pub use namespace::{enter_namespaces, NamespaceError};
pub use probe::{detect, ensure, required, Feature, IsolationFeatures, MissingFeatures};
pub use seccomp::{DenyAction, SeccompError, SeccompPolicy};
