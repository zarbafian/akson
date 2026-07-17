//! The Linux isolation launcher: namespaces, seccomp, cgroups v2, Landlock, and
//! fail-closed capability probing (design §13.1).
//!
//! The isolation *mechanism* (the launcher backend) is decided by ADR-0006 and
//! requires a permissive Linux environment to validate. This module lands the
//! backend-independent, always-testable piece first: [`detect`]ing which kernel
//! isolation features are available and [`ensure`]-ing the required ones are
//! present before any worker runs — a launch is refused, never downgraded, when
//! isolation cannot be established.

mod launcher;
mod probe;

pub use launcher::{
    MountOp, Namespace, NativeLauncher, SandboxError, SandboxLauncher, SandboxPlan, SandboxSpec,
};
pub use probe::{detect, ensure, required, Feature, IsolationFeatures, MissingFeatures};
