# ADR-0006: Sandbox launcher — pure-Rust native launcher behind a trait seam

Status: accepted
Date: 2026-07-17

## Context

The v1 clean worker (design §13.1) must run in a strong Linux isolation backend:
user/mount/PID/net/IPC/UTS namespaces, `no_new_privs`, a default-deny seccomp
filter, cgroup v2 limits, a digest-pinned read-only runtime with tmpfs
scratch/output, an fd allowlist, a private `/proc`, no network, and Landlock
where available. This is the single most security-critical boundary in the
system: a sandbox escape is catastrophic.

Two backends were weighed:

- **bubblewrap (`bwrap`)** — the reviewed, battle-tested unprivileged sandbox
  (Flatpak, Firefox). Axon would author the policy as a bwrap command line and
  bwrap would enforce it.
- **a pure-Rust native launcher** — Axon applies the isolation itself via Rust
  crates (`nix`/`rustix` namespaces + mount + `pivot_root`, `seccompiler` seccomp,
  the `landlock` crate, direct cgroup v2 writes).

The decisive considerations:

1. **Neither can be validated on a restricting host.** Both namespace paths need
   unprivileged user namespaces, which this environment blocks
   (`kernel.apparmor_restrict_unprivileged_userns = 1`). So bwrap's "get to
   correct faster" edge is weak — you cannot confirm correctness here regardless,
   and in a permissive environment a native launcher is equally testable.
2. **Pure-Rust integrity and packaging.** The rest of Axon is one auditable
   language with no C (ADR-0011), and the daemon is a self-contained binary. bwrap
   reintroduces C, an external binary, a subprocess boundary, and a versioned
   runtime dependency the signed package and SBOM (§17.2) must carry. A native
   launcher keeps the product self-contained.
3. **Two pillars are validatable *now*.** seccomp (with `no_new_privs`) and
   Landlock require no user namespace, so a native launcher can enforce and
   *test* them unprivileged — including on this restricted host — which bwrap
   cannot expose.

bwrap's one remaining edge is breadth of external scrutiny on the subtle
namespace/mount/`pivot_root` code. This is real, and is mitigated by keeping that
surface small, testing it in a permissive environment, and the fail-closed probe.

## Decision

Build a **pure-Rust native launcher** (`NativeLauncher`) behind a
`SandboxLauncher` trait seam.

- Axon authors the isolation policy as a `SandboxSpec`; `NativeLauncher` resolves
  it into a `SandboxPlan` (the ordered isolation steps — namespaces to unshare,
  mounts, env, capability drop, `no_new_privs`, seccomp filter, Landlock ruleset,
  cgroup limits) and applies it. The **plan is data**, so it is fully unit-tested
  without executing.
- seccomp filters are built with `seccompiler` and Landlock rulesets with the
  `landlock` crate — both pure Rust — and are **enforced and tested unprivileged**
  (seccomp under `no_new_privs`, Landlock via `restrict_self`), including on a
  userns-restricted host.
- The namespace/mount/`pivot_root`/exec sequence (via `nix`/`rustix`) is applied
  after the capability probe; its live validation (the §13.1 checklist) runs in a
  permissive Linux environment.
- Every launch is gated by the **capability probe** (`axon_sandbox::ensure`): a
  missing required feature refuses the launch, never a downgrade (fail closed).
- The `SandboxLauncher` trait is the swap seam — bwrap (or another backend)
  remains a localized alternative implementation, and may be used as a **test
  oracle** to cross-check the native isolation in a permissive environment.

## Consequences

- `axon-sandbox` exposes `SandboxLauncher` + `NativeLauncher` + `SandboxSpec` +
  `SandboxPlan`. No external runtime binary; the daemon stays self-contained, and
  M14 packaging carries no bwrap dependency.
- `SandboxPlan` construction (the policy) is unit-tested; seccomp and Landlock
  enforcement are validated unprivileged in-repo; the namespace/mount/exec path is
  validated in a permissive environment and refused (probe) elsewhere.
- We own the escape surface: the namespace/mount/`pivot_root` code is kept minimal
  and reviewed, and may be cross-checked against bwrap as an oracle.
- Dependencies to add as the pieces land: `nix` (namespaces/mount/exec),
  `seccompiler` (seccomp BPF), `landlock` (Landlock ruleset).
- Supersedes both the "open" ADR-0006 placeholder and the earlier same-session
  bubblewrap draft.
