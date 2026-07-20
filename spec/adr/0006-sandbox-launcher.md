# ADR-0006: Sandbox launcher — bubblewrap for namespaces/mount, pure-Rust seccomp + Landlock

Status: accepted
Date: 2026-07-17 (revised after adversarial review — supersedes the same-session
native-launcher draft)

## Context

The v1 clean worker (design §13.1) must run in a strong Linux isolation backend:
user/mount/PID/net/IPC/UTS namespaces, `no_new_privs`, a default-deny seccomp
filter, cgroup v2 limits, a digest-pinned read-only runtime with tmpfs
scratch/output, an **inherited-fd allowlist**, a private `/proc`, no network, and
Landlock where available. This is the single most security-critical boundary in
the system: a bug is a sandbox escape.

This ADR was, within one session, first written for **bubblewrap**, then reversed
to a **pure-Rust native launcher** (own the namespace/mount/`pivot_root`/exec code),
then subjected to an adversarial design review. The review reversed it back, for
reasons that survive scrutiny where the native-launcher justifications did not:

- **The design requires a *reviewed* backend.** §13.1 ("select and publish the
  concrete *reviewed* namespace launcher"), §13.4 ("*independently reviewed*
  equivalent backend"), and §19 principle 6 ("reviewed schemes are reused whenever
  they satisfy the requirement") all point at exactly the kind of audited,
  widely-deployed sandbox that bubblewrap is. In-team review of a few-hundred-line
  launcher written this week is not that.
- **Rust buys almost nothing at this boundary.** A sandbox escape is a *logic* bug
  — a wrong mount flag, an ordering mistake, a reachable path, a leaked file
  descriptor — not a memory-safety bug. The namespace/mount module is `unsafe` raw
  syscalls regardless. Memory safety does not prevent a single reachable inode.
- **The native reasons were ergonomic, not security** (pure-Rust integrity,
  self-contained packaging, testability on a userns-restricted dev host). Flipping
  a crown-jewel security decision requires showing the new choice is *at least as
  safe*; those reasons do not clear that bar.
- **Concrete evidence.** The review found real latent escapes in the native code
  that bubblewrap already handles: no inherited-fd allowlist (a leaked dirfd makes
  `pivot_root` cosmetic — §13.1 mandates the allowlist); a predictable
  `/tmp/.akson-root-<pid>` root with `mkdir`-accepts-`EEXIST` (a symlink attack on a
  shared host); and heavy allocation between `fork()` and `execve()` in a
  multithreaded daemon (async-signal-safety hazard). Bubblewrap's fork→exec-a-tiny-
  init model and fd handling avoid this class.

Two of the four pillars — **seccomp** and **Landlock** — need no user namespace,
are already implemented in pure Rust, and are validated by enforcement tests.

## Decision

Use **bubblewrap (`bwrap`) for the namespace / mount / `pivot_root` / exec
boundary, and keep the pure-Rust `seccomp` (`seccompiler`) and `Landlock`
(`landlock` crate) policies** — all behind the existing `SandboxLauncher` trait.

- Akson **authors the isolation policy** (namespaces, no-network, `--clearenv` +
  explicit env, `--die-with-parent`, `--new-session`, `--cap-drop ALL`, private
  `/proc`/`/dev`, read-only digest-pinned runtime binds, tmpfs scratch/output, the
  **fd allowlist**, `--chdir`) and hands bubblewrap the compiled seccomp BPF via
  `--seccomp <fd>`; bubblewrap enforces the namespace/mount policy. The pure-Rust
  seccomp filter and the Landlock ruleset (applied post-exec / by the worker
  entrypoint) are kept — they are validated and lose nothing.
- Every launch is gated by the **capability probe** (fail-closed) — but the probe
  checks feature *presence*, not launcher *correctness*, so it is not the primary
  safety argument; bubblewrap's scrutiny is.
- The **native launcher stays behind the trait as an experimental backend**, not
  the default. It is promoted to default only after (a) differential validation
  against bubblewrap across an escape corpus and (b) independent review + fuzzing —
  and the structural fixes the review named (fd allowlist in the plan, a fork→exec-
  init process model, an unpredictable `O_NOFOLLOW` root, unconditional
  `nosuid`/`nodev`, best-effort Landlock ABI, real cgroup enforcement).

**Accepted tradeoff (owner-signed).** Bubblewrap is C and an external binary:
packaging (M14) declares a `bwrap` dependency with a minimum version and a
provenance note, and the one-use `CLOEXEC` descriptor handoff (§12.3) crosses the
exec boundary. This deviates from the pure-Rust preference (ADR-0011) at this one
boundary — accepted deliberately, because a reviewed sandbox is the correct choice
where a bug is game-over, and §13.1/§13.4/§19 call for it.

## Consequences

- `akson-sandbox` exposes `SandboxLauncher`, a `BubblewrapLauncher` (default v1),
  and the experimental `NativeLauncher`. The pure-Rust `SeccompPolicy` and
  `LandlockPolicy` are backend-independent and used with either.
- The two CRITICAL native gaps (fd leak, fork/alloc) are dissolved for the shipping
  path — bubblewrap handles fd closing and the fork/exec model.
- The bubblewrap argv construction (the policy) is unit-tested; the seccomp and
  Landlock enforcement remain validated unprivileged. Live §13.1-checklist runs in
  a permissive environment (userns enabled locally or a CI runner).
- The native namespace/mount code is retained (validated for user+net entry and
  pivot_root filesystem isolation) as the experimental backend, with the review's
  structural fixes tracked before it could ever be the default.
- Supersedes the "open" placeholder, the same-session bubblewrap draft, and the
  same-session native-launcher revision.
