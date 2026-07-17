# ADR-0006: Sandbox launcher — bubblewrap behind a trait seam

Status: accepted
Date: 2026-07-17

## Context

The v1 clean worker (design §13.1) must run in a strong Linux isolation backend:
user/mount/PID/net/IPC/UTS namespaces, `no_new_privs`, a default-deny seccomp
filter, cgroup v2 limits, a digest-pinned read-only runtime with tmpfs
scratch/output, an fd allowlist, a private `/proc`, no network, and Landlock
where available. This is the single most security-critical boundary in the
system: a sandbox escape is catastrophic.

§19 asks to "select reviewed ... libraries." Hand-rolling the launcher (raw
`clone`/`unshare`, `mount`, `pivot_root`, seccomp BPF, cgroup writes) is exactly
where subtle escapes hide — mount propagation, `pivot_root` vs `chroot`, uid_map
ordering, PID-1 reaping, `/proc` masking. The rest of Axon's crypto stack is
deliberately pure Rust (ADR-0011), which pulls the other way.

Environment note: unprivileged user namespaces are increasingly gated by
distributions (e.g. Ubuntu's `kernel.apparmor_restrict_unprivileged_userns`), so
neither a hand-rolled launcher nor bubblewrap can be *validated* on a host that
restricts them. Live validation of the §13.1 checklist requires a permissive
Linux environment (userns unrestricted, a setuid `bwrap`, or root).

## Decision

Use **bubblewrap (`bwrap`) as the Phase-1 launcher, behind a `SandboxLauncher`
trait seam** (maintainer decision).

- `bwrap` is the reviewed, battle-tested unprivileged sandbox used by Flatpak,
  Firefox, and others. Axon **authors the isolation policy** — the bwrap command
  line: `--unshare-all` (no network unless explicitly shared, which v1 never
  does), `--die-with-parent`, `--new-session`, `--clearenv` + explicit
  `--setenv`, `--proc`/`--dev`, `--tmpfs` scratch/output, digest-pinned
  `--ro-bind` runtime, `--chdir`, `--cap-drop ALL`, and a `--seccomp` fd — and
  bwrap enforces it. The seccomp filter is compiled in pure Rust (`seccompiler`)
  and passed by fd, so policy authorship stays ours.
- The **capability probe** (§13.1, `axon_sandbox::ensure`) gates every launch: if
  a required feature is unavailable the launcher refuses rather than run a worker
  un-isolated (fail closed).
- The `SandboxLauncher` trait is the **swap seam**: a future pure-Rust launcher
  is a localized backend change, not a rewrite — the same pattern as the
  `CryptoProvider` seam in ADR-0011.

**Accepted tradeoff.** `bwrap` is C and an external binary: packaging must ensure
a known-good version is present, and the one-use `CLOEXEC` descriptor handoff
(§12.3) crosses the exec boundary (passed as an inherited fd bwrap keeps open for
the intended child). This deviates from the pure-Rust preference. It is accepted
because a reviewed sandbox is the safer choice for the crown-jewel boundary; the
trait seam preserves the pure-Rust option.

## Consequences

- `axon-sandbox` exposes `SandboxLauncher` + `BubblewrapLauncher`. The bwrap argv
  construction (the security policy) is **unit-tested** — testing the argv is
  testing the policy — so the policy is verified even where isolation cannot be
  executed. `launch()` runs the probe first and fails closed.
- Live §13.1-checklist validation (empty environment, no host reach, no generic
  network, deadline/resource enforcement, probing fails closed) runs in a
  permissive Linux environment; on a restricted host the probe refuses, which is
  itself the correct, tested behavior.
- Packaging (M14) must declare a `bwrap` dependency with a minimum version and a
  provenance note; `axon doctor` (M9/M12) surfaces the probe report.
- The seccomp BPF (via `seccompiler`) and Landlock ruleset (via the `landlock`
  crate) are authored in pure Rust and applied through bwrap / post-exec; they
  land as follow-ups on this launcher.
- Supersedes the "open" ADR-0006 placeholder.
