# Akson interop test harness

Runnable Akson endpoints for **multi-endpoint scenarios** — first contact, contract
exchange, work-order flow, and (later) `codex ↔ claude`-style adapter runs — over
real sockets, real mTLS, and real on-disk state. The harness exercises the shipped
crates end to end; it is **not** the daemon. `aksond` exists — the harness binary
is a separate, seeded, test-only wiring of the same crates, so a scenario can
stand up two endpoints with deterministic keys and no operator state.

## Validation: local on demand + CI

Two complementary paths:

- **Local, on demand** — `./harness/run-checks.sh` runs the whole suite in this
  order: format, the docs drift check, clippy, the unit + integration tests
  (including the seccomp and Landlock enforcement tests), the golden-vector
  cross-check, **both** interop scenarios (pairing, then the coordination
  dispatch), the public-processor CA path, and the live namespace-isolation
  checks. `FAST=1` skips clippy for a quicker loop.

  **Four of those sections can be skipped by the host, and the script says so
  out loud rather than passing quietly.** The docs check needs `python3` (nothing
  else — it is pure stdlib); the cross-check needs the third-party `rfc8785`
  canonicalizer (the whole point is an *independent* rederivation, so
  substituting our own would defeat it); the CA path needs outbound TCP 443; and
  the namespace-isolation checks need **unprivileged user namespaces** — where a
  host restricts them (e.g. Ubuntu's `apparmor_restrict_unprivileged_userns`) the
  script prints the exact one-run enable/restore commands. Each skip prints a
  `SKIPPED` block explaining what was *not* established, and the closing line is
  deliberately not the same sentence as a clean run:

  ~~~text
  ALL ON-DEMAND CHECKS PASSED                                  # nothing skipped
  CHECKS PASSED, WITH 2 SKIPPED — see the SKIPPED block(s) above
  SOME CHECKS FAILED                                           # exit 1
  ~~~

  A green line that hides a skipped check teaches people to stop reading the
  output, so there isn't one.
- **CI** (`.github/workflows/ci.yml`) — the `isolation` job runs on a GitHub
  `ubuntu-latest` runner, which has passwordless sudo, so it **enables unprivileged
  user namespaces itself** and runs the live namespace/mount checklist that a
  restricted local host cannot. This is the home for validating the namespace path
  on every push. Two things a runner does not hand you, and how the job gets them:

  - **bubblewrap** is not in the runner image; the job `apt-get install`s it.
    Without it every live launcher test fails on `spawning bwrap: No such file or
    directory`, which says nothing about isolation.
  - **A delegated cgroup v2 subtree** — `CgroupScope::create()` searches upward
    from the caller's own cgroup for the nearest ancestor with `memory`+`pids` in
    `cgroup.subtree_control` that this user can write. A systemd *user session*
    gives a developer one for free; a runner gives none, because every step lives
    in the runner service's root-owned cgroup. `harness/ci/delegate-cgroup.sh`
    carves one out with sudo and chowns it to the job user — delegation by hand —
    then *proves* it by creating a leaf, setting `memory.max`/`pids.max`, placing
    a process and removing it, all unprivileged.

    Each step then joins the subtree through `harness/ci/in-cgroup.sh`, because
    cgroup membership is per-process and cannot be inherited from an earlier
    step. **Joining needs sudo, and `[ -w ]` cannot tell you so.** cgroup v2
    *delegation containment* lets an unprivileged process migrate a process only
    if it can write both the destination's `cgroup.procs` **and** the
    `cgroup.procs` of the **common ancestor** of source and destination. On a
    runner the step starts inside the runner service's cgroup, so that ancestor
    is at or near the hierarchy root and stays root-owned however much is chowned
    beneath it — `access(2)` reads permission bits and sees none of this.
    Entering the subtree is the *only* privileged act: `exec` keeps the uid, so
    everything the tests then do runs as the job user, and
    `cgroup::refuse_to_run_as_root()` makes the two live cgroup tests panic
    rather than report a meaningless pass if they ever run as root.

  **A gap can be discovered late, and that must not turn the job red.**
  `harness/ci/isolation-env.sh` owns which live tests depend on which capability
  and what a skip looks like, and every discovery routes through it: bubblewrap
  failing to install, no delegated subtree, or a subtree that builds cleanly and
  then refuses to be entered. Each one exits 0, passes libtest `--skip` flags
  naming the affected tests so they are visibly **not run**, prints a `SKIPPED`
  block, raises a workflow warning annotation, writes the gap to the run summary,
  and steps that cannot run at all (the bwrap e2e demos) are `if:`-gated so the
  run's step list shows them skipped. The job closes with a different sentence
  than a complete run:

  ~~~text
  ALL SANDBOX ISOLATION CHECKS RAN — seccomp, Landlock, namespaces, mount, bwrap, cgroup
  ISOLATION CHECKS PASSED, WITH GAPS — cgroup-join — see the SKIPPED block(s) above
  ~~~

  The job is red only when an isolation check actually fails.

  A green tick for a test that did not run is the thing this job exists to avoid.

**Open-source tools only.** Container scenarios use **Podman** (Apache-2.0,
daemonless, rootless) as the reference runtime; the compose file and scripts are
runtime-agnostic and also run under `docker compose`. The three worker adapters
(`adapters/openai`, `adapters/anthropic`, `adapters/gemini`) have landed, but **no
harness scenario uses a model**: every scenario here runs the built-in endpoints
only, so the suite needs no vendor account and no network. The confined-adapter
path is exercised elsewhere — `run-checks.sh` builds the OpenAI adapter and runs
it against a *mock* model reached only through the broker
(`cargo test -p aksond --test receive_e2e the_openai_adapter -- --ignored`), which
needs unprivileged user namespaces. A real local-model scenario (§4.4 — a FOSS
model, no vendor account) is still future work.

## Runner

`harness/runner` builds the `akson-harness` binary — a thin wiring of the shipped
crates into a runnable endpoint (keys and the store KEK are derived from a
`--seed`, so it is **test-only**):

- `akson-harness token --seed <n> [--advertise host:port] --token-out <f>`
- `akson-harness serve --state <db> --seed <n> [--host H] [--advertise A] [--port P] --token-out <f> [--import <token-file> --label <l>] [--agent NAME]`
- `akson-harness introduce --state <db> --seed <n> --token <token-file> [--agent NAME]`
- `akson-harness coord-dispatch --state <db> --seed <n> --token <token-file> [--agent NAME] [--label <l>] [--payload <text>]` — introduce, then drive the whole ADR-0016 coordination chain over **real control sockets**

## Docs drift check

`harness/check-docs.py` holds the published site (`docs/`) to the code and the
specs. The pages state operation names, counts, envelope members, timeouts and a
version — all hand-copied out of sources that move. That is how a false claim
survives a change: the source moves, the prose does not, and nothing fails.

Every mechanically-derivable claim lives inside a marked region of the HTML, so
it can be regenerated and compared rather than eyeballed:

```html
<!--gen:coord-op-count-->eight<!--/gen:coord-op-count-->
```

```sh
python3 harness/check-docs.py           # check; non-zero and a named block on drift
python3 harness/check-docs.py --write   # regenerate every block from the sources
```

- **What you write** is ordinary prose, plus a `<!--gen:NAME-->…<!--/gen:NAME-->`
  wherever a fact belongs to a source rather than to you.
- **The plumbing** is the script: it parses `ControlRequest` and
  `ControlOp::required_surface` for the registry, the envelope schema and the
  `spec/vectors/coordination/` goldens for the wire, `a2a_client.rs` for the
  per-stage carriage timeouts, `akson-store` for the egress states, and
  `Cargo.toml` for the version — then cross-checks code against vectors, resolves
  every internal link and fragment, and parses each page for balanced tags.

The one-line purposes beside each operation and envelope member are editorial, so
they live in the script keyed by the name the source produces. A **new** op or
member therefore fails the check with "no description for it" rather than being
silently omitted from the site: the registry cannot grow without the docs being
told.

Pure stdlib — no packages, so `python3` is the only requirement, and its absence
is a loud `SKIPPED` rather than a quiet pass.

## Scenarios

| # | Scenario | Status | Maps to |
|---|----------|--------|---------|
| 1 | First contact over identity tokens | **runnable** (`scenario-pairing.sh`) | Layer-1 interop checkpoint, §8.2 / ADR-0015 |
| 2 | Consented coordination dispatch (stage → consent → dispatch → carry) | **runnable** (`scenario-coord-dispatch.sh`) | ADR-0016 §2, C4 slice 3 |
| 3 | Signed contract → accept → work order | no two-process harness scenario; the path itself is built and covered in-process by `crates/aksond/tests/receive_e2e.rs` and across two hosts by `bench/` | Layer-2, §10.2 |
| 4 | Crash injection at each commit point | planned (`crates/aksond/tests/crash_matrix.rs` covers the contract path in-process; no harness scenario, and no coordination row) | §19 crash matrix (M15) |
| 5 | `codex ↔ claude` adapter round trip | planned | G0 adapter gate (M13) |

Both runnable scenarios are in `run-checks.sh`, so they are not optional extras.

### Run scenario 1 locally (no containers)

```sh
./harness/interop/scenario-pairing.sh
```

Two processes: each writes its public identity token (the out-of-band
exchange as a file drop); endpoint-a imports endpoint-b's and serves;
endpoint-b imports endpoint-a's and dials the introduction. Prints
`INTRODUCED with endpoint-a` on success.

### Run scenario 1 in containers

```sh
podman build -f harness/interop/Containerfile -t akson-harness .
podman compose -f harness/interop/compose.yaml up --abort-on-container-exit
```

`compose.yaml` covers **scenario 1 only**; there is no containerised form of
scenario 2 yet.

### Run scenario 2 locally (no containers)

```sh
./harness/interop/scenario-coord-dispatch.sh
```

Two processes over real TLS 1.3 mutual authentication. endpoint-b introduces
itself to endpoint-a, then runs the whole coordination surface for real: `stage`
(inert, on the **coord** socket), `stage consent` (the operator's one-shot yes,
on **admin**), and `dispatch` — which spends the receipt, commits, and carries
the staged bytes to endpoint-a in an ADR-0016 coordination envelope. Every step
is a request on the real control socket that owns it, so `authorize(Surface, op)`
actually runs.

```text
INTRODUCED with endpoint-a (Committed)
STAGED stage-3d9c998fa54e0cad… (digest "3d9c998fa54e0cad…")
CONSENT REFUSED ON COORD urn:akson:error:forbidden-surface
CONSENTED consent-79147be5470b71ac69e2a54e650724e8
DISPATCHED sent receipt="dispatch-fc8fb6813da89aa1…" detail="acknowledged by Nps-JjcO…"
REPLAY REFUSED urn:akson:error:consent-spent
SCENARIO OK — a consented coordination payload crossed two processes over mTLS
```

Three of those lines are assertions the scenario fails on, not decoration: the
coordination socket must be **refused** the consent op (it is admin's alone);
`sent` must come from endpoint-a echoing the exact staged digest rather than from
the sender's optimism; and a second execution key against the spent receipt must
be refused `consent-spent`.

What this proves that an in-process test cannot: the bytes crossed a process
boundary and a socket, and endpoint-a verified the envelope's digests against the
payload it actually read and the sender against the certificate it pinned at
introduction. What it does **not** prove: both endpoints are akson, so this is
producer-only — no second implementation has run against this surface. And the
receiving side deliberately does not retain the payload, so there is nothing on
endpoint-a to inspect afterwards beyond the `dispatch_received` event.

## Running the sandbox (§13.1) in a container — read this first

The clean-worker sandbox (`akson-sandbox`, ADR-0006) needs **unprivileged user
namespaces, mount, and `pivot_root`** — exactly the operations a **stock**
container's default seccomp/AppArmor/no-userns profile *blocks*. A naive
`podman run akson-tests` will fail the sandbox checklist the same way a restricted
host does, and it will look like the sandbox is broken when it is not
(sandbox-inside-sandbox: the outer runtime must be permissive enough for the inner
one). Run sandbox-validation scenarios with a deliberately permissive runtime —
`--privileged`, or targeted `--cap-add`/`--security-opt seccomp=unconfined
--security-opt apparmor=unconfined` plus userns config.

For **local, on-demand** validation without containers, the simplest path is to
enable unprivileged user namespaces for a single run and let `run-checks.sh`
execute the namespace checklist directly:

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
./harness/run-checks.sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1   # restore hardening
```

(seccomp and Landlock need no user namespace and are validated directly, even on
a restricted host.)
