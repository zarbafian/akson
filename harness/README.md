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
  order: format, clippy, the unit + integration tests (including the seccomp and
  Landlock enforcement tests), the golden-vector cross-check, **both** interop
  scenarios (pairing, then the coordination dispatch), the public-processor CA
  path, and the live namespace-isolation checks. `FAST=1` skips clippy for a
  quicker loop.

  **Three of those sections can be skipped by the host, and the script says so
  out loud rather than passing quietly.** The cross-check needs the third-party
  `rfc8785` canonicalizer (the whole point is an *independent* rederivation, so
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
    a process and removing it, all unprivileged. Each step that needs it joins the
    subtree through `harness/ci/in-cgroup.sh` (membership is per-process, so it
    cannot be inherited from an earlier step).

  If that fails, `delegate-cgroup.sh` exits 0 and reports `delegated=false` — a
  missing kernel capability is an environment gap, not a failed check, the same
  rule `run-checks.sh` follows. The job then passes libtest `--skip` flags naming
  `cgroup_scope_applies_limits_and_confines_a_process` and
  `live_confined_launch_composes_all_isolation` so they are visibly **not run**,
  prints a `SKIPPED` block, raises a workflow warning annotation, writes the gap
  to the run summary, and closes with a different sentence than a complete run:

  ~~~text
  ALL SANDBOX ISOLATION CHECKS RAN — seccomp, Landlock, namespaces, mount, bwrap, cgroup
  ISOLATION CHECKS PASSED, WITH THE CGROUP HALF SKIPPED — see the SKIPPED block above
  ~~~

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
